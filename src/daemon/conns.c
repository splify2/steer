#include "ctnl.h"
#include "jsonw.h"
#include "spec.h"
#include "groups.h"
#include "nftdump.h"
#include "daemon.h"
#include "rrkeep.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

/* ---- соединения движка: `steer conns` (команда conns управляющего сокета) --------------
 *
 * ЗАЧЕМ. Экран «Соединения» приложения (план C1): какие соединения сейчас идут через каналы
 * движка и в какой выход. Источник правды — conntrack: метку выхода соединению ставят правила
 * движка (ct mark), и она же решает маршрут каждого следующего пакета, то есть запись
 * conntrack с меткой — это ровно «соединение, которое движок куда-то повёл». Инструмента
 * conntrack в образе Android нет, /proc/net/nf_conntrack у ядра телефона нет тоже
 * (CONFIG_NF_CONNTRACK_PROCFS выключен), поэтому — тот же дамп ctnetlink, что у снятия.
 *
 * ЧТО ПОПАДАЕТ. Записи, у которых ПОЛЕ метки движка (STEER_MARK_MASK) не ноль. Чужие биты вне
 * поля (netd на телефоне кладёт в метку номер сети и права) не мешают и не показываются.
 * Значение «все биты поля» на телефоне — не выход, а собственный трафик движка
 * (STEER_SELF_MARK: запросы резолвера наверх), и в список оно не идёт: человеку в «Соединениях»
 * нужны его приложения, а не служебные запросы DNS самого движка.
 *
 * ВЫХОД — по метке из реестра меток каталога состояния (<state>/registry, «имя метка таблица»),
 * а не из спеки. В ядре стоят метки ПРИМЕНЁННОЙ спеки, и реестр — их запись; сохранённая, но
 * не применённая спека (движок выключен, apply отвергнут ядром) меток в пакетах не меняла.
 * Метки нет в реестре (выход убран, а его соединения ещё доживают) — "out":null.
 *
 * UID ПРИЛОЖЕНИЯ здесь нет и не выдумывается: conntrack его не хранит (метка сокета и skuid
 * живут в сокете, а не в записи соединения), и угадывать его по порту значило бы показывать
 * человеку неправду.
 *
 * СЧЁТЧИКИ (packets/bytes, reply_packets/reply_bytes) — только если ядро их ведёт: у 4.9 и у
 * свежих ядер это sysctl net.netfilter.nf_conntrack_acct, по умолчанию выключенный, и запись,
 * заведённая без него, счётчиков не получает и потом. Нет атрибута — нет поля: ноль означал бы
 * «ничего не передано», а это неправда.
 *
 * ПРЕДЕЛ — CONNS_MAX записей в ответе; остальные считаются (total), но не печатаются, и ответ
 * несёт "truncated":true. Запись — до ~350 байт JSON (два адреса IPv6), 2000 записей — ~700 КиБ,
 * с запасом внутри предела вывода управляющего сокета (1 МиБ, CTL_OUT_MAX в ctl.c): ответ
 * через сокет обрезаться посреди JSON не должен никогда. На телефоне живых соединений сотни.
 *
 * БАТАРЕЯ. Одна команда — два дампа (IPv4 и IPv6) по запросу экрана; ничего не остаётся жить. */
#define CONNS_MAX 2000

struct conns_reg { char name[32]; uint32_t mark; };

struct ctnl_conns_ctx {
    FILE *out;
    int shown, total;
    struct conns_reg *reg;                   /* растёт по числу записей реестра */
    size_t reg_n, reg_cap;
};

static const char *ct_proto_name(uint8_t p) {
    switch (p) {
    case IPPROTO_TCP: return "tcp";
    case IPPROTO_UDP: return "udp";
    case IPPROTO_ICMP: return "icmp";
    case IPPROTO_ICMPV6: return "icmpv6";
    case IPPROTO_SCTP: return "sctp";
    case IPPROTO_UDPLITE: return "udplite";
    case IPPROTO_DCCP: return "dccp";
    case IPPROTO_GRE: return "gre";
    default: return NULL;
    }
}

/* Состояние TCP из conntrack — те же имена, что печатает инструмент conntrack, строчными.
 * Номера — enum tcp_conntrack ядра; они не менялись с 2.6 (SYN_SENT2 = 9, прежний LISTEN). */
static const char *ct_tcp_state(uint8_t st) {
    static const char *const N[] = { "none", "syn_sent", "syn_recv", "established", "fin_wait",
                                     "close_wait", "last_ack", "time_wait", "close", "syn_sent2" };
    return st < sizeof(N) / sizeof(N[0]) ? N[st] : NULL;
}

/* Число из атрибута счётчика: be64 у свежих ядер и у 4.9, be32 у очень старых (CTA_COUNTERS32_*).
 * Атрибут be64 в сообщении выровнен только на 4 байта — поэтому чтение по байтам, а не
 * разыменование. */
static int ct_counter(const struct nlattr *nest, int t64, int t32, unsigned long long *v) {
    const struct nlattr *x = ct_attr_in(nest, t64);
    if (x && x->nla_len >= NLA_HDRLEN + 8) {
        /* По байтам, старший первым: так одинаково верно и на little-endian телефоне, и на
         * big-endian роутере (MIPS), без be64toh, которого нет в каждой libc. */
        const uint8_t *q = (const uint8_t *)x + NLA_HDRLEN;
        unsigned long long r = 0;
        for (int i = 0; i < 8; i++) r = (r << 8) | q[i];
        *v = r;
        return 1;
    }
    x = ct_attr_in(nest, t32);
    if (x && x->nla_len >= NLA_HDRLEN + 4) {
        uint32_t b;
        memcpy(&b, (const uint8_t *)x + NLA_HDRLEN, 4);
        *v = ntohl(b);
        return 1;
    }
    return 0;
}

static void ct_print_counters(FILE *out, const struct nlattr *nest, const char *pfx) {
    unsigned long long v;
    if (!nest) return;
    if (ct_counter(nest, CTA_COUNTERS_PACKETS, CTA_COUNTERS32_PACKETS, &v))
        fprintf(out, ",\"%spackets\":%llu", pfx, v);
    if (ct_counter(nest, CTA_COUNTERS_BYTES, CTA_COUNTERS32_BYTES, &v))
        fprintf(out, ",\"%sbytes\":%llu", pfx, v);
}

static int ctnl_conns_rec(const uint8_t *a, const uint8_t *end, uint8_t family, void *vctx) {
    struct ctnl_conns_ctx *x = vctx;
    uint32_t field = ct_mark_of(a, end) & STEER_MARK_MASK;
    if (!field) return 0;
    /* «Сам движок» (только там, где свой трафик метится, — на телефоне) — не выход. */
    if (STEER_SELF_MARK && field == (STEER_SELF_MARK & STEER_MARK_MASK)) return 0;
    const struct nlattr *orig = ct_attr(a, end, CTA_TUPLE_ORIG);
    const struct nlattr *tip = ct_attr_in(orig, CTA_TUPLE_IP);
    const struct nlattr *tpr = ct_attr_in(orig, CTA_TUPLE_PROTO);
    int v6 = family == AF_INET6;
    size_t alen = v6 ? 16 : 4;
    const struct nlattr *sa = ct_attr_in(tip, v6 ? CTA_IP_V6_SRC : CTA_IP_V4_SRC);
    const struct nlattr *da = ct_attr_in(tip, v6 ? CTA_IP_V6_DST : CTA_IP_V4_DST);
    const struct nlattr *pn = ct_attr_in(tpr, CTA_PROTO_NUM);
    if (!sa || !da || !pn || sa->nla_len < NLA_HDRLEN + alen || da->nla_len < NLA_HDRLEN + alen ||
        pn->nla_len < NLA_HDRLEN + 1)
        return 0;                              /* запись без кортежа — показывать нечего */
    x->total++;
    if (x->shown >= CONNS_MAX) return 0;
    char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
    inet_ntop(family, (const uint8_t *)sa + NLA_HDRLEN, s, sizeof(s));
    inet_ntop(family, (const uint8_t *)da + NLA_HDRLEN, d, sizeof(d));
    uint8_t proto = *((const uint8_t *)pn + NLA_HDRLEN);
    FILE *out = x->out;
    fprintf(out, "%s{\"family\":\"%s\",\"proto\":", x->shown ? "," : "", v6 ? "ipv6" : "ipv4");
    const char *pnm = ct_proto_name(proto);
    if (pnm) fprintf(out, "\"%s\"", pnm);
    else fprintf(out, "\"%u\"", proto);
    fprintf(out, ",\"src\":\"%s\"", s);
    /* Порты — только у протоколов с портами: у ICMP в кортеже вместо них тип, код и номер. */
    const struct nlattr *sp = ct_attr_in(tpr, CTA_PROTO_SRC_PORT);
    const struct nlattr *dp = ct_attr_in(tpr, CTA_PROTO_DST_PORT);
    uint16_t pv;
    if (sp && sp->nla_len >= NLA_HDRLEN + 2) {
        memcpy(&pv, (const uint8_t *)sp + NLA_HDRLEN, 2);
        fprintf(out, ",\"sport\":%u", ntohs(pv));
    }
    fprintf(out, ",\"dst\":\"%s\"", d);
    if (dp && dp->nla_len >= NLA_HDRLEN + 2) {
        memcpy(&pv, (const uint8_t *)dp + NLA_HDRLEN, 2);
        fprintf(out, ",\"dport\":%u", ntohs(pv));
    }
    fprintf(out, ",\"mark\":\"0x%08x\",\"out\":", field);
    const char *on = NULL;
    for (size_t i = 0; i < x->reg_n; i++)
        if (x->reg[i].mark == field) { on = x->reg[i].name; break; }
    /* Имя выхода из спеки проверено name_ok, но реестр — файл на диске, и строку JSON из него
     * собирает тот же экранирующий писатель, что у журнала имён. */
    if (on) jsonw_str_ascii(out, on);
    else fputs("null", out);
    if (proto == IPPROTO_TCP) {
        const struct nlattr *pi = ct_attr(a, end, CTA_PROTOINFO);
        const struct nlattr *st = ct_attr_in(ct_attr_in(pi, CTA_PROTOINFO_TCP),
                                             CTA_PROTOINFO_TCP_STATE);
        const char *sn = st && st->nla_len >= NLA_HDRLEN + 1
                             ? ct_tcp_state(*((const uint8_t *)st + NLA_HDRLEN)) : NULL;
        if (sn) fprintf(out, ",\"state\":\"%s\"", sn);
    }
    ct_print_counters(out, ct_attr(a, end, CTA_COUNTERS_ORIG), "");
    ct_print_counters(out, ct_attr(a, end, CTA_COUNTERS_REPLY), "reply_");
    fputc('}', out);
    x->shown++;
    return 0;
}

/* Реестр меток: «имя метка таблица» построчно — тот же разбор, что у registry_assign (model/registry.c),
 * и то же отсечение меток вне поля: такая запись осталась от сборки с другим полем и
 * сопоставлять её с записями conntrack нельзя. Только читается: conns ничего не раздаёт. */
static void conns_registry(struct ctnl_conns_ctx *x) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/registry", steer_state_dir());
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32];
    unsigned mark;
    int table;
    while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
        if (!mark || (mark & ~STEER_MARK_MASK)) continue;
        if (x->reg_n == x->reg_cap) {
            size_t nc = x->reg_cap ? x->reg_cap * 2 : 32;
            struct conns_reg *nr = realloc(x->reg, nc * sizeof(*nr));
            if (!nr) break;
            x->reg = nr;
            x->reg_cap = nc;
        }
        snprintf(x->reg[x->reg_n].name, sizeof(x->reg[0].name), "%s", name);
        x->reg[x->reg_n++].mark = mark;
    }
    fclose(f);
}

/* Печать ответа `steer conns`. 0 — готово; 1 — conntrack недоступен (нет сокета
 * NETLINK_NETFILTER, модуля nf_conntrack_netlink или прав), причина — в stderr, stdout пуст. */
int ctnl_conns_print(FILE *out) {
    static struct ctnl_conns_ctx x;
    free(x.reg);                    /* реестр прошлого вызова (в процессе демона вызовов много) */
    memset(&x, 0, sizeof(x));
    x.out = out;
    conns_registry(&x);
    int dfd = ctnl_socket();
    uint8_t *buf = malloc(CTNL_RCVBUF);
    if (dfd < 0 || !buf) {
        fprintf(stderr, "steer[warn] conns: нет сокета ctnetlink (%s)\n", strerror(errno));
        if (dfd >= 0) close(dfd);
        free(buf);
        return 1;
    }
    /* Ответ копится в памяти, а не пишется по ходу: разговор с ядром может оборваться на
     * втором семействе, и тогда в stdout не должно остаться половины JSON. */
    char *mem = NULL;
    size_t memn = 0;
    FILE *m = open_memstream(&mem, &memn);
    if (!m) { close(dfd); free(buf); return 1; }
    x.out = m;
    static const uint8_t fam[] = { AF_INET, AF_INET6 };
    uint32_t seq = (uint32_t)time(NULL);
    int rc = 0;
    for (size_t i = 0; i < sizeof(fam) && rc == 0; i++)
        rc = ctnl_dump(dfd, fam[i], 0, 0, 0, &seq, buf, ctnl_conns_rec, &x);
    fclose(m);
    close(dfd);
    free(buf);
    if (rc != 0) {
        fprintf(stderr, "steer[warn] conns: conntrack не ответил на дамп — нет модуля "
                        "nf_conntrack_netlink или прав\n");
        free(mem);
        return 1;
    }
    fprintf(out, "{\"schema\":1,\"conns\":[%s],\"shown\":%d,\"total\":%d,\"truncated\":%s}\n",
            mem ? mem : "", x.shown, x.total, x.total > x.shown ? "true" : "false");
    free(mem);
    return 0;
}

/* ---- смена выхода правила: соединения прежнего выхода снимаются (apply, reload) ------------
 *
 * ЗАЧЕМ. Метка выхода пишется в метку соединения (`ct mark set mark`), и по ней решают не только
 * маршрут, но и липкость: цепочка balance ведёт соединение, у которого метка — один из её
 * членов, к тому же члену (src/compile/balance.c). Правило перевели с выхода A на группу
 * balance, в которой A — член, — и установленные соединения правила остаются на A до своего
 * конца, а новые идут по раздаче: один сеанс сайта с двух-трёх внешних адресов (живой роутер,
 * 2026-10-03: 29 соединений Discord и Google на прежнем выходе через 25 минут после apply,
 * YouTube — «подозрительный трафик из вашей сети»). Без липкости не лучше: пакет установленного
 * соединения получает новую метку и уходит в другое устройство с подменой адреса, выбранной ещё
 * для прежнего, — сервер такого соединения не знает. Снятая запись conntrack заводится заново по
 * новым правилам: следующий пакет идёт новым путём, сервер отвечает сбросом, приложение
 * соединяется заново уже через новый выход.
 *
 * ЧТО СНИМАЕТСЯ. Правило узнаётся по имени (без имени — по номеру). Изменилось — выход у правила
 * другой, правило снято или выключено. Метки прежнего выхода такого правила — его метка и, у
 * группы balance, метки членов (они и пишутся в соединение). Метка, которую не держит ни одно
 * неизменившееся правило, снимается целиком. Метку держит и неизменившееся правило — тогда
 * снимаются только записи, чьё назначение не лежит ни в одном наборе групп, ведущих в выход с
 * этой меткой (наборы новых правил из ядра, после nft -f: у fake-IP — поддельные адреса
 * резолвера); у такой группы нет набора («весь трафик») или наборы не прочитать — снимается
 * целиком. Привязка выхода сторожем (failover.c, bind_device) — отдельный случай: там правило то
 * же, меняется устройство. */

#define LOG_I "steer[info] ctl: "

struct rr_rule {
    char key[40];
    char out[32];
    unsigned *marks;
    size_t marks_n;
};

struct rr_snap {
    struct rr_rule *r;
    size_t n;
};

static int rr_mark_add(unsigned **v, size_t *n, unsigned m) {
    if (!m) return 0;
    for (size_t i = 0; i < *n; i++) if ((*v)[i] == m) return 0;
    unsigned *nv = realloc(*v, (*n + 1) * sizeof(**v));
    if (!nv) return -1;
    nv[(*n)++] = m;
    *v = nv;
    return 0;
}

/* Метки, которые соединение через выход o может нести: свою и, у balance, — членов (вглубь). */
static int rr_marks_of(const struct spec *sp, const struct output *o, unsigned **v, size_t *n,
                       int depth) {
    if (!o || depth > 16) return 0;
    if (out_needs_mark(o) && rr_mark_add(v, n, o->mark & STEER_MARK_MASK) < 0) return -1;
    if (out_group(o) && o->grp.pick == PICK_BALANCE)
        for (size_t i = 0; i < o->grp.members_n; i++)
            if (rr_marks_of(sp, spec_out(sp, o->grp.members[i]), v, n, depth + 1) < 0) return -1;
    return 0;
}

static void rr_key(const struct spec *sp, size_t i, char *dst, size_t n) {
    if (sp->rule[i].name[0]) snprintf(dst, n, "n:%s", sp->rule[i].name);
    else snprintf(dst, n, "#%zu", i);
}

void reroute_snap_free(struct rr_snap *s) {
    if (!s) return;
    for (size_t i = 0; i < s->n; i++) free(s->r[i].marks);
    free(s->r);
    free(s);
}

struct rr_snap *reroute_snap(const struct spec *sp) {
    if (!sp) return NULL;
    struct rr_snap *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->r = calloc(sp->rule_n ? sp->rule_n : 1, sizeof(*s->r));
    if (!s->r) { free(s); return NULL; }
    for (size_t i = 0; i < sp->rule_n; i++) {
        const struct spec_rule *ru = &sp->rule[i];
        if (ru->disabled || ru->out < 0) continue;
        const struct output *o = spec_out(sp, (size_t)ru->out);
        if (!o) continue;
        struct rr_rule *r = &s->r[s->n];
        rr_key(sp, i, r->key, sizeof(r->key));
        snprintf(r->out, sizeof(r->out), "%s", o->name);
        if (rr_marks_of(sp, o, &r->marks, &r->marks_n, 0) < 0) { reroute_snap_free(s); return NULL; }
        s->n++;
    }
    return s;
}

/* Элементы одного набора, как отдаёт ядро: начала и концы (флаг INTERVAL_END, конец — первый
 * адрес ПОСЛЕ диапазона) порознь; пары собираются после дампа. */
struct rr_raw { uint8_t k[16]; int end; };
struct rr_rawset { struct rr_raw *e; size_t n, cap; size_t alen; int bad; };

static void rr_raw_elem(void *arg, const struct nfd_elem *e) {
    struct rr_rawset *r = arg;
    if (e->klen != r->alen || e->key_end) { r->bad = 1; return; }  /* не адрес одного поля */
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 64;
        struct rr_raw *ne = realloc(r->e, nc * sizeof(*ne));
        if (!ne) { r->bad = 1; return; }
        r->e = ne;
        r->cap = nc;
    }
    memset(r->e[r->n].k, 0, 16);
    memcpy(r->e[r->n].k, e->key, r->alen);
    r->e[r->n].end = (e->flags & 1u) != 0;     /* NFT_SET_ELEM_INTERVAL_END */
    r->n++;
}

static void rr_raw_reset(void *arg) {
    struct rr_rawset *r = arg;
    r->n = 0;
    r->bad = 0;
}

static int rr_raw_cmp(const void *a, const void *b) {
    const struct rr_raw *x = a, *y = b;
    int c = memcmp(x->k, y->k, 16);
    if (c) return c;
    return y->end - x->end;                    /* конец прежнего диапазона — раньше начала */
}

int rr_iv_cmp(const void *a, const void *b) {
    return memcmp(((const struct rr_iv *)a)->lo, ((const struct rr_iv *)b)->lo, 16);
}

static void rr_dec(uint8_t *k, size_t alen) {
    for (size_t i = alen; i-- > 0;) if (k[i]-- != 0) break;
}

static int rr_iv_push(struct rr_ivs *iv, int v6, const uint8_t *lo, const uint8_t *hi) {
    struct rr_iv **v = v6 ? &iv->v6 : &iv->v4;
    size_t *n = v6 ? &iv->n6 : &iv->n4, *c = v6 ? &iv->c6 : &iv->c4;
    if (*n == *c) {
        size_t nc = *c ? *c * 2 : 64;
        struct rr_iv *nv = realloc(*v, nc * sizeof(*nv));
        if (!nv) return -1;
        *v = nv;
        *c = nc;
    }
    memcpy((*v)[*n].lo, lo, 16);
    memcpy((*v)[*n].hi, hi, 16);
    (*n)++;
    return 0;
}

/* Набор name (семейство по alen) — в интервалы. 0 — прочитан или его нет; -1 — не прочитать. */
static int rr_load_set(struct rr_ivs *iv, const char *name, size_t alen) {
    struct rr_rawset r = { NULL, 0, 0, alen, 0 };
    int stable = 0, rc = 0;
    for (int tries = 0; !stable; tries++) {
        if (tries == 3) { rc = -1; break; }
        rr_raw_reset(&r);
        int e = nfd_set_elems(NFD_INET, nft_table(), name, rr_raw_elem, rr_raw_reset, &r, &stable);
        if (e == ENOENT) { free(r.e); return 0; }
        if (e != 0) { rc = -1; break; }
    }
    if (rc == 0 && r.bad) rc = -1;
    if (rc == 0) {
        qsort(r.e, r.n, sizeof(*r.e), rr_raw_cmp);
        int has_end = 0;
        for (size_t i = 0; i < r.n; i++) has_end |= r.e[i].end;
        uint8_t max[16];
        memset(max, 0, 16);
        memset(max, 0xff, alen);
        for (size_t i = 0; i < r.n && rc == 0; i++) {
            if (r.e[i].end) continue;
            if (!has_end) { rc = rr_iv_push(iv, alen == 16, r.e[i].k, r.e[i].k); continue; }
            /* Начало интервального набора: конец — следующий элемент с флагом конца; нет его —
             * диапазон до последнего адреса. */
            uint8_t hi[16];
            if (i + 1 < r.n && r.e[i + 1].end) {
                memcpy(hi, r.e[i + 1].k, 16);
                rr_dec(hi, alen);
            } else {
                memcpy(hi, max, 16);
            }
            rc = rr_iv_push(iv, alen == 16, r.e[i].k, hi);
        }
    }
    free(r.e);
    return rc;
}

/* После сортировки по началу: pm[i] = max(hi[0..i]). Интервалы перекрываются, и «назначение лежит
 * в каком-то из них с началом не больше адреса» — это «наибольший конец среди них не меньше адреса»:
 * rr_keep отвечает двоичным поиском, без прохода назад по всем интервалам для каждой записи. */
void rr_iv_ready(struct rr_iv *v, size_t n) {
    for (size_t i = 0; i < n; i++) {
        memcpy(v[i].pm, v[i].hi, 16);
        if (i && memcmp(v[i - 1].pm, v[i].pm, 16) > 0) memcpy(v[i].pm, v[i - 1].pm, 16);
    }
}

int rr_keep(uint8_t family, const uint8_t *dst, void *ctx) {
    const struct rr_ivs *iv = ctx;
    int v6 = family == AF_INET6;
    size_t alen = v6 ? 16 : 4, n = v6 ? iv->n6 : iv->n4;
    const struct rr_iv *v = v6 ? iv->v6 : iv->v4;
    uint8_t k[16];
    memset(k, 0, 16);
    memcpy(k, dst, alen);
    /* Интервалы с началом не больше адреса — префикс; адрес в одном из них, если не дальше
     * наибольшего конца префикса (pm, rr_iv_ready). Перекрытия разных наборов этому не мешают. */
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (memcmp(v[mid].lo, k, 16) <= 0) lo = mid + 1; else hi = mid;
    }
    return lo > 0 && memcmp(v[lo - 1].pm, k, 16) >= 0;
}

/* Снятие для одной метки, которую держат и неизменившиеся правила: оставить записи с
 * назначением в наборах групп, ведущих в выход с этой меткой. 0 — снято по наборам; -1 — по
 * наборам нельзя (группа без набора, набор не прочитан): вызывающий снимает целиком. */
static int rr_evict_filtered(const struct spec *sp, const struct groups *gr, unsigned mark,
                             int *evicted) {
    struct rr_ivs iv;
    memset(&iv, 0, sizeof(iv));
    int rc = 0, any = 0;
    for (size_t i = 0; i < gr->n && rc == 0; i++) {
        const struct group *g = &gr->g[i];
        const struct output *o = out_by_name(sp, g->out);
        unsigned *m = NULL;
        size_t mn = 0;
        if (rr_marks_of(sp, o, &m, &mn, 0) < 0) rc = -1;
        int hit = 0;
        for (size_t k = 0; k < mn; k++) hit |= m[k] == mark;
        free(m);
        if (rc || !hit) continue;
        any = 1;
        if (!group_has_set(g)) { rc = -1; break; }
        char s6[80];
        group_set6_name(g, s6, sizeof(s6));
        if (rr_load_set(&iv, g->name, 4) < 0 || rr_load_set(&iv, s6, 16) < 0) rc = -1;
    }
    if (rc == 0 && !any) rc = -1;
    if (rc == 0) {
        qsort(iv.v4, iv.n4, sizeof(*iv.v4), rr_iv_cmp);
        qsort(iv.v6, iv.n6, sizeof(*iv.v6), rr_iv_cmp);
        rr_iv_ready(iv.v4, iv.n4);
        rr_iv_ready(iv.v6, iv.n6);
        *evicted = ctnl_evict_mark_keep(mark, STEER_MARK_MASK, rr_keep, &iv);
        if (*evicted < 0) rc = -1;
    }
    free(iv.v4);
    free(iv.v6);
    return rc;
}

void reroute_evict(const struct rr_snap *old, const struct spec *sp, const struct groups *gr) {
    if (!old || !sp || !gr) return;
    struct rr_snap *now = reroute_snap(sp);
    if (!now) return;
    unsigned *cand = NULL, *pin = NULL;
    size_t cand_n = 0, pin_n = 0;
    char names[512] = "";
    size_t nl = 0;
    int oom = 0;
    for (size_t i = 0; i < old->n && !oom; i++) {
        const struct rr_rule *r = &old->r[i];
        const struct rr_rule *nr = NULL;
        for (size_t k = 0; k < now->n; k++)
            if (!strcmp(now->r[k].key, r->key)) { nr = &now->r[k]; break; }
        if (nr && !strcmp(nr->out, r->out)) {
            /* Правило то же — его выход держит свои метки (в новой спеке). */
            for (size_t k = 0; k < nr->marks_n && !oom; k++)
                oom = rr_mark_add(&pin, &pin_n, nr->marks[k]) < 0;
            continue;
        }
        for (size_t k = 0; k < r->marks_n && !oom; k++)
            oom = rr_mark_add(&cand, &cand_n, r->marks[k]) < 0;
        if (nl < sizeof(names) - 1)
            nl += (size_t)snprintf(names + nl, sizeof(names) - nl, "%s%s → %s", nl ? ", " : "",
                                   r->key[0] == 'n' ? r->key + 2 : r->key, nr ? nr->out : "—");
        if (nl >= sizeof(names)) nl = sizeof(names) - 1;
    }
    for (size_t i = 0; i < cand_n && !oom; i++) {
        unsigned m = cand[i];
        int pinned = 0, n = -1;
        for (size_t k = 0; k < pin_n; k++) pinned |= pin[k] == m;
        const char *how = "целиком";
        if (pinned && rr_evict_filtered(sp, gr, m, &n) == 0) how = "по наборам";
        else n = ctnl_evict_mark(m, STEER_MARK_MASK);
        if (n < 0) {
            conntrack_evict(m);               /* запасной путь — внешний conntrack */
            fprintf(stderr, LOG_I "смена выхода правил (%s): соединения метки 0x%08x сняты "
                            "внешним conntrack\n", names, m);
        } else if (n > 0) {
            fprintf(stderr, LOG_I "смена выхода правил (%s): снято соединений метки 0x%08x — %d "
                            "(%s)\n", names, m, n, how);
        }
    }
    free(cand);
    free(pin);
    reroute_snap_free(now);
}
