/* МОДЕЛЬ → СПЕКА v2 (`steer spec convert`; docs/architecture.md, раздел 3; docs/spec-v2.md).
 *
 * Печатает модель — какой бы спекой она ни была прочитана — спекой v2 в стиле примера раздела 3:
 * разделы в том же порядке (version, lan, clients, lists, outputs, dns, rules), сущность — одной
 * строкой в потоковой записи `имя: { ключ: значение }`, имена выровнены. Главное назначение —
 * перевод v1: модель, собранная переводчиком v1 (model/v1.c), печатается так, что разбор v2
 * (model/v2.c) даёт из напечатанного тот же набор правил до байта (стенд tests/v2match.sh).
 *
 * ЧТО ПРИДУМЫВАЕТСЯ ПРИ ПЕРЕВОДЕ. У v1 клиенты и списки безымянные (по одному на канал), а пул
 * `devices` — группа из безымянных членов. В v2 всё названо, поэтому:
 *   - клиент и список канала получают имя канала, если оно годится в идентификатор (name_ok, до
 *     24 байт), иначе `rule<N>`; совпадение имён — суффикс `-2`, `-3`…;
 *   - список «весь трафик» без сужения печатается как `to: all`, с сужением — списком `all: true`;
 *   - член пула становится выходом kind: interface с именем `<группа>.<устройство>`. Такие выходы
 *     печатаются ПОСЛЕ всех выходов спеки: реестр раздаёт метки по порядку выходов, и прежние
 *     выходы сохраняют прежние метки;
 *   - ключи видов печатает вид (kind_ops.keys_of — обратное его разбору), выведенные из имени
 *     умолчания (путь conf, имя устройства) не печатаются. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "spec.h"
#include "v2.h"

/* ---- скаляры ------------------------------------------------------------------------------- */

/* Годится ли строка в скаляр без кавычек: буквы, цифры и немного знаков, без пробелов и
 * служебных символов YAML, и не слово, которое YAML 1.1 прочёл бы логическим значением. */
static int plain_ok(const char *s) {
    static const char *const RESERVED[] = { "true", "false", "null", "yes", "no", "on", "off", "y",
                                            "n", "~", NULL };
    if (!*s || *s == '-' || *s == ':' || *s == '.') return 0;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == '/' || c == '-' || c == '+' || c == '@' || c == ':'))
            return 0;
    }
    if (s[strlen(s) - 1] == ':') return 0;
    for (size_t i = 0; RESERVED[i]; i++)
        if (!strcasecmp(s, RESERVED[i])) return 0;
    return 1;
}

static void yq(FILE *f, const char *s) {
    if (plain_ok(s)) { fputs(s, f); return; }
    fputc('"', f);
    for (const char *p = s; *p; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', f);
        fputc(*p, f);
    }
    fputc('"', f);
}

/* Разделитель ключей внутри `{ … }`: перед первым — ничего. */
struct flow { FILE *f; int n; };

static void fk(struct flow *w, const char *key) {
    fprintf(w->f, "%s%s: ", w->n++ ? ", " : "", key);
}

static void fs(struct flow *w, const char *key, const char *v) {
    fk(w, key);
    yq(w->f, v);
}

static void fseq(struct flow *w, const char *key, const char *const *v, size_t n) {
    fk(w, key);
    fputc('[', w->f);
    for (size_t i = 0; i < n; i++) {
        if (i) fputs(", ", w->f);
        yq(w->f, v[i]);
    }
    fputc(']', w->f);
}

/* Перечень из массива строк одинаковой ширины (`char (*)[stride]` спеки): без промежуточного
 * массива указателей — раньше он лежал на стеке под предельное число записей. */
static void fseq_s(struct flow *w, const char *key, const char *base, size_t stride, size_t n) {
    fk(w, key);
    fputc('[', w->f);
    for (size_t i = 0; i < n; i++) {
        if (i) fputs(", ", w->f);
        yq(w->f, base + i * stride);
    }
    fputc(']', w->f);
}

/* Имена выходов по номеру, каким его хранит модель: именованные — [0, named), безымянные члены
 * пулов (SPEC_ANON_BASE + k) — следом. */
struct onames { const char (*v)[32]; size_t named; };
static const char *oname_of(const struct onames *on, size_t idx) {
    return on->v[idx >= SPEC_ANON_BASE ? on->named + (idx - SPEC_ANON_BASE) : idx];
}

/* Апстрим DNS одним отображением `{ url: …, out: …, ips: […], bootstrap: […] }`, группа серверов —
 * `{ servers: […], mode: … }` (mode печатается всегда: умолчание failover в спеке не очевидно). */
static void dns_up_flow(FILE *f, const struct spec *s, const struct spec_dns_up *u,
                        const struct onames *oname) {
    struct flow w = { f, 0 };
    fputs("{ ", f);
    if (u->grp) {
        const char **m = malloc((u->mem_n + 1) * sizeof(*m));
        size_t n = 0;
        for (size_t k = 0; m && k < u->mem_n; k++)
            if (u->mem[k] < s->dns.up_n) m[n++] = s->dns.up[u->mem[k]].name;
        if (m) fseq(&w, "servers", (const char *const *)m, n);
        free(m);
        fs(&w, "mode", u->grp == DNSG_RACE ? "race" : "failover");
        fputs(" }", f);
        return;
    }
    fs(&w, "url", u->url);
    if (u->out >= 0) fs(&w, "out", oname_of(oname, (size_t)u->out));
    if (u->ips_n) fseq_s(&w, "ips", u->ips[0], sizeof(u->ips[0]), u->ips_n);
    if (u->boot_n) fseq_s(&w, "bootstrap", u->boot[0], sizeof(u->boot[0]), u->boot_n);
    fputs(" }", f);
}

/* ---- имена ----------------------------------------------------------------------------------- */

struct names { char (*v)[32]; size_t n, cap; };

static int name_used(const struct names *ns, const char *s) {
    for (size_t i = 0; i < ns->n; i++) if (!strcmp(ns->v[i], s)) return 1;
    return 0;
}

/* Свободное имя из base (с суффиксом при совпадении); reserved — занятое словом формата. */
static void name_take(struct names *ns, const char *base, const char *reserved, char *dst) {
    char b[32];
    snprintf(b, sizeof(b), "%.24s", base);
    snprintf(dst, 32, "%s", b);
    for (int k = 2; name_used(ns, dst) || (reserved && !strcmp(dst, reserved)); k++)
        snprintf(dst, 32, "%.24s-%d", b, k % 1000);
    if (ns->n == ns->cap) {
        size_t nc = ns->cap ? ns->cap * 2 : 32;
        char (*nv)[32] = realloc(ns->v, nc * sizeof(*nv));
        if (!nv) return;                /* без памяти имя не запоминается: печать всё равно идёт */
        ns->v = nv;
        ns->cap = nc;
    }
    snprintf(ns->v[ns->n++], 32, "%s", dst);
}

/* Имя, которое сущность правила получит от правила: имя канала, если годится, иначе rule<N>. */
static void rule_base(const struct spec *s, size_t ri, char *dst, size_t n) {
    const char *rn = s->rule[ri].name;
    if (name_ok(rn) && strlen(rn) <= 24) snprintf(dst, n, "%s", rn);
    else snprintf(dst, n, "rule%zu", ri + 1);
}

/* Ширина имени в тексте — с кавычками, если без них нельзя. */
static size_t yq_len(const char *s) { return strlen(s) + (plain_ok(s) ? 0 : 2); }

static size_t width(const char (*v)[32], size_t n, const unsigned char *show) {
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
        if ((!show || show[i]) && yq_len(v[i]) > w) w = yq_len(v[i]);
    return w;
}

static void key_pad(FILE *f, const char *name, size_t w) {
    fputs("  ", f);
    yq(f, name);
    fputc(':', f);
    for (size_t i = yq_len(name); i < w + 1; i++) fputc(' ', f);
}

/* ---- разделы --------------------------------------------------------------------------------- */

/* Записи клиента: адреса, MAC, приложения телефона (uid:N[-M]) и self. */
static void client_flow(FILE *f, const struct spec_client *c) {
    /* Три перечня — один кусок на 3 * from_n указателей (записей каждого вида не больше from_n). */
    const char **buf = calloc(c->from_n * 3 + 1, sizeof(*buf));
    if (!buf) return;
    const char **addr = buf, **mac = buf + c->from_n, **uid = buf + 2 * c->from_n;
    size_t an = 0, mn = 0, un = 0;
    int self = 0;
    for (size_t i = 0; i < c->from_n; i++) {
        const char *v = c->from[i];
        if (!strcmp(v, "self")) self = 1;
        else if (!strncmp(v, "uid:", 4)) uid[un++] = v + 4;
        /* MAC — по форме MAC, а не по двоеточию: с 1.9 в addr бывают и адреса IPv6. */
        else if (spec_is_mac(v)) mac[mn++] = v;
        else addr[an++] = v;
    }
    struct flow w = { f, 0 };
    fputs("{ ", f);
    if (an) fseq(&w, "addr", addr, an);
    if (mn) fseq(&w, "mac", mac, mn);
    if (un) fseq(&w, "uid", uid, un);
    if (self) { fk(&w, "self"); fputs("true", f); }
    fputs(" }", f);
    free(buf);
}

/* ПУТИ — АБСОЛЮТНЫМИ. У v1 относительный путь — от рабочего каталога движка, у v2 — от каталога
 * файла спеки (v2.c, path_of); напечатать его как есть значило бы сменить файл. */
static const char *absp(char *buf, size_t n, const char *p) {
    char cwd[512];
    if (p[0] == '/' || !getcwd(cwd, sizeof(cwd))) return p;
    snprintf(buf, n, "%.511s/%.255s", cwd, p);
    return buf;
}

static void fpaths(struct flow *w, const char *key, const char *const *v, size_t n) {
    /* Путь за путём, без массива промежуточных строк: их число не ограничено. */
    fk(w, key);
    fputc('[', w->f);
    for (size_t i = 0; i < n; i++) {
        char b[800];
        if (i) fputs(", ", w->f);
        yq(w->f, absp(b, sizeof(b), v[i]));
    }
    fputc(']', w->f);
}

static void fpath(struct flow *w, const char *key, const char *v) {
    char b[800];
    fs(w, key, absp(b, sizeof(b), v));
}

static void list_flow(FILE *f, const struct spec_list *l) {
    struct flow w = { f, 0 };
    fputs("{ ", f);
    if (l->all) { fk(&w, "all"); fputs("true", f); }
    if (l->srs_n) fpaths(&w, "srs", l->srs_files, l->srs_n);
    if (l->prefixes_n) fpaths(&w, "prefixes_file", l->prefixes_files, l->prefixes_n);
    if (l->domains_n) fpaths(&w, "domains_file", l->domains_files, l->domains_n);
    if (l->l4.proto != CH_PROTO_ANY) fs(&w, "proto", l->l4.proto == CH_PROTO_TCP ? "tcp" : "udp");
    if (l->l4.ports_n) {
        fk(&w, "ports");
        fputc('[', f);
        for (size_t i = 0; i < l->l4.ports_n; i++) {
            const struct port_range *r = &l->l4.ports[i];
            if (r->lo == r->hi) fprintf(f, "%s%u", i ? ", " : "", r->lo);
            else fprintf(f, "%s%u-%u", i ? ", " : "", r->lo, r->hi);
        }
        fputc(']', f);
    }
    fputs(" }", f);
}

static const char *on_fail_name(enum on_fail f) {
    return f == FAIL_DIRECT ? "direct" : f == FAIL_ZAPRET ? "zapret" : "drop";
}

static void output_flow(FILE *f, const struct output *o, const struct onames *oname) {
    const struct kind_ops *k = kind_of(o);
    const struct group_cfg *g = out_group(o);
    struct flow w = { f, 0 };
    fputs("{ ", f);
    if (g) {
        static const char *const PICK[] = { "order", "latency", "manual", "balance" };
        fs(&w, "kind", "group");
        fs(&w, "pick", PICK[g->pick]);
        fk(&w, "members");
        fputc('[', f);
        for (size_t i = 0; i < g->members_n; i++) {
            if (i) fputs(", ", f);
            yq(f, oname_of(oname, g->members[i]));
        }
        fputc(']', f);
        if (g->pick == PICK_MANUAL && g->def >= 0 && (size_t)g->def < g->members_n)
            fs(&w, "default", oname_of(oname, g->members[g->def]));
        if (g->pick == PICK_LATENCY && g->lat_tolerance_ms >= 0) {   /* ноль — заданный допуск, а не «нет» */
            fk(&w, "tolerance");
            fprintf(f, "%d", g->lat_tolerance_ms);
        }
        if (g->pick == PICK_LATENCY && g->lat_interval_s) {
            fk(&w, "interval");
            fprintf(f, "%d", g->lat_interval_s);
        }
        if (g->pick == PICK_LATENCY && g->url[0]) fs(&w, "url", g->url);
        if (g->pick == PICK_LATENCY && g->idle_timeout_s >= 0) {
            fk(&w, "idle_timeout");
            fprintf(f, "%d", g->idle_timeout_s);
        }
        int weighted = 0;
        for (size_t i = 0; i < g->members_n; i++)
            if (g->weight[i] > 1) weighted = 1;
        if (g->pick == PICK_BALANCE && weighted) {
            fk(&w, "weights");
            fputc('[', f);
            for (size_t i = 0; i < g->members_n; i++)
                fprintf(f, "%s%u", i ? ", " : "", g->weight[i] ? g->weight[i] : 1u);
            fputc(']', f);
        }
        if (g->pick == PICK_BALANCE && g->by != BY_CONNECTION) fs(&w, "by", group_by_name(g->by));
    } else {
        struct out_keys kk;
        memset(&kk, 0, sizeof(kk));
        kk.v2 = 1;
        if (k->keys_of) k->keys_of(o, &kk);
        if (v2_tunnel_proto(k->name)) {
            fs(&w, "kind", "tunnel");
            fs(&w, "protocol", k->name);
        } else fs(&w, "kind", k->name);
        if (out_has_device(o) && o->device[0] && !kk.device_derived) fs(&w, "device", o->device);
        if (kk.sub_file[0]) fpath(&w, "subscription", kk.sub_file);
        if (kk.nodes_n) {
            fk(&w, "nodes");
            fputc('[', f);
            for (size_t i = 0; i < kk.nodes_n; i++) fprintf(f, "%s%d", i ? ", " : "", kk.nodes[i]);
            fputc(']', f);
        }
        if (kk.transports) {
            /* Одно имя — строкой, как в примере раздела 3 (`transport: ws`), несколько — списком
             * в порядке имён (tcp, grpc, xhttp, ws, httpupgrade), не в порядке записи: это
             * множество, и печать обязана быть неподвижной точкой convert. */
            unsigned c = 0;
            for (unsigned i = 0; i < TT_COUNT; i++) c += (kk.transports >> i) & 1u;
            fk(&w, "transport");
            if (c > 1) fputc('[', f);
            for (unsigned i = 0, m = 0; i < TT_COUNT; i++)
                if (kk.transports & (1u << i)) fprintf(f, "%s%s", m++ ? ", " : "", tunnel_transport_name(i));
            if (c > 1) fputc(']', f);
        }
        if (kk.insecure) { fk(&w, "insecure"); fputs("true", f); }
        if (kk.excl.cc_n) fseq_s(&w, "exclude", kk.excl.cc[0], 3, kk.excl.cc_n);
        if (kk.excl.names_n) fseq(&w, "exclude_name", kk.excl.names, kk.excl.names_n);
        /* Пул узлов туннеля — только отличное от умолчания (struct tun_pool). */
        if (kk.pool.active > 1) { fk(&w, "active"); fprintf(f, "%d", kk.pool.active); }
        if (kk.pool.by != BY_CONNECTION) fs(&w, "by", group_by_name(kk.pool.by));
        if (kk.pool.interval_s) { fk(&w, "interval"); fprintf(f, "%d", kk.pool.interval_s); }
        if (kk.pool.silence_s) { fk(&w, "silence"); fprintf(f, "%d", kk.pool.silence_s < 0 ? 0 : kk.pool.silence_s); }
        if (kk.conf[0]) fpath(&w, "conf", kk.conf);
        if (kk.stream) { fk(&w, "stream"); fputs("true", f); }
        if (kk.stream_port) { fk(&w, "stream_port"); fprintf(f, "%d", kk.stream_port); }
        if (kk.opts_file[0]) fpath(&w, "strategy", kk.opts_file);
        if (kk.domain[0]) fs(&w, "domain", kk.domain);
        if (kk.obfs.on) {
            char sv[96], lv[96];
            snprintf(sv, sizeof(sv), "%s:%d", kk.obfs.server, kk.obfs.server_port);
            snprintf(lv, sizeof(lv), "%s:%d", kk.obfs.listen, kk.obfs.listen_port);
            fk(&w, "obfs");
            struct flow ow = { f, 0 };
            fputs("{ ", f);
            fs(&ow, "server", sv);
            fs(&ow, "listen", lv);
            fputs(" }", f);
        }
    }
    if (o->over[0]) fs(&w, "over", o->over);
    if (o->on_fail != FAIL_DROP) fs(&w, "on_fail", on_fail_name(o->on_fail));
    /* Ключ ipv6 (шаг 8 выпуска 1.10) — как записан, а prefix — только записанный: выведенный из
     * адресов раздачи — состояние, а не настройка. Спека v1 ключа не знает, и её перевод печатается
     * прежним текстом. */
    if (o->ipv6 != OUT_V6_KIND) {
        static const char *const V6[] = { "", "routed", "nat", "off" };
        fs(&w, "ipv6", V6[o->ipv6]);
        if (o->ipv6 == OUT_V6_ROUTED && o->v6pfx_given) {
            char p[64];
            v6pfx_str(&o->v6pfx, p, sizeof(p));
            fs(&w, "prefix", p);
        }
    }
    fputs(" }", f);
}

/* Рабочие таблицы печати: имена всех сущностей модели — выходы (именованные и безымянные члены),
 * клиенты, списки. По числу сущностей спеки, а не на предельное число (раньше — статические
 * массивы под 16 + 64 + 64 + 64 имён). */
struct pv2 {
    char (*oname)[32], (*cname)[32], (*lname)[32];
    unsigned char *cshow, *lshow;
    struct names on, cn, ln;
    size_t *anon_order;
};

static int spec_print_v2_body(FILE *f, const struct spec *s, struct err *e, struct pv2 *pv);

int spec_print_v2(FILE *f, const struct spec *s, struct err *e) {
    struct pv2 pv;
    memset(&pv, 0, sizeof(pv));
    pv.oname = calloc(s->out_n + s->anon_n + 1, sizeof(*pv.oname));
    pv.cname = calloc(s->client_n + 1, sizeof(*pv.cname));
    pv.lname = calloc(s->list_n + 1, sizeof(*pv.lname));
    pv.cshow = calloc(s->client_n + 1, 1);
    pv.lshow = calloc(s->list_n + 1, 1);
    pv.anon_order = calloc(s->anon_n + 1, sizeof(*pv.anon_order));
    int rc = -1;
    if (pv.oname && pv.cname && pv.lname && pv.cshow && pv.lshow && pv.anon_order)
        rc = spec_print_v2_body(f, s, e, &pv);
    else if (e) err_set(e, "%s", "недостаточно памяти для печати спеки");
    free(pv.oname); free(pv.cname); free(pv.lname); free(pv.cshow); free(pv.lshow);
    free(pv.anon_order); free(pv.on.v); free(pv.cn.v); free(pv.ln.v);
    return rc;
}

static int spec_print_v2_body(FILE *f, const struct spec *s, struct err *e, struct pv2 *pv) {
    char (*oname)[32] = pv->oname, (*cname)[32] = pv->cname, (*lname)[32] = pv->lname;
    unsigned char *cshow = pv->cshow, *lshow = pv->lshow;
    struct names *on = &pv->on, *cn = &pv->cn, *ln = &pv->ln;
    size_t *anon_order = pv->anon_order;
    struct onames onm = { (const char (*)[32])oname, s->out_n };

    for (size_t i = 0; i < s->out_n; i++) name_take(on, s->out[i].name, NULL, oname[i]);
    /* Члены пулов — после именованных, в порядке групп. Имя члена лежит в oname за именованными
     * (oname_of): позиция = out_n + номер в sp->anon. */
    size_t anon_n = 0;
    for (size_t i = 0; i < s->out_n; i++) {
        const struct group_cfg *g = out_group(&s->out[i]);
        for (size_t k = 0; g && k < g->members_n; k++) {
            size_t m = g->members[k];
            if (spec_is_named(m)) continue;
            size_t slot = s->out_n + (m - SPEC_ANON_BASE);
            if (oname[slot][0]) continue;
            char base[64];
            snprintf(base, sizeof(base), "%.15s.%.15s", s->out[i].name, spec_out(s, m)->device);
            if (!name_ok(base)) {
                if (e) err_set(e, "выход %s: имя члена группы не складывается из имени и устройства",
                               s->out[i].name);
                return -1;
            }
            name_take(on, base, NULL, oname[slot]);
            anon_order[anon_n++] = slot;
        }
    }
    /* Клиенты и списки: свои имена (спека v2) или имя правила, которое на них ссылается первым. */
    for (size_t i = 0; i < s->client_n; i++)
        if (s->client[i].name[0]) { name_take(cn, s->client[i].name, "lan", cname[i]); cshow[i] = 1; }
    for (size_t i = 0; i < s->list_n; i++)
        if (s->list[i].name[0]) { name_take(ln, s->list[i].name, "all", lname[i]); lshow[i] = 1; }
    for (size_t r = 0; r < s->rule_n; r++) {
        const struct spec_rule *ru = &s->rule[r];
        char base[32];
        rule_base(s, r, base, sizeof(base));
        for (size_t k = 0; k < ru->clients_n; k++) {
            size_t c = ru->clients[k];
            if (cshow[c] || !s->client[c].from_n) continue;
            name_take(cn, base, "lan", cname[c]);
            cshow[c] = 1;
        }
        for (size_t k = 0; k < ru->lists_n; k++) {
            size_t l = ru->lists[k];
            const struct spec_list *li = &s->list[l];
            if (lshow[l]) continue;
            /* «Весь трафик» без сужения — это `to: all`, списка для него не нужно. */
            if (li->all && l4match_empty(&li->l4) && !li->srs_n && !li->prefixes_n && !li->domains_n)
                continue;
            name_take(ln, base, "all", lname[l]);
            lshow[l] = 1;
        }
    }

    fputs("version: 2\n\n", f);

    /* lan */
    {
        struct flow w = { f, 0 };
        fputs("lan: { ", f);
        fseq_s(&w, "devices", s->lan_dev[0], sizeof(s->lan_dev[0]), s->lan_dev_n);
        if (s->lan.from_n)
            fseq_s(&w, "addr", s->lan.from[0], sizeof(s->lan.from[0]), s->lan.from_n);
        fputs(" }\n", f);
    }

    size_t cw = width(cname, s->client_n, cshow);
    if (cw) {
        fputs("\nclients:\n", f);
        for (size_t i = 0; i < s->client_n; i++) {
            if (!cshow[i]) continue;
            key_pad(f, cname[i], cw);
            client_flow(f, &s->client[i]);
            fputc('\n', f);
        }
    }

    size_t lw = width(lname, s->list_n, lshow);
    if (lw) {
        fputs("\nlists:\n", f);
        for (size_t i = 0; i < s->list_n; i++) {
            if (!lshow[i]) continue;
            key_pad(f, lname[i], lw);
            list_flow(f, &s->list[i]);
            fputc('\n', f);
        }
    }

    if (s->out_n) {
        size_t ow = width(oname, s->out_n, NULL);
        for (size_t i = 0; i < anon_n; i++)
            if (yq_len(oname[anon_order[i]]) > ow) ow = yq_len(oname[anon_order[i]]);
        fputs("\noutputs:\n", f);
        for (size_t i = 0; i < s->out_n; i++) {
            key_pad(f, oname[i], ow);
            output_flow(f, &s->out[i], &onm);
            fputc('\n', f);
        }
        for (size_t i = 0; i < anon_n; i++) {
            const struct output *m = spec_out(s, SPEC_ANON_BASE + (anon_order[i] - s->out_n));
            key_pad(f, oname[anon_order[i]], ow);
            output_flow(f, m, &onm);
            fputc('\n', f);
        }
    }

    size_t named_up = 0;
    for (size_t i = 0; i < s->dns.up_n; i++) named_up += !s->dns.up[i].inl;
    if (s->traceroute_hops || s->dns.cache || named_up || s->dns.boot_n) {
        fputs("\ndns:\n", f);
        if (s->traceroute_hops) fputs("  traceroute_hops: true\n", f);
        if (s->dns.cache) {
            fprintf(f, "  cache: %ld\n", s->dns.cache);
            if (s->dns.ttl_min != 10 || s->dns.ttl_max != 3600 || s->dns.ttl_neg != 30)
                fprintf(f, "  cache_ttl: { min: %ld, max: %ld, negative: %ld }\n", s->dns.ttl_min,
                        s->dns.ttl_max, s->dns.ttl_neg);
        }
        if (s->dns.boot_n) {
            struct flow w = { f, 0 };
            fputs("  ", f);
            fseq_s(&w, "bootstrap", s->dns.boot[0], sizeof(s->dns.boot[0]), s->dns.boot_n);
            fputc('\n', f);
        }
        if (s->dns.general && s->dns.general <= s->dns.up_n)
            fprintf(f, "  upstream: %s\n", s->dns.up[s->dns.general - 1].name);
        if (s->dns.other && s->dns.other <= s->dns.up_n)
            fprintf(f, "  other: %s\n", s->dns.up[s->dns.other - 1].name);
        if (named_up) {
            fputs("  upstreams:\n", f);
            for (size_t i = 0; i < s->dns.up_n; i++) {
                if (s->dns.up[i].inl) continue;
                fputs("    ", f);
                yq(f, s->dns.up[i].name);
                fputs(": ", f);
                dns_up_flow(f, s, &s->dns.up[i], &onm);
                fputc('\n', f);
            }
        }
    }

    if (s->rule_n) {
        fputs("\nrules:\n", f);
        for (size_t r = 0; r < s->rule_n; r++) {
            const struct spec_rule *ru = &s->rule[r];
            struct flow w = { f, 0 };
            fputs("  - { ", f);
            fs(&w, "name", ru->name);
            const char **refs = malloc((ru->clients_n + ru->lists_n + 1) * sizeof(*refs));
            if (!refs) return e ? err_set(e, "%s", "недостаточно памяти для печати спеки") : -1;
            size_t rn = 0;
            for (size_t k = 0; k < ru->clients_n; k++)
                if (cshow[ru->clients[k]]) refs[rn++] = cname[ru->clients[k]];
            if (rn) fseq(&w, "for", refs, rn);
            rn = 0;
            for (size_t k = 0; k < ru->lists_n; k++)
                if (lshow[ru->lists[k]]) refs[rn++] = lname[ru->lists[k]];
            if (rn) fseq(&w, "to", refs, rn);
            else fs(&w, "to", "all");
            free(refs);
            fs(&w, "out", oname[ru->out]);
            if (ru->realip) fs(&w, "resolve", "realip");
            if (ru->dns && ru->dns <= s->dns.up_n) {
                const struct spec_dns_up *du = &s->dns.up[ru->dns - 1];
                if (du->inl) {
                    fk(&w, "dns");
                    dns_up_flow(f, s, du, &onm);
                } else {
                    fs(&w, "dns", du->name);
                }
            }
            if (ru->dev_scope) fs(&w, "scope", "device");
            if (ru->disabled) { fk(&w, "enabled"); fputs("false", f); }
            fputs(" }\n", f);
        }
    }
    return ferror(f) ? (e ? err_set(e, "не удалось напечатать спеку", NULL) : -1) : 0;
}
