/* nf_tables по netlink — чтение. Устройство и доводы — в nftdump.h. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "nlbuf.h"
#include "nftdump.h"

/* Номера из nf_tables.h, появившиеся позже 4.9, — числами: заголовки ядра в тулчейне бывают
 * старше ядра, на котором движок работает, а значения в ABI не меняются никогда. */
#define NFD_MSG_GETFLOWTABLE     23   /* NFT_MSG_GETFLOWTABLE, 4.16 */
#define NFD_HOOK_DEVS             4   /* NFTA_HOOK_DEVS, 5.5 */
#define NFD_SET_ELEM_KEY_END     10   /* NFTA_SET_ELEM_KEY_END, 5.6 */
#define NFD_FT_TABLE              1   /* NFTA_FLOWTABLE_TABLE */
#define NFD_FT_NAME               2   /* NFTA_FLOWTABLE_NAME */
#define NFD_FT_HOOK               3   /* NFTA_FLOWTABLE_HOOK */
#define NFD_FT_HOOK_DEVS          3   /* NFTA_FLOWTABLE_HOOK_DEVS */
#define NFD_DEVICE_NAME           1   /* NFTA_DEVICE_NAME */
#define NFD_REG32_00              8   /* NFT_REG32_00, 4.1 */
/* Типы записей userdata, как их пишет libnftnl (nftnl_udata): комментарий правила и цепочки —
 * 0, набора — 7. */
#define NFD_UDATA_COMMENT         0
#define NFD_UDATA_SET_COMMENT     7

static uint32_t g_nfd_seq;

static int nfd_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    /* Страховка от вечного recv — тот же приём, что у rtnl.c: ядро отвечает внутри вызова. */
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

typedef void (*nfd_cb)(const struct nlmsghdr *h, void *arg);

/* Один запрос и весь ответ. dump — NLM_F_DUMP (ответ частями до NLMSG_DONE), иначе одиночный GET
 * с подтверждением. До двух строковых атрибутов запроса (таблица, имя). 0, errno ответа ядра
 * (ENOENT — объекта нет) или EINTR — набор правил поменялся посреди дампа (NLM_F_DUMP_INTR). */
static int nfd_talk(int fd, uint16_t msg, int dump, uint8_t family,
                    uint16_t a1, const char *s1, uint16_t a2, const char *s2,
                    nfd_cb cb, void *arg) {
    _Alignas(8) uint8_t req[512];
    memset(req, 0, sizeof(req));
    struct nlbuf b;
    nlbuf_init(&b, req, sizeof(req));
    struct nlmsghdr *nh = (struct nlmsghdr *)req;
    nh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | msg);
    nh->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | (dump ? NLM_F_DUMP : NLM_F_ACK));
    nh->nlmsg_seq = ++g_nfd_seq;
    b.p += NLMSG_HDRLEN;
    struct nfgenmsg *g = (struct nfgenmsg *)b.p;
    g->nfgen_family = family;
    g->version = NFNETLINK_V0;
    g->res_id = 0;
    b.p += NLMSG_ALIGN(sizeof(*g));
    if (s1) nlbuf_put_str(&b, a1, s1);
    if (s2) nlbuf_put_str(&b, a2, s2);
    if (b.overflow) return EMSGSIZE;
    nh->nlmsg_len = (uint32_t)(b.p - b.base);

    struct sockaddr_nl to;
    memset(&to, 0, sizeof(to));
    to.nl_family = AF_NETLINK;
    if (sendto(fd, req, nh->nlmsg_len, 0, (struct sockaddr *)&to, sizeof(to)) < 0) return errno;

    /* Буфер на вызов, а не статический: вызовы не вкладываются, но на куче он не держит 64 КБ
     * памяти процесса между опросами. */
    size_t cap = 65536;
    uint8_t *rbuf = malloc(cap);
    if (!rbuf) return ENOMEM;
    int rc = EIO, intr = 0;
    for (int done = 0; !done; ) {
        ssize_t n = recv(fd, rbuf, cap, 0);
        if (n < 0) { if (errno == EINTR) continue; rc = errno; break; }
        if (n == 0) break;
        for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != nh->nlmsg_seq) continue;
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) intr = 1;
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e = NLMSG_DATA(h);
                rc = e->error ? -e->error : 0;
                done = 1;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) { rc = 0; done = 1; break; }
            if (cb) cb(h, arg);
        }
    }
    free(rbuf);
    return rc == 0 && intr ? EINTR : rc;
}

/* ---- атрибуты ------------------------------------------------------------------------------ */

static void nfd_parse(const void *p, size_t len, const struct nlattr **tb, int max) {
    for (int i = 0; i <= max; i++) tb[i] = NULL;
    const uint8_t *q = p;
    while (len >= NLA_HDRLEN) {
        const struct nlattr *a = (const struct nlattr *)q;
        if (a->nla_len < NLA_HDRLEN || a->nla_len > len) break;
        int t = a->nla_type & NLA_TYPE_MASK;
        if (t <= max) tb[t] = a;
        size_t al = NLA_ALIGN(a->nla_len);
        if (al >= len) break;
        q += al;
        len -= al;
    }
}

static const uint8_t *nla_ptr(const struct nlattr *a) { return (const uint8_t *)a + NLA_HDRLEN; }
static size_t nla_size(const struct nlattr *a) { return a->nla_len - NLA_HDRLEN; }

static void nfd_nested(const struct nlattr *a, const struct nlattr **tb, int max) {
    nfd_parse(nla_ptr(a), nla_size(a), tb, max);
}

static uint32_t nla_be32(const struct nlattr *a) {
    uint32_t v = 0;
    if (a && nla_size(a) >= 4) memcpy(&v, nla_ptr(a), 4);
    return ntohl(v);
}

static uint64_t nla_be64(const struct nlattr *a) {
    uint64_t v = 0;
    if (a && nla_size(a) >= 8) {
        const uint8_t *p = nla_ptr(a);
        for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    }
    return v;
}

/* Строка атрибута в буфер: ядро кладёт её с нулём, но доверять этому незачем. */
static const char *nla_cstr(const struct nlattr *a, char *buf, size_t n) {
    buf[0] = '\0';
    if (!a || !n) return buf;
    size_t l = nla_size(a);
    if (l >= n) l = n - 1;
    memcpy(buf, nla_ptr(a), l);
    buf[l] = '\0';
    return buf;
}

/* Атрибуты сообщения ответа — после nfgenmsg. */
static void msg_attrs(const struct nlmsghdr *h, const struct nlattr **tb, int max) {
    size_t hl = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if (h->nlmsg_len < hl) { nfd_parse(NULL, 0, tb, max); return; }
    nfd_parse((const uint8_t *)h + hl, h->nlmsg_len - hl, tb, max);
}

static uint8_t msg_family(const struct nlmsghdr *h) {
    return ((const struct nfgenmsg *)NLMSG_DATA(h))->nfgen_family;
}

static int msg_is(const struct nlmsghdr *h, uint16_t msg) {
    return h->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | msg);
}

/* Запись userdata с данным типом — строкой (TLV libnftnl: тип, длина, значение). */
static void udata_str(const struct nlattr *a, uint8_t type, char *out, size_t on) {
    out[0] = '\0';
    if (!a || !on) return;
    const uint8_t *p = nla_ptr(a);
    size_t n = nla_size(a);
    while (n >= 2) {
        uint8_t t = p[0], l = p[1];
        if ((size_t)l + 2 > n) break;
        if (t == type) {
            size_t k = 0;
            while (k < l && k + 1 < on && p[2 + k]) { out[k] = (char)p[2 + k]; k++; }
            out[k] = '\0';
            return;
        }
        p += 2 + l;
        n -= 2 + (size_t)l;
    }
}

/* Перебор вложенного списка NFTA_LIST_ELEM. */
#define NLA_FOR_EACH(a, list)                                                                   \
    for (const uint8_t *_q = nla_ptr(list), *_e = nla_ptr(list) + nla_size(list);              \
         _q + NLA_HDRLEN <= _e && ((a) = (const struct nlattr *)_q)->nla_len >= NLA_HDRLEN &&  \
         _q + (a)->nla_len <= _e;                                                               \
         _q += NLA_ALIGN((a)->nla_len))

/* Дамп с повтором: набор правил, поменявшийся посреди дампа, ядро отмечает флагом, и тогда
 * читаем заново — так делает и nft. Три попытки: больше значило бы, что правила меняют без
 * передышки, и тогда годится любой из снимков. */
static int nfd_dump(int fd, uint16_t msg, uint8_t family, uint16_t a1, const char *s1,
                    uint16_t a2, const char *s2, nfd_cb cb, void *arg, void (*reset)(void *)) {
    int rc = EINTR;
    for (int i = 0; i < 3 && rc == EINTR; i++) {
        if (i && reset) reset(arg);
        rc = nfd_talk(fd, msg, 1, family, a1, s1, a2, s2, cb, arg);
    }
    return rc == EINTR ? 0 : rc;
}

/* ---- правила цепочки: комментарий и счётчик ------------------------------------------------ */

struct chain_rules_ctx {
    const char *table;
    const char *const *chains;
    size_t chains_n;
    nfd_rule_fn fn;
    void *arg;
};

static void chain_rules_cb(const struct nlmsghdr *h, void *arg) {
    struct chain_rules_ctx *c = arg;
    if (!msg_is(h, NFT_MSG_NEWRULE)) return;
    const struct nlattr *tb[NFTA_RULE_MAX + 1];
    msg_attrs(h, tb, NFTA_RULE_MAX);
    char t[64], ch[64];
    if (strcmp(nla_cstr(tb[NFTA_RULE_TABLE], t, sizeof(t)), c->table) != 0) return;
    nla_cstr(tb[NFTA_RULE_CHAIN], ch, sizeof(ch));
    size_t k = 0;
    while (k < c->chains_n && strcmp(ch, c->chains[k]) != 0) k++;
    if (k == c->chains_n) return;
    char comment[256];
    udata_str(tb[NFTA_RULE_USERDATA], NFD_UDATA_COMMENT, comment, sizeof(comment));
    int has = 0;
    uint64_t pk = 0, by = 0;
    if (tb[NFTA_RULE_EXPRESSIONS]) {
        const struct nlattr *e;
        NLA_FOR_EACH(e, tb[NFTA_RULE_EXPRESSIONS]) {
            const struct nlattr *et[NFTA_EXPR_MAX + 1];
            nfd_nested(e, et, NFTA_EXPR_MAX);
            char name[32];
            if (strcmp(nla_cstr(et[NFTA_EXPR_NAME], name, sizeof(name)), "counter") != 0 ||
                !et[NFTA_EXPR_DATA])
                continue;
            const struct nlattr *ct[NFTA_COUNTER_MAX + 1];
            nfd_nested(et[NFTA_EXPR_DATA], ct, NFTA_COUNTER_MAX);
            by = nla_be64(ct[NFTA_COUNTER_BYTES]);
            pk = nla_be64(ct[NFTA_COUNTER_PACKETS]);
            has = 1;
            break;
        }
    }
    c->fn(c->arg, comment, has, pk, by);
}

int nfd_chain_rules(uint8_t family, const char *table, const char *const *chains, size_t n,
                    nfd_rule_fn fn, void *arg) {
    int fd = nfd_open();
    if (fd < 0) return errno ? errno : EIO;
    struct chain_rules_ctx c = { table, chains, n, fn, arg };
    /* Один дамп таблицы на все цепочки: и одно мгновение для всех счётчиков, и один ответ ядра
     * вместо нескольких. Без повтора: счётчики, снятые посреди перестройки, — такое же
     * мгновение, как любое другое, а повтор выдал бы правила дважды тому, кто их складывает. */
    int rc = nfd_talk(fd, NFT_MSG_GETRULE, 1, family, NFTA_RULE_TABLE, table, 0, NULL,
                      chain_rules_cb, &c);
    close(fd);
    return rc == ENOENT || rc == EINTR ? 0 : rc;
}

/* ---- число элементов набора ---------------------------------------------------------------- */

static void set_count_cb(const struct nlmsghdr *h, void *arg) {
    long *n = arg;
    if (!msg_is(h, NFT_MSG_NEWSETELEM)) return;
    const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1];
    msg_attrs(h, tb, NFTA_SET_ELEM_LIST_MAX);
    if (!tb[NFTA_SET_ELEM_LIST_ELEMENTS]) return;
    const struct nlattr *e;
    NLA_FOR_EACH(e, tb[NFTA_SET_ELEM_LIST_ELEMENTS]) {
        const struct nlattr *et[NFD_SET_ELEM_KEY_END + 1];
        nfd_nested(e, et, NFD_SET_ELEM_KEY_END);
        if (nla_be32(et[NFTA_SET_ELEM_FLAGS]) & NFT_SET_ELEM_INTERVAL_END) continue;
        (*n)++;
    }
}

static void count_reset(void *arg) { *(long *)arg = 0; }

long nfd_set_count(uint8_t family, const char *table, const char *set) {
    int fd = nfd_open();
    if (fd < 0) return -1;
    long n = 0;
    int rc = nfd_dump(fd, NFT_MSG_GETSETELEM, family, NFTA_SET_ELEM_LIST_TABLE, table,
                      NFTA_SET_ELEM_LIST_SET, set, set_count_cb, &n, count_reset);
    close(fd);
    return rc ? -1 : n;
}

/* ---- наличие ------------------------------------------------------------------------------- */

int nfd_table_exists(uint8_t family, const char *table) {
    int fd = nfd_open();
    if (fd < 0) return 0;
    int rc = nfd_talk(fd, NFT_MSG_GETTABLE, 0, family, NFTA_TABLE_NAME, table, 0, NULL, NULL, NULL);
    close(fd);
    return rc == 0;
}

int nfd_chain_exists(uint8_t family, const char *table, const char *chain) {
    int fd = nfd_open();
    if (fd < 0) return 0;
    int rc = nfd_talk(fd, NFT_MSG_GETCHAIN, 0, family, NFTA_CHAIN_TABLE, table,
                      NFTA_CHAIN_NAME, chain, NULL, NULL);
    close(fd);
    return rc == 0;
}

/* ---- отпечаток таблицы --------------------------------------------------------------------- *
 *
 * Для apply-сверки демона (src/daemon/recon.c, «СВЕРКА С ЯДРОМ»): то, что в таблице меняет только
 * nft -f, свёрнутое в одно число. Сравнивается отпечаток ядра с отпечатком, снятым сразу после
 * нашей загрузки, — а не с текстом, который печатает generate: разобрать тот текст в атрибуты
 * netlink значило бы повторить nft, а «что стояло сразу после нашего nft -f» и есть ожидаемое.
 *
 * ЧТО ВХОДИТ. Цепочки (имя, тип, хук, приоритет, политика), правила по порядку в цепочке
 * (выражения целиком и комментарий), заголовки наборов и карт (имя, тип ключа и значения, флаги,
 * срок, описание) — в том числе безымянных: их набор живёт и умирает вместе со своим правилом.
 *
 * ЧЕГО НЕ ВХОДИТ — всего, что меняется, пока таблица стоит, без нашего nft -f:
 *   - номера (handle) таблицы, цепочек, правил и наборов: подменённую таблицу видит уже
 *     recon_table_handle, а правило, снятое и поставленное заново тем же текстом, ничего не
 *     ломает;
 *   - состояние выражений: counter (пакеты и байты), quota (израсходованное), last (время), а у
 *     цепочек — их счётчики и число ссылок на них (use — производное от правил, которые и так в
 *     отпечатке);
 *   - элементы именованных наборов и карт. Их кладут не только nft -f: резолвер — адреса
 *     доменных каналов, fake-IP и real-ip, сторож — метки «пущен напрямую» и карты раздачи
 *     balance. В доменном наборе постоянные элементы адресных списков лежат вперемешку с
 *     постоянными элементами резолвера (поддельные адреса без срока). А адресные списки — это
 *     сотни тысяч элементов: отпечаток снимается на каждом проходе сторожа, и дамп элементов
 *     стоил бы ему сотен миллисекунд. Элементы статических наборов сверяются отдельно и только
 *     на apply и reload — сводкой, которую снимает ребёнок демона (nfd_sets и nfd_set_elems
 *     ниже; что сверяется и почему — в recon.c, «СВЕРКА ЭЛЕМЕНТОВ»). Элементы безымянных
 *     наборов не нужны вовсе: ядро их не меняет (набор постоянный), а снять их можно только
 *     вместе с правилом.
 *
 * Порядок атрибутов и их байты ядро отдаёт одни и те же, пока объект тот же, поэтому свёртка —
 * прямо по байтам ответа, без разбора выражений по видам. Правила и цепочки — в порядке дампа (он
 * порядок таблицы).
 *
 * ВСЕ СЕМЕЙСТВА — ЧЕТЫРЬМЯ ОБМЕНАМИ. С 2026-09-28 отпечаток снимается не только на apply, но и на
 * каждом проходе сторожа демона (recon.c, «СВЕРКА НА ПРОХОДЕ СТОРОЖА»), и число обменов с ядром
 * стало ценой прохода. Прежде каждое из трёх семейств (inet, ip, ip6 — у раскладки старого
 * ядра) стоило своего запроса таблицы и трёх дампов, а номер таблицы — ещё одного запроса: до
 * тринадцати обменов. Теперь дамп на вид объекта один на все семейства (nfgen_family =
 * NFPROTO_UNSPEC), а раскладка по семействам — по семейству ответа:
 *   таблицы  — дамп всех таблиц (их на машине единицы): есть ли наши в каждом семействе и номер
 *              таблицы inet;
 *   цепочки  — дамп всех цепочек: фильтра по таблице у дампа цепочек в ядре нет, отбор по имени
 *              таблицы — здесь (у fw4 роутера цепочек десятки — это заголовки, килобайты);
 *   наборы   — дамп всех наборов без атрибута таблицы: с NFPROTO_UNSPEC ядро ищет таблицу по
 *              имени И семейству (nft_ctx_init_from_setattr) и отвечает ENOENT, поэтому фильтр
 *              — здесь; ответ — только заголовки;
 *   правила  — дамп с атрибутом таблицы: этот фильтр новое ядро понимает и при NFPROTO_UNSPEC
 *              (на 4.9 его нет вовсе, и отбор всё равно повторяется здесь).
 * Нет наших таблиц ни в одном семействе — остальные три дампа не нужны. Цепочки берутся любые:
 * имена и хуки не разбираются, так что цепочка на любом хуке (в том числе inet ingress, со своим
 * списком устройств) входит в отпечаток так же, как prerouting_mark. */

/* Номера атрибутов — числами (заголовки тулчейна бывают старше ядра, ABI не меняется). */
#define NFD_RULE_HANDLE    3
#define NFD_RULE_POSITION  6
#define NFD_RULE_PAD       8
#define NFD_RULE_ID        9
#define NFD_RULE_POS_ID   10
#define NFD_RULE_CHAIN_ID 11
#define NFD_CHAIN_HANDLE   2
#define NFD_CHAIN_USE      6
#define NFD_CHAIN_COUNTERS 8
#define NFD_CHAIN_PAD      9
#define NFD_CHAIN_ID      11
#define NFD_SET_ID        10
#define NFD_SET_PAD       14
#define NFD_SET_HANDLE    16
#define NFD_SET_EXPR      17
#define NFD_SET_EXPRS     18

#define NFD_FNV_INIT 14695981039346656037ULL

static void fp_mix(uint64_t *h, const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 1099511628211ULL; }
}

/* Атрибут целиком: номер, длина, данные. */
static void fp_attr(uint64_t *h, const struct nlattr *a) {
    uint16_t t = a->nla_type & NLA_TYPE_MASK, l = (uint16_t)nla_size(a);
    fp_mix(h, &t, sizeof(t));
    fp_mix(h, &l, sizeof(l));
    fp_mix(h, nla_ptr(a), l);
}

/* Выражения правила: имя каждого и его данные — кроме данных выражений с состоянием. */
static void fp_exprs(uint64_t *h, const struct nlattr *list) {
    const struct nlattr *e;
    NLA_FOR_EACH(e, list) {
        const struct nlattr *et[NFTA_EXPR_MAX + 1];
        nfd_nested(e, et, NFTA_EXPR_MAX);
        char name[32];
        nla_cstr(et[NFTA_EXPR_NAME], name, sizeof(name));
        fp_mix(h, name, strlen(name) + 1);
        if (!strcmp(name, "counter") || !strcmp(name, "quota") || !strcmp(name, "last")) continue;
        if (et[NFTA_EXPR_DATA]) fp_attr(h, et[NFTA_EXPR_DATA]);
    }
}

/* Семейства таблиц движка: номер в отпечатке и бит в nfd_tfp.fams. -1 — не наше семейство. */
static const uint8_t g_tfp_fams[3] = { NFD_INET, NFD_IP, NFD_IP6 };

static int tfp_fam(uint8_t f) {
    for (int i = 0; i < 3; i++)
        if (g_tfp_fams[i] == f) return i;
    return -1;
}

struct tfp_ctx {
    const char *table;
    uint16_t msg;                   /* NFT_MSG_NEW* объектов этого дампа */
    uint32_t skip;                  /* маска номеров атрибутов, которые не входят */
    uint64_t h[3];                  /* по семейству (g_tfp_fams) */
    unsigned n[3];
};

static void tfp_cb(const struct nlmsghdr *m, void *arg) {
    struct tfp_ctx *c = arg;
    if (!msg_is(m, c->msg)) return;
    int fi = tfp_fam(msg_family(m));
    if (fi < 0) return;
    size_t hl = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if (m->nlmsg_len < hl) return;
    /* Таблица — первый атрибут у всех трёх видов (NFTA_*_TABLE == 1): фильтр дампа по таблице
     * старое ядро не понимает, поэтому отбор здесь. */
    const struct nlattr *tb[2];
    nfd_parse((const uint8_t *)m + hl, m->nlmsg_len - hl, tb, 1);
    char t[64];
    if (!tb[1] || strcmp(nla_cstr(tb[1], t, sizeof(t)), c->table) != 0) return;
    uint64_t h = NFD_FNV_INIT;
    const uint8_t *q = (const uint8_t *)m + hl;
    size_t len = m->nlmsg_len - hl;
    while (len >= NLA_HDRLEN) {
        const struct nlattr *a = (const struct nlattr *)q;
        if (a->nla_len < NLA_HDRLEN || a->nla_len > len) break;
        int ty = a->nla_type & NLA_TYPE_MASK;
        if (ty >= 32 || !(c->skip & (1u << ty))) {
            if (c->msg == NFT_MSG_NEWRULE && ty == NFTA_RULE_EXPRESSIONS) fp_exprs(&h, a);
            else fp_attr(&h, a);
        }
        size_t al = NLA_ALIGN(a->nla_len);
        if (al >= len) break;
        q += al;
        len -= al;
    }
    fp_mix(&c->h[fi], &h, sizeof(h));
    c->n[fi]++;
}

static void tfp_reset(void *arg) {
    struct tfp_ctx *c = arg;
    for (int i = 0; i < 3; i++) { c->h[i] = NFD_FNV_INIT; c->n[i] = 0; }
}

/* Дамп отпечатка — с повтором прерванного, но без «годится любой снимок», как у nfd_dump:
 * прерывает дамп (NLM_F_DUMP_INTR) любая транзакция посреди него, в том числе элемент, который
 * кладёт резолвер, — а снимок, склеенный из двух состояний таблицы, дал бы другой отпечаток и
 * ложное «изменено снаружи», то есть замену набора правил на пустом месте. Пять попыток подряд
 * прерваны — «ядро не ответило»: проход сторожа тогда ничего не решает (решит следующий), apply
 * ставит набор заново, как при любом незнании. */
static int tfp_dump(int fd, uint16_t msg, uint16_t attr, const char *table, struct tfp_ctx *c) {
    int rc = EINTR;
    for (int i = 0; i < 5 && rc == EINTR; i++) {
        tfp_reset(c);
        rc = nfd_talk(fd, msg, 1, NFPROTO_UNSPEC, attr, attr ? table : NULL, 0, NULL, tfp_cb, c);
    }
    return rc;
}

struct ttab_ctx {
    const char *table;
    unsigned fams;
    uint64_t handle;
};

#define NFD_TABLE_HANDLE 4          /* NFTA_TABLE_HANDLE, 4.16 */

static void ttab_cb(const struct nlmsghdr *m, void *arg) {
    struct ttab_ctx *c = arg;
    if (!msg_is(m, NFT_MSG_NEWTABLE)) return;
    int fi = tfp_fam(msg_family(m));
    if (fi < 0) return;
    const struct nlattr *tb[NFD_TABLE_HANDLE + 1];
    msg_attrs(m, tb, NFD_TABLE_HANDLE);
    char t[64];
    if (strcmp(nla_cstr(tb[NFTA_TABLE_NAME], t, sizeof(t)), c->table) != 0) return;
    c->fams |= 1u << fi;
    if (fi == 0) c->handle = nla_be64(tb[NFD_TABLE_HANDLE]);
}

static void ttab_reset(void *arg) {
    struct ttab_ctx *c = arg;
    c->fams = 0;
    c->handle = 0;
}

int nfd_table_fp(const char *table, struct nfd_tfp *out) {
    memset(out, 0, sizeof(*out));
    int fd = nfd_open();
    if (fd < 0) return -1;
    struct ttab_ctx tt = { table, 0, 0 };
    int rc = EINTR;
    for (int i = 0; i < 5 && rc == EINTR; i++) {
        ttab_reset(&tt);
        rc = nfd_talk(fd, NFT_MSG_GETTABLE, 1, NFPROTO_UNSPEC, 0, NULL, 0, NULL, ttab_cb, &tt);
    }
    if (rc != 0) { close(fd); return -1; }
    uint64_t h = NFD_FNV_INIT;
    fp_mix(&h, &tt.fams, sizeof(tt.fams));
    if (!tt.fams) {
        close(fd);
        out->fp = h;
        return 0;
    }
    /* attr — фильтр дампа по таблице (0 — без него, см. шапку раздела). */
    static const struct { uint16_t get, add, attr; uint32_t skip; } kinds[3] = {
        { NFT_MSG_GETCHAIN, NFT_MSG_NEWCHAIN, 0,
          1u << NFD_CHAIN_HANDLE | 1u << NFD_CHAIN_USE | 1u << NFD_CHAIN_COUNTERS |
          1u << NFD_CHAIN_PAD | 1u << NFD_CHAIN_ID },
        { NFT_MSG_GETSET, NFT_MSG_NEWSET, 0,
          1u << NFD_SET_ID | 1u << NFD_SET_PAD | 1u << NFD_SET_HANDLE | 1u << NFD_SET_EXPR |
          1u << NFD_SET_EXPRS },
        { NFT_MSG_GETRULE, NFT_MSG_NEWRULE, NFTA_RULE_TABLE,
          1u << NFD_RULE_HANDLE | 1u << NFD_RULE_POSITION | 1u << NFD_RULE_PAD |
          1u << NFD_RULE_ID | 1u << NFD_RULE_POS_ID | 1u << NFD_RULE_CHAIN_ID },
    };
    struct tfp_ctx c[3];
    for (int k = 0; k < 3; k++) {
        c[k].table = table;
        c[k].msg = kinds[k].add;
        c[k].skip = kinds[k].skip;
        rc = tfp_dump(fd, kinds[k].get, kinds[k].attr, table, &c[k]);
        if (rc != 0 && rc != ENOENT) { close(fd); return -1; }
    }
    close(fd);
    /* По семейству: есть ли таблица, затем три вида объектов — число и свёртка. */
    for (int f = 0; f < 3; f++) {
        if (!(tt.fams & (1u << f))) continue;
        fp_mix(&h, &g_tfp_fams[f], 1);
        for (int k = 0; k < 3; k++) {
            fp_mix(&h, &k, sizeof(k));
            fp_mix(&h, &c[k].n[f], sizeof(c[k].n[f]));
            fp_mix(&h, &c[k].h[f], sizeof(c[k].h[f]));
        }
    }
    out->fp = h;
    out->handle = tt.handle;
    out->fams = tt.fams;
    return 0;
}

/* ---- наборы и их элементы (сверка элементов статических наборов, recon.c) ------------------ */

#define NFD_SET_KEY_LEN      5      /* NFTA_SET_KEY_LEN */
#define NFD_SET_ELEM_TIMEOUT 4      /* NFTA_SET_ELEM_TIMEOUT */
#define NFD_SET_ELEM_EXPIRE  5      /* NFTA_SET_ELEM_EXPIRATION */

struct sets_ctx {
    const char *table;
    nfd_set_fn fn;
    void *arg;
};

static void sets_list_cb(const struct nlmsghdr *m, void *arg) {
    struct sets_ctx *c = arg;
    if (!msg_is(m, NFT_MSG_NEWSET)) return;
    const struct nlattr *tb[NFTA_SET_MAX + 1];
    msg_attrs(m, tb, NFTA_SET_MAX);
    char t[64];
    if (strcmp(nla_cstr(tb[NFTA_SET_TABLE], t, sizeof(t)), c->table) != 0) return;
    struct nfd_set s;
    memset(&s, 0, sizeof(s));
    s.family = msg_family(m);
    nla_cstr(tb[NFTA_SET_NAME], s.name, sizeof(s.name));
    s.flags = nla_be32(tb[NFTA_SET_FLAGS]);
    s.klen = nla_be32(tb[NFD_SET_KEY_LEN]);
    c->fn(c->arg, &s);
}

int nfd_sets(const char *table, nfd_set_fn fn, void *arg) {
    int fd = nfd_open();
    if (fd < 0) return errno ? errno : EIO;
    struct sets_ctx c = { table, fn, arg };
    /* Без атрибута таблицы и без фильтра по семейству — почему, в шапке раздела отпечатка.
     * Без повтора: заголовки наборов меняет только nft -f, а набор, которого к дампу его
     * элементов уже нет, вызывающий (сверка элементов) и так считает «не прочитать». */
    int rc = nfd_talk(fd, NFT_MSG_GETSET, 1, NFPROTO_UNSPEC, 0, NULL, 0, NULL, sets_list_cb, &c);
    close(fd);
    return rc;
}

struct elems_ctx {
    nfd_elem_fn fn;
    void *arg;
    int msgs;
    uint16_t gen;                   /* res_id первого ответа */
    int gen_moved;                  /* у какого-то ответа res_id другой */
};

static void elems_list_cb(const struct nlmsghdr *m, void *arg) {
    struct elems_ctx *c = arg;
    if (!msg_is(m, NFT_MSG_NEWSETELEM)) return;
    /* Номер поколения набора правил (nfgenmsg.res_id: младшие 16 бит base_seq — так отвечает и
     * 4.9, проверено на tools/vm49): растёт с каждой транзакцией, в том числе с элементом
     * резолвера. Разный у ответов одного дампа — посреди дампа кто-то писал. */
    uint16_t g = ((const struct nfgenmsg *)NLMSG_DATA(m))->res_id;
    if (!c->msgs++) c->gen = g;
    else if (g != c->gen) c->gen_moved = 1;
    const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1];
    msg_attrs(m, tb, NFTA_SET_ELEM_LIST_MAX);
    if (!tb[NFTA_SET_ELEM_LIST_ELEMENTS]) return;
    const struct nlattr *e;
    NLA_FOR_EACH(e, tb[NFTA_SET_ELEM_LIST_ELEMENTS]) {
        const struct nlattr *et[NFD_SET_ELEM_KEY_END + 1];
        nfd_nested(e, et, NFD_SET_ELEM_KEY_END);
        struct nfd_elem x;
        memset(&x, 0, sizeof(x));
        static const uint8_t none[1];
        x.key = none;
        if (et[NFTA_SET_ELEM_KEY]) {
            const struct nlattr *dt[NFTA_DATA_MAX + 1];
            nfd_nested(et[NFTA_SET_ELEM_KEY], dt, NFTA_DATA_MAX);
            if (dt[NFTA_DATA_VALUE]) {
                x.key = nla_ptr(dt[NFTA_DATA_VALUE]);
                x.klen = nla_size(dt[NFTA_DATA_VALUE]);
            }
        }
        if (et[NFD_SET_ELEM_KEY_END]) {
            const struct nlattr *dt[NFTA_DATA_MAX + 1];
            nfd_nested(et[NFD_SET_ELEM_KEY_END], dt, NFTA_DATA_MAX);
            if (dt[NFTA_DATA_VALUE]) {
                x.key_end = nla_ptr(dt[NFTA_DATA_VALUE]);
                x.kelen = nla_size(dt[NFTA_DATA_VALUE]);
            }
        }
        x.flags = nla_be32(et[NFTA_SET_ELEM_FLAGS]);
        x.timeout = et[NFD_SET_ELEM_TIMEOUT] || et[NFD_SET_ELEM_EXPIRE];
        x.data = et[NFTA_SET_ELEM_DATA] != NULL;
        c->fn(c->arg, &x);
    }
}

int nfd_set_elems(uint8_t family, const char *table, const char *set, nfd_elem_fn fn,
                  void (*reset)(void *arg), void *arg, int *stable) {
    int fd = nfd_open();
    if (fd < 0) return errno ? errno : EIO;
    struct elems_ctx c;
    int rc = EINTR;
    for (int i = 0; i < 3 && rc == EINTR; i++) {
        if (i && reset) reset(arg);
        memset(&c, 0, sizeof(c));
        c.fn = fn;
        c.arg = arg;
        rc = nfd_talk(fd, NFT_MSG_GETSETELEM, 1, family, NFTA_SET_ELEM_LIST_TABLE, table,
                      NFTA_SET_ELEM_LIST_SET, set, elems_list_cb, &c);
    }
    close(fd);
    if (stable) *stable = !c.gen_moved;
    return rc;
}

/* ---- redirect на порт ---------------------------------------------------------------------- */

/* Регистр выражения — в номер 32-битной ячейки (NFT_REG_1..4 — по четыре ячейки). -1 — не данные. */
static int reg_slot(uint32_t r) {
    if (r >= NFT_REG_1 && r <= NFT_REG_4) return (int)(r - NFT_REG_1) * 4;
    if (r >= NFD_REG32_00 && r < NFD_REG32_00 + 16) return (int)(r - NFD_REG32_00);
    return -1;
}

struct redir_ctx {
    const char *table;
    uint16_t port_be;
    int found;
};

static void redir_cb(const struct nlmsghdr *h, void *arg) {
    struct redir_ctx *c = arg;
    if (c->found || !msg_is(h, NFT_MSG_NEWRULE)) return;
    const struct nlattr *tb[NFTA_RULE_MAX + 1];
    msg_attrs(h, tb, NFTA_RULE_MAX);
    char t[64];
    if (strcmp(nla_cstr(tb[NFTA_RULE_TABLE], t, sizeof(t)), c->table) != 0 ||
        !tb[NFTA_RULE_EXPRESSIONS])
        return;
    /* Порт — в регистре, куда его положило immediate перед redir. */
    int have[16] = {0};
    uint16_t val[16] = {0};
    const struct nlattr *e;
    NLA_FOR_EACH(e, tb[NFTA_RULE_EXPRESSIONS]) {
        const struct nlattr *et[NFTA_EXPR_MAX + 1];
        nfd_nested(e, et, NFTA_EXPR_MAX);
        char name[32];
        nla_cstr(et[NFTA_EXPR_NAME], name, sizeof(name));
        if (!et[NFTA_EXPR_DATA]) continue;
        if (!strcmp(name, "immediate")) {
            const struct nlattr *it[NFTA_IMMEDIATE_MAX + 1];
            nfd_nested(et[NFTA_EXPR_DATA], it, NFTA_IMMEDIATE_MAX);
            int s = reg_slot(nla_be32(it[NFTA_IMMEDIATE_DREG]));
            if (s < 0 || !it[NFTA_IMMEDIATE_DATA]) continue;
            const struct nlattr *dt[NFTA_DATA_MAX + 1];
            nfd_nested(it[NFTA_IMMEDIATE_DATA], dt, NFTA_DATA_MAX);
            if (!dt[NFTA_DATA_VALUE] || nla_size(dt[NFTA_DATA_VALUE]) < 2) continue;
            memcpy(&val[s], nla_ptr(dt[NFTA_DATA_VALUE]), 2);
            have[s] = 1;
        } else if (!strcmp(name, "redir")) {
            const struct nlattr *rt[NFTA_REDIR_MAX + 1];
            nfd_nested(et[NFTA_EXPR_DATA], rt, NFTA_REDIR_MAX);
            if (!rt[NFTA_REDIR_REG_PROTO_MIN]) continue;
            int s = reg_slot(nla_be32(rt[NFTA_REDIR_REG_PROTO_MIN]));
            if (s >= 0 && have[s] && val[s] == c->port_be) c->found = 1;
        }
    }
}

int nfd_has_redirect(uint8_t family, const char *table, uint16_t port) {
    int fd = nfd_open();
    if (fd < 0) return 0;
    struct redir_ctx c = { table, htons(port), 0 };
    int rc = nfd_talk(fd, NFT_MSG_GETRULE, 1, family, NFTA_RULE_TABLE, table, 0, NULL,
                      redir_cb, &c);
    close(fd);
    (void)rc;
    return c.found;
}

/* ---- набор правил текстом ------------------------------------------------------------------ *
 *
 * Снимок в памяти: таблицы, наборы (у безымянных — их элементы: они печатаются внутри правила),
 * flowtable, цепочки, правила уже строками. Печать — в порядке nft: у таблицы сначала наборы и
 * flowtable, потом цепочки, каждая со своими правилами. */

struct sbuf {
    char *p;
    size_t n, cap;
    int oom;
};

static void sb_putn(struct sbuf *s, const char *t, size_t l) {
    if (s->oom) return;
    if (s->n + l + 1 > s->cap) {
        size_t nc = s->cap ? s->cap : 4096;
        while (s->n + l + 1 > nc) nc *= 2;
        char *np = realloc(s->p, nc);
        if (!np) { s->oom = 1; return; }
        s->p = np;
        s->cap = nc;
    }
    memcpy(s->p + s->n, t, l);
    s->n += l;
    s->p[s->n] = '\0';
}

static void sb_puts(struct sbuf *s, const char *t) { sb_putn(s, t, strlen(t)); }

static void sb_printf(struct sbuf *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(struct sbuf *s, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (k < 0) return;
    sb_putn(s, tmp, (size_t)k < sizeof(tmp) ? (size_t)k : sizeof(tmp) - 1);
}

struct rs_elem {
    uint8_t key[16];
    uint8_t klen;
    int verdict;          /* у карты вердиктов: 1 — есть */
    int32_t vcode;
    char vchain[64];
};

struct rs_set {
    uint8_t fam;
    char table[64], name[64], comment[128];
    uint32_t flags;
    struct rs_elem *el;
    size_t el_n, el_cap;
};

struct rs_obj {           /* таблица, цепочка или flowtable */
    uint8_t fam;
    char table[64], name[64];
    char *head;           /* строки заголовка (тип, хук, устройства, комментарий), malloc */
};

struct rs_rule {
    uint8_t fam;
    char table[64], chain[64];
    char *text;
};

struct rs {
    struct rs_obj *tab; size_t tab_n, tab_cap;
    struct rs_set *set; size_t set_n, set_cap;
    struct rs_obj *ft;  size_t ft_n, ft_cap;
    struct rs_obj *ch;  size_t ch_n, ch_cap;
    struct rs_rule *ru; size_t ru_n, ru_cap;
    int oom;
    struct rs_set *cur;   /* набор, чьи элементы сейчас дампятся */
};

static void *rs_grow(void **arr, size_t *n, size_t *cap, size_t sz, int *oom) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        void *np = realloc(*arr, nc * sz);
        if (!np) { *oom = 1; return NULL; }
        *arr = np;
        *cap = nc;
    }
    void *slot = (uint8_t *)*arr + (*n)++ * sz;
    memset(slot, 0, sz);
    return slot;
}
#define RS_ADD(r, field) \
    rs_grow((void **)&(r)->field, &(r)->field##_n, &(r)->field##_cap, sizeof(*(r)->field), &(r)->oom)

static const char *fam_name(uint8_t f) {
    switch (f) {
    case NFPROTO_INET: return "inet";
    case NFPROTO_IPV4: return "ip";
    case NFPROTO_IPV6: return "ip6";
    case NFPROTO_ARP: return "arp";
    case NFPROTO_BRIDGE: return "bridge";
    case NFPROTO_NETDEV: return "netdev";
    default: return "unknown";
    }
}

static void tables_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    if (!msg_is(h, NFT_MSG_NEWTABLE)) return;
    const struct nlattr *tb[NFTA_TABLE_MAX + 1];
    msg_attrs(h, tb, NFTA_TABLE_MAX);
    struct rs_obj *o = RS_ADD(r, tab);
    if (!o) return;
    o->fam = msg_family(h);
    nla_cstr(tb[NFTA_TABLE_NAME], o->name, sizeof(o->name));
}

static void sets_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    if (!msg_is(h, NFT_MSG_NEWSET)) return;
    const struct nlattr *tb[NFTA_SET_MAX + 1];
    msg_attrs(h, tb, NFTA_SET_MAX);
    struct rs_set *s = RS_ADD(r, set);
    if (!s) return;
    s->fam = msg_family(h);
    nla_cstr(tb[NFTA_SET_TABLE], s->table, sizeof(s->table));
    nla_cstr(tb[NFTA_SET_NAME], s->name, sizeof(s->name));
    s->flags = nla_be32(tb[NFTA_SET_FLAGS]);
    udata_str(tb[NFTA_SET_USERDATA], NFD_UDATA_SET_COMMENT, s->comment, sizeof(s->comment));
}

static void elems_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    struct rs_set *s = r->cur;
    if (!s || !msg_is(h, NFT_MSG_NEWSETELEM)) return;
    const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1];
    msg_attrs(h, tb, NFTA_SET_ELEM_LIST_MAX);
    if (!tb[NFTA_SET_ELEM_LIST_ELEMENTS]) return;
    const struct nlattr *e;
    NLA_FOR_EACH(e, tb[NFTA_SET_ELEM_LIST_ELEMENTS]) {
        const struct nlattr *et[NFD_SET_ELEM_KEY_END + 1];
        nfd_nested(e, et, NFD_SET_ELEM_KEY_END);
        if (nla_be32(et[NFTA_SET_ELEM_FLAGS]) & NFT_SET_ELEM_INTERVAL_END) continue;
        struct rs_elem *x = rs_grow((void **)&s->el, &s->el_n, &s->el_cap, sizeof(*s->el), &r->oom);
        if (!x) return;
        if (et[NFTA_SET_ELEM_KEY]) {
            const struct nlattr *dt[NFTA_DATA_MAX + 1];
            nfd_nested(et[NFTA_SET_ELEM_KEY], dt, NFTA_DATA_MAX);
            if (dt[NFTA_DATA_VALUE]) {
                size_t l = nla_size(dt[NFTA_DATA_VALUE]);
                if (l > sizeof(x->key)) l = sizeof(x->key);
                memcpy(x->key, nla_ptr(dt[NFTA_DATA_VALUE]), l);
                x->klen = (uint8_t)l;
            }
        }
        if (et[NFTA_SET_ELEM_DATA]) {
            const struct nlattr *dt[NFTA_DATA_MAX + 1];
            nfd_nested(et[NFTA_SET_ELEM_DATA], dt, NFTA_DATA_MAX);
            if (dt[NFTA_DATA_VERDICT]) {
                const struct nlattr *vt[NFTA_VERDICT_MAX + 1];
                nfd_nested(dt[NFTA_DATA_VERDICT], vt, NFTA_VERDICT_MAX);
                x->verdict = 1;
                x->vcode = (int32_t)nla_be32(vt[NFTA_VERDICT_CODE]);
                nla_cstr(vt[NFTA_VERDICT_CHAIN], x->vchain, sizeof(x->vchain));
            }
        }
    }
}

/* Порядок элементов — как у nft: он печатает безымянный набор отсортированным по значению ключа,
 * а ядро отдаёт его в порядке своей хеш-таблицы. Порядок не косметика: fw_check берёт из строки
 * первый переход (`jump`), и в карте вердиктов `{ "wg0" : jump a, "wg1" : goto b }` от него
 * зависит, какая цепочка засчитается. */
static int elem_cmp(const void *a, const void *b) {
    const struct rs_elem *x = a, *y = b;
    size_t n = x->klen < y->klen ? x->klen : y->klen;
    int c = memcmp(x->key, y->key, n);
    return c ? c : (int)x->klen - (int)y->klen;
}

static void elems_reset(void *arg) {
    struct rs *r = arg;
    if (r->cur) r->cur->el_n = 0;
}

/* Устройства хука (NFTA_HOOK_DEVS / NFTA_FLOWTABLE_HOOK_DEVS): `devices = { a, b }`. */
static void put_devs(struct sbuf *s, const struct nlattr *devs) {
    sb_puts(s, "devices = { ");
    const struct nlattr *d;
    int first = 1;
    NLA_FOR_EACH(d, devs) {
        char name[IFNAMSIZ + 1];
        if ((d->nla_type & NLA_TYPE_MASK) != NFD_DEVICE_NAME) continue;
        sb_printf(s, "%s%s", first ? "" : ", ", nla_cstr(d, name, sizeof(name)));
        first = 0;
    }
    sb_puts(s, " }");
}

static const char *hook_name(uint8_t fam, uint32_t n) {
    if (fam == NFPROTO_NETDEV) return n == 0 ? "ingress" : n == 1 ? "egress" : "?";
    switch (n) {
    case NF_INET_PRE_ROUTING: return "prerouting";
    case NF_INET_LOCAL_IN: return "input";
    case NF_INET_FORWARD: return "forward";
    case NF_INET_LOCAL_OUT: return "output";
    case NF_INET_POST_ROUTING: return "postrouting";
    case 5: return "ingress";   /* NF_INET_INGRESS, 5.10 */
    default: return "?";
    }
}

static void chains_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    if (!msg_is(h, NFT_MSG_NEWCHAIN)) return;
    const struct nlattr *tb[NFTA_CHAIN_MAX + 1];
    msg_attrs(h, tb, NFTA_CHAIN_MAX);
    struct rs_obj *o = RS_ADD(r, ch);
    if (!o) return;
    o->fam = msg_family(h);
    nla_cstr(tb[NFTA_CHAIN_TABLE], o->table, sizeof(o->table));
    nla_cstr(tb[NFTA_CHAIN_NAME], o->name, sizeof(o->name));
    struct sbuf s = {0};
    if (tb[NFTA_CHAIN_HOOK]) {
        const struct nlattr *ht[NFD_HOOK_DEVS + 1];
        nfd_nested(tb[NFTA_CHAIN_HOOK], ht, NFD_HOOK_DEVS);
        char type[32], dev[IFNAMSIZ + 1];
        sb_printf(&s, "\t\ttype %s hook %s", nla_cstr(tb[NFTA_CHAIN_TYPE], type, sizeof(type)),
                  hook_name(o->fam, nla_be32(ht[NFTA_HOOK_HOOKNUM])));
        if (ht[NFD_HOOK_DEVS]) {
            sb_puts(&s, " ");
            put_devs(&s, ht[NFD_HOOK_DEVS]);
        } else if (ht[NFTA_HOOK_DEV]) {
            sb_printf(&s, " device \"%s\"", nla_cstr(ht[NFTA_HOOK_DEV], dev, sizeof(dev)));
        }
        sb_printf(&s, " priority %d; policy %s;\n", (int)nla_be32(ht[NFTA_HOOK_PRIORITY]),
                  tb[NFTA_CHAIN_POLICY] && nla_be32(tb[NFTA_CHAIN_POLICY]) == NF_DROP
                      ? "drop" : "accept");
    }
    char comment[256];
    udata_str(tb[NFTA_CHAIN_USERDATA], NFD_UDATA_COMMENT, comment, sizeof(comment));
    if (comment[0]) sb_printf(&s, "\t\tcomment \"%s\"\n", comment);
    if (s.oom) { free(s.p); r->oom = 1; return; }
    o->head = s.p;
}

static void flowtables_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    if (!msg_is(h, NFD_MSG_GETFLOWTABLE - 1)) return;   /* NFT_MSG_NEWFLOWTABLE */
    const struct nlattr *tb[NFD_FT_HOOK + 1];
    msg_attrs(h, tb, NFD_FT_HOOK);
    struct rs_obj *o = RS_ADD(r, ft);
    if (!o) return;
    o->fam = msg_family(h);
    nla_cstr(tb[NFD_FT_TABLE], o->table, sizeof(o->table));
    nla_cstr(tb[NFD_FT_NAME], o->name, sizeof(o->name));
    if (!tb[NFD_FT_HOOK]) return;
    const struct nlattr *ht[NFD_FT_HOOK_DEVS + 1];
    nfd_nested(tb[NFD_FT_HOOK], ht, NFD_FT_HOOK_DEVS);
    if (!ht[NFD_FT_HOOK_DEVS]) return;
    struct sbuf s = {0};
    sb_puts(&s, "\t\t");
    put_devs(&s, ht[NFD_FT_HOOK_DEVS]);
    sb_puts(&s, "\n");
    if (s.oom) { free(s.p); r->oom = 1; return; }
    o->head = s.p;
}

/* ---- правило строкой ----------------------------------------------------------------------- */

/* RK_NFPROTO — `meta nfproto`: семейство, для которого правило в таблице inet написано. Печатается
 * ради fw_check (src/daemon/fwcheck.c): fw4 пишет masquerade зоны двумя правилами — `meta nfproto
 * ipv4 masquerade` (masq) и `meta nfproto ipv6 masquerade` (masq6), — и проверка NAT по семействам
 * (шаг 8 выпуска 1.10) без этого слова в тексте от ядра засчитала бы masq6 за IPv4, как раньше. */
enum rk { RK_NONE, RK_IFNAME, RK_IFINDEX, RK_CTSTATE, RK_CTSTATUS, RK_NFPROTO };

struct rctx {
    struct rs *r;
    uint8_t fam;
    const char *table;
    struct sbuf *s;
    enum rk kind[16];
    uint32_t mask[16];
    int masked[16];
};

static void put_word(struct sbuf *s, const char *w) {
    if (s->n && s->p[s->n - 1] != ' ' && s->p[s->n - 1] != '\t') sb_puts(s, " ");
    sb_puts(s, w);
}

static void put_bits(struct sbuf *s, enum rk k, uint32_t v) {
    static const struct { uint32_t bit; const char *name; } st[] = {
        { 1u << 0, "invalid" }, { 1u << 1, "established" }, { 1u << 2, "related" },
        { 1u << 3, "new" }, { 1u << 6, "untracked" },
    }, ss[] = {
        { 1u << 0, "expected" }, { 1u << 1, "seen-reply" }, { 1u << 2, "assured" },
        { 1u << 3, "confirmed" }, { 1u << 4, "snat" }, { 1u << 5, "dnat" }, { 1u << 9, "dying" },
    };
    const size_t n = k == RK_CTSTATE ? sizeof(st) / sizeof(st[0]) : sizeof(ss) / sizeof(ss[0]);
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        uint32_t bit = k == RK_CTSTATE ? st[i].bit : ss[i].bit;
        if (!(v & bit)) continue;
        if (first) put_word(s, k == RK_CTSTATE ? st[i].name : ss[i].name);
        else { sb_puts(s, ","); sb_puts(s, k == RK_CTSTATE ? st[i].name : ss[i].name); }
        first = 0;
    }
}

/* Значение по виду регистра, из которого его сравнивают. Прочие виды не печатаются. */
static void put_value(struct sbuf *s, enum rk k, const uint8_t *d, size_t l) {
    if (k == RK_IFNAME) {
        char name[IFNAMSIZ + 2];
        size_t i = 0;
        while (i < l && i < IFNAMSIZ && d[i]) { name[i] = (char)d[i]; i++; }
        /* Без нуля в сравнении — маска имени («eth*»): nft сравнивает только начало. */
        if (i == l && i < IFNAMSIZ) name[i++] = '*';
        name[i] = '\0';
        put_word(s, "\"");
        sb_puts(s, name);
        sb_puts(s, "\"");
    } else if (k == RK_IFINDEX && l >= 4) {
        uint32_t idx;
        memcpy(&idx, d, 4);
        char name[IF_NAMESIZE];
        if (if_indextoname(idx, name)) {
            put_word(s, "\"");
            sb_puts(s, name);
            sb_puts(s, "\"");
        } else {
            char num[16];
            snprintf(num, sizeof(num), "%u", idx);
            put_word(s, num);
        }
    } else if ((k == RK_CTSTATE || k == RK_CTSTATUS) && l >= 4) {
        uint32_t v;
        memcpy(&v, d, 4);
        put_bits(s, k, v);
    } else if (k == RK_NFPROTO && l >= 1) {
        /* NFPROTO_IPV4 = 2, NFPROTO_IPV6 = 10 — так их и пишет nft (`meta nfproto ipv4`). */
        char num[8];
        snprintf(num, sizeof(num), "%u", d[0]);
        put_word(s, d[0] == NFPROTO_IPV4 ? "ipv4" : d[0] == NFPROTO_IPV6 ? "ipv6" : num);
    }
}

static void put_verdict(struct sbuf *s, int32_t code, const char *chain) {
    switch (code) {
    case NF_ACCEPT: put_word(s, "accept"); break;
    case NF_DROP: put_word(s, "drop"); break;
    case NF_QUEUE: put_word(s, "queue"); break;
    case NFT_CONTINUE: put_word(s, "continue"); break;
    case NFT_RETURN: put_word(s, "return"); break;
    case NFT_JUMP: put_word(s, "jump"); put_word(s, chain); break;
    case NFT_GOTO: put_word(s, "goto"); put_word(s, chain); break;
    default: break;
    }
}

static const struct rs_set *find_set(const struct rs *r, uint8_t fam, const char *table,
                                     const char *name) {
    for (size_t i = 0; i < r->set_n; i++)
        if (r->set[i].fam == fam && !strcmp(r->set[i].table, table) &&
            !strcmp(r->set[i].name, name))
            return &r->set[i];
    return NULL;
}

static void expr_meta(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_META_MAX + 1];
    nfd_nested(data, t, NFTA_META_MAX);
    if (!t[NFTA_META_DREG]) return;       /* `meta … set` — не про устройства */
    int sl = reg_slot(nla_be32(t[NFTA_META_DREG]));
    if (sl < 0) return;
    c->masked[sl] = 0;
    switch (nla_be32(t[NFTA_META_KEY])) {
    case NFT_META_IIFNAME: c->kind[sl] = RK_IFNAME; put_word(c->s, "iifname"); break;
    case NFT_META_OIFNAME: c->kind[sl] = RK_IFNAME; put_word(c->s, "oifname"); break;
    case NFT_META_IIF: c->kind[sl] = RK_IFINDEX; put_word(c->s, "iif"); break;
    case NFT_META_OIF: c->kind[sl] = RK_IFINDEX; put_word(c->s, "oif"); break;
    case NFT_META_NFPROTO: c->kind[sl] = RK_NFPROTO; put_word(c->s, "meta nfproto"); break;
    default: c->kind[sl] = RK_NONE; break;
    }
}

static void expr_ct(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_CT_MAX + 1];
    nfd_nested(data, t, NFTA_CT_MAX);
    if (!t[NFTA_CT_DREG]) return;
    int sl = reg_slot(nla_be32(t[NFTA_CT_DREG]));
    if (sl < 0) return;
    c->masked[sl] = 0;
    switch (nla_be32(t[NFTA_CT_KEY])) {
    case NFT_CT_STATE: c->kind[sl] = RK_CTSTATE; put_word(c->s, "ct state"); break;
    case NFT_CT_STATUS: c->kind[sl] = RK_CTSTATUS; put_word(c->s, "ct status"); break;
    default: c->kind[sl] = RK_NONE; break;
    }
}

static void expr_bitwise(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_BITWISE_MAX + 1];
    nfd_nested(data, t, NFTA_BITWISE_MAX);
    int sr = reg_slot(nla_be32(t[NFTA_BITWISE_SREG]));
    int dr = reg_slot(nla_be32(t[NFTA_BITWISE_DREG]));
    if (dr < 0) return;
    enum rk k = sr >= 0 ? c->kind[sr] : RK_NONE;
    c->kind[dr] = k;
    c->masked[dr] = 0;
    if ((k == RK_CTSTATE || k == RK_CTSTATUS) && t[NFTA_BITWISE_MASK]) {
        const struct nlattr *dt[NFTA_DATA_MAX + 1];
        nfd_nested(t[NFTA_BITWISE_MASK], dt, NFTA_DATA_MAX);
        if (dt[NFTA_DATA_VALUE] && nla_size(dt[NFTA_DATA_VALUE]) >= 4) {
            memcpy(&c->mask[dr], nla_ptr(dt[NFTA_DATA_VALUE]), 4);
            c->masked[dr] = 1;
        }
    }
}

static void expr_cmp(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_CMP_MAX + 1];
    nfd_nested(data, t, NFTA_CMP_MAX);
    int sl = reg_slot(nla_be32(t[NFTA_CMP_SREG]));
    if (sl < 0 || c->kind[sl] == RK_NONE || !t[NFTA_CMP_DATA]) return;
    const struct nlattr *dt[NFTA_DATA_MAX + 1];
    nfd_nested(t[NFTA_CMP_DATA], dt, NFTA_DATA_MAX);
    if (!dt[NFTA_DATA_VALUE]) return;
    const uint8_t *d = nla_ptr(dt[NFTA_DATA_VALUE]);
    size_t l = nla_size(dt[NFTA_DATA_VALUE]);
    uint32_t op = nla_be32(t[NFTA_CMP_OP]);
    /* `ct state established,related`: маска, затем «не ноль» — печатаются биты маски. */
    if (c->masked[sl] && l >= 4) {
        uint32_t v;
        memcpy(&v, d, 4);
        if (op == NFT_CMP_NEQ && v == 0) { put_bits(c->s, c->kind[sl], c->mask[sl]); return; }
    }
    if (op == NFT_CMP_NEQ) put_word(c->s, "!=");
    put_value(c->s, c->kind[sl], d, l);
}

static void expr_lookup(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_LOOKUP_MAX + 1];
    nfd_nested(data, t, NFTA_LOOKUP_MAX);
    char name[64];
    nla_cstr(t[NFTA_LOOKUP_SET], name, sizeof(name));
    int sl = reg_slot(nla_be32(t[NFTA_LOOKUP_SREG]));
    enum rk k = sl >= 0 ? c->kind[sl] : RK_NONE;
    int vmap = t[NFTA_LOOKUP_DREG] && nla_be32(t[NFTA_LOOKUP_DREG]) == NFT_REG_VERDICT;
    if (nla_be32(t[NFTA_LOOKUP_FLAGS]) & NFT_LOOKUP_F_INV) put_word(c->s, "!=");
    const struct rs_set *s = find_set(c->r, c->fam, c->table, name);
    if (vmap) put_word(c->s, "vmap");
    else if (t[NFTA_LOOKUP_DREG]) put_word(c->s, "map");
    if (!s || !(s->flags & NFT_SET_ANONYMOUS)) {
        put_word(c->s, "@");
        sb_puts(c->s, name);
        return;
    }
    /* Ключ печатается, только когда его вид известен (устройство, ct); у прочих элементов
     * остаётся вердикт карты — переход в цепочку fw_check читает и из него. */
    put_word(c->s, "{");
    int first = 1;
    for (size_t i = 0; i < s->el_n; i++) {
        size_t at = c->s->n;
        if (!first) sb_puts(c->s, ",");
        size_t mark = c->s->n;
        put_value(c->s, k, s->el[i].key, s->el[i].klen);
        if (s->el[i].verdict) {
            put_word(c->s, ":");
            put_verdict(c->s, s->el[i].vcode, s->el[i].vchain);
        }
        if (c->s->n == mark) {        /* сказать об элементе нечего — и запятой не нужно */
            c->s->n = at;
            if (c->s->p) c->s->p[at] = '\0';
            continue;
        }
        first = 0;
    }
    put_word(c->s, "}");
}

static void expr_immediate(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_IMMEDIATE_MAX + 1];
    nfd_nested(data, t, NFTA_IMMEDIATE_MAX);
    if (!t[NFTA_IMMEDIATE_DATA]) return;
    const struct nlattr *dt[NFTA_DATA_MAX + 1];
    nfd_nested(t[NFTA_IMMEDIATE_DATA], dt, NFTA_DATA_MAX);
    if (nla_be32(t[NFTA_IMMEDIATE_DREG]) != NFT_REG_VERDICT) {
        int sl = reg_slot(nla_be32(t[NFTA_IMMEDIATE_DREG]));
        if (sl >= 0) { c->kind[sl] = RK_NONE; c->masked[sl] = 0; }
        return;
    }
    if (!dt[NFTA_DATA_VERDICT]) return;
    const struct nlattr *vt[NFTA_VERDICT_MAX + 1];
    nfd_nested(dt[NFTA_DATA_VERDICT], vt, NFTA_VERDICT_MAX);
    char chain[64];
    put_verdict(c->s, (int32_t)nla_be32(vt[NFTA_VERDICT_CODE]),
                nla_cstr(vt[NFTA_VERDICT_CHAIN], chain, sizeof(chain)));
}

/* fib: `fib saddr . iif oif` — слово oif в строке правила читает fw_check. */
static void expr_fib(struct rctx *c, const struct nlattr *data) {
    const struct nlattr *t[NFTA_FIB_MAX + 1];
    nfd_nested(data, t, NFTA_FIB_MAX);
    uint32_t f = nla_be32(t[NFTA_FIB_FLAGS]);
    put_word(c->s, "fib");
    if (f & NFTA_FIB_F_SADDR) put_word(c->s, "saddr");
    if (f & NFTA_FIB_F_DADDR) put_word(c->s, "daddr");
    if (f & NFTA_FIB_F_MARK) put_word(c->s, ". mark");
    if (f & NFTA_FIB_F_IIF) put_word(c->s, ". iif");
    if (f & NFTA_FIB_F_OIF) put_word(c->s, ". oif");
    switch (nla_be32(t[NFTA_FIB_RESULT])) {
    case NFT_FIB_RESULT_OIF: put_word(c->s, "oif"); break;
    case NFT_FIB_RESULT_OIFNAME: put_word(c->s, "oifname"); break;
    case NFT_FIB_RESULT_ADDRTYPE: put_word(c->s, "type"); break;
    default: break;
    }
    int sl = reg_slot(nla_be32(t[NFTA_FIB_DREG]));
    if (sl >= 0) { c->kind[sl] = RK_NONE; c->masked[sl] = 0; }
}

static void expr_one(struct rctx *c, const char *name, const struct nlattr *data) {
    if (!strcmp(name, "meta")) expr_meta(c, data);
    else if (!strcmp(name, "ct")) expr_ct(c, data);
    else if (!strcmp(name, "bitwise")) expr_bitwise(c, data);
    else if (!strcmp(name, "cmp")) expr_cmp(c, data);
    else if (!strcmp(name, "lookup")) expr_lookup(c, data);
    else if (!strcmp(name, "immediate")) expr_immediate(c, data);
    else if (!strcmp(name, "fib")) expr_fib(c, data);
    else if (!strcmp(name, "masq")) put_word(c->s, "masquerade");
    else if (!strcmp(name, "redir")) put_word(c->s, "redirect");
    else if (!strcmp(name, "counter")) put_word(c->s, "counter");
    else if (!strcmp(name, "reject")) put_word(c->s, "reject");
    else if (!strcmp(name, "notrack")) put_word(c->s, "notrack");
    else if (!strcmp(name, "queue")) put_word(c->s, "queue");
    else if (!strcmp(name, "nat")) {
        const struct nlattr *t[NFTA_NAT_MAX + 1];
        nfd_nested(data, t, NFTA_NAT_MAX);
        put_word(c->s, nla_be32(t[NFTA_NAT_TYPE]) == NFT_NAT_SNAT ? "snat to" : "dnat to");
    } else if (!strcmp(name, "log")) {
        const struct nlattr *t[NFTA_LOG_MAX + 1];
        nfd_nested(data, t, NFTA_LOG_MAX);
        put_word(c->s, "log");
        if (t[NFTA_LOG_PREFIX]) {
            char p[160];
            put_word(c->s, "prefix \"");
            sb_puts(c->s, nla_cstr(t[NFTA_LOG_PREFIX], p, sizeof(p)));
            sb_puts(c->s, "\"");
        }
    } else {
        /* Выражения, которые грузят регистр чем-то, что не устройство и не ct (адрес, порт,
         * метка маршрута…): сравнение с таким регистром не печатается, поэтому регистр
         * забывает прежний вид. Номер атрибута DREG у них разный. */
        static const struct { const char *name; int dreg; } LOADS[] = {
            { "payload", 1 }, { "exthdr", 1 }, { "rt", 1 }, { "numgen", 1 }, { "osf", 1 },
            { "xfrm", 1 }, { "socket", 2 }, { "hash", 2 }, { "byteorder", 2 },
        };
        for (size_t i = 0; i < sizeof(LOADS) / sizeof(LOADS[0]); i++) {
            if (strcmp(name, LOADS[i].name) != 0) continue;
            const struct nlattr *t[3];
            nfd_nested(data, t, 2);
            int sl = t[LOADS[i].dreg] ? reg_slot(nla_be32(t[LOADS[i].dreg])) : -1;
            if (sl >= 0) { c->kind[sl] = RK_NONE; c->masked[sl] = 0; }
            break;
        }
    }
}

static void rules_cb(const struct nlmsghdr *h, void *arg) {
    struct rs *r = arg;
    if (!msg_is(h, NFT_MSG_NEWRULE)) return;
    const struct nlattr *tb[NFTA_RULE_MAX + 1];
    msg_attrs(h, tb, NFTA_RULE_MAX);
    struct rs_rule *ru = RS_ADD(r, ru);
    if (!ru) return;
    ru->fam = msg_family(h);
    nla_cstr(tb[NFTA_RULE_TABLE], ru->table, sizeof(ru->table));
    nla_cstr(tb[NFTA_RULE_CHAIN], ru->chain, sizeof(ru->chain));
    struct sbuf s = {0};
    sb_puts(&s, "\t\t");
    struct rctx c;
    memset(&c, 0, sizeof(c));
    c.r = r;
    c.fam = ru->fam;
    c.table = ru->table;
    c.s = &s;
    if (tb[NFTA_RULE_EXPRESSIONS]) {
        const struct nlattr *e;
        NLA_FOR_EACH(e, tb[NFTA_RULE_EXPRESSIONS]) {
            const struct nlattr *et[NFTA_EXPR_MAX + 1];
            nfd_nested(e, et, NFTA_EXPR_MAX);
            char name[32];
            nla_cstr(et[NFTA_EXPR_NAME], name, sizeof(name));
            if (et[NFTA_EXPR_DATA]) expr_one(&c, name, et[NFTA_EXPR_DATA]);
            else expr_one(&c, name, e);   /* masq/counter без данных: e как пустой список */
        }
    }
    char comment[256];
    udata_str(tb[NFTA_RULE_USERDATA], NFD_UDATA_COMMENT, comment, sizeof(comment));
    if (comment[0]) {
        put_word(&s, "comment \"");
        sb_puts(&s, comment);
        sb_puts(&s, "\"");
    }
    sb_puts(&s, "\n");
    if (s.oom) { free(s.p); r->oom = 1; r->ru_n--; return; }
    ru->text = s.p;
}

static void rs_free(struct rs *r) {
    for (size_t i = 0; i < r->set_n; i++) free(r->set[i].el);
    for (size_t i = 0; i < r->ch_n; i++) free(r->ch[i].head);
    for (size_t i = 0; i < r->ft_n; i++) free(r->ft[i].head);
    for (size_t i = 0; i < r->ru_n; i++) free(r->ru[i].text);
    free(r->tab);
    free(r->set);
    free(r->ft);
    free(r->ch);
    free(r->ru);
}

static void tables_reset(void *arg) { ((struct rs *)arg)->tab_n = 0; }
static void sets_reset(void *arg) { ((struct rs *)arg)->set_n = 0; }
static void chains_reset(void *arg) {
    struct rs *r = arg;
    for (size_t i = 0; i < r->ch_n; i++) free(r->ch[i].head);
    r->ch_n = 0;
}
static void fts_reset(void *arg) {
    struct rs *r = arg;
    for (size_t i = 0; i < r->ft_n; i++) free(r->ft[i].head);
    r->ft_n = 0;
}
static void rules_reset(void *arg) {
    struct rs *r = arg;
    for (size_t i = 0; i < r->ru_n; i++) free(r->ru[i].text);
    r->ru_n = 0;
}

char *nfd_ruleset_text(void) {
    int fd = nfd_open();
    if (fd < 0) return NULL;
    struct rs r;
    memset(&r, 0, sizeof(r));
    int rc = nfd_dump(fd, NFT_MSG_GETTABLE, NFPROTO_UNSPEC, 0, NULL, 0, NULL,
                      tables_cb, &r, tables_reset);
    if (!rc) rc = nfd_dump(fd, NFT_MSG_GETSET, NFPROTO_UNSPEC, 0, NULL, 0, NULL,
                           sets_cb, &r, sets_reset);
    /* Элементы — только у безымянных наборов: они печатаются внутри правил. Именованные nft -t
     * печатает без элементов, и их бывают десятки тысяч. */
    for (size_t i = 0; !rc && i < r.set_n; i++) {
        if (!(r.set[i].flags & NFT_SET_ANONYMOUS)) continue;
        r.cur = &r.set[i];
        rc = nfd_dump(fd, NFT_MSG_GETSETELEM, r.set[i].fam, NFTA_SET_ELEM_LIST_TABLE,
                      r.set[i].table, NFTA_SET_ELEM_LIST_SET, r.set[i].name,
                      elems_cb, &r, elems_reset);
        /* Набор мог исчезнуть между дампами — это не отказ всего снимка. */
        if (rc == ENOENT) rc = 0;
        if (r.set[i].el_n > 1) qsort(r.set[i].el, r.set[i].el_n, sizeof(*r.set[i].el), elem_cmp);
        r.cur = NULL;
    }
    /* flowtable ядро знает с 4.16; раньше — отказ, и печатать нечего. */
    if (!rc) (void)nfd_dump(fd, NFD_MSG_GETFLOWTABLE, NFPROTO_UNSPEC, 0, NULL, 0, NULL,
                            flowtables_cb, &r, fts_reset);
    if (!rc) rc = nfd_dump(fd, NFT_MSG_GETCHAIN, NFPROTO_UNSPEC, 0, NULL, 0, NULL,
                           chains_cb, &r, chains_reset);
    if (!rc) rc = nfd_dump(fd, NFT_MSG_GETRULE, NFPROTO_UNSPEC, 0, NULL, 0, NULL,
                           rules_cb, &r, rules_reset);
    close(fd);
    if (rc || r.oom) { rs_free(&r); return NULL; }

    struct sbuf s = {0};
    sb_puts(&s, "");
    for (size_t t = 0; t < r.tab_n; t++) {
        const struct rs_obj *tb = &r.tab[t];
        sb_printf(&s, "table %s %s {\n", fam_name(tb->fam), tb->name);
        for (size_t i = 0; i < r.set_n; i++) {
            const struct rs_set *st = &r.set[i];
            if (st->fam != tb->fam || strcmp(st->table, tb->name) || (st->flags & NFT_SET_ANONYMOUS))
                continue;
            sb_printf(&s, "\t%s %s {\n", st->flags & NFT_SET_MAP ? "map" : "set", st->name);
            if (st->comment[0]) sb_printf(&s, "\t\tcomment \"%s\"\n", st->comment);
            sb_puts(&s, "\t}\n");
        }
        for (size_t i = 0; i < r.ft_n; i++) {
            const struct rs_obj *o = &r.ft[i];
            if (o->fam != tb->fam || strcmp(o->table, tb->name)) continue;
            sb_printf(&s, "\tflowtable %s {\n", o->name);
            if (o->head) sb_puts(&s, o->head);
            sb_puts(&s, "\t}\n");
        }
        for (size_t i = 0; i < r.ch_n; i++) {
            const struct rs_obj *o = &r.ch[i];
            if (o->fam != tb->fam || strcmp(o->table, tb->name)) continue;
            sb_printf(&s, "\tchain %s {\n", o->name);
            if (o->head) sb_puts(&s, o->head);
            for (size_t k = 0; k < r.ru_n; k++) {
                const struct rs_rule *ru = &r.ru[k];
                if (ru->fam == o->fam && !strcmp(ru->table, o->table) &&
                    !strcmp(ru->chain, o->name) && ru->text)
                    sb_puts(&s, ru->text);
            }
            sb_puts(&s, "\t}\n");
        }
        sb_puts(&s, "}\n");
    }
    rs_free(&r);
    if (s.oom) { free(s.p); return NULL; }
    return s.p;
}
