/* rtnetlink в процессе — устройство и доводы в rtnl.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include "nlbuf.h"
#include "rtnl.h"

static uint32_t g_rtnl_seq;
/* Семейство дампа правил и маршрутов: AF_INET (прежние rtnl_*_text) или AF_INET6 (…_text6,
 * маршрутизация IPv6 выходов с 1.9). Переменной, а не параметром колбэков: вызов синхронный и
 * однопоточный (см. rtnl.h), и так печатник у обоих семейств один. */
static int g_fam = AF_INET;

/* Адрес семейства g_fam текстом; полная длина префикса — 32 или 128. */
static int fam_alen(void) { return g_fam == AF_INET6 ? 16 : 4; }
static unsigned fam_full(void) { return g_fam == AF_INET6 ? 128u : 32u; }

static int rtnl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    /* Страховка от вечного recv: ядро отвечает внутри того же вызова, и в работе срок не
     * срабатывает (тот же приём, что у nl_open в kinds/awg.c). */
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

typedef void (*rtnl_cb)(const struct nlmsghdr *h, void *ctx);

/* Отправить одно сообщение и дочитать ответ: до подтверждения, до NLMSG_DONE у дампа. Каждое
 * сообщение ответа, кроме служебных, — в cb. 0 или errno. */
static int rtnl_talk(void *msg, size_t len, rtnl_cb cb, void *ctx) {
    int fd = rtnl_open();
    if (fd < 0) return errno ? errno : EIO;
    struct nlmsghdr *req = msg;
    struct sockaddr_nl to;
    memset(&to, 0, sizeof(to));
    to.nl_family = AF_NETLINK;
    int rc = EIO;
    if (sendto(fd, msg, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        rc = errno;
        close(fd);
        return rc;
    }
    static _Alignas(8) uint8_t rbuf[65536];
    for (int done = 0; !done; ) {
        ssize_t n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n < 0) { if (errno == EINTR) continue; rc = errno; break; }
        if (n == 0) break;
        for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != req->nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e = NLMSG_DATA(h);
                rc = e->error ? -e->error : 0;
                done = 1;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) { rc = 0; done = 1; break; }
            if (cb) cb(h, ctx);
        }
    }
    close(fd);
    return rc;
}

static struct nlmsghdr *msg_begin(struct nlbuf *b, void *mem, size_t cap, uint16_t type,
                                  uint16_t flags, const void *hdr, size_t hl) {
    memset(mem, 0, cap);
    nlbuf_init(b, mem, cap);
    struct nlmsghdr *nh = mem;
    nh->nlmsg_type = type;
    nh->nlmsg_flags = flags;
    nh->nlmsg_seq = ++g_rtnl_seq;
    b->p += NLMSG_HDRLEN;
    memcpy(b->p, hdr, hl);
    b->p += NLMSG_ALIGN(hl);
    return nh;
}

static size_t msg_end(struct nlbuf *b, struct nlmsghdr *nh) {
    nh->nlmsg_len = (uint32_t)(b->p - b->base);
    return nh->nlmsg_len;
}

static void attrs_parse(const void *p, size_t len, const struct rtattr **tb, int max) {
    for (int i = 0; i <= max; i++) tb[i] = NULL;
    const struct rtattr *a = p;
    int left = (int)len;
    for (; RTA_OK(a, left); a = RTA_NEXT(a, left))
        if (a->rta_type <= max) tb[a->rta_type] = a;
}

static uint32_t rta_u32(const struct rtattr *a) {
    uint32_t v = 0;
    if (a && RTA_PAYLOAD(a) >= 4) memcpy(&v, RTA_DATA(a), 4);
    return v;
}

/* ---- печать в форме `ip` ----------------------------------------------------------------- */

struct textbuf {
    char *p;
    size_t n, len;
    int full;
};

/* Одна строка целиком или никак: обрезанная строка разобралась бы как другая. */
static void tb_line(struct textbuf *t, const char *line) {
    size_t l = strlen(line);
    if (t->full || t->len + l + 1 > t->n) { t->full = 1; return; }
    memcpy(t->p + t->len, line, l);
    t->len += l;
    t->p[t->len] = '\0';
}

static const char *table_name(uint32_t t, char *buf, size_t n) {
    if (t == RT_TABLE_LOCAL) return "local";
    if (t == RT_TABLE_MAIN) return "main";
    if (t == RT_TABLE_DEFAULT) return "default";
    snprintf(buf, n, "%u", t);
    return buf;
}

static void rule_cb(const struct nlmsghdr *h, void *ctx) {
    struct textbuf *t = ctx;
    if (h->nlmsg_type != RTM_NEWRULE) return;
    const struct fib_rule_hdr *fr = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*fr));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || fr->family != g_fam) return;
    const struct rtattr *tb[FRA_MAX + 1];
    attrs_parse((const uint8_t *)fr + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, FRA_MAX);
    char line[512], a[INET6_ADDRSTRLEN], tn[16];
    size_t k = 0;
#define PUT(...) do { int w_ = snprintf(line + k, sizeof(line) - k, __VA_ARGS__); \
                      if (w_ > 0) k += (size_t)w_ < sizeof(line) - k ? (size_t)w_ : sizeof(line) - k - 1; } while (0)
    PUT("%u:\tfrom ", tb[FRA_PRIORITY] ? rta_u32(tb[FRA_PRIORITY]) : 0u);
    if (fr->src_len && tb[FRA_SRC] && RTA_PAYLOAD(tb[FRA_SRC]) >= (size_t)fam_alen()) {
        inet_ntop(g_fam, RTA_DATA(tb[FRA_SRC]), a, sizeof(a));
        if (fr->src_len != fam_full()) PUT("%s/%u", a, fr->src_len); else PUT("%s", a);
    } else PUT("all");
    if (fr->dst_len && tb[FRA_DST] && RTA_PAYLOAD(tb[FRA_DST]) >= (size_t)fam_alen()) {
        inet_ntop(g_fam, RTA_DATA(tb[FRA_DST]), a, sizeof(a));
        if (fr->dst_len != fam_full()) PUT(" to %s/%u", a, fr->dst_len); else PUT(" to %s", a);
    }
    /* Метка — как у iproute2: маска печатается, только если она не 0xffffffff. Этим
     * отличается прежняя форма правила без маски, и разбор на это рассчитывает. */
    if (tb[FRA_FWMARK] || tb[FRA_FWMASK]) {
        uint32_t mark = rta_u32(tb[FRA_FWMARK]);
        uint32_t mask = tb[FRA_FWMASK] ? rta_u32(tb[FRA_FWMASK]) : 0xffffffffu;
        if (mask != 0xffffffffu) PUT(" fwmark 0x%x/0x%x", mark, mask);
        else PUT(" fwmark 0x%x", mark);
    }
    if (tb[FRA_IIFNAME]) PUT(" iif %.16s", (const char *)RTA_DATA(tb[FRA_IIFNAME]));
    if (tb[FRA_OIFNAME]) PUT(" oif %.16s", (const char *)RTA_DATA(tb[FRA_OIFNAME]));
    uint32_t table = tb[FRA_TABLE] ? rta_u32(tb[FRA_TABLE]) : fr->table;
    switch (fr->action) {
    case FR_ACT_TO_TBL:      PUT(" lookup %s", table_name(table, tn, sizeof(tn))); break;
    case FR_ACT_GOTO:        PUT(" goto %u", tb[FRA_GOTO] ? rta_u32(tb[FRA_GOTO]) : 0u); break;
    case FR_ACT_NOP:         PUT(" nop"); break;
    case FR_ACT_BLACKHOLE:   PUT(" blackhole"); break;
    case FR_ACT_UNREACHABLE: PUT(" unreachable"); break;
    case FR_ACT_PROHIBIT:    PUT(" prohibit"); break;
    default:                 PUT(" action %u", fr->action); break;
    }
    PUT("\n");
#undef PUT
    tb_line(t, line);
}

/* Дамп правил в out (n байт); *full — не всё влезло. */
static int rules_text_full(char *out, size_t n, int *full) {
    if (!n) return -1;
    out[0] = '\0';
    uint8_t buf[64];
    struct nlbuf b;
    struct fib_rule_hdr fr;
    memset(&fr, 0, sizeof(fr));
    fr.family = (uint8_t)g_fam;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETRULE,
                                    NLM_F_REQUEST | NLM_F_DUMP, &fr, sizeof(fr));
    struct textbuf t = { out, n, 0, 0 };
    if (rtnl_talk(buf, msg_end(&b, nh), rule_cb, &t) != 0) { out[0] = '\0'; return -1; }
    if (full) *full = t.full;
    return 0;
}

int rtnl_rules_text(char *out, size_t n) {
    return rules_text_full(out, n, NULL);
}

char *rtnl_rules_dup(int v6) {
    size_t n = 16384;
    int saved = g_fam;
    g_fam = v6 ? AF_INET6 : AF_INET;
    char *res = NULL;
    for (;;) {
        char *p = malloc(n);
        if (!p) break;
        int full = 0;
        if (rules_text_full(p, n, &full) != 0) { free(p); break; }
        if (!full) { res = p; break; }
        free(p);
        /* Потолок 64 МиБ — не размер таблицы правил, а защита от дампа, который не кончается:
         * правил столько не бывает (одно на выход и на семейство плюс десяток ядерных). */
        if (n >= ((size_t)64 << 20)) break;
        n *= 2;
    }
    g_fam = saved;
    return res;
}

int rtnl_rules_text6(char *out, size_t n) {
    g_fam = AF_INET6;
    int rc = rtnl_rules_text(out, n);
    g_fam = AF_INET;
    return rc;
}

struct route_ctx {
    uint32_t table;
    struct textbuf t;
    /* Для сброса таблицы: сами сообщения дампа — их же и отправляют обратно с RTM_DELROUTE,
     * как делает `ip route flush`. */
    uint8_t *raw;
    size_t raw_n, raw_cap;
};

static const char *rt_type_name(unsigned t) {
    switch (t) {
    case RTN_BLACKHOLE:   return "blackhole";
    case RTN_UNREACHABLE: return "unreachable";
    case RTN_PROHIBIT:    return "prohibit";
    case RTN_THROW:       return "throw";
    case RTN_LOCAL:       return "local";
    case RTN_BROADCAST:   return "broadcast";
    case RTN_MULTICAST:   return "multicast";
    case RTN_ANYCAST:     return "anycast";
    case RTN_NAT:         return "nat";
    default:              return NULL;
    }
}

static void route_cb(const struct nlmsghdr *h, void *ctx) {
    struct route_ctx *c = ctx;
    if (h->nlmsg_type != RTM_NEWROUTE) return;
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || rt->rtm_family != g_fam) return;
    if (rt->rtm_flags & RTM_F_CLONED) return;
    const struct rtattr *tb[RTA_MAX + 1];
    attrs_parse((const uint8_t *)rt + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, RTA_MAX);
    uint32_t table = tb[RTA_TABLE] ? rta_u32(tb[RTA_TABLE]) : rt->rtm_table;
    if (table != c->table) return;
    if (c->raw) {
        if (c->raw_n + h->nlmsg_len <= c->raw_cap) {
            memcpy(c->raw + c->raw_n, h, h->nlmsg_len);
            c->raw_n += NLMSG_ALIGN(h->nlmsg_len);
        }
        return;
    }
    char line[512], a[INET6_ADDRSTRLEN], dev[IF_NAMESIZE];
    size_t k = 0;
#define PUT(...) do { int w_ = snprintf(line + k, sizeof(line) - k, __VA_ARGS__); \
                      if (w_ > 0) k += (size_t)w_ < sizeof(line) - k ? (size_t)w_ : sizeof(line) - k - 1; } while (0)
    const char *type = rt_type_name(rt->rtm_type);
    size_t al = (size_t)fam_alen();
    if (type) PUT("%s ", type);
    if (!rt->rtm_dst_len) PUT("default");
    else if (tb[RTA_DST] && RTA_PAYLOAD(tb[RTA_DST]) >= al) {
        inet_ntop(g_fam, RTA_DATA(tb[RTA_DST]), a, sizeof(a));
        if (rt->rtm_dst_len != fam_full()) PUT("%s/%u", a, rt->rtm_dst_len); else PUT("%s", a);
    } else PUT("%s/%u", g_fam == AF_INET6 ? "::" : "0.0.0.0", rt->rtm_dst_len);
    if (tb[RTA_GATEWAY] && RTA_PAYLOAD(tb[RTA_GATEWAY]) >= al) {
        inet_ntop(g_fam, RTA_DATA(tb[RTA_GATEWAY]), a, sizeof(a));
        PUT(" via %s", a);
    }
    /* Запрет в IPv6 ядро держит на петле (dev lo) — `ip -6 route` печатает его так же, но для
     * разбора и снятия по ключу (table_prune в failover.c) устройство у запрета лишнее: снять
     * `blackhole default dev lo` по такому ключу ядро не всегда соглашается. */
    int v6_reject = g_fam == AF_INET6 && type &&
                    (rt->rtm_type == RTN_BLACKHOLE || rt->rtm_type == RTN_UNREACHABLE ||
                     rt->rtm_type == RTN_PROHIBIT);
    if (tb[RTA_OIF] && !v6_reject) {
        unsigned idx = rta_u32(tb[RTA_OIF]);
        if (if_indextoname(idx, dev)) PUT(" dev %s", dev);
        else PUT(" dev if%u", idx);
    }
    if (rt->rtm_protocol == RTPROT_KERNEL) PUT(" proto kernel");
    if (rt->rtm_scope == RT_SCOPE_LINK) PUT(" scope link");
    else if (rt->rtm_scope == RT_SCOPE_HOST) PUT(" scope host");
    if (tb[RTA_PREFSRC] && RTA_PAYLOAD(tb[RTA_PREFSRC]) >= al) {
        inet_ntop(g_fam, RTA_DATA(tb[RTA_PREFSRC]), a, sizeof(a));
        PUT(" src %s", a);
    }
    if (tb[RTA_PRIORITY]) PUT(" metric %u", rta_u32(tb[RTA_PRIORITY]));
    PUT("\n");
#undef PUT
    tb_line(&c->t, line);
}

static int routes_dump(struct route_ctx *c) {
    uint8_t buf[64];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = (uint8_t)g_fam;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETROUTE,
                                    NLM_F_REQUEST | NLM_F_DUMP, &rt, sizeof(rt));
    return rtnl_talk(buf, msg_end(&b, nh), route_cb, c);
}

int rtnl_routes_text(int table, char *out, size_t n) {
    if (!n) return -1;
    out[0] = '\0';
    struct route_ctx c;
    memset(&c, 0, sizeof(c));
    c.table = (uint32_t)table;
    c.t.p = out;
    c.t.n = n;
    if (routes_dump(&c) != 0) { out[0] = '\0'; return -1; }
    return 0;
}

int rtnl_routes_text6(int table, char *out, size_t n) {
    g_fam = AF_INET6;
    int rc = rtnl_routes_text(table, out, n);
    g_fam = AF_INET;
    return rc;
}

int rtnl_table_flush(int table) {
    static _Alignas(8) uint8_t raw[16384];
    struct route_ctx c;
    memset(&c, 0, sizeof(c));
    c.table = (uint32_t)table;
    c.raw = raw;
    c.raw_cap = sizeof(raw);
    int rc = routes_dump(&c);
    if (rc) return rc;
    for (size_t off = 0; off + NLMSG_HDRLEN <= c.raw_n; ) {
        struct nlmsghdr *h = (struct nlmsghdr *)(raw + off);
        size_t len = h->nlmsg_len;
        if (len < NLMSG_HDRLEN || off + len > c.raw_n) break;
        h->nlmsg_type = RTM_DELROUTE;
        h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        h->nlmsg_seq = ++g_rtnl_seq;
        h->nlmsg_pid = 0;
        rtnl_talk(h, len, NULL, NULL);
        off += NLMSG_ALIGN(len);
    }
    return 0;
}

int rtnl_rule_from(int add, struct in_addr src, int table, int prio) {
    uint8_t buf[128];
    struct nlbuf b;
    struct fib_rule_hdr fr;
    memset(&fr, 0, sizeof(fr));
    fr.family = AF_INET;
    fr.src_len = 32;
    fr.action = FR_ACT_TO_TBL;
    fr.table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), add ? RTM_NEWRULE : RTM_DELRULE,
                                    NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE : 0),
                                    &fr, sizeof(fr));
    nlbuf_put_data(&b, FRA_SRC, &src, 4);
    nlbuf_put_u32(&b, FRA_TABLE, (uint32_t)table);
    nlbuf_put_u32(&b, FRA_PRIORITY, (uint32_t)prio);
    return rtnl_talk(buf, msg_end(&b, nh), NULL, NULL);
}

int rtnl_rule_fwmark(int fam, uint32_t mark, uint32_t mask, int table, int prio) {
    uint8_t buf[128];
    struct nlbuf b;
    struct fib_rule_hdr fr;
    memset(&fr, 0, sizeof(fr));
    fr.family = fam == 6 ? AF_INET6 : AF_INET;
    fr.action = FR_ACT_TO_TBL;
    fr.table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    /* NLM_F_EXCL — как у `ip rule add`: ядро тогда отвечает EEXIST на точную копию, и вторая
     * одинаковая не появляется. Без приоритета ядро выбирает его само — тем же правилом, что и
     * для `ip rule add` без pref. */
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_NEWRULE,
                                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                                    &fr, sizeof(fr));
    nlbuf_put_u32(&b, FRA_FWMARK, mark);
    nlbuf_put_u32(&b, FRA_FWMASK, mask);
    nlbuf_put_u32(&b, FRA_TABLE, (uint32_t)table);
    if (prio > 0) nlbuf_put_u32(&b, FRA_PRIORITY, (uint32_t)prio);
    int rc = rtnl_talk(buf, msg_end(&b, nh), NULL, NULL);
    return rc == EEXIST ? 0 : rc;
}

int rtnl_route_default_dev(int table, int ifindex) {
    uint8_t buf[128];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = AF_INET;
    rt.rtm_table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    rt.rtm_protocol = RTPROT_BOOT;
    rt.rtm_scope = RT_SCOPE_LINK;
    rt.rtm_type = RTN_UNICAST;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_NEWROUTE,
                                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
                                    &rt, sizeof(rt));
    nlbuf_put_u32(&b, RTA_TABLE, (uint32_t)table);
    nlbuf_put_u32(&b, RTA_OIF, (uint32_t)ifindex);
    return rtnl_talk(buf, msg_end(&b, nh), NULL, NULL);
}

int rtnl_route6_backstop(int table, int metric) {
    uint8_t buf[128];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = AF_INET6;
    rt.rtm_table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    rt.rtm_protocol = RTPROT_BOOT;
    rt.rtm_scope = RT_SCOPE_UNIVERSE;
    /* prohibit, а не blackhole: тот же вид, что кладёт table_bind6 (table_bh_type в failover.c —
     * запрет IPv6 отвечает клиенту ICMPv6 сразу, шаг 8 выпуска 1.10). Замена, как у
     * `ip -6 route replace` в backstop_set_fam: стоящий запрет той же метрики она не дублирует и
     * blackhole прежней версии заменяет на месте. Устройства в сообщении нет — ядро само вешает
     * запрет на lo. */
    rt.rtm_type = RTN_PROHIBIT;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_NEWROUTE,
                                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
                                    &rt, sizeof(rt));
    nlbuf_put_u32(&b, RTA_TABLE, (uint32_t)table);
    nlbuf_put_u32(&b, RTA_PRIORITY, (uint32_t)metric);
    return rtnl_talk(buf, msg_end(&b, nh), NULL, NULL);
}

/* ---- вопросы diag ------------------------------------------------------------------------ */

static void default6_cb(const struct nlmsghdr *h, void *ctx) {
    int *found = ctx;
    if (h->nlmsg_type != RTM_NEWROUTE) return;
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || rt->rtm_family != AF_INET6) return;
    if ((rt->rtm_flags & RTM_F_CLONED) || rt->rtm_dst_len != 0) return;
    const struct rtattr *tb[RTA_MAX + 1];
    attrs_parse((const uint8_t *)rt + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, RTA_MAX);
    uint32_t table = tb[RTA_TABLE] ? rta_u32(tb[RTA_TABLE]) : rt->rtm_table;
    if (table == RT_TABLE_MAIN) *found = 1;
}

int rtnl_default6(void) {
    uint8_t buf[64];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = AF_INET6;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETROUTE,
                                    NLM_F_REQUEST | NLM_F_DUMP, &rt, sizeof(rt));
    int found = 0;
    if (rtnl_talk(buf, msg_end(&b, nh), default6_cb, &found) != 0) return -1;
    return found;
}

struct route_dev_ctx { char *dev; size_t n; };

static void route_dev_cb(const struct nlmsghdr *h, void *ctx) {
    struct route_dev_ctx *c = ctx;
    if (h->nlmsg_type != RTM_NEWROUTE) return;
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return;
    const struct rtattr *tb[RTA_MAX + 1];
    attrs_parse((const uint8_t *)rt + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, RTA_MAX);
    char name[IF_NAMESIZE];
    if (tb[RTA_OIF] && if_indextoname(rta_u32(tb[RTA_OIF]), name))
        snprintf(c->dev, c->n, "%s", name);
}

int rtnl_route_dev(struct in_addr dst, char *dev, size_t n) {
    if (!n) return EINVAL;
    dev[0] = '\0';
    uint8_t buf[128];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = AF_INET;
    rt.rtm_dst_len = 32;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETROUTE,
                                    NLM_F_REQUEST | NLM_F_ACK, &rt, sizeof(rt));
    nlbuf_put_data(&b, RTA_DST, &dst, 4);
    struct route_dev_ctx c = { dev, n };
    int rc = rtnl_talk(buf, msg_end(&b, nh), route_dev_cb, &c);
    if (rc == 0 && !dev[0]) rc = ENOENT;
    return rc;
}

/* ---- маршруты main IPv6 для префикса донора (rtnl.h) ---------------------------------------- */

struct main6_ctx { struct rtnl_route6 *v; size_t n, max; };

static void main6_cb(const struct nlmsghdr *h, void *ctx) {
    struct main6_ctx *c = ctx;
    if (h->nlmsg_type != RTM_NEWROUTE) return;
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || rt->rtm_family != AF_INET6) return;
    if (rt->rtm_flags & RTM_F_CLONED) return;
    const struct rtattr *tb[RTA_MAX + 1];
    attrs_parse((const uint8_t *)rt + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, RTA_MAX);
    uint32_t table = tb[RTA_TABLE] ? rta_u32(tb[RTA_TABLE]) : rt->rtm_table;
    if (table != RT_TABLE_MAIN) return;
    int nullroute = rt->rtm_type == RTN_UNREACHABLE && rt->rtm_dst_len > 0;
    int srcdef = rt->rtm_dst_len == 0 && rt->rtm_src_len > 0;
    if ((!nullroute && !srcdef) || c->n >= c->max) return;
    struct rtnl_route6 *r = &c->v[c->n];
    memset(r, 0, sizeof(*r));
    r->type = rt->rtm_type;
    r->dst_len = rt->rtm_dst_len;
    r->src_len = rt->rtm_src_len;
    if (tb[RTA_DST] && RTA_PAYLOAD(tb[RTA_DST]) >= 16) memcpy(r->dst, RTA_DATA(tb[RTA_DST]), 16);
    if (tb[RTA_SRC] && RTA_PAYLOAD(tb[RTA_SRC]) >= 16) memcpy(r->src, RTA_DATA(tb[RTA_SRC]), 16);
    r->oif = tb[RTA_OIF] ? (int)rta_u32(tb[RTA_OIF]) : 0;
    c->n++;
}

int rtnl_main6_routes(struct rtnl_route6 *v, size_t max) {
    uint8_t buf[64];
    struct nlbuf b;
    struct rtmsg rt;
    memset(&rt, 0, sizeof(rt));
    rt.rtm_family = AF_INET6;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETROUTE,
                                    NLM_F_REQUEST | NLM_F_DUMP, &rt, sizeof(rt));
    struct main6_ctx c = { v, 0, max };
    if (rtnl_talk(buf, msg_end(&b, nh), main6_cb, &c) != 0) return -1;
    return (int)c.n;
}

/* ---- адреса IPv6 с признаками (rtnl.h) ------------------------------------------------------ */

struct addr6_ctx { struct rtnl_addr6 *v; size_t n, max; };

static void addr6_cb(const struct nlmsghdr *h, void *ctx) {
    struct addr6_ctx *c = ctx;
    if (h->nlmsg_type != RTM_NEWADDR || c->n >= c->max) return;
    const struct ifaddrmsg *ia = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*ia));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || ia->ifa_family != AF_INET6) return;
    const struct rtattr *tb[IFA_MAX + 1];
    attrs_parse((const uint8_t *)ia + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, IFA_MAX);
    /* У IPv6 IFA_ADDRESS — сам адрес (IFA_LOCAL у него бывает только у точка-точка). */
    const struct rtattr *a = tb[IFA_LOCAL] ? tb[IFA_LOCAL] : tb[IFA_ADDRESS];
    if (!a || RTA_PAYLOAD(a) < 16) return;
    struct rtnl_addr6 *r = &c->v[c->n];
    memset(r, 0, sizeof(*r));
    memcpy(r->a, RTA_DATA(a), 16);
    r->plen = ia->ifa_prefixlen;
    r->ifindex = (int)ia->ifa_index;
    /* Флаги — 32-битным IFA_FLAGS (с 3.14), иначе байтом заголовка: DEPRECATED в обоих. Срок
     * предпочтения 0 — тот же «устаревший»: ядро ставит флаг по нему, но на миг их расхождения
     * смотрим и на срок. */
    r->flags = tb[IFA_FLAGS] && RTA_PAYLOAD(tb[IFA_FLAGS]) >= 4 ? rta_u32(tb[IFA_FLAGS])
                                                                : ia->ifa_flags;
    if (tb[IFA_CACHEINFO] && RTA_PAYLOAD(tb[IFA_CACHEINFO]) >= sizeof(struct ifa_cacheinfo)) {
        struct ifa_cacheinfo ci;
        memcpy(&ci, RTA_DATA(tb[IFA_CACHEINFO]), sizeof(ci));
        if (ci.ifa_prefered == 0) r->flags |= IFA_F_DEPRECATED;
    }
    c->n++;
}

int rtnl_addrs6(struct rtnl_addr6 *v, size_t max) {
    uint8_t buf[64];
    struct nlbuf b;
    struct ifaddrmsg ia;
    memset(&ia, 0, sizeof(ia));
    ia.ifa_family = AF_INET6;
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof(buf), RTM_GETADDR,
                                    NLM_F_REQUEST | NLM_F_DUMP, &ia, sizeof(ia));
    struct addr6_ctx c = { v, 0, max };
    if (rtnl_talk(buf, msg_end(&b, nh), addr6_cb, &c) != 0) return -1;
    return (int)c.n;
}
