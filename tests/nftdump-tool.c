/* Инструмент стенда tests/nftdumpmatch.sh: дампы nftables по netlink (src/lib/nftdump.c).
 *   rules TABLE CHAIN        — сколько правил цепочки отдал nfd_chain_rules;
 *   chain TABLE CHAIN        — nfd_chain_exists (1/0);
 *   sets TABLE               — имена наборов таблицы, по одному в строке;
 *   elems TABLE SET          — «число_элементов длина_ключа» первого элемента;
 *   fp TABLE                 — отпечаток таблицы (nfd_table_fp) шестнадцатеричным числом;
 *   fpunit                   — свёртка набора не зависит от атрибутов, которых ядро steer не задаёт:
 *                              сообщения NEWSET, различающиеся числом элементов (NFTA_SET_COUNT, 20),
 *                              устройством набора (NFTA_SET_TYPE, 19) и неизвестным атрибутом 21, —
 *                              одна свёртка; другое имя или флаги — другая. Печатает «ok» или что не так. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "nftdump.h"

/* Сообщение NEWSET таблицы inet «t»: имя, флаги и, если count >= 0, число элементов (атрибут 20),
 * если type — устройство набора (19), если extra — атрибут 21, которого сегодня нет. */
static size_t mk_set(uint8_t *buf, const char *name, uint32_t flags, long count, const char *type, int extra) {
    memset(buf, 0, 512);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    h->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;
    struct nfgenmsg *g = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
    g->nfgen_family = NFD_INET;
    size_t off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*g));
#define PUT(ty, p, n) do { struct nlattr *a = (struct nlattr *)(buf + off); a->nla_type = (ty); \
        a->nla_len = (uint16_t)(NLA_HDRLEN + (n)); memcpy(buf + off + NLA_HDRLEN, (p), (n)); \
        off += NLA_ALIGN(a->nla_len); } while (0)
    uint32_t be;
    PUT(1, "t", 2);
    PUT(2, name, strlen(name) + 1);
    be = htonl(flags); PUT(3, &be, 4);
    be = htonl(4); PUT(5, &be, 4);
    if (type) PUT(19, type, strlen(type) + 1);
    if (count >= 0) { be = htonl((uint32_t)count); PUT(20, &be, 4); }
    if (extra) { be = htonl((uint32_t)extra); PUT(21, &be, 4); }
#undef PUT
    h->nlmsg_len = (uint32_t)off;
    return off;
}

static uint64_t set_fp(const char *name, uint32_t flags, long count, const char *type, int extra) {
    _Alignas(8) uint8_t buf[512];
    uint64_t fp = 0;
    size_t n = mk_set(buf, name, flags, count, type, extra);
    if (!nfd_fp_msg(buf, n, "t", &fp)) return 0;
    return fp;
}

static int fpunit(void) {
    uint64_t base = set_fp("s", 4, -1, NULL, 0);
    int bad = 0;
#define SAME(what, v) do { if (!base || (v) != base) { printf("%s: свёртка изменилась\n", what); bad = 1; } } while (0)
#define DIFF(what, v) do { if ((v) == base) { printf("%s: свёртка не изменилась\n", what); bad = 1; } } while (0)
    SAME("число элементов 0 (атрибут 20)", set_fp("s", 4, 0, NULL, 0));
    SAME("число элементов 7 (атрибут 20)", set_fp("s", 4, 7, NULL, 0));
    SAME("устройство набора (атрибут 19)", set_fp("s", 4, -1, "rbtree", 0));
    SAME("неизвестный атрибут 21", set_fp("s", 4, 3, "hash", 1));
    SAME("неизвестный атрибут 21, другое значение", set_fp("s", 4, 3, "hash", 2));
    DIFF("другое имя набора", set_fp("s2", 4, -1, NULL, 0));
    DIFF("другие флаги набора", set_fp("s", 5, -1, NULL, 0));
#undef SAME
#undef DIFF
    if (!bad) printf("ok\n");
    return bad;
}

static void rule_cb(void *arg, const char *comment, int has_counter, uint64_t p, uint64_t b) {
    (void)comment; (void)has_counter; (void)p; (void)b;
    (*(int *)arg)++;
}

static void set_cb(void *arg, const struct nfd_set *s) {
    (void)arg;
    printf("%s\n", s->name);
}

struct el { int n; size_t klen; };

static void elem_cb(void *arg, const struct nfd_elem *e) {
    struct el *x = arg;
    if (!x->n++) x->klen = e->klen;
}

int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "rules")) {
        int n = 0;
        const char *ch[1] = { argv[3] };
        int rc = nfd_chain_rules(NFD_INET, argv[2], ch, 1, rule_cb, &n);
        printf("%d\n", rc ? -1 : n);
    } else if (argc >= 4 && !strcmp(argv[1], "chain")) {
        printf("%d\n", nfd_chain_exists(NFD_INET, argv[2], argv[3]));
    } else if (argc >= 3 && !strcmp(argv[1], "sets")) {
        return nfd_sets(argv[2], set_cb, NULL) != 0;
    } else if (argc >= 4 && !strcmp(argv[1], "elems")) {
        struct el x = { 0, 0 };
        int rc = nfd_set_elems(NFD_INET, argv[2], argv[3], elem_cb, NULL, &x, NULL);
        printf("%d %zu\n", rc ? -1 : x.n, x.klen);
    } else if (argc >= 3 && !strcmp(argv[1], "fp")) {
        struct nfd_tfp t;
        if (nfd_table_fp(argv[2], &t) != 0) { printf("-\n"); return 1; }
        printf("%016llx\n", (unsigned long long)t.fp);
    } else if (argc >= 2 && !strcmp(argv[1], "fpunit")) {
        return fpunit();
    } else {
        fprintf(stderr, "nftdump-tool: rules|chain|sets|elems|fp|fpunit\n");
        return 2;
    }
    return 0;
}
