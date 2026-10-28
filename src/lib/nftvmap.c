/* nf_tables по netlink — карта вердиктов группы balance. Устройство и доводы — в nftvmap.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "nlbuf.h"
#include "nftvmap.h"

/* Буфер батча и приёма. Элемент на запись — около 80 байт (ключ, вердикт, имя цепочки), батч
 * из двух сообщений на 240 элементов — около 20 КБ; вложенный атрибут ограничен 64 КБ длины,
 * и сообщение больше этого не выражается вовсе — предел slots проверяется ниже. */
#define NFV_BUF 131072
#define NFV_SLOTS_MAX 512

static uint32_t g_nfv_seq;

static int nfv_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    /* Ядро отвечает внутри вызова; срок — только от вечного recv. */
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Заголовок nlmsghdr + nfgenmsg в b; возвращает nlmsghdr (длину ставит nfv_msg_end). */
static struct nlmsghdr *nfv_msg_begin(struct nlbuf *b, uint16_t type, uint16_t flags,
                                      uint8_t family, uint16_t res_id) {
    size_t need = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if ((size_t)(b->end - b->p) < need) { b->overflow = 1; return NULL; }
    struct nlmsghdr *nh = (struct nlmsghdr *)b->p;
    memset(nh, 0, need);
    nh->nlmsg_type = type;
    nh->nlmsg_flags = flags;
    nh->nlmsg_seq = ++g_nfv_seq;
    b->p += NLMSG_HDRLEN;
    struct nfgenmsg *g = (struct nfgenmsg *)b->p;
    g->nfgen_family = family;
    g->version = NFNETLINK_V0;
    g->res_id = htons(res_id);
    b->p += NLMSG_ALIGN(sizeof(*g));
    return nh;
}

static void nfv_msg_end(struct nlbuf *b, struct nlmsghdr *nh) {
    if (nh) nh->nlmsg_len = (uint32_t)(b->p - (uint8_t *)nh);
}

static int nfv_send(int fd, const void *p, size_t n) {
    struct sockaddr_nl to;
    memset(&to, 0, sizeof(to));
    to.nl_family = AF_NETLINK;
    ssize_t w = sendto(fd, p, n, 0, (struct sockaddr *)&to, sizeof(to));
    if (w < 0) return -1;
    if ((size_t)w != n) { errno = EMSGSIZE; return -1; }
    return 0;
}

/* ---- атрибуты ответа ---------------------------------------------------------------------- */

static void nfv_parse(const void *p, size_t len, const struct nlattr **tb, int max) {
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

struct nfv_rd {
    char (*chain)[NFV_CHAIN_MAX];
    size_t slots;
    int n;
};

/* Один элемент списка: ключ (номер, порядок хоста) и вердикт goto/jump <цепочка>. */
static void nfv_elem(const struct nlattr *el, struct nfv_rd *rd) {
    const struct nlattr *te[NFTA_SET_ELEM_MAX + 1];
    nfv_parse(nla_ptr(el), nla_size(el), te, NFTA_SET_ELEM_MAX);
    if (!te[NFTA_SET_ELEM_KEY]) return;
    const struct nlattr *tk[NFTA_DATA_MAX + 1];
    nfv_parse(nla_ptr(te[NFTA_SET_ELEM_KEY]), nla_size(te[NFTA_SET_ELEM_KEY]), tk, NFTA_DATA_MAX);
    if (!tk[NFTA_DATA_VALUE] || nla_size(tk[NFTA_DATA_VALUE]) != 4) return;
    uint32_t key;
    memcpy(&key, nla_ptr(tk[NFTA_DATA_VALUE]), 4);
    char name[NFV_CHAIN_MAX] = "";
    if (te[NFTA_SET_ELEM_DATA]) {
        const struct nlattr *td[NFTA_DATA_MAX + 1];
        nfv_parse(nla_ptr(te[NFTA_SET_ELEM_DATA]), nla_size(te[NFTA_SET_ELEM_DATA]), td,
                  NFTA_DATA_MAX);
        if (td[NFTA_DATA_VERDICT]) {
            const struct nlattr *tv[NFTA_VERDICT_MAX + 1];
            nfv_parse(nla_ptr(td[NFTA_DATA_VERDICT]), nla_size(td[NFTA_DATA_VERDICT]), tv,
                      NFTA_VERDICT_MAX);
            if (tv[NFTA_VERDICT_CHAIN]) {
                size_t l = nla_size(tv[NFTA_VERDICT_CHAIN]);
                if (l >= sizeof(name)) l = sizeof(name) - 1;
                memcpy(name, nla_ptr(tv[NFTA_VERDICT_CHAIN]), l);
                name[l] = '\0';
            }
        }
    }
    /* Элемент без цепочки (accept, drop) — в нашей карте его не бывает; считается, но в chain
     * не пишется ничего, кроме пустоты: сверка увидит расхождение и перепишет его. */
    rd->n++;
    if (key < rd->slots && name[0]) snprintf(rd->chain[key], NFV_CHAIN_MAX, "%s", name);
}

static void nfv_rd_msg(const struct nlmsghdr *h, struct nfv_rd *rd) {
    size_t off = NLMSG_ALIGN(sizeof(struct nfgenmsg));
    if (h->nlmsg_len < NLMSG_HDRLEN + off) return;
    const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1];
    nfv_parse((const uint8_t *)NLMSG_DATA(h) + off, h->nlmsg_len - NLMSG_HDRLEN - off, tb,
              NFTA_SET_ELEM_LIST_MAX);
    const struct nlattr *l = tb[NFTA_SET_ELEM_LIST_ELEMENTS];
    if (!l) return;
    const uint8_t *q = nla_ptr(l);
    size_t len = nla_size(l);
    while (len >= NLA_HDRLEN) {
        const struct nlattr *a = (const struct nlattr *)q;
        if (a->nla_len < NLA_HDRLEN || a->nla_len > len) break;
        if ((a->nla_type & NLA_TYPE_MASK) == NFTA_LIST_ELEM) nfv_elem(a, rd);
        size_t al = NLA_ALIGN(a->nla_len);
        if (al >= len) break;
        q += al;
        len -= al;
    }
}

int nfv_map_read(uint8_t family, const char *table, const char *map, char (*chain)[NFV_CHAIN_MAX],
                 size_t slots) {
    for (size_t i = 0; i < slots; i++) chain[i][0] = '\0';
    int fd = nfv_open();
    if (fd < 0) return -1;
    uint8_t req[512];
    struct nlbuf b;
    nlbuf_init(&b, req, sizeof(req));
    struct nlmsghdr *nh = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM,
                                        NLM_F_REQUEST | NLM_F_DUMP, family, 0);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, map);
    if (!nh || b.overflow) { close(fd); errno = EMSGSIZE; return -1; }
    nfv_msg_end(&b, nh);
    if (nfv_send(fd, req, nh->nlmsg_len) != 0) { int e = errno; close(fd); errno = e; return -1; }

    uint8_t *rbuf = malloc(NFV_BUF);
    if (!rbuf) { close(fd); errno = ENOMEM; return -1; }
    struct nfv_rd rd = { chain, slots, 0 };
    int rc = EIO, intr = 0;
    for (int done = 0; !done; ) {
        ssize_t n = recv(fd, rbuf, NFV_BUF, 0);
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
            nfv_rd_msg(h, &rd);
        }
    }
    free(rbuf);
    close(fd);
    /* Набор правил сменился посреди дампа (apply) — ответ может быть не из одного мгновения;
     * вызывающий (сторож) сверит на следующем проходе. */
    if (rc == 0 && intr) rc = EINTR;
    if (rc) {
        for (size_t i = 0; i < slots; i++) chain[i][0] = '\0';
        errno = rc;
        return -1;
    }
    return rd.n;
}

/* ---- запись ------------------------------------------------------------------------------ */

/* Элемент в список: ключ i, для add — ещё и вердикт goto chain. */
static void nfv_put_elem(struct nlbuf *b, uint32_t key, const char *chain) {
    struct nlattr *el = nlbuf_begin_nested(b, NFTA_LIST_ELEM);
    struct nlattr *k = nlbuf_begin_nested(b, NFTA_SET_ELEM_KEY);
    nlbuf_put_data(b, NFTA_DATA_VALUE, &key, 4);          /* тип mark — порядок хоста */
    nlbuf_end_nested(b, k);
    if (chain) {
        struct nlattr *d = nlbuf_begin_nested(b, NFTA_SET_ELEM_DATA);
        struct nlattr *v = nlbuf_begin_nested(b, NFTA_DATA_VERDICT);
        nlbuf_put_be32(b, NFTA_VERDICT_CODE, (uint32_t)NFT_GOTO);
        nlbuf_put_str(b, NFTA_VERDICT_CHAIN, chain);
        nlbuf_end_nested(b, v);
        nlbuf_end_nested(b, d);
    }
    nlbuf_end_nested(b, el);
}

/* Сообщение DELSETELEM (add = 0) или NEWSETELEM (add = 1) со всеми элементами, которые меняются.
 * Возврат — nlmsghdr или NULL, если менять в эту сторону нечего. */
static struct nlmsghdr *nfv_elems_msg(struct nlbuf *b, int add, uint8_t family, const char *table,
                                      const char *map, const char (*want)[NFV_CHAIN_MAX],
                                      const char (*have)[NFV_CHAIN_MAX], size_t slots) {
    size_t cnt = 0;
    for (size_t i = 0; i < slots; i++) {
        const char *h = have ? have[i] : "", *w = want ? want[i] : "";
        if (!strcmp(h, w)) continue;
        if (add ? w[0] != '\0' : h[0] != '\0') cnt++;
    }
    if (!cnt) return NULL;
    uint16_t type = (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) |
                               (add ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM));
    uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE : 0);
    struct nlmsghdr *nh = nfv_msg_begin(b, type, flags, family, 0);
    nlbuf_put_str(b, NFTA_SET_ELEM_LIST_TABLE, table);
    nlbuf_put_str(b, NFTA_SET_ELEM_LIST_SET, map);
    struct nlattr *l = nlbuf_begin_nested(b, NFTA_SET_ELEM_LIST_ELEMENTS);
    for (size_t i = 0; i < slots; i++) {
        const char *h = have ? have[i] : "", *w = want ? want[i] : "";
        if (!strcmp(h, w)) continue;
        if (add && w[0]) nfv_put_elem(b, (uint32_t)i, w);
        if (!add && h[0]) nfv_put_elem(b, (uint32_t)i, NULL);
    }
    nlbuf_end_nested(b, l);
    nfv_msg_end(b, nh);
    return nh;
}

int nfv_map_write(uint8_t family, const char *table, const char *map,
                  const char (*want)[NFV_CHAIN_MAX], const char (*have)[NFV_CHAIN_MAX],
                  size_t slots) {
    if (slots > NFV_SLOTS_MAX) { errno = E2BIG; return -1; }
    uint8_t *buf = malloc(NFV_BUF);
    if (!buf) { errno = ENOMEM; return -1; }
    struct nlbuf b;
    nlbuf_init(&b, buf, NFV_BUF);
    struct nlmsghdr *bb = nfv_msg_begin(&b, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, bb);
    /* Сначала снять, потом положить: элемент, меняющий цепочку, в одной транзакции уходит и
     * возвращается — ядро не принимает NEWSETELEM поверх существующего ключа с другими данными. */
    struct nlmsghdr *del = nfv_elems_msg(&b, 0, family, table, map, want, have, slots);
    struct nlmsghdr *add = nfv_elems_msg(&b, 1, family, table, map, want, have, slots);
    struct nlmsghdr *be = nfv_msg_begin(&b, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, be);
    if (b.overflow) { free(buf); errno = EMSGSIZE; return -1; }
    if (!del && !add) { free(buf); return 0; }   /* уже как надо */

    int fd = nfv_open();
    if (fd < 0) { int e = errno; free(buf); errno = e; return -1; }
    if (nfv_send(fd, buf, (size_t)(b.p - b.base)) != 0) {
        int e = errno; close(fd); free(buf); errno = e; return -1;
    }
    /* Подтверждение ждём на каждое сообщение с элементами. При отказе ядро откатывает батч
     * целиком и присылает ошибку отказавшего; подтверждения остальных могут прийти, а могут и
     * нет — первой ошибки достаточно. */
    uint32_t seq_del = del ? del->nlmsg_seq : 0, seq_add = add ? add->nlmsg_seq : 0;
    int need = (del != NULL) + (add != NULL), got = 0, err = 0;
    while (got < need && !err) {
        ssize_t n = recv(fd, buf, NFV_BUF, 0);
        if (n < 0) { if (errno == EINTR) continue; err = errno; break; }
        if (n == 0) { err = EIO; break; }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type != NLMSG_ERROR) continue;
            if (h->nlmsg_seq != seq_del && h->nlmsg_seq != seq_add) {
                /* Ошибка на сам батч (BEGIN/END, например нет подсистемы) — тоже отказ. */
                const struct nlmsgerr *e = NLMSG_DATA(h);
                if (e->error) { err = -e->error; break; }
                continue;
            }
            const struct nlmsgerr *e = NLMSG_DATA(h);
            if (e->error) { err = -e->error; break; }
            got++;
        }
    }
    close(fd);
    free(buf);
    if (err) { errno = err; return -1; }
    return 0;
}

/* ---- интервальный набор ipv6_addr: префикс хоста у донора (nftvmap.h) ------------------------ */

struct nfv_r6 {
    uint8_t st[NFV_RANGES6_MAX][16], en[NFV_RANGES6_MAX][16];
    size_t sn, en_n;
    int over;
};

static void nfv_r6_elem(const struct nlattr *el, struct nfv_r6 *rd) {
    const struct nlattr *te[NFTA_SET_ELEM_MAX + 1];
    nfv_parse(nla_ptr(el), nla_size(el), te, NFTA_SET_ELEM_MAX);
    if (!te[NFTA_SET_ELEM_KEY]) return;
    const struct nlattr *tk[NFTA_DATA_MAX + 1];
    nfv_parse(nla_ptr(te[NFTA_SET_ELEM_KEY]), nla_size(te[NFTA_SET_ELEM_KEY]), tk, NFTA_DATA_MAX);
    if (!tk[NFTA_DATA_VALUE] || nla_size(tk[NFTA_DATA_VALUE]) != 16) return;
    uint32_t fl = 0;
    if (te[NFTA_SET_ELEM_FLAGS] && nla_size(te[NFTA_SET_ELEM_FLAGS]) >= 4) {
        memcpy(&fl, nla_ptr(te[NFTA_SET_ELEM_FLAGS]), 4);
        fl = ntohl(fl);
    }
    int end = (fl & NFT_SET_ELEM_INTERVAL_END) != 0;
    size_t *n = end ? &rd->en_n : &rd->sn;
    if (*n >= NFV_RANGES6_MAX) { rd->over = 1; return; }
    memcpy(end ? rd->en[*n] : rd->st[*n], nla_ptr(tk[NFTA_DATA_VALUE]), 16);
    (*n)++;
}

static int k16_cmp(const void *a, const void *b) { return memcmp(a, b, 16); }

int nfv_ranges6_read(uint8_t family, const char *table, const char *set, struct nfv_range6 *v,
                     size_t max) {
    int fd = nfv_open();
    if (fd < 0) return -1;
    uint8_t req[512];
    struct nlbuf b;
    nlbuf_init(&b, req, sizeof(req));
    struct nlmsghdr *nh = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM,
                                        NLM_F_REQUEST | NLM_F_DUMP, family, 0);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, set);
    if (!nh || b.overflow) { close(fd); errno = EMSGSIZE; return -1; }
    nfv_msg_end(&b, nh);
    if (nfv_send(fd, req, nh->nlmsg_len) != 0) { int e = errno; close(fd); errno = e; return -1; }
    uint8_t *rbuf = malloc(NFV_BUF);
    static struct nfv_r6 rd;
    memset(&rd, 0, sizeof(rd));
    if (!rbuf) { close(fd); errno = ENOMEM; return -1; }
    int rc = EIO, intr = 0;
    for (int done = 0; !done; ) {
        ssize_t n = recv(fd, rbuf, NFV_BUF, 0);
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
            size_t off = NLMSG_ALIGN(sizeof(struct nfgenmsg));
            if (h->nlmsg_len < NLMSG_HDRLEN + off) continue;
            const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1];
            nfv_parse((const uint8_t *)NLMSG_DATA(h) + off, h->nlmsg_len - NLMSG_HDRLEN - off, tb,
                      NFTA_SET_ELEM_LIST_MAX);
            const struct nlattr *l = tb[NFTA_SET_ELEM_LIST_ELEMENTS];
            if (!l) continue;
            const uint8_t *q = nla_ptr(l);
            size_t len = nla_size(l);
            while (len >= NLA_HDRLEN) {
                const struct nlattr *a = (const struct nlattr *)q;
                if (a->nla_len < NLA_HDRLEN || a->nla_len > len) break;
                if ((a->nla_type & NLA_TYPE_MASK) == NFTA_LIST_ELEM) nfv_r6_elem(a, &rd);
                size_t al = NLA_ALIGN(a->nla_len);
                if (al >= len) break;
                q += al;
                len -= al;
            }
        }
    }
    free(rbuf);
    close(fd);
    if (rc == 0 && intr) rc = EINTR;
    if (rc == 0 && (rd.over || rd.sn != rd.en_n)) rc = ERANGE;
    if (rc) { errno = rc; return -1; }
    /* Ядро отдаёт элементы в порядке своего дерева; отрезок — начало и ближайший за ним маркер
     * конца, поэтому обе половины сортируются и идут парами (отрезки набора не пересекаются). */
    qsort(rd.st, rd.sn, 16, k16_cmp);
    qsort(rd.en, rd.en_n, 16, k16_cmp);
    size_t n = rd.sn < max ? rd.sn : max;
    for (size_t i = 0; i < n; i++) {
        memcpy(v[i].lo, rd.st[i], 16);
        memcpy(v[i].hi, rd.en[i], 16);
    }
    return (int)rd.sn;
}

/* Элемент отрезка в список: начало (флагов нет) или маркер конца (NFT_SET_ELEM_INTERVAL_END). */
static void nfv_put_key16(struct nlbuf *b, const uint8_t k[16], int end) {
    struct nlattr *el = nlbuf_begin_nested(b, NFTA_LIST_ELEM);
    struct nlattr *kk = nlbuf_begin_nested(b, NFTA_SET_ELEM_KEY);
    nlbuf_put_data(b, NFTA_DATA_VALUE, k, 16);
    nlbuf_end_nested(b, kk);
    if (end) nlbuf_put_be32(b, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
    nlbuf_end_nested(b, el);
}

/* Элемент набора без отрезков: только ключ. */
static void nfv_put_key(struct nlbuf *b, const uint8_t *k, size_t n) {
    struct nlattr *el = nlbuf_begin_nested(b, NFTA_LIST_ELEM);
    struct nlattr *kk = nlbuf_begin_nested(b, NFTA_SET_ELEM_KEY);
    nlbuf_put_data(b, NFTA_DATA_VALUE, k, n);
    nlbuf_end_nested(b, kk);
    nlbuf_end_nested(b, el);
}

/* Транзакция «набор целиком»: сброс (DELSETELEM без списка) и элементы ключами по klen байт. */
static int nfv_set_replace(uint8_t family, const char *table, const char *set,
                           const uint8_t *keys, size_t klen, size_t n) {
    size_t cap = 512 + n * (klen + 32);
    uint8_t *buf = malloc(cap < NFV_BUF ? NFV_BUF : cap);
    if (!buf) { errno = ENOMEM; return -1; }
    if (cap < NFV_BUF) cap = NFV_BUF;
    struct nlbuf b;
    nlbuf_init(&b, buf, cap);
    struct nlmsghdr *bb = nfv_msg_begin(&b, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, bb);
    struct nlmsghdr *del = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM,
                                         NLM_F_REQUEST | NLM_F_ACK, family, 0);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, set);
    nfv_msg_end(&b, del);
    struct nlmsghdr *add = NULL;
    if (n) {
        add = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM,
                            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, family, 0);
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, set);
        struct nlattr *l = nlbuf_begin_nested(&b, NFTA_SET_ELEM_LIST_ELEMENTS);
        for (size_t i = 0; i < n; i++) nfv_put_key(&b, keys + i * klen, klen);
        nlbuf_end_nested(&b, l);
        nfv_msg_end(&b, add);
    }
    struct nlmsghdr *be = nfv_msg_begin(&b, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, be);
    if (b.overflow || !del) { free(buf); errno = EMSGSIZE; return -1; }
    int fd = nfv_open();
    if (fd < 0) { int e = errno; free(buf); errno = e; return -1; }
    if (nfv_send(fd, buf, (size_t)(b.p - b.base)) != 0) {
        int e = errno; close(fd); free(buf); errno = e; return -1;
    }
    uint32_t seq_del = del->nlmsg_seq, seq_add = add ? add->nlmsg_seq : 0;
    int need = 1 + (add != NULL), got = 0, err = 0;
    while (got < need && !err) {
        ssize_t r = recv(fd, buf, cap, 0);
        if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
        if (r == 0) { err = EIO; break; }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)r);
             h = NLMSG_NEXT(h, r)) {
            if (h->nlmsg_type != NLMSG_ERROR) continue;
            const struct nlmsgerr *e = NLMSG_DATA(h);
            if (e->error) { err = -e->error; break; }
            if (h->nlmsg_seq == seq_del || h->nlmsg_seq == seq_add) got++;
        }
    }
    close(fd);
    free(buf);
    if (err) { errno = err; return -1; }
    return 0;
}

int nfv_ifnames_write(uint8_t family, const char *table, const char *set, const char *const *names, size_t n) {
    uint8_t *keys = calloc(n ? n : 1, IFNAMSIZ);
    if (!keys) { errno = ENOMEM; return -1; }
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(names[i]);
        if (l >= IFNAMSIZ) { free(keys); errno = ENAMETOOLONG; return -1; }
        memcpy(keys + i * IFNAMSIZ, names[i], l);
    }
    int rc = nfv_set_replace(family, table, set, keys, IFNAMSIZ, n);
    int e = errno;
    free(keys);
    errno = e;
    return rc;
}

int nfv_ranges6_write(uint8_t family, const char *table, const char *set,
                      const struct nfv_range6 *want, size_t n) {
    if (n > NFV_RANGES6_MAX) { errno = E2BIG; return -1; }
    uint8_t *buf = malloc(NFV_BUF);
    if (!buf) { errno = ENOMEM; return -1; }
    struct nlbuf b;
    nlbuf_init(&b, buf, NFV_BUF);
    struct nlmsghdr *bb = nfv_msg_begin(&b, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, bb);
    /* Сброс набора — DELSETELEM без списка элементов (так nft делает `flush set`), затем новые
     * отрезки; в одной транзакции пакет видит либо прежний набор, либо новый. */
    struct nlmsghdr *del = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM,
                                         NLM_F_REQUEST | NLM_F_ACK, family, 0);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, set);
    nfv_msg_end(&b, del);
    struct nlmsghdr *add = NULL;
    if (n) {
        add = nfv_msg_begin(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM,
                            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, family, 0);
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, table);
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, set);
        struct nlattr *l = nlbuf_begin_nested(&b, NFTA_SET_ELEM_LIST_ELEMENTS);
        for (size_t i = 0; i < n; i++) {
            nfv_put_key16(&b, want[i].lo, 0);
            nfv_put_key16(&b, want[i].hi, 1);
        }
        nlbuf_end_nested(&b, l);
        nfv_msg_end(&b, add);
    }
    struct nlmsghdr *be = nfv_msg_begin(&b, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC,
                                        NFNL_SUBSYS_NFTABLES);
    nfv_msg_end(&b, be);
    if (b.overflow || !del) { free(buf); errno = EMSGSIZE; return -1; }
    int fd = nfv_open();
    if (fd < 0) { int e = errno; free(buf); errno = e; return -1; }
    if (nfv_send(fd, buf, (size_t)(b.p - b.base)) != 0) {
        int e = errno; close(fd); free(buf); errno = e; return -1;
    }
    uint32_t seq_del = del->nlmsg_seq, seq_add = add ? add->nlmsg_seq : 0;
    int need = 1 + (add != NULL), got = 0, err = 0;
    while (got < need && !err) {
        ssize_t r = recv(fd, buf, NFV_BUF, 0);
        if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
        if (r == 0) { err = EIO; break; }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)r);
             h = NLMSG_NEXT(h, r)) {
            if (h->nlmsg_type != NLMSG_ERROR) continue;
            const struct nlmsgerr *e = NLMSG_DATA(h);
            if (e->error) { err = -e->error; break; }
            if (h->nlmsg_seq == seq_del || h->nlmsg_seq == seq_add) got++;
        }
    }
    close(fd);
    free(buf);
    if (err) { errno = err; return -1; }
    return 0;
}
