/* Конец дампа netlink глазами читателей ядра steer (src/lib/nftdump.c, nftvmap.c, rtnl.c, ctnl.c)
 * — на подставном ядре, без прав и без сетевого пространства.
 *
 * Ядро обрывает дамп, когда не может отдать очередную часть (ENOBUFS, нехватка памяти, отказ
 * обработчика): последним приходит NLMSG_DONE, и в нём не 0, а -errno. Раньше все четыре читателя
 * принимали любой DONE за «дамп пройден», и сверка решала по обрезанному ответу. Второе — дамп,
 * который ядро пометило NLM_F_DUMP_INTR (таблица менялась посреди него): rtnl.c его не замечал.
 *
 * Подстановка — ключами компоновщика --wrap=sendto и --wrap=recv (Makefile): исходники читателей
 * собираются как есть, сокет netlink у них настоящий (открыть его можно и без прав), а запрос и
 * ответ проходят через __wrap_sendto и __wrap_recv ниже. Ответ строится по сценарию g_mode на
 * номер запроса — тот, что прислал читатель. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "nftdump.h"
#include "nftvmap.h"
#include "rtnl.h"
#include "ctnl.h"

enum mode {
    M_DONE_ERR,      /* одна запись и DONE с -ENOBUFS */
    M_DONE_OK,       /* одна запись и DONE с 0 */
    M_INTR_ONCE,     /* первый дамп: запись с NLM_F_DUMP_INTR, DONE 0; второй: пусто, DONE 0 */
    M_INTR_ALWAYS,   /* каждый дамп помечен NLM_F_DUMP_INTR */
};
static enum mode g_mode;
static int g_reqs;               /* сколько запросов прислано */
static uint32_t g_seq;           /* номер последнего */
static uint16_t g_type;          /* тип последнего запроса */
static int g_pending;            /* ответ на последний ещё не отдан */

ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __real_recv(int, void *, size_t, int);

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to,
                      socklen_t tl) {
    (void)fd; (void)flags; (void)to; (void)tl;
    const struct nlmsghdr *h = buf;
    g_seq = h->nlmsg_seq;
    g_type = h->nlmsg_type;
    g_reqs++;
    g_pending = 1;
    return (ssize_t)len;
}

/* Запись дампа. rtnetlink — маршрут по умолчанию таблицы main через петлю; nfnetlink (подсистема
 * в старшем байте типа запроса) — пустое сообщение той же подсистемы, один заголовок nfgenmsg:
 * читателям nftables и conntrack здесь важен только конец дампа. */
static size_t put_route(uint8_t *p, uint16_t flags) {
    struct nlmsghdr *h = (struct nlmsghdr *)p;
    memset(p, 0, 256);
    h->nlmsg_flags = (uint16_t)(NLM_F_MULTI | flags);
    h->nlmsg_seq = g_seq;
    if (g_type >> 8) {
        h->nlmsg_type = (uint16_t)(g_type & 0xff00);
        h->nlmsg_len = NLMSG_LENGTH(4);                   /* struct nfgenmsg — 4 байта нулей */
        return NLMSG_ALIGN(h->nlmsg_len);
    }
    h->nlmsg_type = RTM_NEWROUTE;
    struct rtmsg *rt = NLMSG_DATA(h);
    rt->rtm_family = AF_INET;
    rt->rtm_table = RT_TABLE_MAIN;
    rt->rtm_type = RTN_UNICAST;
    struct rtattr *a = (struct rtattr *)((uint8_t *)rt + NLMSG_ALIGN(sizeof(*rt)));
    a->rta_type = RTA_OIF;
    a->rta_len = RTA_LENGTH(4);
    uint32_t lo = if_nametoindex("lo");
    memcpy(RTA_DATA(a), &lo, 4);
    h->nlmsg_len = (uint32_t)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rt)) + RTA_ALIGN(a->rta_len));
    return NLMSG_ALIGN(h->nlmsg_len);
}

static size_t put_done(uint8_t *p, int err, uint16_t flags) {
    struct nlmsghdr *h = (struct nlmsghdr *)p;
    memset(p, 0, NLMSG_LENGTH(sizeof(int)));
    h->nlmsg_type = NLMSG_DONE;
    h->nlmsg_flags = (uint16_t)(NLM_F_MULTI | flags);
    h->nlmsg_seq = g_seq;
    h->nlmsg_len = NLMSG_LENGTH(sizeof(int));
    memcpy(NLMSG_DATA(h), &err, sizeof(err));
    return NLMSG_ALIGN(h->nlmsg_len);
}

ssize_t __wrap_recv(int fd, void *buf, size_t cap, int flags) {
    (void)fd; (void)flags;
    if (!g_pending || cap < 512) { errno = EAGAIN; return -1; }
    g_pending = 0;
    uint8_t *p = buf;
    size_t n = 0;
    switch (g_mode) {
    case M_DONE_ERR:
        n += put_route(p + n, 0);
        n += put_done(p + n, -ENOBUFS, 0);
        break;
    case M_DONE_OK:
        n += put_route(p + n, 0);
        n += put_done(p + n, 0, 0);
        break;
    case M_INTR_ONCE:
        if (g_reqs == 1) n += put_route(p + n, NLM_F_DUMP_INTR);
        n += put_done(p + n, 0, g_reqs == 1 ? NLM_F_DUMP_INTR : 0);
        break;
    case M_INTR_ALWAYS:
        n += put_route(p + n, NLM_F_DUMP_INTR);
        n += put_done(p + n, 0, NLM_F_DUMP_INTR);
        break;
    }
    return (ssize_t)n;
}

static int pass, fail;
static void check(const char *what, long want, long got) {
    if (want == got) { pass++; return; }
    fail++;
    printf("FAIL %s\n  expected: %ld\n  actual:   %ld\n", what, want, got);
}

static void rule_fn(void *arg, const char *c, int hc, uint64_t p, uint64_t b) {
    (void)arg; (void)c; (void)hc; (void)p; (void)b;
}
static int ct_fn(const uint8_t *a, const uint8_t *end, uint8_t fam, void *ctx) {
    (void)a; (void)end; (void)fam; (void)ctx;
    return 0;
}
static void dev_fn(const char *dev, void *ctx) {
    (void)dev;
    (*(int *)ctx)++;
}

static void start(enum mode m) { g_mode = m; g_reqs = 0; g_pending = 0; }

int main(void) {
    const char *chains[] = { "c" };
    char map[4][NFV_CHAIN_MAX];
    static uint8_t ctbuf[CTNL_RCVBUF];
    uint32_t seq = 0;
    int devs;

    /* ---- оборванный дамп (DONE с -ENOBUFS) — ошибка, а не «прочитано» ---- */
    start(M_DONE_ERR);
    check("nftdump: правила цепочек — оборванный дамп даёт ошибку", ENOBUFS,
          nfd_chain_rules(NFD_INET, "t", chains, 1, rule_fn, NULL));
    start(M_DONE_ERR);
    check("nftdump: число элементов набора — оборванный дамп даёт -1", -1, nfd_set_count(NFD_INET, "t", "s"));
    start(M_DONE_ERR);
    check("nftvmap: карта — оборванный дамп даёт -1", -1, nfv_map_read(NFD_INET, "t", "m", map, 4));
    start(M_DONE_ERR);
    check("rtnl: маршрут по умолчанию таблицы — оборванный дамп даёт -1", -1, rtnl_table_has_default(RT_TABLE_MAIN));
    start(M_DONE_ERR);
    devs = 0;
    check("rtnl: устройства WAN — оборванный дамп даёт -1", -1, rtnl_default_devs(dev_fn, &devs));
    check("  и ни одного устройства вызывающему", 0, devs);
    start(M_DONE_ERR);
    check("ctnl: дамп conntrack — оборванный даёт -1", -1,
          ctnl_dump(-1, AF_INET, 0, 0, 0, &seq, ctbuf, ct_fn, NULL));

    /* ---- полный дамп — по-прежнему успех ---- */
    start(M_DONE_OK);
    check("nftdump: полный дамп — 0", 0, nfd_chain_rules(NFD_INET, "t", chains, 1, rule_fn, NULL));
    start(M_DONE_OK);
    check("rtnl: полный дамп — маршрут по умолчанию есть", 1, rtnl_table_has_default(RT_TABLE_MAIN));
    start(M_DONE_OK);
    devs = 0;
    check("rtnl: полный дамп — устройства WAN отданы", 0, rtnl_default_devs(dev_fn, &devs));
    check("  одно (lo)", 1, devs);
    start(M_DONE_OK);
    check("ctnl: полный дамп — 0", 0, ctnl_dump(-1, AF_INET, 0, 0, 0, &seq, ctbuf, ct_fn, NULL));

    /* ---- таблица менялась посреди дампа (NLM_F_DUMP_INTR): повтор с чистого листа ---- */
    start(M_INTR_ONCE);
    check("rtnl: прерванный дамп повторён — ответ второго (маршрута нет)", 0, rtnl_table_has_default(RT_TABLE_MAIN));
    check("  запросов два", 2, g_reqs);
    start(M_INTR_ONCE);
    devs = 0;
    check("rtnl: устройства WAN после прерванного дампа — 0", 0, rtnl_default_devs(dev_fn, &devs));
    check("  устройство прерванного прохода не осталось", 0, devs);
    start(M_INTR_ALWAYS);
    check("rtnl: таблица меняется без передышки — отказ, а не смесь мгновений", -1,
          rtnl_table_has_default(RT_TABLE_MAIN));
    check("  после пяти попыток", 5, g_reqs);

    printf("nldonematch: %d passed, %d failed\n", pass, fail);
    return fail != 0;
}
