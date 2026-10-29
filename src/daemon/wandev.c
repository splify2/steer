#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "loop.h"
#include "rtnl.h"
#include "nftvmap.h"
#include "nftdump.h"
#include "spec.h"
#include "marks.h"
#include "wandev.h"

#define LOG_I "steer[info] wan_dev: "
#define LOG_W "steer[warn] wan_dev: "

static struct {
    int fd;
    char **cur;      /* последний записанный список, по возрастанию */
    size_t n;
    int known;       /* cur — то, что лежит в наборе */
} W = { .fd = -1 };

struct devs { char **v; size_t n, cap; };

static void devs_add(const char *dev, void *arg) {
    struct devs *d = arg;
    for (size_t i = 0; i < d->n; i++)
        if (!strcmp(d->v[i], dev)) return;
    if (d->n == d->cap) {
        size_t c = d->cap ? d->cap * 2 : 4;
        char **nv = realloc(d->v, c * sizeof(*nv));
        if (!nv) return;
        d->v = nv;
        d->cap = c;
    }
    char *s = strdup(dev);
    if (s) d->v[d->n++] = s;
}

static void devs_free(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

static int str_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void wandev_sync(int force) {
    struct devs d = { 0 };
    if (rtnl_default_devs(devs_add, &d) != 0) { devs_free(d.v, d.n); return; }
    if (d.n) qsort(d.v, d.n, sizeof(*d.v), str_cmp);
    /* force — после apply набор напечатан заново, и маршрут мог смениться, пока шла перезагрузка:
     * переписать без сверки с прошлым (одна транзакция). */
    int same = !force && W.known && d.n == W.n;
    for (size_t i = 0; same && i < d.n; i++) same = !strcmp(d.v[i], W.cur[i]);
    if (same) { devs_free(d.v, d.n); return; }
    if (nfv_ifnames_write(NFD_INET, nft_table(), "wan_dev", (const char *const *)d.v, d.n) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, LOG_W "набор не переписан: %s\n", strerror(errno));
            devs_free(d.v, d.n);
            return;          /* следующее событие попробует снова */
        }
    } else {
        char line[512];
        size_t o = 0;
        line[0] = '\0';
        for (size_t i = 0; i < d.n && o < sizeof(line); i++)
            o += (size_t)snprintf(line + o, sizeof(line) - o, "%s%s", i ? " " : "", d.v[i]);
        if (!force) fprintf(stderr, LOG_I "WAN сменился: %s\n", d.n ? line : "нет маршрута по умолчанию");
    }
    devs_free(W.cur, W.n);
    W.cur = d.v; W.n = d.n; W.known = 1;
}

/* Маршрут по умолчанию таблицы main — то, что меняет набор. */
static int is_main_default(const struct nlmsghdr *h) {
    if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) return 0;
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl || rt->rtm_dst_len != 0) return 0;
    uint32_t table = rt->rtm_table;
    int left = (int)(h->nlmsg_len - NLMSG_HDRLEN - hl);
    for (const struct rtattr *a = (const struct rtattr *)((const uint8_t *)rt + hl); RTA_OK(a, left);
         a = RTA_NEXT(a, left))
        if (a->rta_type == RTA_TABLE && RTA_PAYLOAD(a) >= 4) memcpy(&table, RTA_DATA(a), 4);
    return table == RT_TABLE_MAIN;
}

static void wandev_on(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)events; (void)arg;
    _Alignas(struct nlmsghdr) char buf[8192];
    int hit = 0;
    ssize_t r;
    while ((r = recv(fd, buf, sizeof(buf), 0)) > 0 || (r < 0 && (errno == ENOBUFS || errno == EINTR))) {
        if (r < 0) { if (errno == ENOBUFS) hit = 1; continue; }   /* события потеряны — сверить */
        size_t m = (size_t)r;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, m); h = NLMSG_NEXT(h, m))
            if (is_main_default(h)) hit = 1;
    }
    if (hit) wandev_sync(0);
}

int wandev_start(struct loop *l) {
    if (W.fd >= 0) return 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || loop_fd_add(l, fd, EPOLLIN, wandev_on, NULL) != 0) {
        close(fd);
        return -1;
    }
    W.fd = fd;
    wandev_sync(1);
    return 0;
}
