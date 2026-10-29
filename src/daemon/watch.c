#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "daemon.h"

/* Общее для сторожа в демоне (watchd.c): сокет событий сети и решение «вернуть ли masquerade». */
/* Сокет событий ядра для сторожа: смена состояния интерфейса и его адресов. -1 — не
 * открылся, и сторож живёт одним периодом.
 *
 * ИНТЕРФЕЙСЫ И АДРЕСА, НО НЕ МАРШРУТЫ. Маршруты в таблицах выходов меняет сам сторож (и apply)
 * — подписка на них будила бы его собственными действиями по кругу. А то, ради чего события и
 * нужны, видно именно здесь: сменилась сеть (у Wi-Fi или сотовой появился или пропал адрес),
 * поднялся TUN выхода, который создал помощник, упал интерфейс туннеля. */
int watch_nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

/* Дочитать всё, что накопилось. 1 — было хоть одно событие. */
int watch_nl_drain(int fd) {
    char buf[8192];
    int any = 0;
    ssize_t r;
    while ((r = recv(fd, buf, sizeof(buf), 0)) > 0 || (r < 0 && errno == ENOBUFS))
        any = 1;   /* ENOBUFS — события потеряны переполнением: это тоже «что-то сменилось» */
    return any;
}

/* Возвращать ли masquerade (телефон, iptables_masq_ensure) после этого прохода. iptables -C —
 * процесс на устройство, а сторож работает без процессов на проход; правило же пропадает только
 * при перезапуске netd, который перестраивает iptables. Поэтому — после проходов по событию
 * сети или смене спеки (force) и не реже раза в WATCH_MASQ_S. */
int watch_masq_due(long *last, int force) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long now = (long)t.tv_sec;
    if (!force && *last && now - *last < WATCH_MASQ_S) return 0;
    *last = now ? now : 1;
    return 1;
}
