/* Очередь эхо-запросов через туннель подбора — потери, задержка и «обрыв».
 *
 * Как у апстрима Zapret Manager (_st_warp_probe): 10 запросов с шагом 200 мс к 1.1.1.1. Обрыв —
 * ответы были, но последние WB_TORN и больше запросов остались без ответа: DPI пропускает начало
 * сессии и режет её, когда распознаёт, — туннель с таким поведением сначала «работает», а потом
 * встаёт, и брать его нельзя, даже если потери в сумме невелики.
 *
 * Сокет ICMP сырой (модуль — root), а не «ping»-датаграммный: тот зависит от ping_group_range и в
 * новом пространстве сети по умолчанию закрыт. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#include "wbping.h"

#define WB_TORN 3

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000000L + t.tv_nsec / 1000L;
}

static uint16_t csum(const void *p, size_t n) {
    const uint8_t *b = p;
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(b[i] << 8 | b[i + 1]);
    if (n & 1) s += (uint32_t)b[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons((uint16_t)~s);
}

int wb_ping_burst(const char *dst, int count, int step_ms, int wait_ms, struct wb_ping *r) {
    memset(r, 0, sizeof(*r));
    r->rtt = -1;
    struct sockaddr_in to = { .sin_family = AF_INET };
    if (count <= 0 || count > 64 || inet_pton(AF_INET, dst, &to.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ICMP);
    if (fd < 0) return -1;
    uint16_t id = (uint16_t)(getpid() ^ (now_us() & 0xffff));
    long sent_at[64] = { 0 };
    int seen[64] = { 0 };
    long rtt_sum = 0;
    int hi = -1, next = 0;
    long t0 = now_us(), next_at = t0, end = 0;
    for (;;) {
        long now = now_us();
        if (next < count && now >= next_at) {
            uint8_t pkt[64] = { 0 };
            struct icmphdr *ic = (struct icmphdr *)pkt;
            ic->type = ICMP_ECHO;
            ic->un.echo.id = htons(id);
            ic->un.echo.sequence = htons((uint16_t)next);
            ic->checksum = csum(pkt, sizeof(pkt));
            sent_at[next] = now;
            if (sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)) > 0) r->sent++;
            next++;
            next_at = now + step_ms * 1000L;
            if (next == count) end = now + wait_ms * 1000L;
        }
        if (next == count && (now >= end || r->got == r->sent)) break;
        long until = next < count ? next_at : end;
        int ms = (int)((until - now + 999) / 1000);
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, ms > 0 ? ms : 0) <= 0) continue;
        uint8_t buf[1500];
        ssize_t n;
        while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
            const struct iphdr *ip = (const struct iphdr *)buf;
            size_t hl = (size_t)ip->ihl * 4;
            if ((size_t)n < hl + sizeof(struct icmphdr)) continue;
            const struct icmphdr *ic = (const struct icmphdr *)(buf + hl);
            if (ic->type != ICMP_ECHOREPLY || ntohs(ic->un.echo.id) != id) continue;
            if (ip->saddr != to.sin_addr.s_addr) continue;
            int seq = ntohs(ic->un.echo.sequence);
            if (seq >= next || seen[seq]) continue;
            seen[seq] = 1;
            r->got++;
            rtt_sum += now_us() - sent_at[seq];
            if (seq > hi) hi = seq;
        }
    }
    close(fd);
    if (!r->sent) return -1;
    r->loss = (r->sent - r->got) * 100 / r->sent;
    if (r->got) r->rtt = (int)(rtt_sum / r->got / 1000);
    r->torn = r->got > 0 && r->sent - 1 - hi >= WB_TORN;
    return 0;
}
