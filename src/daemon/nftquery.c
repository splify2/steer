#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "nftquery.h"
#include "generate.h"
#include "nftdump.h"

/* Сколько элементов в наборе по мнению ядра. -1 — набора нет.
 *
 * Прежде — `nft list set` через popen и счёт запятых в выводе; теперь дамп элементов по netlink
 * (src/lib/nftdump.c): ни процесса, ни второй копии списка в памяти ради одного числа, а имя
 * набора в командную строку больше не попадает вовсе. */
long set_count(const char *name) {
    return nfd_set_count(NFD_INET, nft_table(), name);
}

/* Есть ли цепочка движка в ядре. */
int nft_chain_here(const char *chain) {
    return nfd_chain_exists(NFD_INET, nft_table(), chain);
}

/* "A.B.C.D[/N]" → сеть и маска. 0, если строка не префикс.
 *
 * Сдвиг на 32 — неопределённое поведение, поэтому нулевая длина считается отдельно, а не
 * выводится из общей формулы: /0 в списке встречается («весь интернет в туннель»), и на
 * нём же общая формула и сломалась бы. */
int parse_prefix(const char *s, uint32_t *net, uint32_t *mask) {
    unsigned a, b, c, d, len = 32;
    int n = sscanf(s, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &len);
    if (n < 4 || a > 255 || b > 255 || c > 255 || d > 255 || len > 32) return 0;
    *mask = len ? ~0u << (32 - len) : 0;
    *net = (((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d) & *mask;
    return 1;
}

/* Asks the KERNEL, channel by channel in spec order, instead of re-reading the
 * list files: the answer has to describe what the box will actually do, including
 * the case where a set failed to load. This is the one answer raw nft cannot give. */
/* Адрес или префикс IPv4 в диапазон [lo, hi]. 0 — не адрес. Диапазон «a-b» — тоже: так nft
 * печатает интервалы, не укладывающиеся в один префикс. */
int ipv4_span(const char *t, uint32_t *lo, uint32_t *hi) {
    char buf[40];
    size_t n = strlen(t);
    if (!n || n >= sizeof(buf)) return 0;
    memcpy(buf, t, n + 1);
    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        struct in_addr a, b;
        if (inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, dash + 1, &b) != 1) return 0;
        *lo = ntohl(a.s_addr);
        *hi = ntohl(b.s_addr);
        return *lo <= *hi;
    }
    char *sl = strchr(buf, '/');
    int len = 32;
    if (sl) {
        *sl = '\0';
        char *e;
        long v = strtol(sl + 1, &e, 10);
        if (*e || v < 0 || v > 32) return 0;
        len = (int)v;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t m = len ? 0xffffffffu << (32 - len) : 0;
    *lo = ntohl(a.s_addr) & m;
    *hi = *lo | ~m;
    return 1;
}

/* То же для IPv6 (адрес, префикс, диапазон): границы — 16 байт в порядке сети, сравниваются
 * memcmp. Нужна explain: в составном наборе адрес ищется дампом (set_scan_mixed). */
int ipv6_span(const char *t, uint8_t lo[16], uint8_t hi[16]) {
    char buf[96];
    size_t n = strlen(t);
    if (!n || n >= sizeof(buf)) return 0;
    memcpy(buf, t, n + 1);
    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        if (inet_pton(AF_INET6, buf, lo) != 1 || inet_pton(AF_INET6, dash + 1, hi) != 1) return 0;
        return memcmp(lo, hi, 16) <= 0;
    }
    char *sl = strchr(buf, '/');
    int len = 128;
    if (sl) {
        *sl = '\0';
        char *e;
        long v = strtol(sl + 1, &e, 10);
        if (*e || v < 0 || v > 128) return 0;
        len = (int)v;
    }
    uint8_t a[16];
    if (inet_pton(AF_INET6, buf, a) != 1) return 0;
    for (int i = 0; i < 16; i++) {
        int bits = len - i * 8;
        uint8_t m = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));
        lo[i] = a[i] & m;
        hi[i] = (uint8_t)(lo[i] | (uint8_t)~m);
    }
    return 1;
}
