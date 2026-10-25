/* Программа раздачи в ядре (tun_steer_attach, R-146): ядро кладёт пакет в ту очередь, которую назовёт
 * tun_flow_owner — до бита тот же хэш, которым рабочий проверяет «пакет мой».
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Программа собрана из инструкций eBPF руками, а хэш в C — обычный код, и
 * совпадать они обязаны на каждом пакете: иначе половина соединения уйдёт чужому рабочему, и соединение
 * встанет — ровно тот отказ, ради которого раздачу взяли на себя. Модульным стендом это не проверить:
 * исполняет программу ядро. Поэтому стенд поднимает настоящее устройство с несколькими очередями в своём
 * сетевом пространстве, ставит программу и шлёт через него трафик ядра:
 *   - UDP с разных портов источника на разные порты назначения — каждый пакет в очереди своего хэша;
 *   - TCP SYN (неблокирующий connect) — то же для TCP;
 *   - UDP крупнее MTU — фрагменты: все куски одной датаграммы в одной очереди, и это очередь хэша
 *     без портов;
 *   - трафик действительно расходится по очередям (иначе «все в нулевой» тоже сошлось бы).
 * Нужен root (своё сетевое пространство); без него — пропуск, не падение. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/tunnel/tun.h"
#include "unit.h"

#define NQ 4
#define DEV "steer-st0"

static int udp_send(uint16_t sport, const char *dst, uint16_t dport, size_t len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(sport) };
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) { close(s); return -1; }
    /* Не запрещать фрагментацию: крупная датаграмма должна уйти кусками. */
    int pmtu = IP_PMTUDISC_DONT;
    setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(dport) };
    inet_pton(AF_INET, dst, &d.sin_addr);
    static unsigned char buf[4000];
    memset(buf, 0x5a, sizeof(buf));
    ssize_t r = sendto(s, buf, len, 0, (struct sockaddr *)&d, sizeof(d));
    close(s);
    return r == (ssize_t)len ? 0 : -1;
}

/* То же по IPv6: источник выбирает ядро (адрес устройства), крупная датаграмма уходит кусками с
 * заголовком фрагментации. */
static int udp6_send(uint16_t sport, const char *dst, uint16_t dport, size_t len) {
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(sport), .sin6_addr = IN6ADDR_ANY_INIT };
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) { close(s); return -1; }
    int pmtu = IPV6_PMTUDISC_DONT;
    setsockopt(s, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu, sizeof(pmtu));
    struct sockaddr_in6 d = { .sin6_family = AF_INET6, .sin6_port = htons(dport) };
    inet_pton(AF_INET6, dst, &d.sin6_addr);
    static unsigned char buf[4000];
    memset(buf, 0x5a, sizeof(buf));
    ssize_t r = sendto(s, buf, len, 0, (struct sockaddr *)&d, sizeof(d));
    close(s);
    return r == (ssize_t)len ? 0 : -1;
}

static void tcp6_syn(const char *dst, uint16_t dport) {
    int s = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) return;
    struct sockaddr_in6 d = { .sin6_family = AF_INET6, .sin6_port = htons(dport) };
    inet_pton(AF_INET6, dst, &d.sin6_addr);
    if (connect(s, (struct sockaddr *)&d, sizeof(d)) != 0 && errno != EINPROGRESS) { close(s); return; }
    static int nk6;
    if (nk6++ >= 64) close(s);
}

static void tcp_syn(const char *dst, uint16_t dport) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) return;
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(dport) };
    inet_pton(AF_INET, dst, &d.sin_addr);
    if (connect(s, (struct sockaddr *)&d, sizeof(d)) != 0 && errno != EINPROGRESS) { close(s); return; }
    /* Держим открытым до чтения очередей: закрытие послало бы ещё и RST. */
    static int nk;
    if (nk++ >= 64) close(s);   /* остальные держим до выхода стенда */
}

int main(void) {
    if (geteuid() != 0 || unshare(CLONE_NEWNET) != 0) {
        printf("tunsteermatch: ПРОПУСК — нужен root и своё сетевое пространство (это не падение)\n");
        return 0;
    }
    if (system("ip link set lo up") != 0) { printf("tunsteermatch: ПРОПУСК — нет ip\n"); return 0; }

    struct tun_dev q[NQ];
    int n = tun_open(q, NQ, DEV);
    check("устройство: открыто очередей", NQ, n);
    if (n != NQ) return unit_done("tunsteermatch");
    char why[256];
    int rc = tun_steer_attach(q[0].fd, NQ, why, sizeof(why));
    if (rc != 0) printf("     причина: %s\n", why);
    check("программа раздачи встала", 0, rc);
    if (rc != 0) return unit_done("tunsteermatch");
    for (int i = 0; i < NQ; i++) {
        int fl = fcntl(q[i].fd, F_GETFL, 0);
        fcntl(q[i].fd, F_SETFL, fl | O_NONBLOCK);
    }
    if (system("ip addr add 10.99.0.1/24 dev " DEV " && ip link set " DEV " mtu 1500 up") != 0) {
        check("адрес и подъём устройства", 0, 1);
        return unit_done("tunsteermatch");
    }

    /* Трафик: 64 UDP-потока, 32 TCP SYN, 8 крупных датаграмм кусками. */
    for (int i = 0; i < 64; i++) udp_send((uint16_t)(20000 + i * 7), i & 1 ? "10.99.0.7" : "10.99.0.9",
                                          (uint16_t)(5000 + i * 13), 100);
    for (int i = 0; i < 32; i++) tcp_syn(i & 1 ? "10.99.0.5" : "10.99.0.6", (uint16_t)(8000 + i));
    for (int i = 0; i < 8; i++) udp_send((uint16_t)(30000 + i), "10.99.0.8", (uint16_t)(6000 + i), 3000);
    /* IPv6 — тем же набором: адрес устройства и маршрут на сеть, потом UDP, SYN и крупные датаграммы. */
    int v6 = system("ip -6 addr add fd99::1/64 dev " DEV " nodad") == 0;
    if (v6) {
        for (int i = 0; i < 64; i++) udp6_send((uint16_t)(21000 + i * 7), i & 1 ? "fd99::7" : "fd99::9",
                                               (uint16_t)(5000 + i * 13), 100);
        for (int i = 0; i < 32; i++) tcp6_syn(i & 1 ? "fd99::5" : "fd99::6", (uint16_t)(8000 + i));
        for (int i = 0; i < 8; i++) udp6_send((uint16_t)(31000 + i), "fd99::8", (uint16_t)(6000 + i), 3000);
    } else {
        printf("     IPv6 на устройстве не встал — половина IPv6 пропущена\n");
    }
    usleep(200000);

    int total = 0, wrong = 0, per[NQ] = { 0 }, frags = 0, frag_wrong = 0;
    int ipid_q[65536];
    memset(ipid_q, -1, sizeof(ipid_q));
    int frag_split = 0;
    int total6 = 0, wrong6 = 0, per6[NQ] = { 0 }, frags6 = 0, frag6_wrong = 0, frag6_split = 0;
    static int fid_q[1 << 16];                      /* номер фрагментации IPv6 (младшие 16 бит) → очередь */
    memset(fid_q, -1, sizeof(fid_q));
    static unsigned char pkt[70000];
    for (int i = 0; i < NQ; i++) {
        for (;;) {
            ssize_t r = tun_read_packet(&q[i], pkt, sizeof(pkt));
            if (r < 0) break;
            if (r == 0) continue;
            if ((pkt[0] >> 4) == 6) {
                /* Наши — только TCP, UDP и фрагменты (следующий заголовок 6, 17, 44); служебное ядра (соседи,
                 * MLD: ICMPv6 и hop-by-hop) — не наше. */
                if (pkt[6] != 6 && pkt[6] != 17 && pkt[6] != 44) continue;
                total6++;
                per6[i]++;
                unsigned o6 = tun_flow_owner(pkt, (size_t)r, NQ);
                if (o6 != (unsigned)i) wrong6++;
                if (pkt[6] == 44) {
                    frags6++;
                    if (o6 != (unsigned)i) frag6_wrong++;
                    unsigned fid = (unsigned)(((pkt[46] << 8) | pkt[47]) & 0xFFFF);
                    if (fid_q[fid] >= 0 && fid_q[fid] != i) frag6_split++;
                    fid_q[fid] = i;
                }
                continue;
            }
            if ((pkt[0] >> 4) != 4) continue;
            total++;
            per[i]++;
            unsigned o = tun_flow_owner(pkt, (size_t)r, NQ);
            if (o != (unsigned)i) wrong++;
            if ((((pkt[6] << 8) | pkt[7]) & 0x3FFF) != 0) {
                frags++;
                if (o != (unsigned)i) frag_wrong++;
                unsigned id = (unsigned)((pkt[4] << 8) | pkt[5]);
                if (ipid_q[id] >= 0 && ipid_q[id] != i) frag_split++;
                ipid_q[id] = i;
            }
        }
    }
    printf("     пакетов %d, по очередям %d %d %d %d, фрагментов %d\n", total, per[0], per[1], per[2], per[3],
           frags);
    check("пакетов прочитано (64 UDP + 32 SYN + куски 8 датаграмм)", 1, total >= 64 + 32 + 16);
    check("каждый пакет — в очереди своего хэша (tun_flow_owner)", 0, wrong);
    check("фрагменты пришли", 1, frags >= 16);
    check("фрагменты — в очереди хэша без портов", 0, frag_wrong);
    check("куски одной датаграммы не разошлись по очередям", 0, frag_split);
    int used = 0;
    for (int i = 0; i < NQ; i++) used += per[i] > 0;
    check("трафик разошёлся по всем очередям", NQ, used);
    if (v6) {
        printf("     IPv6: пакетов %d, по очередям %d %d %d %d, фрагментов %d\n", total6, per6[0], per6[1],
               per6[2], per6[3], frags6);
        check("IPv6: пакетов прочитано (64 UDP + 32 SYN + куски 8 датаграмм)", 1, total6 >= 64 + 32 + 16);
        check("IPv6: каждый пакет — в очереди своего хэша (tun_flow_owner)", 0, wrong6);
        check("IPv6: фрагменты пришли", 1, frags6 >= 16);
        check("IPv6: фрагменты — в очереди хэша без портов", 0, frag6_wrong);
        check("IPv6: куски одной датаграммы не разошлись по очередям", 0, frag6_split);
        int used6 = 0;
        for (int i = 0; i < NQ; i++) used6 += per6[i] > 0;
        check("IPv6: трафик разошёлся по всем очередям", NQ, used6);
    }
    return unit_done("tunsteermatch");
}
