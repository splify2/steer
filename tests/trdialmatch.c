/* Установление сокета до узла (src/proto/transport/trdial.c) по IPv4 и IPv6: прямой литерал,
 * имя только с AAAA, смешанный набор, адрес-победитель в кэше, scope id у link-local, UDP.
 * Issue splify2/steer#7: дозвон был зашит на AF_INET — узел по адресу IPv6 и по имени только
 * с AAAA не открывался вовсе («имя не разрешилось» у proxy-probe).
 *
 * РЕЗОЛВЕР ПОДМЕНЁН В САМОМ СТЕНДЕ: getaddrinfo, freeaddrinfo и connect определены здесь и
 * перекрывают libc для trdial.o (динамическая компоновка — символ исполняемого файла
 * побеждает). Подмена getaddrinfo честно соблюдает hints.ai_family, как настоящий: старый код
 * просил AF_INET и от имени только с AAAA получал пустой ответ. Литералы и неизвестные имена
 * уходят настоящему getaddrinfo — «::1» и «fe80::1%lo» разбирает libc. Подмена connect только
 * записывает адрес, который передали ядру (scope id проверяется по нему), и зовёт настоящий.
 * Сети наружу нет: все узлы — петля. Без IPv6 на lo стенд громко пропускается. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <time.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "transport.h"
#include "unit.h"

/* ---- подмена резолвера и connect ------------------------------------------------------------ */

struct fake_name { const char *name; const char *ips[4]; };
static const struct fake_name g_names[] = {
    { "v6only.test",  { "::1", NULL } },
    { "v4only.test",  { "127.0.0.1", NULL } },
    { "mixed.test",   { "::1", "127.0.0.1", NULL } },      /* v6 первым, как отдаёт RFC 6724 */
    { "mixed4.test",  { "127.0.0.1", "::1", NULL } },
    { "cache4.test",  { "::1", "127.0.0.1", NULL } },
    { "cache6.test",  { "127.0.0.1", "::1", NULL } },
    { "udpmix.test",  { "::1", "127.0.0.1", NULL } },
    { NULL, { NULL } },
};
static char g_marker[] = "steer-test-fake";

static int g_gai_calls;

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res) {
    static int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
    if (!real) real = dlsym(RTLD_NEXT, "getaddrinfo");
    g_gai_calls++;
    const struct fake_name *f = NULL;
    for (const struct fake_name *p = g_names; node && p->name; p++)
        if (!strcmp(p->name, node)) f = p;
    if (!f) return real(node, service, hints, res);
    int fam = hints ? hints->ai_family : AF_UNSPEC;
    unsigned port = service ? (unsigned)atoi(service) : 0;
    struct addrinfo *head = NULL, **tail = &head;
    for (int i = 0; f->ips[i]; i++) {
        struct sockaddr_in6 s6; struct sockaddr_in s4;
        memset(&s6, 0, sizeof s6); memset(&s4, 0, sizeof s4);
        int af = inet_pton(AF_INET6, f->ips[i], &s6.sin6_addr) == 1 ? AF_INET6 : AF_INET;
        if (af == AF_INET) inet_pton(AF_INET, f->ips[i], &s4.sin_addr);
        if (fam != AF_UNSPEC && fam != af) continue;
        struct addrinfo *a = calloc(1, sizeof *a);
        a->ai_family = af;
        a->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
        a->ai_canonname = g_marker;
        if (af == AF_INET6) {
            s6.sin6_family = AF_INET6; s6.sin6_port = htons((uint16_t)port);
            a->ai_addrlen = sizeof s6; a->ai_addr = malloc(sizeof s6); memcpy(a->ai_addr, &s6, sizeof s6);
        } else {
            s4.sin_family = AF_INET; s4.sin_port = htons((uint16_t)port);
            a->ai_addrlen = sizeof s4; a->ai_addr = malloc(sizeof s4); memcpy(a->ai_addr, &s4, sizeof s4);
        }
        *tail = a; tail = &a->ai_next;
    }
    if (!head) return EAI_NODATA;
    *res = head;
    return 0;
}

void freeaddrinfo(struct addrinfo *ai) {
    static void (*real)(struct addrinfo *);
    if (!real) real = dlsym(RTLD_NEXT, "freeaddrinfo");
    if (ai && ai->ai_canonname == g_marker) {
        while (ai) { struct addrinfo *n = ai->ai_next; free(ai->ai_addr); free(ai); ai = n; }
        return;
    }
    real(ai);
}

#define CONN_LOG 32
static struct { int fam; unsigned scope; char ip[INET6_ADDRSTRLEN]; } g_conn[CONN_LOG];
static int g_conn_n;

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) real = dlsym(RTLD_NEXT, "connect");
    if (g_conn_n < CONN_LOG && (sa->sa_family == AF_INET || sa->sa_family == AF_INET6)) {
        g_conn[g_conn_n].fam = sa->sa_family;
        g_conn[g_conn_n].scope = 0;
        if (sa->sa_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const void *)sa;
            g_conn[g_conn_n].scope = a->sin6_scope_id;
            inet_ntop(AF_INET6, &a->sin6_addr, g_conn[g_conn_n].ip, sizeof g_conn[0].ip);
        } else {
            inet_ntop(AF_INET, &((const struct sockaddr_in *)(const void *)sa)->sin_addr,
                      g_conn[g_conn_n].ip, sizeof g_conn[0].ip);
        }
        g_conn_n++;
    }
    return real(fd, sa, len);
}

/* ---- помощники ------------------------------------------------------------------------------ */

static int open_fds(void) {
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

/* Слушатель TCP на петле нужного семейства. port == 0 — любой; возвращает порт через *port. */
static int listen_on(int fam, uint16_t *port) {
    int fd = socket(fam, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (fam == AF_INET6) {
        struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT,
                                  .sin6_port = htons(*port) };
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    } else {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(*port) };
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    }
    if (listen(fd, 8) != 0) { close(fd); return -1; }
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    getsockname(fd, (struct sockaddr *)&ss, &sl);
    *port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                           : ((struct sockaddr_in *)&ss)->sin_port);
    return fd;
}

static int peer_family(int fd) {
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) return -1;
    return ss.ss_family;
}

static int g_prep_n, g_prep_refuse, g_prep_unconn;
static int prep_cb(void *ctx, int fd) {
    (*(int *)ctx)++;
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    g_prep_unconn = getpeername(fd, (struct sockaddr *)&ss, &sl) != 0;   /* ещё не соединён */
    return g_prep_refuse ? -1 : 0;
}

static void conn_reset(void) { g_conn_n = 0; memset(g_conn, 0, sizeof g_conn); }

int main(void) {
    /* IPv6 на петле: без него ни одной проверки не выйдет. */
    uint16_t p6 = 0;
    int probe = listen_on(AF_INET6, &p6);
    if (probe < 0) { printf("trdialmatch: на lo нет IPv6 (%s) — стенд пропущен\n", strerror(errno)); return 0; }
    close(probe);

    /* Один порт на оба семейства: имя отдаёт один порт, а адреса — разных семейств. */
    uint16_t port = 0;
    int l4 = listen_on(AF_INET, &port);
    int l6 = listen_on(AF_INET6, &port);
    if (l4 < 0 || l6 < 0) { printf("trdialmatch: не нашёл общий порт петли — стенд пропущен\n"); return 0; }
    int fds0 = open_fds();
    int fd;

    /* ---- TCP: литералы ---- */
    fd = tr_dial("::1", port, 3);
    check("TCP: литерал ::1 соединяется", 1, fd >= 0);
    check("TCP: ::1 — сокет IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial("127.0.0.1", port, 3);
    check("TCP: литерал IPv4 по-прежнему соединяется", 1, fd >= 0);
    check("TCP: IPv4 — сокет IPv4", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);

    /* ---- TCP: имена ---- */
    fd = tr_dial("v6only.test", port, 3);
    check("TCP: имя только с AAAA соединяется", 1, fd >= 0);
    check("TCP: AAAA-имя — сокет IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial("v4only.test", port, 3);
    check("TCP: имя только с A соединяется", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial("net.invalid.test", port, 3);
    check("TCP: имя не разрешилось — TR_EDNS", TR_EDNS, fd);

    /* ---- TCP: смешанный набор, у адреса v6 никто не слушает ---- */
    close(l6);
    conn_reset();
    fd = tr_dial("mixed.test", port, 3);
    check("TCP: v6 отказал — берётся следующий (v4)", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    check("TCP: первым пробовался адрес IPv6 из ответа", AF_INET6, g_conn[0].fam);
    if (fd >= 0) close(fd);
    l6 = listen_on(AF_INET6, &port);
    if (l6 < 0) { printf("trdialmatch: порт v6 не вернулся\n"); return 1; }

    /* ---- TCP: кэш победителя запоминает и семейство ---- */
    /* Победил v4 (v6 в этот момент закрыт), дальше v6 снова жив, но в ответе он первый:
     * кэш обязан поставить прошлого победителя — IPv4 — впереди. */
    close(l6);
    fd = tr_dial("cache4.test", port, 3);
    if (fd >= 0) close(fd);
    l6 = listen_on(AF_INET6, &port);
    conn_reset();
    fd = tr_dial("cache4.test", port, 3);
    check("кэш: прошлый победитель v4 идёт первым, хотя v6 стоит выше", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    check("кэш: и пробовался он ОДИН (v6 даже не начат)", 1, g_conn_n);
    if (fd >= 0) close(fd);
    /* И наоборот: победил v6 — он остаётся первым, даже когда в ответе стоит позже. */
    fd = tr_dial("cache6.test", port, 3);   /* v4 первым в ответе, оба живы: победит v4 */
    if (fd >= 0) close(fd);
    close(l4);
    fd = tr_dial("cache6.test", port, 3);   /* v4 умер → победил v6 */
    check("кэш: v4 мёртв — соединился v6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    l4 = listen_on(AF_INET, &port);
    conn_reset();
    fd = tr_dial("cache6.test", port, 3);
    check("кэш: прошлый победитель v6 идёт первым, хотя v4 стоит выше", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    check("кэш: пробовался один адрес", 1, g_conn_n);
    if (fd >= 0) close(fd);

    /* ---- TCP: все мертвы — отказ без висения и без утечки дескрипторов ---- */
    close(l4); close(l6);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fd = tr_dial("mixed4.test", port, 3);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    check("TCP: все адреса отказали — TR_ECONNECT", TR_ECONNECT, fd);
    check("TCP: отказ быстрый (отказ петли, не таймаут)", 1,
          (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < 1500);
    check("TCP: дескрипторы не утекли", fds0 - 2, open_fds());   /* -2: закрыты оба слушателя */

    /* ---- TCP: scope id у link-local ---- */
    conn_reset();
    unsigned lo = if_nametoindex("lo");
    fd = tr_dial("fe80::1%lo", port, 2);
    check("scope: link-local на lo без хозяина — отказ, не висение", 1, fd < 0);
    check("scope: адрес ушёл в connect семейством IPv6", AF_INET6, g_conn[0].fam);
    check("scope: sin6_scope_id = индекс lo", (long)lo, (long)g_conn[0].scope);

    /* ---- UDP ---- */
    fd = tr_dial_udp("::1", 9);
    check("UDP: литерал ::1 — сокет есть", 1, fd >= 0);
    check("UDP: ::1 — сокет IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial_udp("v6only.test", 9);
    check("UDP: имя только с AAAA — сокет IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial_udp("127.0.0.1", 9);
    check("UDP: IPv4 по-прежнему", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    fd = tr_dial_udp("net.invalid.test", 9);
    check("UDP: имя не разрешилось — TR_EDNS", TR_EDNS, fd);
    /* UDP за адресом, которым TCP уже пользовался, идёт тем же семейством: у датаграмм
     * рукопожатия нет, и «первый из ответа» мог бы оказаться чёрной дырой. */
    l4 = listen_on(AF_INET, &port);
    fd = tr_dial("udpmix.test", port, 3);   /* v6 никто не слушает — победит v4 */
    if (fd >= 0) close(fd);
    fd = tr_dial_udp("udpmix.test", port);
    check("UDP: берёт семейство, победившее у TCP (v4, хотя v6 в ответе первый)", AF_INET,
          fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    close(l4);

    /* ---- via: метка обязательна — IPv6 к цели не ходит (иначе ушёл бы мимо цели) ---- */
    l4 = listen_on(AF_INET, &port);
    l6 = listen_on(AF_INET6, &port);
    transport_set_sock_mark(0x1234, 1);
    conn_reset();
    fd = tr_dial("::1", port, 2);
    check("via: литерал IPv6 — отказ", TR_ECONNECT, fd);
    check("via: к IPv6 не было ни одного connect", 0, g_conn_n);
    fd = tr_dial_udp("::1", 9);
    check("via: UDP на IPv6 — отказ", TR_ECONNECT, fd);
    int mk = socket(AF_INET, SOCK_STREAM, 0), mark_ok = 0;
    if (mk >= 0) { unsigned m = 0x1234; mark_ok = setsockopt(mk, SOL_SOCKET, SO_MARK, &m, sizeof m) == 0; close(mk); }
    if (mark_ok) {
        conn_reset();
        fd = tr_dial("mixed.test", port, 3);
        check("via: имя с A и AAAA — идёт по IPv4", AF_INET, fd >= 0 ? peer_family(fd) : -1);
        check("via: IPv6 из ответа не пробовался", AF_INET, g_conn[0].fam);
        if (fd >= 0) close(fd);
    } else {
        printf("via: SO_MARK недоступен (нет CAP_NET_ADMIN) — проверка IPv4 под меткой пропущена\n");
    }
    transport_set_sock_mark(0, 0);

    /* ---- подготовка сокета хостом (по PR #12): до connect, отказ — закрыт и не соединён ---- */
    g_prep_n = 0; g_prep_refuse = 0;
    transport_set_socket_prepare(prep_cb, &g_prep_n);
    fd = tr_dial("127.0.0.1", port, 3);
    check("подготовка: TCP — крючок позван на сокете до connect", 1, fd >= 0 && g_prep_n == 1 && g_prep_unconn);
    if (fd >= 0) close(fd);
    g_prep_n = 0;
    fd = tr_dial_udp("127.0.0.1", 9);
    check("подготовка: UDP — крючок позван", 1, fd >= 0 && g_prep_n == 1 && g_prep_unconn);
    if (fd >= 0) close(fd);
    g_prep_refuse = 1;
    fd = tr_dial("127.0.0.1", port, 3);
    check("подготовка: хост отказал — TCP не соединяется", 1, fd < 0);
    fd = tr_dial_udp("127.0.0.1", 9);
    check("подготовка: хост отказал — UDP TR_ESOCK", TR_ESOCK, fd);
    transport_set_socket_prepare(NULL, NULL);

    close(l4); close(l6);
    check("итог: дескрипторы не утекли", fds0 - 2, open_fds());

    return unit_done("trdialmatch");
}
