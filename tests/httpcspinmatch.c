/* HTTPS-клиент libsteer (httpc.c) ждёт данных сервера poll'ом, а не холостой петлёй (аудит 2.1.0, F2).
 *
 * Чтение TLS не ждёт (tls13_read_ref берёт сокет с MSG_DONTWAIT — так нужно циклу туннеля), и прежде
 * read_head и цикл тела принимали «0 байт» за порцию и звали снова: 100 % ядра на всё ожидание (PoC аудита:
 * 1,4 млн вызовов за 3 с), а срок молчания idle_ms — SO_RCVTIMEO, которого неблокирующее чтение не замечает,
 * — не наступал никогда. Без общего срока (скачивание пакета плагина) петля была бесконечной.
 *
 * Стенд зовёт настоящий http_get по https:// к серверу на петле. Чтение TLS — настоящий tls13.c (записи
 * ChangeCipherSpec он пропускает без расшифровки, как в tls13readmatch), а рукопожатие, запись и
 * освобождение подменены обёрткой компоновщика: до криптографии дело не доходит. Вызовы tls13_read_ref
 * считаются. Сервер принимает ClientHello и молчит — или капает служебными записями чаще срока. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "reality.h"
#include "tls13.h"
#include "httpc.h"
#include "unit.h"

static long g_calls;
int __real_tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *n);
int __wrap_tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *n) {
    g_calls++;
    return __real_tls13_read_ref(t, b, n);
}
int __wrap_tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *h, size_t hn, const unsigned char *s,
                                const struct tls13_auth *a) {
    (void)h; (void)hn; (void)s; (void)a;
    t->fd = fd;
    t->ready = 1;
    t->alpn[0] = 0;
    return 0;
}
int __wrap_tls13_write(struct tls13 *t, const unsigned char *d, size_t n) { (void)t; (void)d; (void)n; return 0; }
void __wrap_tls13_free(struct tls13 *t) { (void)t; }
const char *tls_cert_roots(void) { return NULL; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car, unsigned char *out, size_t out_n, size_t *out_len) {
    (void)cfg; (void)st; (void)car; (void)out_n;
    memset(out, 0x16, 16);
    *out_len = 16;
    return 0;
}

static long ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int g_lfd, g_port, g_mode;      /* 0 — молчать, 1 — служебная запись раз в 300 мс */
static volatile int g_stop;

static void *server(void *a) {
    (void)a;
    for (;;) {
        int c = accept(g_lfd, NULL, NULL);
        if (c < 0) return NULL;
        static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        while (!g_stop) {
            if (g_mode == 1 && send(c, ccs, sizeof ccs, MSG_NOSIGNAL) != (ssize_t)sizeof ccs) break;
            usleep(300000);
        }
        close(c);
        g_stop = 0;
    }
}

static int get_once(int mode, int idle_ms, long *dt) {
    g_mode = mode;
    char url[64], why[300] = "";
    snprintf(url, sizeof url, "https://127.0.0.1:%d/x", g_port);
    struct http_req q = { .url = url, .idle_ms = idle_ms };
    struct http_resp r = { 0 };
    g_calls = 0;
    long t0 = ms_now();
    int rc = http_get(&q, &r, why, sizeof why);
    *dt = ms_now() - t0;
    g_stop = 1;
    http_resp_free(&r);
    printf("  %s, idle %d мс: код %d через %ld мс, вызовов tls13_read_ref %ld (%s)\n",
           mode ? "служебные записи раз в 300 мс" : "сервер молчит", idle_ms, rc, *dt, g_calls, why);
    usleep(400000);
    return rc;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t sl = sizeof sa;
    if (bind(g_lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_lfd, 4) != 0) return 2;
    getsockname(g_lfd, (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, server, NULL);

    long dt;
    int rc = get_once(0, 1000, &dt);
    check("молчащий сервер: срок молчания наступает (HTTPC_ETIMEOUT)", HTTPC_ETIMEOUT, rc);
    check("  через idle_ms, а не раньше и не много позже", 1, dt >= 950 && dt < 1500);
    check("  без холостой петли (меньше сотни чтений за секунду)", 1, g_calls < 100);

    rc = get_once(1, 1000, &dt);
    check("служебные записи без данных срок молчания не продлевают", HTTPC_ETIMEOUT, rc);
    check("  срок — тот же idle_ms", 1, dt >= 950 && dt < 1500);

    check("общий срок вызова по умолчанию — 30 минут", 1800000, HTTPC_TOTAL_DEFAULT_MS);
    return unit_done("httpcspinmatch");
}
