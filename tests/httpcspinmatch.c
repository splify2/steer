/* HTTPS-клиент libsteer (httpc.c) ждёт данных сервера poll'ом, а не холостой петлёй (аудит 2.1.0, F2).
 *
 * Чтение TLS не ждёт (tls13_read_ref берёт сокет с MSG_DONTWAIT — так нужно циклу туннеля), и прежде
 * read_head и цикл тела принимали «0 байт» за порцию и звали снова: 100 % ядра на всё ожидание (PoC аудита:
 * 1,4 млн вызовов за 3 с), а срок молчания idle_ms — SO_RCVTIMEO, которого неблокирующее чтение не замечает,
 * — не наступал никогда. Без общего срока (скачивание пакета плагина) петля была бесконечной.
 *
 * Стенд включает httpc.c (read_head — static), TLS — настоящий tls13.c (криптография не нужна: записи
 * ChangeCipherSpec он пропускает без расшифровки, как в tls13readmatch), вызовы tls13_read_ref считаются
 * обёрткой компоновщика. Сервер — сокетная пара: молчит, а потом капает служебными записями чаще срока. */
#define _GNU_SOURCE
#include "../src/proto/tls/httpc.c"
#include <pthread.h>
#include <sys/socket.h>
#include "unit.h"

static long g_calls;
int __real_tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *n);
int __wrap_tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *n) {
    g_calls++;
    return __real_tls13_read_ref(t, b, n);
}
const char *tls_cert_roots(void) { return NULL; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car, unsigned char *out, size_t out_n, size_t *out_len) {
    (void)cfg; (void)st; (void)car; (void)out; (void)out_n; (void)out_len;
    return -1;
}

static struct tls13 g_t;
static int g_peer = -1;
static volatile int g_stop;

/* Служебная запись (ChangeCipherSpec) раз в 300 мс — данных нет, но сокет «живой». */
static void *ccs_drip(void *a) {
    (void)a;
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    while (!g_stop) {
        if (send(g_peer, ccs, sizeof ccs, MSG_NOSIGNAL) != (ssize_t)sizeof ccs) break;
        usleep(300000);
    }
    return NULL;
}

static int head_once(int idle_ms, long *dt) {
    struct conn *k = calloc(1, sizeof *k);
    k->fd = g_t.fd;
    k->t = &g_t;
    struct http_req q = { .url = "https://x/", .idle_ms = idle_ms };
    struct http_resp r = { 0 };
    char why[200] = "";
    struct ctx c = { .q = &q, .r = &r, .why = why, .wn = sizeof why, .sink_fd = -1 };
    struct reply y = { 0 };
    g_calls = 0;
    long t0 = mono_ms();
    int rc = read_head(&c, k, &y);
    *dt = mono_ms() - t0;
    reply_free(&y);
    free(k);
    return rc;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
    g_t.fd = sv[0];
    g_t.ready = 1;
    g_peer = sv[1];

    long dt;
    int rc = head_once(1000, &dt);
    printf("  сервер молчит, idle 1000 мс: код %d через %ld мс, вызовов tls13_read_ref %ld\n", rc, dt, g_calls);
    check("молчащий сервер: срок молчания наступает (HTTPC_ETIMEOUT)", HTTPC_ETIMEOUT, rc);
    check("  через idle_ms, а не раньше и не много позже", 1, dt >= 950 && dt < 1500);
    check("  без холостой петли (меньше сотни чтений за секунду)", 1, g_calls < 100);

    pthread_t d;
    pthread_create(&d, NULL, ccs_drip, NULL);
    rc = head_once(1000, &dt);
    g_stop = 1;
    pthread_join(d, NULL);
    printf("  служебные записи раз в 300 мс, idle 1000 мс: код %d через %ld мс, вызовов %ld\n", rc, dt, g_calls);
    check("служебные записи без данных срок молчания не продлевают", HTTPC_ETIMEOUT, rc);
    check("  срок — тот же idle_ms", 1, dt >= 950 && dt < 1500);

    check("общий срок вызова по умолчанию — 30 минут", 1800000, HTTPC_TOTAL_DEFAULT_MS);
    close(sv[0]);
    close(sv[1]);
    return unit_done("httpcspinmatch");
}
