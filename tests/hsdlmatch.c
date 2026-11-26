/* Общий срок установления: tr_dial регистрирует локальную socketpair через
 * тестовый шов, TLS получает штатный frozen ClientHello и ждёт ответа на
 * пустом сокете. Конечное ожидание и отдельный бракованный Hello отличают
 * таймаут от немедленного отказа парсера. Сеть и криптография не нужны. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "transport.h"
#include "tls13.h"
#include "scrypto.h"
#include "unit.h"
#include "chello-frozen.h"
#include "tls13_offered.h"
/* Швы только этой сборки: сам tr_dial и сторож остаются настоящими. */
void hsdl_test_restart_watch(int fd, int ms);

/* Хеш рукопожатия — заглушка: ClientHello вбирается в транскрипт до первого чтения. */
static atomic_int g_hello_hashed;
size_t sc_hash_len(enum sc_hash h) { return h == SC_SHA384 ? 48 : h == SC_SHA512 ? 64 : 32; }
int sc_hash_init(struct sc_hash_ctx *c, enum sc_hash h) { c->alg = h; return 0; }
int sc_hash_update(struct sc_hash_ctx *c, const void *d, size_t n) { (void)c; (void)d; (void)n; atomic_store(&g_hello_hashed, 1); return 0; }
int sc_hash_final(struct sc_hash_ctx *c, unsigned char *out) { memset(out, 0, sc_hash_len(c->alg)); return 0; }
int sc_hash_clone(struct sc_hash_ctx *dst, const struct sc_hash_ctx *src) { *dst = *src; return 0; }
void sc_hash_free(struct sc_hash_ctx *c) { c->alg = 0; }

static long ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int g_srv = -1;
int hsdl_test_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port; (void)timeout_s;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return -1;
    g_srv = pair[1];
    return pair[0];
}

static struct tls13 g_t;
static int g_rc;
static long g_ms;
static int g_fd = -1;
static atomic_int g_done;
static int g_bad;

static void *hs(void *a) {
    (void)a;
    const unsigned char bad[64] = { 0x16, 3, 1, 0, 59, 1 };
    const unsigned char *hello = g_bad ? bad : (const unsigned char *)FROZEN_AES;
    size_t hello_n = g_bad ? sizeof bad : FROZEN_N;
    unsigned char priv[32] = { 0 };
    struct tls13_auth au = { .host = "example.com" };
    long t0 = ms_now();
    g_rc = tls13_handshake_auth(&g_t, g_fd, hello, hello_n, priv, &au);
    g_ms = ms_now() - t0;
    g_done = 1;
    return NULL;
}

/* Ожидание ограничено; main открывает scope и регистрирует socketpair через tr_dial. */
static int run(int scope_ms, int wait_ms, int bad) {
    g_bad = bad;
    g_srv = -1;
    g_fd = -1;
    g_ms = -2;
    g_rc = 0;
    atomic_store(&g_done, 0);
    atomic_store(&g_hello_hashed, 0);
    if (scope_ms > 0) tr_watch_begin(scope_ms);
    g_fd = tr_dial("fixture", 443, 8);
    if (g_fd < 0 || g_srv < 0) {
        if (scope_ms > 0) tr_watch_end();
        return -2;
    }
    memset(&g_t, 0, sizeof g_t);
    pthread_t h;
    if (pthread_create(&h, NULL, hs, NULL) != 0) {
        if (scope_ms > 0) tr_watch_end();
        close(g_fd); close(g_srv);
        return -2;
    }
    long end = ms_now() + wait_ms;
    while (ms_now() < end && !atomic_load(&g_done)) usleep(10000);
    int finished = atomic_load(&g_done);
    if (!finished) shutdown(g_fd, SHUT_RDWR);
    pthread_join(h, NULL);
    int fired = scope_ms > 0 ? tr_watch_end() : -1;
    if (!finished) g_ms = -1;
    close(g_fd); close(g_srv);
    tls13_free(&g_t);
    return fired;
}

/* Один scope: реальный обмен через секунду не должен сдвинуть дедлайн.
 * В отрицательном контроле намеренно подменяем срок после обмена новым. */
static int absolute_budget(int refresh) {
    long start = ms_now();
    tr_watch_begin(2000);
    int fd = tr_dial("fixture", 443, 8), peer = g_srv;
    if (fd < 0 || peer < 0) { tr_watch_end(); return 0; }
    usleep(1000000);
    char b = 0;
    int progressed = send(peer, "p", 1, MSG_NOSIGNAL) == 1 &&
                     recv(fd, &b, 1, MSG_DONTWAIT) == 1 && b == 'p';
    if (refresh) hsdl_test_restart_watch(fd, 2000);
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int ready = poll(&p, 1, 4000);
    long elapsed = ms_now() - start;
    int fired = tr_watch_end();
    close(fd); close(peer);
    printf("  бюджет: обмен=%d, срок=%ld мс, fired=%d%s\n",
           progressed, elapsed, fired, refresh ? " (с подменой)" : "");
    return progressed && ready == 1 && fired == 1 && elapsed >= 1850 && elapsed < 2600;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct tls13_offered offer;
    check("штатный AES ClientHello принят парсером", 0,
          parse_client_offer((const unsigned char *)FROZEN_AES + 5, FROZEN_N - 5, &offer));
    check("штатный ChaCha ClientHello принят парсером", 0,
          parse_client_offer((const unsigned char *)FROZEN_CHACHA + 5, FROZEN_N - 5, &offer));
    int fired = run(1500, 3000, 1);
    check("негодный ClientHello отвергнут парсером", TLS13_EBADREC, g_rc);
    check("немедленный отказ — не таймаут сторожа", 0, fired);
    check("негодный Hello отвергнут до срока", 1, g_ms >= 0 && g_ms < 1400);

    run(0, 1000, 0);
    check("без общего срока штатное рукопожатие ждёт ответ", -1, g_ms);
    check("  штатный ClientHello принят и добавлен в транскрипт", 1, atomic_load(&g_hello_hashed));
    fired = run(1500, 6000, 0);
    printf("  срок 1,5 с: рукопожатие вернуло %d через %ld мс\n", g_rc, g_ms);
    check("со сроком 1,5 с рукопожатие кончается", 1, g_ms >= 0);
    check("  не раньше срока и не позже чем через 1 с после него", 1, g_ms >= 1400 && g_ms < 2500);
    check("  отказом, но не отказом парсера", 1, g_rc != 0 && g_rc != TLS13_EBADREC);
    check("  tr_watch_end: срок вышел", 1, fired);
    check("прогресс не продлевает исходный общий срок", 1, absolute_budget(0));
    check("подмена исходного срока новым интервалом обнаруживается", 0, absolute_budget(1));

    tr_watch_begin(5000);
    int fd = tr_dial("fixture", 443, 8);
    int peer = g_srv;
    int w = (int)send(fd, "x", 1, MSG_NOSIGNAL);
    char b = 0;
    int r = (int)recv(peer, &b, 1, 0);
    check("срок не вышел: tr_watch_end отвечает 0", 0, tr_watch_end());
    int w2 = (int)send(fd, "y", 1, MSG_NOSIGNAL);
    check("  сокет после снятия срока жив", 1, w == 1 && r == 1 && b == 'x' && w2 == 1);
    close(fd); close(peer);
    check("вне срока tr_watch_end отвечает 0", 0, tr_watch_end());
    return unit_done("hsdlmatch");
}
