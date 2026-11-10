/* Общий срок установления связи с узлом (аудит 2.1.0, F1): «капельница» не держит рукопожатие бесконечно.
 *
 * Сокет к узлу блокирующий, со сроком на КАЖДОЕ чтение (SO_RCVTIMEO в trdial.c). Сервер, отдающий ответ по
 * байту чаще этого срока, держал tls13_handshake_auth часами (PoC аудита: капля раз в 700 мс при сроке 1 с —
 * через 12 с рукопожатие всё ещё ждёт), а с ним — поток установщика туннеля; 64 таких — и новые соединения
 * не открывались. Срок теперь держит слой сокетов (tr_watch_begin/tr_watch_end): по истечении сокет связи
 * закрывается на чтение и запись, и рукопожатие выходит с ошибкой.
 *
 * Стенд: настоящий tr_dial до слушателя на петле, настоящий tls13.c (криптография заглушена — до неё дело
 * не доходит: сервер не досылает даже ServerHello), сервер капает по байту раз в 300 мс при сроке чтения
 * 8 с. Без общего срока (первая проверка) рукопожатие за 3 с не кончается; со сроком 1,5 с — кончается
 * отказом около 1,5 с, а tr_watch_end говорит «срок вышел». Срок, не вышедший, ничего не трогает. */
#define _GNU_SOURCE
#include <pthread.h>
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

/* Хеш рукопожатия — заглушка: ClientHello вбирается в транскрипт до первого чтения. */
size_t sc_hash_len(enum sc_hash h) { return h == SC_SHA384 ? 48 : h == SC_SHA512 ? 64 : 32; }
int sc_hash_init(struct sc_hash_ctx *c, enum sc_hash h) { c->alg = h; return 0; }
int sc_hash_update(struct sc_hash_ctx *c, const void *d, size_t n) { (void)c; (void)d; (void)n; return 0; }
int sc_hash_final(struct sc_hash_ctx *c, unsigned char *out) { memset(out, 0, sc_hash_len(c->alg)); return 0; }
int sc_hash_clone(struct sc_hash_ctx *dst, const struct sc_hash_ctx *src) { *dst = *src; return 0; }
void sc_hash_free(struct sc_hash_ctx *c) { c->alg = 0; }

static long ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int g_srv = -1;
static volatile int g_stop;

/* Запись ServerHello на 16383 байта — по байту раз в 300 мс. */
static void *drip(void *a) {
    (void)a;
    static const unsigned char hdr[5] = { 0x16, 3, 3, 0x3f, 0xff };
    for (int i = 0; !g_stop; i++) {
        unsigned char b = i < 5 ? hdr[i] : 0;
        if (send(g_srv, &b, 1, MSG_NOSIGNAL) != 1) break;
        usleep(300000);
    }
    return NULL;
}

static struct tls13 g_t;
static int g_rc;
static long g_ms;
static int g_fd = -1;
static volatile int g_done;

static void *hs(void *a) {
    (void)a;
    unsigned char hello[64] = { 0x16, 3, 1, 0, 59, 1 }, priv[32] = { 0 };
    struct tls13_auth au = { .host = "example.com" };
    long t0 = ms_now();
    g_rc = tls13_handshake_auth(&g_t, g_fd, hello, sizeof hello, priv, &au);
    g_ms = ms_now() - t0;
    g_done = 1;
    return NULL;
}

static int listener(uint16_t *port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (l < 0 || bind(l, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(l, 4) != 0 ||
        getsockname(l, (struct sockaddr *)&sa, &sl) != 0) return -1;
    *port = ntohs(sa.sin_port);
    return l;
}

/* Одно рукопожатие против капельницы; scope_ms > 0 — внутри общего срока. Возвращает, ответил ли
 * tr_watch_end «срок вышел» (-1 — срока не было). Ждёт не дольше wait_ms. */
static int run(int scope_ms, int wait_ms) {
    uint16_t port;
    int l = listener(&port);
    if (l < 0) return -2;
    if (scope_ms > 0) tr_watch_begin(scope_ms);
    g_fd = tr_dial("127.0.0.1", port, 8);
    g_srv = accept(l, NULL, NULL);
    close(l);
    g_stop = 0;
    g_done = 0;
    memset(&g_t, 0, sizeof g_t);
    pthread_t d, h;
    pthread_create(&d, NULL, drip, NULL);
    pthread_create(&h, NULL, hs, NULL);
    for (int i = 0; i < wait_ms / 10 && !g_done; i++) usleep(10000);
    int fired = -1;
    if (g_done) {
        pthread_join(h, NULL);
        if (scope_ms > 0) fired = tr_watch_end();
    } else {
        /* Не дождались — так и задумано в первой проверке: обрываем сами, чтобы стенд не висел. */
        shutdown(g_fd, SHUT_RDWR);
        pthread_join(h, NULL);
        if (scope_ms > 0) fired = tr_watch_end();
        g_ms = -1;
    }
    g_stop = 1;
    shutdown(g_srv, SHUT_RDWR);
    pthread_join(d, NULL);
    close(g_srv);
    if (g_fd >= 0) close(g_fd);
    tls13_free(&g_t);
    return fired;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* Без общего срока — прежнее поведение: каждый байт продлевает срок чтения, и за 3 с рукопожатие не
     * кончается (дальше стенд обрывает его сам). */
    run(0, 3000);
    printf("  без общего срока: %s\n", g_ms < 0 ? "через 3 с рукопожатие ещё ждёт" : "кончилось");
    check("без общего срока капельница держит рукопожатие (проверка стенда)", -1, g_ms < 0 ? -1 : 0);

    int fired = run(1500, 6000);
    printf("  срок 1,5 с: рукопожатие вернуло %d через %ld мс\n", g_rc, g_ms);
    check("со сроком 1,5 с рукопожатие кончается", 1, g_ms >= 0);
    check("  не раньше срока и не позже чем через 1 с после него", 1, g_ms >= 1400 && g_ms < 2500);
    check("  отказом, а не успехом", 1, g_rc != 0);
    check("  tr_watch_end: срок вышел", 1, fired);

    /* Срок, который не вышел, сокета не трогает: соединились, сказали и закрыли — end отвечает 0. */
    uint16_t port;
    int l = listener(&port);
    tr_watch_begin(5000);
    int fd = tr_dial("127.0.0.1", port, 8);
    int s = accept(l, NULL, NULL);
    int w = (int)send(fd, "x", 1, MSG_NOSIGNAL);
    char b = 0;
    int r = (int)recv(s, &b, 1, 0);
    check("срок не вышел: tr_watch_end отвечает 0", 0, tr_watch_end());
    int w2 = (int)send(fd, "y", 1, MSG_NOSIGNAL);
    check("  сокет после снятия срока жив (запись и чтение идут)", 1, w == 1 && r == 1 && b == 'x' && w2 == 1);
    close(fd); close(s); close(l);

    /* Вне срока tr_watch_end — ноль, ничего не держится. */
    check("вне срока tr_watch_end отвечает 0", 0, tr_watch_end());
    return unit_done("hsdlmatch");
}
