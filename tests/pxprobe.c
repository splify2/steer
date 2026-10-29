/* pxprobe <ссылка> <tcp|udp> <адрес> <порт> [N]: прогнать поток или датаграммы через дайлер
 * протокола прокси (src/proto/proxy) до настоящего сервера (Xray) и напечатать ответы; код 0 — все
 * ответы пришли. Как tests/xudpprobe.c: дайлер драйвится напрямую (clear, flow_open, connect, send,
 * read, deliver), без TUN и стека — для проверки провода это то же, что делает стек.
 *
 * tcp: отправляет HTTP-запрос и ждёт ответ. udp: N датаграмм по одной, каждая ждёт эхо; BURST=1 —
 * три датаграммы одним send и одна 1400 байт. Стек подменён заглушками ниже. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>

#include "proxy.h"
#include "pxdial.h"
#include "dialer.h"
#include "stack.h"
#include "pool.h"

time_t stack_now_s(void) { return time(NULL); }
int stack_run(const struct tun_out *o, const struct dialer *d, stack_ready_fn ready, void *arg) {
    (void)o; (void)d; (void)ready; (void)arg; return 1;
}
int pool_run(const struct tun_out *o, const struct pool_cfg *pc, stack_ready_fn ready, void *arg) {
    (void)o; (void)pc; (void)ready; (void)arg; return 1;
}

static int g_got;
static int emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    g_got++;
    printf("  ответ %d: %zu байт: %.*s\n", g_got, n, (int)(n > 48 ? 48 : n), p);
    return 0;
}

static int pump(const struct dialer_ops *ops, const struct px_node *n, void *sess, int udp, int ms) {
    struct pollfd p = { .fd = ops->fd(sess), .events = POLLIN };
    if (poll(&p, 1, ms) <= 0 && !ops->has_data(sess)) return 0;
    static unsigned char rx[65536];
    const unsigned char *data = NULL;
    size_t got = 0;
    int rr = ops->read(sess, rx, sizeof rx, &data, &got);
    if (rr != 0) { printf("read: rc=%d\n", rr); return -1; }
    if (got && ops->deliver(n, sess, udp, data, got, emit, NULL) != 0) { printf("deliver: конец\n"); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "pxprobe <ссылка> <tcp|udp> <адрес> <порт> [N]\n"); return 2; }
    int udp = !strcmp(argv[2], "udp");
    struct px_node n;
    int rc = px_parse_url(argv[1], &n, 0);
    if (rc) { printf("узел не годен: rc=%d %s\n", rc, n.skip_reason); return 2; }
    const struct dialer_ops *ops = px_dialer_for(n.proto);
    struct flow_key k;
    memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "10.99.1.9", &k.src);
    inet_pton(AF_INET, argv[3], &k.dst);
    k.sport = 40000;
    k.dport = (uint16_t)atoi(argv[4]);
    int cnt = argc > 5 ? atoi(argv[5]) : 3;

    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    if (ops->flow_open(&n, sess, &k, udp) != 0) { printf("flow_open: отказ\n"); return 3; }
    if (ops->connect(&n, sess, 10) != 0) { printf("connect: отказ\n"); return 3; }

    if (!udp && getenv("UPLOAD")) {
        /* UPLOAD=N: N байт потоком кусками по 16000, как их отдаёт стек (SEND_AGAIN — подождать
         * и повторить тот же кусок, SEND_FATAL — провал); сервер за узлом читает медленно и в
         * конце отвечает «GOT N». Проверяет отправку под давлением: полный буфер сокета. */
        long total = atol(getenv("UPLOAD")), sent = 0;
        static unsigned char chunk[16000];
        memset(chunk, 'u', sizeof chunk);
        while (sent < total) {
            size_t c = total - sent < (long)sizeof chunk ? (size_t)(total - sent) : sizeof chunk;
            int sr = ops->send(&n, sess, &k, 0, chunk, c);
            if (sr == SEND_FATAL) { printf("upload: SEND_FATAL после %ld байт\n", sent); return 1; }
            if (sr == SEND_AGAIN) {
                struct pollfd w = { .fd = ops->fd(sess), .events = POLLOUT };
                poll(&w, 1, 100);
                continue;
            }
            sent += (long)c;
        }
        printf("upload: отправлено %ld\n", sent);
        for (int i = 0; i < 300 && g_got == 0; i++) if (pump(ops, &n, sess, 0, 200) < 0) break;
        ops->close(sess);
        return g_got ? 0 : 1;
    }

    if (!udp) {
        char req[256];
        int rl = snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", argv[3]);
        int sr = ops->send(&n, sess, &k, 0, (unsigned char *)req, (size_t)rl);
        printf("send: rc=%d\n", sr);
        for (int i = 0; i < 50 && g_got == 0; i++) if (pump(ops, &n, sess, 0, 200) < 0) break;
        ops->close(sess);
        return g_got ? 0 : 1;
    }

    if (getenv("BURST")) {
        unsigned char fr[4096];
        size_t fn = 0;
        for (int i = 0; i < 3; i++) {
            char msg[32];
            int ml = snprintf(msg, sizeof msg, "burst-%d", i);
            fn += ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr + fn, sizeof fr - fn);
        }
        printf("burst send: rc=%d\n", ops->send(&n, sess, &k, 1, fr, fn));
        unsigned char big[1400], bf[1500];
        memset(big, 'x', sizeof big);
        size_t bn = ops->dgram_frame(big, sizeof big, bf, sizeof bf);
        printf("big send: rc=%d\n", ops->send(&n, sess, &k, 1, bf, bn));
        for (int i = 0; i < 60 && g_got < 4; i++) pump(ops, &n, sess, 1, 200);
        ops->close(sess);
        return g_got >= 4 ? 0 : 1;
    }

    int want = 0;
    for (int d = 0; d < cnt; d++) {
        char msg[32];
        int ml = snprintf(msg, sizeof msg, "ping-%d", d);
        unsigned char fr[64];
        size_t fn = ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr, sizeof fr);
        if (ops->send(&n, sess, &k, 1, fr, fn) == SEND_FATAL) { printf("send fatal\n"); break; }
        want++;
        for (int i = 0; i < 30 && g_got < want; i++) pump(ops, &n, sess, 1, 100);
    }
    ops->close(sess);
    return g_got >= want && want > 0 ? 0 : 1;
}
