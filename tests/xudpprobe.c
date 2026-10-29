/* xudpprobe <ссылка vless://> <адрес> <порт> [N]: прогнать датаграммы UDP через дайлер VLESS (vldial.c) до
 * настоящего сервера и напечатать ответы; код возврата 0 — все ответы пришли.
 *
 * Дайлер драйвится напрямую (connect, flow_open, dgram_frame, send, read, deliver), без TUN и стека: для
 * проверки провода это то же самое, что делает стек, а поднимать устройство ради него не нужно (и нельзя
 * без root). Так проверяется именно то, что отправляет и разбирает клиент: у узла с flow=xtls-rprx-vision
 * UDP идёт командой Mux с рамками XUDP (vldial.c, блок XUDP), у узла без flow — командой 2.
 *
 * N датаграмм по одной, каждая ждёт эхо. BURST=1 — вместо этого три датаграммы ОДНИМ вызовом send (так их
 * склеивает early_hold стека, пока идёт рукопожатие) и затем датаграмма 1400 байт: рамки нескольких
 * датаграмм в одной записи и рамка, которая не влезает в одну запись TLS у мелкого MTU.
 *
 * Стек подменён заглушками ниже: vldial.c зовёт из него три функции, а стек в стенд не входит. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include "vless.h"
#include "vldial.h"
#include "dialer.h"
#include "stack.h"
#include "pool.h"

time_t stack_now_s(void) { return time(NULL); }
int stack_run(const struct tun_out *o, const struct dialer *d, stack_ready_fn ready, void *arg) {
    (void)o; (void)d; (void)ready; (void)arg;
    return 1;
}
int pool_run(const struct tun_out *o, const struct pool_cfg *pc, stack_ready_fn ready, void *arg) {
    (void)o; (void)pc; (void)ready; (void)arg;
    return 1;
}

static int g_got;
static int emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    g_got++;
    printf("  ответ %d: %zu байт: %.*s\n", g_got, n, (int)(n > 40 ? 40 : n), p);
    return 0;
}

/* Прочитать и разобрать всё, что пришло за ~100 мс. -11 у read — «данных пока нет», не отказ. */
static int pump(const struct dialer_ops *ops, const struct vless_node *n, void *sess) {
    static unsigned char rx[65536];
    struct pollfd p = { .fd = ops->fd(sess), .events = POLLIN };
    if (poll(&p, 1, 100) <= 0 && !ops->has_data(sess)) return 0;
    const unsigned char *data = NULL;
    size_t got = 0;
    int rr = ops->read(sess, rx, sizeof rx, &data, &got);
    if (rr != 0 && rr != -11) { printf("read: rc=%d\n", rr); return -1; }
    if (got && ops->deliver(n, sess, 1, data, got, emit, NULL) != 0) { printf("deliver: конец потока\n"); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "xudpprobe <ссылка> <адрес> <порт> [N]\n"); return 2; }
    struct vless_node n;
    int rc = vless_parse_url(argv[1], &n);
    if (rc) { printf("узел не годен: rc=%d %s\n", rc, n.skip_reason); return 2; }
    struct flow_key k;
    memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "10.99.1.9", &k.src);
    inet_pton(AF_INET, argv[2], &k.dst);
    k.sport = 40000;
    k.dport = (uint16_t)atoi(argv[3]);
    int cnt = argc > 4 ? atoi(argv[4]) : 3;
    const struct dialer_ops *ops = &vless_dialer;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    if (ops->connect(&n, sess, 10) != 0) { printf("connect: отказ\n"); return 3; }
    if (ops->flow_open(&n, sess, &k, 1) != 0) { printf("flow_open: отказ\n"); return 3; }

    if (getenv("BURST")) {
        unsigned char fr[4000];
        size_t fn = 0;
        for (int i = 0; i < 3; i++) {
            char msg[32];
            int ml = snprintf(msg, sizeof msg, "burst-%d", i);
            fn += ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr + fn, sizeof fr - fn);
        }
        printf("burst send: rc=%d\n", ops->send(&n, sess, &k, 1, fr, fn));
        unsigned char big[1400];
        memset(big, 'B', sizeof big);
        fn = ops->dgram_frame(big, sizeof big, fr, sizeof fr);
        printf("big send: rc=%d\n", ops->send(&n, sess, &k, 1, fr, fn));
        for (int t = 0; t < 60 && g_got < 4; t++)
            if (pump(ops, &n, sess) != 0) return 4;
        printf(g_got == 4 ? "ok burst\n" : "FAIL burst: ответов %d\n", g_got);
        ops->close(sess);
        return g_got == 4 ? 0 : 6;
    }
    for (int i = 0; i < cnt; i++) {
        char msg[64];
        int ml = snprintf(msg, sizeof msg, "xudp-ping-%d", i);
        unsigned char fr[200];
        size_t fn = ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr, sizeof fr);
        printf("send %d: rc=%d\n", i, ops->send(&n, sess, &k, 1, fr, fn));
        int before = g_got;
        for (int t = 0; t < 30 && g_got == before; t++)
            if (pump(ops, &n, sess) != 0) return 4;
        if (g_got == before) { printf("нет ответа на %d\n", i); return 6; }
    }
    printf("ok: %d ответов\n", g_got);
    ops->close(sess);
    return 0;
}
