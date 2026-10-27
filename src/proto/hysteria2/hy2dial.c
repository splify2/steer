/* Дайлер hysteria2: таблица dialer_ops (src/tunnel/dialer.h) поверх соединения QUIC в цикле рабочего
 * (hy2conn.c).
 *
 * Сессия дайлера — сам поток клиента (struct hy2_flow): ни дескриптора, ни пары сокетов. Запрос потока к
 * серверу, TCPResponse, обёртки датаграмм и их фрагментация — в hy2conn.c, а стек получает готовые
 * байты потока или целые датаграммы указателем на очередь, без копии (DC_INLOOP, подробно — у бита в
 * dialer.h).
 *
 * ЧЕГО НЕТ. Пула запасных сессий (DC_PRECONNECT): адрес назначения уходит серверу первым же
 * запросом потока, так что заранее нечего готовить, а рукопожатие с узлом у нас общее и уже сделано.
 * Переезда связи (take) поэтому нет: стек его не зовёт без пула. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "dialer.h"
#include "hy2conn.h"
#include "hy2dial.h"
#include "stack.h"
#include "tun.h"

static const char *h2_peer(const void *ctx) {
    return ((const struct hy2_node *)ctx)->host;
}

static void h2_describe(const void *ctx, char *out, size_t n) {
    const struct hy2_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u hysteria2%s%s%s)", nd->name, nd->host, nd->port,
             nd->up_bps ? " brutal" : " bbr", nd->obfs == 2 ? " +gecko" : nd->obfs ? " +salamander" : "",
             nd->hop_n ? " +hop" : "");
}

static const char *h2_strerror(int rc) {
    return hy2c_strerror(rc);
}

/* Сессию стек готовит один раз на соединение клиента, и очищается она целиком здесь: clear трогает только
 * начало (q), а остальное могло остаться от прежнего соединения слота. */
static int h2_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx;
    struct hy2_flow *f = sess;
    memset(f, 0, sizeof *f);
    f->udp = (uint8_t)udp;
    f->v6 = k->v6;
    memcpy(f->dst, flow_dst_bytes(k), flow_alen(k));
    f->dport = k->dport;
    return 0;
}

static int h2_connect(const void *ctx, void *sess, int timeout_s) {
    (void)ctx;
    return hy2c_connect(sess, timeout_s);
}

static void h2_close(void *sess) {
    hy2c_close(sess);
}

static void h2_clear(void *sess) {
    ((struct hy2_flow *)sess)->q = NULL;
}

static int h2_fd(const void *sess) {
    return hy2c_fd(sess);
}

static int h2_has_data(const void *sess) {
    return hy2c_has_data(sess);
}

static int h2_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    return hy2c_send(sess, d, n);
}

static long h2_room(const void *ctx, void *sess) {
    (void)ctx;
    return hy2c_room(sess);
}

/* Датаграмма клиента уходит серверу как есть: границы сообщений держит сам QUIC (датаграмма RFC 9221),
 * обрамления длиной, как у VLESS, не нужно. */
static size_t h2_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > cap) return 0;
    memcpy(out, p, n);
    return n;
}

static int h2_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data,
                   size_t *got) {
    (void)buf;
    return hy2c_read(sess, cap, data, got);
}

static int h2_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}

static int h2_aborted(const void *sess) {
    return hy2c_aborted(sess);
}

const struct dialer_ops hy2_dialer = {
    .name = "hysteria2",
    /* DC_INLOOP: QUIC живёт в цикле рабочего потока, у соединения клиента нет ни дескриптора, ни потока,
     * ни пары сокетов. Окно клиента — место в буфере потока QUIC (room): подтверждать нечем и незачем
     * придерживать, оно само растёт по ACK узла. */
    .caps = DC_INLOOP,
    .sess_size = sizeof(struct hy2_flow),
    .peer = h2_peer,
    .describe = h2_describe,
    .strerror = h2_strerror,
    .connect = h2_connect,
    .close = h2_close,
    .clear = h2_clear,
    .fd = h2_fd,
    .has_data = h2_has_data,
    .flow_open = h2_flow_open,
    .send = h2_send,
    .room = h2_room,
    .dgram_frame = h2_dgram_frame,
    .dgram_max = UDP_DGRAM_ABS,
    .read = h2_read,
    .deliver = h2_deliver,
    .loop_start = hy2c_loop_start,
    .loop_poll = hy2c_loop_poll,
    .loop_wait = hy2c_loop_wait,
    .loop_stop = hy2c_loop_stop,
    .aborted = h2_aborted,
};

int hy2_tunnel_run(const struct tun_out *o, const struct hy2_node *node,
                   void (*ready)(void *arg, const char *dev), void *arg) {
    if (hy2c_init(node) != 0) {
        fprintf(stderr, "steer[warn]: hysteria2: соединение с узлом %s не запустилось\n", node->name);
        return 1;
    }
    static struct dialer d;
    d.ops = &hy2_dialer;
    d.ctx = node;
    return stack_run(o, &d, ready, arg);
}
