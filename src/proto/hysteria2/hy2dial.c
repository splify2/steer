/* Дайлер hysteria2: таблица dialer_ops (src/tunnel/dialer.h) поверх мультиплексора hy2conn.c.
 *
 * Сессия дайлера — один дескриптор: клиентский конец пары SOCK_SEQPACKET, второй конец которой
 * держит мультиплексор. Всё, что делает дайлер VLESS с транспортом, здесь — send/recv на
 * сокете: запрос потока к серверу, TCPResponse, обёртки и фрагментация уже на стороне
 * мультиплексора, а стек получает готовые байты потока или целые датаграммы.
 *
 * ЧЕГО НЕТ. Пула запасных сессий (DC_PRECONNECT): адрес назначения уходит серверу первым же
 * запросом потока, так что заранее нечего готовить, а рукопожатие с узлом у нас общее и уже сделано.
 * Переезда связи (take) поэтому нет: стек его не зовёт без пула. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dialer.h"
#include "hy2conn.h"
#include "hy2dial.h"
#include "stack.h"
#include "tun.h"

struct hy2_sess {
    int fd;                     /* первым полем: clear трогает только начало */
    int udp;
    uint32_t dst;               /* IPv4 назначения, сетевой порядок */
    uint16_t dport;
};

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

static int h2_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx;
    struct hy2_sess *s = sess;
    s->udp = udp;
    s->dst = k->dst;
    s->dport = k->dport;
    return 0;
}

static int h2_connect(const void *ctx, void *sess, int timeout_s) {
    (void)ctx;
    struct hy2_sess *s = sess;
    char host[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = s->dst };
    inet_ntop(AF_INET, &a, host, sizeof host);
    int fd = hy2c_open(s->udp, host, s->dport, timeout_s);
    /* Исход слежке за узлом: «сервер отказал в этом адресе» узел не порочит — он ответил. */
    hy2_watch_seen(fd >= 0 || fd == HY2E_DENIED || fd == HY2E_NOUDP ? 0 : fd);
    if (fd < 0) return fd;
    s->fd = fd;
    return 0;
}

static void h2_take(void *dst, void *src) {
    (void)dst; (void)src;       /* запасных сессий нет */
}

static void h2_close(void *sess) {
    struct hy2_sess *s = sess;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}

static void h2_clear(void *sess) {
    struct hy2_sess *s = sess;
    s->fd = -1;
}

static int h2_fd(const void *sess) {
    return ((const struct hy2_sess *)sess)->fd;
}

static int h2_has_data(const void *sess) {
    (void)sess;
    return 0;                   /* своего буфера нет: всё, что пришло, лежит в сокете */
}

/* Одна запись — одно сообщение: либо принято целиком, либо ничего (SEQPACKET). */
static int h2_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    struct hy2_sess *s = sess;
    if (!n) return SEND_OK;
    ssize_t w = send(s->fd, d, n, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (w == (ssize_t)n) return SEND_OK;
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == EINTR))
        return SEND_AGAIN;
    return SEND_FATAL;
}

/* Датаграмма клиента уходит серверу как есть: границы сообщений держит сокет, обрамления
 * длиной, как у VLESS, не нужно. */
static size_t h2_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > cap) return 0;
    memcpy(out, p, n);
    return n;
}

static int h2_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data,
                   size_t *got) {
    struct hy2_sess *s = sess;
    *got = 0;
    *data = buf;
    /* Датаграмма UDP приходит одним сообщением SEQPACKET, и сообщение длиннее буфера чтения
     * ядро обрезает, а остаток выбрасывает: клиент получил бы обрубок под видом целой
     * датаграммы. Буфер стека (TUNNEL_BUF) меньше самой крупной датаграммы (UDP_DGRAM_ABS),
     * поэтому читаем в свой, по размеру протокола. Поток TCP режется на куски не больше
     * буфера стека (CHUNK в hy2conn.c) и читается как раньше. */
    if (s->udp) {
        static __thread unsigned char big[UDP_DGRAM_ABS];
        buf = big;
        cap = sizeof big;
        *data = big;
    }
    ssize_t r = recv(s->fd, buf, cap, MSG_DONTWAIT);
    if (r > 0) { *got = (size_t)r; return 0; }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return -1;                  /* 0 — сервер закончил передачу, иначе ошибка сокета */
}

static int h2_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}

const struct dialer_ops hy2_dialer = {
    .name = "hysteria2",
    /* DC_ACK_PACED: очередь к мультиплексору — пара SEQPACKET, и мультиплексор (один поток: шифр
     * QUIC и системный вызов на каждую датаграмму) разбирает её медленнее, чем клиент способен
     * лить. Стек подтверждает данные клиента, только пока дескриптор готов к записи, — иначе
     * очередь переполнялась, и выгрузка вставала (подробно — у бита в dialer.h). Окно клиента — не
     * больше того, что вмещает очередь пары (HY2_CLIENT_WND, hy2conn.h): потолок стека — мегабайты. */
    .caps = DC_ACK_PACED,
    .rcv_wnd_max = HY2_CLIENT_WND,
    .sess_size = sizeof(struct hy2_sess),
    .peer = h2_peer,
    .describe = h2_describe,
    .strerror = h2_strerror,
    .connect = h2_connect,
    .take = h2_take,
    .close = h2_close,
    .clear = h2_clear,
    .fd = h2_fd,
    .has_data = h2_has_data,
    .flow_open = h2_flow_open,
    .send = h2_send,
    .dgram_frame = h2_dgram_frame,
    .dgram_max = UDP_DGRAM_ABS,
    .read = h2_read,
    .deliver = h2_deliver,
};

int hy2_tunnel_run(struct output *o, const struct hy2_node *node,
                   void (*ready)(void *arg, const char *dev), void *arg) {
    if (hy2c_start(node) != 0) {
        fprintf(stderr, "steer[warn]: hysteria2: соединение с узлом %s не запустилось\n", node->name);
        return 1;
    }
    static struct dialer d;
    d.ops = &hy2_dialer;
    d.ctx = node;
    return stack_run(o, &d, ready, arg);
}
