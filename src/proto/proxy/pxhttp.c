/* Дайлер http: прокси HTTP CONNECT, по желанию поверх TLS, с базовой авторизацией. UDP у CONNECT
 * нет (docs/proxy.md). Поток — поверх общего транспорта (type=tcp, security=none или tls).
 *
 * Рукопожатие: CONNECT адрес:порт HTTP/1.1, ответ 200 — дальше поток цели как есть. Адрес — IPv4
 * клиента (имён не передаём). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

#include "pxdial.h"
#include "stack.h"

#define HT_RESP_MAX 1024

struct http_sess {
    uint8_t established;
    uint16_t pend_off, pend_n;   /* байты цели, пришедшие вместе с ответом 200 (pend) */
    uint32_t dst; uint16_t dport;
    unsigned char dst6[16];
    int ipv6;
    struct transport t;
    unsigned char pend[HT_RESP_MAX];
};

static const char *ht_peer(const void *ctx) { return ((const struct px_node *)ctx)->vn.host; }
static void ht_describe(const void *ctx, char *out, size_t n) {
    const struct px_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u http/%s)", nd->name, nd->vn.host, nd->vn.port, nd->vn.security);
}

static void ht_clear(void *sess) {
    struct http_sess *s = sess;
    s->established = 0;
    s->pend_off = s->pend_n = 0;
    s->t.link.fd = -1;
}

static int ht_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    struct http_sess *s = sess;
    if (udp) {
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 10) { said = now;
            fprintf(stderr, "steer[warn]: http CONNECT не несёт UDP — датаграммы узла %s не пойдут\n",
                    ((const struct px_node *)ctx)->name); }
        return -1;
    }
    s->dst = k->dst;
    s->ipv6 = flow_is6(k);
    memcpy(s->dst6, k->dst6, 16);
    s->dport = k->dport;
    return 0;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t b64enc(const unsigned char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? B64[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

/* Рукопожатие CONNECT: собрать запрос, прочитать ответ до конца заголовков, проверить «200». */
static int http_connect(const struct px_node *n, struct http_sess *s, int timeout_s) {
    char ip[INET6_ADDRSTRLEN + 2];
    struct in_addr a = { .s_addr = s->dst };
    if (s->ipv6) {
        char numeric[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, s->dst6, numeric, sizeof(numeric))) return PX_EPROTO;
        snprintf(ip, sizeof(ip), "[%s]", numeric);
    } else if (!inet_ntop(AF_INET, &a, ip, sizeof(ip))) return PX_EPROTO;
    /* Буфер — под самые длинные имя и пароль узла: строка CONNECT (до 70 знаков), Basic от
     * «имя:пароль» (до 4/3 от PX_USER_MAX + PX_PASS_MAX) и обрамление. Прежние 512 не вмещали
     * длинный Basic, а длина снова прибавлялась к rl — следующий snprintf писал за буфер. */
    char cred[PX_USER_MAX + PX_PASS_MAX + 2], b64[((PX_USER_MAX + PX_PASS_MAX + 2) * 4) / 3 + 8];
    char req[256 + sizeof b64];
    b64[0] = '\0';
    if (n->user[0]) {
        int cl = snprintf(cred, sizeof cred, "%s:%s", n->user, n->pass);
        b64enc((const unsigned char *)cred, (size_t)cl, b64);
    }
    int rl = snprintf(req, sizeof req, "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n%s%s%s\r\n",
                      ip, s->dport, ip, s->dport, b64[0] ? "Proxy-Authorization: Basic " : "",
                      b64, b64[0] ? "\r\n" : "");
    if (rl < 0 || (size_t)rl >= sizeof req) return TR_EIO;
    if (transport_write(&s->t, (const unsigned char *)req, (size_t)rl)) return TR_EIO;

    char resp[HT_RESP_MAX];
    size_t rn = 0;
    int64_t deadline_ms;
    { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
      deadline_ms = (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000 + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000; }
    for (;;) {
        size_t got = 0;
        int rc = transport_read(&s->t, (unsigned char *)resp + rn, sizeof resp - 1 - rn, &got);
        if (rc) return rc;
        if (got) {
            rn += got;
            resp[rn] = '\0';
            if (strstr(resp, "\r\n\r\n")) break;
            if (rn >= sizeof resp - 1) return PX_EPROTO;
            continue;
        }
        struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
        if ((int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000 >= deadline_ms) return TR_EIO;
        struct pollfd pw = { .fd = transport_fd(&s->t), .events = POLLIN };
        poll(&pw, 1, 200);
    }
    /* «HTTP/1.1 200 …» */
    if (strncmp(resp, "HTTP/1.", 7) != 0) return PX_EPROTO;
    const char *sp = strchr(resp, ' ');
    if (!sp || sp[1] != '2' || sp[2] != '0' || sp[3] != '0') return PX_EADDR;
    /* Что пришло за пустой строкой — уже поток цели (сервер, который говорит первым: SSH, SMTP);
     * его отдаёт первое чтение (ht_read), а не выбрасывает рукопожатие. */
    size_t hl = (size_t)(strstr(resp, "\r\n\r\n") - resp) + 4;
    s->pend_off = 0;
    s->pend_n = (uint16_t)(rn - hl);
    memcpy(s->pend, resp + hl, rn - hl);
    return 0;
}

static int ht_connect(const void *ctx, void *sess, int timeout_s) {
    const struct px_node *n = ctx;
    struct http_sess *s = sess;
    int rc = px_stream_open(n, &s->t, timeout_s);
    if (rc == 0) rc = http_connect(n, s, timeout_s);
    if (rc) { transport_close(&s->t); return rc; }
    s->established = 1;
    return 0;
}

static void ht_take(void *dst, void *src) { (void)dst; (void)src; }   /* пула нет */
static void ht_close(void *sess) { transport_close(&((struct http_sess *)sess)->t); }
static int ht_fd(const void *sess) { return transport_fd(&((const struct http_sess *)sess)->t); }
static int ht_has_data(const void *sess) {
    const struct http_sess *s = sess;
    return s->pend_off < s->pend_n || transport_has_data(&s->t);
}

static int ht_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    (void)ctx; (void)k; (void)udp;
    struct http_sess *s = sess;
    int rc = transport_write(&s->t, data, n);
    if (rc == H2_EWINDOW) return SEND_AGAIN;
    return rc ? SEND_FATAL : SEND_OK;
}

static size_t ht_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    (void)p; (void)n; (void)out; (void)cap;
    return 0;                                    /* UDP нет (ht_flow_open отклоняет) */
}

static int ht_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct http_sess *s = sess;
    if (s->pend_off < s->pend_n) {
        size_t k = (size_t)(s->pend_n - s->pend_off);
        if (k > cap) k = cap;
        memcpy(buf, s->pend + s->pend_off, k);
        s->pend_off = (uint16_t)(s->pend_off + k);
        *data = buf; *got = k;
        return 0;
    }
    return transport_read_zc(&s->t, buf, cap, data, got);
}

static int ht_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return got ? emit(arg, rx, got) : 0;
}

const struct dialer_ops proxy_http_dialer = {
    .name = "http",
    .caps = 0,
    .sess_size = sizeof(struct http_sess),
    .peer = ht_peer, .describe = ht_describe, .strerror = px_strerror,
    .connect = ht_connect, .take = ht_take, .close = ht_close, .clear = ht_clear,
    .fd = ht_fd, .has_data = ht_has_data,
    .flow_open = ht_flow_open, .send = ht_send, .dgram_frame = ht_dgram_frame,
    .read = ht_read, .deliver = ht_deliver,
};
