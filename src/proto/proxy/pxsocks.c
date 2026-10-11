/* Дайлер socks: socks5 (с авторизацией и без), socks4/4a. Поток и, у socks5, UDP ASSOCIATE.
 * Эталон — RFC 1928/1929 и RFC 1928 §7 (UDP). socks без TLS: голый TCP, поэтому свой дескриптор, а
 * не struct transport.
 *
 * TCP: приветствие, при нужде авторизация имя/пароль, запрос CONNECT с адресом SOCKS5, ответ —
 * дальше поток как есть. UDP (socks5): по управляющему TCP идёт UDP ASSOCIATE, сервер называет
 * ретранслятор, датаграммы идут своим сокетом [RSV(2) FRAG(1) адрес SOCKS5 данные]. socks4/4a UDP
 * не знает — такой узел для UDP отклоняется. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pxdial.h"
#include "pxwire.h"
#include "stack.h"

struct socks_sess {
    uint8_t header_sent;
    uint8_t udp;
    int cfd;                     /* TCP: поток; UDP: управляющее соединение */
    int udpfd;                   /* UDP: сокет к ретранслятору; TCP: -1 */
    uint32_t dst; uint16_t dport;
};

static const char *sk_peer(const void *ctx) { return ((const struct px_node *)ctx)->vn.host; }
static void sk_describe(const void *ctx, char *out, size_t n) {
    const struct px_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u socks%u)", nd->name, vless_host_fmt(nd->vn.host).s, nd->vn.port, nd->socks_ver);
}

static void sk_clear(void *sess) {
    struct socks_sess *s = sess;
    s->header_sent = 0;
    s->cfd = -1;
    s->udpfd = -1;
}

static int sk_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    const struct px_node *n = ctx;
    struct socks_sess *s = sess;
    s->udp = (uint8_t)udp;
    s->dst = k->dst;
    s->dport = k->dport;
    if (udp && n->socks_ver != 5) {
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 10) { said = now;
            fprintf(stderr, "steer[warn]: socks4 не знает UDP — датаграммы узла %s не пойдут\n", n->name); }
        return -1;
    }
    return 0;
}

static int rd_full(int fd, unsigned char *b, size_t n) {
    size_t o = 0;
    while (o < n) {
        ssize_t r = read(fd, b + o, n - o);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        o += (size_t)r;
    }
    return 0;
}
static int wr_full(int fd, const unsigned char *b, size_t n) {
    size_t o = 0;
    while (o < n) {
        /* MSG_NOSIGNAL: сервер SOCKS, закрывший соединение посреди рукопожатия, — отказ, а не сигнал. */
        ssize_t w = send(fd, b + o, n - o, MSG_NOSIGNAL);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return -1; }
        o += (size_t)w;
    }
    return 0;
}

/* Приветствие и, если нужно, авторизация имя/пароль по управляющему/потоковому fd. 0 — ок. */
static int socks5_hello(int fd, const struct px_node *n) {
    unsigned char buf[2 + PX_USER_MAX + PX_PASS_MAX];
    int auth = n->user[0] != 0;
    if (auth) { unsigned char g[] = { 5, 1, 2 }; if (wr_full(fd, g, 3)) return TR_EIO; }
    else { unsigned char g[] = { 5, 1, 0 }; if (wr_full(fd, g, 3)) return TR_EIO; }
    if (rd_full(fd, buf, 2)) return TR_EIO;
    if (buf[0] != 5) return PX_EPROTO;
    if (buf[1] == 2) {
        size_t ul = strlen(n->user), pl = strlen(n->pass), o = 0;
        buf[o++] = 1;
        buf[o++] = (unsigned char)ul; memcpy(buf + o, n->user, ul); o += ul;
        buf[o++] = (unsigned char)pl; memcpy(buf + o, n->pass, pl); o += pl;
        if (wr_full(fd, buf, o)) return TR_EIO;
        if (rd_full(fd, buf, 2)) return TR_EIO;
        if (buf[1] != 0) return PX_EAUTH;
    } else if (buf[1] != 0) {
        return PX_EAUTH;
    }
    return 0;
}

/* Прочитать ответ-адрес SOCKS5 (ATYP+ADDR+PORT) после кода ответа. bnd — текстом адреса (IPv4 или
 * IPv6 по ATYP 4) для UDP ASSOCIATE; пустая строка у неуказанного 0.0.0.0 и :: и у имени (ATYP 3 —
 * как прежде, ретранслятор ждёт по адресу самого узла). Прежний код читал только ATYP 1 — ответ
 * ATYP 4 от сервера на IPv6 терялся, и датаграммы шли на адрес узла вместо названного. */
static int socks5_skip_reply_addr(int fd, char *bnd, size_t bnd_n, uint16_t *bnd_port) {
    unsigned char a[260];
    if (rd_full(fd, a, 1)) return -1;            /* ATYP */
    size_t al;
    int atyp = a[0];
    if (atyp == 1) al = 4; else if (atyp == 4) al = 16;
    else if (atyp == 3) { if (rd_full(fd, a + 1, 1)) return -1; al = a[1]; }
    else return -1;
    if (rd_full(fd, a + 2, al)) return -1;
    unsigned char port[2];
    if (rd_full(fd, port, 2)) return -1;
    if (bnd && bnd_n) {
        bnd[0] = '\0';
        static const unsigned char zero[16];
        if ((atyp == 1 || atyp == 4) && memcmp(a + 2, zero, al) != 0)
            inet_ntop(atyp == 1 ? AF_INET : AF_INET6, a + 2, bnd, (socklen_t)bnd_n);
    }
    if (bnd_port) *bnd_port = (uint16_t)((port[0] << 8) | port[1]);
    return 0;
}

static int socks5_request(int fd, uint8_t cmd, uint32_t dst, uint16_t dport,
                          char *bnd, size_t bnd_n, uint16_t *bnd_port) {
    unsigned char req[10], rep[3];
    req[0] = 5; req[1] = cmd; req[2] = 0;
    req[3] = 1; memcpy(req + 4, &dst, 4);
    req[8] = (unsigned char)(dport >> 8); req[9] = (unsigned char)dport;
    if (wr_full(fd, req, 10)) return TR_EIO;
    if (rd_full(fd, rep, 3)) return TR_EIO;
    if (rep[0] != 5) return PX_EPROTO;
    if (rep[1] != 0) return PX_EADDR;
    if (socks5_skip_reply_addr(fd, bnd, bnd_n, bnd_port) != 0) return PX_EPROTO;
    return 0;
}

static int socks4_request(int fd, uint32_t dst, uint16_t dport, const char *user) {
    unsigned char req[9 + PX_USER_MAX], rep[8];
    size_t o = 0;
    req[o++] = 4; req[o++] = 1;
    req[o++] = (unsigned char)(dport >> 8); req[o++] = (unsigned char)dport;
    memcpy(req + o, &dst, 4); o += 4;
    size_t ul = user[0] ? strlen(user) : 0;
    if (ul) { memcpy(req + o, user, ul); o += ul; }
    req[o++] = 0;
    if (wr_full(fd, req, o)) return TR_EIO;
    if (rd_full(fd, rep, 8)) return TR_EIO;
    if (rep[1] != 0x5a) return PX_EADDR;
    return 0;
}

static int sk_connect(const void *ctx, void *sess, int timeout_s) {
    const struct px_node *n = ctx;
    struct socks_sess *s = sess;
    int fd = tr_dial(n->vn.host, n->vn.port, timeout_s);
    if (fd < 0) return fd;
    int rc;
    if (n->socks_ver == 5) {
        rc = socks5_hello(fd, n);
        if (rc == 0) {
            if (!s->udp) {
                rc = socks5_request(fd, 1, s->dst, s->dport, NULL, 0, NULL);
            } else {
                char bnd[INET6_ADDRSTRLEN] = "";
                uint16_t bport = 0;
                /* UDP ASSOCIATE: адрес/порт отправителя неизвестны — 0.0.0.0:0. */
                rc = socks5_request(fd, 3, 0, 0, bnd, sizeof bnd, &bport);
                if (rc == 0) {
                    /* Ретранслятор: его порт, адрес — названный (IPv4 или IPv6), если не
                     * неуказанный 0.0.0.0/::, иначе адрес узла. */
                    const char *host = bnd[0] ? bnd : n->vn.host;
                    int uf = tr_dial_udp(host, bport);
                    if (uf < 0) rc = uf; else s->udpfd = uf;
                }
            }
        }
    } else {
        rc = s->udp ? PX_EPROTO : socks4_request(fd, s->dst, s->dport, n->user);
    }
    if (rc != 0) { close(fd); return rc; }
    /* Сокет остаётся блокирующим со сроком SO_SNDTIMEO (tr_dial), как связь транспорта у
     * остальных дайлеров: отправка (sk_send) пишет кусок целиком. Чтение — MSG_DONTWAIT. */
    s->cfd = fd;
    return 0;
}

static void sk_take(void *dst, void *src) { (void)dst; (void)src; }   /* пула нет */
static void sk_close(void *sess) {
    struct socks_sess *s = sess;
    if (s->udpfd >= 0) { close(s->udpfd); s->udpfd = -1; }
    if (s->cfd >= 0) { close(s->cfd); s->cfd = -1; }
}
static int sk_fd(const void *sess) {
    const struct socks_sess *s = sess;
    return s->udpfd >= 0 ? s->udpfd : s->cfd;
}
static int sk_has_data(const void *sess) { (void)sess; return 0; }

static int sk_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    (void)ctx; (void)k;
    struct socks_sess *s = sess;
    if (!udp) {
        /* Кусок — целиком или никак: SEND_AGAIN значит «ничего не ушло», а неблокирующий send
         * при почти полном буфере сокета отдаёт часть, и хвост терялся бы. Поэтому запись
         * блокирующая до конца куска, со сроком сокета — как tr_link_write у транспорта. */
        size_t o = 0;
        while (o < n) {
            ssize_t w = send(s->cfd, data + o, n - o, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) return SEND_FATAL;
            o += (size_t)w;
        }
        return SEND_OK;
    }
    /* data — череда [длина(2)][датаграмма]; каждая → пакет socks5 UDP. */
    const unsigned char *p = data;
    size_t left = n;
    while (left >= 2) {
        size_t dl = ((size_t)p[0] << 8) | p[1];
        p += 2; left -= 2;
        if (dl > left) return SEND_FATAL;
        unsigned char pkt[3 + 7 + UDP_DGRAM_MAX];
        size_t o = 0;
        pkt[o++] = 0; pkt[o++] = 0; pkt[o++] = 0;    /* RSV RSV FRAG */
        o += px_socks_addr(pkt + o, s->dst, s->dport);
        memcpy(pkt + o, p, dl); o += dl;
        ssize_t w = send(s->udpfd, pkt, o, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SEND_AGAIN;
        if (w != (ssize_t)o) return SEND_FATAL;
        p += dl; left -= dl;
    }
    return left ? SEND_FATAL : SEND_OK;
}

static size_t sk_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_MAX || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8); out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

static int sk_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct socks_sess *s = sess;
    *data = buf; *got = 0;
    int fd = s->udpfd >= 0 ? s->udpfd : s->cfd;
    ssize_t r = recv(fd, buf, cap, MSG_DONTWAIT);
    if (r > 0) { *got = (size_t)r; return 0; }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return -1;
}

static int sk_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess;
    if (!udp) return got ? emit(arg, rx, got) : 0;
    if (got < 3) return 0;
    /* [RSV(2) FRAG(1) адрес SOCKS5 данные]; фрагментированные (FRAG != 0) не поддерживаем. */
    if (rx[2] != 0) return 0;
    size_t o = 3, al;
    if (rx[o] == 1) al = 7; else if (rx[o] == 4) al = 19;
    else if (rx[o] == 3) { if (got < o + 2) return 0; al = 2 + rx[o + 1] + 2; }
    else return 0;
    if (got < o + al) return 0;
    return emit(arg, rx + o + al, got - o - al);
}

const struct dialer_ops proxy_socks_dialer = {
    .name = "socks",
    .caps = DC_UDP_OWN,
    .sess_size = sizeof(struct socks_sess),
    .peer = sk_peer, .describe = sk_describe, .strerror = px_strerror,
    .connect = sk_connect, .take = sk_take, .close = sk_close, .clear = sk_clear,
    .fd = sk_fd, .has_data = sk_has_data,
    .flow_open = sk_flow_open, .send = sk_send, .dgram_frame = sk_dgram_frame,
    .read = sk_read, .deliver = sk_deliver,
};
