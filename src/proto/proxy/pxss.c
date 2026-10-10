/* Дайлер shadowsocks: AEAD (aes-128/256-gcm, chacha20-ietf-poly1305), SIP022 2022-blake3-* и
 * none/plain. Эталоны — shadowsocks-libev (AEAD), spec SIP022 и sing-box (2022).
 *
 * TCP: соль(keylen) ‖ куски AEAD [длина(2)+тег][данные+тег], nonce — счётчик LE с нуля, +1 на
 * каждую операцию. Первый кусок данных начинается с адреса SOCKS5. 2022 вместо этого: соль ‖ [EIH*]
 * ‖ фикс-заголовок (type,timestamp,длина var) ‖ var-заголовок (адрес, набивка, данные), дальше —
 * те же куски. Поток — поверх общего транспорта (ss без TLS: голый TCP, security=none).
 *
 * UDP (своим сокетом к узлу, DC_UDP_OWN): каждая датаграмма — соль ‖ AEAD(nonce=0, адрес ‖ данные).
 * У 2022 UDP формат иной (сессии, AES-ECB заголовок) — он не поддержан, UDP такого узла отклоняется
 * с причиной (docs/proxy.md). none — без шифрования: [адрес][данные]. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "pxdial.h"
#include "pxwire.h"
#include "stack.h"
#include "scrypto.h"

#define SS_CHUNK 0x3FFF          /* предел куска AEAD (SIP004); отправляем такими же и в 2022 */
#define SS2022_CHUNK 0xFFFF      /* предел куска SIP022: сервер 2022 вправе прислать столько */

enum { RS_SALT = 0, RS_FIXED, RS_LEN, RS_PAY };

struct ss_sess {
    uint8_t header_sent;
    uint8_t udp;
    int udpfd;                   /* UDP-own: сокет к узлу; TCP: -1 */
    struct transport t;

    uint8_t is2022, has_enc, has_dec;
    uint8_t rx;                  /* RS_* */
    size_t keylen;
    struct sc_aead enc, dec;
    unsigned char snonce[12], rnonce[12];
    unsigned char salt_sent[32];
    uint32_t dst; uint16_t dport;

    size_t acc_n, want;          /* накопитель и сколько байт ждём на стадии */
    /* Расшифрованный кусок, который за один проход не влез в место стека, лежит в acc
     * [out_off, out_n): ss_read отдаёт его следующим проходом, а у сокета в это время не читает. */
    size_t out_off, out_n;
    uint8_t flushing;            /* ss_read только что вернул остаток — deliver отдаёт его как есть */
    /* Под наибольший кусок, какой может прислать сервер (SIP022 — 0xFFFF и тег). Страницы
     * таблицы сессий стек отображает лениво: хвост буфера занимает память, только когда кусок
     * больше 0x3FFF на самом деле пришёл. */
    unsigned char acc[SS2022_CHUNK + 16];
};

static const char *ss_peer(const void *ctx) { return ((const struct px_node *)ctx)->vn.host; }
static void ss_describe(const void *ctx, char *out, size_t n) {
    const struct px_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u shadowsocks)", nd->name, nd->vn.host, nd->vn.port);
}

static enum sc_aead_alg ss_alg(enum ss_method m) {
    switch (m) {
    case SS_AES128_GCM: case SS_2022_AES128: return SC_AES128_GCM;
    case SS_AES256_GCM: case SS_2022_AES256: return SC_AES256_GCM;
    case SS_CHACHA20_POLY1305: case SS_2022_CHACHA20: return SC_CHACHA20_POLY1305;
    default: return (enum sc_aead_alg)0;
    }
}

static void nonce_inc(unsigned char n[12]) {
    for (int i = 0; i < 12; i++) if (++n[i]) break;
}

static void ss_clear(void *sess) {
    struct ss_sess *s = sess;
    s->header_sent = 0;
    s->udpfd = -1;
    s->is2022 = s->has_enc = s->has_dec = 0;
    s->rx = RS_SALT;
    s->acc_n = s->want = 0;
    s->out_off = s->out_n = 0; s->flushing = 0;
    s->t.link.fd = -1;
}

static int ss_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    const struct px_node *n = ctx;
    struct ss_sess *s = sess;
    s->udp = (uint8_t)udp;
    s->dst = k->dst;
    s->dport = k->dport;
    s->keylen = n->ss_key_n ? n->ss_key_n : 16;
    s->is2022 = n->ss_method >= SS_2022_AES128;
    if (udp && s->is2022) {
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 10) { said = now;
            fprintf(stderr, "steer[warn]: shadowsocks 2022: UDP не поддержан (сессии/AES-ECB), "
                            "датаграммы узла %s не пойдут\n", n->name); }
        return -1;
    }
    return 0;
}

/* Ключ сессии: AEAD — EVP(пароль)+HKDF(salt); 2022 — BLAKE3(PSK,salt). Для AEAD ключ из пароля
 * выводится здесь, при установлении (pxsub хранит пароль, не ключ). */
static int ss_subkey(const struct px_node *n, const unsigned char *salt, unsigned char *subkey) {
    if (n->ss_method >= SS_2022_AES128) {
        px_ss2022_subkey(n->ss_key, n->ss_key_n, salt, subkey);
        return 0;
    }
    unsigned char master[32];
    px_ss_evp_key(n->pass, master, n->ss_key_n);
    return px_ss_subkey(master, n->ss_key_n, salt, subkey);
}

static int ss_udp_open(struct ss_sess *s, const struct px_node *n) {
    int fd = tr_dial_udp(n->vn.host, n->vn.port);
    if (fd < 0) return fd;
    s->udpfd = fd;
    return 0;
}

static int ss_connect(const void *ctx, void *sess, int timeout_s) {
    const struct px_node *n = ctx;
    struct ss_sess *s = sess;
    int rc = s->udp ? ss_udp_open(s, n) : px_stream_open(n, &s->t, timeout_s);
    return rc;
}

static void ss_take(void *dst, void *src) {
    struct ss_sess *d = dst, *ss = src;
    memcpy(&d->t, &ss->t, sizeof(d->t));
    transport_moved(&d->t);
}
static void ss_close(void *sess) {
    struct ss_sess *s = sess;
    if (s->udpfd >= 0) { close(s->udpfd); s->udpfd = -1; }
    else transport_close(&s->t);
    if (s->has_enc) { sc_aead_free(&s->enc); s->has_enc = 0; }
    if (s->has_dec) { sc_aead_free(&s->dec); s->has_dec = 0; }
}
static int ss_fd(const void *sess) {
    const struct ss_sess *s = sess;
    return s->udpfd >= 0 ? s->udpfd : transport_fd(&s->t);
}
static int ss_has_data(const void *sess) {
    const struct ss_sess *s = sess;
    if (s->udpfd >= 0) return 0;
    return s->out_off < s->out_n || transport_has_data(&s->t);
}

/* Добавить к out зашифрованный кусок данных (len-кадр + полезная нагрузка). */
static size_t ss_seal_chunk(struct ss_sess *s, const unsigned char *p, size_t n,
                            unsigned char *out) {
    size_t o = 0;
    unsigned char lb[2] = { (unsigned char)(n >> 8), (unsigned char)n };
    memcpy(out + o, lb, 2);
    sc_aead_seal(&s->enc, s->snonce, NULL, 0, out + o, 2, out + o + 2); nonce_inc(s->snonce);
    o += 2 + 16;
    memcpy(out + o, p, n);
    sc_aead_seal(&s->enc, s->snonce, NULL, 0, out + o, n, out + o + n); nonce_inc(s->snonce);
    o += n + 16;
    return o;
}

/* AEAD-TCP: собрать первый кусок (соль, заголовок, данные) или продолжение. */
static int ss_send_tcp(const struct px_node *n, struct ss_sess *s, const unsigned char *data,
                       size_t dn) {
    static __thread unsigned char out[TUNNEL_BUF];
    size_t o = 0;
    if (!s->header_sent) {
        unsigned char salt[32], subkey[32];
        if (getrandom(salt, s->keylen, 0) != (ssize_t)s->keylen) return SEND_FATAL;
        memcpy(s->salt_sent, salt, s->keylen);
        memcpy(out, salt, s->keylen);
        o = s->keylen;
        if (n->ss_method == SS_NONE) {
            /* none: соль не нужна, но адрес и данные идут в открытую. Перепишем: без соли. */
            o = 0;
            o += px_socks_addr(out + o, s->dst, s->dport);
            if (o + dn > sizeof out) return SEND_FATAL;
            memcpy(out + o, data, dn); o += dn;
            s->header_sent = 1;
            return transport_write(&s->t, out, o) ? SEND_FATAL : SEND_OK;
        }
        if (ss_subkey(n, salt, subkey) != 0) return SEND_FATAL;
        if (s->has_enc) { sc_aead_free(&s->enc); s->has_enc = 0; }   /* повтор после закрытого окна */
        if (sc_aead_setkey(&s->enc, ss_alg(n->ss_method), subkey) != 0) return SEND_FATAL;
        s->has_enc = 1;
        memset(s->snonce, 0, 12);
        unsigned char addr[8];
        size_t al = px_socks_addr(addr, s->dst, s->dport);
        if (s->is2022) {
            /* EIH для многопользовательского (один уровень реле). */
            if (n->ss_ipsk_n) {
                unsigned char eih[16];
                if (px_ss2022_eih(n->ss_ipsk, n->ss_key_n, n->ss_key, salt, eih) != 0) return SEND_FATAL;
                /* EIH идёт сразу после соли, в открытую (до фикс-заголовка). */
                memcpy(out + o, eih, 16); o += 16;
            }
            /* Фикс-заголовок: type(0) ts(8) varlen(2). */
            unsigned char fixed[11];
            fixed[0] = 0;
            uint64_t ts = (uint64_t)time(NULL);
            for (int i = 0; i < 8; i++) fixed[1 + i] = (unsigned char)(ts >> (56 - 8 * i));
            size_t varlen = al + 2 + dn;         /* адрес + padlen(2)=0 + данные */
            fixed[9] = (unsigned char)(varlen >> 8);
            fixed[10] = (unsigned char)varlen;
            memcpy(out + o, fixed, 11);
            sc_aead_seal(&s->enc, s->snonce, NULL, 0, out + o, 11, out + o + 11); nonce_inc(s->snonce);
            o += 11 + 16;
            /* var: адрес + padlen(2)=0 + данные. */
            static __thread unsigned char var[8 + 2 + TUNNEL_BUF];
            memcpy(var, addr, al);
            var[al] = 0; var[al + 1] = 0;
            memcpy(var + al + 2, data, dn);
            size_t vl = al + 2 + dn;
            memcpy(out + o, var, vl);
            sc_aead_seal(&s->enc, s->snonce, NULL, 0, out + o, vl, out + o + vl); nonce_inc(s->snonce);
            o += vl + 16;
        } else {
            /* Первый кусок: адрес + данные одним куском (≤ SS_CHUNK). */
            static __thread unsigned char first[8 + SS_CHUNK];
            size_t fn = al;
            memcpy(first, addr, al);
            size_t take = dn > SS_CHUNK - al ? SS_CHUNK - al : dn;
            memcpy(first + al, data, take); fn += take;
            o += ss_seal_chunk(s, first, fn, out + o);
            data += take; dn -= take;
            while (dn) {
                size_t t = dn > SS_CHUNK ? SS_CHUNK : dn;
                if (o + t + 34 > sizeof out) break;
                o += ss_seal_chunk(s, data, t, out + o);
                data += t; dn -= t;
            }
        }
        s->header_sent = 1;
        int rc = transport_write(&s->t, out, o);
        if (rc == H2_EWINDOW) { s->header_sent = 0; return SEND_AGAIN; }
        return rc ? SEND_FATAL : SEND_OK;
    }
    /* Продолжение: обычные куски. */
    if (n->ss_method == SS_NONE)
        return transport_write(&s->t, data, dn) ? SEND_FATAL : SEND_OK;
    while (dn) {
        size_t t = dn > SS_CHUNK ? SS_CHUNK : dn;
        if (o + t + 34 > sizeof out) {
            if (transport_write(&s->t, out, o)) return SEND_FATAL;
            o = 0;
        }
        o += ss_seal_chunk(s, data, t, out + o);
        data += t; dn -= t;
    }
    int rc = o ? transport_write(&s->t, out, o) : 0;
    if (rc == H2_EWINDOW) return SEND_AGAIN;
    return rc ? SEND_FATAL : SEND_OK;
}

/* UDP: data — череда [длина(2)][датаграмма] (dgram_frame). Каждую — своим пакетом в сокет. */
static int ss_send_udp(const struct px_node *n, struct ss_sess *s, const unsigned char *data,
                       size_t dn) {
    const unsigned char *p = data;
    size_t left = dn;
    while (left >= 2) {
        size_t dl = ((size_t)p[0] << 8) | p[1];
        p += 2; left -= 2;
        if (dl > left) return SEND_FATAL;
        unsigned char pkt[32 + 8 + UDP_DGRAM_MAX + 16], addr[8];
        size_t al = px_socks_addr(addr, s->dst, s->dport);
        size_t o = 0;
        if (n->ss_method == SS_NONE) {
            memcpy(pkt, addr, al); o = al;
            memcpy(pkt + o, p, dl); o += dl;
        } else {
            unsigned char salt[32], subkey[32];
            if (getrandom(salt, s->keylen, 0) != (ssize_t)s->keylen) return SEND_FATAL;
            memcpy(pkt, salt, s->keylen); o = s->keylen;
            if (ss_subkey(n, salt, subkey) != 0) return SEND_FATAL;
            struct sc_aead k;
            if (sc_aead_setkey(&k, ss_alg(n->ss_method), subkey) != 0) return SEND_FATAL;
            unsigned char body[8 + UDP_DGRAM_MAX];
            memcpy(body, addr, al);
            memcpy(body + al, p, dl);
            size_t bl = al + dl;
            unsigned char zero[12] = { 0 };
            memcpy(pkt + o, body, bl);
            sc_aead_seal(&k, zero, NULL, 0, pkt + o, bl, pkt + o + bl);
            sc_aead_free(&k);
            o += bl + 16;
        }
        ssize_t w = send(s->udpfd, pkt, o, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SEND_AGAIN;
        if (w != (ssize_t)o) return SEND_FATAL;
        p += dl; left -= dl;
    }
    return left ? SEND_FATAL : SEND_OK;
}

static int ss_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    (void)k;
    struct ss_sess *s = sess;
    return udp ? ss_send_udp(ctx, s, data, n) : ss_send_tcp(ctx, s, data, n);
}

static size_t ss_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_MAX || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8); out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

/* Сколько сырых байт можно взять у сокета за проход, чтобы расшифровка не отдала стеку больше
 * cap байт.
 *
 * Стек берёт у дайлера не больше cap (TUNNEL_BUF) за проход и перед проходом проверяет место в
 * кольце повтора ровно под это число (CLIENT_ROOM_RESERVE). Расшифровка же отдаёт не столько,
 * сколько прочитано, а сколько накопилось: недобранный кусок из прошлого прохода (acc_n байт)
 * плюс всё, что прочитано сейчас. Прежний код читал cap сырых байт всегда и отдавал до
 * acc_n + cap: у сервера с кусками по 8 КБ это 24474 байта при месте под 19472 — emit отказывал,
 * и исправное соединение рвалось на 135-420 МБ, как только кольцо наполнялось. Здесь вход
 * режется так, чтобы acc_n + прочитанное не выходило за cap.
 *
 * Кусок, который не влезает в cap сам по себе (SIP022: до 0xFFFF), добирается ровно до конца,
 * без хвоста, а отдаётся по cap за проход (ss_tcp_down, out_off). */
static size_t ss_take_limit(const struct ss_sess *s, size_t cap) {
    if (s->rx != RS_PAY) return cap;
    size_t need = s->want - s->acc_n;                 /* до конца текущего куска */
    size_t pl = s->want - 16;                         /* его нагрузка */
    size_t lim = need + (cap > pl ? cap - pl : 0);
    return lim < cap ? lim : cap;
}

static int ss_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct ss_sess *s = sess;
    *data = buf; *got = 0;
    if (s->udpfd >= 0) {
        ssize_t r = recv(s->udpfd, buf, cap, MSG_DONTWAIT);
        if (r > 0) { *got = (size_t)r; return 0; }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        return -1;
    }
    if (s->out_off < s->out_n) {                      /* остаток прошлого куска — раньше сокета */
        size_t k = s->out_n - s->out_off;
        if (k > cap) k = cap;
        *data = s->acc + s->out_off; *got = k;
        s->out_off += k;
        s->flushing = 1;
        return 0;
    }
    return transport_read(&s->t, buf, ss_take_limit(s, cap), got);
}

/* Снять адрес SOCKS5 в начале буфера: вернуть его длину, 0 — не хватает/брак. */
static size_t skip_socks_addr(const unsigned char *p, size_t n) {
    if (n < 1) return 0;
    if (p[0] == 1) return n >= 7 ? 7 : 0;
    if (p[0] == 4) return n >= 19 ? 19 : 0;
    if (p[0] == 3) { if (n < 2) return 0; size_t l = 2 + p[1] + 2; return n >= l ? l : 0; }
    return 0;
}

/* UDP вниз: датаграмма пришла целиком (recv), снять соль/дешифровать, выкинуть адрес, отдать. */
static int ss_udp_down(const struct px_node *n, struct ss_sess *s, const unsigned char *d, size_t len,
                       dialer_emit_fn emit, void *arg) {
    unsigned char plain[UDP_DGRAM_MAX + 32];
    const unsigned char *body;
    size_t bn;
    if (n->ss_method == SS_NONE) { body = d; bn = len; }
    else {
        if (len < s->keylen + 16) return 0;
        unsigned char subkey[32]; struct sc_aead k; unsigned char zero[12] = { 0 };
        if (ss_subkey(n, d, subkey) != 0) return 0;
        if (sc_aead_setkey(&k, ss_alg(n->ss_method), subkey) != 0) return 0;
        size_t cl = len - s->keylen - 16;
        if (cl > sizeof plain) { sc_aead_free(&k); return 0; }
        memcpy(plain, d + s->keylen, cl);
        int rc = sc_aead_open(&k, zero, NULL, 0, plain, cl, d + len - 16);
        sc_aead_free(&k);
        if (rc != 0) return 0;               /* чужая датаграмма — молча мимо, как UDP */
        body = plain; bn = cl;
    }
    size_t al = skip_socks_addr(body, bn);
    if (!al || al > bn) return 0;
    return emit(arg, body + al, bn - al);
}

/* TCP вниз: соль, затем куски. Накопитель s->acc собирает текущую стадию. */
static int ss_tcp_down(const struct px_node *n, struct ss_sess *s, const unsigned char *d, size_t len,
                       dialer_emit_fn emit, void *arg) {
    if (n->ss_method == SS_NONE) return len ? emit(arg, d, len) : 0;
    if (s->flushing) {                    /* остаток куска из ss_read: уже расшифрован */
        s->flushing = 0;
        return len ? emit(arg, d, len) : 0;
    }
    size_t emitted = 0;                   /* за этот проход — не больше TUNNEL_BUF */
    while (len) {
        if (s->rx == RS_SALT) {
            size_t need = s->keylen - s->acc_n;
            size_t take = len < need ? len : need;
            memcpy(s->acc + s->acc_n, d, take); s->acc_n += take; d += take; len -= take;
            if (s->acc_n < s->keylen) return 0;
            unsigned char subkey[32];
            if (ss_subkey(n, s->acc, subkey) != 0) return -1;
            if (sc_aead_setkey(&s->dec, ss_alg(n->ss_method), subkey) != 0) return -1;
            s->has_dec = 1;
            memset(s->rnonce, 0, 12);
            s->acc_n = 0;
            s->rx = s->is2022 ? RS_FIXED : RS_LEN;
            s->want = s->is2022 ? (size_t)(11 + s->keylen + 16) : (size_t)(2 + 16);
            continue;
        }
        size_t need = s->want - s->acc_n;
        size_t take = len < need ? len : need;
        if (s->acc_n + take > sizeof s->acc) return -1;
        memcpy(s->acc + s->acc_n, d, take); s->acc_n += take; d += take; len -= take;
        if (s->acc_n < s->want) return 0;
        size_t ct = s->want - 16;
        if (sc_aead_open(&s->dec, s->rnonce, NULL, 0, s->acc, ct, s->acc + ct) != 0) return -1;
        nonce_inc(s->rnonce);
        s->acc_n = 0;
        if (s->rx == RS_FIXED) {
            /* type(1)=1, ts(8), reqsalt(keylen), varlen(2). */
            if (s->acc[0] != 1 || memcmp(s->acc + 9, s->salt_sent, s->keylen) != 0) return -1;
            size_t varlen = ((size_t)s->acc[9 + s->keylen] << 8) | s->acc[10 + s->keylen];
            s->rx = RS_PAY;
            s->want = varlen + 16;
        } else if (s->rx == RS_LEN) {
            size_t want = ((size_t)s->acc[0] << 8) | s->acc[1];
            if (!want || want > (s->is2022 ? SS2022_CHUNK : SS_CHUNK)) return -1;
            s->rx = RS_PAY;
            s->want = want + 16;
        } else {                              /* RS_PAY */
            s->rx = RS_LEN;
            s->want = 2 + 16;
            size_t room = TUNNEL_BUF - emitted;
            size_t k = ct < room ? ct : room;
            if (emit(arg, s->acc, k) != 0) return -1;
            emitted += k;
            if (k < ct) {
                /* Кусок больше места за проход: остаток ждёт в acc, пока ss_read его не отдаст.
                 * Вход после такого куска ss_take_limit не оставляет; если он всё же есть,
                 * его некуда деть — это не наш read. */
                s->out_off = k; s->out_n = ct;
                return len ? -1 : 0;
            }
        }
    }
    return 0;
}

static int ss_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    struct ss_sess *s = sess;
    if (udp) return got ? ss_udp_down(ctx, s, rx, got, emit, arg) : 0;
    return got ? ss_tcp_down(ctx, s, rx, got, emit, arg) : 0;
}

const struct dialer_ops proxy_ss_dialer = {
    .name = "shadowsocks",
    .caps = DC_UDP_OWN,
    .sess_size = sizeof(struct ss_sess),
    .peer = ss_peer, .describe = ss_describe, .strerror = px_strerror,
    .connect = ss_connect, .take = ss_take, .close = ss_close, .clear = ss_clear,
    .fd = ss_fd, .has_data = ss_has_data,
    .flow_open = ss_flow_open, .send = ss_send, .dgram_frame = ss_dgram_frame,
    .read = ss_read, .deliver = ss_deliver,
};
