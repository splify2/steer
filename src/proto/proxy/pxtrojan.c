/* Дайлер trojan: поток и UDP поверх того же транспорта, что vless (TLS/Reality + tcp/ws/grpc/
 * xhttp/httpupgrade). Эталон — trojan-gfw/trojan и sing-box.
 *
 * Запрос (trojan protocol): hex(SHA224(пароль))[56] CRLF  CMD(1)  адрес SOCKS5  CRLF  данные.
 * CMD=1 Connect (TCP), CMD=3 UDP Associate. Ответа-заголовка у trojan нет: при TCP сразу идёт
 * поток цели. UDP — пакеты [адрес SOCKS5][длина(2)][CRLF][данные] в обе стороны; адрес у нас один
 * (поток на пару адрес-порт), как у vless. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pxdial.h"
#include "pxwire.h"
#include "stack.h"
#include "scrypto.h"

/* Состояние разбора UDP-пакета trojan от сервера: читаем адрес, затем длину, CRLF, данные. */
/* TJ_SKIP — дочитать имя в адресе и вернуться к длине; TJ_SKIPD — выбросить крупную датаграмму и начать
 * следующий пакет с адреса (прежде оба кончались на TJ_LEN, и после выброшенной датаграммы адрес следующей
 * читался как длина). */
enum { TJ_ADDR = 0, TJ_LEN, TJ_CRLF, TJ_DATA, TJ_SKIP, TJ_SKIPD };

struct trojan_sess {
    uint8_t header_sent;
    uint8_t rx;                  /* TJ_* — состояние разбора UDP вниз */
    uint8_t alen;                /* сколько байт адреса ещё ждём (после первого байта ATYP) */
    uint8_t ahdr;               /* первый байт адреса (ATYP) прочитан */
    unsigned char lenb, lenb_n;
    uint16_t dg_want, dg_have;
    uint32_t dg_skip;
    char pwhex[57];             /* hex(SHA224(пароль)), выводится один раз на соединение */
    struct transport t;
    unsigned char dg[UDP_DGRAM_MAX];
    /* Датаграмма крупнее dg собирается в куче, при первой такой потока, и освобождается при закрытии
     * сессии: платит только тот поток, по которому идёт крупное (I-528). */
    unsigned char *dgbig;
};

static const char *tj_peer(const void *ctx) { return ((const struct px_node *)ctx)->vn.host; }
static void tj_describe(const void *ctx, char *out, size_t n) {
    const struct px_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u trojan %s/%s)", nd->name, vless_host_fmt(nd->vn.host).s, nd->vn.port,
             nd->vn.security, nd->vn.type);
}

static void pw_hex(const char *pass, char out[57]) {
    unsigned char h[28];
    sc_hash(SC_SHA224, pass, strlen(pass), h);
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 28; i++) { out[2 * i] = hx[h[i] >> 4]; out[2 * i + 1] = hx[h[i] & 15]; }
    out[56] = '\0';
}

static int tj_connect(const void *ctx, void *sess, int timeout_s) {
    struct trojan_sess *s = sess;
    int rc = px_stream_open(ctx, &s->t, timeout_s);
    return rc;
}
static void tj_take(void *dst, void *src) {
    struct trojan_sess *d = dst, *s = src;
    memcpy(&d->t, &s->t, sizeof(d->t));
    transport_moved(&d->t);
}
static void tj_close(void *sess) {
    struct trojan_sess *s = sess;
    transport_close(&s->t);
    free(s->dgbig);
    s->dgbig = NULL;
}
static void tj_clear(void *sess) {
    struct trojan_sess *s = sess;
    s->header_sent = 0;
    s->rx = 0; s->alen = 0; s->ahdr = 0; s->lenb_n = 0;
    s->dg_want = s->dg_have = 0; s->dg_skip = 0;
    s->dgbig = NULL;
    s->t.link.fd = -1;
}
static int tj_fd(const void *sess) { return transport_fd(&((const struct trojan_sess *)sess)->t); }
static int tj_has_data(const void *sess) { return transport_has_data(&((const struct trojan_sess *)sess)->t); }

static int tj_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k; (void)udp;
    struct trojan_sess *s = sess;
    s->header_sent = 0;
    pw_hex(((const struct px_node *)ctx)->pass, s->pwhex);
    return 0;
}

/* Собрать заголовок запроса (hex пароля + CRLF + CMD + адрес + CRLF). */
static size_t tj_header(struct trojan_sess *s, const struct flow_key *k, int udp,
                        unsigned char *out, size_t cap) {
    if (cap < 56 + 2 + 1 + 7 + 2) return 0;
    size_t o = 0;
    memcpy(out, s->pwhex, 56); o += 56;
    out[o++] = '\r'; out[o++] = '\n';
    out[o++] = udp ? 3 : 1;
    o += px_socks_addr(out + o, k->dst, k->dport);
    out[o++] = '\r'; out[o++] = '\n';
    return o;
}

static int tj_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    (void)ctx;
    struct trojan_sess *s = sess;
    static __thread unsigned char small[TUNNEL_BUF];
    unsigned char *out = small;
    size_t cap = sizeof(small);
    size_t len = 0;
    unsigned char *heap = NULL;
    /* Крупная датаграмма UDP не влезает в буфер записи: на неё берётся буфер по размеру (I-528). */
    if (udp && n + 64 + 2 * 16 > cap) {
        cap = n + 64 + 7 + 2 + 2 + 56 + 16;
        heap = out = malloc(cap);
        if (!out) return SEND_FATAL;
    }
    if (!s->header_sent) {
        len = tj_header(s, k, udp, out, cap);
        if (!len) { free(heap); return SEND_FATAL; }
    }
    if (!udp) {
        if (len + n > cap) {
            /* Заголовок уже собран, но данные с ним не влезают: отправим заголовок отдельно. */
            if (transport_write(&s->t, out, len)) return SEND_FATAL;
            s->header_sent = 1;
            int rc = transport_write(&s->t, data, n);
            return rc ? SEND_FATAL : SEND_OK;
        }
        memcpy(out + len, data, n);
        len += n;
    } else {
        /* data — череда [длина(2)][датаграмма] (dgram_frame); каждую обернуть пакетом trojan UDP. */
        const unsigned char *p = data;
        size_t left = n;
        while (left >= 2) {
            size_t dl = ((size_t)p[0] << 8) | p[1];
            p += 2; left -= 2;
            if (dl > left) { free(heap); return SEND_FATAL; }
            size_t need = 7 + 2 + 2 + dl;       /* адрес + длина + CRLF + данные */
            if (len + need > cap) { free(heap); return SEND_FATAL; }
            len += px_socks_addr(out + len, k->dst, k->dport);
            out[len++] = (unsigned char)(dl >> 8);
            out[len++] = (unsigned char)dl;
            out[len++] = '\r'; out[len++] = '\n';
            memcpy(out + len, p, dl); len += dl;
            p += dl; left -= dl;
        }
        if (left) { free(heap); return SEND_FATAL; }
    }
    int rc = transport_write(&s->t, out, len);
    free(heap);
    if (rc == H2_EWINDOW) return SEND_AGAIN;
    if (rc) return SEND_FATAL;
    s->header_sent = 1;
    return SEND_OK;
}

/* Длина датаграммы в пакете trojan — два байта, но стек и UDP по IPv4 не несут больше UDP_DGRAM_ABS. */
static size_t tj_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_ABS || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

static int tj_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    return transport_read_zc(&((struct trojan_sess *)sess)->t, buf, cap, data, got);
}

/* Разбор потока UDP-пакетов trojan вниз: [адрес][длина(2)][CRLF][данные]. */
static int tj_udp_down(struct trojan_sess *s, const unsigned char *d, size_t n,
                       dialer_emit_fn emit, void *arg) {
    while (n) {
        switch (s->rx) {
        case TJ_ADDR:
            if (!s->ahdr) {
                unsigned atyp = d[0];
                if (atyp != 1 && atyp != 3 && atyp != 4) return -1;   /* границ дальше не найти */
                d++; n--;
                s->ahdr = 1;
                s->alen = atyp == 1 ? 4 + 2 : atyp == 4 ? 16 + 2 : 0;
                if (atyp == 3) s->ahdr = 2;   /* домен: его длина — в следующем байте (ниже) */
                break;
            }
            if (s->ahdr == 2) { s->dg_skip = (uint32_t)d[0] + 2; d++; n--; s->ahdr = 1; s->rx = TJ_SKIP; break; }
            {
                size_t take = s->alen < n ? s->alen : n;
                d += take; n -= take; s->alen = (uint8_t)(s->alen - take);
                if (!s->alen) { s->rx = TJ_LEN; s->lenb_n = 0; s->ahdr = 0; }
            }
            break;
        case TJ_SKIP: {
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take; n -= take; s->dg_skip -= take;
            if (!s->dg_skip) { s->rx = TJ_LEN; s->lenb_n = 0; s->ahdr = 0; }
            break;
        }
        case TJ_SKIPD: {
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take; n -= take; s->dg_skip -= take;
            if (!s->dg_skip) { s->rx = TJ_ADDR; s->ahdr = 0; s->dg_want = s->dg_have = 0; }
            break;
        }
        case TJ_LEN:
            if (!s->lenb_n) { s->lenb = d[0]; s->lenb_n = 1; d++; n--; if (!n) return 0; }
            s->dg_want = (uint16_t)((s->lenb << 8) | d[0]); d++; n--;
            s->lenb_n = 0; s->dg_have = 0;
            s->rx = TJ_CRLF; s->alen = 2;        /* CRLF */
            if (s->dg_want > UDP_DGRAM_MAX) {
                if (s->dg_want > UDP_DGRAM_ABS || !(s->dgbig || (s->dgbig = malloc(UDP_DGRAM_ABS)))) {
                    s->dg_skip = s->dg_want + 2;           /* выбросить ровно по длине, поток остаётся */
                    s->rx = TJ_SKIPD;
                }
            }
            break;
        case TJ_CRLF: {
            size_t take = s->alen < n ? s->alen : n;
            d += take; n -= take; s->alen = (uint8_t)(s->alen - take);
            if (!s->alen) s->rx = TJ_DATA;
            break;
        }
        default: {                                /* TJ_DATA */
            size_t need = (size_t)s->dg_want - s->dg_have;
            size_t take = n < need ? n : need;
            unsigned char *dg = s->dg_want <= sizeof s->dg ? s->dg : s->dgbig;
            memcpy(dg + s->dg_have, d, take);
            s->dg_have = (uint16_t)(s->dg_have + take);
            d += take; n -= take;
            if (s->dg_have < s->dg_want) return 0;
            if (emit(arg, dg, s->dg_want) != 0) return -1;
            s->rx = TJ_ADDR; s->ahdr = 0; s->dg_want = s->dg_have = 0;
            break;
        }
        }
    }
    return 0;
}

static int tj_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx;
    struct trojan_sess *s = sess;
    if (!udp) return got ? emit(arg, rx, got) : 0;
    return got ? tj_udp_down(s, rx, got, emit, arg) : 0;
}

const struct dialer_ops proxy_trojan_dialer = {
    .name = "trojan",
    .caps = DC_PRECONNECT,
    .sess_size = sizeof(struct trojan_sess),
    .peer = tj_peer, .describe = tj_describe, .strerror = px_strerror,
    .connect = tj_connect, .take = tj_take, .close = tj_close, .clear = tj_clear,
    .fd = tj_fd, .has_data = tj_has_data,
    .flow_open = tj_flow_open, .send = tj_send, .dgram_frame = tj_dgram_frame, .dgram_max = UDP_DGRAM_ABS,
    .read = tj_read, .deliver = tj_deliver,
};
