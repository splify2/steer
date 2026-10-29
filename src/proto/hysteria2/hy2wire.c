/* Провод hysteria2 — см. hy2wire.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>

#include "hy2wire.h"

/* ---- целые QUIC ---------------------------------------------------------------------------- */

size_t hy2_varint_len(uint64_t v) {
    if (v < (1ull << 6)) return 1;
    if (v < (1ull << 14)) return 2;
    if (v < (1ull << 30)) return 4;
    if (v <= HY2_VARINT_MAX) return 8;
    return 0;
}

size_t hy2_varint_put(uint8_t *out, size_t cap, uint64_t v) {
    size_t l = hy2_varint_len(v);
    if (!l || cap < l) return 0;
    switch (l) {
    case 1: out[0] = (uint8_t)v; break;
    case 2: out[0] = (uint8_t)(0x40 | (v >> 8)); out[1] = (uint8_t)v; break;
    case 4:
        out[0] = (uint8_t)(0x80 | (v >> 24)); out[1] = (uint8_t)(v >> 16);
        out[2] = (uint8_t)(v >> 8); out[3] = (uint8_t)v;
        break;
    default:
        out[0] = (uint8_t)(0xc0 | (v >> 56));
        for (int i = 1; i < 8; i++) out[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
    return l;
}

size_t hy2_varint_get(const uint8_t *d, size_t n, uint64_t *v) {
    if (!n) return 0;
    size_t l = (size_t)1 << (d[0] >> 6);
    if (n < l) return 0;
    uint64_t x = d[0] & 0x3f;
    for (size_t i = 1; i < l; i++) x = (x << 8) | d[i];
    *v = x;
    return l;
}

/* Писатель с проверкой предела: первое переполнение помнится, дальше ничего не пишется, и
 * вызывающий проверяет один раз в конце. Иначе каждая строка сборки кадра несла бы свой if. */
struct wr {
    uint8_t *p;
    size_t cap, n;
    int over;
};
static void w_bytes(struct wr *w, const void *d, size_t n) {
    if (w->over || w->n + n > w->cap) { w->over = 1; return; }
    if (n) memcpy(w->p + w->n, d, n);
    w->n += n;
}
static void w_u8(struct wr *w, unsigned v) { uint8_t b = (uint8_t)v; w_bytes(w, &b, 1); }
static void w_vi(struct wr *w, uint64_t v) {
    uint8_t b[8];
    size_t l = hy2_varint_put(b, sizeof b, v);
    if (!l) { w->over = 1; return; }
    w_bytes(w, b, l);
}
static void w_pad(struct wr *w, size_t n) {
    /* Набивка — печатные знаки: сервер её не читает, а в отладочном журнале эталона видно, что это. */
    static const char al[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t r[64];
    while (n) {
        size_t k = n < sizeof r ? n : sizeof r;
        if (getrandom(r, k, 0) != (ssize_t)k) memset(r, 0x55, k);
        for (size_t i = 0; i < k; i++) r[i] = (uint8_t)al[r[i] % (sizeof al - 1)];
        w_bytes(w, r, k);
        n -= k;
    }
}

/* ---- управляющий поток HTTP/3 --------------------------------------------------------------- */

size_t hy2_h3_control(uint8_t *out, size_t cap) {
    struct wr w = { out, cap, 0, 0 };
    w_u8(&w, 0x00);                         /* тип потока: управляющий */
    w_u8(&w, 0x04);                         /* кадр SETTINGS */
    /* SETTINGS ПУСТ, и это принципиально. Первая редакция объявляла H3_DATAGRAM (0x33) = 1 — и
     * сервер эталона терял каждую вторую датаграмму UDP: включив у себя датаграммы HTTP/3, его
     * слой HTTP/3 начинает читать ту же очередь датаграмм QUIC, что и приложение (hysteria2
     * читает их сам, без префикса потока), и два читателя делят поток пополам. Клиент эталона
     * этой настройки не шлёт (у него EnableDatagrams только на уровне QUIC). Нашли сверкой
     * с настоящим сервером (tests/run-hy2.sh). */
    w_vi(&w, 0);                            /* длина: ни одной настройки */
    return w.over ? 0 : w.n;
}

/* ---- QPACK ---------------------------------------------------------------------------------- */

/* Целое с префиксом из bits бит (RFC 7541, 5.1; тот же формат у QPACK). first — старшие биты
 * первого байта, уже установленные вызывающим. */
static void w_qint(struct wr *w, uint8_t first, unsigned bits, uint64_t v) {
    uint64_t mx = (1u << bits) - 1;
    if (v < mx) { w_u8(w, first | (unsigned)v); return; }
    w_u8(w, first | (unsigned)mx);
    v -= mx;
    while (v >= 128) { w_u8(w, (unsigned)(v & 127) | 128); v >>= 7; }
    w_u8(w, (unsigned)v);
}

/* Поле «литерал с литеральным именем» (001NHxxx), без Huffman: клиент пишет короткие строки, и
 * выигрыш от сжатия не стоит таблицы в этом направлении. */
static void w_field(struct wr *w, const char *name, const char *val) {
    size_t nl = strlen(name), vl = strlen(val);
    w_qint(w, 0x20, 3, nl);                 /* 0010 0nnn: N = 0, H = 0 */
    w_bytes(w, name, nl);
    w_qint(w, 0x00, 7, vl);                 /* H = 0 */
    w_bytes(w, val, vl);
}

/* Поле с именем из статической таблицы (01NT xxxx, T = 1): 0x50 | индекс. */
static void w_field_static(struct wr *w, unsigned idx, const char *val) {
    size_t vl = strlen(val);
    w_qint(w, 0x50, 4, idx);
    w_qint(w, 0x00, 7, vl);
    w_bytes(w, val, vl);
}

size_t hy2_auth_request(uint8_t *out, size_t cap, const char *auth, uint64_t rx_bps, size_t pad) {
    uint8_t sec[1024 + 512];
    struct wr s = { sec, sizeof sec, 0, 0 };
    w_u8(&s, 0x00);                         /* Required Insert Count = 0 */
    w_u8(&s, 0x00);                         /* Base: знак 0, дельта 0 */
    w_u8(&s, 0xc0 | 20);                    /* :method POST — статическая таблица, 20 */
    w_u8(&s, 0xc0 | 23);                    /* :scheme https — 23 */
    w_field_static(&s, 0, "hysteria");      /* :authority (имя — 0) */
    w_field_static(&s, 1, "/auth");         /* :path (имя — 1) */
    w_field(&s, "hysteria-auth", auth);
    char rx[24];
    snprintf(rx, sizeof rx, "%llu", (unsigned long long)rx_bps);
    w_field(&s, "hysteria-cc-rx", rx);
    /* Набивка: значение из pad знаков. Собирается отдельно — w_field берёт строку. */
    {
        char padv[256];
        size_t k = pad < sizeof padv - 1 ? pad : sizeof padv - 1;
        struct wr p = { (uint8_t *)padv, sizeof padv - 1, 0, 0 };
        w_pad(&p, k);
        padv[p.n] = '\0';
        w_field(&s, "hysteria-padding", padv);
    }
    if (s.over) return 0;
    struct wr w = { out, cap, 0, 0 };
    w_u8(&w, 0x01);                         /* HEADERS */
    w_vi(&w, s.n);
    w_bytes(&w, sec, s.n);
    return w.over ? 0 : w.n;
}

/* Таблица Huffman из RFC 7541 (приложение B): код и длина 257 символов; 256 — EOS. Её же
 * использует QPACK. */
static const uint32_t HC[257] = {
    0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,
    0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
    0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,0x14,0x3f8,0x3f9,0xffa,
    0x1ff9,0x15,0xf8,0x7fa,0x3fa,0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,0x18,
    0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,
    0x7ffc,0x20,0xffb,0x3fc,0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,
    0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
    0x6f,0x70,0x71,0x72,0xfc,0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,
    0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,0x26,0x27,0x6,0x74,0x75,
    0x28,0x29,0x2a,0x7,0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,
    0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,0xfffe6,0x3fffd2,0xfffe7,0xfffe8,
    0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,
    0xffffec,0xffffed,0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,
    0x3fffd9,0x7fffe6,0x7fffe7,0xffffef,0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,0x1fffde,
    0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,
    0x7fffed,0x3fffe1,0x7fffee,0x7fffef,0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,
    0x3ffffe0,0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,0x3ffffe2,0x3ffffe3,0x3ffffe4,0x7ffffde,
    0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,0x7fff2,0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,
    0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,0xfffed,0x1fffe6,
    0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,
    0x3ffffeb,0x7ffffe6,0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,0x7ffffeb,0xffffffe,0x7ffffec,0x7ffffed,
    0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,0x3fffffff,
};
static const uint8_t HL[257] = {
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,
    6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,
    13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
    15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,
    20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,
    22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,
    26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,
    20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,
    30,
};

/* Развернуть строку Huffman в out (с завершающим нулём). Побитовый разбор с поиском по таблице —
 * медленно, но строк в ответе три-четыре по десятку знаков, а таблица индексов стоила бы килобайты.
 * Возвращает длину или -1: символ EOS в строке, недобор, набивка не из единиц (RFC 7541, 5.2). */
static int huff_decode(const uint8_t *in, size_t n, char *out, size_t cap) {
    uint32_t code = 0;
    unsigned len = 0;
    size_t o = 0;
    for (size_t i = 0; i < n * 8; i++) {
        code = (code << 1) | ((in[i >> 3] >> (7 - (i & 7))) & 1u);
        len++;
        if (len > 30) return -1;
        for (unsigned s = 0; s < 257; s++) {
            if (HL[s] != len || HC[s] != code) continue;
            if (s == 256) return -1;
            /* Строка длиннее места (набивка ответа сервера — до двух килобайт) читается до конца,
             * чтобы проверить её и найти границу, но хранится только начало. */
            if (o + 1 < cap) out[o++] = (char)s;
            code = 0;
            len = 0;
            break;
        }
    }
    /* Хвост — не больше семи бит и только единицы. */
    if (len > 7 || code != (1u << len) - 1) return -1;
    out[o] = '\0';
    return (int)o;
}

/* Прочитать целое с префиксом; возвращает занятые байты или 0 (мало / переполнение). */
static size_t r_qint(const uint8_t *d, size_t n, unsigned bits, uint64_t *v) {
    if (!n) return 0;
    uint64_t mx = (1u << bits) - 1, x = d[0] & mx;
    size_t i = 1;
    if (x < mx) { *v = x; return 1; }
    unsigned sh = 0;
    for (;;) {
        if (i >= n || sh > 28) return 0;
        x += (uint64_t)(d[i] & 127) << sh;
        sh += 7;
        if (!(d[i++] & 128)) break;
    }
    *v = x;
    return i;
}

/* Строка: H в бите hbit первого байта, длина — в остальных prefix битах. */
static size_t r_str(const uint8_t *d, size_t n, unsigned prefix, char *out, size_t cap) {
    uint64_t l;
    size_t k = r_qint(d, n, prefix, &l);
    if (!k || l > n - k) return 0;
    int huff = (d[0] >> prefix) & 1;
    if (huff) {
        if (huff_decode(d + k, (size_t)l, out, cap) < 0) return 0;
    } else {
        size_t keep = (size_t)l + 1 > cap ? cap - 1 : (size_t)l;      /* хранится начало, см. huff_decode */
        memcpy(out, d + k, keep);
        out[keep] = '\0';
    }
    return k + (size_t)l;
}

/* Статические имена :status: 24-28 и 63-71 (RFC 9204, приложение A). */
static int static_is_status(uint64_t i) { return (i >= 24 && i <= 28) || (i >= 63 && i <= 71); }
static int static_status_val(uint64_t i) {
    static const int v24[] = { 103, 200, 304, 404, 503 };
    static const int v63[] = { 100, 204, 206, 302, 400, 403, 421, 425, 500 };
    if (i >= 24 && i <= 28) return v24[i - 24];
    if (i >= 63 && i <= 71) return v63[i - 63];
    return 0;
}

static void note_header(struct hy2_auth_resp *r, const char *name, const char *val) {
    if (!strcasecmp(name, ":status")) r->status = atoi(val);
    else if (!strcasecmp(name, "hysteria-udp")) r->udp = !strcasecmp(val, "true");
    else if (!strcasecmp(name, "hysteria-cc-rx")) {
        if (!strcasecmp(val, "auto")) r->rx_auto = 1;
        else r->rx = strtoull(val, NULL, 10);
    }
}

static int qpack_section(const uint8_t *d, size_t n, struct hy2_auth_resp *r, const char **why) {
    uint64_t v;
    size_t k = r_qint(d, n, 8, &v);
    if (!k || v != 0) { if (why) *why = "ответ ссылается на динамическую таблицу QPACK"; return -1; }
    d += k; n -= k;
    k = r_qint(d, n, 7, &v);
    if (!k) { if (why) *why = "заголовки ответа обрезаны"; return -1; }
    d += k; n -= k;
    char name[64], val[320];
    while (n) {
        uint8_t b = d[0];
        if (b & 0x80) {                                 /* 1T: индекс */
            if (!(b & 0x40)) { if (why) *why = "динамическая таблица QPACK"; return -1; }
            k = r_qint(d, n, 6, &v);
            if (!k) goto trunc;
            if (static_is_status(v)) r->status = static_status_val(v);
        } else if ((b & 0xc0) == 0x40) {                /* 01NT: имя по индексу */
            if (!(b & 0x10)) { if (why) *why = "динамическая таблица QPACK"; return -1; }
            k = r_qint(d, n, 4, &v);
            if (!k) goto trunc;
            size_t m = r_str(d + k, n - k, 7, val, sizeof val);
            if (!m) goto trunc;
            k += m;
            if (static_is_status(v)) note_header(r, ":status", val);
        } else if ((b & 0xe0) == 0x20) {                /* 001NH: литеральное имя */
            size_t m1 = r_str(d, n, 3, name, sizeof name);
            if (!m1) goto trunc;
            size_t m2 = r_str(d + m1, n - m1, 7, val, sizeof val);
            if (!m2) goto trunc;
            k = m1 + m2;
            note_header(r, name, val);
        } else {                                        /* 0001, 0000: после-базовые — их нет без таблицы */
            if (why) *why = "динамическая таблица QPACK";
            return -1;
        }
        d += k; n -= k;
    }
    return 0;
trunc:
    if (why) *why = "заголовки ответа не разобрать";
    return -1;
}

int hy2_auth_response(const uint8_t *d, size_t n, struct hy2_auth_resp *r, const char **why) {
    memset(r, 0, sizeof *r);
    size_t off = 0;
    for (;;) {
        uint64_t type, len;
        size_t a = hy2_varint_get(d + off, n - off, &type);
        if (!a) return 0;
        size_t b = hy2_varint_get(d + off + a, n - off - a, &len);
        if (!b) return 0;
        size_t hdr = a + b;
        if (len > (1u << 16)) { if (why) *why = "кадр ответа слишком велик"; return -1; }
        if (n - off - hdr < len) return 0;
        if (type == 0x01) {
            if (qpack_section(d + off + hdr, (size_t)len, r, why) != 0) return -1;
            if (!r->status) { if (why) *why = "в ответе нет :status"; return -1; }
            return 1;
        }
        if (type == 0x00) { if (why) *why = "данные раньше заголовков ответа"; return -1; }
        off += hdr + (size_t)len;                       /* незнакомый кадр, GREASE — пропустить */
    }
}

/* ---- TCP ------------------------------------------------------------------------------------ */

size_t hy2_tcp_request(uint8_t *out, size_t cap, const char *host, uint16_t port, size_t pad) {
    char addr[300];
    int l = strchr(host, ':') ? snprintf(addr, sizeof addr, "[%s]:%u", host, port)
                              : snprintf(addr, sizeof addr, "%s:%u", host, port);
    if (l <= 0 || (size_t)l >= sizeof addr) return 0;
    struct wr w = { out, cap, 0, 0 };
    w_vi(&w, HY2_TCP_REQ_ID);
    w_vi(&w, (uint64_t)l);
    w_bytes(&w, addr, (size_t)l);
    w_vi(&w, pad);
    w_pad(&w, pad);
    return w.over ? 0 : w.n;
}

int hy2_tcp_response(const uint8_t *d, size_t n, struct hy2_tcp_resp *r) {
    memset(r, 0, sizeof *r);
    if (!n) return 0;
    size_t off = 1;
    uint64_t ml, pl;
    size_t k = hy2_varint_get(d + off, n - off, &ml);
    if (!k) return 0;
    off += k;
    if (ml > 4096) return -1;
    if (n - off < ml) return 0;
    size_t cp = ml < sizeof r->msg - 1 ? (size_t)ml : sizeof r->msg - 1;
    memcpy(r->msg, d + off, cp);
    r->msg[cp] = '\0';
    off += (size_t)ml;
    k = hy2_varint_get(d + off, n - off, &pl);
    if (!k) return 0;
    off += k;
    if (pl > 4096) return -1;
    if (n - off < pl) return 0;
    off += (size_t)pl;
    r->ok = d[0] == 0;
    return (int)off;
}

/* ---- UDP ------------------------------------------------------------------------------------ */

size_t hy2_udp_header(uint8_t *out, size_t cap, uint32_t sid, uint16_t pkt, uint8_t frag,
                      uint8_t nfrag, const char *addr) {
    struct wr w = { out, cap, 0, 0 };
    uint8_t h[8] = { (uint8_t)(sid >> 24), (uint8_t)(sid >> 16), (uint8_t)(sid >> 8), (uint8_t)sid,
                     (uint8_t)(pkt >> 8), (uint8_t)pkt, frag, nfrag };
    w_bytes(&w, h, sizeof h);
    size_t al = strlen(addr);
    w_vi(&w, al);
    w_bytes(&w, addr, al);
    return w.over ? 0 : w.n;
}

int hy2_udp_parse(const uint8_t *d, size_t n, struct hy2_udp_msg *m) {
    if (n < 9) return -1;
    m->sid = (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
    m->pkt = (uint16_t)(d[4] << 8 | d[5]);
    m->frag = d[6];
    m->nfrag = d[7];
    uint64_t al;
    size_t k = hy2_varint_get(d + 8, n - 8, &al);
    if (!k || al >= sizeof m->addr || n - 8 - k < al) return -1;
    memcpy(m->addr, d + 8 + k, (size_t)al);
    m->addr[al] = '\0';
    m->data = d + 8 + k + al;
    m->n = n - 8 - k - (size_t)al;
    if (!m->nfrag || m->frag >= m->nfrag) return -1;
    return 0;
}

/* ---- BLAKE2b-256 ---------------------------------------------------------------------------- */

static const uint64_t B2IV[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};
static const uint8_t B2S[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define B2G(a, b, c, d, x, y) do { \
    v[a] = v[a] + v[b] + (x); v[d] = ROTR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];       v[b] = ROTR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + (y); v[d] = ROTR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];       v[b] = ROTR64(v[b] ^ v[c], 63); } while (0)

static void b2_compress(uint64_t h[8], const uint8_t blk[128], uint64_t t, int last) {
    uint64_t v[16], m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = 0;
        for (int j = 7; j >= 0; j--) m[i] = (m[i] << 8) | blk[i * 8 + j];
    }
    for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = B2IV[i]; }
    v[12] ^= t;                                 /* счётчик байт: старшие 64 бита нужны при 2^64+ */
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = B2S[r];
        B2G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        B2G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        B2G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        B2G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        B2G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        B2G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        B2G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

void hy2_blake2b256(uint8_t out[32], const uint8_t *in, size_t n) {
    uint64_t h[8];
    for (int i = 0; i < 8; i++) h[i] = B2IV[i];
    h[0] ^= 0x01010000ull ^ 32;                 /* параметры: длина выхода 32, без ключа, fanout=depth=1 */
    uint64_t t = 0;
    while (n > 128) {
        t += 128;
        b2_compress(h, in, t, 0);
        in += 128; n -= 128;
    }
    uint8_t last[128];
    memset(last, 0, sizeof last);
    if (n) memcpy(last, in, n);
    t += n;
    b2_compress(h, last, t, 1);
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(h[i / 8] >> (8 * (i % 8)));
}

/* ---- Salamander ----------------------------------------------------------------------------- */

void hy2_salamander_init(struct hy2_salamander *s, const char *password) {
    size_t l = strlen(password);
    if (l > sizeof s->key) l = sizeof s->key;
    memcpy(s->key, password, l);
    s->keylen = l;
}

/* Ключ потока пакета: BLAKE2b-256(ключ || соль). */
static void sm_stream(const struct hy2_salamander *s, const uint8_t *salt, uint8_t k[32]) {
    uint8_t in[sizeof s->key + HY2_SALT];
    memcpy(in, s->key, s->keylen);
    memcpy(in + s->keylen, salt, HY2_SALT);
    hy2_blake2b256(k, in, s->keylen + HY2_SALT);
}

size_t hy2_salamander_tx_salt(const struct hy2_salamander *s, const uint8_t salt[HY2_SALT],
                              uint8_t *dst, const uint8_t *src, size_t n) {
    uint8_t k[32];
    sm_stream(s, salt, k);
    memmove(dst + HY2_SALT, src, n);
    memcpy(dst, salt, HY2_SALT);
    for (size_t i = 0; i < n; i++) dst[HY2_SALT + i] ^= k[i % 32];
    return n + HY2_SALT;
}

size_t hy2_salamander_tx(void *user, uint8_t *dst, const uint8_t *src, size_t n) {
    uint8_t salt[HY2_SALT];
    if (getrandom(salt, sizeof salt, 0) != (ssize_t)sizeof salt) memset(salt, 0xa5, sizeof salt);
    return hy2_salamander_tx_salt(user, salt, dst, src, n);
}

size_t hy2_salamander_rx(void *user, uint8_t *dst, const uint8_t *src, size_t n) {
    if (n <= HY2_SALT) return 0;
    uint8_t k[32];
    sm_stream(user, src, k);
    size_t m = n - HY2_SALT;
    /* Соль читается до сдвига: при dst == src memmove затрёт её первой. */
    memmove(dst, src + HY2_SALT, m);
    for (size_t i = 0; i < m; i++) dst[i] ^= k[i % 32];
    return m;
}

/* ---- Gecko ---------------------------------------------------------------------------------- */

#include <time.h>

#define GK_HDR 5                /* geckoHeaderSize */
#define GK_CHUNK 1500           /* место под кусок при сборке: датаграмма QUIC не длиннее */
#define GK_TTL_MS 8000          /* geckoReassemblyTTL */

static uint32_t gk_rand(uint32_t n) {
    uint32_t r;
    if (getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) r = (uint32_t)time(NULL) * 2654435761u;
    return n <= 1 ? 0 : r % n;
}

static uint64_t gk_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

int hy2_gecko_init(struct hy2_gecko *g, const char *password, unsigned minp, unsigned maxp) {
    memset(g, 0, sizeof *g);
    if (!minp) minp = HY2_GECKO_MIN_DEF;
    if (!maxp) maxp = HY2_GECKO_MAX_DEF;
    if (minp > maxp || maxp > 2048) return -1;
    hy2_salamander_init(&g->sm, password);
    g->minp = minp;
    g->maxp = maxp;
    return 0;
}

void hy2_gecko_free(struct hy2_gecko *g) {
    for (int i = 0; i < HY2_GECKO_SLOTS; i++) { free(g->slot[i].buf); g->slot[i].buf = NULL; g->slot[i].used = 0; }
}

int hy2_gecko_tx(void *user, const uint8_t *src, size_t n,
                 void (*out)(void *ctx, const uint8_t *d, size_t n), void *ctx) {
    struct hy2_gecko *g = user;
    uint8_t frame[2600], wire[2700];
    if (!n || n > 2048) return -1;
    if (!(src[0] & 0x80)) {                                 /* короткий заголовок — как есть */
        size_t l = hy2_salamander_tx(&g->sm, wire, src, n);
        out(ctx, wire, l);
        return 0;
    }
    unsigned chunks = 2 + gk_rand(7);                       /* 2..8 */
    size_t csz = n / chunks;
    uint8_t msgid = ++g->msgid;
    for (unsigned i = 0; i < chunks; i++) {
        size_t start = i * csz, end = i < chunks - 1 ? start + csz : n, clen = end - start;
        /* Набивка доводит итоговую датаграмму (соль + заголовок + набивка + кусок) до случайного
         * размера в [minp, maxp]; кусок больше maxp остаётся без набивки (randomPadLen эталона). */
        size_t base = HY2_SALT + GK_HDR + clen, lo = base > g->minp ? base : g->minp, pad = 0;
        if (lo <= g->maxp) pad = lo - base + gk_rand((uint32_t)(g->maxp - lo + 1));
        if (GK_HDR + pad + clen > sizeof frame) return -1;
        frame[0] = 0x80;
        frame[1] = msgid;
        frame[2] = (uint8_t)(i << 4 | (chunks & 0x0f));
        frame[3] = (uint8_t)(pad >> 8);
        frame[4] = (uint8_t)pad;
        if (pad && getrandom(frame + GK_HDR, pad, 0) != (ssize_t)pad) memset(frame + GK_HDR, 0x5a, pad);
        memcpy(frame + GK_HDR + pad, src + start, clen);
        size_t l = hy2_salamander_tx(&g->sm, wire, frame, GK_HDR + pad + clen);
        out(ctx, wire, l);
    }
    return 0;
}

/* dst вмещает собранный пакет — до 8 кусков по GK_CHUNK (QUIC даёт фильтру свой буфер
 * QC_FILTER_RX_MAX, а не слот приёма: сборка на месте писала за его границу, I-517). */
size_t hy2_gecko_rx(void *user, uint8_t *dst, const uint8_t *src, size_t n) {
    struct hy2_gecko *g = user;
    uint8_t buf[2200];
    if (n > sizeof buf + HY2_SALT) return 0;
    size_t m = hy2_salamander_rx(&g->sm, buf, src, n);
    if (!m) return 0;
    if (!(buf[0] & 0x80)) { memcpy(dst, buf, m); return m; }        /* обычный пакет */
    if (m < GK_HDR) return 0;
    uint8_t msgid = buf[1], idx = buf[2] >> 4, total = buf[2] & 0x0f;
    size_t pad = (size_t)buf[3] << 8 | buf[4];
    if (total < 2 || total > 8 || idx >= total || GK_HDR + pad > m) return 0;
    const uint8_t *chunk = buf + GK_HDR + pad;
    size_t clen = m - GK_HDR - pad;
    if (clen > GK_CHUNK) return 0;
    uint64_t now = gk_now_ms();
    struct hy2_gecko_slot *s = NULL, *free_s = NULL, *old = &g->slot[0];
    for (int i = 0; i < HY2_GECKO_SLOTS; i++) {
        struct hy2_gecko_slot *c = &g->slot[i];
        if (c->used && now - c->at_ms > GK_TTL_MS) c->used = 0;     /* протухшая сборка */
        if (c->used && c->msgid == msgid) s = c;
        if (!c->used && !free_s) free_s = c;
        if (c->at_ms < old->at_ms) old = c;
    }
    if (s && s->total != total) return 0;                   /* несогласованное число кусков */
    if (!s) {
        s = free_s ? free_s : old;                          /* нет места — вытесняем самую старую */
        if (!s->buf) s->buf = malloc((size_t)8 * GK_CHUNK);
        if (!s->buf) return 0;
        s->used = 1; s->msgid = msgid; s->total = total; s->got = 0; s->at_ms = now;
        memset(s->len, 0, sizeof s->len);
    }
    if (s->len[idx]) return 0;                              /* повтор куска */
    memcpy(s->buf + (size_t)idx * GK_CHUNK, chunk, clen);
    s->len[idx] = (uint16_t)(clen ? clen : 0xffff);         /* 0xffff — пустой кусок помечен, но занят */
    if (++s->got < s->total) return 0;
    size_t tot = 0;
    for (unsigned i = 0; i < s->total; i++) {
        size_t l = s->len[i] == 0xffff ? 0 : s->len[i];
        memcpy(dst + tot, s->buf + (size_t)i * GK_CHUNK, l);
        tot += l;
    }
    s->used = 0;
    return tot;
}

uint64_t hy2_brutal_share(uint64_t cap, unsigned n) {
    if (!cap) return 0;
    uint64_t s = cap / (n ? n : 1);
    return s ? s : 1;
}

/* a * b целиком, 128 бит парой слов: на 32-битных целях __int128 нет */
static void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t a0 = (uint32_t)a, a1 = a >> 32;
    uint64_t b0 = (uint32_t)b, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    *lo = (mid << 32) | (uint32_t)p00;
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

int hy2_worker_busy(uint64_t bytes, uint64_t ms, uint64_t share_bps) {
    if (!bytes) return 0;
    if (!ms) return 1;
    /* bytes * 8000 / ms >= share_bps / 8, без деления */
    uint64_t lh, ll, rh, rl;
    mul64(bytes, 64000u, &lh, &ll);
    mul64(share_bps, ms, &rh, &rl);
    return lh > rh || (lh == rh && ll >= rl);
}

/* ---- сборка фрагментов ---- */

struct hy2_rasm {
    struct hy2_rasm *next;
    uint64_t t;                 /* когда пришёл первый фрагмент */
    uint32_t total;             /* сумма длин пришедших */
    uint16_t pkt;
    uint8_t n, got;
    struct { uint8_t *p; uint16_t len; } fr[];
};

static void rasm_free_one(struct hy2_rasm *r) {
    for (unsigned i = 0; i < r->n; i++) free(r->fr[i].p);
    free(r);
}

void hy2_rasm_free(struct hy2_rasm **head) {
    while (*head) {
        struct hy2_rasm *r = *head;
        *head = r->next;
        rasm_free_one(r);
    }
}

uint8_t *hy2_rasm_feed(struct hy2_rasm **head, const struct hy2_udp_msg *m, uint64_t now_ms, size_t pre,
                       size_t *total) {
    if (!m->nfrag || m->frag >= m->nfrag) return NULL;
    struct hy2_rasm *r = NULL, **pp = head;
    while (*pp) {
        struct hy2_rasm *c = *pp;
        if (c->pkt == m->pkt && c->n == m->nfrag) { r = c; pp = &c->next; continue; }
        if (now_ms - c->t > HY2_RASM_TTL_MS) { *pp = c->next; rasm_free_one(c); continue; }
        pp = &c->next;
    }
    if (!r) {
        r = calloc(1, sizeof *r + (size_t)m->nfrag * sizeof r->fr[0]);
        if (!r) return NULL;
        r->t = now_ms;
        r->pkt = m->pkt;
        r->n = m->nfrag;
        r->next = *head;
        *head = r;
    }
    if (r->fr[m->frag].p) return NULL;                  /* повтор фрагмента */
    r->fr[m->frag].p = malloc(m->n ? m->n : 1);
    if (!r->fr[m->frag].p) return NULL;
    memcpy(r->fr[m->frag].p, m->data, m->n);
    r->fr[m->frag].len = (uint16_t)m->n;
    r->total += (uint32_t)m->n;
    if (++r->got < r->n) return NULL;
    for (pp = head; *pp != r; pp = &(*pp)->next) {}
    *pp = r->next;
    uint8_t *blk = r->total <= 65507 ? malloc(pre + r->total) : NULL;   /* больше датаграммы UDP по IPv4 не бывает */
    if (blk) {
        size_t t = pre;
        for (unsigned i = 0; i < r->n; i++) { memcpy(blk + t, r->fr[i].p, r->fr[i].len); t += r->fr[i].len; }
        *total = r->total;
    }
    rasm_free_one(r);
    return blk;
}
