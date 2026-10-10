/* Кадры DoH по HTTP/3 и QPACK (статическая таблица): запрос, ответ, поток управления. Соединение —
 * в dup.c, устройство и доводы — в шапке doh3.h. */

#include <stdio.h>
#include <string.h>
#include "doh3.h"
#include "doh2.h"

/* ---- целые переменной длины (RFC 9000, 16) ---------------------------------------------------- */

size_t h3d_varint_put(uint8_t *dst, size_t cap, uint64_t v) {
    size_t n = v < 0x40 ? 1 : v < 0x4000 ? 2 : v < 0x40000000 ? 4 : 8;
    if (v >= (1ull << 62) || cap < n) return 0;
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    dst[0] |= n == 1 ? 0x00 : n == 2 ? 0x40 : n == 4 ? 0x80 : 0xC0;
    return n;
}

size_t h3d_varint_get(const uint8_t *buf, size_t n, uint64_t *v) {
    if (!n) return 0;
    size_t len = (size_t)1 << (buf[0] >> 6);
    if (n < len) return 0;
    uint64_t x = buf[0] & 0x3F;
    for (size_t i = 1; i < len; i++) x = (x << 8) | buf[i];
    *v = x;
    return len;
}

/* ---- запись ------------------------------------------------------------------------------------ */

struct wb { uint8_t *p; size_t n, cap; };
static void wput(struct wb *b, const void *d, size_t n) {
    if (b->n + n <= b->cap) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void wbyte(struct wb *b, unsigned v) { uint8_t c = (uint8_t)v; wput(b, &c, 1); }
static void wvar(struct wb *b, uint64_t v) {
    uint8_t t[8];
    size_t k = h3d_varint_put(t, sizeof(t), v);
    wput(b, t, k);
}

/* Целое QPACK с префиксом в bits бит (RFC 9204, 4.1.1): та же запись, что у HPACK. */
static void qp_int(struct wb *b, unsigned prefix, unsigned bits, uint32_t v) {
    uint32_t max = (1u << bits) - 1;
    if (v < max) { wbyte(b, prefix | v); return; }
    wbyte(b, prefix | max);
    v -= max;
    while (v >= 128) { wbyte(b, (v & 0x7F) | 0x80); v >>= 7; }
    wbyte(b, v);
}

/* Литерал без индексации с именем из статической таблицы (RFC 9204, 4.5.4: 01, N = 0, T = 1), значение
 * строкой без Хаффмана. */
static void qp_lit(struct wb *b, unsigned name_idx, const char *v, size_t n) {
    qp_int(b, 0x50, 4, name_idx);
    qp_int(b, 0x00, 7, (uint32_t)n);
    wput(b, v, n);
}

/* Поле целиком по статической таблице (RFC 9204, 4.5.2: 11 — по номеру). */
#define QP_STATIC(i) (0xC0u | (unsigned)(i))

/* Статическая таблица QPACK (RFC 9204, приложение A) — строки, которыми пользуемся. */
enum {
    QS_AUTHORITY = 0, QS_PATH = 1, QS_METHOD_POST = 20, QS_SCHEME_HTTPS = 23,
    QS_ACCEPT_DNS = 30, QS_CTYPE_DNS = 44,
};

size_t h3d_control_open(uint8_t *dst, size_t cap) {
    struct wb b = { dst, 0, cap };
    wvar(&b, 0x00);                                 /* тип потока: управление */
    wvar(&b, H3D_SETTINGS);
    uint8_t st[8];
    struct wb s = { st, 0, sizeof(st) };
    wvar(&s, H3D_S_QPACK_MAX_TABLE_CAPACITY); wvar(&s, 0);
    wvar(&s, H3D_S_QPACK_BLOCKED_STREAMS);    wvar(&s, 0);
    wvar(&b, s.n);
    wput(&b, st, s.n);
    return b.n <= cap ? b.n : 0;
}

size_t h3d_request(uint8_t *dst, size_t cap, const char *authority, const char *path,
                   const uint8_t *q, size_t qn) {
    if (qn < 12 || qn > H3D_MSG_MAX) return 0;
    uint8_t hb[1024];
    struct wb h = { hb, 0, sizeof(hb) };
    wbyte(&h, 0x00); wbyte(&h, 0x00);               /* префикс: обязательный счёт вставок 0, база 0 */
    wbyte(&h, QP_STATIC(QS_METHOD_POST));
    wbyte(&h, QP_STATIC(QS_SCHEME_HTTPS));
    qp_lit(&h, QS_AUTHORITY, authority, strlen(authority));
    qp_lit(&h, QS_PATH, path, strlen(path));
    wbyte(&h, QP_STATIC(QS_CTYPE_DNS));
    wbyte(&h, QP_STATIC(QS_ACCEPT_DNS));
    if (h.n > sizeof(hb)) return 0;
    struct wb o = { dst, 0, cap };
    wvar(&o, H3D_HEADERS); wvar(&o, h.n); wput(&o, hb, h.n);
    wvar(&o, H3D_DATA); wvar(&o, qn);
    wput(&o, q, qn);
    if (o.n > cap) return 0;
    dst[o.n - qn] = 0;                              /* номер сообщения — 0 (RFC 8484, 4.1) */
    dst[o.n - qn + 1] = 0;
    return o.n;
}

/* ---- чтение :status из блока QPACK ------------------------------------------------------------- */

/* Целое с префиксом; -1 — оборвано или слишком велико. */
static int64_t qp_dint(const uint8_t *p, size_t n, size_t *i, unsigned bits) {
    if (*i >= n) return -1;
    uint32_t max = (1u << bits) - 1;
    uint64_t v = p[(*i)++] & max;
    if (v < max) return (int64_t)v;
    unsigned shift = 0;
    for (;;) {
        if (*i >= n || shift > 28) return -1;
        uint8_t b = p[(*i)++];
        v += (uint64_t)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    return (int64_t)v;
}

/* Строки :status в статической таблице: 24–28 и 63–71 (RFC 9204, приложение A). */
static int static_status(int64_t idx) {
    switch (idx) {
    case 24: return 103; case 25: return 200; case 26: return 304; case 27: return 404; case 28: return 503;
    case 63: return 100; case 64: return 204; case 65: return 206; case 66: return 302; case 67: return 400;
    case 68: return 403; case 69: return 421; case 70: return 425; case 71: return 500;
    default: return 0;
    }
}

int h3d_status(const uint8_t *blk, size_t n) {
    size_t i = 0;
    int status = 0;
    /* Префикс блока: обязательный счёт вставок и база. Таблицу мы не разрешали, поэтому счёт — 0
     * (RFC 9204, 4.5.1.1); база при нём значения не имеет. */
    if (qp_dint(blk, n, &i, 8) != 0) return -1;
    if (qp_dint(blk, n, &i, 7) < 0) return -1;
    while (i < n) {
        uint8_t b = blk[i];
        if (b & 0x80) {                              /* по номеру: 1 T номер(6) */
            int64_t idx = qp_dint(blk, n, &i, 6);
            if (idx < 0 || !(b & 0x40) || idx > 98) return -1;   /* T = 0 — динамическая таблица */
            int s = static_status(idx);
            if (s && !status) status = s;
            continue;
        }
        int is_status = 0;
        if ((b & 0xC0) == 0x40) {                    /* литерал с именем по номеру: 01 N T номер(4) */
            int64_t idx = qp_dint(blk, n, &i, 4);
            if (idx < 0 || !(b & 0x10) || idx > 98) return -1;
            is_status = static_status(idx) != 0;
        } else if ((b & 0xE0) == 0x20) {             /* литерал с именем строкой: 001 N H длина(3) */
            int nh = (b & 0x08) != 0;
            int64_t nl = qp_dint(blk, n, &i, 3);
            if (nl < 0 || (size_t)nl > n - i) return -1;
            is_status = !nh && nl == 7 && memcmp(blk + i, ":status", 7) == 0;
            i += (size_t)nl;
        } else {
            return -1;                               /* 0001 и 0000: после-базовые, нужна динамическая таблица */
        }
        if (i >= n) return -1;
        int vh = (blk[i] & 0x80) != 0;
        int64_t vl = qp_dint(blk, n, &i, 7);
        if (vl < 0 || (size_t)vl > n - i) return -1;
        if (is_status && !status) {
            int v = h2d_status_value(blk + i, (size_t)vl, vh);   /* Хаффман тот же, что у HPACK */
            if (v < 100 || v > 599) return -1;
            status = v;
        }
        i += (size_t)vl;
    }
    return status;
}

/* ---- ответ -------------------------------------------------------------------------------------- */

#define H3D_E_FRAME_ERROR 0x106

static int bad(const char **why, uint64_t *err, const char *w, uint64_t e) {
    *why = w;
    *err = e;
    return -1;
}

int h3d_response(uint8_t *rx, size_t n, int fin, int *status, size_t *blen, const char **why, uint64_t *err) {
    size_t i = 0, total = 0;
    int have = 0, st = 0;
    while (i < n) {
        uint64_t t = 0, l = 0;
        size_t k = h3d_varint_get(rx + i, n - i, &t);
        if (!k) break;
        size_t k2 = h3d_varint_get(rx + i + k, n - i - k, &l);
        if (!k2) break;
        size_t hdr = k + k2;
        if (l > n - i - hdr) break;                  /* кадр ещё не весь */
        const uint8_t *p = rx + i + hdr;
        switch (t) {
        case H3D_HEADERS:
            if (!have) {
                int s = h3d_status(p, (size_t)l);
                if (s < 0) return bad(why, err, "заголовки ответа нарушают QPACK", H3D_E_QPACK_DECOMPRESSION);
                if (s == 0) return bad(why, err, "в ответе нет :status", H3D_E_MESSAGE_ERROR);
                if (s >= 200) { have = 1; st = s; }  /* 1xx — промежуточный, окончательный впереди */
            }
            break;                                   /* трейлеры — не читаем */
        case H3D_DATA:
            if (!have) return bad(why, err, "тело ответа раньше заголовков", H3D_E_FRAME_UNEXPECTED);
            total += (size_t)l;
            if (total > H3D_MSG_MAX) return bad(why, err, "тело ответа длиннее сообщения DNS", H3D_E_MESSAGE_ERROR);
            break;
        case 0x2: case 0x3: case 0x4: case 0x5: case 0x6: case 0x7: case 0x8: case 0x9: case 0xd:
            /* Кадры потока управления и перенумерованные кадры HTTP/2 на потоке запроса недопустимы
             * (RFC 9114, 7.2, 11.2.1). */
            return bad(why, err, "кадр не для потока запроса", H3D_E_FRAME_UNEXPECTED);
        default:
            break;                                   /* неизвестный: пропустить (RFC 9114, 9) */
        }
        i += hdr + (size_t)l;
    }
    if (i < n && fin) return bad(why, err, "поток закончен посреди кадра", H3D_E_FRAME_ERROR);
    if (!fin || i < n) return 0;
    if (!have) return bad(why, err, "ответ без окончательных заголовков", H3D_E_MESSAGE_ERROR);
    /* Тело — в начало буфера: кадры DATA склеиваются, обвязка выбрасывается. Назначение не обгоняет
     * источник, поэтому memmove без временного буфера. */
    size_t o = 0;
    for (i = 0; i < n;) {
        uint64_t t = 0, l = 0;
        size_t k = h3d_varint_get(rx + i, n - i, &t);
        size_t k2 = h3d_varint_get(rx + i + k, n - i - k, &l);
        if (t == H3D_DATA) { memmove(rx + o, rx + i + k + k2, (size_t)l); o += (size_t)l; }
        i += k + k2 + (size_t)l;
    }
    *status = st;
    *blen = o;
    return 1;
}

const char *h3d_errname(uint64_t code, char *buf, size_t cap) {
    switch (code) {
    case 0x100: return "H3_NO_ERROR";
    case 0x101: return "H3_GENERAL_PROTOCOL_ERROR";
    case 0x102: return "H3_INTERNAL_ERROR";
    case 0x103: return "H3_STREAM_CREATION_ERROR";
    case 0x104: return "H3_CLOSED_CRITICAL_STREAM";
    case 0x105: return "H3_FRAME_UNEXPECTED";
    case 0x106: return "H3_FRAME_ERROR";
    case 0x107: return "H3_EXCESSIVE_LOAD";
    case 0x108: return "H3_ID_ERROR";
    case 0x109: return "H3_SETTINGS_ERROR";
    case 0x10a: return "H3_MISSING_SETTINGS";
    case 0x10b: return "H3_REQUEST_REJECTED";
    case 0x10c: return "H3_REQUEST_CANCELLED";
    case 0x10d: return "H3_REQUEST_INCOMPLETE";
    case 0x10e: return "H3_MESSAGE_ERROR";
    case 0x10f: return "H3_CONNECT_ERROR";
    case 0x110: return "H3_VERSION_FALLBACK";
    case 0x200: return "QPACK_DECOMPRESSION_FAILED";
    case 0x201: return "QPACK_ENCODER_STREAM_ERROR";
    case 0x202: return "QPACK_DECODER_STREAM_ERROR";
    default: snprintf(buf, cap, "код 0x%llx", (unsigned long long)code); return buf;
    }
}
