/* DoH по HTTP/2: кадры и HPACK без сети. Устройство и доводы — в doh2.h. */
#include <stdio.h>
#include <string.h>

#include "doh2.h"

static void put24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

int h2d_next(const uint8_t *buf, size_t n, struct h2d_frame *f) {
    if (n < 9) return 0;
    size_t len = ((size_t)buf[0] << 16) | ((size_t)buf[1] << 8) | buf[2];
    if (len > H2D_MAX_FRAME) return -1;
    if (n < 9 + len) return 0;
    f->type = buf[3];
    f->flags = buf[4];
    f->sid = (((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 8) | buf[8]) & 0x7FFFFFFFu;
    f->body = buf + 9;
    f->len = len;
    f->total = 9 + len;
    return 1;
}

size_t h2d_frame_put(uint8_t *dst, size_t cap, uint8_t type, uint8_t flags, uint32_t sid,
                     const uint8_t *body, size_t n) {
    if (n > H2D_MAX_FRAME || cap < 9 + n) return 0;
    put24(dst, (uint32_t)n);
    dst[3] = type;
    dst[4] = flags;
    put32(dst + 5, sid);
    if (n) memcpy(dst + 9, body, n);
    return 9 + n;
}

size_t h2d_hello(uint8_t *dst, size_t cap) {
    static const char pre[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    /* Два параметра по шесть байт: HEADER_TABLE_SIZE = 0 (ответ без динамической таблицы) и
     * ENABLE_PUSH = 0 (PUSH_PROMISE не придёт, разбирать его нечем). Окна, число потоков и размер
     * кадра — значения по умолчанию: ответ на вопрос DNS ≤ 64 КиБ, то есть ровно в окно потока. */
    static const uint8_t st[12] = { 0, H2D_S_HEADER_TABLE_SIZE, 0, 0, 0, 0,
                                    0, H2D_S_ENABLE_PUSH,       0, 0, 0, 0 };
    if (cap < 24 + 9 + sizeof(st)) return 0;
    memcpy(dst, pre, 24);
    return 24 + h2d_frame_put(dst + 24, cap - 24, H2D_SETTINGS, 0, 0, st, sizeof(st));
}

/* ---- HPACK: запись ---------------------------------------------------------------------------- */

struct wb { uint8_t *p; size_t n, cap; };
static void wput(struct wb *b, const void *d, size_t n) {
    if (b->n + n <= b->cap) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void wbyte(struct wb *b, unsigned v) { uint8_t c = (uint8_t)v; wput(b, &c, 1); }

/* Целое HPACK с префиксом в bits бит (RFC 7541, 5.1). */
static void hp_int(struct wb *b, unsigned prefix, unsigned bits, uint32_t v) {
    uint32_t max = (1u << bits) - 1;
    if (v < max) { wbyte(b, prefix | v); return; }
    wbyte(b, prefix | max);
    v -= max;
    while (v >= 128) { wbyte(b, (v & 0x7F) | 0x80); v >>= 7; }
    wbyte(b, v);
}

/* Литерал без индексации: имя из статической таблицы по номеру, значение строкой без Хаффмана. */
static void hp_lit(struct wb *b, unsigned name_idx, const char *v) {
    size_t n = strlen(v);
    hp_int(b, 0x00, 4, name_idx);
    hp_int(b, 0x00, 7, (uint32_t)n);
    wput(b, v, n);
}

size_t h2d_request(uint8_t *dst, size_t cap, uint32_t sid, const char *authority, const char *path,
                   const uint8_t *q, size_t qn) {
    if (qn < 12 || qn > H2D_MAX_FRAME - 1) return 0;
    uint8_t hb[1024];
    struct wb h = { hb, 0, sizeof(hb) };
    char len[16];
    snprintf(len, sizeof(len), "%zu", qn);
    wbyte(&h, 0x80 | 3);                         /* :method: POST (статическая 3) */
    wbyte(&h, 0x80 | 7);                         /* :scheme: https (7) */
    hp_lit(&h, 4, path);                         /* :path */
    hp_lit(&h, 1, authority);                    /* :authority */
    hp_lit(&h, 31, "application/dns-message");   /* content-type */
    hp_lit(&h, 19, "application/dns-message");   /* accept */
    hp_lit(&h, 28, len);                         /* content-length */
    if (h.n > sizeof(hb) || h.n > H2D_MAX_FRAME) return 0;
    size_t o = h2d_frame_put(dst, cap, H2D_HEADERS, H2D_F_END_HEADERS, sid, hb, h.n);
    if (!o) return 0;
    uint8_t body[H2D_MAX_FRAME];
    memcpy(body, q, qn);
    body[0] = body[1] = 0;
    size_t d = h2d_frame_put(dst + o, cap - o, H2D_DATA, H2D_F_END_STREAM, sid, body, qn);
    return d ? o + d : 0;
}

/* ---- HPACK: чтение статуса --------------------------------------------------------------------- */

/* Целое с префиксом; -1 — оборвано или слишком велико. *i сдвигается за целое. */
static int64_t hp_dint(const uint8_t *p, size_t n, size_t *i, unsigned bits) {
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

/* Три цифры статуса кодом Хаффмана (RFC 7541, приложение B): «0»…«2» — пятибитные коды 00000…00010,
 * «3»…«9» — шестибитные 011001…011111. Остальные знаки — не статус (-1). Остаток короче байта —
 * набивка единицами (5.2). */
static int status_huff(const uint8_t *p, size_t n) {
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t i = 0;
    int v = 0, digits = 0;
    for (;;) {
        while (bits < 6 && i < n) { acc = (acc << 8) | p[i++]; bits += 8; }
        if (i == n && bits < 8 && acc == (1u << bits) - 1) break;   /* конец: набивка единицами */
        if (bits < 5) return -1;
        unsigned c5 = (acc >> (bits - 5)) & 0x1F, d;
        if (c5 <= 2) { d = c5; bits -= 5; }
        else {
            if (bits < 6) return -1;
            unsigned c6 = (acc >> (bits - 6)) & 0x3F;
            if (c6 < 0x19 || c6 > 0x1F) return -1;  /* выше 0x1F — '=', 'A', '_' и прочие, не цифры */
            d = c6 - 0x19 + 3;
            bits -= 6;
        }
        v = v * 10 + (int)d;
        if (++digits > 3) return -1;
        acc &= (1u << bits) - 1;
    }
    return digits == 3 ? v : -1;
}

int h2d_status_value(const uint8_t *p, size_t n, int huff) {
    if (!huff) {
        if (n != 3 || p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9' || p[2] < '0' || p[2] > '9') return -1;
        return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    }
    return status_huff(p, n);
}

int h2d_status(const uint8_t *blk, size_t n) {
    size_t i = 0;
    int status = 0;
    while (i < n) {
        uint8_t b = blk[i];
        if (b & 0x80) {                          /* поле по номеру */
            int64_t idx = hp_dint(blk, n, &i, 7);
            if (idx <= 0 || idx > 61) return -1; /* 0 не бывает, выше 61 — динамическая таблица */
            static const int st[] = { 200, 204, 206, 304, 400, 404, 500 };
            if (idx >= 8 && idx <= 14 && !status) status = st[idx - 8];
            continue;
        }
        if ((b & 0xE0) == 0x20) {                /* новый размер таблицы: значение нам безразлично */
            if (hp_dint(blk, n, &i, 5) < 0) return -1;
            continue;
        }
        /* Литерал: с индексацией (01, 6 бит), без неё (0000) или никогда (0001) — 4 бита. */
        unsigned bits = (b & 0x40) ? 6 : 4;
        int64_t nidx = hp_dint(blk, n, &i, bits);
        if (nidx < 0 || nidx > 61) return -1;
        int is_status = nidx == 8;
        if (nidx == 0) {                         /* имя строкой */
            if (i >= n) return -1;
            int nh = (blk[i] & 0x80) != 0;
            int64_t nl = hp_dint(blk, n, &i, 7);
            if (nl < 0 || (size_t)nl > n - i) return -1;
            is_status = !nh && nl == 7 && memcmp(blk + i, ":status", 7) == 0;
            i += (size_t)nl;
        }
        if (i >= n) return -1;
        int vh = (blk[i] & 0x80) != 0;
        int64_t vl = hp_dint(blk, n, &i, 7);
        if (vl < 0 || (size_t)vl > n - i) return -1;
        if (is_status && !status) {
            int v = h2d_status_value(blk + i, (size_t)vl, vh);
            if (v < 100 || v > 599) return -1;
            status = v;
        }
        i += (size_t)vl;
    }
    return status;
}

const char *h2d_errname(uint32_t code, char *buf, size_t cap) {
    static const char *const nm[] = { "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR",
                                      "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM",
                                      "CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM",
                                      "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED" };
    if (code < sizeof(nm) / sizeof(nm[0])) return nm[code];
    snprintf(buf, cap, "код %u", code);
    return buf;
}
