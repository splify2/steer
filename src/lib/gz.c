/* gzip из памяти потоком (gz.h). Окно распаковки — 32 КиБ внутри puff_stream, результат целиком
 * нигде не копится, поэтому размер распакованного ничем не ограничен.
 *
 * Сверяется всё, что даёт обёртка (RFC 1952): метод, длина и CRC-32 распакованного. Битый gzip —
 * отказ, а не «что распаковалось». Склеенные члены (несколько gzip подряд) не читаются: после
 * первого читается только то, что внутри него, остаток входа игнорируется — так делал и прежний
 * разбор подписки, а `tar czf` и панели подписок отдают один член. */
#include <stdlib.h>
#include <string.h>
#include "gz.h"
#include "puff.h"

struct gz {
    struct puff_stream ps;
    const unsigned char *z;
    size_t n, off;                 /* вход и начало DEFLATE в нём */
    unsigned long crc, total;
    int state;                     /* 0 — идёт, 1 — кончился и хвост сошёлся, -1 — испорчен */
    unsigned long tab[256];
};

static unsigned long crc_add(const unsigned long *tab, unsigned long c, const unsigned char *p, size_t n) {
    c = ~c & 0xffffffffUL;
    while (n--) c = tab[(c ^ *p++) & 0xff] ^ (c >> 8);
    return ~c & 0xffffffffUL;
}

struct gz *gz_open(const void *zv, size_t n) {
    const unsigned char *z = zv;
    if (n < 18 || z[0] != 0x1f || z[1] != 0x8b || z[2] != 8) return NULL;   /* 8 — deflate, другого нет */
    /* Заголовок: 10 байт и необязательные поля по флагам. */
    unsigned flg = z[3];
    size_t off = 10;
    if (flg & 4) {                                   /* FEXTRA */
        if (off + 2 > n) return NULL;
        off += 2 + (size_t)(z[off] | (z[off + 1] << 8));
    }
    for (unsigned bit = 8; bit <= 16; bit <<= 1)     /* FNAME, FCOMMENT: строки до нуля */
        if (flg & bit) {
            while (off < n && z[off]) off++;
            off++;
        }
    if (flg & 2) off += 2;                           /* FHCRC */
    if (off + 8 > n) return NULL;

    struct gz *g = calloc(1, sizeof *g);
    if (!g) return NULL;
    g->z = z;
    g->n = n;
    g->off = off;
    for (unsigned i = 0; i < 256; i++) {
        unsigned long c = i;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320UL & (0UL - (c & 1)));
        g->tab[i] = c;
    }
    puff_stream_init(&g->ps, z + off, (unsigned long)(n - off - 8));
    return g;
}

long gz_read(struct gz *g, void *dstv, size_t cap) {
    if (g->state) return g->state < 0 ? -1 : 0;
    if (!cap) return 0;
    long k = puff_stream_read(&g->ps, dstv, cap < 65536 ? cap : 65536);
    if (k < 0) { g->state = -1; return -1; }
    if (k > 0) {
        g->crc = crc_add(g->tab, g->crc, dstv, (size_t)k);
        g->total += (unsigned long)k;
        return k;
    }
    /* Поток кончился: хвост — сразу за последним байтом DEFLATE, CRC-32 и длина по модулю 2^32. */
    const unsigned char *t = g->z + g->off + g->ps.incnt;
    if (!puff_stream_done(&g->ps) || t + 8 > g->z + g->n ||
        (t[0] | t[1] << 8 | t[2] << 16 | (unsigned long)t[3] << 24) != g->crc ||
        (t[4] | t[5] << 8 | t[6] << 16 | (unsigned long)t[7] << 24) != (g->total & 0xffffffffUL)) {
        g->state = -1;
        return -1;
    }
    g->state = 1;
    return 0;
}

size_t gz_trailing(const struct gz *g) {
    size_t used = g->off + g->ps.incnt + 8;
    return g->state == 1 && used <= g->n ? g->n - used : 0;
}

void gz_close(struct gz *g) {
    free(g);
}
