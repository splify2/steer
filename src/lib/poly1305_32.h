/* Poly1305 (RFC 8439, раздел 2.5) на 32-битных словах — для 32-битных MIPS (mipsel_24kc, mips_24kc).
 *
 * ЗАЧЕМ. Поставляемая wolfSSL на 32-битной цели без ассемблера считает Poly1305 пятью 26-битными
 * ветвями: двадцать пять умножений 32x32->64 на блок, переносы между 64-битными суммами по одному и
 * побайтовая сборка пяти слов (poly1305.c, ветка «if not 64 bit then use 32 bit»). Здесь основание 2^32:
 * четыре слова состояния и ключа, шестнадцать умножений плюс одно малое, а на MIPS — цепочка
 * multu/maddu в паре HI:LO (суммы столбцов влезают в 64 бита: слова r клампятся до 28 бит, s = r + r/4
 * меньше 2^29, слово h — меньше 2^32, пять произведений — меньше 2^63). Чтение слов сообщения — через
 * memcpy: на MIPS это lwl/lwr, а не четыре lbu со сдвигами. Под qemu-user (относительные числа) блок
 * считается примерно вчетверо быстрее.
 *
 * Вывод столбцов (h = h0..h3 + 2^128*h4, r клампован: r1..r3 кратны 4, поэтому 5/4*r_j = r_j + (r_j >> 2)
 * без остатка; 2^128 = 5/4 * 2^130 = 5/4 (mod p)): слагаемое h_i*r_j с i+j >= 4 уходит в столбец
 * i+j-4 с множителем 5/4, то есть берёт s_j вместо r_j; h4*r0 остаётся в старшем столбце. Остаток после
 * неполной редукции — h4 <= 4, окончательная редукция и сложение с s — в sp32_final.
 *
 * Только заголовок: его читает src/lib/scrypto.c и tests/cpmatch.c (сверка с wolfSSL на случайных
 * входах и на предельных ключах). Правило тут одно: код здесь НЕ зависит от секретов ветвлениями —
 * ни одного условного перехода по данным ключа или сообщения. */
#ifndef STEER_POLY1305_32_H
#define STEER_POLY1305_32_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct sp32 {
    uint32_t r[4], s[3], pad[4], h[5];
    uint8_t buf[16];
    unsigned left;
};

static inline uint32_t sp32_ld(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}
static inline void sp32_st(uint8_t *p, uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    memcpy(p, &v, 4);
}

static inline void sp32_init(struct sp32 *st, const uint8_t key[32]) {
    st->r[0] = sp32_ld(key) & 0x0fffffffu;
    st->r[1] = sp32_ld(key + 4) & 0x0ffffffcu;
    st->r[2] = sp32_ld(key + 8) & 0x0ffffffcu;
    st->r[3] = sp32_ld(key + 12) & 0x0ffffffcu;
    for (int i = 0; i < 3; i++) st->s[i] = st->r[i + 1] + (st->r[i + 1] >> 2);
    for (int i = 0; i < 4; i++) st->pad[i] = sp32_ld(key + 16 + 4 * i);
    memset(st->h, 0, sizeof st->h);
    st->left = 0;
}

/* a0*b0 + a1*b1 + a2*b2 + a3*b3 (+ a4*b4): сумма влезает в 64 бита (r и s < 2^29, h < 2^32).
 * На 32-битном MIPS — цепочкой multu/maddu в регистровой паре HI:LO: компилятор выпускает
 * только три maddu из шестнадцати и считает остальные переносы по одному. */
#if defined(__mips__) && !defined(__mips64) && !defined(STEER_POLY32_PORTABLE)
static inline uint64_t sp32_dot4(uint32_t a0, uint32_t b0, uint32_t a1, uint32_t b1, uint32_t a2, uint32_t b2,
                                 uint32_t a3, uint32_t b3) {
    uint32_t lo, hi;
    __asm__("multu %2,%3\n\tmaddu %4,%5\n\tmaddu %6,%7\n\tmaddu %8,%9\n\tmflo %0\n\tmfhi %1"
            : "=&r"(lo), "=&r"(hi)
            : "r"(a0), "r"(b0), "r"(a1), "r"(b1), "r"(a2), "r"(b2), "r"(a3), "r"(b3)
            : "hi", "lo");
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t sp32_dot5(uint32_t a0, uint32_t b0, uint32_t a1, uint32_t b1, uint32_t a2, uint32_t b2,
                                 uint32_t a3, uint32_t b3, uint32_t a4, uint32_t b4) {
    uint32_t lo, hi;
    __asm__("multu %2,%3\n\tmaddu %4,%5\n\tmaddu %6,%7\n\tmaddu %8,%9\n\tmaddu %10,%11\n\tmflo %0\n\tmfhi %1"
            : "=&r"(lo), "=&r"(hi)
            : "r"(a0), "r"(b0), "r"(a1), "r"(b1), "r"(a2), "r"(b2), "r"(a3), "r"(b3), "r"(a4), "r"(b4)
            : "hi", "lo");
    return ((uint64_t)hi << 32) | lo;
}
#else
static inline uint64_t sp32_dot4(uint32_t a0, uint32_t b0, uint32_t a1, uint32_t b1, uint32_t a2, uint32_t b2,
                                 uint32_t a3, uint32_t b3) {
    return (uint64_t)a0 * b0 + (uint64_t)a1 * b1 + (uint64_t)a2 * b2 + (uint64_t)a3 * b3;
}
static inline uint64_t sp32_dot5(uint32_t a0, uint32_t b0, uint32_t a1, uint32_t b1, uint32_t a2, uint32_t b2,
                                 uint32_t a3, uint32_t b3, uint32_t a4, uint32_t b4) {
    return sp32_dot4(a0, b0, a1, b1, a2, b2, a3, b3) + (uint64_t)a4 * b4;
}
#endif

static inline void sp32_blocks(struct sp32 *st, const uint8_t *m, size_t nb, uint32_t hibit) {
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3];
    const uint32_t s1 = st->s[0], s2 = st->s[1], s3 = st->s[2];
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (nb--) {
        uint64_t t;
        t = (uint64_t)h0 + sp32_ld(m);          h0 = (uint32_t)t;
        t = (uint64_t)h1 + sp32_ld(m + 4) + (t >> 32);  h1 = (uint32_t)t;
        t = (uint64_t)h2 + sp32_ld(m + 8) + (t >> 32);  h2 = (uint32_t)t;
        t = (uint64_t)h3 + sp32_ld(m + 12) + (t >> 32); h3 = (uint32_t)t;
        h4 += (uint32_t)(t >> 32) + hibit;
        m += 16;

        uint64_t d0 = sp32_dot4(h0, r0, h1, s3, h2, s2, h3, s1);
        uint64_t d1 = sp32_dot5(h0, r1, h1, r0, h2, s3, h3, s2, h4, s1);
        uint64_t d2 = sp32_dot5(h0, r2, h1, r1, h2, r0, h3, s3, h4, s2);
        uint64_t d3 = sp32_dot5(h0, r3, h1, r2, h2, r1, h3, r0, h4, s3);
        uint32_t d4 = h4 * r0;

        h0 = (uint32_t)d0;
        d1 += d0 >> 32; h1 = (uint32_t)d1;
        d2 += d1 >> 32; h2 = (uint32_t)d2;
        d3 += d2 >> 32; h3 = (uint32_t)d3;
        h4 = d4 + (uint32_t)(d3 >> 32);

        /* неполная редукция: 2^130 = 5 (mod p) */
        t = (uint64_t)(h4 >> 2) * 5 + h0;       h0 = (uint32_t)t;
        t = (uint64_t)h1 + (t >> 32);           h1 = (uint32_t)t;
        t = (uint64_t)h2 + (t >> 32);           h2 = (uint32_t)t;
        t = (uint64_t)h3 + (t >> 32);           h3 = (uint32_t)t;
        h4 = (h4 & 3) + (uint32_t)(t >> 32);
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static inline void sp32_update(struct sp32 *st, const uint8_t *m, size_t n) {
    if (st->left) {
        size_t k = 16 - st->left;
        if (k > n) k = n;
        memcpy(st->buf + st->left, m, k);
        st->left += (unsigned)k; m += k; n -= k;
        if (st->left < 16) return;
        sp32_blocks(st, st->buf, 1, 1);
        st->left = 0;
    }
    if (n >= 16) {
        size_t nb = n / 16;
        sp32_blocks(st, m, nb, 1);
        m += nb * 16; n -= nb * 16;
    }
    if (n) { memcpy(st->buf, m, n); st->left = (unsigned)n; }
}

static inline void sp32_final(struct sp32 *st, uint8_t tag[16]) {
    if (st->left) {
        memset(st->buf + st->left, 0, 16 - st->left);
        st->buf[st->left] = 1;
        sp32_blocks(st, st->buf, 1, 0);
        st->left = 0;
    }
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint64_t t;
    /* h < 2^131: ещё раз свернуть старшие биты, чтобы h4 <= 3 */
    t = (uint64_t)(h4 >> 2) * 5 + h0;   h0 = (uint32_t)t;
    t = (uint64_t)h1 + (t >> 32);       h1 = (uint32_t)t;
    t = (uint64_t)h2 + (t >> 32);       h2 = (uint32_t)t;
    t = (uint64_t)h3 + (t >> 32);       h3 = (uint32_t)t;
    h4 = (h4 & 3) + (uint32_t)(t >> 32);
    /* g = h + 5; если g >= 2^130, то h = g mod 2^130 */
    uint64_t g;
    uint32_t g0, g1, g2, g3, g4;
    g = (uint64_t)h0 + 5;       g0 = (uint32_t)g;
    g = (uint64_t)h1 + (g >> 32); g1 = (uint32_t)g;
    g = (uint64_t)h2 + (g >> 32); g2 = (uint32_t)g;
    g = (uint64_t)h3 + (g >> 32); g3 = (uint32_t)g;
    g4 = h4 + (uint32_t)(g >> 32);
    uint32_t mask = (uint32_t)0 - (g4 >> 2);   /* все единицы, если g >= 2^130 */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    /* tag = (h + s) mod 2^128 */
    t = (uint64_t)h0 + st->pad[0];            sp32_st(tag, (uint32_t)t);
    t = (uint64_t)h1 + st->pad[1] + (t >> 32); sp32_st(tag + 4, (uint32_t)t);
    t = (uint64_t)h2 + st->pad[2] + (t >> 32); sp32_st(tag + 8, (uint32_t)t);
    t = (uint64_t)h3 + st->pad[3] + (t >> 32); sp32_st(tag + 12, (uint32_t)t);
}
#endif
