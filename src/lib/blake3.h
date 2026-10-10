/* BLAKE3 для VLESS encryption: хеш и вывод ключа (derive_key), портативным C, без библиотеки.
 *
 * ЗАЧЕМ СВОЙ. VLESS encryption в Xray-core (proxy/vless/encryption) стоит на BLAKE3: им выводится
 * каждый ключ AEAD (blake3.DeriveKey(k, string(ctx), key) в NewAEAD), ключ гаммы xorpub/random
 * (DeriveKey с контекстом "VLESS") и хеш ключей реле (blake3.Sum256). Совместимость с сервером — это
 * байт в байт тот же BLAKE3, а в wolfSSL 5.9.4 его нет (есть BLAKE2). Зависимость ради двух функций
 * не оправдана: алгоритм — это сорок строк сжатия и дерево из чанков.
 *
 * ПОЧЕМУ ЗАГОЛОВОК СО static, а не отдельный .c. Публичные sc_blake3_* определены в scrypto.c (они часть
 * слоя примитивов), а собирается scrypto.c в шести местах по-разному (ext-test.sh, dnsup.sh, bench.sh,
 * Android.bp, build-ext.sh, sources.mk): ещё один файл значил бы шесть правок и шесть мест, где его
 * можно забыть. Заголовок цепляется одним #include, а стенд `make test` (tests/b3match.c) включает
 * его сам и проверяет BLAKE3 без wolfSSL.
 *
 * ПОЧЕМУ ВЕСЬ ВХОД ЗА РАЗ, а не потоковый интерфейс. Все входы у VLESS encryption известны целиком до
 * вызова (ключи, iv, шифротекст, открытый ключ), поэтому потоковое состояние — лишний код и лишние
 * ошибки. Зато вход НЕ ограничен одним чанком: контекст NewAEAD — это pfsPublicKey длиной 1216 байт,
 * то есть 2 чанка по 1024, а хеш открытого ключа ML-KEM (1184 байта) — тоже 2. Поэтому дерево
 * (родительские узлы, стек значений цепочки) реализовано полностью и проверено векторами из
 * репозитория BLAKE3 на длинах 0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 3073, 31744 —
 * это границы блока, чанка и глубины дерева (tests/scryptomatch.c).
 *
 * Скорость не критична: вызовов на рукопожатие десяток, на запись данных — ни одного (ключ записи
 * выводится один раз на смену ключа, то есть раз в 2^96 записей, см. vlenc.c). Потому — переносимый C
 * без SIMD; подробность о векторных вариантах reference implementation не нужна. */
#ifndef STEER_BLAKE3_H
#define STEER_BLAKE3_H
#include <stdint.h>
#include <string.h>
#include "wipe.h"

#define B3_CHUNK_START 1u
#define B3_CHUNK_END 2u
#define B3_PARENT 4u
#define B3_ROOT 8u
#define B3_DERIVE_CONTEXT 32u
#define B3_DERIVE_MATERIAL 64u

static const uint32_t B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

static const uint8_t B3_PERM[16] = { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static inline void g(uint32_t *s, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx; s[d] = rotr(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];      s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my; s[d] = rotr(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];      s[b] = rotr(s[b] ^ s[c], 7);
}

static void round_fn(uint32_t *s, const uint32_t *m) {
    g(s, 0, 4, 8, 12, m[0], m[1]);   g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);  g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);  g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]); g(s, 3, 4, 9, 14, m[14], m[15]);
}

/* Сжатие одного блока. out — все 16 слов состояния после финального XOR: первые 8 — новое значение
 * цепочки, все 16 — расширяемый вывод корня. */
static void compress(const uint32_t cv[8], const uint8_t blk[64], uint8_t blen, uint64_t ctr,
                     uint32_t flags, uint32_t out[16]) {
    uint32_t m[16], s[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)blk[4 * i] | (uint32_t)blk[4 * i + 1] << 8 |
               (uint32_t)blk[4 * i + 2] << 16 | (uint32_t)blk[4 * i + 3] << 24;
    memcpy(s, cv, 32);
    memcpy(s + 8, B3_IV, 16);
    s[12] = (uint32_t)ctr; s[13] = (uint32_t)(ctr >> 32); s[14] = blen; s[15] = flags;
    for (int r = 0; r < 7; r++) {
        round_fn(s, m);
        if (r < 6) {
            uint32_t t[16];
            for (int i = 0; i < 16; i++) t[i] = m[B3_PERM[i]];
            memcpy(m, t, sizeof m);
        }
    }
    for (int i = 0; i < 8; i++) { s[i] ^= s[i + 8]; s[i + 8] ^= cv[i]; }
    memcpy(out, s, 64);
}

/* Отложенное сжатие: последний узел (блок последнего чанка либо родитель) сжимается дважды —
 * значением цепочки для вышестоящего узла и с флагом ROOT для вывода, поэтому хранится не результат,
 * а входы. */
struct b3_out { uint32_t cv[8]; uint8_t blk[64]; uint8_t blen; uint64_t ctr; uint32_t flags; };

static void out_cv(const struct b3_out *o, uint32_t cv[8]) {
    uint32_t w[16];
    compress(o->cv, o->blk, o->blen, o->ctr, o->flags, w);
    memcpy(cv, w, 32);
}

static void put_words(uint8_t *dst, const uint32_t *w, int n) {
    for (int i = 0; i < n; i++) {
        dst[4 * i] = (uint8_t)w[i]; dst[4 * i + 1] = (uint8_t)(w[i] >> 8);
        dst[4 * i + 2] = (uint8_t)(w[i] >> 16); dst[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

static void out_root(const struct b3_out *o, uint8_t *out, size_t n) {
    uint64_t blockno = 0;
    while (n) {
        uint32_t w[16];
        uint8_t buf[64];
        compress(o->cv, o->blk, o->blen, blockno++, o->flags | B3_ROOT, w);
        put_words(buf, w, 16);
        size_t take = n < 64 ? n : 64;
        memcpy(out, buf, take);
        out += take; n -= take;
    }
}

/* Узел, чей вход — один чанк (до 1024 байт), кроме сжатия ПОСЛЕДНЕГО блока: его возвращает как b3_out. */
static struct b3_out chunk_out(const uint32_t key[8], const uint8_t *in, size_t n, uint64_t ctr,
                               uint32_t flags) {
    uint32_t cv[8];
    memcpy(cv, key, 32);
    uint32_t start = B3_CHUNK_START;
    while (n > 64) {
        uint32_t w[16];
        compress(cv, in, 64, ctr, flags | start, w);
        memcpy(cv, w, 32);
        in += 64; n -= 64; start = 0;
    }
    struct b3_out o;
    memcpy(o.cv, cv, 32);
    memset(o.blk, 0, 64);
    if (n) memcpy(o.blk, in, n);
    o.blen = (uint8_t)n; o.ctr = ctr; o.flags = flags | start | B3_CHUNK_END;
    return o;
}

static struct b3_out parent_out(const uint32_t key[8], const uint32_t l[8], const uint32_t r[8],
                                uint32_t flags) {
    struct b3_out o;
    memcpy(o.cv, key, 32);
    put_words(o.blk, l, 8);
    put_words(o.blk + 32, r, 8);
    o.blen = 64; o.ctr = 0; o.flags = flags | B3_PARENT;
    return o;
}

/* Хеш всего входа с ключом key и флагами flags (0 либо DERIVE_*), вывод n байт. */
static void b3_run(const uint32_t key[8], uint32_t flags, const uint8_t *in, size_t n,
                   uint8_t *out, size_t out_n) {
    uint32_t stack[54][8];
    int depth = 0;
    uint64_t chunks = 0;
    /* Все чанки, кроме последнего, сворачиваются в стек; последний остаётся отложенным. */
    while (n > 1024) {
        struct b3_out c = chunk_out(key, in, 1024, chunks, flags);
        uint32_t cv[8];
        out_cv(&c, cv);
        in += 1024; n -= 1024;
        chunks++;
        for (uint64_t t = chunks; (t & 1) == 0; t >>= 1) {
            struct b3_out p = parent_out(key, stack[--depth], cv, flags);
            out_cv(&p, cv);
        }
        memcpy(stack[depth++], cv, 32);
    }
    struct b3_out o = chunk_out(key, in, n, chunks, flags);
    while (depth) {
        uint32_t cv[8];
        out_cv(&o, cv);
        o = parent_out(key, stack[--depth], cv, flags);
    }
    out_root(&o, out, out_n);
}

static void b3_hash(unsigned char out[32], const void *in, size_t n) {
    b3_run(B3_IV, 0, in, n, out, 32);
}

static void b3_derive_key(unsigned char *out, size_t out_n, const void *ctx, size_t ctx_n,
                          const void *material, size_t material_n) {
    uint8_t ck[32];
    uint32_t key[8];
    b3_run(B3_IV, B3_DERIVE_CONTEXT, ctx, ctx_n, ck, 32);
    for (int i = 0; i < 8; i++)
        key[i] = (uint32_t)ck[4 * i] | (uint32_t)ck[4 * i + 1] << 8 |
                 (uint32_t)ck[4 * i + 2] << 16 | (uint32_t)ck[4 * i + 3] << 24;
    b3_run(key, B3_DERIVE_MATERIAL, material, material_n, out, out_n);
    steer_wipe(ck, sizeof ck);
    steer_wipe(key, sizeof key);
}

#endif
