/* ChaCha20-Poly1305 своим порядком (src/lib/scrypto.c, ветка SC_CP_OWN, src/lib/poly1305_32.h) против
 * wolfSSL: та же ветка, что на 32-битном MIPS, но собранная на хосте (-DSTEER_CP_OWN
 * -DSTEER_POLY32_PORTABLE) — логика проверяется здесь, а команды multu/maddu — тем же файлом под
 * qemu-user (tests/cpmips.sh). Сверка случайная, с предельными ключами (r и s из одних единиц, сообщение из
 * 0xff — худший случай для переносов), со всеми четырьмя выравниваниями буфера и со всеми длинами у границ
 * блока (16, 64) и куска обмена (256). Любое расхождение — провал.
 *
 * Собирается с ключами wolfSSL (как scrypto.c): против него идёт сравнение. */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scrypto.h"
#include "poly1305_32.h"

static unsigned long long rs = 88172645463325252ULL;
static unsigned rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (unsigned)(rs >> 16); }
static int fails;
#define FAIL(...) do { if (fails++ < 10) { printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static void poly_cases(void) {
    static unsigned char m[5000];
    unsigned char key[32], t1[16], t2[16];
    int n = 0, bad = 0;
    for (int it = 0; it < 20000; it++) {
        int mode = it % 4;   /* 0 — случайно; 1 — ключ и данные из 0xff; 2 — данные из 0xff; 3 — с нулями */
        for (int i = 0; i < 32; i++) key[i] = mode == 1 ? 0xff : (unsigned char)rnd();
        size_t len = rnd() % (it < 3000 ? 5000 : 300);
        for (size_t i = 0; i < len; i++)
            m[i] = (mode == 1 || mode == 2) ? 0xff : (mode == 3 && rnd() % 3 == 0) ? 0 : (unsigned char)rnd();
        Poly1305 p;
        struct sp32 s;
        wc_Poly1305SetKey(&p, key, 32);
        sp32_init(&s, key);
        for (size_t off = 0; off < len;) {   /* куски разной длины: остаток блока между вызовами */
            size_t k = rnd() % 40;
            if (k > len - off) k = len - off;
            wc_Poly1305Update(&p, m + off, k);
            sp32_update(&s, m + off, k);
            off += k;
        }
        wc_Poly1305Final(&p, t1);
        sp32_final(&s, t2);
        n++;
        if (memcmp(t1, t2, 16)) { bad++; FAIL("poly1305 расходится: режим %d, длина %zu", mode, len); }
    }
    printf("cpmatch: poly1305 свой против wolfSSL: %d случаев, расхождений %d\n", n, bad);
}

static void aead_cases(void) {
    enum { PAD = 8, MAXN = 3300 };
    static unsigned char arena[MAXN + 2 * PAD + 8], ref_ct[MAXN], ref_pt[MAXN], aadb[128];
    static const size_t edge[] = { 0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 255, 256, 257, 511, 512, 513, 1400, 1500 };
    int cases = 0, bad = 0;
    struct sc_aead k;
    unsigned char key[32], nonce[12], tag[16], rtag[16];
    for (int it = 0; it < 6000; it++) {
        if (it % 8 == 0) {
            for (int i = 0; i < 32; i++) key[i] = (unsigned char)rnd();
            if (sc_aead_setkey(&k, SC_CHACHA20_POLY1305, key) != 0) { FAIL("setkey"); return; }
        }
        for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)rnd();
        size_t n = it < 400 ? edge[it % (sizeof edge / sizeof *edge)] : rnd() % MAXN;
        size_t an = rnd() % 100;
        unsigned off = it % 4;
        for (size_t i = 0; i < an; i++) aadb[i] = (unsigned char)rnd();
        unsigned char *buf = arena + PAD + off;
        memset(arena, 0xa5, sizeof arena);
        for (size_t i = 0; i < n; i++) ref_pt[i] = buf[i] = (unsigned char)rnd();
        if (wc_ChaCha20Poly1305_Encrypt(key, nonce, aadb, (word32)an, ref_pt, (word32)n, ref_ct, rtag) != 0) { FAIL("эталон"); return; }
        if (sc_aead_seal(&k, nonce, aadb, an, buf, n, tag) != 0) FAIL("seal отказал: n=%zu", n);
        cases++;
        if (memcmp(buf, ref_ct, n) || memcmp(tag, rtag, 16)) { bad++; FAIL("seal расходится: n=%zu aad=%zu смещение %u", n, an, off); }
        for (int i = 0; i < PAD + (int)off; i++) if (arena[i] != 0xa5) { bad++; FAIL("запись до буфера"); break; }
        for (size_t i = PAD + off + n; i < sizeof arena; i++) if (arena[i] != 0xa5) { bad++; FAIL("запись за буфером: n=%zu", n); break; }
        /* расшифровка того же */
        if (sc_aead_open(&k, nonce, aadb, an, buf, n, tag) != 0) FAIL("open отказал: n=%zu", n);
        if (memcmp(buf, ref_pt, n)) { bad++; FAIL("open расходится: n=%zu смещение %u", n, off); }
        /* подмена: тег, шифртекст, AAD — отказ SC_EAUTH, буфер обнулён (как у wolfSSL) */
        memcpy(buf, ref_ct, n);
        unsigned char badtag[16];
        memcpy(badtag, rtag, 16);
        badtag[rnd() % 16] ^= (unsigned char)(1u << (rnd() % 8));
        if (sc_aead_open(&k, nonce, aadb, an, buf, n, badtag) != SC_EAUTH) { bad++; FAIL("подменённый тег принят: n=%zu", n); }
        else { size_t z = 0; for (size_t i = 0; i < n; i++) z |= buf[i]; if (z) { bad++; FAIL("после отказа буфер не обнулён"); } }
        if (n) {
            memcpy(buf, ref_ct, n);
            buf[rnd() % n] ^= 0x40;
            if (sc_aead_open(&k, nonce, aadb, an, buf, n, rtag) != SC_EAUTH) { bad++; FAIL("подменённый шифртекст принят: n=%zu", n); }
        }
        if (an) {
            memcpy(buf, ref_ct, n);
            aadb[rnd() % an] ^= 1;
            if (sc_aead_open(&k, nonce, aadb, an, buf, n, rtag) != SC_EAUTH) { bad++; FAIL("подменённый AAD принят"); }
        }
    }
    sc_aead_free(&k);
    printf("cpmatch: ChaCha20-Poly1305 слой против wolfSSL: %d записей (смещения 0..3), расхождений %d\n", cases, bad);
}

int main(void) {
    poly_cases();
    aead_cases();
    if (fails) { printf("cpmatch: ПРОВАЛ (%d)\n", fails); return 1; }
    printf("cpmatch: ok\n");
    return 0;
}
