/* Слой криптографических примитивов на wolfCrypt. Зачем слой и почему контексты устроены так,
 * как устроены, — в scrypto.h.
 *
 * Это ЕДИНСТВЕННЫЙ файл движка, который видит wolfSSL. Опции библиотеки — в
 * build/wolfssl/user_settings.h, и этот файл обязан компилироваться с ними же (ключ
 * -DWOLFSSL_USER_SETTINGS и -I на build/wolfssl), иначе размеры структур здесь и в библиотеке
 * разойдутся. Проверки _Static_assert ниже ловят только то, что хранилище в заголовке мало; то,
 * что библиотека собрана с другими опциями, ловится лишь тем, что сборка у нас одна
 * (build/wolfssl/build.sh, Android.bp — сверяет tests/buildmatch.sh).
 *
 * Правило для правок: ни одна функция не возвращает кодов wolfSSL наружу — только SC_*.
 * Код библиотеки ничего не говорит вызывающему, а смена библиотеки не должна менять ни одной
 * ветки у него. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

#include "scrypto.h"
#include "blake3.h"
#include "poly1305_32.h"

/* ---- хранилища против настоящих размеров --------------------------------------------------
 *
 * Хранилище в заголовке — массив байт с выравниванием 16; в нём лежит объект wolfSSL. Проверка
 * здесь, а не в рантайме: слишком маленькое хранилище — это не ошибка, которую можно вернуть,
 * а запись за пределы поля, и узнать о ней надо при сборке под ту архитектуру, где она случится. */
_Static_assert(sizeof(wc_Sha256) <= SC_HASH_CTX_SIZE && _Alignof(wc_Sha256) <= 16, "SC_HASH_CTX_SIZE мал для wc_Sha256");
_Static_assert(sizeof(wc_Sha512) <= SC_HASH_CTX_SIZE && _Alignof(wc_Sha512) <= 16, "SC_HASH_CTX_SIZE мал для wc_Sha512");
_Static_assert(sizeof(wc_Sha384) <= SC_HASH_CTX_SIZE && _Alignof(wc_Sha384) <= 16, "SC_HASH_CTX_SIZE мал для wc_Sha384");
_Static_assert(sizeof(Aes) <= SC_AEAD_CTX_SIZE && _Alignof(Aes) <= 16, "SC_AEAD_CTX_SIZE мал для Aes");
_Static_assert(sizeof(Aes) <= SC_AESCTR_CTX_SIZE, "SC_AESCTR_CTX_SIZE мал для Aes");
/* Хеши протоколов steer-proxy (scrypto.h). wc_Sha224 у wolfSSL — тот же тип, что wc_Sha256. */
_Static_assert(sizeof(wc_Sha) <= SC_HASH_CTX_SIZE && _Alignof(wc_Sha) <= 16, "SC_HASH_CTX_SIZE мал для wc_Sha");
_Static_assert(sizeof(wc_Sha224) <= SC_HASH_CTX_SIZE && _Alignof(wc_Sha224) <= 16, "SC_HASH_CTX_SIZE мал для wc_Sha224");
_Static_assert(sizeof(wc_Md5) <= SC_HASH_CTX_SIZE && _Alignof(wc_Md5) <= 16, "SC_HASH_CTX_SIZE мал для wc_Md5");
_Static_assert(sizeof(wc_Shake) <= SC_SHAKE_CTX_SIZE && _Alignof(wc_Shake) <= 16, "SC_SHAKE_CTX_SIZE мал для wc_Shake");

/* ChaCha20-Poly1305: развёрнутый ключ ChaCha плюс рабочий Poly1305 (его ключ свой на каждую
 * запись, RFC 8439 §2.6). Лежат рядом в одном хранилище. */
struct chachapoly {
    ChaCha   chacha;
    Poly1305 poly;
};
_Static_assert(sizeof(struct chachapoly) <= SC_AEAD_CTX_SIZE && _Alignof(struct chachapoly) <= 16,
               "SC_AEAD_CTX_SIZE мал для ChaCha+Poly1305");

/* ---- хеши ----------------------------------------------------------------------------------- */

size_t sc_hash_len(enum sc_hash h) {
    switch (h) {
        case SC_SHA256: return 32;
        case SC_SHA384: return 48;
        case SC_SHA512: return 64;
        case SC_SHA1:   return 20;
        case SC_SHA224: return 28;
        case SC_MD5:    return 16;
    }
    return 0;
}

/* Тип хеша wolfSSL: для HMAC и HKDF это WC_SHA256 и соседи, для PSS и OID — enum wc_HashType. */
static int wc_type(enum sc_hash h) {
    switch (h) {
        case SC_SHA256: return WC_SHA256;
        case SC_SHA384: return WC_SHA384;
        case SC_SHA512: return WC_SHA512;
        case SC_SHA1:   return WC_SHA;
        case SC_SHA224: return WC_SHA224;
        case SC_MD5:    return WC_MD5;
    }
    return -1;
}
static enum wc_HashType wc_htype(enum sc_hash h) {
    switch (h) {
        case SC_SHA256: return WC_HASH_TYPE_SHA256;
        case SC_SHA384: return WC_HASH_TYPE_SHA384;
        case SC_SHA512: return WC_HASH_TYPE_SHA512;
        /* Хеши протоколов steer-proxy (scrypto.h) подписей не проверяют: цепочке и PSS они не
         * отдаются, и подпись SHA-1 по-прежнему отвергается. */
        case SC_SHA1: case SC_SHA224: case SC_MD5: break;
    }
    return WC_HASH_TYPE_NONE;
}

int sc_hash_init(struct sc_hash_ctx *c, enum sc_hash h) {
    int rc = -1;
    c->alg = 0;
    switch (h) {
        case SC_SHA256: rc = wc_InitSha256_ex((wc_Sha256 *)c->st, NULL, INVALID_DEVID); break;
        case SC_SHA384: rc = wc_InitSha384_ex((wc_Sha384 *)c->st, NULL, INVALID_DEVID); break;
        case SC_SHA512: rc = wc_InitSha512_ex((wc_Sha512 *)c->st, NULL, INVALID_DEVID); break;
        case SC_SHA1:   rc = wc_InitSha_ex((wc_Sha *)c->st, NULL, INVALID_DEVID); break;
        case SC_SHA224: rc = wc_InitSha224_ex((wc_Sha224 *)c->st, NULL, INVALID_DEVID); break;
        case SC_MD5:    rc = wc_InitMd5_ex((wc_Md5 *)c->st, NULL, INVALID_DEVID); break;
        default: return SC_EINVAL;
    }
    if (rc != 0) return SC_ECRYPTO;
    c->alg = (int)h;
    return 0;
}

int sc_hash_update(struct sc_hash_ctx *c, const void *d, size_t n) {
    int rc;
    if (n > UINT32_MAX) return SC_EINVAL;
    switch (c->alg) {
        case SC_SHA256: rc = wc_Sha256Update((wc_Sha256 *)c->st, d, (word32)n); break;
        case SC_SHA384: rc = wc_Sha384Update((wc_Sha384 *)c->st, d, (word32)n); break;
        case SC_SHA512: rc = wc_Sha512Update((wc_Sha512 *)c->st, d, (word32)n); break;
        case SC_SHA1:   rc = wc_ShaUpdate((wc_Sha *)c->st, d, (word32)n); break;
        case SC_SHA224: rc = wc_Sha224Update((wc_Sha224 *)c->st, d, (word32)n); break;
        case SC_MD5:    rc = wc_Md5Update((wc_Md5 *)c->st, d, (word32)n); break;
        default: return SC_EINVAL;
    }
    return rc == 0 ? 0 : SC_ECRYPTO;
}

int sc_hash_final(struct sc_hash_ctx *c, unsigned char *out) {
    int rc;
    switch (c->alg) {
        case SC_SHA256: rc = wc_Sha256Final((wc_Sha256 *)c->st, out); break;
        case SC_SHA384: rc = wc_Sha384Final((wc_Sha384 *)c->st, out); break;
        case SC_SHA512: rc = wc_Sha512Final((wc_Sha512 *)c->st, out); break;
        case SC_SHA1:   rc = wc_ShaFinal((wc_Sha *)c->st, out); break;
        case SC_SHA224: rc = wc_Sha224Final((wc_Sha224 *)c->st, out); break;
        case SC_MD5:    rc = wc_Md5Final((wc_Md5 *)c->st, out); break;
        default: return SC_EINVAL;
    }
    return rc == 0 ? 0 : SC_ECRYPTO;
}

/* Копия — функцией библиотеки, а не memcpy: у wolfSSL в контексте хеша бывают указатели (кэш
 * расписания при WOLFSSL_SMALL_STACK_CACHE, данные устройства), и побайтовая копия разделила бы
 * их между двумя контекстами, а free обоих освободил бы одно дважды. */
int sc_hash_clone(struct sc_hash_ctx *dst, const struct sc_hash_ctx *src) {
    int rc;
    dst->alg = 0;
    switch (src->alg) {
        case SC_SHA256:
            rc = wc_InitSha256_ex((wc_Sha256 *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_Sha256Copy((wc_Sha256 *)src->st, (wc_Sha256 *)dst->st);
            break;
        case SC_SHA384:
            rc = wc_InitSha384_ex((wc_Sha384 *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_Sha384Copy((wc_Sha384 *)src->st, (wc_Sha384 *)dst->st);
            break;
        case SC_SHA512:
            rc = wc_InitSha512_ex((wc_Sha512 *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_Sha512Copy((wc_Sha512 *)src->st, (wc_Sha512 *)dst->st);
            break;
        case SC_SHA1:
            rc = wc_InitSha_ex((wc_Sha *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_ShaCopy((wc_Sha *)src->st, (wc_Sha *)dst->st);
            break;
        case SC_SHA224:
            rc = wc_InitSha224_ex((wc_Sha224 *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_Sha224Copy((wc_Sha224 *)src->st, (wc_Sha224 *)dst->st);
            break;
        case SC_MD5:
            rc = wc_InitMd5_ex((wc_Md5 *)dst->st, NULL, INVALID_DEVID);
            if (rc == 0) rc = wc_Md5Copy((wc_Md5 *)src->st, (wc_Md5 *)dst->st);
            break;
        default: return SC_EINVAL;
    }
    if (rc != 0) return SC_ECRYPTO;
    dst->alg = src->alg;
    return 0;
}

void sc_hash_free(struct sc_hash_ctx *c) {
    switch (c->alg) {
        case SC_SHA256: wc_Sha256Free((wc_Sha256 *)c->st); break;
        case SC_SHA384: wc_Sha384Free((wc_Sha384 *)c->st); break;
        case SC_SHA512: wc_Sha512Free((wc_Sha512 *)c->st); break;
        case SC_SHA1:   wc_ShaFree((wc_Sha *)c->st); break;
        case SC_SHA224: wc_Sha224Free((wc_Sha224 *)c->st); break;
        case SC_MD5:    wc_Md5Free((wc_Md5 *)c->st); break;
        default: return;
    }
    c->alg = 0;
}

int sc_hash(enum sc_hash h, const void *d, size_t n, unsigned char *out) {
    struct sc_hash_ctx c;
    int rc = sc_hash_init(&c, h);
    if (rc) return rc;
    rc = sc_hash_update(&c, d, n);
    if (rc == 0) rc = sc_hash_final(&c, out);
    sc_hash_free(&c);
    return rc;
}

/* ---- HMAC и HKDF ---------------------------------------------------------------------------- */

int sc_hmac2(enum sc_hash h, const void *key, size_t key_n,
             const void *msg, size_t n, const void *msg2, size_t n2, unsigned char *out) {
    int t = wc_type(h);
    if (t < 0 || key_n > UINT32_MAX || n > UINT32_MAX || n2 > UINT32_MAX) return SC_EINVAL;
    /* Hmac у wolfSSL — больше полукилобайта (два состояния хеша и две набивки), поэтому в куче,
     * а не на стеке: HMAC зовут потоки соединителей, у которых стек скромный. */
    Hmac *m = malloc(sizeof(*m));
    if (!m) return SC_ENOMEM;
    /* Пустой ключ законен (HKDF-Extract без соли в RFC 5869 — это HMAC с ключом из нулей, но
     * вызывающий вправе передать и пустой), а wolfSSL не принимает NULL даже при нулевой длине. */
    static const unsigned char nokey[1];
    int rc = wc_HmacInit(m, NULL, INVALID_DEVID);
    if (rc == 0) rc = wc_HmacSetKey(m, t, key_n ? key : nokey, (word32)key_n);
    if (rc == 0 && n) rc = wc_HmacUpdate(m, msg, (word32)n);
    if (rc == 0 && n2) rc = wc_HmacUpdate(m, msg2, (word32)n2);
    if (rc == 0) rc = wc_HmacFinal(m, out);
    wc_HmacFree(m);
    wc_ForceZero(m, sizeof(*m));
    free(m);
    return rc == 0 ? 0 : SC_ECRYPTO;
}

int sc_hmac(enum sc_hash h, const void *key, size_t key_n,
            const void *msg, size_t n, unsigned char *out) {
    return sc_hmac2(h, key, key_n, msg, n, NULL, 0, out);
}

/* HKDF (RFC 5869) — функциями wolfSSL. Пустая соль и пустой ikm передаются им НЕ нулевым
 * указателем: wolfSSL отказывает на NULL при ненулевой длине, а при нулевой заменяет соль
 * нулями длины хеша — ровно как требует RFC, и HMAC с пустым ключом даёт то же самое. Вывод
 * expand не должен перекрывать prk: библиотека пишет out по блокам, читая prk на каждом. */
int sc_hkdf_extract(enum sc_hash h, const void *salt, size_t salt_n,
                    const void *ikm, size_t ikm_n, unsigned char *prk) {
    static const unsigned char empty[1];
    int t = wc_type(h);
    if (t < 0 || salt_n > UINT32_MAX || ikm_n > UINT32_MAX) return SC_EINVAL;
    return wc_HKDF_Extract(t, salt_n ? salt : NULL, (word32)salt_n, ikm_n ? ikm : empty,
                           (word32)ikm_n, prk) == 0 ? 0 : SC_ECRYPTO;
}

int sc_hkdf_expand(enum sc_hash h, const void *prk, size_t prk_n,
                   const void *info, size_t info_n, unsigned char *out, size_t out_n) {
    static const unsigned char empty[1];
    int t = wc_type(h);
    if (t < 0 || prk_n > UINT32_MAX || info_n > UINT32_MAX || out_n > 255 * sc_hash_len(h))
        return SC_EINVAL;
    return wc_HKDF_Expand(t, prk, (word32)prk_n, info_n ? info : empty, (word32)info_n,
                          out, (word32)out_n) == 0 ? 0 : SC_ECRYPTO;
}

int sc_hkdf(enum sc_hash h, const void *salt, size_t salt_n, const void *ikm, size_t ikm_n,
            const void *info, size_t info_n, unsigned char *out, size_t out_n) {
    unsigned char prk[SC_HASH_MAX];
    int rc = sc_hkdf_extract(h, salt, salt_n, ikm, ikm_n, prk);
    if (rc == 0) rc = sc_hkdf_expand(h, prk, sc_hash_len(h), info, info_n, out, out_n);
    wc_ForceZero(prk, sizeof(prk));
    return rc;
}

/* ---- AEAD ----------------------------------------------------------------------------------- */

/* ---- ChaCha20-Poly1305 своим порядком на 32-битном MIPS --------------------------------------
 *
 * Два места, где поставляемая wolfSSL без ассемблера теряет на этих процессорах (MT7621 и родня:
 * 880 МГц, ни AES, ни SIMD, а ChaCha20-Poly1305 тут единственный быстрый шифр туннеля):
 *
 *  1. Poly1305 — основание 2^26 с побайтовой сборкой слов; у нас poly1305_32.h (основание 2^32,
 *     multu/maddu).
 *  2. Гамма ChaCha20 накладывается xorbufout(): словами — только когда выход, вход и блок гаммы
 *     выровнены одинаково, иначе по байту (64 итерации на блок, около 40 % времени самого ChaCha20).
 *     Запись TLS и xsteer лежит в буфере со сдвигом на 5 байт заголовка, то есть невыровнена
 *     как правило. Поэтому невыровненные данные идут через выровненный буфер: копия, шифр на месте, копия.
 *
 * Порядок тот же, что у wc_ChaCha20Poly1305_Encrypt_ex/_Decrypt_ex: ключ Poly1305 — первые 32 байта
 * блока 0, данные с блока 1, дополнение нулями до 16, затем длины; при расшифровке сначала тег (по
 * шифртексту), и только при совпадении — данные, а при несовпадении буфер обнуляется, как у wolfSSL.
 * Включается на __mips__ без 64 битов; STEER_CP_OWN включает ту же ветку на другом процессоре (стенд
 * tests/cpmatch.c гоняет её на хосте и сверяет с wolfSSL); STEER_CP_STOCK на MIPS возвращает путь
 * wolfSSL — для замеров «до и после». */
#if (defined(__mips__) && !defined(__mips64) && !defined(STEER_CP_STOCK)) || defined(STEER_CP_OWN)
#define SC_CP_OWN 1

#define CP_BOUNCE 256   /* кратно 64: блоки гаммы не рвутся на границе куска */

/* ChaCha20 над buf на месте; ctx стоит на счётчике 1 и ведёт его дальше. */
static int cp_stream(ChaCha *ch, unsigned char *buf, size_t n, struct sp32 *mac) {
    if (((uintptr_t)buf & 3) == 0) {
        if (wc_Chacha_Process(ch, buf, buf, (word32)n) != 0) return -1;
        if (mac) sp32_update(mac, buf, n);
        return 0;
    }
    uint32_t bounce[CP_BOUNCE / 4];
    unsigned char *b = (unsigned char *)bounce;
    while (n) {
        size_t k = n < CP_BOUNCE ? n : CP_BOUNCE;
        memcpy(b, buf, k);
        if (wc_Chacha_Process(ch, b, b, (word32)k) != 0) { wc_ForceZero(b, sizeof(bounce)); return -1; }
        if (mac) sp32_update(mac, b, k);
        memcpy(buf, b, k);
        buf += k; n -= k;
    }
    wc_ForceZero(b, sizeof(bounce));
    return 0;
}

static void cp_pad16(struct sp32 *mac, size_t n) {
    static const uint8_t zero[16];
    if (n & 15) sp32_update(mac, zero, 16 - (n & 15));
}

static void cp_lens(struct sp32 *mac, size_t aad_n, size_t n) {
    uint8_t l[16];
    memset(l, 0, sizeof l);
    for (int i = 0; i < 4; i++) { l[i] = (uint8_t)(aad_n >> (8 * i)); l[8 + i] = (uint8_t)(n >> (8 * i)); }
    sp32_update(mac, l, 16);
}

/* Ключ Poly1305 и счётчик 1 для данных. */
static int cp_begin(ChaCha *ch, struct sp32 *mac, const unsigned char nonce[12]) {
    uint8_t pk[32];
    memset(pk, 0, sizeof pk);
    int rc = wc_Chacha_SetIV(ch, nonce, 0);
    if (rc == 0) rc = wc_Chacha_Process(ch, pk, pk, sizeof pk);
    if (rc == 0) rc = wc_Chacha_SetIV(ch, nonce, 1);
    if (rc == 0) sp32_init(mac, pk);
    wc_ForceZero(pk, sizeof pk);
    return rc;
}

static int cp_seal(ChaCha *ch, const unsigned char nonce[12], const void *aad, size_t aad_n,
                   unsigned char *buf, size_t n, unsigned char tag[16]) {
    struct sp32 mac;
    int rc = cp_begin(ch, &mac, nonce);
    if (rc != 0) { wc_ForceZero(&mac, sizeof mac); return rc; }
    if (aad_n) { sp32_update(&mac, aad, aad_n); cp_pad16(&mac, aad_n); }
    if (n && cp_stream(ch, buf, n, &mac) != 0) { wc_ForceZero(&mac, sizeof mac); return -1; }
    cp_pad16(&mac, n);
    cp_lens(&mac, aad_n, n);
    sp32_final(&mac, tag);
    wc_ForceZero(&mac, sizeof mac);
    return 0;
}

/* 0 — тег верен и данные расшифрованы; 1 — тег неверен (буфер обнулён); -1 — ошибка шифра. */
static int cp_open(ChaCha *ch, const unsigned char nonce[12], const void *aad, size_t aad_n,
                   unsigned char *buf, size_t n, const unsigned char tag[16]) {
    struct sp32 mac;
    unsigned char calc[16];
    int rc = cp_begin(ch, &mac, nonce);
    if (rc != 0) { wc_ForceZero(&mac, sizeof mac); return -1; }
    if (aad_n) { sp32_update(&mac, aad, aad_n); cp_pad16(&mac, aad_n); }
    if (n) sp32_update(&mac, buf, n);
    cp_pad16(&mac, n);
    cp_lens(&mac, aad_n, n);
    sp32_final(&mac, calc);
    wc_ForceZero(&mac, sizeof mac);
    unsigned diff = 0;
    for (int i = 0; i < 16; i++) diff |= (unsigned)(calc[i] ^ tag[i]);
    wc_ForceZero(calc, sizeof calc);
    if (diff) { if (n) wc_ForceZero(buf, n); return 1; }
    if (n && cp_stream(ch, buf, n, NULL) != 0) { wc_ForceZero(buf, n); return -1; }
    return 0;
}
#endif

size_t sc_aead_key_len(enum sc_aead_alg a) {
    switch (a) {
        case SC_AES128_GCM: return 16;
        case SC_AES256_GCM: return 32;
        case SC_CHACHA20_POLY1305: return 32;
    }
    return 0;
}

int sc_aead_setkey(struct sc_aead *k, enum sc_aead_alg a, const unsigned char *key) {
    size_t kn = sc_aead_key_len(a);
    k->alg = 0;
    if (!kn) return SC_EINVAL;
    if (a == SC_CHACHA20_POLY1305) {
        struct chachapoly *cp = (struct chachapoly *)k->st;
        memset(cp, 0, sizeof(*cp));
        if (wc_Chacha_SetKey(&cp->chacha, key, (word32)kn) != 0) return SC_ECRYPTO;
    } else {
        Aes *aes = (Aes *)k->st;
        if (wc_AesInit(aes, NULL, INVALID_DEVID) != 0) return SC_ECRYPTO;
        if (wc_AesGcmSetKey(aes, key, (word32)kn) != 0) { wc_AesFree(aes); return SC_ECRYPTO; }
    }
    k->alg = (int)a;
    return 0;
}

void sc_aead_free(struct sc_aead *k) {
    if (!k->alg) return;
    if (k->alg == SC_CHACHA20_POLY1305) {
        wc_ForceZero(k->st, sizeof(struct chachapoly));
    } else {
        wc_AesFree((Aes *)k->st);
        wc_ForceZero(k->st, sizeof(Aes));
    }
    k->alg = 0;
}

int sc_aead_seal(struct sc_aead *k, const unsigned char nonce[12],
                 const void *aad, size_t aad_n, unsigned char *buf, size_t n,
                 unsigned char tag[16]) {
    int rc;
    if (n > UINT32_MAX || aad_n > UINT32_MAX) return SC_EINVAL;
    if (k->alg == SC_CHACHA20_POLY1305) {
        struct chachapoly *cp = (struct chachapoly *)k->st;
#ifdef SC_CP_OWN
        rc = cp_seal(&cp->chacha, nonce, aad, aad_n, buf, n, tag);
#else
        rc = wc_ChaCha20Poly1305_Encrypt_ex(&cp->chacha, &cp->poly, buf, buf, (word32)n, nonce,
                                            tag, aad, (word32)aad_n);
#endif
    } else if (k->alg == SC_AES128_GCM || k->alg == SC_AES256_GCM) {
        rc = wc_AesGcmEncrypt((Aes *)k->st, buf, buf, (word32)n, nonce, 12, tag, 16,
                              aad, (word32)aad_n);
    } else {
        return SC_EINVAL;
    }
    return rc == 0 ? 0 : SC_ECRYPTO;
}

int sc_aead_open(struct sc_aead *k, const unsigned char nonce[12],
                 const void *aad, size_t aad_n, unsigned char *buf, size_t n,
                 const unsigned char tag[16]) {
    int rc;
    if (n > UINT32_MAX || aad_n > UINT32_MAX) return SC_EINVAL;
    if (k->alg == SC_CHACHA20_POLY1305) {
        struct chachapoly *cp = (struct chachapoly *)k->st;
#ifdef SC_CP_OWN
        rc = cp_open(&cp->chacha, nonce, aad, aad_n, buf, n, tag);
        if (rc == 1) return SC_EAUTH;
#else
        rc = wc_ChaCha20Poly1305_Decrypt_ex(&cp->chacha, &cp->poly, buf, buf, (word32)n, nonce,
                                            tag, aad, (word32)aad_n);
        if (rc == WC_NO_ERR_TRACE(MAC_CMP_FAILED_E)) return SC_EAUTH;
#endif
    } else if (k->alg == SC_AES128_GCM || k->alg == SC_AES256_GCM) {
        rc = wc_AesGcmDecrypt((Aes *)k->st, buf, buf, (word32)n, nonce, 12, tag, 16,
                              aad, (word32)aad_n);
        if (rc == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) return SC_EAUTH;
    } else {
        return SC_EINVAL;
    }
    return rc == 0 ? 0 : SC_ECRYPTO;
}

/* ---- AES-256-CTR ---------------------------------------------------------------------------- */

int sc_aesctr_init(struct sc_aesctr *c, const unsigned char key[32], const unsigned char iv[16]) {
    Aes *aes = (Aes *)c->st;
    c->ready = 0;
    if (wc_AesInit(aes, NULL, INVALID_DEVID) != 0) return SC_ECRYPTO;
    /* Для CTR ключ всегда «на шифрование»: гамма одна и та же в обе стороны. */
    if (wc_AesCtrSetKey(aes, key, 32, iv, AES_ENCRYPTION) != 0) { wc_AesFree(aes); return SC_ECRYPTO; }
    c->ready = 1;
    return 0;
}

int sc_aesctr_xor(struct sc_aesctr *c, const unsigned char *in, unsigned char *out, size_t n) {
    if (!c->ready || n > UINT32_MAX) return SC_EINVAL;
    if (!n) return 0;
    return wc_AesCtrEncrypt((Aes *)c->st, out, in, (word32)n) == 0 ? 0 : SC_ECRYPTO;
}

void sc_aesctr_free(struct sc_aesctr *c) {
    if (!c->ready) return;
    wc_AesFree((Aes *)c->st);
    wc_ForceZero(c->st, sizeof(Aes));
    c->ready = 0;
}

/* ---- AES одним блоком ------------------------------------------------------------------------ */

/* Aes — под килобайт, поэтому в куче: зовут и потоки соединителей стека, у которых стек скромный
 * (довод — у sc_hmac2). Прямой блок (WOLFSSL_AES_DIRECT в user_settings.h) — без режима и IV. */
int sc_aes_block(const unsigned char *key, size_t key_n, int decrypt,
                 const unsigned char in[16], unsigned char out[16]) {
    if (key_n != 16 && key_n != 32) return SC_EINVAL;
    Aes *aes = malloc(sizeof(*aes));
    if (!aes) return SC_ENOMEM;
    int rc = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesSetKey(aes, key, (word32)key_n, NULL, decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
        if (rc == 0) rc = decrypt ? wc_AesDecryptDirect(aes, out, in) : wc_AesEncryptDirect(aes, out, in);
        wc_AesFree(aes);
    }
    wc_ForceZero(aes, sizeof(*aes));
    free(aes);
    return rc == 0 ? 0 : SC_ECRYPTO;
}

/* ---- XChaCha20-Poly1305 --------------------------------------------------------------------- */

int sc_xchacha_seal(const unsigned char key[32], const unsigned char nonce[24],
                    const void *aad, size_t aad_n, const unsigned char *in, size_t n,
                    unsigned char *out) {
    static const unsigned char empty[1];
    if (n > UINT32_MAX - 16 || aad_n > UINT32_MAX) return SC_EINVAL;
    int rc = wc_XChaCha20Poly1305_Encrypt(out, n + 16, n ? in : empty, n, aad_n ? aad : empty,
                                          aad_n, nonce, 24, key, 32);
    return rc == 0 ? 0 : SC_ECRYPTO;
}

int sc_xchacha_open(const unsigned char key[32], const unsigned char nonce[24],
                    const void *aad, size_t aad_n, const unsigned char *in, size_t n,
                    unsigned char *out) {
    static const unsigned char empty[1];
    if (n < 16 || n > UINT32_MAX || aad_n > UINT32_MAX) return SC_EINVAL;
    /* Пустая датаграмма: выход нулевой длины, но wolfSSL не берёт NULL и на отказе тега обнуляет
     * весь переданный ему размер выхода — поэтому ему отдаётся свой байт, а не out вызывающего. */
    unsigned char none[1];
    int rc = wc_XChaCha20Poly1305_Decrypt(n > 16 ? out : none, n > 16 ? n - 16 : 1, in, n,
                                          aad_n ? aad : empty, aad_n, nonce, 24, key, 32);
    if (rc == WC_NO_ERR_TRACE(MAC_CMP_FAILED_E)) return SC_EAUTH;
    return rc == 0 ? 0 : SC_ECRYPTO;
}

/* ---- SHAKE128 потоком ----------------------------------------------------------------------- */

/* Absorb wolfSSL поглощает вход и сразу закрывает его набивкой SHAKE (0x1f), после чего
 * SqueezeBlocks отдаёт блоки по 168 байт подряд — ровно поток вывода XOF. Блок отдаётся
 * вызывающему кусками, остаток лежит в s->blk до следующего чтения. */
int sc_shake128_init(struct sc_shake *s, const void *in, size_t n) {
    static const unsigned char empty[1];
    s->ready = 0;
    s->pos = SC_SHAKE128_RATE;
    if (n > UINT32_MAX) return SC_EINVAL;
    wc_Shake *k = (wc_Shake *)s->st;
    if (wc_InitShake128(k, NULL, INVALID_DEVID) != 0) return SC_ECRYPTO;
    if (wc_Shake128_Absorb(k, n ? in : empty, (word32)n) != 0) { wc_Shake128_Free(k); return SC_ECRYPTO; }
    s->ready = 1;
    return 0;
}

int sc_shake128_read(struct sc_shake *s, unsigned char *out, size_t n) {
    if (!s->ready) return SC_EINVAL;
    while (n) {
        if (s->pos >= SC_SHAKE128_RATE) {
            if (wc_Shake128_SqueezeBlocks((wc_Shake *)s->st, s->blk, 1) != 0) return SC_ECRYPTO;
            s->pos = 0;
        }
        size_t take = SC_SHAKE128_RATE - s->pos;
        if (take > n) take = n;
        memcpy(out, s->blk + s->pos, take);
        s->pos = (uint16_t)(s->pos + take);
        out += take;
        n -= take;
    }
    return 0;
}

void sc_shake128_free(struct sc_shake *s) {
    if (!s->ready) return;
    wc_Shake128_Free((wc_Shake *)s->st);
    wc_ForceZero(s, sizeof(*s));
}

/* ---- X25519 --------------------------------------------------------------------------------- */

/* wolfSSL принимает только ПРИЖАТЫЙ скаляр (и отказывает на любом другом), а функция X25519 из
 * RFC 7748 прижимает его сама — поэтому прижимаем копию. Для ключей, сгенерированных как надо
 * (reality.c прижимает свой, wg genkey и xsteer-key тоже), это ничего не меняет. */
static void clamp(unsigned char s[32], const unsigned char in[32]) {
    memcpy(s, in, 32);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static int all_zero(const unsigned char *p, size_t n) {
    unsigned char acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

int sc_x25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]) {
    unsigned char s[32];
    clamp(s, scalar);
    int rc = wc_curve25519_generic(32, out, 32, s, 32, point);
    wc_ForceZero(s, sizeof(s));
    if (rc != 0) return SC_ECRYPTO;
    /* Точка малого порядка даёт нулевой секрет, известный кому угодно (RFC 7748 §6.1). */
    if (all_zero(out, 32)) return SC_ECRYPTO;
    return 0;
}

int sc_x25519_base(unsigned char pub[32], const unsigned char scalar[32]) {
    unsigned char s[32];
    clamp(s, scalar);
    int rc = wc_curve25519_make_pub(32, pub, 32, s);
    wc_ForceZero(s, sizeof(s));
    return rc == 0 ? 0 : SC_ECRYPTO;
}

/* ---- подписи -------------------------------------------------------------------------------- */

/* Сравнение без раннего выхода: подписи и дайджесты здесь не секретны, но привычку сравнивать
 * криптографические значения memcmp'ом в этом файле заводить не стоит. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

/* ---- ML-KEM-768 ------------------------------------------------------------------------------ */

/* Ключ заводится на время вызова через wc_MlKemKey_New (куча), а не значением в структуре вызывающего:
 * так его размер не входит в ABI между libsteer и libsteer-wolfssl (sc_abi_check) и не раздувает
 * struct tls13. Цена — один malloc на рукопожатие, ничто по сравнению с самим ML-KEM. */
static MlKemKey *kem_new(void) {
    return wc_MlKemKey_New(WC_ML_KEM_768, NULL, INVALID_DEVID);
}

int sc_mlkem768_keygen(unsigned char ek[SC_MLKEM768_EK], unsigned char dk[SC_MLKEM768_DK],
                       const unsigned char seed[SC_MLKEM768_SEED]) {
    MlKemKey *k = kem_new();
    if (!k) return SC_ENOMEM;
    int rc = SC_ECRYPTO;
    if (wc_MlKemKey_MakeKeyWithRandom(k, seed, SC_MLKEM768_SEED) == 0 &&
        wc_MlKemKey_EncodePublicKey(k, ek, SC_MLKEM768_EK) == 0 &&
        wc_MlKemKey_EncodePrivateKey(k, dk, SC_MLKEM768_DK) == 0)
        rc = 0;
    wc_MlKemKey_Delete(k, &k);
    return rc;
}

int sc_mlkem768_ek_check(const unsigned char ek[SC_MLKEM768_EK]) {
    MlKemKey *k = kem_new();
    if (!k) return SC_ENOMEM;
    unsigned char back[SC_MLKEM768_EK];
    int rc = SC_EPARSE;
    /* DecodePublicKey у wolfSSL проверяет коэффициенты (< q), но проверку подтверждаем круговым
     * кодированием: Go сверяет ровно так (FIPS 203, 7.2), и расхождение здесь означало бы, что
     * ключ, отвергнутый сервером, мы принимаем. */
    if (wc_MlKemKey_DecodePublicKey(k, ek, SC_MLKEM768_EK) == 0 &&
        wc_MlKemKey_EncodePublicKey(k, back, sizeof back) == 0 &&
        ct_equal(ek, back, sizeof back))
        rc = 0;
    wc_MlKemKey_Delete(k, &k);
    return rc;
}

int sc_mlkem768_encaps(unsigned char ct[SC_MLKEM768_CT], unsigned char ss[SC_MLKEM768_SS],
                       const unsigned char ek[SC_MLKEM768_EK], const unsigned char rnd[SC_MLKEM768_RND]) {
    MlKemKey *k = kem_new();
    if (!k) return SC_ENOMEM;
    int rc = SC_EPARSE;
    unsigned char back[SC_MLKEM768_EK];
    if (wc_MlKemKey_DecodePublicKey(k, ek, SC_MLKEM768_EK) == 0 &&
        wc_MlKemKey_EncodePublicKey(k, back, sizeof back) == 0 && ct_equal(ek, back, sizeof back))
        rc = wc_MlKemKey_EncapsulateWithRandom(k, ct, ss, rnd, SC_MLKEM768_RND) == 0 ? 0 : SC_ECRYPTO;
    wc_MlKemKey_Delete(k, &k);
    return rc;
}

int sc_mlkem768_decaps(unsigned char ss[SC_MLKEM768_SS], const unsigned char dk[SC_MLKEM768_DK],
                       const unsigned char ct[SC_MLKEM768_CT]) {
    MlKemKey *k = kem_new();
    if (!k) return SC_ENOMEM;
    int rc = SC_EPARSE;
    if (wc_MlKemKey_DecodePrivateKey(k, dk, SC_MLKEM768_DK) == 0)
        rc = wc_MlKemKey_Decapsulate(k, ss, ct, SC_MLKEM768_CT) == 0 ? 0 : SC_ECRYPTO;
    wc_MlKemKey_Delete(k, &k);
    return rc;
}

/* ---- ML-DSA-65: только проверка --------------------------------------------------------------- */

int sc_mldsa65_verify(const unsigned char pk[SC_MLDSA65_PK], const unsigned char *msg, size_t msg_n,
                      const unsigned char *sig, size_t sig_n) {
    if (sig_n != SC_MLDSA65_SIG) return SC_ESIG;
    wc_MlDsaKey *k = wc_MlDsaKey_New(NULL, INVALID_DEVID);
    if (!k) return SC_ENOMEM;
    int rc = SC_EPARSE, res = 0;
    if (wc_MlDsaKey_SetParams(k, WC_ML_DSA_65) == 0 &&
        wc_MlDsaKey_ImportPubRaw(k, pk, SC_MLDSA65_PK) == 0) {
        int vr = wc_MlDsaKey_VerifyCtx(k, sig, (word32)sig_n, NULL, 0, msg, (word32)msg_n, &res);
        rc = (vr == 0 && res == 1) ? 0 : SC_ESIG;
    }
    wc_MlDsaKey_Delete(k, &k);
    return rc;
}


static int mgf_of(enum sc_hash h) {
    switch (h) {
        case SC_SHA256: return WC_MGF1SHA256;
        case SC_SHA384: return WC_MGF1SHA384;
        case SC_SHA512: return WC_MGF1SHA512;
    }
    return WC_MGF1NONE;
}

static int verify_rsa(const unsigned char *spki, word32 spki_n, enum sc_sig_alg alg,
                      enum sc_hash h, const unsigned char *digest, size_t dn,
                      const unsigned char *sig, size_t sig_n) {
    RsaKey *key = malloc(sizeof(*key));
    /* Вывод открытого преобразования — длиной с модуль; 1024 байта — ключ до 8192 бит. */
    unsigned char *out = malloc(1024);
    int rc = SC_ENOMEM;
    if (!key || !out) goto done;
    rc = SC_EPARSE;
    if (wc_InitRsaKey(key, NULL) != 0) { free(key); key = NULL; goto done; }
    word32 idx = 0;
    if (wc_RsaPublicKeyDecode(spki, &idx, key, spki_n) != 0) goto done_key;
    rc = SC_ESIG;
    if (alg == SC_SIG_RSA_PSS) {
        int n = wc_RsaPSS_Verify_ex(sig, (word32)sig_n, out, 1024, wc_htype(h), mgf_of(h),
                                    RSA_PSS_SALT_LEN_DISCOVER, key);
        if (n > 0 && wc_RsaPSS_CheckPadding_ex2(digest, (word32)dn, out, (word32)n, wc_htype(h),
                                                RSA_PSS_SALT_LEN_DISCOVER,
                                                wc_RsaEncryptSize(key) * 8, NULL) == 0)
            rc = 0;
    } else {
        /* PKCS#1 v1.5: после открытого преобразования должен выйти ровно DigestInfo с OID
         * нашего хеша — собираем эталон и сравниваем целиком, а не ищем дайджест в хвосте. */
        unsigned char want[SC_HASH_MAX + 32];
        int n = wc_RsaSSL_Verify(sig, (word32)sig_n, out, 1024, key);
        word32 wn = wc_EncodeSignature(want, digest, (word32)dn, wc_HashGetOID(wc_htype(h)));
        if (n > 0 && wn > 0 && (word32)n == wn && ct_equal(out, want, wn)) rc = 0;
    }
done_key:
    wc_FreeRsaKey(key);
done:
    free(key);
    free(out);
    return rc;
}

static int verify_ecdsa(const unsigned char *spki, word32 spki_n,
                        const unsigned char *digest, size_t dn,
                        const unsigned char *sig, size_t sig_n) {
    ecc_key *key = malloc(sizeof(*key));
    int rc = SC_ENOMEM, ok = 0;
    if (!key) return rc;
    rc = SC_EPARSE;
    if (wc_ecc_init(key) != 0) { free(key); return rc; }
    word32 idx = 0;
    if (wc_EccPublicKeyDecode(spki, &idx, key, spki_n) == 0) {
        rc = SC_ESIG;
        if (wc_ecc_verify_hash(sig, (word32)sig_n, digest, (word32)dn, &ok, key) == 0 && ok == 1)
            rc = 0;
    }
    wc_ecc_free(key);
    free(key);
    return rc;
}

int sc_cert_verify_sig(const unsigned char *cert_der, size_t cert_n,
                       enum sc_sig_alg alg, enum sc_hash h,
                       const unsigned char *digest, size_t digest_n,
                       const unsigned char *sig, size_t sig_n) {
    if (!cert_der || !digest || !sig || cert_n > UINT32_MAX || sig_n > 4096 ||
        digest_n != sc_hash_len(h) || !digest_n)
        return SC_EINVAL;
    /* Ключ — из SubjectPublicKeyInfo сертификата: разбирать сертификат целиком ради ключа
     * незачем, а SPKI понимают обе функции разбора ключа. Сертификат с ключом больше
     * 8192 бит сюда не приходит — такого нет ни у одного узла и ни у одного корня. */
    word32 spki_n = 2048;
    unsigned char *spki = malloc(spki_n);
    if (!spki) return SC_ENOMEM;
    int rc;
    if (wc_GetSubjectPubKeyInfoDerFromCert(cert_der, (word32)cert_n, spki, &spki_n) != 0)
        rc = SC_EPARSE;
    else if (alg == SC_SIG_ECDSA)
        rc = verify_ecdsa(spki, spki_n, digest, digest_n, sig, sig_n);
    else if (alg == SC_SIG_RSA_PSS || alg == SC_SIG_RSA_PKCS1)
        rc = verify_rsa(spki, spki_n, alg, h, digest, digest_n, sig, sig_n);
    else
        rc = SC_EINVAL;
    free(spki);
    return rc;
}

/* ---- хранилище корней и цепочка ------------------------------------------------------------
 *
 * Цепочку строит и проверяет wolfSSL_X509_verify_cert, а корни держит CertManager внутри
 * WOLFSSL_X509_STORE. Почему не голый CertManager: он проверяет ОДИН сертификат против того, что
 * в нём уже лежит, а промежуточные присланы сервером и доверенными не являются. Положить их туда
 * значило бы либо засорять общее хранилище чужими сертификатами навсегда, либо строить путь
 * самим — со своей проверкой признака CA, keyCertSign, длины пути и ограничений имён, то есть
 * своей реализацией ровно того, что у библиотеки уже есть и уже чинилось (CVE-2026-89133 про
 * ограничения имён — в ней, а не у нас). verify_cert делает всё это сам, включая имя (SAN, IP).
 *
 * Цена — одна проверка за раз: verify_cert кладёт промежуточные в CertManager хранилища как
 * временные и снимает ВСЕ временные по окончании, так что две проверки на одном хранилище
 * одновременно мешали бы друг другу (об этом прямо пишет x509_str.c). Отсюда мьютекс: проверок
 * цепочки — по одной на рукопожатие security=tls, миллисекунды, и очередь за ним ничего не стоит,
 * а хранилище на поток стоило бы по сотне килобайт корней на каждый соединитель. */
struct sc_roots {
    WOLFSSL_X509_STORE *store;
    pthread_mutex_t mu;
};

/* ---- сверка с загруженной libsteer-wolfssl.so ---------------------------------------------
 *
 * steer_wolfssl_abi определён в libsteer-wolfssl.so (build/wolfssl/abi.c — порядок полей там тот
 * же, см. комментарий у него). В статической сборке символа нет — слабая ссылка нулевая, и сверять
 * нечего: библиотека там собрана в тот же бинарник теми же опциями. В libsteer.so ссылка обязана
 * быть видна за пределы библиотеки (visibility default), иначе компоновщик разрешил бы её нулём.
 *
 * Расхождение — не ошибка, которую можно вернуть: хранилища контекстов слоя уже расставлены по
 * структурам вызывающих. Поэтому процесс гасится сразу, при загрузке (конструктор), строкой,
 * которая называет причину и лечение, а не падает позже в чужом поле. */
extern const unsigned long steer_wolfssl_abi[SC_ABI_N] __attribute__((weak, visibility("default")));

struct chachapoly_sz { ChaCha c; Poly1305 p; };

__attribute__((constructor)) static void sc_abi_check(void) {
    if (!steer_wolfssl_abi) return;
    const unsigned long want[SC_ABI_N] = {
        LIBWOLFSSL_VERSION_HEX,
        sizeof(wc_Sha256), sizeof(wc_Sha512), sizeof(wc_Sha384),
        sizeof(Aes), sizeof(struct chachapoly_sz),
        SC_HASH_CTX_SIZE, SC_AEAD_CTX_SIZE, SC_AESCTR_CTX_SIZE,
        sizeof(WOLFSSL_X509_STORE), offsetof(WOLFSSL_X509_STORE, cm),
        sizeof(wc_Shake), SC_SHAKE_CTX_SIZE,
    };
    for (int i = 0; i < SC_ABI_N; i++) {
        if (steer_wolfssl_abi[i] == want[i]) continue;
        static const char msg[] =
            "steer: libsteer-wolfssl.so другой сборки, чем libsteer.so (версия wolfSSL или размеры "
            "структур не совпали) — обновите пакеты libsteer и libsteer-wolfssl вместе\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(3);
    }
}

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static int g_init_rc = -1;
static void lib_init(void) { g_init_rc = wolfSSL_Init() == WOLFSSL_SUCCESS ? 0 : -1; }

int sc_roots_load(struct sc_roots **out, const unsigned char *pem, size_t n) {
    *out = NULL;
    if (!pem || !n || n > INT32_MAX) return SC_EINVAL;
    pthread_once(&g_init_once, lib_init);
    if (g_init_rc != 0) return SC_ECRYPTO;
    struct sc_roots *r = calloc(1, sizeof(*r));
    if (!r) return SC_ENOMEM;
    r->store = wolfSSL_X509_STORE_new();
    if (!r->store) { free(r); return SC_ENOMEM; }
    pthread_mutex_init(&r->mu, NULL);
    /* IGNORE_ERR: запись, которая не разобралась, пропускается, остальные грузятся (см. заголовок).
     * Сколько корней загрузилось, wolfSSL не сообщает; «ни одного» узнаётся по отказу вызова. */
    int rc = wolfSSL_CertManagerLoadCABuffer_ex(r->store->cm, pem, (long)n, WOLFSSL_FILETYPE_PEM,
                                                0, WOLFSSL_LOAD_FLAG_IGNORE_ERR);
    if (rc != WOLFSSL_SUCCESS) { sc_roots_free(r); return SC_EPARSE; }
    *out = r;
    return 0;
}

/* Хранилище из ОДНОГО сертификата в DER — закреплённый отпечатком центр (Xray pinnedPeerCertSha256,
 * когда отпечаток совпал с промежуточным или корнем цепочки). Отличается от sc_roots_load форматом и
 * тем, что запись должна разобраться: сертификат, который не годится в центры (нет признака CA,
 * алгоритма нет в сборке), — отказ SC_EPARSE, и вызывающий трактует его как «отпечаток не нашёл
 * центра», ровно как Xray (в его verifyChain закрепление работает только для cert.IsCA). */
int sc_roots_load_der(struct sc_roots **out, const unsigned char *der, size_t n) {
    *out = NULL;
    if (!der || !n || n > INT32_MAX) return SC_EINVAL;
    pthread_once(&g_init_once, lib_init);
    if (g_init_rc != 0) return SC_ECRYPTO;
    struct sc_roots *r = calloc(1, sizeof(*r));
    if (!r) return SC_ENOMEM;
    r->store = wolfSSL_X509_STORE_new();
    if (!r->store) { free(r); return SC_ENOMEM; }
    pthread_mutex_init(&r->mu, NULL);
    int rc = wolfSSL_CertManagerLoadCABuffer(r->store->cm, der, (long)n, WOLFSSL_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) { sc_roots_free(r); return SC_EPARSE; }
    *out = r;
    return 0;
}

void sc_roots_free(struct sc_roots *r) {
    if (!r) return;
    wolfSSL_X509_STORE_free(r->store);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

int sc_chain_verify(struct sc_roots *r, const unsigned char *const *der, const size_t *der_n,
                    size_t count, const char *host) {
    if (!r || !der || !der_n || !count || !host || !host[0]) return SC_EINVAL;
    for (size_t i = 0; i < count; i++) if (!der[i] || !der_n[i] || der_n[i] > INT32_MAX) return SC_EINVAL;

    WOLFSSL_X509 *leaf = wolfSSL_X509_d2i(NULL, der[0], (int)der_n[0]);
    if (!leaf) return SC_EPARSE;
    int rc = SC_ENOMEM;
    WOLF_STACK_OF(WOLFSSL_X509) *sk = wolfSSL_sk_X509_new_null();
    WOLFSSL_X509_STORE_CTX *ctx = wolfSSL_X509_STORE_CTX_new();
    if (!sk || !ctx) goto out;
    /* Промежуточный, который не разобрался, пропускается, а не роняет проверку: цепочка нередко
     * приезжает с запасом, и лишний сертификат с незнакомым алгоритмом ничего не решает. Если он
     * был нужен — путь до корня не построится, и это будет честный отказ цепочки. */
    for (size_t i = 1; i < count; i++) {
        WOLFSSL_X509 *x = wolfSSL_X509_d2i(NULL, der[i], (int)der_n[i]);
        if (x && wolfSSL_sk_X509_push(sk, x) <= 0) wolfSSL_X509_free(x);
    }

    pthread_mutex_lock(&r->mu);
    rc = SC_ECHAIN;
    if (wolfSSL_X509_STORE_CTX_init(ctx, r->store, leaf, sk) == WOLFSSL_SUCCESS) {
        WOLFSSL_X509_VERIFY_PARAM *param = wolfSSL_X509_STORE_CTX_get0_param(ctx);
        /* Имя-адрес сверяется с SAN IP, имя — с SAN DNS (и CN, если SAN нет): так же, как
         * mbedtls_x509_crt_verify прежде. */
        unsigned char ip[16];
        int is_ip = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;
        int set = param && (is_ip ? wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(param, host)
                                  : wolfSSL_X509_VERIFY_PARAM_set1_host(param, host, strlen(host)));
        if (set == WOLFSSL_SUCCESS && wolfSSL_X509_verify_cert(ctx) == WOLFSSL_SUCCESS) rc = 0;
    }
    pthread_mutex_unlock(&r->mu);
out:
    if (ctx) wolfSSL_X509_STORE_CTX_free(ctx);
    if (sk) wolfSSL_sk_X509_pop_free(sk, wolfSSL_X509_free);
    wolfSSL_X509_free(leaf);
    return rc;
}

/* ---- BLAKE3 --------------------------------------------------------------------------------- */

void sc_blake3_hash(unsigned char out[32], const void *in, size_t n) { b3_hash(out, in, n); }

void sc_blake3_derive_key(unsigned char *out, size_t out_n, const void *ctx, size_t ctx_n,
                          const void *material, size_t material_n) {
    b3_derive_key(out, out_n, ctx, ctx_n, material, material_n);
}
