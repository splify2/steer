/* Выпуск сертификатов и подписи для стендов — то, чего у движка нет и быть не должно.
 *
 * Движку от X.509 нужна только ПРОВЕРКА (src/lib/scrypto.c). Стендам security=tls
 * (tests/vlessmatch.c, tests/androidroots.c) нужна и другая половина: выпустить корень и листы
 * на месте, со сроком от текущего времени (замороженный в репозитории сертификат однажды истёк
 * бы и покрасил стенд не по своей вине, R-118), и подписать CertificateVerify от имени сервера.
 * Прежде это делал mbedtls_x509write; теперь — wolfCrypt, собранный для стендов с добавочным
 * ключом WOLFSSL_CERT_GEN (tests/ext-test.sh, STEER_WOLFSSL_DEFS). В опциях движка
 * (build/wolfssl/user_settings.h) выпуска сертификатов нет.
 *
 * ОТДЕЛЬНЫЙ ФАЙЛ, А НЕ КОД ВНУТРИ СТЕНДА, по той же причине, по какой в движке wolfSSL видит один
 * scrypto.c: стенды включают исходник клиента целиком (#include client.c), и заголовки wolfSSL
 * рядом с ним — это их макросы и имена в одной единице трансляции с нашими. Здесь интерфейс без
 * единого типа библиотеки, как у слоя.
 *
 * Ключи — ECDSA P-256: генерация RSA занимает секунды и ничего не добавила бы проверяемому. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "certgen.h"

#if !defined(WOLFSSL_CERT_GEN)
#error "tests/certgen.c собирается с WOLFSSL_CERT_GEN (tests/ext-test.sh, STEER_WOLFSSL_DEFS)"
#endif

struct tcg_key {
    ecc_key k;
};

static WC_RNG g_rng;
static int g_rng_ok;

static WC_RNG *rng(void) {
    if (!g_rng_ok && wc_InitRng(&g_rng) == 0) g_rng_ok = 1;
    return g_rng_ok ? &g_rng : NULL;
}

struct tcg_key *tcg_key_new(void) {
    struct tcg_key *k = calloc(1, sizeof(*k));
    if (!k || !rng()) { free(k); return NULL; }
    if (wc_ecc_init(&k->k) != 0) { free(k); return NULL; }
    if (wc_ecc_make_key_ex(rng(), 32, &k->k, ECC_SECP256R1) != 0) {
        wc_ecc_free(&k->k);
        free(k);
        return NULL;
    }
    return k;
}

void tcg_key_free(struct tcg_key *k) {
    if (!k) return;
    wc_ecc_free(&k->k);
    free(k);
}

int tcg_issue(struct tcg_key *subj, const char *cn, const char *org, int is_ca,
              struct tcg_key *ikey, const unsigned char *issuer_der, size_t issuer_n,
              unsigned char *der, size_t cap, size_t *der_n) {
    Cert *c = calloc(1, sizeof(*c));
    int rc = -1;
    if (!c || !rng()) goto out;
    if (wc_InitCert(c) != 0) goto out;
    snprintf(c->subject.commonName, sizeof(c->subject.commonName), "%s", cn);
    if (org) snprintf(c->subject.org, sizeof(c->subject.org), "%s", org);
    c->isCA = is_ca ? 1 : 0;
    c->sigType = CTC_SHA256wECDSA;
    /* Срок — от текущего времени: wolfSSL ставит начало на «сейчас», конец — через daysValid. */
    c->daysValid = 365 * 5;
#ifdef WOLFSSL_CERT_EXT
    if (wc_SetSubjectKeyIdFromPublicKey(c, NULL, &subj->k) != 0) goto out;
    if (is_ca) c->keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
#endif
    if (issuer_der) {
        /* Издатель — чужой сертификат: имя и (при CERT_EXT) идентификатор ключа берутся из него. */
        if (wc_SetIssuerBuffer(c, issuer_der, (int)issuer_n) != 0) goto out;
#ifdef WOLFSSL_CERT_EXT
        if (wc_SetAuthKeyIdFromCert(c, issuer_der, (int)issuer_n) != 0) goto out;
#endif
    }
    int n = wc_MakeCert(c, der, (word32)cap, NULL, &subj->k, rng());
    if (n < 0) goto out;
    n = wc_SignCert(c->bodySz, c->sigType, der, (word32)cap, NULL, ikey ? &ikey->k : &subj->k, rng());
    if (n < 0) goto out;
    *der_n = (size_t)n;
    rc = 0;
out:
    free(c);
    return rc;
}

int tcg_der_to_pem(const unsigned char *der, size_t n, char *pem, size_t cap) {
    int r = wc_DerToPem(der, (word32)n, (byte *)pem, (word32)(cap - 1), CERT_TYPE);
    if (r <= 0) return -1;
    pem[r] = '\0';
    return 0;
}

int tcg_sign_sha256(struct tcg_key *k, const unsigned char digest[32],
                    unsigned char *sig, size_t cap, size_t *sig_n) {
    word32 sn = (word32)cap;
    if (!rng() || wc_ecc_sign_hash(digest, 32, sig, &sn, rng(), &k->k) != 0) return -1;
    *sig_n = sn;
    return 0;
}
int tcg_ed25519_public(const unsigned char seed[32], unsigned char public_key[32]) {
    ed25519_key key;
    if (wc_ed25519_init(&key)) return -1;
    int rc = wc_ed25519_import_private_only(seed,32,&key);
    if (!rc) rc = wc_ed25519_make_public(&key,public_key,32);
    wc_ed25519_free(&key); return rc ? -1 : 0;
}
int tcg_ed25519_sign(const unsigned char seed[32], const unsigned char *message,
                     size_t length, unsigned char signature[64]) {
    if (length > UINT32_MAX) return -1;
    ed25519_key key; unsigned char public_key[32]; word32 size = 64;
    if (wc_ed25519_init(&key)) return -1;
    int rc = wc_ed25519_import_private_only(seed,32,&key);
    if (!rc) rc = wc_ed25519_make_public(&key,public_key,32);
    if (!rc) rc = wc_ed25519_sign_msg(message,(word32)length,signature,&size,&key);
    wc_ed25519_free(&key); return rc || size != 64 ? -1 : 0;
}

int tcg_count_pem_certs(const char *pem, size_t n) {
    static const char B[] = "-----BEGIN CERTIFICATE-----", E[] = "-----END CERTIFICATE-----";
    int count = 0;
    const char *p = pem, *end = pem + n;
    unsigned char *der = malloc(8192);
    if (!der) return -1;
    while (p < end) {
        const char *b = strstr(p, B);
        if (!b) break;
        const char *e = strstr(b, E);
        if (!e) break;
        e += sizeof(E) - 1;
        /* Каждый блок — отдельно: разбирается ровно он, текст вокруг (формат Android: вывод
         * `openssl x509 -text` перед PEM) в разбор не попадает. */
        int dn = wc_CertPemToDer((const unsigned char *)b, (int)(e - b), der, 8192, CERT_TYPE);
        if (dn > 0) {
            DecodedCert dc;
            wc_InitDecodedCert(&dc, der, (word32)dn, NULL);
            if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0) count++;
            wc_FreeDecodedCert(&dc);
        }
        p = e;
    }
    free(der);
    return count;
}
