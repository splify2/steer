/* Сертификат клиента MASQUE и ключ сервера — DER руками (модуль steer-warpbox, этап 2).
 *
 * ЗАЧЕМ РУКАМИ. Cloudflare узнаёт клиента MASQUE по ключу P-256, выданному при регистрации: клиент
 * предъявляет самоподписанный сертификат с этим ключом (пустые subject и issuer, срок сутки — так
 * делают официальный клиент и usque, WARPBOX.md в хабе). Выпуск сертификатов в нашей wolfSSL выключен
 * (WOLFSSL_CERT_GEN — только стендам, build/wolfssl/user_settings.h), а сертификат здесь — сотня байт
 * постоянной формы: собрать его самим дешевле, чем тащить в библиотеку выпуск X.509 целиком.
 *
 * Ключ СЕРВЕРА сверяется с выданным при регистрации по полю SubjectPublicKeyInfo листового
 * сертификата, найденному разбором DER, а не поиском байтов: выданный ключ можно вписать в
 * расширение своего сертификата и подписать рукопожатие своим ключом — поиск принял бы такой лист. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "reality.h"
#include "scrypto.h"
#include "wbx509.h"

/* AlgorithmIdentifier id-ecPublicKey + prime256v1 и заголовок SPKI с BIT STRING на 66 байт. */
static const unsigned char SPKI_HEAD[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};
/* ecdsa-with-SHA256. */
static const unsigned char SIG_ALG[] = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

size_t wb_p256_spki(const unsigned char pub[65], unsigned char out[WB_SPKI_P256]) {
    memcpy(out, SPKI_HEAD, sizeof(SPKI_HEAD));
    memcpy(out + sizeof(SPKI_HEAD), pub, 65);
    return WB_SPKI_P256;
}

size_t wb_p256_sec1(const unsigned char priv[32], const unsigned char pub[65], unsigned char out[WB_SEC1_P256]) {
    static const unsigned char head[] = { 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20 };
    static const unsigned char mid[] = { 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                                         0xa1, 0x44, 0x03, 0x42, 0x00 };
    size_t n = 0;
    memcpy(out + n, head, sizeof(head)); n += sizeof(head);
    memcpy(out + n, priv, 32); n += 32;
    memcpy(out + n, mid, sizeof(mid)); n += sizeof(mid);
    memcpy(out + n, pub, 65); n += 65;
    return n;
}

/* Длина DER: короткая (< 128) или 0x81/0x82. */
static size_t put_len(unsigned char *p, size_t len) {
    if (len < 128) { p[0] = (unsigned char)len; return 1; }
    if (len < 256) { p[0] = 0x81; p[1] = (unsigned char)len; return 2; }
    p[0] = 0x82; p[1] = (unsigned char)(len >> 8); p[2] = (unsigned char)len;
    return 3;
}

static size_t put_tlv(unsigned char *p, unsigned char tag, const unsigned char *v, size_t vn) {
    p[0] = tag;
    size_t h = 1 + put_len(p + 1, vn);
    memmove(p + h, v, vn);
    return h + vn;
}

/* UTCTime «ГГММДДЧЧММССZ». */
static size_t put_time(unsigned char *p, time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);
    char s[48];
    snprintf(s, sizeof(s), "%02d%02d%02d%02d%02d%02dZ", tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    return put_tlv(p, 0x17, (const unsigned char *)s, 13);
}

int wb_mq_cert(const unsigned char priv[32], unsigned char *out, size_t cap, size_t *outn) {
    unsigned char pub[65];
    if (sc_p256_public(priv, pub) != 0 || cap < 512) return -1;
    unsigned char tbs[400], body[380];
    size_t b = 0;
    /* [0] EXPLICIT version v3 */
    static const unsigned char ver[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
    memcpy(body + b, ver, sizeof(ver)); b += sizeof(ver);
    /* serialNumber — 8 случайных байт, старший бит снят: число положительное. */
    unsigned char serial[8];
    time_t now = time(NULL);
    if (xc_random(serial, sizeof(serial)) != 0) return -1;
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    b += put_tlv(body + b, 0x02, serial, sizeof(serial));
    memcpy(body + b, SIG_ALG, sizeof(SIG_ALG)); b += sizeof(SIG_ALG);
    body[b++] = 0x30; body[b++] = 0x00;            /* issuer — пустое имя */
    unsigned char val[40];
    size_t vn = put_time(val, now - 3600);         /* час назад: часы роутера и сервера расходятся */
    vn += put_time(val + vn, now + 24 * 3600);
    b += put_tlv(body + b, 0x30, val, vn);
    body[b++] = 0x30; body[b++] = 0x00;            /* subject — пустое имя */
    b += wb_p256_spki(pub, body + b);
    size_t tn = put_tlv(tbs, 0x30, body, b);
    unsigned char digest[32], sig[SC_P256_SIG_MAX + 1];
    size_t sn = 0;
    if (sc_hash(SC_SHA256, tbs, tn, digest) != 0 || sc_p256_sign(priv, digest, sig + 1, &sn) != 0) return -1;
    sig[0] = 0x00;                                  /* BIT STRING: неиспользуемых бит — ноль */
    unsigned char all[512];
    size_t an = 0;
    memcpy(all, tbs, tn); an += tn;
    memcpy(all + an, SIG_ALG, sizeof(SIG_ALG)); an += sizeof(SIG_ALG);
    an += put_tlv(all + an, 0x03, sig, sn + 1);
    *outn = put_tlv(out, 0x30, all, an);
    return 0;
}

/* ---- разбор: SubjectPublicKeyInfo листового сертификата ------------------------------------- */

/* Элемент DER в [p, end): тег, начало значения, длина. 0 — разобран. */
static int der_item(const unsigned char *p, const unsigned char *end, unsigned char *tag,
                    const unsigned char **val, size_t *len, const unsigned char **next) {
    if (end - p < 2) return -1;
    *tag = p[0];
    size_t l = p[1], h = 2;
    if (l & 0x80) {
        size_t k = l & 0x7f;
        if (k == 0 || k > 3 || (size_t)(end - p) < 2 + k) return -1;
        l = 0;
        for (size_t i = 0; i < k; i++) l = (l << 8) | p[2 + i];
        h = 2 + k;
    }
    if ((size_t)(end - p) - h < l) return -1;
    *val = p + h;
    *len = l;
    *next = p + h + l;
    return 0;
}

int wb_cert_spki(const unsigned char *cert, size_t n, const unsigned char **spki, size_t *spki_n) {
    const unsigned char *v, *next, *end = cert + n;
    size_t l;
    unsigned char tag;
    /* Certificate ::= SEQUENCE { tbsCertificate, ... } */
    if (der_item(cert, end, &tag, &v, &l, &next) || tag != 0x30) return -1;
    end = v + l;
    if (der_item(v, end, &tag, &v, &l, &next) || tag != 0x30) return -1;    /* tbsCertificate */
    const unsigned char *p = v, *tend = v + l;
    if (der_item(p, tend, &tag, &v, &l, &next)) return -1;
    if (tag == 0xa0) { p = next; if (der_item(p, tend, &tag, &v, &l, &next)) return -1; }   /* version */
    /* serialNumber, signature, issuer, validity, subject — пять полей до SPKI. */
    for (int i = 0; i < 4; i++) {
        p = next;
        if (der_item(p, tend, &tag, &v, &l, &next)) return -1;
    }
    p = next;
    if (der_item(p, tend, &tag, &v, &l, &next) || tag != 0x30) return -1;
    *spki = p;
    *spki_n = (size_t)(next - p);
    return 0;
}
