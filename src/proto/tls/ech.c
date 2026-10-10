/* Encrypted Client Hello, клиентская половина — см. ech.h (что это, что здесь, чего нет).
 *
 * Свой HPKE, а не wolfCrypt HPKE: режим base с DHKEM(X25519) — это два HKDF и один AEAD, и всё нужное уже
 * лежит в слое примитивов (scrypto.h: X25519, HKDF-SHA256, AES-128-GCM, ChaCha20-Poly1305). Включать ради
 * ста строк HAVE_HPKE в поставляемую wolfSSL значило бы менять раскладку библиотеки и её размер для всех
 * пакетов; своя реализация сверена с Go crypto/hpke (tests/echmatch.sh) и с настоящим сервером ECH
 * (Xray-core на crypto/tls Go) — оба расшифровывают то, что она запечатывает. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "scrypto.h"
#include "reality.h"
#include "ech.h"
#include "wipe.h"

static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static size_t be24(const uint8_t *p) { return ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2]; }

int ech_b64_decode(const char *in, uint8_t *out, size_t cap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (; *in; in++) {
        int c = (unsigned char)*in, v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        else return -1;
        acc = ((acc << 6) | (uint32_t)v) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)o;
}

/* ---- ECHConfigList ---------------------------------------------------------------------------
 *
 *   ECHConfigList  = u16 длина, затем ECHConfig подряд
 *   ECHConfig      = u16 версия (0xfe0d), u16 длина, содержимое
 *   содержимое     = u8 config_id, u16 kem_id, u16 длина + открытый ключ,
 *                    u16 длина + пары (u16 kdf_id, u16 aead_id), u8 maximum_name_length,
 *                    u8 длина + public_name, u16 длина + расширения (u16 тип, u16 длина + данные)
 */
static int name_ok(const char *s, size_t n) {
    if (n == 0 || n > 253) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
        if (!ok) return 0;
    }
    return s[0] != '.' && s[0] != '-' && s[n - 1] != '-';
}

int ech_pick(const uint8_t *list, size_t n, struct ech_cfg *out) {
    if (n < 2 || (size_t)be16(list) + 2 != n) return ECH_EPARSE;
    size_t p = 2;
    while (p + 4 <= n) {
        unsigned ver = be16(list + p);
        size_t len = be16(list + p + 2);
        if (p + 4 + len > n) return ECH_EPARSE;
        const uint8_t *c = list + p + 4;
        const uint8_t *raw = list + p;
        size_t rawn = 4 + len;
        p += rawn;
        if (ver != 0xfe0d) continue;                      /* другая версия — не наша, пропуск */

        /* Содержимое: структурная ошибка — список негоден целиком, смысловое несоответствие — пропуск записи. */
        size_t q = 0;
        if (len < 1 + 2 + 2) return ECH_EPARSE;
        uint8_t id = c[q++];
        unsigned kem = be16(c + q); q += 2;
        size_t pkn = be16(c + q); q += 2;
        if (q + pkn + 2 > len) return ECH_EPARSE;
        const uint8_t *pk = c + q; q += pkn;
        size_t sn = be16(c + q); q += 2;
        if (q + sn + 1 + 1 > len || (sn & 3)) return ECH_EPARSE;
        const uint8_t *suites = c + q; q += sn;
        uint8_t maxn = c[q++];
        size_t pnn = c[q++];
        if (q + pnn + 2 > len) return ECH_EPARSE;
        const char *pn = (const char *)(c + q); q += pnn;
        size_t xn = be16(c + q); q += 2;
        if (q + xn != len) return ECH_EPARSE;
        int mandatory = 0;
        for (size_t x = 0; x < xn;) {
            if (x + 4 > xn) return ECH_EPARSE;
            unsigned xt = be16(c + q + x);
            size_t xl = be16(c + q + x + 2);
            if (x + 4 + xl > xn) return ECH_EPARSE;
            if (xt & 0x8000u) mandatory = 1;              /* обязательное расширение, которого мы не знаем */
            x += 4 + xl;
        }
        if (mandatory || kem != 0x0020 || pkn != 32 || !name_ok(pn, pnn) || rawn > sizeof out->raw) continue;
        for (size_t s = 0; s < sn; s += 4) {
            unsigned kdf = be16(suites + s), aead = be16(suites + s + 2);
            if (kdf != 0x0001 || (aead != 0x0001 && aead != 0x0003)) continue;
            memset(out, 0, sizeof *out);
            out->config_id = id;
            out->kdf_id = (uint16_t)kdf;
            out->aead_id = (uint16_t)aead;
            memcpy(out->pk, pk, 32);
            out->max_name = maxn;
            memcpy(out->public_name, pn, pnn);
            memcpy(out->raw, raw, rawn);
            out->raw_n = rawn;
            return 0;
        }
    }
    return ECH_ENOCONFIG;
}

/* ---- HPKE (RFC 9180), режим base ----------------------------------------------------------- */

/* Buf под "HPKE-v1" ‖ suite_id ‖ label ‖ ikm: самый длинный ikm — info ("tls ech\0" ‖ ECHConfig ≤ 1032 байт). */
#define HB 1200

static int labeled_extract(const uint8_t *suite, size_t sn, const uint8_t *salt, size_t saltn,
                           const char *label, const uint8_t *ikm, size_t ikmn, uint8_t out[32]) {
    uint8_t b[HB];
    size_t ln = strlen(label), i = 0;
    if (7 + sn + ln + ikmn > sizeof b) return -1;
    memcpy(b, "HPKE-v1", 7); i = 7;
    memcpy(b + i, suite, sn); i += sn;
    memcpy(b + i, label, ln); i += ln;
    if (ikmn) memcpy(b + i, ikm, ikmn);
    i += ikmn;
    return sc_hkdf_extract(SC_SHA256, salt, saltn, b, i, out);
}

static int labeled_expand(const uint8_t prk[32], const uint8_t *suite, size_t sn, const char *label,
                          const uint8_t *info, size_t infon, size_t L, uint8_t *out) {
    uint8_t b[HB];
    size_t ln = strlen(label), i = 0;
    if (2 + 7 + sn + ln + infon > sizeof b) return -1;
    b[i++] = (uint8_t)(L >> 8);
    b[i++] = (uint8_t)L;
    memcpy(b + i, "HPKE-v1", 7); i += 7;
    memcpy(b + i, suite, sn); i += sn;
    memcpy(b + i, label, ln); i += ln;
    if (infon) memcpy(b + i, info, infon);
    i += infon;
    return sc_hkdf_expand(SC_SHA256, prk, 32, b, i, out, L);
}

int ech_hpke_seal(const struct ech_cfg *cfg, const uint8_t *eph,
                  const uint8_t *aad, size_t aad_n, const uint8_t *pt, size_t pt_n,
                  uint8_t enc[32], uint8_t *ct) {
    uint8_t sk[32], dh[32], prk[32], shared[32], secret[32], key[32], nonce[12];
    if (eph) memcpy(sk, eph, 32);
    else if (xc_random(sk, 32) != 0) return ECH_ECRYPTO;
    if (sc_x25519_base(enc, sk) != 0 || sc_x25519(dh, sk, cfg->pk) != 0) return ECH_ECRYPTO;

    /* DHKEM(X25519, HKDF-SHA256): suite_id = "KEM" ‖ kem_id. */
    static const uint8_t KEM[5] = { 'K', 'E', 'M', 0x00, 0x20 };
    uint8_t kctx[64];
    memcpy(kctx, enc, 32);
    memcpy(kctx + 32, cfg->pk, 32);
    if (labeled_extract(KEM, 5, NULL, 0, "eae_prk", dh, 32, prk) != 0 ||
        labeled_expand(prk, KEM, 5, "shared_secret", kctx, 64, 32, shared) != 0) return ECH_ECRYPTO;

    /* KeySchedule(base): suite_id = "HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id. */
    uint8_t suite[10] = { 'H', 'P', 'K', 'E', 0x00, 0x20, (uint8_t)(cfg->kdf_id >> 8), (uint8_t)cfg->kdf_id,
                          (uint8_t)(cfg->aead_id >> 8), (uint8_t)cfg->aead_id };
    uint8_t info[8 + 1024];
    if (8 + cfg->raw_n > sizeof info) return ECH_ETOOBIG;
    memcpy(info, "tls ech", 7);
    info[7] = 0;
    memcpy(info + 8, cfg->raw, cfg->raw_n);
    uint8_t ksc[1 + 32 + 32];
    ksc[0] = 0;                                              /* режим base */
    if (labeled_extract(suite, 10, NULL, 0, "psk_id_hash", NULL, 0, ksc + 1) != 0 ||
        labeled_extract(suite, 10, NULL, 0, "info_hash", info, 8 + cfg->raw_n, ksc + 33) != 0 ||
        labeled_extract(suite, 10, shared, 32, "secret", NULL, 0, secret) != 0) return ECH_ECRYPTO;
    enum sc_aead_alg alg = cfg->aead_id == 0x0003 ? SC_CHACHA20_POLY1305 : SC_AES128_GCM;
    size_t kn = sc_aead_key_len(alg);
    if (labeled_expand(secret, suite, 10, "key", ksc, sizeof ksc, kn, key) != 0 ||
        labeled_expand(secret, suite, 10, "base_nonce", ksc, sizeof ksc, 12, nonce) != 0) return ECH_ECRYPTO;

    /* Первое сообщение контекста: seq = 0, nonce = base_nonce. */
    struct sc_aead k;
    if (sc_aead_setkey(&k, alg, key) != 0) return ECH_ECRYPTO;
    if (pt_n) memcpy(ct, pt, pt_n);
    int rc = sc_aead_seal(&k, nonce, aad, aad_n, ct, pt_n, ct + pt_n);
    sc_aead_free(&k);
    steer_wipe(sk, sizeof sk);
    steer_wipe(key, sizeof key);
    return rc == 0 ? 0 : ECH_ECRYPTO;
}

/* ---- сборка Outer/Inner ------------------------------------------------------------------- */

struct wb {
    uint8_t *p;
    size_t n, cap;
    int bad;
};
static void w_put(struct wb *w, const void *d, size_t n) {
    if (w->bad || w->n + n > w->cap) { w->bad = 1; return; }
    if (n) memcpy(w->p + w->n, d, n);
    w->n += n;
}
static void w_u8(struct wb *w, unsigned v) { uint8_t b = (uint8_t)v; w_put(w, &b, 1); }
static void w_u16(struct wb *w, unsigned v) { uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v }; w_put(w, b, 2); }
static void w_u24(struct wb *w, size_t v) { uint8_t b[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v }; w_put(w, b, 3); }

#define EXT_ECH 0xfe0d

int ech_wrap(const struct ech_cfg *cfg, const uint8_t *hello, size_t hello_n,
             uint8_t *out, size_t cap, size_t *out_n, struct ech_state *st) {
    /* ---- разбор готового Hello ---- */
    if (hello_n < 5 + 4 + 35 || hello[0] != 0x16 || hello[5] != 0x01) return ECH_EPARSE;
    if ((size_t)be16(hello + 3) + 5 != hello_n || be24(hello + 6) + 9 != hello_n) return ECH_EPARSE;
    const uint8_t *b = hello + 9;
    size_t bn = hello_n - 9, p = 34;
    size_t sid_n = b[p];
    size_t sid_off = p + 1;
    p = sid_off + sid_n;
    if (p + 2 > bn) return ECH_EPARSE;
    p += 2 + be16(b + p);
    if (p + 1 > bn) return ECH_EPARSE;
    p += 1 + b[p];
    size_t pre_end = p;                                     /* здесь длина списка расширений */
    if (p + 2 > bn) return ECH_EPARSE;
    size_t ext_raw_n = be16(b + p), ext_off = p + 2;
    if (ext_off + ext_raw_n != bn) return ECH_EPARSE;
    /* Расширения без ECH: сборщик Hello по образцу Chrome кладёт в Hello GREASE-расширение ECH (0xfe0d со
     * случайной нагрузкой), и оно уступает место настоящему — два расширения одного типа недопустимы. */
    uint8_t ex[ECH_INNER_MAX], exi[ECH_INNER_MAX];         /* расширения Outer и Inner */
    size_t ex_n = 0, exi_n = 0, sni_len = 0;
    int have_sni = 0;
    for (size_t q = ext_off; q + 4 <= bn;) {
        unsigned t = be16(b + q);
        size_t l = be16(b + q + 2);
        if (q + 4 + l > bn) return ECH_EPARSE;
        if (t == 0 && l >= 5) { sni_len = be16(b + q + 5 + 2); have_sni = 1; }   /* список(2) тип(1) длина(2) */
        if (t != EXT_ECH) {
            if (ex_n + 4 + l > sizeof ex || exi_n + 4 + l > sizeof exi) return ECH_ETOOBIG;
            memcpy(ex + ex_n, b + q, 4 + l);
            ex_n += 4 + l;
            if (t == 0x002b && l >= 1) {
                /* supported_versions Inner: только TLS 1.3 и выше (RFC 9849, 6.1) — Go и BoringSSL отвергают
                 * Inner, предлагающий 1.2; GREASE-значения остаются, как в Hello. */
                size_t ln = b[q + 4], keep = 0;
                if (1 + ln != l || (ln & 1)) return ECH_EPARSE;
                exi[exi_n++] = b[q]; exi[exi_n++] = b[q + 1];       /* тип */
                size_t len_at = exi_n;
                exi_n += 3;                                          /* длина данных и длина списка — ниже */
                for (size_t v = 0; v < ln; v += 2) {
                    unsigned ver = be16(b + q + 5 + v);
                    int grease = (ver & 0x0F0F) == 0x0A0A && (ver & 0xFF) == (ver >> 8);
                    if (grease || ver >= 0x0304) { exi[exi_n++] = b[q + 5 + v]; exi[exi_n++] = b[q + 6 + v]; keep += 2; }
                }
                exi[len_at] = (uint8_t)((keep + 1) >> 8);
                exi[len_at + 1] = (uint8_t)(keep + 1);
                exi[len_at + 2] = (uint8_t)keep;
            } else {
                memcpy(exi + exi_n, b + q, 4 + l);
                exi_n += 4 + l;
            }
        }
        q += 4 + l;
    }
    if (!have_sni) return ECH_EPARSE;

    /* ---- Inner: полное сообщение для транскрипта (то же Hello + расширение ech_is_inner) ---- */
    struct wb w = { st->inner, 0, sizeof st->inner, 0 };
    w_u8(&w, 0x01);
    w_u24(&w, pre_end + 2 + exi_n + 5);
    w_put(&w, b, pre_end);
    w_u16(&w, exi_n + 5);
    w_put(&w, exi, exi_n);
    w_u16(&w, EXT_ECH); w_u16(&w, 1); w_u8(&w, 1);          /* inner: тип 1 */
    if (w.bad) return ECH_ETOOBIG;
    st->inner_n = w.n;
    memcpy(st->random, b + 2, 32);

    /* ---- EncodedClientHelloInner: то же без legacy_session_id (сервер вернёт его из Outer) + набивка ---- */
    uint8_t enc_in[ECH_INNER_MAX + 64];
    struct wb e = { enc_in, 0, sizeof enc_in - 64, 0 };
    w_put(&e, b, 34);
    w_u8(&e, 0);
    w_put(&e, b + sid_off + sid_n, pre_end - (sid_off + sid_n));
    w_u16(&e, exi_n + 5);
    w_put(&e, exi, exi_n);
    w_u16(&e, EXT_ECH); w_u16(&e, 1); w_u8(&e, 1);
    if (e.bad) return ECH_ETOOBIG;
    /* Набивка (RFC 9849, 6.1.3): имя дополняется до maximum_name_length, целое — до кратного 32. */
    size_t pad = cfg->max_name > sni_len ? cfg->max_name - sni_len : 0;
    pad += 31 - ((e.n + pad - 1) % 32);
    if (e.n + pad > sizeof enc_in) return ECH_ETOOBIG;
    memset(enc_in + e.n, 0, pad);
    size_t enc_n = e.n + pad, payload_n = enc_n + 16;

    /* ---- Outer ---- */
    uint8_t eph[32], enc_key[32];
    if (xc_random(eph, 32) != 0 || sc_x25519_base(enc_key, eph) != 0) return ECH_ECRYPTO;
    uint8_t orand[32];
    if (xc_random(orand, 32) != 0) return ECH_ECRYPTO;
    const size_t pn = strlen(cfg->public_name);
    const size_t ech_ext_n = 1 + 2 + 2 + 1 + 2 + 32 + 2 + payload_n;       /* данные расширения */
    /* Длина расширений Outer: исходные, за вычетом старого SNI, плюс новый SNI и ECH. */
    size_t old_sni_total = 0;
    for (size_t q = 0; q + 4 <= ex_n;) {
        size_t l = be16(ex + q + 2);
        if (be16(ex + q) == 0) old_sni_total = 4 + l;
        q += 4 + l;
    }
    const size_t new_sni_total = 4 + 2 + 1 + 2 + pn;
    const size_t o_ext_n = ex_n - old_sni_total + new_sni_total + 4 + ech_ext_n;
    const size_t o_body_n = 2 + 32 + 1 + sid_n + (pre_end - (sid_off + sid_n)) + 2 + o_ext_n;
    if (o_ext_n > 0xFFFF || 5 + 4 + o_body_n > cap) return ECH_ETOOBIG;

    struct wb o = { out, 0, cap, 0 };
    w_u8(&o, 0x16); w_u16(&o, 0x0301); w_u16(&o, 4 + o_body_n);
    w_u8(&o, 0x01); w_u24(&o, o_body_n);
    const size_t body0 = o.n;
    w_put(&o, b, 2);                                        /* версия */
    w_put(&o, orand, 32);                                   /* свой random у Outer */
    w_u8(&o, sid_n);
    w_put(&o, b + sid_off, sid_n);                          /* session_id один и тот же у обоих */
    w_put(&o, b + sid_off + sid_n, pre_end - (sid_off + sid_n));
    w_u16(&o, o_ext_n);
    for (size_t q = 0; q + 4 <= ex_n;) {
        size_t l = be16(ex + q + 2);
        if (be16(ex + q) == 0) {
            w_u16(&o, 0); w_u16(&o, 2 + 1 + 2 + pn);
            w_u16(&o, 1 + 2 + pn); w_u8(&o, 0); w_u16(&o, pn);
            w_put(&o, cfg->public_name, pn);
        } else {
            w_put(&o, ex + q, 4 + l);
        }
        q += 4 + l;
    }
    w_u16(&o, EXT_ECH); w_u16(&o, ech_ext_n);
    w_u8(&o, 0);                                            /* outer */
    w_u16(&o, cfg->kdf_id); w_u16(&o, cfg->aead_id);
    w_u8(&o, cfg->config_id);
    w_u16(&o, 32); w_put(&o, enc_key, 32);
    w_u16(&o, payload_n);
    const size_t payload_off = o.n;
    uint8_t zero[64] = { 0 };
    for (size_t z = payload_n; z > 0;) { size_t t = z < sizeof zero ? z : sizeof zero; w_put(&o, zero, t); z -= t; }
    if (o.bad || o.n != 5 + 4 + o_body_n) return ECH_ETOOBIG;

    /* AAD — Outer без заголовков (тело сообщения) с обнулённой нагрузкой; запечатывается Inner. */
    uint8_t ct[ECH_INNER_MAX + 64 + 16], enc_check[32];
    int rc = ech_hpke_seal(cfg, eph, out + body0, o_body_n, enc_in, enc_n, enc_check, ct);
    if (rc != 0) return rc;
    if (memcmp(enc_check, enc_key, 32) != 0) return ECH_ECRYPTO;
    memcpy(out + payload_off, ct, payload_n);
    *out_n = o.n;
    steer_wipe(eph, sizeof eph);
    return 0;
}
