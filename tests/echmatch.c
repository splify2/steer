/* Encrypted Client Hello (src/proto/tls/ech.c) на настоящей криптобиблиотеке: разбор ECHConfigList, HPKE против
 * известного ответа и форма внешнего Hello. Запускается из tests/ext-test.sh (нужен wolfSSL за scrypto.h).
 *
 * ИЗВЕСТНЫЙ ОТВЕТ. Значения ниже (enc, ct) получены этим же кодом и затем РАСШИФРОВАНЫ настоящим crypto/hpke
 * из Go 1.27 (один раз, вручную: программа на 30 строк, читающая закрытый ключ, enc, aad, ct и info и
 * печатающая открытый текст) — и AES-128-GCM, и ChaCha20-Poly1305. Здесь они стоят защитой от случайного
 * изменения расписания ключей; что сервер принимает нагрузку целиком, проверяет tests/ech.sh против Xray-core.
 *
 * Списки конфигураций — настоящие: сгенерированный `xray tls ech` (девять наборов шифров) и опубликованный
 * Cloudflare (HTTPS-запись cloudflare-ech.com). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ech.h"
#include "reality.h"
#include "scrypto.h"

static int g_fail;
static void check(const char *what, int ok) {
    printf("%-78s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail++;
}

static int unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h) / 2;
    if (n > cap) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)n;
}

/* Расширение типа t в теле ClientHello (без заголовка сообщения); 1 — нашлось. */
static int find_ext(const uint8_t *b, size_t bn, unsigned t, const uint8_t **d, size_t *dn) {
    size_t p = 34;
    if (bn < 36) return 0;
    p += 1 + b[p];
    p += 2 + ((size_t)b[p] << 8 | b[p + 1]);
    p += 1 + b[p];
    if (p + 2 > bn) return 0;
    size_t en = (size_t)b[p] << 8 | b[p + 1], q = p + 2;
    if (q + en != bn) return 0;
    while (q + 4 <= bn) {
        unsigned et = b[q] << 8 | b[q + 1];
        size_t el = (size_t)b[q + 2] << 8 | b[q + 3];
        if (et == t) { *d = b + q + 4; *dn = el; return 1; }
        q += 4 + el;
    }
    return 0;
}

static const char XRAY_LIST[] =
    "AGH+DQBdAAAgACBKucSK28OK1Tj2jNOOe7CewFXPruMgsl39t6zFkD2HegAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAA5wdWJsaWMuZXhhbXBsZQAA";
static const char CF_LIST[] =
    "AEX+DQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f+95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

static int fill_sid_zero(void *ctx, unsigned char sid[32], const unsigned char *hs, size_t hs_n,
                         const unsigned char shared[32]) {
    (void)ctx; (void)hs; (void)hs_n; (void)shared;
    memset(sid, 0x5A, 32);
    return 0;
}

int main(void) {
    uint8_t list[1100];
    struct ech_cfg c;
    int n;

    n = ech_b64_decode(XRAY_LIST, list, sizeof list);
    check("Xray: список декодирован (99 байт)", n == 99);
    check("Xray: запись выбрана", ech_pick(list, (size_t)n, &c) == 0);
    check("Xray: id 0, HKDF-SHA256 + AES-128-GCM (первый набор списка), maximum_name_length 0",
          c.config_id == 0 && c.kdf_id == 1 && c.aead_id == 1 && c.max_name == 0);
    check("Xray: public_name public.example", !strcmp(c.public_name, "public.example"));

    n = ech_b64_decode(CF_LIST, list, sizeof list);
    check("Cloudflare: запись выбрана", ech_pick(list, (size_t)n, &c) == 0);
    check("Cloudflare: cloudflare-ech.com, maximum_name_length 0",
          !strcmp(c.public_name, "cloudflare-ech.com") && c.max_name == 0 && c.config_id == 0x37);

    /* Порча: длина списка не сходится; чужая версия; KEM не X25519; пустой набор. */
    n = ech_b64_decode(CF_LIST, list, sizeof list);
    list[1] ^= 1;
    check("список с неверной длиной — разбор отказывает", ech_pick(list, (size_t)n, &c) == ECH_EPARSE);
    list[1] ^= 1;
    list[2] = 0xfe; list[3] = 0x0c;
    check("чужая версия записи — пропуск, записей нет", ech_pick(list, (size_t)n, &c) == ECH_ENOCONFIG);
    list[3] = 0x0d;
    list[8] = 0x21;                                          /* kem_id 0x0021 (P-256/другой) */
    check("KEM не X25519 — пропуск", ech_pick(list, (size_t)n, &c) == ECH_ENOCONFIG);
    check("мусор вместо base64", ech_b64_decode("!!!", list, sizeof list) < 0);

    /* HPKE: известный ответ. */
    uint8_t skR[32], pkR[32];
    for (int i = 0; i < 32; i++) skR[i] = (uint8_t)(i * 7 + 1);
    sc_x25519_base(pkR, skR);
    uint8_t cfg[200], lst[220];
    size_t k = 0;
    cfg[k++] = 0xfe; cfg[k++] = 0x0d;
    size_t lp = k; k += 2;
    cfg[k++] = 7; cfg[k++] = 0; cfg[k++] = 0x20; cfg[k++] = 0; cfg[k++] = 32; memcpy(cfg + k, pkR, 32); k += 32;
    cfg[k++] = 0; cfg[k++] = 8; cfg[k++] = 0; cfg[k++] = 1; cfg[k++] = 0; cfg[k++] = 1; cfg[k++] = 0; cfg[k++] = 1; cfg[k++] = 0; cfg[k++] = 3;
    cfg[k++] = 32; cfg[k++] = 14; memcpy(cfg + k, "public.example", 14); k += 14; cfg[k++] = 0; cfg[k++] = 0;
    cfg[lp] = (uint8_t)((k - lp - 2) >> 8); cfg[lp + 1] = (uint8_t)(k - lp - 2);
    lst[0] = (uint8_t)(k >> 8); lst[1] = (uint8_t)k; memcpy(lst + 2, cfg, k);
    check("собственный список: запись выбрана", ech_pick(lst, k + 2, &c) == 0 && c.max_name == 32);

    static const struct { int aead; const char *enc, *ct; } KAT[] = {
        { 1, "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a",
             "af87037334647bec97c95ffb3bbbdf6f52f968e7c1f7a3dd1b16cec061dda9111fd4fdc27275b3dc2f24bd753e" },
        { 3, "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a",
             "12ded18e962790ed0538a212973bf9b55c7944f851db8c4e052a1c54dfc1b1f06783125f0bb6d8e7e570a9beb8" },
    };
    for (int i = 0; i < 2; i++) {
        c.aead_id = (uint16_t)KAT[i].aead;
        uint8_t eph[32], enc[32], ct[64], want_enc[32], want_ct[64];
        for (int j = 0; j < 32; j++) eph[j] = (uint8_t)(0x40 + j);
        const char *pt = "Beauty is truth, truth beauty", *aad = "aad-bytes-0123";
        int rc = ech_hpke_seal(&c, eph, (const uint8_t *)aad, strlen(aad), (const uint8_t *)pt, strlen(pt), enc, ct);
        int wn = unhex(KAT[i].ct, want_ct, sizeof want_ct);
        unhex(KAT[i].enc, want_enc, sizeof want_enc);
        char what[160];
        snprintf(what, sizeof what, "HPKE %s: enc и шифротекст совпали с проверенными Go",
                 KAT[i].aead == 1 ? "AES-128-GCM" : "ChaCha20-Poly1305");
        check(what, rc == 0 && wn == (int)strlen(pt) + 16 && !memcmp(enc, want_enc, 32) && !memcmp(ct, want_ct, (size_t)wn));
    }

    /* Внешний Hello: настоящий сборщик (облик Chrome, GREASE-ECH внутри, TLS 1.2 в supported_versions). */
    c.aead_id = 1;
    struct reality_cfg rcfg = { .sni = "secret.example", .plain = 1, .pq = 1, .fp = "chrome" };
    struct reality_state rst;
    static unsigned char hello[2560], outer[6144];
    size_t hn = 0, on = 0;
    static struct ech_state es;
    check("Hello собран сборщиком", reality_build_hello(&rcfg, &rst, hello, sizeof hello, &hn) == 0);
    check("ech_wrap: внешний Hello собран", ech_wrap(&c, hello, hn, outer, sizeof outer, &on, &es) == 0);
    check("  запись TLS: длина заголовка сходится", on > 5 && (size_t)(outer[3] << 8 | outer[4]) + 5 == on);
    check("  настоящего имени во внешнем Hello нет", memmem(outer, on, "secret.example", 14) == NULL);
    check("  public_name в SNI есть", memmem(outer, on, "public.example", 14) != NULL);
    check("  внутренний Hello хранит настоящее имя", memmem(es.inner, es.inner_n, "secret.example", 14) != NULL);
    check("  random внутреннего — из собранного Hello, внешнего — другой",
          !memcmp(es.random, hello + 11, 32) && memcmp(outer + 11, hello + 11, 32) != 0);
    check("  session_id один и тот же у обоих", outer[43] == hello[43] && !memcmp(outer + 44, hello + 44, hello[43]));
    check("  внутренний: сообщение ClientHello, длина сходится",
          es.inner[0] == 1 && ((size_t)es.inner[1] << 16 | (size_t)es.inner[2] << 8 | es.inner[3]) + 4 == es.inner_n);
    /* supported_versions внутреннего — без TLS 1.2 (0x0303); во внешнем остаётся. */
    const uint8_t *vi, *vo;
    size_t vin, von;
    int fi = find_ext(es.inner + 4, es.inner_n - 4, 0x002b, &vi, &vin);
    int fo = find_ext(outer + 9, on - 9, 0x002b, &vo, &von);
    int has12_in = 0, has12_out = 0, has13_in = 0;
    for (size_t q = 1; fi && q + 1 < vin; q += 2) { unsigned v = vi[q] << 8 | vi[q + 1]; has12_in |= v == 0x0303; has13_in |= v == 0x0304; }
    for (size_t q = 1; fo && q + 1 < von; q += 2) has12_out |= (vo[q] << 8 | vo[q + 1]) == 0x0303;
    check("  во внутреннем supported_versions: TLS 1.3 есть, TLS 1.2 нет", fi && has13_in && !has12_in);
    check("  во внешнем TLS 1.2 остался (облик Chrome)", fo && has12_out);
    const uint8_t *ei;
    size_t ein;
    check("  во внутреннем ech_is_inner (тип 1), во внешнем — outer (тип 0) единственный",
          find_ext(es.inner + 4, es.inner_n - 4, 0xfe0d, &ei, &ein) && ein == 1 && ei[0] == 1 &&
          find_ext(outer + 9, on - 9, 0xfe0d, &ei, &ein) && ein > 100 && ei[0] == 0);

    /* I-216: на пути носителя (fill_sid) authkey не выводится — но и мусором со стека он не остаётся. */
    {
        struct reality_cfg pc = { .sni = "secret.example", .plain = 1, .fp = "chrome" };
        struct reality_state ps;
        struct reality_carrier car;
        memset(&car, 0, sizeof car);
        car.fill_sid = fill_sid_zero;
        memset(&ps, 0xAA, sizeof ps);
        size_t pn = 0;
        int prc = reality_build_hello_carry(&pc, &ps, &car, hello, sizeof hello, &pn);
        static const uint8_t zero[32];
        check("I-216: носитель — Hello собран", prc == 0 && pn > 0);
        check("I-216: носитель — authkey и shared обнулены, а не мусор со стека",
              !memcmp(ps.authkey, zero, 32) && !memcmp(ps.shared, zero, 32));
    }

    printf(g_fail ? "echmatch: ПРОВАЛОВ %d\n" : "echmatch: все проверки прошли\n", g_fail);
    return g_fail ? 1 : 0;
}
