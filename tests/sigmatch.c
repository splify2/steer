/* Проверка подписи Ed25519 в формате usign (src/lib/sigverify.c, scrypto.c: sc_ed25519_verify).
 *
 * ВЕКТОРЫ НАСТОЯЩИЕ: ключи и подписи в tests/sigvec выпущены утилитой usign из репозитория
 * OpenWrt (git.openwrt.org/project/usign, c4c72b1): `usign -G`, `usign -S`. Два ключа — A и B;
 * msg.txt.sig подписан A, msg.txt.sigB — B. Секретные ключи в дерево не кладутся — стенду
 * нужны только открытые. Порчу (бит в подписи, бит в сообщении, чужой keynum, чужой алгоритм,
 * мусор в base64, хвост файла) стенд делает сам над настоящими векторами.
 *
 * Нужна настоящая криптобиблиотека (Ed25519 — wolfSSL за scrypto.h), поэтому стенд идёт в make
 * ext-test, а не в make test. Рабочий каталог — корень дерева (ext-test.sh). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unit.h"
#include "sigverify.h"

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { printf("нет файла %s\n", path); exit(2); }
    size_t cap = 4096, len = 0;
    char *b = malloc(cap);
    size_t got;
    while ((got = fread(b + len, 1, cap - len, f)) > 0) {
        len += got;
        if (len == cap) b = realloc(b, cap *= 2);
    }
    fclose(f);
    *n = len;
    return b;
}

int main(void) {
    size_t an, bn, mn, sn, sbn;
    char *apub = slurp("tests/sigvec/a.pub", &an);
    char *bpub = slurp("tests/sigvec/b.pub", &bn);
    char *msg = slurp("tests/sigvec/msg.txt", &mn);
    char *sigA = slurp("tests/sigvec/msg.txt.sig", &sn);
    char *sigB = slurp("tests/sigvec/msg.txt.sigB", &sbn);

    struct sigv_key ka, kb;
    struct sigv_sig sa, sb;
    check("разбор ключа A", 0, sigv_parse_key(apub, an, &ka));
    check("разбор ключа B", 0, sigv_parse_key(bpub, bn, &kb));
    check("разбор подписи A", 0, sigv_parse_sig(sigA, sn, &sa));
    check("разбор подписи B", 0, sigv_parse_sig(sigB, sbn, &sb));
    check("keynum подписи A = keynum ключа A", 0, memcmp(ka.keynum, sa.keynum, 8));
    check("keynum ключей A и B различны", 1, memcmp(ka.keynum, kb.keynum, 8) != 0);

    check("подпись A над сообщением — верна", 0, sigv_verify(&ka, &sa, msg, mn));
    check("подпись B над сообщением — верна ключом B", 0, sigv_verify(&kb, &sb, msg, mn));
    check("подпись B ключом A — чужой keynum", SIGV_EKEYNUM, sigv_verify(&ka, &sb, msg, mn));
    check("подпись A ключом B — чужой keynum", SIGV_EKEYNUM, sigv_verify(&kb, &sa, msg, mn));

    /* Порча сообщения: каждый бит первого байта, последний байт, усечение, дописывание. */
    char *m2 = malloc(mn + 1);
    int all_bad = 1;
    for (int bit = 0; bit < 8; bit++) {
        memcpy(m2, msg, mn);
        m2[0] ^= (char)(1 << bit);
        if (sigv_verify(&ka, &sa, m2, mn) != SIGV_EBAD) all_bad = 0;
    }
    check("любой бит первого байта сообщения — подпись не сходится", 1, all_bad);
    memcpy(m2, msg, mn);
    m2[mn - 1] ^= 1;
    check("порча последнего байта сообщения", SIGV_EBAD, sigv_verify(&ka, &sa, m2, mn));
    check("сообщение короче на байт", SIGV_EBAD, sigv_verify(&ka, &sa, msg, mn - 1));
    memcpy(m2, msg, mn);
    m2[mn] = '\n';
    check("сообщение длиннее на байт", SIGV_EBAD, sigv_verify(&ka, &sa, m2, mn + 1));
    check("пустое сообщение", SIGV_EBAD, sigv_verify(&ka, &sa, "", 0));

    /* Порча подписи: по биту в R-половине, в S-половине и в последнем байте. */
    int off[] = { 0, 31, 32, 40, 63 };
    all_bad = 1;
    for (size_t i = 0; i < sizeof off / sizeof off[0]; i++) {
        struct sigv_sig bad = sa;
        bad.sig[off[i]] ^= 0x01;
        if (sigv_verify(&ka, &bad, msg, mn) != SIGV_EBAD) all_bad = 0;
    }
    check("бит в подписи (R, S, последний байт) — подпись не сходится", 1, all_bad);
    {
        struct sigv_sig bad = sa;
        memset(bad.sig + 32, 0xff, 32);   /* S >= L: неканоническая подпись */
        check("неканоническая S (>= L) отвергнута", SIGV_EBAD, sigv_verify(&ka, &bad, msg, mn));
        bad = sa;
        bad.keynum[7] ^= 0x80;
        check("подпись A с испорченным keynum — чужой keynum", SIGV_EKEYNUM, sigv_verify(&ka, &bad, msg, mn));
    }
    {
        struct sigv_key bad = ka;
        bad.pk[5] ^= 0x10;
        int rc = sigv_verify(&bad, &sa, msg, mn);
        check("испорченный ключ — отказ (разбор или подпись)", 1, rc == SIGV_EBAD);
    }

    /* Набор доверенных ключей. */
    struct sigv_key set[2] = { kb, ka };
    check("набор {B,A}: подпись A — ключ индекса 1", 1, sigv_verify_any(set, 2, &sa, msg, mn));
    check("набор {B,A}: подпись B — ключ индекса 0", 0, sigv_verify_any(set, 2, &sb, msg, mn));
    check("набор {B}: подпись A — ключа с таким keynum нет", SIGV_EKEYNUM, sigv_verify_any(&kb, 1, &sa, msg, mn));
    check("пустой набор", SIGV_EKEYNUM, sigv_verify_any(NULL, 0, &sa, msg, mn));
    m2[0] ^= 1;
    check("набор {A}: испорченное сообщение", SIGV_EBAD, sigv_verify_any(&ka, 1, &sa, m2, mn));

    /* Файлом. */
    check("sigv_check_file: msg.txt", 0, sigv_check_file(&ka, &sa, "tests/sigvec/msg.txt"));
    check("sigv_check_file: другой файл", SIGV_EBAD, sigv_check_file(&ka, &sa, "tests/sigvec/a.pub"));
    check("sigv_check_file: файла нет", SIGV_EIO, sigv_check_file(&ka, &sa, "tests/sigvec/нет"));

    /* Формат. */
    struct sigv_sig tmp;
    struct sigv_key tk;
    check("пустой файл", SIGV_EFORMAT, sigv_parse_sig("", 0, &tmp));
    check("нет строки комментария", SIGV_EFORMAT, sigv_parse_sig(strchr(sigA, '\n') + 1, sn - (size_t)(strchr(sigA, '\n') + 1 - sigA), &tmp));
    check("только комментарий", SIGV_EFORMAT, sigv_parse_sig("untrusted comment: x\n", 21, &tmp));
    {
        /* Ключ в роли подписи и наоборот: длины разные. */
        check("ключ вместо подписи", SIGV_EFORMAT, sigv_parse_sig(apub, an, &tmp));
        check("подпись вместо ключа", SIGV_EFORMAT, sigv_parse_key(sigA, sn, &tk));
        char *x = malloc(sn + 16);
        memcpy(x, sigA, sn);
        memcpy(x + sn, "extra\n", 6);
        check("хвост после второй строки", SIGV_EFORMAT, sigv_parse_sig(x, sn + 6, &tmp));
        /* CRLF вместо LF — допустим. */
        char *crlf = malloc(sn + 4);
        size_t o = 0;
        for (size_t i = 0; i < sn; i++) { if (sigA[i] == '\n') crlf[o++] = '\r'; crlf[o++] = sigA[i]; }
        check("перевод строки CRLF", 0, sigv_parse_sig(crlf, o, &tmp));
        /* Без завершающего перевода строки — допустим. */
        check("без завершающего перевода строки", 0, sigv_parse_sig(sigA, sn - 1, &tmp));
        /* Испорченный base64. */
        memcpy(x, sigA, sn);
        char *p = strchr(x, '\n') + 1;
        p[10] = '!';
        check("символ вне алфавита base64", SIGV_EFORMAT, sigv_parse_sig(x, sn, &tmp));
        memcpy(x, sigA, sn);
        p = strchr(x, '\n') + 1;
        p[20] = ' ';
        check("пробел внутри base64", SIGV_EFORMAT, sigv_parse_sig(x, sn, &tmp));
        /* Другой алгоритм: «ED» (подпись над дайджестом) — base64 «RE». */
        memcpy(x, sigA, sn);
        p = strchr(x, '\n') + 1;
        p[0] = 'R'; p[1] = 'E';
        check("алгоритм ED (над дайджестом) не поддержан", SIGV_EALG, sigv_parse_sig(x, sn, &tmp));
        memcpy(x, sigA, sn);
        p = strchr(x, '\n') + 1;
        p[0] = 'S'; p[1] = 'S';
        check("неизвестный алгоритм", SIGV_EALG, sigv_parse_sig(x, sn, &tmp));
        /* Усечённый base64: длина не кратна четырём и кратна, но короче. */
        size_t bl = (size_t)(strchr(sigA, '\n') - sigA) + 1;
        memcpy(x, sigA, sn);
        x[bl + 96] = '\n';
        check("усечённая подпись (кратная длина)", SIGV_EFORMAT, sigv_parse_sig(x, bl + 97, &tmp));
        check("усечённая подпись (некратная длина)", SIGV_EFORMAT, sigv_parse_sig(x, bl + 99, &tmp));
        free(x); free(crlf);
    }
    free(m2); free(apub); free(bpub); free(msg); free(sigA); free(sigB);
    return unit_done("sigmatch");
}
