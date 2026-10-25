/* Проверка подписи Ed25519 в формате usign/signify. Формат и коды — в sigverify.h.
 *
 * ЗАЧЕМ ЭТОТ ФОРМАТ. Пакеты плагинов подписываются usign — той же утилитой и тем же форматом ключей,
 * что и пакеты OpenWrt: у владельца уже есть привычка и ключи в /etc/opkg/keys, и ничего нового
 * выдумывать не пришлось. Сам формат — не безопасность, а упаковка: две строки, base64, 10 байт
 * заголовка. Безопасность — Ed25519 и список доверенных ключей у вызывающего.
 *
 * РАЗБОР СТРОГИЙ. base64 — по алфавиту RFC 4648 с обязательной набивкой и без пробелов внутри;
 * длина декодированного — ровно 42 и 74 байта. Файл ключа с хвостом или подпись с двумя строками
 * base64 — отказ, а не «что разобралось»: подпись, у которой неясно, что именно проверено, не
 * проверка. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sigverify.h"

#define COMMENT "untrusted comment:"

static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Декодировать base64 строки s длиной n в out (cap байт). Возвращает число байт или -1. */
static int b64dec(const char *s, size_t n, unsigned char *out, size_t cap) {
    if (n == 0 || n % 4) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4], pad = 0;
        for (int k = 0; k < 4; k++) {
            unsigned char c = (unsigned char)s[i + k];
            if (c == '=') {
                /* Набивка — только в хвосте последней четвёрки. */
                if (i + 4 != n || k < 2) return -1;
                pad++;
                v[k] = 0;
            } else {
                if (pad) return -1;
                v[k] = b64val(c);
                if (v[k] < 0) return -1;
            }
        }
        unsigned x = (unsigned)v[0] << 18 | (unsigned)v[1] << 12 | (unsigned)v[2] << 6 | (unsigned)v[3];
        size_t take = 3 - (size_t)pad;
        if (o + take > cap) return -1;
        for (size_t k = 0; k < take; k++) out[o++] = (unsigned char)(x >> (16 - 8 * k));
    }
    return (int)o;
}

/* Блок файла с начала t: строка комментария и строка base64. *b, *bn — вторая строка без перевода
 * строки, *used — сколько байт занял весь блок (с переводом строки после второй, если он есть).
 * false — формат не тот. */
static int block_line(const char *t, size_t n, const char **b, size_t *bn, size_t *used) {
    size_t cl = strlen(COMMENT);
    if (n < cl || memcmp(t, COMMENT, cl) != 0) return 0;
    const char *nl = memchr(t, '\n', n);
    if (!nl) return 0;
    const char *p = nl + 1;
    size_t left = n - (size_t)(p - t);
    const char *e = memchr(p, '\n', left);
    size_t l = e ? (size_t)(e - p) : left;
    *used = (size_t)(p - t) + l + (e ? 1 : 0);
    if (l && p[l - 1] == '\r') l--;
    if (!l) return 0;
    *b = p;
    *bn = l;
    return 1;
}

/* Вторая строка файла из одного блока; после неё допустим только её перевод строки. */
static int body_line(const char *t, size_t n, const char **b, size_t *bn) {
    size_t used;
    if (!block_line(t, n, b, bn, &used)) return 0;
    return used == n;
}

/* Общая часть: base64 → "Ed" ‖ keynum ‖ тело (len байт). */
static int parse_common(const char *text, size_t n, unsigned char keynum[8], unsigned char *body,
                        size_t body_n) {
    const char *b;
    size_t bn;
    if (!body_line(text, n, &b, &bn)) return SIGV_EFORMAT;
    unsigned char raw[2 + 8 + SC_ED25519_SIG];
    int r = b64dec(b, bn, raw, sizeof raw);
    if (r < 0 || (size_t)r != 2 + 8 + body_n) return SIGV_EFORMAT;
    if (raw[0] != 'E' || raw[1] != 'd') return SIGV_EALG;
    memcpy(keynum, raw + 2, 8);
    memcpy(body, raw + 10, body_n);
    return 0;
}

int sigv_parse_key(const char *text, size_t n, struct sigv_key *k) {
    return parse_common(text, n, k->keynum, k->pk, sizeof k->pk);
}

int sigv_parse_sig(const char *text, size_t n, struct sigv_sig *s) {
    return parse_common(text, n, s->keynum, s->sig, sizeof s->sig);
}

int sigv_parse_sigs(const char *text, size_t n, struct sigv_sigs *out) {
    out->v = NULL;
    out->n = 0;
    size_t cap = 0, off = 0;
    while (off < n) {
        const char *b;
        size_t bn, used;
        if (!block_line(text + off, n - off, &b, &bn, &used)) { sigv_sigs_free(out); return SIGV_EFORMAT; }
        if (out->n == cap) {
            size_t nc = cap ? cap * 2 : 2;
            struct sigv_sig *nv = realloc(out->v, nc * sizeof *nv);
            if (!nv) { sigv_sigs_free(out); return SIGV_ENOMEM; }
            out->v = nv;
            cap = nc;
        }
        int rc = sigv_parse_sig(text + off, used, &out->v[out->n]);
        if (rc) { sigv_sigs_free(out); return rc; }
        out->n++;
        off += used;
    }
    if (!out->n) return SIGV_EFORMAT;
    return 0;
}

void sigv_sigs_free(struct sigv_sigs *s) {
    free(s->v);
    s->v = NULL;
    s->n = 0;
}

int sigv_verify_blocks(const struct sigv_key *keys, size_t nkeys, const struct sigv_sigs *s,
                       const void *msg, size_t msg_n, size_t *key_idx) {
    int worst = SIGV_EKEYNUM;
    for (size_t i = 0; i < s->n; i++) {
        int rc = sigv_verify_any(keys, nkeys, &s->v[i], msg, msg_n);
        if (rc >= 0) {
            if (key_idx) *key_idx = (size_t)rc;
            return (int)i;
        }
        if (rc == SIGV_EBAD) worst = SIGV_EBAD;
        else if (rc != SIGV_EKEYNUM) return rc;
    }
    return worst;
}

void sigv_keynum_hex(const unsigned char keynum[8], char out[17]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) { out[2 * i] = hx[keynum[i] >> 4]; out[2 * i + 1] = hx[keynum[i] & 15]; }
    out[16] = 0;
}

int sigv_verify(const struct sigv_key *k, const struct sigv_sig *s, const void *msg, size_t msg_n) {
    if (memcmp(k->keynum, s->keynum, 8) != 0) return SIGV_EKEYNUM;
    int rc = sc_ed25519_verify(k->pk, msg, msg_n, s->sig);
    if (rc == 0) return 0;
    return rc == SC_ENOMEM ? SIGV_ENOMEM : SIGV_EBAD;
}

int sigv_verify_any(const struct sigv_key *keys, size_t nkeys, const struct sigv_sig *s,
                    const void *msg, size_t msg_n) {
    for (size_t i = 0; i < nkeys; i++) {
        if (memcmp(keys[i].keynum, s->keynum, 8) != 0) continue;
        int rc = sigv_verify(&keys[i], s, msg, msg_n);
        if (rc == 0) return (int)i;
        /* Ключ с этим keynum подпись не принял; другой ключ с тем же keynum (коллизия 64 бит
         * не случайна) всё ещё может — продолжаем. */
        if (rc != SIGV_EBAD) return rc;
    }
    for (size_t i = 0; i < nkeys; i++)
        if (memcmp(keys[i].keynum, s->keynum, 8) == 0) return SIGV_EBAD;
    return SIGV_EKEYNUM;
}

int sigv_check_file(const struct sigv_key *k, const struct sigv_sig *s, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return SIGV_EIO;
    unsigned char *buf = NULL;
    size_t n = 0, cap = 0;
    for (;;) {
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 65536;
            unsigned char *nb = realloc(buf, nc);
            if (!nb) { free(buf); fclose(f); return SIGV_ENOMEM; }
            buf = nb;
            cap = nc;
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) break;
    }
    int bad = ferror(f);
    fclose(f);
    int rc = bad ? SIGV_EIO : sigv_verify(k, s, buf, n);
    free(buf);
    return rc;
}
