/* Значение по пути в ответе JSON — для ответов API Cloudflare и проверок через туннель.
 *
 * Читатель спеки (src/lib/jsonr.c) ходит по документу известной формы и отказывает на чужой; здесь
 * форма чужая и меняется без спроса, поэтому нужен поиск: пройти к значению по пути, пропуская всё
 * остальное (js_skip). Поверх тех же js_*, своего разбора не заводим. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonr.h"
#include "wbjson.h"

/* Пропустить значение под j, не копируя строк: у js_skip строка внутри значения ограничена буфером
 * в 512 байт, а в ответе API бывают строки длиннее (ключи, лицензии) — на них обход обрывался, и
 * поля после них не находились (включение MASQUE, 2026-10-12). */
static int skip_str(struct js *j) {
    if (*j->p != '"') return -1;
    for (j->p++; *j->p; j->p++) {
        if (*j->p == '\\') { if (!*++j->p) return -1; continue; }
        if (*j->p == '"') { j->p++; return 0; }
    }
    return -1;
}

static int skip_val(struct js *j) {
    js_ws(j);
    if (*j->p == '"') return skip_str(j);
    if (*j->p == '{' || *j->p == '[') {
        int depth = 0;
        do {
            if (*j->p == '"') { if (skip_str(j)) return -1; continue; }
            if (*j->p == '{' || *j->p == '[') depth++;
            else if (*j->p == '}' || *j->p == ']') depth--;
            if (!*j->p) return -1;
            j->p++;
        } while (depth > 0);
        return 0;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
    return 0;
}

/* Строка с позиции p (кавычка) в out: экранирования JSON целиком (\\n — перевод строки, а не «n»:
 * так ключ PEM в ответе API терял переводы строк и получал лишние буквы). \\uXXXX — в UTF-8. */
static int get_str(const char *p, char *out, size_t n) {
    if (*p++ != '"') return -1;
    size_t o = 0;
    while (*p && *p != '"') {
        unsigned c = (unsigned char)*p++;
        if (c == '\\') {
            switch (*p++) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'u': {
                unsigned v = 0;
                for (int i = 0; i < 4; i++, p++) {
                    int d = *p >= '0' && *p <= '9' ? *p - '0' : *p >= 'a' && *p <= 'f' ? *p - 'a' + 10
                          : *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : -1;
                    if (d < 0) return -1;
                    v = v << 4 | (unsigned)d;
                }
                char u[4];
                size_t ul = v < 0x80 ? 1 : v < 0x800 ? 2 : 3;
                if (ul == 1) u[0] = (char)v;
                else if (ul == 2) { u[0] = (char)(0xc0 | v >> 6); u[1] = (char)(0x80 | (v & 0x3f)); }
                else { u[0] = (char)(0xe0 | v >> 12); u[1] = (char)(0x80 | ((v >> 6) & 0x3f)); u[2] = (char)(0x80 | (v & 0x3f)); }
                if (o + ul >= n) return -1;
                memcpy(out + o, u, ul);
                o += ul;
                continue;
            }
            default: return -1;
            }
        }
        if (o + 1 >= n) return -1;
        out[o++] = (char)c;
    }
    if (*p != '"') return -1;
    out[o] = '\0';
    return 0;
}

/* Встать на значение под ключом key в объекте под j. 0 — стоим на значении. */
static int obj_key(struct js *j, const char *key, size_t kn, struct err *e) {
    if (js_lit(j, '{') != 0) return -1;
    js_ws(j);
    if (*j->p == '}') return -1;
    for (;;) {
        js_ws(j);
        /* Ключ — сравнением на месте: ключи ответа короткие и без экранирования, а длинный чужой ключ
         * просто не совпадёт. */
        const char *k = j->p + 1;
        if (skip_str(j) != 0) return -1;
        size_t klen = (size_t)(j->p - k) - 1;        /* без закрывающей кавычки */
        if (js_lit(j, ':') != 0) return -1;
        if (klen == kn && !memcmp(k, key, kn)) { js_ws(j); return 0; }
        (void)e;
        if (skip_val(j) != 0) return -1;
        if (js_lit(j, ',') != 0) return -1;
    }
}

/* Встать на элемент idx массива под j. */
static int arr_idx(struct js *j, unsigned long idx, struct err *e) {
    if (js_lit(j, '[') != 0) return -1;
    js_ws(j);
    if (*j->p == ']') return -1;
    for (unsigned long i = 0;; i++) {
        js_ws(j);
        if (i == idx) return 0;
        (void)e;
        if (skip_val(j) != 0 || js_lit(j, ',') != 0) return -1;
    }
}

int wb_json_get(const char *doc, const char *path, char *out, size_t n) {
    if (!doc || !n) return -1;
    struct js j = { doc };
    struct err e;
    e.msg[0] = '\0';
    for (const char *s = path; *s;) {
        size_t sl = strcspn(s, ".");
        js_ws(&j);
        char *end;
        unsigned long idx = strtoul(s, &end, 10);
        int r = *j.p == '[' && end == s + sl && sl ? arr_idx(&j, idx, &e) : obj_key(&j, s, sl, &e);
        if (r != 0) return -1;
        s += sl;
        if (*s == '.') s++;
    }
    js_ws(&j);
    if (*j.p == '"') return get_str(j.p, out, n);
    if (*j.p == '{' || *j.p == '[' || !*j.p) return -1;
    size_t vl = strcspn(j.p, ",}] \t\r\n");
    if (!vl || vl >= n) return -1;
    memcpy(out, j.p, vl);
    out[vl] = '\0';
    return 0;
}
