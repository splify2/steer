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

/* Встать на значение под ключом key в объекте под j. 0 — стоим на значении. */
static int obj_key(struct js *j, const char *key, size_t kn, struct err *e) {
    if (js_lit(j, '{') != 0) return -1;
    js_ws(j);
    if (*j->p == '}') return -1;
    for (;;) {
        char k[128];
        if (js_str(j, k, sizeof(k), e) != 0 || js_lit(j, ':') != 0) return -1;
        if (strlen(k) == kn && !memcmp(k, key, kn)) { js_ws(j); return 0; }
        if (js_skip(j, e) != 0) return -1;
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
        if (js_skip(j, e) != 0 || js_lit(j, ',') != 0) return -1;
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
    if (*j.p == '"') return js_str(&j, out, n, &e);
    if (*j.p == '{' || *j.p == '[' || !*j.p) return -1;
    size_t vl = strcspn(j.p, ",}] \t\r\n");
    if (!vl || vl >= n) return -1;
    memcpy(out, j.p, vl);
    out[vl] = '\0';
    return 0;
}
