/* Значение по пути в ответе JSON — для ответов API Cloudflare и проверок через туннель.
 *
 * Читатель спеки (src/lib/jsonr.c) ходит по документу известной формы и отказывает на чужой; здесь
 * форма чужая и меняется без спроса, поэтому нужен поиск: пройти к значению по пути, пропуская всё
 * остальное (js_skip). Поверх тех же js_*, своего разбора не заводим. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

/* Четыре шестнадцатеричные цифры с p в *v. 0 — они. */
static int hex4(const char *p, unsigned *v) {
    unsigned r = 0;
    for (int i = 0; i < 4; i++) {
        int d = p[i] >= '0' && p[i] <= '9' ? p[i] - '0' : p[i] >= 'a' && p[i] <= 'f' ? p[i] - 'a' + 10
              : p[i] >= 'A' && p[i] <= 'F' ? p[i] - 'A' + 10 : -1;
        if (d < 0) return -1;
        r = r << 4 | (unsigned)d;
    }
    *v = r;
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
                if (hex4(p, &v) != 0) return -1;
                p += 4;
                /* Суррогатная пара \uD83D\uDE00 — один знак за пределами BMP (эмодзи в имени
                 * устройства, в названии точки). Кодировать половины порознь значило писать CESU-8,
                 * которое не UTF-8, а потом отдавать его в JSON статуса (I-543). Одиночная половина
                 * — U+FFFD, как делают разборщики JSON. */
                if (v >= 0xD800 && v < 0xDC00) {
                    unsigned w = 0;
                    if (p[0] == '\\' && p[1] == 'u' && hex4(p + 2, &w) == 0 && w >= 0xDC00 && w < 0xE000) {
                        v = 0x10000 + ((v - 0xD800) << 10) + (w - 0xDC00);
                        p += 6;
                    } else v = 0xFFFD;
                } else if (v >= 0xDC00 && v < 0xE000) v = 0xFFFD;
                char u[4];
                size_t ul = v < 0x80 ? 1 : v < 0x800 ? 2 : v < 0x10000 ? 3 : 4;
                if (ul == 1) u[0] = (char)v;
                else if (ul == 2) { u[0] = (char)(0xc0 | v >> 6); u[1] = (char)(0x80 | (v & 0x3f)); }
                else if (ul == 3) { u[0] = (char)(0xe0 | v >> 12); u[1] = (char)(0x80 | ((v >> 6) & 0x3f)); u[2] = (char)(0x80 | (v & 0x3f)); }
                else { u[0] = (char)(0xf0 | v >> 18); u[1] = (char)(0x80 | ((v >> 12) & 0x3f)); u[2] = (char)(0x80 | ((v >> 6) & 0x3f)); u[3] = (char)(0x80 | (v & 0x3f)); }
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

/* Разобрать ответ целиком: статус, заголовки, тело (Content-Length, chunked или до закрытия). Тело
 * пишется на место в buf (chunked сжимается). 0 — разобрано; -1 — не HTTP; -2 — ответ оборван:
 * тела меньше Content-Length или у chunked нет завершающего куска. Раньше обрыв считался концом
 * ответа, и усечённое тело принималось за целое (I-543). Без Content-Length и chunked концом тела
 * служит закрытие соединения — вызывающий обязан отличить его от обрыва сам. */
int wb_http_split(char *buf, size_t n, int *status, size_t *body_off, size_t *body_n) {
    if (n < 12 || strncmp(buf, "HTTP/1.", 7) || buf[8] != ' ') return -1;
    *status = atoi(buf + 9);
    char *end = memmem(buf, n, "\r\n\r\n", 4);
    if (!end) return -1;
    size_t hoff = (size_t)(end - buf) + 4;
    int chunked = 0;
    long clen = -1;
    for (char *l = memchr(buf, '\n', hoff); l && l < end; l = memchr(l + 1, '\n', (size_t)(end - l))) {
        const char *h = l + 1;
        if (!strncasecmp(h, "Transfer-Encoding:", 18) && strstr(h, "chunked") && strstr(h, "chunked") < end)
            chunked = 1;
        if (!strncasecmp(h, "Content-Length:", 15)) clen = atol(h + 15);
    }
    *body_off = hoff;
    if (!chunked) {
        size_t have = n - hoff;
        if (clen >= 0 && (size_t)clen > have) return -2;
        *body_n = clen >= 0 ? (size_t)clen : have;
        return 0;
    }
    /* chunked: <hex>\r\n<data>\r\n ... 0\r\n\r\n — данные сдвигаются к началу тела. */
    size_t r = hoff, w = hoff;
    int term = 0;                        /* пришёл завершающий кусок «0» */
    for (;;) {
        if (r >= n) break;
        char *nl = memchr(buf + r, '\n', n - r);
        if (!nl) break;
        /* Размер — шестнадцатеричные цифры без знака (до «;расширения» или CRLF). strtoul принимал «-1» и
         * ULONG_MAX, а сумма r + len переполнялась и пропускала memmove с размером 2^64-1. Число сверх
         * длины буфера — заведомо не кусок этого ответа, разбор на этом кончается. */
        size_t len = 0;
        int nd = 0, bad = 0;
        for (const char *p = buf + r; p < nl; p++) {
            int dv = *p >= '0' && *p <= '9' ? *p - '0' : *p >= 'a' && *p <= 'f' ? *p - 'a' + 10
                   : *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : -1;
            if (dv < 0) break;
            if (len > n) { bad = 1; break; }
            len = len * 16 + (size_t)dv;
            nd++;
        }
        r = (size_t)(nl - buf) + 1;
        if (bad || !nd) return -1;       /* размер куска — не число: это не chunked */
        if (!len) { term = 1; break; }
        if (len > n - r) break;          /* кусок оборван */
        memmove(buf + w, buf + r, len);
        w += len;
        /* + 2 — CRLF после данных; len <= n - r, поэтому r не уйдёт за n больше чем на 2, а цикл проверяет r >= n. */
        r += len + 2;
    }
    if (!term) return -2;
    *body_n = w - hoff;
    return 0;
}

