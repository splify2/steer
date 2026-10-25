/* Мелочи плагинной части ядра (plugin.c, plugprep.c): растущая строка, чтение файла, векторы строк.
 * static inline в заголовке, а не отдельный файл: обе единицы собираются во всех профилях и стендах,
 * лишний .c потребовал бы правки списков сборки (build/sources.mk, Android.bp). */
#ifndef STEER_PLUGUTIL_H
#define STEER_PLUGUTIL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline char *xdup(const char *s) { return s ? strdup(s) : NULL; }

/* Печатаемая строка, растущая сама. oom — нехватка памяти где-то по пути: проверяют один раз в конце. */
struct sbuf { char *p; size_t n, cap; int oom; };

static inline void sb_put(struct sbuf *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) { b->oom = 1; return; }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}
static inline void sb_str(struct sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }
__attribute__((format(printf, 2, 3)))
static inline void sb_printf(struct sbuf *b, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) { sb_put(b, tmp, (size_t)n); return; }
    char *big = malloc((size_t)n + 1);
    if (!big) { b->oom = 1; return; }
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_put(b, big, (size_t)n);
    free(big);
}
/* Строка JSON: кавычки и экранирование управляющих знаков; UTF-8 проходит как есть. */
static inline void sb_json(struct sbuf *b, const char *s) {
    sb_put(b, "\"", 1);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { char t[2] = { '\\', (char)c }; sb_put(b, t, 2); }
        else if (c == '\n') sb_str(b, "\\n");
        else if (c == '\r') sb_str(b, "\\r");
        else if (c == '\t') sb_str(b, "\\t");
        else if (c < 0x20) sb_printf(b, "\\u%04x", c);
        else sb_put(b, (const char *)&c, 1);
    }
    sb_put(b, "\"", 1);
}

static inline char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap);
    while (buf) {
        if (n + 1 >= cap) {
            char *nb = realloc(buf, cap * 2);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb;
            cap *= 2;
        }
        size_t got = fread(buf + n, 1, cap - 1 - n, f);
        if (!got) break;
        n += got;
    }
    fclose(f);
    if (!buf) return NULL;
    buf[n] = '\0';
    if (len) *len = n;
    return buf;
}

static inline void vec_free(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

static inline int vec_add(char ***v, size_t *n, const char *s) {
    char *c = strdup(s);
    if (!c) return -1;
    char **nv = realloc(*v, (*n + 1) * sizeof(*nv));
    if (!nv) { free(c); return -1; }
    nv[(*n)++] = c;
    *v = nv;
    return 0;
}


#endif
