/* JSON для программ плагина (pkjson.h). */
#define _GNU_SOURCE
#include "pkjson.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pr {
    const char *b, *p, *e;
    char *err;
    size_t errn;
    int depth;
};

static void *pfail(struct pr *r, const char *fmt, ...) {
    if (r->err && r->errn && !r->err[0]) {
        char m[200];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(m, sizeof m, fmt, ap);
        va_end(ap);
        snprintf(r->err, r->errn, "JSON, байт %zu: %s", (size_t)(r->p - r->b), m);
    }
    return NULL;
}

static void ws(struct pr *r) {
    while (r->p < r->e && (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r')) r->p++;
}

static struct pkj *node(enum pkj_type t) {
    struct pkj *j = calloc(1, sizeof(*j));
    if (j) j->t = t;
    return j;
}

static int push(struct pkj *j, struct pkj *v, char *k) {
    struct pkj **nv = realloc(j->v, (j->n + 1) * sizeof(*nv));
    if (!nv) return -1;
    j->v = nv;
    if (j->t == PKJ_OBJ) {
        char **nk = realloc(j->k, (j->n + 1) * sizeof(*nk));
        if (!nk) return -1;
        j->k = nk;
        j->k[j->n] = k;
    }
    j->v[j->n++] = v;
    return 0;
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static void put_utf8(char *o, size_t *k, unsigned cp) {
    if (cp < 0x80) o[(*k)++] = (char)cp;
    else if (cp < 0x800) { o[(*k)++] = (char)(0xc0 | (cp >> 6)); o[(*k)++] = (char)(0x80 | (cp & 0x3f)); }
    else if (cp < 0x10000) {
        o[(*k)++] = (char)(0xe0 | (cp >> 12));
        o[(*k)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[(*k)++] = (char)(0x80 | (cp & 0x3f));
    } else {
        o[(*k)++] = (char)(0xf0 | (cp >> 18));
        o[(*k)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        o[(*k)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[(*k)++] = (char)(0x80 | (cp & 0x3f));
    }
}

/* Строка; курсор на открывающей кавычке. Результат в куче. */
static char *str(struct pr *r) {
    r->p++;
    const char *s = r->p;
    size_t cap = 0;
    while (s < r->e && *s != '"') { if (*s == '\\') s++; s++; cap++; }
    char *o = malloc(cap * 4 + 1);
    if (!o) return pfail(r, "нет памяти");
    size_t k = 0;
    while (r->p < r->e && *r->p != '"') {
        unsigned char c = (unsigned char)*r->p;
        if (c < 0x20) { free(o); return pfail(r, "управляющий байт в строке"); }
        if (c != '\\') { o[k++] = (char)c; r->p++; continue; }
        if (++r->p >= r->e) break;
        switch (*r->p) {
        case '"': o[k++] = '"'; break;
        case '\\': o[k++] = '\\'; break;
        case '/': o[k++] = '/'; break;
        case 'b': o[k++] = '\b'; break;
        case 'f': o[k++] = '\f'; break;
        case 'n': o[k++] = '\n'; break;
        case 'r': o[k++] = '\r'; break;
        case 't': o[k++] = '\t'; break;
        case 'u': {
            unsigned cp, lo;
            if (r->e - r->p < 5 || hex4(r->p + 1, &cp) != 0) { free(o); return pfail(r, "неверное \\u"); }
            r->p += 4;
            if (cp >= 0xd800 && cp < 0xdc00 && r->e - r->p >= 7 && r->p[1] == '\\' && r->p[2] == 'u' &&
                hex4(r->p + 3, &lo) == 0 && lo >= 0xdc00 && lo < 0xe000) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                r->p += 6;
            }
            put_utf8(o, &k, cp);
            break;
        }
        default: free(o); return pfail(r, "неверная escape-последовательность");
        }
        r->p++;
    }
    if (r->p >= r->e) { free(o); return pfail(r, "строка не закрыта"); }
    r->p++;
    o[k] = '\0';
    return o;
}

static struct pkj *value(struct pr *r);

static struct pkj *container(struct pr *r, int obj) {
    if (++r->depth > 512) return pfail(r, "вложенность больше 512");
    struct pkj *j = node(obj ? PKJ_OBJ : PKJ_ARR);
    if (!j) return pfail(r, "нет памяти");
    r->p++;
    ws(r);
    char close = obj ? '}' : ']';
    if (r->p < r->e && *r->p == close) { r->p++; r->depth--; return j; }
    for (;;) {
        char *k = NULL;
        ws(r);
        if (obj) {
            if (r->p >= r->e || *r->p != '"') { pkj_free(j); return pfail(r, "нужен ключ в кавычках"); }
            if (!(k = str(r))) { pkj_free(j); return NULL; }
            ws(r);
            if (r->p >= r->e || *r->p != ':') { free(k); pkj_free(j); return pfail(r, "нужно «:»"); }
            r->p++;
        }
        struct pkj *v = value(r);
        if (!v) { free(k); pkj_free(j); return NULL; }
        if (push(j, v, k) != 0) { free(k); pkj_free(v); pkj_free(j); return pfail(r, "нет памяти"); }
        ws(r);
        if (r->p < r->e && *r->p == ',') { r->p++; continue; }
        if (r->p < r->e && *r->p == close) { r->p++; break; }
        pkj_free(j);
        return pfail(r, obj ? "нужно «,» или «}»" : "нужно «,» или «]»");
    }
    r->depth--;
    return j;
}

static struct pkj *value(struct pr *r) {
    ws(r);
    if (r->p >= r->e) return pfail(r, "документ оборван");
    char c = *r->p;
    if (c == '{' || c == '[') return container(r, c == '{');
    if (c == '"') {
        struct pkj *j = node(PKJ_STR);
        if (!j) return pfail(r, "нет памяти");
        if (!(j->s = str(r))) { free(j); return NULL; }
        return j;
    }
    static const struct { const char *w; enum pkj_type t; int b; } LIT[] = {
        { "true", PKJ_BOOL, 1 }, { "false", PKJ_BOOL, 0 }, { "null", PKJ_NULL, 0 } };
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(LIT[i].w);
        if ((size_t)(r->e - r->p) >= l && !memcmp(r->p, LIT[i].w, l)) {
            r->p += l;
            struct pkj *j = node(LIT[i].t);
            if (!j) return pfail(r, "нет памяти");
            j->b = LIT[i].b;
            return j;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *s = r->p;
        int frac = 0;
        if (*r->p == '-') r->p++;
        if (r->p >= r->e || *r->p < '0' || *r->p > '9') return pfail(r, "неверное число");
        while (r->p < r->e && ((*r->p >= '0' && *r->p <= '9') || *r->p == '.' || *r->p == 'e' ||
                               *r->p == 'E' || *r->p == '+' || *r->p == '-')) {
            if (*r->p == '.' || *r->p == 'e' || *r->p == 'E') frac = 1;
            r->p++;
        }
        struct pkj *j = node(PKJ_NUM);
        if (!j || !(j->s = strndup(s, (size_t)(r->p - s)))) { free(j); return pfail(r, "нет памяти"); }
        char *end;
        errno = 0;
        j->num = strtod(j->s, &end);
        if (*end) { pkj_free(j); return pfail(r, "неверное число"); }
        j->integer = !frac;
        return j;
    }
    return pfail(r, "неожиданный знак «%c»", c);
}

struct pkj *pkj_parse(const char *txt, size_t len, char *err, size_t errn) {
    struct pr r = { txt, txt, txt + len, err, errn, 0 };
    if (err && errn) err[0] = '\0';
    struct pkj *j = value(&r);
    if (!j) return NULL;
    ws(&r);
    if (r.p != r.e) { pkj_free(j); return pfail(&r, "лишнее после документа"); }
    return j;
}

struct pkj *pkj_load(const char *path, char *err, size_t errn) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) { snprintf(err, errn, "%s: %s", path, strerror(errno)); return NULL; }
    size_t cap = 4096, n = 0;
    char *b = malloc(cap);
    for (size_t rd; b && (rd = fread(b + n, 1, cap - n, f)) > 0;) {
        n += rd;
        if (n == cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); b = NULL; } else b = nb; }
    }
    if (f != stdin) fclose(f);
    if (!b) { snprintf(err, errn, "%s: нет памяти", path); return NULL; }
    struct pkj *j = pkj_parse(b, n, err, errn);
    if (!j && err && errn) {
        char m[256];
        snprintf(m, sizeof m, "%s", err);
        snprintf(err, errn, "%s: %s", path, m);
    }
    free(b);
    return j;
}

void pkj_free(struct pkj *j) {
    if (!j) return;
    for (size_t i = 0; i < j->n; i++) {
        pkj_free(j->v[i]);
        if (j->k) free(j->k[i]);
    }
    free(j->v);
    free(j->k);
    free(j->s);
    free(j);
}

const struct pkj *pkj_get(const struct pkj *j, const char *key) {
    if (!j || j->t != PKJ_OBJ) return NULL;
    for (size_t i = 0; i < j->n; i++)
        if (!strcmp(j->k[i], key)) return j->v[i];
    return NULL;
}

const char *pkj_str(const struct pkj *j) { return j && j->t == PKJ_STR ? j->s : NULL; }

int pkj_long(const struct pkj *j, long *out) {
    if (!j || j->t != PKJ_NUM || !j->integer) return -1;
    *out = (long)j->num;
    return 0;
}

int pkj_bool(const struct pkj *j, int *out) {
    if (!j || j->t != PKJ_BOOL) return -1;
    *out = j->b;
    return 0;
}

const struct pkj *pkj_at(const struct pkj *j, size_t i) {
    return j && j->t == PKJ_ARR && i < j->n ? j->v[i] : NULL;
}

size_t pkj_len(const struct pkj *j) {
    return j && (j->t == PKJ_ARR || j->t == PKJ_OBJ) ? j->n : 0;
}

const struct pkj *pkj_path(const struct pkj *j, const char *path) {
    char key[128];
    while (j && *path) {
        const char *d = strchr(path, '.');
        size_t l = d ? (size_t)(d - path) : strlen(path);
        if (l >= sizeof key) return NULL;
        memcpy(key, path, l);
        key[l] = '\0';
        j = pkj_get(j, key);
        path += l + (d ? 1 : 0);
    }
    return j;
}
