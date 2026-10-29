/* Менеджер плагинов: semver и диапазоны в синтаксисе npm (manifest.md, «compat»).
 *
 * Версия — MAJOR[.MINOR[.PATCH]][-pre][+build]; недостающие части — нули (оси compat пишутся
 * «1.0»). Диапазон — наборы компараторов через «||», внутри набора — через пробел («и»);
 * компаратор — «=», «^», «~», «>=», «>», «<=», «<» или голая версия, части можно опускать или
 * писать «x»/«*». Пред-выпуски сравниваются по правилам semver 2.0 (по полям через точку). */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "pm.h"

struct sv {
    long n[3];
    int parts;              /* сколько частей названо (0 — «*») */
    const char *pre;        /* после «-» до «+» или конца; NULL — нет */
    size_t pre_n;
};

/* Разобрать версию из [s, s+len). 0 — годится. */
static int sv_parse(const char *s, size_t len, struct sv *v) {
    memset(v, 0, sizeof(*v));
    const char *p = s, *end = s + len;
    if (p < end && (*p == 'v' || *p == 'V')) p++;
    for (int i = 0; i < 3; i++) {
        if (p >= end) break;
        if (*p == 'x' || *p == 'X' || *p == '*') {
            p++;
            if (p < end && *p == '.') { p++; continue; }
            break;
        }
        if (!isdigit((unsigned char)*p)) return -1;
        long x = 0;
        while (p < end && isdigit((unsigned char)*p)) {
            if (x > 100000000L) return -1;
            x = x * 10 + (*p - '0');
            p++;
        }
        v->n[i] = x;
        v->parts = i + 1;
        if (p < end && *p == '.') { p++; continue; }
        break;
    }
    if (p < end && *p == '-') {
        p++;
        v->pre = p;
        while (p < end && *p != '+') p++;
        v->pre_n = (size_t)(p - v->pre);
        if (!v->pre_n) return -1;
    }
    if (p < end && *p == '+') p = end;
    return p == end ? 0 : -1;
}

static int pre_cmp(const struct sv *a, const struct sv *b) {
    if (!a->pre && !b->pre) return 0;
    if (!a->pre) return 1;           /* выпуск старше пред-выпуска */
    if (!b->pre) return -1;
    const char *x = a->pre, *xe = a->pre + a->pre_n, *y = b->pre, *ye = b->pre + b->pre_n;
    while (x < xe && y < ye) {
        const char *xd = memchr(x, '.', (size_t)(xe - x)), *yd = memchr(y, '.', (size_t)(ye - y));
        if (!xd) xd = xe;
        if (!yd) yd = ye;
        size_t xl = (size_t)(xd - x), yl = (size_t)(yd - y);
        int xn = 1, yn = 1;
        for (size_t i = 0; i < xl; i++) if (!isdigit((unsigned char)x[i])) xn = 0;
        for (size_t i = 0; i < yl; i++) if (!isdigit((unsigned char)y[i])) yn = 0;
        int c;
        if (xn && yn) c = xl != yl ? (xl < yl ? -1 : 1) : memcmp(x, y, xl);
        else if (xn) c = -1;
        else if (yn) c = 1;
        else {
            c = memcmp(x, y, xl < yl ? xl : yl);
            if (!c && xl != yl) c = xl < yl ? -1 : 1;
        }
        if (c) return c < 0 ? -1 : 1;
        x = xd < xe ? xd + 1 : xe;
        y = yd < ye ? yd + 1 : ye;
    }
    if (x < xe) return 1;
    if (y < ye) return -1;
    return 0;
}

static int sv_cmp(const struct sv *a, const struct sv *b) {
    for (int i = 0; i < 3; i++)
        if (a->n[i] != b->n[i]) return a->n[i] < b->n[i] ? -1 : 1;
    return pre_cmp(a, b);
}

int pm_ver_ok(const char *v) {
    struct sv s;
    return v && *v && sv_parse(v, strlen(v), &s) == 0 && s.parts >= 1;
}

int pm_ver_cmp(const char *a, const char *b) {
    struct sv x, y;
    int okx = a && sv_parse(a, strlen(a), &x) == 0;
    int oky = b && sv_parse(b, strlen(b), &y) == 0;
    if (!okx || !oky) return okx - oky;
    return sv_cmp(&x, &y);
}

long pm_ver_major(const char *v) {
    struct sv s;
    if (!v || sv_parse(v, strlen(v), &s) != 0) return -1;
    return s.n[0];
}

/* Нижняя и верхняя граница: [lo, hi) и lo_incl. Пустая граница — нет её. */
struct bound { int has_lo, lo_incl, has_hi, hi_incl; struct sv lo, hi; };

static void bump(struct sv *v, int part) {
    v->n[part]++;
    for (int i = part + 1; i < 3; i++) v->n[i] = 0;
    v->pre = NULL;
    v->pre_n = 0;
}

/* Один компаратор → граница. -1 — не разобрался. */
static int comp_parse(const char *s, size_t len, struct bound *b) {
    memset(b, 0, sizeof(*b));
    const char *p = s, *end = s + len;
    char op[3] = "";
    if (p < end && (*p == '^' || *p == '~' || *p == '=')) { op[0] = *p++; }
    else if (p < end && (*p == '>' || *p == '<')) {
        op[0] = *p++;
        if (p < end && *p == '=') op[1] = *p++;
    }
    while (p < end && *p == ' ') p++;
    struct sv v;
    if (sv_parse(p, (size_t)(end - p), &v) != 0) return -1;
    if (v.parts == 0) return 0;                          /* «*» — без границ */
    struct sv hi = v;
    switch (op[0]) {
    case '^': {
        b->has_lo = b->lo_incl = 1; b->lo = v;
        int part;
        if (v.n[0] > 0 || v.parts == 1) part = 0;
        else if (v.n[1] > 0 || v.parts == 2) part = 1;
        else part = 2;
        bump(&hi, part);
        b->has_hi = 1; b->hi = hi;
        return 0;
    }
    case '~':
        b->has_lo = b->lo_incl = 1; b->lo = v;
        bump(&hi, v.parts >= 2 ? 1 : 0);
        b->has_hi = 1; b->hi = hi;
        return 0;
    case '>':
        if (op[1] == '=') { b->has_lo = b->lo_incl = 1; b->lo = v; return 0; }
        if (v.parts < 3) { bump(&hi, v.parts - 1); b->has_lo = b->lo_incl = 1; b->lo = hi; return 0; }
        b->has_lo = 1; b->lo = v;
        return 0;
    case '<':
        if (op[1] == '=') {
            if (v.parts < 3) { bump(&hi, v.parts - 1); b->has_hi = 1; b->hi = hi; return 0; }
            b->has_hi = b->hi_incl = 1; b->hi = v;
            return 0;
        }
        b->has_hi = 1; b->hi = v;
        return 0;
    default:                                             /* «=» и голая версия */
        if (v.parts < 3) {
            b->has_lo = b->lo_incl = 1; b->lo = v;
            bump(&hi, v.parts - 1);
            b->has_hi = 1; b->hi = hi;
            return 0;
        }
        b->has_lo = b->lo_incl = b->has_hi = b->hi_incl = 1;
        b->lo = b->hi = v;
        return 0;
    }
}

static int in_bound(const struct bound *b, const struct sv *v) {
    if (b->has_lo) {
        int c = sv_cmp(v, &b->lo);
        if (c < 0 || (c == 0 && !b->lo_incl)) return 0;
    }
    if (b->has_hi) {
        int c = sv_cmp(v, &b->hi);
        if (c > 0 || (c == 0 && !b->hi_incl)) return 0;
    }
    return 1;
}

int pm_range_match(const char *r, const char *ver) {
    struct sv v;
    if (!ver || sv_parse(ver, strlen(ver), &v) != 0) return 0;
    if (!r) return 1;
    const char *p = r;
    int any_ok = 0, parsed_any = 0;
    for (;;) {
        const char *bar = strstr(p, "||");
        const char *se = bar ? bar : p + strlen(p);
        /* набор компараторов [p, se) */
        int all = 1, nonempty = 0;
        const char *q = p;
        while (q < se) {
            while (q < se && *q == ' ') q++;
            if (q >= se) break;
            const char *ws = q;
            /* оператор может стоять отдельно от версии: «>= 1.2» */
            while (q < se && (*q == '>' || *q == '<' || *q == '=' || *q == '^' || *q == '~')) q++;
            while (q < se && *q == ' ') q++;
            while (q < se && *q != ' ') q++;
            struct bound b;
            if (comp_parse(ws, (size_t)(q - ws), &b) != 0) return -1;
            nonempty = 1;
            if (!in_bound(&b, &v)) all = 0;
        }
        parsed_any = 1;
        if (all || !nonempty) any_ok = 1;
        if (!bar) break;
        p = bar + 2;
    }
    return parsed_any && any_ok;
}
