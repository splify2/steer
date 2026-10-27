#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "err.h"

/* Прежний немедленный отказ — оставлен для точек входа. Печатает ровно то же, что печатал
 * всегда: "steer: " + fmt%a + "\n" в stderr, потом exit(2). */
void die(const char *fmt, const char *a) {
    fprintf(stderr, "steer: ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
    exit(2);
}

/* Тот же текст, что собрал бы die(fmt, a) между "steer: " и "\n", — но в буфер, а не в stderr,
 * и без exit. snprintf, а не sprintf: буфер фиксирован (1024), и сообщение с длинной
 * подстановкой (например, путь из спеки) не должно переписать чужую память.
 *
 * noinline — НАРОЧНО, и не ради скорости. fmt здесь — параметр, не литерал, и сам по себе
 * анализу -Wformat-truncation не подлежит; но стенды, включающие исходники модели одним
 * #include (specmatch, dnsmatch, obfsmatch, awgmatch), собирают эту функцию в одной единице
 * трансляции с её вызывающими, и при инлайне компилятор протягивает КОНКРЕТНЫЙ литерал из
 * места вызова прямо в snprintf — тогда «выход %s: …» с непредсказуемым по длине именем
 * выхода выглядит как потенциальное усечение и попадает в предупреждение, хотя усечение здесь
 * ровно то поведение, ради которого snprintf (а не sprintf) и выбран. noinline держит границу
 * анализа там же, где raньше её держал fprintf(stderr, fmt, a) в die() — внутри одной функции,
 * которая просто передаёт fmt дальше, не зная его содержимого на этапе компиляции. */
__attribute__((noinline))
int err_set(struct err *e, const char *fmt, const char *a) {
    snprintf(e->msg, sizeof(e->msg), fmt, a);
    e->code[0] = 0;
    e->args[0] = 0;
    return -1;
}

void err_args_add(char *args, size_t cap, const char *name, const char *val) {
    char v[256];
    size_t n = strlen(val ? val : "");
    if (n > 240) {
        n = 240;
        while (n && ((unsigned char)val[n] & 0xC0) == 0x80) n--;   /* не посреди символа UTF-8 */
    }
    memcpy(v, val ? val : "", n);
    v[n] = 0;
    char esc[6 * 256 + 8];
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c == '"' || c == '\\') { esc[o++] = '\\'; esc[o++] = (char)c; }
        else if (c < 0x20) o += (size_t)snprintf(esc + o, 8, "\\u%04x", c);
        else esc[o++] = (char)c;
    }
    esc[o] = 0;
    size_t len = strlen(args);
    char item[6 * 256 + 64];
    int w = snprintf(item, sizeof(item), "\"%s\":\"%s\"}", name, esc);
    if (w < 0 || len + (size_t)w + 2 > cap) return;
    if (len == 0) { args[0] = '{'; memcpy(args + 1, item, (size_t)w + 1); }
    else { args[len - 1] = ','; memcpy(args + len, item, (size_t)w + 1); }
}

int err_setc(struct err *e, const char *code, const char *fmt, const char *a) {
    err_set(e, fmt, a);
    snprintf(e->code, sizeof(e->code), "%s", code ? code : "");
    if (a && strcmp(fmt, "%s") && strstr(fmt, "%s")) err_args_add(e->args, sizeof(e->args), "1", a);
    return -1;
}

int err_vsetc(struct err *e, const char *code, const char *fmt, va_list ap) {
    va_list cp;
    va_copy(cp, ap);
    vsnprintf(e->msg, sizeof(e->msg), fmt, cp);
    va_end(cp);
    snprintf(e->code, sizeof(e->code), "%s", code ? code : "");
    e->args[0] = 0;
    int idx = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;
        int star = 0;
        while (*p && strchr("-+ #0123456789.*", *p)) { if (*p == '*') star = 1; p++; }
        if (star) (void)va_arg(ap, int);
        int lng = 0;
        while (*p == 'l' || *p == 'z' || *p == 'h') { lng++; p++; }
        char name[16], val[64];
        const char *sv = val;
        switch (*p) {
        case 's': sv = va_arg(ap, const char *); if (!sv) sv = "(null)"; break;
        case 'd': case 'i':
            snprintf(val, sizeof(val), "%lld", lng ? (long long)va_arg(ap, long) : (long long)va_arg(ap, int)); break;
        case 'u': case 'x': case 'o':
            snprintf(val, sizeof(val), "%llu", lng ? (unsigned long long)va_arg(ap, unsigned long) : (unsigned long long)va_arg(ap, unsigned)); break;
        case 'c': snprintf(val, sizeof(val), "%c", va_arg(ap, int)); break;
        default: return -1;   /* спецификатор, которого здесь нет, — код остаётся, подстановки пропущены */
        }
        snprintf(name, sizeof(name), "%d", ++idx);
        err_args_add(e->args, sizeof(e->args), name, sv);
        if (!*p) break;
    }
    return -1;
}

int err_setf(struct err *e, const char *code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    err_vsetc(e, code, fmt, ap);
    va_end(ap);
    return -1;
}

int err_json(const struct err *e, char *buf, size_t cap) {
    char m[6 * 1024 + 8];
    size_t o = 0;
    for (const char *p = e->msg; *p && o < sizeof(m) - 8; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { m[o++] = '\\'; m[o++] = (char)c; }
        else if (c < 0x20) o += (size_t)snprintf(m + o, 8, "\\u%04x", c);
        else m[o++] = (char)c;
    }
    m[o] = 0;
    int w = snprintf(buf, cap, "{\"ok\":false,\"error\":\"%s\"", m);
    if (w < 0 || (size_t)w >= cap) return -1;
    if (e->code[0]) w += snprintf(buf + w, cap - (size_t)w, ",\"code\":\"%s\",\"args\":%s", e->code, e->args[0] ? e->args : "{}");
    if ((size_t)w + 2 > cap) return -1;
    buf[w++] = '}';
    buf[w] = 0;
    return w;
}

void err_print(const struct err *e) {
    fprintf(stderr, "steer: %s\n", e->msg);
    if (getenv("STEER_ERR_JSON")) {
        char b[8192];
        if (err_json(e, b, sizeof(b)) > 0) fprintf(stderr, "%s\n", b);
    }
}

void err_die(const struct err *e) {
    err_print(e);
    exit(2);
}
