/* Формат целиком — в шапке evline.h. Здесь — запись (сторона помощника) и разбор (сторона
 * демона) одной и той же строки. */
#include "evline.h"
#include "jsonw.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

/* -2 — evline_open() ещё не звали (ленивая инициализация из evline_emit); -1 — звали, и
 * труба выключена; иначе — дескриптор. Один процесс — одна труба, глобал оправдан тем же,
 * чем оправдан он у остальных помощников (g_sp, g_cf и соседи в xsclient.c): второй трубы
 * событий у процесса не бывает. */
static int g_fd = -2;

/* Помощник демона не переживает демона (src/daemon/supd.c, шапка, «Помощники демона не
 * переживают»). Демон ставит ребёнку PR_SET_PDEATHSIG(SIGTERM) до exec и метку STEER_SUPD=<pid
 * демона>:<время старта>:<каталог>; здесь, уже после exec, — вторая половина: признак взводится
 * заново (exec файла с set-uid или capabilities его снимает, а поставить его заново ничего не
 * стоит), и если родитель уже не тот pid — демон умер раньше, чем мы дошли досюда, и помощник
 * выходит тем же SIGTERM, который прислало бы ядро: своим обычным путём (обработчик SIGTERM,
 * если он уже поставлен, иначе действие по умолчанию). Без метки (ручной запуск, стенды,
 * `steer supervise`) — ничего не делает. */
static void supd_parent_check(void) {
    const char *t = getenv("STEER_SUPD");
    if (!t || !*t) return;
    char *end = NULL;
    long p = strtol(t, &end, 10);
    if (end == t || *end != ':' || p <= 0) return;
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != (pid_t)p) raise(SIGTERM);
}

void evline_open(void) {
    if (g_fd != -2) return;             /* идемпотентно — вторая попытка ничего не меняет */
    g_fd = -1;
    const char *s = getenv("STEER_EVENT_FD");
    if (!s || !*s) return;              /* нет переменной — выключено */
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 0 || v > INT_MAX) return;   /* негодная — выключено */
    int fd = (int)v;
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) return;                 /* дескриптора нет вовсе — выключено */
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return;
    g_fd = fd;
    supd_parent_check();
}

static void evline_ensure_open(void) {
    if (g_fd == -2) evline_open();
}

int evline_enabled(void) {
    evline_ensure_open();
    return g_fd >= 0;
}

/* Предел — PIPE_BUF (evline.h, EVLINE_LINE_MAX): до него write в трубу атомарен, а событие
 * длиннее может пройти частью и оставить в трубе обрубок невалидного JSON. Прежние 480 байт
 * резали список активных узлов пула уже на сотне узлов — теперь событие, не влезшее и в
 * четыре килобайта, теряется целиком, но с длиной в журнале (stderr помощника). */
#define EVLINE_WRITE_MAX EVLINE_LINE_MAX

void evline_emit(const char *ev, ...) {
    evline_ensure_open();
    if (g_fd < 0) return;

    char *mem = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&mem, &n);
    if (!f) return;

    fputs("{\"ev\":", f);
    jsonw_str_ascii(f, ev);

    va_list ap;
    va_start(ap, ev);
    for (;;) {
        const char *key = va_arg(ap, const char *);
        if (!key) break;
        enum evline_type type = (enum evline_type)va_arg(ap, int);
        fputc(',', f);
        jsonw_str_ascii(f, key);
        fputc(':', f);
        if (type == EVLINE_STR) {
            const char *sv = va_arg(ap, const char *);
            jsonw_str_ascii(f, sv);
        } else {
            long iv = va_arg(ap, long);
            fprintf(f, "%ld", iv);
        }
    }
    va_end(ap);
    fputs("}\n", f);
    fclose(f);

    /* Одна запись, атомарная по построению трубы; O_NONBLOCK (evline_open) не даёт ей
     * заблокировать помощника, если демон отстал, — короткая запись или EAGAIN теряют
     * событие молча, ошибку никому сообщать не нужно (следующее событие важнее этого).
     *
     * EPIPE — другое: конец чтения закрыт, то есть демона нет (он держит его до supd_stop, а там
     * гасит помощника раньше, чем закрывает трубу — и тогда помощник уже в своём SIGTERM). Здесь
     * это единственный способ узнать о закрытой трубе: SIGPIPE у модульных команд выключен
     * (cli/modcmd.c, ради сокетов узла — запись TLS в закрытое соединение иначе убивала весь
     * модуль), как у моста tgws и резолвера, и запись возвращает EPIPE. Помощник без демона не
     * нужен (src/daemon/supd.c, «Помощники демона не переживают») — выход тем же SIGTERM, что по
     * PDEATHSIG. Только с меткой демона: у ручного запуска с чужой трубой свои правила. */
    if (mem && n > EVLINE_WRITE_MAX)
        fprintf(stderr, "steer[warn] событие %s не влезло в трубу: %zu байт при пределе %d — потеряно\n",
                ev, n, EVLINE_WRITE_MAX);
    if (mem && n > 0 && n <= EVLINE_WRITE_MAX) {
        ssize_t w = write(g_fd, mem, n);
        if (w < 0 && errno == EPIPE && getenv("STEER_SUPD")) raise(SIGTERM);
    }
    free(mem);
}

void evline_hello(const char *module, const char *version) {
    evline_emit("hello", "ver", EVLINE_STR, version, "mod", EVLINE_STR, module, (const char *)NULL);
}

/* ---- разбор ------------------------------------------------------------------------- */

/* Строка в кавычках, курсор *p стоит на открывающей. Разворачивает ТЕ escape-последовательности,
 * которые сама печатает jsonw_str_ascii (\", \\, управляющие и байты вне ASCII через \u00XX —
 * то есть кодовая точка не больше 0xff, она же исходный байт) плюс обычные \/ \b \f \n \r \t на
 * случай ручной строки в отладке. Что не влезло в буфер — обрезается, разбор всё равно
 * заканчивается корректно (курсор доходит до закрывающей кавычки). Возвращает указатель СРАЗУ
 * ЗА закрывающей кавычкой, либо NULL, если строка не закрылась. */
static const char *parse_jstr(const char *p, char *out, size_t outsz) {
    if (*p != '"') return NULL;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            p++;
            if (!*p) return NULL;
            char v;
            switch (*p) {
            case '"': v = '"'; break;
            case '\\': v = '\\'; break;
            case '/': v = '/'; break;
            case 'b': v = '\b'; break;
            case 'f': v = '\f'; break;
            case 'n': v = '\n'; break;
            case 'r': v = '\r'; break;
            case 't': v = '\t'; break;
            case 'u': {
                if (!isxdigit((unsigned char)p[1]) || !isxdigit((unsigned char)p[2]) ||
                    !isxdigit((unsigned char)p[3]) || !isxdigit((unsigned char)p[4]))
                    return NULL;
                char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                unsigned code = (unsigned)strtoul(hex, NULL, 16);
                /* Свой писатель кодирует только исходный байт (0..0xff) в нижних двух шестнадцатеричных
                 * цифрах — старшая половина всегда 00. Значение вне этого — не наша строка, но не
                 * повод отказывать разбору целиком: кладём как есть, обрезав до байта. */
                if (o + 1 < outsz) out[o++] = (char)(code & 0xff);
                p += 5;
                continue;
            }
            default:
                return NULL;
            }
            if (o + 1 < outsz) out[o++] = v;
            p++;
        } else {
            if (o + 1 < outsz) out[o++] = (char)c;
            p++;
        }
    }
    if (*p != '"') return NULL;
    out[o < outsz ? o : outsz - 1] = 0;
    return p + 1;
}

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

void evline_free(struct evline *e) {
    for (int i = 0; i < e->n; i++) {
        free(e->f[i].key);
        if (e->f[i].type == EVLINE_STR) free(e->f[i].v.s);
    }
    free(e->f);
    free(e->ev);
    memset(e, 0, sizeof(*e));
}

/* Поле в конец разбора: key и s уходят в разбор (при отказе освобождаются здесь). */
static int add_field(struct evline *out, char *key, enum evline_type type, char *s, long i) {
    if (out->n == out->cap) {
        int nc = out->cap ? out->cap * 2 : 8;
        struct evline_field *nf = realloc(out->f, (size_t)nc * sizeof(*nf));
        if (!nf) { free(key); free(s); return -1; }
        out->f = nf;
        out->cap = nc;
    }
    struct evline_field *fl = &out->f[out->n++];
    fl->key = key;
    fl->type = type;
    if (type == EVLINE_STR) fl->v.s = s; else fl->v.i = i;
    return 0;
}

int evline_parse(const char *line, struct evline *out) {
    memset(out, 0, sizeof(*out));
    const char *p = skip_ws(line);
    if (*p != '{') return -1;
    p++;
    /* Строка, ключ и значение после разбора экранирования не длиннее самой строки. */
    size_t cap = strlen(p) + 1;
    char *tmp = malloc(cap);
    if (!tmp) return -1;
    int have_ev = 0;
    for (;;) {
        p = skip_ws(p);
        if (*p == '}') { p++; break; }
        const char *q = parse_jstr(p, tmp, cap);
        if (!q) goto bad;
        char *key = strdup(tmp);
        if (!key) goto bad;
        p = skip_ws(q);
        if (*p != ':') { free(key); goto bad; }
        p = skip_ws(p + 1);

        if (!strcmp(key, "ev")) {
            free(key);
            const char *r = parse_jstr(p, tmp, cap);
            if (!r) goto bad;
            free(out->ev);
            if (!(out->ev = strdup(tmp))) goto bad;
            have_ev = 1;
            p = r;
        } else if (*p == '"') {
            const char *r = parse_jstr(p, tmp, cap);
            char *val = r ? strdup(tmp) : NULL;
            if (!val) { free(key); goto bad; }
            p = r;
            if (add_field(out, key, EVLINE_STR, val, 0) != 0) goto bad;
        } else {
            char *end = NULL;
            errno = 0;
            long iv = strtol(p, &end, 10);
            if (end == p) { free(key); goto bad; }
            if (add_field(out, key, EVLINE_INT, NULL, iv) != 0) goto bad;
            p = end;
        }
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') { p++; break; }
        goto bad;
    }
    free(tmp);
    if (have_ev) return 0;
    evline_free(out);
    return -1;
bad:
    free(tmp);
    evline_free(out);
    return -1;
}

const char *evline_str(const struct evline *e, const char *key) {
    for (int i = 0; i < e->n; i++)
        if (e->f[i].type == EVLINE_STR && !strcmp(e->f[i].key, key)) return e->f[i].v.s;
    return NULL;
}

int evline_int(const struct evline *e, const char *key, long *out) {
    for (int i = 0; i < e->n; i++)
        if (e->f[i].type == EVLINE_INT && !strcmp(e->f[i].key, key)) { *out = e->f[i].v.i; return 1; }
    return 0;
}
