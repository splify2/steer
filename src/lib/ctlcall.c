/* Разговор с управляющим сокетом демона со стороны спрашивающего — устройство и доводы в
 * ctlcall.h. Код перенесён из клиента steer (src/client/main.c) без изменения поведения. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include "platform.h"
#include "ctlcall.h"

/* Ответ: stdout до 1 МиБ и stderr до 64 КиБ, а экранирование (\u00XX) раздувает до шести раз. */
#define RESP_MAX (8UL * 1024UL * 1024UL)

static const char *g_sock;

const char *ctlcall_socket(const char *path) {
    const char *e = getenv("STEER_SOCKET");
    g_sock = path && *path ? path : e && *e ? e : plat()->ctl_sock;
    return g_sock;
}

int ctlcall_open(int timeout_s) {
    if (!g_sock) ctlcall_socket(NULL);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(g_sock) >= sizeof(a.sun_path)) return -1;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", g_sock);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    struct timeval tv = { timeout_s, 0 };
    if (timeout_s > 0) setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return s;
}

static int write_all(int fd, const char *p, size_t n) {
    while (n) {
        /* send с MSG_NOSIGNAL, а не write: демон, закрывший сокет раньше, чем дочитал тело, —
         * отказ записи, после которого ответ всё равно читается (ctlcall_roundtrip, ниже), а не
         * SIGPIPE, убивающий вызвавшего молча. Из этого файла пишут и модули (xsteer-peers). */
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

char *ctlcall_roundtrip(const char *line, const char *body, size_t body_n, int timeout_s) {
    int s = ctlcall_open(timeout_s);
    if (s < 0) return NULL;
    /* Ошибка записи не повод молчать: сервер мог отказать (тело больше предела) и закрыть
     * соединение, не читая, — его ответ всё равно лежит в сокете. */
    if (write_all(s, line, strlen(line)) == 0 && body_n) write_all(s, body, body_n);
    size_t cap = 4096, n = 0;
    char *r = malloc(cap);
    if (!r) { close(s); return NULL; }
    for (;;) {
        if (n + 1 >= cap) {
            if (cap >= RESP_MAX) break;
            char *q = realloc(r, cap * 2);
            if (!q) break;
            r = q;
            cap *= 2;
        }
        ssize_t m = read(s, r + n, cap - n - 1);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        n += (size_t)m;
        if (memchr(r + n - (size_t)m, '\n', (size_t)m)) break;
    }
    close(s);
    r[n] = '\0';
    char *nl = strchr(r, '\n');
    if (!nl) { free(r); return NULL; }
    *nl = '\0';
    return r;
}

/* ---- ответ --------------------------------------------------------------------------------
 *
 * Разбор ровно того, что пишет сервер (src/daemon/ctl.c): объект верхнего уровня, строки с
 * экранированием cb_json (\" \\ \n \t \r и \u00XX для управляющих байтов; байты от 0x80 идут
 * как есть), целые, true/false, вложенные объекты и массивы (reload, changed) — пропускаются. */

static const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Строка JSON с s на открывающей кавычке. dst NULL — только пропустить. NULL — не строка. */
static const char *json_str(const char *s, struct ctlcall_str *dst) {
    if (*s != '"') return NULL;
    s++;
    size_t cap = 64, n = 0;
    char *b = dst ? malloc(cap) : NULL;
    if (dst && !b) return NULL;
    while (*s && *s != '"') {
        unsigned cp;
        int esc_u = 0;
        if (*s == '\\') {
            s++;
            switch (*s) {
            case 'n': cp = '\n'; break;
            case 't': cp = '\t'; break;
            case 'r': cp = '\r'; break;
            case 'b': cp = '\b'; break;
            case 'f': cp = '\f'; break;
            case 'u': {
                int h[4];
                for (int k = 0; k < 4; k++)
                    if ((h[k] = hexv(s[1 + k])) < 0) { free(b); return NULL; }
                cp = (unsigned)(h[0] << 12 | h[1] << 8 | h[2] << 4 | h[3]);
                esc_u = 1;
                s += 4;
                break;
            }
            case '\0': free(b); return NULL;
            default: cp = (unsigned char)*s; break;
            }
            s++;
        } else {
            cp = (unsigned char)*s++;
        }
        if (!dst) continue;
        unsigned char enc[4];
        size_t k = 0;
        /* Байт как есть — и сырой байт строки (UTF-8 сервер не экранирует), и \u00XX ниже 0x80
         * (так сервер пишет управляющие байты). Выше 0x7f через \u сервер не пишет; если
         * придёт — кодируется в UTF-8 честно. */
        if (!esc_u || cp < 0x80) enc[k++] = (unsigned char)cp;
        else if (cp < 0x800) {
            enc[k++] = (unsigned char)(0xC0 | cp >> 6);
            enc[k++] = (unsigned char)(0x80 | (cp & 0x3F));
        } else {
            enc[k++] = (unsigned char)(0xE0 | cp >> 12);
            enc[k++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
            enc[k++] = (unsigned char)(0x80 | (cp & 0x3F));
        }
        if (n + k + 1 > cap) {
            while (n + k + 1 > cap) cap *= 2;
            char *q = realloc(b, cap);
            if (!q) { free(b); return NULL; }
            b = q;
        }
        memcpy(b + n, enc, k);
        n += k;
    }
    if (*s != '"') { free(b); return NULL; }
    if (dst) {
        b[n] = '\0';
        dst->p = b;
        dst->n = n;
    }
    return s + 1;
}

/* Пропустить значение любого вида. */
static const char *json_skip(const char *s) {
    s = skip_ws(s);
    if (*s == '"') return json_str(s, NULL);
    if (*s == '{' || *s == '[') {
        int depth = 0;
        while (*s) {
            if (*s == '"') { s = json_str(s, NULL); if (!s) return NULL; continue; }
            if (*s == '{' || *s == '[') depth++;
            else if (*s == '}' || *s == ']') { if (--depth == 0) return s + 1; }
            s++;
        }
        return NULL;
    }
    while (*s && *s != ',' && *s != '}') s++;
    return s;
}

int ctlcall_parse(const char *s, struct ctlcall_resp *r) {
    memset(r, 0, sizeof(*r));
    r->enabled = r->applied = -1;
    s = skip_ws(s);
    if (*s++ != '{') return -1;
    for (;;) {
        s = skip_ws(s);
        if (*s == '}') return 0;
        struct ctlcall_str key = {0};
        if (!(s = json_str(s, &key))) return -1;
        s = skip_ws(s);
        if (*s++ != ':') { free(key.p); return -1; }
        s = skip_ws(s);
        struct ctlcall_str *dst = NULL;
        if (!strcmp(key.p, "stdout")) dst = &r->out;
        else if (!strcmp(key.p, "stderr")) dst = &r->err;
        else if (!strcmp(key.p, "error")) dst = &r->error;
        else if (!strcmp(key.p, "message")) dst = &r->message;
        else if (!strcmp(key.p, "spec_path")) dst = &r->spec_path;
        else if (!strcmp(key.p, "state_dir")) dst = &r->state_dir;
        else if (!strcmp(key.p, "ecode")) dst = &r->ecode;
        if (dst && *s == '"') {
            free(dst->p);
            s = json_str(s, dst);
        } else if (!strcmp(key.p, "args") && *s == '{') {
            const char *end = json_skip(s);
            if (end) {
                free(r->args.p);
                r->args.p = strndup(s, (size_t)(end - s));
                r->args.n = (size_t)(end - s);
            }
            s = end;
        } else if (!strcmp(key.p, "code")) {
            char *e = NULL;
            long v = strtol(s, &e, 10);
            if (e == s) { free(key.p); return -1; }
            r->has_code = 1;
            r->code = (int)v;
            s = e;
        } else {
            int *flag = !strcmp(key.p, "truncated") ? &r->truncated :
                        !strcmp(key.p, "enabled") ? &r->enabled :
                        !strcmp(key.p, "applied") ? &r->applied : NULL;
            if (flag && !strncmp(s, "true", 4)) *flag = 1;
            else if (flag && !strncmp(s, "false", 5)) *flag = 0;
            s = json_skip(s);
        }
        free(key.p);
        if (!s) return -1;
        s = skip_ws(s);
        if (*s == ',') { s++; continue; }
        if (*s == '}') return 0;
        return -1;
    }
}

void ctlcall_resp_free(struct ctlcall_resp *r) {
    free(r->out.p); free(r->err.p); free(r->error.p); free(r->message.p);
    free(r->spec_path.p); free(r->state_dir.p); free(r->ecode.p); free(r->args.p);
    memset(r, 0, sizeof(*r));
}

/* Путь для сверки: realpath, если файл есть, иначе как написан. */
static void canon(const char *p, char *buf, size_t n) {
    char rp[PATH_MAX];
    snprintf(buf, n, "%s", realpath(p, rp) ? rp : p);
}

int ctlcall_same_daemon(const char *spec, const char *state_dir, int timeout_s) {
    char *raw = ctlcall_roundtrip("version\n", NULL, 0, timeout_s);
    if (!raw) return 0;
    struct ctlcall_resp r;
    int ok = ctlcall_parse(raw, &r) == 0 && r.spec_path.p && r.state_dir.p;
    free(raw);
    if (ok) {
        char a[PATH_MAX + 1], b[PATH_MAX + 1];
        /* Пара по умолчанию — тот файл, что лежит (plat_spec_resolve): init-скрипт зовёт
         * `reload --spec /etc/steer/spec.json` и при spec.yaml, а демон отвечает лежащим. */
        canon(plat_spec_resolve(spec), a, sizeof(a));
        canon(r.spec_path.p, b, sizeof(b));
        ok = !strcmp(a, b);
        canon(state_dir ? state_dir : plat()->state_dir, a, sizeof(a));
        canon(r.state_dir.p, b, sizeof(b));
        ok = ok && !strcmp(a, b);
    }
    ctlcall_resp_free(&r);
    return ok;
}

int ctlcall_forward(const char *line, const char *spec, const char *state_dir, int timeout_s) {
    if (!ctlcall_same_daemon(spec, state_dir, timeout_s)) return -1;
    char *raw = ctlcall_roundtrip(line, NULL, 0, timeout_s);
    if (!raw) return -1;
    struct ctlcall_resp r;
    int ok = ctlcall_parse(raw, &r) == 0 && r.has_code && !r.truncated && !r.error.p;
    free(raw);
    if (!ok) { ctlcall_resp_free(&r); return -1; }
    if (r.err.n) fwrite(r.err.p, 1, r.err.n, stderr);
    if (r.out.n) fwrite(r.out.p, 1, r.out.n, stdout);
    fflush(stdout);
    int code = r.code;
    ctlcall_resp_free(&r);
    return code;
}
