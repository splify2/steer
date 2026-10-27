/* Менеджер плагинов: пути, файлы, JSON, время, место, блокировка (pm.h). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "pm.h"
#include "err.h"
#include "jsonw.h"

int pm_errf(struct pm_err *e, const char *fmt, ...) {
    if (!e) return -1;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
    va_end(ap);
    return -1;
}

void *pm_alloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    if (!p) { fputs("steer plugin: нет памяти\n", stderr); exit(1); }
    return p;
}

void *pm_realloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("steer plugin: нет памяти\n", stderr); exit(1); }
    return q;
}

char *pm_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = pm_alloc(n + 1);
    memcpy(p, s, n);
    return p;
}

char *pm_fmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *p = NULL;
    int r = vasprintf(&p, fmt, ap);
    va_end(ap);
    if (r < 0 || !p) { fputs("steer plugin: нет памяти\n", stderr); exit(1); }
    return p;
}

char *pm_path(const char *a, const char *b) {
    size_t la = strlen(a);
    return pm_fmt("%s%s%s", a, la && a[la - 1] == '/' ? "" : "/", b);
}

static const char *envor(const char *name, const char *dflt) {
    const char *v = getenv(name);
    return v && *v ? v : dflt;
}

const char *pm_root(void)  { return envor("STEER_PLUGIN_DIR", "/usr/lib/steer/plugins"); }
const char *pm_etc(void)   { return envor("STEER_PLUGIN_ETC", "/etc/steer/plugins"); }
const char *pm_keys(void)  { return envor("STEER_PLUGIN_KEYS", "/usr/share/steer/keys"); }
const char *pm_seed(void)  { return envor("STEER_PLUGIN_SEED", "/usr/share/steer/seed"); }
const char *pm_run(void)   { return envor("STEER_PLUGIN_RUN", "/var/run/steer/plugins"); }
const char *pm_tmp(void)   { return envor("STEER_PLUGIN_TMP", "/tmp/steer-plugins"); }
const char *pm_keepd(void) { return envor("STEER_PLUGIN_KEEPD", "/lib/upgrade/keep.d/steer-plugins"); }
const char *pm_sysroot(void) { const char *v = getenv("STEER_PLUGIN_SYSROOT"); return v ? v : ""; }

/* ---- файлы ---- */

char *pm_read(const char *path, size_t *n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 4096, got = 0;
    char *b = pm_alloc(cap);
    for (;;) {
        if (got + 1 >= cap) { cap *= 2; b = pm_realloc(b, cap); }
        ssize_t m = read(fd, b + got, cap - got - 1);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0) { close(fd); free(b); return NULL; }
        if (m == 0) break;
        got += (size_t)m;
    }
    close(fd);
    b[got] = '\0';
    if (n) *n = got;
    return b;
}

int pm_mkdirs(const char *path) {
    char *p = pm_strdup(path);
    for (char *s = p + 1; *s; s++) {
        if (*s != '/') continue;
        *s = '\0';
        if (mkdir(p, 0755) != 0 && errno != EEXIST) { free(p); return -1; }
        *s = '/';
    }
    int r = mkdir(p, 0755);
    free(p);
    return r == 0 || errno == EEXIST ? 0 : -1;
}

static void fsync_dir_of(const char *path) {
    char *d = pm_strdup(path);
    char *sl = strrchr(d, '/');
    if (sl) {
        if (sl == d) sl[1] = '\0'; else *sl = '\0';
        int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) { fsync(fd); close(fd); }
    }
    free(d);
}

int pm_write_atomic(const char *path, const void *d, size_t n, unsigned mode) {
    char *dir = pm_strdup(path);
    char *sl = strrchr(dir, '/');
    if (sl && sl != dir) { *sl = '\0'; pm_mkdirs(dir); }
    free(dir);
    char *tmp = pm_fmt("%s.tmp.%d", path, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) { free(tmp); return -1; }
    const char *p = d;
    size_t left = n;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { close(fd); unlink(tmp); free(tmp); return -1; }
        p += w;
        left -= (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        free(tmp);
        return -1;
    }
    free(tmp);
    fsync_dir_of(path);
    return 0;
}

int pm_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

int pm_is_dir(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int rmrf_at(int dfd, const char *name) {
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode)) return unlinkat(dfd, name, 0);
    int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    DIR *d = fdopendir(fd);
    if (!d) { close(fd); return -1; }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (rmrf_at(dirfd(d), de->d_name) != 0) rc = -1;
    }
    closedir(d);
    if (unlinkat(dfd, name, AT_REMOVEDIR) != 0) rc = -1;
    return rc;
}

int pm_rmrf(const char *path) {
    return rmrf_at(AT_FDCWD, path);
}

static unsigned long long du_at(int dfd, const char *name) {
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return S_ISREG(st.st_mode) ? (unsigned long long)st.st_size : 0;
    int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    DIR *d = fdopendir(fd);
    if (!d) { close(fd); return 0; }
    unsigned long long sum = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        sum += du_at(dirfd(d), de->d_name);
    }
    closedir(d);
    return sum;
}

unsigned long long pm_du(const char *path) {
    return du_at(AT_FDCWD, path);
}

unsigned long long pm_free(const char *path, int is_tmp) {
    /* Стенд подменяет statvfs числом: «корень[:tmp]». */
    const char *ov = getenv("STEER_PLUGIN_FREE");
    if (ov && *ov) {
        const char *colon = strchr(ov, ':');
        if (!is_tmp) return strtoull(ov, NULL, 10);
        if (colon) return strtoull(colon + 1, NULL, 10);
    }
    char *p = pm_strdup(path);
    struct statvfs v;
    /* Каталога может ещё не быть: спросить ближайший существующий родитель. */
    while (statvfs(p, &v) != 0) {
        char *sl = strrchr(p, '/');
        if (!sl || sl == p) { strcpy(p, "/"); if (statvfs(p, &v) != 0) { free(p); return 0; } break; }
        *sl = '\0';
    }
    free(p);
    return (unsigned long long)v.f_bavail * (unsigned long long)v.f_frsize;
}

void pm_human(unsigned long long b, char *out, size_t n) {
    if (b >= 1024ull * 1024ull) {
        unsigned long long t = (b * 10 + 512 * 1024) / (1024 * 1024);   /* десятые МБ */
        snprintf(out, n, "%llu,%llu МБ", t / 10, t % 10);
    } else {
        snprintf(out, n, "%llu КБ", (b + 1023) / 1024);
    }
}

static int g_lock_fd = -1;

int pm_lock(void) {
    if (g_lock_fd >= 0) return 0;
    pm_mkdirs(pm_root());
    char *p = pm_path(pm_root(), ".lock");
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    free(p);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return -1; }
    g_lock_fd = fd;
    return 0;
}

void pm_unlock(void) {
    if (g_lock_fd >= 0) { close(g_lock_fd); g_lock_fd = -1; }
}

/* ---- время ---- */

time_t pm_parse_time(const char *s) {
    if (!s) return -1;
    int Y, M, D, h, m, sec;
    char z = 0;
    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%c", &Y, &M, &D, &h, &m, &sec, &z) < 6) return -1;
    struct tm tm = {0};
    tm.tm_year = Y - 1900; tm.tm_mon = M - 1; tm.tm_mday = D;
    tm.tm_hour = h; tm.tm_min = m; tm.tm_sec = sec;
    return timegm(&tm);
}

void pm_time_str(time_t t, char *out, size_t n) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ---- JSON: чтение ---- */

struct ydoc *pm_json_parse(const char *buf, size_t n, const char *name, struct pm_err *e) {
    struct err ye = {{0}};
    struct ydoc *d = ydoc_parse_buf(buf, n, name, &ye);
    if (!d) { pm_errf(e, "%s", ye.msg[0] ? ye.msg : "JSON не разобрался"); return NULL; }
    if (!ydoc_root(d)) { ydoc_free(d); pm_errf(e, "%s: пустой документ", name); return NULL; }
    return d;
}

struct ydoc *pm_json_load(const char *path, struct pm_err *e) {
    size_t n = 0;
    char *b = pm_read(path, &n);
    if (!b) { if (e) e->msg[0] = '\0'; return NULL; }
    struct ydoc *d = pm_json_parse(b, n, path, e);
    free(b);
    return d;
}

int yn_is_str(const struct ynode *n) {
    return n && n->kind == YN_SCALAR && !(n->style == YS_PLAIN && ynode_is_null(n));
}

const char *yn_str(const struct ynode *map, const char *key) {
    const struct ynode *n = ynode_get(map, key);
    return yn_is_str(n) ? n->str : NULL;
}

int yn_bool(const struct ynode *map, const char *key, int dflt) {
    const struct ynode *n = ynode_get(map, key);
    int v;
    return n && ynode_bool(n, &v) == 0 ? v : dflt;
}

long yn_long(const struct ynode *map, const char *key, long dflt) {
    const struct ynode *n = ynode_get(map, key);
    long v;
    return n && ynode_long(n, &v) == 0 ? v : dflt;
}

int yn_equal(const struct ynode *a, const struct ynode *b) {
    if (!a || !b) {
        /* отсутствие поля равно null и пустому объекту */
        const struct ynode *x = a ? a : b;
        if (!x) return 1;
        if (x->kind == YN_SCALAR) return x->style == YS_PLAIN && ynode_is_null(x);
        return x->len == 0;
    }
    if (a->kind != b->kind) return 0;
    if (a->kind == YN_SCALAR) return a->len == b->len && !memcmp(a->str, b->str, a->len);
    if (a->len != b->len) return 0;
    if (a->kind == YN_SEQ) {
        for (size_t i = 0; i < a->len; i++)
            if (!yn_equal(a->items[i], b->items[i])) return 0;
        return 1;
    }
    for (size_t i = 0; i < a->len; i++) {
        const struct ynode *k = a->items[2 * i];
        const struct ynode *bv = ynode_get(b, k->str);
        if (!bv || !yn_equal(a->items[2 * i + 1], bv)) return 0;
    }
    return 1;
}

/* ---- JSON: запись ---- */

void jw_init(struct jw *w, FILE *f) { w->f = f; w->comma = 0; }
static void jw_sep(struct jw *w) { if (w->comma) fputc(',', w->f); }
void jw_obj(struct jw *w) { jw_sep(w); fputc('{', w->f); w->comma = 0; }
void jw_end(struct jw *w) { fputc('}', w->f); w->comma = 1; }
void jw_arr(struct jw *w) { jw_sep(w); fputc('[', w->f); w->comma = 0; }
void jw_aend(struct jw *w) { fputc(']', w->f); w->comma = 1; }
void jw_key(struct jw *w, const char *k) { jw_sep(w); jsonw_str(w->f, k); fputc(':', w->f); w->comma = 0; }
void jw_str(struct jw *w, const char *s) {
    jw_sep(w);
    if (s) jsonw_str(w->f, s); else fputs("null", w->f);
    w->comma = 1;
}
void jw_int(struct jw *w, long long v) { jw_sep(w); fprintf(w->f, "%lld", v); w->comma = 1; }
void jw_bool(struct jw *w, int v) { jw_sep(w); fputs(v ? "true" : "false", w->f); w->comma = 1; }
void jw_null(struct jw *w) { jw_sep(w); fputs("null", w->f); w->comma = 1; }

/* Скаляр без кавычек, похожий на число JSON. */
static int json_number(const char *s) {
    const char *p = s;
    if (*p == '-') p++;
    if (!(*p >= '0' && *p <= '9')) return 0;
    if (*p == '0' && p[1] >= '0' && p[1] <= '9') return 0;
    while (*p >= '0' && *p <= '9') p++;
    if (*p == '.') { p++; if (!(*p >= '0' && *p <= '9')) return 0; while (*p >= '0' && *p <= '9') p++; }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!(*p >= '0' && *p <= '9')) return 0;
        while (*p >= '0' && *p <= '9') p++;
    }
    return *p == '\0';
}

void jw_node(struct jw *w, const struct ynode *n) {
    if (!n) { jw_null(w); return; }
    if (n->kind == YN_MAP) {
        jw_obj(w);
        for (size_t i = 0; i < n->len; i++) {
            jw_key(w, n->items[2 * i]->str);
            jw_node(w, n->items[2 * i + 1]);
        }
        jw_end(w);
        return;
    }
    if (n->kind == YN_SEQ) {
        jw_arr(w);
        for (size_t i = 0; i < n->len; i++) jw_node(w, n->items[i]);
        jw_aend(w);
        return;
    }
    if (n->style == YS_PLAIN) {
        int b;
        if (ynode_is_null(n)) { jw_null(w); return; }
        if (ynode_bool(n, &b) == 0) { jw_bool(w, b); return; }
        if (json_number(n->str)) { jw_sep(w); fputs(n->str, w->f); w->comma = 1; return; }
    }
    jw_str(w, n->str);
}

void jw_kstr(struct jw *w, const char *k, const char *s) { jw_key(w, k); jw_str(w, s); }
void jw_kint(struct jw *w, const char *k, long long v) { jw_key(w, k); jw_int(w, v); }
void jw_kbool(struct jw *w, const char *k, int v) { jw_key(w, k); jw_bool(w, v); }
void jw_knode(struct jw *w, const char *k, const struct ynode *n) { jw_key(w, k); jw_node(w, n); }
