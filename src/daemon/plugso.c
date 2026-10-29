/* .so-плагины в процессе steerd: загрузчик, таблица host_v1, журнал виновного. Правила — plugso.h. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "plugso.h"
#include "daemon.h"
#include "gaiw.h"
#include "helpers.h"
#include "kind.h"
#include "loop.h"
#include "marks.h"
#include "platform.h"
#include "sockmark.h"
#include "spec.h"
#include "state.h"
#include "watchd.h"

const char *steer_engine_version(void);

/* HTTPS-клиент ядра (src/proto/tls/plughttp.c над httpc.c) есть не в каждой сборке: слабая ссылка без
 * заголовка — каталог TLS не слой демона (как urltls_start в urltest.c), нет — host->http отвечает отказом. */
extern int plugso_http_get(const char *method, const char *url, const char *headers, const void *body,
                           size_t body_n, uint32_t mark, uint32_t timeout_ms,
                           int (*sink)(void *, const void *, size_t), void *arg, int *status, char *why,
                           size_t wn) __attribute__((weak));

/* ---- хеш-таблица с цепочками: дескрипторы, таймеры, status ---------------------------------- */

struct hent { struct hent *next; unsigned long key; };
struct htab { struct hent **b; size_t nb, n; };

static struct hent **ht_slot(const struct htab *t, unsigned long key) {
    return t->nb ? &t->b[key % t->nb] : NULL;
}
static struct hent *ht_first(const struct htab *t, unsigned long key) {
    struct hent **s = ht_slot(t, key);
    return s ? *s : NULL;
}
static struct hent *ht_find(const struct htab *t, unsigned long key) {
    for (struct hent *e = ht_first(t, key); e; e = e->next)
        if (e->key == key) return e;
    return NULL;
}
static int ht_add(struct htab *t, struct hent *e) {
    if (t->n >= t->nb) {
        size_t nb = t->nb ? t->nb * 2 : 16;
        struct hent **b = calloc(nb, sizeof(*b));
        if (!b) return -1;
        for (size_t i = 0; i < t->nb; i++)
            for (struct hent *x = t->b[i], *nx; x; x = nx) {
                nx = x->next;
                x->next = b[x->key % nb];
                b[x->key % nb] = x;
            }
        free(t->b);
        t->b = b;
        t->nb = nb;
    }
    struct hent **s = ht_slot(t, e->key);
    e->next = *s;
    *s = e;
    t->n++;
    return 0;
}
static void ht_del(struct htab *t, struct hent *e) {
    struct hent **s = ht_slot(t, e->key);
    for (struct hent **pp = s; pp && *pp; pp = &(*pp)->next)
        if (*pp == e) { *pp = e->next; t->n--; return; }
}
static unsigned long str_hash(const char *s) {
    unsigned long h = 1469598103934665603UL;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211UL;
    return h;
}

/* ---- запись плагина ----------------------------------------------------------------------- */

struct plugso {
    struct plugso *next;                 /* список только растёт: по нему идёт обработчик сигнала */
    char *id, *version, *dir, *so, *path;
    enum plugso_state state;
    char *why;
    void *dl;
    const struct steer_plugin_v1 *pl;
    uintptr_t lo, hi;                    /* адреса, занятые .so: чей код упал */
    int crashes;
    struct steer_host_v1 host;           /* своя копия таблицы: каталоги у каждого плагина свои */
    char *conf_dir, *state_dir;
    struct htab fds, timers, stat;
    int next_tid;
};

static struct plugso *g_head, *g_tail;
static size_t g_n;
static struct steerd *g_d;
static const struct plugso_model_ops *g_model;
static struct steerd_sub g_sub;
static int g_sub_on;

static const char *base_of(const char *p) {
    const char *b = strrchr(p, '/');
    return b ? b + 1 : p;
}

static void set_why(struct plugso *p, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_why(struct plugso *p, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    free(p->why);
    p->why = strdup(buf);
}

static void say(char *why, size_t n, const struct plugso *p) {
    if (why && n) snprintf(why, n, "%s", p->why ? p->why : "");
}

/* ---- сторож вызовов и журнал виновного ---------------------------------------------------- */

static struct plugso *volatile g_cur_p;
static const char *volatile g_cur_fn;
static volatile long g_cur_t;
static volatile unsigned g_seq;
static volatile int g_wd_fired;
static int g_crash_fd = -1;
static int g_armed;

static long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void plugso_enter(struct plugso_guard *saved, struct plugso *p, const char *fn) {
    saved->p = g_cur_p;
    saved->fn = g_cur_fn;
    saved->t = g_cur_t;
    __atomic_add_fetch(&g_seq, 1, __ATOMIC_SEQ_CST);
    g_cur_p = p;
    g_cur_fn = fn;
    g_cur_t = mono_ms();
    __atomic_add_fetch(&g_seq, 1, __ATOMIC_SEQ_CST);
}

void plugso_leave(const struct plugso_guard *saved) {
    __atomic_add_fetch(&g_seq, 1, __ATOMIC_SEQ_CST);
    g_cur_p = saved->p;
    g_cur_fn = saved->fn;
    g_cur_t = saved->t;
    __atomic_add_fetch(&g_seq, 1, __ATOMIC_SEQ_CST);
}

/* Дальше — только то, что можно из обработчика сигнала: write, time, чтение переменных. */
static char *put_s(char *w, char *end, const char *s) {
    for (; s && *s && w < end; s++) *w++ = (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') ? '_' : *s;
    return w;
}
static char *put_raw(char *w, char *end, const char *s) {
    for (; *s && w < end; s++) *w++ = *s;
    return w;
}
static char *put_u(char *w, char *end, unsigned long v) {
    char t[24];
    int n = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v && n < (int)sizeof t);
    while (n && w < end) *w++ = t[--n];
    return w;
}

static void crash_record(const struct plugso *p, const char *fn, const char *sig, const char *where) {
    char buf[512], *w = buf, *end = buf + sizeof buf - 2;
    w = put_s(w, end, p->id);
    if (w < end) *w++ = ' ';
    w = put_s(w, end, fn ? fn : "-");
    if (w < end) *w++ = ' ';
    w = put_s(w, end, sig);
    if (w < end) *w++ = ' ';
    w = put_u(w, end, (unsigned long)time(NULL));
    if (w < end) *w++ = ' ';
    w = put_s(w, end, where);
    *w++ = '\n';
    if (g_crash_fd >= 0) {
        ssize_t r = write(g_crash_fd, buf, (size_t)(w - buf));
        (void)r;
    }
    /* Человеку — в журнал демона (stderr). */
    char msg[640], *m = msg, *me = msg + sizeof msg - 2;
    m = put_raw(m, me, "steer[err] plugin: ");
    m = put_s(m, me, p->id);
    m = put_raw(m, me, " упал: ");
    m = put_s(m, me, fn ? fn : "-");
    if (m < me) *m++ = ' ';
    m = put_s(m, me, sig);
    *m++ = '\n';
    ssize_t r = write(2, msg, (size_t)(m - msg));
    (void)r;
}

static uintptr_t pc_of(const void *uc) {
    const ucontext_t *u = uc;
    if (!u) return 0;
#if defined(__x86_64__) && defined(REG_RIP)
    return (uintptr_t)u->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__) && defined(REG_EIP)
    return (uintptr_t)u->uc_mcontext.gregs[REG_EIP];
#elif defined(__aarch64__)
    return (uintptr_t)u->uc_mcontext.pc;
#elif defined(__arm__)
    return (uintptr_t)u->uc_mcontext.arm_pc;
#elif defined(__mips__)
    return (uintptr_t)u->uc_mcontext.pc;
#else
    return 0;
#endif
}

static struct plugso *by_pc(uintptr_t pc) {
    for (struct plugso *p = __atomic_load_n(&g_head, __ATOMIC_ACQUIRE); p; p = __atomic_load_n(&p->next, __ATOMIC_ACQUIRE))
        if (p->hi && pc >= p->lo && pc < p->hi) return p;
    return NULL;
}

static const char *sig_name(int sig) {
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL";
    case SIGFPE: return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    default: return "SIG";
    }
}

/* Виновный: плагин, чей вызов идёт (сторож), а если вызова нет — плагин, в чьём коде стоял счётчик
 * команд. «where»: so — команда в .so, host — в ядре или libc по вызову плагина, ? — адрес не
 * известен. Запись дописывается и при падении ядра внутри вызова плагина: человеку полезнее лишний
 * подозреваемый, а отключение — по трём падениям за десять минут. */
static void crash_sig(int sig, siginfo_t *si, void *uc) {
    if (!g_wd_fired) {
        struct plugso *p = g_cur_p;
        const char *fn = g_cur_fn;
        uintptr_t pc = pc_of(uc);
        struct plugso *q = pc ? by_pc(pc) : NULL;
        const char *where = pc ? (q ? "so" : "host") : "?";
        if (!p && q) { p = q; fn = "-"; }
        if (p) crash_record(p, fn, sig_name(sig), where);
    }
    /* SA_RESETHAND вернул действие по умолчанию. Падение по адресу повторится при возврате и
     * убьёт процесс с дампом; пришедшее из kill/raise — повторяем сами. */
    if (sig == SIGABRT || (si && si->si_code <= 0)) raise(sig);
}

static void *watchdog(void *arg) {
    (void)arg;
    for (;;) {
        struct timespec ts = { 1, 0 };
        nanosleep(&ts, NULL);
        unsigned s1 = __atomic_load_n(&g_seq, __ATOMIC_SEQ_CST);
        if (s1 & 1) continue;
        struct plugso *p = g_cur_p;
        const char *fn = g_cur_fn;
        long t = g_cur_t;
        if (__atomic_load_n(&g_seq, __ATOMIC_SEQ_CST) != s1 || !p) continue;
        if (mono_ms() - t <= PLUGSO_CALL_LIMIT_MS) continue;
        g_wd_fired = 1;
        crash_record(p, fn, "WATCHDOG", "so");
        abort();
    }
}

static void arm_crash_machinery(const char *rootdir) {
    if (g_armed) return;
    char path[PATH_MAX + 16];
    snprintf(path, sizeof path, "%s/so.crash", rootdir);
    g_crash_fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    /* Свой стек для обработчика: переполнение стека плагином — тоже его падение. */
    stack_t ss;
    ss.ss_size = 64 * 1024;
    ss.ss_sp = malloc(ss.ss_size);
    ss.ss_flags = 0;
    if (ss.ss_sp) sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_sig;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &sa, NULL);
    pthread_t th;
    pthread_attr_t at;
    int ok = pthread_attr_init(&at) == 0;
    if (ok) pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, ok ? &at : NULL, watchdog, NULL) != 0)
        fprintf(stderr, "steer[warn] plugin: сторожевой поток не создан: %s — зависание плагина не будет замечено\n",
                strerror(errno));
    if (ok) pthread_attr_destroy(&at);
    g_armed = 1;
}

/* ---- счётчик падений: <state>/plugin/so.crash и отметка <id>.off ----------------------------- */

static void root_dir(char *buf, size_t n) {
    snprintf(buf, n, "%s/plugin", steer_state_dir());
}

static void mkdirs(const char *path) {
    char t[PATH_MAX];
    snprintf(t, sizeof t, "%s", path);
    for (char *s = t + 1; *s; s++)
        if (*s == '/') { *s = 0; mkdir(t, 0755); *s = '/'; }
    mkdir(t, 0755);
}

static char *slurp(const char *path, size_t *n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    char *b = malloc((size_t)st.st_size + 1);
    if (!b) { close(fd); return NULL; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, b + got, (size_t)st.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    b[got] = 0;
    if (n) *n = got;
    return b;
}

struct crash_info { int n; char fn[64], sig[16]; };

/* Записи плагина id за окно; stale — сколько записей (всех плагинов) старше окна. */
static void crash_scan(const char *rootdir, const char *id, struct crash_info *ci, int *stale) {
    char path[PATH_MAX + 16];
    snprintf(path, sizeof path, "%s/so.crash", rootdir);
    memset(ci, 0, sizeof *ci);
    *stale = 0;
    char *txt = slurp(path, NULL);
    if (!txt) return;
    time_t now = time(NULL);
    for (char *l = txt, *nx; *l; l = nx) {
        nx = strchr(l, '\n');
        if (nx) *nx++ = 0; else nx = l + strlen(l);
        char lid[128], fn[64], sg[16];
        long t;
        if (sscanf(l, "%127s %63s %15s %ld", lid, fn, sg, &t) != 4) continue;
        if (now - t > PLUGSO_CRASH_WINDOW_S) { (*stale)++; continue; }
        if (strcmp(lid, id) != 0) continue;
        ci->n++;
        snprintf(ci->fn, sizeof ci->fn, "%s", fn);
        snprintf(ci->sig, sizeof ci->sig, "%s", sg);
    }
    free(txt);
}

/* Переписать so.crash без записей старше окна и без записей плагина drop (NULL — ничьих). На месте,
 * тем же файлом: открытый демоном дескриптор с O_APPEND продолжает писать в его конец. */
static void crash_compact(const char *rootdir, const char *drop) {
    char path[PATH_MAX + 16];
    snprintf(path, sizeof path, "%s/so.crash", rootdir);
    char *txt = slurp(path, NULL);
    if (!txt) return;
    time_t now = time(NULL);
    size_t cap = strlen(txt) + 1, w = 0;
    char *keep = malloc(cap);
    if (!keep) { free(txt); return; }
    for (char *l = txt, *nx; *l; l = nx) {
        nx = strchr(l, '\n');
        size_t len = nx ? (size_t)(nx - l) : strlen(l);
        nx = nx ? nx + 1 : l + len;
        char line[512], lid[128], fn[64], sg[16];
        long t;
        if (len >= sizeof line) continue;
        memcpy(line, l, len);
        line[len] = 0;
        if (sscanf(line, "%127s %63s %15s %ld", lid, fn, sg, &t) != 4) continue;
        if (now - t > PLUGSO_CRASH_WINDOW_S) continue;
        if (drop && !strcmp(lid, drop)) continue;
        memcpy(keep + w, line, len);
        w += len;
        keep[w++] = '\n';
    }
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd >= 0) {
        size_t off = 0;
        while (off < w) {
            ssize_t r = write(fd, keep + off, w - off);
            if (r <= 0) break;
            off += (size_t)r;
        }
        close(fd);
    }
    free(keep);
    free(txt);
}

static void off_path(char *buf, size_t n, const char *rootdir, const char *id) {
    snprintf(buf, n, "%s/%s.off", rootdir, id);
}

/* ---- проверка ELF: плагин не связан с libsteer* ------------------------------------------- */

/* 0 — годится; -1 — отказ (why). Нечитаемое и не-ELF отдаём dlopen: у него отказ точнее. */
static int elf_check(const char *path, char *why, size_t wn) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { snprintf(why, wn, "%s: %s", base_of(path), strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(ElfW(Ehdr))) { close(fd); return 0; }
    size_t sz = (size_t)st.st_size;
    const unsigned char *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;
    int rc = 0;
    const ElfW(Ehdr) *eh = (const void *)m;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) goto out;
    if (eh->e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)) {
        snprintf(why, wn, "%s собран для %d-разрядной машины, ядро — %d-разрядное", base_of(path),
                 eh->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32, (int)sizeof(void *) * 8);
        rc = -1;
        goto out;
    }
    if (eh->e_phoff == 0 || eh->e_phentsize != sizeof(ElfW(Phdr)) ||
        eh->e_phoff + (size_t)eh->e_phnum * sizeof(ElfW(Phdr)) > sz) goto out;
    const ElfW(Phdr) *ph = (const void *)(m + eh->e_phoff);
    const ElfW(Phdr) *dyn = NULL;
    for (unsigned i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC) dyn = &ph[i];
    if (!dyn || dyn->p_offset + dyn->p_filesz > sz) goto out;
    const ElfW(Dyn) *d = (const void *)(m + dyn->p_offset);
    size_t nd = dyn->p_filesz / sizeof(*d);
    ElfW(Addr) strtab = 0;
    for (size_t i = 0; i < nd && d[i].d_tag != DT_NULL; i++)
        if (d[i].d_tag == DT_STRTAB) strtab = d[i].d_un.d_ptr;
    size_t stoff = 0;
    int have = 0;
    for (unsigned i = 0; i < eh->e_phnum && strtab; i++)
        if (ph[i].p_type == PT_LOAD && strtab >= ph[i].p_vaddr && strtab - ph[i].p_vaddr < ph[i].p_filesz) {
            stoff = (size_t)(strtab - ph[i].p_vaddr + ph[i].p_offset);
            have = 1;
            break;
        }
    if (!have || stoff >= sz) goto out;
    for (size_t i = 0; i < nd && d[i].d_tag != DT_NULL; i++) {
        if (d[i].d_tag != DT_NEEDED) continue;
        size_t o = stoff + (size_t)d[i].d_un.d_val;
        if (o >= sz) continue;
        const char *nm = (const char *)m + o;
        size_t room = sz - o;
        if (memchr(nm, 0, room) && !strncmp(base_of(nm), "libsteer", 8)) {
            snprintf(why, wn, "%s связан с %s: плагин не берёт символов ядра, всё приходит таблицей в init",
                     base_of(path), nm);
            rc = -1;
            break;
        }
    }
out:
    munmap((void *)m, sz);
    return rc;
}

/* ---- статическая сборка --------------------------------------------------------------------- */

static int is_static_exe(void) {
    unsigned long ph = getauxval(AT_PHDR), n = getauxval(AT_PHNUM), ent = getauxval(AT_PHENT);
    if (!ph || !n || !ent) return 0;
    for (unsigned long i = 0; i < n; i++)
        if (((const ElfW(Phdr) *)(ph + i * ent))->p_type == PT_INTERP) return 0;
    return 1;
}

int plugso_supported(char *why, size_t n) {
    if (!is_static_exe()) return 0;
    if (why && n) snprintf(why, n, "эта сборка steerd статическая: загрузить .so нечем (dlopen в ней нет)");
    return -1;
}

/* ---- таблица функций ядра ------------------------------------------------------------------- */

static struct plugso *P(struct steer_host *h) { return (struct plugso *)h; }

static const struct spec *cur_spec(void) {
    return g_d && g_d->have ? g_d->sp : NULL;
}

static void h_vlog(struct steer_host *h, int level, const char *fmt, va_list ap) {
    const char *lv = level <= STEER_LOG_ERR ? "error: " : level == STEER_LOG_WARN ? "warn: " :
                     level >= STEER_LOG_DEBUG ? "debug: " : "";
    char line[2048];
    int k = snprintf(line, sizeof line, "steer[%s] %s", P(h)->id, lv);
    if (k < 0 || (size_t)k >= sizeof line) return;
    vsnprintf(line + k, sizeof line - (size_t)k, fmt, ap);
    fprintf(stderr, "%s\n", line);
}
static void h_log(struct steer_host *h, int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    h_vlog(h, level, fmt, ap);
    va_end(ap);
}
static void *h_alloc(size_t n) { return malloc(n ? n : 1); }
static void h_free(void *p) { free(p); }

static const struct steer_out *h_out_by_name(struct steer_host *h, const struct steer_spec *sp, const char *name) {
    (void)h;
    return sp && name ? (const struct steer_out *)out_by_name((const struct spec *)sp, name) : NULL;
}
static size_t h_out_count(struct steer_host *h, const struct steer_spec *sp) {
    (void)h;
    return sp ? ((const struct spec *)sp)->out_n : 0;
}
static const struct steer_out *h_out_at(struct steer_host *h, const struct steer_spec *sp, size_t i) {
    (void)h;
    const struct spec *s = (const struct spec *)sp;
    return s && i < s->out_n ? (const struct steer_out *)&s->out[i] : NULL;
}
#define O(o) ((const struct output *)(o))
static const char *h_out_name(const struct steer_out *o) { return O(o)->name; }
static const char *h_out_kind(const struct steer_out *o) { return out_kind_name(O(o)); }
static const char *h_out_keys_json(const struct steer_out *o) {
    return g_model && g_model->out_keys_json ? g_model->out_keys_json(O(o)) : NULL;
}
static const char *h_out_conf_json(const struct steer_out *o) {
    return g_model && g_model->out_conf_json ? g_model->out_conf_json(O(o)) : NULL;
}
static const char *h_out_device(const struct steer_out *o) { return O(o)->device; }
static uint32_t h_out_mark(const struct steer_out *o) { return O(o)->mark; }
static int h_out_table(const struct steer_out *o) { return O(o)->table; }
static const char *h_out_owner(const struct steer_out *o) {
    return g_model && g_model->out_owner ? g_model->out_owner(O(o)) : NULL;
}

/* -- цикл: дескрипторы и таймеры -- */
struct pfd { struct hent h; struct plugso *p; int fd; steer_fd_cb *cb; void *arg; };
struct ptm { struct hent h; struct plugso *p; struct loop_timer *t; steer_timer_cb *cb; void *arg; };

static void fd_tramp(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l;
    struct pfd *w = arg;
    struct plugso_guard g;
    plugso_enter(&g, w->p, "fd");
    w->cb(w->arg, fd, ev & (STEER_FD_IN | STEER_FD_OUT | STEER_FD_ERR | STEER_FD_HUP));
    plugso_leave(&g);
}

static int h_watch_fd(struct steer_host *h, int fd, uint32_t events, steer_fd_cb *cb, void *arg) {
    struct plugso *p = P(h);
    if (!g_d || !g_d->loop || fd < 0 || !cb) return -1;
    uint32_t ev = events & (STEER_FD_IN | STEER_FD_OUT | STEER_FD_ERR | STEER_FD_HUP);
    struct pfd *w = (struct pfd *)ht_find(&p->fds, (unsigned long)fd);
    if (w) {
        w->cb = cb;
        w->arg = arg;
        return loop_fd_mod(g_d->loop, fd, ev);
    }
    w = calloc(1, sizeof *w);
    if (!w) return -1;
    w->h.key = (unsigned long)fd;
    w->p = p;
    w->fd = fd;
    w->cb = cb;
    w->arg = arg;
    if (ht_add(&p->fds, &w->h) != 0 || loop_fd_add(g_d->loop, fd, ev, fd_tramp, w) != 0) {
        if (ht_find(&p->fds, (unsigned long)fd) == &w->h) ht_del(&p->fds, &w->h);
        free(w);
        return -1;
    }
    return 0;
}
static void h_unwatch_fd(struct steer_host *h, int fd) {
    struct plugso *p = P(h);
    struct pfd *w = (struct pfd *)ht_find(&p->fds, (unsigned long)fd);
    if (!w) return;
    if (g_d && g_d->loop) loop_fd_del(g_d->loop, fd);
    ht_del(&p->fds, &w->h);
    free(w);
}

static void tm_tramp(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l;
    struct ptm *w = arg;
    struct plugso *p = w->p;
    steer_timer_cb *cb = w->cb;
    void *a = w->arg;
    ht_del(&p->timers, &w->h);
    loop_timer_free(t);
    free(w);
    struct plugso_guard g;
    plugso_enter(&g, p, "timer");
    cb(a);
    plugso_leave(&g);
}

static int h_timer(struct steer_host *h, uint32_t ms, steer_timer_cb *cb, void *arg) {
    struct plugso *p = P(h);
    if (!g_d || !g_d->loop || !cb) return -1;
    struct ptm *w = calloc(1, sizeof *w);
    if (!w) return -1;
    p->next_tid = p->next_tid >= INT_MAX ? 1 : p->next_tid + 1;
    w->h.key = (unsigned long)p->next_tid;
    w->p = p;
    w->cb = cb;
    w->arg = arg;
    w->t = loop_timer_new(g_d->loop, tm_tramp, w);
    if (!w->t || ht_add(&p->timers, &w->h) != 0) {
        if (w->t) loop_timer_free(w->t);
        free(w);
        return -1;
    }
    loop_timer_set(w->t, (long)ms);
    return (int)w->h.key;
}
static void h_timer_cancel(struct steer_host *h, int id) {
    struct plugso *p = P(h);
    struct ptm *w = id > 0 ? (struct ptm *)ht_find(&p->timers, (unsigned long)id) : NULL;
    if (!w) return;
    ht_del(&p->timers, &w->h);
    loop_timer_free(w->t);
    free(w);
}

/* -- сеть -- */

/* Метка сокета, чтобы его трафик шёл подложкой выхода out (или мимо каналов, out == NULL): то же
 * правило, что у туннелей (out_underlay_mark, awg_sock_mark). */
static uint32_t underlay_mark_of(const char *via) {
    struct output t;
    memset(&t, 0, sizeof t);
    const struct spec *sp = cur_spec();
    if (!sp) return STEER_SELF_MARK;
    if (via && *via) snprintf(t.over, sizeof t.over, "%s", via);
    return out_underlay_mark(sp, &t);
}
static int h_sock_mark(struct steer_host *h, int fd, const struct steer_out *out) {
    (void)h;
    if (fd < 0) return -1;
    return steer_sock_mark(fd, underlay_mark_of(out ? O(out)->name : NULL));
}

struct pres {
    struct plugso *p;
    steer_resolve_cb *cb;
    void *arg;
    struct gaiw *g;
    struct loop_timer *t;
    struct kind_name nm;
};
static void pres_done(struct pres *r, const struct kind_name *nm) {
    struct plugso_guard g;
    plugso_enter(&g, r->p, "resolve");
    if (nm->rc == 0) r->cb(r->arg, 0, &nm->addr, 1);
    else r->cb(r->arg, nm->rc, NULL, 0);
    plugso_leave(&g);
}
static void pres_gaiw(void *arg, const struct kind_name *names, size_t n) {
    struct pres *r = arg;
    if (n >= 1) pres_done(r, &names[0]);
    free(r);
}
static void pres_sync(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l;
    struct pres *r = arg;
    loop_timer_free(t);
    pres_done(r, &r->nm);
    free(r);
}
static int h_resolve(struct steer_host *h, const char *host, uint16_t port, int family,
                     steer_resolve_cb *cb, void *arg) {
    if (!g_d || !g_d->loop || !host || !cb || strlen(host) >= sizeof(((struct kind_name *)0)->host)) return -1;
    struct pres *r = calloc(1, sizeof *r);
    if (!r) return -1;
    r->p = P(h);
    r->cb = cb;
    r->arg = arg;
    snprintf(r->nm.host, sizeof r->nm.host, "%s", host);
    r->nm.port = port;
    r->nm.v4only = family == 2 /* AF_INET */;
    r->nm.v6only = family == 10 /* AF_INET6 */;
    r->g = gaiw_start(g_d->loop, &r->nm, 1, pres_gaiw, r);
    if (r->g) return 0;
    /* Поток не создался: имя разрешено тут же, ответ — со следующего оборота цикла, как и у потока. */
    r->t = loop_timer_new(g_d->loop, pres_sync, r);
    if (!r->t) { free(r); return -1; }
    loop_timer_set(r->t, 0);
    return 0;
}

/* HTTPS: клиент ядра блокирует, поэтому — в рабочем потоке, ответ на цикле через socketpair. */
struct phttp {
    struct plugso *p;
    steer_http_cb *cb;
    void *arg;
    int rd, wr;
    char *url, *method, *headers, *reqbody;
    size_t reqbody_n;
    uint32_t mark, timeout_ms;
    char *body;
    size_t body_n, body_cap;
    int status;
    char why[256];
};
static pthread_mutex_t g_http_mu = PTHREAD_MUTEX_INITIALIZER;

static int phttp_sink(void *arg, const void *data, size_t n) {
    struct phttp *w = arg;
    if (w->body_n + n + 1 > w->body_cap) {
        size_t nc = w->body_cap ? w->body_cap : 4096;
        while (nc < w->body_n + n + 1) nc *= 2;
        char *b = realloc(w->body, nc);
        if (!b) return -1;
        w->body = b;
        w->body_cap = nc;
    }
    memcpy(w->body + w->body_n, data, n);
    w->body_n += n;
    w->body[w->body_n] = 0;
    return 0;
}
static void *phttp_thread(void *arg) {
    struct phttp *w = arg;
    int fd = w->wr;
    pthread_mutex_lock(&g_http_mu);
    int rc = plugso_http_get(w->method, w->url, w->headers, w->reqbody, w->reqbody_n, w->mark, w->timeout_ms,
                             phttp_sink, w, &w->status, w->why, sizeof w->why);
    pthread_mutex_unlock(&g_http_mu);
    if (rc != 0) w->status = -1;
    if (rc != 0 && !w->why[0]) snprintf(w->why, sizeof w->why, "ошибка HTTPS (%d)", rc);
    char b = 1;
    ssize_t k = write(fd, &b, 1);
    (void)k;
    close(fd);
    return NULL;
}
static void phttp_free(struct phttp *w) {
    free(w->url); free(w->method); free(w->headers); free(w->reqbody); free(w->body);
    free(w);
}
static void phttp_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)ev;
    struct phttp *w = arg;
    char b;
    if (read(fd, &b, 1) < 0 && errno == EAGAIN) return;
    loop_fd_del(l, fd);
    close(fd);
    struct plugso_guard g;
    plugso_enter(&g, w->p, "http");
    w->cb(w->arg, w->status, w->body ? w->body : "", w->body_n, w->status < 0 ? w->why : NULL);
    plugso_leave(&g);
    phttp_free(w);
}
static int h_http(struct steer_host *h, const struct steer_http_req *rq, steer_http_cb *cb, void *arg) {
    if (!g_d || !g_d->loop || !rq || !cb || !rq->url || !STEER_HAS(rq, via_out)) return -1;
    if (!plugso_http_get) return -1;    /* HTTPS-клиента в этой сборке нет */
    struct phttp *w = calloc(1, sizeof *w);
    if (!w) return -1;
    w->p = P(h);
    w->cb = cb;
    w->arg = arg;
    w->rd = w->wr = -1;
    w->url = strdup(rq->url);
    w->method = strdup(rq->method ? rq->method : "GET");
    w->timeout_ms = rq->timeout_ms ? rq->timeout_ms : 30000;
    if (rq->body && rq->body_len) {
        w->reqbody = malloc(rq->body_len);
        if (!w->reqbody) goto bad;
        memcpy(w->reqbody, rq->body, rq->body_len);
        w->reqbody_n = rq->body_len;
    }
    if (rq->headers) {
        size_t n = 1;
        for (const char *const *hd = rq->headers; *hd; hd++) n += strlen(*hd) + 2;
        w->headers = malloc(n);
        if (!w->headers) goto bad;
        char *t = w->headers;
        *t = 0;
        for (const char *const *hd = rq->headers; *hd; hd++) t += sprintf(t, "%s\r\n", *hd);
    }
    if (!w->url || !w->method) goto bad;
    w->mark = rq->via_out ? underlay_mark_of(rq->via_out) : 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) goto bad;
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    w->rd = sv[0];
    w->wr = sv[1];
    if (loop_fd_add(g_d->loop, w->rd, EPOLLIN, phttp_ready, w) != 0) {
        close(sv[0]); close(sv[1]);
        goto bad;
    }
    pthread_t th;
    pthread_attr_t at;
    int ok = pthread_attr_init(&at) == 0;
    if (ok) pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&th, ok ? &at : NULL, phttp_thread, w);
    if (ok) pthread_attr_destroy(&at);
    if (rc != 0) {
        loop_fd_del(g_d->loop, w->rd);
        close(w->rd); close(w->wr);
        goto bad;
    }
    return 0;
bad:
    phttp_free(w);
    return -1;
}

/* -- nft, события, ресурсы, status, сторож -- */

static plugso_nft_sink *g_sink;
static void *g_sink_arg;
static struct plugso *g_sink_p;

static int h_nft_rule(struct steer_host *h, const char *slot, const char *rule) {
    if (!g_sink || g_sink_p != P(h) || !slot || !rule) return -1;   /* только из emit своего плагина */
    return g_sink(g_sink_arg, P(h)->id, slot, rule);
}

static int h_emit(struct steer_host *h, const char *ev, const char *fields_json) {
    (void)h;
    if (!g_d || !ev || !*ev) return -1;
    for (const char *s = ev; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_')) return -1;
    char *fields = NULL;
    if (fields_json) {
        const char *a = fields_json, *e = fields_json + strlen(fields_json);
        while (a < e && (*a == ' ' || *a == '\t')) a++;
        while (e > a && (e[-1] == ' ' || e[-1] == '\t')) e--;
        if (e - a < 2 || *a != '{' || e[-1] != '}') return -1;
        for (const char *s = a; s < e; s++)
            if (*s == '\n' || *s == '\r') return -1;
        size_t n = (size_t)(e - a) - 2;
        if (n) {
            fields = malloc(n + 2);
            if (!fields) return -1;
            fields[0] = ',';
            memcpy(fields + 1, a + 1, n);
            fields[n + 1] = 0;
        }
    }
    steerd_emit(g_d, ev, fields);
    free(fields);
    return 0;
}

static int h_resource(struct steer_host *h, const char *kind, unsigned i, uint32_t *out) {
    if (!g_model || !g_model->resource || !kind || !out) return -1;
    return g_model->resource(P(h)->id, kind, i, out);
}

struct pst { struct hent h; char name[sizeof(((struct output *)0)->name)]; char *json; };
static int h_set_status(struct steer_host *h, const struct steer_out *out, const char *json) {
    struct plugso *p = P(h);
    if (!out) return -1;
    const char *nm = O(out)->name;
    unsigned long k = str_hash(nm);
    struct pst *s = NULL;
    for (struct hent *e = ht_first(&p->stat, k); e; e = e->next)
        if (e->key == k && !strcmp(((struct pst *)e)->name, nm)) { s = (struct pst *)e; break; }
    if (!json) {
        if (s) { ht_del(&p->stat, &s->h); free(s->json); free(s); }
        return 0;
    }
    char *j = strdup(json);
    if (!j) return -1;
    if (!s) {
        s = calloc(1, sizeof *s);
        if (!s) { free(j); return -1; }
        s->h.key = k;
        snprintf(s->name, sizeof s->name, "%s", nm);
        if (ht_add(&p->stat, &s->h) != 0) { free(s); free(j); return -1; }
    }
    free(s->json);
    s->json = j;
    return 0;
}

static void h_wake_watch(struct steer_host *h) {
    (void)h;
    if (g_d && g_d->watch) watchd_preempt(g_d->watch);
}
static int h_member_verdict(struct steer_host *h, const struct steer_out *out, int ok) {
    if (!g_d || !g_d->sup || !out || ok < -1 || ok > 1) return -1;
    supd_member_set(g_d->sup, P(h)->id, O(out)->name, ok);
    return 0;
}

static void fill_host(struct plugso *p) {
    struct steer_host_v1 *t = &p->host;
    memset(t, 0, sizeof *t);
    t->size = sizeof *t;
    t->abi_major = STEER_ABI_MAJOR;
    t->abi_minor = STEER_ABI_MINOR;
    t->core_version = steer_engine_version();
    t->api_version = "1.0";
    t->log = h_log;
    t->vlog = h_vlog;
    t->alloc = h_alloc;
    t->free = h_free;
    t->out_by_name = h_out_by_name;
    t->out_count = h_out_count;
    t->out_at = h_out_at;
    t->out_name = h_out_name;
    t->out_kind = h_out_kind;
    t->out_keys_json = h_out_keys_json;
    t->out_conf_json = h_out_conf_json;
    t->out_device = h_out_device;
    t->out_mark = h_out_mark;
    t->out_table = h_out_table;
    t->out_owner = h_out_owner;
    t->watch_fd = h_watch_fd;
    t->unwatch_fd = h_unwatch_fd;
    t->timer = h_timer;
    t->timer_cancel = h_timer_cancel;
    t->sock_mark = h_sock_mark;
    t->resolve = h_resolve;
    t->http = h_http;
    t->nft_rule = h_nft_rule;
    t->emit = h_emit;
    t->resource = h_resource;
    t->set_status = h_set_status;
    t->wake_watch = h_wake_watch;
    t->member_verdict = h_member_verdict;
    t->plugin_dir = p->dir;
    t->conf_dir = p->conf_dir;
    t->state_dir = p->state_dir;
}

/* ---- реестр и загрузка --------------------------------------------------------------------- */

size_t plugso_n(void) { return g_n; }
struct plugso *plugso_at(size_t i) {
    struct plugso *p = g_head;
    for (; p && i; i--) p = p->next;
    return p;
}
struct plugso *plugso_find(const char *id) {
    for (struct plugso *p = g_head; p; p = p->next)
        if (!strcmp(p->id, id)) return p;
    return NULL;
}
const char *plugso_id(const struct plugso *p) { return p->id; }
const char *plugso_version(const struct plugso *p) { return p->version; }
const char *plugso_why(const struct plugso *p) { return p->why; }
enum plugso_state plugso_state(const struct plugso *p) { return p->state; }
const struct steer_plugin_v1 *plugso_desc(const struct plugso *p) {
    return p->state == PLUGSO_LOADED ? p->pl : NULL;
}
int plugso_crashes(const struct plugso *p) { return p->crashes; }
const struct steer_kind_v1 *plugso_kind_find(const struct plugso *p, const char *name) {
    if (p->state != PLUGSO_LOADED || !STEER_HAS(p->pl, kinds) || !p->pl->kinds) return NULL;
    for (const struct steer_kind_v1 *const *k = p->pl->kinds; *k; k++)
        if ((*k)->name && !strcmp((*k)->name, name)) return *k;
    return NULL;
}

void plugso_set_model(const struct plugso_model_ops *m) { g_model = m; }

static struct plugso *reg_new(const char *id) {
    struct plugso *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->id = strdup(id);
    if (!p->id) { free(p); return NULL; }
    if (g_tail) __atomic_store_n(&g_tail->next, p, __ATOMIC_RELEASE);
    else __atomic_store_n(&g_head, p, __ATOMIC_RELEASE);
    g_tail = p;
    g_n++;
    return p;
}

static int id_ok(const char *id) {
    if (!id || !*id || strlen(id) > 64) return 0;
    for (const char *s = id; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_')) return 0;
    return 1;
}
static int rel_ok(const char *s) {
    if (!s || !*s || s[0] == '/') return 0;
    for (const char *p = s; *p;) {
        const char *e = strchr(p, '/');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == 2 && p[0] == '.' && p[1] == '.') return 0;
        p += n + (e ? 1 : 0);
    }
    return 1;
}

struct range_arg { uintptr_t addr; uintptr_t lo, hi; int found; };
static int range_cb(struct dl_phdr_info *info, size_t sz, void *argp) {
    (void)sz;
    struct range_arg *a = argp;
    uintptr_t lo = (uintptr_t)-1, hi = 0;
    int hit = 0;
    for (unsigned i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t s = info->dlpi_addr + ph->p_vaddr, e = s + ph->p_memsz;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
        if (a->addr >= s && a->addr < e) hit = 1;
    }
    if (hit) { a->lo = lo; a->hi = hi; a->found = 1; return 1; }
    return 0;
}

static void fail(struct plugso *p, enum plugso_state st, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void fail(struct plugso *p, enum plugso_state st, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    p->state = st;
    set_why(p, "%s", buf);
}

static void ev_push(struct steerd_sub *s, const char *line, size_t n);

static void adopt_events(struct plugso *p) {
    if (!g_d || g_sub_on || !STEER_HAS(p->pl, on_event) || !p->pl->on_event) return;
    g_sub.push = ev_push;
    steerd_sub_add(g_d, &g_sub);
    g_sub_on = 1;
}

static void load_one(struct plugso *p) {
    char root[PATH_MAX], why[512];
    free(p->why);
    p->why = NULL;
    p->state = PLUGSO_FAILED;
    root_dir(root, sizeof root);

    if (plugso_supported(why, sizeof why) != 0) { fail(p, PLUGSO_FAILED, "%s", why); return; }

    /* Отключение по падениям: отметка человека/ядра или три записи в окне. */
    char off[PATH_MAX + 80];
    off_path(off, sizeof off, root, p->id);
    struct crash_info ci;
    int stale;
    crash_scan(root, p->id, &ci, &stale);
    p->crashes = ci.n;
    if (access(off, F_OK) == 0 || ci.n >= PLUGSO_CRASH_LIMIT) {
        char *prev = slurp(off, NULL);
        if (ci.n >= PLUGSO_CRASH_LIMIT && access(off, F_OK) != 0) {
            mkdirs(root);
            char msg[400];
            snprintf(msg, sizeof msg, "steerd падал в %s (%s, %s) — плагин отключён", base_of(p->so),
                     ci.fn, ci.sig);
            FILE *f = fopen(off, "w");
            if (f) { fputs(msg, f); fputc('\n', f); fclose(f); }
            fail(p, PLUGSO_OFF, "%s", msg);
        } else if (prev && *prev) {
            char *nl = strchr(prev, '\n');
            if (nl) *nl = 0;
            fail(p, PLUGSO_OFF, "%s", prev);
        } else fail(p, PLUGSO_OFF, "steerd падал в %s — плагин отключён", base_of(p->so));
        free(prev);
        return;
    }
    if (stale) crash_compact(root, NULL);

    struct stat st;
    if (stat(p->path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fail(p, PLUGSO_FAILED, "нет файла %s", p->path);
        return;
    }
    if (elf_check(p->path, why, sizeof why) != 0) { fail(p, PLUGSO_FAILED, "%s", why); return; }

    mkdirs(root);
    arm_crash_machinery(root);

    struct plugso_guard g;
    plugso_enter(&g, p, "dlopen");
    void *dl = dlopen(p->path, RTLD_NOW | RTLD_LOCAL);
    plugso_leave(&g);
    if (!dl) {
        const char *e = dlerror();
        fail(p, PLUGSO_FAILED, "%s не загрузился: %s", base_of(p->so), e ? e : "dlopen");
        return;
    }
    p->dl = dl;
    steer_plugin_v1_entry_fn *entry = (steer_plugin_v1_entry_fn *)dlsym(dl, STEER_PLUGIN_ENTRY);
    if (!entry) {
        fail(p, PLUGSO_FAILED, "в %s нет %s", base_of(p->so), STEER_PLUGIN_ENTRY);
        return;
    }
    struct range_arg ra = { (uintptr_t)entry, 0, 0, 0 };
    dl_iterate_phdr(range_cb, &ra);
    if (ra.found) { p->lo = ra.lo; p->hi = ra.hi; }

    const struct steer_plugin_v1 *pl;
    plugso_enter(&g, p, "entry");
    pl = entry(STEER_ABI_MAJOR, STEER_ABI_MINOR);
    plugso_leave(&g);
    if (!pl) {
        fail(p, PLUGSO_FAILED, "%s не принял steer-abi %d.%d ядра (%s вернул NULL)", base_of(p->so),
             STEER_ABI_MAJOR, STEER_ABI_MINOR, STEER_PLUGIN_ENTRY);
        return;
    }
    if (!STEER_HAS(pl, version) || pl->abi_major != STEER_ABI_MAJOR || pl->abi_minor > STEER_ABI_MINOR) {
        fail(p, PLUGSO_FAILED, "%s собран для steer-abi %u.%u, у ядра %d.%d", base_of(p->so),
             STEER_HAS(pl, abi_minor) ? pl->abi_major : 0, STEER_HAS(pl, abi_minor) ? pl->abi_minor : 0,
             STEER_ABI_MAJOR, STEER_ABI_MINOR);
        return;
    }
    if (pl->fingerprint != STEER_ABI_FINGERPRINT) {
        fail(p, PLUGSO_FAILED, "%s собран с другим отпечатком (разрядность, time_t, порядок байт): 0x%x, у ядра 0x%x",
             base_of(p->so), pl->fingerprint, (unsigned)STEER_ABI_FINGERPRINT);
        return;
    }
    if (!pl->id || strcmp(pl->id, p->id) != 0) {
        fail(p, PLUGSO_FAILED, "%s называет себя «%s», а в манифесте «%s»", base_of(p->so),
             pl->id ? pl->id : "", p->id);
        return;
    }
    if (p->version && (!pl->version || strcmp(pl->version, p->version) != 0)) {
        fail(p, PLUGSO_FAILED, "%s версии «%s», а в манифесте «%s»", base_of(p->so),
             pl->version ? pl->version : "", p->version);
        return;
    }
    p->pl = pl;
    fill_host(p);
    mkdirs(p->state_dir);
    if (STEER_HAS(pl, init) && pl->init) {
        why[0] = 0;
        plugso_enter(&g, p, "init");
        int rc = pl->init((struct steer_host *)p, &p->host, why, sizeof why);
        plugso_leave(&g);
        if (rc != 0) {
            p->pl = NULL;
            fail(p, PLUGSO_FAILED, "%s: %s", p->id, why[0] ? why : "init отказал");
            return;
        }
    }
    p->state = PLUGSO_LOADED;
    adopt_events(p);
}

int plugso_load(const char *id, const char *version, const char *dir, const char *so,
                struct plugso **out, char *why, size_t n) {
    if (out) *out = NULL;
    if (!id_ok(id) || !dir || !rel_ok(so)) {
        if (why && n) snprintf(why, n, "плагин .so: id, каталог или путь не годятся");
        return -1;
    }
    struct plugso *p = plugso_find(id);
    if (p && p->state == PLUGSO_LOADED) { if (out) *out = p; return 0; }
    if (!p) {
        p = reg_new(id);
        if (!p) { if (why && n) snprintf(why, n, "нет памяти"); return -1; }
        char etc[PATH_MAX], root[PATH_MAX];
        const char *e = getenv("STEER_PLUGINS_ETC");
        if (e && *e) snprintf(etc, sizeof etc, "%s", e);
        else snprintf(etc, sizeof etc, "%s/plugins", plat()->etc_dir);
        root_dir(root, sizeof root);
        char buf[PATH_MAX + 128];
        snprintf(buf, sizeof buf, "%s/conf/%s", etc, id);
        p->conf_dir = strdup(buf);
        snprintf(buf, sizeof buf, "%s/%s", root, id);
        p->state_dir = strdup(buf);
    }
    /* Адреса могли смениться (обновление плагина) — запись берёт новые. */
    free(p->version); free(p->dir); free(p->so); free(p->path);
    p->version = version ? strdup(version) : NULL;
    p->dir = strdup(dir);
    p->so = strdup(so);
    char path[PATH_MAX * 2];
    snprintf(path, sizeof path, "%s/%s", dir, so);
    p->path = strdup(path);
    if (!p->dir || !p->so || !p->path || !p->conf_dir || !p->state_dir) {
        if (why && n) snprintf(why, n, "нет памяти");
        return -1;
    }
    if (p->dl) {
        /* musl не выгружает библиотеки: ту, что уже в памяти и не годилась, заменить нельзя. */
        fail(p, PLUGSO_FAILED, "%s уже загружался и отказал; обновить его можно только перезапуском steerd",
             base_of(so));
    } else load_one(p);
    if (out) *out = p;
    if (p->state == PLUGSO_LOADED) return 0;
    say(why, n, p);
    return -1;
}

int plugso_enable(const char *id) {
    char root[PATH_MAX], off[PATH_MAX + 80];
    if (!id_ok(id)) return -1;
    root_dir(root, sizeof root);
    off_path(off, sizeof off, root, id);
    unlink(off);
    crash_compact(root, id);
    struct plugso *p = plugso_find(id);
    if (p && p->state == PLUGSO_OFF && p->dir && p->so) {
        p->crashes = 0;
        load_one(p);
    }
    return 0;
}

void plugso_fini_all(void) {
    for (struct plugso *p = g_head; p; p = p->next) {
        if (p->state != PLUGSO_LOADED || !STEER_HAS(p->pl, fini) || !p->pl->fini) continue;
        struct plugso_guard g;
        plugso_enter(&g, p, "fini");
        p->pl->fini((struct steer_host *)p);
        plugso_leave(&g);
    }
}

/* ---- вызовы плагина ---------------------------------------------------------------------------- */

#define HOST(p) ((struct steer_host *)(p))
#define SP(s) ((const struct steer_spec *)(s))
#define OU(o) ((const struct steer_out *)(o))

int plugso_call_check(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                      const struct output *o, char *why, size_t n) {
    if (!STEER_HAS(k, check) || !k->check) return 0;
    struct plugso_guard g;
    plugso_enter(&g, p, "check");
    int rc = k->check(HOST(p), SP(sp), OU(o), why, n);
    plugso_leave(&g);
    return rc;
}

void plugso_call_emit(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                      const struct output *o, plugso_nft_sink *sink, void *arg) {
    if (!STEER_HAS(k, emit) || !k->emit) return;
    struct plugso_guard g;
    g_sink = sink;
    g_sink_arg = arg;
    g_sink_p = p;
    plugso_enter(&g, p, "emit");
    k->emit(HOST(p), SP(sp), OU(o));
    plugso_leave(&g);
    g_sink = NULL;
    g_sink_arg = NULL;
    g_sink_p = NULL;
}

int plugso_call_health(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                       const struct output *o, const char *dev) {
    if (!STEER_HAS(k, health) || !k->health) return -1;
    struct plugso_guard g;
    plugso_enter(&g, p, "health");
    int rc = k->health(HOST(p), SP(sp), OU(o), dev);
    plugso_leave(&g);
    return rc;
}

int plugso_call_revive(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                       const struct output *o, const char *dev) {
    if (!STEER_HAS(k, revive) || !k->revive) return -1;
    struct plugso_guard g;
    plugso_enter(&g, p, "revive");
    int rc = k->revive(HOST(p), SP(sp), OU(o), dev);
    plugso_leave(&g);
    return rc;
}

int plugso_call_apply_all(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                          char *why, size_t n) {
    if (!STEER_HAS(k, apply_all) || !k->apply_all) return 0;
    struct plugso_guard g;
    plugso_enter(&g, p, "apply_all");
    int rc = k->apply_all(HOST(p), SP(sp), why, n);
    plugso_leave(&g);
    return rc;
}

int plugso_call_down_all(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp) {
    if (!STEER_HAS(k, down_all) || !k->down_all) return 0;
    struct plugso_guard g;
    plugso_enter(&g, p, "down_all");
    int rc = k->down_all(HOST(p), SP(sp));
    plugso_leave(&g);
    return rc;
}

char *plugso_call_status(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                         const struct output *o) {
    if (!STEER_HAS(k, status) || !k->status) return NULL;
    struct plugso_guard g;
    plugso_enter(&g, p, "status");
    char *r = k->status(HOST(p), SP(sp), OU(o));
    plugso_leave(&g);
    return r;
}

int plugso_call_expand(struct plugso *p, const struct steer_kind_v1 *k, const char *out_json,
                       char **frag_json, char *why, size_t n) {
    if (!STEER_HAS(k, expand) || !k->expand) return -1;
    struct plugso_guard g;
    plugso_enter(&g, p, "expand");
    int rc = k->expand(HOST(p), out_json, frag_json, why, n);
    plugso_leave(&g);
    return rc;
}

int plugso_call_pre_apply(struct plugso *p, const char *spec_json, char **out_json, char *why, size_t n) {
    if (p->state != PLUGSO_LOADED || !STEER_HAS(p->pl, pre_apply) || !p->pl->pre_apply) return -1;
    struct plugso_guard g;
    plugso_enter(&g, p, "pre_apply");
    int rc = p->pl->pre_apply(HOST(p), spec_json, out_json, why, n);
    plugso_leave(&g);
    return rc;
}

int plugso_call_ctl(struct plugso *p, const char *cmd, const char *const *argv, size_t argc,
                    const char *body, size_t body_len, char **resp_json) {
    if (p->state != PLUGSO_LOADED || !STEER_HAS(p->pl, ctl) || !p->pl->ctl) return -1;
    struct plugso_guard g;
    plugso_enter(&g, p, "ctl");
    int rc = p->pl->ctl(HOST(p), cmd, argv, argc, body, body_len, resp_json);
    plugso_leave(&g);
    return rc;
}

/* ---- демон ---------------------------------------------------------------------------------------- */

static void ev_push(struct steerd_sub *s, const char *line, size_t n) {
    (void)s;
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
    char *ev = malloc(n + 1);
    if (!ev) return;
    memcpy(ev, line, n);
    ev[n] = 0;
    for (struct plugso *p = g_head; p; p = p->next) {
        if (p->state != PLUGSO_LOADED || !STEER_HAS(p->pl, on_event) || !p->pl->on_event) continue;
        struct plugso_guard g;
        plugso_enter(&g, p, "on_event");
        p->pl->on_event(HOST(p), ev);
        plugso_leave(&g);
    }
    free(ev);
}

void plugso_attach(struct steerd *d) {
    g_d = d;
}

void plugso_boot(struct steerd *d) {
    g_d = d;
    char root[PATH_MAX], path[PATH_MAX + 16];
    root_dir(root, sizeof root);
    const char *over = getenv("STEER_PLUGSO_LIST");
    if (over && *over) snprintf(path, sizeof path, "%s", over);
    else snprintf(path, sizeof path, "%s/so.load", root);
    char *txt = slurp(path, NULL);
    if (!txt) return;
    for (char *l = txt, *nx; *l; l = nx) {
        nx = strchr(l, '\n');
        if (nx) *nx++ = 0; else nx = l + strlen(l);
        if (*l == '#' || !*l) continue;
        char *f[4];
        int k = 0;
        for (char *s = l; k < 4; ) {
            f[k++] = s;
            char *t = strchr(s, '\t');
            if (!t) break;
            *t = 0;
            s = t + 1;
        }
        if (k != 4) {
            fprintf(stderr, "steer[warn] plugin: %s: строка «%s» не годится (нужно: id версия каталог путь)\n", path, l);
            continue;
        }
        char why[512];
        struct plugso *p = NULL;
        if (plugso_load(f[0], *f[1] ? f[1] : NULL, f[2], f[3], &p, why, sizeof why) == 0)
            fprintf(stderr, "steer[info] plugin: %s %s загружен (.so)\n", f[0], f[1]);
        else
            fprintf(stderr, "steer[warn] plugin: %s: %s\n", f[0], why);
    }
    free(txt);
}

void plugso_status_print(FILE *out) {
    if (!g_head) return;
    fprintf(out, ",\"plugins_so\":[");
    for (struct plugso *p = g_head; p; p = p->next) {
        char esc[1100];
        const char *st = p->state == PLUGSO_LOADED ? "loaded" : p->state == PLUGSO_OFF ? "off" : "failed";
        fprintf(out, "%s{\"id\":\"%s\",\"state\":\"%s\",\"crashes\":%d", p == g_head ? "" : ",", p->id, st,
                p->crashes);
        if (p->version) {
            steerd_json_str(esc, sizeof esc, p->version);
            fprintf(out, ",\"version\":%s", esc);
        }
        if (p->why) {
            steerd_json_str(esc, sizeof esc, p->why);
            fprintf(out, ",\"why\":%s", esc);
        }
        fprintf(out, "}");
    }
    fprintf(out, "]");
}

void plugso_status_out(FILE *out, const char *out_name) {
    unsigned long k = str_hash(out_name);
    for (struct plugso *p = g_head; p; p = p->next)
        for (struct hent *e = ht_first(&p->stat, k); e; e = e->next)
            if (e->key == k && !strcmp(((struct pst *)e)->name, out_name)) {
                fprintf(out, ",\"plugin\":%s", ((struct pst *)e)->json);
                return;
            }
}
