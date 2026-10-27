/* Сторона плагина в API ядра (plugkit.h). */
#define _GNU_SOURCE
#include "plugkit.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evline.h"
#include "platform.h"
#include "pool.h"

/* Пул и стек — в net1; у программ без стека (obfs) их нет — ссылки слабые. */
#pragma weak pool_set_status_path
#pragma weak stack_set_fakeip_path

void pk_fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("steer: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

static char *xdup(const char *s) {
    if (!s) return NULL;
    char *c = strdup(s);
    if (!c) pk_fail("нет памяти");
    return c;
}

static int hexmark(const struct pkj *j, uint32_t *out) {
    const char *s = pkj_str(j);
    long v;
    if (s) { *out = (uint32_t)strtoul(s, NULL, 0); return 0; }
    if (pkj_long(j, &v) == 0) { *out = (uint32_t)v; return 0; }
    return -1;
}

static void cpy(char *dst, size_t n, const char *s) { snprintf(dst, n, "%s", s ? s : ""); }

int pk_conf_load(const char *path, struct pk_out *o, char *err, size_t errn) {
    memset(o, 0, sizeof(*o));
    char e2[256];
    o->doc = pkj_load(path, e2, sizeof e2);
    if (!o->doc) {
        snprintf(err, errn, "файл настройки выхода не читается — %s", e2);
        return -1;
    }
    const struct pkj *out = pkj_get(o->doc, "output"), *paths = pkj_get(o->doc, "paths");
    const char *name = pkj_str(pkj_get(out, "name")), *kind = pkj_str(pkj_get(out, "kind"));
    if (!name || !kind) {
        snprintf(err, errn, "%s: в файле настройки выхода нет output.name или output.kind", path);
        pkj_free(o->doc);
        o->doc = NULL;
        return -1;
    }
    o->output = out;
    o->keys = pkj_get(out, "keys");
    cpy(o->tun.name, sizeof o->tun.name, name);
    cpy(o->kind, sizeof o->kind, kind);
    cpy(o->tun.device, sizeof o->tun.device, pkj_str(pkj_get(out, "device")));
    cpy(o->over, sizeof o->over, pkj_str(pkj_get(pkj_get(out, "over"), "name")));
    hexmark(pkj_get(out, "mark"), &o->tun.mark);
    hexmark(pkj_get(out, "mark_mask"), &o->mark_mask);
    hexmark(pkj_get(out, "sock_mark"), &o->sock_mark);
    long v;
    if (pkj_long(pkj_get(out, "table"), &v) == 0) o->tun.table = (int)v;
    if (pkj_long(pkj_get(out, "tcp_port"), &v) == 0) o->tun.tcp_port = (int)v;
    int b;
    if (pkj_bool(pkj_get(out, "sock_mark_required"), &b) == 0) o->sock_mark_required = b;
    o->ipv6 = pkj_bool(pkj_get(out, "ipv6"), &b) == 0 ? b : 1;
    o->conf_path = xdup(path);
    o->etc = xdup(pkj_str(pkj_get(paths, "etc")));
    o->state = xdup(pkj_str(pkj_get(paths, "state")));
    o->plugin_conf = xdup(pkj_str(pkj_get(paths, "conf")));
    o->plugin_dir = xdup(pkj_str(pkj_get(paths, "plugin")));
    o->fakeip = xdup(pkj_str(pkj_get(paths, "fakeip")));
    o->platform = xdup(pkj_str(pkj_get(o->doc, "platform")));
    const char *ps = pkj_str(pkj_get(paths, "plugin_state"));
    if (ps) o->plugin_state = xdup(ps);
    else {
        /* Каталог {conf} — свой каталог плагина: ядро создало его и пишет туда {conf}. */
        o->plugin_state = xdup(path);
        char *sl = strrchr(o->plugin_state, '/');
        if (sl) *sl = '\0';
        else strcpy(o->plugin_state, ".");
    }
    if (asprintf(&o->status_path, "%s/%s.status.json", o->plugin_state, name) < 0) pk_fail("нет памяти");
    return 0;
}

static struct pk_out g_po;
static int g_have;

const struct pk_out *pk_out(void) { return g_have ? &g_po : NULL; }

void pk_conf_apply(const struct pk_out *o) {
    if (o->platform && *o->platform) {
        setenv("STEER_PLATFORM", o->platform, 1);
        plat_select(o->platform);
    }
    if (o->plugin_state) steer_set_state_dir(o->plugin_state);
    /* Счётчики стека туннеля — по файлу-выключателю {etc}/stats, как у прежних модулей. */
    if (o->etc) {
        char st[4200];
        snprintf(st, sizeof st, "%s/stats", o->etc);
        if (access(st, F_OK) == 0) setenv("STEER_TUN_STATS", "1", 0);
    }
    if (pool_set_status_path) pool_set_status_path(o->status_path);
    if (o->fakeip && stack_set_fakeip_path) stack_set_fakeip_path(o->fakeip);
}

uint32_t pk_sock_mark(const struct pk_out *o) { return o ? o->sock_mark : plat()->self_mark; }

const char *pk_key_str(const struct pk_out *o, const char *key) {
    return o ? pkj_str(pkj_get(o->keys, key)) : NULL;
}

int pk_key_bool(const struct pk_out *o, const char *key, int def) {
    int b;
    return o && pkj_bool(pkj_get(o->keys, key), &b) == 0 ? b : def;
}

long pk_key_long(const struct pk_out *o, const char *key, long def) {
    long v;
    return o && pkj_long(pkj_get(o->keys, key), &v) == 0 ? v : def;
}

int pk_key_ints(const struct pk_out *o, const char *key, int **out, size_t *n) {
    *out = NULL;
    *n = 0;
    const struct pkj *j = o ? pkj_get(o->keys, key) : NULL;
    if (!j) return 0;
    size_t k = j->t == PKJ_ARR ? j->n : 1;
    int *a = calloc(k ? k : 1, sizeof(*a));
    if (!a) return -1;
    for (size_t i = 0; i < k; i++) {
        long v;
        if (pkj_long(j->t == PKJ_ARR ? j->v[i] : j, &v) != 0) { free(a); return -1; }
        a[i] = (int)v;
    }
    *out = a;
    *n = k;
    return 0;
}

int pk_key_strs(const struct pk_out *o, const char *key, const char ***out, size_t *n) {
    *out = NULL;
    *n = 0;
    const struct pkj *j = o ? pkj_get(o->keys, key) : NULL;
    if (!j) return 0;
    size_t k = j->t == PKJ_ARR ? j->n : 1;
    const char **a = calloc(k ? k : 1, sizeof(*a));
    if (!a) return -1;
    for (size_t i = 0; i < k; i++) {
        a[i] = pkj_str(j->t == PKJ_ARR ? j->v[i] : j);
        if (!a[i]) { free(a); return -1; }
    }
    *out = a;
    *n = k;
    return 0;
}

int pk_status_write(const struct pk_out *o, const char *json) {
    if (!o || !o->status_path) return 0;
    char *tmp;
    if (asprintf(&tmp, "%s.tmp", o->status_path) < 0) return -1;
    FILE *f = fopen(tmp, "w");
    if (!f) { free(tmp); return -1; }
    fputs(json, f);
    fputc('\n', f);
    int rc = fclose(f) == 0 && rename(tmp, o->status_path) == 0 ? 0 : -1;
    if (rc) unlink(tmp);
    free(tmp);
    if (!rc) evline_emit("state", (const char *)NULL);
    return rc;
}

/* ---- командная строка ---- */

const char *pk_opt(const struct pk_args *a, const char *name) {
    for (int i = 0; i < a->nf; i++)
        if (!strcmp(a->fk[i], name)) return a->fv[i];
    return NULL;
}

int pk_has(const struct pk_args *a, const char *name) { return pk_opt(a, name) != NULL; }

long pk_opt_long(const struct pk_args *a, const char *name, long def, long lo, long hi) {
    const char *s = pk_opt(a, name);
    if (!s) return def;
    char *e;
    errno = 0;
    long v = strtol(s, &e, 10);
    if (e == s || *e || errno || v < lo || v > hi)
        pk_fail("--%s: «%s» — нужно целое от %ld до %ld", name, s, lo, hi);
    return v;
}

/* Флаг name есть в списке команды; *val — нужно ли значение. */
static int flag_known(const char *list, const char *name, size_t nl, int *val) {
    for (const char *p = list; p && *p;) {
        while (*p == ' ') p++;
        const char *e = p;
        while (*e && *e != ' ') e++;
        size_t l = (size_t)(e - p);
        int v = l && p[l - 1] == ':';
        if (v) l--;
        if (l == nl && !strncmp(p, name, nl)) { *val = v; return 1; }
        p = e;
    }
    return 0;
}

static void help(FILE *f, const char *id, const struct pk_cmd *c) {
    fprintf(f, "steer %s %s\n\n%s\n", c->name, c->args ? c->args : "", c->help ? c->help : "");
    if (c->flags && *c->flags) fprintf(f, "\nФлаги: %s (и --conf, --state-dir, --platform)\n", c->flags);
    (void)id;
}

int pk_main(int argc, char **argv, const char *id, const char *version, const struct pk_cmd *cmds, size_t n) {
    /* --platform — в любом месте строки, до всего остального: от неё пути по умолчанию. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--platform") != 0) continue;
        if (i + 1 >= argc) pk_fail("флаг --platform остался без значения (%s)", plat_names());
        if (plat_select(argv[i + 1]) != 0) pk_fail("--platform %s: такой платформы нет (есть %s)", argv[i + 1], plat_names());
        memmove(&argv[i], &argv[i + 2], (size_t)(argc - i - 1) * sizeof *argv);
        argc -= 2;
        i--;
    }
    /* hello — первое, что видит ядро (steer-api.md, 2.1): версия API, своя версия, id. */
    evline_emit("hello", "api", EVLINE_STR, PK_API, "ver", EVLINE_STR, version, "mod", EVLINE_STR, id,
                (const char *)NULL);
    /* Запись в закрытое соединение — отказ записи, а не смерть процесса со всеми соединениями
     * (прежний довод cli/modcmd.c: TLS пишет в сокет без MSG_NOSIGNAL). */
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        fprintf(stderr, "%s: нужна подкоманда:", id);
        for (size_t i = 0; i < n; i++) fprintf(stderr, " %s", cmds[i].name);
        fputc('\n', stderr);
        return 2;
    }
    const struct pk_cmd *c = NULL;
    for (size_t i = 0; i < n && !c; i++) if (!strcmp(cmds[i].name, argv[1])) c = &cmds[i];
    if (!c) pk_fail("%s: подкоманды %s нет", id, argv[1]);
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { help(stdout, id, c); return 0; }
    struct pk_args a;
    memset(&a, 0, sizeof a);
    a.cmd = c->name;
    a.pos = calloc((size_t)argc, sizeof(*a.pos));
    a.fk = calloc((size_t)argc, sizeof(*a.fk));
    a.fv = calloc((size_t)argc, sizeof(*a.fv));
    if (!a.pos || !a.fk || !a.fv) pk_fail("нет памяти");
    const char *conf = NULL, *state_dir = NULL;
    for (int i = 2; i < argc; i++) {
        const char *w = argv[i];
        if (w[0] != '-' || !w[1] || (w[1] != '-' && w[0] == '-' && w[1] >= '0' && w[1] <= '9')) {
            if (a.npos >= c->npos_max)
                pk_fail("команда %s принимает %d слов%s, а получила ещё и «%s»", c->name, c->npos_max,
                        c->npos_max == 1 ? "о" : "", w);
            a.pos[a.npos++] = w;
            continue;
        }
        if (w[1] != '-') pk_fail("неизвестный флаг: %s (подсказка: steer %s --help)", w, c->name);
        const char *nm = w + 2;
        if (!strcmp(nm, "conf") || !strcmp(nm, "state-dir")) {
            if (i + 1 >= argc) pk_fail("флаг %s остался без значения", w);
            if (nm[0] == 'c') conf = argv[++i];
            else state_dir = argv[++i];
            continue;
        }
        int val = 0;
        if (!flag_known(c->flags, nm, strlen(nm), &val))
            pk_fail("команда %s не понимает флаг %s (подсказка: steer %s --help)", c->name, w, c->name);
        a.fk[a.nf] = nm;
        if (val) {
            if (i + 1 >= argc) pk_fail("флаг %s остался без значения", w);
            a.fv[a.nf++] = argv[++i];
        } else a.fv[a.nf++] = "";
    }
    if (a.npos < c->npos_min) pk_fail("команде %s нужен аргумент %s (подсказка: steer %s --help)", c->name,
                                      c->args ? c->args : "", c->name);
    if (state_dir) steer_set_state_dir(state_dir);
    if (conf) {
        char err[512];
        if (pk_conf_load(conf, &g_po, err, sizeof err) != 0) pk_fail("%s", err);
        g_have = 1;
        pk_conf_apply(&g_po);
        a.out = &g_po;
        /* Имя выхода — слово человека или имя из {conf}; разойтись им нельзя. */
        if (a.npos && a.pos[0][0] != '/' && strcmp(a.pos[0], g_po.tun.name) != 0)
            pk_fail("выход %s, а файл настройки — выхода %s", a.pos[0], g_po.tun.name);
    } else if (c->conf) {
        pk_fail("%s: нужен --conf — файл настройки выхода (его пишет ядро steer; steer helper-conf <выход>)",
                c->name);
    }
    return c->run(&a);
}

/* ---- раздел программ (PK_PROGRAM) ---- */

extern const struct pk_prog __start_steer_pk[] __attribute__((weak));
extern const struct pk_prog __stop_steer_pk[] __attribute__((weak));

const struct pk_prog *pk_prog_find(const char *id) {
    if (!__start_steer_pk || !__stop_steer_pk) return NULL;
    for (const struct pk_prog *p = __start_steer_pk; p < __stop_steer_pk; p++)
        if (!id || !strcmp(p->id, id)) return p;
    return NULL;
}

int pk_prog_run(const struct pk_prog *p, int argc, char **argv) {
    return pk_main(argc, argv, p->id, p->version, p->cmds, p->n);
}
