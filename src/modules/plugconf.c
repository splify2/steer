/* {conf} помощника протокола (plugconf.h). */
#define _GNU_SOURCE
#include "plugconf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "err.h"
#include "jsonw.h"
#include "spec.h"
#include "marks.h"
#include "ynode.h"
#include "pool.h"
#include "stack.h"

/* Пул и стек — в net1 (раскладка 2.1) или в libsteer 2.0; у модуля моста их нет вовсе — ссылки слабые. */
#pragma weak pool_set_status_path
#pragma weak stack_set_fakeip_path

static struct plugconf g_pc;

const struct plugconf *plugconf_get(void) { return &g_pc; }

/* Реестр плагинов ВНУТРИ помощника (kinds/plugin.c) пуст: помощник разбирает спеку своей копией модели,
 * и его собственный вид (tunnel:vless…) обязан быть встроенным видом этой копии — иначе вид выхода взялся
 * бы из манифеста этого же плагина, и помощник не узнал бы своего выхода. Корень реестра — каталог самой
 * программы: подкаталогов с plugin.json в нём нет, реестр пуст, но «раскладка есть» (виды чужих плагинов —
 * недоступные выходы, а не отказ всей спеке). */
static void registry_off(void) {
    static char dir[4096];
    ssize_t l = readlink("/proc/self/exe", dir, sizeof(dir) - 1);
    if (l <= 0) return;
    dir[l] = '\0';
    char *sl = strrchr(dir, '/');
    if (!sl || sl == dir) return;
    *sl = '\0';
    setenv("STEER_PLUGINS_ROOT", dir, 1);
    setenv("STEER_PLUGIN_DIR", dir, 1);
}

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 4096, k = 0;
    char *b = malloc(cap);
    for (size_t r; b && (r = fread(b + k, 1, cap - k, f)) > 0;) {
        k += r;
        if (k == cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); b = NULL; } else b = nb; }
    }
    fclose(f);
    *n = k;
    return b;
}

/* Узел ключей вида — в JSON как есть: скаляр без кавычек (число, true, null) — как написан, с
 * кавычками — строкой. Ядро отдало ключи уже проверенными схемой. */
static void yjson(FILE *f, const struct ynode *n) {
    if (!n) { fputs("null", f); return; }
    if (n->kind == YN_SCALAR) {
        long v;
        int b;
        if (n->style == YS_PLAIN && (ynode_long(n, &v) == 0 || ynode_bool(n, &b) == 0 || ynode_is_null(n)))
            fputs(ynode_is_null(n) ? "null" : n->str, f);
        else if (n->style == YS_PLAIN && n->len && strspn(n->str, "-+0123456789.eE") == n->len)
            fputs(n->str, f);
        else jsonw_str(f, n->str);
        return;
    }
    fputc(n->kind == YN_MAP ? '{' : '[', f);
    for (size_t i = 0; i < ynode_len(n); i++) {
        if (i) fputc(',', f);
        if (n->kind == YN_MAP) {
            jsonw_str(f, ynode_key_at(n, i)->str);
            fputc(':', f);
            yjson(f, ynode_val_at(n, i));
        } else yjson(f, ynode_at(n, i));
    }
    fputc(n->kind == YN_MAP ? '}' : ']', f);
}

static const char *sget(const struct ynode *m, const char *k) {
    const struct ynode *v = ynode_get(m, k);
    return v && v->kind == YN_SCALAR && !ynode_is_null(v) ? v->str : NULL;
}

static __attribute__((noreturn)) void fail(const char *path, const char *why) {
    fprintf(stderr, "steer: %s — %s\n", path, why);
    exit(2);
}

static char *xasprintf(const char *fmt, const char *a, const char *b) {
    char *s = NULL;
    if (asprintf(&s, fmt, a, b) < 0) { fprintf(stderr, "steer: нет памяти\n"); exit(2); }
    return s;
}

char **plugconf_argv(int *argc, char **argv) {
    registry_off();
    int at = -1;
    for (int i = 1; i + 1 < *argc; i++)
        if (!strcmp(argv[i], "--conf")) { at = i; break; }
    if (at < 0) return argv;
    const char *path = argv[at + 1];
    size_t len = 0;
    char *txt = slurp(path, &len);
    if (!txt) fail(path, "файл настройки выхода не читается");
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(txt, len, path, &e);
    if (!d) fail(path, e.msg[0] ? e.msg : "файл настройки выхода не разобран");
    const struct ynode *root = ydoc_root(d), *out = ynode_get(root, "output"), *paths = ynode_get(root, "paths");
    const char *name = sget(out, "name"), *kind = sget(out, "kind");
    if (!name || !kind) fail(path, "в файле настройки выхода нет output.name или output.kind");

    /* Каталог {conf} — <state>/plugin/<id>: свой каталог плагина, ядро его создало и пишет туда {conf}. */
    char *dir = strdup(path);
    char *sl = dir ? strrchr(dir, '/') : NULL;
    if (sl) *sl = '\0';
    else { free(dir); dir = strdup("."); }
    const char *ps = sget(paths, "plugin_state");
    const char *state = ps ? ps : dir;

    /* Спека из одного выхода: вид и протокол — из output.kind («tunnel:vless» → tunnel + vless), ключи
     * вида — как есть, устройство — output.device, IPv6 снят — `ipv6: off` (только у туннеля). */
    char *spec = xasprintf("%s/%s.spec.json", dir, name);
    char *tmp = xasprintf("%s/%s.spec.json.tmp", dir, name);
    FILE *f = fopen(tmp, "w");
    if (!f) fail(tmp, strerror(errno));
    const char *colon = strchr(kind, ':');
    fputs("{\"version\":2,\"outputs\":{", f);
    jsonw_str(f, name);
    fputs(":{\"kind\":", f);
    if (colon) {
        char k0[64];
        snprintf(k0, sizeof k0, "%.*s", (int)(colon - kind), kind);
        jsonw_str(f, k0);
        fputs(",\"protocol\":", f);
        jsonw_str(f, colon + 1);
    } else jsonw_str(f, kind);
    const char *dev = sget(out, "device");
    if (dev && *dev) { fputs(",\"device\":", f); jsonw_str(f, dev); }
    int v6 = 1;
    if (colon && ynode_bool(ynode_get(out, "ipv6"), &v6) == 0 && !v6) fputs(",\"ipv6\":\"off\"", f);
    const struct ynode *keys = ynode_get(out, "keys");
    for (size_t i = 0; keys && keys->kind == YN_MAP && i < ynode_len(keys); i++) {
        fputc(',', f);
        jsonw_str(f, ynode_key_at(keys, i)->str);
        fputc(':', f);
        yjson(f, ynode_val_at(keys, i));
    }
    fputs("}}}\n", f);
    if (fclose(f) != 0 || rename(tmp, spec) != 0) fail(spec, strerror(errno));
    free(tmp);

    g_pc.active = 1;
    g_pc.mark = (uint32_t)strtoul(sget(out, "mark") ? sget(out, "mark") : "0", NULL, 0);
    g_pc.sock_mark = (uint32_t)strtoul(sget(out, "sock_mark") ? sget(out, "sock_mark") : "0", NULL, 0);
    long v;
    if (ynode_long(ynode_get(out, "table"), &v) == 0) g_pc.table = (int)v;
    if (ynode_long(ynode_get(out, "tcp_port"), &v) == 0) g_pc.tcp_port = (int)v;
    int b;
    if (ynode_bool(ynode_get(out, "sock_mark_required"), &b) == 0) g_pc.sock_mark_required = b;
    g_pc.status_path = xasprintf("%s/%s.status.json", dir, name);
    const char *fk = sget(paths, "fakeip");
    g_pc.fakeip_path = fk ? strdup(fk) : NULL;
    /* Платформа — та же, что у ядра: от неё поле метки и порт слушателя (out_tcp_port). */
    const char *plat = sget(root, "platform");
    if (plat) setenv("STEER_PLATFORM", plat, 1);

    char **av = calloc((size_t)*argc + 4, sizeof(*av));
    if (!av) { fprintf(stderr, "steer: нет памяти\n"); exit(2); }
    int n = 0;
    for (int i = 0; i < *argc; i++) {
        if (i == at) {
            av[n++] = "--spec";
            av[n++] = spec;
            av[n++] = "--state-dir";
            av[n++] = strdup(state);
            i++;
            continue;
        }
        av[n++] = argv[i];
    }
    av[n] = NULL;
    *argc = n;
    ydoc_free(d);
    free(txt);
    return av;
}

void plugconf_out(struct output *o) {
    if (!g_pc.active || !o) return;
    o->mark = g_pc.mark;
    o->table = g_pc.table;
    if (pool_set_status_path) pool_set_status_path(g_pc.status_path);
    if (g_pc.fakeip_path && stack_set_fakeip_path) stack_set_fakeip_path(g_pc.fakeip_path);
    if (g_pc.tcp_port && out_tcp_port(o) != g_pc.tcp_port)
        fprintf(stderr, "steer[warn] выход %s: порт слушателя по метке %d, а ядро назначило %d\n",
                o->name, out_tcp_port(o), g_pc.tcp_port);
}
