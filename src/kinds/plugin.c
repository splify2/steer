/* Плагины в ядре (plugin.h): реестр видов, подкоманд и хуков из манифестов; схема ключей вида; вид
 * unavail — выход, чей вид сейчас недоступен.
 *
 * ЧТО ЧИТАЕТ ЯДРО. /usr/lib/steer/plugins/<id>/plugin.json каждого плагина (каталог переопределяет
 * STEER_PLUGINS_ROOT — так стенды кладут фальшивые плагины во временный каталог) и state.json
 * менеджера (включён ли). Всё остальное — схема ключей вида (kinds/<вид>.schema.json), шаблоны nft,
 * программы — читается и запускается по пути из манифеста. Манифесты и схемы разбирает тот же
 * ynode, что спеку v2: JSON — подмножество YAML, второго разборщика ядру не нужно.
 *
 * НИЧЕГО ЗАШИТОГО. Перечня видов плагинов в ядре нет: вид приходит из манифеста вместе со схемой,
 * свойствами, помощником и шаблонами. Какой плагин даёт вид, которого нет, ядро узнаёт из индекса семени
 * (provides.kinds, seed_kind_plugin), а не из своего списка.
 *
 * ОТКАЗЫ НЕ ВАЛЯТ РЕЕСТР. Манифест, который не читается, несовместим по steer-api, конфликтует по
 * имени или назван в state.json отключённым, превращает свой плагин в выключенный с причиной
 * (struct plugin.why); остальные плагины работают. Виды выключенного плагина реестр помнит —
 * отказ скажет не «неизвестный kind», а «плагин X отключён: …». */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "spec.h"
#include "awg.h"
#include "cli.h"
#include "plugin.h"
#include "plugutil.h"
#include "module.h"
#include "ynode.h"
#include "ir.h"
#include "marks.h"
#include "jsonw.h"
#include "rtnl.h"

extern const struct cli_cmd *cli_lookup(const char *name) __attribute__((weak));

/* ---- мелочи ------------------------------------------------------------------------------- */

/* ---- пути --------------------------------------------------------------------------------- */

/* Файл плагина: настоящий — с диска, вкомпилированного (PLUGIN_BUILTIN_DIR/<id>/<путь>) — из
 * steer_plugin_embed, с версией ядра вместо @VERSION@. NULL — нет файла. */
static char *pl_read(const char *path, size_t *n) {
    static const char pre[] = PLUGIN_BUILTIN_DIR "/";
    if (strncmp(path, pre, sizeof(pre) - 1) != 0) return slurp(path, n);
    if (!steer_plugin_embed) return NULL;
    const char *id = path + sizeof(pre) - 1, *sl = strchr(id, '/');
    if (!sl) return NULL;
    for (const struct plugin_embed *e = steer_plugin_embed; e->id; e++) {
        if (strlen(e->id) != (size_t)(sl - id) || strncmp(e->id, id, (size_t)(sl - id)) != 0) continue;
        for (const struct plugin_embed_file *f = e->files; f->path; f++) {
            if (strcmp(f->path, sl + 1) != 0) continue;
            struct sbuf b = { 0 };
            const char *t = f->text, *v;
            while ((v = strstr(t, "@VERSION@"))) {
                sb_put(&b, t, (size_t)(v - t));
                sb_str(&b, steer_engine_version());
                t = v + 9;
            }
            sb_str(&b, t);
            if (b.oom || !b.p) { free(b.p); return NULL; }
            if (n) *n = b.n;
            return b.p;
        }
    }
    return NULL;
}

const char *plugin_root(void) {
    const char *e = getenv("STEER_PLUGINS_ROOT");
    return e && *e ? e : "/usr/lib/steer/plugins";
}

const char *plugin_etc(char *buf, size_t n) {
    const char *e = getenv("STEER_PLUGINS_ETC");
    if (e && *e) snprintf(buf, n, "%s", e);
    else snprintf(buf, n, "%s/plugins", plat()->etc_dir);
    return buf;
}

/* Путь внутри каталога плагина: не абсолютный и без «..» (manifest.md, «Общие правила»). */
static int relpath_ok(const char *s) {
    if (!*s || s[0] == '/') return 0;
    for (const char *p = s; *p; ) {
        const char *e = strchr(p, '/');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == 2 && p[0] == '.' && p[1] == '.') return 0;
        if (!e) break;
        p = e + 1;
    }
    return 1;
}

/* ---- версии и диапазоны (compat) ------------------------------------------------------------ */

static int ver_parse(const char *s, long v[3], const char **end) {
    char *e;
    v[0] = v[1] = v[2] = 0;
    if (!isdigit((unsigned char)*s)) return -1;
    v[0] = strtol(s, &e, 10);
    if (*e == '.' && isdigit((unsigned char)e[1])) {
        v[1] = strtol(e + 1, &e, 10);
        if (*e == '.' && isdigit((unsigned char)e[1])) v[2] = strtol(e + 1, &e, 10);
    }
    if (end) *end = e;
    return 0;
}

static int ver_cmp(const long a[3], const long b[3]) {
    for (int i = 0; i < 3; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

/* Одно сравнение синтаксиса npm: ^, ~, >=, >, <=, <, = или голая версия. 1 — подходит, 0 — нет,
 * -1 — не разобрано. */
static int cmp_one(const char *c, size_t n, const long have[3]) {
    char t[64];
    if (n >= sizeof(t)) return -1;
    memcpy(t, c, n);
    t[n] = '\0';
    const char *p = t;
    char op[3] = { 0 };
    if (*p == '^' || *p == '~' || *p == '=') { op[0] = *p++; }
    else if (*p == '>' || *p == '<') { op[0] = *p++; if (*p == '=') op[1] = *p++; }
    long want[3];
    const char *end;
    if (ver_parse(p, want, &end) < 0 || *end) return -1;
    if (!op[0] || op[0] == '=') return ver_cmp(have, want) == 0;
    if (!strcmp(op, ">=")) return ver_cmp(have, want) >= 0;
    if (!strcmp(op, ">")) return ver_cmp(have, want) > 0;
    if (!strcmp(op, "<=")) return ver_cmp(have, want) <= 0;
    if (!strcmp(op, "<")) return ver_cmp(have, want) < 0;
    long hi[3] = { want[0], want[1], want[2] };
    if (op[0] == '~' || want[0] == 0) {
        if (op[0] == '^' && want[0] == 0 && want[1] == 0) hi[2]++;
        else if (op[0] == '^' && want[0] == 0) hi[1]++, hi[2] = 0;
        else hi[1]++, hi[2] = 0;
    } else {
        hi[0]++, hi[1] = hi[2] = 0;
    }
    return ver_cmp(have, want) >= 0 && ver_cmp(have, hi) < 0;
}

/* Диапазон «^1.0», «>=1.2 <2», «^1.0 || ^2.0» против версии. -1 — диапазон не разобран. */
static int range_ok(const char *range, const char *ver) {
    long have[3];
    if (ver_parse(ver, have, NULL) < 0) return -1;
    const char *p = range;
    int any = 0;
    for (;;) {
        int all = 1;
        while (*p == ' ') p++;
        while (*p && !(p[0] == '|' && p[1] == '|')) {
            const char *s = p;
            while (*p && *p != ' ' && !(p[0] == '|' && p[1] == '|')) p++;
            if (p == s) break;
            int r = cmp_one(s, (size_t)(p - s), have);
            if (r < 0) return -1;
            if (!r) all = 0;
            while (*p == ' ') p++;
        }
        if (all) any = 1;
        if (p[0] == '|' && p[1] == '|') { p += 2; continue; }
        break;
    }
    return any;
}

/* ---- реестр ------------------------------------------------------------------------------- */

static struct plugin *g_pl;
static size_t g_pl_n;
static struct plugin_kind **g_kind;     /* виды включённых плагинов в порядке реестра, без impl: core */
static size_t g_kind_n;
static int g_loaded;

static struct pnft *pnft_load(const char *path, int per_out, char *why, size_t wn);
static void pnft_free(struct pnft *f);

static void prog_free(struct plugin_prog *p) {
    free(p->prog);
    vec_free(p->argv, p->argc);
    vec_free(p->env, p->envc);
    memset(p, 0, sizeof(*p));
}

static void kind_free(struct plugin_kind *k) {
    if (!k) return;
    free(k->name);
    ydoc_free(k->schema_doc);
    free(k->schema_path);
    prog_free(&k->helper);
    free(k->helper_cmd);
    prog_free(&k->check);
    prog_free(&k->expand);
    vec_free(k->nft, k->nft_n);
    for (size_t i = 0; i < k->nft_n; i++) pnft_free(k->nftp ? k->nftp[i] : NULL);
    free(k->nftp);
    free(k->lan_only); free(k->novia); free(k->selfnat_why);
    free(k->desc); free(k->helper_when);
    vec_free(k->watch, k->watch_n);
    free(k);
}

static void plugin_free(struct plugin *p) {
    free(p->id); free(p->version); free(p->dir); free(p->name); free(p->desc); free(p->why);
    for (size_t i = 0; i < p->cmd_n; i++) {
        free(p->cmd[i].name);
        prog_free(&p->cmd[i].run);
        free(p->cmd[i].help);
        free(p->cmd[i].usage);
        for (size_t j = 0; j < p->cmd[i].ctl_args_n; j++) { free(p->cmd[i].ctl_args[j].kind); free(p->cmd[i].ctl_args[j].flag); }
        free(p->cmd[i].ctl_args);
    }
    free(p->cmd);
    for (size_t i = 0; i < p->svc_n; i++) { free(p->svc[i].name); prog_free(&p->svc[i].run); }
    free(p->svc);
    vec_free(p->nft, p->nft_n);
    for (size_t i = 0; i < p->nft_n; i++) pnft_free(p->nftp ? p->nftp[i] : NULL);
    free(p->nftp);
    for (size_t i = 0; i < p->kind_n; i++) kind_free(p->kind[i]);
    free(p->kind);
    prog_free(&p->pre_apply);
    vec_free(p->requires, p->requires_n);
    vec_free(p->kind_names, p->kind_names_n);
    free(p->manifest);
}

/* Прежние реестры не освобождаются: выходы живых спек (плагинный вид, plugin_out.pk) указывают в
 * записи видов, и спека, читаемая сторожем или status в этот миг, пережила бы reload. Реестр —
 * килобайты, а перечитывается он только при смене плагинов (plugin_refresh), поэтому «прежние
 * живут до конца процесса» дешевле счётчика ссылок на каждой спеке. */
struct retired { struct plugin *pl; size_t n; struct plugin_kind **kind; };
static struct retired *g_old;
static size_t g_old_n;

static void registry_clear(void) {
    if (g_pl || g_kind) {
        struct retired *nr = realloc(g_old, (g_old_n + 1) * sizeof(*nr));
        if (nr) {
            g_old = nr;
            g_old[g_old_n++] = (struct retired){ g_pl, g_pl_n, g_kind };
        }                           /* нет памяти — прежний реестр просто остаётся висеть, как и был */
    }
    g_pl = NULL; g_kind = NULL;
    g_pl_n = g_kind_n = 0;
}

/* Манифест: узлы. */
static const char *m_str(const struct ynode *n, const char *key) {
    const struct ynode *v = ynode_get(n, key);
    return v && v->kind == YN_SCALAR && !ynode_is_null(v) ? v->str : NULL;
}

/* Строки списка (скаляры) в кучу. Не список — отказ с текстом в why. */
static int m_strs(const struct ynode *list, const char *what, char ***dst, size_t *n, char *why, size_t wn) {
    *dst = NULL;
    *n = 0;
    if (!list || ynode_is_null(list)) return 0;
    if (list->kind != YN_SEQ) { snprintf(why, wn, "%s: нужен список", what); return -1; }
    for (size_t i = 0; i < list->len; i++) {
        const struct ynode *it = ynode_at(list, i);
        if (!it || it->kind != YN_SCALAR) { snprintf(why, wn, "%s: в списке нужны строки", what); return -1; }
        if (vec_add(dst, n, it->str) != 0) { snprintf(why, wn, "нет памяти"); return -1; }
    }
    return 0;
}

/* Программа манифеста: prog, argv, env, timeout_s. node NULL или null — программы нет (prog остаётся
 * NULL). prog проверяется на выход за каталог плагина. */
static int m_prog(const char *dir, const struct ynode *node, const char *what, struct plugin_prog *p,
                  char *why, size_t wn) {
    memset(p, 0, sizeof(*p));
    if (!node || ynode_is_null(node)) return 0;
    if (node->kind != YN_MAP) { snprintf(why, wn, "%s: нужен объект", what); return -1; }
    const char *prog = m_str(node, "prog");
    if (!prog) { snprintf(why, wn, "%s: нет prog", what); return -1; }
    if (!relpath_ok(prog)) { snprintf(why, wn, "%s: путь %s выходит за каталог плагина", what, prog); return -1; }
    if (!strncmp(dir, PLUGIN_BUILTIN_DIR "/", sizeof(PLUGIN_BUILTIN_DIR))) {
        /* Вкомпилированный плагин: программа — этот же бинарник; какая из вкомпилированных — по
         * STEER_PK_BUILTIN (plugin_env, plugin_kind_helper; src/daemon/main.c). */
        p->prog = strdup("/proc/self/exe");
    } else {
        size_t l = strlen(dir) + strlen(prog) + 2;
        p->prog = malloc(l);
        if (p->prog) snprintf(p->prog, l, "%s/%s", dir, prog);
    }
    if (!p->prog) { snprintf(why, wn, "нет памяти"); return -1; }
    if (m_strs(ynode_get(node, "argv"), what, &p->argv, &p->argc, why, wn) != 0) return -1;
    const struct ynode *env = ynode_get(node, "env");
    if (env && env->kind == YN_MAP) {
        for (size_t i = 0; i < ynode_len(env); i++) {
            const struct ynode *k = ynode_key_at(env, i), *v = ynode_val_at(env, i);
            if (!v || v->kind != YN_SCALAR) { snprintf(why, wn, "%s: env — строки", what); return -1; }
            char tmp[1024];
            snprintf(tmp, sizeof(tmp), "%s=%s", k->str, v->str);
            if (vec_add(&p->env, &p->envc, tmp) != 0) { snprintf(why, wn, "нет памяти"); return -1; }
        }
    } else if (m_strs(env, what, &p->env, &p->envc, why, wn) != 0) return -1;
    const struct ynode *t = ynode_get(node, "timeout_s");
    long tv;
    if (t && !ynode_is_null(t)) {
        if (ynode_long(t, &tv) != 0 || tv < 1) { snprintf(why, wn, "%s: timeout_s — целое от 1", what); return -1; }
        p->timeout_s = (int)tv;
    }
    return 0;
}

static const struct { const char *name; unsigned bit; } CAPS[] = {
    { "device", KC_DEVICE }, { "mark", KC_MARK }, { "ctmark", KC_CTMARK },
    { "engine-owned", KC_ENGINE_OWNED }, { "self-nat", KC_SELF_NAT }, { "over", KC_OVER },
    { "tcp-probe", KC_TCP_PROBE }, { "flow-udp", KC_FLOW_UDP }, { "ipv6", KC_IPV6 },
    { "tcp-redir", KC_TCP_REDIR },
};

static void plugin_kind_ops_init(struct plugin_kind *k);

static struct plugin_kind *kind_load(const struct plugin *pl, const struct ynode *kn, char *why, size_t wn) {
    const char *name = m_str(kn, "name");
    if (!name || !*name) { snprintf(why, wn, "вид без имени"); return NULL; }
    struct plugin_kind *k = calloc(1, sizeof(*k));
    if (!k) { snprintf(why, wn, "нет памяти"); return NULL; }
    k->owner = pl;
    k->name = strdup(name);
    if (!k->name) { snprintf(why, wn, "нет памяти"); kind_free(k); return NULL; }
    if (!strncmp(name, "tunnel:", 7)) k->proto = k->name + 7;
    const char *impl = m_str(kn, "impl");
    if (impl && !strcmp(impl, "core")) k->impl_core = 1;
    else if (impl && strcmp(impl, "plugin") != 0) {
        snprintf(why, wn, "вид %s: impl — plugin или core", name);
        kind_free(k);
        return NULL;
    }
    const struct ynode *caps = ynode_get(kn, "caps");
    if (caps && caps->kind == YN_SEQ) {
        for (size_t i = 0; i < caps->len; i++) {
            const char *c = ynode_at(caps, i)->str;
            size_t j = 0;
            while (j < sizeof(CAPS) / sizeof(CAPS[0]) && strcmp(CAPS[j].name, c ? c : "")) j++;
            if (j == sizeof(CAPS) / sizeof(CAPS[0])) {
                snprintf(why, wn, "вид %s: нет такого свойства «%s» в caps", name, c ? c : "");
                kind_free(k);
                return NULL;
            }
            k->caps |= CAPS[j].bit;
        }
    }
    char w2[256] = "";
    if (m_prog(pl->dir, ynode_get(kn, "helper"), "helper", &k->helper, w2, sizeof(w2)) != 0 ||
        m_prog(pl->dir, ynode_get(kn, "check"), "check", &k->check, w2, sizeof(w2)) != 0 ||
        m_prog(pl->dir, ynode_get(kn, "expand"), "expand", &k->expand, w2, sizeof(w2)) != 0) {
        snprintf(why, wn, "вид %s: %s", name, w2);
        kind_free(k);
        return NULL;
    }
    const struct ynode *hn = ynode_get(kn, "helper");
    if (k->helper.prog) {
        const char *cmd = m_str(hn, "cmd");
        k->helper_cmd = strdup(cmd ? cmd : name);
        k->helper_argv_set = ynode_get(hn, "argv") != NULL;
        /* helper.when (manifest.md, kinds[]): помощник только у выходов, где записан этот ключ вида —
         * так плагин даёт помощника виду ядра (impl: core): обфускатор выходу interface с obfs. */
        k->helper_when = xdup(m_str(hn, "when"));
        if (k->helper_when && !k->impl_core) {
            snprintf(why, wn, "вид %s: helper.when — только у вида ядра (impl: core); у своего вида помощник "
                     "нужен всякому выходу", name);
            kind_free(k);
            return NULL;
        }
    }
    const char *keys = m_str(kn, "keys");
    if (keys) {
        if (!relpath_ok(keys)) {
            snprintf(why, wn, "вид %s: схема %s выходит за каталог плагина", name, keys);
            kind_free(k);
            return NULL;
        }
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", pl->dir, keys);
        size_t n;
        char *txt = pl_read(path, &n);
        if (!txt) {
            snprintf(why, wn, "вид %s: схема ключей %s не читается", name, keys);
            kind_free(k);
            return NULL;
        }
        struct err e;
        memset(&e, 0, sizeof(e));
        k->schema_doc = ydoc_parse_buf(txt, n, path, &e);
        free(txt);
        if (!k->schema_doc) {
            snprintf(why, wn, "вид %s: %s", name, e.msg);
            kind_free(k);
            return NULL;
        }
        k->schema = ydoc_root(k->schema_doc);
        k->schema_path = strdup(path);
        /* x-watch (manifest.md, «Слова схемы»): ключ-путь (x-path), содержимое файла которого помощник
         * читает при старте — подпись перезапуска берёт и его (подписка обновилась — клиент
         * перезапускается с новыми узлами). */
        const struct ynode *props = ynode_get(k->schema, "properties");
        for (size_t i = 0; props && props->kind == YN_MAP && i < ynode_len(props); i++) {
            const struct ynode *pv = ynode_val_at(props, i);
            int on = 0;
            if (ynode_get(pv, "x-watch") && ynode_bool(ynode_get(pv, "x-watch"), &on) == 0 && on) {
                if (!ynode_get(pv, "x-path")) {
                    snprintf(why, wn, "вид %s: x-watch у ключа %s — только у пути (x-path)", name,
                             ynode_key_at(props, i)->str);
                    kind_free(k);
                    return NULL;
                }
                if (vec_add(&k->watch, &k->watch_n, ynode_key_at(props, i)->str) != 0) {
                    snprintf(why, wn, "нет памяти");
                    kind_free(k);
                    return NULL;
                }
            }
        }
    }
    const struct ynode *nft = ynode_get(kn, "nft");
    char **nl = NULL;
    size_t nn = 0;
    if (m_strs(nft, "nft", &nl, &nn, w2, sizeof(w2)) != 0) {
        snprintf(why, wn, "вид %s: %s", name, w2);
        kind_free(k);
        return NULL;
    }
    for (size_t i = 0; i < nn; i++) {
        if (!relpath_ok(nl[i])) {
            snprintf(why, wn, "вид %s: файл nft %s выходит за каталог плагина", name, nl[i]);
            vec_free(nl, nn);
            kind_free(k);
            return NULL;
        }
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", pl->dir, nl[i]);
        struct pnft **np = realloc(k->nftp, (k->nft_n + 1) * sizeof(*np));
        if (!np || vec_add(&k->nft, &k->nft_n, path) != 0) {
            if (np) k->nftp = np;
            snprintf(why, wn, "нет памяти");
            vec_free(nl, nn);
            kind_free(k);
            return NULL;
        }
        k->nftp = np;
        k->nftp[k->nft_n - 1] = pnft_load(path, 1, why, wn);
        if (!k->nftp[k->nft_n - 1]) {
            vec_free(nl, nn);
            kind_free(k);
            return NULL;
        }
    }
    vec_free(nl, nn);
    const struct ynode *res = ynode_get(kn, "resources");
    long rv;
    if (res && res->kind == YN_MAP) {
        const struct ynode *r;
        if ((r = ynode_get(res, "ports")) && ynode_long(r, &rv) == 0 && rv >= 0) k->res_ports = (unsigned)rv;
        if ((r = ynode_get(res, "queues")) && ynode_long(r, &rv) == 0 && rv >= 0) k->res_queues = (unsigned)rv;
    }
    k->desc = xdup(m_str(kn, "description"));
    if (!k->desc) k->desc = xdup(pl->desc);
    /* health (manifest.md, kinds[]): events — здоровье и задержку выхода судит помощник своими up и
     * down (клиент звезды xsteer: проба через устройство проверила бы интернет у хаба, а не туннель);
     * tcp, icmp, probe и отсутствие ключа — общая проба ядра по свойствам вида. */
    const char *hl = m_str(kn, "health");
    if (hl && !strcmp(hl, "events")) k->health_events = 1;
    else if (hl && strcmp(hl, "tcp") && strcmp(hl, "icmp") && strcmp(hl, "probe")) {
        snprintf(why, wn, "вид %s: health — events, tcp, icmp или probe, а не «%s»", name, hl);
        kind_free(k);
        return NULL;
    }
    /* paths (steer-api 1.4): помощник отставляет пути событием health — status выхода несёт paths_down
     * всегда (пустой — отставленных нет), а не только после первого события. */
    int pb = 0;
    if (ynode_get(kn, "paths") && ynode_bool(ynode_get(kn, "paths"), &pb) == 0) k->paths = pb;
    const struct ynode *tx = ynode_get(kn, "texts");
    if (tx && tx->kind == YN_MAP) {
        k->lan_only = xdup(m_str(tx, "lan_only"));
        k->novia = xdup(m_str(tx, "novia"));
        k->selfnat_why = xdup(m_str(tx, "selfnat_why"));
    }
    plugin_kind_ops_init(k);
    return k;
}

/* Один каталог плагина → запись реестра (всегда; негодный плагин — выключенный с причиной). */
static int plugin_load(const char *root, const char *dirname, struct plugin *p, int *skip) {
    char path[PATH_MAX];
    *skip = 0;
    memset(p, 0, sizeof(*p));
    snprintf(path, sizeof(path), "%s/%s/plugin.json", root, dirname);
    size_t n;
    char *txt = pl_read(path, &n);
    if (!txt) { *skip = 1; return 0; }
    p->id = strdup(dirname);
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/%s", root, dirname);
    p->dir = strdup(dir);
    p->manifest = txt;
    p->manifest_len = n;
    if (!p->id || !p->dir) return -1;
    char why[512] = "";
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(txt, n, path, &e);
    if (!d) { snprintf(why, sizeof(why), "plugin.json не читается: %s", e.msg); goto bad; }
    const struct ynode *root_n = ydoc_root(d);
    const char *id = m_str(root_n, "id"), *ver = m_str(root_n, "version");
    if (!id || !ver) { snprintf(why, sizeof(why), "plugin.json: нужны id и version"); ydoc_free(d); goto bad; }
    if (strcmp(id, dirname) != 0) {
        snprintf(why, sizeof(why), "id %s не совпадает с каталогом %s", id, dirname);
        ydoc_free(d);
        goto bad;
    }
    p->version = strdup(ver);
    p->name = xdup(m_str(root_n, "name"));
    p->desc = xdup(m_str(root_n, "description"));
    const struct ynode *st = ynode_get(root_n, "steer");
    /* Имена видов — до всех проверок: у плагина, выключенного ниже, их помнит отказ вида. */
    {
        const struct ynode *kn0 = ynode_get(st, "kinds");
        for (size_t i = 0; kn0 && kn0->kind == YN_SEQ && i < kn0->len; i++) {
            const char *nm0 = m_str(ynode_at(kn0, i), "name");
            if (nm0 && vec_add(&p->kind_names, &p->kind_names_n, nm0) != 0) { ydoc_free(d); return -1; }
        }
    }
    const struct ynode *compat = ynode_get(ynode_get(root_n, "compat"), "steer-api");
    if (st && st->kind == YN_MAP && ynode_len(st)) {
        if (!compat || compat->kind != YN_SCALAR) {
            snprintf(why, sizeof(why), "нет compat.steer-api — несовместим с ядром (steer-api %s)", STEER_API_VERSION);
            ydoc_free(d);
            goto bad;
        }
        int r = range_ok(compat->str, STEER_API_VERSION);
        if (r < 0) { snprintf(why, sizeof(why), "compat.steer-api: «%s» — диапазон не разобран", compat->str); ydoc_free(d); goto bad; }
        if (!r) {
            snprintf(why, sizeof(why), "%s %s требует steer-api %s, у ядра %s", id, ver, compat->str, STEER_API_VERSION);
            ydoc_free(d);
            goto bad;
        }
    }
    /* steer.settings (steer-api 1.4): "restart" — настройки плагина (conf/<id>/settings.json) входят в
     * подпись перезапуска всех его помощников и служб; хост, записав их, зовёт reload. */
    {
        const char *sv = m_str(st, "settings");
        if (sv && !strcmp(sv, "restart")) p->settings_restart = 1;
        else if (sv) {
            snprintf(why, sizeof(why), "steer.settings — только «restart», а не «%s»", sv);
            ydoc_free(d);
            goto bad;
        }
    }
    const struct ynode *res = ynode_get(root_n, "resources");
    long rv;
    if (res && res->kind == YN_MAP) {
        const struct ynode *r;
        if ((r = ynode_get(res, "ports")) && ynode_long(r, &rv) == 0 && rv > 0) p->res_ports = (unsigned)rv;
        if ((r = ynode_get(res, "queues")) && ynode_long(r, &rv) == 0 && rv > 0) p->res_queues = (unsigned)rv;
        if ((r = ynode_get(res, "mark_bits")) && ynode_long(r, &rv) == 0 && rv > 0) p->res_marks = (unsigned)rv;
        if (p->res_ports || p->res_queues || p->res_marks) p->has_hooks = 1;
    }
    const struct ynode *rq = ynode_get(ynode_get(root_n, "requires"), "plugins");
    for (size_t i = 0; rq && rq->kind == YN_MAP && i < ynode_len(rq); i++)
        if (vec_add(&p->requires, &p->requires_n, ynode_key_at(rq, i)->str) != 0) { ydoc_free(d); return -1; }
    const struct ynode *kinds = ynode_get(st, "kinds");
    for (size_t i = 0; kinds && kinds->kind == YN_SEQ && i < kinds->len; i++) {
        struct plugin_kind *k = kind_load(p, ynode_at(kinds, i), why, sizeof(why));
        if (!k) { ydoc_free(d); goto bad; }
        struct plugin_kind **nk = realloc(p->kind, (p->kind_n + 1) * sizeof(*nk));
        if (!nk) { kind_free(k); ydoc_free(d); return -1; }
        p->kind = nk;
        p->kind[p->kind_n++] = k;
        if (k->check.prog || k->expand.prog) p->has_hooks = 1;
        if (k->res_ports || k->res_queues) p->has_hooks = 1;
    }
    const struct ynode *cmds = ynode_get(st, "commands");
    for (size_t i = 0; cmds && cmds->kind == YN_SEQ && i < cmds->len; i++) {
        const struct ynode *cn = ynode_at(cmds, i);
        const char *nm = m_str(cn, "name");
        if (!nm || !*nm) { snprintf(why, sizeof(why), "подкоманда без имени"); ydoc_free(d); goto bad; }
        struct plugin_cmd *nc = realloc(p->cmd, (p->cmd_n + 1) * sizeof(*nc));
        if (!nc) { ydoc_free(d); return -1; }
        p->cmd = nc;
        struct plugin_cmd *c = &p->cmd[p->cmd_n];
        memset(c, 0, sizeof(*c));
        p->cmd_n++;
        c->name = strdup(nm);
        c->owner = p;
        char w2[256] = "";
        if (m_prog(p->dir, cn, nm, &c->run, w2, sizeof(w2)) != 0) {
            snprintf(why, sizeof(why), "подкоманда %s: %s", nm, w2);
            ydoc_free(d);
            goto bad;
        }
        if (!c->run.argc) {          /* умолчание argv — [<name>] */
            if (vec_add(&c->run.argv, &c->run.argc, nm) != 0) { ydoc_free(d); return -1; }
        }
        c->help = xdup(m_str(cn, "help"));
        c->usage = xdup(m_str(cn, "usage"));
        int cf = 0;
        if (ynode_get(cn, "conf") && ynode_bool(ynode_get(cn, "conf"), &cf) == 0) c->conf = cf;
        const struct ynode *ctl = ynode_get(cn, "ctl");
        if (ctl && ctl->kind == YN_MAP) {
            long tv = 0;
            c->ctl = 1;
            if (ynode_get(ctl, "timeout_s") && ynode_long(ynode_get(ctl, "timeout_s"), &tv) == 0) c->ctl_timeout_s = (int)tv;
            if (ynode_get(ctl, "optional") && ynode_long(ynode_get(ctl, "optional"), &tv) == 0) c->ctl_optional = (int)tv;
            int lk = 0;
            if (ynode_get(ctl, "lock") && ynode_bool(ynode_get(ctl, "lock"), &lk) == 0) c->ctl_lock = lk;
            const char *body = m_str(ctl, "body");
            if (body && !strcmp(body, "file")) {
                c->ctl_body_max = 16L * 1024 * 1024;
                if (ynode_get(ctl, "body_max") && ynode_long(ynode_get(ctl, "body_max"), &tv) == 0 && tv > 0)
                    c->ctl_body_max = tv;
            } else if (body && strcmp(body, "none") != 0) {
                snprintf(why, sizeof(why), "подкоманда %s: ctl.body — none или file, а не «%s»", nm, body);
                ydoc_free(d);
                goto bad;
            }
            if (ynode_get(ctl, "spec")) {
                snprintf(why, sizeof(why), "подкоманда %s: ctl.spec снят — спеку программа плагина не читает; "
                         "выход ей даёт conf: true ({conf}, steer-api.md 1.4)", nm);
                ydoc_free(d);
                goto bad;
            }
            static const char *const KINDS[] = { "name", "int", "target", "file", "word", NULL };
            const struct ynode *args = ynode_get(ctl, "args");
            for (size_t ai = 0; args && args->kind == YN_SEQ && ai < args->len; ai++) {
                const struct ynode *an = ynode_at(args, ai);
                const char *k = an->kind == YN_SCALAR ? an->str : m_str(an, "kind");
                size_t ki = 0;
                while (KINDS[ki] && strcmp(KINDS[ki], k ? k : "")) ki++;
                if (!KINDS[ki]) {
                    snprintf(why, sizeof(why), "подкоманда %s: ctl.args — name, int, target, file или word, а не «%s»",
                             nm, k ? k : "?");
                    ydoc_free(d);
                    goto bad;
                }
                struct plugin_ctl_arg *na = realloc(c->ctl_args, (c->ctl_args_n + 1) * sizeof(*na));
                if (!na) { ydoc_free(d); return -1; }
                c->ctl_args = na;
                struct plugin_ctl_arg *ca = &c->ctl_args[c->ctl_args_n++];
                memset(ca, 0, sizeof(*ca));
                ca->kind = strdup(KINDS[ki]);
                ca->lo = -2147483647L;
                ca->hi = 2147483647L;
                if (an->kind == YN_MAP) {
                    ca->flag = xdup(m_str(an, "flag"));
                    long v;
                    if (ynode_get(an, "min") && ynode_long(ynode_get(an, "min"), &v) == 0) ca->lo = v;
                    if (ynode_get(an, "max") && ynode_long(ynode_get(an, "max"), &v) == 0) ca->hi = v;
                    if (ca->flag && strncmp(ca->flag, "--", 2) != 0) {
                        snprintf(why, sizeof(why), "подкоманда %s: ctl.args: флаг «%s» — с «--»", nm, ca->flag);
                        ydoc_free(d);
                        goto bad;
                    }
                }
            }
        }
    }
    const struct ynode *svcs = ynode_get(st, "services");
    for (size_t i = 0; svcs && svcs->kind == YN_SEQ && i < svcs->len; i++) {
        const struct ynode *sn = ynode_at(svcs, i);
        const char *nm = m_str(sn, "name");
        if (!nm || !*nm) { snprintf(why, sizeof(why), "служба без имени"); ydoc_free(d); goto bad; }
        for (size_t j = 0; j < p->svc_n; j++)
            if (!strcmp(p->svc[j].name, nm)) {
                snprintf(why, sizeof(why), "служба %s названа дважды", nm);
                ydoc_free(d);
                goto bad;
            }
        struct plugin_svc *ns = realloc(p->svc, (p->svc_n + 1) * sizeof(*ns));
        if (!ns) { ydoc_free(d); return -1; }
        p->svc = ns;
        struct plugin_svc *sv = &p->svc[p->svc_n];
        memset(sv, 0, sizeof(*sv));
        p->svc_n++;
        sv->name = strdup(nm);
        sv->owner = p;
        char w2[256] = "";
        if (!sv->name || m_prog(p->dir, sn, nm, &sv->run, w2, sizeof(w2)) != 0) {
            snprintf(why, sizeof(why), "служба %s: %s", nm, w2);
            ydoc_free(d);
            goto bad;
        }
        if (!sv->run.argc && vec_add(&sv->run.argv, &sv->run.argc, nm) != 0) { ydoc_free(d); return -1; }
        /* Ресурсы службы (очередь, метка) выдаются при подготовке спеки — ей нужен проход шага. */
        p->has_hooks = 1;
    }
    const struct ynode *hooks = ynode_get(st, "hooks");
    {
        char w2[256] = "";
        if (m_prog(p->dir, ynode_get(hooks, "pre_apply"), "pre_apply", &p->pre_apply, w2, sizeof(w2)) != 0) {
            snprintf(why, sizeof(why), "хук %s", w2);
            ydoc_free(d);
            goto bad;
        }
        if (p->pre_apply.prog) p->has_hooks = 1;
    }
    {
        char w2[256] = "";
        char **nl = NULL;
        size_t nn = 0;
        if (m_strs(ynode_get(st, "nft"), "steer.nft", &nl, &nn, w2, sizeof(w2)) != 0) {
            snprintf(why, sizeof(why), "%s", w2);
            ydoc_free(d);
            goto bad;
        }
        for (size_t i = 0; i < nn; i++) {
            if (!relpath_ok(nl[i])) {
                snprintf(why, sizeof(why), "файл nft %s выходит за каталог плагина", nl[i]);
                vec_free(nl, nn);
                ydoc_free(d);
                goto bad;
            }
            char fp[PATH_MAX];
            snprintf(fp, sizeof(fp), "%s/%s", p->dir, nl[i]);
            struct pnft **np = realloc(p->nftp, (p->nft_n + 1) * sizeof(*np));
            if (!np || vec_add(&p->nft, &p->nft_n, fp) != 0) { vec_free(nl, nn); ydoc_free(d); return -1; }
            p->nftp = np;
            p->nftp[p->nft_n - 1] = pnft_load(fp, 0, why, sizeof(why));
            if (!p->nftp[p->nft_n - 1]) { vec_free(nl, nn); ydoc_free(d); goto bad; }
        }
        vec_free(nl, nn);
    }
    ydoc_free(d);
    p->enabled = 1;
    return 0;
bad:
    p->enabled = 0;
    p->why = strdup(why);
    return 0;
}

static int pl_cmp(const void *a, const void *b) {
    return strcmp(((const struct plugin *)a)->id, ((const struct plugin *)b)->id);
}

/* state.json менеджера: что включено. Нет файла — включено всё, что лежит (стенды, ручная
 * раскладка); есть — только записанное с enabled: true. */
static int state_enabled(const char *id, int have_state, const struct ydoc *sd, char **why) {
    *why = NULL;
    if (!have_state) return 1;
    const struct ynode *pl = ynode_get(ynode_get(ydoc_root(sd), "plugins"), id);
    if (!pl) { *why = strdup("не записан в state.json менеджера"); return 0; }
    int en = 1;
    const struct ynode *e = ynode_get(pl, "enabled");
    if (e && ynode_bool(e, &en) != 0) en = 1;
    if (!en) {
        const char *w = m_str(pl, "why");
        *why = strdup(w ? w : "отключён");
        return 0;
    }
    const char *state = m_str(pl, "state");
    if (state && !strcmp(state, "failed")) {
        const char *w = m_str(pl, "why");
        *why = strdup(w ? w : "не работает");
        return 0;
    }
    return 1;
}

/* Конфликты имён: регистрируется плагин, стоявший раньше (по id), второй — выключен с причиной. */
static void resolve_conflicts(void) {
    for (size_t i = 0; i < g_pl_n; i++) {
        struct plugin *p = &g_pl[i];
        if (!p->enabled) continue;
        for (size_t j = 0; j < i && p->enabled; j++) {
            const struct plugin *q = &g_pl[j];
            if (!q->enabled) continue;
            for (size_t a = 0; a < p->kind_n && p->enabled; a++)
                for (size_t b = 0; b < q->kind_n; b++)
                    if (!strcmp(p->kind[a]->name, q->kind[b]->name)) {
                        char w[300];
                        snprintf(w, sizeof(w), "вид %s уже есть у плагина %s", p->kind[a]->name, q->id);
                        p->enabled = 0;
                        p->why = strdup(w);
                        break;
                    }
            for (size_t a = 0; a < p->cmd_n && p->enabled; a++)
                for (size_t b = 0; b < q->cmd_n; b++)
                    if (!strcmp(p->cmd[a].name, q->cmd[b].name)) {
                        char w[300];
                        snprintf(w, sizeof(w), "подкоманда %s уже есть у плагина %s", p->cmd[a].name, q->id);
                        p->enabled = 0;
                        p->why = strdup(w);
                        break;
                    }
        }
        for (size_t j = 0; j < i && p->enabled; j++) {
            const struct plugin *q = &g_pl[j];
            if (!q->enabled) continue;
            for (size_t a = 0; a < p->svc_n && p->enabled; a++)
                for (size_t b = 0; b < q->svc_n; b++)
                    if (!strcmp(p->svc[a].name, q->svc[b].name)) {
                        char w[300];
                        snprintf(w, sizeof(w), "служба %s уже есть у плагина %s", p->svc[a].name, q->id);
                        p->enabled = 0;
                        p->why = strdup(w);
                        break;
                    }
        }
        /* Имена подкоманд ядра плагину не даются (steer-api.md, 4.3). */
        for (size_t a = 0; a < p->cmd_n && p->enabled; a++)
            if (cli_lookup && cli_lookup(p->cmd[a].name)) {
                char w[300];
                snprintf(w, sizeof(w), "подкоманда %s — команда ядра", p->cmd[a].name);
                p->enabled = 0;
                p->why = strdup(w);
            }
    }
}

/* Отпечаток того, из чего собран реестр: каталог плагинов (менеджер подменяет <id> переименованием,
 * и время каталога меняется) и state.json (его пишет менеджер атомарно). */
static int stamp_of(struct timespec *a, struct timespec *b, off_t *sz) {
    struct stat st;
    char etc[PATH_MAX], sp[PATH_MAX + 16];
    memset(a, 0, sizeof(*a)); memset(b, 0, sizeof(*b)); *sz = -1;
    int have = 0;
    if (stat(plugin_root(), &st) == 0) { *a = st.st_mtim; have = 1; }
    plugin_etc(etc, sizeof(etc));
    snprintf(sp, sizeof(sp), "%s/state.json", etc);
    if (stat(sp, &st) == 0) { *b = st.st_mtim; *sz = st.st_size; have = 1; }
    return have;
}
static struct timespec g_stamp_a, g_stamp_b;
static off_t g_stamp_sz = -1;

int plugin_reload(const char *root) {
    registry_clear();
    g_loaded = 1;
    stamp_of(&g_stamp_a, &g_stamp_b, &g_stamp_sz);
    if (!root) root = plugin_root();
    DIR *d = opendir(root);
    char etc[PATH_MAX], sp[PATH_MAX + 16];
    plugin_etc(etc, sizeof(etc));
    snprintf(sp, sizeof(sp), "%s/state.json", etc);
    size_t sn;
    char *stxt = slurp(sp, &sn);
    struct ydoc *sd = NULL;
    if (stxt) {
        struct err e;
        memset(&e, 0, sizeof(e));
        sd = ydoc_parse_buf(stxt, sn, sp, &e);
    }
    struct dirent *de;
    int rc = 0;
    /* Сначала каталог плагинов, затем вкомпилированные — те, чьего id в каталоге нет. */
    const struct plugin_embed *emb = steer_plugin_embed;
    for (;;) {
        const char *r, *nm;
        if (d && (de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            r = root;
            nm = de->d_name;
        } else {
            if (d) { closedir(d); d = NULL; }
            if (!emb || !emb->id) break;
            nm = (emb++)->id;
            r = PLUGIN_BUILTIN_DIR;
            int have = 0;
            for (size_t i = 0; i < g_pl_n && !have; i++) have = !strcmp(g_pl[i].id, nm);
            if (have) continue;
        }
        struct plugin p;
        int skip;
        if (plugin_load(r, nm, &p, &skip) != 0) { plugin_free(&p); rc = -1; break; }
        if (skip) { plugin_free(&p); continue; }
        p.builtin = r != root;
        if (p.enabled) {
            char *why;
            if (!state_enabled(p.id, sd != NULL, sd, &why)) { p.enabled = 0; p.why = why; }
        }
        struct plugin *np = realloc(g_pl, (g_pl_n + 1) * sizeof(*np));
        if (!np) { plugin_free(&p); rc = -1; break; }
        g_pl = np;
        g_pl[g_pl_n++] = p;
    }
    if (d) closedir(d);
    ydoc_free(sd);
    free(stxt);
    if (g_pl_n > 1) qsort(g_pl, g_pl_n, sizeof(*g_pl), pl_cmp);
    /* Записи видов указывают на плагин по адресу в g_pl: после сортировки и роста массива
     * владельцев переставляют заново. */
    for (size_t i = 0; i < g_pl_n; i++) {
        for (size_t j = 0; j < g_pl[i].kind_n; j++) g_pl[i].kind[j]->owner = &g_pl[i];
        for (size_t j = 0; j < g_pl[i].cmd_n; j++) g_pl[i].cmd[j].owner = &g_pl[i];
        for (size_t j = 0; j < g_pl[i].svc_n; j++) g_pl[i].svc[j].owner = &g_pl[i];
    }
    resolve_conflicts();
    for (size_t i = 0; i < g_pl_n; i++) {
        if (!g_pl[i].enabled) continue;
        for (size_t j = 0; j < g_pl[i].kind_n; j++) {
            if (g_pl[i].kind[j]->impl_core) continue;
            struct plugin_kind **nk = realloc(g_kind, (g_kind_n + 1) * sizeof(*nk));
            if (!nk) { rc = -1; break; }
            g_kind = nk;
            g_kind[g_kind_n++] = g_pl[i].kind[j];
        }
    }
    return rc;
}

int plugin_refresh(void) {
    struct timespec a, b;
    off_t sz;
    stamp_of(&a, &b, &sz);
    if (g_loaded && a.tv_sec == g_stamp_a.tv_sec && a.tv_nsec == g_stamp_a.tv_nsec &&
        b.tv_sec == g_stamp_b.tv_sec && b.tv_nsec == g_stamp_b.tv_nsec && sz == g_stamp_sz)
        return 0;
    plugin_reload(NULL);
    return 1;
}

static void ensure(void) { if (!g_loaded) plugin_reload(NULL); }

size_t plugin_n(void) { ensure(); return g_pl_n; }
const struct plugin *plugin_at(size_t i) { ensure(); return i < g_pl_n ? &g_pl[i] : NULL; }
const struct plugin *plugin_find(const char *id) {
    ensure();
    for (size_t i = 0; i < g_pl_n; i++) if (!strcmp(g_pl[i].id, id)) return &g_pl[i];
    return NULL;
}

size_t plugin_kinds_n(void) { ensure(); return g_kind_n; }
const struct kind_ops *plugin_kind_ops_at(size_t i) { ensure(); return i < g_kind_n ? &g_kind[i]->ops : NULL; }

const struct plugin_kind *plugin_kind_find(const char *name) {
    ensure();
    for (size_t i = 0; i < g_kind_n; i++) if (!strcmp(g_kind[i]->name, name)) return g_kind[i];
    return NULL;
}

const struct plugin_kind *plugin_kind_of_ops(const struct kind_ops *k) {
    return k ? k->plugin : NULL;
}

size_t plugin_svc_n(void) {
    ensure();
    size_t n = 0;
    for (size_t i = 0; i < g_pl_n; i++)
        if (g_pl[i].enabled) n += g_pl[i].svc_n;
    return n;
}

const struct plugin_svc *plugin_svc_at(size_t k) {
    ensure();
    for (size_t i = 0; i < g_pl_n; i++) {
        if (!g_pl[i].enabled) continue;
        if (k < g_pl[i].svc_n) return &g_pl[i].svc[k];
        k -= g_pl[i].svc_n;
    }
    return NULL;
}

const struct plugin_cmd *plugin_cmd_find(const char *name) {
    ensure();
    for (size_t i = 0; i < g_pl_n; i++) {
        if (!g_pl[i].enabled) continue;
        for (size_t j = 0; j < g_pl[i].cmd_n; j++)
            if (!strcmp(g_pl[i].cmd[j].name, name)) return &g_pl[i].cmd[j];
    }
    return NULL;
}

/* Какой плагин даёт вид, которого нет: индекс семени (steer-core кладёт его в /usr/share/steer/seed,
 * STEER_PLUGIN_SEED — стендам), поле provides.kinds версий (plugin-sdk/docs/index.md). Своего перечня
 * «вид → плагин» у ядра нет: имя плагина приходит из индекса, как и сам плагин. id — в куче (free);
 * NULL — индекса нет или вид в нём не назван. */
static char *seed_kind_plugin(const char *kind) {
    const char *dir = getenv("STEER_PLUGIN_SEED");
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/index.json", dir && *dir ? dir : "/usr/share/steer/seed");
    size_t n;
    char *txt = slurp(path, &n);
    if (!txt) return NULL;
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(txt, n, path, &e);
    free(txt);
    char *id = NULL;
    const struct ynode *pls = d ? ynode_get(ydoc_root(d), "plugins") : NULL;
    for (size_t i = 0; !id && pls && pls->kind == YN_MAP && i < ynode_len(pls); i++) {
        const struct ynode *vs = ynode_get(ynode_val_at(pls, i), "versions");
        for (size_t j = 0; !id && vs && vs->kind == YN_SEQ && j < ynode_len(vs); j++) {
            const struct ynode *ks = ynode_get(ynode_get(ynode_at(vs, j), "provides"), "kinds");
            for (size_t k = 0; !id && ks && ks->kind == YN_SEQ && k < ynode_len(ks); k++)
                if (ynode_at(ks, k)->kind == YN_SCALAR && !strcmp(ynode_at(ks, k)->str, kind))
                    id = strdup(ynode_key_at(pls, i)->str);
        }
    }
    ydoc_free(d);
    return id;
}

const char *plugin_kind_why(const char *name, char *buf, size_t n, const char **id) {
    ensure();
    if (id) *id = NULL;
    for (size_t i = 0; i < g_pl_n; i++)
        for (size_t j = 0; j < g_pl[i].kind_names_n; j++)
            if (!strcmp(g_pl[i].kind_names[j], name)) {
                if (id) *id = g_pl[i].id;
                if (g_pl[i].enabled) snprintf(buf, n, "плагин %s не отдал вид %s", g_pl[i].id, name);
                else snprintf(buf, n, "плагин %s отключён: %s", g_pl[i].id, g_pl[i].why ? g_pl[i].why : "—");
                return buf;
            }
    char *sid = seed_kind_plugin(name);
    if (!sid) return NULL;
    /* id — строка реестра, если плагин стоит; иначе — своя копия на время процесса (её отдают вызывающим). */
    const struct plugin *p = plugin_find(sid);
    static char *g_seed_id;
    if (p) { if (id) *id = p->id; }
    else { free(g_seed_id); g_seed_id = sid; sid = NULL; if (id) *id = g_seed_id; }
    if (p && !p->enabled) snprintf(buf, n, "плагин %s отключён: %s", p->id, p->why ? p->why : "—");
    else snprintf(buf, n, "нужен плагин %s — поставить", p ? p->id : g_seed_id);
    free(sid);
    return buf;
}

/* ---- ключи вида по схеме -------------------------------------------------------------------
 *
 * Подмножество JSON Schema (schema/kind-keys.schema.json плагинной документации): type, enum, const,
 * default, pattern (POSIX ERE), minLength/maxLength, minimum/maximum, items, minItems/maxItems,
 * uniqueItems, properties, required, additionalProperties (false/true) и расширения — x-secret,
 * x-path и слова схемы спеки ядра (docs/spec-schema.md): x-ref и x-needs (проверяет разбор),
 * x-one-or-list (одно значение вместо списка), x-when, x-when-set, x-example (подсказки форме,
 * разбор их не применяет; x-plugin ставит само ядро, автор не пишет). Ядро проверяет само, без сторонней библиотеки. Ключевое слово вне списка —
 * ошибка схемы, а не молчаливый пропуск: схему пишет автор плагина, и «не действует» хуже отказа.
 *
 * Результат — keys_json: JSON-объект ключей с умолчаниями схемы, значения напечатаны по типу СХЕМЫ
 * («5» у type: string остаётся строкой, у integer — числом), пути x-path абсолютные. x-secret ядро
 * здесь ничем не помечает: keys_json лежит в спеке и уходит помощнику в {conf} (файл 0600); в status,
 * diag и журнал ключи вида не печатаются вовсе (kind_ops.status плагина их не выводит).
 *
 * Отказ — err_set без места: сообщение начинается с пути ключа внутри выхода («nodes[1]: …»), место в
 * тексте спеки — узел *at, который вызывающий отдаёт ynode_err. */
struct sch {
    const char *etc, *conf;
    struct err *e;
    const struct ynode *at;
    struct sbuf *out;
};

static const char *const SCH_WORDS[] = {
    "$schema", "$id", "title", "description", "type", "enum", "const", "default", "pattern",
    "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "uniqueItems", "items",
    "properties", "required", "additionalProperties", "x-secret", "x-path",
    "x-ref", "x-one-or-list", "x-when", "x-when-set", "x-needs", "x-example", "x-watch", NULL
};

/* Разделы спеки, на которые может указывать x-ref (те же, что у ключей ядра, v2keys.h: ref). */
static const char *const REF_SECTIONS[] = { "outputs", "lists", "clients", "dns.upstreams", NULL };

__attribute__((format(printf, 5, 6)))
static int sch_fail(struct sch *c, const struct ynode *at, const char *path, const char *code, const char *fmt, ...) {
    char msg[800];
    struct err t;
    va_list ap;
    va_start(ap, fmt);
    err_vsetc(&t, code, fmt, ap);
    va_end(ap);
    snprintf(msg, sizeof(msg), "%s%s%.700s", path, *path ? ": " : "", t.msg);
    c->at = at;
    err_set(c->e, "%s", msg);
    snprintf(c->e->code, sizeof(c->e->code), "%s", code);
    snprintf(c->e->args, sizeof(c->e->args), "%s", t.args);
    if (*path) err_args_add(c->e->args, sizeof(c->e->args), "path", path);
    return -1;
}

static int type_has(const struct ynode *ty, const char *name) {
    if (!ty) return 0;
    if (ty->kind == YN_SCALAR) return !strcmp(ty->str, name);
    for (size_t i = 0; i < ynode_len(ty); i++) if (!strcmp(ynode_at(ty, i)->str, name)) return 1;
    return 0;
}

static int is_plain_num(const struct ynode *v, int integer) {
    long l;
    if (v->kind != YN_SCALAR || v->style != YS_PLAIN) return 0;
    if (ynode_long(v, &l) == 0) return 1;
    if (integer || !*v->str) return 0;
    char *end;
    strtod(v->str, &end);
    return !*end;
}

/* Значение скаляра v как JSON по типу t ("string", "integer", "number", "boolean", "null"). */
static void sch_scalar_json(struct sbuf *b, const struct ynode *v, const char *t) {
    if (!strcmp(t, "string")) { sb_json(b, v->str); return; }
    if (!strcmp(t, "boolean")) { int x = 0; ynode_bool(v, &x); sb_str(b, x ? "true" : "false"); return; }
    if (!strcmp(t, "null")) { sb_str(b, "null"); return; }
    sb_str(b, v->str);              /* integer, number */
}

/* Какой тип у скаляра без type в схеме: по записи (как строки JSON без кавычек читает YAML). */
static const char *scalar_infer(const struct ynode *v) {
    int x;
    if (v->style != YS_PLAIN) return "string";
    if (ynode_is_null(v)) return "null";
    if (ynode_bool(v, &x) == 0) return "boolean";
    if (is_plain_num(v, 1)) return "integer";
    if (is_plain_num(v, 0)) return "number";
    return "string";
}

static int sch_node(struct sch *c, const struct ynode *sch, const struct ynode *v, const char *path);

/* Сравнение значений по ключевому слову enum/const: скаляр против скаляра строкой записи. */
static int scalar_eq(const struct ynode *a, const struct ynode *b) {
    return a->kind == YN_SCALAR && b->kind == YN_SCALAR && !strcmp(a->str, b->str);
}

/* Список строк: x-when-set, значения x-when и x-needs, also у x-ref. */
static int str_list_ok(const struct ynode *n, int nonempty) {
    if (!n || n->kind != YN_SEQ || (nonempty && !ynode_len(n))) return 0;
    for (size_t i = 0; i < ynode_len(n); i++)
        if (ynode_at(n, i)->kind != YN_SCALAR) return 0;
    return 1;
}

/* Отображение «значение → [соседи]»: x-when и x-needs. */
static int word_map_ok(struct sch *c, const struct ynode *w, const char *path, const char *word) {
    if (!w || w->kind != YN_MAP)
        return sch_fail(c, w, path, "schema.word_map", "%s в схеме вида — отображение «значение: [ключи]»", word);
    for (size_t i = 0; i < ynode_len(w); i++)
        if (!str_list_ok(ynode_val_at(w, i), 1))
            return sch_fail(c, ynode_val_at(w, i), path, "schema.word_list", "%s: у «%s» нужен список строк", word,
                            ynode_key_at(w, i)->str);
    return 0;
}

static int sch_words_ok(struct sch *c, const struct ynode *sch, const char *path) {
    for (size_t i = 0; i < ynode_len(sch); i++) {
        const char *k = ynode_key_at(sch, i)->str;
        size_t w = 0;
        while (SCH_WORDS[w] && strcmp(SCH_WORDS[w], k)) w++;
        if (!SCH_WORDS[w])
            return sch_fail(c, ynode_key_at(sch, i), path, "schema.unsupported_word", "в схеме вида ключевое слово «%s» не поддерживается", k);
    }
    const struct ynode *xr = ynode_get(sch, "x-ref");
    if (xr) {
        const struct ynode *sec = xr->kind == YN_MAP ? ynode_get(xr, "section") : NULL;
        const struct ynode *also = xr->kind == YN_MAP ? ynode_get(xr, "also") : NULL;
        size_t w = 0;
        while (sec && sec->kind == YN_SCALAR && REF_SECTIONS[w] && strcmp(REF_SECTIONS[w], sec->str)) w++;
        if (!sec || sec->kind != YN_SCALAR || !REF_SECTIONS[w])
            return sch_fail(c, xr, path, "schema.xref_form", "x-ref — {section: outputs, lists, clients или dns.upstreams}");
        if (also && !str_list_ok(also, 0))
            return sch_fail(c, also, path, "schema.xref_also", "x-ref.also — список слов");
        for (size_t i = 0; i < ynode_len(xr); i++) {
            const char *k = ynode_key_at(xr, i)->str;
            if (strcmp(k, "section") && strcmp(k, "also"))
                return sch_fail(c, ynode_key_at(xr, i), path, "schema.xref_key", "в x-ref ключа «%s» нет (есть: section, also)", k);
        }
    }
    const struct ynode *ol = ynode_get(sch, "x-one-or-list");
    int olv;
    if (ol && ynode_bool(ol, &olv) != 0)
        return sch_fail(c, ol, path, "schema.one_or_list_bool", "x-one-or-list — true или false");
    if (ol && olv && !type_has(ynode_get(sch, "type"), "array"))
        return sch_fail(c, ol, path, "schema.one_or_list_array", "x-one-or-list — у массива (type: array)");
    const struct ynode *wh = ynode_get(sch, "x-when"), *ws = ynode_get(sch, "x-when-set");
    if (wh && word_map_ok(c, wh, path, "x-when")) return -1;
    if (ws && !str_list_ok(ws, 1)) return sch_fail(c, ws, path, "schema.when_set_list", "x-when-set — список ключей-соседей");
    const struct ynode *nd = ynode_get(sch, "x-needs");
    if (nd && word_map_ok(c, nd, path, "x-needs")) return -1;
    return 0;
}

static int sch_path(struct sch *c, const struct ynode *sch, const struct ynode *v, const char *path,
                    struct sbuf *dst) {
    const char *xp = m_str(sch, "x-path");
    char abs[PATH_MAX];
    const char *s = v->str;
    if (!strcmp(xp, "abs")) {
        if (s[0] != '/') return sch_fail(c, v, path, "schema.abs_path", "«%s» — нужен абсолютный путь файла", s);
        snprintf(abs, sizeof(abs), "%s", s);
    } else if (s[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", s);
    } else if (!strcmp(xp, "etc")) {
        snprintf(abs, sizeof(abs), "%s/%s", c->etc, s);
    } else if (!strcmp(xp, "conf")) {
        snprintf(abs, sizeof(abs), "%s/%s", c->conf, s);
    } else {
        return sch_fail(c, sch, path, "schema.xpath_word", "x-path — etc, conf или abs, а не «%s»", xp);
    }
    sb_json(dst, abs);
    return 0;
}

static int sch_node(struct sch *c, const struct ynode *sch, const struct ynode *v, const char *path) {
    if (!sch || sch->kind != YN_MAP) return sch_fail(c, sch, path, "schema.object_needed", "схема вида: нужен объект");
    if (sch_words_ok(c, sch, path)) return -1;
    const struct ynode *ty = ynode_get(sch, "type");
    char np[256];
    /* ---- тип и значение ---- */
    if (v->kind == YN_MAP) {
        if (ty && !type_has(ty, "object")) return sch_fail(c, v, path, "schema.value_not_map", "здесь нужно значение, а не отображение");
        const struct ynode *props = ynode_get(sch, "properties");
        const struct ynode *ap = ynode_get(sch, "additionalProperties");
        int extra_ok = 1, abv;
        if (ap && ynode_bool(ap, &abv) == 0) extra_ok = abv;
        const struct ynode *req = ynode_get(sch, "required");
        for (size_t i = 0; req && i < ynode_len(req); i++)
            if (!ynode_get(v, ynode_at(req, i)->str))
                return sch_fail(c, v, path, "schema.required_key", "нет обязательного ключа %s", ynode_at(req, i)->str);
        /* x-needs: при этом значении ключа без этих соседей разбор отказывает; "*" — при любом. Условия
         * x-when и x-when-set разбор не применяет — это подсказки форме. */
        for (size_t i = 0; i < ynode_len(v); i++) {
            const struct ynode *k = ynode_key_at(v, i), *val = ynode_val_at(v, i);
            const struct ynode *nd = ynode_get(ynode_get(props, k->str), "x-needs");
            if (!nd || val->kind != YN_SCALAR) continue;
            const struct ynode *need = ynode_get(nd, val->str);
            if (!need) need = ynode_get(nd, "*");
            for (size_t j = 0; need && j < ynode_len(need); j++) {
                const char *nb = ynode_at(need, j)->str;
                if (ynode_get(v, nb)) continue;
                snprintf(np, sizeof(np), "%s%s%s", path, *path ? "." : "", k->str);
                return sch_fail(c, val, np, "schema.needs_key", "%s: %s — без ключа %s он не разобран", k->str,
                                !ynode_get(nd, val->str) ? "при любом значении" : val->str, nb);
            }
        }
        sb_str(c->out, "{");
        size_t put = 0;
        for (size_t i = 0; i < ynode_len(v); i++) {
            const struct ynode *k = ynode_key_at(v, i), *val = ynode_val_at(v, i);
            const struct ynode *ps = ynode_get(props, k->str);
            snprintf(np, sizeof(np), "%s%s%s", path, *path ? "." : "", k->str);
            if (!ps) {
                if (!extra_ok) {
                    char list[300] = "";
                    size_t l = 0;
                    for (size_t j = 0; j < ynode_len(props) && l + 40 < sizeof(list); j++)
                        l += (size_t)snprintf(list + l, sizeof(list) - l, "%s%s", j ? ", " : "", ynode_key_at(props, j)->str);
                    if (list[0])
                        return sch_fail(c, k, *path ? path : "", "schema.unknown_key_list", "неизвестный ключ «%s» (есть: %s)",
                                        k->str, list);
                    return sch_fail(c, k, *path ? path : "", "schema.unknown_key", "неизвестный ключ «%s»", k->str);
                }
            }
            if (put++) sb_str(c->out, ",");
            sb_json(c->out, k->str);
            sb_str(c->out, ":");
            if (ps) { if (sch_node(c, ps, val, np)) return -1; }
            else {
                /* Ключ без схемы при additionalProperties: true — как записан. */
                if (val->kind != YN_SCALAR) return sch_fail(c, val, np, "schema.simple_value", "для ключа без схемы нужно простое значение");
                sch_scalar_json(c->out, val, scalar_infer(val));
            }
        }
        /* Умолчания схемы для отсутствующих ключей. */
        for (size_t i = 0; props && i < ynode_len(props); i++) {
            const struct ynode *pk = ynode_key_at(props, i), *ps = ynode_val_at(props, i);
            const struct ynode *df = ynode_get(ps, "default");
            if (ynode_get(v, pk->str) || !df) continue;
            if (put++) sb_str(c->out, ",");
            sb_json(c->out, pk->str);
            sb_str(c->out, ":");
            if (df->kind == YN_SCALAR) {
                const struct ynode *pt = ynode_get(ps, "type");
                const char *t = pt && pt->kind == YN_SCALAR ? pt->str : scalar_infer(df);
                if (ynode_get(ps, "x-path")) {
                    if (sch_path(c, ps, df, np, c->out)) return -1;
                } else sch_scalar_json(c->out, df, t);
            } else sb_str(c->out, df->kind == YN_SEQ ? "[]" : "{}");
        }
        sb_str(c->out, "}");
        return 0;
    }
    if (v->kind == YN_SEQ) {
        if (ty && !type_has(ty, "array")) return sch_fail(c, v, path, "schema.value_not_list", "здесь нужно значение, а не список");
        const struct ynode *mn = ynode_get(sch, "minItems"), *mx = ynode_get(sch, "maxItems");
        long l;
        if (mn && ynode_long(mn, &l) == 0 && (long)v->len < l)
            return sch_fail(c, v, path, "schema.list_min", "в списке %zu элементов, а нужно не меньше %ld", v->len, l);
        if (mx && ynode_long(mx, &l) == 0 && (long)v->len > l)
            return sch_fail(c, v, path, "schema.list_max", "в списке %zu элементов, а можно не больше %ld", v->len, l);
        const struct ynode *items = ynode_get(sch, "items");
        const struct ynode *uq = ynode_get(sch, "uniqueItems");
        int uniq = 0;
        if (uq) ynode_bool(uq, &uniq);
        sb_str(c->out, "[");
        for (size_t i = 0; i < v->len; i++) {
            const struct ynode *it = ynode_at(v, i);
            snprintf(np, sizeof(np), "%s[%zu]", path, i);
            if (uniq)
                for (size_t j = 0; j < i; j++)
                    if (scalar_eq(it, ynode_at(v, j))) return sch_fail(c, it, np, "schema.list_dup", "«%s» уже есть в списке", it->str);
            if (i) sb_str(c->out, ",");
            if (items) { if (sch_node(c, items, it, np)) return -1; }
            else if (it->kind == YN_SCALAR) sch_scalar_json(c->out, it, scalar_infer(it));
            else return sch_fail(c, it, np, "schema.list_simple", "для списка без схемы нужны простые значения");
        }
        sb_str(c->out, "]");
        return 0;
    }
    /* x-one-or-list: одно значение вместо списка из одного элемента (как у ключей ядра). */
    if (v->kind == YN_SCALAR) {
        const struct ynode *ol = ynode_get(sch, "x-one-or-list");
        int olv = 0;
        if (ol && ynode_bool(ol, &olv) == 0 && olv) {
            const struct ynode *mn = ynode_get(sch, "minItems");
            long l;
            if (mn && ynode_long(mn, &l) == 0 && l > 1)
                return sch_fail(c, v, path, "schema.list_min_one", "в списке 1 элемент, а нужно не меньше %ld", l);
            const struct ynode *items = ynode_get(sch, "items");
            snprintf(np, sizeof(np), "%s[0]", path);
            sb_str(c->out, "[");
            if (items) { if (sch_node(c, items, v, np)) return -1; }
            else sch_scalar_json(c->out, v, scalar_infer(v));
            sb_str(c->out, "]");
            return 0;
        }
    }
    /* скаляр */
    const char *want = NULL;          /* тип, которым скаляр печатается */
    if (ty) {
        static const char *const ORD[] = { "boolean", "integer", "number", "null", "string", NULL };
        for (size_t i = 0; ORD[i] && !want; i++) {
            if (!type_has(ty, ORD[i])) continue;
            if (!strcmp(ORD[i], "string")) { if (!(v->style == YS_PLAIN && ynode_is_null(v))) want = "string"; }
            else if (!strcmp(ORD[i], "boolean")) { int x; if (v->style == YS_PLAIN && ynode_bool(v, &x) == 0) want = "boolean"; }
            else if (!strcmp(ORD[i], "integer")) { if (is_plain_num(v, 1)) want = "integer"; }
            else if (!strcmp(ORD[i], "number")) { if (is_plain_num(v, 0)) want = "number"; }
            else if (!strcmp(ORD[i], "null")) { if (v->style == YS_PLAIN && ynode_is_null(v)) want = "null"; }
        }
        if (!want) {
            const char *t = ty->kind == YN_SCALAR ? ty->str : ynode_at(ty, 0)->str;
            const char *what = !strcmp(t, "integer") ? "целое число" : !strcmp(t, "number") ? "число" :
                               !strcmp(t, "boolean") ? "true или false" : !strcmp(t, "string") ? "строка" :
                               !strcmp(t, "null") ? "пусто" : "значение";
            return sch_fail(c, v, path, "schema.need_what", "«%s» — нужно: %s", v->str, what);
        }
    } else want = scalar_infer(v);
    /* ---- ограничения ---- */
    const struct ynode *en = ynode_get(sch, "enum");
    if (en) {
        int found = 0;
        for (size_t i = 0; i < ynode_len(en); i++) if (scalar_eq(v, ynode_at(en, i))) found = 1;
        if (!found) {
            char list[300] = "";
            size_t l = 0;
            for (size_t i = 0; i < ynode_len(en) && l + 40 < sizeof(list); i++)
                l += (size_t)snprintf(list + l, sizeof(list) - l, "%s%s", i ? ", " : "", ynode_at(en, i)->str);
            return sch_fail(c, v, path, "schema.need_one_of", "«%s» — нужно одно из: %s", v->str, list);
        }
    }
    const struct ynode *cs = ynode_get(sch, "const");
    if (cs && !scalar_eq(v, cs)) return sch_fail(c, v, path, "schema.need_const", "«%s» — нужно «%s»", v->str, cs->str);
    long lim;
    const struct ynode *l;
    if ((!strcmp(want, "string")) ) {
        size_t len = 0;
        for (const char *q = v->str; *q; q++) if (((unsigned char)*q & 0xC0) != 0x80) len++;
        if ((l = ynode_get(sch, "minLength")) && ynode_long(l, &lim) == 0 && (long)len < lim)
            return sch_fail(c, v, path, "schema.too_short", "короче %ld знаков", lim);
        if ((l = ynode_get(sch, "maxLength")) && ynode_long(l, &lim) == 0 && (long)len > lim)
            return sch_fail(c, v, path, "schema.too_long", "длиннее %ld знаков", lim);
        const char *pat = m_str(sch, "pattern");
        if (pat) {
            regex_t re;
            int rc = regcomp(&re, pat, REG_EXTENDED | REG_NOSUB);
            if (rc != 0) return sch_fail(c, sch, path, "schema.bad_pattern", "pattern «%s» схемы не разобран", pat);
            rc = regexec(&re, v->str, 0, NULL, 0);
            regfree(&re);
            if (rc != 0) return sch_fail(c, v, path, "schema.pattern_mismatch", "«%s» не подходит под %s", v->str, pat);
        }
    }
    if (!strcmp(want, "integer") || !strcmp(want, "number")) {
        double dv = strtod(v->str, NULL);
        if ((l = ynode_get(sch, "minimum")) && dv < strtod(l->str, NULL))
            return sch_fail(c, v, path, "schema.below_min", "%s — меньше допустимого %s", v->str, l->str);
        if ((l = ynode_get(sch, "maximum")) && dv > strtod(l->str, NULL))
            return sch_fail(c, v, path, "schema.above_max", "%s — больше допустимого %s", v->str, l->str);
    }
    if (ynode_get(sch, "x-path")) {
        if (strcmp(want, "string")) return sch_fail(c, sch, path, "schema.xpath_string", "x-path — у строки");
        return sch_path(c, sch, v, path, c->out);
    }
    sch_scalar_json(c->out, v, want);
    return 0;
}

/* ---- x-ref: имена из разделов спеки ---------------------------------------------------------
 * Разделы читаются после всей спеки (ключ выхода может назвать выход, список или апстрим, что ниже
 * по тексту), поэтому проверка ссылок — отдельный проход: plugin_keys_refs, его зовёт разбор спеки,
 * когда все разделы уже есть. Слова also из x-ref законны вместо имени. */
struct refw {
    plugin_ref_fn has;
    void *ctx;
    struct err *e;
    const struct ynode *at;
};

static int refs_node(struct refw *r, const struct ynode *sch, const struct ynode *v, const char *path) {
    if (!sch || sch->kind != YN_MAP) return 0;
    char np[256];
    if (v->kind == YN_MAP) {
        const struct ynode *props = ynode_get(sch, "properties");
        for (size_t i = 0; props && i < ynode_len(v); i++) {
            const struct ynode *ps = ynode_get(props, ynode_key_at(v, i)->str);
            if (!ps) continue;
            snprintf(np, sizeof(np), "%s%s%s", path, *path ? "." : "", ynode_key_at(v, i)->str);
            if (refs_node(r, ps, ynode_val_at(v, i), np)) return -1;
        }
        return 0;
    }
    if (v->kind == YN_SEQ) {
        const struct ynode *items = ynode_get(sch, "items");
        for (size_t i = 0; items && i < ynode_len(v); i++) {
            snprintf(np, sizeof(np), "%s[%zu]", path, i);
            if (refs_node(r, items, ynode_at(v, i), np)) return -1;
        }
        return 0;
    }
    const struct ynode *xr = ynode_get(sch, "x-ref");
    if (!xr) {      /* одно значение вместо списка: ссылка стоит на items */
        const struct ynode *items = ynode_get(sch, "items");
        if (items && v->kind == YN_SCALAR) return refs_node(r, items, v, path);
        return 0;
    }
    const char *sec = m_str(xr, "section");
    const struct ynode *also = ynode_get(xr, "also");
    for (size_t i = 0; also && i < ynode_len(also); i++)
        if (!strcmp(ynode_at(also, i)->str, v->str)) return 0;
    if (sec && r->has(r->ctx, sec, v->str)) return 0;
    char list[200] = "";
    size_t l = 0;
    for (size_t i = 0; also && i < ynode_len(also) && l + 40 < sizeof(list); i++)
        l += (size_t)snprintf(list + l, sizeof(list) - l, "%s%s", i ? ", " : "", ynode_at(also, i)->str);
    r->at = v;
    if (list[0])
        err_setf(r->e, "schema.ref_missing_also", "«%s» — в разделе %s такой записи нет (и это не %s)", v->str,
                 sec ? sec : "?", list);
    else
        err_setf(r->e, "schema.ref_missing", "«%s» — в разделе %s такой записи нет", v->str, sec ? sec : "?");
    /* Путь ключа — спереди, как у отказов схемы (подстановка "path"). */
    {
        char msg[sizeof(r->e->msg)];
        snprintf(msg, sizeof(msg), "%s: %.900s", path, r->e->msg);
        snprintf(r->e->msg, sizeof(r->e->msg), "%s", msg);
        if (*path) err_args_add(r->e->args, sizeof(r->e->args), "path", path);
    }
    return -1;
}

int plugin_keys_refs(const struct plugin_kind *pk, const struct ynode *keys, plugin_ref_fn has, void *ctx,
                     const struct ynode **at, struct err *e) {
    struct refw r = { .has = has, .ctx = ctx, .e = e };
    if (at) *at = NULL;
    if (!pk->schema || !keys) return 0;
    if (refs_node(&r, pk->schema, keys, "") != 0) {
        if (at) *at = r.at;
        return -1;
    }
    return 0;
}

void plugin_node_json(struct sbuf *b, const struct ynode *n) {
    if (n->kind == YN_SCALAR) {
        const char *t = scalar_infer(n);
        if (!strcmp(t, "integer") || !strcmp(t, "number")) sb_str(b, n->str);
        else if (!strcmp(t, "boolean")) sb_str(b, !strcmp(n->str, "true") || !strcmp(n->str, "True") || !strcmp(n->str, "TRUE") ? "true" : "false");
        else if (!strcmp(t, "null")) sb_str(b, "null");
        else sb_json(b, n->str);
    } else if (n->kind == YN_SEQ) {
        sb_str(b, "[");
        for (size_t i = 0; i < n->len; i++) { if (i) sb_str(b, ","); plugin_node_json(b, ynode_at(n, i)); }
        sb_str(b, "]");
    } else {
        sb_str(b, "{");
        for (size_t i = 0; i < ynode_len(n); i++) {
            if (i) sb_str(b, ",");
            sb_json(b, ynode_key_at(n, i)->str);
            sb_str(b, ":");
            plugin_node_json(b, ynode_val_at(n, i));
        }
        sb_str(b, "}");
    }
}

int plugin_keys_raw(const struct ynode *keys, char **json) {
    struct sbuf b = { 0 };
    plugin_node_json(&b, keys);
    if (b.oom || !b.p) { free(b.p); return -1; }
    *json = b.p;
    return 0;
}

int plugin_keys_check(const struct plugin_kind *pk, const struct ynode *keys, const char *etc,
                      const char *conf, char **json, const struct ynode **at, struct err *e) {
    struct sbuf b = { 0 };
    struct sch c = { .etc = etc, .conf = conf, .e = e, .out = &b };
    *json = NULL;
    if (at) *at = NULL;
    int rc;
    if (!pk->schema) {
        /* Схемы нет — у вида нет ключей: любой — отказ, как у вида ядра без ключа. */
        if (keys && ynode_len(keys)) {
            c.at = ynode_key_at(keys, 0);
            rc = err_setf(e, "schema.kind_has_no_keys", "неизвестный ключ «%s» — у вида %s ключей нет",
                          ynode_key_at(keys, 0)->str, pk->name);
            if (at) *at = c.at;
            return rc;
        }
        sb_str(&b, "{}");
    } else {
        static const struct ynode EMPTY = { .kind = YN_MAP };
        rc = sch_node(&c, pk->schema, keys ? keys : &EMPTY, "");
        if (rc != 0) {
            free(b.p);
            if (at) *at = c.at;
            return -1;
        }
    }
    if (b.oom || !b.p) { free(b.p); return err_set(e, "%s", "недостаточно памяти для ключей вида"); }
    *json = b.p;
    return 0;
}

/* ---- подстановки для хуков ---- */
static char *subst(const struct plugin *pl, const struct spec *sp, const struct output *o,
                   const char *oname, const char *s, char *why, size_t wn);
char *plugin_subst(const struct plugin *pl, const char *out_name, const char *s, char *why, size_t wn) {
    return subst(pl, NULL, NULL, out_name, s, why, wn);
}

/* ---- окружение программ плагина (steer-api.md, 1.2) --------------------------------------------- */

static void env_put(const char *k, const char *v) { setenv(k, v, 1); }
static void plugin_env(const struct plugin *pl, const struct plugin_prog *p);
void plugin_env_set(const struct plugin *pl, const struct plugin_prog *p) { plugin_env(pl, p); }

/* Окружение каждой программы плагина: версии, каталоги, платформа. Переменные из env манифеста
 * ставятся после и не заменяют эти. */
static void plugin_env(const struct plugin *pl, const struct plugin_prog *p) {
    char buf[2 * PATH_MAX], etc[PATH_MAX];
    env_put("STEER_API", STEER_API_VERSION);
    env_put("STEER_CORE_VERSION", steer_engine_version());
    env_put("STEER_PLUGIN_ID", pl->id);
    env_put("STEER_PLUGIN_VERSION", pl->version);
    env_put("STEER_PLUGIN_DIR", pl->dir);
    plugin_etc(etc, sizeof(etc));
    snprintf(buf, sizeof(buf), "%s/conf/%s", etc, pl->id);
    env_put("STEER_PLUGIN_CONF", buf);
    snprintf(buf, sizeof(buf), "%s/plugin/%s", steer_state_dir(), pl->id);
    env_put("STEER_PLUGIN_STATE", buf);
    env_put("STEER_ETC_DIR", plat()->etc_dir);
    env_put("STEER_STATE_DIR", steer_state_dir());
    env_put("STEER_CTL_SOCK", plat()->ctl_sock);
    env_put("STEER_PLATFORM", plat()->name);
    if (pl->builtin) env_put("STEER_PK_BUILTIN", pl->id);
    else unsetenv("STEER_PK_BUILTIN");
    for (size_t i = 0; p && i < p->envc; i++) {
        const char *eq = strchr(p->env[i], '=');
        if (!eq) continue;
        char name[128];
        size_t l = (size_t)(eq - p->env[i]);
        if (l >= sizeof(name) || !strncmp(p->env[i], "STEER_", 6)) continue;
        memcpy(name, p->env[i], l);
        name[l] = '\0';
        env_put(name, eq + 1);
    }
}

/* ---- подстановки (steer-api.md, 1.3) ------------------------------------------------------- */

/* Подстановки в строке s: {out}, {conf}, {plugin_dir}, {plugin_conf}, {plugin_state}, {out_mark},
 * {out_table}, {steer_mask}, {tcp_port}, {mark}/{mark<N>}/{port<N>}/{queue<N>} (ресурсы плагина),
 * {out_port<N>} и {out_queue<N>} (ресурсы выхода); {{ и }} — буквальные скобки. o может быть NULL (подстановки выхода тогда — отказ).
 * Возврат — строка в куче или NULL с причиной в why. */
static char *subst(const struct plugin *pl, const struct spec *sp, const struct output *o,
                   const char *oname, const char *s, char *why, size_t wn) {
    if (o) oname = o->name;
    struct sbuf b = { 0 };
    char etc[PATH_MAX];
    plugin_etc(etc, sizeof(etc));
    for (const char *p = s; *p; p++) {
        if (p[0] == '{' && p[1] == '{') { sb_put(&b, "{", 1); p++; continue; }
        if (p[0] == '}' && p[1] == '}') { sb_put(&b, "}", 1); p++; continue; }
        if (*p != '{') { sb_put(&b, p, 1); continue; }
        /* Подстановка — «{имя}» из строчных букв, цифр и «_» вплотную; всё остальное — буквальная
         * скобка: множество nft «{ 443, 80 }» проходит как есть. */
        const char *e = p + 1;
        while (islower((unsigned char)*e) || isdigit((unsigned char)*e) || *e == '_') e++;
        if (e == p + 1 || *e != '}') { sb_put(&b, p, 1); continue; }
        char name[48];
        size_t l = (size_t)(e - p - 1);
        if (l >= sizeof(name)) { snprintf(why, wn, "в «%s» неизвестная подстановка", s); free(b.p); return NULL; }
        memcpy(name, p + 1, l);
        name[l] = '\0';
        p = e;
        if (!strcmp(name, "plugin_dir")) sb_str(&b, pl->dir);
        else if (!strcmp(name, "plugin_conf")) sb_printf(&b, "%s/conf/%s", etc, pl->id);
        else if (!strcmp(name, "plugin_state")) sb_printf(&b, "%s/plugin/%s", steer_state_dir(), pl->id);
        else if (!strcmp(name, "steer_mask")) sb_printf(&b, "0x%08x", plat()->mark_mask);
        else if (oname && !strcmp(name, "out")) sb_str(&b, oname);
        else if (oname && !strcmp(name, "conf")) sb_printf(&b, "%s/plugin/%s/%s.json", steer_state_dir(), pl->id, oname);
        else if (o && !strcmp(name, "out_mark")) sb_printf(&b, "0x%08x", o->mark);
        else if (o && !strcmp(name, "out_table")) sb_printf(&b, "%d", o->table);
        else if (o && !strcmp(name, "tcp_port")) sb_printf(&b, "%d", out_tcp_port(o));
        else if (o && !strncmp(name, "out_port", 8) && isdigit((unsigned char)name[8])) {
            size_t i = (size_t)atoi(name + 8);
            if (!kind_of(o)->plugin || i >= o->plg.ports_n) {
                snprintf(why, wn, "{%s}: у выхода %s нет порта с номером %zu", name, o->name, i);
                free(b.p);
                return NULL;
            }
            sb_printf(&b, "%u", o->plg.ports[i]);
        } else if (o && !strncmp(name, "out_queue", 9) && isdigit((unsigned char)name[9])) {
            size_t i = (size_t)atoi(name + 9);
            if (!kind_of(o)->plugin || i >= o->plg.queues_n) {
                snprintf(why, wn, "{%s}: у выхода %s нет очереди с номером %zu", name, o->name, i);
                free(b.p);
                return NULL;
            }
            sb_printf(&b, "%u", o->plg.queues[i]);
        } else if (!strcmp(name, "mark") || ((!strncmp(name, "mark", 4) || !strncmp(name, "queue", 5) ||
                                              !strncmp(name, "port", 4)) && isdigit((unsigned char)name[strlen(name) - 1]))) {
            /* Ресурсы плагина (resources манифеста): выданы при подготовке спеки, alloc.json. */
            struct plugin_res r;
            if (plugin_res_get(pl, &r) != 0) {
                snprintf(why, wn, "{%s}: ресурсы плагина не выданы — нужен reload", name);
                free(b.p);
                return NULL;
            }
            int bad = 0;
            if (!strcmp(name, "mark")) {
                uint32_t m = 0;
                for (size_t i = 0; i < r.bits_n; i++) m |= 1u << r.bits[i];
                if (!r.bits_n) bad = 1;
                else sb_printf(&b, "0x%08x", m);
            } else {
                int dl = !strncmp(name, "mark", 4) ? 4 : !strncmp(name, "queue", 5) ? 5 : 4;
                size_t i = (size_t)atoi(name + dl);
                if (!strncmp(name, "mark", 4)) { if (i >= r.bits_n) bad = 1; else sb_printf(&b, "0x%08x", 1u << r.bits[i]); }
                else if (!strncmp(name, "queue", 5)) { if (i >= r.queues_n) bad = 1; else sb_printf(&b, "%u", r.queues[i]); }
                else { if (i >= r.ports_n) bad = 1; else sb_printf(&b, "%u", r.ports[i]); }
            }
            plugin_res_free(&r);
            if (bad) {
                snprintf(why, wn, "{%s}: у плагина %s нет такого ресурса (resources манифеста)", name, pl->id);
                free(b.p);
                return NULL;
            }
        } else {
            snprintf(why, wn, "неизвестная подстановка {%s}", name);
            free(b.p);
            return NULL;
        }
    }
    (void)sp;
    if (b.oom) { free(b.p); snprintf(why, wn, "нет памяти"); return NULL; }
    if (!b.p) b.p = strdup("");
    return b.p;
}

/* ---- вид плагина: kind_ops ------------------------------------------------------------------- */

/* Свойства, которые зависят от настройки выхода, у вида плагина не бывают: caps из манифеста. */

static int plg_parse(struct output *o, const struct out_keys *k, struct err *e) {
    if (k->devices_n)
        return err_set(e, "outputs.%s: у kind плагина нет списка устройств", o->name);
    /* Устройство — ключ `device` (общий) или выведенное по правилу awg: имя не должно выдавать
     * туннель. */
    if ((kind_of(o)->caps & KC_DEVICE) && !o->device[0])
        awg_default_ifname(o->name, o->device, sizeof(o->device));
    return 0;
}

static void plg_keys_of(const struct output *o, struct out_keys *k) {
    (void)o; (void)k;           /* ключи вида печатает v2print из keys_json */
}

/* ---- файл настройки выхода {conf} (steer-api.md, 1.4) ------------------------------------------
 *
 * Помощник плагина спеку не читает и с libsteer не связан: всё, что ему нужно знать о своём выходе
 * (ключи по схеме, устройство, метка, таблица, подложка, метка сокетов, порты и очереди), ядро кладёт
 * в этот файл перед запуском. Хеш его содержимого — часть подписи перезапуска помощника: сменилось
 * что-то из этого — помощник гасится и поднимается сразу. */
const struct plugin_kind *plugin_helper_kind(const struct output *o) {
    const struct plugin_kind *pk = out_plugin_kind(o);
    if (pk) return pk->helper.prog ? pk : NULL;
    if (!o->owner_plugin || !o->owner_out || strcmp(o->owner_out, o->name) != 0) return NULL;
    const struct plugin *pl = plugin_find(o->owner_plugin);
    for (size_t i = 0; pl && pl->enabled && i < pl->kind_n; i++)
        if (pl->kind[i]->expand.prog && pl->kind[i]->helper.prog) return pl->kind[i];
    return NULL;
}

char *plugin_conf_json(const struct spec *sp, const struct output *o, const struct plugin_kind *pk) {
    const struct plugin *pl = pk->owner;
    struct sbuf b = { 0 };
    char etc[PATH_MAX];
    plugin_etc(etc, sizeof(etc));
    sb_str(&b, "{\"api\":\"" STEER_API_VERSION "\",\"plugin\":{\"id\":");
    sb_json(&b, pl->id);
    sb_str(&b, ",\"version\":");
    sb_json(&b, pl->version);
    sb_str(&b, "},\"output\":{\"name\":");
    sb_json(&b, o->name);
    /* Развёрнутый выход с помощником (owner — он сам): вид и ключи — те, с которыми его записал
     * человек и получил разворот (owner.kind, owner.keys), а не группа, которой он стал. */
    int self_owned = !out_plugin_kind(o) && o->owner_out && !strcmp(o->owner_out, o->name);
    sb_str(&b, ",\"kind\":");
    sb_json(&b, out_plugin_kind(o) ? pk->name : self_owned && o->owner_kind ? o->owner_kind : kind_of(o)->name);
    sb_str(&b, ",\"keys\":");
    const char *kj = out_plugin_keys(o);
    if (!kj && self_owned) kj = o->owner_keys;
    char *ck = NULL;
    size_t ckn = 0;
    /* У выхода вида ядра (помощник от плагина, impl: core) ключи вида печатает сам вид. */
    if (!kj && kind_of(o)->conf_keys) {
        FILE *m = open_memstream(&ck, &ckn);
        if (m) { kind_of(o)->conf_keys(m, o); fclose(m); }
        kj = ck;
    }
    sb_str(&b, kj && *kj ? kj : "{}");
    free(ck);
    sb_str(&b, ",\"device\":");
    sb_json(&b, out_has_device(o) ? o->device : "");
    sb_printf(&b, ",\"mark\":\"0x%08x\",\"mark_mask\":\"0x%08x\",\"table\":%d,\"ipv6\":%s", o->mark,
              plat()->mark_mask, o->table, out_route6(o) ? "true" : "false");
    sb_printf(&b, ",\"on_fail\":\"%s\"", o->on_fail == FAIL_DROP ? "drop" : o->on_fail == FAIL_ZAPRET ? "zapret" : "direct");
    const struct output *over = o->over[0] ? out_over(sp, o) : NULL;
    if (over) {
        sb_str(&b, ",\"over\":{\"name\":");
        sb_json(&b, over->name);
        sb_printf(&b, ",\"mark\":\"0x%08x\"}", over->mark);
    } else sb_str(&b, ",\"over\":null");
    sb_printf(&b, ",\"sock_mark\":\"0x%08x\",\"sock_mark_required\":%s,\"tcp_port\":%d", out_underlay_mark(sp, o),
              o->over[0] ? "true" : "false", (out_caps(o) & KC_TCP_REDIR) ? out_tcp_port(o) : 0);
    sb_str(&b, ",\"ports\":[");
    for (size_t i = 0; out_plugin_kind(o) && i < o->plg.ports_n; i++) sb_printf(&b, "%s%u", i ? "," : "", o->plg.ports[i]);
    sb_str(&b, "],\"queues\":[");
    for (size_t i = 0; out_plugin_kind(o) && i < o->plg.queues_n; i++) sb_printf(&b, "%s%u", i ? "," : "", o->plg.queues[i]);
    sb_str(&b, "]");
    /* Члены развёрнутого выхода (steer-api.md, 1.4: output.members) — выходы, которые завёл его
     * разворот: помощник ведёт их (member, revive) и должен знать их устройства, метки и таблицы. */
    if (self_owned) {
        sb_str(&b, ",\"members\":[");
        size_t mn = 0;
        for (size_t i = 0; sp && i < sp->out_n; i++) {
            const struct output *m = &sp->out[i];
            if (m == o || !m->owner_plugin || !m->owner_out || strcmp(m->owner_plugin, o->owner_plugin) != 0 ||
                strcmp(m->owner_out, o->name) != 0)
                continue;
            if (mn++) sb_str(&b, ",");
            sb_str(&b, "{\"name\":");
            sb_json(&b, m->name);
            sb_str(&b, ",\"kind\":");
            sb_json(&b, kind_of(m)->name);
            sb_str(&b, ",\"device\":");
            sb_json(&b, out_has_device(m) ? m->device : "");
            sb_printf(&b, ",\"mark\":\"0x%08x\",\"table\":%d,\"ipv6\":%s", m->mark, m->table,
                      out_route6(m) ? "true" : "false");
            sb_str(&b, ",\"over\":");
            if (m->over[0]) sb_json(&b, m->over);
            else sb_str(&b, "null");
            sb_printf(&b, ",\"sock_mark\":\"0x%08x\",\"sock_mark_required\":%s}", out_underlay_mark(sp, m),
                      m->over[0] ? "true" : "false");
        }
        sb_str(&b, "]");
    }
    sb_str(&b, "},\"paths\":{\"etc\":");
    sb_json(&b, plat()->etc_dir);
    /* Таблица fake-IP резолвера (только чтение): по ней туннель плагина узнаёт имя за поддельным адресом
     * (steer-api.md, 1.4, paths.fakeip). Файл пишет резолвер ядра; формат — там же. */
    sb_str(&b, ",\"fakeip\":");
    {
        char fk[PATH_MAX];
        snprintf(fk, sizeof fk, "%s/fakeip.state", steer_state_dir());
        sb_json(&b, fk);
    }
    sb_str(&b, ",\"state\":");
    sb_json(&b, steer_state_dir());
    sb_str(&b, ",\"lists\":");
    sb_json(&b, plat()->lists_dir);
    sb_str(&b, ",\"plugin\":");
    sb_json(&b, pl->dir);
    sb_printf(&b, ",\"conf\":\"%s/conf/%s\",\"plugin_state\":\"%s/plugin/%s\"},\"platform\":", etc, pl->id, steer_state_dir(), pl->id);
    sb_json(&b, plat()->name);
    sb_str(&b, "}\n");
    if (b.oom) { free(b.p); return NULL; }
    return b.p;
}

/* Настройки плагина в подписи перезапуска (steer.settings: "restart", steer-api 1.4): содержимое
 * <etc>/conf/<id>/settings.json; файла нет — свой знак, чтобы появление и удаление файла тоже меняли
 * подпись. Хост пишет файл атомарно (переименованием) и зовёт reload — помощник поднимается сразу,
 * без паузы перезапуска и без слежки за файлом в самом плагине. */
static void settings_sig(const struct plugin *pl, unsigned long long *sig) {
    if (!pl->settings_restart) return;
    char etc[PATH_MAX], path[2 * PATH_MAX];
    plugin_etc(etc, sizeof(etc));
    snprintf(path, sizeof(path), "%s/conf/%s/settings.json", etc, pl->id);
    FILE *f = fopen(path, "r");
    if (!f) { kind_sig_mix(sig, "settings:-", 10); return; }
    kind_sig_mix(sig, "settings:", 9);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(sig, buf, n);
    fclose(f);
}

/* Помощник выхода: программа плагина с раскрытым argv. Подпись перезапуска — версия плагина и
 * ключи вида (а когда {conf} пишет демон — хеш его содержимого, steer-api.md, 1.4). */
int plugin_kind_helper(const struct plugin_kind *pk, const struct spec *sp, const struct output *o,
                       struct kind_helper *h) {
    if (!pk || !pk->helper.prog) return -1;
    const struct plugin *pl = pk->owner;
    char why[256];
    if (kind_helper_cmd(h, pk->helper_cmd ? pk->helper_cmd : pk->name) != 0) return -1;
    if (kind_helper_prog(h, pk->helper.prog) != 0) return -1;
    h->plugin = pl->id;
    h->paths = pk->paths;
    /* {conf} несёт метки и таблицы — супервизор без демона назначает их до сбора (kind.h, marks). */
    h->marks = 1;
    char conf[PATH_MAX];
    snprintf(conf, sizeof(conf), "%s/plugin/%s/%s.json", steer_state_dir(), pl->id, o->name);
    if (kind_helper_conf(h, conf) != 0) return -1;
    /* argv манифеста; умолчание — [<cmd>, "{out}", "--conf", "{conf}"]. */
    static const char *const DEF[] = { "{out}", "--conf", "{conf}" };
    size_t n = pk->helper_argv_set ? pk->helper.argc : 3;
    if (!pk->helper_argv_set && kind_helper_arg(h, pk->helper_cmd ? pk->helper_cmd : pk->name) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        char *a = subst(pl, sp, o, NULL, pk->helper_argv_set ? pk->helper.argv[i] : DEF[i], why, sizeof(why));
        if (!a) {
            fprintf(stderr, "steer[warn] плагин %s: помощник %s: %s\n", pl->id, o->name, why);
            return -1;
        }
        int rc = kind_helper_arg(h, a);
        free(a);
        if (rc != 0) return -1;
    }
    for (size_t i = 0; i < pk->helper.envc; i++)
        if (kind_helper_env(h, pk->helper.env[i]) != 0) return -1;
    if (pl->builtin) {
        char be[96];
        snprintf(be, sizeof(be), "STEER_PK_BUILTIN=%s", pl->id);
        if (kind_helper_env(h, be) != 0) return -1;
    }
    kind_sig_mix(&h->sig, pl->version, strlen(pl->version));
    /* Подпись перезапуска — версия плагина, всё содержимое {conf} (steer-api.md, 1.4) и содержимое
     * файлов ключей x-watch. */
    char *cj = plugin_conf_json(sp, o, pk);
    if (!cj) return -1;
    kind_sig_mix(&h->sig, cj, strlen(cj));
    free(cj);
    settings_sig(pl, &h->sig);
    const char *kj = out_plugin_keys(o);
    if (pk->watch_n && kj) {
        struct err e;
        memset(&e, 0, sizeof(e));
        struct ydoc *d = ydoc_parse_buf(kj, strlen(kj), "keys", &e);
        for (size_t i = 0; d && i < pk->watch_n; i++) {
            const struct ynode *v = ynode_get(ydoc_root(d), pk->watch[i]);
            if (!v || v->kind != YN_SCALAR) continue;
            FILE *f = fopen(v->str, "r");
            if (!f) { kind_sig_mix(&h->sig, "-", 1); continue; }
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(&h->sig, buf, n);
            fclose(f);
        }
        ydoc_free(d);
    }
    return 0;
}

int plugin_svc_helper(const struct plugin_svc *sv, const struct spec *sp, struct kind_helper *h) {
    if (!sv || !sv->run.prog) return -1;
    const struct plugin *pl = sv->owner;
    char why[256];
    if (kind_helper_cmd(h, sv->name) != 0) return -1;
    if (kind_helper_prog(h, sv->run.prog) != 0) return -1;
    h->plugin = pl->id;
    /* Каталоги плагина (steer-api.md, 1.2): настройки и состояние создаются до запуска, пишутся программой. */
    {
        char d[2 * PATH_MAX], etc[PATH_MAX];
        plugin_etc(etc, sizeof(etc));
        snprintf(d, sizeof(d), "%s/conf", etc);
        mkdir(d, 0755);
        snprintf(d, sizeof(d), "%s/conf/%s", etc, pl->id);
        mkdir(d, 0755);
        snprintf(d, sizeof(d), "%s/plugin", steer_state_dir());
        mkdir(d, 0755);
        snprintf(d, sizeof(d), "%s/plugin/%s", steer_state_dir(), pl->id);
        mkdir(d, 0700);
    }
    kind_sig_mix(&h->sig, pl->version, strlen(pl->version));
    settings_sig(pl, &h->sig);
    for (size_t i = 0; i < sv->run.argc; i++) {
        char *a = subst(pl, sp, NULL, NULL, sv->run.argv[i], why, sizeof(why));
        if (!a) {
            fprintf(stderr, "steer[warn] плагин %s: служба %s: %s\n", pl->id, sv->name, why);
            return -1;
        }
        /* Слова с выданными ресурсами ({queue0}, {mark}) входят в подпись: сменился номер — служба перезапускается. */
        kind_sig_mix(&h->sig, a, strlen(a));
        int rc = kind_helper_arg(h, a);
        free(a);
        if (rc != 0) return -1;
    }
    for (size_t i = 0; i < sv->run.envc; i++) {
        kind_sig_mix(&h->sig, sv->run.env[i], strlen(sv->run.env[i]));
        if (kind_helper_env(h, sv->run.env[i]) != 0) return -1;
    }
    if (pl->builtin) {
        char be[96];
        snprintf(be, sizeof(be), "STEER_PK_BUILTIN=%s", pl->id);
        if (kind_helper_env(h, be) != 0) return -1;
    }
    return 0;
}

const struct plugin_kind *plugin_core_ext(const char *kind, const char *key) {
    ensure();
    for (size_t i = 0; i < g_pl_n; i++) {
        if (!g_pl[i].enabled) continue;
        for (size_t j = 0; j < g_pl[i].kind_n; j++) {
            const struct plugin_kind *k = g_pl[i].kind[j];
            if (k->impl_core && k->helper.prog && k->helper_when && !strcmp(k->name, kind) &&
                !strcmp(k->helper_when, key))
                return k;
        }
    }
    return NULL;
}

static int plg_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    return plugin_kind_helper(o->plg.pk, sp, o, h);
}

/* Помощник РАЗВЁРНУТОГО выхода: хук expand вернул helper: true, и выход (группа вида ядра под своим
 * прежним именем) помечен владельцем — owner = {плагин, он сам}. Помощник — тот, что у вида плагина с
 * разворотом (steer-api.md, 3.3: он ведёт членов, member и revive), как steer-warpbox ведёт группу
 * `kind: warp`. -1 — у выхода такого помощника нет. */
int plugin_owner_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    if (!o->owner_plugin || !o->owner_out || strcmp(o->owner_out, o->name) != 0) return -1;
    const struct plugin *pl = plugin_find(o->owner_plugin);
    if (!pl || !pl->enabled) return -1;
    for (size_t i = 0; i < pl->kind_n; i++)
        if (pl->kind[i]->expand.prog && pl->kind[i]->helper.prog) return plugin_kind_helper(pl->kind[i], sp, o, h);
    return -1;
}

/* status: `"plugin":{id, version, state}` (spec-fields.md, раздел 8); state — файл состояния, который
 * помощник пишет в <state>/plugin/<id>/<выход>.status.json, как есть, если это объект JSON.
 *
 * У туннеля (`tunnel:<протокол>`) то же состояние идёт и прежним полем `"<протокол>"` — так его
 * печатали виды протоколов, пока жили в ядре (`"vless":{"active":…}`), и так его читают панели; имя
 * поля — из имени вида манифеста, своего списка протоколов у ядра нет. */
static int state_is_object(const char *txt) {
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(txt, strlen(txt), "state", &e);
    int ok = d && ydoc_root(d)->kind == YN_MAP;
    ydoc_free(d);
    return ok;
}

static void state_emit(FILE *out, const struct plugin *pl, const struct output *o, const char *proto) {
    struct sbuf b = { 0 };
    sb_str(&b, ",\"plugin\":{\"id\":");
    sb_json(&b, pl->id);
    sb_str(&b, ",\"version\":");
    sb_json(&b, pl->version);
    if (b.p) fputs(b.p, out);
    free(b.p);
    char *txt = plugin_out_state(o);
    if (txt && !state_is_object(txt)) { free(txt); txt = NULL; }
    if (txt) fprintf(out, ",\"state\":%s", txt);
    fputc('}', out);
    if (txt && proto && *proto) {
        struct sbuf b = { 0 };
        sb_str(&b, ",");
        sb_json(&b, proto);
        sb_str(&b, ":");
        if (b.p && !b.oom) fprintf(out, "%s%s", b.p, txt);
        free(b.p);
    }
    free(txt);
}

static void plg_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    const struct plugin_kind *pk = out_plugin_kind(o);
    if (pk) state_emit(out, pk->owner, o, pk->proto);
}

void plugin_owner_status(FILE *out, const struct output *o) {
    if (!o->owner_plugin || !o->owner_out || strcmp(o->owner_out, o->name) != 0) return;
    const struct plugin *pl = plugin_find(o->owner_plugin);
    if (pl) state_emit(out, pl, o, NULL);
}

char *plugin_out_state(const struct output *o) {
    const struct plugin_kind *pk = out_plugin_kind(o);
    const char *id = pk ? pk->owner->id : o->owner_plugin && o->owner_out && !strcmp(o->owner_out, o->name)
                                             ? o->owner_plugin : NULL;
    if (!id) return NULL;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/plugin/%s/%s.status.json", steer_state_dir(), id, o->name);
    size_t n;
    char *txt = slurp(path, &n);
    if (!txt) return NULL;
    while (n && (txt[n - 1] == '\n' || txt[n - 1] == ' ')) txt[--n] = '\0';
    if (txt[0] != '{') { free(txt); return NULL; }
    /* Файл мёртвого процесса правды не говорит: kill -9 убрать за собой не даст. */
    const char *p = strstr(txt, "\"pid\":");
    long pid = 0;
    if (p && sscanf(p + 6, "%ld", &pid) == 1 && pid > 0 && kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
        free(txt);
        return NULL;
    }
    return txt;
}

/* health: events — приговор здоровью выносит помощник (up/down, supd.c); ядро не пробует устройство и
 * не меряет задержку: проба через устройство проверила бы не туннель (у звезды xsteer — интернет у хаба,
 * и сторож уронил бы исправный выход). Устройство сторож проверил до вопроса виду. */
static int plg_health_events(const struct spec *sp, const struct output *o, const char *dev) {
    (void)sp; (void)o; (void)dev;
    return 1;
}
static int plg_latency_events(const struct spec *sp, const struct output *o, const char *dev) {
    (void)sp; (void)o; (void)dev;
    return -1;
}

static void plugin_kind_ops_init(struct plugin_kind *k) {
    struct kind_ops *o = &k->ops;
    memset(o, 0, sizeof(*o));
    o->name = k->proto ? k->proto : k->name;
    o->plugin = k;
    /* Общий обход DPI (zapret системы) трафик вида плагина не трогает — как у всякого вида ядра, кроме
     * direct: бит ставит ядро, плагин его не выбирает (manifest.md, caps). */
    o->caps = k->caps | KC_SKIP_ZAPRET;
    o->novia = k->novia;
    o->selfnat_why = k->selfnat_why;
    o->lan_only = k->lan_only;
    o->parse = plg_parse;
    o->keys_of = plg_keys_of;
    o->status = plg_status;
    if (k->health_events) {
        o->health = plg_health_events;
        o->latency = plg_latency_events;
    }
    /* Шаблоны nft вида ядро раскладывает само (plugin_emit_all): порядок правил по плагинам задаёт
     * реестр, а не порядок видов, и общий отказ с именем файла не помещается в void emit. */
    if (k->helper.prog) o->helper = plg_helper;
}

/* ---- подкоманды ---------------------------------------------------------------------------- */

/* ---- nft: слоты и шаблоны плагинов ---------------------------------------------------------
 *
 * Файл плагина (steer-api.md, 5.3) — подмножество синтаксиса nft: на верхнем уровне только `set`,
 * `map` и `chain <слот>`. Ядро переименовывает: набор X → p_<id>_X (и ссылки @X в правилах этого
 * файла), chain <слот> → plugin_<id>_<слот> (обычная цепочка без хука); таблицу, хук и приоритет
 * плагин не пишет. Базовую цепочку plugin_<слот> со своим хуком и приоритетом заводит ядро — только
 * когда слот занят — и пишет в неё `jump plugin_<id>_<слот>` по плагинам в порядке id.
 *
 * Файл разбирается ОДИН РАЗ, при чтении манифеста (pnft_load): синтаксическая ошибка выключает
 * плагин с причиной «файл:строка: …», а не рушит apply. Подстановки ({out_mark}…) раскрываются при
 * построении набора правил, когда известен выход. Правило — одна логическая строка (скобки { }
 * внутри строки допустимы и могут переноситься); построчные комментарии `#` снимаются. */
enum { PN_SET, PN_MAP, PN_CHAIN };

struct pn_rule { char *text; unsigned line; };
struct pn_item {
    int kind;
    char *name;                 /* набор/карта — имя; цепочка — слот */
    unsigned line;
    char *type, *data;          /* ключ набора, значение карты */
    unsigned flags;             /* NFT_SET_* */
    char **el;  size_t el_n;
    struct pn_rule *rule;  size_t rule_n;
};
struct pnft {
    char *path;
    struct pn_item *it;  size_t it_n;
    int per_out;                /* шаблон вида: только chain */
};

static const struct { const char *name, *type, *hook, *prio; int off; } SLOTS[] = {
    { "prerouting-raw",   "filter", "prerouting",  "raw",    1 },
    { "prerouting-pre",   "filter", "prerouting",  "mangle", 0 },
    { "prerouting-post",  "filter", "prerouting",  "mangle", 3 },
    { "prerouting-dnat",  "nat",    "prerouting",  "dstnat", 1 },
    { "forward",          "filter", "forward",     "filter", -5 },
    { "input",            "filter", "input",       "filter", 0 },
    { "output-raw",       "filter", "output",      "raw",    1 },
    { "output-pre",       "route",  "output",      "mangle", 0 },
    { "output-post",      "route",  "output",      "mangle", 2 },
    { "postrouting-pre",  "filter", "postrouting", "filter", -5 },
    { "postrouting-post", "filter", "postrouting", "srcnat", 20 },
};
#define SLOTS_N (sizeof(SLOTS) / sizeof(SLOTS[0]))

static int slot_index(const char *name) {
    for (size_t i = 0; i < SLOTS_N; i++) if (!strcmp(SLOTS[i].name, name)) return (int)i;
    return -1;
}

static void pnft_free(struct pnft *f) {
    if (!f) return;
    for (size_t i = 0; i < f->it_n; i++) {
        struct pn_item *it = &f->it[i];
        free(it->name); free(it->type); free(it->data);
        vec_free(it->el, it->el_n);
        for (size_t j = 0; j < it->rule_n; j++) free(it->rule[j].text);
        free(it->rule);
    }
    free(f->it);
    free(f->path);
    free(f);
}

/* Символ имени nft: буква, цифра, _ - . */
static int nm_ch(int c) { return isalnum(c) || c == '_' || c == '-' || c == '.'; }

__attribute__((format(printf, 5, 6)))
static void pn_fail(char *why, size_t wn, const char *path, unsigned line, const char *fmt, ...) {
    char tail[300];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tail, sizeof(tail), fmt, ap);
    va_end(ap);
    snprintf(why, wn, "%s:%u: %s", path, line, tail);
}

/* Тело блока [b, e) → логические строки/операторы. semis — разделитель операторов не только \n, но
 * и ';'. Скобки группируют: разделитель внутри { } не режет, перенос внутри скобок — пробел.
 * Комментарий # — до конца строки. line0 — строка файла, с которой начинается тело. */
static int pn_split(const char *b, const char *e, unsigned line0, int semis,
                    char ***txt, unsigned **ln, size_t *n, char *why, size_t wn, const char *path) {
    *txt = NULL; *ln = NULL; *n = 0;
    struct sbuf cur = { 0 };
    unsigned line = line0, start = line0;
    int depth = 0, rc = 0;
    for (const char *p = b; p <= e && !rc; p++) {
        int c = p < e ? (unsigned char)*p : '\n';
        if (c == '#') { while (p < e && *p != '\n') p++; c = '\n'; }
        if ((c == '\n' || (semis && c == ';')) && depth == 0) {
            if (cur.n) {
                size_t l = cur.n;
                while (l && isspace((unsigned char)cur.p[l - 1])) l--;
                char **nt = realloc(*txt, (*n + 1) * sizeof(char *));
                unsigned *nl = realloc(*ln, (*n + 1) * sizeof(unsigned));
                if (nt) *txt = nt;
                if (nl) *ln = nl;
                if (!nt || !nl || !((*txt)[*n] = strndup(cur.p, l))) { rc = -1; break; }
                (*ln)[*n] = start;
                (*n)++;
                cur.n = 0;
                cur.p[0] = '\0';
            }
            if (c == '\n') line++;
            continue;
        }
        if (!cur.n && isspace(c)) { if (c == '\n') line++; continue; }
        if (!cur.n) start = line;
        if (c == '{') depth++;
        else if (c == '}' && --depth < 0) { pn_fail(why, wn, path, line, "лишняя «}»"); rc = -2; break; }
        int ch = c == '\n' ? ' ' : c;
        sb_put(&cur, (const char *)&ch, 1);
        if (c == '\n') line++;
    }
    if (!rc && depth) { pn_fail(why, wn, path, line, "не закрыта «{»"); rc = -2; }
    if (!rc && cur.oom) rc = -1;
    free(cur.p);
    if (rc) {
        if (rc == -1) snprintf(why, wn, "нет памяти");
        for (size_t i = 0; i < *n; i++) free((*txt)[i]);
        free(*txt); free(*ln);
        *txt = NULL; *ln = NULL; *n = 0;
        return -1;
    }
    return 0;
}

/* Одно слово из s с позиции *pp (после пробелов); возвращает длину, *pp — начало. 0 — конец. */
static size_t pn_word(const char **pp) {
    const char *p = *pp;
    while (*p && isspace((unsigned char)*p)) p++;
    *pp = p;
    size_t l = 0;
    while (p[l] && !isspace((unsigned char)p[l]) && p[l] != '{') l++;
    return l;
}

static int pn_set_stmt(struct pn_item *it, const char *txt, unsigned line, const char *path, char *why, size_t wn) {
    const char *p = txt;
    size_t l = pn_word(&p);
    if (l == 4 && !strncmp(p, "type", 4)) {
        const char *v = p + 4;
        while (isspace((unsigned char)*v)) v++;
        if (!*v) { pn_fail(why, wn, path, line, "после type нужен тип ключа"); return -1; }
        if (it->kind == PN_MAP) {
            const char *colon = strchr(v, ':');
            if (!colon) { pn_fail(why, wn, path, line, "у map нужно «type ключ : значение»"); return -1; }
            char *k = strndup(v, (size_t)(colon - v)), *d = strdup(colon + 1);
            if (!k || !d) return -1;
            size_t kl = strlen(k);
            while (kl && isspace((unsigned char)k[kl - 1])) k[--kl] = '\0';
            char *dd = d;
            while (isspace((unsigned char)*dd)) dd++;
            it->type = k;
            it->data = strdup(dd);
        } else it->type = strdup(v);
        return 0;
    }
    if (l == 5 && !strncmp(p, "flags", 5)) {
        const char *v = p + 5;
        while (*v) {
            while (*v && (isspace((unsigned char)*v) || *v == ',')) v++;
            const char *s = v;
            while (*v && !isspace((unsigned char)*v) && *v != ',') v++;
            if (v == s) break;
            if ((size_t)(v - s) == 8 && !strncmp(s, "interval", 8)) it->flags |= NFT_SET_INTERVAL;
            else if ((size_t)(v - s) == 7 && !strncmp(s, "timeout", 7)) it->flags |= NFT_SET_TIMEOUT;
            else { pn_fail(why, wn, path, line, "flags: «%.*s» не поддерживается (есть interval, timeout)", (int)(v - s), s); return -1; }
        }
        return 0;
    }
    if (l == 8 && !strncmp(p, "elements", 8)) {
        const char *v = strchr(p, '{');
        const char *e = strrchr(p, '}');
        if (!v || !e || e < v) { pn_fail(why, wn, path, line, "elements = { … }"); return -1; }
        const char *q = v + 1;
        while (q < e) {
            const char *s = q;
            int d = 0;
            while (q < e && !(d == 0 && *q == ',')) { if (*q == '{') d++; if (*q == '}') d--; q++; }
            char *el = strndup(s, (size_t)(q - s));
            if (!el) return -1;
            char *t = el;
            size_t tl = strlen(t);
            while (tl && isspace((unsigned char)t[tl - 1])) t[--tl] = '\0';
            while (*t && isspace((unsigned char)*t)) t++;
            if (*t && vec_add(&it->el, &it->el_n, t) != 0) { free(el); return -1; }
            free(el);
            if (q < e) q++;
        }
        return 0;
    }
    pn_fail(why, wn, path, line, "в наборе допустимы type, flags и elements, а не «%.*s»", (int)l, p);
    return -1;
}

static struct pnft *pnft_load(const char *path, int per_out, char *why, size_t wn) {
    size_t n;
    char *txt = slurp(path, &n);
    if (!txt) { snprintf(why, wn, "файл nft %s не читается", path); return NULL; }
    struct pnft *f = calloc(1, sizeof(*f));
    if (!f) { free(txt); snprintf(why, wn, "нет памяти"); return NULL; }
    f->path = strdup(path);
    f->per_out = per_out;
    const char *p = txt, *end = txt + n;
    unsigned line = 1;
    for (;;) {
        /* пробелы и комментарии */
        for (;;) {
            while (p < end && isspace((unsigned char)*p)) { if (*p == '\n') line++; p++; }
            if (p < end && *p == '#') { while (p < end && *p != '\n') p++; continue; }
            break;
        }
        if (p >= end) break;
        unsigned bl = line;
        const char *w = p;
        while (p < end && isalpha((unsigned char)*p)) p++;
        size_t wl = (size_t)(p - w);
        int kind;
        if (wl == 3 && !strncmp(w, "set", 3)) kind = PN_SET;
        else if (wl == 3 && !strncmp(w, "map", 3)) kind = PN_MAP;
        else if (wl == 5 && !strncmp(w, "chain", 5)) kind = PN_CHAIN;
        else { pn_fail(why, wn, path, bl, "на верхнем уровне допустимы set, map и chain <слот>"); goto bad; }
        if (per_out && kind != PN_CHAIN) {
            pn_fail(why, wn, path, bl, "в шаблоне вида допустим только chain <слот>: набор на каждый выход назвался бы одинаково");
            goto bad;
        }
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        const char *nm = p;
        while (p < end && nm_ch((unsigned char)*p)) p++;
        if (p == nm) { pn_fail(why, wn, path, bl, "нужно имя"); goto bad; }
        char *name = strndup(nm, (size_t)(p - nm));
        while (p < end && isspace((unsigned char)*p)) { if (*p == '\n') line++; p++; }
        if (p >= end || *p != '{') { free(name); pn_fail(why, wn, path, bl, "после имени нужна «{»"); goto bad; }
        const char *bs = ++p;
        int depth = 1;
        unsigned body_line = line;
        while (p < end && depth) {
            if (*p == '#') { while (p < end && *p != '\n') p++; continue; }
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (!depth) break; }
            if (*p == '\n') line++;
            p++;
        }
        if (depth) { free(name); pn_fail(why, wn, path, bl, "не закрыта «{»"); goto bad; }
        const char *be = p++;
        if (kind == PN_CHAIN && slot_index(name) < 0) {
            char list[400] = "";
            size_t l = 0;
            for (size_t i = 0; i < SLOTS_N; i++) l += (size_t)snprintf(list + l, sizeof(list) - l, "%s%s", i ? ", " : "", SLOTS[i].name);
            pn_fail(why, wn, path, bl, "слота «%s» нет (есть: %s)", name, list);
            free(name);
            goto bad;
        }
        struct pn_item *ni = realloc(f->it, (f->it_n + 1) * sizeof(*ni));
        if (!ni) { free(name); snprintf(why, wn, "нет памяти"); goto bad; }
        f->it = ni;
        struct pn_item *it = &f->it[f->it_n++];
        memset(it, 0, sizeof(*it));
        it->kind = kind;
        it->name = name;
        it->line = bl;
        char **st; unsigned *sl; size_t sn;
        if (pn_split(bs, be, body_line, kind != PN_CHAIN, &st, &sl, &sn, why, wn, path) != 0) goto bad;
        for (size_t i = 0; i < sn; i++) {
            if (kind == PN_CHAIN) {
                struct pn_rule *nr = realloc(it->rule, (it->rule_n + 1) * sizeof(*nr));
                if (!nr) { snprintf(why, wn, "нет памяти"); goto bad; }
                it->rule = nr;
                it->rule[it->rule_n].text = st[i];
                it->rule[it->rule_n].line = sl[i];
                it->rule_n++;
                st[i] = NULL;
            } else if (pn_set_stmt(it, st[i], sl[i], path, why, wn) != 0) {
                for (size_t j = 0; j < sn; j++) free(st[j]);
                free(st); free(sl);
                goto bad;
            }
        }
        for (size_t i = 0; i < sn; i++) free(st[i]);
        free(st); free(sl);
        if (kind != PN_CHAIN && !it->type) {
            pn_fail(why, wn, path, bl, "у %s %s нет type", kind == PN_SET ? "набора" : "карты", it->name);
            goto bad;
        }
    }
    free(txt);
    return f;
bad:
    free(txt);
    pnft_free(f);
    return NULL;
}

/* Имя набора плагина в таблице steer. */
static void pn_setname(const struct plugin *pl, const char *x, char *dst, size_t n) {
    snprintf(dst, n, "p_%s_%s", pl->id, x);
}

/* Правило файла → текст для ir_x: подстановки выхода и переименование ссылок @набор. own — наборы
 * этого файла (имена); @lan_dev и @wan_dev — наборы ядра, остаются. */
static char *pn_rule_text(const struct plugin *pl, const struct spec *sp, const struct output *o,
                          const struct pnft *f, const char *rule, char *why, size_t wn) {
    char *sub = subst(pl, sp, o, NULL, rule, why, wn);
    if (!sub) return NULL;
    struct sbuf b = { 0 };
    for (const char *p = sub; *p; p++) {
        if (*p != '@') { sb_put(&b, p, 1); continue; }
        const char *s = ++p;
        while (nm_ch((unsigned char)*p)) p++;
        size_t l = (size_t)(p - s);
        p--;
        int own = 0;
        for (size_t i = 0; i < f->it_n && !own; i++)
            if (f->it[i].kind != PN_CHAIN && strlen(f->it[i].name) == l && !strncmp(f->it[i].name, s, l)) own = 1;
        if (own) sb_printf(&b, "@p_%s_%.*s", pl->id, (int)l, s);
        else if ((l == 7 && !strncmp(s, "lan_dev", 7)) || (l == 7 && !strncmp(s, "wan_dev", 7))) sb_printf(&b, "@%.*s", (int)l, s);
        else {
            snprintf(why, wn, "набор @%.*s не объявлен в файле (и это не @lan_dev и не @wan_dev)", (int)l, s);
            free(b.p);
            free(sub);
            return NULL;
        }
    }
    free(sub);
    if (b.oom) { free(b.p); snprintf(why, wn, "нет памяти"); return NULL; }
    return b.p ? b.p : strdup("");
}

static const char *const NFT_PRIO_NAME[] = { "raw", "mangle", "dstnat", "filter", "srcnat", NULL };
static int nft_prio_num(const char *name, int off) {
    static const int NUM[] = { -300, -150, -100, 0, 100 };
    for (size_t i = 0; NFT_PRIO_NAME[i]; i++) if (!strcmp(NFT_PRIO_NAME[i], name)) return NUM[i] + off;
    return off;
}

struct pn_emit {
    struct nft_rs *rs;
    struct nft_table *t;
    const struct spec *sp;
    int lan_set, wan_set;
};

/* Цепочка плагина в слоте: заводит базовую plugin_<слот> и свою plugin_<id>_<слот> с jump. */
static struct nft_chain *pn_slot_chain(struct pn_emit *pe, const struct plugin *pl, int slot) {
    char bn[96], on[160];
    snprintf(bn, sizeof(bn), "plugin_%s", SLOTS[slot].name);
    snprintf(on, sizeof(on), "plugin_%s_%s", pl->id, SLOTS[slot].name);
    struct nft_chain *own = ir_chain_find(pe->t, on);
    if (own) return own;
    struct nft_chain *base = ir_chain_find(pe->t, bn);
    if (!base) {
        base = ir_base_chain_add(pe->t, bn, SLOTS[slot].type, SLOTS[slot].hook, SLOTS[slot].prio, SLOTS[slot].off);
        if (!base) return NULL;
        ir_gap(base);
    }
    own = ir_chain_add(pe->t, on);
    if (!own) return NULL;
    ir_gap(own);
    struct nft_rule *j = ir_rule(base);
    if (!j) return NULL;
    ir_x(j, "jump %s", on);
    return own;
}

struct wan_ctx { struct nft_set *s; char **seen; size_t n; };

static void wan_dev_add(const char *dev, void *arg) {
    struct wan_ctx *c = arg;
    for (size_t i = 0; i < c->n; i++)
        if (!strcmp(c->seen[i], dev)) return;
    if (vec_add(&c->seen, &c->n, dev) != 0) return;
    char q[96];
    snprintf(q, sizeof(q), "\"%s\"", dev);
    ir_set_value(c->s, q);
}

/* Наборы ядра, которые читает плагин: @lan_dev — устройства раздачи спеки; @wan_dev — устройства
 * маршрутов по умолчанию таблицы main, v4 и v6 (open.md О-9; steer-api 1.2). */
static void pn_kernel_sets(struct pn_emit *pe, const char *text) {
    for (const char *p = text; (p = strchr(p, '@')); p++) {
        if (!strncmp(p + 1, "lan_dev", 7) && !nm_ch((unsigned char)p[8]) && !pe->lan_set) {
            pe->lan_set = 1;
            struct nft_set *s = ir_set_add(pe->t, "lan_dev", "ifname");
            if (s) {
                ir_gap(s);
                for (size_t i = 0; i < pe->sp->lan_dev_n; i++) {
                    char q[96];
                    snprintf(q, sizeof(q), "\"%s\"", pe->sp->lan_dev[i]);
                    ir_set_value(s, q);
                }
            }
        } else if (!strncmp(p + 1, "wan_dev", 7) && !nm_ch((unsigned char)p[8]) && !pe->wan_set) {
            pe->wan_set = 1;
            struct nft_set *s = ir_set_add(pe->t, "wan_dev", "ifname");
            if (s) {
                ir_gap(s);
                /* Устройства маршрутов по умолчанию main, как они лежат сейчас. Сменился WAN — событие сети будит демон
                 * (hotplug 95-steer, сторож), reload печатает набор заново, и текст правил меняется. */
                struct wan_ctx wc = { .s = s };
                rtnl_default_devs(wan_dev_add, &wc);
                vec_free(wc.seen, wc.n);
            }
        }
    }
}

/* Файл f плагина pl; o — выход вида (шаблон вида) или NULL (файл плагина). */
static int pn_emit_file(struct pn_emit *pe, const struct plugin *pl, const struct pnft *f,
                        const struct output *o, struct err *e) {
    char why[400];
    for (size_t i = 0; i < f->it_n; i++) {
        const struct pn_item *it = &f->it[i];
        if (it->kind != PN_CHAIN) {
            char nm[160];
            pn_setname(pl, it->name, nm, sizeof(nm));
            struct nft_set *s = it->kind == PN_MAP ? ir_map_add(pe->t, nm, it->type, it->data)
                                                   : ir_set_add(pe->t, nm, it->type);
            if (!s) return err_set(e, "плагин %s: нет памяти для набора", pl->id);
            ir_gap(s);
            s->flags = it->flags;
            for (size_t k = 0; k < it->el_n; k++) ir_set_value(s, it->el[k]);
            continue;
        }
        struct nft_chain *c = pn_slot_chain(pe, pl, slot_index(it->name));
        if (!c) return err_set(e, "плагин %s: нет памяти для цепочки", pl->id);
        for (size_t k = 0; k < it->rule_n; k++) {
            char *t = pn_rule_text(pl, pe->sp, o, f, it->rule[k].text, why, sizeof(why));
            if (!t) {
                char m[900];
                snprintf(m, sizeof(m), "плагин %s: %s:%u: %s%s%s", pl->id, f->path, it->rule[k].line, why,
                         o ? " (выход " : "", o ? o->name : "");
                if (o) { size_t l = strlen(m); if (l + 2 < sizeof(m)) { m[l] = ')'; m[l + 1] = '\0'; } }
                return err_set(e, "%s", m);
            }
            pn_kernel_sets(pe, t);
            struct nft_rule *r = ir_rule(c);
            if (!r) { free(t); return err_set(e, "плагин %s: нет памяти для правила", pl->id); }
            ir_x(r, "%s", t);
            if (o) ir_comment(r, "steer:plugin:%s:%s", pl->id, o->name);
            else ir_comment(r, "steer:plugin:%s", pl->id);
            free(t);
        }
    }
    return 0;
}

int plugin_emit_all(struct nft_rs *rs, const struct spec *sp, struct err *e) {
    ensure();
    struct pn_emit pe = { .rs = rs, .sp = sp };
    pe.t = ir_table_find(rs, NFT_FAM_INET, NULL);
    if (!pe.t) return 0;
    for (size_t i = 0; i < g_pl_n; i++) {
        const struct plugin *pl = &g_pl[i];
        if (!pl->enabled) continue;
        for (size_t f = 0; f < pl->nft_n; f++)
            if (pn_emit_file(&pe, pl, pl->nftp[f], NULL, e) != 0) return -1;
        for (size_t k = 0; k < pl->kind_n; k++) {
            const struct plugin_kind *pk = pl->kind[k];
            if (!pk->nft_n || pk->impl_core) continue;
            for (size_t oi = 0; oi < sp->out_n; oi++) {
                const struct output *o = &sp->out[oi];
                if (out_plugin_kind(o) != pk) continue;
                for (size_t f = 0; f < pk->nft_n; f++)
                    if (pn_emit_file(&pe, pl, pk->nftp[f], o, e) != 0) return -1;
            }
        }
    }
    return 0;
}

/* ---- steer nft-map ---------------------------------------------------------------------------- */

/* Базовые цепочки ядра: steer-api.md, 5.1. Постоянные числа API v1 — как у слотов: перенос цепочки
 * ядра — major. Сверяется стендом (tests/pluginkindmatch.sh) с набором правил, который строит
 * компилятор. */
static const struct { const char *name, *type, *hook, *prio; int off; const char *what; } KCHAINS[] = {
    { "ingress_mark",         "filter", "ingress",     "filter", 10, "разметка на ingress устройств раздачи" },
    { "prerouting_raw",       "filter", "prerouting",  "raw",    0,  "traceroute для доменных каналов" },
    { "prerouting_mark",      "filter", "prerouting",  "mangle", 1,  "разметка каналов" },
    { "prerouting_failopen",  "filter", "prerouting",  "mangle", 2,  "пуск напрямую упавших выходов" },
    { "forward_v6",           "filter", "forward",     "mangle", 0,  "IPv6 по выходам" },
    { "prerouting_dns",       "nat",    "prerouting",  "dstnat", -2, "DNS в резолвер" },
    { "prerouting_tcp_redir", "nat",    "prerouting",  "dstnat", -1, "TCP выходов tcp-redir к слушателю" },
    { "prerouting_dnat",      "nat",    "prerouting",  "dstnat", 0,  "fake-IP и подмена порта" },
    { "prerouting_restore",   "filter", "prerouting",  "dstnat", 10, "восстановление метки из conntrack" },
    { "output_mark",          "route",  "output",      "mangle", 1,  "каналы самого устройства (при local_channels)" },
    { "output_tcp_redir",     "nat",    "output",      "dstnat", -1, "TCP выходов tcp-redir для своего трафика" },
    { "output_dns",           "nat",    "output",      "dstnat", 0,  "DNS самого устройства" },
    { "postrouting_guard",    "filter", "postrouting", "filter", 0,  "запреты утечек" },
    { "postrouting_fakeguard","filter", "postrouting", "filter", 0,  "запреты утечек fake-IP" },
    { "postrouting_nat4",     "nat",    "postrouting", "srcnat", 0,  "masquerade выходов IPv4" },
    { "postrouting_nat6",     "nat",    "postrouting", "srcnat", 0,  "masquerade выходов IPv6" },
    { "postrouting_down",     "filter", "postrouting", "srcnat", 10, "отказ трафику упавших выходов" },
    { "input_down",           "filter", "input",       "filter", 10, "то же для входящего" },
};

void plugin_nft_map(FILE *out, int json) {
    const char *table = nft_table();
    uint32_t mask = plat()->mark_mask;
    if (!json) {
        fprintf(out, "Таблица: inet %s\nПоле метки steer: 0x%08x (биты %u..%u)\n\nЦепочки ядра:\n", table, mask,
                (unsigned)__builtin_ctz(mask), (unsigned)(31 - __builtin_clz(mask)));
        for (size_t i = 0; i < sizeof(KCHAINS) / sizeof(KCHAINS[0]); i++)
            fprintf(out, "  %-22s %-7s %-12s приоритет %5d  %s\n", KCHAINS[i].name, KCHAINS[i].type, KCHAINS[i].hook,
                    nft_prio_num(KCHAINS[i].prio, KCHAINS[i].off), KCHAINS[i].what);
        fputs("\nСлоты плагинов:\n", out);
        for (size_t i = 0; i < SLOTS_N; i++)
            fprintf(out, "  %-18s %-7s %-12s приоритет %5d  цепочка plugin_%s\n", SLOTS[i].name, SLOTS[i].type,
                    SLOTS[i].hook, nft_prio_num(SLOTS[i].prio, SLOTS[i].off), SLOTS[i].name);
        return;
    }
    fprintf(out, "{\"table\":\"%s\",\"family\":\"inet\",\"api\":\"%s\",", table, STEER_API_VERSION);
    fprintf(out, "\"mark\":{\"mask\":\"0x%08x\",\"base\":%u,\"bits\":%u},\"chains\":[", mask,
            (unsigned)__builtin_ctz(mask), plat()->mark_bits);
    for (size_t i = 0; i < sizeof(KCHAINS) / sizeof(KCHAINS[0]); i++)
        fprintf(out, "%s{\"name\":\"%s\",\"type\":\"%s\",\"hook\":\"%s\",\"priority\":%d}", i ? "," : "",
                KCHAINS[i].name, KCHAINS[i].type, KCHAINS[i].hook, nft_prio_num(KCHAINS[i].prio, KCHAINS[i].off));
    fputs("],\"slots\":[", out);
    for (size_t i = 0; i < SLOTS_N; i++)
        fprintf(out, "%s{\"name\":\"%s\",\"chain\":\"plugin_%s\",\"type\":\"%s\",\"hook\":\"%s\",\"priority\":%d}",
                i ? "," : "", SLOTS[i].name, SLOTS[i].name, SLOTS[i].type, SLOTS[i].hook,
                nft_prio_num(SLOTS[i].prio, SLOTS[i].off));
    fputs("],\"sets\":[\"lan_dev\",\"wan_dev\"]}\n", out);
}

/* ---- вид unavail ---------------------------------------------------------------------------
 *
 * Выход, вид которого не работает здесь и сейчас: плагин не поставлен или отключён, спека ещё не
 * подготовлена (steer-api.md, 3.5). Решение владельца: при старте и reload такой выход не рушит
 * спеку — он получает свою метку и таблицу, устройства у него нет, он `failed` и живёт по своему
 * on_fail, а остальные выходы работают; при apply из интерфейса спека с таким выходом — отказ с
 * причиной (LOAD_STRICT, spec.h).
 *
 * caps — устройство и метка: ровно столько нужно реестру меток и правилам on_fail, чтобы выход
 * ушёл в drop или direct, как у выхода, чьё устройство пропало. Своих ключей, правил и помощника у
 * вида нет; ключи неизвестного вида разбор пропускает молча — проверить их нечем. */
static int unavail_parse(struct output *o, const struct out_keys *k, struct err *e) {
    (void)k; (void)e;
    if (!o->device[0]) awg_default_ifname(o->name, o->device, sizeof(o->device));
    return 0;
}

static void unavail_keys_of(const struct output *o, struct out_keys *k) {
    (void)o; (void)k;
}

const struct kind_ops kind_unavail = {
    .name = "unavail",
    .caps = KC_DEVICE | KC_MARK,
    .parse = unavail_parse,
    .keys_of = unavail_keys_of,
};

int out_make_unavail(struct spec *sp, struct output *o, const char *why, const char *plugin,
                     const char *shown) {
    const char *w = spec_strdup(sp, why);
    const char *p = plugin ? spec_strdup(sp, plugin) : NULL;
    const char *sh = shown ? spec_strdup(sp, shown) : NULL;
    if (!w || (plugin && !p) || (shown && !sh)) return -1;
    memset(&o->plg, 0, sizeof(o->plg));
    o->kind = &kind_unavail;
    o->unavail = w;
    o->unavail_plugin = p;
    o->plg.shown = sh;
    o->failed = 1;
    if (!o->device[0]) awg_default_ifname(o->name, o->device, sizeof(o->device));
    return 0;
}
