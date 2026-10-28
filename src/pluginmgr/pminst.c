/* Менеджер плагинов: установка, обновление, откат, снятие, включение (s2p.md, «Установка и
 * обновление», «Проверка здоровья», «Откат»; manifest.md, «Проверки при установке»).
 *
 * ПОРЯДОК (всё под блокировкой менеджера — её берёт pmmain.c):
 *   1. план: отбор версий по всему графу requires.plugins, библиотеки раньше зависимых;
 *   2. место на разделе плагинов (Σ installed) и во /tmp (Σ size); не хватает на полный вариант, а
 *      облегчённый помещается — он, с причиной в state.json; иначе отказ числами;
 *   3. скачивание по адресам репозитория и зеркалам, сверка size и sha256 из подписанного индекса;
 *   4–6. распаковка в .stage/<id>-<версия> одним проходом: первые три записи — plugin.json, MANIFEST,
 *      MANIFEST.sig; подпись проверяется на третьей, до остального; каждый следующий файл сверяется
 *      с MANIFEST (sha256, размер, режим) сразу после записи; затем права, имена, системные пакеты,
 *      пути ядра, scripts/postinst --check;
 *   7. подмена двумя rename(2): <id> → .prev/<id>, .stage/… → <id>;
 *   8. scripts/migrate (сменился major) и scripts/postinst <старая>;
 *   9–10. plugin-reload у демона и проверка здоровья; не здоров — откат и bad_versions. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "pm.h"
#include "httpc.h"
#include "untar.h"
#include "scrypto.h"
#include "ctlcall.h"
#include "cli.h"
#include "module.h"
#include "platform.h"

struct ydoc *pm_manifest(const char *id) {
    char *p = pm_fmt("%s/%s/plugin.json", pm_root(), id);
    struct pm_err e;
    struct ydoc *d = pm_json_load(p, &e);
    free(p);
    return d;
}

static size_t mhash(const char *s) {
    size_t h = 1469598103934665603ULL & (size_t)-1;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * (size_t)1099511628211ULL;
    return h;
}

static struct pm_mslot *mslot(struct pm_ctx *x, const char *id) {
    for (size_t i = mhash(id) & (x->mcap - 1);; i = (i + 1) & (x->mcap - 1))
        if (!x->mc[i].id || !strcmp(x->mc[i].id, id)) return &x->mc[i];
}

void pm_mcache_on(struct pm_ctx *x) { x->mcache = 1; }

void pm_mcache_free(struct pm_ctx *x) {
    for (size_t i = 0; i < x->mcap; i++) {
        free(x->mc[i].id);
        if (x->mc[i].d) ydoc_free(x->mc[i].d);
    }
    free(x->mc);
    x->mc = NULL;
    x->mcap = x->mn = 0;
    x->mcache = 0;
}

const struct ynode *pm_manifest_ro(struct pm_ctx *x, const char *id, struct ydoc **own) {
    *own = NULL;
    if (!x->mcache) {
        *own = pm_manifest(id);
        return *own ? ydoc_root(*own) : NULL;
    }
    if (2 * (x->mn + 1) > x->mcap) {
        struct pm_mslot *old = x->mc;
        size_t ocap = x->mcap;
        x->mcap = ocap ? 2 * ocap : 16;
        x->mc = pm_alloc(sizeof(*x->mc) * x->mcap);
        memset(x->mc, 0, sizeof(*x->mc) * x->mcap);
        for (size_t i = 0; i < ocap; i++)
            if (old[i].id) *mslot(x, old[i].id) = old[i];
        free(old);
    }
    struct pm_mslot *s = mslot(x, id);
    if (!s->id) {
        s->id = pm_strdup(id);
        s->d = pm_manifest(id);   /* и отсутствие запоминается */
        x->mn++;
    }
    return s->d ? ydoc_root(s->d) : NULL;
}

void pm_result_free(struct pm_result *r) {
    for (size_t i = 0; i < r->n; i++) { free(r->v[i].id); free(r->v[i].version); free(r->v[i].from); free(r->v[i].old); }
    free(r->v);
    for (size_t i = 0; i < r->nfailed; i++) free(r->failed[i]);
    free(r->failed);
    memset(r, 0, sizeof(*r));
}

static int has_str(const struct ynode *seq, const char *s) {
    for (size_t i = 0; i < ynode_len(seq); i++)
        if (yn_is_str(ynode_at(seq, i)) && !strcmp(ynode_at(seq, i)->str, s)) return 1;
    return 0;
}

/* ---- запуск программ ---- */

/* Запустить argv (без shell) в каталоге dir с добавочным окружением env (NULL-конец); stdout и
 * stderr — в out (malloc, может быть NULL). Код выхода или -1. */
static int run_prog(char *const argv[], const char *dir, char *const env[], char **out, int timeout_s) {
    int pp[2];
    if (out) *out = NULL;
    if (pipe2(pp, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pp[0]); close(pp[1]); return -1; }
    if (pid == 0) {
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(pp[1], 1);
        dup2(pp[1], 2);
        if (dir && chdir(dir) != 0) _exit(126);
        for (size_t i = 0; env && env[i]; i++) putenv(env[i]);
        signal(SIGPIPE, SIG_DFL);
        execvp(argv[0], argv);
        dprintf(2, "не запустить %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(pp[1]);
    size_t cap = 4096, n = 0;
    char *b = pm_alloc(cap);
    long deadline = timeout_s > 0 ? (long)time(NULL) + timeout_s : 0;
    int killed = 0;
    for (;;) {
        struct pollfd pf = { pp[0], POLLIN, 0 };
        int r = poll(&pf, 1, 1000);
        if (r < 0 && errno == EINTR) continue;
        if (r > 0) {
            if (n + 4096 >= cap) { cap *= 2; b = pm_realloc(b, cap); }
            ssize_t m = read(pp[0], b + n, cap - n - 1);
            if (m < 0 && errno == EINTR) continue;
            if (m <= 0) break;
            n += (size_t)m;
        }
        if (deadline && time(NULL) > deadline && !killed) { kill(-pid, SIGKILL); kill(pid, SIGKILL); killed = 1; }
    }
    close(pp[0]);
    b[n] = '\0';
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (out) *out = b; else free(b);
    if (killed) return 124;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static char *trim_out(char *s) {
    if (!s) return pm_strdup("");
    size_t l = strlen(s);
    while (l && (s[l - 1] == '\n' || s[l - 1] == ' ' || s[l - 1] == '\r')) s[--l] = '\0';
    /* последняя содержательная строка — суть отказа */
    char *last = strrchr(s, '\n');
    char *r = pm_strdup(last ? last + 1 : s);
    free(s);
    return r;
}

/* scripts.<name> плагина из каталога dir с аргументом arg. 0 — нет скрипта или прошёл. */
static int run_script(const char *id, const char *dir, const struct ynode *man, const char *name,
                      const char *arg, struct pm_err *e) {
    const char *rel = yn_str(ynode_get(man, "scripts"), name);
    if (!rel) return 0;
    if (rel[0] == '/' || strstr(rel, "..")) return pm_errc(e, "plugin.script_path", PMA("id", id, "name", name), "у %s путь scripts.%s вне каталога плагина", id, name);
    char *prog = pm_path(dir, rel);
    char *conf = pm_fmt("%s/conf/%s", pm_etc(), id);
    pm_mkdirs(conf);
    char *env[] = { pm_fmt("STEER_PLUGIN_ID=%s", id), pm_fmt("STEER_PLUGIN_DIR=%s", dir),
                    pm_fmt("STEER_PLUGIN_CONF=%s", conf), pm_fmt("STEER_API=%s", PM_STEER_API), NULL };
    char *argv[] = { prog, (char *)arg, NULL };
    char *out = NULL;
    int rc = run_prog(argv, dir, env, &out, 300);
    for (int i = 0; env[i]; i++) free(env[i]);
    free(conf);
    free(prog);
    if (rc != 0) {
        char *last = trim_out(out);
        pm_errc(e, !strcmp(arg, "--check") ? "plugin.script_check_refused" : "plugin.script_failed", PMA("name", name, "id", id, "rc", pm_itoa(rc), "sep", *last ? ": " : "", "last", last), "scripts/%s плагина %s %s (код %d)%s%s", name, id,
                !strcmp(arg, "--check") ? "отказал в проверке" : "не прошёл", rc, *last ? ": " : "", last);
        free(last);
        return -1;
    }
    free(out);
    return 0;
}

/* ---- демон ---- */

static int reload_once(struct pm_ctx *x, struct pm_err *e) {
    if (x->no_daemon) return 0;
    ctlcall_socket(NULL);
    char *r = ctlcall_roundtrip("plugin-reload\n", NULL, 0, 300);
    if (!r) { x->no_daemon = 1; return 0; }
    struct ctlcall_resp rp;
    memset(&rp, 0, sizeof(rp));
    int ok = ctlcall_parse(r, &rp) == 0;
    free(r);
    if (!ok) return pm_errc(e, "plugin.reload_bad_reply", NULL, "демон ответил не по форме на plugin-reload");
    if (rp.error.p && !strcmp(rp.error.p, "unknown-command")) { ctlcall_resp_free(&rp); return 0; }
    if (!rp.has_code || rp.code != 0) {
        const char *why = rp.err.n ? rp.err.p : rp.message.p ? rp.message.p : "без причины";
        char *w = trim_out(pm_strdup(why));
        pm_errc(e, "plugin.reload_failed", PMA("why", w), "ядро не перечитало плагины: %s", w);
        free(w);
        ctlcall_resp_free(&rp);
        return -1;
    }
    ctlcall_resp_free(&rp);
    return 0;
}

/* plugin-reload. Отказ «нужен reload» — подготовка спеки не поспела за сменой плагинов (кэш подготовленной
 * спеки ключуется версиями и манифестами, и первая подготовка могла упереться в то, что ещё не лежало на
 * диске): перечитывание повторяется один раз, а не оставляется человеку. */
int pm_daemon_reload(struct pm_ctx *x, struct pm_err *e) {
    if (reload_once(x, e) == 0) return 0;
    if (!strstr(e->msg, "нужен reload")) return -1;
    struct pm_err again = {0};
    if (reload_once(x, &again) == 0) return 0;
    *e = again;
    return -1;
}

void pm_event(struct pm_ctx *x, const char *id, const char *state, const char *version, const char *from,
              const char *why) {
    if (x->no_daemon) return;
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return;
    struct jw w;
    jw_init(&w, f);
    jw_obj(&w);
    jw_kstr(&w, "id", id);
    jw_kstr(&w, "state", state);
    jw_kstr(&w, "version", version);
    jw_kstr(&w, "from", from);
    jw_kstr(&w, "why", why);
    jw_kstr(&w, "by", x->by ? x->by : "human");
    jw_end(&w);
    fclose(f);
    char line[64];
    snprintf(line, sizeof(line), "plugin-event %zu\n", n);
    ctlcall_socket(NULL);
    char *r = ctlcall_roundtrip(line, buf, n, 10);
    free(r);
    free(buf);
}

/* Демон отвечает status с кодом 0 — спека прочитана. Нет — отказ plugin-reload не вина плагина:
 * спека была негодной и до него. */
static int daemon_spec_ok(struct pm_ctx *x);

/* Выходы видов плагина, которые сейчас подняты (по status демона). */
struct outs { char **v; size_t n; };

static int kind_matches(const char *status_kind, const struct ynode *kinds) {
    for (size_t i = 0; i < ynode_len(kinds); i++) {
        const char *k = yn_str(ynode_at(kinds, i), "name");
        if (!k) continue;
        if (!strcmp(k, status_kind)) return 1;
        const char *colon = strchr(k, ':');
        if (colon && !strcmp(colon + 1, status_kind)) return 1;
    }
    return 0;
}

static struct ydoc *daemon_status(struct pm_ctx *x) {
    if (x->no_daemon) return NULL;
    ctlcall_socket(NULL);
    char *r = ctlcall_roundtrip("status\n", NULL, 0, 30);
    if (!r) return NULL;
    struct ctlcall_resp rp;
    memset(&rp, 0, sizeof(rp));
    struct ydoc *d = NULL;
    if (ctlcall_parse(r, &rp) == 0 && rp.has_code && rp.code == 0 && rp.out.p) {
        struct pm_err e;
        d = pm_json_parse(rp.out.p, rp.out.n, "status", &e);
    }
    ctlcall_resp_free(&rp);
    free(r);
    return d;
}

static int daemon_spec_ok(struct pm_ctx *x) {
    struct ydoc *d = daemon_status(x);
    if (!d) return 0;
    ydoc_free(d);
    return 1;
}

static void outs_up(struct pm_ctx *x, const struct ynode *kinds, struct outs *o) {
    memset(o, 0, sizeof(*o));
    if (!ynode_len(kinds)) return;
    struct ydoc *d = daemon_status(x);
    if (!d) return;
    const struct ynode *outs = ynode_get(ydoc_root(d), "outputs");
    for (size_t i = 0; i < ynode_len(outs); i++) {
        const struct ynode *v = ynode_val_at(outs, i);
        const char *k = yn_str(v, "kind");
        if (!k || !kind_matches(k, kinds) || !yn_bool(v, "up", 0)) continue;
        o->v = pm_realloc(o->v, sizeof(char *) * (o->n + 1));
        o->v[o->n++] = pm_strdup(ynode_key_at(outs, i)->str);
    }
    ydoc_free(d);
}

static void outs_free(struct outs *o) {
    for (size_t i = 0; i < o->n; i++) free(o->v[i]);
    free(o->v);
    memset(o, 0, sizeof(*o));
}

/* Будильники ожидания выходов: подписка на события демона (subscribe — helper-up, switched, revived,
 * failed, applied) и группа RTMGRP_LINK netlink (operstate устройства — то, по чему status судит об up у
 * выхода без помощника: интерфейс, awg, вид плагина с устройством). Любое событие — повод спросить status
 * снова; его ответ — единственный судья.
 *
 * ЧТО БЫЛО. Опрос status с шагом 20 мс, удваивавшимся до 640: выход, вставший через 0,7 с, замечался
 * через 1,3 с (замер на netns, вид плагина на dummy). Теперь — через время ответа status после события.
 * Опрос остаётся страховкой раз в секунду: нет netlink (политика SELinux телефона) или подписки (демон
 * старше subscribe) — ожидание всё равно кончается, только медленнее. */
static int wake_sub(void) {
    int s = ctlcall_open(0);
    if (s < 0) return -1;
    static const char req[] = "subscribe\n";
    if (send(s, req, sizeof(req) - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof(req) - 1)) { close(s); return -1; }
    shutdown(s, SHUT_WR);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    return s;
}

static int wake_link(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (s < 0) return -1;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_LINK;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) { close(s); return -1; }
    return s;
}

/* Вычерпать сокет. 0 — закрыт (демон ушёл или отключил подписчика): больше не ждать на нём. */
static int wake_drain(int fd) {
    char b[8192];
    for (;;) {
        ssize_t m = recv(fd, b, sizeof(b), 0);
        if (m > 0) continue;
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) return 1;
        return 0;
    }
}

static long long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Ждать, пока выходы, бывшие up, снова up. 0 — дождались; -1 — причина в e. */
static int wait_outs(struct pm_ctx *x, const struct outs *o, int timeout_s, struct pm_err *e) {
    if (!o->n || x->no_daemon) return 0;
    long long until_ms = mono_ms() + (long long)timeout_s * 1000;
    /* Будильники — до первого status: событие между ответом и подпиской не теряется. */
    struct pollfd pf[2] = { { wake_sub(), POLLIN, 0 }, { wake_link(), POLLIN, 0 } };
    int rc = -1;
    for (;;) {
        struct ydoc *d = daemon_status(x);
        const char *down = NULL;
        if (d) {
            const struct ynode *outs = ynode_get(ydoc_root(d), "outputs");
            for (size_t i = 0; i < o->n && !down; i++)
                if (!yn_bool(ynode_get(outs, o->v[i]), "up", 0)) down = o->v[i];
            if (!down) { ydoc_free(d); rc = 0; break; }
        }
        long long now_ms = mono_ms();
        if (now_ms >= until_ms) {
            pm_errc(e, "plugin.output_not_up", PMA("name", down ? down : "?", "seconds", pm_itoa(timeout_s)), "выход %s не поднялся за %d с", down ? down : "?", timeout_s);
            if (d) ydoc_free(d);
            break;
        }
        if (d) ydoc_free(d);
        long long left = until_ms - now_ms;
        int nap = left < 1000 ? (int)left : 1000;
        if (poll(pf, 2, nap) > 0)
            for (int i = 0; i < 2; i++)
                if (pf[i].revents && !wake_drain(pf[i].fd)) { close(pf[i].fd); pf[i].fd = -1; }
    }
    for (int i = 0; i < 2; i++) if (pf[i].fd >= 0) close(pf[i].fd);
    return rc;
}

/* ---- системные пакеты ---- */

static int pkg_installed(const struct pm_ctx *x, const char *name) {
    /* --pkg ИМЯ: менеджер зовёт скрипт этого пакета изнутри его транзакции — в базе его ещё нет (apk и opkg
     * пишут базу в конце транзакции, после скриптов). */
    if (x && x->pkg_tx && !strcmp(x->pkg_tx, name)) return 1;
    const char *pk = getenv("STEER_PLUGIN_PKG");
    if (pk && *pk) {
        char *argv[] = { (char *)pk, "installed", (char *)name, NULL };
        return run_prog(argv, NULL, NULL, NULL, 60) == 0;
    }
    size_t n = 0;
    char *db = pm_read("/lib/apk/db/installed", &n);
    if (db) {
        int hit = 0;
        for (char *l = strtok(db, "\n"); l && !hit; l = strtok(NULL, "\n"))
            if (l[0] == 'P' && l[1] == ':' && !strcmp(l + 2, name)) hit = 1;
        free(db);
        return hit;
    }
    db = pm_read("/usr/lib/opkg/status", &n);
    if (!db) return 0;
    int hit = 0, cur = 0;
    for (char *l = strtok(db, "\n"); l && !hit; l = strtok(NULL, "\n")) {
        if (!strncmp(l, "Package: ", 9)) cur = !strcmp(l + 9, name);
        else if (cur && !strncmp(l, "Status: ", 8) && strstr(l, " installed")) hit = 1;
    }
    free(db);
    return hit;
}

/* Поставить пакет. Единственный вызов чужой утилиты менеджера (manifest.md, requires.system). */
static int pkg_add(const char *name, struct pm_err *e) {
    const char *pk = getenv("STEER_PLUGIN_PKG");
    char *out = NULL;
    int rc;
    if (pk && *pk) {
        char *argv[] = { (char *)pk, "add", (char *)name, NULL };
        rc = run_prog(argv, NULL, NULL, &out, 600);
    } else if (pm_exists("/lib/apk/db/installed")) {
        char *argv[] = { "apk", "add", (char *)name, NULL };
        rc = run_prog(argv, NULL, NULL, &out, 600);
    } else {
        char *argv[] = { "opkg", "install", (char *)name, NULL };
        rc = run_prog(argv, NULL, NULL, &out, 600);
        if (rc != 0) {
            /* Списки фидов opkg живут в /var (tmpfs) и после перезагрузки пусты. */
            free(out);
            char *up[] = { "opkg", "update", NULL };
            run_prog(up, NULL, NULL, NULL, 600);
            rc = run_prog(argv, NULL, NULL, &out, 600);
        }
    }
    if (rc != 0) {
        char *last = trim_out(out);
        pm_errc(e, "plugin.package_failed", PMA("name", name, "sep", *last ? ": " : "", "last", last), "пакет %s не поставился%s%s", name, *last ? ": " : "", last);
        free(last);
        return -1;
    }
    free(out);
    return 0;
}

/* ---- план ---- */

struct item { struct pm_cand c; };
struct plan { struct item *v; size_t n; };

static struct item *plan_find(struct plan *p, const char *id) {
    for (size_t i = 0; i < p->n; i++)
        if (!strcmp(p->v[i].c.id, id)) return &p->v[i];
    return NULL;
}

struct stk { const char *id; const struct stk *up; };

static int resolve(struct pm_ctx *x, struct plan *p, const char *id, const char *range, const char *exact,
                   struct pm_repo *prefer, const char *variant, const struct stk *up, int is_root,
                   const struct pm_opts *o, struct pm_repos *seedrs, struct pm_err *e);

static int resolve_in(struct pm_ctx *x, struct plan *p, struct pm_repo *r, const char *id, const char *range,
                      const char *exact, const char *variant, const struct stk *up, const struct pm_opts *o,
                      struct pm_repos *seedrs, struct pm_err *e) {
    const char *below = NULL;
    char *below_buf = NULL;
    struct pm_err first = {0};
    for (;;) {
        struct pm_cand c;
        struct pm_err se = {0};
        if (pm_select(x, r, id, range, exact, variant, below, &c, &se) != 0) {
            if (!first.msg[0]) first = se;
            break;
        }
        size_t save = p->n;
        struct stk me = { c.id, up };
        const struct ynode *deps = ynode_get(ynode_get(c.ver, "requires"), "plugins");
        int ok = 1;
        for (size_t i = 0; i < ynode_len(deps) && ok; i++) {
            const char *did = ynode_key_at(deps, i)->str;
            const struct ynode *dr = ynode_val_at(deps, i);
            struct pm_err de = {0};
            if (resolve(x, p, did, yn_is_str(dr) ? dr->str : NULL, NULL, r, "full", &me, 0, o, seedrs, &de) != 0) {
                ok = 0;
                if (!first.msg[0]) pm_errc(&first, "plugin.dependency_failed", PMA("id", c.id, "version", c.version, "why", de.msg), "%s %s: %s", c.id, c.version, de.msg);
            }
        }
        if (ok) {
            p->v = pm_realloc(p->v, sizeof(*p->v) * (p->n + 1));
            p->v[p->n++].c = c;
            free(below_buf);
            return 0;
        }
        p->n = save;
        free(below_buf);
        below_buf = pm_strdup(c.version);
        below = below_buf;
        if (exact) break;
    }
    free(below_buf);
    *e = first;
    if (!e->msg[0]) pm_errc(e, "plugin.no_suitable_version", PMA("id", id), "нет годной версии %s", id);
    return -1;
}

static int resolve(struct pm_ctx *x, struct plan *p, const char *id, const char *range, const char *exact,
                   struct pm_repo *prefer, const char *variant, const struct stk *up, int is_root,
                   const struct pm_opts *o, struct pm_repos *seedrs, struct pm_err *e) {
    for (const struct stk *s = up; s; s = s->up) {
        if (strcmp(s->id, id)) continue;
        char *chain = pm_strdup(id);
        for (const struct stk *t = up; t; t = t->up) {
            char *n = pm_fmt("%s → %s", t->id, chain);
            free(chain);
            chain = n;
            if (!strcmp(t->id, id)) break;
        }
        pm_errc(e, "plugin.dependency_cycle", PMA("chain", chain), "цикл зависимостей: %s", chain);
        free(chain);
        return -1;
    }
    struct item *have = plan_find(p, id);
    if (have) {
        if (range && pm_range_match(range, have->c.version) <= 0)
            return pm_errc(e, "plugin.version_conflict", PMA("id", id, "range", range, "have", have->c.version), "нужен %s %s, а план уже берёт %s", id, range, have->c.version);
        return 0;
    }
    struct pm_inst *inst = pm_state_find(&x->st, id);
    if (!is_root && inst && inst->version && (!range || pm_range_match(range, inst->version) > 0) &&
        (!inst->state || strcmp(inst->state, "failed")))
        return 0;
    struct pm_repos *rs = o->seed_only ? seedrs : &x->repos;
    /* Обновление — только из репозитория, из которого плагин поставлен (index.md). */
    if (!o->seed_only && inst && inst->repo) {
        struct pm_repo *own = pm_repo_find(rs, inst->repo);
        if (!own) return pm_errc(e, "plugin.repo_disabled", PMA("repo", inst->repo, "id", id), "репозиторий %s, из которого поставлен %s, отключён", inst->repo, id);
        struct pm_err ie = {0};
        if (pm_index_get(own, 1, &ie) != 0) return pm_errcopy(e, &ie);
        return resolve_in(x, p, own, id, range, exact, variant, up, o, seedrs, e);
    }
    struct pm_err best = {0};
    int tried = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < rs->n; i++) {
            struct pm_repo *r = &rs->v[i];
            if ((pass == 0) != (r == prefer)) continue;
            struct pm_err ie = {0};
            if (pm_index_get(r, !o->seed_only, &ie) != 0) {
                if (!best.msg[0]) best = ie;
                continue;
            }
            if (!pm_index_plugin(r, id)) continue;
            tried = 1;
            struct pm_err re = {0};
            if (resolve_in(x, p, r, id, range, exact, variant, up, o, seedrs, &re) == 0) return 0;
            if (!best.msg[0] || tried == 1) best = re;
            if (exact) break;
        }
    }
    if (!tried && !best.msg[0]) return pm_errc(e, "plugin.not_in_any_repo", PMA("id", id), "плагина %s нет ни в одном репозитории", id);
    if (!tried) return pm_errc(e, "plugin.not_in_any_available_repo", PMA("id", id, "why", best.msg), "плагина %s нет ни в одном доступном репозитории (%s)", id, best.msg);
    *e = best;
    return -1;
}

/* ---- архив: получение ---- */

int pm_file_sha256(const char *path, unsigned char out[32], unsigned long long *size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct sc_hash_ctx h;
    if (sc_hash_init(&h, SC_SHA256) != 0) { close(fd); return -1; }
    unsigned char buf[65536];
    unsigned long long n = 0;
    for (;;) {
        ssize_t m = read(fd, buf, sizeof(buf));
        if (m < 0 && errno == EINTR) continue;
        if (m < 0) { sc_hash_free(&h); close(fd); return -1; }
        if (m == 0) break;
        sc_hash_update(&h, buf, (size_t)m);
        n += (unsigned long long)m;
    }
    close(fd);
    sc_hash_final(&h, out);
    sc_hash_free(&h);
    *size = n;
    return 0;
}

static void hex32(const unsigned char *b, char out[65]) {
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[64] = '\0';
}

/* Файл сходится с size и sha256 индекса? NULL — да; иначе что не так. */
static const char *asset_mismatch(const char *path, const struct ynode *asset, char *buf, size_t n) {
    unsigned char h[32];
    unsigned long long sz = 0;
    if (pm_file_sha256(path, h, &sz) != 0) { snprintf(buf, n, "не читается"); return buf; }
    long want = yn_long(asset, "size", -1);
    if (want >= 0 && (unsigned long long)want != sz) {
        snprintf(buf, n, "размер %llu, а в индексе %ld", sz, want);
        return buf;
    }
    char hx[65];
    hex32(h, hx);
    const char *ws = yn_str(asset, "sha256");
    if (!ws || strcasecmp(ws, hx)) { snprintf(buf, n, "sha256 не совпадает с индексом"); return buf; }
    return NULL;
}

/* Архив кандидата: путь к проверенному по индексу файлу (malloc), *tmp — его надо удалить. */
static char *fetch_asset(struct pm_ctx *x, const struct pm_cand *c, int *tmp, struct pm_err *e) {
    const char *path = yn_str(c->asset, "path");
    *tmp = 0;
    char why[512] = "";
    if (c->repo->seed) {
        const char *base = path ? strrchr(path, '/') : NULL;
        char *cands[2] = { path ? pm_path(pm_seed(), path) : NULL,
                           path ? pm_path(pm_seed(), base ? base + 1 : path) : NULL };
        for (int i = 0; i < 2; i++) {
            if (!cands[i] || !pm_exists(cands[i])) continue;
            if (!asset_mismatch(cands[i], c->asset, why, sizeof(why))) {
                char *r = cands[i];
                for (int j = 0; j < 2; j++) if (j != i) free(cands[j]);
                return r;
            }
        }
        free(cands[0]); free(cands[1]);
        pm_errc(e, why[0] ? "plugin.seed_archive_broken" : "plugin.seed_archive_missing", PMA("id", c->id, "version", c->version, "why", why), "архива %s %s в семени нет%s%s", c->id, c->version, why[0] ? " или он испорчен: " : "", why);
        return NULL;
    }
    pm_mkdirs(pm_tmp());
    char *dest = pm_fmt("%s/%s-%s-%s.s2p", pm_tmp(), c->id, c->version, c->asset_key);
    /* Адреса: репозиторий, его зеркала, зеркала индекса — с относительным path; затем url[]. */
    size_t nu = 0;
    char **urls = NULL;
    if (path) {
        const struct ynode *im = ynode_get(c->repo->iroot, "mirrors");
        size_t nb = 1 + c->repo->nmirrors + ynode_len(im);
        for (size_t i = 0; i < nb; i++) {
            const char *b = i == 0 ? c->repo->url : i <= c->repo->nmirrors ? c->repo->mirrors[i - 1]
                                    : (yn_is_str(ynode_at(im, i - 1 - c->repo->nmirrors)) ? ynode_at(im, i - 1 - c->repo->nmirrors)->str : NULL);
            if (!b || !*b) continue;
            urls = pm_realloc(urls, sizeof(char *) * (nu + 1));
            urls[nu++] = pm_path(b, path);
        }
    }
    const struct ynode *ul = ynode_get(c->asset, "url");
    for (size_t i = 0; i < ynode_len(ul); i++) {
        if (!yn_is_str(ynode_at(ul, i))) continue;
        urls = pm_realloc(urls, sizeof(char *) * (nu + 1));
        urls[nu++] = pm_strdup(ynode_at(ul, i)->str);
    }
    char *last = NULL;
    char *res = NULL;
    int last_tamper = 0;     /* причина «подмена» важнее сбоя сети на следующем зеркале */
    for (size_t i = 0; i < nu && !res; i++) {
        pm_progress(x, "скачивание %s %s", c->id, c->version);
        struct http_req q = {0};
        q.url = urls[i];
        q.dest_path = dest;
        q.connect_ms = 10000;
        q.idle_ms = 30000;
        struct http_resp rp = {0};
        char hw[256] = "";
        int rc = http_get(&q, &rp, hw, sizeof(hw));
        if (rc == 0 && (rp.status < 200 || rp.status > 299)) { snprintf(hw, sizeof(hw), "ответ %d", rp.status); rc = -1; }
        http_resp_free(&rp);
        if (rc != 0) {
            if (!last_tamper) {
                free(last);
                last = pm_fmt("%s: %s", urls[i], hw);
            }
            unlink(dest);
            continue;
        }
        if (asset_mismatch(dest, c->asset, why, sizeof(why))) {
            free(last);
            last_tamper = 1;
            last = pm_fmt("архив %s %s с %s не совпал с подписанным индексом (%s) — подмена", c->id, c->version, urls[i], why);
            unlink(dest);
            continue;
        }
        res = dest;
        *tmp = 1;
    }
    for (size_t i = 0; i < nu; i++) free(urls[i]);
    free(urls);
    if (!res) {
        if (!nu) pm_errc(e, "plugin.no_archive_url", PMA("id", c->id, "version", c->version), "у архива %s %s в индексе нет адреса", c->id, c->version);
        else pm_errc(e, "plugin.archive_download", PMA("why", last ? last : "архив не скачался"), "%s", last ? last : "архив не скачался");
        free(dest);
    }
    free(last);
    return res;
}

/* ---- архив: распаковка с проверкой ---- */

struct mline { char *path; unsigned char sha[32]; unsigned long long size; unsigned mode; int seen; };

struct uv {
    const char *stage, *id;
    const struct pm_keyset *ks;
    int unsigned_ok, is_unsigned;
    int count;
    unsigned char pj_sha[32];
    unsigned long long pj_size;
    struct mline *m; size_t nm;
    char **dirs; size_t ndirs;
    char hdr_id[128], hdr_ver[128], hdr_arch[128];
    struct pm_err *e;
};

static int mline_cmp(const void *a, const void *b) {
    return strcmp(((const struct mline *)a)->path, ((const struct mline *)b)->path);
}

static int unhex(const char *s, unsigned char *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return s[2 * n] == ' ' ? 0 : -1;
}

static int manifest_parse(struct uv *u, char *text) {
    char *save = NULL;
    char *l = strtok_r(text, "\n", &save);
    if (!l || sscanf(l, "s2p 1 %127s %127s %127s", u->hdr_id, u->hdr_ver, u->hdr_arch) != 3)
        return pm_errc(u->e, "plugin.manifest_header", PMA("id", u->id), "MANIFEST %s: заголовок не «s2p 1 <id> <версия> <арх>»", u->id);
    for (l = strtok_r(NULL, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        struct mline m = {0};
        unsigned long long sz;
        unsigned mode;
        int off = 0;
        if (strlen(l) < 66 || unhex(l, m.sha, 32) != 0 ||
            sscanf(l + 65, "%llu %o %n", &sz, &mode, &off) < 2 || !off || !l[65 + off])
            return pm_errc(u->e, "plugin.manifest_line", PMA("id", u->id, "line", l), "MANIFEST %s: строка не разбирается: %.80s", u->id, l);
        m.size = sz;
        m.mode = mode;
        m.path = pm_strdup(l + 65 + off);
        u->m = pm_realloc(u->m, sizeof(*u->m) * (u->nm + 1));
        u->m[u->nm++] = m;
    }
    qsort(u->m, u->nm, sizeof(*u->m), mline_cmp);
    for (size_t i = 1; i < u->nm; i++)
        if (!strcmp(u->m[i - 1].path, u->m[i].path))
            return pm_errc(u->e, "plugin.manifest_file_twice", PMA("id", u->id, "path", u->m[i].path), "MANIFEST %s: файл %s назван дважды", u->id, u->m[i].path);
    return 0;
}

static struct mline *mline_find(struct uv *u, const char *path) {
    struct mline key = { (char *)path, {0}, 0, 0, 0 };
    return bsearch(&key, u->m, u->nm, sizeof(*u->m), mline_cmp);
}

static int uv_cb(void *arg, const struct untar_entry *en) {
    struct uv *u = arg;
    int idx = u->count++;
    unsigned special = en->rawmode & 07000;
    if (special) return pm_errc(u->e, "plugin.entry_special", PMA("path", en->path), "запись %s: setuid, setgid или sticky", en->path);
    static const char *first[3] = { "plugin.json", "MANIFEST", "MANIFEST.sig" };
    if (idx < 3) {
        if (en->type != UNTAR_FILE || strcmp(en->path, first[idx]))
            return pm_errc(u->e, "plugin.entry_order", PMA("id", u->id, "index", pm_itoa(idx + 1), "want", first[idx], "path", en->path), "архив %s: запись %d должна быть %s, а это %s", u->id, idx + 1, first[idx], en->path);
        if ((en->rawmode & 0777) != 0644)
            return pm_errc(u->e, "plugin.entry_mode_file", PMA("path", en->path, "mode", pm_oct(en->rawmode & 0777)), "запись %s: режим %03o, а нужен 0644", en->path, en->rawmode & 0777);
        if (idx == 0) { memcpy(u->pj_sha, en->sha256, 32); u->pj_size = en->size; }
        if (idx < 2) return 0;
        /* Третья запись — подпись: проверить MANIFEST до остального. */
        char *mp = pm_path(u->stage, "MANIFEST"), *sp = pm_path(u->stage, "MANIFEST.sig");
        size_t mn = 0, sn = 0;
        char *mt = pm_read(mp, &mn), *st = pm_read(sp, &sn);
        free(mp); free(sp);
        if (!mt || !st) { free(mt); free(st); return pm_errc(u->e, "plugin.manifest_unreadable", PMA("id", u->id), "MANIFEST %s не читается", u->id); }
        if (sn == 0) {
            if (!u->unsigned_ok) { free(mt); free(st); return pm_errc(u->e, "plugin.archive_unsigned", PMA("id", u->id), "архив %s не подписан", u->id); }
            u->is_unsigned = 1;
        } else {
            char *what = pm_fmt("MANIFEST %s", u->id);
            int r = pm_sig_check(u->ks, st, sn, mt, mn, what, u->e);
            free(what);
            if (r != 0) { free(mt); free(st); return -1; }
        }
        free(st);
        int r = manifest_parse(u, mt);
        free(mt);
        if (r != 0) return -1;
        struct mline *pj = mline_find(u, "plugin.json");
        if (!pj || pj->size != u->pj_size || memcmp(pj->sha, u->pj_sha, 32))
            return pm_errc(u->e, "plugin.json_manifest_mismatch", PMA("id", u->id), "plugin.json %s не совпадает с MANIFEST — подмена", u->id);
        pj->seen = 1;
        return 0;
    }
    if (en->type == UNTAR_DIR) {
        if ((en->rawmode & 0777) != 0755)
            return pm_errc(u->e, "plugin.dir_mode", PMA("path", en->path, "mode", pm_oct(en->rawmode & 0777)), "каталог %s: режим %03o, а нужен 0755", en->path, en->rawmode & 0777);
        u->dirs = pm_realloc(u->dirs, sizeof(char *) * (u->ndirs + 1));
        u->dirs[u->ndirs++] = pm_strdup(en->path);
        return 0;
    }
    if (en->type != UNTAR_FILE) return pm_errc(u->e, "plugin.entry_not_file", PMA("path", en->path), "запись %s: не файл и не каталог", en->path);
    if (!strcmp(en->path, "MANIFEST") || !strcmp(en->path, "MANIFEST.sig") || !strcmp(en->path, "plugin.json"))
        return pm_errc(u->e, "plugin.entry_twice", PMA("id", u->id, "path", en->path), "архив %s: запись %s повторена", u->id, en->path);
    struct mline *m = mline_find(u, en->path);
    if (!m) return pm_errc(u->e, "plugin.extra_file", PMA("id", u->id, "path", en->path), "в архиве %s лишний файл %s, которого нет в MANIFEST — подмена", u->id, en->path);
    unsigned mode = en->rawmode & 0777;
    if (mode != 0644 && mode != 0755) return pm_errc(u->e, "plugin.file_mode", PMA("path", en->path, "mode", pm_oct(mode)), "файл %s: режим %03o, а нужен 0644 или 0755", en->path, mode);
    if (m->size != en->size || memcmp(m->sha, en->sha256, 32))
        return pm_errc(u->e, "plugin.file_mismatch", PMA("path", en->path, "id", u->id), "файл %s архива %s не совпадает с MANIFEST — подмена", en->path, u->id);
    if (m->mode != mode) return pm_errc(u->e, "plugin.file_mode_mismatch", PMA("path", en->path, "mode", pm_oct(mode), "want", pm_oct(m->mode)), "файл %s: режим %03o, а в MANIFEST %03o", en->path, mode, m->mode);
    m->seen = 1;
    return 0;
}

static void uv_free(struct uv *u) {
    for (size_t i = 0; i < u->nm; i++) free(u->m[i].path);
    free(u->m);
    for (size_t i = 0; i < u->ndirs; i++) free(u->dirs[i]);
    free(u->dirs);
}

/* Распаковать archive в stage с полной сверкой. 0 — годится; *is_unsigned — без подписи. */
static int unpack_verified(const char *archive, const char *stage, const char *id, const struct pm_keyset *ks,
                           int unsigned_ok, int *is_unsigned, char *hdr_id, char *hdr_ver, char *hdr_arch, size_t hn,
                           struct pm_err *e) {
    pm_rmrf(stage);
    char *sd = pm_path(pm_root(), ".stage");
    pm_mkdirs(sd);
    free(sd);
    struct uv u = {0};
    u.stage = stage;
    u.id = id ? id : "из файла";
    u.ks = ks;
    u.unsigned_ok = unsigned_ok;
    u.e = e;
    e->msg[0] = '\0';
    struct untar_opts uo = { uv_cb, &u, 0, UNTAR_NO_LINKS | UNTAR_STRICT_END };
    char why[512] = "";
    int rc = untar_gz_file(archive, stage, &uo, why, sizeof(why));
    if (rc != 0) {
        if (!e->msg[0]) pm_errc(e, "plugin.unpack_failed", PMA("id", id, "why", why), "архив %s не распаковался: %s", id, why);
        uv_free(&u);
        pm_rmrf(stage);
        return -1;
    }
    if (u.count < 3) { pm_errc(e, "plugin.archive_incomplete", PMA("id", id), "архив %s: нет plugin.json, MANIFEST и MANIFEST.sig", id); goto bad; }
    for (size_t i = 0; i < u.nm; i++)
        if (!u.m[i].seen) { pm_errc(e, "plugin.archive_file_missing", PMA("id", id, "path", u.m[i].path), "в архиве %s нет файла %s из MANIFEST — подмена", id, u.m[i].path); goto bad; }
    for (size_t i = 0; i < u.ndirs; i++) {
        size_t dl = strlen(u.dirs[i]);
        int used = 0;
        for (size_t j = 0; j < u.nm && !used; j++)
            if (!strncmp(u.m[j].path, u.dirs[i], dl) && u.m[j].path[dl] == '/') used = 1;
        if (!used) { pm_errc(e, "plugin.extra_dir", PMA("id", id, "path", u.dirs[i]), "в архиве %s лишний каталог %s", id, u.dirs[i]); goto bad; }
    }
    if (id && strcmp(u.hdr_id, id)) { pm_errc(e, "plugin.archive_name", PMA("got", u.hdr_id, "want", id), "архив назван %s, а ждали %s — подмена", u.hdr_id, id); goto bad; }
    *is_unsigned = u.is_unsigned;
    snprintf(hdr_id, hn, "%s", u.hdr_id);
    snprintf(hdr_ver, hn, "%s", u.hdr_ver);
    snprintf(hdr_arch, hn, "%s", u.hdr_arch);
    uv_free(&u);
    return 0;
bad:
    uv_free(&u);
    pm_rmrf(stage);
    return -1;
}

/* ---- проверки манифеста ---- */

static int has_perm(const struct ynode *man, const char *p) {
    return has_str(ynode_get(man, "permissions"), p);
}

static int nonempty(const struct ynode *n) {
    if (!n) return 0;
    if (n->kind == YN_SCALAR) return !(n->style == YS_PLAIN && ynode_is_null(n)) && n->len;
    return n->len > 0;
}

/* Путь вне каталогов плагина разрешён правом fs:<путь> (каталог — с «/» на конце или любой путь под ним). */
static int fs_allowed(const struct ynode *man, const char *k) {
    const struct ynode *perms = ynode_get(man, "permissions");
    for (size_t j = 0; j < ynode_len(perms); j++) {
        const char *p = yn_is_str(ynode_at(perms, j)) ? ynode_at(perms, j)->str : "";
        if (strncmp(p, "fs:", 3)) continue;
        size_t pl = strlen(p + 3);
        if (pl && !strncmp(k, p + 3, pl) && (k[pl] == '\0' || k[pl] == '/' || p[3 + pl - 1] == '/')) return 1;
    }
    return 0;
}

/* Права, impl: core, standalone, занятые имена (manifest.md, «Проверки при установке»). */
static int manifest_checks(struct pm_ctx *x, const char *id, const struct ynode *man, int official,
                           const char *repo, struct pm_err *e) {
    const struct ynode *steer = ynode_get(man, "steer");
    const struct ynode *kinds = ynode_get(steer, "kinds");
    int nft = nonempty(ynode_get(steer, "nft")), transform = nonempty(ynode_get(ynode_get(steer, "hooks"), "pre_apply"));
    for (size_t i = 0; i < ynode_len(kinds); i++) {
        const struct ynode *k = ynode_at(kinds, i);
        if (nonempty(ynode_get(k, "nft"))) nft = 1;
        if (nonempty(ynode_get(k, "expand"))) transform = 1;
        const char *impl = yn_str(k, "impl");
        if (impl && !strcmp(impl, "core")) {
            const char *kn = yn_str(k, "name");
            if (!official) return pm_errc(e, "plugin.core_impl_official", PMA("id", id), "%s: impl: core принимается только из официального репозитория", id);
            if (!kn || strcmp(kn, "awg")) return pm_errc(e, "plugin.core_impl_kind", PMA("id", id, "kind", kn ? kn : "?"), "%s: вида %s ядро не знает — impl: core для него нельзя", id, kn ? kn : "?");
        }
    }
    if (nft && !has_perm(man, "nft")) return pm_errc(e, "plugin.perm_nft", PMA("id", id), "%s: файлы nft без права nft", id);
    if (transform && !has_perm(man, "spec.transform")) return pm_errc(e, "plugin.perm_transform", PMA("id", id), "%s: хуки pre_apply/expand без права spec.transform", id);
    if (nonempty(ynode_get(steer, "so")) && !has_perm(man, "so")) return pm_errc(e, "plugin.perm_so", PMA("id", id), "%s: steer.so без права so", id);
    if (nonempty(ynode_get(ynode_get(man, "requires"), "system")) && !has_perm(man, "system-packages"))
        return pm_errc(e, "plugin.perm_system", PMA("id", id), "%s: requires.system без права system-packages", id);
    if (nonempty(ynode_get(man, "standalone")) && !official) return pm_errc(e, "plugin.standalone_official", PMA("id", id), "%s: standalone разрешён только официальному репозиторию", id);
    const struct ynode *keep = ynode_get(man, "keep");
    for (size_t i = 0; i < ynode_len(keep); i++) {
        const char *k = yn_is_str(ynode_at(keep, i)) ? ynode_at(keep, i)->str : NULL;
        if (!k || k[0] != '/' || strstr(k, "..")) return pm_errc(e, "plugin.keep_path", PMA("id", id, "path", k ? k : ""), "%s: путь keep «%s» не абсолютный", id, k ? k : "");
        if (!fs_allowed(man, k)) return pm_errc(e, "plugin.keep_perm", PMA("id", id, "path", k), "%s: путь keep %s без права fs:", id, k);
    }
    /* Имена глобальны: вид, подкоманда, служба, занятые другим плагином или ядром. */
    struct { const char *sect, *what; } names[] = { {"kinds", "вид"}, {"commands", "подкоманда"}, {"services", "служба"} };
    for (int s = 0; s < 3; s++) {
        const struct ynode *list = ynode_get(steer, names[s].sect);
        for (size_t i = 0; i < ynode_len(list); i++) {
            const char *nm = yn_str(ynode_at(list, i), "name");
            if (!nm) continue;
            /* Имя подкоманды ядра плагину не даётся — тот же отбор, что в реестре (kinds/plugin.c). */
            if (s == 1 && cli_lookup(nm)) return pm_errc(e, "plugin.subcommand_core", PMA("name", nm), "подкоманда %s — команда ядра, плагину её не дать", nm);
            for (size_t j = 0; j < x->st.n; j++) {
                const struct pm_inst *o = &x->st.v[j];
                if (!strcmp(o->id, id)) continue;
                struct ydoc *om = pm_manifest(o->id);
                if (!om) continue;
                const struct ynode *ol = ynode_get(ynode_get(ydoc_root(om), "steer"), names[s].sect);
                int hit = 0;
                for (size_t k = 0; k < ynode_len(ol) && !hit; k++) {
                    const char *on = yn_str(ynode_at(ol, k), "name");
                    if (on && !strcmp(on, nm)) hit = 1;
                }
                ydoc_free(om);
                if (hit) {
                    static const char *const wk[] = { "kind", "command", "service" };
                    char tc[64];
                    snprintf(tc, sizeof(tc), "plugin.name_taken_%s%s", wk[s], o->repo ? "" : "_file");
                    return pm_errc(e, tc, PMA("name", nm, "owner", o->id, "repo", o->repo ? o->repo : ""), "%s %s уже есть у %s из %s", names[s].what, nm, o->id, o->repo ? o->repo : "файла");
                }
            }
        }
    }
    (void)repo;
    return 0;
}

/* Системные пакеты и пути ядра. sys_out — что поставлено менеджером. */
static int system_deps(struct pm_ctx *x, const char *id, const struct ynode *man, char ***sys_out, size_t *nsys,
                       struct pm_err *e) {
    const struct ynode *req = ynode_get(man, "requires");
    const struct ynode *sys = ynode_get(req, "system");
    for (size_t i = 0; i < ynode_len(sys); i++) {
        const char *alt = yn_is_str(ynode_at(sys, i)) ? ynode_at(sys, i)->str : NULL;
        if (!alt) continue;
        char *copy = pm_strdup(alt), *save = NULL, *firstp = NULL;
        int have = 0;
        for (char *p = strtok_r(copy, "|", &save); p && !have; p = strtok_r(NULL, "|", &save)) {
            while (*p == ' ') p++;
            if (!firstp) firstp = p;
            if (pkg_installed(x, p)) have = 1;
        }
        if (!have && firstp && x->pkg_tx) {
            /* Изнутри транзакции apk/opkg база заперта: поставить пакет нельзя. */
            free(copy);
            return pm_errc(e, "plugin.needs_package_after", PMA("id", id, "pkg", firstp, "tx", x->pkg_tx), "%s не встаёт: нужен пакет %s — поставьте его после установки %s", id, firstp, x->pkg_tx);
        }
        if (!have && firstp) {
            pm_progress(x, "пакет %s для %s", firstp, id);
            if (pkg_add(firstp, e) != 0) { free(copy); return -1; }
            *sys_out = pm_realloc(*sys_out, sizeof(char *) * (*nsys + 1));
            (*sys_out)[(*nsys)++] = pm_strdup(firstp);
        }
        free(copy);
    }
    const struct ynode *kern = ynode_get(req, "kernel");
    for (size_t i = 0; i < ynode_len(kern); i++) {
        const char *alt = yn_is_str(ynode_at(kern, i)) ? ynode_at(kern, i)->str : NULL;
        if (!alt) continue;
        char *copy = pm_strdup(alt), *save = NULL;
        int have = 0;
        for (char *p = strtok_r(copy, "|", &save); p && !have; p = strtok_r(NULL, "|", &save)) {
            while (*p == ' ') p++;
            if (pm_exists(p)) have = 1;
        }
        free(copy);
        if (!have) {
            const char *pk = ynode_len(sys) ? (yn_is_str(ynode_at(sys, 0)) ? ynode_at(sys, 0)->str : NULL) : NULL;
            return pm_errc(e, pk ? "plugin.system_missing_pkg" : "plugin.system_missing", PMA("id", id, "alt", alt, "package", pk ? pk : ""), "%s не встаёт: нет %s%s%s", id, alt, pk ? " (нужен пакет " : "", pk ? pk : "");
        }
    }
    return 0;
}

/* ---- keep.d ---- */

int pm_keepd_write(struct pm_ctx *x) {
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return -1;
    fprintf(f, "%s/\n%s/\n", pm_root(), pm_etc());
    for (size_t i = 0; i < x->st.n; i++) {
        struct ydoc *m = pm_manifest(x->st.v[i].id);
        if (!m) continue;
        const struct ynode *keep = ynode_get(ydoc_root(m), "keep");
        for (size_t j = 0; j < ynode_len(keep); j++)
            if (yn_is_str(ynode_at(keep, j))) fprintf(f, "%s\n", ynode_at(keep, j)->str);
        /* Копии настроек steer.links (mode: conf) — то же, что conffiles пакета: переживают sysupgrade. */
        const struct ynode *links = ynode_get(ynode_get(ydoc_root(m), "steer"), "links");
        for (size_t j = 0; j < ynode_len(links); j++) {
            const char *lm = yn_str(ynode_at(links, j), "mode"), *lp = yn_str(ynode_at(links, j), "path");
            if (lp && lm && !strcmp(lm, "conf")) fprintf(f, "%s\n", lp);
        }
        ydoc_free(m);
    }
    fclose(f);
    int r = pm_write_atomic(pm_keepd(), buf, n, 0644);
    free(buf);
    return r;
}

/* ---- steer.links (steer-api 1.3; manifest.md, «steer.links») ----
 *
 * Пути в системе, которые плагин занимает, пока стоит: то, что чужая программа ищет по известному адресу, а
 * плагин держит у себя в каталоге (box-connector: /usr/bin/sing-box и /etc/init.d/sing-box для podkop и forkop,
 * страница LuCI). Код у плагина — только в его каталоге; в системе — ссылки, которые ведёт менеджер:
 *   link (умолчание) — символическая ссылка path → <каталог плагина>/<target>. Каталог плагина при обновлении и
 *        откате меняется rename(2) под тем же именем, так что ссылка переживает и то и другое; снимается вместе
 *        с плагином;
 *   conf — копия target, если файла path нет: настройки, которые правит чужая программа (uci). Не
 *        перезаписывается, переживает снятие (как conffiles пакета) и sysupgrade (keep.d); --purge убирает.
 * Каждый path — под правом fs:, у одного плагина; путь, занятый не менеджером (файл пакета), — отказ, который
 * называет пакет. Ссылки живут, пока плагин стоит, включён он или выключен: чужая программа ищет их всегда. */

/* Пакет, которому принадлежит path (NULL — ничей или базы нет). Заглушка стенда — STEER_PLUGIN_PKG owner. */
static char *pkg_owner(const char *path) {
    const char *pk = getenv("STEER_PLUGIN_PKG");
    if (pk && *pk) {
        char *argv[] = { (char *)pk, "owner", (char *)path, NULL };
        char *out = NULL;
        if (run_prog(argv, NULL, NULL, &out, 60) != 0) { free(out); return NULL; }
        char *r = trim_out(out);
        if (!*r) { free(r); return NULL; }
        return r;
    }
    size_t n = 0;
    char *db = pm_read("/lib/apk/db/installed", &n);
    const char *rel = path[0] == '/' ? path + 1 : path;
    if (db) {
        /* P:пакет, F:каталог, R:файл каталога — путь без начального «/». */
        char *pkg = NULL, *hit = NULL;
        const char *dir = "";
        for (char *l = strtok(db, "\n"); l && !hit; l = strtok(NULL, "\n")) {
            if (l[0] == 'P' && l[1] == ':') { pkg = l + 2; dir = ""; }
            else if (l[0] == 'F' && l[1] == ':') dir = l + 2;
            else if (l[0] == 'R' && l[1] == ':' && pkg) {
                size_t dl = strlen(dir);
                if (dl ? (!strncmp(rel, dir, dl) && rel[dl] == '/' && !strcmp(rel + dl + 1, l + 2)) : !strcmp(rel, l + 2))
                    hit = pm_strdup(pkg);
            }
        }
        free(db);
        return hit;
    }
    /* opkg: /usr/lib/opkg/info/<пакет>.list — по пути на строку. */
    char *hit = NULL;
    DIR *dd = opendir("/usr/lib/opkg/info");
    if (!dd) return NULL;
    struct dirent *de;
    while (!hit && (de = readdir(dd))) {
        size_t nl = strlen(de->d_name);
        if (nl < 6 || strcmp(de->d_name + nl - 5, ".list")) continue;
        char *lp = pm_fmt("/usr/lib/opkg/info/%s", de->d_name);
        char *lst = pm_read(lp, &n);
        free(lp);
        if (!lst) continue;
        for (char *l = strtok(lst, "\n"); l && !hit; l = strtok(NULL, "\n"))
            if (!strcmp(l, path)) hit = pm_fmt("%.*s", (int)(nl - 5), de->d_name);
        free(lst);
    }
    closedir(dd);
    return hit;
}

/* Ссылка ли path менеджера на каталог плагина id (любой target). */
static int link_ours(const char *full, const char *id) {
    char buf[4096];
    ssize_t r = readlink(full, buf, sizeof(buf) - 1);
    if (r < 0) return 0;
    buf[r] = '\0';
    char *pre = pm_fmt("%s/%s/", pm_root(), id);
    int ours = !strncmp(buf, pre, strlen(pre));
    free(pre);
    return ours;
}

static const char *link_mode(const struct ynode *l) {
    const char *m = yn_str(l, "mode");
    return m ? m : "link";
}

static const struct ynode *links_of(const struct ynode *man) {
    return man ? ynode_get(ynode_get(man, "steer"), "links") : NULL;
}

static int links_has(const struct ynode *links, const char *path) {
    for (size_t i = 0; i < ynode_len(links); i++) {
        const char *p = yn_str(ynode_at(links, i), "path");
        if (p && !strcmp(p, path)) return 1;
    }
    return 0;
}

/* Проверка steer.links до подмены: форма, права, цели в base (каталог плагина или распаковка), чужие плагины,
 * занятые пути. */
static int links_validate(struct pm_ctx *x, const char *id, const struct ynode *man, const char *base,
                          struct pm_err *e) {
    const struct ynode *links = links_of(man);
    for (size_t i = 0; i < ynode_len(links); i++) {
        const struct ynode *l = ynode_at(links, i);
        const char *path = yn_str(l, "path"), *target = yn_str(l, "target"), *mode = link_mode(l);
        if (!path || path[0] != '/' || strstr(path, "..") || strlen(path) < 2 || path[strlen(path) - 1] == '/')
            return pm_errc(e, "plugin.link_path", PMA("id", id, "path", path ? path : ""), "%s: путь ссылки «%s» не абсолютный путь файла", id, path ? path : "");
        if (!target || target[0] == '/' || strstr(target, ".."))
            return pm_errc(e, "plugin.link_target_outside", PMA("id", id, "path", path), "%s: цель ссылки %s вне каталога плагина", id, path);
        if (strcmp(mode, "link") && strcmp(mode, "conf")) return pm_errc(e, "plugin.link_mode", PMA("id", id, "path", path, "mode", mode), "%s: ссылка %s — неизвестный mode «%s»", id, path, mode);
        if (!strncmp(path, "/usr/lib/steer/", 15) || !strncmp(path, "/etc/steer/", 11) || !strncmp(path, "/usr/sbin/steer", 15) ||
            !strcmp(path, "/etc/init.d/steer"))
            return pm_errc(e, "plugin.link_core_path", PMA("id", id, "path", path), "%s: ссылка %s — путь ядра steer, плагину его не дать", id, path);
        if (!fs_allowed(man, path)) return pm_errc(e, "plugin.link_perm", PMA("id", id, "path", path), "%s: ссылка %s без права fs:", id, path);
        char *src = pm_path(base, target);
        struct stat st;
        int okf = stat(src, &st) == 0 && S_ISREG(st.st_mode);
        free(src);
        if (!okf) return pm_errc(e, "plugin.link_target_missing", PMA("id", id, "path", path, "target", target), "%s: цели ссылки %s (%s) нет в плагине", id, path, target);
        for (size_t j = 0; j < x->st.n; j++) {
            const struct pm_inst *o = &x->st.v[j];
            if (!strcmp(o->id, id)) continue;
            struct ydoc *om = pm_manifest(o->id);
            if (!om) continue;
            int hit = links_has(links_of(ydoc_root(om)), path);
            ydoc_free(om);
            if (hit) return pm_errc(e, "plugin.link_taken", PMA("path", path, "other", o->id, "repo", o->repo ? o->repo : "файла"), "путь %s уже занят плагином %s из %s", path, o->id, o->repo ? o->repo : "файла");
        }
        if (!strcmp(mode, "conf")) continue;           /* стоящий файл настроек остаётся как есть */
        char *full = pm_fmt("%s%s", pm_sysroot(), path);
        struct stat ls;
        int busy = lstat(full, &ls) == 0 && !(S_ISLNK(ls.st_mode) && link_ours(full, id));
        free(full);
        if (busy) {
            char *own = pkg_owner(path);
            if (own) pm_errc(e, "plugin.link_owned_by_package", PMA("id", id, "path", path, "pkg", own), "%s не встаёт: %s принадлежит пакету %s", id, path, own);
            else pm_errc(e, "plugin.link_busy", PMA("id", id, "path", path), "%s не встаёт: %s уже есть, и поставил его не менеджер плагинов", id, path);
            free(own);
            return -1;
        }
    }
    return 0;
}

/* Привести ссылки плагина id к манифесту want: убрать те из drop, которых в want нет (только свои ссылки; копии
 * conf — только с purge), поставить недостающие из want. want NULL — снять всё. */
static int links_apply(const char *id, const struct ynode *want, const struct ynode *drop, int purge, struct pm_err *e) {
    const struct ynode *wl = links_of(want), *dl = links_of(drop);
    for (size_t i = 0; i < ynode_len(dl); i++) {
        const struct ynode *l = ynode_at(dl, i);
        const char *path = yn_str(l, "path");
        if (!path || links_has(wl, path)) continue;
        char *full = pm_fmt("%s%s", pm_sysroot(), path);
        if (!strcmp(link_mode(l), "conf")) { if (purge) unlink(full); }
        else if (link_ours(full, id)) unlink(full);
        free(full);
    }
    int rc = 0;
    for (size_t i = 0; i < ynode_len(wl); i++) {
        const struct ynode *l = ynode_at(wl, i);
        const char *path = yn_str(l, "path"), *target = yn_str(l, "target");
        if (!path || !target) continue;
        char *full = pm_fmt("%s%s", pm_sysroot(), path);
        char *src = pm_fmt("%s/%s/%s", pm_root(), id, target);
        char *parent = pm_strdup(full);
        char *sl = strrchr(parent, '/');
        if (sl && sl != parent) { *sl = '\0'; pm_mkdirs(parent); }
        free(parent);
        if (!strcmp(link_mode(l), "conf")) {
            struct stat st;
            if (lstat(full, &st) != 0) {
                size_t n = 0;
                char *d = pm_read(src, &n);
                struct stat ss;
                unsigned mode = stat(src, &ss) == 0 && (ss.st_mode & 0111) ? 0755 : 0644;
                if (!d || pm_write_atomic(full, d, n, mode) != 0) rc = pm_errc(e, "plugin.link_write", PMA("path", path, "why", strerror(errno)), "не записать %s: %s", path, strerror(errno));
                free(d);
            }
        } else {
            char buf[4096];
            ssize_t r = readlink(full, buf, sizeof(buf) - 1);
            if (r >= 0) buf[r] = '\0';
            if (r < 0 || strcmp(buf, src)) {
                struct stat st;
                if (lstat(full, &st) == 0 && !(S_ISLNK(st.st_mode) && link_ours(full, id))) {
                    rc = pm_errc(e, "plugin.link_exists", PMA("path", path), "%s уже есть, и поставил его не менеджер плагинов", path);
                } else {
                    char *tmp = pm_fmt("%s.steer-plugin.%d", full, (int)getpid());
                    unlink(tmp);
                    if (symlink(src, tmp) != 0 || rename(tmp, full) != 0) {
                        rc = pm_errc(e, "plugin.link_create", PMA("path", path, "why", strerror(errno)), "не поставить ссылку %s: %s", path, strerror(errno));
                        unlink(tmp);
                    }
                    free(tmp);
                }
            }
        }
        free(full);
        free(src);
    }
    return rc;
}

int pm_links_repair(struct pm_ctx *x, const char *id, struct pm_err *e) {
    struct ydoc *m = pm_manifest(id);
    if (!m) return 0;
    char *dir = pm_path(pm_root(), id);
    int rc = links_validate(x, id, ydoc_root(m), dir, e);
    if (rc == 0) rc = links_apply(id, ydoc_root(m), NULL, 0, e);
    free(dir);
    ydoc_free(m);
    return rc;
}

/* ---- одна установка ---- */

static char *s_or_null(const char *s) { return s ? pm_strdup(s) : NULL; }

struct snap { char *repo, *version, *arch, *variant, *state, *why, *from, *installed_at; int unsigned_; int had; };

static void snap_take(struct snap *s, const struct pm_inst *p) {
    memset(s, 0, sizeof(*s));
    if (!p) return;
    s->had = 1;
    s->repo = s_or_null(p->repo); s->version = s_or_null(p->version); s->arch = s_or_null(p->arch);
    s->variant = s_or_null(p->variant); s->state = s_or_null(p->state); s->why = s_or_null(p->why);
    s->from = s_or_null(p->from); s->installed_at = s_or_null(p->installed_at); s->unsigned_ = p->unsigned_;
}

static void snap_put(const struct snap *s, struct pm_inst *p) {
    pm_inst_set(&p->repo, s->repo); pm_inst_set(&p->version, s->version); pm_inst_set(&p->arch, s->arch);
    pm_inst_set(&p->variant, s->variant); pm_inst_set(&p->state, s->state); pm_inst_set(&p->why, s->why);
    pm_inst_set(&p->from, s->from); pm_inst_set(&p->installed_at, s->installed_at); p->unsigned_ = s->unsigned_;
}

static void snap_free(struct snap *s) {
    free(s->repo); free(s->version); free(s->arch); free(s->variant); free(s->state); free(s->why);
    free(s->from); free(s->installed_at);
}

/* Группа (pm_opts.group): плагины встают подряд без проверки здоровья каждого, потом одна проверка на всю
 * группу; не здорова — откат всех, в обратном порядке. Запись держит то, что нужно для отката. */
struct undo {
    char *id, *dir, *prev, *old_ver, *mver;
    int had_dir, was_disabled, timeout_s;
    struct snap old;
    struct outs before;
};

static void undo_free(struct undo *u) {
    free(u->id); free(u->dir); free(u->prev); free(u->old_ver); free(u->mver);
    snap_free(&u->old);
    outs_free(&u->before);
}

static void undo_clear(struct pm_ctx *x) {
    struct undo *u = x->undo;
    for (size_t i = 0; i < x->nundo; i++) undo_free(&u[i]);
    free(u);
    x->undo = NULL;
    x->nundo = 0;
}

/* Откат одной установки: файлы из .prev, состояние из снимка (нет прежнего — запись убирается). */
static void undo_apply(struct pm_ctx *x, struct undo *u, const char *why) {
    struct ydoc *nm = pm_manifest(u->id);
    pm_rmrf(u->dir);
    int restored = 0;
    if (u->had_dir && rename(u->prev, u->dir) == 0) restored = 1;
    {
        /* Ссылки (steer.links) — к восстановленной версии. */
        struct ydoc *rd = restored ? pm_manifest(u->id) : NULL;
        struct pm_err le = {0};
        links_apply(u->id, rd ? ydoc_root(rd) : NULL, nm ? ydoc_root(nm) : NULL, 0, &le);
        if (rd) ydoc_free(rd);
        if (nm) ydoc_free(nm);
    }
    struct pm_inst *inst = pm_state_find(&x->st, u->id);
    char *bad_why = restored ? pm_fmt("%s — возвращена %s", why, u->old_ver ? u->old_ver : "прежняя") : pm_strdup(why);
    if (restored && inst) {
        snap_put(&u->old, inst);
        pm_bad_set(inst, u->mver, bad_why);
    } else if (inst) {
        pm_state_del(&x->st, u->id);
    }
    pm_event(x, u->id, restored ? "rolled-back" : "failed", restored ? u->old_ver : u->mver, u->mver, bad_why);
    free(bad_why);
}

/* Одна проверка здоровья на всю группу. 0 — здорова (прежние каталоги убраны); -1 — всё откатано, причина в e. */
static int group_finish(struct pm_ctx *x, int before_bad, const char *before_msg, struct pm_err *e) {
    struct undo *u = x->undo;
    size_t n = x->nundo;
    struct pm_err he = {0};
    int healthy = 1;
    int active = 0;
    for (size_t i = 0; i < n; i++) if (!u[i].was_disabled) active = 1;
    if (active && !x->no_daemon) {
        pm_progress(x, "проверка здоровья группы (%zu)", n);
        if (pm_daemon_reload(x, &he) != 0) {
            /* Ошибка, которая была и до группы, — не вина группы: не хуже, чем было. */
            if (before_bad && !strcmp(before_msg, he.msg)) pm_progress(x, "перечитывание плагинов не удавалось и до установки — %s", he.msg);
            else healthy = 0;
        }
        for (size_t i = 0; healthy && i < n; i++)
            if (!u[i].was_disabled && wait_outs(x, &u[i].before, u[i].timeout_s, &he) != 0) healthy = 0;
    }
    struct pm_err se = {0};
    if (healthy) {
        for (size_t i = 0; i < n; i++) pm_rmrf(u[i].prev);
        return 0;
    }
    pm_progress(x, "откат группы (%zu): %s", n, he.msg);
    for (size_t i = n; i-- > 0;) undo_apply(x, &u[i], he.msg);
    pm_state_save(&x->st, &se);
    pm_keepd_write(x);
    struct pm_err re = {0};
    pm_daemon_reload(x, &re);
    pm_errc(e, "plugin.group_health_failed", PMA("why", he.msg), "группа плагинов не прошла проверку здоровья: %s — возвращены прежние версии", he.msg);
    return -1;
}

/* Источник установки: кандидат индекса или файл. */
struct src {
    const struct pm_cand *c;     /* NULL — файл */
    const char *file;
    int unsigned_ok;
    const char *reason;          /* причина варианта (облегчённый) */
};

static int install_one(struct pm_ctx *x, const struct src *s, const char *want_id, struct pm_result *res,
                       struct pm_err *e) {
    char *archive = NULL;
    int archive_tmp = 0;
    struct pm_keyset ks;
    const char *id = want_id;
    const char *repo = NULL, *from = "file";
    int official = 0;
    if (s->c) {
        id = s->c->id;
        repo = s->c->repo->seed ? yn_str(ynode_get(s->c->repo->iroot, "repo"), "id") : s->c->repo->name;
        from = s->c->repo->seed ? "seed" : "network";
        official = s->c->repo->official;
        archive = fetch_asset(x, s->c, &archive_tmp, e);
        if (!archive) return -1;
        if (official) {
            const char *role = yn_str(s->c->plug, "key_role");
            pm_keys_role(&ks, role && (!strcmp(role, "protocols") || !strcmp(role, "plugins")) ? role : "plugins");
        } else {
            pm_keys_repo(&ks, s->c->repo);
        }
    } else {
        archive = pm_strdup(s->file);
        pm_keys_all(&ks);
    }
    /* id архива из файла узнаётся из MANIFEST: распаковка во временный stage. */
    char *stage = s->c ? pm_fmt("%s/.stage/%s-%s", pm_root(), id, s->c->version)
                       : pm_fmt("%s/.stage/file-%d", pm_root(), (int)getpid());
    pm_progress(x, "проверка подписи %s", id ? id : archive);
    int is_unsigned = 0;
    char hid[128] = "", hver[128] = "", harch[128] = "";
    int rc = -1;
    struct ydoc *man = NULL;
    struct snap old;
    memset(&old, 0, sizeof(old));
    char **sys = NULL;
    size_t nsys = 0;
    struct outs before = {0};
    const char *mid = id;
    /* У файла id ещё неизвестен: распаковка под временным именем, id — из заголовка MANIFEST. */
    if (unpack_verified(archive, stage, s->c ? id : NULL, &ks, s->c ? 0 : s->unsigned_ok, &is_unsigned, hid, hver,
                        harch, sizeof(hver), e) != 0)
        goto out;
    {
        char *pj = pm_path(stage, "plugin.json");
        struct pm_err je = {0};
        man = pm_json_load(pj, &je);
        free(pj);
        if (!man) { pm_errc(e, "plugin.json_unparsable", PMA("why", je.msg), "plugin.json не разбирается: %s", je.msg); goto out_stage; }
    }
    const struct ynode *m = ydoc_root(man);
    if (yn_long(m, "schema", -1) != 1) { pm_errc(e, "plugin.manifest_new_schema", PMA("id", yn_str(m, "id") ? yn_str(m, "id") : "?"), "манифест %s нового формата (schema) — обновите ядро", yn_str(m, "id") ? yn_str(m, "id") : "?"); goto out_stage; }
    mid = yn_str(m, "id");
    const char *mver = yn_str(m, "version");
    if (!mid || !mver) { pm_errc(e, "plugin.no_id_version", NULL, "в plugin.json нет id или version"); goto out_stage; }
    if (!s->c) {
        /* Файл: заголовок MANIFEST и id из plugin.json должны совпасть (проверка в unpack шла с пустым id). */
        char *real = pm_fmt("%s/.stage/%s-%s", pm_root(), mid, mver);
        pm_rmrf(real);
        if (rename(stage, real) != 0) { free(real); pm_errc(e, "plugin.stage_move_failed", NULL, "не переложить распаковку"); goto out_stage; }
        free(stage);
        stage = real;
        if (strcmp(hid, mid)) { pm_errc(e, "plugin.json_id_mismatch", PMA("id", mid, "header", hid), "plugin.json (%s) не совпадает с MANIFEST (%s) — подмена", mid, hid); goto out_stage; }
        id = mid;
        struct pm_inst *ex = pm_state_find(&x->st, mid);
        repo = is_unsigned ? NULL : ex && ex->repo ? ex->repo : NULL;
    }
    if (strcmp(mid, id) || strcmp(mver, hver) || (s->c && strcmp(mver, s->c->version))) {
        pm_errc(e, "plugin.json_index_mismatch", PMA("id", mid, "version", mver), "plugin.json (%s %s) не совпадает с MANIFEST и индексом — подмена", mid, mver);
        goto out_stage;
    }
    {
        /* Архитектура заголовка — та, под которую брали; у «all» — all. */
        char want[96];
        if (s->c) {
            snprintf(want, sizeof(want), "%s", s->c->asset_key);
            char *at = strchr(want, '@');
            if (at) *at = '\0';
        } else {
            snprintf(want, sizeof(want), "%s", strcmp(harch, "all") ? (x->tg.arch ? x->tg.arch : "") : "all");
        }
        if (strcmp(harch, want)) { pm_errc(e, "plugin.wrong_arch", PMA("id", id, "got", harch, "want", want), "архив %s собран под %s, а нужен %s", id, harch, want); goto out_stage; }
        const char *variant = yn_str(m, "variant");
        if (s->c && strcmp(variant ? variant : "full", s->c->variant)) {
            pm_errc(e, "plugin.wrong_variant", PMA("id", id, "got", variant ? variant : "full", "want", s->c->variant), "вариант архива %s (%s) не тот, что в индексе (%s)", id, variant ? variant : "full", s->c->variant);
            goto out_stage;
        }
    }
    if (s->c) {
        static const char *same[] = { "compat", "requires", "conflicts", NULL };
        for (int i = 0; same[i]; i++)
            if (!yn_equal(ynode_get(m, same[i]), ynode_get(s->c->ver, same[i]))) {
                pm_errc(e, "plugin.index_archive_mismatch", PMA("id", id, "version", mver, "field", same[i]), "индекс и архив %s %s не совпадают (%s)", id, mver, same[i]);
                goto out_stage;
            }
    } else {
        char cb[512];
        const char *cw = pm_compat_why(&x->tg, ynode_get(m, "compat"), cb, sizeof(cb));
        if (cw) { pm_compat_err(e, id, mver, cw); goto out_stage; }
        const struct ynode *deps = ynode_get(ynode_get(m, "requires"), "plugins");
        for (size_t i = 0; i < ynode_len(deps); i++) {
            const char *did = ynode_key_at(deps, i)->str;
            const struct ynode *dr = ynode_val_at(deps, i);
            struct pm_inst *d = pm_state_find(&x->st, did);
            if (!d || !d->version || (yn_is_str(dr) && pm_range_match(dr->str, d->version) <= 0)) {
                pm_errc(e, "plugin.needs_plugin", PMA("id", id, "dep", did, "range", yn_is_str(dr) ? dr->str : ""), "%s требует плагин %s %s — поставьте его", id, did, yn_is_str(dr) ? dr->str : "");
                goto out_stage;
            }
        }
    }
    if (manifest_checks(x, id, m, official, repo, e) != 0) goto out_stage;
    if (links_validate(x, id, m, stage, e) != 0) goto out_stage;
    if (system_deps(x, id, m, &sys, &nsys, e) != 0) goto out_stage;
    if (run_script(id, stage, m, "postinst", "--check", e) != 0) goto out_stage;

    /* Подмена. */
    struct pm_inst *inst = pm_state_find(&x->st, id);
    snap_take(&old, inst);
    char *dir = pm_path(pm_root(), id);
    char *prevd = pm_path(pm_root(), ".prev");
    char *prev = pm_path(prevd, id);
    pm_mkdirs(prevd);
    pm_rmrf(prev);
    int had_dir = pm_is_dir(dir);
    char *old_ver = NULL;
    struct ydoc *oldman = had_dir ? pm_manifest(id) : NULL;
    if (oldman) old_ver = pm_strdup(yn_str(ydoc_root(oldman), "version"));
    if (!old_ver && old.version) old_ver = pm_strdup(old.version);
    {
        /* Выходы видов прежней и новой версии, поднятые до обновления. */
        const struct ynode *k = ynode_get(ynode_get(m, "steer"), "kinds");
        if (!ynode_len(k) && oldman) k = ynode_get(ynode_get(ydoc_root(oldman), "steer"), "kinds");
        outs_up(x, k, &before);
    }
    int spec_ok = x->no_daemon ? 1 : daemon_spec_ok(x);
    /* Что говорило ядро о перечитывании плагинов ДО установки: прежняя ошибка — не вина этого плагина. */
    if (!x->defer) x->before_bad = !x->no_daemon && pm_daemon_reload(x, &x->before_err) != 0;
    if (oldman) {
        struct pm_err pe = {0};
        if (run_script(id, dir, ydoc_root(oldman), "prerm", mver, &pe) != 0)
            pm_progress(x, "%s", pe.msg);
        ydoc_free(oldman);
    }
    if (had_dir && rename(dir, prev) != 0) {
        pm_errc(e, "plugin.prev_move_failed", PMA("id", id, "why", strerror(errno)), "не убрать прежнюю версию %s в .prev: %s", id, strerror(errno));
        free(dir); free(prevd); free(prev); free(old_ver);
        goto out_stage;
    }
    if (rename(stage, dir) != 0) {
        pm_errc(e, "plugin.place_failed", PMA("id", id, "why", strerror(errno)), "не поставить %s на место: %s", id, strerror(errno));
        if (had_dir) rename(prev, dir);
        free(dir); free(prevd); free(prev); free(old_ver);
        goto out_stage;
    }
    pm_progress(x, "%s %s на месте", id, mver);
    /* Состояние. */
    inst = pm_state_add(&x->st, id);
    pm_inst_set(&inst->version, mver);
    pm_inst_set(&inst->repo, repo);
    pm_inst_set(&inst->arch, harch);
    pm_inst_set(&inst->variant, s->c ? s->c->variant : (yn_str(m, "variant") ? yn_str(m, "variant") : "full"));
    pm_inst_set(&inst->from, from);
    inst->unsigned_ = is_unsigned;
    if (is_unsigned) inst->auto_update = 0;
    {
        char ts[32];
        pm_time_str(time(NULL), ts, sizeof(ts));
        pm_inst_set(&inst->installed_at, ts);
    }
    int was_disabled = old.had && old.state && !strcmp(old.state, "disabled");
    pm_inst_set(&inst->state, was_disabled ? "disabled" : "enabled");
    pm_inst_set(&inst->why, s->reason);
    for (size_t i = 0; i < nsys; i++) {
        int dup = 0;
        for (size_t j = 0; j < inst->nsystem; j++) if (!strcmp(inst->system[j], sys[i])) dup = 1;
        if (!dup) {
            inst->system = pm_realloc(inst->system, sizeof(char *) * (inst->nsystem + 1));
            inst->system[inst->nsystem++] = pm_strdup(sys[i]);
        }
        pm_sys_ours_add(&x->st, sys[i]);
    }
    struct pm_err he = {0};
    int healthy = 1;
    /* Ссылки в системе (steer.links) — до скриптов: postinst видит плагин на своих путях. Прежняя версия лежит
     * в .prev: её ссылки, которых в новой нет, снимаются. */
    {
        char *pp = pm_path(prev, "plugin.json");
        struct pm_err le = {0};
        struct ydoc *pd = had_dir ? pm_json_load(pp, &le) : NULL;
        free(pp);
        if (links_apply(id, m, pd ? ydoc_root(pd) : NULL, 0, &he) != 0) healthy = 0;
        if (pd) ydoc_free(pd);
    }
    /* Скрипты: migrate при смене major, затем postinst <старая>. */
    if (healthy && old_ver && pm_ver_major(old_ver) != pm_ver_major(mver) &&
        run_script(id, dir, m, "migrate", old_ver, &he) != 0) healthy = 0;
    if (healthy && run_script(id, dir, m, "postinst", old_ver ? old_ver : "", &he) != 0) healthy = 0;
    struct pm_err se = {0};
    pm_state_save(&x->st, &se);
    pm_keepd_write(x);
    if (healthy && x->defer) {
        /* Группа: проверка здоровья одна, в конце (group_finish); здесь — только запись для отката. */
        struct undo *u;
        x->undo = pm_realloc(x->undo, sizeof(struct undo) * (x->nundo + 1));
        u = &((struct undo *)x->undo)[x->nundo++];
        memset(u, 0, sizeof(*u));
        u->id = pm_strdup(id); u->dir = pm_strdup(dir); u->prev = pm_strdup(prev);
        u->old_ver = s_or_null(old_ver); u->mver = pm_strdup(mver);
        u->had_dir = had_dir; u->was_disabled = was_disabled;
        u->timeout_s = (int)yn_long(ynode_get(m, "health"), "timeout_s", 60);
        u->old = old; memset(&old, 0, sizeof(old));
        u->before = before; memset(&before, 0, sizeof(before));
    } else if (healthy && !was_disabled) {
        pm_progress(x, "проверка здоровья %s", id);
        if (pm_daemon_reload(x, &he) != 0) {
            if (spec_ok && !(x->before_bad && !strcmp(x->before_err.msg, he.msg))) healthy = 0;
            else if (spec_ok) pm_progress(x, "перечитывание плагинов не удавалось и до установки — %s", he.msg);
            else pm_progress(x, "спека не читалась и до установки — %s", he.msg);
        }
        if (healthy) {
            long t = yn_long(ynode_get(m, "health"), "timeout_s", 60);
            if (wait_outs(x, &before, (int)t, &he) != 0) healthy = 0;
        }
    }
    if (!healthy) {
        /* Откат (s2p.md, «Откат»). */
        pm_progress(x, "откат %s: %s", id, he.msg);
        pm_rmrf(dir);
        int restored = 0;
        if (had_dir && rename(prev, dir) == 0) restored = 1;
        {
            /* Ссылки — к восстановленной версии; новые пути без неё снимаются. */
            struct ydoc *rd = restored ? pm_manifest(id) : NULL;
            struct pm_err le = {0};
            links_apply(id, rd ? ydoc_root(rd) : NULL, m, 0, &le);
            if (rd) ydoc_free(rd);
        }
        inst = pm_state_find(&x->st, id);
        char *bad_why = restored ? pm_fmt("%s — возвращена %s", he.msg, old_ver ? old_ver : "прежняя")
                                 : pm_strdup(he.msg);
        if (restored && inst) {
            snap_put(&old, inst);
            pm_bad_set(inst, mver, bad_why);
        } else if (inst) {
            pm_state_del(&x->st, id);
        }
        pm_state_save(&x->st, &se);
        pm_keepd_write(x);
        struct pm_err re = {0};
        if (restored && pm_daemon_reload(x, &re) != 0 && inst) {
            /* И откат не здоров: плагин failed, его выходы — в on_fail. */
            inst = pm_state_find(&x->st, id);
            if (inst) { pm_inst_set(&inst->state, "failed"); pm_inst_set(&inst->why, re.msg); pm_state_save(&x->st, &se); }
        }
        pm_event(x, id, restored ? "rolled-back" : "failed", restored ? old_ver : mver, mver, bad_why);
        pm_errc(e, restored ? "plugin.health_failed_restored" : "plugin.health_failed", PMA("id", id, "version", mver, "why", he.msg), "%s %s не прошёл проверку здоровья: %s%s", id, mver, he.msg,
                restored ? " — возвращена прежняя версия" : "");
        free(bad_why);
        free(dir); free(prevd); free(prev); free(old_ver);
        goto out;
    }
    if (!x->defer) {
        pm_rmrf(prev);
        pm_event(x, id, old_ver && strcmp(old_ver, mver) ? "updated" : (was_disabled ? "installed" : "enabled"), mver,
                 old_ver, s->reason);
    }
    res->v = pm_realloc(res->v, sizeof(*res->v) * (res->n + 1));
    struct pm_done *d = &res->v[res->n++];
    d->id = pm_strdup(id);
    d->version = pm_strdup(mver);
    d->from = pm_strdup(from);
    d->old = s_or_null(old_ver);
    d->updated = old_ver && strcmp(old_ver, mver);
    free(dir); free(prevd); free(prev); free(old_ver);
    rc = 0;
    goto out;
out_stage:
    pm_rmrf(stage);
out:
    if (man) ydoc_free(man);
    snap_free(&old);
    outs_free(&before);
    for (size_t i = 0; i < nsys; i++) free(sys[i]);
    free(sys);
    if (archive_tmp) unlink(archive);
    free(archive);
    free(stage);
    pm_keys_free(&ks);
    return rc;
}

/* ---- установка по запросу ---- */

static int space_check(struct pm_ctx *x, const struct plan *p, struct pm_err *e) {
    unsigned long long need = 0, need_tmp = 0;
    for (size_t i = 0; i < p->n; i++) {
        const struct pm_inst *have = pm_state_find(&x->st, p->v[i].c.id);
        if (have && have->version && !strcmp(have->version, p->v[i].c.version) &&
            (!have->variant || !strcmp(have->variant, p->v[i].c.variant)))
            continue;
        long in = yn_long(p->v[i].c.asset, "installed", 0), sz = yn_long(p->v[i].c.asset, "size", 0);
        need += in > 0 ? (unsigned long long)in : 0;
        if (!p->v[i].c.repo->seed) need_tmp += sz > 0 ? (unsigned long long)sz : 0;
    }
    unsigned long long fr = pm_free(pm_root(), 0);
    char a[32], b[32];
    if (need > fr) {
        pm_human(need, a, sizeof(a));
        pm_human(fr, b, sizeof(b));
        return pm_errc(e, "plugin.no_space_root", PMA("path", pm_root(), "need", a, "free", b), "нет места на разделе плагинов (%s): нужно %s, свободно %s", pm_root(), a, b);
    }
    unsigned long long ft = pm_free(pm_tmp(), 1);
    if (need_tmp > ft) {
        pm_human(need_tmp, a, sizeof(a));
        pm_human(ft, b, sizeof(b));
        return pm_errc(e, "plugin.no_space_tmp", PMA("path", pm_tmp(), "need", a, "free", b), "нет места во временном каталоге (%s): нужно %s, свободно %s", pm_tmp(), a, b);
    }
    return 0;
}

static int plan_build(struct pm_ctx *x, struct plan *p, const struct pm_req *req, size_t nreq, const char *variant,
                      const struct pm_opts *o, struct pm_repos *seedrs, struct pm_err *e) {
    p->n = 0;
    for (size_t i = 0; i < nreq; i++)
        if (resolve(x, p, req[i].id, NULL, req[i].version, NULL, variant, NULL, 1, o, seedrs, e) != 0) return -1;
    return 0;
}

int pm_install(struct pm_ctx *x, const struct pm_req *req, size_t nreq, const struct pm_opts *o,
               struct pm_result *res, struct pm_err *e) {
    memset(res, 0, sizeof(*res));
    if (o->file) {
        struct src s = { NULL, o->file, o->unsigned_ok, NULL };
        return install_one(x, &s, NULL, res, e);
    }
    x->allow_bad = o->allow_bad;
    struct pm_repos seedrs = {0};
    struct pm_repo *sr = NULL;
    if (o->seed_only) {
        sr = pm_seed_repo();
        if (!sr) return pm_errc(e, "plugin.no_seed_at", PMA("path", pm_seed()), "семени нет (%s)", pm_seed());
        seedrs.v = sr;
        seedrs.n = 1;
    }
    struct plan p = {0};
    const char *reason = NULL;
    char *reason_buf = NULL;
    if (o->group) {
        x->defer = 1;
        x->before_bad = !x->no_daemon && pm_daemon_reload(x, &x->before_err) != 0;
    }
    int rc = plan_build(x, &p, req, nreq, "full", o, &seedrs, e);
    if (rc == 0 && space_check(x, &p, e) != 0) {
        /* На полный вариант нет места: облегчённый, если он есть и помещается (manifest.md). */
        struct pm_err le = {0};
        struct plan lp = {0};
        char *full_why = pm_strdup(e->msg);
        if (plan_build(x, &lp, req, nreq, "lite", o, &seedrs, &le) == 0 && space_check(x, &lp, &le) == 0) {
            free(p.v);
            p = lp;
            reason_buf = pm_fmt("облегчённый вариант: на полный %s", full_why);
            reason = reason_buf;
        } else {
            free(lp.v);
            rc = -1;
        }
        free(full_why);
    }
    if (rc != 0) {
        x->defer = 0;
        free(p.v);
        free(reason_buf);
        if (sr) { free(sr->name); free(sr->url); if (sr->idx) ydoc_free(sr->idx); free(sr); }
        return -1;
    }
    for (size_t i = 0; i < p.n; i++) {
        const struct pm_cand *c = &p.v[i].c;
        struct pm_inst *inst = pm_state_find(&x->st, c->id);
        /* Уже стоит ровно эта версия и вариант — нечего делать. */
        char *cd = pm_path(pm_root(), c->id);
        int here = pm_is_dir(cd);
        free(cd);
        if (inst && inst->version && !strcmp(inst->version, c->version) && here &&
            (!inst->variant || !strcmp(inst->variant, c->variant)) && (!inst->state || strcmp(inst->state, "failed")))
            continue;
        int lite = strcmp(c->variant, "full") != 0;
        struct src s = { c, NULL, 0, lite ? reason : NULL };
        if (install_one(x, &s, c->id, res, e) != 0) {
            res->failed = pm_realloc(res->failed, sizeof(char *) * (res->nfailed + 1));
            res->failed[res->nfailed++] = pm_strdup(c->id);
            rc = -1;
            break;
        }
    }
    free(p.v);
    free(reason_buf);
    if (sr) { free(sr->name); free(sr->url); if (sr->idx) ydoc_free(sr->idx); free(sr); }
    if (o->group) {
        x->defer = 0;
        struct undo *u = x->undo;
        if (rc != 0) {
            /* Одна из группы не встала: откат всех, что уже стоят. */
            struct pm_err se = {0};
            for (size_t i = x->nundo; i-- > 0;) undo_apply(x, &u[i], e->msg);
            if (x->nundo) { pm_state_save(&x->st, &se); pm_keepd_write(x); pm_daemon_reload(x, &se); }
            pm_result_free(res);
            memset(res, 0, sizeof(*res));
        } else if (x->nundo) {
            struct pm_err ge = {0};
            if (group_finish(x, x->before_bad, x->before_err.msg, &ge) != 0) {
                *e = ge;
                pm_result_free(res);
                memset(res, 0, sizeof(*res));
                rc = -1;
            } else {
                for (size_t i = 0; i < x->nundo; i++)
                    pm_event(x, u[i].id, u[i].old_ver && strcmp(u[i].old_ver, u[i].mver) ? "updated" : (u[i].was_disabled ? "installed" : "enabled"),
                             u[i].mver, u[i].old_ver, NULL);
            }
        }
        undo_clear(x);
    }
    return rc;
}

/* ---- снятие, включение ---- */

/* Выходы спеки, которым нужен вид плагина: «nl, de — вида tunnel:vless». NULL — никому. */
static char *spec_needs(const struct ynode *kinds) {
    if (!ynode_len(kinds)) return NULL;
    const char *sp = getenv("STEER_PLUGIN_SPEC");
    const char *path = sp && *sp ? sp : plat_spec_resolve(NULL);
    struct pm_err e;
    struct ydoc *d = path ? pm_json_load(path, &e) : NULL;
    if (!d) return NULL;
    const struct ynode *outs = ynode_get(ydoc_root(d), "outputs");
    char *names = NULL, *kind_hit = NULL;
    size_t n = ynode_len(outs);
    for (size_t i = 0; i < n; i++) {
        const struct ynode *o = outs->kind == YN_MAP ? ynode_val_at(outs, i) : ynode_at(outs, i);
        const char *on = outs->kind == YN_MAP ? ynode_key_at(outs, i)->str : yn_str(o, "name");
        const char *k = yn_str(o, "kind");
        if (!k || !on) continue;
        char *full = !strcmp(k, "tunnel") && yn_str(o, "protocol") ? pm_fmt("tunnel:%s", yn_str(o, "protocol")) : pm_strdup(k);
        int hit = 0;
        for (size_t j = 0; j < ynode_len(kinds) && !hit; j++) {
            const char *kn = yn_str(ynode_at(kinds, j), "name");
            if (kn && !strcmp(kn, full)) hit = 1;
        }
        if (hit) {
            char *t = pm_fmt("%s%s%s", names ? names : "", names ? ", " : "", on);
            free(names);
            names = t;
            if (!kind_hit) kind_hit = pm_strdup(full);
        }
        free(full);
    }
    ydoc_free(d);
    if (!names) return NULL;
    char *r = pm_fmt("выходы %s — вида %s", names, kind_hit);
    free(names);
    free(kind_hit);
    return r;
}

int pm_remove(struct pm_ctx *x, const char *id, int force, int purge, struct pm_err *e) {
    struct pm_inst *inst = pm_state_find(&x->st, id);
    char *dir = pm_path(pm_root(), id);
    if (!inst && !pm_is_dir(dir)) { free(dir); return pm_errc(e, "plugin.not_installed", PMA("id", id), "плагин %s не установлен", id); }
    struct ydoc *man = pm_manifest(id);
    const struct ynode *m = man ? ydoc_root(man) : NULL;
    if (!force) {
        /* Зависимые плагины. */
        char *users = NULL;
        for (size_t i = 0; i < x->st.n; i++) {
            if (!strcmp(x->st.v[i].id, id)) continue;
            struct ydoc *om = pm_manifest(x->st.v[i].id);
            if (!om) continue;
            if (ynode_get(ynode_get(ynode_get(ydoc_root(om), "requires"), "plugins"), id)) {
                char *t = pm_fmt("%s%s%s", users ? users : "", users ? ", " : "", x->st.v[i].id);
                free(users);
                users = t;
            }
            ydoc_free(om);
        }
        if (users) {
            pm_errc(e, "plugin.needed_by_plugins", PMA("id", id, "users", users), "плагин %s нужен плагинам %s; снять всё равно — с --force", id, users);
            free(users); free(dir);
            if (man) ydoc_free(man);
            return -1;
        }
        char *needs = spec_needs(ynode_get(ynode_get(m, "steer"), "kinds"));
        if (needs) {
            pm_errc(e, "plugin.needed_by_outputs", PMA("id", id, "outputs", needs), "плагин %s нужен выходам: %s; снять всё равно — с --force", id, needs);
            free(needs); free(dir);
            if (man) ydoc_free(man);
            return -1;
        }
    }
    const char *ver = inst && inst->version ? inst->version : m ? yn_str(m, "version") : NULL;
    char *verc = s_or_null(ver);
    if (m) {
        struct pm_err pe = {0};
        if (run_script(id, dir, m, "prerm", "", &pe) != 0) pm_progress(x, "%s", pe.msg);
        /* Ссылки в системе — вместе с плагином; копии настроек (mode: conf) — только с --purge. */
        if (links_apply(id, NULL, m, purge, &pe) != 0) pm_progress(x, "%s", pe.msg);
    }
    if (man) ydoc_free(man);
    if (pm_rmrf(dir) != 0) { pm_errc(e, "plugin.remove_failed", PMA("path", dir, "why", strerror(errno)), "не удалить %s: %s", dir, strerror(errno)); free(dir); free(verc); return -1; }
    char *prev = pm_fmt("%s/.prev/%s", pm_root(), id);
    pm_rmrf(prev);
    free(prev);
    if (purge) {
        char *conf = pm_fmt("%s/conf/%s", pm_etc(), id);
        pm_rmrf(conf);
        free(conf);
    }
    pm_state_del(&x->st, id);
    struct pm_err se = {0};
    if (pm_state_save(&x->st, &se) != 0) { *e = se; free(dir); free(verc); return -1; }
    pm_keepd_write(x);
    struct pm_err re = {0};
    if (pm_daemon_reload(x, &re) != 0) pm_progress(x, "%s", re.msg);
    pm_event(x, id, "removed", verc, NULL, NULL);
    free(dir);
    free(verc);
    return 0;
}

int pm_set_enabled(struct pm_ctx *x, const char *id, int on, struct pm_err *e) {
    struct pm_inst *inst = pm_state_find(&x->st, id);
    if (!inst) return pm_errc(e, "plugin.not_installed", PMA("id", id), "плагин %s не установлен", id);
    if (on) {
        struct ydoc *man = pm_manifest(id);
        if (!man) return pm_errc(e, "plugin.files_missing", PMA("id", id), "файлов плагина %s нет — поставьте его заново", id);
        char cb[512];
        const char *cw = pm_compat_why(&x->tg, ynode_get(ydoc_root(man), "compat"), cb, sizeof(cb));
        if (cw) {
            char *w = pm_fmt("%s %s", id, cw);
            pm_compat_err(e, id, NULL, cw);
            free(w);
            ydoc_free(man);
            return -1;
        }
        ydoc_free(man);
    }
    int spec_ok = x->no_daemon ? 1 : daemon_spec_ok(x);
    pm_inst_set(&inst->state, on ? "enabled" : "disabled");
    pm_inst_set(&inst->why, NULL);
    struct pm_err se = {0};
    if (pm_state_save(&x->st, &se) != 0) { *e = se; return -1; }
    struct pm_err re = {0};
    if (pm_daemon_reload(x, &re) != 0) {
        if (on && spec_ok) {
            inst = pm_state_find(&x->st, id);
            pm_inst_set(&inst->state, "failed");
            pm_inst_set(&inst->why, re.msg);
            pm_state_save(&x->st, &se);
            pm_event(x, id, "failed", inst->version, NULL, re.msg);
            return pm_errcopy(e, &re);
        }
        pm_progress(x, "%s", re.msg);
    }
    inst = pm_state_find(&x->st, id);
    pm_event(x, id, on ? "enabled" : "disabled", inst->version, NULL, NULL);
    return 0;
}
