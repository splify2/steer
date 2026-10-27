/* ШАГ ПОДГОТОВКИ СПЕКИ: хуки плагинов check, expand, pre_apply (steer-api.md, раздел 3) и выдача
 * ресурсов (раздел 6).
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ ШАГ. Спеку читает десяток мест — status, diag, explain, сторож, супервизор, — и
 * fork/exec плагина в каждом из них был бы и медленным, и разным по времени. Поэтому load_spec хуков
 * не исполняет: их исполняет spec_prepare, а результат — ПОДГОТОВЛЕННАЯ СПЕКА, JSON той же формы v2 —
 * ложится в кэш рядом с ключом (sha256 байт спеки человека, версий и манифестов плагинов с хуками).
 * load_spec берёт её, если ключ совпал (spec_prepared_text, parse.c); не совпал — читает спеку
 * человека, а выходы видов с разворотом считает неготовыми («спека не подготовлена — нужен reload»).
 *
 * КТО ЗОВЁТ spec_prepare: старт демона и reload (steerd_load), `steer apply` и apply-plan (check и
 * apply сокета). Без хуков и ресурсов ни в одном включённом плагине шаг ничего не делает и ничего не
 * пишет: подготовленной спеки нет, читается спека человека, как до плагинов.
 *
 * ПОРЯДОК ВНУТРИ (steer-api.md, 3.1):
 *   1. разбор спеки человека; выход вида плагина — по схеме ключей;
 *   2. check каждого выхода вида плагина;
 *   3. expand каждого выхода вида с разворотом;
 *   4. pre_apply плагинов — в порядке зависимостей (requires.plugins), затем по id; каждый видит
 *      результат предыдущего;
 *   5. разбор и проверки ядра по итоговой спеке (пробная загрузка подготовленной).
 *
 * ХУКИ ДЕТЕРМИНИРОВАНЫ: одинаковый вход — одинаковый выход. Сеть, время, случайность запрещены (у них
 * свои места: помощник и служба). Поэтому ядро кэширует ответ хука по sha256 его входа в
 * <данные менеджера>/cache/<id>/ — повторная подготовка той же спеки процессов не запускает.
 *
 * ГДЕ ЛЕЖИТ КЭШ. Подготовленная спека — файл на ключ (cache/prepared/<ключ>.json), а не один общий:
 * apply-plan готовит спеку-кандидата, пока сторож и status читают живую, и общий файл заставил бы
 * живую «терять подготовку» на время плана. Файлы чужих ключей старше суток убираются при записи
 * нового — по возрасту, а не по числу: числа тут не причина. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#include "spec.h"
#include "plugin.h"
#include "registry.h"
#include "plugutil.h"
#include "ynode.h"
#include "v2.h"
#include "plugalloc.h"

extern void steer_sha256(const unsigned char *in, size_t n, unsigned char out[32]) __attribute__((weak));

/* ---- мелочи ------------------------------------------------------------------------------- */

static int sha_hex(const void *d, size_t n, char hex[65]) {
    unsigned char h[32];
    if (!steer_sha256) return -1;
    steer_sha256(d, n, h);
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
    return 0;
}

static void cache_dir(char *buf, size_t n) {
    char etc[PATH_MAX - 16];            /* путь каталога данных плюс «/cache» обязан влезть в PATH_MAX */
    plugin_etc(etc, sizeof(etc));
    snprintf(buf, n, "%s/cache", etc);
}

/* Нужна ли подготовка: у какого-то включённого плагина есть хук или ресурсы видов. */
static int needs_prepare(void) {
    for (size_t i = 0; i < plugin_n(); i++)
        if (plugin_at(i)->enabled && plugin_at(i)->has_hooks) return 1;
    return 0;
}

/* Ключ подготовки: байты спеки человека, затем у каждого включённого плагина с хуками — id, версия,
 * plugin.json и MANIFEST (если есть). */
static int prepare_key(const char *human, size_t hn, char key[65]) {
    struct sbuf b = { 0 };
    sb_put(&b, human, hn);
    for (size_t i = 0; i < plugin_n(); i++) {
        const struct plugin *p = plugin_at(i);
        if (!p->enabled || !p->has_hooks) continue;
        sb_put(&b, "\0", 1);
        sb_str(&b, p->id);
        sb_put(&b, "\0", 1);
        sb_str(&b, p->version);
        sb_put(&b, "\0", 1);
        sb_put(&b, p->manifest, p->manifest_len);
        char mp[PATH_MAX + 16];
        snprintf(mp, sizeof(mp), "%s/MANIFEST", p->dir);
        size_t mn;
        char *mt = slurp(mp, &mn);
        if (mt) { sb_put(&b, "\0", 1); sb_put(&b, mt, mn); free(mt); }
    }
    int rc = b.oom || !b.p ? -1 : sha_hex(b.p, b.n, key);
    free(b.p);
    return rc;
}

static void prepared_path(char *buf, size_t n, const char *key, const char *ext) {
    char c[PATH_MAX];
    cache_dir(c, sizeof(c));
    snprintf(buf, n, "%s/prepared/%s%s", c, key, ext);
}

int spec_prepared_text(const char *path, const char *human, size_t human_n, char **text, size_t *n,
                       char key[65]) {
    (void)path;
    if (!needs_prepare()) return 0;
    if (prepare_key(human, human_n, key) != 0) return 0;
    char pp[PATH_MAX + 80];
    prepared_path(pp, sizeof(pp), key, ".json");
    char *t = slurp(pp, n);
    if (!t) return 0;
    *text = t;
    return 1;
}

int spec_prepare_report(const char *path, char **json) {
    struct err e;
    memset(&e, 0, sizeof(e));
    char *human;
    size_t hn;
    if (spec_read_text(path, &human, &hn, &e) != 0) return -1;
    char key[65];
    int rc = prepare_key(human, hn, key);
    free(human);
    if (rc != 0) return -1;
    char pp[PATH_MAX + 80];
    prepared_path(pp, sizeof(pp), key, ".report.json");
    *json = slurp(pp, NULL);
    return *json ? 0 : -1;
}

/* {conf} выхода — перед запуском его помощника (steer-api.md, 1.4). */
int plugin_conf_write(const struct spec *sp, const struct output *o) {
    const struct plugin_kind *pk = plugin_helper_kind(o);
    if (!pk) return -1;
    char *json = plugin_conf_json(sp, o, pk);
    if (!json) return -1;
    char dir[PATH_MAX], path[PATH_MAX + 64];
    snprintf(dir, sizeof(dir), "%s/plugin/%s", steer_state_dir(), pk->owner->id);
    snprintf(path, sizeof(path), "%s/%s.json", dir, o->name);
    int rc = pu_mkdir_p(dir) == 0 ? pu_write_atomic(path, json, strlen(json), 0600) : -1;
    free(json);
    return rc;
}

/* ---- подкоманды плагинов (steer-api.md, 4.3; manifest.md, commands[]) ------------------------------ */

/* Файл настройки выхода для подкоманды с conf (manifest.md, commands[].conf): выход name — вид этого
 * плагина или развёрнутый им выход; {conf} — тот же, что у помощника (plugin_conf_json), в memfd без
 * CLOEXEC, чтобы его увидела программа после exec («/proc/self/fd/N»). Нет memfd — файл помощника в
 * каталоге плагина. Путь — в path; 0 — готово, иначе 2 и причина в stderr. */
static int cmd_conf(const struct plugin_cmd *c, const char *name, const char *spec_path, const char *state_dir,
                    char *path, size_t pn) {
    if (state_dir) steer_set_state_dir(state_dir);
    struct spec *sp = calloc(1, sizeof(*sp));
    if (!sp) { fprintf(stderr, "steer: нет памяти\n"); return 2; }
    struct err e;
    memset(&e, 0, sizeof(e));
    if (load_spec(plat_spec_resolve(spec_path), sp, &e) < 0 || registry_assign(sp, &e) < 0) {
        fprintf(stderr, "steer: %s\n", e.msg[0] ? e.msg : "спека не прочитана");
        return 2;
    }
    const struct output *o = out_by_name(sp, name);
    if (!o) { fprintf(stderr, "steer: %s: выхода %s нет в спеке\n", c->name, name); return 2; }
    const struct plugin_kind *pk = out_plugin_kind(o);
    if (!pk) pk = plugin_helper_kind(o);
    if (!pk || pk->owner != c->owner) {
        fprintf(stderr, "steer: %s: выход %s — не выход плагина %s (kind %s)\n", c->name, name, c->owner->id,
                out_kind_name(o));
        return 2;
    }
    char *json = plugin_conf_json(sp, o, pk);
    if (!json) { fprintf(stderr, "steer: нет памяти\n"); return 2; }
    int fd = (int)syscall(SYS_memfd_create, "steer-conf", 0);
    if (fd >= 0) {
        size_t len = strlen(json), off = 0;
        while (off < len) {
            ssize_t w = write(fd, json + off, len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        snprintf(path, pn, "/proc/self/fd/%d", fd);
        free(json);
        return off == len ? 0 : 2;
    }
    free(json);
    if (plugin_conf_write(sp, o) != 0) {
        fprintf(stderr, "steer: %s: файл настройки выхода %s не записан: %s\n", c->name, name, strerror(errno));
        return 2;
    }
    snprintf(path, pn, "%s/plugin/%s/%s.json", steer_state_dir(), pk->owner->id, o->name);
    return 0;
}

int plugin_cmd_exec(const struct plugin_cmd *c, int argc, char **argv) {
    /* conf: --spec и --state-dir человека — ядру (по ним выход и его {conf}); программе — --conf. */
    const char *spec_path = NULL, *state_dir = NULL;
    char confp[PATH_MAX] = "";
    if (c->conf) {
        int k = 0;
        for (int i = 0; i < argc; i++) {
            if ((!strcmp(argv[i], "--spec") || !strcmp(argv[i], "--state-dir")) && i + 1 < argc) {
                if (argv[i][2] == 's' && argv[i][3] == 'p') spec_path = argv[i + 1];
                else state_dir = argv[i + 1];
                i++;
                continue;
            }
            argv[k++] = argv[i];
        }
        argc = k;
        if (argc >= 1 && argv[0][0] != '/' && argv[0][0] != '-') {
            int rc = cmd_conf(c, argv[0], spec_path, state_dir, confp, sizeof(confp));
            if (rc) return rc;
        }
    }
    size_t n = c->run.argc + (size_t)argc + 4;
    char **av = calloc(n, sizeof(*av));
    if (!av) { fprintf(stderr, "steer: нет памяти\n"); return 2; }
    size_t k = 0;
    av[k++] = c->run.prog;
    char why[256];
    for (size_t i = 0; i < c->run.argc; i++) {
        av[k] = plugin_subst(c->owner, NULL, c->run.argv[i], why, sizeof(why));
        if (!av[k]) { fprintf(stderr, "steer: подкоманда %s: %s\n", c->name, why); return 2; }
        k++;
    }
    for (int i = 0; i < argc; i++) av[k++] = argv[i];
    if (confp[0]) {
        av[k++] = "--conf";
        av[k++] = confp;
    }
    av[k] = NULL;
    plugin_env_set(c->owner, &c->run);
    execv(c->run.prog, av);
    fprintf(stderr, "steer: не удалось запустить %s (плагин %s): %s\n", c->run.prog, c->owner->id,
            strerror(errno));
    return 2;
}

/* ---- запуск программы хука ------------------------------------------------------------------ */

/* Последняя непустая строка stderr — причина отказа (steer-api.md, 1.5). */
static char *last_line(const char *s) {
    size_t l = strlen(s);
    while (l && (s[l - 1] == '\n' || s[l - 1] == '\r' || s[l - 1] == ' ')) l--;
    size_t e = l;
    while (l && s[l - 1] != '\n') l--;
    return strndup(s + l, e - l);
}

/* Результат запуска: code — код выхода (>=0) или -сигнал; timeout — срок вышел. */
struct hrun { int code; int timeout; struct sbuf out, err; };

static int hook_exec(const struct plugin *pl, const struct plugin_prog *p, const char *out_name, const char *in,
                     int timeout_s, struct hrun *r, struct err *e) {
    memset(r, 0, sizeof(*r));
    char why[256];
    size_t n = p->argc + 2;
    char **av = calloc(n, sizeof(*av));
    if (!av) return err_set(e, "%s", "недостаточно памяти для запуска хука");
    size_t k = 0;
    av[k++] = p->prog;
    for (size_t i = 0; i < p->argc; i++) {
        av[k] = plugin_subst(pl, out_name, p->argv[i], why, sizeof(why));
        if (!av[k]) {
            char m[400];
            snprintf(m, sizeof(m), "плагин %s: %s", pl->id, why);
            for (size_t j = 1; j < k; j++) free(av[j]);
            free(av);
            return err_set(e, "%s", m);
        }
        k++;
    }
    av[k] = NULL;
    int pin[2], pout[2], perr[2];
    if (pipe(pin) != 0 || pipe(pout) != 0 || pipe(perr) != 0) {
        for (size_t j = 1; j < k; j++) free(av[j]);
        free(av);
        return err_set(e, "%s", "не создать трубы для хука");
    }
    pid_t pid = fork();
    if (pid < 0) {
        for (size_t j = 1; j < k; j++) free(av[j]);
        free(av);
        return err_set(e, "%s", "не запустить хук: fork отказал");
    }
    if (pid == 0) {
        dup2(pin[0], 0);
        dup2(pout[1], 1);
        dup2(perr[1], 2);
        /* Хуку нужны только его три дескриптора: остальные (сокеты демона, файлы) закрываются разом
         * close_range (ядро 5.9+), а на старом — перебором до RLIMIT_NOFILE. */
        int closed = 0;
#ifdef SYS_close_range
        closed = syscall(SYS_close_range, 3u, ~0u, 0) == 0;
#endif
        if (!closed) {
            long mx = sysconf(_SC_OPEN_MAX);
            if (mx < 0 || mx > 1048576) mx = 1048576;
            for (int fd = 3; fd < mx; fd++) close(fd);
        }
        signal(SIGPIPE, SIG_DFL);
        plugin_env_set(pl, p);
        execv(p->prog, av);
        fprintf(stderr, "не запустить %s: %s\n", p->prog, strerror(errno));
        _exit(127);
    }
    close(pin[0]); close(pout[1]); close(perr[1]);
    for (size_t j = 1; j < k; j++) free(av[j]);
    free(av);
    fcntl(pin[1], F_SETFL, O_NONBLOCK);
    struct sigaction ign = { .sa_handler = SIG_IGN }, old;
    sigaction(SIGPIPE, &ign, &old);
    size_t inl = strlen(in), off = 0;
    int win = pin[1], rout = pout[0], rerr = perr[0];
    if (!inl) { close(win); win = -1; }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (win >= 0 || rout >= 0 || rerr >= 0) {
        struct pollfd pf[3];
        int np = 0, wi = -1, oi = -1, ei = -1;
        if (win >= 0) { wi = np; pf[np++] = (struct pollfd){ win, POLLOUT, 0 }; }
        if (rout >= 0) { oi = np; pf[np++] = (struct pollfd){ rout, POLLIN, 0 }; }
        if (rerr >= 0) { ei = np; pf[np++] = (struct pollfd){ rerr, POLLIN, 0 }; }
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long left = (long)timeout_s * 1000 - ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
        if (left <= 0) { r->timeout = 1; kill(pid, SIGKILL); break; }
        int pr = poll(pf, (nfds_t)np, (int)(left > 1000000 ? 1000000 : left));
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (wi >= 0 && (pf[wi].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t w = write(win, in + off, inl - off);
            if (w > 0) off += (size_t)w;
            if (off >= inl || (w < 0 && errno != EAGAIN && errno != EINTR)) { close(win); win = -1; }
        }
        char buf[4096];
        if (oi >= 0 && (pf[oi].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t g = read(rout, buf, sizeof(buf));
            if (g > 0) sb_put(&r->out, buf, (size_t)g);
            else if (g == 0 || (errno != EAGAIN && errno != EINTR)) { close(rout); rout = -1; }
        }
        if (ei >= 0 && (pf[ei].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t g = read(rerr, buf, sizeof(buf));
            if (g > 0) sb_put(&r->err, buf, (size_t)g);
            else if (g == 0 || (errno != EAGAIN && errno != EINTR)) { close(rerr); rerr = -1; }
        }
    }
    if (win >= 0) close(win);
    if (rout >= 0) close(rout);
    if (rerr >= 0) close(rerr);
    sigaction(SIGPIPE, &old, NULL);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    r->code = WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? -WTERMSIG(st) : -1);
    if (r->out.oom || r->err.oom) return err_set(e, "%s", "недостаточно памяти для ответа хука");
    return 0;
}

static void hrun_free(struct hrun *r) { free(r->out.p); free(r->err.p); }

/* Хук с кэшем. 0 — удача, *stdout_txt — ответ (куча, возможно пустая строка); 2 — отказ плагина,
 * *why — причина для человека (куча); -1 — сбой (текст в e). label — «check», «expand», «pre_apply». */
static int hook_run(const struct plugin *pl, const struct plugin_prog *p, const char *label,
                    const char *out_name, int dflt_timeout, const char *in, char **stdout_txt, char **why,
                    struct err *e) {
    *stdout_txt = NULL;
    *why = NULL;
    /* Ключ кэша: что запускали и что подали. */
    struct sbuf kb = { 0 };
    sb_str(&kb, label);
    sb_put(&kb, "\0", 1);
    sb_str(&kb, pl->version);
    sb_put(&kb, "\0", 1);
    sb_str(&kb, p->prog);
    for (size_t i = 0; i < p->argc; i++) { sb_put(&kb, "\0", 1); sb_str(&kb, p->argv[i]); }
    sb_put(&kb, "\0", 1);
    sb_str(&kb, in);
    char ck[65];
    int have_key = !kb.oom && kb.p && sha_hex(kb.p, kb.n, ck) == 0;
    free(kb.p);
    char cdir[PATH_MAX], cfile[PATH_MAX + 120];
    cache_dir(cdir, sizeof(cdir));
    snprintf(cfile, sizeof(cfile), "%s/%s/%s.json", cdir, pl->id, ck);
    if (have_key) {
        char *hit = slurp(cfile, NULL);
        if (hit) { *stdout_txt = hit; return 0; }
    }
    struct hrun r;
    if (hook_exec(pl, p, out_name, in, p->timeout_s ? p->timeout_s : dflt_timeout, &r, e) != 0) return -1;
    char m[600];
    if (r.timeout) {
        snprintf(m, sizeof(m), "плагин %s: %s не уложился в %d с", pl->id, label, p->timeout_s ? p->timeout_s : dflt_timeout);
        hrun_free(&r);
        return err_set(e, "%s", m);
    }
    if (r.code == 0) {
        *stdout_txt = r.out.p ? r.out.p : strdup("");
        r.out.p = NULL;
        if (have_key) {
            char sub[PATH_MAX + 16];
            snprintf(sub, sizeof(sub), "%s/%s", cdir, pl->id);
            if (pu_mkdir_p(sub) == 0) pu_write_atomic(cfile, *stdout_txt, strlen(*stdout_txt), 0644);
        }
        hrun_free(&r);
        return 0;
    }
    if (r.code == 2) {
        char *l = last_line(r.err.p ? r.err.p : "");
        *why = l && *l ? l : strdup("отказ без причины");
        if (l && !*l) free(l);
        hrun_free(&r);
        return 2;
    }
    if (r.code == 3) {
        snprintf(m, sizeof(m), "плагин %s: %s не готов (код 3) — повторите позже", pl->id, label);
    } else if (r.code == 127) {
        char *l = last_line(r.err.p ? r.err.p : "");
        snprintf(m, sizeof(m), "плагин %s: %s не запустился: %s", pl->id, label, l ? l : "");
        free(l);
    } else {
        snprintf(m, sizeof(m), "плагин %s: %s упал (код %d)", pl->id, label, r.code);
    }
    hrun_free(&r);
    return err_set(e, "%s", m);
}

/* ---- подготовка ---------------------------------------------------------------------------- */

static int is_common_key(const char *k) {
    static const char *const C[] = { "kind", "protocol", "on_fail", "ipv6", "prefix", "over", "device", "owner", NULL };
    for (size_t i = 0; C[i]; i++) if (!strcmp(C[i], k)) return 1;
    return 0;
}

static const char *scalar_of(const struct ynode *n) {
    return n && n->kind == YN_SCALAR ? n->str : NULL;
}

/* Имя вида выхода по манифесту: «tunnel:vless», «warp», «xsteer». */
static int kind_name_of(const struct ynode *rec, char *buf, size_t n) {
    const char *k = scalar_of(ynode_get(rec, "kind"));
    if (!k) return -1;
    if (!strcmp(k, "tunnel")) {
        const char *p = scalar_of(ynode_get(rec, "protocol"));
        if (!p) return -1;
        snprintf(buf, n, "tunnel:%s", p);
    } else snprintf(buf, n, "%s", k);
    return 0;
}

static void json_member_key(struct sbuf *b, const char *k) {
    sb_json(b, k);
    sb_str(b, ":");
}

/* Запись выхода как JSON с первым ключом owner (если owner не NULL); собственный owner записи
 * заменяется. */
static void record_json(struct sbuf *b, const struct ynode *rec, const char *owner_json) {
    if (rec->kind != YN_MAP) { plugin_node_json(b, rec); return; }
    sb_str(b, "{");
    size_t put = 0;
    if (owner_json) { json_member_key(b, "owner"); sb_str(b, owner_json); put++; }
    for (size_t i = 0; i < ynode_len(rec); i++) {
        const char *k = ynode_key_at(rec, i)->str;
        if (owner_json && !strcmp(k, "owner")) continue;
        if (put++) sb_str(b, ",");
        json_member_key(b, k);
        plugin_node_json(b, ynode_val_at(rec, i));
    }
    sb_str(b, "}");
}

static char *owner_json_of(const char *plugin, const char *out) {
    struct sbuf b = { 0 };
    sb_str(&b, "{\"plugin\":");
    sb_json(&b, plugin);
    if (out) { sb_str(&b, ",\"out\":"); sb_json(&b, out); }
    sb_str(&b, "}");
    return b.oom ? NULL : b.p;
}

/* Владелец развёрнутого выхода с помощником: {plugin, out, kind, keys}. */
static char *owner_self_json(const char *plugin, const char *out, const char *kind, const char *keys_json) {
    struct sbuf b = { 0 };
    sb_str(&b, "{\"plugin\":");
    sb_json(&b, plugin);
    sb_str(&b, ",\"out\":");
    sb_json(&b, out);
    sb_str(&b, ",\"kind\":");
    sb_json(&b, kind);
    sb_str(&b, ",\"keys\":");
    sb_str(&b, keys_json && *keys_json ? keys_json : "{}");
    sb_str(&b, "}");
    return b.oom ? NULL : b.p;
}

/* Имя выхода из фрагмента expand: [A-Za-z0-9_.-], не длиннее 31 знака (предел имени выхода в сокете,
 * ctl.md) — число называет отказ. */
static int fragment_name_ok(const char *n, char *why, size_t wn) {
    size_t l = strlen(n);
    if (!l || l > 31) { snprintf(why, wn, "имя «%s» — от 1 до 31 знака (предел имени выхода в сокете), а не %zu", n, l); return 0; }
    for (const char *p = n; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.' || *p == '-')) {
            snprintf(why, wn, "в имени «%s» допустимы буквы, цифры и _ . -", n);
            return 0;
        }
    return 1;
}

struct prep {
    const char *path;
    struct ydoc *d;
    struct err *e;
    char base[4096];
    struct sbuf members;        /* члены outputs подготовленной спеки */
    struct sbuf rep_expand;     /* отчёт: развороты */
    struct sbuf rep_warn;       /* отчёт: предупреждения */
    struct sbuf rep_pre;        /* отчёт: pre_apply */
    size_t out_put;             /* сколько членов уже записано */
    const char **names;         /* имена выходов спеки человека — вход хуков */
    size_t names_n;
    struct pal al;
    int al_changed;
    /* Выходы, заведённые хуками: имя → плагин и из какого выхода — для сообщений об ошибках. */
    struct { char *name, *plugin, *from; } *made;
    size_t made_n;
};

static void prep_free(struct prep *p) {
    free(p->members.p); free(p->rep_expand.p); free(p->rep_warn.p); free(p->rep_pre.p);
    free(p->names);
    pal_free(&p->al);
    for (size_t i = 0; i < p->made_n; i++) { free(p->made[i].name); free(p->made[i].plugin); free(p->made[i].from); }
    free(p->made);
}

static int prep_made(struct prep *p, const char *name, const char *plugin, const char *from) {
    void *nm = realloc(p->made, (p->made_n + 1) * sizeof(*p->made));
    if (!nm) return -1;
    p->made = nm;
    p->made[p->made_n].name = strdup(name);
    p->made[p->made_n].plugin = strdup(plugin);
    p->made[p->made_n].from = strdup(from);
    p->made_n++;
    return 0;
}

static void warn_collect(struct prep *p, const struct plugin *pl, const char *out_name, const char *stdout_txt) {
    if (!stdout_txt || !*stdout_txt) return;
    struct err pe;
    memset(&pe, 0, sizeof(pe));
    struct ydoc *d = ydoc_parse_buf(stdout_txt, strlen(stdout_txt), "хук", &pe);
    if (!d) return;
    const struct ynode *w = ynode_get(ydoc_root(d), "warnings");
    for (size_t i = 0; w && w->kind == YN_SEQ && i < w->len; i++) {
        const char *s = scalar_of(ynode_at(w, i));
        if (!s) continue;
        fprintf(stderr, "steer[warn] плагин %s: %s%s%s\n", pl->id, out_name ? out_name : "", out_name ? ": " : "", s);
        if (p->rep_warn.n) sb_str(&p->rep_warn, ",");
        sb_json(&p->rep_warn, s);
    }
    ydoc_free(d);
}

/* Вход check и expand (steer-api.md, 3.2): ключи вида по схеме и общие ключи записи (on_fail, ipv6,
 * over, device — как записаны): разворот переносит их на то, во что превращает выход. */
static char *hook_input(struct prep *p, const char *name, const char *kind, const char *keys_json,
                        const struct ynode *rec) {
    struct sbuf b = { 0 };
    char etc[PATH_MAX];
    sb_str(&b, "{\"api\":\"" STEER_API_VERSION "\",\"output\":{\"name\":");
    sb_json(&b, name);
    sb_str(&b, ",\"kind\":");
    sb_json(&b, kind);
    sb_str(&b, ",\"keys\":");
    sb_str(&b, keys_json);
    sb_str(&b, ",\"common\":{");
    size_t cn = 0;
    for (size_t i = 0; rec && i < ynode_len(rec); i++) {
        const char *k = ynode_key_at(rec, i)->str;
        if (!is_common_key(k) || !strcmp(k, "kind") || !strcmp(k, "protocol") || !strcmp(k, "owner")) continue;
        if (cn++) sb_str(&b, ",");
        json_member_key(&b, k);
        plugin_node_json(&b, ynode_val_at(rec, i));
    }
    sb_str(&b, "}},\"spec\":{\"etc\":");
    snprintf(etc, sizeof(etc), "%s", plat()->etc_dir);
    sb_json(&b, etc);
    sb_str(&b, ",\"outputs\":[");
    for (size_t i = 0; i < p->names_n; i++) {
        if (i) sb_str(&b, ",");
        sb_json(&b, p->names[i]);
    }
    sb_str(&b, "]},\"platform\":");
    sb_json(&b, plat()->name);
    sb_str(&b, "}");
    if (b.oom) { free(b.p); return NULL; }
    return b.p;
}

static int member_put(struct prep *p, const char *name, const struct ynode *rec, const char *owner_json,
                      const char *raw_json) {
    if (p->out_put++) sb_str(&p->members, ",\n  ");
    json_member_key(&p->members, name);
    if (raw_json) sb_str(&p->members, raw_json);
    else record_json(&p->members, rec, owner_json);
    return p->members.oom ? -1 : 0;
}

/* Один выход спеки человека: check, expand, ресурсы. */
static int prep_output(struct prep *p, const struct ynode *kn, const struct ynode *rec) {
    const char *name = kn->str;
    char kname[96];
    const struct plugin_kind *pk = NULL;
    if (rec && rec->kind == YN_MAP && kind_name_of(rec, kname, sizeof(kname)) == 0) pk = plugin_kind_find(kname);
    struct err *e = p->e;
    if (!pk || (!pk->check.prog && !pk->expand.prog && !pk->res_ports && !pk->res_queues))
        return member_put(p, name, rec, NULL, NULL) == 0 ? 0 : err_set(e, "%s", "недостаточно памяти");
    const struct plugin *pl = pk->owner;
    /* Ключи вида — по схеме (как в разборе спеки). */
    size_t kc = 0;
    for (size_t i = 0; i < ynode_len(rec); i++) if (!is_common_key(ynode_key_at(rec, i)->str)) kc++;
    struct ynode km = { .kind = YN_MAP };
    km.items = calloc(2 * (kc ? kc : 1), sizeof(*km.items));
    if (!km.items) return err_set(e, "%s", "недостаточно памяти");
    for (size_t i = 0; i < ynode_len(rec); i++) {
        if (is_common_key(ynode_key_at(rec, i)->str)) continue;
        km.items[2 * km.len] = (struct ynode *)ynode_key_at(rec, i);
        km.items[2 * km.len + 1] = (struct ynode *)ynode_val_at(rec, i);
        km.len++;
    }
    char *kjson = NULL, conf[2 * PATH_MAX], etc[PATH_MAX];
    const struct ynode *at = NULL;
    plugin_etc(etc, sizeof(etc));
    snprintf(conf, sizeof(conf), "%s/conf/%s", etc, pl->id);
    struct err ke;
    memset(&ke, 0, sizeof(ke));
    if (plugin_keys_check(pk, &km, p->base, conf, &kjson, &at, &ke) != 0) {
        char m[sizeof(ke.msg) + 80];
        snprintf(m, sizeof(m), "outputs.%s: %s", name, ke.msg);
        free(km.items);
        ynode_err(e, p->d, at ? at : rec, "%s", m);
        return -1;
    }
    free(km.items);
    int rc = 0;
    char *out_txt = NULL, *why = NULL;
    if (pk->check.prog) {
        char *in = hook_input(p, name, kname, kjson, rec);
        if (!in) { free(kjson); return err_set(e, "%s", "недостаточно памяти"); }
        int hr = hook_run(pl, &pk->check, "check", name, 10, in, &out_txt, &why, e);
        free(in);
        if (hr == 2) {
            char m[900];
            snprintf(m, sizeof(m), "outputs.%s: %s", name, why);
            free(why);
            free(kjson);
            ynode_err(e, p->d, rec, "%s", m);
            return -1;
        }
        if (hr != 0) { free(kjson); return -1; }
        warn_collect(p, pl, name, out_txt);
        free(out_txt);
        out_txt = NULL;
    }
    if (pk->res_ports || pk->res_queues) {
        char owner[200];
        snprintf(owner, sizeof(owner), "%s/%s", pl->id, name);
        if (pal_ensure(&p->al, owner, pk->res_ports, pk->res_queues, &p->al_changed, e) != 0) { free(kjson); return -1; }
    }
    if (!pk->expand.prog) {
        free(kjson);
        return member_put(p, name, rec, NULL, NULL) == 0 ? 0 : err_set(e, "%s", "недостаточно памяти");
    }
    /* expand: self и новые выходы (steer-api.md, 3.3). */
    char *in = hook_input(p, name, kname, kjson, rec);
    if (!in) { free(kjson); return err_set(e, "%s", "недостаточно памяти"); }
    int hr = hook_run(pl, &pk->expand, "expand", name, 10, in, &out_txt, &why, e);
    free(in);
    if (hr == 2) {
        char m[900];
        snprintf(m, sizeof(m), "плагин %s: разворот %s — %s", pl->id, name, why);
        free(why);
        free(kjson);
        return err_set(e, "%s", m);
    }
    if (hr != 0) { free(kjson); return -1; }
    struct err pe;
    memset(&pe, 0, sizeof(pe));
    struct ydoc *fd = ydoc_parse_buf(out_txt, strlen(out_txt), "ответ expand", &pe);
    if (!fd) {
        char m[900];
        snprintf(m, sizeof(m), "плагин %s: разворот %s — ответ не разобран: %s", pl->id, name, pe.msg);
        free(out_txt);
        free(kjson);
        return err_set(e, "%s", m);
    }
    free(out_txt);
    const struct ynode *fr = ydoc_root(fd);
    const struct ynode *self = ynode_get(fr, "self"), *outs = ynode_get(fr, "outputs");
    const struct ynode *hn = ynode_get(fr, "helper");
    int helper = 0;
    if (hn) ynode_bool(hn, &helper);
    char msg[900];
    if (!self || self->kind != YN_MAP) {
        snprintf(msg, sizeof(msg), "плагин %s: разворот %s — в ответе нет self", pl->id, name);
        ydoc_free(fd); free(kjson);
        return err_set(e, "%s", msg);
    }
    {
        char sk[96];
        if (kind_name_of(self, sk, sizeof(sk)) == 0 && plugin_kind_find(sk) &&
            plugin_kind_find(sk)->expand.prog) {
            snprintf(msg, sizeof(msg), "плагин %s: разворот %s — self сам вида с разворотом (%s): разворот однократный",
                     pl->id, name, sk);
            ydoc_free(fd); free(kjson);
            return err_set(e, "%s", msg);
        }
    }
    /* Имена новых выходов: не заняты человеком и друг другом. */
    for (size_t i = 0; outs && outs->kind == YN_MAP && i < ynode_len(outs); i++) {
        const char *nn = ynode_key_at(outs, i)->str;
        char w2[300];
        if (!fragment_name_ok(nn, w2, sizeof(w2))) {
            snprintf(msg, sizeof(msg), "плагин %s: разворот %s — outputs.%s: %s", pl->id, name, nn, w2);
            ydoc_free(fd); free(kjson);
            return err_set(e, "%s", msg);
        }
        for (size_t k = 0; k < p->names_n; k++)
            if (!strcmp(p->names[k], nn)) {
                snprintf(msg, sizeof(msg), "плагин %s: разворот %s — outputs.%s: такой выход уже есть в спеке", pl->id, name, nn);
                ydoc_free(fd); free(kjson);
                return err_set(e, "%s", msg);
            }
        for (size_t k = 0; k < p->made_n; k++)
            if (!strcmp(p->made[k].name, nn)) {
                snprintf(msg, sizeof(msg), "плагин %s: разворот %s — outputs.%s: уже заведён плагином %s", pl->id, name, nn, p->made[k].plugin);
                ydoc_free(fd); free(kjson);
                return err_set(e, "%s", msg);
            }
    }
    /* self — выход под прежним именем; с помощником — помечен владельцем (помощник вида ведёт
     * членов, а ядру нужно знать, чей он). */
    /* Владелец self с помощником несёт и вид с ключами, как их получил разворот: {conf} помощника
     * развёрнутого выхода говорит ему вид плагина и его ключи (steer-api.md, 1.4), а не «group». */
    char *oj_self = helper ? owner_self_json(pl->id, name, pk->name, kjson) : NULL;
    if (member_put(p, name, self, oj_self, NULL) != 0) { free(oj_self); ydoc_free(fd); free(kjson); return err_set(e, "%s", "недостаточно памяти"); }
    free(oj_self);
    if (p->rep_expand.n) sb_str(&p->rep_expand, ",");
    sb_printf(&p->rep_expand, "{\"id\":");
    sb_json(&p->rep_expand, pl->id);
    sb_str(&p->rep_expand, ",\"out\":");
    sb_json(&p->rep_expand, name);
    sb_str(&p->rep_expand, ",\"outputs\":[");
    for (size_t i = 0; outs && outs->kind == YN_MAP && i < ynode_len(outs); i++) {
        const char *nn = ynode_key_at(outs, i)->str;
        char *oj = owner_json_of(pl->id, name);
        if (!oj || member_put(p, nn, ynode_val_at(outs, i), oj, NULL) != 0 || prep_made(p, nn, pl->id, name) != 0) {
            free(oj);
            ydoc_free(fd); free(kjson);
            return err_set(e, "%s", "недостаточно памяти");
        }
        free(oj);
        if (i) sb_str(&p->rep_expand, ",");
        sb_json(&p->rep_expand, nn);
    }
    sb_str(&p->rep_expand, "]}");
    ydoc_free(fd); free(kjson);
    return rc;
}

/* ---- pre_apply -------------------------------------------------------------------------------- */

static char *node_text(const struct ynode *n) {
    struct sbuf b = { 0 };
    plugin_node_json(&b, n);
    return b.oom ? NULL : b.p;
}

/* Порядок pre_apply: плагины с хуком, затем по id, но requires.plugins — раньше зависимого. */
static size_t pre_order(const struct plugin **order, size_t max) {
    size_t n = 0, total = 0;
    const struct plugin **all = calloc(plugin_n() ? plugin_n() : 1, sizeof(*all));
    if (!all) return 0;
    for (size_t i = 0; i < plugin_n(); i++)
        if (plugin_at(i)->enabled && plugin_at(i)->pre_apply.prog) all[total++] = plugin_at(i);
    char *used = calloc(total ? total : 1, 1);
    if (!used) { free(all); return 0; }
    while (n < total && n < max) {
        size_t pick = total;
        for (size_t i = 0; i < total && pick == total; i++) {
            if (used[i]) continue;
            int ready = 1;
            for (size_t r = 0; r < all[i]->requires_n; r++)
                for (size_t j = 0; j < total; j++)
                    if (!used[j] && j != i && !strcmp(all[j]->id, all[i]->requires[r])) ready = 0;
            if (ready) pick = i;
        }
        if (pick == total)                          /* круг зависимостей — по id */
            for (size_t i = 0; i < total; i++) if (!used[i]) { pick = i; break; }
        used[pick] = 1;
        order[n++] = all[pick];
    }
    free(used);
    free(all);
    return n;
}

static void list_add(struct sbuf *b, size_t *cnt, const char *s) {
    if ((*cnt)++) sb_str(b, ",");
    sb_json(b, s);
}

/* Новая спека после pre_apply (nw) против прежней (old) → текст JSON с owner на добавленном и отчёт
 * (added, changed). Выходы, правила, списки и клиенты, которых не было, получают owner = {плагин}. */
static char *spec_diff_mark(const struct ynode *nw, const struct ynode *old, const char *plugin,
                            struct sbuf *added, size_t *na, struct sbuf *changed, size_t *nc) {
    struct sbuf b = { 0 };
    char *oj = owner_json_of(plugin, NULL);
    if (!oj) return NULL;
    sb_str(&b, "{\n");
    for (size_t i = 0; i < ynode_len(nw); i++) {
        const char *k = ynode_key_at(nw, i)->str;
        const struct ynode *v = ynode_val_at(nw, i), *ov = ynode_get(old, k);
        if (i) sb_str(&b, ",\n");
        sb_printf(&b, "  ");
        json_member_key(&b, k);
        int is_map = !strcmp(k, "outputs") || !strcmp(k, "lists") || !strcmp(k, "clients");
        if (is_map && v->kind == YN_MAP) {
            sb_str(&b, "{");
            for (size_t j = 0; j < ynode_len(v); j++) {
                const char *nm = ynode_key_at(v, j)->str;
                const struct ynode *rec = ynode_val_at(v, j), *orec = ynode_get(ov, nm);
                char path[200];
                snprintf(path, sizeof(path), "%s.%s", k, nm);
                if (j) sb_str(&b, ",");
                sb_str(&b, "\n    ");
                json_member_key(&b, nm);
                if (!orec) {
                    list_add(added, na, path);
                    record_json(&b, rec, oj);
                } else {
                    char *a = node_text(rec), *o = node_text(orec);
                    if (a && o && strcmp(a, o) != 0) {
                        /* что именно изменилось — по ключам записи */
                        for (size_t f = 0; rec->kind == YN_MAP && f < ynode_len(rec); f++) {
                            const char *fk = ynode_key_at(rec, f)->str;
                            char *fa = node_text(ynode_val_at(rec, f)), *fo = node_text(ynode_get(orec, fk) ? ynode_get(orec, fk) : rec);
                            if (!ynode_get(orec, fk) || (fa && fo && strcmp(fa, fo) != 0)) {
                                char fp[300];
                                snprintf(fp, sizeof(fp), "%s.%s", path, fk);
                                list_add(changed, nc, fp);
                            }
                            free(fa); free(fo);
                        }
                        for (size_t f = 0; orec->kind == YN_MAP && f < ynode_len(orec); f++)
                            if (!ynode_get(rec, ynode_key_at(orec, f)->str)) {
                                char fp[300];
                                snprintf(fp, sizeof(fp), "%s.%s", path, ynode_key_at(orec, f)->str);
                                list_add(changed, nc, fp);
                            }
                    }
                    free(a); free(o);
                    /* владелец прежней записи хук не снимает */
                    const struct ynode *oo = ynode_get(orec, "owner");
                    if (oo && !ynode_get(rec, "owner")) {
                        char *oy = node_text(oo);
                        record_json(&b, rec, oy);
                        free(oy);
                    } else record_json(&b, rec, NULL);
                }
            }
            sb_str(&b, "\n  }");
        } else if (!strcmp(k, "rules") && v->kind == YN_SEQ) {
            sb_str(&b, "[");
            for (size_t j = 0; j < v->len; j++) {
                const struct ynode *rec = ynode_at(v, j);
                char *a = node_text(rec);
                int had = 0;
                for (size_t q = 0; ov && ov->kind == YN_SEQ && q < ov->len && !had; q++) {
                    char *o = node_text(ynode_at(ov, q));
                    if (a && o && !strcmp(a, o)) had = 1;
                    free(o);
                }
                free(a);
                if (j) sb_str(&b, ",");
                sb_str(&b, "\n    ");
                if (had) record_json(&b, rec, NULL);
                else {
                    char path[64];
                    snprintf(path, sizeof(path), "rules[%zu]", j);
                    list_add(added, na, path);
                    record_json(&b, rec, oj);
                }
            }
            sb_str(&b, "\n  ]");
        } else {
            char *a = node_text(v), *o = ov ? node_text(ov) : NULL;
            if (!ov || (a && o && strcmp(a, o) != 0)) list_add(changed, nc, k);
            if (a) sb_str(&b, a);
            free(a); free(o);
        }
    }
    sb_str(&b, "\n}\n");
    free(oj);
    if (b.oom) { free(b.p); return NULL; }
    return b.p;
}

/* ---- spec_prepare ------------------------------------------------------------------------------- */

/* Сообщение разбора v2 начинается «имя:строка:столбец: » — строки подготовленного текста человеку
 * ничего не говорят, позицию снимаем. */
static const char *strip_pos(const char *m) {
    for (const char *q = m; (q = strchr(q, ':')); q++) {
        unsigned a, b;
        int used = 0;
        if (sscanf(q, ":%u:%u: %n", &a, &b, &used) >= 2 && used) return q + used;
    }
    return m;
}

/* Отказ пробной загрузки подготовленной спеки. Если он про выход, заведённый хуком, к нему
 * добавляются плагин и выход, из которого развёрнуто: «плагин warpbox: разворот w — outputs.w.1: …». */
static int trial_error(struct prep *p, struct err *e, const char *msg) {
    const char *m = strip_pos(msg);
    char out[1000];
    size_t best = 0;
    size_t bi = p->made_n;
    for (size_t i = 0; i < p->made_n; i++) {
        char pat[80];
        snprintf(pat, sizeof(pat), "outputs.%s", p->made[i].name);
        size_t pl = strlen(pat);
        const char *f = strstr(m, pat);
        if (f && (f[pl] == ':' || f[pl] == ' ' || f[pl] == '.' || !f[pl]) && pl > best) { best = pl; bi = i; }
    }
    if (bi < p->made_n)
        snprintf(out, sizeof(out), "плагин %s: разворот %s — %s", p->made[bi].plugin, p->made[bi].from, m);
    else
        snprintf(out, sizeof(out), "подготовленная спека не разобрана: %s", m);
    return err_set(e, "%s", out);
}

static void prune_old(const char *dir, const char *keep_key) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    time_t now = time(NULL);
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.' || strncmp(de->d_name, keep_key, 64) == 0) continue;
        char f[PATH_MAX + 300];
        snprintf(f, sizeof(f), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(f, &st) == 0 && S_ISREG(st.st_mode) && now - st.st_mtime > 24 * 3600) unlink(f);
    }
    closedir(d);
}

int spec_prepare(const char *path, struct err *e) {
    if (!needs_prepare()) return 0;
    char *human = NULL;
    size_t hn = 0;
    if (spec_read_text(path, &human, &hn, e) != 0) return -1;
    char key[65];
    if (prepare_key(human, hn, key) != 0) { free(human); return 0; }
    char pp[PATH_MAX + 80];
    prepared_path(pp, sizeof(pp), key, ".json");
    if (access(pp, F_OK) == 0) { free(human); return 0; }       /* уже подготовлена */
    /* Спека человека разбирается как написана ДО хуков: её ошибки (опечатка, ключ вне схемы, нет
     * выхода) называются настоящими строкой и столбцом, а не «подготовленная спека не разобрана». */
    {
        struct spec *hs = calloc(1, sizeof(*hs));
        if (!hs) { free(human); return err_set(e, "%s", "недостаточно памяти для подготовки"); }
        int hr = load_spec_mode(path, hs, e, LOAD_HUMAN);
        spec_release(hs);
        free(hs);
        if (hr != 0) { free(human); return -1; }
    }
    struct err pe;
    memset(&pe, 0, sizeof(pe));
    struct ydoc *d = ydoc_parse_buf(human, hn, path, &pe);
    const struct ynode *root = d ? ydoc_root(d) : NULL;
    /* Не спека v2 (v1, не разбирается) — готовить нечего: ошибки назовёт load_spec. */
    if (!d || !root || root->kind != YN_MAP || !ynode_get(root, "version")) { ydoc_free(d); free(human); return 0; }
    free(human);

    struct prep p;
    memset(&p, 0, sizeof(p));
    p.path = path;
    p.d = d;
    p.e = e;
    v2_base_dir(ydoc_name(d), p.base, sizeof(p.base));
    int rc = -1;
    char *text = NULL;
    const struct ynode *outs = ynode_get(root, "outputs");
    p.names = calloc(outs ? ynode_len(outs) + 1 : 1, sizeof(*p.names));
    if (!p.names) { err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
    for (size_t i = 0; outs && outs->kind == YN_MAP && i < ynode_len(outs); i++)
        p.names[p.names_n++] = ynode_key_at(outs, i)->str;
    /* Владельца выхода, правила, списка и клиента пишет только плагин: в спеке человека `owner` — отказ,
     * иначе человек выдал бы свою запись за запись плагина. */
    {
        static const char *const SEC[] = { "outputs", "lists", "clients", NULL };
        for (size_t si = 0; SEC[si]; si++) {
            const struct ynode *sec = ynode_get(root, SEC[si]);
            for (size_t i = 0; sec && sec->kind == YN_MAP && i < ynode_len(sec); i++) {
                const struct ynode *ow = ynode_get(ynode_val_at(sec, i), "owner");
                if (ow) {
                    char m[300];
                    snprintf(m, sizeof(m), "%s.%s: owner пишет только плагин — в спеке человека его нет", SEC[si],
                             ynode_key_at(sec, i)->str);
                    ynode_err(e, d, ow, "%s", m);
                    goto done;
                }
            }
        }
        const struct ynode *rl = ynode_get(root, "rules");
        for (size_t i = 0; rl && rl->kind == YN_SEQ && i < rl->len; i++) {
            const struct ynode *ow = ynode_get(ynode_at(rl, i), "owner");
            if (ow) {
                char m[160];
                snprintf(m, sizeof(m), "rules[%zu]: owner пишет только плагин — в спеке человека его нет", i);
                ynode_err(e, d, ow, "%s", m);
                goto done;
            }
        }
    }
    if (pal_load(&p.al) != 0) { err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
    for (size_t i = 0; i < plugin_n(); i++) {
        const struct plugin *pl = plugin_at(i);
        if (pl->enabled && (pl->res_ports || pl->res_queues || pl->res_marks) &&
            pal_ensure_plugin(&p.al, pl, &p.al_changed, e) != 0)
            goto done;
    }
    for (size_t i = 0; outs && outs->kind == YN_MAP && i < ynode_len(outs); i++)
        if (prep_output(&p, ynode_key_at(outs, i), ynode_val_at(outs, i)) != 0) goto done;

    /* Спека с выходами после check и expand. */
    struct sbuf full = { 0 };
    sb_str(&full, "{\n");
    for (size_t i = 0; i < ynode_len(root); i++) {
        const char *k = ynode_key_at(root, i)->str;
        if (i) sb_str(&full, ",\n");
        sb_str(&full, "  ");
        json_member_key(&full, k);
        if (!strcmp(k, "outputs")) {
            sb_str(&full, "{\n  ");
            sb_put(&full, p.members.p ? p.members.p : "", p.members.n);
            sb_str(&full, "\n  }");
        } else plugin_node_json(&full, ynode_val_at(root, i));
    }
    sb_str(&full, "\n}\n");
    if (full.oom) { free(full.p); err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
    text = full.p;

    /* pre_apply: каждый плагин видит результат предыдущего. */
    size_t np = plugin_n();
    const struct plugin **order = calloc(np ? np : 1, sizeof(*order));
    if (!order) { err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
    size_t on = pre_order(order, np);
    for (size_t i = 0; i < on; i++) {
        const struct plugin *pl = order[i];
        char *out_txt = NULL, *why = NULL;
        int hr = hook_run(pl, &pl->pre_apply, "pre_apply", NULL, 30, text, &out_txt, &why, e);
        if (hr == 2) {
            char m[900];
            snprintf(m, sizeof(m), "плагин %s: %s", pl->id, why);
            free(why);
            free(order);
            err_set(e, "%s", m);
            goto done;
        }
        if (hr != 0) { free(order); goto done; }
        struct err xe;
        memset(&xe, 0, sizeof(xe));
        struct ydoc *nd = ydoc_parse_buf(out_txt, strlen(out_txt), "ответ pre_apply", &xe);
        struct ydoc *od = ydoc_parse_buf(text, strlen(text), "спека", &xe);
        const struct ynode *nr = nd ? ydoc_root(nd) : NULL;
        if (!nd || !od || !nr || nr->kind != YN_MAP) {
            char m[900];
            snprintf(m, sizeof(m), "плагин %s: pre_apply вернул спеку, которая не читается: %s", pl->id,
                     nd ? "не отображение" : xe.msg);
            ydoc_free(nd); ydoc_free(od);
            free(out_txt); free(order);
            err_set(e, "%s", m);
            goto done;
        }
        struct sbuf added = { 0 }, changed = { 0 };
        size_t na = 0, nc = 0;
        char *nt = spec_diff_mark(nr, ydoc_root(od), pl->id, &added, &na, &changed, &nc);
        ydoc_free(nd); ydoc_free(od);
        free(out_txt);
        if (!nt) { free(added.p); free(changed.p); free(order); err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
        free(text);
        text = nt;
        if (na || nc) {
            if (p.rep_pre.n) sb_str(&p.rep_pre, ",");
            sb_str(&p.rep_pre, "{\"id\":");
            sb_json(&p.rep_pre, pl->id);
            sb_printf(&p.rep_pre, ",\"added\":[%s],\"changed\":[%s]}", added.p ? added.p : "", changed.p ? changed.p : "");
        }
        free(added.p); free(changed.p);
    }
    free(order);

    /* Подготовленная спека и отчёт — в кэш; пробная загрузка проверяет итог разбором ядра. */
    {
        char cdir[PATH_MAX], pdir[PATH_MAX + 16];
        cache_dir(cdir, sizeof(cdir));
        snprintf(pdir, sizeof(pdir), "%s/prepared", cdir);
        if (pu_mkdir_p(pdir) != 0 || pu_write_atomic(pp, text, strlen(text), 0644) != 0) {
            char m[PATH_MAX + 120];
            snprintf(m, sizeof(m), "не записать подготовленную спеку в %s: %s", pdir, strerror(errno));
            err_set(e, "%s", m);
            goto done;
        }
        /* Выдача ресурсов — на диск ДО пробной загрузки: подготовленную спеку читает разбор ядра, и порты и
         * очереди выхода вида плагина он берёт из alloc.json (plugin_alloc_lookup). Сохранённая после, она
         * не находилась при первой подготовке — «ресурсы выхода не выданы — нужен reload», и reload падал
         * тем же. Номера выданы насовсем (steer-api.md, 6), так что отказ пробы их не отнимает. */
        if (p.al_changed) { pal_save(&p.al); p.al_changed = 0; }
        struct spec *trial = calloc(1, sizeof(*trial));
        struct err te;
        memset(&te, 0, sizeof(te));
        if (!trial) { unlink(pp); err_set(e, "%s", "недостаточно памяти для подготовки"); goto done; }
        int lr = load_spec_mode(path, trial, &te, LOAD_PREPARED);
        int was_prepared = trial->prepared;
        spec_release(trial);
        free(trial);
        if (lr != 0 || !was_prepared) {
            unlink(pp);
            if (lr != 0) trial_error(&p, e, te.msg);
            else err_set(e, "%s", "подготовленная спека не прочиталась обратно");
            goto done;
        }
        struct sbuf rep = { 0 };
        sb_printf(&rep, "{\"pre_apply\":[%s],\"expand\":[%s],\"warnings\":[%s]}\n", p.rep_pre.p ? p.rep_pre.p : "",
                  p.rep_expand.p ? p.rep_expand.p : "", p.rep_warn.p ? p.rep_warn.p : "");
        char rp[PATH_MAX + 100];
        prepared_path(rp, sizeof(rp), key, ".report.json");
        if (!rep.oom && rep.p) pu_write_atomic(rp, rep.p, rep.n, 0644);
        free(rep.p);
        prune_old(pdir, key);
        if (p.al_changed) pal_save(&p.al);
    }
    rc = 0;
done:
    free(text);
    prep_free(&p);
    ydoc_free(d);
    return rc;
}
