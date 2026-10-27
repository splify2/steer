/* `steer plugin …` — менеджер плагинов из командной строки (steer-api.md, 4.2; бэкенд splify2 —
 * docs/rpcd-api.md, «Плагины»).
 *
 *   list [--json]                    стоящие плагины: состояние, причина, поля манифеста, доступное обновление
 *   search [слово] [--json]          каталог всех подключённых репозиториев
 *   status [id] [--json]             состояние (с id — ещё сверка файлов с MANIFEST)
 *   install <id> [версия]            установка (самая новая совместимая или названная)
 *   install --file x.s2p [--unsigned]
 *   update [id] [--auto [--if-stale]]  обновление одного или всех; --auto — фоновое (окно, откат)
 *   remove <id> [--force] [--purge]
 *   enable <id> | disable <id>
 *   autoupdate <id> on|off
 *   repo list | repo add <url> <номер ключа> [--key-file F] (иначе ключ — stdin) | repo del <имя>
 *   ensure <id>…                     поставить недостающие (без сети — из семени)
 *   migrate                          плагины по спеке и по прежним пакетам модулей, из семени (переход на 2.1)
 *   job <номер>                      ход и итог задания (install/update с --job)
 *
 * Ответ с --json — объект в stdout; отказ — {"ok":false,"error":…} в stdout, те же слова в stderr, код 1.
 * Ход — строками в stderr. Изменяющие действия идут под блокировкой менеджера; занято — «busy: …». */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "pm.h"
#include "err.h"
#include "sigverify.h"

static const char *g_job_log;     /* в задании: ход — ещё и в файл */

void pm_progress(struct pm_ctx *x, const char *fmt, ...) {
    if (x && x->quiet) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* ---- ответы ---- */

static int fail(struct pm_ctx *x, const char *msg) {
    fprintf(stderr, "steer plugin: %s\n", msg);
    if (x->json) {
        struct jw w;
        jw_init(&w, stdout);
        jw_obj(&w);
        jw_kbool(&w, "ok", 0);
        jw_kstr(&w, "error", msg);
        jw_end(&w);
        fputc('\n', stdout);
    }
    return 1;
}

static int usage(void) {
    fputs("steer plugin list | search [слово] | status [id] | install <id> [версия] | install --file F [--unsigned]\n"
          "             | update [id] [--auto] | remove <id> [--force] [--purge] | enable <id> | disable <id>\n"
          "             | autoupdate <id> on|off | repo list | repo add <url> <номер ключа> | repo del <имя>\n"
          "             | ensure <id>... | migrate | job <номер>      (--json — ответ JSON; --job — install/update заданием)\n",
          stderr);
    return 2;
}

static int id_ok(const char *s) {
    if (!s || !*s || strlen(s) > 64) return 0;
    if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9'))) return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-')) return 0;
    return 1;
}

/* ---- записи списка ---- */

static const struct pm_repo *repo_of(struct pm_ctx *x, const char *name) {
    return name ? pm_repo_find(&x->repos, name) : NULL;
}

static const char *trust_of(struct pm_ctx *x, const struct pm_inst *p) {
    if (p && p->unsigned_) return "unsigned";
    const struct pm_repo *r = repo_of(x, p ? p->repo : NULL);
    if (!p || !p->repo) return "unsigned";
    return r && r->official ? "official" : "third-party";
}

/* Доступное обновление из кэша индекса (без сети). */
static const char *update_of(struct pm_ctx *x, const struct pm_inst *p, int *security, const char **yanked) {
    *security = 0;
    *yanked = NULL;
    if (!p || !p->repo || !p->version || p->unsigned_) return NULL;
    struct pm_repo *r = pm_repo_find(&x->repos, p->repo);
    if (!r) return NULL;
    struct pm_err e;
    if (pm_index_get(r, 0, &e) != 0) return NULL;
    const struct ynode *pl = pm_index_plugin(r, p->id);
    const struct ynode *vs = ynode_get(pl, "versions");
    for (size_t i = 0; i < ynode_len(vs); i++) {
        const struct ynode *v = ynode_at(vs, i);
        const char *ver = yn_str(v, "version");
        if (ver && !strcmp(ver, p->version)) {
            const struct ynode *y = ynode_get(v, "yanked");
            if (y && y->kind == YN_MAP) {
                *yanked = yn_str(y, "why") ? yn_str(y, "why") : "версия отозвана";
                *security = yn_bool(y, "security", 0);
            }
        }
    }
    struct pm_cand c;
    if (pm_select(x, r, p->id, NULL, NULL, p->variant ? p->variant : "full", NULL, &c, &e) != 0) return NULL;
    return pm_ver_cmp(c.version, p->version) > 0 ? c.version : NULL;
}

static void emit_themes(struct jw *w, const char *dir, const struct ynode *themes) {
    jw_arr(w);
    for (size_t i = 0; i < ynode_len(themes); i++) {
        const struct ynode *t = ynode_at(themes, i);
        const char *file = yn_str(t, "file");
        struct ydoc *td = NULL;
        if (dir && file && file[0] != '/' && !strstr(file, "..")) {
            char *p = pm_path(dir, file);
            struct pm_err e;
            td = pm_json_load(p, &e);
            free(p);
        }
        /* Панель ждёт содержимое темы (name, light, dark, css) — вкладываем файл с id манифеста. */
        jw_obj(w);
        for (size_t j = 0; j < ynode_len(t); j++) jw_knode(w, ynode_key_at(t, j)->str, ynode_val_at(t, j));
        if (td) {
            const struct ynode *r = ydoc_root(td);
            for (size_t j = 0; j < ynode_len(r); j++) {
                const char *k = ynode_key_at(r, j)->str;
                if (ynode_get(t, k)) continue;
                jw_knode(w, k, ynode_val_at(r, j));
            }
            ydoc_free(td);
        }
        jw_end(w);
    }
    jw_aend(w);
}

static void emit_names(struct jw *w, const struct ynode *list) {
    jw_arr(w);
    for (size_t i = 0; i < ynode_len(list); i++) {
        const char *n = yn_str(ynode_at(list, i), "name");
        if (n) jw_str(w, n);
    }
    jw_aend(w);
}

static void emit_entry(struct pm_ctx *x, struct jw *w, const struct pm_inst *p, const char *id, int deep) {
    struct ydoc *md = pm_manifest(id);
    const struct ynode *m = md ? ydoc_root(md) : NULL;
    char *dir = pm_path(pm_root(), id);
    jw_obj(w);
    jw_kstr(w, "id", id);
    jw_kstr(w, "name", m && yn_str(m, "name") ? yn_str(m, "name") : id);
    jw_kstr(w, "description", m ? yn_str(m, "description") : NULL);
    jw_kstr(w, "version", p && p->version ? p->version : m ? yn_str(m, "version") : NULL);
    jw_kstr(w, "repo", p ? p->repo : NULL);
    jw_kstr(w, "trust", trust_of(x, p));
    jw_kstr(w, "type", m && yn_str(m, "type") ? yn_str(m, "type") : "plugin");
    const char *state = p && p->state ? p->state : "installed";
    const char *why = p ? p->why : "положен руками — не включён";
    if (!m && p) { state = "failed"; why = "файлов плагина нет — поставьте его заново"; }
    jw_kstr(w, "state", state);
    jw_kstr(w, "why", why);
    jw_kbool(w, "enabled", !strcmp(state, "enabled"));
    jw_kbool(w, "auto_update", p ? p->auto_update && !p->unsigned_ : 0);
    jw_kbool(w, "pinned", p && p->pinned);
    jw_kstr(w, "pinned_version", p ? p->pinned : NULL);
    jw_kstr(w, "variant", p && p->variant ? p->variant : "full");
    jw_kbool(w, "unsigned", p && p->unsigned_);
    jw_kstr(w, "from", p ? p->from : NULL);
    jw_kstr(w, "installed_at", p ? p->installed_at : NULL);
    int sec = 0;
    const char *yanked = NULL;
    const char *upd = update_of(x, p, &sec, &yanked);
    jw_kstr(w, "update", upd);
    if (upd && sec) jw_kbool(w, "update_security", 1);
    if (yanked) jw_kstr(w, "yanked", yanked);
    jw_knode(w, "compat", m ? ynode_get(m, "compat") : NULL);
    jw_knode(w, "ui", m ? ynode_get(m, "ui") : NULL);
    jw_knode(w, "i18n", m ? ynode_get(m, "i18n") : NULL);
    jw_knode(w, "languages", m ? ynode_get(ynode_get(m, "i18n"), "languages") : NULL);
    jw_key(w, "themes");
    emit_themes(w, dir, m ? ynode_get(m, "themes") : NULL);
    jw_knode(w, "permissions", m ? ynode_get(m, "permissions") : NULL);
    const struct ynode *steer = m ? ynode_get(m, "steer") : NULL;
    jw_key(w, "kinds");
    emit_names(w, ynode_get(steer, "kinds"));
    jw_key(w, "commands");
    emit_names(w, ynode_get(steer, "commands"));
    jw_key(w, "services");
    emit_names(w, ynode_get(steer, "services"));
    jw_knode(w, "rpc", m ? ynode_get(m, "rpc") : NULL);
    jw_knode(w, "requires", m ? ynode_get(m, "requires") : NULL);
    jw_key(w, "packages");
    jw_arr(w);
    for (size_t i = 0; p && i < p->nsystem; i++) jw_str(w, p->system[i]);
    jw_aend(w);
    jw_key(w, "used_by");
    jw_arr(w);
    for (size_t i = 0; i < x->st.n; i++) {
        if (!strcmp(x->st.v[i].id, id)) continue;
        struct ydoc *om = pm_manifest(x->st.v[i].id);
        if (om && ynode_get(ynode_get(ynode_get(ydoc_root(om), "requires"), "plugins"), id)) jw_str(w, x->st.v[i].id);
        if (om) ydoc_free(om);
    }
    jw_aend(w);
    jw_key(w, "bad_versions");
    jw_obj(w);
    for (size_t i = 0; p && i < p->nbad; i++) jw_kstr(w, p->bad[i].ver, p->bad[i].why);
    jw_end(w);
    if (deep) {
        /* Сверка файлов с MANIFEST (как служба steer-plugins после sysupgrade, s2p.md). */
        char *mp = pm_path(dir, "MANIFEST");
        char *mt = pm_read(mp, NULL);
        free(mp);
        const char *bad = NULL;
        char *badbuf = NULL;
        if (!mt) bad = "нет MANIFEST";
        else {
            char *save = NULL;
            char *l = strtok_r(mt, "\n", &save);
            for (l = strtok_r(NULL, "\n", &save); l && !bad; l = strtok_r(NULL, "\n", &save)) {
                if (strlen(l) < 66) continue;
                const char *rest = l + 65;
                const char *sp1 = strchr(rest, ' ');
                const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
                if (!sp2) continue;
                char *fp = pm_path(dir, sp2 + 1);
                unsigned char h[32];
                unsigned long long sz;
                char hx[65];
                if (pm_file_sha256(fp, h, &sz) != 0) { badbuf = pm_fmt("нет файла %s", sp2 + 1); bad = badbuf; }
                else {
                    for (int i = 0; i < 32; i++) sprintf(hx + 2 * i, "%02x", h[i]);
                    if (strncmp(hx, l, 64)) { badbuf = pm_fmt("файл %s изменён", sp2 + 1); bad = badbuf; }
                }
                free(fp);
            }
        }
        free(mt);
        jw_kbool(w, "files_ok", !bad);
        if (bad) jw_kstr(w, "files_why", bad);
        free(badbuf);
        char *prev = pm_fmt("%s/.prev/%s", pm_root(), id);
        jw_kbool(w, "prev", pm_is_dir(prev));
        free(prev);
    }
    jw_end(w);
    free(dir);
    if (md) ydoc_free(md);
}

/* Все id: state.json и каталоги, положенные руками. */
static char **all_ids(struct pm_ctx *x, size_t *n) {
    char **v = NULL;
    *n = 0;
    for (size_t i = 0; i < x->st.n; i++) {
        v = pm_realloc(v, sizeof(char *) * (*n + 1));
        v[(*n)++] = pm_strdup(x->st.v[i].id);
    }
    DIR *d = opendir(pm_root());
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.' || !id_ok(de->d_name) || pm_state_find(&x->st, de->d_name)) continue;
            char *pj = pm_fmt("%s/%s/plugin.json", pm_root(), de->d_name);
            int ok = pm_exists(pj);
            free(pj);
            if (!ok) continue;
            v = pm_realloc(v, sizeof(char *) * (*n + 1));
            v[(*n)++] = pm_strdup(de->d_name);
        }
        closedir(d);
    }
    return v;
}

static int cmd_list(struct pm_ctx *x, const char *only, int deep) {
    size_t n = 0;
    char **ids = all_ids(x, &n);
    if (only && !pm_state_find(&x->st, only)) {
        int found = 0;
        for (size_t i = 0; i < n; i++) if (!strcmp(ids[i], only)) found = 1;
        if (!found) {
            for (size_t i = 0; i < n; i++) free(ids[i]);
            free(ids);
            char *m = pm_fmt("плагин %s не установлен", only);
            int r = fail(x, m);
            free(m);
            return r;
        }
    }
    if (x->json) {
        struct jw w;
        jw_init(&w, stdout);
        jw_obj(&w);
        jw_kbool(&w, "ok", 1);
        jw_key(&w, "plugins");
        jw_arr(&w);
        for (size_t i = 0; i < n; i++) {
            if (only && strcmp(only, ids[i])) continue;
            emit_entry(x, &w, pm_state_find(&x->st, ids[i]), ids[i], deep);
        }
        jw_aend(&w);
        if (deep) {
            jw_key(&w, "auto");
            jw_obj(&w);
            jw_kstr(&w, "window", x->st.auto_window ? x->st.auto_window : "03:00-05:00");
            jw_kstr(&w, "last_check", x->st.last_check);
            jw_kstr(&w, "next", x->st.next_check);
            jw_end(&w);
            jw_key(&w, "system_ours");
            jw_arr(&w);
            for (size_t i = 0; i < x->st.nsys; i++) jw_str(&w, x->st.system_ours[i]);
            jw_aend(&w);
            int busy = pm_lock() != 0;
            if (!busy) pm_unlock();
            jw_kbool(&w, "busy", busy);
        }
        jw_end(&w);
        fputc('\n', stdout);
    } else {
        for (size_t i = 0; i < n; i++) {
            if (only && strcmp(only, ids[i])) continue;
            const struct pm_inst *p = pm_state_find(&x->st, ids[i]);
            int sec;
            const char *y;
            const char *u = update_of(x, p, &sec, &y);
            printf("%-16s %-10s %-9s %-10s%s%s%s%s\n", ids[i], p && p->version ? p->version : "?",
                   p && p->state ? p->state : "installed", p && p->repo ? p->repo : "-",
                   u ? " обновление " : "", u ? u : "", p && p->why ? " — " : "", p && p->why ? p->why : "");
        }
    }
    for (size_t i = 0; i < n; i++) free(ids[i]);
    free(ids);
    return 0;
}

static int cmd_search(struct pm_ctx *x, const char *q) {
    struct jw w;
    jw_init(&w, stdout);
    if (x->json) {
        jw_obj(&w);
        jw_kbool(&w, "ok", 1);
        jw_key(&w, "plugins");
        jw_arr(&w);
    }
    char *errs = NULL;
    for (size_t i = 0; i < x->repos.n; i++) {
        struct pm_repo *r = &x->repos.v[i];
        struct pm_err e = {{0}};
        if (pm_index_get(r, 1, &e) != 0) {
            char *t = pm_fmt("%s%s%s", errs ? errs : "", errs ? "; " : "", e.msg);
            free(errs);
            errs = t;
            continue;
        }
        const struct ynode *pls = ynode_get(r->iroot, "plugins");
        for (size_t j = 0; j < ynode_len(pls); j++) {
            const char *id = ynode_key_at(pls, j)->str;
            const struct ynode *pl = ynode_val_at(pls, j);
            const char *name = yn_str(pl, "name"), *desc = yn_str(pl, "description");
            if (q && *q && !strcasestr(id, q) && !(name && strcasestr(name, q)) && !(desc && strcasestr(desc, q))) {
                int tag = 0;
                const struct ynode *tags = ynode_get(pl, "tags");
                for (size_t k = 0; k < ynode_len(tags); k++)
                    if (yn_is_str(ynode_at(tags, k)) && strcasestr(ynode_at(tags, k)->str, q)) tag = 1;
                if (!tag) continue;
            }
            struct pm_cand c;
            struct pm_err se = {{0}};
            int ok = pm_select(x, r, id, NULL, NULL, "full", NULL, &c, &se) == 0;
            /* Самая новая версия вообще — для показа несовместимых. */
            const struct ynode *vs = ynode_get(pl, "versions"), *latest = NULL;
            for (size_t k = 0; k < ynode_len(vs); k++) {
                const struct ynode *v = ynode_at(vs, k);
                if (!latest || pm_ver_cmp(yn_str(v, "version"), yn_str(latest, "version")) > 0) latest = v;
            }
            const struct ynode *shown = ok ? c.ver : latest;
            const struct pm_inst *inst = pm_state_find(&x->st, id);
            if (!x->json) {
                printf("%-16s %-10s %-10s %s%s%s\n", id, shown ? yn_str(shown, "version") : "?", r->name,
                       name ? name : "", ok ? "" : " — ", ok ? "" : se.msg);
                continue;
            }
            jw_obj(&w);
            jw_kstr(&w, "id", id);
            jw_kstr(&w, "name", name ? name : id);
            jw_kstr(&w, "description", desc);
            jw_kstr(&w, "type", yn_str(pl, "type") ? yn_str(pl, "type") : "plugin");
            jw_knode(&w, "tags", ynode_get(pl, "tags"));
            jw_kstr(&w, "version", shown ? yn_str(shown, "version") : NULL);
            jw_kstr(&w, "latest", latest ? yn_str(latest, "version") : NULL);
            jw_kstr(&w, "repo", r->name);
            jw_kstr(&w, "trust", r->official ? "official" : "third-party");
            jw_kbool(&w, "official", r->official);
            jw_kbool(&w, "default", yn_bool(pl, "default", 0));
            jw_kbool(&w, "compatible", ok);
            jw_kstr(&w, "why", ok ? NULL : se.msg);
            jw_kbool(&w, "installed", inst != NULL);
            jw_kstr(&w, "installed_version", inst ? inst->version : NULL);
            const struct ynode *prov = shown ? ynode_get(shown, "provides") : NULL;
            jw_knode(&w, "kinds", ynode_get(prov, "kinds"));
            jw_knode(&w, "commands", ynode_get(prov, "commands"));
            jw_knode(&w, "languages", ynode_get(prov, "languages"));
            jw_knode(&w, "compat", shown ? ynode_get(shown, "compat") : NULL);
            jw_knode(&w, "requires", shown ? ynode_get(shown, "requires") : NULL);
            if (ok) {
                jw_kint(&w, "size", yn_long(c.asset, "size", 0));
                jw_kint(&w, "installed_size", yn_long(c.asset, "installed", 0));
            }
            jw_knode(&w, "changelog", shown ? ynode_get(shown, "changelog") : NULL);
            jw_kstr(&w, "homepage", yn_str(pl, "homepage"));
            jw_kstr(&w, "license", yn_str(pl, "license"));
            jw_end(&w);
        }
    }
    if (x->json) {
        jw_aend(&w);
        if (errs) jw_kstr(&w, "errors", errs);
        jw_end(&w);
        fputc('\n', stdout);
    } else if (errs) {
        fprintf(stderr, "steer plugin: %s\n", errs);
    }
    free(errs);
    return 0;
}

static int cmd_repo_list(struct pm_ctx *x) {
    if (!x->json) {
        for (size_t i = 0; i < x->repos.n; i++) {
            const struct pm_repo *r = &x->repos.v[i];
            printf("%-12s %s%s\n", r->name, r->url ? r->url : "", r->official ? " (официальный)" : "");
        }
        return 0;
    }
    struct jw w;
    jw_init(&w, stdout);
    jw_obj(&w);
    jw_kbool(&w, "ok", 1);
    jw_key(&w, "repos");
    jw_arr(&w);
    for (size_t i = 0; i < x->repos.n; i++) {
        const struct pm_repo *r = &x->repos.v[i];
        jw_obj(&w);
        jw_kstr(&w, "name", r->name);
        jw_kstr(&w, "id", r->name);
        jw_kstr(&w, "url", r->url);
        jw_key(&w, "mirrors");
        jw_arr(&w);
        for (size_t j = 0; j < r->nmirrors; j++) jw_str(&w, r->mirrors[j]);
        jw_aend(&w);
        jw_kbool(&w, "official", r->official);
        jw_kint(&w, "priority", r->priority);
        jw_kstr(&w, "key_id", r->nkeys ? r->keys[0] : NULL);
        jw_key(&w, "keys");
        jw_arr(&w);
        for (size_t j = 0; j < r->nkeys; j++) jw_str(&w, r->keys[j]);
        jw_aend(&w);
        jw_kstr(&w, "last_generated", r->last_generated);
        jw_kbool(&w, "auto_update", r->auto_update);
        jw_end(&w);
    }
    jw_aend(&w);
    jw_end(&w);
    fputc('\n', stdout);
    return 0;
}

static int name_ok(const char *s) {
    if (!s || !*s || strlen(s) > 64 || *s == '.' || *s == '-') return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' ||
              *p == '_' || *p == '.')) return 0;
    return 1;
}

static int cmd_repo_add(struct pm_ctx *x, const char *url, const char *keyid, const char *keyfile) {
    if (strncmp(url, "https://", 8) && strncmp(url, "http://", 7)) return fail(x, "адрес репозитория — https://…");
    if (strpbrk(url, " \t\r\n")) return fail(x, "в адресе репозитория недопустимые знаки");
    size_t kn = 0;
    char *kt = NULL;
    if (keyfile) kt = pm_read(keyfile, &kn);
    else {
        size_t cap = 4096;
        kt = pm_alloc(cap);
        for (;;) {
            if (kn + 1 >= cap) { cap *= 2; kt = pm_realloc(kt, cap); }
            ssize_t m = read(0, kt + kn, cap - kn - 1);
            if (m < 0 && errno == EINTR) continue;
            if (m <= 0) break;
            kn += (size_t)m;
        }
        kt[kn] = '\0';
    }
    struct sigv_key k;
    if (!kt || sigv_parse_key(kt, kn, &k) != 0) { free(kt); return fail(x, "ключ не распознан"); }
    char hex[17];
    sigv_keynum_hex(k.keynum, hex);
    if (strcasecmp(hex, keyid)) {
        char *m = pm_fmt("номер ключа %s не совпадает с ключом (%s)", keyid, hex);
        int r = fail(x, m);
        free(m); free(kt);
        return r;
    }
    if (pm_key_revoked(hex)) { free(kt); return fail(x, "этот ключ отозван"); }
    /* Индекс — по адресу, подпись — этим ключом; имя репозитория — из индекса. */
    char *iu = pm_path(url, "index.json"), *su = pm_path(url, "index.json.sig");
    char *body = NULL, *sig = NULL;
    size_t bn = 0, sn = 0;
    char why[256] = "";
    if (pm_http_mem(iu, &body, &bn, why, sizeof(why)) != 0) {
        char *m = pm_fmt("индекс %s не скачался: %s", iu, why);
        int r = fail(x, m);
        free(m); free(iu); free(su); free(kt);
        return r;
    }
    if (pm_http_mem(su, &sig, &sn, why, sizeof(why)) != 0) {
        char *m = pm_fmt("подпись индекса %s не скачалась: %s", su, why);
        int r = fail(x, m);
        free(m); free(iu); free(su); free(kt); free(body);
        return r;
    }
    free(iu); free(su);
    struct pm_keyset ks = {0};
    ks.k = &k;
    ks.n = 1;
    struct pm_err e = {{0}};
    int vr = pm_sig_check(&ks, sig, sn, body, bn, "индекс репозитория", &e);
    free(sig);
    if (vr != 0) { free(body); free(kt); return fail(x, e.msg); }
    struct ydoc *d = pm_json_parse(body, bn, "index.json", &e);
    free(body);
    if (!d) { free(kt); return fail(x, e.msg); }
    const struct ynode *root = ydoc_root(d);
    const char *name = yn_str(ynode_get(root, "repo"), "id");
    if (yn_long(root, "schema", -1) != 1) { ydoc_free(d); free(kt); return fail(x, "индекс нового формата — обновите ядро"); }
    if (!name_ok(name)) { ydoc_free(d); free(kt); return fail(x, "индекс не называет репозиторий (repo.id)"); }
    struct pm_repo *ex = pm_repo_find(&x->repos, name);
    if (ex && ex->official) {
        char *m = pm_fmt("репозиторий %s — официальный, сторонний под этим именем не подключается", name);
        int r = fail(x, m);
        free(m); ydoc_free(d); free(kt);
        return r;
    }
    if (ex && (!ex->url || strcmp(ex->url, url))) {
        char *m = pm_fmt("репозиторий %s уже подключён с адресом %s", name, ex->url ? ex->url : "");
        int r = fail(x, m);
        free(m); ydoc_free(d); free(kt);
        return r;
    }
    char *kp = pm_fmt("%s/keys/%s/%s.pub", pm_etc(), name, hex);
    if (pm_write_atomic(kp, kt, kn, 0644) != 0) { free(kp); ydoc_free(d); free(kt); return fail(x, "не записать ключ"); }
    free(kp);
    free(kt);
    struct pm_repo nr = {0};
    long prio = 100;
    for (size_t i = 0; i < x->repos.n; i++) if (x->repos.v[i].priority >= prio) prio = x->repos.v[i].priority + 10;
    nr.name = (char *)name;
    nr.url = (char *)url;
    nr.priority = ex ? ex->priority : prio;
    char *keys[1] = { hex };
    nr.keys = keys;
    nr.nkeys = 1;
    nr.auto_update = 1;
    nr.last_generated = (char *)yn_str(root, "generated");
    if (pm_repo_save(&nr, &e) != 0) { ydoc_free(d); return fail(x, e.msg); }
    if (x->json) {
        struct jw w;
        jw_init(&w, stdout);
        jw_obj(&w);
        jw_kbool(&w, "ok", 1);
        jw_kstr(&w, "name", name);
        jw_kstr(&w, "key_id", hex);
        jw_kbool(&w, "official", 0);
        jw_end(&w);
        fputc('\n', stdout);
    } else {
        printf("подключён репозиторий %s (ключ %s) — не официальный, splify2 за него не отвечает\n", name, hex);
    }
    ydoc_free(d);
    return 0;
}

static int cmd_repo_del(struct pm_ctx *x, const char *name) {
    struct pm_repo *r = pm_repo_find(&x->repos, name);
    if (!r) { char *m = pm_fmt("репозитория %s нет", name); int rc = fail(x, m); free(m); return rc; }
    if (r->official) return fail(x, "официальный репозиторий не отключается");
    if (r->file) unlink(r->file);
    char *kd = pm_fmt("%s/keys/%s", pm_etc(), name);
    pm_rmrf(kd);
    free(kd);
    char *cd = pm_path(pm_run(), name);
    pm_rmrf(cd);
    free(cd);
    if (x->json) {
        struct jw w;
        jw_init(&w, stdout);
        jw_obj(&w);
        jw_kbool(&w, "ok", 1);
        jw_kstr(&w, "name", name);
        jw_key(&w, "plugins");
        jw_arr(&w);
        for (size_t i = 0; i < x->st.n; i++)
            if (x->st.v[i].repo && !strcmp(x->st.v[i].repo, name)) jw_str(&w, x->st.v[i].id);
        jw_aend(&w);
        jw_end(&w);
        fputc('\n', stdout);
    }
    return 0;
}

/* ---- установка, обновление ---- */

static void emit_result(struct pm_ctx *x, const struct pm_result *res, const char *extra_key, char **extra, size_t ne) {
    if (!x->json) {
        for (size_t i = 0; i < res->n; i++)
            printf("%s %s %s%s%s\n", res->v[i].updated ? "обновлён" : "поставлен", res->v[i].id, res->v[i].version,
                   !strcmp(res->v[i].from, "seed") ? " (семя)" : "", "");
        return;
    }
    struct jw w;
    jw_init(&w, stdout);
    jw_obj(&w);
    jw_kbool(&w, "ok", 1);
    if (res->n) { jw_kstr(&w, "id", res->v[res->n - 1].id); jw_kstr(&w, "version", res->v[res->n - 1].version); }
    jw_key(&w, "installed");
    jw_arr(&w);
    for (size_t i = 0; i < res->n; i++) {
        jw_obj(&w);
        jw_kstr(&w, "id", res->v[i].id);
        jw_kstr(&w, "version", res->v[i].version);
        jw_kstr(&w, "from", res->v[i].from);
        jw_kstr(&w, "old", res->v[i].old);
        jw_end(&w);
    }
    jw_aend(&w);
    if (extra_key) {
        jw_key(&w, extra_key);
        jw_arr(&w);
        for (size_t i = 0; i < ne; i++) jw_str(&w, extra[i]);
        jw_aend(&w);
    }
    jw_end(&w);
    fputc('\n', stdout);
}

static int cmd_install(struct pm_ctx *x, const char *id, const char *ver, const char *file, int unsigned_ok) {
    struct pm_opts o = {0};
    struct pm_req rq = { id, ver };
    o.file = file;
    o.unsigned_ok = unsigned_ok;
    o.allow_bad = ver != NULL;
    o.allow_seed = 1;
    struct pm_result res;
    struct pm_err e = {{0}};
    int rc = pm_install(x, &rq, file ? 0 : 1, &o, &res, &e);
    if (rc != 0) { pm_result_free(&res); return fail(x, e.msg); }
    emit_result(x, &res, NULL, NULL, 0);
    pm_result_free(&res);
    return 0;
}

/* Окно установки «ЧЧ:ММ-ЧЧ:ММ» местного времени. */
static int window_parse(const char *w, int *a, int *b) {
    int h1, m1, h2, m2;
    if (!w || sscanf(w, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) != 4) return -1;
    *a = h1 * 60 + m1;
    *b = h2 * 60 + m2;
    return *a >= 0 && *a <= 1440 && *b >= 0 && *b <= 1440 ? 0 : -1;
}

static int in_window(const char *w, time_t now, time_t *next_start) {
    int a, b;
    if (window_parse(w, &a, &b) != 0) window_parse("03:00-05:00", &a, &b);
    struct tm tm;
    localtime_r(&now, &tm);
    int cur = tm.tm_hour * 60 + tm.tm_min;
    int in = a <= b ? (cur >= a && cur < b) : (cur >= a || cur < b);
    if (next_start) {
        int delta = a - cur;
        if (delta <= 0) delta += 1440;
        *next_start = now + (time_t)delta * 60 - tm.tm_sec;
    }
    return in;
}

static int cmd_update(struct pm_ctx *x, const char *id, int auto_, int if_stale) {
    time_t now = time(NULL);
    if (auto_ && if_stale && x->st.last_check) {
        time_t lc = pm_parse_time(x->st.last_check);
        if (lc >= 0 && now - lc < 24 * 3600) {
            if (x->json) puts("{\"ok\":true,\"skipped\":\"проверка была меньше суток назад\"}");
            return 0;
        }
    }
    struct pm_result all = {0};
    char **errs = NULL;
    size_t nerr = 0;
    int waiting = 0, security_now = 0;
    const char *window = x->st.auto_window ? x->st.auto_window : "03:00-05:00";
    int inwin = in_window(window, now, NULL);
    /* Порядок зависимостей: библиотеки (type library) — раньше. */
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < x->st.n; i++) {
            struct pm_inst *p = &x->st.v[i];
            if (id && strcmp(p->id, id)) continue;
            struct ydoc *m = pm_manifest(p->id);
            int lib = m && yn_str(ydoc_root(m), "type") && !strcmp(yn_str(ydoc_root(m), "type"), "library");
            if (m) ydoc_free(m);
            if ((pass == 0) != lib) continue;
            if (!p->repo || p->unsigned_) continue;
            if (!id && p->pinned) continue;
            if (auto_ && (!p->auto_update || p->pinned || (p->state && !strcmp(p->state, "failed")))) continue;
            struct pm_repo *r = pm_repo_find(&x->repos, p->repo);
            if (!r || (auto_ && !r->auto_update)) continue;
            struct pm_err e = {{0}};
            if (pm_index_get(r, 1, &e) != 0) {
                errs = pm_realloc(errs, sizeof(char *) * (nerr + 1));
                errs[nerr++] = pm_strdup(e.msg);
                continue;
            }
            int pending = p->state && !strcmp(p->state, "pending");
            int sec = 0;
            const char *yanked = NULL;
            const char *upd = update_of(x, p, &sec, &yanked);
            if (!upd && !pending) continue;
            if (auto_ && !pending && !sec && !inwin) { waiting++; continue; }
            if (sec) security_now++;
            struct pm_opts o = {0};
            o.update = 1;
            o.auto_ = auto_;
            o.allow_seed = 1;
            struct pm_req rq = { p->id, NULL };
            struct pm_result res;
            char *pid = pm_strdup(p->id);
            if (pm_install(x, &rq, 1, &o, &res, &e) != 0) {
                errs = pm_realloc(errs, sizeof(char *) * (nerr + 1));
                errs[nerr++] = pm_strdup(e.msg);
            }
            for (size_t k = 0; k < res.n; k++) {
                all.v = pm_realloc(all.v, sizeof(*all.v) * (all.n + 1));
                all.v[all.n++] = res.v[k];
            }
            free(res.v);
            res.v = NULL; res.n = 0;
            pm_result_free(&res);
            free(pid);
        }
    }
    if (id && !pm_state_find(&x->st, id)) {
        char *m = pm_fmt("плагин %s не установлен", id);
        int r = fail(x, m);
        free(m);
        pm_result_free(&all);
        return r;
    }
    if (auto_) {
        char ts[32];
        pm_time_str(now, ts, sizeof(ts));
        pm_inst_set(&x->st.last_check, ts);
        srand((unsigned)(now ^ getpid()));
        time_t next = now + 24 * 3600 + rand() % 3600;
        time_t ws;
        in_window(window, now, &ws);
        if (waiting && ws < next) next = ws + rand() % 600;
        int pend = 0;
        for (size_t i = 0; i < x->st.n; i++) if (x->st.v[i].state && !strcmp(x->st.v[i].state, "pending")) pend = 1;
        if (pend) {
            /* Повтор плагинов pending: 10 минут с удвоением до часа (migration-2.1.md, 3.4). */
            long rs = x->st.retry_s ? x->st.retry_s * 2 : 600;
            if (rs > 3600) rs = 3600;
            x->st.retry_s = rs;
            if (now + rs < next) next = now + rs;
        } else {
            x->st.retry_s = 0;
        }
        pm_time_str(next, ts, sizeof(ts));
        pm_inst_set(&x->st.next_check, ts);
        struct pm_err se;
        pm_state_save(&x->st, &se);
    }
    int rc = 0;
    if (nerr && !all.n && !auto_) {
        char *m = pm_strdup(errs[0]);
        rc = fail(x, m);
        free(m);
    } else if (x->json) {
        struct jw w;
        jw_init(&w, stdout);
        jw_obj(&w);
        jw_kbool(&w, "ok", nerr == 0);
        jw_key(&w, "updated");
        jw_arr(&w);
        for (size_t i = 0; i < all.n; i++) {
            jw_obj(&w);
            jw_kstr(&w, "id", all.v[i].id);
            jw_kstr(&w, "version", all.v[i].version);
            jw_kstr(&w, "old", all.v[i].old);
            jw_end(&w);
        }
        jw_aend(&w);
        if (auto_) { jw_kint(&w, "waiting", waiting); jw_kint(&w, "security", security_now); jw_kstr(&w, "next", x->st.next_check); }
        if (nerr) {
            jw_kstr(&w, "error", errs[0]);
            jw_key(&w, "errors");
            jw_arr(&w);
            for (size_t i = 0; i < nerr; i++) jw_str(&w, errs[i]);
            jw_aend(&w);
        }
        jw_end(&w);
        fputc('\n', stdout);
        if (nerr) rc = 1;
    } else {
        for (size_t i = 0; i < all.n; i++) printf("обновлён %s %s → %s\n", all.v[i].id, all.v[i].old ? all.v[i].old : "?", all.v[i].version);
        for (size_t i = 0; i < nerr; i++) fprintf(stderr, "steer plugin: %s\n", errs[i]);
        if (!all.n && !nerr) printf("обновлений нет\n");
        if (nerr) rc = 1;
    }
    for (size_t i = 0; i < nerr; i++) free(errs[i]);
    free(errs);
    pm_result_free(&all);
    return rc;
}

/* Один плагин: стоит — в present; нет — из сети, не вышло — из семени той же подписью
 * (migration-2.1.md, 3.3). 0 — готов; иначе причина в e. */
static int ensure_one(struct pm_ctx *x, const char *id, struct pm_result *all, char ***present, size_t *np,
                      struct pm_err *e) {
    struct pm_inst *p = pm_state_find(&x->st, id);
    char *d = pm_path(pm_root(), id);
    int here = pm_is_dir(d);
    free(d);
    if (p && here && (!p->state || strcmp(p->state, "failed"))) {
        for (size_t k = 0; k < *np; k++)
            if (!strcmp((*present)[k], id)) return 0;       /* уже учтён (сам или как зависимость) */
        *present = pm_realloc(*present, sizeof(char *) * (*np + 1));
        (*present)[(*np)++] = (char *)id;
        /* Зависимости стоящего плагина тоже должны стоять: убранную руками библиотеку возвращаем
         * из семени, а стоящие попадают в present — повторный запуск показывает весь набор. */
        struct ydoc *m = pm_manifest(id);
        const struct ynode *deps = m ? ynode_get(ynode_get(ydoc_root(m), "requires"), "plugins") : NULL;
        for (size_t k = 0; k < ynode_len(deps); k++) {
            /* имя переживает manifest: present держит указатели до конца команды (команда короткая) */
            char *dep = pm_strdup(ynode_key_at(deps, k)->str);
            if (ensure_one(x, dep, all, present, np, e) != 0) { ydoc_free(m); return -1; }
        }
        ydoc_free(m);
        return 0;
    }
    struct pm_req rq = { id, NULL };
    struct pm_opts o = {0};
    o.allow_seed = 1;
    struct pm_result res;
    int rc = pm_install(x, &rq, 1, &o, &res, e);
    if (rc != 0 && pm_seed_repo()) {
        struct pm_err se = {{0}};
        pm_result_free(&res);
        o.seed_only = 1;
        pm_progress(x, "%s из сети не встал (%s) — ставлю из семени", id, e->msg);
        rc = pm_install(x, &rq, 1, &o, &res, &se);
        if (rc != 0) {
            char *net = pm_strdup(e->msg);
            pm_errf(e, "%s; из семени: %s", net, se.msg);
            free(net);
        }
    }
    if (rc != 0) {
        pm_result_free(&res);
        return -1;
    }
    for (size_t k = 0; k < res.n; k++) {
        all->v = pm_realloc(all->v, sizeof(*all->v) * (all->n + 1));
        all->v[all->n++] = res.v[k];
    }
    free(res.v);
    return 0;
}

static int cmd_ensure(struct pm_ctx *x, char **ids, size_t n) {
    struct pm_result all = {0};
    char **present = NULL;
    size_t np = 0;
    for (size_t i = 0; i < n; i++) {
        struct pm_err e = {{0}};
        if (ensure_one(x, ids[i], &all, &present, &np, &e) != 0) {
            free(present);
            pm_result_free(&all);
            return fail(x, e.msg);
        }
    }
    emit_result(x, &all, "present", present, np);
    free(present);
    pm_result_free(&all);
    return 0;
}

/* ---- переход с пакетов модулей 2.0.x (migration-2.1.md, 3.3) ---- */

struct idset { char **v; size_t n; };
static void idset_add(struct idset *s, const char *id) {
    for (size_t i = 0; i < s->n; i++) if (!strcmp(s->v[i], id)) return;
    s->v = pm_realloc(s->v, sizeof(char *) * (s->n + 1));
    s->v[s->n++] = pm_strdup(id);
}

/* Виды из выходов спеки: `tunnel` — по протоколу (`tunnel:vless`), остальные — по имени вида. */
static void spec_kinds(const char *path, struct idset *kinds, int *have) {
    size_t n = 0;
    char *buf = pm_read(path, &n);
    if (!buf) return;
    *have = 1;
    struct err ye = {{0}};
    struct ydoc *d = ydoc_parse_buf(buf, n, path, &ye);
    if (d) {
        const struct ynode *outs = ynode_get(ydoc_root(d), "outputs");
        for (size_t i = 0; i < ynode_len(outs); i++) {
            const struct ynode *o = ynode_val_at(outs, i);
            const char *k = yn_str(o, "kind");
            if (!k) continue;
            if (!strcmp(k, "tunnel")) {
                const char *pr = yn_str(o, "protocol");
                char *kn = pm_fmt("tunnel:%s", pr ? pr : "vless");
                idset_add(kinds, kn);
                free(kn);
            } else {
                idset_add(kinds, k);
                if (ynode_get(o, "obfs")) idset_add(kinds, "obfs-key");
            }
        }
        ydoc_free(d);
    }
    free(buf);
}

/* Какой плагин даёт вид по индексу семени (provides.kinds). */
static const char *seed_plugin_for(const struct ynode *plugins, const char *kind) {
    for (size_t i = 0; i < ynode_len(plugins); i++) {
        const struct ynode *vs = ynode_get(ynode_val_at(plugins, i), "versions");
        for (size_t j = 0; j < ynode_len(vs); j++) {
            const struct ynode *ks = ynode_get(ynode_get(ynode_at(vs, j), "provides"), "kinds");
            for (size_t k = 0; k < ynode_len(ks); k++) {
                const struct ynode *c = ynode_at(ks, k);
                if (yn_is_str(c) && !strcmp(c->str, kind)) return ynode_key_at(plugins, i)->str;
            }
        }
    }
    return NULL;
}

/* Обновление стоящих плагинов из семени (переход на новое ядро): плагин, поставленный из официального
 * репозитория семени, получает версию семени, если она выше стоящей и подходит этому ядру (compat). Так
 * библиотека net1 1.2.0 доходит до 1.3.0, а плагин, чей steer-api новое ядро не принимает, — до версии,
 * которая принимает. Плагины из файла, из чужих репозиториев и более новые, чем в семени, не трогаются. */
static void migrate_refresh(struct pm_ctx *x, struct pm_result *all, struct idset *bad, size_t *nfail) {
    struct pm_repo *sr = pm_seed_repo();
    if (!sr) return;
    struct pm_err e = {{0}};
    if (pm_index_get(sr, 0, &e) != 0) goto out;
    const char *rid = yn_str(ynode_get(sr->iroot, "repo"), "id");
    if (!rid) goto out;
    /* Набор для обновления: все, у кого в семени версия выше. Ставятся ОДНОЙ группой (зависимости и
     * зависимые вместе — новый warpbox без нового net1 не встаёт, и наоборот): одна проверка здоровья
     * на группу, не прошла — откат всей группы. */
    struct idset ids = {0};
    for (size_t i = 0; i < x->st.n; i++) {
        struct pm_inst *p = &x->st.v[i];
        if (!p->version || !p->repo || p->unsigned_ || strcmp(p->repo, rid)) continue;
        if (!pm_index_plugin(sr, p->id)) continue;
        struct pm_cand c;
        struct pm_err se = {{0}};
        if (pm_select(x, sr, p->id, NULL, NULL, p->variant ? p->variant : "full", NULL, &c, &se) != 0) continue;
        if (pm_ver_cmp(c.version, p->version) <= 0) continue;
        idset_add(&ids, p->id);
    }
    if (ids.n) {
        struct pm_req *rq = pm_alloc(sizeof(*rq) * ids.n);
        for (size_t i = 0; i < ids.n; i++) { rq[i].id = ids.v[i]; rq[i].version = NULL; }
        struct pm_opts o = {0};
        o.seed_only = 1;
        o.group = 1;
        struct pm_result res;
        struct pm_err ie = {{0}};
        if (pm_install(x, rq, ids.n, &o, &res, &ie) != 0) {
            char *m = pm_fmt("обновление из семени: %s", ie.msg);
            idset_add(bad, m);
            free(m);
            (*nfail)++;
        }
        for (size_t k = 0; k < res.n; k++) {
            all->v = pm_realloc(all->v, sizeof(*all->v) * (all->n + 1));
            all->v[all->n++] = res.v[k];
        }
        free(res.v);
        res.v = NULL; res.n = 0;
        pm_result_free(&res);
        free(rq);
    }
out:
    free(sr->name); free(sr->url);
    if (sr->idx) ydoc_free(sr->idx);
    free(sr);
}

/* `steer plugin migrate`: плагины, которых требует спека человека, и те, что стояли пакетами
 * (migrate.json, его пишет pre-upgrade/preinst steer-core 2.1); при первой установке — все `default: true`
 * индекса семени. Работает без демона; неудача одного плагина остальные не останавливает. */
static int cmd_migrate(struct pm_ctx *x) {
    struct pm_err e = {{0}};
    struct idset kinds = {0}, want = {0};
    int have_spec = 0;
    const char *sp = getenv("STEER_SPEC");
    if (sp) spec_kinds(sp, &kinds, &have_spec);
    else {
        spec_kinds("/etc/steer/spec.yaml", &kinds, &have_spec);
        spec_kinds("/etc/steer/spec.json", &kinds, &have_spec);
    }
    char *mj = pm_path(pm_etc(), "migrate.json");
    int have_mj = 0;
    struct ydoc *md = pm_json_load(mj, &e);
    if (md) {
        have_mj = 1;
        const struct ynode *pk = ynode_get(ydoc_root(md), "packages");
        for (size_t i = 0; i < ynode_len(pk); i++) {
            const struct ynode *c = ynode_at(pk, i);
            if (!yn_is_str(c) || strncmp(c->str, "steer-", 6)) continue;
            const char *m = c->str + 6;
            if (!strcmp(m, "extended")) { idset_add(&want, "vless"); idset_add(&want, "xsteer"); idset_add(&want, "obfs"); }
            else if (strcmp(m, "tgws") && strcmp(m, "core") && strcmp(m, "box-connector")) idset_add(&want, m);
        }
        ydoc_free(md);
    }
    char *ip = pm_path(pm_seed(), "index.json");
    struct ydoc *idx = pm_json_load(ip, &e);
    free(ip);
    const struct ynode *plugins = idx ? ynode_get(ydoc_root(idx), "plugins") : NULL;
    if (!plugins) {
        free(mj);
        return fail(x, "в семени нет индекса: нечего ставить");
    }
    for (size_t i = 0; i < kinds.n; i++) {
        const char *id = seed_plugin_for(plugins, kinds.v[i]);
        /* Виды без записи в provides.kinds: warp ведёт warpbox (он тянет awg), obfs у interface — ключ. */
        if (!id && !strcmp(kinds.v[i], "warp")) id = "warpbox";
        if (!id && !strcmp(kinds.v[i], "awg")) id = "awg";
        if (!id && !strcmp(kinds.v[i], "obfs-key")) id = "obfs";
        if (id) idset_add(&want, id);
    }
    if (!have_spec && !have_mj)
        for (size_t i = 0; i < ynode_len(plugins); i++)
            if (yn_bool(ynode_val_at(plugins, i), "default", 0)) idset_add(&want, ynode_key_at(plugins, i)->str);
    /* Только то, что есть в индексе семени (tgws и прочие пакеты — не наши). */
    struct pm_result all = {0};
    char **present = NULL;
    size_t np = 0, nfail = 0;
    struct idset bad = {0};
    for (size_t i = 0; i < want.n; i++) {
        if (!ynode_get(plugins, want.v[i])) continue;
        struct pm_err ee = {{0}};
        if (ensure_one(x, want.v[i], &all, &present, &np, &ee) != 0) {
            char *m = pm_fmt("%s: %s", want.v[i], ee.msg);
            idset_add(&bad, m);
            free(m);
            nfail++;
        }
    }
    migrate_refresh(x, &all, &bad, &nfail);
    if (!x->json) {
        emit_result(x, &all, NULL, NULL, 0);
        for (size_t i = 0; i < bad.n; i++) fprintf(stderr, "не удалось: %s\n", bad.v[i]);
    } else {
        emit_result(x, &all, "present", present, np);
    }
    if (have_mj && !nfail) {
        char *dn = pm_path(pm_etc(), "migrate.done.json");
        rename(mj, dn);
        free(dn);
    }
    free(mj);
    free(present);
    pm_result_free(&all);
    ydoc_free(idx);
    return nfail ? 1 : 0;
}

/* ---- задания ---- */

static char *jobs_dir(void) { return pm_path(pm_run(), "jobs"); }

static void jobs_sweep(void) {
    char *jd = jobs_dir();
    DIR *d = opendir(jd);
    if (d) {
        struct dirent *de;
        time_t now = time(NULL);
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            char *p = pm_path(jd, de->d_name);
            struct stat st;
            if (stat(p, &st) == 0 && now - st.st_mtime > 3600) pm_rmrf(p);
            free(p);
        }
        closedir(d);
    }
    free(jd);
}

/* Отдать работу ребёнку: родитель печатает {"ok":true,"job":…} и выходит, ребёнок продолжает с
 * выводом в файлы задания. 1 — мы ребёнок (продолжать); 0 — мы родитель (выйти с кодом *rc). */
static int job_fork(struct pm_ctx *x, int *rc) {
    jobs_sweep();
    char id[64];
    snprintf(id, sizeof(id), "%ld-%d", (long)time(NULL), (int)getpid());
    char *jd = jobs_dir();
    char *dir = pm_path(jd, id);
    free(jd);
    if (pm_mkdirs(dir) != 0) { free(dir); *rc = fail(x, "не завести задание"); return 0; }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) { free(dir); *rc = fail(x, "не завести задание"); return 0; }
    if (pid > 0) {
        printf(x->json ? "{\"ok\":true,\"job\":\"%s\"}\n" : "задание %s\n", id);
        free(dir);
        *rc = 0;
        return 0;
    }
    setsid();
    char *out = pm_path(dir, "out"), *log = pm_path(dir, "log"), *pidf = pm_path(dir, "pid");
    int fo = open(out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    int fl = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fo >= 0) { dup2(fo, 1); close(fo); }
    if (fl >= 0) { dup2(fl, 2); close(fl); }
    int nul = open("/dev/null", O_RDONLY);
    if (nul >= 0) { dup2(nul, 0); close(nul); }
    char pb[32];
    int n = snprintf(pb, sizeof(pb), "%d\n", (int)getpid());
    pm_write_atomic(pidf, pb, (size_t)n, 0644);
    g_job_log = log;
    x->json = 1;
    free(out); free(pidf);
    setenv("STEER_PLUGIN_JOB_DIR", dir, 1);
    free(dir);
    return 1;
}

static void job_finish(int rc) {
    const char *dir = getenv("STEER_PLUGIN_JOB_DIR");
    if (!dir) return;
    fflush(stdout);
    fflush(stderr);
    char *p = pm_path(dir, "rc");
    char b[16];
    int n = snprintf(b, sizeof(b), "%d\n", rc);
    pm_write_atomic(p, b, (size_t)n, 0644);
    free(p);
}

static int cmd_job(struct pm_ctx *x, const char *id) {
    if (!id || strchr(id, '/') || id[0] == '.') return fail(x, "такого задания нет");
    char *jd = jobs_dir();
    char *dir = pm_path(jd, id);
    free(jd);
    if (!pm_is_dir(dir)) { free(dir); return fail(x, "такого задания нет"); }
    char *rcp = pm_path(dir, "rc"), *outp = pm_path(dir, "out"), *logp = pm_path(dir, "log"), *pidp = pm_path(dir, "pid");
    char *rcs = pm_read(rcp, NULL), *out = pm_read(outp, NULL), *log = pm_read(logp, NULL), *pids = pm_read(pidp, NULL);
    /* Последняя строка хода. */
    char *progress = NULL;
    if (log) {
        size_t l = strlen(log);
        while (l && log[l - 1] == '\n') log[--l] = '\0';
        char *nl = strrchr(log, '\n');
        progress = nl ? nl + 1 : log;
        if (!strncmp(progress, "steer plugin: ", 14)) progress += 14;
    }
    const char *state;
    int alive = pids && kill(atoi(pids), 0) == 0;
    if (rcs) state = atoi(rcs) == 0 ? "done" : "failed";
    else state = alive ? "running" : "failed";
    struct jw w;
    jw_init(&w, stdout);
    jw_obj(&w);
    jw_kbool(&w, "ok", strcmp(state, "failed") != 0);
    jw_kstr(&w, "id", id);
    jw_kstr(&w, "state", state);
    if (!strcmp(state, "running")) { if (progress && *progress) jw_kstr(&w, "progress", progress); }
    else {
        struct pm_err e;
        struct ydoc *d = out && *out ? pm_json_parse(out, strlen(out), "out", &e) : NULL;
        if (!strcmp(state, "failed")) {
            const char *er = d ? yn_str(ydoc_root(d), "error") : NULL;
            jw_kstr(&w, "error", er ? er : rcs ? (progress && *progress ? progress : "задание не удалось") : "задание оборвано");
            jw_kstr(&w, "code", "failed");
        }
        if (d) { jw_knode(&w, "result", ydoc_root(d)); ydoc_free(d); }
    }
    jw_end(&w);
    fputc('\n', stdout);
    free(rcp); free(outp); free(logp); free(pidp); free(rcs); free(out); free(log); free(pids); free(dir);
    (void)x;
    return 0;
}

/* ---- главная ---- */

int pm_main(int argc, char **argv) {
    struct pm_ctx x;
    memset(&x, 0, sizeof(x));
    x.by = "human";
    const char *pos[16];
    size_t npos = 0;
    char **ens = NULL;
    size_t nens = 0;
    const char *file = NULL, *keyfile = NULL;
    int force = 0, purge = 0, unsigned_ok = 0, auto_ = 0, if_stale = 0, job = 0;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--json")) x.json = 1;
        else if (!strcmp(a, "--force")) force = 1;
        else if (!strcmp(a, "--purge")) purge = 1;
        else if (!strcmp(a, "--unsigned")) unsigned_ok = 1;
        else if (!strcmp(a, "--auto")) auto_ = 1;
        else if (!strcmp(a, "--if-stale")) if_stale = 1;
        else if (!strcmp(a, "--job")) job = 1;
        else if (!strcmp(a, "--file") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(a, "--key-file") && i + 1 < argc) keyfile = argv[++i];
        else if (!strcmp(a, "--by") && i + 1 < argc) x.by = argv[++i];
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) return usage();
        else if (a[0] == '-' && a[1]) { fprintf(stderr, "steer plugin: неизвестный флаг %s\n", a); return usage(); }
        else {
            if (npos < sizeof(pos) / sizeof(pos[0])) pos[npos++] = a;
            ens = pm_realloc(ens, sizeof(char *) * (nens + 1));
            ens[nens++] = (char *)a;
        }
    }
    if (!npos) { free(ens); return usage(); }
    const char *act = pos[0];
    if (auto_) x.by = "auto";
    int rc = 2;
    struct pm_err e = {{0}};
    if (pm_state_load(&x.st, &e) != 0 || pm_repos_load(&x.repos, &e) != 0) { rc = fail(&x, e.msg); goto out; }
    pm_target_load(&x.tg);
    if (!x.tg.arch) x.tg.arch = pm_strdup("");
    /* Только чтение — без блокировки. */
    if (!strcmp(act, "list") && npos == 1) { rc = cmd_list(&x, NULL, 0); goto out; }
    if (!strcmp(act, "status") && npos <= 2) {
        if (npos == 2 && !id_ok(pos[1])) { rc = fail(&x, "недопустимое имя плагина"); goto out; }
        rc = cmd_list(&x, npos == 2 ? pos[1] : NULL, 1);
        goto out;
    }
    if (!strcmp(act, "search") && npos <= 2) { rc = cmd_search(&x, npos == 2 ? pos[1] : NULL); goto out; }
    if (!strcmp(act, "repo") && npos == 2 && !strcmp(pos[1], "list")) { rc = cmd_repo_list(&x); goto out; }
    if (!strcmp(act, "job") && npos == 2) { rc = cmd_job(&x, pos[1]); goto out; }

    /* Изменяющие — под блокировкой. */
    int known = (!strcmp(act, "install") && (file ? npos == 1 : (npos == 2 || npos == 3))) ||
                (!strcmp(act, "update") && npos <= 2) ||
                (!strcmp(act, "remove") && npos == 2) ||
                ((!strcmp(act, "enable") || !strcmp(act, "disable")) && npos == 2) ||
                (!strcmp(act, "autoupdate") && npos == 3) ||
                (!strcmp(act, "repo") && npos >= 2 && ((!strcmp(pos[1], "add") && npos == 4) || (!strcmp(pos[1], "del") && npos == 3))) ||
                (!strcmp(act, "ensure") && npos >= 2) || (!strcmp(act, "migrate") && npos == 1);
    if (!known) { rc = usage(); goto out; }
    if (!(!strcmp(act, "repo"))) {
        for (size_t i = 1; i < npos; i++) {
            if (!strcmp(act, "install") && i == 2) { if (!pm_ver_ok(pos[i])) { rc = fail(&x, "недопустимая версия"); goto out; } continue; }
            if (!strcmp(act, "autoupdate") && i == 2) continue;
            if (!id_ok(pos[i])) { rc = fail(&x, "недопустимое имя плагина"); goto out; }
        }
    }
    if (pm_lock() != 0) { rc = fail(&x, "busy: менеджер плагинов занят другим запросом — повторите позже"); goto out; }
    /* Состояние — заново под блокировкой: прочитанное до неё могло устареть. */
    pm_state_free(&x.st);
    if (pm_state_load(&x.st, &e) != 0) { rc = fail(&x, e.msg); goto out; }
    if (job && (!strcmp(act, "install") || !strcmp(act, "update") || !strcmp(act, "ensure"))) {
        int prc = 0;
        if (!job_fork(&x, &prc)) { rc = prc; goto out_nojob; }
    }
    if (!strcmp(act, "install")) rc = cmd_install(&x, file ? NULL : pos[1], npos == 3 ? pos[2] : NULL, file, unsigned_ok);
    else if (!strcmp(act, "update")) rc = cmd_update(&x, npos == 2 ? pos[1] : NULL, auto_, if_stale);
    else if (!strcmp(act, "ensure")) rc = cmd_ensure(&x, ens + 1, nens - 1);
    else if (!strcmp(act, "migrate")) rc = cmd_migrate(&x);
    else if (!strcmp(act, "remove")) {
        rc = pm_remove(&x, pos[1], force, purge, &e) == 0 ? 0 : fail(&x, e.msg);
        if (!rc && x.json) printf("{\"ok\":true,\"id\":\"%s\"}\n", pos[1]);
    } else if (!strcmp(act, "enable") || !strcmp(act, "disable")) {
        rc = pm_set_enabled(&x, pos[1], !strcmp(act, "enable"), &e) == 0 ? 0 : fail(&x, e.msg);
        if (!rc && x.json) printf("{\"ok\":true,\"id\":\"%s\"}\n", pos[1]);
    } else if (!strcmp(act, "autoupdate")) {
        struct pm_inst *p = pm_state_find(&x.st, pos[1]);
        int on = !strcmp(pos[2], "on");
        if (!on && strcmp(pos[2], "off")) rc = fail(&x, "нужно on или off");
        else if (!p) { char *m = pm_fmt("плагин %s не установлен", pos[1]); rc = fail(&x, m); free(m); }
        else if (on && p->unsigned_) rc = fail(&x, "у плагина без подписи автообновления нет");
        else {
            p->auto_update = on;
            rc = pm_state_save(&x.st, &e) == 0 ? 0 : fail(&x, e.msg);
            if (!rc && x.json) printf("{\"ok\":true,\"id\":\"%s\",\"auto_update\":%s}\n", pos[1], on ? "true" : "false");
        }
    } else if (!strcmp(act, "repo")) {
        if (!strcmp(pos[1], "add")) {
            if (strlen(pos[3]) != 16 || strspn(pos[3], "0123456789abcdefABCDEF") != 16) rc = fail(&x, "номер ключа — 16 знаков hex");
            else rc = cmd_repo_add(&x, pos[2], pos[3], keyfile);
        } else {
            if (!name_ok(pos[2])) rc = fail(&x, "недопустимое имя репозитория");
            else rc = cmd_repo_del(&x, pos[2]);
        }
    }
    job_finish(rc);
out_nojob:
    pm_unlock();
out:
    fflush(stdout);
    pm_state_free(&x.st);
    pm_repos_free(&x.repos);
    free(x.tg.core); free(x.tg.api); free(x.tg.abi); free(x.tg.host); free(x.tg.splify2); free(x.tg.arch);
    free(ens);
    (void)g_job_log;
    return rc;
}
