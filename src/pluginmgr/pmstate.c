/* Менеджер плагинов: state.json, репозитории (repos.d), ключи по ролям (s2p.md, «Раскладка»,
 * «Ключи и ротация»; index.md, «Репозитории на роутере»). */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pm.h"

/* ---- state.json ---- */

void pm_inst_set(char **field, const char *v) {
    free(*field);
    *field = pm_strdup(v);
}

static char **str_list(const struct ynode *seq, size_t *n) {
    *n = 0;
    if (!seq || seq->kind != YN_SEQ) return NULL;
    char **v = pm_alloc(sizeof(*v) * (seq->len + 1));
    for (size_t i = 0; i < seq->len; i++)
        if (yn_is_str(seq->items[i])) v[(*n)++] = pm_strdup(seq->items[i]->str);
    return v;
}

static void free_list(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

static char *state_path(void) { return pm_path(pm_etc(), "state.json"); }

int pm_state_load(struct pm_state *s, struct pm_err *e) {
    memset(s, 0, sizeof(*s));
    s->retry_s = 0;
    char *p = state_path();
    struct pm_err le = {0};
    struct ydoc *d = pm_json_load(p, &le);
    if (!d) {
        if (le.msg[0]) { pm_errc(e, "plugin.file_unreadable", PMA("path", p, "why", le.msg), "%s не читается: %s", p, le.msg); free(p); return -1; }
        free(p);
        return 0;
    }
    free(p);
    const struct ynode *r = ydoc_root(d);
    const struct ynode *pl = ynode_get(r, "plugins");
    for (size_t i = 0; i < ynode_len(pl); i++) {
        const struct ynode *k = ynode_key_at(pl, i), *v = ynode_val_at(pl, i);
        struct pm_inst *x = pm_state_add(s, k->str);
        pm_inst_set(&x->repo, yn_str(v, "repo"));
        pm_inst_set(&x->version, yn_str(v, "version"));
        pm_inst_set(&x->arch, yn_str(v, "arch"));
        pm_inst_set(&x->variant, yn_str(v, "variant"));
        pm_inst_set(&x->state, yn_str(v, "state"));
        pm_inst_set(&x->why, yn_str(v, "why"));
        x->auto_update = yn_bool(v, "auto_update", 1);
        pm_inst_set(&x->pinned, yn_str(v, "pinned"));
        const struct ynode *bad = ynode_get(v, "bad_versions");
        for (size_t j = 0; j < ynode_len(bad); j++)
            pm_bad_set(x, ynode_key_at(bad, j)->str, yn_is_str(ynode_val_at(bad, j)) ? ynode_val_at(bad, j)->str : "");
        free_list(x->system, x->nsystem);
        x->system = str_list(ynode_get(v, "system"), &x->nsystem);
        pm_inst_set(&x->installed_at, yn_str(v, "installed_at"));
        pm_inst_set(&x->from, yn_str(v, "from"));
        x->unsigned_ = yn_bool(v, "unsigned", 0);
        x->disabled_by_human = x->state && !strcmp(x->state, "disabled");
    }
    s->system_ours = str_list(ynode_get(r, "system_ours"), &s->nsys);
    s->auto_window = pm_strdup(yn_str(r, "auto_window"));
    const struct ynode *au = ynode_get(r, "auto");
    s->last_check = pm_strdup(yn_str(au, "last_check"));
    s->next_check = pm_strdup(yn_str(au, "next"));
    s->retry_s = yn_long(au, "retry_s", 0);
    ydoc_free(d);
    return 0;
}

int pm_state_save(const struct pm_state *s, struct pm_err *e) {
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return pm_errc(e, "plugin.no_memory", NULL, "нет памяти");
    struct jw w;
    jw_init(&w, f);
    jw_obj(&w);
    jw_kint(&w, "schema", 1);
    jw_key(&w, "plugins");
    jw_obj(&w);
    for (size_t i = 0; i < s->n; i++) {
        const struct pm_inst *x = &s->v[i];
        jw_key(&w, x->id);
        jw_obj(&w);
        jw_kstr(&w, "repo", x->repo);
        jw_kstr(&w, "version", x->version);
        jw_kstr(&w, "arch", x->arch);
        if (x->variant && strcmp(x->variant, "full")) jw_kstr(&w, "variant", x->variant);
        jw_kbool(&w, "enabled", x->state && !strcmp(x->state, "enabled"));
        jw_kstr(&w, "state", x->state);
        jw_kstr(&w, "why", x->why);
        jw_kbool(&w, "auto_update", x->auto_update);
        jw_kstr(&w, "pinned", x->pinned);
        jw_key(&w, "bad_versions");
        jw_obj(&w);
        for (size_t j = 0; j < x->nbad; j++) jw_kstr(&w, x->bad[j].ver, x->bad[j].why);
        jw_end(&w);
        jw_key(&w, "system");
        jw_arr(&w);
        for (size_t j = 0; j < x->nsystem; j++) jw_str(&w, x->system[j]);
        jw_aend(&w);
        jw_kstr(&w, "installed_at", x->installed_at);
        jw_kstr(&w, "from", x->from);
        if (x->unsigned_) jw_kbool(&w, "unsigned", 1);
        jw_end(&w);
    }
    jw_end(&w);
    jw_key(&w, "system_ours");
    jw_arr(&w);
    for (size_t j = 0; j < s->nsys; j++) jw_str(&w, s->system_ours[j]);
    jw_aend(&w);
    if (s->auto_window) jw_kstr(&w, "auto_window", s->auto_window);
    if (s->last_check || s->next_check || s->retry_s) {
        jw_key(&w, "auto");
        jw_obj(&w);
        if (s->last_check) jw_kstr(&w, "last_check", s->last_check);
        if (s->next_check) jw_kstr(&w, "next", s->next_check);
        if (s->retry_s) jw_kint(&w, "retry_s", s->retry_s);
        jw_end(&w);
    }
    jw_end(&w);
    fputc('\n', f);
    if (fclose(f) != 0) { free(buf); return pm_errc(e, "plugin.no_memory", NULL, "нет памяти"); }
    char *p = state_path();
    int r = pm_write_atomic(p, buf, n, 0644);
    free(buf);
    if (r != 0) { pm_errc(e, "plugin.write_failed", PMA("path", p), "не записать %s", p); free(p); return -1; }
    free(p);
    return 0;
}

static void inst_free(struct pm_inst *x) {
    free(x->id); free(x->repo); free(x->version); free(x->arch); free(x->variant);
    free(x->state); free(x->why); free(x->pinned); free(x->installed_at); free(x->from);
    for (size_t j = 0; j < x->nbad; j++) { free(x->bad[j].ver); free(x->bad[j].why); }
    free(x->bad);
    free_list(x->system, x->nsystem);
}

void pm_state_free(struct pm_state *s) {
    for (size_t i = 0; i < s->n; i++) inst_free(&s->v[i]);
    free(s->v);
    free(s->hx);
    free_list(s->system_ours, s->nsys);
    free(s->auto_window); free(s->last_check); free(s->next_check);
    memset(s, 0, sizeof(*s));
}

static size_t id_hash(const char *s) {
    size_t h = (size_t)1469598103934665603ULL;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * (size_t)1099511628211ULL;
    return h;
}

/* Ячейка хеша для id: занятая им или первая пустая. */
static size_t *hx_slot(const struct pm_state *s, const char *id) {
    for (size_t i = id_hash(id) & (s->hcap - 1);; i = (i + 1) & (s->hcap - 1))
        if (!s->hx[i] || !strcmp(s->v[s->hx[i] - 1].id, id)) return &s->hx[i];
}

/* Перестроить хеш под n записей (после роста и удаления — индексы сдвигаются). */
static void hx_rebuild(struct pm_state *s) {
    size_t want = 16;
    while (want < 2 * (s->n + 1)) want *= 2;
    if (want != s->hcap) {
        free(s->hx);
        s->hx = pm_alloc(sizeof(*s->hx) * want);
        s->hcap = want;
    }
    memset(s->hx, 0, sizeof(*s->hx) * s->hcap);
    for (size_t i = 0; i < s->n; i++) *hx_slot(s, s->v[i].id) = i + 1;
}

struct pm_inst *pm_state_find(struct pm_state *s, const char *id) {
    if (!s->n || !id) return NULL;
    size_t k = *hx_slot(s, id);
    return k ? &s->v[k - 1] : NULL;
}

struct pm_inst *pm_state_add(struct pm_state *s, const char *id) {
    struct pm_inst *x = pm_state_find(s, id);
    if (x) return x;
    if (s->n == s->cap) {
        s->cap = s->cap ? 2 * s->cap : 8;
        s->v = pm_realloc(s->v, sizeof(*s->v) * s->cap);
    }
    x = &s->v[s->n++];
    memset(x, 0, sizeof(*x));
    x->id = pm_strdup(id);
    x->auto_update = 1;
    if (2 * (s->n + 1) > s->hcap) hx_rebuild(s);
    else *hx_slot(s, id) = s->n;
    return x;
}

void pm_state_del(struct pm_state *s, const char *id) {
    struct pm_inst *x = pm_state_find(s, id);
    if (!x) return;
    size_t i = (size_t)(x - s->v);
    inst_free(x);
    memmove(&s->v[i], &s->v[i + 1], sizeof(*s->v) * (s->n - i - 1));
    s->n--;
    hx_rebuild(s);
}

const char *pm_bad_why(const struct pm_inst *p, const char *ver) {
    if (!p || !ver) return NULL;
    for (size_t j = 0; j < p->nbad; j++)
        if (!strcmp(p->bad[j].ver, ver)) return p->bad[j].why;
    return NULL;
}

void pm_bad_set(struct pm_inst *p, const char *ver, const char *why) {
    for (size_t j = 0; j < p->nbad; j++)
        if (!strcmp(p->bad[j].ver, ver)) { pm_inst_set(&p->bad[j].why, why); return; }
    p->bad = pm_realloc(p->bad, sizeof(*p->bad) * (p->nbad + 1));
    p->bad[p->nbad].ver = pm_strdup(ver);
    p->bad[p->nbad].why = pm_strdup(why);
    p->nbad++;
}

/* Пометки «не прошла проверку здоровья» с ошибкой перечитывания плагинов ядром снимаются: прежнее
 * поведение метило версию и тогда, когда ошибка была и до установки (спека сломана чем-то другим), и
 * версия застревала. Зовётся при переходе на новое ядро (migrate). Возвращает, сколько снято. */
size_t pm_bad_clear_reload(struct pm_state *s) {
    size_t gone = 0;
    for (size_t i = 0; i < s->n; i++) {
        struct pm_inst *p = &s->v[i];
        size_t k = 0;
        for (size_t j = 0; j < p->nbad; j++) {
            if (p->bad[j].why && strstr(p->bad[j].why, "ядро не перечитало плагины")) {
                free(p->bad[j].ver); free(p->bad[j].why);
                gone++;
                continue;
            }
            p->bad[k++] = p->bad[j];
        }
        p->nbad = k;
    }
    return gone;
}

void pm_sys_ours_add(struct pm_state *s, const char *pkg) {
    for (size_t j = 0; j < s->nsys; j++)
        if (!strcmp(s->system_ours[j], pkg)) return;
    s->system_ours = pm_realloc(s->system_ours, sizeof(char *) * (s->nsys + 1));
    s->system_ours[s->nsys++] = pm_strdup(pkg);
}

/* ---- repos.d ---- */

static void repo_free(struct pm_repo *r) {
    free(r->name); free(r->url); free(r->file); free(r->last_generated); free(r->idx_err); free(r->idx_miss);
    free_list(r->mirrors, r->nmirrors);
    free_list(r->keys, r->nkeys);
    if (r->idx) ydoc_free(r->idx);
}

static int repo_cmp(const void *a, const void *b) {
    const struct pm_repo *x = a, *y = b;
    if (x->priority != y->priority) return x->priority < y->priority ? -1 : 1;
    return strcmp(x->name, y->name);
}

int pm_repos_load(struct pm_repos *rs, struct pm_err *e) {
    memset(rs, 0, sizeof(*rs));
    char *dir = pm_path(pm_etc(), "repos.d");
    DIR *d = opendir(dir);
    if (!d) { free(dir); return 0; }
    struct dirent *de;
    while ((de = readdir(d))) {
        size_t l = strlen(de->d_name);
        if (de->d_name[0] == '.' || l < 6 || strcmp(de->d_name + l - 5, ".json")) continue;
        char *p = pm_path(dir, de->d_name);
        struct pm_err le = {0};
        struct ydoc *doc = pm_json_load(p, &le);
        if (!doc) {
            closedir(d);
            pm_errc(e, "plugin.repo_unreadable", PMA("path", p, "why", le.msg), "репозиторий %s не читается: %s", p, le.msg);
            free(p); free(dir);
            return -1;
        }
        const struct ynode *r = ydoc_root(doc);
        rs->v = pm_realloc(rs->v, sizeof(*rs->v) * (rs->n + 1));
        struct pm_repo *x = &rs->v[rs->n++];
        memset(x, 0, sizeof(*x));
        const char *id = yn_str(r, "id");
        x->name = id ? pm_strdup(id) : pm_fmt("%.*s", (int)(l - 5), de->d_name);
        x->url = pm_strdup(yn_str(r, "url"));
        x->file = p;
        x->mirrors = str_list(ynode_get(r, "mirrors"), &x->nmirrors);
        x->keys = str_list(ynode_get(r, "keys"), &x->nkeys);
        x->official = yn_bool(r, "official", 0);
        x->priority = yn_long(r, "priority", x->official ? 0 : 100);
        x->auto_update = yn_bool(r, "auto_update", 1);
        x->last_generated = pm_strdup(yn_str(r, "last_generated"));
        ydoc_free(doc);
    }
    closedir(d);
    free(dir);
    if (rs->n > 1) qsort(rs->v, rs->n, sizeof(*rs->v), repo_cmp);
    return 0;
}

void pm_repos_free(struct pm_repos *rs) {
    for (size_t i = 0; i < rs->n; i++) repo_free(&rs->v[i]);
    free(rs->v);
    memset(rs, 0, sizeof(*rs));
}

struct pm_repo *pm_repo_find(struct pm_repos *rs, const char *name) {
    for (size_t i = 0; i < rs->n; i++)
        if (!strcmp(rs->v[i].name, name)) return &rs->v[i];
    return NULL;
}

int pm_repo_save(const struct pm_repo *x, struct pm_err *e) {
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return pm_errc(e, "plugin.no_memory", NULL, "нет памяти");
    struct jw w;
    jw_init(&w, f);
    jw_obj(&w);
    jw_kstr(&w, "id", x->name);
    jw_kstr(&w, "url", x->url);
    jw_key(&w, "mirrors");
    jw_arr(&w);
    for (size_t i = 0; i < x->nmirrors; i++) jw_str(&w, x->mirrors[i]);
    jw_aend(&w);
    jw_kbool(&w, "official", x->official);
    jw_kint(&w, "priority", x->priority);
    jw_key(&w, "keys");
    jw_arr(&w);
    for (size_t i = 0; i < x->nkeys; i++) jw_str(&w, x->keys[i]);
    jw_aend(&w);
    jw_kstr(&w, "last_generated", x->last_generated);
    jw_kbool(&w, "auto_update", x->auto_update);
    jw_end(&w);
    fputc('\n', f);
    fclose(f);
    char *p = x->file ? pm_strdup(x->file) : pm_fmt("%s/repos.d/%s.json", pm_etc(), x->name);
    int r = pm_write_atomic(p, buf, n, 0644);
    free(buf);
    if (r != 0) { pm_errc(e, "plugin.write_failed", PMA("path", p), "не записать %s", p); free(p); return -1; }
    free(p);
    return 0;
}

struct pm_repo *pm_seed_repo(void) {
    char *ip = pm_path(pm_seed(), "index.json");
    int have = pm_exists(ip);
    free(ip);
    if (!have) return NULL;
    struct pm_repo *r = pm_alloc(sizeof(*r));
    r->seed = 1;
    r->official = 1;
    r->url = pm_strdup(pm_seed());
    r->name = pm_strdup("seed");
    return r;
}

/* ---- ключи ---- */

static int keys_revoked_load(struct pm_keyset *ks) {
    char *p = pm_path(pm_keys(), "revoked");
    char *b = pm_read(p, NULL);
    free(p);
    if (!b) return 0;
    for (char *s = strtok(b, " \t\r\n"); s; s = strtok(NULL, " \t\r\n")) {
        if (*s == '#') continue;
        ks->revoked = pm_realloc(ks->revoked, sizeof(char *) * (ks->nrev + 1));
        ks->revoked[ks->nrev++] = pm_strdup(s);
    }
    free(b);
    return 0;
}

int pm_key_revoked(const char *hex) {
    struct pm_keyset ks = {0};
    keys_revoked_load(&ks);
    int r = 0;
    for (size_t i = 0; i < ks.nrev; i++)
        if (!strcasecmp(ks.revoked[i], hex)) r = 1;
    pm_keys_free(&ks);
    return r;
}

static int is_revoked(const struct pm_keyset *ks, const unsigned char keynum[8]) {
    char hex[17];
    sigv_keynum_hex(keynum, hex);
    for (size_t i = 0; i < ks->nrev; i++)
        if (!strcasecmp(ks->revoked[i], hex)) return 1;
    return 0;
}

static void keys_add_file(struct pm_keyset *ks, const char *path) {
    size_t n = 0;
    char *b = pm_read(path, &n);
    if (!b) return;
    struct sigv_key k;
    if (sigv_parse_key(b, n, &k) == 0 && !is_revoked(ks, k.keynum)) {
        ks->k = pm_realloc(ks->k, sizeof(*ks->k) * (ks->n + 1));
        ks->k[ks->n++] = k;
    }
    free(b);
}

static void keys_add_dir(struct pm_keyset *ks, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        size_t l = strlen(de->d_name);
        if (de->d_name[0] == '.' || l < 5 || strcmp(de->d_name + l - 4, ".pub")) continue;
        char *p = pm_path(dir, de->d_name);
        keys_add_file(ks, p);
        free(p);
    }
    closedir(d);
}

void pm_keys_role(struct pm_keyset *ks, const char *role) {
    memset(ks, 0, sizeof(*ks));
    keys_revoked_load(ks);
    char *d = pm_path(pm_keys(), role);
    keys_add_dir(ks, d);
    free(d);
}

void pm_keys_repo(struct pm_keyset *ks, const struct pm_repo *r) {
    memset(ks, 0, sizeof(*ks));
    keys_revoked_load(ks);
    char *d = pm_fmt("%s/keys/%s", pm_etc(), r->name);
    /* Годны только ключи, принятые человеком для этого репозитория (repos.d keys). */
    for (size_t i = 0; i < r->nkeys; i++) {
        char *p = pm_fmt("%s/%s.pub", d, r->keys[i]);
        keys_add_file(ks, p);
        free(p);
    }
    free(d);
}

void pm_keys_all(struct pm_keyset *ks) {
    pm_keys_role(ks, "protocols");
    char *d = pm_path(pm_keys(), "plugins");
    keys_add_dir(ks, d);
    free(d);
    struct pm_repos rs;
    struct pm_err e;
    if (pm_repos_load(&rs, &e) == 0) {
        for (size_t i = 0; i < rs.n; i++) {
            if (rs.v[i].official) continue;
            struct pm_keyset rk;
            pm_keys_repo(&rk, &rs.v[i]);
            for (size_t j = 0; j < rk.n; j++) {
                ks->k = pm_realloc(ks->k, sizeof(*ks->k) * (ks->n + 1));
                ks->k[ks->n++] = rk.k[j];
            }
            pm_keys_free(&rk);
        }
        pm_repos_free(&rs);
    }
}

void pm_keys_free(struct pm_keyset *ks) {
    free(ks->k);
    free_list(ks->revoked, ks->nrev);
    memset(ks, 0, sizeof(*ks));
}

int pm_sig_check(const struct pm_keyset *ks, const char *sig, size_t sig_n, const void *msg,
                 size_t msg_n, const char *what, struct pm_err *e) {
    struct sigv_sigs ss = {0};
    if (!sig || !sig_n) return pm_errc(e, "plugin.unsigned", PMA("what", what), "%s не подписан", what);
    if (sigv_parse_sigs(sig, sig_n, &ss) != 0) return pm_errc(e, "plugin.signature_unreadable", PMA("what", what), "подпись %s не разбирается", what);
    int r = sigv_verify_blocks(ks->k, ks->n, &ss, msg, msg_n, NULL);
    if (r >= 0) { sigv_sigs_free(&ss); return 0; }
    if (r == SIGV_EKEYNUM) {
        /* Назвать номера ключей подписи; отозванный — отдельными словами. */
        char *names = pm_strdup(""), hex[17];
        int revoked = 0;
        for (size_t i = 0; i < ss.n; i++) {
            sigv_keynum_hex(ss.v[i].keynum, hex);
            if (pm_key_revoked(hex)) revoked = 1;
            char *t = pm_fmt("%s%s%s", names, i ? ", " : "", hex);
            free(names);
            names = t;
        }
        sigv_sigs_free(&ss);
        if (revoked)
            pm_errc(e, "plugin.signed_revoked_key", PMA("what", what, "keys", names), "%s подписан отозванным ключом %s", what, names);
        else
            pm_errc(e, "plugin.signed_unknown_key", PMA("what", what, "keys", names), "%s подписан ключом %s, такого ключа у ядра нет", what, names);
        free(names);
        return -1;
    }
    sigv_sigs_free(&ss);
    return pm_errc(e, "plugin.signature_mismatch", PMA("what", what), "подпись %s не сходится — файл подменён или испорчен", what);
}
