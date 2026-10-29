/* Менеджер плагинов: индекс репозитория и отбор версии (index.md).
 *
 * ЗАГРУЗКА. Индекс берётся по адресу репозитория и его зеркалам по порядку: условный запрос с ETag
 * прежнего ответа (кэш — /var/run/steer/plugins/<repo>/, tmpfs), затем подпись. Без годной подписи
 * индекс не разбирается вовсе; затем schema, expires и generated (не старее виденного — защита от
 * отката на индекс с уязвимой версией). Сеть не вышла — кэш (та же проверка); у официального
 * репозитория — ещё индекс семени (подписан тем же ключом роли index; срок у снимка не проверяется:
 * семя для того и есть, чтобы ставить без сети).
 *
 * ОТБОР (index.md, «Отбор версии»): версии по убыванию semver; отозванные, из bad_versions, без
 * сборки под архитектуру, несовместимые по осям compat и конфликтующие со стоящими — мимо, с
 * причиной от самой новой. Зависимости разрешает план (pminst.c). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pm.h"
#include "httpc.h"

const char *cli_core_version(void);

/* ---- цель ---- */

/* Каталог данных панели splify2: версии её осей совместимости (compat/<ось>), host-api. Стенды подменяют. */
static const char *panel_dir(void) {
    const char *d = getenv("STEER_PLUGIN_PANEL_DIR");
    return d && *d ? d : "/usr/share/splify2";
}

static char *first_line(const char *path) {
    char *b = pm_read(path, NULL);
    if (!b) return NULL;
    b[strcspn(b, "\r\n")] = '\0';
    char *s = b;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s) { free(b); return NULL; }
    char *r = pm_strdup(s);
    free(b);
    return r;
}

/* Архитектура opkg: старший приоритет из «arch <имя> <приоритет>» в /etc/opkg.conf и
 * /etc/opkg/<имя>.conf, кроме all и noarch. */
static char *opkg_arch(void) {
    const char *files[] = {"/etc/opkg.conf", "/etc/opkg/arch.conf", "/etc/opkg/customfeeds.conf", NULL};
    char *best = NULL;
    long bp = -1;
    for (int i = 0; files[i]; i++) {
        char *b = pm_read(files[i], NULL);
        if (!b) continue;
        for (char *l = strtok(b, "\n"); l; l = strtok(NULL, "\n")) {
            char name[128];
            long pr;
            if (sscanf(l, " arch %127s %ld", name, &pr) != 2) continue;
            if (!strcmp(name, "all") || !strcmp(name, "noarch")) continue;
            if (pr > bp) { bp = pr; free(best); best = pm_strdup(name); }
        }
        free(b);
    }
    return best;
}

void pm_target_load(struct pm_target *t) {
    memset(t, 0, sizeof(*t));
    const char *c = getenv("STEER_PLUGIN_CORE");
    t->core = pm_strdup(c && *c ? c : cli_core_version());
    /* «2.1.0-r1» и подобное — версия ядра без ревизии пакета. */
    char *dash = strstr(t->core, "-r");
    if (dash) *dash = '\0';
    t->api = pm_strdup(PM_STEER_API);
    t->abi = pm_strdup(PM_STEER_ABI);
    const char *h = getenv("STEER_PLUGIN_HOST_API");
    if (h) t->host = *h ? pm_strdup(h) : NULL;
    else {
        char path[512];
        snprintf(path, sizeof path, "%s/compat/host-api", panel_dir());
        if (!(t->host = first_line(path))) {
            snprintf(path, sizeof path, "%s/host-api", panel_dir());
            t->host = first_line(path);
        }
    }
    const char *sv = getenv("STEER_PLUGIN_SPLIFY2");
    if (sv) t->splify2 = *sv ? pm_strdup(sv) : NULL;
    else t->splify2 = first_line("/usr/share/splify2/version");
    const char *a = getenv("STEER_PLUGIN_ARCH");
    if (a && *a) t->arch = pm_strdup(a);
    else if (!(t->arch = first_line("/etc/apk/arch"))) t->arch = opkg_arch();
}

/* Версия последней прочитанной оси панели: держится до следующего вызова pm_compat_why, как buf. */
static char *axis_have;

/* Причина несовместимости в машинном виде — для той же фразы, что вернул pm_compat_why: код и подстановки без id и
 * версии плагина (их добавляет pm_compat_err). */
static char cw_code[64], cw_args[512];
static void cw_set(const char *code, const char *k1, const char *v1, const char *k2, const char *v2,
                   const char *k3, const char *v3) {
    snprintf(cw_code, sizeof(cw_code), "%s", code);
    cw_args[0] = 0;
    if (k1) err_args_add(cw_args, sizeof(cw_args), k1, v1);
    if (k2) err_args_add(cw_args, sizeof(cw_args), k2, v2);
    if (k3) err_args_add(cw_args, sizeof(cw_args), k3, v3);
}

/* Отказ «id версия + причина совместимости» по последнему pm_compat_why (cw — его фраза). */
void pm_compat_err(struct pm_err *e, const char *id, const char *ver, const char *cw) {
    pm_errc(e, cw_code[0] ? cw_code : "plugin.incompatible", PMA("id", id, "version", ver ? ver : ""),
            ver ? "%s %s %s" : "%s%s %s", id, ver ? ver : "", cw);
    /* подстановки причины — следом за id и version */
    if (cw_args[0]) {
        const char *p = cw_args + 1;       /* без «{» */
        size_t l = strlen(e->args);
        if (l && strlen(p) + l + 2 < sizeof(e->args)) { e->args[l - 1] = ','; memcpy(e->args + l, p, strlen(p) + 1); }
    }
    if (!cw_code[0]) pm_err_arg(e, "why", cw);
}

const char *pm_compat_why(const struct pm_target *t, const struct ynode *compat, char *buf, size_t n) {
    cw_code[0] = 0;
    for (size_t i = 0; i < ynode_len(compat); i++) {
        const char *axis = ynode_key_at(compat, i)->str;
        const struct ynode *rv = ynode_val_at(compat, i);
        const char *range = yn_is_str(rv) ? rv->str : NULL;
        const char *have = NULL, *who = "у ядра";
        if (!strcmp(axis, "steer-api")) have = t->api;
        else if (!strcmp(axis, "steer-abi")) have = t->abi;
        else if (!strcmp(axis, "steer-core")) have = t->core;
        else if (!strcmp(axis, "host-api")) { have = t->host; who = "у панели"; if (!have) continue; }
        else if (!strcmp(axis, "splify2")) { have = t->splify2; who = "у панели"; if (!have) continue; }
        else if (!strncmp(axis, "splify2-", 8)) {
            /* Оси панели (splify2-api, splify2-luci и будущие) ядро не перечисляет: их версии панель кладёт
             * файлами в <каталог панели>/compat/<ось>. Панели нет — ось не про этот роутер, как host-api. */
            char path[512];
            snprintf(path, sizeof path, "%s/compat/%s", panel_dir(), axis);
            free(axis_have);
            axis_have = first_line(path);
            if (!axis_have) {
                if (access(panel_dir(), F_OK) != 0) continue;
                snprintf(buf, n, "неизвестная ось совместимости %s — обновите панель splify2", axis);
                cw_set("plugin.compat_unknown_axis_panel", "axis", axis, NULL, NULL, NULL, NULL);
                return buf;
            }
            have = axis_have;
            who = "у панели";
        } else {
            snprintf(buf, n, "неизвестная ось совместимости %s — обновите ядро", axis);
            cw_set("plugin.compat_unknown_axis_core", "axis", axis, NULL, NULL, NULL, NULL);
            return buf;
        }
        if (!range) { snprintf(buf, n, "ось %s без диапазона", axis); cw_set("plugin.compat_no_range", "axis", axis, NULL, NULL, NULL, NULL); return buf; }
        if (!strcmp(axis, "steer-core") && strncmp(range, ">=", 2) != 0) {
            snprintf(buf, n, "ось steer-core принимает только «>=», а не «%s»", range);
            cw_set("plugin.compat_core_op", "range", range, NULL, NULL, NULL, NULL);
            return buf;
        }
        int m = pm_range_match(range, have);
        if (m < 0) { snprintf(buf, n, "диапазон %s «%s» не разобрался", axis, range); cw_set("plugin.compat_bad_range", "axis", axis, "range", range, NULL, NULL); return buf; }
        if (!m) {
            snprintf(buf, n, "требует %s %s, %s %s", axis, range, who, have ? have : "нет");
            cw_set(!strcmp(who, "у ядра") ? "plugin.compat_needs_core" : "plugin.compat_needs_panel", "axis", axis, "range", range, "have", have ? have : "none");
            return buf;
        }
    }
    return NULL;
}

/* ---- загрузка ---- */

static char *cache_dir(const struct pm_repo *r) {
    return pm_path(pm_run(), r->name);
}

static void idx_set(struct pm_repo *r, struct ydoc *d) {
    if (r->idx) ydoc_free(r->idx);
    r->idx = d;
    r->iroot = d ? ydoc_root(d) : NULL;
}

/* Проверить и разобрать байты индекса. check_time — сверять expires и generated. */
static struct ydoc *idx_verify(struct pm_repo *r, const char *body, size_t bn, const char *sig, size_t sn,
                               int check_time, int seed, struct pm_err *e) {
    struct pm_keyset ks;
    if (r->official || seed) pm_keys_role(&ks, "index");
    else pm_keys_repo(&ks, r);
    char *what = pm_fmt("индекс репозитория %s", r->name);
    int vr = pm_sig_check(&ks, sig, sn, body, bn, what, e);
    pm_keys_free(&ks);
    free(what);
    if (vr != 0) return NULL;
    struct ydoc *d = pm_json_parse(body, bn, "index.json", e);
    if (!d) return NULL;
    const struct ynode *root = ydoc_root(d);
    if (yn_long(root, "schema", -1) != 1) {
        ydoc_free(d);
        pm_errc(e, "plugin.index_new_format", PMA("name", r->name), "индекс репозитория %s нового формата — обновите ядро", r->name);
        return NULL;
    }
    const char *rid = yn_str(ynode_get(root, "repo"), "id");
    if (!seed && (!rid || strcmp(rid, r->name))) {
        ydoc_free(d);
        pm_errc(e, "plugin.index_foreign", PMA("name", r->name, "id", rid ? rid : ""), "индекс репозитория %s назван «%s» — это чужой индекс", r->name, rid ? rid : "");
        return NULL;
    }
    if (check_time) {
        time_t now = time(NULL);
        time_t ex = pm_parse_time(yn_str(root, "expires"));
        if (ex >= 0 && ex < now) {
            ydoc_free(d);
            pm_errc(e, "plugin.index_expired", PMA("name", r->name, "expires", yn_str(root, "expires")), "индекс репозитория %s просрочен (%s) — зеркало отдаёт старый индекс", r->name,
                    yn_str(root, "expires"));
            return NULL;
        }
        time_t gen = pm_parse_time(yn_str(root, "generated"));
        time_t seen = pm_parse_time(r->last_generated);
        if (gen >= 0 && seen >= 0 && gen < seen) {
            ydoc_free(d);
            pm_errc(e, "plugin.index_rollback", PMA("name", r->name, "generated", yn_str(root, "generated"), "seen", r->last_generated), "индекс репозитория %s старее уже виденного (%s < %s) — откат индекса отвергнут",
                    r->name, yn_str(root, "generated"), r->last_generated);
            return NULL;
        }
    }
    return d;
}

static int http_to_mem(const char *url, const char *etag, char **body, size_t *bn, char **etag_out,
                       int *not_modified, char *why, size_t wn) {
    char *tmpd = pm_strdup(pm_tmp());
    pm_mkdirs(tmpd);
    char *dest = pm_fmt("%s/.idx.%d", tmpd, (int)getpid());
    free(tmpd);
    struct http_req q = {0};
    q.url = url;
    q.etag = etag;
    q.dest_path = dest;
    q.connect_ms = 10000;
    q.idle_ms = 30000;
    q.total_ms = 120000;
    struct http_resp rp = {0};
    int rc = http_get(&q, &rp, why, wn);
    *not_modified = 0;
    if (rc == 0 && rp.not_modified) {
        *not_modified = 1;
        http_resp_free(&rp);
        unlink(dest);
        free(dest);
        return 0;
    }
    if (rc == 0 && (rp.status < 200 || rp.status > 299)) {
        snprintf(why, wn, "ответ %d", rp.status);
        rc = -1;
    }
    if (rc == 0) {
        *body = pm_read(dest, bn);
        if (!*body) { snprintf(why, wn, "не прочитать скачанное"); rc = -1; }
        if (etag_out) *etag_out = rp.etag ? pm_strdup(rp.etag) : NULL;
    }
    http_resp_free(&rp);
    unlink(dest);
    free(dest);
    return rc;
}

int pm_http_mem(const char *url, char **body, size_t *n, char *why, size_t wn) {
    int nm = 0;
    *body = NULL;
    return http_to_mem(url, NULL, body, n, NULL, &nm, why, wn);
}

static int idx_from_cache(struct pm_repo *r, struct pm_err *e) {
    char *cd = cache_dir(r);
    char *ip = pm_path(cd, "index.json"), *sp = pm_path(cd, "index.json.sig");
    size_t bn = 0, sn = 0;
    char *b = pm_read(ip, &bn), *s = pm_read(sp, &sn);
    free(ip); free(sp); free(cd);
    if (!b || !s) { free(b); free(s); return -1; }
    struct ydoc *d = idx_verify(r, b, bn, s, sn, 1, 0, e);
    free(b); free(s);
    if (!d) return -1;
    idx_set(r, d);
    return 0;
}

static int idx_from_seed(struct pm_repo *r, struct pm_err *e) {
    char *ip = pm_path(pm_seed(), "index.json"), *sp = pm_path(pm_seed(), "index.json.sig");
    size_t bn = 0, sn = 0;
    char *b = pm_read(ip, &bn), *s = pm_read(sp, &sn);
    free(ip); free(sp);
    if (!b) { free(s); return pm_errc(e, "plugin.no_seed", NULL, "семени нет"); }
    struct ydoc *d = idx_verify(r, b, bn, s, sn, 0, 1, e);
    free(b); free(s);
    if (!d) return -1;
    const char *rid = yn_str(ynode_get(ydoc_root(d), "repo"), "id");
    if (!r->seed && (!rid || strcmp(rid, r->name))) { ydoc_free(d); return pm_errc(e, "plugin.seed_other_repo", NULL, "семя — индекс другого репозитория"); }
    idx_set(r, d);
    r->seed = 1;
    free(r->url);
    r->url = pm_strdup(pm_seed());
    return 0;
}

int pm_index_get(struct pm_repo *r, int refresh, struct pm_err *e) {
    if (r->iroot) return 0;
    /* Кэш и семя без сети уже не дали индекса: перечитывать и проверять подпись заново на каждый
     * плагин списка незачем — та же причина. Запрос с сетью пробует снова. */
    if (!refresh && r->idx_miss) { *e = *r->idx_miss; return -1; }
    if (r->seed) return idx_from_seed(r, e);
    struct pm_err ce = {0};
    char *cd = cache_dir(r);
    char *etag_p = pm_path(cd, "etag");
    char *etag = NULL;
    {
        char *ip = pm_path(cd, "index.json");
        if (pm_exists(ip)) etag = pm_read(etag_p, NULL);
        free(ip);
        if (etag) etag[strcspn(etag, "\r\n")] = '\0';
    }
    char *net_err = NULL;
    if (refresh) {
        size_t nb = 1 + r->nmirrors;
        for (size_t i = 0; i < nb; i++) {
            const char *base = i == 0 ? r->url : r->mirrors[i - 1];
            if (!base || !*base) continue;
            char *u = pm_path(base, "index.json");
            char why[256] = "";
            char *body = NULL, *netag = NULL;
            size_t bn = 0;
            int nm = 0;
            int rc = http_to_mem(u, etag && *etag ? etag : NULL, &body, &bn, &netag, &nm, why, sizeof(why));
            if (rc != 0) {
                free(net_err);
                net_err = pm_fmt("%s: %s", u, why);
                free(u);
                continue;
            }
            if (nm) {
                free(u);
                if (idx_from_cache(r, &ce) == 0) {
                    r->idx_fresh = 1;
                    goto done;
                }
                /* кэш испорчен — повторить без условия */
                free(etag);
                etag = NULL;
                i--;
                continue;
            }
            char *su = pm_path(base, "index.json.sig");
            char *sig = NULL;
            size_t sn = 0;
            int snm = 0;
            char why2[256] = "";
            rc = http_to_mem(su, NULL, &sig, &sn, NULL, &snm, why2, sizeof(why2));
            free(su);
            if (rc != 0) {
                free(net_err);
                net_err = pm_fmt("%s.sig: %s", u, why2);
                free(u); free(body); free(netag);
                continue;
            }
            free(u);
            struct ydoc *d = idx_verify(r, body, bn, sig, sn, 1, 0, e);
            if (!d) {
                /* Подпись или срок не сошлись — это не сбой сети: зеркало отдаёт чужое. Следующее
                 * зеркало может быть честным; если нет — отказ с этой причиной. */
                free(net_err);
                net_err = pm_strdup(e->msg);
                free(body); free(sig); free(netag);
                r->idx_err = pm_strdup(e->msg);
                continue;
            }
            /* Принят: кэш и last_generated. */
            pm_mkdirs(cd);
            char *ip = pm_path(cd, "index.json"), *sp = pm_path(cd, "index.json.sig");
            pm_write_atomic(ip, body, bn, 0644);
            pm_write_atomic(sp, sig, sn, 0644);
            if (netag) pm_write_atomic(etag_p, netag, strlen(netag), 0644);
            else unlink(etag_p);
            free(ip); free(sp);
            const char *gen = yn_str(ydoc_root(d), "generated");
            if (gen && (!r->last_generated || strcmp(gen, r->last_generated))) {
                free(r->last_generated);
                r->last_generated = pm_strdup(gen);
                struct pm_err se;
                pm_repo_save(r, &se);
            }
            idx_set(r, d);
            r->idx_fresh = 1;
            free(body); free(sig); free(netag);
            goto done;
        }
    }
    /* Сеть не дала годного индекса: кэш, затем семя у официального. */
    if (r->idx_err) {
        /* Подпись не сошлась на всех зеркалах — кэшу и семени это не повод не верить, но человеку
         * нужна причина. Кэш годен, если он подписан. */
    }
    if (idx_from_cache(r, &ce) == 0) goto done;
    if (r->official && idx_from_seed(r, &ce) == 0) goto done;
    if (r->idx_err) pm_errc(e, "plugin.index_failed", PMA("name", r->name, "why", r->idx_err), "%s", r->idx_err);
    else if (net_err) pm_errc(e, "plugin.index_download", PMA("name", r->name, "why", net_err), "индекс репозитория %s не скачался: %s", r->name, net_err);
    else pm_errc(e, "plugin.index_missing", PMA("name", r->name, "why", ce.msg[0] ? ce.msg : "кэш пуст"), "индекса репозитория %s нет: %s", r->name, ce.msg[0] ? ce.msg : "кэш пуст");
    if (!refresh) {
        if (!r->idx_miss) r->idx_miss = pm_alloc(sizeof(*r->idx_miss));
        *r->idx_miss = *e;
    }
    free(net_err); free(etag); free(etag_p); free(cd);
    return -1;
done:
    free(net_err); free(etag); free(etag_p); free(cd);
    return 0;
}

const struct ynode *pm_index_plugin(const struct pm_repo *r, const char *id) {
    return ynode_get(ynode_get(r->iroot, "plugins"), id);
}

/* ---- отбор ---- */

static int ver_desc(const void *a, const void *b) {
    const struct ynode *x = *(const struct ynode *const *)a, *y = *(const struct ynode *const *)b;
    return -pm_ver_cmp(yn_str(x, "version"), yn_str(y, "version"));
}

/* Установленный плагин id объявляет конфликт с other (или наоборот — по манифесту стоящего). */
static const char *conflict_with(struct pm_ctx *x, const char *id, const struct ynode *conf) {
    for (size_t i = 0; i < ynode_len(conf); i++) {
        const struct ynode *c = ynode_at(conf, i);
        if (!yn_is_str(c) || !strcmp(c->str, id)) continue;
        if (pm_state_find(&x->st, c->str)) return c->str;
    }
    for (size_t i = 0; i < x->st.n; i++) {
        const char *other = x->st.v[i].id;
        if (!strcmp(other, id)) continue;
        struct ydoc *own;
        const struct ynode *m = pm_manifest_ro(x, other, &own);
        if (!m) continue;
        const struct ynode *oc = ynode_get(m, "conflicts");
        int hit = 0;
        for (size_t j = 0; j < ynode_len(oc); j++)
            if (yn_is_str(ynode_at(oc, j)) && !strcmp(ynode_at(oc, j)->str, id)) hit = 1;
        if (own) ydoc_free(own);
        if (hit) return other;
    }
    return NULL;
}

static const struct ynode *asset_for(const struct ynode *assets, const char *arch, const char *variant,
                                     char *key, size_t kn) {
    const char *suffix = variant && strcmp(variant, "full") ? variant : NULL;
    const char *archs[2] = {arch, "all"};
    for (int i = 0; i < 2; i++) {
        if (!archs[i]) continue;
        if (suffix) snprintf(key, kn, "%s@%s", archs[i], suffix);
        else snprintf(key, kn, "%s", archs[i]);
        const struct ynode *a = ynode_get(assets, key);
        if (a && a->kind == YN_MAP) return a;
    }
    return NULL;
}

/* Строка ключа id в отображении (живёт вместе с индексом). */
static const char *key_of(const struct ynode *map, const char *id) {
    for (size_t i = 0; i < ynode_len(map); i++)
        if (!strcmp(ynode_key_at(map, i)->str, id)) return ynode_key_at(map, i)->str;
    return id;
}

int pm_select(struct pm_ctx *x, struct pm_repo *r, const char *id, const char *range, const char *exact,
              const char *variant, const char *below, struct pm_cand *c, struct pm_err *e) {
    const struct ynode *pl = pm_index_plugin(r, id);
    if (!pl) return pm_errc(e, "plugin.not_in_repo", PMA("id", id, "name", r->name), "плагина %s нет в репозитории %s", id, r->name);
    const struct ynode *vs = ynode_get(pl, "versions");
    size_t n = ynode_len(vs);
    if (!n) return pm_errc(e, "plugin.no_versions", PMA("id", id), "у плагина %s нет версий", id);
    const struct ynode **sorted = pm_alloc(sizeof(*sorted) * n);
    for (size_t i = 0; i < n; i++) sorted[i] = ynode_at(vs, i);
    qsort(sorted, n, sizeof(*sorted), ver_desc);
    struct pm_inst *inst = pm_state_find(&x->st, id);
    struct pm_err reason_e = {0}, why_e = {0};   /* почему версия не подошла: текст, код и подстановки */
    int found = 0;
    for (size_t i = 0; i < n && !found; i++) {
        const struct ynode *v = sorted[i];
        const char *ver = yn_str(v, "version");
        why_e.msg[0] = 0;
        if (!ver || !pm_ver_ok(ver)) continue;
        if (exact && strcmp(exact, ver)) continue;
        if (below && pm_ver_cmp(ver, below) >= 0) continue;
        if (range) {
            int m = pm_range_match(range, ver);
            if (m <= 0) {
                if (!reason_e.msg[0]) pm_errc(&reason_e, "plugin.no_version_in_range", PMA("id", id, "range", range), "нет версии %s в диапазоне %s", id, range);
                continue;
            }
        }
        const struct ynode *y = ynode_get(v, "yanked");
        if (y && y->kind == YN_MAP) {
            pm_errc(&why_e, "plugin.version_yanked", PMA("id", id, "version", ver, "why", yn_str(y, "why") ? yn_str(y, "why") : "без причины"), "%s %s отозвана: %s", id, ver, yn_str(y, "why") ? yn_str(y, "why") : "без причины");
            goto skip;
        }
        const char *bw = pm_bad_why(inst, ver);
        if (bw && !exact && !x->allow_bad) {
            pm_errc(&why_e, "plugin.version_unhealthy", PMA("id", id, "version", ver, "why", bw), "%s %s уже не прошла проверку здоровья: %s", id, ver, bw);
            goto skip;
        }
        char key[96];
        const struct ynode *asset = asset_for(ynode_get(v, "assets"), x->tg.arch, variant, key, sizeof(key));
        if (!asset) {
            char vb[80];
            snprintf(vb, sizeof(vb), "%s%s", variant && strcmp(variant, "full") ? "@" : "", variant && strcmp(variant, "full") ? variant : "");
            pm_errc(&why_e, "plugin.version_no_build", PMA("id", id, "version", ver, "arch", x->tg.arch ? x->tg.arch : "?", "variant", vb), "у %s %s нет сборки под %s%s%s", id, ver, x->tg.arch ? x->tg.arch : "эту архитектуру",
                     variant && strcmp(variant, "full") ? "@" : "", variant && strcmp(variant, "full") ? variant : "");
            goto skip;
        }
        char cb[512];
        const char *cw = pm_compat_why(&x->tg, ynode_get(v, "compat"), cb, sizeof(cb));
        if (cw) { pm_compat_err(&why_e, id, ver, cw); goto skip; }
        const char *cf = conflict_with(x, id, ynode_get(v, "conflicts"));
        if (cf) { pm_errc(&why_e, "plugin.version_conflict_installed", PMA("id", id, "version", ver, "other", cf), "%s %s не ставится рядом с установленным %s", id, ver, cf); goto skip; }
        memset(c, 0, sizeof(*c));
        c->repo = r;
        c->id = key_of(ynode_get(r->iroot, "plugins"), id);
        c->version = ver;
        c->plug = pl;
        c->ver = v;
        c->asset = asset;
        snprintf(c->variant, sizeof(c->variant), "%s", variant && *variant ? variant : "full");
        snprintf(c->asset_key, sizeof(c->asset_key), "%s", key);
        found = 1;
        break;
    skip:
        if (!reason_e.msg[0] || (exact && why_e.msg[0])) reason_e = why_e;
    }
    free(sorted);
    if (found) return 0;
    if (exact && !reason_e.msg[0]) return pm_errc(e, "plugin.version_not_in_repo", PMA("id", id, "version", exact, "name", r->name), "версии %s %s нет в репозитории %s", id, exact, r->name);
    if (reason_e.msg[0]) return pm_errcopy(e, &reason_e);
    return pm_errc(e, "plugin.no_suitable_version", PMA("id", id), "нет годной версии");
}
