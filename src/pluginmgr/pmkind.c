/* Виды ядра под impl: core и плагины выходов спеки (pmkind.h). */
#include <stdio.h>
#include <string.h>

#include "pmkind.h"
#include "err.h"

/* Виды ядра, которые плагин официального репозитория дополняет (impl: core). key — ключ выхода, при
 * котором плагин нужен (helper.when его манифеста); NULL — нужен всякому выходу вида. */
static const struct { const char *kind, *key, *plugin; } CORE_EXT[] = {
    { "awg",       NULL,   "awg"  },   /* допуск, зависимости и UI вида awg */
    { "interface", "obfs", "obfs" },   /* обфускатор WireGuard выходу interface с obfs */
};
#define CORE_EXT_N (sizeof(CORE_EXT) / sizeof(CORE_EXT[0]))

int pm_core_ext_kind(const char *name) {
    if (!name) return 0;
    for (size_t i = 0; i < CORE_EXT_N; i++)
        if (!strcmp(CORE_EXT[i].kind, name)) return 1;
    return 0;
}

static const char *str_of(const struct ynode *n) {
    if (!n || n->kind != YN_SCALAR || (n->style == YS_PLAIN && ynode_is_null(n))) return NULL;
    return n->str;
}

/* Какой плагин даёт вид по индексу семени (provides.kinds). */
static const char *seed_plugin_for(const struct ynode *plugins, const char *kind) {
    for (size_t i = 0; i < ynode_len(plugins); i++) {
        const struct ynode *vs = ynode_get(ynode_val_at(plugins, i), "versions");
        for (size_t j = 0; j < ynode_len(vs); j++) {
            const struct ynode *ks = ynode_get(ynode_get(ynode_at(vs, j), "provides"), "kinds");
            for (size_t k = 0; k < ynode_len(ks); k++) {
                const char *c = str_of(ynode_at(ks, k));
                if (c && !strcmp(c, kind)) return ynode_key_at(plugins, i)->str;
            }
        }
    }
    return NULL;
}

int pm_spec_plugins(const char *buf, size_t n, const char *name, const struct ynode *plugins,
                    void (*add)(void *arg, const char *id), void *arg) {
    struct err ye;
    memset(&ye, 0, sizeof(ye));
    struct ydoc *d = ydoc_parse_buf(buf, n, name ? name : "spec", &ye);
    if (!d) return -1;
    const struct ynode *outs = ynode_get(ydoc_root(d), "outputs");
    for (size_t i = 0; i < ynode_len(outs); i++) {
        const struct ynode *o = ynode_val_at(outs, i);
        const char *k = str_of(ynode_get(o, "kind"));
        if (!k) continue;
        /* Вид ядра: плагин — по правилу перечня, provides.kinds тут не в счёт (obfs записан там видом
         * interface, но выходу interface без ключа obfs он не нужен). */
        if (pm_core_ext_kind(k)) {
            for (size_t j = 0; j < CORE_EXT_N; j++)
                if (!strcmp(CORE_EXT[j].kind, k) && (!CORE_EXT[j].key || ynode_get(o, CORE_EXT[j].key)))
                    add(arg, CORE_EXT[j].plugin);
            continue;
        }
        char kn[160];
        if (!strcmp(k, "tunnel")) {
            const char *pr = str_of(ynode_get(o, "protocol"));
            snprintf(kn, sizeof(kn), "tunnel:%s", pr ? pr : "vless");
        } else snprintf(kn, sizeof(kn), "%s", k);
        const char *id = seed_plugin_for(plugins, kn);
        /* warp в provides.kinds не записан: группу warp ведёт warpbox (он тянет awg). */
        if (!id && !strcmp(kn, "warp")) id = "warpbox";
        if (id) add(arg, id);
    }
    ydoc_free(d);
    return 0;
}
