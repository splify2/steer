/* Виды ядра под impl: core и плагины выходов спеки для `steer plugin migrate` (src/pluginmgr/pmkind.c).
 *
 * Переход 2.0.5 → 2.1.0: манифест obfs объявляет вид ядра interface с impl: core (помощник по ключу obfs,
 * helper.when), а менеджер принимал impl: core только у awg — установка obfs отказывала «вида interface
 * ядро не знает». И migrate ставил obfs всякой спеке с выходом interface: индекс семени пишет obfs в
 * provides.kinds видом interface. Здесь — оба случая: манифесты дерева (plugins/<id>/plugin.json)
 * проходят проверку impl: core, а плагин obfs migrate берёт только выходу interface с obfs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "err.h"
#include "ynode.h"
#include "pmkind.h"

static struct ydoc *parse(const char *txt) {
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(txt, strlen(txt), "test", &e);
    if (!d) fprintf(stderr, "разбор: %s\n", e.msg);
    return d;
}

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *b = NULL;
    size_t cap = 0, len = 0, r;
    char tmp[4096];
    while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0) {
        if (len + r + 1 > cap) { cap = (len + r + 1) * 2; b = realloc(b, cap); if (!b) { fclose(f); return NULL; } }
        memcpy(b + len, tmp, r);
        len += r;
    }
    fclose(f);
    if (!b) b = calloc(1, 1);
    else b[len] = '\0';
    *n = len;
    return b;
}

/* Собранный список плагинов: «a,b» в порядке добавления, без повторов. */
struct acc { char s[256]; };
static void add(void *arg, const char *id) {
    struct acc *a = arg;
    char probe[96];
    snprintf(probe, sizeof(probe), ",%s,", id);
    char have[260];
    snprintf(have, sizeof(have), ",%s,", a->s);
    if (strstr(have, probe)) return;
    if (a->s[0]) strncat(a->s, ",", sizeof(a->s) - strlen(a->s) - 1);
    strncat(a->s, id, sizeof(a->s) - strlen(a->s) - 1);
}

static const char *want_for(const struct ynode *plugins, const char *spec) {
    static struct acc a;
    memset(&a, 0, sizeof(a));
    if (pm_spec_plugins(spec, strlen(spec), "spec", plugins, add, &a) != 0) return "<отказ разбора>";
    return a.s;
}

/* Индекс семени — как его пишет s2p index: у obfs вид interface в provides.kinds. */
static const char SEED[] =
    "{\"plugins\":{"
    "\"awg\":{\"versions\":[{\"version\":\"2.1.0\",\"provides\":{\"kinds\":[\"awg\"]}}]},"
    "\"obfs\":{\"default\":true,\"versions\":[{\"version\":\"2.1.0\",\"provides\":{\"commands\":[\"obfs-server\"],\"kinds\":[\"interface\"]}}]},"
    "\"vless\":{\"versions\":[{\"version\":\"2.1.0\",\"provides\":{\"kinds\":[\"tunnel:vless\"]}}]},"
    "\"proxy\":{\"versions\":[{\"version\":\"2.1.0\",\"provides\":{\"kinds\":[\"tunnel:socks\",\"tunnel:trojan\"]}}]},"
    "\"warpbox\":{\"versions\":[{\"version\":\"2.1.0\",\"provides\":{\"kinds\":[\"warp\"]}}]}"
    "}}";

int main(void) {
    /* ---- impl: core: какие виды плагин может дополнить ---- */
    check("impl: core у awg", 1, pm_core_ext_kind("awg"));
    check("impl: core у interface (помощник obfs)", 1, pm_core_ext_kind("interface"));
    check("impl: core у direct — нельзя", 0, pm_core_ext_kind("direct"));
    check("impl: core у протокола tunnel:vless — нельзя", 0, pm_core_ext_kind("tunnel:vless"));
    check("impl: core у неизвестного вида — нельзя", 0, pm_core_ext_kind("nosuch"));
    check("impl: core без имени — нельзя", 0, pm_core_ext_kind(NULL));

    /* Манифесты дерева: каждый вид с impl: core проходит ту же проверку, что у менеджера (pminst.c). */
    static const char *const ids[] = { "awg", "obfs", "vless", "hysteria2", "proxy", "warpbox", "xsteer", "net1", "tgws" };
    int ncore = 0, obfs_iface = 0;
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char path[128];
        snprintf(path, sizeof(path), "plugins/%s/plugin.json", ids[i]);
        size_t n;
        char *txt = slurp(path, &n);
        if (!txt) continue;
        struct err e;
        memset(&e, 0, sizeof(e));
        struct ydoc *d = ydoc_parse_buf(txt, n, path, &e);
        free(txt);
        check(path, 1, d != NULL);
        if (!d) continue;
        const struct ynode *kinds = ynode_get(ynode_get(ydoc_root(d), "steer"), "kinds");
        for (size_t j = 0; j < ynode_len(kinds); j++) {
            const struct ynode *k = ynode_at(kinds, j), *impl = ynode_get(k, "impl"), *nm = ynode_get(k, "name");
            if (!impl || !impl->str || strcmp(impl->str, "core")) continue;
            const char *kn = nm && nm->str ? nm->str : "";
            char what[200];
            snprintf(what, sizeof(what), "%s: вид %s с impl: core принимается", path, kn);
            check(what, 1, pm_core_ext_kind(kn));
            ncore++;
            if (!strcmp(ids[i], "obfs") && !strcmp(kn, "interface")) obfs_iface = 1;
        }
        ydoc_free(d);
    }
    check("в дереве есть виды impl: core (awg, obfs)", 1, ncore >= 2);
    check("obfs объявляет interface с impl: core", 1, obfs_iface);

    /* ---- migrate: какие плагины нужны выходам спеки ---- */
    struct ydoc *sd = parse(SEED);
    check("индекс семени разобран", 1, sd != NULL);
    const struct ynode *plugins = ynode_get(ydoc_root(sd), "plugins");

    check_str("interface без obfs — obfs не нужен", "",
              want_for(plugins, "version: 2\noutputs:\n  wg0: { kind: interface, device: wg0 }\n"));
    check_str("interface с obfs — obfs", "obfs",
              want_for(plugins, "version: 2\noutputs:\n  wg0:\n    kind: interface\n    device: wg0\n"
                                "    obfs: { server: 192.0.2.1:443, listen: 127.0.0.1:51821 }\n"));
    check_str("awg — плагин awg", "awg", want_for(plugins, "version: 2\noutputs:\n  a: { kind: awg, conf: /etc/a.conf }\n"));
    check_str("tunnel по протоколу — из provides.kinds", "vless,proxy",
              want_for(plugins, "version: 2\noutputs:\n  v: { kind: tunnel, protocol: vless, subscription: /x }\n"
                                "  s: { kind: tunnel, protocol: socks, server: 1.2.3.4:1080 }\n"));
    check_str("tunnel без protocol — vless", "vless", want_for(plugins, "version: 2\noutputs:\n  v: { kind: tunnel }\n"));
    check_str("warp — warpbox", "warpbox", want_for(plugins, "version: 2\noutputs:\n  w: { kind: warp }\n"));
    check_str("warp без семени — всё равно warpbox", "warpbox", want_for(NULL, "version: 2\noutputs:\n  w: { kind: warp }\n"));
    check_str("direct и block — ничего", "",
              want_for(plugins, "version: 2\noutputs:\n  d: { kind: direct }\n  b: { kind: block }\n"));
    check_str("спека JSON: interface без obfs и с obfs", "obfs",
              want_for(plugins, "{\"version\":2,\"outputs\":{\"a\":{\"kind\":\"interface\",\"device\":\"wg0\"},"
                                "\"b\":{\"kind\":\"interface\",\"device\":\"wg1\",\"obfs\":{\"server\":\"192.0.2.1:443\"}}}}"));
    check_str("неизвестный вид без плагина — ничего", "", want_for(plugins, "version: 2\noutputs:\n  x: { kind: nosuch }\n"));
    check_str("спека не разобралась — отказ", "<отказ разбора>", want_for(plugins, "outputs: [\n"));
    ydoc_free(sd);
    return unit_done("pmkindmatch");
}
