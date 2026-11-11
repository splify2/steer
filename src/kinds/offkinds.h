/* ПОРОЖДЁН build/offkinds.sh из plugins/<id>/plugin.json — не править руками (tests/buildmatch.sh сверяет).
 *
 * Виды официальных плагинов и их id (plugin.c, plugin_kind_why; pmkind.c, pm_spec_plugins): вид из
 * таблицы без плагина — недоступный выход «нужен плагин <id>», а не «неизвестный kind», даже если
 * плагина нет в семени (tgws — из репозитория splify2-extended-plugins). */
#ifndef STEER_OFFKINDS_H
#define STEER_OFFKINDS_H

static const struct { const char *kind, *plugin; } OFFICIAL_KINDS[] = {
    { "tgws", "tgws" },
    { "tunnel:http", "proxy" },
    { "tunnel:hysteria2", "hysteria2" },
    { "tunnel:shadowsocks", "proxy" },
    { "tunnel:socks", "proxy" },
    { "tunnel:trojan", "proxy" },
    { "tunnel:vless", "vless" },
    { "tunnel:vmess", "proxy" },
    { "warp", "warpbox" },
    { "xsteer", "xsteer" },
};
#define OFFICIAL_KINDS_N (sizeof(OFFICIAL_KINDS) / sizeof(OFFICIAL_KINDS[0]))

static inline const char *official_kind_plugin(const char *kind) {
    for (size_t i = 0; i < OFFICIAL_KINDS_N; i++)
        if (!strcmp(OFFICIAL_KINDS[i].kind, kind)) return OFFICIAL_KINDS[i].plugin;
    return NULL;
}

#endif
