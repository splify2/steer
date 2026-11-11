#!/bin/sh
# Виды официальных плагинов: `sh build/offkinds.sh > src/kinds/offkinds.h`.
#
# Какой плагин даёт вид, которого нет, ядро узнаёт из индекса семени (provides.kinds). Но в семя входят
# не все официальные плагины: мост Telegram tgws это дерево собирает, а выпускает репозиторий
# splify2-extended-plugins, и в семени его нет. Без таблицы вид tgws был бы ядру «неизвестен», и спека
# с таким выходом не загружалась бы целиком — после перехода с 2.0.x (пакет steer-tgws) роутер
# оставался без правил вовсе. Источник таблицы — манифесты plugins/*/plugin.json этого дерева: те же,
# из которых собираются архивы; кэши индексов репозиториев для этого не годятся — они в /var/run
# (tmpfs) и пусты при загрузке, ровно когда демон поднимает спеку.
#
# Виды impl: core (awg, interface у obfs) — виды ядра, плагин их лишь дополняет: в таблицу не идут.
# Файл — плод этого сценария и лежит в дереве (как src/plugkit/pkembed.c), tests/buildmatch.sh сверяет.
set -eu
cd "$(dirname "$0")/.."
python3 - plugins/*/plugin.json <<'EOF'
import json, sys
rows = []
for f in sys.argv[1:]:
    d = json.load(open(f))
    for k in d.get("steer", {}).get("kinds", []):
        if k.get("impl") == "core":
            continue
        rows.append((k["name"], d["id"]))
rows.sort()
print("""/* ПОРОЖДЁН build/offkinds.sh из plugins/<id>/plugin.json — не править руками (tests/buildmatch.sh сверяет).
 *
 * Виды официальных плагинов и их id (plugin.c, plugin_kind_why; pmkind.c, pm_spec_plugins): вид из
 * таблицы без плагина — недоступный выход «нужен плагин <id>», а не «неизвестный kind», даже если
 * плагина нет в семени (tgws — из репозитория splify2-extended-plugins). */
#ifndef STEER_OFFKINDS_H
#define STEER_OFFKINDS_H

static const struct { const char *kind, *plugin; } OFFICIAL_KINDS[] = {""")
for k, p in rows:
    print('    { "%s", "%s" },' % (k, p))
print("""};
#define OFFICIAL_KINDS_N (sizeof(OFFICIAL_KINDS) / sizeof(OFFICIAL_KINDS[0]))

static inline const char *official_kind_plugin(const char *kind) {
    for (size_t i = 0; i < OFFICIAL_KINDS_N; i++)
        if (!strcmp(OFFICIAL_KINDS[i].kind, kind)) return OFFICIAL_KINDS[i].plugin;
    return NULL;
}

#endif""")
EOF
