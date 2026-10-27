#!/bin/sh
# Манифесты вкомпилированных плагинов: `sh build/pkembed.sh > src/plugkit/pkembed.c`.
#
# Статическая сборка (телефон, plugin-sdk open.md, О-13) несёт программы плагинов PLUGINS_EMBED
# (build/sources.mk) в себе (PK_PROGRAM), а каталога плагинов рядом с ней нет. Их манифесты и файлы
# (plugins/<id>/, без bin/) идут в бинарник строками: реестр ядра читает их как каталог «@builtin/<id>»
# (src/kinds/plugin.h, steer_plugin_embed). Файл — плод этого сценария и лежит в дереве, чтобы его брали
# все сборки (make, build.sh, Android.bp) без шага генерации; tests/buildmatch.sh сверяет его с plugins/.
set -eu
cd "$(dirname "$0")/.."
. build/sources.sh
IDS="$(profile_var PLUGINS_EMBED)"

# Строка C из файла: построчно, с \n в конце каждой строки; \ и " экранируются.
cstr() {
    awk '{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); printf "    \"%s\\n\"\n", $0 }' "$1"
}

cat <<'EOF'
/* ПОРОЖДЁН build/pkembed.sh из plugins/<id>/ — не править руками (tests/buildmatch.sh сверяет).
 *
 * Манифесты и файлы плагинов, вкомпилированных в статическую сборку (src/kinds/plugin.h,
 * steer_plugin_embed): реестр ядра читает их как каталог «@builtin/<id>». */
#include <stddef.h>

#include "plugin.h"
EOF
for id in $IDS; do
    v="$(printf '%s' "$id" | tr -c 'a-z0-9\n' '_')"
    files="plugin.json $(cd "plugins/$id" && find . -type f ! -name plugin.json ! -path './bin/*' | sed 's|^\./||' | LC_ALL=C sort)"
    printf '\nstatic const struct plugin_embed_file f_%s[] = {\n' "$v"
    for f in $files; do
        printf '    { "%s",\n    ""\n' "$f"
        cstr "plugins/$id/$f"
        printf '    },\n'
    done
    printf '    { NULL, NULL },\n};\n'
done
printf '\nconst struct plugin_embed steer_plugin_embed[] = {\n'
for id in $IDS; do
    v="$(printf '%s' "$id" | tr -c 'a-z0-9\n' '_')"
    printf '    { "%s", f_%s },\n' "$id" "$v"
done
printf '    { NULL, NULL },\n};\n'
