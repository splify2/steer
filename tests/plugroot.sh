#!/bin/sh
# Каталог плагинов для стендов ядра: `sh tests/plugroot.sh КАТАЛОГ [BUILD]`.
#
# Виды протоколов ядро берёт только из манифестов плагинов (src/kinds/plugin.c). Стенду нужны манифесты и
# схемы официальных плагинов дерева (plugins/<id>/), а программы — те, что умеют хуки check и expand без
# сети: build/pkhooks (tests/pkhooks.c) под именем bin/<id> каждого плагина. Версия @VERSION@ — из VERSION.
set -eu
D="${1:?нужен каталог}"
B="${2:-build}"
[ -x "$B/pkhooks" ] || { echo "plugroot: нет $B/pkhooks (make $B/pkhooks)" >&2; exit 2; }
V="$(cat VERSION)"
H="$(cd "$B" && pwd)/pkhooks"
mkdir -p "$D"
for p in plugins/*/; do
    id="$(basename "$p")"
    mkdir -p "$D/$id/bin"
    cp -r "$p"* "$D/$id/"
    sed "s/@VERSION@/$V/g" "$p/plugin.json" > "$D/$id/plugin.json"
    ln -sfn "$H" "$D/$id/bin/$id"
done
