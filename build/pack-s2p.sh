#!/bin/sh
# Архивы .s2p плагинов протоколов и net1 под ОДНУ архитектуру и семя steer-core из них (раскладка 2.1,
# build/sources.mk; plugin-sdk/docs/s2p.md, migration-2.1.md, раздел 5).
#
#     sh build/pack-s2p.sh КАТАЛОГ_LIBS АРХ ВЕРСИЯ ВЫХОД_S2P [КАТАЛОГ_СЕМЕНИ]
#
# КАТАЛОГ_LIBS — выход build/build-libs.sh (plugins/<id>/bin/<id>, plugins/net1/lib/libs2p-net.so.1).
# Манифесты и схемы ключей — plugins/<id>/ дерева; `@VERSION@` в plugin.json протоколов становится
# ВЕРСИЕЙ сборки (hello помощника сверяется с ядром: supd.c, пока реестр плагинов не снял сверку), у
# net1 версия своя (src/net1/s2pnet.h, S2P_NET_VERSION; сверяет tests/buildmatch.sh).
#
# Инструмент — s2p из plugin-sdk: $S2P, `s2p` в PATH или ../plugin-sdk/bin/s2p (раскладка хаба). Ключ
# подписи — $S2P_KEY (ключ роли protocols, секрет CI); без него — ТЕСТОВЫЙ ключ build/s2p-testkey/test.sec
# (создаётся при первой сборке, в дерево не входит): архивы такой сборки примет только ядро, которому
# этот ключ положили руками. Индекс семени подписывает $S2P_KEY_INDEX, иначе тот же тестовый ключ.
# Нет s2p — громкий пропуск с кодом 3 (сборка пакетов ядра идёт дальше, без семени).
set -eu
LIBS="${1:?нужен каталог libs}"; ARCH="${2:?нужна архитектура}"; VERSION="${3:?нужна версия}"
DIST="${4:?нужен выходной каталог}"; SEED="${5:-}"

S2P_BIN="${S2P:-}"
[ -n "$S2P_BIN" ] || S2P_BIN="$(command -v s2p 2>/dev/null || true)"
[ -n "$S2P_BIN" ] || { [ -x ../plugin-sdk/bin/s2p ] && S2P_BIN="$(cd ../plugin-sdk/bin && pwd)/s2p"; } || true
if [ -z "$S2P_BIN" ] || [ ! -x "$S2P_BIN" ]; then
    echo "pack-s2p: нет инструмента s2p (S2P=путь, s2p в PATH или ../plugin-sdk/bin/s2p) — ПРОПУСК .s2p и семени" >&2
    exit 3
fi
. build/sources.sh
KEY="${S2P_KEY:-}"
TESTKEY=""
if [ -z "$KEY" ]; then
    mkdir -p build/s2p-testkey
    [ -f build/s2p-testkey/test.sec ] || "$S2P_BIN" keygen -o build/s2p-testkey/test >/dev/null
    KEY=build/s2p-testkey/test.sec
    TESTKEY=1
fi
IKEY="${S2P_KEY_INDEX:-$KEY}"
N1VER="$(sed -n 's/^#define S2P_NET_VERSION "\(.*\)"$/\1/p' src/net1/s2pnet.h)"

ST="build/s2p-stage/$ARCH"
rm -rf "$ST"
mkdir -p "$ST" "$DIST"
stage() {  # ID ФАЙЛ-В-LIBS ПУТЬ-В-АРХИВЕ
    _id="$1"; _d="$ST/$_id"
    mkdir -p "$_d/$(dirname "$3")"
    cp -R "plugins/$_id/." "$_d/"
    sed -i "s/\"@VERSION@\"/\"$VERSION\"/" "$_d/plugin.json"
    # Архив — под одну архитектуру: в манифесте остаётся она (s2p lint сверяет ELF с ней).
    cp "$LIBS/$2" "$_d/$3"
    chmod 0755 "$_d/$3"
    "$S2P_BIN" build "$_d" --arch "$ARCH" --key "$KEY" -o "$DIST" >/dev/null
}
stage net1 plugins/net1/lib/libs2p-net.so.1 lib/libs2p-net.so.1
for _p in $(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC); do
    stage "$_p" "plugins/$_p/bin/$_p" "bin/$_p"
done
ls "$DIST"/*-"$ARCH".s2p >/dev/null

# Семя: индекс тех же архивов (migration-2.1.md, раздел 5). default — протоколы (их ставит migrate при
# первой установке), net1 тянется по requires.plugins.
if [ -n "$SEED" ]; then
    rm -rf "$SEED"
    mkdir -p "$SEED"
    _meta="$ST/meta.json"
    {
        printf '{'
        printf '"net1":{"key_role":"protocols","tags":["library"]}'
        for _p in $(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC); do
            printf ',"%s":{"default":true,"key_role":"protocols","tags":["protocol"]}' "$_p"
        done
        printf '}\n'
    } > "$_meta"
    _in="$ST/seed-in"
    mkdir -p "$_in"
    cp "$DIST/net1-$N1VER-$ARCH.s2p" "$_in/"
    for _p in $(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC); do cp "$DIST/$_p-$VERSION-$ARCH.s2p" "$_in/"; done
    "$S2P_BIN" index "$_in" -o "$SEED" --repo splify2 --name splify2 --meta "$_meta" \
        --pub "${KEY%.sec}.pub" --key "$IKEY" --mirror https://splify2.github.io/plugins/ >/dev/null
fi
[ -z "$TESTKEY" ] || echo "pack-s2p: $ARCH — подписано ТЕСТОВЫМ ключом build/s2p-testkey/test.sec" >&2
echo "pack-s2p: $ARCH — $(ls "$DIST"/*-"$ARCH".s2p | wc -l) архивов${SEED:+, семя $SEED}"
