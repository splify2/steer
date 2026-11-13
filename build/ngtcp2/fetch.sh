#!/bin/sh
# Исходники ngtcp2 для сборки движка: скачать выпуск, СВЕРИТЬ СУММУ, распаковать, наложить наши
# патчи (build/ngtcp2/patches/*.patch).
#
#     sh build/ngtcp2/fetch.sh <каталог>
#     sh build/ngtcp2/fetch.sh version
#     sh build/ngtcp2/fetch.sh soname     версия и серия патчей: хвост SONAME libsteer-ngtcp2.so
#
# ВЕРСИЯ И СУММА ЗАПИСАНЫ ЗДЕСЬ И ТОЛЬКО ЗДЕСЬ — как у build/wolfssl/fetch.sh, и по тем же
# причинам: образ сборки (build/Dockerfile копирует скрипт и патчи и зовёт его), стенды на
# хосте (tests/ext-test.sh) и проверка сборки под телефон (make ndk-check) берут исходники
# одним и тем же способом, поэтому версия у всех одна, а сменить её — правка двух строк ниже. Сверяет
# это tests/buildmatch.sh.
#
# ПОЧЕМУ СКАЧИВАНИЕ + ПАТЧИ, А НЕ ИСХОДНИКИ В ДЕРЕВЕ. Выпуск ngtcp2 — 700 КБ архива и около 300
# файлов, из которых сборке нужно 46 файлов lib/ и один crypto/wolfssl. Своё в нём — только патч
# Brutal (build/ngtcp2/patches/0001-*.patch, ~350 строк, из них 250 — два новых файла), и хранить
# нужно его, а не чужой код: обновление библиотеки тогда — правка версии, суммы и, если патч
# не лёг, переноса (порядок — в шапке патча).
#
# ПОЧЕМУ ИМЕННО ЭТА СУММА. Берётся релизный архив .tar.xz с GitHub-страницы выпуска
# (github.com/ngtcp2/ngtcp2/releases/tag/v1.25.0), а не архив тега: в релизном лежат созданные
# автотулзами файлы (lib/includes/ngtcp2/version.h), которых в архиве тега нет. Рядом с ним лежат
# checksums.txt и ngtcp2-1.25.0.tar.xz.asc — подпись Tatsuhiro Tsujikawa
# (<tatsuhiro.t@gmail.com>), основной ключ F4F3 B914 74D1 EB29 889B D0EF 7E84 03D5 D673 C366, подключ
# подписи 516B 6229 18D1 5C47 8AB1 EA3A 5339 A2BE 82E0 7DEC. Подпись проверена этим ключом
# (gpg --verify: «Good signature») при записи суммы сюда; сумма совпала с checksums.txt из выпуска.
# Сборка дальше сверяет сумму, а не подпись: gpg и сеть к серверу ключей в образе и на машине
# сборки не нужны — так же, как у wolfSSL.
#
# 1.25.0 — последний выпуск (26 июля 2026), лицензия MIT.
set -eu

NGTCP2_VERSION=1.25.0
NGTCP2_SHA256=2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb
URL="https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.xz"
HERE=$(cd "$(dirname "$0")" && pwd)

# Серия наших патчей: растёт с каждой правкой build/ngtcp2/patches, меняющей то, что видят потребители
# (заголовки, поля, функции). Входит в SONAME общей библиотеки ядра libsteer-ngtcp2.so.<версия>-<серия>
# (build/build-libs.sh): плагин net1 прежней серии с ней не загрузится, а не прочтёт чужие поля. Сверяет
# сумму патчей с записанной для серии build/wolfssl/crypto.lst (tests/buildmatch.sh).
NGTCP2_PATCHLEVEL=2
[ "${1:-}" = version ] && { echo "$NGTCP2_VERSION"; exit 0; }
[ "${1:-}" = soname ] && { echo "$NGTCP2_VERSION-$NGTCP2_PATCHLEVEL"; exit 0; }
DEST="${1:?нужен каталог, куда распаковать исходники}"
# Метка — сумма тарбола и сумма наших патчей: другая версия или другой патч в том же каталоге
# заменяются, а не берутся.
PATCHSUM=$(cat "$HERE"/patches/*.patch | sha256sum | cut -d' ' -f1)
STAMP="$NGTCP2_SHA256 $PATCHSUM"
if [ -f "$DEST/lib/includes/ngtcp2/ngtcp2.h" ] && [ "$(cat "$DEST/.steer-ngtcp2" 2>/dev/null)" = "$STAMP" ]; then
    exit 0
fi

mkdir -p "$DEST"
TGZ="$DEST.tar.xz"
# Готовый тарбол можно подложить (NGTCP2_TARBALL) — сборка без сети; сверяется он так же.
if [ -n "${NGTCP2_TARBALL:-}" ]; then
    TGZ="$NGTCP2_TARBALL"
elif ! curl -fsSL -o "$TGZ" "$URL"; then
    echo "ngtcp2: не скачать $URL" >&2
    rm -f "$TGZ"
    exit 1
fi
if ! echo "$NGTCP2_SHA256  $TGZ" | sha256sum -c - >/dev/null 2>&1; then
    echo "ngtcp2: сумма тарбола $TGZ не сошлась (ждали $NGTCP2_SHA256) — не распаковываю" >&2
    [ -n "${NGTCP2_TARBALL:-}" ] || rm -f "$TGZ"
    exit 1
fi
# Распаковка — в соседний каталог и подмена целиком, как у wolfSSL: удалённый в новом выпуске
# файл иначе остался бы и собрался.
NEW="$DEST.new"
rm -rf "$NEW"
mkdir -p "$NEW"
tar xJf "$TGZ" -C "$NEW" --strip-components=1
[ -n "${NGTCP2_TARBALL:-}" ] || rm -f "$TGZ"
[ -f "$NEW/lib/includes/ngtcp2/ngtcp2.h" ] || { echo "ngtcp2: в тарболе нет исходников" >&2; exit 1; }
# Патчи — по порядку имён. Отказ любого — отказ сборки, с именем патча: после обновления версии это
# первое, что увидит человек, и переносить нужно именно его.
for p in "$HERE"/patches/*.patch; do
    if ! (cd "$NEW" && patch -p1 -s < "$p"); then
        echo "ngtcp2: патч $(basename "$p") не лёг на $NGTCP2_VERSION — перенести (шапка патча)" >&2
        rm -rf "$NEW"
        exit 1
    fi
done
echo "$STAMP" > "$NEW/.steer-ngtcp2"
rm -rf "$DEST"
mv "$NEW" "$DEST"
echo "ngtcp2: исходники $NGTCP2_VERSION в $DEST (sha256 сошлась, патчей: $(ls "$HERE"/patches/*.patch | wc -l))"
