#!/bin/sh
# Собрать внешний модуль steer под одну архитектуру: build/ext-build.sh АРХ ВЫХОД ИМЯ:ИСХОДНИКИ
#
# Внешний модуль — бинарник из исходников вне этого дерева, связанный с libsteer (сейчас один:
# steer-box-connector, github.com/splify2/steer-box-connector). Собирается тем же образом, той же
# целью zig и тем же загрузчиком, что модули steer (build/arches.sh, build/build-libs.sh), — иначе
# он встал бы рядом с libsteer из пакета steer-core с чужой ABI. В ВЫХОД ложатся libsteer той же
# версии (только для компоновки — на роутере работает библиотека из steer-core) и сам бинарник.
#
# ВЫХОД и ИСХОДНИКИ — пути на этой машине внутри каталога MOUNT (умолчание — родитель дерева steer:
# так steer подмодулем в репозитории модуля виден вместе с его исходниками).
set -eu
# --static — программа плагина: без libsteer, со своей копией TLS и wolfSSL (build/sources.mk, EXT_TLS_SRC).
STATIC=""
[ "${1:-}" = "--static" ] && { STATIC=1; shift; }
[ $# -ge 3 ] || { echo "usage: $0 [--static] АРХ ВЫХОД ИМЯ:ИСХОДНИКИ [ИМЯ:ИСХОДНИКИ…]" >&2; exit 2; }
ARCH="$1"; OUTD="$2"; shift 2
STEER="$(cd "$(dirname "$0")/.." && pwd -P)"
MOUNT="$(cd "${MOUNT:-$STEER/..}" && pwd -P)"
cd "$STEER"
. ./build/arches.sh
spec="$(printf '%s\n' "$ISAS" | grep "^$ARCH:" || true)"
[ -n "$spec" ] || { echo "ext-build: неизвестная архитектура $ARCH" >&2; exit 2; }
rest=${spec#*:}; target=${rest%%:*}; mcpu=${rest#*:}
IMAGE="${STEER_BUILDER_IMAGE:-steer-builder:wolfssl}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "ext-build: образа $IMAGE нет — собираю из build/Dockerfile"
    docker build -t "$IMAGE" build/ >/dev/null
fi
VERSION="$(cat VERSION)"
# Не на теге — номер из VERSION и коммит, как у build.sh.
REV="$(git describe --tags --exact-match 2>/dev/null ||
      { _h="$(git rev-parse --short HEAD 2>/dev/null)" && echo "$VERSION-g$_h"; } || echo неизвестна)"
inside() {  # путь на машине -> путь в контейнере
    _a="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
    case "$_a" in "$MOUNT"/*) echo "/w/${_a#"$MOUNT"/}" ;; *) echo "ext-build: $1 вне $MOUNT" >&2; exit 2 ;; esac
}
mkdir -p "$OUTD"
apps=""
for a in "$@"; do apps="$apps ${a%%:*}:$(inside "${a#*:}")"; done
# Всё, что считается функциями, — ДО docker run, присваиванием: `exit 2` из inside() внутри $(…) в
# аргументах команды гасится подоболочкой, и docker запускался бы с пустым путём вместо остановки
# скрипта; у присваивания статус подстановки доходит до set -e.
steer_in="$(inside "$STEER")"
outd_in="$(inside "$OUTD")"
interp="$(interp_of "$target" "$mcpu")"
owner="$(id -u):$(id -g)"
# Объектные файлы и владелец выхода — внутри контейнера: docker пишет от root, а снаружи (GitHub
# Actions — не root) их не удалить.
docker run --rm -v "$MOUNT:/w" -w "$steer_in" --entrypoint sh \
    -e CC="zig cc -target $target -mcpu=$mcpu" -e AR="zig ar" -e ZIG=1 \
    -e INTERP="$interp" -e STEER_EXT_APPS="${apps# }" -e STEER_EXT_ONLY=1 -e STEER_EXT_STATIC="$STATIC" "$IMAGE" -c \
    'sh build/build-libs.sh "$1" "$2" "$3"; rc=$?; rm -rf "$1/obj"; chown -R "$4" "$1"; exit $rc' _ \
    "$outd_in" "$VERSION" "$REV" "$owner"
