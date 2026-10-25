#!/bin/sh
# Версия steer-abi этого ядра (контракт .so-плагинов, docs плагинов: steer-abi.md) — «major.minor».
# Единственный источник — STEER_ABI_MAJOR и STEER_ABI_MINOR в src/daemon/plugabi.h (копии
# include/steer/plugin.h из plugin-sdk); build.sh кладёт её в steer-core файлом usr/share/steer/steer-abi, чтобы менеджер
# плагинов и пакетный менеджер сверяли тег compat.steer-abi, не запуская steerd.
set -eu
H="$(dirname "$0")/../src/daemon/plugabi.h"
maj="$(sed -n 's/^#define STEER_ABI_MAJOR[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$H")"
min="$(sed -n 's/^#define STEER_ABI_MINOR[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$H")"
[ -n "$maj" ] && [ -n "$min" ] || { echo "abi.sh: в $H нет STEER_ABI_MAJOR/MINOR" >&2; exit 1; }
printf '%s.%s\n' "$maj" "$min"
