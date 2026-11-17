#!/bin/sh
# Builds kernel ownership test; network mutations only with explicit namespace gate.
set -eu
OUT=${1:?isolated output directory}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT"; cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) F="$F -fsanitize=address,undefined -fno-omit-frame-pointer";;thread) F="$F -fsanitize=thread -fno-omit-frame-pointer";;0) :;;*) exit 2;;esac
${CC:-cc} $F @"$OUT/includes.rsp" experimental/provider/kernel_wg_owned_test.c src/kinds/awgdev.c -Wl,--gc-sections -o "$OUT/owned"
"$OUT/owned" --wire
${CC:-cc} $F @"$OUT/includes.rsp" -I../plugin-sdk/include -pthread experimental/provider/kernel_wg_ownership_test.c experimental/provider/kernel_wg_ownership.c src/kinds/awgdev.c -Wl,--gc-sections,--wrap=awg_dev_link_create_owned_until,--wrap=awg_dev_link_delete_owned_until -o "$OUT/recovery"
"$OUT/recovery" --record
${CC:-cc} $F @"$OUT/includes.rsp" -I../plugin-sdk/include -pthread experimental/provider/kernel_wg_config_owned_test.c experimental/provider/kernel_wg_ownership.c src/kinds/awgdev.c -Wl,--gc-sections,--wrap=malloc,--wrap=free -o "$OUT/config"
"$OUT/config" --wire
