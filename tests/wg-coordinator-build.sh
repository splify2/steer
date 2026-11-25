#!/bin/sh
# Builds/runs only the injected offline lifecycle; no nft, IP or WG commands.
set -eu
OUT=${1:?absolute isolated build directory}
case "$OUT" in /*) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT"
cd "$HERE"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) F="$F -fsanitize=address,undefined -fno-omit-frame-pointer";;0) :;;*) exit 2;;esac
${CC:-cc} $F -I../plugin-sdk/include -Isrc/kinds -Isrc/lib \
    experimental/provider/kernel_wg_coordinator_test.c experimental/provider/kernel_wg_coordinator.c \
    experimental/provider/kernel_wg_guard_record.c experimental/provider/kernel_wg_ownership.c \
    experimental/spec/execution_journal.c -Wl,--gc-sections,--wrap=fsync -o "$OUT/wg-coordinator"
cd "$OUT"
state=$(mktemp -d "$OUT/wg-journal.XXXXXX")
trap 'rm -rf -- "$state"' EXIT
"$OUT/wg-coordinator" "$state"
