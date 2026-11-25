#!/bin/sh
# Default is compilation and a refusal check. Real WG requires --netns.
set -eu
OUT=${1:?absolute isolated build directory}
case "$OUT" in /*) ;; *) exit 2;; esac
case "${2:-}" in ""|--netns) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT"
cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) F="$F -fsanitize=address,undefined -fno-omit-frame-pointer";;0) :;;*) exit 2;;esac
${CC:-cc} $F @"$OUT/includes.rsp" -I../plugin-sdk/include \
    experimental/provider/kernel_wg_linux_link_test.c experimental/provider/kernel_wg_linux_link.c \
    experimental/provider/kernel_wg_coordinator.c experimental/provider/kernel_wg_guard_record.c \
    experimental/provider/kernel_wg_ownership.c experimental/spec/execution_journal.c \
    src/kinds/awgdev.c -Wl,--gc-sections -o "$OUT/wg-linux-link"
cd "$OUT"
"$OUT/wg-linux-link" --check-boundary
if [ "${2:-}" = --netns ]; then
    state=$(mktemp -d "$OUT/wg-link-journal.XXXXXX")
    trap 'rm -rf -- "$state"' EXIT
    unshare -n -- "$OUT/wg-linux-link" "$state" 3</proc/self/ns/net
fi
