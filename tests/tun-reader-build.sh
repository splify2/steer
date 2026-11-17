#!/bin/sh
set -eu
OUT=${1:?isolated output directory}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT";cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) F="$F -fsanitize=address,undefined -fno-omit-frame-pointer";;thread) F="$F -fsanitize=thread -fno-omit-frame-pointer";;0) :;;*) exit 2;;esac
${CC:-cc} $F "-DSTEER_READER_STACK_SOURCE=\"${STACK_SOURCE:-../src/tunnel/stack.c}\"" @"$OUT/includes.rsp" tests/tunreadermatch.c src/tunnel/tun.c -pthread -Wl,--gc-sections -o "$OUT/reader"
"$OUT/reader"
