#!/bin/sh
# Focused transport/race gates. Query test is read-only; no device mutation.
set -eu
OUT=${1:?isolated output directory required}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT"; OUT=$(CDPATH= cd -- "$OUT" && pwd); cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
FLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) FLAGS="$FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer";; thread) FLAGS="$FLAGS -fsanitize=thread -fno-omit-frame-pointer";; 0) :;; *) exit 2;; esac
SOURCE=${AWGDEV_SOURCE:-src/kinds/awgdev.c}
# shellcheck disable=SC2086
${CC:-cc} $FLAGS @"$OUT/includes.rsp" experimental/provider/kernel_wg_query_threads_test.c "$SOURCE" \
 -pthread -Wl,--gc-sections -o "$OUT/query"
"$OUT/query"
if [ "${QUERY_ONLY:-0}" = 1 ]; then exit 0; fi
# shellcheck disable=SC2086
${CC:-cc} $FLAGS -DSTEER_AWG_NETLINK_TEST @"$OUT/includes.rsp" experimental/provider/kernel_wg_netlink_test.c "$SOURCE" \
 -Wl,--gc-sections,--wrap=malloc,--wrap=free,--wrap=poll,--wrap=__poll_chk,--wrap=clock_gettime,--wrap=sendto,--wrap=recvmsg -o "$OUT/exchange"
"$OUT/exchange"

# shellcheck disable=SC2086
${CC:-cc} $FLAGS @"$OUT/includes.rsp" experimental/provider/kernel_wg_deadline_test.c "$SOURCE" \
 -Wl,--gc-sections -o "$OUT/deadline"
"$OUT/deadline"
