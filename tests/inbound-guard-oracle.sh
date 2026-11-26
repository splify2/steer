#!/bin/sh
# Build and test only in a new disposable network namespace; no host mutation.
set -eu
OUT=${1:?absolute isolated build directory}
SDK=${SDK:-../plugin-sdk}
case "$OUT" in /*) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT"
cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
${CC:-cc} -O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    @"$OUT/includes.rsp" -I"$SDK/include" -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L -pthread \
    experimental/provider/inbound_guard_oracle_fixture.c experimental/provider/kernel_wg_ownership.c \
    experimental/provider/kernel_wg_guard.c experimental/provider/kernel_wg_guard_record.c experimental/provider/policy.c \
    src/kinds/awgdev.c src/lib/ir.c src/lib/run.c src/lib/nftdump.c src/lib/ynode.c src/lib/err.c src/compile/print.c \
    src/third_party/libyaml/api.c src/third_party/libyaml/reader.c src/third_party/libyaml/scanner.c \
    src/third_party/libyaml/parser.c -Wl,--gc-sections -o "$OUT/fixture"
unshare -n python3 -B experimental/provider/inbound_guard_oracle_test.py "$OUT/fixture" 3</proc/self/ns/net
