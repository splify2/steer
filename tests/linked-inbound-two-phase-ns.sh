#!/bin/sh
# Real store, journal and WG peer; each case runs in a new disposable netns.
set -eu
OUT=${1:?absolute isolated build directory}
SDK=${SDK:-../plugin-sdk}
PROTOCOLS=${PROTOCOLS:-../steer-protocols}
case "$OUT" in /*) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT";cd "$HERE"
SDK=$(realpath "$SDK")
PROTOCOLS=$(realpath "$PROTOCOLS")
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
${CC:-cc} $F @"$OUT/includes.rsp" -I"$SDK/include" -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L -pthread \
    experimental/provider/linked_inbound_two_phase_test.c experimental/provider/linked_inbound_participant.c \
    experimental/provider/prototype_store.c experimental/provider/kernel_wg_linux_guard.c experimental/provider/kernel_wg_linux_link.c \
    experimental/provider/kernel_wg_coordinator.c experimental/provider/kernel_wg_ownership.c experimental/provider/kernel_wg_guard.c \
    experimental/provider/kernel_wg_guard_record.c experimental/provider/policy.c experimental/spec/execution_journal.c \
    src/kinds/awgdev.c src/lib/ir.c src/lib/run.c src/lib/nftdump.c src/lib/ynode.c src/lib/err.c src/compile/print.c \
    src/third_party/libyaml/api.c src/third_party/libyaml/reader.c src/third_party/libyaml/scanner.c \
    src/third_party/libyaml/parser.c -Wl,--gc-sections,--wrap=renameat,--wrap=fsync -o "$OUT/two-phase"
make -s NANO=1 NANO_BUILD="$OUT/socks" NANO_SDK="$SDK" NANO_PROTOCOLS="$PROTOCOLS"
for mode in s n r p a u j o f m x k; do
    unshare -n python3 -B experimental/provider/linked_inbound_two_phase_test.py "$OUT/two-phase" "$mode" "$OUT/socks/steer-nano" 3</proc/self/ns/net
done
