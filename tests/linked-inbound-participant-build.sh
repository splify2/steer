#!/bin/sh
# Compile and run an isolated fake-kernel transaction test; no network changes.
set -eu
OUT=${1:?absolute build directory}
SDK=${SDK:-../plugin-sdk}
case "$OUT" in /*) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$OUT"
cd "$HERE"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
${CC:-cc} -O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    @"$OUT/includes.rsp" -I"$SDK/include" -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L -pthread \
    experimental/provider/linked_inbound_participant_test.c experimental/provider/linked_inbound_participant.c \
    experimental/provider/prototype_store.c \
    experimental/provider/kernel_wg_coordinator.c experimental/provider/kernel_wg_guard_record.c \
    experimental/provider/kernel_wg_ownership.c experimental/provider/kernel_wg_guard.c experimental/provider/policy.c \
    experimental/spec/execution_journal.c src/kinds/awgdev.c src/lib/ir.c src/lib/run.c src/lib/nftdump.c \
    src/lib/ynode.c src/lib/err.c src/compile/print.c src/third_party/libyaml/api.c \
    src/third_party/libyaml/reader.c src/third_party/libyaml/scanner.c src/third_party/libyaml/parser.c \
    -Wl,--gc-sections,--wrap=fsync -o "$OUT/participant"
state=$(mktemp -d "$OUT/state.XXXXXX")
"$OUT/participant" "$state"
