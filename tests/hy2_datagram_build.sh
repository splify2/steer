#!/bin/sh
# Source-only UDP adapter gate; no daemon/listener registration or deployment.
set -eu
OUT=${1:?isolated output directory required}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
cd "$HERE"
FLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror -pedantic'
if [ "${SANITIZE:-0}" = 1 ]; then FLAGS="$FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"; fi
# shellcheck disable=SC2086
${CC:-cc} $FLAGS -I../plugin-sdk/include -Iexperimental/provider -Isrc/daemon -Isrc/proto/hysteria2 -Isrc/lib \
 experimental/provider/hy2_datagram_test.c experimental/provider/hy2_datagram.c \
 experimental/provider/datagram_routes.c experimental/provider/datagram.c experimental/provider/binding_lease.c \
 experimental/provider/flow_metadata.c experimental/provider/buffers.c experimental/provider/operations.c \
 experimental/provider/resolver.c src/daemon/loop.c src/proto/hysteria2/hy2wire.c -pthread -o "$OUT/hy2-datagram"
"$OUT/hy2-datagram"
