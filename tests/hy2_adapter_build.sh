#!/bin/sh
# Disposable adapter fixture, explicitly excluded from product source lists.
set -eu
NGLIB=${1:?ngtcp2 archive required}
WLIB=${2:?server-enabled wolfSSL archive required}
OUT=${3:?isolated output directory required}
CC=${CC:-cc}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
cd "$HERE"
grep -q -- '-DSTEER_WOLFSSL_SERVER' "$WLIB.cflags"
grep -q -- '-DWOLFSSL_VALIDATE_ECC_IMPORT' "$WLIB.cflags"
grep -Eq -- '(^|[[:space:]])-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1([[:space:]]|$)' "$WLIB.cflags"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
NGFLAGS=$(cat "$NGLIB.cflags")
WFLAGS=$(cat "$WLIB.cflags")
FLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror'
if [ "${SANITIZE:-0}" = 1 ]; then FLAGS="$FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"; fi
# shellcheck disable=SC2086
$CC $FLAGS $NGFLAGS $WFLAGS @"$OUT/includes.rsp" -Itests -DQC_WITH_ENDPOINT \
    -Iexperimental/provider -I../plugin-sdk/include -I../steer-protocols/src -I../steer-protocols/src/hysteria2 \
    experimental/provider/hy2_adapter_lab.c experimental/provider/hy2_inbound.c \
    experimental/provider/hy2_datagram.c experimental/provider/flow_metadata.c src/proto/hysteria2/hy2wire.c \
    experimental/provider/stream.c experimental/provider/buffers.c \
    experimental/provider/operations.c experimental/provider/route_dial.c \
    experimental/provider/resolver.c src/daemon/loop.c \
    ../steer-protocols/src/hysteria2/server.c ../steer-protocols/src/hysteria2/auth.c \
    ../steer-protocols/src/hysteria2/inbound.c src/proto/quic/quic.c src/proto/quic/qcssl.c \
    "$NGLIB" "$WLIB" -Wl,--wrap=steer_draft_route_dial -lpthread -lm -o "$OUT/hy2-adapter"
