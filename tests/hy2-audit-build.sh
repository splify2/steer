#!/bin/sh
# Isolated source regression build. Dependencies must be verified beforehand.
set -eu
NGLIB=${1:?ngtcp2 archive required}
WLIB=${2:?server-enabled wolfSSL archive required}
OUT=${3:?isolated output directory required}
CC=${CC:-cc}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
cd "$HERE"
[ -r "$NGLIB.cflags" ] && [ -r "$WLIB.cflags" ]
grep -q -- '-DSTEER_WOLFSSL_SERVER' "$WLIB.cflags"
grep -q -- '-DWOLFSSL_VALIDATE_ECC_IMPORT' "$WLIB.cflags"
grep -Eq -- '(^|[[:space:]])-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1([[:space:]]|$)' "$WLIB.cflags"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
NGFLAGS=$(cat "$NGLIB.cflags")
WFLAGS=$(cat "$WLIB.cflags")
FLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror'
if [ "${SANITIZE:-0}" = 1 ]; then FLAGS="$FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"; fi
# shellcheck disable=SC2086
$CC $FLAGS -Isrc/proto/hysteria2 tests/hy2rasmbudget.c src/proto/hysteria2/hy2wire.c \
    -pthread -Wl,--wrap=malloc,--wrap=calloc -o "$OUT/hy2rasmbudget"
"$OUT/hy2rasmbudget"
for test in hy2respmatch hy2finmatch; do
    # Flags come only from the repository dependency build recipes.
    # shellcheck disable=SC2086
    $CC $FLAGS $NGFLAGS $WFLAGS @"$OUT/includes.rsp" -Itests \
        -ffunction-sections -fdata-sections -Wl,--gc-sections \
        -DQC_WITH_SERVER -DSTEER_HY2_RESPONSE_TEST \
        "tests/$test.c" src/proto/hysteria2/hy2conn.c src/proto/hysteria2/hy2wire.c \
        src/proto/quic/quic.c src/proto/quic/qcssl.c "$NGLIB" "$WLIB" -lpthread -lm -o "$OUT/$test"
    "$OUT/$test"
done
# shellcheck disable=SC2086
$CC $FLAGS $NGFLAGS $WFLAGS @"$OUT/includes.rsp" -Itests -DQC_WITH_SERVER \
    tests/qcloop.c src/proto/quic/quic.c src/proto/quic/qcssl.c "$NGLIB" "$WLIB" -lpthread -lm -o "$OUT/qcloop"
"$OUT/qcloop"
