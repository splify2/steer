#!/bin/sh
# Instrument pinned ssl.c too: normal archive-only TSan misses its init counter.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WSRC=${1:?pinned wolfSSL source required}
WLIB=${2:?wolfSSL archive required}
NGLIB=${3:?ngtcp2 archive required}
OUT=${4:?isolated output directory required}
CC=${CC:-cc}
mkdir -p "$OUT"
cd "$HERE"
WFLAGS=$(cat "$WLIB.cflags")
NGFLAGS=$(cat "$NGLIB.cflags")
SAN=${SANITIZE:-thread}
FLAGS="-O1 -g -fPIC -fsanitize=$SAN -fno-omit-frame-pointer -pthread"
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
# Replace precisely ssl.o with the instrumented pinned source. Other dependency
# objects are not instrumented; this gate does not claim full-library race proof.
$CC $FLAGS $WFLAGS -c "$WSRC/src/ssl.c" -o "$OUT/ssl.o"
$CC $FLAGS -std=c11 $WFLAGS $NGFLAGS -Ibuild/wolfssl @"$OUT/includes.rsp" \
    -Itests -DQC_WITH_SERVER -ffunction-sections -fdata-sections -Wl,--gc-sections \
    tests/cryptocoldmatch.c src/proto/quic/qcssl.c src/lib/scrypto.c \
    "$OUT/ssl.o" "$NGLIB" "$WLIB" -lm -o "$OUT/cold"
i=0
while [ "$i" -lt "${RUNS:-10}" ]; do
    "$OUT/cold"
    i=$((i+1))
done

$CC $FLAGS -std=c11 $WFLAGS -Ibuild/wolfssl tests/cryptoinitfailure.c \
    build/wolfssl/steer_init.c -Wl,--wrap=wolfSSL_Init -o "$OUT/failure"
"$OUT/failure"
