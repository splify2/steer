#!/bin/sh
set -eu
CC=${CC:-cc}
cd "$(dirname "$0")/.."
WSRC=${1:?source}; WLIB=${2:?PIC archive}; NGLIB=${3:?ngtcp2}; OUT=${4:?output}
mkdir -p "$OUT"
WF=$(cat "$WLIB.cflags"); NF=$(cat "$NGLIB.cflags")
F='-O1 -g -fPIC -fsanitize=thread -fno-omit-frame-pointer -pthread'
find src -type d -print | sed 's|.*|"-I&"|' > "$OUT/includes.rsp"
$CC $F $WF -c "$WSRC/src/ssl.c" -o "$OUT/ssl.o"
cp "$WLIB" "$OUT/backend.a"
ar d "$OUT/backend.a" src_ssl.c.o
$CC $F -shared "$OUT/ssl.o" -Wl,--whole-archive "$OUT/backend.a" -Wl,--no-whole-archive -Wl,--version-script=build/wolfssl/libsteer-wolfssl.map -lm -o "$OUT/libbackend.so"
printf '%s\n' '{ global: qcssl_ctx_client; qcssl_ctx_server; qcssl_ctx_free; local: *; };' > "$OUT/qc.map"
printf '%s\n' '{ global: sc_roots_load_der; sc_roots_free; local: *; };' > "$OUT/roots.map"
$CC $F $WF $NF -Ibuild/wolfssl @"$OUT/includes.rsp" -DQC_WITH_SERVER -ffunction-sections -fdata-sections -shared src/proto/quic/qcssl.c "$NGLIB" -L"$OUT" -lbackend -Wl,-rpath,'$ORIGIN',--gc-sections,--version-script="$OUT/qc.map" -o "$OUT/libqc.so"
$CC $F $WF -Ibuild/wolfssl @"$OUT/includes.rsp" -shared -ffunction-sections -fdata-sections src/lib/scrypto.c -L"$OUT" -lbackend -Wl,-rpath,'$ORIGIN',--gc-sections,--version-script="$OUT/roots.map" -o "$OUT/libroots.so"
$CC $F -std=c11 @"$OUT/includes.rsp" -Itests -DQC_WITH_SERVER tests/cryptocoldmatch.c -L"$OUT" -lqc -lroots -lbackend -Wl,-rpath,'$ORIGIN' -o "$OUT/cold"
i=0
while [ "$i" -lt "${RUNS:-10}" ]; do LD_BIND_NOW=1 "$OUT/cold"; i=$((i+1)); done
# Symbol-retention probe only; old manifests remain incompatible with axis2.0.
printf '%s\n' 'int wolfSSL_Init(void); int main(void) { return wolfSSL_Init()==1 ? 0 : 1; }' > "$OUT/old-symbol.c"
$CC $F "$OUT/old-symbol.c" -L"$OUT" -lbackend -Wl,-rpath,'$ORIGIN' -o "$OUT/old-symbol"
LD_BIND_NOW=1 "$OUT/old-symbol"
