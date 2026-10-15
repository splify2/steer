#!/bin/sh
# Ветка ChaCha20-Poly1305 для 32-битного MIPS (src/lib/scrypto.c SC_CP_OWN, poly1305_32.h с настоящими
# multu/maddu) под qemu-user: слой собирается под mipsel с wolfSSL (тот же рецепт, что у роутерной
# сборки), tests/cpmatch.c сверяет его с wolfSSL, tests/scryptomatch.c — с векторами RFC 8439.
# Не входит в make test: нужен кросс-компилятор и qemu-user.
#
#     CC='zig cc -target mipsel-linux-musl -mcpu=mips32r2+soft_float' AR='zig ar' sh tests/cpmips.sh
#     (QEMU=qemu-mipsel-static; STEER_WOLFSSL=<исходники wolfSSL>; BUILD=<каталог>; для mips (big-endian)
#      — цель mips-linux-musl и QEMU=qemu-mips-static)
#
# Нет компилятора или qemu — громкий пропуск (выход 0), как у ext-test.sh.
set -e
CC=${CC:-}
QEMU=${QEMU:-qemu-mipsel-static}
BUILD=${BUILD:-build/cpmips}
WSRC="${STEER_WOLFSSL:-build/wolfssl-host/src}"
[ -n "$CC" ] && command -v "$QEMU" >/dev/null 2>&1 && [ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || {
    echo "cpmips: нужны CC (кросс-компилятор под MIPS), $QEMU и исходники wolfSSL ($WSRC) — ПРОПУСК (это не падение)."
    exit 0
}
. build/sources.sh
STEER_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
mkdir -p "$BUILD"
WLIB="$BUILD/libwolfssl.a"
CC="$CC" AR="${AR:-ar}" CFLAGS="-O2 -g" STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DSTEER_WOLFSSL_SERVER" \
    sh build/wolfssl/build.sh "$WSRC" "$WLIB" asm
WCFLAGS=$(cat "$WLIB.cflags")
# shellcheck disable=SC2086
$CC -O2 -g -w $STEER_INC $WCFLAGS -c src/lib/scrypto.c -o "$BUILD/scrypto.o"
# shellcheck disable=SC2086
$CC -O2 -g -w $STEER_INC $WCFLAGS -Isrc/lib -static -o "$BUILD/cpmatch" tests/cpmatch.c "$BUILD/scrypto.o" "$WLIB" -lpthread
# shellcheck disable=SC2086
$CC -O2 -g -w $STEER_INC -Itests -static -o "$BUILD/scryptomatch" tests/scryptomatch.c "$BUILD/scrypto.o" "$WLIB" -lpthread
echo "cpmips: прогоняю под $QEMU..."
"$QEMU" "$BUILD/cpmatch"
"$QEMU" "$BUILD/scryptomatch"
