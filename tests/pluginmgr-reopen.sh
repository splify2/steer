#!/bin/sh
# Из корня репозитория: WOLFSSL_LIB=… sh tests/pluginmgr-reopen.sh
# Архив wolfSSL и его .cflags той же сборки, например build/wolfssl-host/libwolfssl-cc.a.
set -eu
CC=${CC:-cc}
WOLFSSL_LIB=${WOLFSSL_LIB:-build/wolfssl-host/libwolfssl-cc.a}
[ -r "$WOLFSSL_LIB" ] && [ -r "$WOLFSSL_LIB.cflags" ] || {
    echo "pluginmgr-reopen: нужны WOLFSSL_LIB и WOLFSSL_LIB.cflags" >&2
    exit 2
}
t=$(mktemp -d "${TMPDIR:-/tmp}/pm-reopen-build.XXXXXX")
trap 'rm -rf "$t"' EXIT
. build/sources.sh
inc=$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)
# shellcheck disable=SC2086
$CC -O0 -g $inc $(profile_var THIRD_DEFS) $(cat "$WOLFSSL_LIB.cflags") \
    -DSTEER_VERSION="\"$(cat VERSION)\"" -o "$t/steerd-pm" \
    $(profile_src extended) $(profile_var PLUGMGR_SRC) tests/pluginmgr-reopen-fault.c \
    -Wl,--wrap=rename "$WOLFSSL_LIB" -lpthread
python3 tests/pluginmgr-reopen.py "$t/steerd-pm"
