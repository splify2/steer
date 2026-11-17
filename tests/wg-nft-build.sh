#!/bin/sh
# Read-only nft worker transport gate; kernel query needs explicit disposable ns.
set -eu
OUT=${1:?isolated output directory}
HERE=${STEER_SOURCE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
mkdir -p "$OUT";cd "$HERE"
F='-O1 -g -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections'
case "${SANITIZE:-0}" in address) F="$F -fsanitize=address,undefined -fno-omit-frame-pointer";;thread) F="$F -fsanitize=thread -fno-omit-frame-pointer";;0) :;;*) exit 2;;esac
${CC:-cc} $F -Isrc/lib experimental/provider/kernel_wg_nft_query_test.c src/lib/nftdump.c -pthread -Wl,--gc-sections -o "$OUT/query"
${CC:-cc} $F -Isrc/lib -Isrc/kinds -DSTEER_NFD_NETLINK_TEST -DSTEER_NETLINK_TEST_EXCHANGE=steer_nfd_netlink_test_exchange experimental/provider/kernel_wg_netlink_test.c src/lib/nftdump.c -Wl,--gc-sections,--wrap=malloc,--wrap=free,--wrap=poll,--wrap=__poll_chk,--wrap=clock_gettime,--wrap=sendto,--wrap=recvmsg -o "$OUT/exchange"
"$OUT/exchange"
