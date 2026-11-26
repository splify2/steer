#!/bin/sh
set -eu
OUT=${1:?absolute build directory required}
SDK=${SDK:-../plugin-sdk}
PROTOCOLS=${PROTOCOLS:-../steer-protocols}
case "$OUT" in /*) ;; *) exit 2;; esac
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$HERE"
SDK=$(realpath "$SDK")
PROTOCOLS=$(realpath "$PROTOCOLS")
make -s -C experimental/provider BUILD="$OUT" SDK="$SDK" PROTOCOLS="$PROTOCOLS" \
    "$OUT/steer-prototype-wg-netns" "$OUT/store-fault.so"
for mode in normal restarted not-renamed unsynced foreign cleanup postcommit-foreign disconnect shutdown; do
    unshare -n python3 -B experimental/provider/linked_inbound_remove_test.py \
        "$OUT/steer-prototype-wg-netns" "$mode" "$OUT/store-fault.so" 3</proc/self/ns/net
done
