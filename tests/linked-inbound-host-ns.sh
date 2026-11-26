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
    "$OUT/steer-prototype-wg-netns" "$OUT/steer-prototype-inbound-fault" "$OUT/steer-prototype-inbound-pause" "$OUT/store-fault.so"
for mode in success fault shutdown disconnect not-renamed unsynced shutdown-publish foreign-shutdown; do
    binary="$OUT/steer-prototype-wg-netns"
    if [ "$mode" = fault ]; then binary="$OUT/steer-prototype-inbound-fault"; fi
    if [ "$mode" = shutdown-publish ]; then binary="$OUT/steer-prototype-inbound-pause"; fi
    unshare -n python3 -B experimental/provider/linked_inbound_host_test.py \
        "$binary" "$mode" "$OUT/store-fault.so" 3</proc/self/ns/net
done
