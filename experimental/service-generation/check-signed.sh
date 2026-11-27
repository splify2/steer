#!/bin/sh
# UI checkout at 6195d89 with sibling steer and plugin-sdk, s2p, steerd libs.
set -eu
test "$#" -eq 3
ui=$(realpath "$1")
test "$(git -C "$ui" rev-parse HEAD)" = 6195d89589f347c15538c64fb2179cafdd9f7225
test -z "$(git -C "$ui" status --porcelain --untracked-files=no)"
src=$(cd "$(dirname "$0")" && pwd)
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    umask 022
    mount -t tmpfs tmpfs /run
    mkdir -m 755 /run/e4 /run/e4/feed
    cd /run/e4
    make -s -C "$1" BUILD=/run/e4/build NANO=0 LDFLAGS=-static service-host
    mkdir -p pkg/bin pkg/licenses
    cp build/steer-ui-service pkg/bin/
    sha256sum pkg/bin/steer-ui-service | cut -d" " -f1 > host.sha256
    cp -R "$1/assets" "$1/LICENSE" "$1/experimental/linux-s2p/plugin.json" pkg/
    cp "$1/../steer/src/third_party/libyaml/LICENSE" pkg/licenses/libyaml.txt
    cp "$2" s2p
    cp "$3"/steerd "$3"/libsteer*.so.* "$4"/controller.py "$4"/signed.py "$4"/check_signed.py .
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    ldconfig -X -f /dev/null /run/e4
    python3 -B check_signed.py fixtures
    rm -r build pkg
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu check_signed.py
' sh "$ui" "$(realpath "$2")" "$(realpath "$3")" "$src"
