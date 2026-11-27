#!/bin/sh
# Inputs: 6195d89 make service-host output, matching assets, shared build of steerd.
set -eu
test "$#" -eq 3
src=$(cd "$(dirname "$0")" && pwd)
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    mount -t tmpfs tmpfs /run
    mkdir -m 755 /run/e4
    cp "$1" /run/e4/host
    cp -r "$2" /run/e4/assets
    cp "$3"/steerd "$3"/libsteer*.so.* "$4"/controller.py "$4"/check.py /run/e4/
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    ldconfig -X -f /dev/null /run/e4
    cd /run/e4
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu check.py
' sh "$(realpath "$1")" "$(realpath "$2")" "$(realpath "$3")" "$src"
