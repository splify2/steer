#!/bin/sh
# Each invocation measures one native (libc-only) steerd in a fresh namespace.
set -eu
test "$#" = 1
bin=$(realpath "$1")
script=$(realpath "$(dirname "$0")/dns-tcpc-cost.py")
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    mount -t tmpfs tmpfs /run
    cp "$1" /run/steerd
    cp "$2" /run/measure.py
    cd /run
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu /run/measure.py
' sh "$bin" "$script"
