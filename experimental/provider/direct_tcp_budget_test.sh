#!/bin/sh
# Local native Linux acceptance only. Source and binaries may be in private worktrees.
set -eu
test "$#" = 2
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    mount -t tmpfs tmpfs /run
    cp "$1" /run/full
    cp "$2" /run/nano
    for name in direct_tcp_budget_test prototype_test prototype_socks_outbound_test socks_loopback_test vless_loopback_test; do
        cp "$3/$name.py" /run/
    done
    cd /run
    for d in /etc /tmp /var; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        prlimit --nofile=4096:4096 env -i PATH=/usr/bin:/bin HOME=/tmp \
        python3 -Bu direct_tcp_budget_test.py /run/full /run/nano
' sh "$(realpath "$1")" "$(realpath "$2")" "$(realpath "$(dirname "$0")")"
