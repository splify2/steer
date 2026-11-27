#!/bin/sh
# x86_64/glibc, cpus 0,1; three shared build directories, ELF A, ELF B, SDK, optional mode.
set -eu
test "$#" -eq 6 || test "$#" -eq 7
mode=${7:-main}
case $mode in main|stream|native) ;; *) exit 2;; esac
src=$(cd "$(dirname "$0")" && pwd)
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    mount -t tmpfs tmpfs /run
    cd /run
    cp "$7/pluginmgr-install-cost.py" .
    gcc -O2 -Wall -Wextra -Werror "$7/pluginmgr-cost-meter.c" -pthread -o meter
    gcc -O2 -Wall -Wextra -Werror -shared -fPIC "$7/pluginmgr-file-cut.c" -ldl -o cut.so
    for ver in v214 file core; do
        case $ver in v214) d=$1;; file) d=$2;; core) d=$3;; esac
        mkdir "$ver"
        cp "$d/steerd" "$d"/libsteer.so.* "$ver/"
    done
    mkdir native crypto volume
    cp "$1"/libsteer-*.so.* native/
    cp "$3"/libsteer-*.so.* crypto/
    for k in A B; do
        case $k in A) d=$4;; B) d=$5;; esac
        mkdir "$k"
        cp "$d/plugins/net1/lib/libs2p-net.so.1" "$d/plugins/vless/bin/vless" "$k/"
    done
    for p in examples/net1/plugin.json examples/vless/plugin.json examples/vless/kinds/vless.schema.json; do
        mkdir -p "$(dirname "$p")"
        git -C "$6" show "fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd:$p" >"$p"
    done
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    mount -t tmpfs -o size=512m,noatime,uid=65534,gid=65534 tmpfs /run/volume
    ldconfig -X -f /dev/null /run/crypto
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu /run/pluginmgr-install-cost.py "$8"
' sh "$(realpath "$1")" "$(realpath "$2")" "$(realpath "$3")" \
     "$(realpath "$4")" "$(realpath "$5")" "$(realpath "$6")" "$src" "$mode"
