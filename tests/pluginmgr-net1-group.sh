#!/bin/sh
# Linux x86_64/glibc: A и B (реальные ELF), SDK, s2p и проверяемый build-libs.
set -eu
test "$#" -eq 5
here=$(cd "$(dirname "$0")" && pwd)
exec unshare --mount --propagation private --net --pid --fork --mount-proc sh -ec '
    mount -t tmpfs tmpfs /run
    (cd "$5/.."; . build/sources.sh
     cc -shared -fPIC -Wall -Wextra -Werror $(for d in $(profile_var INC_DIRS); do echo "-I$d"; done) \
        -o /run/fingerprint.so tests/pluginmgr-net1-fingerprint.c -ldl)
    cd /run
    cp "$6"/steerd "$6"/libsteer*.so.* .
    cp "$4" s2p
    cp "$5/pluginmgr-net1-audit.c" "$5/pluginmgr-net1-group.py" .
    cp "$5/pluginmgr-file-cut.c" .
    for g in A B; do
        case "$g" in A) d=$1;; B) d=$2;; esac
        mkdir "$g"
        cp "$d/plugins/net1/lib/libs2p-net.so.1" "$d/plugins/vless/bin/vless" "$g/"
    done
    sdk=fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd
    for p in examples/net1/plugin.json examples/vless/plugin.json examples/vless/kinds/vless.schema.json; do
        mkdir -p "$(dirname "$p")"
        git -C "$3" show "$sdk:$p" > "$p"
    done
    mount -t tmpfs tmpfs /tmp
    chmod 1777 /tmp
    cc -shared -fPIC -Wall -Wextra -Werror -o cut.so pluginmgr-file-cut.c -ldl
    cc -shared -fPIC -Wall -Wextra -Werror -o audit.so pluginmgr-net1-audit.c
    for d in /etc /var; do mount -t tmpfs tmpfs "$d"; done
    ldconfig -X -f /dev/null /run
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu pluginmgr-net1-group.py
' sh "$(realpath "$1")" "$(realpath "$2")" "$(realpath "$3")" "$(realpath "$4")" "$here" "$(realpath "$5")"
