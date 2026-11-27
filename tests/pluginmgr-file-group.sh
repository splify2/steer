#!/bin/sh
# Проверка восстановления подписанной файловой группы.
# Из корня: sh tests/pluginmgr-file-group.sh /путь/к/steerd-с-pluginmgr
# Нужны Linux unshare/mount/setpriv, cc, python3-cryptography и нативный
# динамически связанный с libc steerd (extended + PLUGMGR_SRC + wolfSSL).
set -eu
bin=$(realpath "${1:?нужен исполняемый steerd}") && test -x "$bin"
src=$(cd "$(dirname "$0")" && pwd)
exec unshare --mount --propagation private --net --pid --fork --mount-proc sh -ec '
    mount -t tmpfs tmpfs /run
    cd /run
    cp "$1" steerd
    cp "$2/pluginmgr-file-cut.c" "$2/pluginmgr-file-group.py" .
    mount -t tmpfs tmpfs /tmp
    chmod 1777 /tmp
    cc -Wall -Wextra -Werror -shared -fPIC pluginmgr-file-cut.c -ldl -o cut.so
    for d in /etc /var; do mount -t tmpfs tmpfs "$d"; done
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu /run/pluginmgr-file-group.py
' sh "$bin" "$src"
