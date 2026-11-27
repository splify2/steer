#!/bin/sh
# Проверка восстановления подписанной файловой группы.
# Из корня: sh tests/pluginmgr-file-group.sh /путь/к/steerd-с-pluginmgr [каталог-библиотек]
# Нужны Linux unshare/mount/setpriv, cc, python3-cryptography и нативный
# динамически связанный с libc steerd. Для раскладки build-libs на glibc
# второй аргумент задаёт точный набор .so (в том числе для смешанной пары).
set -eu
bin=$(realpath "${1:?нужен исполняемый steerd}") && test -x "$bin"
libs=""
if [ "$#" -eq 2 ]; then libs=$(realpath "$2"); fi
src=$(cd "$(dirname "$0")" && pwd)
exec unshare --mount --propagation private --net --pid --fork --mount-proc sh -ec '
    mount -t tmpfs tmpfs /run
    cd /run
    cp "$1" steerd
    cp "$2/pluginmgr-file-cut.c" "$2/pluginmgr-file-group.py" .
    if [ -n "$3" ]; then
        mkdir /run/group-libs
        cp "$3"/libsteer.so.* "$3"/libsteer-wolfssl.so.* "$3"/libsteer-ngtcp2.so.* /run/group-libs/
    fi
    mount -t tmpfs tmpfs /tmp
    chmod 1777 /tmp
    cc -Wall -Wextra -Werror -shared -fPIC pluginmgr-file-cut.c -ldl -o cut.so
    for d in /etc /var; do mount -t tmpfs tmpfs "$d"; done
    if [ -n "$3" ]; then
        # Свой cache в private /etc: даже дочерний daemon с чистым окружением
        # видит тот же комплект. Убедиться, что каждый SONAME разрешён именно туда.
        ldconfig -X -f /dev/null /run/group-libs
        loaded=$(env -i LD_TRACE_LOADED_OBJECTS=1 /run/steerd)
        for so in /run/group-libs/*; do
            echo "$loaded" | grep -F "${so##*/} => $so ("
        done
    fi
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu /run/pluginmgr-file-group.py
' sh "$bin" "$src" "$libs"
