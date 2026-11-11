#!/bin/sh
# Серверная половина обфускации (VPS): то, что получает сервер, отвечает на obfs-server.
#
# С 2.1 команда obfs-server есть только у программы плагина obfs (src/modules/main_obfs.c), а ядро steerd
# и клиент сокета build/steer её не несут. Оба пути на VPS этого не учли: архив steer-obfs-<версия>-<арх>
# собирался из steerd-<арх>, а server/install.sh из исходников собирал `make all` и ставил build/steer —
# сервер вставал юнитом, который падал с «нет такой команды: obfs-server».
#
# Проверяется:
#   1. `make obfs-server` даёт бинарник, который отвечает на `obfs-server --help`;
#   2. server/install.sh из исходников (DESTDIR — без root и без systemd) ставит именно его: бинарник
#      под DESTDIR отвечает на obfs-server, юнит зовёт `steer obfs-server --listen … --forward …`;
#   3. собранный архив out/steer-obfs-<версия>-<арх>.tar.gz (если build.sh его собрал): состав, бинарник
#      своей архитектуры отвечает на obfs-server --help, установщик из архива берёт готовый бинарник.
set -u
cd "$(dirname "$0")/.."
BUILD="${BUILD:-build}"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
has() {
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет подстроки: %s\n  в тексте: %s\n' "$1" "$3" "$2" ;; esac
}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- 1. цель make --------------------------------------------------------------------------------
make -s BUILD="$BUILD" obfs-server >"$tmp/make.log" 2>&1
check "make obfs-server собирается" "0" "$?"
o="$("$BUILD/obfs-server" obfs-server --help 2>&1)"; rc=$?
check "build/obfs-server отвечает на obfs-server --help" "0" "$rc"
has "  справка — о сервере обфускации" "$o" "сервер обфускации"
o="$("$BUILD/obfs-server" obfs-server --listen 0 --forward 127.0.0.1:1 2>&1)"
has "  флаги obfs-server разбираются (порт 0 — отказ разбора, а не «нет команды»)" "$o" "нужно целое от 1 до 65535"

# ---- 2. установка из исходников ------------------------------------------------------------------
o="$(DESTDIR="$tmp/d1" sh server/install.sh --port 4567 --forward 127.0.0.1:51820 2>&1)"; rc=$?
check "server/install.sh из исходников (DESTDIR): код 0" "0" "$rc"
has "  собирает obfs-server, а не ядро" "$o" "собираю obfs-server"
o="$("$tmp/d1/usr/local/sbin/steer" obfs-server --help 2>&1)"
check "  поставленный steer отвечает на obfs-server --help" "0" "$?"
has "  юнит зовёт obfs-server" "$(cat "$tmp/d1/etc/systemd/system/steer-obfs.service" 2>&1)" \
    'ExecStart=/usr/local/sbin/steer obfs-server --listen ${OBFS_PORT} --forward ${OBFS_FORWARD}'
has "  настройки — порт и адрес" "$(cat "$tmp/d1/etc/default/steer-obfs" 2>&1)" "OBFS_PORT=4567"

# ---- 3. архив выпуска ----------------------------------------------------------------------------
V="$(cat VERSION)"
n=0
for a in out/steer-obfs-"$V"-*.tar.gz; do
    [ -f "$a" ] || continue
    n=$((n + 1))
    ua="${a##*-}"; ua="${ua%.tar.gz}"
    d="$tmp/a-$ua"
    mkdir -p "$d"
    tar -xzf "$a" -C "$d"
    check "$a: состав — steer, install.sh, README.md" "obfs-$ua/README.md obfs-$ua/install.sh obfs-$ua/steer" \
        "$(cd "$d" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    if [ "$(uname -m)" = "$ua" ]; then
        o="$("$d/obfs-$ua/steer" obfs-server --help 2>&1)"; rc=$?
        check "  бинарник архива отвечает на obfs-server --help" "0" "$rc"
        has "  и это сервер обфускации" "$o" "сервер обфускации"
        o="$(DESTDIR="$tmp/d-$ua" sh "$d/obfs-$ua/install.sh" 2>&1)"; rc=$?
        check "  install.sh из архива: код 0" "0" "$rc"
        has "  берёт готовый бинарник" "$o" "беру готовый бинарник"
        cmp -s "$d/obfs-$ua/steer" "$tmp/d-$ua/usr/local/sbin/steer"
        check "  и ставит его" "0" "$?"
    else
        echo "obfsserver: $a — чужая архитектура ($ua), запуск не проверен"
    fi
done
[ "$n" -gt 0 ] || echo "obfsserver: архивов out/steer-obfs-$V-*.tar.gz нет (STEER_ARCH=x86_64 sh build.sh) — часть 3 ПРОПУЩЕНА"

echo "obfsserver: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
