#!/bin/sh
# Дампы ядра по netlink (src/lib/rtnl.c) на больших таблицах — в своём сетевом пространстве.
#
# Раньше дампы шли в буферы по 8-16 КиБ и на 256-записные массивы, и больший дамп молча
# обрезался, возвращая успех: сверка сторожа читала неполное состояние (I-525). Здесь на
# устройстве d0 ставится 700 правил и маршрутов каждого семейства, 300 нуль-маршрутов IPv6 в
# main и 300 адресов; инструмент build/rtnl-tool обязан отдать их все, а сброс таблицы — снять
# все маршруты.
# Нужны ip и unshare (root: unshare -n; не root: unshare -Urn); без них — пропуск.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="${RTNL_TOOL:-$ROOT/build/rtnl-tool}"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
skip() { echo "rtnlmatch: $1 — пропуск"; exit 0; }
if [ ! -x "$TOOL" ]; then
    (cd "$ROOT" && cc $(make -s print-inc) -O2 -Wall -Wextra -o "$TOOL" tests/rtnl-tool.c \
        src/lib/rtnl.c) || { echo "rtnlmatch: инструмент не собрался"; exit 1; }
fi
command -v ip >/dev/null 2>&1 || skip "ip нет"
if [ "${RTNL_INNER:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ]; then ns="unshare -n"; else ns="unshare -Urn"; fi
    $ns true 2>/dev/null || skip "unshare недоступен"
    RTNL_INNER=1 exec $ns sh "$0" "$@"
fi
ip link set lo up
ip link add d0 type dummy 2>/dev/null || skip "dummy недоступен"
ip link set d0 up
T() { "$TOOL" "$@"; }

# Пакетом через `ip -batch`: семь сотен вызовов ip по одному стенд бы растянули. Семейство —
# ключом самого ip, в пакете `-6` не принимается, поэтому два файла.
b4="${TMPDIR:-/tmp}/rtnlmatch.$$.4" b6="${TMPDIR:-/tmp}/rtnlmatch.$$.6"
trap 'rm -f "$b4" "$b6"' EXIT
i=1
while [ $i -le 700 ]; do
    echo "route add 10.$((i / 250)).$((i % 250)).0/24 dev d0 table 200"
    echo "rule add fwmark $i table 200 priority $((1000 + i))"
    i=$((i + 1))
done > "$b4"
i=1
while [ $i -le 700 ]; do
    echo "route add 2001:db8:$i::/48 dev d0 table 200"
    echo "rule add fwmark $i table 200 priority $((1000 + i))"
    i=$((i + 1))
done > "$b6"
i=1
while [ $i -le 300 ]; do
    echo "route add unreachable 2001:db9:$i::/48"
    echo "addr add 2001:db8:ffff::$i/128 dev d0 nodad"
    i=$((i + 1))
done >> "$b6"
ip -force -batch "$b4" >/dev/null 2>&1
ip -6 -force -batch "$b6" >/dev/null 2>&1

check "маршруты IPv4: 700 строк (дамп больше 16 КиБ)" "700" "$(T routes 4 200)"
check "маршруты IPv6: 700 строк" "700" "$(T routes 6 200)"
check "правила IPv4: 700 наших и три ядерных" "703" "$(T rules 4)"
check "правила IPv6: 700 наших и два ядерных" "702" "$(T rules 6)"
n="$(ip -6 route show table main | grep -c '^unreachable 2001:db9:')"
check "нуль-маршрутов IPv6 в main поставлено 300" "300" "$n"
check "rtnl_main6_routes: все 300 (было не больше 256)" "300" "$(T main6)"
a="$(ip -6 addr show dev d0 | grep -c 'inet6 2001:db8:ffff::')"
check "адресов на d0 поставлено 300" "300" "$a"
check "rtnl_addrs6: не меньше 300 (было не больше 256)" "1" "$([ "$(T addrs6)" -ge 300 ] && echo 1 || echo 0)"
check "сброс таблицы: код 0" "0" "$(T flush 200)"
check "… в таблице IPv4 пусто" "0" "$(T routes 4 200)"
check "… в таблице IPv6 700 маршрутов остались (сброс — семейства IPv4)" "700" "$(T routes 6 200)"

echo "rtnlmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
