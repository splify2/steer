#!/bin/sh
# @wan_dev на лету (src/daemon/wandev.c): демон переписывает набор wan_dev таблицы steer по событию
# rtnetlink о маршруте по умолчанию таблицы main — без apply и reload.
#
# В своём сетевом пространстве: устройства d0 и d1, набор wan_dev с «d0», демон без спеки.
#  1. маршрут по умолчанию переехал на d1 — в наборе d1;
#  2. добавился маршрут IPv6 через d0 — в наборе оба;
#  3. маршрутов нет — набор пуст;
#  4. маршрут в чужой таблице (как у выхода) набор не трогает.
# Нужны root (или sudo -n), unshare и nft; без них — пропуск.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${STEER:-$ROOT/build/steer}"
if [ "${WANDEV_INNER:-}" != 1 ]; then
    command -v nft >/dev/null 2>&1 || { echo "wandevmatch: нет nft — пропускаю"; exit 0; }
    if [ "$(id -u)" = 0 ]; then WANDEV_INNER=1 exec unshare -n sh "$0" "$@"; fi
    sudo -n true 2>/dev/null || { echo "wandevmatch: нужен root или sudo -n — пропускаю"; exit 0; }
    exec sudo -n env WANDEV_INNER=1 STEER="$BIN" unshare -n sh "$0" "$@"
fi
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
tmp="$(mktemp -d)"
D=""
trap 'kill $D 2>/dev/null; wait $D 2>/dev/null; rm -rf "$tmp"' EXIT
set_of() { nft -j list set inet steer wan_dev | python3 -c 'import json,sys
s=[x["set"] for x in json.load(sys.stdin)["nftables"] if "set" in x][0]
print(" ".join(sorted(s.get("elem",[]))))'; }
wait_set() {
    i=0
    while [ $i -lt 30 ]; do [ "$(set_of)" = "$1" ] && return 0; sleep 0.1; i=$((i + 1)); done
}
ip link set lo up
ip link add d0 type dummy && ip link add d1 type dummy && ip link set d0 up && ip link set d1 up
ip addr add 10.1.0.2/24 dev d0 && ip addr add 10.2.0.2/24 dev d1
ip -6 addr add fd00::2/64 dev d0 nodad
ip route add default via 10.1.0.1 dev d0
nft -f - <<N
table inet steer { set wan_dev { type ifname; elements = { "d0" }; }; }
N
LD_LIBRARY_PATH="$(dirname "$BIN")" "$BIN" daemon --socket "$tmp/s.sock" --state-dir "$tmp/st" >"$tmp/out" 2>"$tmp/err" &
D=$!
i=0; while [ $i -lt 50 ] && [ ! -S "$tmp/s.sock" ]; do sleep 0.1; i=$((i + 1)); done

ip route replace default via 10.2.0.1 dev d1; wait_set d1
check "1. маршрут по умолчанию на d1 — набор d1" "d1" "$(set_of)"
ip -6 route add default via fd00::1 dev d0; wait_set "d0 d1"
check "2. плюс IPv6 через d0 — оба" "d0 d1" "$(set_of)"
ip route del default; ip -6 route del default; wait_set ""
check "3. маршрутов нет — набор пуст" "" "$(set_of)"
ip route add default via 10.2.0.1 dev d1 table 100; sleep 0.5
check "4. маршрут чужой таблицы набор не трогает" "" "$(set_of)"
check "   в журнале — смена WAN" "1" "$(grep -c 'wan_dev: WAN сменился: d1$' "$tmp/err")"
echo "wandevmatch: $pass проверок пройдено, $fail провалено"
[ "$fail" = 0 ]
