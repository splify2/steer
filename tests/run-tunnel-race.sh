#!/bin/sh
# Подъём выхода при мёртвых первых узлах подписки (I-535): проверки наперегонки, а не по 8 секунд на узел.
#
# В подписке пять узлов: четыре первых не отвечают (пакеты к ним отбрасываются правилом nft — соединение висит до
# срока проверки, 8 с), пятый — живой (tests/fake-vless.py). Подъём перебирал их по порядку: 4 × 8 с = 32 с до
# устройства. Наперегонки каждый следующий кандидат стартует через 250 мс, и живой пятый отвечает через ~1 с.
# Стенд замеряет время от запуска модуля до появления устройства; предел — 5 с (прежде — больше 30).
#
# Использование: tests/run-tunnel-race.sh   STEER=<бинарник> — по умолчанию ./build/libs-host/steerd.
# Нужен root: своё сетевое пространство.
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH

NS=steer-tunnel-race
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10803
LIVE=10.66.4.9
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

: > "$WORK/sub.txt"
for i in 1 2 3 4; do
    printf '%s\n' "vless://$UUID@10.66.4.$i:$PORT?security=none&type=tcp#dead$i" >> "$WORK/sub.txt"
done
printf '%s\n' "vless://$UUID@$LIVE:$PORT?security=none&type=tcp#live" >> "$WORK/sub.txt"
cat > "$WORK/spec.json" <<SPEC
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$WORK/sub.txt"}},
 "channels":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
for i in 1 2 3 4 9; do ip netns exec "$NS" ip addr add "10.66.4.$i/32" dev stand; done
ip netns exec "$NS" ip link set stand up
# Мёртвые узлы молчат: SYN к ним отбрасывается (отказ RST пришёл бы сразу, и проверять было бы нечего).
ip netns exec "$NS" nft -f - <<NFT
table inet steer_race_drop {
    chain out { type filter hook output priority 0; policy accept; ip daddr 10.66.4.1-10.66.4.4 drop; }
}
NFT

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$LIVE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

t0=$(date +%s.%N)
ip netns exec "$NS" "$BIN" vless vl --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!
up=0
for _ in $(seq 600); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && { up=1; break; }
    sleep 0.1
done
t1=$(date +%s.%N)
dt=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b - a}')
fail=0
if [ "$up" = 1 ]; then echo "  устройство поднялось за $dt с (мёртвых узлов перед живым: 4)"; else
    echo "  устройство не поднялось за 60 с"; fail=1; fi
[ "$up" = 1 ] && { awk -v d="$dt" 'BEGIN{exit !(d < 5.0)}' || { echo "  ОШИБКА: подъём дольше 5 с — кандидаты проверяются по очереди"; fail=1; }; }
grep -q "выбран live" "$WORK/tun.log" || { echo "  ОШИБКА: выбран не живой узел"; fail=1; }
if [ "$fail" = 0 ]; then echo "run-tunnel-race: ok"; else
    echo "--- журнал туннеля ---"; tail -15 "$WORK/tun.log" | sed 's/^/  /'; echo "run-tunnel-race: ПРОВАЛ"; fi
exit "$fail"
