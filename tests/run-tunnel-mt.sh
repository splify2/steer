#!/bin/sh
# Несколько рабочих потоков модуля: соединения расходятся по рабочим и каждое — целиком у своего (R-146, R-152).
#
# Что проверяется. TCP клиентов завершает ядро и перенаправляет к слушателю модуля (здесь правило ставит
# стенд, tests/lib-redir.sh; на роутере — демон). Слушатель у каждого рабочего свой, и принятое соединение
# раздаётся по кругу (kaccept): много параллельных соединений при N рабочих, каждое одновременно отдаёт и
# принимает свой объём (потоковое эхо, tests/mtclient.py), и весь объём возвращается байт в байт;
#   - соединения действительно разошлись по рабочим (у каждого из двух и больше — «соединений» в
#     статистике): иначе «зелёный» результат ничего не доказывает — один поток из четырёх тоже проходит;
#   - TCP в устройство не попадал (счётчик «TCP из TUN сброшено» — ноль): всё шло через слушатель.
#
# Использование: tests/run-tunnel-mt.sh [рабочих=4] [соединений=32] [МБ_на_соединение=2]
#   STEER=<бинарник> — по умолчанию ./build/libs-host/steerd; STEER_TUN_THREADS здесь не читается,
#   рабочих задаёт первый аргумент.
# Нужен root: своё сетевое пространство.
set -eu
cd "$(dirname "$0")/.."

THREADS="${1:-4}"
CONNS="${2:-32}"
MB="${3:-2}"
BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
# steerd динамический: libsteer.so и libsteer-wolfssl.so лежат рядом с ним, а не в системных путях.
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH

NS=steer-tunnel-mt
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10801
NODE=10.66.2.1
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '%s\n' "vless://$UUID@$NODE:$PORT?security=none&type=tcp#local" > "$WORK/sub.txt"
cat > "$WORK/spec.json" <<SPEC
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$WORK/sub.txt","node":0}},
 "channels":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
ip netns exec "$NS" ip addr add "$NODE/32" dev stand
ip netns exec "$NS" ip link set stand up

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

ip netns exec "$NS" env STEER_TUN_STATS=1 STEER_TUN_THREADS="$THREADS" "$BIN" vless vl \
    --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip link show vl >/dev/null 2>&1; then
    echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi
grep -iE "разгрузк|потоков" "$WORK/tun.log" | sed 's/^/  /' || true

TARGET=203.0.113.8
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl
. tests/lib-redir.sh
redir_dev "$NS" vl   # TCP — к слушателю модуля (R-152), как на роутере

rc=0
ip netns exec "$NS" python3 tests/mtclient.py "$TARGET" 8 "$CONNS" "$MB" || rc=1

# Счётчики печатаются раз в две секунды: после трафика ждём, пока каждый рабочий выдаст строку.
sleep 3.5

fail=0
if [ "$rc" != 0 ]; then echo "  ОШИБКА: не все соединения вернули объём байт в байт"; fail=1; fi

# Сколько рабочих несли соединения: наибольшее «соединений N» по каждому рабочему.
used=$(grep -o '^tun-stats\[[0-9]*\].*соединений [0-9]*' "$WORK/tun.log" |
    sed 's/^tun-stats\[\([0-9]*\)\].*соединений \([0-9]*\)$/\1 \2/' |
    awk '{if ($2 > m[$1]) m[$1]=$2} END{for (k in m) if (m[k] > 0) n++; print n+0}')
want=2; [ "$THREADS" -lt 2 ] && want=1
echo "  рабочих с соединениями: $used из $THREADS"
[ "$used" -ge "$want" ] || { echo "  ОШИБКА: соединения не разошлись по рабочим"; fail=1; }

rst=$(grep -o 'TCP из TUN сброшено всего [0-9]*' "$WORK/tun.log" | grep -o '[0-9]*$' | sort -n | tail -1)
echo "  TCP в устройство: ${rst:-0}"
[ "${rst:-0}" = 0 ] || { echo "  ОШИБКА: TCP шёл в устройство, а не через слушатель"; fail=1; }

if [ "$fail" = 0 ]; then echo "run-tunnel-mt: рабочих $THREADS, соединений $CONNS: ok"; else
    echo "--- журнал туннеля ---"; tail -20 "$WORK/tun.log" | sed 's/^/  /'; echo "run-tunnel-mt: ПРОВАЛ"; fi
exit "$fail"
