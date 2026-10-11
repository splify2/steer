#!/bin/sh
# Несколько рабочих потоков стека: «половины соединения не разъезжаются» (R-146).
#
# Что проверяется. Прежний отказ от нескольких потоков — подтверждения клиента попадали в очередь
# TUN чужого потока, владелец соединения их не видел, окно не открывалось, и соединение висело
# живым и пустым (12 против 292 Мбит/с на роутере). Теперь пакеты раздаёт один читатель по хэшу
# соединения, и стенд проверяет ровно это свойство на настоящем трафике:
#   - много параллельных соединений при N рабочих; каждое одновременно отдаёт и принимает свой
#     объём (потоковое эхо, tests/mtclient.py), и весь объём возвращается байт в байт;
#   - счётчик «не у владельца» (рабочему пришёл пакет не его соединения) равен нулю у каждого
#     рабочего: это та же проверка хэшем, но с другой стороны — на стороне получателя;
#   - трафик действительно разошёлся по рабочим (иначе «зелёный» результат ничего не доказывает:
#     один поток из четырёх тоже проходит);
#   - кольцо читателя не переполнялось (иначе байты дошли повтором TCP, а не раздачей).
#
# Использование: tests/run-tunnel-mt.sh [рабочих=4] [соединений=32] [МБ_на_соединение=2]
#   STEER=<бинарник> — по умолчанию ./build/steer-ext-check; STEER_TUN_THREADS здесь не читается,
#   рабочих задаёт первый аргумент.
# Нужен root: своё сетевое пространство. На прежнем коде (где нет читателя и счётчика) стенд краснеет.
set -eu
cd "$(dirname "$0")/.."

THREADS="${1:-4}"
CONNS="${2:-32}"
MB="${3:-2}"
BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (собери extended)"; exit 2; }

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

rc=0
ip netns exec "$NS" python3 tests/mtclient.py "$TARGET" 8 "$CONNS" "$MB" || rc=1

# Счётчики печатаются раз в две секунды: после трафика ждём, пока каждый рабочий выдаст строку, а
# читатель — свою (рабочие просыпаются не реже раза в секунду).
sleep 3.5

fail=0
if [ "$rc" != 0 ]; then echo "  ОШИБКА: не все соединения вернули объём байт в байт"; fail=1; fi

# «не у владельца всего N»: последнее значение у каждого рабочего (счётчик накопительный).
own=$(grep -o '^tun-stats\[[0-9]*\].*не у владельца всего [0-9]*' "$WORK/tun.log" |
    sed 's/^tun-stats\[\([0-9]*\)\].*всего \([0-9]*\)$/\1 \2/' | sort -n | awk '{v[$1]=$2} END{for(k in v) print k, v[k]}')
if [ -z "$own" ]; then
    echo "  ОШИБКА: счётчика «не у владельца» в журнале нет (нет раздачи по потокам?)"; fail=1
else
    bad=$(printf '%s\n' "$own" | awk '$2 != 0' | wc -l)
    echo "  рабочих отчиталось: $(printf '%s\n' "$own" | wc -l), не у владельца у них: $(printf '%s\n' "$own" | awk '{s+=$2} END{print s+0}')"
    [ "$bad" = 0 ] || { echo "  ОШИБКА: пакеты пришли рабочему не по хэшу"; fail=1; }
fi
if grep -q "ошибка раздачи" "$WORK/tun.log"; then echo "  ОШИБКА: в журнале «ошибка раздачи»"; fail=1; fi

# Кто получал пакеты: из кольца всего, последнее значение по каждому.
used=$(grep -o '^tun-stats\[[0-9]*\].*из кольца всего [0-9]*' "$WORK/tun.log" |
    sed 's/^tun-stats\[\([0-9]*\)\].*всего \([0-9]*\)$/\1 \2/' | awk '{v[$1]=$2} END{for(k in v) if (v[k] > 0) n++; print n+0}')
want=2; [ "$THREADS" -lt 2 ] && want=1
echo "  рабочих с трафиком: $used из $THREADS"
[ "$used" -ge "$want" ] || { echo "  ОШИБКА: трафик не разошёлся по рабочим"; fail=1; }

# Кто раздавал пакеты: ядро (программа на устройстве) или читатель (STEER_TUN_NOSTEER, ядро без bpf).
grep -o 'пакеты раздаёт [^)]*\|раздача пакетов ядром недоступна.*' "$WORK/tun.log" | head -2 | sed 's/^/  /' || true
ovf=$(grep -o 'кольцо переполнено [0-9]*' "$WORK/tun.log" | tail -1 | grep -o '[0-9]*$' || true)
echo "  кольцо переполнялось: ${ovf:-нет данных (кольца нет: раздаёт ядро)}"
if [ "$THREADS" -gt 1 ] && [ "${ovf:-0}" != 0 ]; then echo "  ОШИБКА: кольцо переполнялось — байты дошли повтором, а не раздачей"; fail=1; fi

if [ "$fail" = 0 ]; then echo "run-tunnel-mt: рабочих $THREADS, соединений $CONNS: ok"; else
    echo "--- журнал туннеля ---"; tail -20 "$WORK/tun.log" | sed 's/^/  /'; echo "run-tunnel-mt: ПРОВАЛ"; fi
exit "$fail"
