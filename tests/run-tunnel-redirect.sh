#!/bin/sh
# TCP через слушатель модуля (R-152): правило nft redirect отдаёт соединения клиента ядру, модуль принимает
# их сокетом и гонит узлу через дайлер. Что проверяется:
#   - много параллельных соединений, каждое одновременно отдаёт и принимает свой объём (потоковое эхо,
#     tests/mtclient.py) — весь объём возвращается байт в байт;
#   - соединения действительно шли через перенаправление: счётчик правила redirect равен числу
#     соединений, а через TUN TCP не шёл (у рабочих «из кольца»/пакетов клиента — только служебное);
#   - прямое подключение к порту модуля (не перенаправленное) закрывается сразу — прокси для всех нет.
# Использование: tests/run-tunnel-redirect.sh [рабочих=2] [соединений=32] [МБ_на_соединение=2]
#   STEER=<бинарник> — по умолчанию ./build/libs-host/steerd.
# Нужен root: своё сетевое пространство.
set -eu
cd "$(dirname "$0")/.."

THREADS="${1:-2}"
CONNS="${2:-32}"
MB="${3:-2}"
BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
# steerd динамический: libsteer.so и libsteer-wolfssl.so лежат рядом с ним, а не в системных путях.
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH

NS=steer-tunnel-redir
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

KPORT=17123
ip netns exec "$NS" env STEER_TUN_STATS=1 ${STEER_TUN_TRACE:+STEER_TUN_TRACE=1} STEER_TUN_THREADS="$THREADS" STEER_TUN_TCPPORT=$KPORT "$BIN" vless vl \
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
# Правило, которое ставит демон (шаг 2 R-152); клиент здесь — процесс того же пространства, поэтому nat
# output. Счётчик правила — сколько соединений ушло слушателю.
ip netns exec "$NS" nft -f - <<NFT
table inet steer_redir_test {
    chain out { type nat hook output priority -101; ip daddr $TARGET tcp dport 8 counter redirect to :$KPORT; }
}
NFT

rc=0
ip netns exec "$NS" python3 tests/mtclient.py "$TARGET" 8 "$CONNS" "$MB" || rc=1

# Прямое подключение к порту модуля — не перенаправленное: модуль обязан закрыть его сразу.
direct=$(ip netns exec "$NS" python3 - "$KPORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.settimeout(3)
try:
    s.sendall(b"x" * 64)
    print("закрыто" if s.recv(1) == b"" else "ответил")
except ConnectionResetError:
    print("закрыто")
except socket.timeout:
    print("висит")
PY
)
sleep 3.5

fail=0
if [ "$rc" != 0 ]; then echo "  ОШИБКА: не все соединения вернули объём байт в байт"; fail=1; fi
red=$(ip netns exec "$NS" nft list chain inet steer_redir_test out | grep -o 'packets [0-9]*' | head -1 | awk '{print $2}')
echo "  перенаправлено правилом: ${red:-0} (соединений $CONNS)"
[ "${red:-0}" -ge "$CONNS" ] || { echo "  ОШИБКА: через слушатель прошли не все соединения"; fail=1; }
# Через TUN TCP не шёл: в устройство за весь прогон ушли единицы пакетов, а не десятки тысяч.
txp=$(ip netns exec "$NS" cat /sys/class/net/vl/statistics/tx_packets 2>/dev/null || echo 0)
echo "  пакетов в TUN за прогон: $txp"
[ "${txp:-0}" -lt 200 ] || { echo "  ОШИБКА: TCP шёл через TUN, а не через слушатель"; fail=1; }
echo "  прямое подключение к порту модуля: $direct"
[ "$direct" = "закрыто" ] || { echo "  ОШИБКА: прямое подключение к порту модуля не закрыто"; fail=1; }
if grep -q "слушатель TCP .* не встал" "$WORK/tun.log"; then echo "  ОШИБКА: слушатель не встал"; fail=1; fi

if [ "$fail" = 0 ]; then echo "run-tunnel-redirect: рабочих $THREADS, соединений $CONNS: ok"; else
    echo "--- журнал туннеля ---"; grep -v "^tun-stats" "$WORK/tun.log" | tail -${TAILN:-20} | sed 's/^/  /'; echo "run-tunnel-redirect: ПРОВАЛ"; exit 1; fi
