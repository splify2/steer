#!/bin/sh
# Медленный узел не останавливает остальные соединения процесса (I-534): запись к узлу не ждёт сокета.
#
# Что проверяется. Клиент A выгружает в узел 24 МБ, а узел первые 3 с не читает (fake-vless.py, порт 10): буфер
# сокета узла и очередь живой записи туннеля заполняются. Раньше send в связь с узлом блокировал поток цикла
# до срока сокета, и ВСЕ остальные соединения этого потока вставали. Теперь запись уходит в очередь связи, а цикл
# перестаёт читать у клиента A (обратное давление) и идёт дальше. Параллельно клиент B открывает короткие соединения
# (эхо, порт 7) и меряет время ответа. Условия:
#   - каждый ответ B быстрее 1 с, пока A стоит (одним рабочим потоком — STEER_TUN_THREADS=1: именно его цикл
#     раньше вставал);
#   - выгрузка A дошла до узла целиком: число байт и SHA-256 совпали.
#
# Использование: tests/run-tunnel-bp.sh [МБ=24]
#   STEER=<бинарник> — по умолчанию ./build/libs-host/steerd. Нужен root: своё сетевое пространство.
set -eu
cd "$(dirname "$0")/.."

MB="${1:-24}"
BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH

NS=steer-tunnel-bp
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10802
NODE=10.66.3.1
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

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" --stall-s 3 \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

ip netns exec "$NS" env STEER_TUN_THREADS=1 "$BIN" vless vl \
    --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!
for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
ip netns exec "$NS" ip link show vl >/dev/null 2>&1 || { echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }

TARGET=203.0.113.9
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl
. tests/lib-redir.sh
redir_dev "$NS" vl

cat > "$WORK/up.py" <<'PY'
import hashlib, socket, struct, sys
host, mb = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, 10), timeout=60)
s.sendall(struct.pack(">Q", mb * 1048576))     # узел читает ровно столько (VLESS не несёт закрытие половины)
h = hashlib.sha256()
blk = bytes((i * 7 + 3) % 251 for i in range(65536))
for _ in range(mb * 16):
    s.sendall(blk)
    h.update(blk)
buf = b""
while not buf.endswith(b"\n"):
    d = s.recv(4096)
    if not d:
        break
    buf += d
print("sent %d %s" % (mb * 1048576, h.hexdigest()))
print(buf.decode().strip())
PY
cat > "$WORK/echo.py" <<'PY'
import socket, sys, time
host = sys.argv[1]
worst = 0.0
for i in range(8):
    t0 = time.monotonic()
    s = socket.create_connection((host, 7), timeout=10)
    s.sendall(b"ping %d\n" % i)
    s.shutdown(socket.SHUT_WR)
    buf = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    s.close()
    dt = time.monotonic() - t0
    worst = max(worst, dt)
    assert buf.endswith(b"ping %d\n" % i), buf
    time.sleep(0.25)
print("worst %.3f" % worst)
PY

ip netns exec "$NS" python3 "$WORK/up.py" "$TARGET" "$MB" > "$WORK/up.out" 2>&1 &
UP_PID=$!
sleep 0.7        # выгрузка пошла, узел ещё стоит
worst=$(ip netns exec "$NS" python3 "$WORK/echo.py" "$TARGET" 2>&1 | sed -n 's/^worst //p')
wait "$UP_PID" || true

fail=0
echo "  худший ответ коротких соединений, пока выгрузка стоит: ${worst:-нет} с"
awk -v w="${worst:-99}" 'BEGIN{exit !(w < 1.0)}' || { echo "  ОШИБКА: ответ дольше 1 с — цикл стоял на записи к узлу"; fail=1; }
sent=$(sed -n 's/^sent //p' "$WORK/up.out")
got=$(sed -n 's/^GOT //p' "$WORK/up.out")
echo "  отправлено: ${sent:-?}"
echo "  принято узлом: ${got:-?}"
[ -n "$sent" ] && [ "$sent" = "$got" ] || { echo "  ОШИБКА: выгрузка дошла не целиком или искажена"; fail=1; }
if [ "$fail" = 0 ]; then echo "run-tunnel-bp: ok"; else
    echo "--- журнал туннеля ---"; tail -20 "$WORK/tun.log" | sed 's/^/  /'; cat "$WORK/up.out" | sed 's/^/  /'; echo "run-tunnel-bp: ПРОВАЛ"; fi
exit "$fail"
