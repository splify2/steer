#!/bin/sh
# Узел VLESS умер МОЛЧА посреди длинной закачки: замечает ли это клиент и что видят приложения.
#
# Сценарий жалобы владельца: «пока соединение установлено, не определяет отвал». Узел пропадает
# (машина выключилась, ТСПУ режет поток после N КБ) — пакеты к нему и от него просто исчезают, без
# RST. Новых соединений приложения не открывают: идёт закачка, звонок, игра. Прежде такое замечала
# только плановая проверка узла раз в минуту, а повисшие соединения никто не сбрасывал — приложения
# ждали своего таймаута (минуты), а подъём на другом узле шёл выходом процесса.
#
# Стенд — своё сетевое пространство (root), два поддельных узла VLESS (tests/fake-vless.py, отдача
# 200 КБ/с — закачка длится минуты) на адресах A и B, клиент туннеля ядром steer под трубой событий
# (STEER_EVENT_FD — как под демоном), подписка из двух узлов, выбирается A. Посреди закачки весь
# трафик с узлом A отбрасывается правилом nft — узел «умер молча». Проверяется:
#
#   1. повисшая закачка через A кончается сбросом (RST, код curl 56), и не позже порога молчания
#      (silence, умолчание 20 с) с запасом 15 с, а не по таймауту приложения;
#   2. простаивающее соединение через A (порт 9 поддельного сервера: открыто и молчит) тоже
#      сброшено — приложение узнаёт об этом сразу;
#   3. новое соединение через туннель работает (узел B) не позже 90 с после смерти A — и тем же
#      процессом клиента, без перезапуска.
#
# Красный до правки (ядро без порога молчания и без пула узлов): закачка висит до --max-time, тихое
# соединение — до конца стенда, а клиент, найдя живой B, выходит, и туннеля больше нет.
#
# Использование: tests/run-silence.sh   (STEER=<бинарник>, по умолчанию ./build/libs-host/steerd)
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
# steerd динамический: libsteer.so и libsteer-wolfssl.so лежат рядом с ним, а не в системных путях.
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH
[ "$(id -u)" = 0 ] || { echo "run-silence: нужен root (сетевое пространство) — ПРОПУСК"; exit 0; }

NS=steer-silence
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
A=10.66.0.1
B=10.66.0.2
SILENCE=20
WORK="$(mktemp -d)"

cleanup() {
    for p in ${SRV_A:-} ${SRV_B:-} ${TUN_PID:-} ${CURL:-} ${IDLE:-}; do kill "$p" 2>/dev/null || true; done
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '%s\n%s\n' "vless://$UUID@$A:$PORT?security=none&type=tcp#nodeA" \
    "vless://$UUID@$B:$PORT?security=none&type=tcp#nodeB" > "$WORK/sub.txt"
# Ключей silence/active в спеке нет нарочно: стенд обязан проходить спекой, которую примет и прежнее
# ядро, — иначе «красный до правки» был бы отказом разбора, а не тем, что проверяется.
cat > "$WORK/spec.json" <<SPEC
{"version":2,
 "outputs":{"vl":{"kind":"tunnel","protocol":"vless","subscription":"$WORK/sub.txt"}},
 "rules":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
ip netns exec "$NS" ip addr add "$A/32" dev stand
ip netns exec "$NS" ip addr add "$B/32" dev stand
ip netns exec "$NS" ip link set stand up

for n in A B; do
    eval addr=\$$n
    ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 64 --kbps 200 \
        --bind "$addr" > "$WORK/srv-$n.log" 2>&1 &
    eval SRV_$n=\$!
done
sleep 1

ip netns exec "$NS" sh -c "exec env STEER_EVENT_FD=3 '$BIN' vless vl --spec '$WORK/spec.json' \
    --state-dir '$WORK/state' 3>'$WORK/ev.log'" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!
for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip link show vl >/dev/null 2>&1; then
    echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi
ip netns exec "$NS" ip route replace 203.0.113.0/24 dev vl
. tests/lib-redir.sh
redir_dev "$NS" vl   # TCP — к слушателю модуля (R-152), как на роутере
grep -q "vl -> nodeA" "$WORK/tun.log" || { echo "стенд: туннель не на узле A"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }
TPID=$(ip netns pids "$NS" | while read -r p; do
    tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q " vless vl " && echo "$p"; done | head -1)

now() { date +%s.%N; }

# Закачка через A и простаивающее соединение через A (порт 9: сервер читает и молчит).
ip netns exec "$NS" sh -c 'curl -s -o /dev/null --max-time 200 http://203.0.113.10/big; echo "rc=$?"' \
    > "$WORK/curl.out" 2>&1 &
CURL=$!
ip netns exec "$NS" python3 -c '
import socket, time, sys
s = socket.create_connection(("203.0.113.12", 9), timeout=5)
s.settimeout(None)
s.sendall(b"hello\n")
t = time.time()
try:
    d = s.recv(1)
    print("idle: closed %r" % d)
except ConnectionResetError:
    print("idle: reset")
except OSError as e:
    print("idle: %r" % e)
' > "$WORK/idle.out" 2>&1 &
IDLE=$!
sleep 5

T0=$(now)
ip netns exec "$NS" nft add table inet dead
ip netns exec "$NS" nft add chain inet dead out '{ type filter hook output priority -300; policy accept; }'
ip netns exec "$NS" nft add rule inet dead out ip daddr "$A" tcp dport "$PORT" drop
ip netns exec "$NS" nft add rule inet dead out ip saddr "$A" tcp sport "$PORT" drop
echo "  узел A молчит с $(date +%T)"

curl_t="" idle_t="" ok_t=""
while :; do
    t=$(echo "$(now) - $T0" | bc)
    if [ -z "$curl_t" ] && ! kill -0 "$CURL" 2>/dev/null; then curl_t=$t; fi
    if [ -z "$idle_t" ] && ! kill -0 "$IDLE" 2>/dev/null; then idle_t=$t; fi
    if [ -z "$ok_t" ]; then
        code=$(ip netns exec "$NS" curl -s -o /dev/null --max-time 3 -w '%{http_code}' \
            http://203.0.113.11/p 2>/dev/null || true)
        [ "$code" = 200 ] && ok_t=$(echo "$(now) - $T0" | bc)
    fi
    [ -n "$curl_t" ] && [ -n "$idle_t" ] && [ -n "$ok_t" ] && break
    [ "$(echo "$t > 120" | bc)" = 1 ] && break
    sleep 1
done

alive=no
[ -n "$TPID" ] && kill -0 "$TPID" 2>/dev/null && alive=yes
crc=$(sed -n 's/^rc=//p' "$WORK/curl.out")
echo "  закачка через A кончилась: ${curl_t:-нет за 120 с} (curl rc=${crc:-—})"
echo "  тихое соединение через A: ${idle_t:-не сброшено за 120 с} ($(cat "$WORK/idle.out" 2>/dev/null))"
echo "  новое соединение работает: ${ok_t:-нет за 120 с}; процесс клиента тот же: $alive"
echo "  журнал клиента:"
grep -E "не отвечает|вместо|активный|выхожу|снова" "$WORK/tun.log" | sed 's/^/    /' || true

fail=0
lim=$((SILENCE + 15))
if [ -z "$curl_t" ] || [ "$crc" != 56 ] || [ "$(echo "$curl_t > $lim" | bc)" = 1 ]; then
    echo "ПРОВАЛ: повисшая закачка не сброшена за $lim с (порог молчания $SILENCE с + 15)"; fail=1
fi
if [ -z "$idle_t" ] || ! grep -q "idle: reset" "$WORK/idle.out" || [ "$(echo "$idle_t > $lim" | bc)" = 1 ]; then
    echo "ПРОВАЛ: тихое соединение через мёртвый узел не сброшено за $lim с"; fail=1
fi
if [ -z "$ok_t" ] || [ "$(echo "$ok_t > 90" | bc)" = 1 ] || [ "$alive" != yes ]; then
    echo "ПРОВАЛ: туннель не восстановился на узле B за 90 с тем же процессом"; fail=1
fi
[ "$fail" = 0 ] && echo "run-silence: все проверки прошли"
exit "$fail"
