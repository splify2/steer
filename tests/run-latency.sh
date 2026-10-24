#!/bin/sh
# pick: latency — самые быстрые узлы подписки в одном туннеле (src/tunnel/pool.c), живым клиентом.
#
# Решение владельца 2026-10-12: «самый быстрый, не держа кучу интерфейсов» — как url-test sing-box и
# Mihomo. Стенд — своё сетевое пространство (root), три поддельных узла VLESS (tests/fake-vless.py) с
# задержкой ответа: A — 400 мс (первый по порядку подписки, его берёт подъём), B — 0, C — 150 мс.
# Клиент туннеля ядром steer, спека `pick: latency, interval: 5`. Проверяется:
#
#   1. после первого замера активный узел — B (самый быстрый), а не A по порядку; файл состояния
#      называет pick и замер всех трёх (B быстрее C быстрее A);
#   2. закачка, начатая через A до пересадки, доходит до конца (curl rc 0): пересадка соединений
#      не рвёт;
#   3. новые соединения после пересадки идут на B (журнал B);
#   4. B умер молча — замена по замеру (C, а не A по порядку), тем же процессом; новое соединение
#      работает.
#
# Использование: tests/run-latency.sh   (STEER=<бинарник>, по умолчанию ./build/steer)
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run-latency: нужен root (сетевое пространство) — ПРОПУСК"; exit 0; }

NS=steer-latency
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
A=10.67.0.1
B=10.67.0.2
C=10.67.0.3
WORK="$(mktemp -d)"

cleanup() {
    for p in ${SRV_A:-} ${SRV_B:-} ${SRV_C:-} ${TUN_PID:-} ${CURL:-}; do kill "$p" 2>/dev/null || true; done
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '%s\n%s\n%s\n' "vless://$UUID@$A:$PORT?security=none&type=tcp#nodeA" \
    "vless://$UUID@$B:$PORT?security=none&type=tcp#nodeB" \
    "vless://$UUID@$C:$PORT?security=none&type=tcp#nodeC" > "$WORK/sub.txt"
cat > "$WORK/spec.json" <<SPEC
{"version":2,
 "outputs":{"vl":{"kind":"tunnel","protocol":"vless","subscription":"$WORK/sub.txt",
                  "pick":"latency","interval":5}},
 "rules":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
for a in $A $B $C; do ip netns exec "$NS" ip addr add "$a/32" dev stand; done
ip netns exec "$NS" ip link set stand up

srv() {   # имя, адрес, задержка мс
    ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 3 --kbps 200 \
        --bind "$2" --delay-ms "$3" --log > "$WORK/srv-$1.log" 2>&1 &
    eval SRV_$1=\$!
}
srv A $A 400
srv B $B 0
srv C $C 150
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
redir_dev "$NS" vl
TPID=$(ip netns pids "$NS" | while read -r p; do
    tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q " vless vl " && echo "$p"; done | head -1)

# Закачка через A — сразу, до первого замера (3 МБ на 200 КБ/с — около 15 с).
ip netns exec "$NS" sh -c 'curl -s -o /dev/null --max-time 60 http://203.0.113.10/big; echo "rc=$?"' \
    > "$WORK/curl.out" 2>&1 &
CURL=$!
sleep 1
a_before=$(grep -c "req 203.0.113.10:80" "$WORK/srv-A.log" || true)

st="$WORK/state/vless-vl"
moved=""
for _ in $(seq 40); do
    grep -q '"active":\[{"index":1,' "$st" 2>/dev/null && { moved=yes; break; }
    sleep 0.5
done
# Приговор по состоянию, а не по счётчику кругов: переключение в последние полсекунды — тоже переключение.
[ "$moved" = yes ] || { grep -q '"active":\[{"index":1,' "$st" 2>/dev/null && moved=yes; }

fail=0
if [ "$moved" = yes ] && [ "$a_before" -ge 1 ]; then echo "  ok: закачка начата через A, после замера активен B"; else
    echo "ПРОВАЛ: после замера активен не B (закачек через A: $a_before)"; sed 's/^/    /' "$st" 2>/dev/null; fail=1; fi
lat=$(cat "$st" 2>/dev/null || true)
la=$(echo "$lat" | sed -n 's/.*"latency":{[^}]*"0":\(-\{0,1\}[0-9]*\).*/\1/p')
lb=$(echo "$lat" | sed -n 's/.*"latency":{[^}]*"1":\(-\{0,1\}[0-9]*\).*/\1/p')
lc=$(echo "$lat" | sed -n 's/.*"latency":{[^}]*"2":\(-\{0,1\}[0-9]*\).*/\1/p')
if echo "$lat" | grep -q '"pick":"latency"' && [ -n "$la" ] && [ -n "$lb" ] && [ -n "$lc" ] &&
   [ "$lb" -ge 0 ] && [ "$lb" -lt "$lc" ] && [ "$lc" -lt "$la" ]; then
    echo "  ok: замер в файле состояния — A $la мс, B $lb мс, C $lc мс"
else echo "ПРОВАЛ: замер в файле состояния: $lat"; fail=1; fi

# Новые соединения — на B.
for i in 1 2 3; do
    ip netns exec "$NS" curl -s -o /dev/null --max-time 5 -r 0-1000 "http://203.0.113.2$i/p" || true
done
nb=$(grep -c "req 203.0.113.2" "$WORK/srv-B.log" || true)
if [ "$nb" -ge 3 ]; then echo "  ok: новые соединения — через B ($nb)"; else
    echo "ПРОВАЛ: новые соединения не через B (у B: $nb)"; fail=1; fi

wait "$CURL" 2>/dev/null || true
crc=$(sed -n 's/^rc=//p' "$WORK/curl.out")
if [ "$crc" = 0 ]; then echo "  ok: закачка через A после пересадки дошла до конца"; else
    echo "ПРОВАЛ: закачка через A оборвана пересадкой (curl rc=${crc:-—})"; fail=1; fi

# B умер молча: замена по замеру — C, а не A.
ip netns exec "$NS" nft add table inet dead
ip netns exec "$NS" nft add chain inet dead out '{ type filter hook output priority -300; policy accept; }'
ip netns exec "$NS" nft add rule inet dead out ip daddr "$B" tcp dport "$PORT" drop
ok_t=""
for t in $(seq 60); do
    if grep -q '"active":\[{"index":2,' "$st" 2>/dev/null; then
        code=$(ip netns exec "$NS" curl -s -o /dev/null --max-time 3 -r 0-1000 -w '%{http_code}' \
            http://203.0.113.30/p 2>/dev/null || true)
        case "$code" in 2*) ok_t=$t; break ;; esac
    fi
    sleep 1
done
# То же для C: переключение, случившееся за последнюю секунду ожидания, не должно считаться провалом.
if [ -z "$ok_t" ] && grep -q '"active":\[{"index":2,' "$st" 2>/dev/null; then
    code=$(ip netns exec "$NS" curl -s -o /dev/null --max-time 3 -r 0-1000 -w '%{http_code}' \
        http://203.0.113.30/p 2>/dev/null || true)
    case "$code" in 2*) ok_t=60 ;; esac
fi
alive=no
[ -n "$TPID" ] && kill -0 "$TPID" 2>/dev/null && alive=yes
if [ -n "$ok_t" ] && [ "$alive" = yes ] && grep -q "req 203.0.113.30" "$WORK/srv-C.log"; then
    echo "  ok: B умер — активен C (быстрее A по замеру), новое соединение работает через ${ok_t} с, процесс тот же"
else echo "ПРОВАЛ: после смерти B не C (процесс жив: $alive)"; sed 's/^/    /' "$st" 2>/dev/null; fail=1; fi

echo "  журнал клиента:"
grep -E "не отвечает|вместо|активный|→|снова" "$WORK/tun.log" | sed 's/^/    /' || true
[ "$fail" = 0 ] && echo "run-latency: все проверки прошли"
exit "$fail"
