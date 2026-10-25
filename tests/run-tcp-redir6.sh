#!/bin/sh
# TCP выхода по IPv6 — к слушателю модуля, целиком через демон (D-S3.1, I-566).
#
# Как tests/run-tcp-redir.sh, только клиент и цель по IPv6: правило nat для IPv6 (`meta nfproto ipv6`) ставит
# сам steerd и ведёт соединение клиента к слушателю модуля двойного стека, модуль берёт назначение у ядра
# (IP6T_SO_ORIGINAL_DST) и гонит поток узлу (VLESS, тип адреса 3):
#   - TCP клиента fd77::2 к 2001:db8:77::8 (через «br-lan» роутера): весь объём возвращается байт в байт, счётчик
#     правила IPv6 steer-tcp-redir — не меньше числа соединений;
#   - клиент по IPv4 приходит к тому же слушателю (адрес ::ffff:a.b.c.d) и тоже проходит — двойной стек не сломал
#     IPv4.
#
# Использование: tests/run-tcp-redir6.sh [соединений=16] [МБ_на_соединение=2]
#   STEER_LIBS=<каталог раскладки> — steerd и модули (build/build-libs.sh); по умолчанию build/libs-host.
# Нужен root: свои сетевые пространства. Каталог имён таблиц (/etc/iproute2) у роутера — свой
# (/etc/netns/<имя>), хост не трогается.
set -eu
cd "$(dirname "$0")/.."

CONNS="${1:-16}"
MB="${2:-2}"
LIBS="${STEER_LIBS:-build/libs-host}"
LIBS="$(cd "$LIBS" 2>/dev/null && pwd)" || { echo "нет раскладки: ${STEER_LIBS:-build/libs-host}"; exit 2; }
[ -x "$LIBS/steerd" ] && [ -x "$LIBS/steer-vless" ] || { echo "в $LIBS нет steerd или steer-vless"; exit 2; }

R=steer-redir6-rt
C=steer-redir6-cl
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10801
NODE=10.66.2.1
TARGET=2001:db8:77::8
TARGET4=203.0.113.8
WORK="$(mktemp -d)"

cleanup() {
    for ns in "$R" "$C"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 0.3
    for ns in "$R" "$C"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns delete "$ns" 2>/dev/null || true
    done
    rm -rf "/etc/netns/$R" "$WORK"
}
trap cleanup EXIT INT TERM
cleanup 2>/dev/null || true
WORK="$(mktemp -d)"

printf '%s\n' "vless://$UUID@$NODE:$PORT?security=none&type=tcp#local" > "$WORK/sub.txt"
printf '203.0.113.0/24\n2001:db8:77::/64\n' > "$WORK/p.lst"
cat > "$WORK/spec.yaml" <<SPEC
version: 2
outputs:
  vl: { kind: tunnel, protocol: vless, subscription: $WORK/sub.txt }
lists:
  p: { prefixes_file: [$WORK/p.lst] }
rules:
  - { name: r, to: [p], out: vl }
SPEC

# Роутер: «br-lan» к клиенту, узел на петлевом устройстве. Имя br-lan — потому что клиенты спеки по
# умолчанию приходят с него (lan по умолчанию), как в доме.
mkdir -p "/etc/netns/$R/iproute2/rt_tables.d"
ip netns add "$R"
ip netns add "$C"
ip netns exec "$R" ip link set lo up
ip netns exec "$C" ip link set lo up
ip link add br-lan netns "$R" type veth peer name cl0 netns "$C"
ip netns exec "$R" ip addr add 192.168.77.1/24 dev br-lan
ip netns exec "$R" ip link set br-lan up
ip netns exec "$C" ip addr add 192.168.77.2/24 dev cl0
ip netns exec "$C" ip link set cl0 up
ip netns exec "$C" ip route add default via 192.168.77.1
ip netns exec "$R" ip -6 addr add fd77::1/64 dev br-lan nodad
ip netns exec "$C" ip -6 addr add fd77::2/64 dev cl0 nodad
ip netns exec "$C" ip -6 route add default via fd77::1 dev cl0
ip netns exec "$R" sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec "$R" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$R" ip link add stand type dummy
ip netns exec "$R" ip addr add "$NODE/32" dev stand
ip netns exec "$R" ip link set stand up

ip netns exec "$R" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
sleep 1

ip netns exec "$R" env LD_LIBRARY_PATH="$LIBS" STEER_MODULE_DIR="$LIBS" STEER_TUN_STATS=1 \
    "$LIBS/steerd" daemon --watch --supervise --apply --spec "$WORK/spec.yaml" \
    --state-dir "$WORK/state" --socket "$WORK/ctl.sock" > "$WORK/d.log" 2>&1 &

elem() { ip netns exec "$R" nft list map inet steer tcp_redir 2>/dev/null | grep -o '0x[0-9a-f]* : [0-9]*' || true; }
wait_elem() { # 1 — ждать появления, 0 — исчезновения; секунды
    want="$1"; t="$2"; i=0
    while [ "$i" -lt $((t * 10)) ]; do
        e="$(elem)"
        if [ "$want" = 1 ] && [ -n "$e" ]; then return 0; fi
        if [ "$want" = 0 ] && [ -z "$e" ]; then return 0; fi
        sleep 0.1; i=$((i + 1))
    done
    # Приговор по состоянию, а не по счётчику кругов.
    e="$(elem)"
    if [ "$want" = 1 ] && [ -n "$e" ]; then return 0; fi
    if [ "$want" = 0 ] && [ -z "$e" ]; then return 0; fi
    return 1
}
redir_count() {   # $1 — семейство правила: ipv6 или ip (protocol tcp)
    ip netns exec "$R" nft list chain inet steer prerouting_tcp_redir 2>/dev/null |
        grep 'steer-tcp-redir' | grep "$1" | grep -o 'packets [0-9]*' | grep -o '[0-9]*' | head -n 1 || echo 0
}

fail=0
say() { echo "  $*"; }
bad() { echo "  ОШИБКА: $*"; fail=1; }

if wait_elem 1 20; then say "элемент карты после up: $(elem)"; else
    bad "элемент карты не появился"; tail -20 "$WORK/d.log" | sed 's/^/    /'
fi

if ip netns exec "$C" python3 tests/mtclient.py "$TARGET" 8 "$CONNS" "$MB"; then
    say "передача 1 по IPv6: $CONNS соединений по $MB МБ — байт в байт"
else
    bad "передача 1 по IPv6 не вернула объём"
fi
n="$(redir_count 'nfproto ipv6')"
say "перенаправлено соединений IPv6: $n"
[ "${n:-0}" -ge "$CONNS" ] || bad "счётчик steer-tcp-redir для IPv6 (${n:-0}) меньше числа соединений ($CONNS)"
if ip netns exec "$C" python3 tests/mtclient.py "$TARGET4" 8 4 1; then
    say "передача по IPv4 к тому же слушателю — байт в байт"
else
    bad "передача по IPv4 не вернула объём"
fi
n4="$(redir_count 'ip protocol tcp')"
[ "${n4:-0}" -ge 4 ] || bad "счётчик steer-tcp-redir для IPv4 (${n4:-0}) меньше числа соединений (4)"

# Модуль под супервизором называется по argv[0] «steer» (helper_argv0) — искать по аргументам и только
# среди процессов своего пространства: pgrep видит все процессы машины, а соседний стенд или замер может
# держать модуль с той же командной строкой.
pid=""
for p in $(ip netns pids "$R" 2>/dev/null); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q " vless vl --spec $WORK/"; then pid="$p"; break; fi
done
if [ -z "$pid" ]; then bad "процесса steer-vless нет"; else
    kill -9 "$pid"
    if wait_elem 0 2; then say "модуль убит — элемент снят"; else bad "элемент не снят после смерти модуля: $(elem)"; fi
    if wait_elem 1 30; then say "модуль поднят заново — элемент вернулся: $(elem)"; else bad "элемент не вернулся"; fi
    if ip netns exec "$C" python3 tests/mtclient.py "$TARGET" 8 4 1; then say "передача 2 по IPv6 после перезапуска — байт в байт"; else
        bad "передача 2 не вернула объём"; fi
fi

if [ "$fail" = 0 ]; then echo "run-tcp-redir6: соединений $CONNS: ok"; else
    echo "--- журнал демона ---"; tail -30 "$WORK/d.log" | sed 's/^/  /'; echo "run-tcp-redir6: ПРОВАЛ"; fi
exit "$fail"
