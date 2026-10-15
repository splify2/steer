#!/bin/sh
# Узел по IPv6 целиком (issue splify2/steer#7): `steer vless-probe` и `steer proxy-probe` по адресу
# IPv6 в скобках и по имени только с AAAA, смешанное имя (AAAA в чёрную дыру, A живой), UDP SOCKS5 с
# адресом ретранслятора ATYP 4 и туннель run-tunnel.sh поверх узла по IPv6. До исправления все эти
# проверки, кроме IPv4, отвечали «имя не разрешилось» / «ссылка не разобрана».
#
# Стенд: пространство steer-nodev6, в нём dummy `stand` с адресами узлов (2001:db8:66::1 — по
# IPv6, 10.66.0.1 — по IPv4) и серверы стенда: tests/fake-vless.py (--bind принимает IPv6) и
# tests/fake-socks.py. Имена — через /etc/hosts в СВОЁМ mount-пространстве (unshare -m + bind),
# хостовый файл не трогается; настоящий резолвер — getaddrinfo, как у роутера:
#   v6only.test  AAAA 2001:db8:66::1
#   mixed.test   AAAA 2001:db8:66::2 (маршрут на dummy, ответа нет — чёрная дыра) и A 10.66.0.1
#
# Бинарники — раскладка libs-host (steerd, модули, библиотеки; её собирает tests/libs-test.sh): LIBS=каталог,
# по умолчанию $BUILD/libs-host. Нужны root, ip netns, unshare, python3; нет — громкий пропуск (код 0).
# UDP-проверка берёт $BUILD/pxprobe (собирает ext-test), нет — пропускается вслух.
set -u
cd "$(dirname "$0")/.."
BUILD="${BUILD:-build}"
LIBS="${LIBS:-$BUILD/libs-host}"
skip() { echo "nodev6: ПРОПУСК — $1. Это не падение."; exit 0; }
[ "$(id -u)" = 0 ] || skip "нужен root"
command -v ip >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 ||
    skip "нужны ip, unshare и python3"
[ -x "$LIBS/steerd" ] || skip "нет $LIBS/steerd (раскладку собирает tests/libs-test.sh)"
LIBS="$(cd "$LIBS" && pwd)"
LD_LIBRARY_PATH="$LIBS"; export LD_LIBRARY_PATH
STEERD="$LIBS/steerd"

NS=steer-nodev6
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
N6=2001:db8:66::1
N4=10.66.0.1
WORK="$(mktemp -d)"
pass=0 fail=0
cleanup() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
# Проверка узла в пространстве, с подменённым /etc/hosts; печатает ответ целиком.
in_ns() { ip netns exec "$NS" unshare -m sh -c "mount --bind '$WORK/hosts' /etc/hosts && exec \"\$@\"" sh "$@"; }
ok_of() { case "$1" in *'"ok":true'*) echo ok ;; *) echo fail ;; esac; }

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS" || skip "ip netns add не удалось"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
ip netns exec "$NS" ip link set stand up
ip netns exec "$NS" ip addr add "$N4/32" dev stand
ip netns exec "$NS" ip addr add "$N6/128" dev stand nodad 2>/dev/null || skip "в пространстве нет IPv6"
# Соседняя 2001:db8:66::2 — на канале dummy: пакет уйдёт и пропадёт (NOARP, ответчика нет).
ip netns exec "$NS" ip -6 route add 2001:db8:66::/64 dev stand
cat > "$WORK/hosts" <<HOSTS
127.0.0.1 localhost
$N6 v6only.test
2001:db8:66::2 mixed.test
$N4 mixed.test
HOSTS

ip netns exec "$NS" python3 tests/fake-vless.py --port 10800 --uuid "$UUID" --mb 1 --bind "$N6" > "$WORK/v6.log" 2>&1 &
ip netns exec "$NS" python3 tests/fake-vless.py --port 10800 --uuid "$UUID" --mb 1 --bind "$N4" > "$WORK/v4.log" 2>&1 &
ip netns exec "$NS" python3 tests/fake-socks.py --bind "$N6" --port 1080 --udp-bnd ::1 > "$WORK/s6.log" 2>&1 &
ip netns exec "$NS" python3 tests/fake-socks.py --bind "$N4" --port 1080 > "$WORK/s4.log" 2>&1 &
sleep 1.5
grep -q "fake-vless" "$WORK/v6.log" || { echo "nodev6: сервер IPv6 не поднялся:"; cat "$WORK/v6.log"; exit 1; }

sub() {   # sub ИМЯ ссылка
    printf '%s\n' "$2" > "$WORK/$1.txt"
}
vprobe() { in_ns "$STEERD" vless-probe "$WORK/$1.txt" --node 0 --timeout 6 2>&1; }
pprobe() { in_ns "$STEERD" proxy-probe "$WORK/$1.txt" --node 0 --timeout 6 2>&1; }
now_ms() { date +%s%3N; }

# ---- VLESS ----
sub vl4 "vless://$UUID@$N4:10800?security=none&type=tcp#v4"
sub vl6 "vless://$UUID@[$N6]:10800?security=none&type=tcp#v6"
sub vln "vless://$UUID@v6only.test:10800?security=none&type=tcp#aaaa"
sub vlm "vless://$UUID@mixed.test:10800?security=none&type=tcp#mixed"
check "vless-probe: IPv4 (без изменений)" ok "$(ok_of "$(vprobe vl4)")"
check "vless-probe: адрес IPv6 в скобках" ok "$(ok_of "$(vprobe vl6)")"
check "vless-probe: имя только с AAAA" ok "$(ok_of "$(vprobe vln)")"
t0=$(now_ms)
check "vless-probe: AAAA в чёрную дыру, A живой — узел отвечает" ok "$(ok_of "$(vprobe vlm)")"
t1=$(now_ms)
check "vless-probe: смешанное имя — за пару секунд, а не за срок AAAA" 1 "$([ $((t1 - t0)) -lt 3000 ] && echo 1 || echo 0)"

# ---- прокси (SOCKS5) ----
sub px4 "socks5://$N4:1080#s4"
sub px6 "socks5://[$N6]:1080#s6"
sub pxn "socks5://v6only.test:1080#aaaa"
check "proxy-probe: IPv4 (без изменений)" ok "$(ok_of "$(pprobe px4)")"
check "proxy-probe: адрес IPv6 в скобках" ok "$(ok_of "$(pprobe px6)")"
check "proxy-probe: имя только с AAAA" ok "$(ok_of "$(pprobe pxn)")"

# ---- UDP ASSOCIATE: ретранслятор назван адресом IPv6 (ATYP 4), не адресом узла ----
if [ -x "$BUILD/pxprobe" ]; then
    out="$(in_ns "$BUILD/pxprobe" "socks5://[$N6]:1080" udp 1.1.1.1 53 3 2>&1)"; rc=$?
    check "pxprobe udp: SOCKS5 по IPv6, ретранслятор ::1 из ответа ATYP 4" 0 "$rc"
    [ "$rc" = 0 ] || echo "$out" | sed 's/^/    /'
else
    echo "nodev6: нет $BUILD/pxprobe — проверка UDP ASSOCIATE пропущена"
fi

# ---- туннель целиком поверх узла по IPv6 ----
if [ -x tests/run-tunnel.sh ] || [ -f tests/run-tunnel.sh ]; then
    if STEER="$STEERD" NODE="$N6" sh tests/run-tunnel.sh > "$WORK/tun.out" 2>&1; then
        check "run-tunnel: узел по IPv6, 8 МБ через туннель" ok ok
    else
        check "run-tunnel: узел по IPv6, 8 МБ через туннель" ok fail
        sed 's/^/    /' "$WORK/tun.out" | tail -15
    fi
fi

echo "nodev6: $pass passed, $fail failed"
[ "$fail" = 0 ]
