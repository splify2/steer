#!/bin/sh
# Разметка каналов на хуке inet ingress (compile/generate.c, «разметка на ingress») с настоящим
# ядром: клиент за МОСТОМ (veth-порт в br-lan), трафик по каналам IPv4 и IPv6, клиент по MAC,
# direct выше канала туннеля, метка соединения (steer conns), fake-IP (dnat по карте после
# разметки на ingress), сужение по порту с фрагментами, balance — раздача по членам и память
# соединения, выгрузка потоков flowtable; откаты — чужая перезапись метки между ingress и нами,
# устройство моста пересоздано (хук ingress снят ядром; apply и reload демона ставят его на новое),
# устройство раздачи, которого нет, STEER_NFT_INGRESS=0.
#
# Сеть — пять пространств: роутер (сам стенд, мост br-lan с портом p0), клиент C за портом (c0),
# «туннели» T (t0) и U (u0) — устройства выходов kind=interface, и «провайдер» W (w0, маршрут по
# умолчанию). Адрес за туннелем есть ТОЛЬКО у туннеля, адрес вне списков — только у провайдера:
# ответ и есть доказательство пути, а утечка напрямую ответила бы там, где ответа быть не должно.
# NAT нет: у T, U и W есть маршрут назад в сеть клиента.
#
# INGRESSNS_BENCH=1 — ещё и грубый замер (iperf3, UDP 64 байта и TCP): разметка на ingress,
# та же спека только в prerouting (STEER_NFT_INGRESS=0) и без движка вовсе. Числа печатаются, не
# проверяются: в make test замер не входит.
#
# Нужны root, unshare, nsenter, ip, nft, ping и python3; ядро без inet ingress — стенд
# пропускается вслух, с кодом 0.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "ingressns: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter ping python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${INGRESSNS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    INGRESSNS_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null
sysctl -qw net.ipv6.conf.all.forwarding=1 2>/dev/null
nft add table inet ingressns_probe 2>/dev/null || skip "nf_tables недоступен"
nft add chain inet ingressns_probe c '{ type filter hook ingress device "lo" priority 10; }' 2>/dev/null ||
    { nft delete table inet ingressns_probe; skip "ядро не принимает цепочку inet ingress"; }
nft delete table inet ingressns_probe

tmp="$(mktemp -d)"
pids=""
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null; done
    [ -n "$tmp" ] && rm -rf "$tmp"
}
trap cleanup EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    # Приговор по фактическому состоянию, а не по счётчику кругов: условие, ставшее истинным в последнюю
    # десятую секунды, иначе объявлялось бы невыполненным.
    eval "$1" && return 0
    return 1
}
unshare -n sleep 900 >/dev/null 2>&1 & C=$!
unshare -n sleep 900 >/dev/null 2>&1 & T=$!
unshare -n sleep 900 >/dev/null 2>&1 & U=$!
unshare -n sleep 900 >/dev/null 2>&1 & W=$!
pids="$C $T $U $W"
sleep 0.3
IC="nsenter -t $C -n"; IT="nsenter -t $T -n"; IU="nsenter -t $U -n"; IW="nsenter -t $W -n"
link() {   # link ЗДЕСЬ ТАМ PID АДРЕС4_ЗДЕСЬ АДРЕС4_ТАМ АДРЕС6_ЗДЕСЬ АДРЕС6_ТАМ
    ip link add "$1" type veth peer name "$2"
    ip link set "$2" netns "$3"
    ip addr add "$4" dev "$1"
    ip addr add "$6" dev "$1" nodad
    ip link set "$1" up
    nsenter -t "$3" -n ip link set lo up
    nsenter -t "$3" -n ip addr add "$5" dev "$2"
    nsenter -t "$3" -n ip addr add "$7" dev "$2" nodad
    nsenter -t "$3" -n ip link set "$2" up
}
# Мост и клиент за его портом: адреса роутера — на мосту, порт p0 без адреса.
mkbridge() {
    ip link add br-lan type bridge
    ip link set br-lan type bridge stp_state 0 forward_delay 0 2>/dev/null
    ip link set p0 master br-lan
    ip addr add 192.168.1.1/24 dev br-lan
    ip addr add fd00:1::1/64 dev br-lan nodad
    ip link set br-lan up
}
ip link add p0 type veth peer name c0 address 02:00:00:00:00:c0
ip link set c0 netns "$C"
ip link set p0 up
mkbridge
$IC ip link set lo up
$IC ip addr add 192.168.1.2/24 dev c0
$IC ip addr add fd00:1::2/64 dev c0 nodad
$IC ip link set c0 up
$IC ip route add default via 192.168.1.1
$IC ip -6 route add default via fd00:1::1
link t0 t1 "$T" 10.9.0.1/30 10.9.0.2/30 fd00:2::1/64 fd00:2::2/64
link u0 u1 "$U" 10.9.1.1/30 10.9.1.2/30 fd00:4::1/64 fd00:4::2/64
link w0 w1 "$W" 10.0.0.1/30 10.0.0.2/30 fd00:3::1/64 fd00:3::2/64
ip route add default via 10.0.0.2
ip -6 route add default via fd00:3::2 dev w0
for ns in $T $U $W; do
    nsenter -t "$ns" -n ip link add dum0 type dummy
    nsenter -t "$ns" -n ip link set dum0 up
done
$IT ip route add 192.168.1.0/24 via 10.9.0.1
$IT ip -6 route add fd00:1::/64 via fd00:2::1
$IU ip route add 192.168.1.0/24 via 10.9.1.1
$IU ip -6 route add fd00:1::/64 via fd00:4::1
$IW ip route add 192.168.1.0/24 via 10.0.0.1
$IW ip -6 route add fd00:1::/64 via fd00:3::1
# Адреса за туннелем T. У настоящего туннеля соседей нет: маршрут выхода — `default dev t0`, и
# роутер спрашивает соседа прямо о цели, поэтому адреса IPv6 цели — на самом t1 (как в v6ns.sh).
$IT ip addr add 203.0.113.9/32 dev dum0
$IT ip addr add 192.0.2.50/32 dev dum0
$IT ip addr add 192.0.2.77/32 dev dum0
$IT ip addr add 2001:db8:1::1/128 dev t1 nodad
$IT ip addr add 198.51.100.50/32 dev dum0
$IT ip addr add 10.2.0.1/32 dev dum0
$IU ip addr add 10.2.0.1/32 dev dum0
# Адреса провайдера: вне списков, и «утечки» — адреса из списков, известные только ему.
$IW ip addr add 198.51.100.9/32 dev dum0
$IW ip addr add 203.0.113.77/32 dev dum0
$IW ip addr add 203.0.113.88/32 dev dum0
$IW ip addr add 198.51.100.50/32 dev dum0
$IW ip addr add 2001:db8:9::1/128 dev dum0
$IW ip addr add 2001:db8:1::77/128 dev dum0
# ARP через туннель: маршрут `default dev t0` без шлюза спрашивает соседа о самой цели.
for d in t1 u1; do
    nsenter -t "$( [ $d = t1 ] && echo $T || echo $U )" -n sysctl -qw net.ipv4.conf.$d.proxy_arp=1
done
sleep 0.5

ping4() { $IC ping -c 1 -W 2 "$1" >/dev/null 2>&1 && echo ok || echo нет; }
ping6c() { $IC ping -6 -c 1 -W 2 "$1" >/dev/null 2>&1 && echo ok || echo нет; }
check "без движка: адрес за туннелем недостижим" "нет" "$(ping4 203.0.113.9)"
check "без движка: адрес провайдера достижим" "ok" "$(ping4 198.51.100.9)"

# ---- ответчики: HTTP «кто я» на 10.2.0.1:8080 (T и U), эхо «кто я» на :9000, UDP-приёмник ----
cat > "$tmp/who.py" <<'PY'
import socket, sys, threading
name, mode = sys.argv[1], sys.argv[2]
if mode == "http":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8080)); s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.recv(1024)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(name), name.encode()))
        finally:
            c.close()
elif mode == "echo":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9000)); s.listen(8)
    def serve(c):
        f = c.makefile("rwb", 0)
        for line in f:
            f.write(name.encode() + b"\n")
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
elif mode == "udp":
    log = sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("198.51.100.50", 5555))
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.bind(("198.51.100.50", 5556))
    import select
    while True:
        r, _, _ = select.select([s, s2], [], [])
        for x in r:
            d, _ = x.recvfrom(65535)
            with open(log, "a") as f:
                f.write("%d %d\n" % (x.getsockname()[1], len(d)))
elif mode == "sink":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9100)); s.listen(8)
    while True:
        c, _ = s.accept()
        n = 0
        while True:
            d = c.recv(65536)
            if not d: break
            n += len(d)
        with open(sys.argv[3], "a") as f:
            f.write("%d\n" % n)
        c.close()
PY
$IT python3 "$tmp/who.py" T http >/dev/null 2>&1 & pids="$pids $!"
$IU python3 "$tmp/who.py" U http >/dev/null 2>&1 & pids="$pids $!"
$IT python3 "$tmp/who.py" T echo >/dev/null 2>&1 & pids="$pids $!"
$IU python3 "$tmp/who.py" U echo >/dev/null 2>&1 & pids="$pids $!"
$IT python3 "$tmp/who.py" T udp "$tmp/udp.T" >/dev/null 2>&1 & pids="$pids $!"
$IW python3 "$tmp/who.py" W udp "$tmp/udp.W" >/dev/null 2>&1 & pids="$pids $!"
$IT python3 "$tmp/who.py" T sink "$tmp/sink.T" >/dev/null 2>&1 & pids="$pids $!"
cat > "$tmp/cli.py" <<'PY'
import socket, sys, time
mode = sys.argv[1]
if mode == "http":
    seen = {}
    for i in range(int(sys.argv[2])):
        s = socket.create_connection(("10.2.0.1", 8080), timeout=3)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        d = b""
        while True:
            x = s.recv(1024)
            if not x: break
            d += x
        s.close()
        w = d.split(b"\r\n\r\n", 1)[-1].decode()
        seen[w] = seen.get(w, 0) + 1
    print(" ".join("%s=%d" % kv for kv in sorted(seen.items())))
elif mode == "sticky":
    # Одно соединение: строка — ответ «кто я»; между строками стенд меняет карту раздачи.
    s = socket.create_connection(("10.2.0.1", 9000), timeout=3)
    f = s.makefile("rwb", 0)
    out = []
    for i in range(int(sys.argv[2])):
        f.write(b"x\n"); out.append(f.readline().strip().decode())
        if i == 0:
            open(sys.argv[3], "w").write(out[0])
            t0 = time.time()
            while time.time() - t0 < 10:
                try:
                    if open(sys.argv[4]).read().strip() == "go": break
                except OSError:
                    pass
                time.sleep(0.1)
    print(" ".join(out))
elif mode == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"u" * int(sys.argv[3]), ("198.51.100.50", int(sys.argv[2])))
elif mode == "sink":
    s = socket.create_connection((sys.argv[2], 9100), timeout=5)
    b = b"z" * 65536
    for i in range(int(sys.argv[3])):
        s.sendall(b)
    s.close()
PY

# ---- спека: direct выше туннеля, туннель, balance, сужение по порту, fake-IP ----
printf '203.0.113.77/32\n' > "$tmp/d.lst"
printf '203.0.113.0/24\n2001:db8:1::/48\n' > "$tmp/a.lst"
printf '10.2.0.0/24\n' > "$tmp/b.lst"
printf '198.51.100.50/32\n' > "$tmp/u.lst"
printf 'fake.test\n' > "$tmp/f.lst"
printf '192.0.2.77/32\n' > "$tmp/m.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
clients:
  me: { mac: [02:00:00:00:00:c0] }
lists:
  m: { prefixes_file: $tmp/m.lst }
  d: { prefixes_file: $tmp/d.lst }
  a: { prefixes_file: $tmp/a.lst }
  b: { prefixes_file: $tmp/b.lst }
  u: { prefixes_file: $tmp/u.lst, proto: udp, ports: [5555] }
  f: { domains_file: $tmp/f.lst }
outputs:
  dir: { kind: direct }
  wg:  { kind: interface, device: t0, on_fail: drop }
  wu:  { kind: interface, device: u0, on_fail: drop }
  bal: { kind: group, pick: balance, members: [wg, wu] }
rules:
  - { name: m, for: [me], to: m, out: wg }
  - { name: d, to: d, out: dir }
  - { name: a, to: a, out: wg }
  - { name: b, to: b, out: bal }
  - { name: u, to: u, out: wg }
  - { name: f, to: f, out: wg }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply.out" 2>&1
check "apply проходит" "0" "$?"
check "  цепочка ingress_mark — на мосту br-lan" "1" \
    "$(nft list chain inet steer ingress_mark 2>/dev/null | grep -c 'hook ingress device "br-lan"')"
check "  prerouting_mark узнаёт разобранное на ingress первым правилом" "1" \
    "$(nft list chain inet steer prerouting_mark | sed -n 4p | grep -c 'comment "steer-ingress"')"
cnt() {   # cnt ЦЕПОЧКА ИМЯ_ПРАВИЛА — пакеты правил канала с этим именем в цепочке
    nft list chain inet steer "$1" 2>/dev/null | grep "comment \"steer:$2\"" |
        sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | awk '{ s += $1 } END { print s + 0 }'
}
gt0() { [ "$1" -gt 0 ] 2>/dev/null && echo yes || echo "no:$1"; }
# Правила a и f ведут в один выход без сужения — это одна группа «про сервис» (адреса и домены в
# одном наборе), её имя — у таблицы резолвера.
GA="$("$BIN" dnsd-table $S 2>/dev/null | awk -F'|' '$5 == "f" { print $1 }')"

# IPv4 и IPv6 канала a — в туннель; прочее — напрямую; утечки нет.
check "IPv4 из списка — в туннель (ответил туннель)" "ok" "$(ping4 203.0.113.9)"
check "  адрес списка, известный только провайдеру, напрямую не ушёл" "нет" "$(ping4 203.0.113.88)"
check "IPv4 вне списков — напрямую" "ok" "$(ping4 198.51.100.9)"
check "IPv6 из списка — в туннель" "ok" "$(ping6c 2001:db8:1::1)"
check "  IPv6 списка, известный только провайдеру, напрямую не ушёл" "нет" "$(ping6c 2001:db8:1::77)"
check "IPv6 вне списков — напрямую" "ok" "$(ping6c 2001:db8:9::1)"
check "direct выше канала туннеля выигрывает (адрес в обоих списках — напрямую)" "ok" \
    "$(ping4 203.0.113.77)"
# Клиент по MAC: ingress моста видит пакет, поднятый мостом в стек, с исходным заголовком
# Ethernet — ether saddr клиента, а не моста.
check "клиент по MAC (за портом моста) — в туннель" "ok" "$(ping4 192.0.2.77)"
GM="$(nft list chain inet steer ingress_mark | sed -n 's/.*ether saddr.* comment "steer:\([^"]*\)".*/\1/p' | head -n 1)"
check "  правило по ether saddr на ingress_mark узнало клиента" "yes" "$(gt0 "$(cnt ingress_mark "$GM")")"
check "счётчики канала a — в ingress_mark" "yes" "$(gt0 "$(cnt ingress_mark "$GA")")"
check "  запасные правила prerouting пакетов не видели" "0" "$(cnt prerouting_mark "$GA")"
check "  счётчик direct — в ingress_mark" "yes" "$(gt0 "$(cnt ingress_mark dir_ip)")"
# Метка соединения ставит prerouting по готовой метке пакета (ingress_ct): `steer conns` видит
# соединение канала на выходе wg, а соединение мимо каналов — нет (значение «разобран» снято до
# записи в conntrack и в ct mark не попадает).
$IC ping -c 1 -W 2 203.0.113.9 >/dev/null 2>&1
$IC ping -c 1 -W 2 198.51.100.9 >/dev/null 2>&1
conns="$("$BIN" conns $S 2>/dev/null)"
check "  метка соединения канала a — на выходе wg (steer conns)" "yes" \
    "$(printf '%s\n' "$conns" | grep -o '{[^{}]*203\.0\.113\.9[^{}]*}' | grep -q '"wg"' && echo yes || echo no)"
check "  у соединения мимо каналов метки соединения нет" "0" \
    "$(printf '%s\n' "$conns" | grep -c '198\.51\.100\.9')"
st=$("$BIN" status $S 2>/dev/null | grep -o "\"name\":\"$GA\"[^]]*" | sed -n 's/.*"packets":\([0-9]*\).*/\1/p' | head -n 1)
check "status: пакеты канала — из ingress_mark" "$(cnt ingress_mark "$GA")" "$st"

# fake-IP: поддельный адрес в наборе канала и в карте — разметка на ingress по поддельному
# адресу, dnat на prerouting по карте, маршрут — туннель (192.0.2.50 есть только там).
set_f="$GA"
nft add element inet steer "$set_f" '{ 198.18.0.5 }'
nft add element inet steer fakeip '{ 198.18.0.5 : 192.0.2.50 }'
check "fake-IP: клиент по поддельному адресу доходит до цели за туннелем" "ok" "$(ping4 198.18.0.5)"
check "  разметка по поддельному адресу — на ingress" "yes" "$(gt0 "$(cnt ingress_mark "$set_f")")"
check "  dnat по карте — на prerouting" "yes" \
    "$(nft list chain inet steer prerouting_dnat | grep '@fakeip' | grep -q 'packets [1-9]' && echo yes || echo no)"

# Сужение по порту и фрагменты: датаграмма 3000 байт на udp/5555 фрагментируется, у второго
# фрагмента портов нет, и на ingress правило канала его не узнаёт; собранный на prerouting пакет
# наследует метку первого фрагмента — доходит до туннеля целиком. Порт 5556 — вне сужения.
$IC python3 "$tmp/cli.py" udp 5555 3000
$IC python3 "$tmp/cli.py" udp 5555 200
$IC python3 "$tmp/cli.py" udp 5556 200
sleep 1
check "UDP 5555 (сужение канала) — в туннель, и большая датаграмма тоже" "5555 3000 5555 200" \
    "$(tr '\n' ' ' < "$tmp/udp.T" 2>/dev/null | sed 's/ $//')"
check "  UDP 5556 (вне сужения) — напрямую" "5556 200" "$(cat "$tmp/udp.W" 2>/dev/null)"

# balance: новые соединения — по обоим членам; установленное остаётся на своём при смене карты.
dist="$($IC python3 "$tmp/cli.py" http 40)"
check "balance: новые соединения расходятся по обоим членам ($dist)" "yes" \
    "$(echo "$dist" | grep -q 'T=' && echo "$dist" | grep -q 'U=' && echo yes || echo no)"
check "  ingress метит группу, prerouting ведёт в её цепочку" "yes" \
    "$(gt0 "$(cnt ingress_mark bal_ip)")"
map="$(nft list table inet steer | sed -n 's/.*map \(balmap_[0-9]*\).*/\1/p' | head -n 1)"
$IC python3 "$tmp/cli.py" sticky 4 "$tmp/first" "$tmp/go" > "$tmp/sticky.out" 2>&1 &
SP=$!
wait_for '[ -s "$tmp/first" ]' 5
first="$(cat "$tmp/first" 2>/dev/null)"
other=$([ "$first" = T ] && echo wu || echo wg)
reg() { awk -v o="$1" '$1 == o { print $3 }' "$tmp/st/registry"; }
# Все слоты карты — другому члену: так сторож уводит группу с члена.
els="$(seq 0 119 | sed "s/\$/ : goto mark_$(reg "$other")/" | tr '\n' ',' | sed 's/,$//')"
nft flush map inet steer "$map"
nft add element inet steer "$map" "{ $els }"
echo go > "$tmp/go"
wait "$SP"
check "  установленное соединение не перескочило при смене карты" "$first $first $first $first" \
    "$(cat "$tmp/sticky.out")"
dist2="$($IC python3 "$tmp/cli.py" http 10)"
check "  новые соединения — по новой карте" "$([ "$first" = T ] && echo U=10 || echo T=10)" "$dist2"

# ---- выгрузка потоков: flowtable на ingress с приоритетом filter — раньше нас ----
# Сначала тот же поток без выгрузки: разметка видит каждый его пакет (на veth — сотни: GRO
# склеивает сегменты в пакеты до 64 КБ). С выгрузкой — единицы: пакеты до установления потока.
b0=$(cnt ingress_mark "$GA")
$IC python3 "$tmp/cli.py" sink 203.0.113.9 160
seen_nf=$(( $(cnt ingress_mark "$GA") - b0 ))
nft -f - <<'EOF'
table inet ftab {
    flowtable ft {
        hook ingress priority filter
        devices = { "br-lan", "t0", "w0" }
    }
    chain f {
        type filter hook forward priority filter; policy accept;
        meta l4proto tcp flow add @ft
    }
}
EOF
if nft list flowtable inet ftab ft >/dev/null 2>&1; then
    b0=$(cnt ingress_mark "$GA")
    $IC python3 "$tmp/cli.py" sink 203.0.113.9 160
    sleep 0.5
    got="$(tail -n 1 "$tmp/sink.T" 2>/dev/null)"
    check "flowtable: поток в туннель дошёл целиком (10 МБ)" "10485760" "$got"
    seen=$(( $(cnt ingress_mark "$GA") - b0 ))
    check "  выгруженные пакеты мимо ingress_mark (разметка увидела $seen пакетов, без выгрузки — $seen_nf)" \
        "yes" "$([ $((seen * 10)) -lt "$seen_nf" ] && echo yes || echo no)"
    nft delete table inet ftab
else
    echo "ingressns: flowtable не встал — проверка выгрузки пропущена"
fi

# ---- откат: чужая перезапись метки между ingress и нами ----
# Так метит Tailscale (и pbr — маской 0x00ff0000): `and 0xff00ffff xor …` в prerouting раньше
# нас. Метка выхода 1-15 от неё обнуляется, и prerouting разбирает пакет заново — как без ingress.
nft -f - <<'EOF'
table inet stomp {
    chain p {
        type filter hook prerouting priority -150; policy accept;
        meta mark set mark and 0xff00ffff xor 0x00040000
    }
}
EOF
p0=$(cnt prerouting_mark "$GA")
check "перезапись метки: трафик канала по-прежнему в туннель" "ok" "$(ping4 203.0.113.9)"
check "  разобран заново запасными правилами prerouting" "yes" \
    "$(gt0 $(( $(cnt prerouting_mark "$GA") - p0 )))"
check "  адрес вне списков — по-прежнему напрямую" "ok" "$(ping4 198.51.100.9)"
nft delete table inet stomp

# ---- откат: мост пересоздан — ядро сняло цепочку ingress, разметку ведёт prerouting ----
ip link del br-lan
check "мост удалён: цепочки ingress_mark в ядре нет (одно устройство — снята целиком)" "1" \
    "$(nft list chain inet steer ingress_mark >/dev/null 2>&1; echo $?)"
mkbridge
sleep 0.5
p0=$(cnt prerouting_mark "$GA")
check "  мост создан заново: трафик канала в туннель (запасные правила prerouting)" "ok" \
    "$(ping4 203.0.113.9)"
# IPv6 нового моста встаёт не сразу (соседи клиента, адрес link-local моста) — ждём до 5 с.
wait_for '[ "$(ping6c 2001:db8:1::1)" = ok ]' 5
check "  и IPv6 тоже" "ok" "$(ping6c 2001:db8:1::1)"
check "  разметка — в prerouting_mark" "yes" "$(gt0 $(( $(cnt prerouting_mark "$GA") - p0 )))"
check "  утечки нет" "нет" "$(ping4 203.0.113.88)"
"$BIN" apply $S >/dev/null 2>&1
check "  apply ставит ingress_mark на новый мост" "1" \
    "$(nft list chain inet steer ingress_mark 2>/dev/null | grep -c 'device "br-lan"')"
check "  трафик снова размечается на ingress" "ok" "$(ping4 203.0.113.9)"

# ---- демон: reload после пересоздания моста — apply-сверка видит, что набор в ядре разошёлся с
# применённым (отпечаток таблицы, хук входит в него целиком), и ставит его заново ----
"$BIN" daemon --apply --socket "$tmp/s.sock" $S >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d.err"' 10
ip link del br-lan
mkbridge
sleep 0.3
check "демон: мост пересоздан — ingress_mark снята ядром" "1" \
    "$(nft list chain inet steer ingress_mark >/dev/null 2>&1; echo $?)"
"$BIN" ctl --socket "$tmp/s.sock" reload >"$tmp/reload.out" 2>&1
check "  reload ставит набор заново — ingress_mark на новом мосту" "1" \
    "$(nft list chain inet steer ingress_mark 2>/dev/null | grep -c 'device "br-lan"')"
check "  трафик канала в туннель" "ok" "$(ping4 203.0.113.9)"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null

# ---- устройство раздачи, которого нет: apply не отказывает, ingress — на существующих ----
sed 's/devices: \[br-lan\]/devices: [br-lan, nosuch0]/' "$tmp/spec.yaml" > "$tmp/spec2.yaml"
"$BIN" apply --spec "$tmp/spec2.yaml" --state-dir "$tmp/st" >"$tmp/apply2.out" 2>&1
check "устройства nosuch0 нет: apply проходит" "0" "$?"
check "  ingress_mark — только на br-lan" "1" \
    "$(nft list chain inet steer ingress_mark 2>/dev/null | grep -c 'hook ingress device "br-lan"')"
check "  трафик канала в туннель" "ok" "$(ping4 203.0.113.9)"

# ---- STEER_NFT_INGRESS=0: прежняя раскладка, только prerouting ----
STEER_NFT_INGRESS=0 "$BIN" apply $S >/dev/null 2>&1
check "без ingress: цепочки ingress_mark нет" "1" \
    "$(nft list chain inet steer ingress_mark >/dev/null 2>&1; echo $?)"
check "  трафик канала в туннель" "ok" "$(ping4 203.0.113.9)"
wait_for '[ "$(ping6c 2001:db8:1::1)" = ok ]' 5
check "  IPv6 канала в туннель" "ok" "$(ping6c 2001:db8:1::1)"

# ---- грубый замер: ingress, prerouting, без движка ----
if [ "${INGRESSNS_BENCH:-}" = 1 ] && command -v iperf3 >/dev/null 2>&1; then
    # Ответчик — на адресе цели (-B): ответ UDP без него уходит с адреса t1, и клиент, чей сокет
    # связан с 203.0.113.9, его не принимает.
    # Большой набор, чтобы поиск в нём стоил столько же, сколько на роутере со списками: 20000
    # подсетей /32 в канале, в который цель не входит, плюс канал цели.
    python3 -c "
import random
random.seed(1)
for i in range(20000):
    print('100.%d.%d.%d/32' % (64 + random.randrange(64), random.randrange(256), random.randrange(256)))
" > "$tmp/big.lst"
    sed 's#^rules:#rules:\n  - { name: big, to: big, out: wu }#; s#^lists:#lists:\n  big: { prefixes_file: '"$tmp"'/big.lst }#' \
        "$tmp/spec.yaml" > "$tmp/bench.yaml"
    B="--spec $tmp/bench.yaml --state-dir $tmp/st"
    run_udp() {
        $IT iperf3 -s -D -1 -B 203.0.113.9 >/dev/null 2>&1; sleep 0.3
        # -b 0 (без предела) на veth забивает и управляющее соединение iperf3; 600 Мбит/с по 64
        # байта — около 1,2 млн пакетов/с предложенной нагрузки, больше, чем пропускает пересылка.
        $IC iperf3 -c 203.0.113.9 -u -b 600M -l 64 -t 5 -J > "$tmp/u.json" 2>&1
        python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
e = d['end'].get('sum')
print('%d' % ((e['packets'] - e['lost_packets']) / e['seconds']) if e else 'нет:%s' % d.get('error'))
" "$tmp/u.json" 2>&1 | tail -n 1
    }
    run_tcp() {
        $IT iperf3 -s -D -1 -B 203.0.113.9 >/dev/null 2>&1; sleep 0.3
        $IC iperf3 -c 203.0.113.9 -t 5 -J 2>/dev/null |
            python3 -c "import json,sys; d=json.load(sys.stdin); print('%.0f' % (d['end']['sum_received']['bits_per_second']/1e6))" 2>/dev/null
    }
    # Режимы по очереди в каждом круге, а не круги подряд в одном режиме: дрейф машины (частота,
    # соседи) тогда ложится на все три одинаково.
    runs="${INGRESSNS_BENCH_RUNS:-3}"
    k=0
    while [ $k -lt "$runs" ]; do
        for mode in ingress prerouting none; do
            case $mode in
                ingress) "$BIN" apply $B >/dev/null 2>&1 ;;
                prerouting) STEER_NFT_INGRESS=0 "$BIN" apply $B >/dev/null 2>&1 ;;
                none) nft delete table inet steer 2>/dev/null
                      ip route add 203.0.113.9/32 dev t0 ;;
            esac
            echo "$(run_udp) $(run_tcp)" >> "$tmp/bench.$mode"
            [ $mode = none ] && ip route del 203.0.113.9/32 dev t0
        done
        k=$((k + 1))
    done
    for mode in ingress prerouting none; do
        python3 -c "
import statistics, sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
u = sorted(int(r[0]) for r in rows if r[0].isdigit())
t = sorted(int(r[1]) for r in rows if len(r) > 1 and r[1].isdigit())
print('ingressns bench: %-10s UDP 64 B, пакетов/с: медиана %d (%s); TCP, Мбит/с: медиана %d (%s)' % (
    sys.argv[2], statistics.median(u), ' '.join(map(str, u)), statistics.median(t), ' '.join(map(str, t))))
" "$tmp/bench.$mode" "$mode"
    done
fi

printf '\ningressns: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
