#!/bin/sh
# IPv6 от хоста через туннель WireGuard (шаг 8 выпуска 1.10; spec.h, enum out_ipv6): ключ `ipv6`
# у выхода — routed (префикс хоста), nat (NAT66 движком), off — с настоящим ядром и настоящим
# WireGuard.
#
# Сеть — пять пространств: роутер (сам стенд, без IPv6 у провайдера), клиент за r0 (адреса из
# префикса хоста 2001:db8:1:10::/64 и ULA fdaa:9::/64), хост-донор S1 за туннелем wg1 (ему
# провайдер «интернета» I маршрутизует 2001:db8:1::/56, а он — пиру), второй сервер S2 за wg2 (у
# пира один адрес 2001:db8:2:ff::2) и «интернет» I с целями IPv6:
#   2001:db8:e::1 — в списке правила в донора, 2001:db8:e::2 — в списке правила во второй выход,
#   2001:db8:e::3 — ни в одном списке.
# До целей IPv4 203.0.113.1 (только у S1) и 198.51.100.1 (только у S2) — ответ и есть путь.
#
# Что проверяется:
#   routed — IPv6 правила в донора идёт в донора; у правила во второй выход IPv6 отвергается сразу
#     (administratively prohibited) и AAAA его имён пуст; IPv4 правил — каждый в свой выход; всё
#     несовпавшее IPv6 из префикса — в донора; источник из префикса — ни одного пакета во второй
#     выход и в WAN (счётчик на postrouting роутера); ULA-источник к поддельному адресу fake-IP —
#     отказ, с адреса из префикса — доходит; туннель донора лёг — отказ сразу (prohibit), не утечка;
#     префикс без `prefix:` выводится из адресов LAN и нуль-маршрута netifd, сторож возвращает его в
#     набор, префикс провайдера не принимается, два кандидата — не угадываются;
#   nat — IPv6 правил в оба выхода, цель видит адрес выхода;
#   off — IPv6 правила в выход отвергается, AAAA пуст;
#   diag — «чего не хватает» по каждому случаю (адрес LAN из префикса, ip6assign, MTU, адрес
#     устройства у nat, ra_default у LAN только с ULA, хост не пускает источник).
#
# Нужны root, unshare, nsenter, ip, nft, ping, wg и модуль wireguard. Чего-то нет — стенд
# пропускается вслух, с кодом 0.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "v6host: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter ping wg; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${V6HOST_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    V6HOST_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up
[ -e /proc/sys/net/ipv6/conf/all/forwarding ] || skip "в ядре нет IPv6"
ip link add v6hwg type wireguard 2>/dev/null || skip "нет модуля wireguard"
ip link del v6hwg
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1 2>/dev/null
nft add table inet v6h_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet v6h_probe

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
unshare -n sleep 900 >/dev/null 2>&1 & S1=$!
unshare -n sleep 900 >/dev/null 2>&1 & S2=$!
unshare -n sleep 900 >/dev/null 2>&1 & I=$!
pids="$C $S1 $S2 $I"
sleep 0.3
IC="nsenter -t $C -n"; IS1="nsenter -t $S1 -n"; IS2="nsenter -t $S2 -n"; II="nsenter -t $I -n"
for n in $C $S1 $S2 $I; do
    nsenter -t "$n" -n ip link set lo up
    nsenter -t "$n" -n sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1 \
        net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
veth() {   # veth ЗДЕСЬ-PID ЗДЕСЬ ТАМ-PID ТАМ (PID «-» — пространство стенда)
    ip link add v6htmp0 type veth peer name v6htmp1
    if [ "$1" = - ]; then ip link set v6htmp0 name "$2"; else ip link set v6htmp0 netns "$1"; nsenter -t "$1" -n ip link set v6htmp0 name "$2"; fi
    ip link set v6htmp1 netns "$3"
    nsenter -t "$3" -n ip link set v6htmp1 name "$4"
    if [ "$1" = - ]; then ip link set "$2" up; else nsenter -t "$1" -n ip link set "$2" up; fi
    nsenter -t "$3" -n ip link set "$4" up
}
veth - r0 "$C" c0
veth - u1 "$S1" n1
veth - u2 "$S2" n2
veth "$S1" x1 "$I" i1
veth "$S2" x2 "$I" i2
# ЛВС: клиент с адресом из префикса хоста и с ULA.
ip addr add 192.168.9.1/24 dev r0
ip addr add 2001:db8:1:10::1/64 dev r0 nodad
ip addr add fdaa:9::1/64 dev r0 nodad
$IC ip addr add 192.168.9.10/24 dev c0
$IC ip addr add 2001:db8:1:10::10/64 dev c0 nodad
$IC ip addr add fdaa:9::10/64 dev c0 nodad
$IC ip route add default via 192.168.9.1
$IC ip -6 route add default via 2001:db8:1:10::1
# «WAN» роутера — только IPv4: своего IPv6 у роутера нет, IPv6 есть только у хостов.
sysctl -qw net.ipv6.conf.u1.disable_ipv6=1 net.ipv6.conf.u2.disable_ipv6=1
ip addr add 10.99.1.2/30 dev u1
ip addr add 10.99.2.2/30 dev u2
$IS1 ip addr add 10.99.1.1/30 dev n1
$IS2 ip addr add 10.99.2.1/30 dev n2
# Провайдер хостов: I маршрутизует префикс хоста в S1 и сеть пира второго сервера в S2.
$IS1 ip addr add 2001:db8:f1::1/64 dev x1 nodad
$IS2 ip addr add 2001:db8:f2::1/64 dev x2 nodad
$II ip addr add 2001:db8:f1::2/64 dev i1 nodad
$II ip addr add 2001:db8:f2::2/64 dev i2 nodad
$IS1 ip -6 route add default via 2001:db8:f1::2
$IS2 ip -6 route add default via 2001:db8:f2::2
$II ip -6 route add 2001:db8:1::/56 via 2001:db8:f1::1
$II ip -6 route add 2001:db8:2::/48 via 2001:db8:f2::1
$II ip link add dum0 type dummy
$II ip link set dum0 up
for a in 2001:db8:e::1 2001:db8:e::2 2001:db8:e::3 2001:db8:e::4; do
    $II ip addr add $a/128 dev dum0 nodad
done
# Кого цель видит источником: счётчики по адресам на входе I.
$II nft -f - <<'EOF'
table inet seen {
    chain in {
        type filter hook input priority 0; policy accept;
        ip6 saddr 2001:db8:1:ff::2 counter comment "exit1"
        ip6 saddr 2001:db8:2:ff::2 counter comment "exit2"
        ip6 saddr 2001:db8:1:10::10 counter comment "client"
    }
}
EOF
seen() { $II nft list chain inet seen in | grep "comment \"$1\"" | sed -n 's/.*packets \([0-9]*\).*/\1/p'; }
for n in "$S1" "$S2"; do
    nsenter -t "$n" -n ip link add dum0 type dummy
    nsenter -t "$n" -n ip link set dum0 up
    nsenter -t "$n" -n ip addr add 1.1.1.1/32 dev dum0
done
$IS1 ip addr add 203.0.113.1/32 dev dum0
$IS2 ip addr add 198.51.100.1/32 dev dum0
# WireGuard: роутер wg1 ↔ S1, wg2 ↔ S2.
for k in r1 r2 s1 s2; do wg genkey > "$tmp/$k.key"; wg pubkey < "$tmp/$k.key" > "$tmp/$k.pub"; done
$IS1 ip link add wg0 type wireguard
$IS2 ip link add wg0 type wireguard
$IS1 wg set wg0 private-key "$tmp/s1.key" listen-port 51820 peer "$(cat "$tmp/r1.pub")" \
    allowed-ips 10.100.1.2/32,192.168.9.0/24,2001:db8:1::/56
$IS2 wg set wg0 private-key "$tmp/s2.key" listen-port 51820 peer "$(cat "$tmp/r2.pub")" \
    allowed-ips 10.100.2.2/32,192.168.9.0/24,2001:db8:2:ff::2/128
for n in "$S1" "$S2"; do nsenter -t "$n" -n ip link set wg0 mtu 1420 up; done
$IS1 ip addr add 10.100.1.1/24 dev wg0
$IS2 ip addr add 10.100.2.1/24 dev wg0
$IS1 ip route add 192.168.9.0/24 dev wg0
$IS2 ip route add 192.168.9.0/24 dev wg0
$IS1 ip -6 route add 2001:db8:1::/56 dev wg0
$IS2 ip -6 route add 2001:db8:2:ff::2/128 dev wg0
ip link add wg1 type wireguard
ip link add wg2 type wireguard
wg set wg1 private-key "$tmp/r1.key" peer "$(cat "$tmp/s1.pub")" endpoint 10.99.1.1:51820 \
    allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 5
wg set wg2 private-key "$tmp/r2.key" peer "$(cat "$tmp/s2.pub")" endpoint 10.99.2.1:51820 \
    allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 5
ip link set wg1 mtu 1420 up
ip link set wg2 mtu 1420 up
ip addr add 10.100.1.2/24 dev wg1
ip addr add 10.100.2.2/24 dev wg2
ip addr add 2001:db8:1:ff::2/128 dev wg1 nodad
ip addr add 2001:db8:2:ff::2/128 dev wg2 nodad
wait_for 'ping -c 1 -W 1 10.100.1.1 >/dev/null 2>&1' 15
wait_for 'ping -c 1 -W 1 10.100.2.1 >/dev/null 2>&1' 15
# IPv6 «у провайдера роутера» — маршрут по умолчанию в main через isp0 (пустышка: что туда ушло,
# никуда не дойдёт, но счётчик утечки ниже это увидит). Так утечка источника из префикса в WAN
# возможна, и проверяется, что её нет.
ip link add isp0 type dummy
ip link set isp0 up
ip addr add 2001:db8:9::1/64 dev isp0 nodad
ip -6 route add default via 2001:db8:9::2 dev isp0
ping6c() { $IC ping -6 -c 1 -W 2 "$@" >/dev/null 2>&1 && echo ok || echo нет; }
# Без движка IPv6 клиента уходит провайдеру роутера (isp0) — и не доходит: цель знает только хост.
check "без движка: цель IPv6 недостижима (её знает только хост)" "нет" "$(ping6c 2001:db8:e::3)"
# Утечка источника из префикса: всё, что уходит с роутера с адресом из 2001:db8:1::/56 не в донора
# и не клиентам (и не самому себе через lo: так ядро отдаёт своим сокетам ошибки ICMPv6), — в
# счётчик.
nft -f - <<'EOF'
table inet leak {
    chain post {
        type filter hook postrouting priority 100; policy accept;
        oifname != { "wg1", "r0", "lo" } ip6 saddr 2001:db8:1::/56 counter comment "leak"
        oifname "wg2" ip6 saddr 2001:db8:1::/56 counter comment "leak-wg2"
        oifname "isp0" ip6 saddr 2001:db8:1::/56 counter comment "leak-isp0"
        oifname "lo" ip6 saddr 2001:db8:1::/56 counter comment "leak-lo"
        oifname != { "wg1", "r0" } ip6 saddr 2001:db8:1::/56 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld2-listener-report } counter comment "leak-nd"
    }
}
EOF
leak() {
    n=$(nft list chain inet leak post | grep 'comment "leak"' | sed -n 's/.*packets \([0-9]*\).*/\1/p')
    [ "$n" = 0 ] || nft list chain inet leak post | grep 'leak-' | grep -v 'packets 0 ' >&2
    echo "$n"
}
pingc() { $IC ping -c 1 -W 2 "$1" >/dev/null 2>&1 && echo ok || echo нет; }
# Отказ сразу: ответ «prohibited» и меньше секунды на всё.
refused() {
    t0=$(date +%s%N)
    out="$($IC ping -6 -c 1 -W 3 "$@" 2>&1)"
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    if printf '%s' "$out" | grep -qiE 'prohibited|unreachable' && [ $ms -lt 1500 ]; then echo сразу
    else echo "нет ($ms мс): $(printf '%s' "$out" | sed -n 2p)"; fi
}
# Пакетов на правиле с комментарием $2 в цепочке $1 (у prerouting_mark — вместе с ingress_mark:
# на ядре с inet ingress правила разметки стоят и там, и счёт идёт там).
cnt() {
    { nft list chain inet steer "$1" 2>/dev/null
      [ "$1" = prerouting_mark ] && nft list chain inet steer ingress_mark 2>/dev/null; } |
        grep "comment \"$2\"" | sed -n 's/.*packets \([0-9]*\).*/\1/p' | awk '{ s += $1 } END { print s + 0 }'
}


printf '203.0.113.1/32\n2001:db8:e::1/128\n' > "$tmp/a.lst"
printf '198.51.100.1/32\n2001:db8:e::2/128\n' > "$tmp/b.lst"
printf '2001:db8:e::4/128\n' > "$tmp/c.lst"
printf 'ahost.test\n' > "$tmp/fa.lst"
printf 'bhost.test\n' > "$tmp/fb.lst"
printf 'fhost.test\n' > "$tmp/ff.lst"
mkspec() {   # mkspec ФАЙЛ КЛЮЧИ_ДОНОРА КЛЮЧИ_ВТОРОГО
    cat > "$1" <<EOF
version: 2
lan: { devices: [r0] }
lists:
  a:  { prefixes_file: $tmp/a.lst }
  b:  { prefixes_file: $tmp/b.lst }
  fa: { domains_file: $tmp/fa.lst }
  fb: { domains_file: $tmp/fb.lst }
  ff: { domains_file: $tmp/ff.lst }
  c:  { prefixes_file: $tmp/c.lst }
outputs:
  host:  { kind: interface, device: wg1$2 }
  other: { kind: interface, device: wg2$3 }
  dir:   { kind: direct }
rules:
  - { name: a,  to: a,  out: host }
  - { name: b,  to: b,  out: other }
  - { name: c,  to: c,  out: dir }
  - { name: fa, to: fa, out: host, resolve: realip }
  - { name: fb, to: fb, out: other, resolve: realip }
  - { name: ff, to: ff, out: host }
EOF
}
mkdir -p "$tmp/uci"
uci_net() {   # uci_net IP6ASSIGN — /etc/config/network стенда
    cat > "$tmp/uci/network" <<EOF
config interface 'lan'
	option device 'r0'
	option proto 'static'
	option ip6assign '$1'

config interface 'wg1'
	option proto 'wireguard'
	option ip6prefix '2001:db8:1::/56'
EOF
}
uci_net 64
cat > "$tmp/uci/dhcp" <<'EOF'
config dhcp 'lan'
	option interface 'lan'
	option ra 'server'
EOF
export STEER_UCI_DIR="$tmp/uci" STEER_V6PROBE_TARGET=2001:db8:e::3
diagv() { "$BIN" diag $S 2>/dev/null | tr '{' '\n' | grep '"id":"ipv6_host"'; }

# ======== routed: префикс хоста записан ========
mkspec "$tmp/r.yaml" ', ipv6: routed, prefix: "2001:db8:1::/56"' ''
S="--spec $tmp/r.yaml --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply-r.out" 2>&1
check "routed: apply проходит (nft принял набор)" "0" "$?"
reg() { awk -v o="$1" '$1 == o { print $'"$2"' }' "$tmp/st/registry"; }
check "  ip -6 rule донора есть" "1" "$(ip -6 rule show | grep -c "fwmark 0x$(reg host 2)/")"
check "  ip -6 rule второго выхода нет (IPv6 у него снят)" "0" \
    "$(ip -6 rule show | grep -c "fwmark 0x$(reg other 2)/")"
check "  набор v6donor — префикс хоста" "1" \
    "$(nft list set inet steer v6donor | grep -c '2001:db8:1::/56')"
check "IPv6 правила в донора — в донора (ответила цель)" "ok" "$(ping6c 2001:db8:e::1)"
check "IPv4 правила в донора — в донора (адрес есть только у S1)" "ok" "$(pingc 203.0.113.1)"
check "IPv4 правила во второй выход — во второй (адрес есть только у S2)" "ok" "$(pingc 198.51.100.1)"
check "IPv6 правила во второй выход — отказ сразу" "сразу" "$(refused 2001:db8:e::2)"
check "  отказ — правилом forward_v6 по метке второго выхода" "yes" \
    "$([ "$(cnt forward_v6 steer-v6drop:other)" -gt 0 ] 2>/dev/null && echo yes || echo no)"
check "IPv6 правила direct из префикса — отказ сразу, в WAN не ушёл" "сразу" "$(refused 2001:db8:e::4)"
check "  отказ — запретом источника из префикса мимо донора" "yes" \
    "$(cnt forward_v6 steer-v6src:host | grep -q '^[1-9]' && echo yes || echo no)"
check "несовпавший IPv6 из префикса — в донора" "ok" "$(ping6c 2001:db8:e::3)"
check "  правило «всё несовпавшее — в донора» считало пакеты" "yes" \
    "$(cnt prerouting_mark steer-v6donor:host | grep -q '^[1-9]' && echo yes || echo no)"
check "цель видела источником адрес клиента из префикса" "yes" \
    "$([ "$(seen client)" -gt 0 ] && echo yes || echo no)"

# Резолвер: AAAA имени под правилом в донора — настоящий адрес (real-ip), во второй выход — пусто.
if command -v python3 >/dev/null 2>&1; then
    cat > "$tmp/up.py" <<'PY'
import socket, sys
A = {b'\x05ahost\x04test\x00': '2001:db8:e::1', b'\x05bhost\x04test\x00': '2001:db8:e::2',
     b'\x05fhost\x04test\x00': '2001:db8:e::1'}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    name = data[12:qend + 1]
    qtype = data[qend + 1] << 8 | data[qend + 2]
    qend += 5
    if qtype == 28 and name in A:
        n, ans = 1, b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + \
            socket.inet_pton(socket.AF_INET6, A[name])
    elif qtype == 1:
        n, ans = 1, b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([203, 0, 113, 1])
    else:
        n, ans = 0, b''
    hdr = data[:2] + b'\x81\x80' + data[4:6] + bytes([0, n, 0, 0, 0, 0])
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
    cat > "$tmp/q6.py" <<'PY'
import socket, struct, sys
server, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
q = struct.pack('>HHHHHH', 0x5a5a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 28, 1)
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (server, port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
if struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(socket.inet_ntop(socket.AF_INET6, d[-16:]))
PY
    python3 "$tmp/up.py" 15493 >/dev/null 2>&1 & UP=$!
    "$BIN" dnsd $S --listen-port 15490 --upstream-port 15493 >"$tmp/dnsd.out" 2>&1 & DN=$!
    pids="$pids $UP $DN"
    sleep 1
    check "AAAA имени под правилом в донора — адрес" "2001:db8:e::1" \
        "$($IC python3 "$tmp/q6.py" 2001:db8:1:10::1 15490 ahost.test)"
    check "AAAA имени под правилом во второй выход — пусто" "empty" \
        "$($IC python3 "$tmp/q6.py" 2001:db8:1:10::1 15490 bhost.test)"
    fk="$($IC python3 "$tmp/q6.py" 2001:db8:1:10::1 15490 fhost.test)"
    check "fake-IP в донора: поддельный IPv6 выдан" "fdfe:dcba:9876::c612" "$(echo "$fk" | sed 's/:[0-9a-f]*$//')"
    # К поддельному адресу (ULA) клиент по RFC 6724 идёт со своего ULA — хост такой источник не
    # пропустит, и роутер отказывает сразу; с адреса из префикса — доходит.
    check "  с ULA-источника — отказ сразу" "сразу" "$(refused -I fdaa:9::10 "$fk")"
    check "  отказ — правилом steer-v6ula" "yes" \
        "$(cnt forward_v6 steer-v6ula:host | grep -q '^[1-9]' && echo yes || echo no)"
    check "  с адреса из префикса — доходит" "ok" "$(ping6c -I 2001:db8:1:10::10 "$fk")"
    kill "$DN" "$UP" 2>/dev/null
    wait "$DN" 2>/dev/null
else
    echo "v6host: python3 нет — AAAA не проверены"
fi
check "таблица резолвера: правило в донора — IPv4 и IPv6, во второй выход — только IPv4" "46 4" \
    "$("$BIN" dnsd-table $S 2>/dev/null | awk -F'|' '$5 == "fa" { a = $4 } $5 == "fb" { b = $4 } END { print a, b }')"

# diag: всё на месте — префикс и адрес LAN из него, хост отвечает по IPv6.
d="$(diagv)"
check "diag routed: префикс хоста и адрес LAN из него" "1" \
    "$(printf '%s\n' "$d" | grep -c '"ok","what":"выход host: префикс хоста 2001:db8:1::/56, у LAN адрес из него"')"
check "diag routed: IPv6 через wg1 отвечает" "1" "$(printf '%s\n' "$d" | grep -c 'IPv6 через wg1 отвечает')"
# Хост не пускает источник: у пира на S1 в AllowedIPs нет префикса.
$IS1 wg set wg0 peer "$(cat "$tmp/r1.pub")" allowed-ips 10.100.1.2/32,192.168.9.0/24
check "diag: хост не пускает адреса префикса — сказано" "1" \
    "$(diagv | grep -c 'сервер не пускает адреса префикса')"
$IS1 wg set wg0 peer "$(cat "$tmp/r1.pub")" allowed-ips 10.100.1.2/32,192.168.9.0/24,2001:db8:1::/56
# У пира на самом роутере в AllowedIPs нет ::/0 — IPv6 в туннель не пускает WireGuard роутера.
wg set wg1 peer "$(cat "$tmp/s1.pub")" allowed-ips 0.0.0.0/0
check "diag: у пира роутера нет ::/0 — сказано" "1" "$(diagv | grep -c 'у пира в AllowedIPs нет ::/0')"
wg set wg1 peer "$(cat "$tmp/s1.pub")" allowed-ips 0.0.0.0/0,::/0
# ip6assign короче префикса.
uci_net 48
check "diag: ip6assign больше префикса — сказано" "1" "$(diagv | grep -c 'ip6assign 48 у lan больше префикса хоста /56')"
uci_net 64
# У LAN нет адреса из префикса. Чего не хватает, diag различает по нуль-маршруту netifd
# (`unreachable P`, им netifd объявляет каждый раздаваемый префикс): его нет — нет ip6prefix; есть —
# LAN не получил куска: нет ip6assign или, если он задан, дело в ip6class.
ip addr del 2001:db8:1:10::1/64 dev r0
check "diag: префикс не раздаётся — сказано, что нет ip6prefix" "1" \
    "$(diagv | grep -c 'префикс 2001:db8:1::/56 не раздаётся — нет ip6prefix","why":"клиенты не получат IPv6 от хоста — задайте ip6prefix у интерфейса wg1"')"
ip -6 route add unreachable 2001:db8:1::/56 metric 2147483647
check "diag: префикс раздаётся, у LAN адреса нет, ip6assign задан — проверить ip6class" "1" \
    "$(diagv | grep -c 'у LAN нет адреса из префикса 2001:db8:1::/56, хотя ip6assign 64 задан","why":"клиенты не получат IPv6 от хоста — проверьте ip6class у LAN"')"
uci_net ''
check "  ip6assign не задан — сказано, что его нет" "1" \
    "$(diagv | grep -c 'у LAN нет адреса из префикса 2001:db8:1::/56 — нет ip6assign","why":"клиенты не получат IPv6 от хоста — задайте ip6assign у LAN"')"
uci_net 64
# Префикс сняли, а адрес из него остался на LAN устаревшим (preferred_lft 0): он не в счёт.
ip addr add 2001:db8:1:10::1/64 dev r0 nodad preferred_lft 0
check "diag: устаревший адрес LAN — не адрес из префикса" "0 1" \
    "$(diagv | grep -c 'у LAN адрес из него') $(diagv | grep -c 'у LAN нет адреса из префикса 2001:db8:1::/56, хотя')"
ip addr del 2001:db8:1:10::1/64 dev r0
ip -6 route del unreachable 2001:db8:1::/56
ip addr add 2001:db8:1:10::1/64 dev r0 nodad
sleep 0.5

# Туннель донора лёг: маршрут в wg1 ядро вычистило, в таблице IPv6 остался запасной prohibit.
ip link set wg1 down
check "донор лёг: IPv6 — отказ сразу (prohibit), а не таймаут" "сразу" "$(refused 2001:db8:e::1)"
check "  несовпавший IPv6 из префикса — тоже отказ сразу" "сразу" "$(refused 2001:db8:e::3)"
check "  в таблице IPv6 донора — prohibit" "1" \
    "$(ip -6 route show table "$(reg host 3)" | grep -c '^prohibit default')"
ip link set wg1 up
ip addr add 2001:db8:1:ff::2/128 dev wg1 nodad 2>/dev/null
"$BIN" failover $S >/dev/null 2>&1
wait_for '[ "$(ping6c 2001:db8:e::1)" = ok ]' 10
check "донор вернулся: IPv6 снова в донора" "ok" "$(ping6c 2001:db8:e::1)"

# MTU ниже 1280 — IPv6 на устройстве выключен ядром.
ip link set wg1 mtu 1200
check "diag: MTU wg1 ниже 1280 — сказано" "1" "$(diagv | grep -c '"fail","what":"выход host: у wg1 MTU 1200')"
ip link set wg1 mtu 1420
ip addr add 2001:db8:1:ff::2/128 dev wg1 nodad 2>/dev/null
"$BIN" apply $S >/dev/null 2>&1
check "источник из префикса: ни одного пакета во второй выход и в WAN" "0" "$(leak)"

# ======== routed: префикс выводится из адресов LAN и нуль-маршрута netifd ========
mkspec "$tmp/d.yaml" ', ipv6: routed' ''
S="--spec $tmp/d.yaml --state-dir $tmp/st"
check "без нуль-маршрута префикс не выводится — набор пуст" "0" \
    "$("$BIN" apply --dry-run $S 2>/dev/null | sed -n '/set v6donor/,/}/p' | grep -c elements)"
ip -6 route add unreachable 2001:db8:1::/56 metric 2147483647
check "нуль-маршрут и адрес LAN из него — префикс выведен" "1" \
    "$("$BIN" apply --dry-run $S 2>/dev/null | sed -n '/set v6donor/,/}/p' | grep -c 'elements = { 2001:db8:1::/56 }')"
"$BIN" apply $S >/dev/null 2>&1
nft flush set inet steer v6donor
check "  набор опустошён снаружи" "0" "$(nft list set inet steer v6donor | grep -c 2001:db8:1::/56)"
"$BIN" failover $S >"$tmp/fo.out" 2>&1
check "  проход сторожа вернул префикс в набор" "1" "$(nft list set inet steer v6donor | grep -c '2001:db8:1::/56')"
check "  и сказал об этом" "1" "$(grep -c 'префикс хоста — 2001:db8:1::/56' "$tmp/fo.out")"
check "  IPv6 несовпавшего — снова в донора" "ok" "$(ping6c 2001:db8:e::3)"
check "status: префикс донора" "1" \
    "$("$BIN" status $S 2>/dev/null | grep -c '"ipv6":"routed","prefix":"2001:db8:1::/56"')"
# Префикс провайдера (маршрут по умолчанию с источником через чужое устройство) — не донора.
ip -6 route add default from 2001:db8:1::/56 via 2001:db8:9::2 dev isp0
check "префикс с маршрутом провайдера — не донора, не выводится" "0" \
    "$("$BIN" apply --dry-run $S 2>/dev/null | sed -n '/set v6donor/,/}/p' | grep -c elements)"
ip -6 route del default from 2001:db8:1::/56 via 2001:db8:9::2 dev isp0
# Два кандидата — не угадываем.
ip addr add 2001:db8:5:10::1/64 dev r0 nodad
ip -6 route add unreachable 2001:db8:5::/56 metric 2147483647
check "два префикса у LAN — не угадывается, apply просит prefix:" "1" \
    "$("$BIN" apply --dry-run $S 2>&1 >/dev/null | grep -c 'задайте prefix: у выхода')"
check "  diag — тоже" "1" "$(diagv | grep -c 'префикс хоста не узнать')"
ip -6 route del unreachable 2001:db8:5::/56
ip addr del 2001:db8:5:10::1/64 dev r0
check "источник из префикса: ни одного пакета во второй выход и в WAN (после вывода)" "0" "$(leak)"

# ======== off ========
mkspec "$tmp/o.yaml" ', ipv6: off' ''
S="--spec $tmp/o.yaml --state-dir $tmp/st"
"$BIN" apply $S >/dev/null 2>&1
check "off: apply проходит" "0" "$?"
check "  IPv6 правила в выход — отказ сразу" "сразу" "$(refused 2001:db8:e::1)"
check "  ip -6 rule выхода снят" "0" "$(ip -6 rule show | grep -c "fwmark 0x$(reg host 2)/")"
check "  таблица резолвера: имя под правилом — только IPv4" "4" \
    "$("$BIN" dnsd-table $S 2>/dev/null | awk -F'|' '$5 == "fa" { print $4 }')"

# ======== nat: у пира один адрес, клиенты на ULA ========
ip addr del 2001:db8:1:10::1/64 dev r0
ip -6 route del unreachable 2001:db8:1::/56
$IC ip addr del 2001:db8:1:10::10/64 dev c0
$IC ip -6 route replace default via fdaa:9::1
mkspec "$tmp/n.yaml" ', ipv6: nat' ', ipv6: nat'
S="--spec $tmp/n.yaml --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply-n.out" 2>&1
check "nat: apply проходит" "0" "$?"
check "  masquerade IPv6 — своей цепочкой движка на оба выхода" "2" \
    "$(nft list chain inet steer postrouting_nat6 | grep -c 'meta nfproto ipv6 counter.* masquerade comment "steer-nat6:')"
check "  IPv6 правила в донора доходит" "ok" "$(ping6c 2001:db8:e::1)"
check "  цель видит адрес выхода wg1" "yes" "$([ "$(seen exit1)" -gt 0 ] && echo yes || echo no)"
check "  IPv6 правила во второй выход доходит" "ok" "$(ping6c 2001:db8:e::2)"
check "  цель видит адрес выхода wg2" "yes" "$([ "$(seen exit2)" -gt 0 ] && echo yes || echo no)"
check "diag nat: у LAN только ULA и ra_default нет — сказано" "1" \
    "$(diagv | grep -c 'задайте ra_default=1 в dhcp.lan')"
# Глобальный адрес на LAN есть, но устаревший (ip6prefix сняли): клиентам он не раздаётся, и про
# ra_default сказать всё равно надо.
ip addr add 2001:db8:1:10::1/64 dev r0 nodad preferred_lft 0
check "  и при устаревшем глобальном адресе на LAN — тоже" "1" \
    "$(diagv | grep -c 'задайте ra_default=1 в dhcp.lan')"
ip addr del 2001:db8:1:10::1/64 dev r0
printf '\toption ra_default %s\n' "'1'" >> "$tmp/uci/dhcp"
check "  ra_default=1 — молчит" "0" "$(diagv | grep -c 'ra_default')"
check "diag nat: хост отвечает по IPv6" "2" "$(diagv | grep -c 'отвечает')"
ip addr del 2001:db8:2:ff::2/128 dev wg2
check "diag nat: у устройства нет адреса IPv6 — сказано" "1" \
    "$(diagv | grep -c '"fail","what":"выход other: у wg2 нет адреса IPv6"')"
ip addr add 2001:db8:2:ff::2/128 dev wg2 nodad
check "status nat: nat6 — подменяет движок" "2" \
    "$("$BIN" status $S 2>/dev/null | grep -o '"nat6":true,"nat6_by":"steer"' | wc -l | tr -d ' ')"

# Группа из выходов с `ipv6: nat`, у самой группы ключа нет: IPv6 её нынешнего члена маскирует
# цепочка движка (правило — на выход-член), и status группы говорит nat6: true, кем — steer.
cat > "$tmp/g.yaml" <<EOF
version: 2
lan: { devices: [r0] }
lists:
  a:  { prefixes_file: $tmp/a.lst }
  b:  { prefixes_file: $tmp/b.lst }
outputs:
  host:  { kind: interface, device: wg1, ipv6: nat }
  other: { kind: interface, device: wg2, ipv6: nat }
  man:   { kind: group, pick: manual, members: [host, other], default: host }
rules:
  - { name: a, to: a, out: man }
  - { name: b, to: b, out: other }
EOF
S="--spec $tmp/g.yaml --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply-g.out" 2>&1
check "группа из членов с ipv6: nat — apply проходит" "0" "$?"
check "  status группы: nat6 — подменяет движок" "1" \
    "$("$BIN" status $S 2>/dev/null | grep -o '"man":{[^}]*' | grep -c '"nat6":true,"nat6_by":"steer"')"
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
check "steer down: набор правил снят" "1" "$(nft list table inet steer >/dev/null 2>&1; echo $?)"
check "  правил IPv6 выходов нет" "0" "$(ip -6 rule show | grep -c 'fwmark 0x')"

[ "$fail" -gt 0 ] && { tail -n 20 "$tmp/apply-r.out" "$tmp/apply-n.out"; }
printf 'v6host: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
