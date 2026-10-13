#!/bin/sh
# Канал с набором sing-box и настоящее ядро: составной набор, пакеты и резолвер.
#
# Генератор проверяется текстом (tests/srsgen.sh), но текст не скажет, примет ли ядро составной
# интервальный набор, поймает ли правило `ip daddr . meta l4proto . th dport @набор` то, что
# должно, и положит ли резолвер в такой набор элемент по netlink. Здесь всё это делается в
# отдельном сетевом пространстве:
#
#  1. Пакеты. Клиент в своём пространстве за veth, набор tests/srs/mixed.srs: 198.51.100.128/25
#     без сужения, 198.51.100.0/24 и 203.0.113.0/25 — udp 50000-65535, 192.0.2.0/24 — udp
#     19000-20000. Ожидаемые попадания в правило канала: ICMP к подсети без сужения — да (у
#     протокола без портов `th dport` читает два байта заголовка, и они в 0-65535); TCP к ней же
#     — да; UDP в сужении — да; UDP вне сужения — нет; ICMP и TCP к подсети «только udp» — нет.
#  2. Проба ядра: без STEER_NFT_CONCAT движок сам спрашивает ядро и выбирает составной набор.
#  3. Резолвер: имена из набора (tests/srs/dnsmixed.srs) ложатся в составной набор ПО NETLINK
#     элементом «поддельный адрес . протокол . порты» — с сужением своей клаузы; имя под
#     исключением («excl.example, но не no.excl.example») не ложится вовсе.
#  4. explain по адресу из составного набора называет канал и его сужение.
#  5. Тот же набор в режиме realip: настоящий адрес — в составной набор со сроком и сужением, а
#     после замены набора правил и HUP — снова там же, из памяти резолвера.
#
# Нужны root, nft, ip, nsenter и python3. Без них стенд пропускается, а не проваливается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
for t in nft ip nsenter python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "srsnft: $t нет — пропускаю"; exit 0; }
done
if [ "${SRSNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "srsnft: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "srsnft: unshare -n недоступен — пропускаю"; exit 0; }
    SRSNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
FIX="$(pwd)/tests/srs"
ip link set lo up
nft add table inet srsnft_probe 2>/dev/null || { echo "srsnft: nf_tables недоступен — пропускаю"; exit 0; }
nft delete table inet srsnft_probe

tmp="$(mktemp -d /tmp/srsnft.XXXXXX)"
trap 'kill ${CPID:-0} ${DPID:-0} ${UPID:-0} 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

# ---- клиент за veth ------------------------------------------------------------------------
unshare -n sleep 600 & CPID=$!
sleep 0.2
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$CPID"
ip addr add 10.99.0.1/24 dev veth0
ip link set veth0 up
inc() { nsenter -t "$CPID" -n "$@"; }
inc ip link set lo up
inc ip addr add 10.99.0.2/24 dev veth1
inc ip link set veth1 up
inc ip route add default via 10.99.0.1

# ---- набор правил ----------------------------------------------------------------------------
cat > "$tmp/spec.yaml" <<EOF
version: 2

lan: { devices: [br-lan], addr: [10.99.0.0/24] }

lists:
  mixed: { srs: [$FIX/mixed.srs] }

outputs:
  vpn: { kind: interface, device: veth0 }

rules:
  - { name: mixed, to: [mixed], out: vpn }
EOF
# Проба ядра — без подсказок окружения: движок сам спрашивает, примет ли ядро составной набор.
env -u STEER_NFT_CONCAT -u STEER_NFT_COMPAT "$BIN" apply --dry-run --spec "$tmp/spec.yaml" \
    --state-dir "$tmp/st" > "$tmp/rs.nft" 2> "$tmp/rs.err"
check "проба ядра: составной набор выбран сам" yes \
    "$(grep -q 'type ipv4_addr . inet_proto . inet_service' "$tmp/rs.nft" && echo yes || echo no)"
nft -f "$tmp/rs.nft" 2> "$tmp/load.err"
check "ядро приняло набор правил с составным набором" 0 "$?"
[ -s "$tmp/load.err" ] && cat "$tmp/load.err"

# Сумма по правилам канала: у доменной группы выхода с IPv6 рядом с правилом IPv4 стоит его
# v6-двойник с тем же комментарием (1.9, fake-IP v6), и счётчик канала — их сумма.
cnt() { nft list chain inet steer prerouting_mark 2>/dev/null |
        sed -n 's/.*counter packets \([0-9]*\) .*comment "steer:vpn_dom_c0_m".*/\1/p' |
        awk '{ s += $1 } END { print s + 0 }'; }
udp() { inc python3 -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'x',('$1',$2))"; }
tcp() { inc python3 -c "
import socket
s=socket.socket(); s.settimeout(0.3)
try: s.connect(('$1',$2))
except Exception: pass"; }
icmp() { inc ping -c1 -W1 "$1" >/dev/null 2>&1; }
# Попало ли в правило канала: разница счётчика до и после.
probe() {   # что ожидается, описание, команда...
    want="$1"; what="$2"; shift 2
    b="$(cnt)"; "$@"; sleep 0.2; a="$(cnt)"
    [ "$a" -gt "$b" ] 2>/dev/null && got=hit || got=miss
    check "$what" "$want" "$got"
}
probe hit  "ICMP к подсети без сужения — в канале"      icmp 198.51.100.200
probe hit  "TCP к подсети без сужения — в канале"       tcp 198.51.100.200 443
probe hit  "UDP 50001 к подсети «udp 50000-65535» — в канале" udp 203.0.113.10 50001
probe miss "UDP 40000 к ней же — мимо (вне сужения)"    udp 203.0.113.10 40000
probe miss "TCP 50001 к ней же — мимо (только udp)"     tcp 203.0.113.10 50001
probe miss "ICMP к ней же — мимо (только udp)"          icmp 203.0.113.10
probe hit  "UDP 19500 к подсети «udp 19000-20000» — в канале" udp 192.0.2.5 19500
probe miss "UDP 50001 к ней — мимо (у неё другое сужение)" udp 192.0.2.5 50001
probe hit  "UDP 50001 к 198.51.100.10 (сужение набора) — в канале" udp 198.51.100.10 50001
probe miss "TCP к 198.51.100.10 — мимо"                  tcp 198.51.100.10 443

# ---- explain по составному набору ------------------------------------------------------------
ex="$("$BIN" explain 203.0.113.10 --spec "$tmp/spec.yaml" --state-dir "$tmp/st" 2>&1)"
check "explain: адрес найден в составном наборе" yes \
    "$(printf '%s' "$ex" | grep -q '"vpn_dom_c0_m"' && echo yes || echo no)"
check "explain: и названо сужение" yes \
    "$(printf '%s' "$ex" | grep -q 'канал сужен: только udp 50000-65535' && echo yes || echo no)"
ex="$("$BIN" explain 198.51.100.200 --spec "$tmp/spec.yaml" --state-dir "$tmp/st" 2>&1)"
check "explain: адрес без сужения — без строки о сужении" no \
    "$(printf '%s' "$ex" | grep -q 'канал сужен' && echo yes || echo no)"

# ---- резолвер: имена набора в составной набор по netlink --------------------------------------
nft delete table inet steer 2>/dev/null
cat > "$tmp/dspec.yaml" <<EOF
version: 2

lan: { devices: [br-lan], addr: [10.99.0.0/24] }

lists:
  names: { srs: [$FIX/dnsmixed.srs] }

outputs:
  vpn: { kind: interface, device: veth0 }

rules:
  - { name: names, to: [names], out: vpn }
EOF
STEER_NFT_CONCAT=1 "$BIN" apply --dry-run --spec "$tmp/dspec.yaml" --state-dir "$tmp/st2" \
    > "$tmp/drs.nft" 2>/dev/null
nft -f "$tmp/drs.nft"
check "набор правил резолверного канала принят" 0 "$?"
SET="$(sed -n 's/^    set \(vpn_dom_c0_m\) {/\1/p' "$tmp/drs.nft")"
check "у канала составной доменный набор" vpn_dom_c0_m "$SET"

LPORT=15410 UPORT=15463
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ip = sys.argv[2] if len(sys.argv) > 2 else "203.0.113.99"
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes(int(x) for x in ip.split("."))
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/client.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
print(".".join(str(b) for b in d[-4:]))
PY
python3 "$tmp/upstream.py" "$UPORT" & UPID=$!
sleep 0.5
STEER_NFT_CONCAT=1 "$BIN" dnsd --spec "$tmp/dspec.yaml" --state-dir "$tmp/st2" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/dnsd.log" 2>&1 & DPID=$!
sleep 1
kill -0 "$DPID" 2>/dev/null || { echo "FAIL резолвер не поднялся:"; cat "$tmp/dnsd.log"; exit 1; }
ask() { python3 "$tmp/client.py" "$LPORT" "$1"; }
els() { nft list set inet steer vpn_dom_c0_m | tr -d '\n\t' | sed 's/  */ /g'; }
fv="$(ask a.voice.example)"
fp="$(ask www.plain.example)"
fx="$(ask www.excl.example)"
fn="$(ask no.excl.example)"
sleep 0.3
E="$(els)"
check "имя из набора — поддельный адрес" 198.18 "$(echo "$fv" | cut -d. -f1-2)"
check "имя с сужением — элемент «адрес . udp . 50000-65535»" yes \
    "$(printf '%s' "$E" | grep -q "$fv . udp . 50000-65535" && echo yes || echo no)"
check "имя без сужения — элемент «адрес . 0-255 . 0-65535»" yes \
    "$(printf '%s' "$E" | grep -q "$fp . 0-255 . 0-65535" && echo yes || echo no)"
check "имя под «и» с исключением — в наборе" yes \
    "$(printf '%s' "$E" | grep -q "$fx . 0-255 . 0-65535" && echo yes || echo no)"
check "исключённое имя — настоящий адрес, не поддельный" 203.0.113.99 "$fn"
check "подсети набора — элементами из набора правил" yes \
    "$(printf '%s' "$E" | grep -q '203.0.113.0/24 . udp . 50000-65535' && echo yes || echo no)"

# ---- резолвер real-ip: составной набор, возврат после замены набора правил ---------------------
# Тот же набор имён в режиме realip: настоящий адрес ложится в составной набор со сроком и с
# сужением своей клаузы; набор правил заменён (наборы пусты) — HUP возвращает элемент из памяти
# резолвера (src/dnsd/realip.c) с тем же сужением и со сроком. Апстрим отвечает адресом вне
# подсетей набора: адрес внутри подсети с тем же сужением ядро в интервальный набор не примет.
kill "$DPID" "$UPID" 2>/dev/null; wait "$DPID" "$UPID" 2>/dev/null
python3 "$tmp/upstream.py" "$UPORT" 100.64.0.7 & UPID=$!
nft delete table inet steer 2>/dev/null
cat > "$tmp/rspec.yaml" <<EOF
version: 2

lan: { devices: [br-lan], addr: [10.99.0.0/24] }

lists:
  names: { srs: [$FIX/dnsmixed.srs] }

outputs:
  vpn: { kind: interface, device: veth0 }

rules:
  - { name: names, to: [names], out: vpn, resolve: realip }
EOF
STEER_NFT_CONCAT=1 "$BIN" apply --dry-run --spec "$tmp/rspec.yaml" --state-dir "$tmp/st3" \
    > "$tmp/rrs.nft" 2>/dev/null
nft -f "$tmp/rrs.nft"
check "real-ip: набор правил принят" 0 "$?"
RS="$(sed -n 's/^    set \(vpn_dom_[a-z0-9_]*_m\) {/\1/p' "$tmp/rrs.nft" | head -n 1)"
check "real-ip: у канала составной доменный набор" yes "$([ -n "$RS" ] && echo yes || echo no)"
STEER_NFT_CONCAT=1 "$BIN" dnsd --spec "$tmp/rspec.yaml" --state-dir "$tmp/st3" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/dnsd3.log" 2>&1 & DPID=$!
sleep 1
rels() { nft list set inet steer "$RS" | tr -d '\n\t' | sed 's/  */ /g'; }
rv="$(ask a.voice.example)"
sleep 0.3
check "real-ip: клиенту — настоящий адрес" 100.64.0.7 "$rv"
check "real-ip: элемент «адрес . udp . 50000-65535» со сроком" yes \
    "$(rels | grep -q '100.64.0.7 . udp . 50000-65535 timeout' && echo yes || echo "no: $(rels)")"
nft flush set inet steer "$RS"
check "real-ip: набор правил заменён — элемента нет" no \
    "$(rels | grep -q '100.64.0.7 ' && echo yes || echo no)"
kill -HUP "$DPID"
sleep 0.5
check "real-ip: после замены набора и HUP элемент снова на месте — с сужением и сроком" yes \
    "$(rels | grep -q '100.64.0.7 . udp . 50000-65535 timeout' && echo yes || echo "no: $(rels)")"

printf '\nsrsnft: %d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\n'
