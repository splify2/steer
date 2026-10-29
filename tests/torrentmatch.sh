#!/bin/sh
# Ключ `torrent` правила (compile/torrent.c): разбор, текст набора правил и — с настоящим ядром —
# распознавание образцов, запоминание сокета и пира, block и direct.
#
# Часть 1 (без привилегий): разбор и отказы, spec convert, место перехода в цепочку распознавания
# (раньше метки правила), без ingress, без ключа — ни наборов, ни цепочек.
# Часть 2 (сетевые пространства: root или unshare -r): клиент C → роутер → «туннель» T (выход
# kind=interface) и «провайдер» W (маршрут по умолчанию); адрес 203.0.113.9 есть и у T, и у W, а
# приёмник пишет, с какого порта источника что пришло, — так виден путь. Образцы — torrent-samples.py:
# всё, что Xray-core или sing-box назовут bittorrent, не должно дойти до T; обычное (HTTP, TLS, QUIC,
# DNS, STUN, простой UDP) — доходит.
# Нет unshare/nsenter/nft/python3 или пространства не завести — часть 2 пропускается вслух.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
done_() { echo "torrentmatch: $pass ok, $fail failed"; [ "$fail" = 0 ]; exit $?; }

if [ "${TORRENT_INNER:-}" != 1 ]; then
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '203.0.113.0/24\n' > "$tmp/a.lst"
dry() { STEER_NFT_INGRESS=all "$BIN" apply --dry-run --spec "$tmp/s.yaml" --state-dir "$tmp/st" 2>&1; }
spec() {
    cat > "$tmp/s.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
lists:
  a: { prefixes_file: $tmp/a.lst }
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  dir: { kind: direct }
  blk: { kind: block }
rules:
$1
EOF
}

# ---- 1. разбор и текст ----------------------------------------------------------------------
python3 "$HERE/torrent-samples.py" ref >"$tmp/ref" 2>&1
check "образцы: логика Xray и sing-box согласна с их тестами, steer не уже их" "0" "$?"
grep -q 'REF-FAIL\|NARROWER' "$tmp/ref" && cat "$tmp/ref"

spec '  - { name: a, to: [a], out: wg1, torrent: direct }
  - { name: rest, to: all, out: wg0, torrent: block }'
out="$(dry)"
check "torrent: block и direct приняты" "0" "$(STEER_NFT_INGRESS=all "$BIN" apply --dry-run --spec "$tmp/s.yaml" --state-dir "$tmp/st" >/dev/null 2>&1; echo $?)"
for o in "set torrent_src {" "set torrent_src6 {" "set torrent_peer {" "set torrent_peer6 {" \
         "chain torrent_block {" "chain torrent_block_hit {" "chain torrent_direct {" "chain torrent_direct_hit {"; do
    check "есть: $o" "1" "$(printf '%s\n' "$out" | grep -c "^ *$o")"
done
check "наборы памяти: dynamic,timeout, потолок и срок" "4 4 4" \
    "$(printf '%s\n' "$out" | grep -A4 'set torrent_' | grep -c 'flags dynamic,timeout') $(printf '%s\n' "$out" | grep -A4 'set torrent_' | grep -c 'size 65535') $(printf '%s\n' "$out" | grep -A4 'set torrent_' | grep -c 'timeout 10m')"
# Переход в распознавание — раньше метки своей группы, а «весь трафик» не трогает свою сеть.
jr="$(printf '%s\n' "$out" | grep -n 'jump torrent_direct comment "steer-torrent:wg1_ip' | cut -d: -f1)"
mr="$(printf '%s\n' "$out" | grep -n 'comment "steer:wg1_ip' | head -n 1 | cut -d: -f1)"
check "переход в torrent_direct раньше метки правила a" "1" "$([ -n "$jr" ] && [ -n "$mr" ] && [ "$jr" -lt "$mr" ] && echo 1)"
check "«весь трафик»: распознавание только для интернета, оба семейства" "2" \
    "$(printf '%s\n' "$out" | grep 'jump torrent_block comment "steer-torrent:wg0_all' | grep -c 'daddr != {')"
check "direct: поток, открытый через выход, — отказ; остальное — без метки" "3" \
    "$(printf '%s\n' "$out" | sed -n '/chain torrent_direct_hit {/,/^    }$/p' | grep -c 'ct mark and 0x0ff00000 != 0x00000000\|counter accept comment "steer-torrent:direct"')"
check "block: без accept" "0" "$(printf '%s\n' "$out" | sed -n '/chain torrent_block_hit {/,/^    }$/p' | grep -c accept)"
check "с torrent разметки на ingress нет" "0" "$(printf '%s\n' "$out" | grep -c 'hook ingress')"
# Правило без ключа своей группы не теряет: его трафик в распознавание не идёт.
spec '  - { name: a, to: [a], out: wg1 }
  - { name: rest, to: all, out: wg0, torrent: block }'
out="$(dry)"
check "правило без ключа — без перехода" "0" "$(printf '%s\n' "$out" | grep -c 'steer-torrent:wg1')"
check "только block — цепочки direct нет" "0" "$(printf '%s\n' "$out" | grep -c 'chain torrent_direct')"
spec '  - { name: rest, to: all, out: wg0 }'
out="$(dry)"
check "без ключа — ни наборов, ни цепочек" "0" "$(printf '%s\n' "$out" | grep -c torrent)"
spec '  - { name: rest, to: all, out: wg0, torrent: allow }'
check "allow — записанное умолчание" "0" "$(dry | grep -c torrent)"
spec '  - { name: k, to: all, out: dir, torrent: block }'
check "block у правила direct — законно (торренты этих клиентов не идут никуда)" "2" "$(dry | grep -c 'jump torrent_block')"

refused() {   # refused ЧТО ОЖИДАЕМЫЙ_КУСОК
    msg="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" --state-dir "$tmp/st" 2>&1 >/dev/null)"
    check "$1" "1" "$(printf '%s' "$msg" | grep -c "$2")"
}
spec '  - { name: k, to: all, out: wg0, torrent: off }'
refused "torrent: неизвестное значение" "«off» — нужен block"
spec '  - { name: k, to: all, out: blk, torrent: block }'
refused "torrent у выхода block — отказ" "torrent у выхода block"
spec '  - { name: k, to: all, out: dir, torrent: direct }'
refused "torrent: direct у выхода direct — отказ" "и так идёт"

# spec convert неподвижен: ключ печатается правилом, копии списка — нет.
spec '  - { name: a, to: [a], out: wg1, torrent: direct, quic: block }
  - { name: rest, to: all, out: wg0, torrent: block }'
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>&1
"$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>&1
check "spec convert печатает ключ и неподвижен" "1 1 1" \
    "$(grep -c 'torrent: direct' "$tmp/c1.yaml") $(grep -c 'torrent: block' "$tmp/c1.yaml") $(cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml" && echo 1)"
check "  и без копий списка" "1" "$(grep -c '^  a:' "$tmp/c1.yaml")"
check "spec-schema знает ключ" "1" "$("$BIN" spec-schema --json 2>/dev/null | grep -o '"torrent"' | head -n 1 | grep -c torrent)"

# ---- 2. ядро ------------------------------------------------------------------------------------
skip2() { echo "torrentmatch: часть 2 пропущена — $1"; done_; }
for t in ip nft unshare nsenter python3; do command -v $t >/dev/null 2>&1 || skip2 "нет $t"; done
if [ "$(id -u)" = 0 ]; then un="unshare -nm"; else un="unshare -rnm"; fi
$un true 2>/dev/null || skip2 "$un недоступен"
set +e
TORRENT_INNER=1 STEER="$BIN" $un sh "$0" > "$tmp/inner" 2>&1
rc=$?
cat "$tmp/inner"
ip=$(sed -n 's/^inner: \([0-9]*\) ok, \([0-9]*\) failed$/\1 \2/p' "$tmp/inner")
pass=$((pass + ${ip%% *}))
fail=$((fail + ${ip##* }))
[ -z "$ip" ] && [ "$rc" != 0 ] && fail=$((fail + 1))
done_
fi

# ---- часть 2, внутри своего пространства ---------------------------------------------------------
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
ip link set lo up
nft add table inet tm_probe 2>/dev/null || { echo "inner: 0 ok, 0 failed"; echo "nf_tables недоступен"; exit 0; }
nft delete table inet tm_probe
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
tmp="$(mktemp -d)"
pids=""
trap 'for p in $pids; do kill $p 2>/dev/null; done; rm -rf "$tmp"' EXIT
unshare -n sleep 600 >/dev/null 2>&1 & C=$!
unshare -n sleep 600 >/dev/null 2>&1 & T=$!
unshare -n sleep 600 >/dev/null 2>&1 & W=$!
pids="$C $T $W"
sleep 0.3
IC="nsenter -t $C -n"; IT="nsenter -t $T -n"; IW="nsenter -t $W -n"
link() {   # link ЗДЕСЬ ТАМ PID АДРЕС_ЗДЕСЬ АДРЕС_ТАМ
    ip link add "$1" type veth peer name "$2"
    ip link set "$2" netns "$3"
    ip addr add "$4" dev "$1"
    ip link set "$1" up
    nsenter -t "$3" -n ip link set lo up
    nsenter -t "$3" -n ip addr add "$5" dev "$2"
    nsenter -t "$3" -n ip link set "$2" up
}
link br-lan c0 "$C" 192.168.1.1/24 192.168.1.2/24
link t0 t1 "$T" 10.9.0.1/30 10.9.0.2/30
link w0 w1 "$W" 10.0.0.1/30 10.0.0.2/30
ip route add default via 10.0.0.2
$IC ip route add default via 192.168.1.1
for ns in $T $W; do
    nsenter -t "$ns" -n ip addr add 203.0.113.9/32 dev lo
    nsenter -t "$ns" -n sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
done
$IT ip route add 192.168.1.0/24 via 10.9.0.1
$IW ip route add 192.168.1.0/24 via 10.0.0.1
$IT sysctl -qw net.ipv4.conf.t1.proxy_arp=1
S="$HERE/torrent-samples.py"
ports="53 443 3478"
i=0
while [ $i -lt 120 ]; do ports="$ports $((42000 + i))"; i=$((i + 1)); done
$IT python3 "$S" recv "$tmp/T.log" $ports >/dev/null 2>&1 & pids="$pids $!"
$IW python3 "$S" recv "$tmp/W.log" $ports >/dev/null 2>&1 & pids="$pids $!"
sleep 0.5

cat > "$tmp/s.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
outputs:
  tun: { kind: interface, device: t0, on_fail: drop }
rules:
  - { name: all, to: all, out: tun, torrent: block }
EOF
"$BIN" apply --spec "$tmp/s.yaml" --state-dir "$tmp/st" >"$tmp/apply.out" 2>&1
check "apply с torrent: block проходит" "0" "$?"
[ -s "$tmp/apply.out" ] && grep -i 'error\|ошибк\|отказ' "$tmp/apply.out"

# Где прошёл образец: T (туннель), W (напрямую) или нигде. Ключ — порт источника.
where() {
    sleep 0.3
    t=$(awk -v p="$1" '$1 == p && $2 > 0' "$tmp/T.log" 2>/dev/null | wc -l)
    w=$(awk -v p="$1" '$1 == p && $2 > 0' "$tmp/W.log" 2>/dev/null | wc -l)
    if [ "$t" -gt 0 ]; then echo T; elif [ "$w" -gt 0 ]; then echo W; else echo -; fi
}
sp=30000 dp=42000
send() {   # send ОБРАЗЕЦ [ПОРТ_НАЗН] → порт источника в p
    sp=$((sp + 1))
    d="${2:-}"
    if [ -z "$d" ]; then dp=$((dp + 1)); d=$dp; fi
    $IC python3 "$S" send "$1" 203.0.113.9 "$d" "$sp" </dev/null >/dev/null 2>&1
    p=$sp
}
python3 "$S" list > "$tmp/list"
tcount() {
    nft list chain inet steer torrent_block_hit 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' |
        awk '{ s += $1 } END { print s + 0 }'
}
while read -r name proto want fixed; do
    [ "$fixed" = 0 ] && fixed=""
    c0=$(tcount)
    send "$name" $fixed
    got=$(where "$p")
    if [ "$want" = bt ]; then exp=-; else exp=T; fi
    # DNS (порт 53) клиентов забирает резолвер роутера, до T он не доходит и без ключа: здесь
    # проверка — что распознавание его не тронуло.
    if [ "$fixed" = 53 ]; then
        [ "$(tcount)" = "$c0" ] && got=T || got=-
    fi
    check "block: $name ($proto, ждём $([ "$want" = bt ] && echo 'отказ' || echo 'в туннель'))" "$exp" "$got"
done < "$tmp/list"

# Запоминание: SYN uTP с порта P — дальше любой UDP с P не в туннель; с другого порта — в туннель.
sp=31000
send utp-syn
$IC python3 -c "
import socket; u=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', $p)); u.sendto(b'plain after syn', ('203.0.113.9', 42100))"
check "память сокета: обычная датаграмма с порта торрента — отказ" "-" "$(where "$p")"
send udp-plain 42100; p2=$p
check "  а с другого порта — в туннель" "T" "$(where "$p2")"
# Пир: SYN uTP к 42101 — затем TCP к тому же пиру с «шифрованной» нагрузкой (MSE) — отказ; к 42102 — проходит.
send utp-syn 42101
send tcp-tls-hello 42101; p3=$p
check "память пира: TCP к пиру из uTP (как MSE) — отказ" "-" "$(where "$p3")"
send tcp-tls-hello 42102; p4=$p
check "  к другому порту — в туннель" "T" "$(where "$p4")"
# Пир на порту ниже 1024 не запоминается: адрес из роя бывает чужим (CDN на 443), и память закрыла
# бы клиенту обычный HTTPS к нему. Само соединение с признаком отвергается.
send tcp-bt-handshake 443; p5=$p
check "рукопожатие к порту 443 — отказ" "-" "$(where "$p5")"
send tcp-http-get 443; p6=$p
check "  а обычный TCP к тому же адресу и порту — в туннель (пир < 1024 не запомнен)" "T" "$(where "$p6")"
check "status: поле torrent со счётчиком отказов" "1" \
    "$("$BIN" status --spec "$tmp/s.yaml" --state-dir "$tmp/st" 2>/dev/null | grep -c '"torrent":{"blocked":{"packets":[1-9]')"
check "status: запомнены сокеты и пиры" "1" \
    "$("$BIN" status --spec "$tmp/s.yaml" --state-dir "$tmp/st" 2>/dev/null | grep -c '"remembered":{"sockets":[1-9][0-9]*,"peers":[1-9]')"

# ---- direct: первая датаграмма — напрямую (W); рукопожатие в открытом через туннель TCP — сброс,
# следующее соединение к тому же пиру — напрямую с первого пакета.
nft flush set inet steer torrent_src 2>/dev/null
nft flush set inet steer torrent_peer 2>/dev/null
sed -i 's/torrent: block/torrent: direct/' "$tmp/s.yaml"
"$BIN" apply --spec "$tmp/s.yaml" --state-dir "$tmp/st" >/dev/null 2>&1
check "apply с torrent: direct проходит" "0" "$?"
sp=32000 dp=42030
send utp-syn; check "direct: SYN uTP — напрямую" "W" "$(where "$p")"
send sb-tracker-1; check "direct: UDP-трекер — напрямую" "W" "$(where "$p")"
send dht-ping; check "direct: DHT — напрямую" "W" "$(where "$p")"
send udp-plain; check "direct: обычный UDP — в туннель" "T" "$(where "$p")"
send tcp-http-get; check "direct: обычный TCP — в туннель" "T" "$(where "$p")"
send tcp-bt-handshake 42050
check "direct: рукопожатие в TCP, открытом через туннель, — не доходит" "-" "$(where "$p")"
send tcp-bt-handshake 42050
check "  следующее соединение к тому же пиру — напрямую" "W" "$(where "$p")"
check "status: пущенное напрямую посчитано" "1" \
    "$("$BIN" status --spec "$tmp/s.yaml" --state-dir "$tmp/st" 2>/dev/null | grep -c '"direct":{"packets":[1-9]')"
echo "inner: $pass ok, $fail failed"
