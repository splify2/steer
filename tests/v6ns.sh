#!/bin/sh
# IPv6 правил с настоящим ядром (docs/architecture.md, «4б»): клиент с адресом IPv6 за роутером,
# трафик к подсети IPv6 из списка уходит в выход (правило `ip -6 rule` и таблица IPv6 выхода), к
# прочим — напрямую; к подсети правила, ведущего в выход без IPv6, — отвергается, а не уходит
# напрямую; `ip -6 rule flush` — страж демона возвращает правило; `steer down` снимает и IPv6.
#
# Сеть — четыре пространства: роутер (сам стенд), клиент за r0 (lan_devices), «туннель» за t0
# (устройство выхода kind=interface — veth, как подделка туннеля в awgns.sh) и «провайдер» за w0
# (маршрут IPv6 по умолчанию). Адрес за туннелем есть ТОЛЬКО у туннеля, адрес вне списков — только
# у провайдера, адрес правила выхода без IPv6 — тоже только у провайдера: ответ на пинг и есть
# доказательство пути. Утечка напрямую ответила бы там, где ответа быть не должно.
#
# Нужны root, unshare, nsenter, ip, nft и ping с IPv6. Чего-то нет — стенд пропускается вслух, с
# кодом 0.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "v6ns: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter ping; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${V6NS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    V6NS_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
# Своё /sys — сторож читает operstate своих устройств, а не устройств машины (как в awgns.sh).
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up
[ -e /proc/sys/net/ipv6/conf/all/forwarding ] || skip "в ядре нет IPv6"
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1 2>/dev/null
nft add table inet v6ns_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet v6ns_probe

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
# Пространства-соседи: pid процесса-якоря у каждого (не через $(…): фоновый якорь держал бы
# открытым вывод подстановки, и она ждала бы его конца).
unshare -n sleep 600 >/dev/null 2>&1 & C=$!
unshare -n sleep 600 >/dev/null 2>&1 & T=$!
unshare -n sleep 600 >/dev/null 2>&1 & W=$!
pids="$C $T $W"
sleep 0.3
IC="nsenter -t $C -n"; IT="nsenter -t $T -n"; IW="nsenter -t $W -n"
link() {   # link ЗДЕСЬ ТАМ PID АДРЕС_ЗДЕСЬ АДРЕС_ТАМ
    ip link add "$1" type veth peer name "$2"
    ip link set "$2" netns "$3"
    ip addr add "$4" dev "$1" nodad
    ip link set "$1" up
    nsenter -t "$3" -n ip link set lo up
    nsenter -t "$3" -n ip addr add "$5" dev "$2" nodad
    nsenter -t "$3" -n ip link set "$2" up
}
link r0 c0 "$C" fd00:1::1/64 fd00:1::2/64
link t0 t1 "$T" fd00:2::1/64 fd00:2::2/64
link w0 w1 "$W" fd00:3::1/64 fd00:3::2/64
# IPv4 туннеля — для пробы сторожа (ICMP к 1.1.1.1 через устройство): её адреса отвечают за t0.
ip addr add 10.9.0.1/30 dev t0
$IT ip addr add 10.9.0.2/30 dev t1
$IC ip -6 route add default via fd00:1::1
ip -6 route add default via fd00:3::2 dev w0
$IT ip link add dum0 type dummy
$IT ip link set dum0 up
# Адрес за туннелем — на самом t1: маршрут выхода — `default dev t0` без шлюза (у настоящего
# туннеля соседей нет), и роутер спрашивает соседа прямо о нём, а соседа IPv6 ядро называет,
# только если адрес на том устройстве, куда пришёл вопрос.
$IT ip addr add 2001:db8:1::1/128 dev t1 nodad
$IT ip addr add 1.1.1.1/32 dev dum0
$IT ip addr add 8.8.8.8/32 dev dum0
$IT ip -6 route add fd00:1::/64 via fd00:2::1
$IW ip link add dum0 type dummy
$IW ip link set dum0 up
$IW ip addr add 2001:db8:9::1/128 dev dum0
$IW ip addr add 2001:db8:5::1/128 dev dum0
# Адрес из списка туннеля, который знает только провайдер: ответ на него — это утечка напрямую.
$IW ip addr add 2001:db8:1::77/128 dev dum0
$IW ip -6 route add fd00:1::/64 via fd00:3::1
sleep 0.5
ping6c() { $IC ping -6 -c 1 -W 2 "$1" >/dev/null 2>&1 && echo ok || echo нет; }
check "без движка: адрес за туннелем недостижим (его знает только туннель)" "нет" \
    "$(ping6c 2001:db8:1::1)"
check "без движка: адрес провайдера достижим" "ok" "$(ping6c 2001:db8:9::1)"
check "без движка: адрес правила tgws достижим напрямую" "ok" "$(ping6c 2001:db8:5::1)"
check "без движка: адрес списка у провайдера достижим напрямую" "ok" "$(ping6c 2001:db8:1::77)"

printf '203.0.113.0/24\n2001:db8:1::/48\n' > "$tmp/a.lst"
printf '2001:db8:5::/48\n' > "$tmp/t.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2, "lan_devices": ["r0"],
  "outputs": { "wg": { "kind": "interface", "device": "t0", "on_fail": "drop" },
               "tg": { "kind": "tgws", "domain": "example.com" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "wg" },
                { "name": "t", "match": { "prefixes_file": "$tmp/t.lst" }, "out": "tg" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply.out" 2>&1
check "apply с правилами IPv6 проходит (nft принял набор)" "0" "$?"
check "  парный набор IPv6 в ядре" "1" \
    "$(nft list set inet steer wg_ip6 2>/dev/null | grep -c '2001:db8:1::/48')"
mark=$(awk '$1 == "wg" { print $2 }' "$tmp/st/registry")
tbl=$(awk '$1 == "wg" { print $3 }' "$tmp/st/registry")
ours6() { ip -6 rule show | grep -c "fwmark 0x$mark/"; }
check "  ip -6 rule выхода wg (та же метка)" "1" "$(ours6)"
check "  в таблице IPv6 выхода — default в t0" "1" \
    "$(ip -6 route show table "$tbl" | grep -c '^default dev t0')"
# Запрет в таблице IPv6 — prohibit (с 1.10): отказ приходит клиенту сразу, а не по таймауту.
check "  и запасной запрет (prohibit)" "1" \
    "$(ip -6 route show table "$tbl" | grep -c '^prohibit default.*metric 65535')"
check "  у выхода без IPv6 (tgws) правила IPv6 нет" "0" \
    "$(ip -6 rule show | grep -c "fwmark 0x$(awk '$1 == "tg" { print $2 }' "$tmp/st/registry")/")"

check "клиент: подсеть IPv6 из списка — в туннель (ответил туннель)" "ok" \
    "$(ping6c 2001:db8:1::1)"
check "клиент: прочий IPv6 — напрямую (ответил провайдер)" "ok" "$(ping6c 2001:db8:9::1)"
check "клиент: правило в выход без IPv6 — отвергнуто, напрямую не ушло" "нет" \
    "$(ping6c 2001:db8:5::1)"
check "  отказ — правилом forward_v6" "yes" \
    "$(nft list chain inet steer forward_v6 2>/dev/null | grep 'steer-v6drop:tg' | grep -q 'packets [1-9]' && echo yes || echo no)"
# Правила каналов: на ядре с хуком inet ingress они стоят в ingress_mark на r0 (там и растут их
# счётчики) и запасными — в prerouting_mark (compile/generate.c, «разметка на ingress»); без
# него — только в prerouting_mark. Считаем по обеим цепочкам: объём канала — их сумма.
marks() { nft list chain inet steer ingress_mark 2>/dev/null; nft list chain inet steer prerouting_mark; }
ING=$(nft list chain inet steer ingress_mark >/dev/null 2>&1 && echo 1 || echo 0)
echo "v6ns: разметка каналов — $([ "$ING" = 1 ] && echo 'на ingress' || echo 'в prerouting')"
check "  счётчик правила IPv6 канала a растёт" "yes" \
    "$(marks | grep 'ip6 daddr @wg_ip6' | grep -q 'packets [1-9]' && echo yes || echo no)"
if [ "$ING" = 1 ]; then
    check "  разметка — на ingress r0: запасные правила prerouting пакетов канала a не видели" "0" \
        "$(nft list chain inet steer prerouting_mark | grep 'comment "steer:wg_ip"' | grep -c 'packets [1-9]')"
fi

check "клиент: адрес списка, известный только провайдеру, напрямую не ушёл" "нет" \
    "$(ping6c 2001:db8:1::77)"

# Счётчик канала — одно число: сумма правила IPv4 и его v6-двойника (одно имя в комментарии,
# counters_load складывает), и через apply он переносится.
pk_nft() {
    marks | grep 'comment "steer:wg_ip"' |
        sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | awk '{ s += $1 } END { print s + 0 }'
}
pk_status() {
    "$BIN" status $S 2>/dev/null | grep -o '"name":"wg_ip"[^]]*' |
        sed -n 's/.*"packets":\([0-9]*\).*/\1/p' | head -n 1
}
check "  у канала a два правила разметки (IPv4 и IPv6)" "2" \
    "$(nft list chain inet steer prerouting_mark | grep -c 'comment "steer:wg_ip"')"
p_nft=$(pk_nft)
check "status: пакеты канала = сумма правил IPv4 и IPv6" "$p_nft" "$(pk_status)"

"$BIN" apply $S >/dev/null 2>&1
check "повторный apply — правило IPv6 одной копией" "1" "$(ours6)"
check "  счётчик канала перенесён через apply" "$p_nft" "$(pk_status)"

# У устройства выхода выключили IPv6: маршрута в него нет, и таблица IPv6 держит запрет — IPv6
# списка стоит, а не уходит напрямую.
sysctl -qw net.ipv6.conf.t0.disable_ipv6=1
"$BIN" apply $S >"$tmp/apply2.out" 2>&1
check "IPv6 на устройстве выключен: apply говорит, что IPv6 выхода остановлен" "1" \
    "$(grep -c 'маршрут IPv6 в t0 не встал' "$tmp/apply2.out")"
check "  в таблице IPv6 — запрет (prohibit)" "1" \
    "$(ip -6 route show table "$tbl" | grep -c '^prohibit default.*metric 1024')"
check "  и прежнего blackhole в таблице IPv6 нет" "0" \
    "$(ip -6 route show table "$tbl" | grep -c '^blackhole')"
check "  адрес списка у провайдера по-прежнему недостижим" "нет" "$(ping6c 2001:db8:1::77)"
# Отказ — сразу: ядро отвечает клиенту «administratively prohibited», а не молчит до таймаута.
check "  клиент получает отказ сразу (administratively prohibited)" "1" \
    "$($IC ping -6 -c 1 -W 2 2001:db8:1::77 2>&1 | grep -ci 'prohibited' | head -n 1)"
sysctl -qw net.ipv6.conf.t0.disable_ipv6=0
ip addr add fd00:2::1/64 dev t0 nodad
"$BIN" apply $S >/dev/null 2>&1
check "IPv6 вернули: маршрут снова в t0" "1" \
    "$(ip -6 route show table "$tbl" | grep -c '^default dev t0')"

# ---- страж правил демона ----
"$BIN" daemon --watch --apply --socket "$tmp/s.sock" $S >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d.err"' 10
wait_for 'grep -q "watch: первый проход" "$tmp/d.err"' 10
sleep 1
check "демон: правило IPv6 на месте" "1" "$(ours6)"
ip -6 rule flush
ip -6 rule add priority 32766 table main 2>/dev/null
check "ip -6 rule flush — правила IPv6 нет" "0" "$(ours6)"
t0=$(date +%s%N)
wait_for '[ "$(ours6)" = 1 ]' 5
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "  через ≤ 3 с страж вернул правило IPv6" "yes" \
    "$([ "$(ours6)" = 1 ] && [ $ms -le 3000 ] && echo yes || echo "no:$ms ms, $(ours6)")"
check "  в журнале демона — строка о починке" "1" "$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d.err")"
check "  клиент снова ходит в туннель" "ok" "$(ping6c 2001:db8:1::1)"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null

# ---- доменные правила по IPv6: fake-IP v6 и real-ip v6 ----
# Имя fake.test — адрес 2001:db8:7::1, имя real.test — 2001:db8:8::1; оба адреса есть ТОЛЬКО за
# туннелем. Клиент спрашивает резолвер (он на роутере, наверху — поддельный апстрим на петле):
#   fake-IP: получает поддельный IPv6 из пула, пинг по нему доходит до цели — значит правило
#            v6-двойник пометило поддельный адрес (набор «<канал>6»), а dnat по карте fakeip6
#            перевёл его в настоящий, и маршрут метки увёл пакет в туннель;
#   real-ip: получает настоящий адрес, он лежит в наборе «<канал>6» со сроком, пинг — в туннель.
# Та же спека записью v1 (dspec.json) даёт тот же набор правил и те же ответы на AAAA — это
# проверяется вторым резолвером в конце раздела.
if command -v python3 >/dev/null 2>&1; then
    $IT ip addr add 2001:db8:7::1/128 dev t1 nodad
    $IT ip addr add 2001:db8:8::1/128 dev t1 nodad
    check "без доменных правил: адрес real.test недостижим (он только за туннелем)" "нет" \
        "$(ping6c 2001:db8:8::1)"
    printf 'fake.test\n' > "$tmp/f.lst"
    printf 'real.test\n' > "$tmp/r.lst"
    cat > "$tmp/dspec.yaml" <<EOF
version: 2
lan: { devices: [r0] }
lists:
  a: { prefixes_file: $tmp/a.lst }
  t: { prefixes_file: $tmp/t.lst }
  f: { domains_file: $tmp/f.lst }
  r: { domains_file: $tmp/r.lst }
outputs:
  wg: { kind: interface, device: t0, on_fail: drop }
  tg: { kind: tgws, domain: example.com }
rules:
  - { name: a, to: a, out: wg }
  - { name: t, to: t, out: tg }
  - { name: f, to: f, out: wg }
  - { name: r, to: r, out: wg, resolve: realip }
EOF
    cat > "$tmp/dspec.json" <<EOF
{ "schema": 2, "lan_devices": ["r0"],
  "outputs": { "wg": { "kind": "interface", "device": "t0", "on_fail": "drop" },
               "tg": { "kind": "tgws", "domain": "example.com" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "wg" },
                { "name": "t", "match": { "prefixes_file": "$tmp/t.lst" }, "out": "tg" },
                { "name": "f", "match": { "domains_files": ["$tmp/f.lst"] }, "out": "wg" },
                { "name": "r", "match": { "domains_files": ["$tmp/r.lst"], "mode": "realip" },
                  "out": "wg" } ] }
EOF
    DS="--spec $tmp/dspec.yaml --state-dir $tmp/st"
    "$BIN" apply $DS >"$tmp/apply-d.out" 2>&1
    check "apply с доменными правилами и IPv6 проходит" "0" "$?"
    tabd="$("$BIN" dnsd-table $DS 2>/dev/null)"
    set_f="$(printf '%s\n' "$tabd" | awk -F'|' '$5 == "f" { print $1 }')"
    set_r="$(printf '%s\n' "$tabd" | awk -F'|' '$5 == "r" { print $1 }')"
    check "  карта fakeip6 в ядре" "0" "$(nft list map inet steer fakeip6 >/dev/null 2>&1; echo $?)"
    check "  парный набор IPv6 доменной группы — с timeout" "1" \
        "$(nft list set inet steer "${set_r}6" 2>/dev/null | grep -c 'flags interval,timeout')"
    cat > "$tmp/up.py" <<'PY'
import socket, sys
A = {b'\x04fake\x04test\x00': '2001:db8:7::1', b'\x04real\x04test\x00': '2001:db8:8::1'}
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
        n, ans = 1, b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([203, 0, 113, 7])
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
    python3 "$tmp/up.py" 15393 >/dev/null 2>&1 & UP=$!
    "$BIN" dnsd $DS --listen-port 15390 --upstream-port 15393 >"$tmp/dnsd.out" 2>&1 & DN=$!
    pids="$pids $UP $DN"
    sleep 1
    fk="$($IC python3 "$tmp/q6.py" fd00:1::1 15390 fake.test)"
    check "fake-IP v6: клиент получил поддельный IPv6 из пула" "fdfe:dcba:9876::c612" \
        "$(echo "$fk" | sed 's/:[0-9a-f]*$//')"
    check "  в карте fakeip6 — настоящий адрес" "1" \
        "$(nft list map inet steer fakeip6 | grep -c "$fk : 2001:db8:7::1")"
    check "  поддельный IPv6 — в наборе правила" "1" \
        "$(nft list set inet steer "${set_f}6" | grep -c "$fk")"
    check "  клиент по поддельному IPv6 доходит до цели (dnat v6 и туннель)" "ok" "$(ping6c "$fk")"
    check "  счётчик dnat v6 растёт" "yes" \
        "$(nft list chain inet steer prerouting_dnat | grep '@fakeip6' | grep -q 'packets [1-9]' && echo yes || echo no)"
    rl="$($IC python3 "$tmp/q6.py" fd00:1::1 15390 real.test)"
    check "real-ip v6: клиент получил настоящий адрес" "2001:db8:8::1" "$rl"
    check "  адрес — в наборе «<канал>6» со сроком" "1" \
        "$(nft list set inet steer "${set_r}6" | grep '2001:db8:8::1' | grep -c timeout)"
    check "  клиент по нему доходит до цели через туннель" "ok" "$(ping6c 2001:db8:8::1)"
    # explain по адресам IPv6: поддельный — с именем, которому он выдан; настоящий из real-ip;
    # подсеть списка; правило в выход без IPv6 — с пометкой, что такой трафик отбрасывается.
    ex="$("$BIN" explain "$fk" $DS 2>/dev/null)"
    check "explain fake6: доменное правило и выход" "1" \
        "$(printf '%s\n' "$ex" | grep -c "^$fk -> domain set \"${set_f}\" -> output \"wg\" -> dev t0")"
    check "  и имя, которому выдан адрес" "1" \
        "$(printf '%s\n' "$ex" | grep -c 'поддельный адрес имени fake.test')"
    check "explain real-ip v6: правило real-ip" "1" \
        "$("$BIN" explain 2001:db8:8::1 $DS 2>/dev/null | grep -c "domain set \"${set_r}\" -> output \"wg\"")"
    # Адресный список «a» и доменный «f» — один выход и одни клиенты, то есть одна группа и один
    # набор (гибридный): подсеть списка лежит в его паре IPv6.
    check "explain подсети IPv6 списка" "1" \
        "$("$BIN" explain 2001:db8:1::9 $DS 2>/dev/null | grep -c "address+domain set \"${set_f}\" -> output \"wg\"")"
    check "explain IPv6 правила в выход без IPv6 — отбрасывается" "1" \
        "$("$BIN" explain 2001:db8:5::1 $DS 2>/dev/null | grep -c 'выход без IPv6')"
    # Спека v1 с теми же каналами: набор правил тот же до байта (с «<канал>6» и v6-двойниками),
    # и таблица резолвера с теми же семействами («46» у обоих каналов), и на AAAA — те же ответы.
    # Свой резолвер на своём порту и со своим каталогом состояния, рядом с первым. Сверка наборов
    # правил — в третьем, чистом каталоге: в $tmp/st уже лежит файл fake-IP, а apply засевает из
    # него карты, и разница была бы в состоянии, а не в спеке.
    D1="--spec $tmp/dspec.json --state-dir $tmp/st1"
    check "спека v1: тот же набор правил, что у v2" "same" \
        "$("$BIN" apply --dry-run --spec "$tmp/dspec.yaml" --state-dir "$tmp/stc" 2>/dev/null > "$tmp/r2.nft"
           "$BIN" apply --dry-run --spec "$tmp/dspec.json" --state-dir "$tmp/stc" 2>/dev/null > "$tmp/r1.nft"
           cmp -s "$tmp/r1.nft" "$tmp/r2.nft" && grep -q "set ${set_f}6 {" "$tmp/r1.nft" &&
           echo same || echo differ)"
    check "спека v1: в таблице резолвера оба канала — IPv4 и IPv6" "46 46" \
        "$("$BIN" dnsd-table $D1 2>/dev/null | awk -F'|' 'NF > 4 { printf "%s%s", s, $4; s = " " }')"
    mkdir -p "$tmp/st1"
    "$BIN" dnsd $D1 --listen-port 15391 --upstream-port 15393 >"$tmp/dnsd1.out" 2>&1 & DN1=$!
    pids="$pids $DN1"
    sleep 1
    check "спека v1: AAAA имени fake-IP — поддельный IPv6 из пула" "fdfe:dcba:9876::c612" \
        "$($IC python3 "$tmp/q6.py" fd00:1::1 15391 fake.test | sed 's/:[0-9a-f]*$//')"
    check "спека v1: AAAA имени real-ip — настоящий адрес" "2001:db8:8::1" \
        "$($IC python3 "$tmp/q6.py" fd00:1::1 15391 real.test)"
    kill "$DN" "$DN1" "$UP" 2>/dev/null
    wait "$DN" 2>/dev/null
    wait "$DN1" 2>/dev/null
    [ "$fail" -gt 0 ] && tail -n 20 "$tmp/dnsd.out" "$tmp/dnsd1.out"
else
    echo "v6ns: python3 нет — доменные правила по IPv6 пропущены"
fi

# ---- steer down ----
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
check "steer down: правила IPv6 выхода нет" "0" "$(ours6)"
check "  таблица IPv6 выхода пуста" "0" "$(ip -6 route show table "$tbl" | grep -c .)"
check "  набора правил нет" "1" "$(nft list table inet steer >/dev/null 2>&1; echo $?)"

printf '\nv6ns: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
