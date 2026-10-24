#!/bin/sh
# Замена набора правил без утечки (перепроверка на QEMU-роутере, 2026-09-28; порядок применения —
# docs/architecture.md, раздел 2, «Набор правил»).
#
# Что было. Каждая полная замена набора правил (загрузка, старт службы, перезапуск демона procd,
# apply после расхождения с ядром) на миг уводила новые соединения клиента к поддельному адресу в
# WAN, мимо выбранного выхода и мимо on_fail=drop. Два промежутка: карта подмены fakeip приходила в
# новом тексте засеянной из fakeip.state, а набор канала — пустым до таблицы резолверу (DNAT есть,
# метки нет); и при старте набор правил грузился раньше правил fwmark и таблиц выходов (метка есть,
# правила нет). Плюс слитый засевом отрезок в наборе канала, из которого резолвер не мог снять
# адрес имени, ушедшего в другой канал, и элементы real-ip, которые до таблицы резолверу стояли
# без метки.
#
# Сеть — четыре пространства, как в v6ns.sh: роутер (сам стенд), клиент за r0, «туннель» за t0
# (устройство выхода kind=interface) и «провайдер» за w0 (маршрут по умолчанию). Настоящий адрес
# 203.0.113.10 есть и за туннелем, и у провайдера; счётчик пакетов к нему у провайдера — это и есть
# утечка, у туннеля — законный путь. Клиент шлёт UDP на поддельный 198.18.0.1 каждые 5 мс, каждый
# пакет — новый сокет, то есть новое соединение (как dig + curl на стенде QEMU).
#
# Что проверяется.
#  1. Текст (apply --dry-run): засев набора канала fake-IP адресами из fakeip.state — тех имён, что
#     входят в канал (и в оба канала, если имя в двух), не каналов real-ip, не имён вне каналов; в
#     ту же строку elements, что и адресные списки; парный набор IPv6 — поддельным IPv6 имени с
#     настоящим IPv6; составной набор — с сужением совпавшей клаузы, соседние адреса не слиты,
#     исключённое имя не засеяно; старая раскладка — в динамическую половину (hash), не в «_n»;
#     отпечаток плана (apply-plan) от файла состояния не зависит; правило «без подмены — drop»
#     стоит за dnat.
#  2. Ядро и трафик, подкоманда: apply с непустым fakeip.state без резолвера — набор канала уже
#     содержит засеянный адрес, пакеты клиента — в туннель, у провайдера ноль; пять замен набора
#     правил под трафиком — у провайдера ноль, метку ставит ingress_mark (клиент — устройство
#     раздачи); ещё три замены с STEER_NFT_INGRESS=0 (метку ставит prerouting_mark) — тоже ноль.
#  3. Поддельный адрес без подмены не уходит никуда: ни к провайдеру, ни в туннель; счётчик правила
#     steer-fakeip-nomap растёт.
#  4. Старт демона с непустым fakeip.state (после `steer down`, то есть без правил fwmark и таблиц
#     выходов), затем kill -9 демона и новый старт — под трафиком, у провайдера ноль. Порядок в
#     журнале вызовов: правило fwmark выхода встаёт раньше загрузки набора правил.
#  5. Резолвер снимает адрес имени, ушедшего в другой канал, из слитого засевом отрезка: отрезок
#     делится, соседи остаются, адрес ложится в новый канал.
#  6. real-ip: сразу после загрузки набора правил демоном загрузчик просит резолвер вернуть
#     элементы (в журнале — строка «right after the ruleset load»), элемент на месте; поддельный
#     адрес в наборе канала — сразу после ответа apply, без ожидания резолвера.
#  7. Засев не отстаёт от памяти резолвера (проверка на QEMU 98b7964, 2026-09-28): файл состояния
#     резолвер переписывал не чаще раза в минуту и при SIGTERM не дописывал, а засев при замене
#     набора правил брался из него. Демон с резолвером (--supervise), клиент с поддельным адресом в
#     кэше DNS:
#     B1 — новое имя и сразу замена набора (снятое правило канала + apply), три раза: пара в карте
#          сразу после ответа apply, туннель получил каждый пакет клиента, у провайдера ноль;
#     B2 — два новых имени (A и AAAA), через секунду `steer restart` (SIGTERM демону, down, старт):
#          после старта карта и fakeip6 — с ними, пять пакетов к поддельному адресу из кэша — все в
#          туннель;
#     B3 — апстрим сменил адрес имени (в памяти и карте новый, файл ещё прежний), затем замена
#          набора: в карте — новый адрес; и отдельно — адрес в карте ядра испорчен руками, SIGHUP
#          резолверу: он сверяет карту с памятью и ставит свой (строка «заменён на тот, что знает
#          резолвер»), а не верит EEXIST.
#
# Нужны root, unshare -nm, nsenter, ip, nft и python3. Чего-то нет — стенд пропускается вслух.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
FIX="$(pwd)/tests/srs"
skip() { echo "swapmatch: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${SWAP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    SWAP_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null
real_nft="$(command -v nft)"
real_ip="$(command -v ip)"
"$real_nft" add table inet swap_probe 2>/dev/null || skip "nf_tables недоступен"
"$real_nft" delete table inet swap_probe

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
has() { printf '%s\n' "$1" | grep -qF -- "$2" && echo yes || echo no; }

# ---- 1. текст: засев в apply --dry-run -------------------------------------------------------
mkdir -p "$tmp/t1"
printf 'seed.test\nboth.test\n' > "$tmp/t1/a.lst"
printf 'both.test\n' > "$tmp/t1/b.lst"
printf 'rip.test\n' > "$tmp/t1/r.lst"
printf '203.0.113.0/24\n' > "$tmp/t1/p.lst"
cat > "$tmp/t1/spec.json" <<EOF
{ "schema": 1, "from_default": ["10.77.1.0/24"],
  "outputs": { "wg": { "kind": "interface", "device": "t0" },
               "wg2": { "kind": "interface", "device": "t0" } },
  "channels": [
    { "name": "a", "match": { "domains_files": ["$tmp/t1/a.lst"],
                              "prefixes_files": ["$tmp/t1/p.lst"] }, "out": "wg" },
    { "name": "b", "match": { "domains_files": ["$tmp/t1/b.lst"] }, "out": "wg2" },
    { "name": "r", "match": { "domains_files": ["$tmp/t1/r.lst"], "mode": "realip" }, "out": "wg" } ] }
EOF
mkdir -p "$tmp/t1/st"
printf 'seed.test\t198.18.0.1\t203.0.113.10\nx.seed.test\t198.18.0.2\nboth.test\t198.18.0.5\t203.0.113.11\nrip.test\t198.18.0.6\t203.0.113.12\nnone.example\t198.18.0.7\t203.0.113.13\n' \
    > "$tmp/t1/st/fakeip.state"
DRY="$(STEER_NFT_COMPAT=modern "$BIN" apply --dry-run --spec "$tmp/t1/spec.json" \
       --state-dir "$tmp/t1/st" 2>/dev/null)"
tab="$(STEER_NFT_COMPAT=modern "$BIN" dnsd-table --spec "$tmp/t1/spec.json" --state-dir "$tmp/t1/st" 2>/dev/null)"
SA="$(printf '%s\n' "$tab" | awk -F'|' '$5 == "a" { print $1 }')"
SB="$(printf '%s\n' "$tab" | awk -F'|' '$5 == "b" { print $1 }')"
SR="$(printf '%s\n' "$tab" | awk -F'|' '$5 == "r" { print $1 }')"
set_els() { printf '%s\n' "$DRY" | awk -v s="$1" '$1 == "set" && $2 == s { f = 1 } f && /elements/ { print; exit } f && /^    }/ { exit }'; }
check "текст: имя канала и его поддомен — в набор канала, в одну строку со списком" \
    "        elements = { 203.0.113.0/24, 198.18.0.1, 198.18.0.2, 198.18.0.5 }" "$(set_els "$SA")"
check "  имя в двух каналах — и во втором" "        elements = { 198.18.0.5 }" "$(set_els "$SB")"
check "  канал real-ip — без засева" "" "$(set_els "$SR")"
check "  имя вне каналов — ни в одном наборе" "no" \
    "$(printf '%s\n' "$DRY" | grep 'elements' | grep -v ' : ' | grep -q '198.18.0.7' && echo yes || echo no)"
check "  карта подмены — как прежде (строки с настоящим адресом)" "yes" \
    "$(has "$DRY" '198.18.0.7 : 203.0.113.13')"
check "  правило «без подмены — drop» стоит за dnat" \
    "ip daddr 198.18.0.0/15 counter dnat ip to ip daddr map @fakeip|ip daddr 198.18.0.0/15 counter drop comment \"steer-fakeip-nomap\"" \
    "$(printf '%s\n' "$DRY" | awk '/chain prerouting_dnat/ { f = 1; next } f && /^    }/ { exit } f && /198\.18/' |
       sed 's/^ *//' | paste -sd'|')"
# Отпечаток плана от файла состояния не зависит (засев в него не входит, print.c).
plan_fp() { STEER_NFT_COMPAT=modern "$BIN" apply-plan --spec "$tmp/t1/spec.json" --state-dir "$1" \
                2>/dev/null | awk '$1 == "ruleset" { print $2 }'; }
mkdir -p "$tmp/t1/st0"
FP1="$(plan_fp "$tmp/t1/st")"
FP0="$(plan_fp "$tmp/t1/st0")"
check "  отпечаток плана — тот же, что без файла состояния" "yes" \
    "$([ -n "$FP1" ] && [ "$FP1" = "$FP0" ] && echo yes || echo "no:$FP1/$FP0")"
# Старая раскладка: засев — в динамическую половину (hash, имя группы), не в «_n».
DRYL="$(STEER_NFT_COMPAT=legacy "$BIN" apply --dry-run --spec "$tmp/t1/spec.json" \
        --state-dir "$tmp/t1/st" 2>/dev/null)"
set_elsl() { printf '%s\n' "$DRYL" | awk -v s="$1" '$1 == "set" && $2 == s { f = 1 } f && /elements/ { print; exit } f && /^    }/ { exit }'; }
check "  старая раскладка: засев — в динамическую половину" \
    "        elements = { 198.18.0.1, 198.18.0.2, 198.18.0.5 }" "$(set_elsl "$SA")"
check "  старая раскладка: «_n» — только список" "        elements = { 203.0.113.0/24 }" \
    "$(set_elsl "${SA}_n")"

# Составной набор (tests/srs/dnsmixed.srs): имя с сужением — с ним, соседние адреса не слиты,
# исключённое имя не засеяно. Ядро такой набор принимает (nft -f ниже, часть 2 — своя таблица).
cat > "$tmp/t1/cspec.json" <<EOF
{ "schema": 1, "from_default": ["10.77.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "t0" } },
  "channels": [ { "name": "names", "match": { "srs_file": "$FIX/dnsmixed.srs" }, "out": "vpn" } ] }
EOF
mkdir -p "$tmp/t1/cst"
printf 'a.voice.example\t198.18.0.1\t203.0.113.20\nb.voice.example\t198.18.0.2\t203.0.113.21\nwww.plain.example\t198.18.0.5\t203.0.113.22\nno.excl.example\t198.18.0.7\t203.0.113.23\nwww.excl.example\t198.18.0.8\t203.0.113.24\n' \
    > "$tmp/t1/cst/fakeip.state"
CDRY="$(STEER_NFT_COMPAT=modern STEER_NFT_CONCAT=1 "$BIN" apply --dry-run \
        --spec "$tmp/t1/cspec.json" --state-dir "$tmp/t1/cst" 2>/dev/null)"
cels="$(printf '%s\n' "$CDRY" | awk '$1 == "set" && $2 == "vpn_dom_c0_m" { f = 1 } f && /elements/ { print; exit }')"
# Протокол в тексте генератора — номером (17), как у подсетей набора.
check "составной: имя с сужением — «адрес . udp . 50000-65535»" "yes" \
    "$(has "$cels" '198.18.0.1 . 17 . 50000-65535')"
check "  соседний адрес того же сужения — отдельным элементом, не слит" "yes" \
    "$(has "$cels" '198.18.0.2 . 17 . 50000-65535')"
check "  имя без сужения — полный ящик" "yes" "$(has "$cels" '198.18.0.5 . 0-255 . 0-65535')"
check "  имя под «и» с исключением — в наборе" "yes" "$(has "$cels" '198.18.0.8 . 0-255 . 0-65535')"
check "  исключённое имя — не засеяно" "no" "$(has "$cels" '198.18.0.7')"
check "  подсети набора — на месте" "yes" "$(has "$cels" '203.0.113.0/24 . 17 . 50000-65535')"
printf '%s\n' "$CDRY" | sed 's/^table inet steer /table inet swap_c /' > "$tmp/t1/c.nft"
"$real_nft" -f "$tmp/t1/c.nft" 2>"$tmp/t1/c.err"
check "  ядро принимает составной набор с засевом" "0" "$?"
"$real_nft" delete table inet swap_c 2>/dev/null

# IPv6: парный набор «<набор>6» — поддельным IPv6 (пара IPv4 в младших 32 битах) имени с
# настоящим IPv6; имя без настоящего IPv6 — только в набор IPv4.
cat > "$tmp/t1/v6.yaml" <<EOF
version: 2
lan: { devices: [r0] }
lists:
  f: { domains_file: $tmp/t1/a.lst }
outputs:
  wg: { kind: interface, device: t0 }
rules:
  - { name: f, to: f, out: wg }
EOF
mkdir -p "$tmp/t1/st6"
printf 'seed.test\t198.18.0.1\t203.0.113.10\t2001:db8:7::1\nx.seed.test\t198.18.0.2\t203.0.113.11\n' \
    > "$tmp/t1/st6/fakeip.state"
DRY6="$(STEER_NFT_COMPAT=modern "$BIN" apply --dry-run --spec "$tmp/t1/v6.yaml" \
        --state-dir "$tmp/t1/st6" 2>/dev/null)"
tab6="$(STEER_NFT_COMPAT=modern "$BIN" dnsd-table --spec "$tmp/t1/v6.yaml" --state-dir "$tmp/t1/st6" 2>/dev/null)"
S6="$(printf '%s\n' "$tab6" | awk -F'|' '$5 == "f" { print $1 }')"
set_els6() { printf '%s\n' "$DRY6" | awk -v s="$1" '$1 == "set" && $2 == s { f = 1 } f && /elements/ { print; exit } f && /^    }/ { exit }'; }
check "IPv6: набор IPv4 — оба имени" "        elements = { 198.18.0.1, 198.18.0.2 }" "$(set_els6 "$S6")"
check "  парный набор IPv6 — поддельный IPv6 имени с настоящим IPv6" \
    "        elements = { fdfe:dcba:9876::c612:1 }" "$(set_els6 "${S6}6")"
check "  правило «без подмены — drop» и для IPv6" "yes" \
    "$(has "$DRY6" 'ip6 daddr fdfe:dcba:9876::/96 counter drop comment "steer-fakeip-nomap"')"

# ---- 2. сеть и трафик -------------------------------------------------------------------------
unshare -n sleep 600 >/dev/null 2>&1 & C=$!
unshare -n sleep 600 >/dev/null 2>&1 & T=$!
unshare -n sleep 600 >/dev/null 2>&1 & W=$!
pids="$C $T $W"
sleep 0.3
IC="nsenter -t $C -n"; IT="nsenter -t $T -n"; IW="nsenter -t $W -n"
link() {   # link ЗДЕСЬ ТАМ PID АДРЕС_ЗДЕСЬ АДРЕС_ТАМ
    "$real_ip" link add "$1" type veth peer name "$2"
    "$real_ip" link set "$2" netns "$3"
    "$real_ip" addr add "$4" dev "$1"
    "$real_ip" link set "$1" up
    nsenter -t "$3" -n "$real_ip" link set lo up
    nsenter -t "$3" -n "$real_ip" addr add "$5" dev "$2"
    nsenter -t "$3" -n "$real_ip" link set "$2" up
}
link r0 c0 "$C" 10.77.1.1/24 10.77.1.2/24
link t0 t1 "$T" 10.9.0.1/30 10.9.0.2/30
link w0 w1 "$W" 10.77.0.1/30 10.77.0.2/30
"$real_ip" link add dm0 type dummy && "$real_ip" link set dm0 up
$IC "$real_ip" route add default via 10.77.1.1
"$real_ip" route add default via 10.77.0.2 dev w0
for ns in "$IT" "$IW"; do
    $ns "$real_ip" link add dum0 type dummy
    $ns "$real_ip" link set dum0 up
    $ns "$real_ip" addr add 203.0.113.10/32 dev dum0
    $ns "$real_nft" -f - <<'N'
table inet cnt {
    chain pre {
        type filter hook prerouting priority -300; policy accept;
        ip daddr 203.0.113.10 counter comment "real"
        ip daddr 198.18.0.0/15 counter comment "pool"
    }
}
N
done
$IT "$real_ip" route add 10.77.1.0/24 via 10.9.0.1
$IW "$real_ip" route add 10.77.1.0/24 via 10.77.0.1
cnt() {   # cnt ПРОСТРАНСТВО real|pool
    $1 "$real_nft" list chain inet cnt pre | grep "comment \"$2\"" |
        sed -n 's/.*counter packets \([0-9]*\).*/\1/p'
}

# Журнал вызовов nft и ip — ОДИН файл на оба: по нему виден порядок.
mkdir -p "$tmp/bin"
for t in nft ip; do
    real="$(command -v $t)"
    printf '#!/bin/sh\nprintf "%s %%s\\n" "$*" >> "%s/calls.log"\nexec "%s" "$@"\n' "$t" "$tmp" "$real" \
        > "$tmp/bin/$t"
    chmod +x "$tmp/bin/$t"
done
PATH="$tmp/bin:$PATH"
export PATH

cat > "$tmp/send.py" <<'PY'
import os, socket, sys, time
dst, stop = sys.argv[1], sys.argv[2]
n = 0
while not os.path.exists(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(b'x', (dst, 9999)); n += 1
    except OSError:
        pass
    s.close()
    time.sleep(0.005)
print(n)
PY
SENDER=""
send_start() { rm -f "$tmp/stop"; $IC python3 "$tmp/send.py" "$1" "$tmp/stop" > "$tmp/sent" & SENDER=$!; }
send_stop() { : > "$tmp/stop"; wait "$SENDER" 2>/dev/null; sleep 0.2; cat "$tmp/sent"; }
burst() { $IC python3 -c "
import socket, time
for i in range($2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b'x', ('$1', 9999))
    except OSError: pass
    s.close(); time.sleep(0.005)
"; sleep 0.2; }

check "без движка: поддельный адрес уходит провайдеру как есть" "yes" \
    "$(burst 198.18.0.1 5; [ "$(cnt "$IW" pool)" -ge 5 ] && echo yes || echo no)"

printf 's19.test\n' > "$tmp/d.lst"
# Клиенты — устройство раздачи r0: так метку каналов ставит цепочка ingress_mark на хуке ingress
# (generate.c, «разметка на ingress»); без неё (STEER_NFT_INGRESS=0) — prerouting_mark. Засев и
# правило без подмены от этого не зависят — ниже проверяется и то, и другое.
cat > "$tmp/spec.json" <<EOF
{ "schema": 2, "lan_devices": ["r0"],
  "outputs": { "wg": { "kind": "interface", "device": "t0", "on_fail": "drop" } },
  "channels": [ { "name": "s", "match": { "domains_files": ["$tmp/d.lst"], "mode": "fakeip" },
                  "out": "wg" } ] }
EOF
mkdir -p "$tmp/st"
printf 's19.test\t198.18.0.1\t203.0.113.10\n' > "$tmp/st/fakeip.state"
S="--spec $tmp/spec.json --state-dir $tmp/st"
"$BIN" apply $S >"$tmp/apply.out" 2>&1
check "apply с непустым fakeip.state (резолвера нет) проходит" "0" "$?"
SS="$("$BIN" dnsd-table $S 2>/dev/null | awk -F'|' '$5 == "s" { print $1 }')"
check "  набор канала уже содержит засеянный поддельный адрес" "1" \
    "$("$real_nft" list set inet steer "$SS" | grep -c '198\.18\.0\.1')"
check "  и карта подмены" "1" "$("$real_nft" list map inet steer fakeip | grep -c '198.18.0.1 : 203.0.113.10')"
W0="$(cnt "$IW" real)" T0="$(cnt "$IT" real)"
burst 198.18.0.1 40
check "  пакеты клиента к поддельному адресу — в туннель" "yes" \
    "$([ $(($(cnt "$IT" real) - T0)) -ge 38 ] && echo yes || echo "no:$(($(cnt "$IT" real) - T0))")"
check "  у провайдера — ни одного" "0" "$(($(cnt "$IW" real) - W0))"

# Пять замен под трафиком: подкоманда apply ставит набор правил заново каждый раз (так же — reapply
# init.d без демона). Правило канала руками здесь не снимается нарочно: пакеты, пришедшие, пока
# правила нет, ушли бы напрямую законно, а проверяется окно самой замены.
W0="$(cnt "$IW" real)" WP0="$(cnt "$IW" pool)" T0="$(cnt "$IT" real)"
send_start 198.18.0.1
sleep 0.3
for k in 1 2 3 4 5; do
    "$BIN" apply $S >/dev/null 2>&1
    sleep 0.1
done
sent="$(send_stop)"
check "пять замен под трафиком: у провайдера ни одного пакета к настоящему адресу" "0" \
    "$(($(cnt "$IW" real) - W0))"
check "  и ни одного к поддельному" "0" "$(($(cnt "$IW" pool) - WP0))"
check "  туннель получал (отправлено $sent)" "yes" \
    "$([ $(($(cnt "$IT" real) - T0)) -gt 100 ] && echo yes || echo "no:$(($(cnt "$IT" real) - T0))")"
check "  метку ставила цепочка ingress_mark" "yes" \
    "$("$real_nft" list chain inet steer ingress_mark 2>/dev/null | grep -q 'counter packets [1-9]' &&
       echo yes || echo no)"

# То же без ingress: метку ставит prerouting_mark.
W0="$(cnt "$IW" real)" WP0="$(cnt "$IW" pool)" T0="$(cnt "$IT" real)"
send_start 198.18.0.1
sleep 0.3
for k in 1 2 3; do
    STEER_NFT_INGRESS=0 "$BIN" apply $S >/dev/null 2>&1
    sleep 0.1
done
sent="$(send_stop)"
check "без ingress (STEER_NFT_INGRESS=0): цепочки ingress_mark нет" "no" \
    "$("$real_nft" list chain inet steer ingress_mark >/dev/null 2>&1 && echo yes || echo no)"
check "  три замены под трафиком: у провайдера ни одного пакета" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" pool) - WP0))"
check "  туннель получал (отправлено $sent)" "yes" \
    "$([ $(($(cnt "$IT" real) - T0)) -gt 50 ] && echo yes || echo "no:$(($(cnt "$IT" real) - T0))")"
"$BIN" apply $S >/dev/null 2>&1

# ---- 3. поддельный адрес без подмены --------------------------------------------------------
nomap() { "$real_nft" list chain inet steer prerouting_dnat | grep 'steer-fakeip-nomap' |
          grep 'ip daddr' | sed -n 's/.*counter packets \([0-9]*\).*/\1/p'; }
WP0="$(cnt "$IW" pool)" TP0="$(cnt "$IT" pool)" N0="$(nomap)"
burst 198.18.0.99 20
check "адрес без подмены: к провайдеру не ушёл" "0" "$(($(cnt "$IW" pool) - WP0))"
check "  и в туннель тоже" "0" "$(($(cnt "$IT" pool) - TP0))"
check "  счётчик правила steer-fakeip-nomap вырос" "yes" \
    "$([ $(($(nomap) - N0)) -ge 20 ] && echo yes || echo no)"

# ---- 4. старт демона с непустым fakeip.state -------------------------------------------------
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
TBL="$(awk '$1 == "wg" { print $3 }' "$tmp/st/registry")"
check "после down: правила fwmark выхода нет" "0" "$("$real_ip" rule show | grep -c "lookup $TBL")"
: > "$tmp/calls.log"
W0="$(cnt "$IW" real)" T0="$(cnt "$IT" real)"
send_start 198.18.0.1
sleep 0.3
"$BIN" daemon --apply --socket "$tmp/s.sock" $S >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d.err"' 15
sleep 0.5
kill -9 "$D" 2>/dev/null
wait "$D" 2>/dev/null
# procd поднимает службу снова: демон не знает, что стоит в ядре, и применяет всё.
"$BIN" daemon --apply --socket "$tmp/s.sock" $S >"$tmp/d2.out" 2>"$tmp/d2.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d2.err"' 15
sleep 0.5
# Расхождение с ядром (чужой набор в нашей таблице): reload демона ставит набор правил заново —
# apply-commit --ruleset, тот же путь, что после снятого руками правила.
"$real_nft" add set inet steer junk '{ type ipv4_addr; }'
"$BIN" ctl --socket "$tmp/s.sock" reload >"$tmp/reload.out" 2>&1
sleep 0.3
check "  reload после расхождения с ядром заменил набор правил" "0" \
    "$("$real_nft" list sets inet 2>/dev/null | grep -c 'set junk')"
sent="$(send_stop)"
check "старт демона, перезапуск после kill -9, reload после расхождения: у провайдера ни одного пакета" "0" \
    "$(($(cnt "$IW" real) - W0))"
check "  туннель получал (отправлено $sent)" "yes" \
    "$([ $(($(cnt "$IT" real) - T0)) -gt 50 ] && echo yes || echo "no:$(($(cnt "$IT" real) - T0))")"
first_rule="$(grep -n "^ip rule add fwmark .* table $TBL" "$tmp/calls.log" | head -n 1 | cut -d: -f1)"
first_load="$(grep -n '^nft -f ' "$tmp/calls.log" | head -n 1 | cut -d: -f1)"
check "  порядок: правило fwmark выхода — раньше загрузки набора правил" "yes" \
    "$([ -n "$first_rule" ] && [ -n "$first_load" ] && [ "$first_rule" -lt "$first_load" ] && echo yes ||
       echo "no:rule=$first_rule load=$first_load")"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null

# Подкоманда — тот же порядок (init без демона, reapply).
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
: > "$tmp/calls.log"
"$BIN" apply $S >/dev/null 2>&1
first_rule="$(grep -n "^ip rule add fwmark .* table $TBL" "$tmp/calls.log" | head -n 1 | cut -d: -f1)"
first_load="$(grep -n '^nft -f ' "$tmp/calls.log" | head -n 1 | cut -d: -f1)"
check "подкоманда apply: правило fwmark — раньше загрузки набора правил" "yes" \
    "$([ -n "$first_rule" ] && [ -n "$first_load" ] && [ "$first_rule" -lt "$first_load" ] && echo yes ||
       echo "no:rule=$first_rule load=$first_load")"

# ---- 5. резолвер вырезает адрес из слитого засевом отрезка -----------------------------------
printf 'x1.a.test\nx2.a.test\nx3.a.test\n' > "$tmp/a.lst"
printf 'zz.b.test\n' > "$tmp/b.lst"
cat > "$tmp/cspec.json" <<EOF
{ "schema": 1, "from_default": ["10.77.1.0/24"],
  "outputs": { "wg": { "kind": "interface", "device": "t0" },
               "dm": { "kind": "interface", "device": "dm0" } },
  "channels": [ { "name": "a", "match": { "domains_files": ["$tmp/a.lst"] }, "out": "wg" },
                { "name": "b", "match": { "domains_files": ["$tmp/b.lst"] }, "out": "dm" } ] }
EOF
mkdir -p "$tmp/cst"
printf 'x1.a.test\t198.18.0.1\t203.0.113.31\nx2.a.test\t198.18.0.2\t203.0.113.32\nx3.a.test\t198.18.0.3\t203.0.113.33\n' \
    > "$tmp/cst/fakeip.state"
CS="--spec $tmp/cspec.json --state-dir $tmp/cst"
"$BIN" apply $CS >/dev/null 2>&1
tabc="$("$BIN" dnsd-table $CS 2>/dev/null)"
CA="$(printf '%s\n' "$tabc" | awk -F'|' '$5 == "a" { print $1 }')"
CB="$(printf '%s\n' "$tabc" | awk -F'|' '$5 == "b" { print $1 }')"
els() { "$real_nft" list set inet steer "$1" | tr -d '\n\t' | sed -n 's/.*elements = { \([^}]*\) }.*/\1/p'; }
check "засев: auto-merge слил соседние адреса канала в отрезок" "198.18.0.1-198.18.0.3" "$(els "$CA")"
cat > "$tmp/up.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04' + bytes([203, 0, 113, 9])
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
python3 "$tmp/up.py" 15575 & UP=$!
pids="$pids $UP"
"$BIN" dnsd $CS --listen-port 15571 --upstream-port 15575 >"$tmp/dnsd.log" 2>&1 & DN=$!
pids="$pids $DN"
wait_for 'grep -q "routes re-asserted" "$tmp/dnsd.log"' 5
check "  резолвер поднялся, отрезок тот же" "198.18.0.1-198.18.0.3" "$(els "$CA")"
printf 'x1.a.test\nx3.a.test\n' > "$tmp/a.lst"
printf 'zz.b.test\nx2.a.test\n' > "$tmp/b.lst"
n0="$(grep -c 'routes re-asserted' "$tmp/dnsd.log")"
kill -HUP "$DN"
wait_for '[ "$(grep -c "routes re-asserted" "$tmp/dnsd.log")" -gt "$n0" ]' 5
check "имя ушло в другой канал: отрезок разделён, соседи на месте" "198.18.0.1, 198.18.0.3" "$(els "$CA")"
check "  адрес — в наборе нового канала" "198.18.0.2" "$(els "$CB")"
kill "$DN" 2>/dev/null
wait "$DN" 2>/dev/null

# ---- 6. real-ip: резолвер возвращает элементы сразу после загрузки ----------------------------
printf 'rip.test\n' > "$tmp/r.lst"
cat > "$tmp/rspec.json" <<EOF
{ "schema": 1, "from_default": ["10.77.1.0/24"],
  "outputs": { "wg": { "kind": "interface", "device": "t0", "on_fail": "drop" } },
  "channels": [ { "name": "s", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "wg" },
                { "name": "r", "match": { "domains_files": ["$tmp/r.lst"], "mode": "realip" },
                  "out": "wg" } ] }
EOF
mkdir -p "$tmp/rst"
printf 's19.test\t198.18.0.1\t203.0.113.10\n' > "$tmp/rst/fakeip.state"
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
"$BIN" daemon --supervise --apply --socket "$tmp/r.sock" --spec "$tmp/rspec.json" \
    --state-dir "$tmp/rst" --dnsd-flag --listen-port --dnsd-flag 15581 \
    --dnsd-flag --upstream-port --dnsd-flag 15575 >"$tmp/rd.out" 2>"$tmp/rd.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/rd.err"' 15
wait_for 'grep -q "channel .*rule(s)" "$tmp/rd.err"' 5
tabr="$("$BIN" dnsd-table --spec "$tmp/rspec.json" --state-dir "$tmp/rst" 2>/dev/null)"
RS="$(printf '%s\n' "$tabr" | awk -F'|' '$5 == "r" { print $1 }')"
FS="$(printf '%s\n' "$tabr" | awk -F'|' '$5 == "s" { print $1 }')"
cat > "$tmp/qa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(".".join(str(b) for b in d[-4:]))
except socket.timeout:
    print("timeout")
PY
check "real-ip: клиенту — настоящий адрес" "203.0.113.9" "$(python3 "$tmp/qa.py" 15581 rip.test)"
rip_in() { "$real_nft" list set inet steer "$RS" 2>/dev/null | grep -c '203\.0\.113\.9 timeout'; }
wait_for '[ "$(rip_in)" = 1 ]' 3
check "  адрес — в наборе канала со сроком" "1" "$(rip_in)"
"$real_nft" add set inet steer junk '{ type ipv4_addr; }'
n0="$(grep -c 'right after the ruleset load' "$tmp/rd.err")"
"$BIN" ctl --socket "$tmp/r.sock" apply < "$tmp/rspec.json" >"$tmp/ra.out" 2>&1
fk_now="$("$real_nft" list set inet steer "$FS" 2>/dev/null | grep -c '198\.18\.0\.1')"
check "замена набора демоном: поддельный адрес в наборе канала сразу после ответа apply" "1" "$fk_now"
wait_for '[ "$(grep -c "right after the ruleset load" "$tmp/rd.err")" -gt "$n0" ]' 3
check "  загрузчик попросил резолвер вернуть real-ip сразу после загрузки" "yes" \
    "$([ "$(grep -c 'right after the ruleset load' "$tmp/rd.err")" -gt "$n0" ] && echo yes || echo no)"
check "  адрес real-ip — снова в наборе со сроком" "1" "$(rip_in)"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/rst" >/dev/null 2>&1

# ---- 7. засев не отстаёт от памяти резолвера ------------------------------------------------
# Апстрим отвечает по файлу «имя адрес-IPv4 адрес-IPv6» (перечитывает на каждый вопрос: B3 меняет
# адрес на ходу); имени нет в файле — 203.0.113.10 и 2001:db8:77::10.
cat > "$tmp/up2.py" <<'PY'
import socket, struct, sys
port, mapf = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
def lookup(name):
    try:
        for ln in open(mapf):
            f = ln.split()
            if len(f) >= 2 and f[0] == name:
                return f[1:] + ["2001:db8:77::10"]
    except OSError:
        pass
    return ["203.0.113.10", "2001:db8:77::10"]
while True:
    data, addr = s.recvfrom(2048)
    qend, labels = 12, []
    while data[qend]:
        l = data[qend]
        labels.append(data[qend + 1:qend + 1 + l].decode().lower())
        qend += 1 + l
    qtype = struct.unpack('>H', data[qend + 1:qend + 3])[0]
    qend += 5
    a = lookup(".".join(labels))
    rd = None
    if qtype == 1:
        rd = socket.inet_pton(socket.AF_INET, a[0])
    elif qtype == 28:
        rd = socket.inet_pton(socket.AF_INET6, a[1])
    hdr = data[:2] + b'\x81\x80' + data[4:6] + (b'\x00\x01' if rd else b'\x00\x00') + b'\x00' * 4
    ans = struct.pack('>HHHIH', 0xc00c, qtype, 1, 300, len(rd)) + rd if rd else b''
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/qa2.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
t = 28 if len(sys.argv) > 3 and sys.argv[3] == "AAAA" else 1
q = struct.pack('>HHHHHH', 0x4243, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', t, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    if not struct.unpack('>H', d[6:8])[0]:
        print("none")
    elif t == 28:
        print(socket.inet_ntop(socket.AF_INET6, d[-16:]))
    else:
        print(".".join(str(b) for b in d[-4:]))
except socket.timeout:
    print("timeout")
PY
: > "$tmp/up2.map"
python3 "$tmp/up2.py" 15595 "$tmp/up2.map" & UP2=$!
pids="$pids $UP2"
cat > "$tmp/f7.yaml" <<EOF
version: 2
lan: { devices: [r0] }
lists:
  f: { domains_file: $tmp/d.lst }
outputs:
  wg: { kind: interface, device: t0, on_fail: drop }
rules:
  - { name: f, to: f, out: wg }
EOF
mkdir -p "$tmp/fst"
F7="--spec $tmp/f7.yaml --state-dir $tmp/fst"
start7() {   # start7 ЖУРНАЛ
    "$BIN" daemon --supervise --apply --socket "$tmp/f.sock" $F7 --dnsd-flag --listen-port \
        --dnsd-flag 15591 --dnsd-flag --upstream-port --dnsd-flag 15595 >/dev/null 2>"$1" &
    D=$!
    pids="$pids $D"
    wait_for "grep -q 'спека применена при старте' '$1'" 15
    wait_for "grep -q 'listening on' '$1'" 5
}
qa7() { python3 "$tmp/qa2.py" 15591 "$@"; }
apply7() { STEER_SOCKET="$tmp/f.sock" "$BIN" apply $F7 >/dev/null 2>&1; }
# Пара «поддельный : настоящий» в карте ядра: элементы — по одному на строку, сравнение целиком.
inmap() {   # inmap КАРТА ПОДДЕЛЬНЫЙ НАСТОЯЩИЙ
    "$real_nft" list map inet steer "$1" 2>/dev/null | tr -d '\n\t' | tr ',{}' '\n\n\n' |
        sed 's/^ *//; s/ *$//' | grep -cxF "$2 : $3"
}
del_chan7() {
    h="$("$real_nft" -a list chain inet steer prerouting_mark | grep 'comment "steer:' | head -n 1 |
         sed -n 's/.*# handle \([0-9]*\).*/\1/p')"
    "$real_nft" delete rule inet steer prerouting_mark handle "$h"
}
start7 "$tmp/fd1.err"
check "7: демон с резолвером поднялся" "1" "$(grep -c 'спека применена при старте' "$tmp/fd1.err")"

# B1. Новое имя — и сразу замена набора: клиент получил поддельный адрес и шлёт на него, а таблицу
# в этот миг ставят заново (правило канала снято снаружи, apply чинит заменой).
lost=0 leak=0 inm=0 tot=0
for k in 1 2 3; do
    F="$(qa7 "b1n$k.s19.test")"
    T0="$(cnt "$IT" real)" W0="$(cnt "$IW" real)"
    send_start "$F"
    sleep 0.1
    del_chan7
    apply7
    inm=$((inm + $(inmap fakeip "$F" 203.0.113.10)))
    sleep 0.5
    sent="$(send_stop)"
    got=$(($(cnt "$IT" real) - T0))
    tot=$((tot + sent))
    [ "$got" -lt "$sent" ] && lost=$((lost + sent - got))
    leak=$((leak + $(cnt "$IW" real) - W0))
done
check "  B1: новое имя, сразу замена набора (×3): пара в карте сразу после apply" "3" "$inm"
check "  клиент с кэшем DNS не потерял ни одного пакета (отправлено $tot), у провайдера ноль" "0 0" \
    "$lost $leak"

# B2. Два новых имени, через секунду — перезапуск службы: SIGTERM демону (он гасит резолвер), down,
# старт. Имена последних секунд обязаны дожить до карты нового набора.
F5="$(qa7 b2n5.s19.test)"
F6="$(qa7 b2n6.s19.test)"
F56="$(qa7 b2n5.s19.test AAAA)"
check "  B2: у имён поддельные адреса (A, A, AAAA)" "yes" \
    "$(case "$F5$F6$F56" in 198.18.*198.18.*fdfe:dcba:9876::*) echo yes ;; *) echo "no:$F5 $F6 $F56" ;; esac)"
sleep 1
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/fst" >/dev/null 2>&1
start7 "$tmp/fd2.err"
check "  после перезапуска карта — с обоими именами, fakeip6 — с IPv6 имени" "1 1 1" \
    "$(inmap fakeip "$F5" 203.0.113.10) $(inmap fakeip "$F6" 203.0.113.10) $(inmap fakeip6 "$F56" 2001:db8:77::10)"
T0="$(cnt "$IT" real)" W0="$(cnt "$IW" real)"
burst "$F5" 5
check "  клиент с поддельным адресом из кэша: 5 из 5 — в туннель, у провайдера ноль" "5 0" \
    "$(($(cnt "$IT" real) - T0)) $(($(cnt "$IW" real) - W0))"

# B3. Апстрим сменил адрес имени: в памяти резолвера и в карте новый, в файле — ещё прежний
# (перезапись по сроку — раз в минуту). Замена набора засевает карту из файла.
printf 'b3n1.s19.test 203.0.113.11\n' > "$tmp/up2.map"
F="$(qa7 b3n1.s19.test)"
wait_for "grep -q '^b3n1.s19.test	$F	203.0.113.11$' '$tmp/fst/fakeip.state'" 3
check "  B3: n1 = .11 — в карте и в файле" "1 1" \
    "$(inmap fakeip "$F" 203.0.113.11) $(grep -c "^b3n1.s19.test	$F	203.0.113.11$" "$tmp/fst/fakeip.state")"
printf 'b3n1.s19.test 203.0.113.12\n' > "$tmp/up2.map"
qa7 b3n1.s19.test >/dev/null
wait_for "[ \"\$(inmap fakeip '$F' 203.0.113.12)\" = 1 ]" 3
check "  апстрим сменил адрес: карта .12, файл ещё .11" "1 1" \
    "$(inmap fakeip "$F" 203.0.113.12) $(grep -c "^b3n1.s19.test	$F	203.0.113.11$" "$tmp/fst/fakeip.state")"
del_chan7
apply7
now12="$(inmap fakeip "$F" 203.0.113.12)"
sleep 1
check "  замена набора: в карте .12 сразу после apply и через секунду, .11 нет" "1 1 0" \
    "$now12 $(inmap fakeip "$F" 203.0.113.12) $(inmap fakeip "$F" 203.0.113.11)"
# Карта испорчена руками — резолвер на SIGHUP сверяет её с памятью, а не верит EEXIST.
"$real_nft" delete element inet steer fakeip "{ $F }"
"$real_nft" add element inet steer fakeip "{ $F : 203.0.113.99 }"
DN="$(pgrep -P "$D" -f dnsd | head -n 1)"
n0="$(grep -c 'заменён на тот, что знает резолвер' "$tmp/fd2.err")"
kill -HUP "$DN" 2>/dev/null
wait_for "[ \"\$(grep -c 'заменён на тот, что знает резолвер' '$tmp/fd2.err')\" -gt $n0 ]" 5
check "  карта испорчена руками, SIGHUP: резолвер вернул свой адрес и сказал об этом" "1 0 yes" \
    "$(inmap fakeip "$F" 203.0.113.12) $(inmap fakeip "$F" 203.0.113.99) $([ "$(grep -c 'заменён на тот, что знает резолвер' "$tmp/fd2.err")" -gt "$n0" ] && echo yes || echo no)"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/fst" >/dev/null 2>&1

echo "swapmatch: $pass ok, $fail fail"
[ "$fail" = 0 ]
