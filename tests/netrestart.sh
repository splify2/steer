#!/bin/sh
# `/etc/init.d/network restart` под трафиком (проверка на QEMU 04664a5, OpenWrt 25.12.5,
# 2026-09-28; устройство — docs/architecture.md, раздел 4а, «Страж правил»).
#
# Что было. netifd при старте снимает все правила ip rule и ставит свои (local, main, default) —
# вместе с ними пропадает правило fwmark выхода, а br-lan пересоздаётся, и ядро снимает с него
# цепочку ingress_mark. Разметка цела (запасной prerouting_mark метит), dnat fake-IP подменяет, а
# правила нет — пакет идёт по main, masquerade, и он в WAN. Страж правил возвращал правило через
# 2-2,5 с, сверка на проходе — цепочку ingress через 3,6-8,6 с.
#
# Сеть — как в swapmatch.sh: роутер (сам стенд, мост br0 с портом r0 — устройство раздачи),
# клиент за r0, «туннель» T за t0 и t2 (пул выхода wg из двух устройств — группа) и «провайдер» W
# за w0 (маршрут по умолчанию). Настоящий адрес 203.0.113.10 есть и за туннелем, и у провайдера;
# пакет к нему у провайдера — утечка. Клиент шлёт UDP на поддельный 198.18.0.1 (карта и набор
# канала засеяны из fakeip.state, резолвер не нужен) каждые 5 мс, каждый пакет — новое соединение.
#
# Что проверяется (A — набор правил и страж).
#  A1. Без демона: снятое правило fwmark выхода — пакеты канала отбрасывает postrouting_guard, у
#      провайдера ни одного; счётчик правила steer-guard растёт.
#  A2. Демон (--watch): снятие всех правил, как netifd (`ip rule flush` + main и default), под
#      трафиком — у провайдера ни одного; правило назад быстрее секунды, с прежним приоритетом, в
#      журнале «возвращены», подписчику repaired.
#  A3. Мост пересоздан и правила сняты одновременно — у провайдера ни одного; цепочка ingress_mark
#      назад на новом br0 быстрее двух секунд, в журнале — сверка по новому устройству раздачи.
#  A4. Законные пути не тронуты: канал в direct — к провайдеру; канал в выход, пущенный напрямую
#      (устройства нет, on_fail=direct: отметка failopen), — тоже к провайдеру.
#  A5. Группа переключилась (t0 упал, сторож увёл выход на t2) — трафик идёт в t2, а не
#      отбрасывается; у провайдера ни одного.
#  A6. Шторм: правило снимают шесть раз подряд — каждый раз оно назад, в журнале одна строка о
#      шторме (страж перешёл на возврат через секунду после пачки).
#  A7. IPv6 на `network restart` (проверка на QEMU 98b7964, 2026-09-28): netifd кладёт lo — ядро
#      снимает с ним запасной запрет таблицы IPv6 выхода, — устройство выхода теряет IPv6 (маршрут
#      `default dev` уходит из таблицы IPv6), и только потом правила сняты обоих семейств. Новый
#      демон (без памяти о прежних возвратах, шторма нет). Запрет IPv6 назад быстрее 300 мс после
#      lo down; правило IPv6 — быстрым путём стража (быстрее 300 мс, «возвращены», а не reload
#      «правила fwmark IPv6 нет»), хотя таблица IPv6 в этот миг пуста; у провайдера — ни одного
#      пакета IPv6. Затем мост пересоздан и lo лёг вместе со снятием правил — цепочка ingress_mark
#      и правила обоих семейств назад быстрее 500 мс.
#  A8. Сверка по новому мосту уже идёт (держит очередь изменяющих команд), и только тогда сняты
#      правила; ip и nft у детей движка медленные, как на слабом роутере. Правила обоих семейств
#      назад стражем быстрее 300 мс, цепочка ingress_mark — быстрее 500 мс после снятия, сверка
#      выход не перепривязывала, у провайдера ни одного пакета.
#
# B — резолвер поднят раньше набора правил (steer restart): его восстановление подмены уходит в
# пустоту (ENOENT), затем набор правил, вопрос одного имени, перезапись файла состояния, снятое
# правило и замена набора под трафиком клиента с поддельными адресами в кэше. Настоящие адреса
# имён, которых не спрашивали (и IPv6), остаются в файле; новая карта (и fakeip6) — со всеми;
# «без подмены» не отброшено ни одного пакета; по SIGHUP резолвер ставит подмену по сохранённым
# адресам. Заодно: смена адреса у засеянного имени — одной транзакцией, а не EEXIST на засеве.
#
# C — лимит починок по сверке прохода (три за пять минут): три снятых правила канала — каждое
# вернула сверка, четвёртое — отказ и одна строка в журнал на окно; мост пропал — расхождение
# объяснимо и чинится мимо исчерпанного лимита; пять пересозданий моста подряд — цепочка ingress
# каждый раз назад.
#
# Нужны root, unshare -nm, nsenter, ip, nft и python3. Чего-то нет — стенд пропускается вслух.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "netrestart: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${NETRESTART_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    NETRESTART_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null
real_nft="$(command -v nft)"
real_ip="$(command -v ip)"
"$real_nft" add table inet nr_probe 2>/dev/null || skip "nf_tables недоступен"
"$real_nft" add chain inet nr_probe c '{ type filter hook ingress device "lo" priority 10; }' \
    2>/dev/null || { "$real_nft" delete table inet nr_probe; skip "ядро не принимает цепочку inet ingress"; }
"$real_nft" delete table inet nr_probe

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
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

# ---- сеть -------------------------------------------------------------------------------------
unshare -n sleep 900 >/dev/null 2>&1 & C=$!
unshare -n sleep 900 >/dev/null 2>&1 & T=$!
unshare -n sleep 900 >/dev/null 2>&1 & W=$!
pids="$C $T $W"
sleep 0.3
IC="nsenter -t $C -n"; IT="nsenter -t $T -n"; IW="nsenter -t $W -n"
link() {   # link ЗДЕСЬ ТАМ PID АДРЕС_ЗДЕСЬ АДРЕС_ТАМ
    "$real_ip" link add "$1" type veth peer name "$2"
    "$real_ip" link set "$2" netns "$3"
    [ -n "$4" ] && "$real_ip" addr add "$4" dev "$1"
    "$real_ip" link set "$1" up
    nsenter -t "$3" -n "$real_ip" link set lo up
    nsenter -t "$3" -n "$real_ip" addr add "$5" dev "$2"
    nsenter -t "$3" -n "$real_ip" link set "$2" up
}
link r0 c0 "$C" "" 10.77.1.2/24
# Порт вне моста не пересылает: между `ip link del br0` и новым мостом пакет клиента приходил бы
# на голый r0 и уходил бы по main мимо «кто» канала (устройство br0). На роутере это закрывает fw4:
# у порта без моста нет зоны, и пересылку с него отвергает политика forward по умолчанию.
sysctl -qw net.ipv4.conf.r0.forwarding=0 2>/dev/null
link t0 t1 "$T" 10.9.0.1/30 10.9.0.2/30
link t2 t3 "$T" 10.9.1.1/30 10.9.1.2/30
link w0 w1 "$W" 10.77.0.1/30 10.77.0.2/30
# IPv6 (A7) — на тех же звеньях, без DAD: адрес готов сразу.
sysctl -qw net.ipv6.conf.all.forwarding=1 2>/dev/null
v6up() {   # адреса IPv6 устройств выхода (A7 снимает их, выключая IPv6 на устройстве)
    "$real_ip" -6 addr add fd09::1/64 dev t0 nodad 2>/dev/null
    "$real_ip" -6 addr add fd09:1::1/64 dev t2 nodad 2>/dev/null
}
v6up
$IT "$real_ip" -6 addr add fd09::2/64 dev t1 nodad
$IT "$real_ip" -6 addr add fd09:1::2/64 dev t3 nodad
"$real_ip" -6 addr add fd77::1/64 dev w0 nodad
$IW "$real_ip" -6 addr add fd77::2/64 dev w1 nodad
$IC "$real_ip" -6 addr add fd77:1::2/64 dev c0 nodad
# Мост раздачи — как br-lan у netifd: пересоздаётся целиком (mkbr после `ip link del br0`).
mkbr() {
    "$real_ip" link add br0 type bridge
    "$real_ip" link set r0 master br0
    "$real_ip" addr add 10.77.1.1/24 dev br0
    "$real_ip" -6 addr add fd77:1::1/64 dev br0 nodad
    "$real_ip" link set br0 up
}
mkbr
$IC "$real_ip" route add default via 10.77.1.1
$IC "$real_ip" -6 route add default via fd77:1::1
"$real_ip" route add default via 10.77.0.2 dev w0
"$real_ip" -6 route add default via fd77::2 dev w0
for ns in "$IT" "$IW"; do
    $ns "$real_ip" link add dum0 type dummy
    $ns "$real_ip" link set dum0 up
    $ns "$real_ip" addr add 203.0.113.10/32 dev dum0
done
# Настоящий IPv6 за туннелем — на самих t1 и t3: маршрут выхода `default dev t0` без шлюза, и сосед
# ищется по ND, а ND отвечает только за адрес своего устройства (у ARP IPv4 — за любой свой).
$IT "$real_ip" -6 addr add 2001:db8:77::10/128 dev t1 nodad
$IT "$real_ip" -6 addr add 2001:db8:77::10/128 dev t3 nodad
$IW "$real_ip" -6 addr add 2001:db8:77::10/128 dev dum0 nodad
# Цели пробы сторожа — за туннелем (выход жив, пока их видно через t0 и t2).
$IT "$real_ip" addr add 1.1.1.1/32 dev dum0
$IT "$real_ip" addr add 8.8.8.8/32 dev dum0
$IW "$real_ip" addr add 198.51.100.7/32 dev dum0
$IW "$real_ip" addr add 198.51.100.8/32 dev dum0
$IT "$real_nft" -f - <<'N'
table inet cnt {
    chain pre {
        type filter hook prerouting priority -300; policy accept;
        iifname "t1" ip daddr 203.0.113.10 counter comment "real1"
        iifname "t3" ip daddr 203.0.113.10 counter comment "real3"
        ip6 daddr 2001:db8:77::10 counter comment "real6"
    }
}
N
$IW "$real_nft" -f - <<'N'
table inet cnt {
    chain pre {
        type filter hook prerouting priority -300; policy accept;
        ip daddr 203.0.113.10 counter comment "real"
        ip daddr 198.18.0.0/15 counter comment "pool"
        ip daddr 198.51.100.7 counter comment "direct"
        ip daddr 198.51.100.8 counter comment "fo"
        ip6 daddr 2001:db8:77::10 counter comment "real6"
    }
}
N
$IT "$real_ip" route add 10.77.1.0/24 via 10.9.0.1
$IW "$real_ip" route add 10.77.1.0/24 via 10.77.0.1
cnt() {   # cnt ПРОСТРАНСТВО МЕТКА
    $1 "$real_nft" list chain inet cnt pre | grep "comment \"$2\"" |
        sed -n 's/.*counter packets \([0-9]*\).*/\1/p'
}
guard() {  # счётчик правила steer-guard:ВЫХОД
    "$real_nft" list chain inet steer postrouting_guard 2>/dev/null | grep "steer-guard:$1\"" |
        sed -n 's/.*counter packets \([0-9]*\).*/\1/p'
}

# ifdown/ifup netifd у стенда нет: сторож оживлял бы ими выход без устройства.
mkdir -p "$tmp/bin"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"
export PATH

cat > "$tmp/send.py" <<'PY'
import os, socket, sys, time
dst, stop = sys.argv[1], sys.argv[2]
fam = socket.AF_INET6 if ':' in dst else socket.AF_INET
n = 0
while not os.path.exists(stop):
    s = socket.socket(fam, socket.SOCK_DGRAM)
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
    s = socket.socket(socket.AF_INET6 if ':' in '$1' else socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b'x', ('$1', 9999))
    except OSError: pass
    s.close(); time.sleep(0.005)
"; sleep 0.2; }

printf 's19.test\n' > "$tmp/d.lst"
printf '198.51.100.7\n' > "$tmp/dir.lst"
printf '198.51.100.8\n' > "$tmp/fo.lst"
printf '2001:db8:77::10/128\n' > "$tmp/v6.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2, "lan_devices": ["br0"],
  "outputs": { "wg": { "kind": "interface", "devices": ["t0", "t2"], "on_fail": "drop" },
               "dx": { "kind": "interface", "device": "nodev0", "on_fail": "direct" },
               "dr": { "kind": "direct" } },
  "channels": [ { "name": "dir", "match": { "prefixes_files": ["$tmp/dir.lst"] }, "out": "dr" },
                { "name": "fo", "match": { "prefixes_files": ["$tmp/fo.lst"] }, "out": "dx" },
                { "name": "s", "match": { "domains_files": ["$tmp/d.lst"], "mode": "fakeip" },
                  "out": "wg" },
                { "name": "v6", "match": { "prefixes_files": ["$tmp/v6.lst"] }, "out": "wg" } ] }
EOF
mkdir -p "$tmp/st"
printf 's19.test\t198.18.0.1\t203.0.113.10\n' > "$tmp/st/fakeip.state"
S="--spec $tmp/spec.json --state-dir $tmp/st"
# Правило выхода wg — по метке из реестра: таблица в выводе ip бывает и именем из rt_tables.d.
ours() { "$real_ip" rule show | grep -c "fwmark 0x$MW/"; }
pref_of() { "$real_ip" rule show | grep "fwmark 0x$MW/" | head -n 1 | cut -d: -f1; }

# ---- A1. без демона: снятое правило — отбрасывание, а не WAN ---------------------------------
"$BIN" apply $S >"$tmp/apply.out" 2>&1
check "A1: apply проходит" "0" "$?"
MW="$(awk '$1 == "wg" { print $2 }' "$tmp/st/registry")"
check "  цепочка postrouting_guard в ядре, правило выхода wg — по устройствам пула" "yes" \
    "$("$real_nft" list chain inet steer postrouting_guard 2>/dev/null |
       grep -q 'oifname != { "t0", "t2" } counter packets [0-9]* bytes [0-9]* drop comment "steer-guard:wg"' &&
       echo yes || echo no)"
W0="$(cnt "$IW" real)" T0="$(cnt "$IT" real1)"
burst 198.18.0.1 20
check "  с правилом: пакеты — в туннель, у провайдера ни одного" "yes 0" \
    "$([ $(($(cnt "$IT" real1) - T0)) -ge 18 ] && echo yes || echo no) $(($(cnt "$IW" real) - W0))"
"$real_ip" rule del fwmark "0x$MW/$("$real_ip" rule show | grep -o "fwmark 0x$MW/[^ ]*" | head -n 1 | cut -d/ -f2)"
check "  правило fwmark выхода снято" "0" "$(ours)"
W0="$(cnt "$IW" real)" G0="$(guard wg)"
burst 198.18.0.1 20
check "  без правила: у провайдера ни одного" "0" "$(($(cnt "$IW" real) - W0))"
check "  отбросило правило steer-guard:wg" "yes" \
    "$([ $(($(guard wg) - G0)) -ge 18 ] && echo yes || echo "no:$(($(guard wg) - G0))")"

# ---- демон ------------------------------------------------------------------------------------
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
"$BIN" daemon --watch --watch-period 3 --apply --socket "$tmp/s.sock" $S >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d.err"' 15
wait_for 'grep -q "^wg t0 " "$tmp/st/active" 2>/dev/null' 15
check "демон: спека применена, выход wg на t0" "1 yes" \
    "$(grep -c 'спека применена при старте' "$tmp/d.err") $(grep -q '^wg t0 ' "$tmp/st/active" && echo yes || echo no)"
STEER_SOCKET="$tmp/s.sock" "$BIN" subscribe $S > "$tmp/sub.out" 2>&1 &
SUB=$!
pids="$pids $SUB"
wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out" 2>/dev/null' 5
sleep 4   # первый проход и его следствия — до опыта

# ---- A2. netifd снимает все правила под трафиком ----------------------------------------------
P0="$(pref_of)"
W0="$(cnt "$IW" real)" WP0="$(cnt "$IW" pool)" T0="$(cnt "$IT" real1)" G0="$(guard wg)"
n0="$(grep -c 'сняты снаружи — возвращены' "$tmp/d.err")"
send_start 198.18.0.1
sleep 0.3
t0="$(now_ms)"
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
wait_for '[ "$(ours)" = 1 ]' 5
ms=$(( $(now_ms) - t0 ))
sleep 0.5
sent="$(send_stop)"
check "A2: ip rule flush как netifd — у провайдера ни одного пакета (отправлено $sent)" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" pool) - WP0))"
echo "     (правило назад через $ms мс)"
check "  правило назад быстрее секунды" "yes" "$([ "$(ours)" = 1 ] && [ $ms -lt 1000 ] && echo yes || echo "no:$ms ms")"
check "  с прежним приоритетом" "$P0" "$(pref_of)"
check "  туннель получал" "yes" \
    "$([ $(($(cnt "$IT" real1) - T0)) -gt 50 ] && echo yes || echo "no:$(($(cnt "$IT" real1) - T0))")"
check "  окно было, и его закрыл steer-guard (отброшено > 0)" "yes" \
    "$([ $(($(guard wg) - G0)) -gt 0 ] && echo yes || echo no)"
check "  в журнале — «возвращены: wg»" "yes" \
    "$([ "$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d.err")" -gt "$n0" ] && echo yes || echo no)"
wait_for 'grep -q "\"ev\":\"repaired\"" "$tmp/sub.out"' 3
check "  подписчику repaired" '{"v":1,"ev":"repaired","outputs":["wg"],"masq":false}' \
    "$(grep '"ev":"repaired"' "$tmp/sub.out" | tail -n 1)"
sleep 6   # внеочередной проход сторожа после починки — до следующего опыта

# ---- A3. мост пересоздан и правила сняты одновременно ------------------------------------------
ing_on_br0() { "$real_nft" list chain inet steer ingress_mark 2>/dev/null | grep -q 'device "br0"' && echo yes || echo no; }
check "A3: до опыта цепочка ingress_mark висит на br0" "yes" "$(ing_on_br0)"
W0="$(cnt "$IW" real)" WP0="$(cnt "$IW" pool)" T0="$(cnt "$IT" real1)"
n0="$(grep -c 'устройство раздачи появилось заново' "$tmp/d.err")"
send_start 198.18.0.1
sleep 0.3
"$real_ip" link del br0
check "  мост снят — цепочку ядро сняло вместе с ним" "no" "$(ing_on_br0)"
t0="$(now_ms)"
mkbr
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
wait_for '[ "$(ing_on_br0)" = yes ] && [ "$(ours)" = 1 ]' 10
ms=$(( $(now_ms) - t0 ))
sleep 0.5
sent="$(send_stop)"
echo "     (цепочка ingress и правило назад через $ms мс)"
check "  у провайдера ни одного пакета (отправлено $sent)" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" pool) - WP0))"
check "  цепочка ingress_mark на новом br0 и правило на месте быстрее двух секунд" "yes" \
    "$([ "$(ing_on_br0)" = yes ] && [ "$(ours)" = 1 ] && [ $ms -lt 2000 ] && echo yes || echo "no:$ms ms")"
check "  в журнале — сверка по новому устройству раздачи" "yes" \
    "$([ "$(grep -c 'устройство раздачи появилось заново' "$tmp/d.err")" -gt "$n0" ] && echo yes || echo no)"
check "  туннель получал" "yes" \
    "$([ $(($(cnt "$IT" real1) - T0)) -gt 20 ] && echo yes || echo "no:$(($(cnt "$IT" real1) - T0))")"
sleep 6

# ---- A4. законные пути в WAN ------------------------------------------------------------------
D0="$(cnt "$IW" direct)" F0="$(cnt "$IW" fo)"
burst 198.51.100.7 20
check "A4: канал в direct — к провайдеру, как прежде" "yes" \
    "$([ $(($(cnt "$IW" direct) - D0)) -ge 18 ] && echo yes || echo "no:$(($(cnt "$IW" direct) - D0))")"
MX="$(awk '$1 == "dx" { print $2 }' "$tmp/st/registry")"
check "  выход dx без устройства (on_fail=direct) отмечен «пущен напрямую»" "yes" \
    "$("$real_nft" list set inet steer failopen 2>/dev/null | grep -q "0x0*$MX" && echo yes || echo no)"
burst 198.51.100.8 20
check "  его канал — к провайдеру, steer-guard не мешает" "yes" \
    "$([ $(($(cnt "$IW" fo) - F0)) -ge 18 ] && echo yes || echo "no:$(($(cnt "$IW" fo) - F0))")"

# ---- A5. группа переключилась ----------------------------------------------------------------
"$real_ip" link set t0 down
wait_for 'grep -q "^wg t2 " "$tmp/st/active" 2>/dev/null' 20
check "A5: t0 упал — сторож увёл выход wg на t2" "yes" \
    "$(grep -q '^wg t2 ' "$tmp/st/active" && echo yes || echo no)"
sleep 1
W0="$(cnt "$IW" real)" T3="$(cnt "$IT" real3)" G0="$(guard wg)"
burst 198.18.0.1 20
check "  трафик идёт в t2, не отбрасывается" "yes 0" \
    "$([ $(($(cnt "$IT" real3) - T3)) -ge 18 ] && echo yes || echo "no:$(($(cnt "$IT" real3) - T3))") $(($(guard wg) - G0))"
check "  у провайдера ни одного" "0" "$(($(cnt "$IW" real) - W0))"
"$real_ip" link set t0 up

# ---- A6. шторм: правило снимают снова и снова ------------------------------------------------
del_ours() { "$real_ip" rule del fwmark "$("$real_ip" rule show | grep -o "fwmark 0x$MW/[^ ]*" | head -n 1 | cut -d' ' -f2)"; }
ok6=0
for k in 1 2 3 4 5 6; do
    del_ours
    wait_for '[ "$(ours)" = 1 ]' 4 && ok6=$((ok6 + 1))
done
check "A6: шесть снятий подряд — правило каждый раз назад (≤ 3 с)" "6" "$ok6"
check "  в журнале — шторм, одной строкой" "1" "$(grep -c 'снимают снаружи снова и снова' "$tmp/d.err")"

# NETRESTART_KEEP=ФАЙЛ — журнал демона сохранить (разбор упавшего опыта).
[ -n "${NETRESTART_KEEP:-}" ] && cp "$tmp/d.err" "$NETRESTART_KEEP"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null

# ---- A7. IPv6: lo лёг, IPv6 устройства выхода ушёл, правила сняты ------------------------------
# Новый демон: у прежнего после A6 — шторм, и он возвращал бы правила через секунду.
"$BIN" daemon --watch --watch-period 3 --apply --socket "$tmp/s.sock" $S >"$tmp/d7.out" 2>"$tmp/d7.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/d7.err"' 15
sleep 4
TW="$(awk '$1 == "wg" { print $3 }' "$tmp/st/registry")"
ours6() { "$real_ip" -6 rule show | grep -c "fwmark 0x$MW/"; }
bs6() { "$real_ip" -6 route show table "$TW" | grep -c '^prohibit default.*metric 65535'; }
dev6() { "$real_ip" -6 route show table "$TW" | grep -c '^default dev t[02]'; }
v6off() { for d in t0 t2; do sysctl -qw "net.ipv6.conf.$d.disable_ipv6=$1"; done; }
check "A7: до опыта у выхода wg правило IPv6, запрет и маршрут IPv6 в устройство" "1 1 1" \
    "$(ours6) $(bs6) $(dev6)"
W6="$(cnt "$IW" real6)" T6="$(cnt "$IT" real6)"
burst 2001:db8:77::10 20
check "  IPv6 канала v6 — в туннель, у провайдера ни одного" "yes 0" \
    "$([ $(($(cnt "$IT" real6) - T6)) -ge 18 ] && echo yes || echo "no:$(($(cnt "$IT" real6) - T6))") $(($(cnt "$IW" real6) - W6))"
W6="$(cnt "$IW" real6)"
nr0="$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")"
send_start 2001:db8:77::10
sleep 0.3
t0="$(now_ms)"
"$real_ip" link set lo down
wait_for '[ "$(bs6)" = 1 ]' 5
ms=$(( $(now_ms) - t0 ))
echo "     (запрет IPv6 назад через $ms мс после lo down)"
check "  lo down: ядро сняло запрет IPv6, страж вернул его быстрее 300 мс" "yes" \
    "$([ "$(bs6)" = 1 ] && [ $ms -lt 300 ] && echo yes || echo "no:$ms ms")"
check "  в журнале — «запрет IPv6 … возвращён: wg»" "1" \
    "$(grep -c 'запрет IPv6 в таблице выхода снят .* возвращён: wg' "$tmp/d7.err")"
v6off 1
wait_for '[ "$(dev6)" = 0 ]' 3
t0="$(now_ms)"
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
"$real_ip" -6 rule flush
"$real_ip" -6 rule add priority 32766 table main
wait_for '[ "$(ours6)" = 1 ] && [ "$(ours)" = 1 ]' 5
ms=$(( $(now_ms) - t0 ))
echo "     (правила обоих семейств назад через $ms мс; таблица IPv6 — только запрет)"
check "  правило IPv6 назад быстрым путём стража, быстрее 300 мс" "yes" \
    "$([ "$(ours6)" = 1 ] && [ $ms -lt 300 ] && echo yes || echo "no:$ms ms, $(ours6)")"
check "  в журнале — «возвращены: wg», а не перепривязка reload" "yes 0" \
    "$([ "$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")" -gt "$nr0" ] && echo yes || echo no) $(grep -c 'правила fwmark IPv6 нет' "$tmp/d7.err")"
"$real_ip" link set lo up
v6off 0
v6up
sleep 0.5
sent="$(send_stop)"
check "  у провайдера ни одного пакета IPv6 (отправлено $sent)" "0" "$(($(cnt "$IW" real6) - W6))"
wait_for '[ "$(dev6)" = 1 ]' 20
check "  IPv6 на устройстве вернулся — проход сторожа вернул маршрут IPv6, запрет на месте" "1 1" \
    "$(dev6) $(bs6)"
T6="$(cnt "$IT" real6)"
burst 2001:db8:77::10 20
check "  IPv6 канала снова в туннель" "yes" \
    "$([ $(($(cnt "$IT" real6) - T6)) -ge 18 ] && echo yes || echo "no:$(($(cnt "$IT" real6) - T6))")"
sleep 6
# Мост пересоздан, lo лёг, IPv6 устройства выхода ушёл, правила сняты — всё разом, как netifd.
check "A7: до опыта цепочка ingress_mark на br0" "yes" "$(ing_on_br0)"
W0="$(cnt "$IW" real)" W6="$(cnt "$IW" real6)"
send_start 198.18.0.1
sleep 0.3
"$real_ip" link del br0
t0="$(now_ms)"
mkbr
"$real_ip" link set lo down
v6off 1
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
"$real_ip" -6 rule flush
"$real_ip" -6 rule add priority 32766 table main
wait_for '[ "$(ing_on_br0)" = yes ] && [ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ] && [ "$(bs6)" = 1 ]' 10
ms=$(( $(now_ms) - t0 ))
echo "     (цепочка ingress, правила и запрет IPv6 назад через $ms мс)"
check "  цепочка ingress_mark на новом br0, правила обоих семейств и запрет IPv6 — быстрее 500 мс" "yes" \
    "$([ "$(ing_on_br0)" = yes ] && [ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ] && [ $ms -lt 500 ] && echo yes || echo "no:$ms ms")"
check "  reload не перепривязывал правило IPv6" "0" "$(grep -c 'правила fwmark IPv6 нет' "$tmp/d7.err")"
"$real_ip" link set lo up
v6off 0
v6up
sleep 0.5
sent="$(send_stop)"
check "  у провайдера ни одного пакета (отправлено $sent)" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" real6) - W6))"

# ---- A8. сверка по новому мосту уже идёт, и только тогда сняты правила --------------------------
# Проверка на QEMU 4192267 (2026-09-29): в 4 прогонах из 5 netifd снимал правила, когда сверка
# набора правил по новому br-lan уже держала очередь изменяющих команд. Страж ждал её конца, а
# сверка, увидев «правила нет», перепривязывала выходы ребёнком apply-commit --route — по ~0,4 с на
# выход (запуски ip), — и набор правил с цепочкой ingress_mark вставал только после них: правила
# назад через 1–3,1 с, ingress_mark — через 3,3–4,4 с. Здесь ip и nft, которые запускают дети
# движка, медленные, как на том роутере (40 мс на запуск ip, 150 мс на nft; стенд сам зовёт
# настоящие): без этого сверка в пространстве стенда кончается раньше, чем правила успевают снять.
# Правила снимаются через 50 мс после начала сверки — пока идёт её план. Без исправления: правила
# назад через ~730 мс (страж ждал всю сверку), ingress — тогда же. Правила обоих семейств назад быстрее 300 мс, цепочка
# ingress — быстрее 500 мс после снятия, выход не перепривязывался, у провайдера ни одного пакета.
sleep 6
printf '#!/bin/sh\nsleep 0.04\nexec %s "$@"\n' "$real_ip" > "$tmp/bin/ip"
printf '#!/bin/sh\nsleep 0.15\nexec %s "$@"\n' "$real_nft" > "$tmp/bin/nft"
chmod +x "$tmp/bin/ip" "$tmp/bin/nft"
check "A8: до опыта цепочка ingress_mark на br0" "yes" "$(ing_on_br0)"
W0="$(cnt "$IW" real)" W6="$(cnt "$IW" real6)"
nl0="$(grep -c 'устройство раздачи появилось заново' "$tmp/d7.err")"
nb0="$(grep -c 'привязываю заново' "$tmp/d7.err")"
nr0="$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")"
send_start 198.18.0.1
sleep 0.3
"$real_ip" link del br0
mkbr
i=0
while [ "$(grep -c 'устройство раздачи появилось заново' "$tmp/d7.err")" -le "$nl0" ] && [ $i -lt 300 ]; do
    sleep 0.01; i=$((i + 1))
done
sleep 0.05
t0="$(now_ms)"
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
"$real_ip" -6 rule flush
"$real_ip" -6 rule add priority 32766 table main
wait_for '[ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ]' 10
msr=$(( $(now_ms) - t0 ))
wait_for '[ "$(ing_on_br0)" = yes ]' 10
msi=$(( $(now_ms) - t0 ))
echo "     (правила назад через $msr мс, цепочка ingress — через $msi мс после снятия правил)"
check "  сверка по новому мосту шла, когда сняли правила" "yes" \
    "$([ "$(grep -c 'устройство раздачи появилось заново' "$tmp/d7.err")" -gt "$nl0" ] && echo yes || echo no)"
check "  правила обоих семейств назад быстрее 300 мс — стражем, а не сверкой" "yes yes" \
    "$([ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ] && [ $msr -lt 300 ] && echo yes || echo "no:$msr ms") $([ "$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")" -gt "$nr0" ] && echo yes || echo no)"
check "  цепочка ingress_mark на новом br0 быстрее 500 мс" "yes" \
    "$([ "$(ing_on_br0)" = yes ] && [ $msi -lt 500 ] && echo yes || echo "no:$msi ms")"
check "  сверка выход не перепривязывала" "0" \
    "$(($(grep -c 'привязываю заново' "$tmp/d7.err") - nb0))"
sleep 0.5
sent="$(send_stop)"
check "  у провайдера ни одного пакета (отправлено $sent)" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" real6) - W6))"

# ---- A9. сверка по проходу сторожа (reload с --route) идёт, правила снимаются в её середине -------
# Проверка на QEMU (a2, a4; network restart при vless и ipv6: nat): ifdown wg0 запускает проход
# сторожа, тот находит расхождение набора правил и ставит reload; пока он идёт с --route, netifd
# снимает правила fwmark. Страж ждал конца всей команды (srv_rules_busy: apply/reload с --route
# или --drop), и правила возвращал сам reload, дойдя до выхода («привязываю заново»), — через
# 1,3–1,65 с вместо ~300 мс. Здесь расхождение — снятое правило канала в наборе правил (сверка
# ставит набор заново) и пустая таблица выхода wg (привязка заново, --route); nft у детей движка
# медленный (0,6 с), так что набор правил грузится долго — уже после привязки, и сама привязка
# снятые посреди набора правила не вернёт. Правила обоих семейств снимаются, когда таблица выхода
# привязана, а apply-commit ещё идёт: назад стражем быстрее 300 мс, без второго «привязываю
# заново», у провайдера ни одного пакета.
sleep 6
# Загрузка набора правил (`nft -f`) у детей ждёт файла nft.go, а не срока: на нагруженной машине
# 0,6 с сна могли кончиться раньше, чем стенд дождётся привязки и снимет правила, и «сверка ещё
# идёт» было неправдой (68/69 через раз). Остальные вызовы nft — медленные, как прежде.
rm -f "$tmp/nft.go"
printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = -f ] && { i=0; while [ ! -e %s ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i + 1)); done; }; done\nsleep 0.6\nexec %s "$@"\n' \
    "$tmp/nft.go" "$real_nft" > "$tmp/bin/nft"
chmod +x "$tmp/bin/nft"
TW="$("$real_ip" rule show | grep "fwmark 0x$MW/" | head -n 1 | sed -n 's/.*lookup \([^ ]*\).*/\1/p')"
W0="$(cnt "$IW" real)" W6="$(cnt "$IW" real6)"
nb0="$(grep -c 'привязываю заново' "$tmp/d7.err")"
nr0="$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")"
send_start 198.18.0.1
sleep 0.3
h="$("$real_nft" -a list chain inet steer prerouting_mark | grep 'comment "steer:' | head -n 1 | sed -n 's/.*# handle \([0-9]*\).*/\1/p')"
"$real_nft" delete rule inet steer prerouting_mark handle "$h"
"$real_ip" route flush table "$TW"
wait_for '[ "$(grep -c "привязываю заново" "$tmp/d7.err")" -gt "$nb0" ]' 12
wait_for '"$real_ip" route show table "$TW" | grep -q default' 10
sleep 0.15
busy=no
pgrep -f apply-commit >/dev/null 2>&1 && busy=yes
t0="$(now_ms)"
"$real_ip" rule flush
"$real_ip" rule add priority 32766 table main
"$real_ip" rule add priority 32767 table default
"$real_ip" -6 rule flush
"$real_ip" -6 rule add priority 32766 table main
wait_for '[ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ]' 10
msr=$(( $(now_ms) - t0 ))
echo "     (правила назад через $msr мс после снятия посреди сверки)"
touch "$tmp/nft.go"
check "A9: правила сняты, пока apply-commit сверки ещё идёт" "yes" "$busy"
check "  правила обоих семейств назад быстрее 300 мс — стражем, а не сверкой" "yes yes" \
    "$([ "$(ours)" = 1 ] && [ "$(ours6)" = 1 ] && [ $msr -lt 300 ] && echo yes || echo "no:$msr ms") $([ "$(grep -c 'сняты снаружи — возвращены: wg' "$tmp/d7.err")" -gt "$nr0" ] && echo yes || echo no)"
sleep 1.5
check "  выход перепривязывался один раз — до снятия, не после" "1" \
    "$(($(grep -c 'привязываю заново' "$tmp/d7.err") - nb0))"
sent="$(send_stop)"
check "  у провайдера ни одного пакета (отправлено $sent)" "0 0" \
    "$(($(cnt "$IW" real) - W0)) $(($(cnt "$IW" real6) - W6))"
rm -f "$tmp/bin/ip" "$tmp/bin/nft"
[ -n "${NETRESTART_KEEP:-}" ] && cp "$tmp/d7.err" "$NETRESTART_KEEP.a7"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1

# ---- B. резолвер поднят раньше набора правил ---------------------------------------------------
# Как `steer restart` на QEMU: таблицы нет, резолвер восстанавливает подмену в пустоту (ENOENT).
# Прежде он забывал при этом настоящие адреса, первая же перезапись файла состояния писала имена
# без них, и следующая замена набора правил засевала карту без них — клиент с поддельным адресом
# в кэше DNS упирался в «без подмены — никуда». n1 в файле — с устаревшим адресом (.99): его ответ
# (.10) и есть повод перезаписать файл; n2 — ещё и с настоящим IPv6.
cat > "$tmp/b.yaml" <<EOF
version: 2
lan: { devices: [br0] }
lists:
  f: { domains_file: $tmp/d.lst }
outputs:
  wg: { kind: interface, device: t0, on_fail: drop }
rules:
  - { name: f, to: f, out: wg }
EOF
mkdir -p "$tmp/bst"
printf 'n1.s19.test\t198.18.0.1\t203.0.113.99\nn2.s19.test\t198.18.0.2\t203.0.113.10\t2001:db8:7::10\nn3.s19.test\t198.18.0.3\t203.0.113.10\n' \
    > "$tmp/bst/fakeip.state"
BS="--spec $tmp/b.yaml --state-dir $tmp/bst"
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
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04' + bytes([203, 0, 113, 10])
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
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
python3 "$tmp/up.py" 15615 & UP=$!
pids="$pids $UP"
"$BIN" dnsd $BS --listen-port 15611 --upstream-port 15615 >"$tmp/dnsd.log" 2>&1 & DN=$!
pids="$pids $DN"
wait_for 'grep -q "listening on" "$tmp/dnsd.log"' 5
check "B: резолвер поднят до набора правил — подмену ставить некуда" "yes" \
    "$(grep -q '0 map rehydrated' "$tmp/dnsd.log" && echo yes || echo no)"
"$BIN" apply $BS >/dev/null 2>&1
check "  набор правил поставлен (карта засеяна из файла)" "1" \
    "$("$real_nft" list map inet steer fakeip 2>/dev/null | grep -c '198.18.0.2 : 203.0.113.10')"
check "  n1 спрошен — клиенту поддельный адрес" "198.18.0.1" "$(python3 "$tmp/qa.py" 15611 n1.s19.test)"
wait_for 'grep -q "^n1.s19.test	198.18.0.1	203.0.113.10$" "$tmp/bst/fakeip.state"' 5
check "  файл перезаписан новым адресом n1" "yes" \
    "$(grep -q "^n1.s19.test	198.18.0.1	203.0.113.10$" "$tmp/bst/fakeip.state" && echo yes || echo no)"
check "  а у имён, которых не спрашивали, настоящие адреса на месте (и IPv6)" "yes yes" \
    "$(grep -q "^n2.s19.test	198.18.0.2	203.0.113.10	2001:db8:7::10$" "$tmp/bst/fakeip.state" && echo yes || echo no) $(grep -q "^n3.s19.test	198.18.0.3	203.0.113.10$" "$tmp/bst/fakeip.state" && echo yes || echo no)"
check "  карта n1 — новый адрес (замена одной транзакцией, а не EEXIST на засеве)" "1" \
    "$("$real_nft" list map inet steer fakeip | grep -c '198.18.0.1 : 203.0.113.10')"
# Снять правило канала и поставить набор заново — под трафиком клиента с поддельными адресами в кэше.
nomap() { "$real_nft" list chain inet steer prerouting_dnat | grep 'steer-fakeip-nomap' |
          grep 'ip daddr' | sed -n 's/.*counter packets \([0-9]*\).*/\1/p'; }
W0="$(cnt "$IW" real)" T0="$(cnt "$IT" real1)"
send_start 198.18.0.3
sleep 0.3
h="$("$real_nft" -a list chain inet steer prerouting_mark | grep 'comment "steer:' | head -n 1 | sed -n 's/.*# handle \([0-9]*\).*/\1/p')"
"$real_nft" delete rule inet steer prerouting_mark handle "$h"
"$BIN" apply $BS >/dev/null 2>&1
N0="$(nomap)"
sleep 0.5
burst 198.18.0.2 20
sent="$(send_stop)"
check "  после замены набора карта — со всеми именами" "3" \
    "$("$real_nft" list map inet steer fakeip | grep -oE '198\.18\.0\.[123] : 203\.0\.113\.10' | wc -l | tr -d ' ')"
check "  и карта fakeip6 — с настоящим IPv6 n2" "1" \
    "$("$real_nft" list map inet steer fakeip6 2>/dev/null | grep -c 'fdfe:dcba:9876::c612:2 : 2001:db8:7::10')"
check "  клиент с кэшем DNS не теряет связь: туннель получал (отправлено $sent), без подмены — ни одного" "yes 0" \
    "$([ $(($(cnt "$IT" real1) - T0)) -gt 50 ] && echo yes || echo "no:$(($(cnt "$IT" real1) - T0))") $(($(nomap) - N0))"
check "  у провайдера ни одного" "0" "$(($(cnt "$IW" real) - W0))"
n0="$(grep -c 'map, .* routes re-asserted' "$tmp/dnsd.log")"
kill -HUP "$DN"
wait_for '[ "$(grep -c "map, .* routes re-asserted" "$tmp/dnsd.log")" -gt "$n0" ]' 5
check "  SIGHUP (таблица появилась): резолвер ставит подмену по сохранённым адресам" "3" \
    "$(grep 'map, .* routes re-asserted' "$tmp/dnsd.log" | tail -n 1 | sed -n 's/.*fake-IP: \([0-9]*\) map.*/\1/p')"
kill "$DN" 2>/dev/null
wait "$DN" 2>/dev/null
"$BIN" down --state-dir "$tmp/bst" >/dev/null 2>&1

# ---- C. лимит починок по сверке прохода ---------------------------------------------------------
# На QEMU после четвёртого и шестого `network restart` за пять минут цепочка ingress не вернулась
# (три починки за пять минут), и в журнале — ни строки. Проход — раз в 2 с.
"$BIN" daemon --watch --watch-period 2 --apply --socket "$tmp/c.sock" $S >"$tmp/c.out" 2>"$tmp/c.err" &
D=$!
pids="$pids $D"
wait_for 'grep -q "спека применена при старте" "$tmp/c.err"' 15
wait_for 'grep -q "^wg t0 " "$tmp/st/active" 2>/dev/null' 15
sleep 4
chan_rules() { "$real_nft" list chain inet steer prerouting_mark 2>/dev/null | grep -c 'comment "steer:'; }
del_chan() {
    h="$("$real_nft" -a list chain inet steer prerouting_mark | grep 'comment "steer:' | head -n 1 |
         sed -n 's/.*# handle \([0-9]*\).*/\1/p')"
    "$real_nft" delete rule inet steer prerouting_mark handle "$h"
}
R0="$(chan_rules)"
ok=0
# Срок — 20 с, а не 10: первые проходы нового демона заняты оживлением выхода dx (устройства
# nodev0 нет, «перезапускаю интерфейс» и пауза на подъём), и первую сверку проход делал через 8 с
# после снятия, а после A8 — через 10–12 с. Проверяется здесь то, что правило вернула сверка
# прохода и что четвёртую не пустил лимит, а не скорость прохода.
for k in 1 2 3; do
    del_chan
    wait_for '[ "$(chan_rules)" = "$R0" ]' 20 && ok=$((ok + 1))
    sleep 1
done
check "C1: три снятых правила канала — каждое вернула сверка прохода" "3" "$ok"
del_chan
wait_for 'grep -q "починок по сверке уже 3" "$tmp/c.err"' 10
check "  четвёртое — отказ по лимиту, строка в журнале" "1" "$(grep -c 'починок по сверке уже 3' "$tmp/c.err")"
sleep 6
check "  строка одна на окно, правило не вернулось" "1 $((R0 - 1))" \
    "$(grep -c 'починок по сверке уже 3' "$tmp/c.err") $(chan_rules)"
# Мост снят и не вернулся: расхождение (цепочку сняло ядро) находит проход — оно объяснимо
# пропажей устройства раздачи и идёт мимо исчерпанного лимита.
"$real_ip" link del br0
wait_for 'grep -q "после пересоздания устройства раздачи" "$tmp/c.err"' 10
check "C2: мост пропал — сверка прохода мимо лимита (расхождение объяснимо)" "yes" \
    "$(grep -q 'после пересоздания устройства раздачи' "$tmp/c.err" && echo yes || echo no)"
mkbr
wait_for '[ "$(ing_on_br0)" = yes ]' 5
check "  мост вернулся — цепочка ingress на месте" "yes" "$(ing_on_br0)"
sleep 2
n0="$(grep -c 'устройство раздачи появилось заново' "$tmp/c.err")"
ok=0
for k in 1 2 3 4 5; do
    "$real_ip" link del br0
    mkbr
    wait_for '[ "$(ing_on_br0)" = yes ]' 5 && ok=$((ok + 1))
    sleep 1
done
check "C3: пять пересозданий моста подряд при исчерпанном лимите — цепочка каждый раз назад" "5" "$ok"
check "  сверок по новому устройству раздачи — пять" "5" \
    "$(($(grep -c 'устройство раздачи появилось заново' "$tmp/c.err") - n0))"
[ -n "${NETRESTART_KEEP:-}" ] && cp "$tmp/c.err" "$NETRESTART_KEEP.c"
kill "$D" 2>/dev/null
wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1

echo "netrestart: $pass ok, $fail fail"
[ "$fail" = 0 ]
