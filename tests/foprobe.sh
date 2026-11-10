#!/bin/sh
# Проба ICMP сторожа (src/daemon/foprobe.c) на настоящих сокетах: потери и задержки эхо-ответов.
#
# Что было. Проба слала ОДИН эхо-запрос на цель и ждала ответа 3 с: одна потерянная датаграмма
# делала цель мёртвой, две (1.1.1.1 и 8.8.8.8) — устройство, и сторож перезапускал туннель, через
# который шёл трафик. Теперь запросов к цели до трёх за тот же срок (через треть срока, пока цель
# молчит), и годится ответ на любой из них.
#
# Сеть: прибор в пространстве P (pa, 10.66.0.1), цель 1.1.1.1 — на lo пространства T за pb.
# Проверяется (foprobematch — та же foprobe_icmp, что зовёт проход):
#  1. путь чист — проба отвечает и с одним запросом, и с тремя;
#  2. у цели пропадают первые два запроса — один запрос: отказ (прежнее поведение), три: ответ;
#  3. ответ приходит через 1,5 с — позже второго запроса: годится ответ на первый (номер не
#     последнего запроса), проба отвечает за ≈1,5 с;
#  4. цель молчит вовсе — отказ ровно по сроку (3 с), не дольше: срок прохода от числа запросов
#     не вырос.
# Нужны root, ip netns, nft и tc (netem). Чего-то нет — стенд пропускается вслух.
set -u
BIN="${BUILD:-./build}/foprobematch"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
skip() { echo "foprobe: пропущен — $1"; exit 0; }
[ "$(id -u)" = 0 ] || skip "нужен root"
for t in ip nft tc; do command -v "$t" >/dev/null 2>&1 || skip "нет $t"; done

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1))
    else fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"; fi
}
P="fop-p-$$" T="fop-t-$$"
cleanup() { ip netns del "$P" 2>/dev/null; ip netns del "$T" 2>/dev/null; }
trap cleanup EXIT
ip netns add "$P" && ip netns add "$T" || skip "ip netns add не вышел"
ip link add pa netns "$P" type veth peer name pb netns "$T" || skip "veth не создаётся"
ip -n "$P" link set lo up; ip -n "$T" link set lo up
ip -n "$P" addr add 10.66.0.1/24 dev pa; ip -n "$P" link set pa up
ip -n "$T" addr add 10.66.0.2/24 dev pb; ip -n "$T" link set pb up
ip -n "$T" addr add 1.1.1.1/32 dev lo
ip -n "$P" route add default via 10.66.0.2 dev pa
# Предел ICMP у ядра цели (icmp_ratelimit) эхо-ответов не касается, но стенд шлёт подряд — снять.
ip netns exec "$T" sysctl -qw net.ipv4.icmp_ratelimit=0 2>/dev/null
ip netns exec "$T" nft add table ip t
ip netns exec "$T" nft add chain ip t in '{ type filter hook input priority 0; policy accept; }'

probe() { ip netns exec "$P" "$BIN" pa 10.66.0.1 1.1.1.1 3000 "$1"; }
verdict() { probe "$1" | cut -d' ' -f1; }
ms() { probe "$1" | cut -d' ' -f2; }

# 1. Путь чист.
check "чистый путь, один запрос — ответ" "ok" "$(verdict 1)"
check "чистый путь, три запроса — ответ" "ok" "$(verdict 3)"

# 2. Первые два запроса пропадают: квота правила — два запроса по 84 байта, дальше правило не
#    совпадает, и запросы доходят. Правило ставится заново перед каждой пробой — квота с нуля.
ip netns exec "$T" nft flush chain ip t in
ip netns exec "$T" nft add rule ip t in icmp type echo-request quota until 168 bytes drop
check "первые два запроса пропали, один запрос — отказ (как прежде)" "fail" "$(verdict 1)"
ip netns exec "$T" nft flush chain ip t in
ip netns exec "$T" nft add rule ip t in icmp type echo-request quota until 168 bytes drop
check "первые два запроса пропали, три запроса — ответ" "ok" "$(verdict 3)"

# 3. Ответ через 1,5 с — после второго запроса. Годен ответ на первый.
ip netns exec "$T" nft flush chain ip t in
ip netns exec "$T" tc qdisc add dev pb root netem delay 1500ms
r="$(probe 3)"
check "ответ позже повтора — годится ответ на первый запрос" "ok" "${r%% *}"
t="${r#* }"
check "  проба ответила за ≈1,5 с (1400–2400 мс), а не по последнему запросу" "1" \
    "$([ "$t" -ge 1400 ] && [ "$t" -le 2400 ] && echo 1 || echo 0)"
ip netns exec "$T" tc qdisc del dev pb root

# 4. Цель молчит — отказ по сроку, не дольше.
ip netns exec "$T" nft add rule ip t in icmp type echo-request drop
r="$(probe 3)"
check "цель молчит — отказ" "fail" "${r%% *}"
t="${r#* }"
check "  отказ по сроку 3 с (2900–3500 мс)" "1" \
    "$([ "$t" -ge 2900 ] && [ "$t" -le 3500 ] && echo 1 || echo 0)"
ip netns exec "$T" nft add table ip cnt
ip netns exec "$T" nft add chain ip cnt c '{ type filter hook prerouting priority -300; policy accept; }'
ip netns exec "$T" nft add rule ip cnt c icmp type echo-request counter
probe 3 >/dev/null
check "  запросов к молчащей цели — три" "3" \
    "$(ip netns exec "$T" nft list chain ip cnt c | sed -n 's/.*counter packets \([0-9]*\).*/\1/p')"

echo "foprobe: $pass passed, $fail failed"
[ "$fail" = 0 ]
