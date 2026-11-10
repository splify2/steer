#!/bin/sh
# Дампы nftables по netlink (src/lib/nftdump.c): длинные имена и длинные ключи — в своём сетевом
# пространстве, против настоящего nft.
#
# Раньше имена таблицы, цепочки и набора читались в буфер на 64 байта, а ключ элемента — на 16:
# имя длиннее совпадало с чужим по обрезанному началу или не совпадало вовсе, ключ из нескольких
# полей (адрес IPv6 . порт — 20 байт) терял хвост, и сверка судила по неполным данным (I-525).
# Ядро допускает имя до 255 байт и значение до 64.
# Нужны nft и unshare (root: unshare -n; не root: unshare -Urn); без них — пропуск.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="${NFTDUMP_TOOL:-$ROOT/build/nftdump-tool}"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
skip() { echo "nftdumpmatch: $1 — пропуск"; exit 0; }
if [ ! -x "$TOOL" ]; then
    (cd "$ROOT" && cc $(make -s print-inc) -O2 -Wall -Wextra -o "$TOOL" tests/nftdump-tool.c \
        src/lib/nftdump.c) || { echo "nftdumpmatch: инструмент не собрался"; exit 1; }
fi
# Отпечаток таблицы не зависит от атрибутов, которых ядро steer не задаёт (без ядра, на сообщениях):
# число элементов набора (ядро 6.15), имя его устройства, атрибут, которого сегодня нет.
if [ "${NFTDUMP_INNER:-}" != 1 ]; then
    check "свёртка набора: чужие атрибуты 19, 20, 21 в неё не входят" "ok" "$("$TOOL" fpunit 2>&1)"
    [ "$fail" = 0 ] || { echo "nftdumpmatch: $pass passed, $fail failed"; exit 1; }
fi
skip() { echo "nftdumpmatch: $1 — часть с ядром пропущена"; echo "nftdumpmatch: $pass passed, $fail failed"; exit 0; }
command -v nft >/dev/null 2>&1 || skip "nft нет"
if [ "${NFTDUMP_INNER:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ]; then ns="unshare -n"; else ns="unshare -Urn"; fi
    $ns true 2>/dev/null || skip "unshare недоступен"
    NFTDUMP_INNER=1 PASS0="$pass" exec $ns sh "$0" "$@"
fi
pass="${PASS0:-0}"
nft add table inet nftdump_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet nftdump_probe

# 100 и 200 знаков: за прежним пределом в 63 и за серединой настоящего в 255.
pad() { printf '%s' "$1"; i=0; while [ $i -lt $2 ]; do printf x; i=$((i + 1)); done; }
T="$(pad table_ 100)"
C="$(pad chain_ 100)"
C2="$(pad chain_ 70)"          # общее начало с C в 63 знака: обрезка слила бы их
S="$(pad set_ 200)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/t.nft" <<EOF
table inet $T {
  set $S { type ipv6_addr . inet_service; elements = { 2001:db8::1 . 80, 2001:db8::2 . 443 }; }
  chain $C { counter comment "a"; counter comment "b"; }
  chain $C2 { counter comment "c"; }
}
EOF
nft -f "$tmp/t.nft" || { echo "nftdumpmatch: таблица не встала"; exit 1; }
X() { "$TOOL" "$@"; }

check "цепочка с именем в 105 знаков есть" "1" "$(X chain "$T" "$C")"
check "цепочки с общим началом различаются" "1" "$(X chain "$T" "$C2")"
check "несуществующая цепочка с тем же началом — нет" "0" "$(X chain "$T" "$(pad chain_ 100)y")"
check "правила цепочки с длинным именем: два" "2" "$(X rules "$T" "$C")"
check "правила её соседки с общим началом: одно" "1" "$(X rules "$T" "$C2")"
check "имя набора в 204 знака читается целиком" "$S" "$(X sets "$T")"
check "элементы набора: два, ключ 20 байт (адрес . порт)" "2 20" "$(X elems "$T" "$S")"

# Отпечаток на настоящем ядре: элемент, положенный в набор или снятый из него (так делает
# резолвер), отпечатка не меняет — на ядре 6.15+ менял (число элементов в заголовке набора), и
# сторож заменял таблицу на каждый элемент; новое правило — меняет.
cat > "$tmp/f.nft" <<EOF
table inet fpt {
  set dyn { type ipv4_addr; flags timeout; }
  set st { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 } }
  chain c { ip daddr @dyn counter; }
}
EOF
nft -f "$tmp/f.nft" || { echo "nftdumpmatch: таблица отпечатка не встала"; exit 1; }
f0="$(X fp fpt)"
nft add element inet fpt dyn '{ 192.0.2.1 timeout 1h, 192.0.2.2 }'
nft add element inet fpt st '{ 172.16.0.0/12 }'
f1="$(X fp fpt)"
check "отпечаток снят" "16" "$(printf '%s' "$f0" | wc -c | tr -d ' ')"
check "элементы наборов отпечатка не меняют (ядро $(uname -r))" "$f0" "$f1"
nft delete element inet fpt dyn '{ 192.0.2.1 }'
check "снятый элемент — тоже" "$f0" "$(X fp fpt)"
nft add rule inet fpt c ip daddr 198.51.100.1 drop
check "новое правило отпечаток меняет" "yes" "$([ "$(X fp fpt)" != "$f0" ] && echo yes || echo no)"

echo "nftdumpmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
