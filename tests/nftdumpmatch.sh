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
command -v nft >/dev/null 2>&1 || skip "nft нет"
if [ "${NFTDUMP_INNER:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ]; then ns="unshare -n"; else ns="unshare -Urn"; fi
    $ns true 2>/dev/null || skip "unshare недоступен"
    NFTDUMP_INNER=1 exec $ns sh "$0" "$@"
fi
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

echo "nftdumpmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
