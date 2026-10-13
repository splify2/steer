#!/bin/sh
# Канал с наборами sing-box (`srs_files`) в генераторе: текст набора правил.
#
# Отдельно от tests/gen.sh нарочно: тот входит в снимок генератора (tests/snapshot.sh), и новые
# спеки в нём сдвинули бы номера снимков. Здесь — только каналы с `.srs`.
#
# Главная проверка — РАВЕНСТВО: канал, читающий набор сам, даёт ровно тот же текст, что канал,
# которому набор разложили руками (`srs-read` в файлы плюс proto/ports). Где сужение у набора
# смешанное, ручной эквивалент — по каналу на вариант сужения (так ядро без составных наборов и
# получает канал: STEER_NFT_CONCAT=0); с составным набором — элементы и правило проверяются
# текстом. Плюс отказы, предупреждения, доп. условия набора, телефон и старая раскладка.
#
# Сети и ядра не нужно: только `apply --dry-run`. Ядро — tests/srsnft.sh.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
FIX="$(pwd)/tests/srs"
pass=0 fail=0
tmp="$(mktemp -d /tmp/srsgen.XXXXXX)"
trap '[ -n "${KEEP:-}" ] || rm -rf "$tmp"' EXIT INT TERM
STEER_NFT_COMPAT=modern; export STEER_NFT_COMPAT

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
has() { printf '%s' "$1" | grep -qF -- "$2" && echo yes || echo no; }

# Спека: вывод apply --dry-run в $tmp/<имя>.nft, stderr — в .err, код — в $rc.
run() {
    name="$1"; shift
    sed "s|FIX|$FIX|g; s|TMP|$tmp|g" > "$tmp/$name.yaml"
    "$@" "$BIN" apply --dry-run --spec "$tmp/$name.yaml" --state-dir "$tmp/st-$name" \
        > "$tmp/$name.nft" 2> "$tmp/$name.err"
    rc=$?
}
cmp_nft() { diff "$tmp/$1.nft" "$tmp/$2.nft" > "$tmp/$1-$2.diff" 2>&1 && echo same || { head -20 "$tmp/$1-$2.diff"; echo differ; }; }

# ---- 1. telegram: имена и подсети в одном наборе --------------------------------------------
"$BIN" srs-read "$FIX/telegram.srs" --out "$tmp/tg.dom" --prefixes-out "$tmp/tg.pfx" 2>/dev/null
run tg_srs env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  tg: { srs: [FIX/telegram.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: tg, to: [tg], out: vpn }
EOF
check "telegram: принят" 0 "$rc"
run tg_lst env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  tg: { prefixes_file: [TMP/tg.pfx], domains_file: [TMP/tg.dom] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: tg, to: [tg], out: vpn }
EOF
check "telegram: тот же набор правил, что с разложенными списками" same "$(cmp_nft tg_srs tg_lst)"
check "telegram: без предупреждений" "" "$(cat "$tmp/tg_srs.err")"

# ---- 2. youtube: одни имена ------------------------------------------------------------------
"$BIN" srs-read "$FIX/youtube.srs" --out "$tmp/yt.dom" 2>/dev/null
run yt_srs env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  yt: { srs: [FIX/youtube.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: yt, to: [yt], out: vpn }
EOF
run yt_lst env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  yt: { domains_file: [TMP/yt.dom] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: yt, to: [yt], out: vpn }
EOF
check "youtube: тот же набор правил" same "$(cmp_nft yt_srs yt_lst)"

# ---- 3. одно сужение у всего набора — обычная группа с сужением -----------------------------
printf '198.51.100.0/24\n192.0.2.0/24\n' > "$tmp/uni.pfx"
run uni_srs env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  voice: { srs: [FIX/uniform.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: voice, to: [voice], out: vpn }
EOF
check "одно сужение: принят (сужение из набора, не из спеки)" 0 "$rc"
run uni_lst env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  voice: { prefixes_file: [TMP/uni.pfx], proto: udp, ports: [50000-65535] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: voice, to: [voice], out: vpn }
EOF
check "одно сужение: тот же текст, что канал с proto/ports" same "$(cmp_nft uni_srs uni_lst)"
check "… и правило с сужением" yes "$(has "$(cat "$tmp/uni_srs.nft")" 'meta l4proto udp th dport 50000-65535 ip daddr @vpn_ip_c0_p1')"

# ---- 4. смешанное сужение без составных наборов — по группе на вариант ----------------------
printf 'mixed.example\n' > "$tmp/mx.dom"
printf '198.51.100.0/24\n203.0.113.0/25\n' > "$tmp/mx1.pfx"
printf '192.0.2.0/24\n' > "$tmp/mx2.pfx"
printf '198.51.100.128/25\n' > "$tmp/mx0.pfx"
run mx_split env STEER_NFT_CONCAT=0 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  mixed: { srs: [FIX/mixed.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: mixed, to: [mixed], out: vpn }
EOF
check "смешанное, деление: принят" 0 "$rc"
run mx_manual env STEER_NFT_CONCAT=0 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  m-dom: { domains_file: [TMP/mx.dom] }
  m-v1:  { prefixes_file: [TMP/mx1.pfx], proto: udp, ports: [50000-65535] }
  m-v2:  { prefixes_file: [TMP/mx2.pfx], proto: udp, ports: [19000-20000] }
  m-all: { prefixes_file: [TMP/mx0.pfx] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: m-dom, to: [m-dom], out: vpn }
  - { name: m-v1, to: [m-v1], out: vpn }
  - { name: m-v2, to: [m-v2], out: vpn }
  - { name: m-all, to: [m-all], out: vpn }
EOF
check "смешанное, деление: тот же текст, что каналы по вариантам сужения" same "$(cmp_nft mx_split mx_manual)"

# ---- 5. смешанное сужение, составной набор ---------------------------------------------------
run mx_comp env STEER_NFT_CONCAT=1 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  mixed: { srs: [FIX/mixed.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: mixed, to: [mixed], out: vpn }
EOF
T="$(cat "$tmp/mx_comp.nft")"
check "составной: принят" 0 "$rc"
check "один набор на канал — составной" yes "$(has "$T" 'type ipv4_addr . inet_proto . inet_service')"
check "… interval,timeout (имена кладёт резолвер)" yes "$(has "$T" 'set vpn_dom_c0_m {
        type ipv4_addr . inet_proto . inet_service
        flags interval,timeout')"
# Пересечение 198.51.100.0/24 (udp 50000-65535) и 198.51.100.128/25 (без сужения) разложено
# без пересечений: ядро составной набор с пересекающимися элементами не принимает.
check "элементы — без пересечений, у каждого своё сужение" yes "$(has "$T" 'elements = { 192.0.2.0/24 . 17 . 19000-20000, 198.51.100.0/25 . 17 . 50000-65535, 198.51.100.128/25 . 0-255 . 0-65535, 203.0.113.0/25 . 17 . 50000-65535 }')"
check "правило одно: адрес . протокол . порт" yes "$(has "$T" 'ip saddr { 192.168.1.0/24 } ip daddr . meta l4proto . th dport @vpn_dom_c0_m meta mark set')"
check "встречный путь — тем же ключом" yes "$(has "$T" 'ip saddr . meta l4proto . th sport @vpn_dom_c0_m counter comment "steer-down:vpn_dom_c0_m"')"
check "правил у канала одно" 1 "$(grep 'comment "steer:' "$tmp/mx_comp.nft" | grep -vc 'ip6 ')"
# Выход с IPv6: у составного доменного набора — пара IPv6 тем же ключом, и её наполняет резолвер
# (fake-IP v6), поэтому с timeout; правило — v6-двойник тем же ключом.
check "… пара IPv6 составного набора — с timeout" yes "$(has "$T" 'set vpn_dom_c0_m6 {
        type ipv6_addr . inet_proto . inet_service
        flags interval,timeout')"
check "… и v6-двойник тем же ключом" 1 \
    "$(grep 'comment "steer:' "$tmp/mx_comp.nft" | grep -c 'ip6 daddr . meta l4proto . th dport @vpn_dom_c0_m6')"
check "отдельного x_l4 у правила нет" no "$(has "$T" 'meta l4proto udp')"

# Свои списки канала рядом с набором — в тот же составной набор, со сужением канала (нет —
# 0-255 × 0-65535), и пересечение с подсетями набора снова разложено.
printf '198.51.100.0/24\n' > "$tmp/own.pfx"
run mx_own env STEER_NFT_CONCAT=1 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  mixed: { srs: [FIX/mixed.srs], prefixes_file: [TMP/own.pfx] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: mixed, to: [mixed], out: vpn }
EOF
check "свои списки + набор: адреса своего списка без сужения накрывают подсеть набора" yes \
    "$(has "$(cat "$tmp/mx_own.nft")" '192.0.2.0/24 . 17 . 19000-20000, 198.51.100.0/24 . 0-255 . 0-65535, 203.0.113.0/25 . 17 . 50000-65535')"

# discord.srs — тот же случай на настоящем файле издателя.
run dc env STEER_NFT_CONCAT=1 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  discord: { srs: [FIX/discord.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: discord, to: [discord], out: vpn }
EOF
check "discord: 104.16.0.0/12 — два сужения у одного адреса, двумя ящиками" yes \
    "$(has "$(cat "$tmp/dc.nft")" '104.16.0.0/12 . 17 . 19000-20000, 104.16.0.0/12 . 17 . 50000-65535')"

# ---- 6. сужение канала против сужения набора -------------------------------------------------
run conflict env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  discord: { srs: [FIX/discord.srs], proto: tcp }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: discord, to: [discord], out: vpn }
EOF
check "канал tcp + набор udp: отказ кодом 2" 2 "$rc"
check "… и сказано, что не пересекаются и что убрать" yes "$(has "$(cat "$tmp/conflict.err")" 'не пересекаются')"
run agree env STEER_NFT_CONCAT=0 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  discord: { srs: [FIX/discord.srs], proto: udp }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: discord, to: [discord], out: vpn }
EOF
check "канал udp + набор udp: принят" 0 "$rc"
check "… имена получили сужение канала" yes "$(has "$(cat "$tmp/agree.nft")" 'meta l4proto udp ip daddr @vpn_dom_c0_p1')"

# ---- 7. доп. условия набора: клиент, исключения, приложения ---------------------------------
run logic env STEER_NFT_CONCAT=1 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  logic: { srs: [FIX/logic.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: logic, to: [logic], out: vpn }
EOF
L="$(cat "$tmp/logic.nft")"; E="$(cat "$tmp/logic.err")"
check "логика: принят" 0 "$rc"
check "source_ip_cidr — вторым ip saddr в правиле доп. группы" yes "$(has "$L" 'ip saddr { 192.168.1.0/24 } ip saddr { 192.168.1.0/28 } ip daddr @vpn_ip_c0_e1')"
check "исключения-подсети — свой набор" yes "$(has "$L" 'set vpn_ip_c0_e2_x {')"
check "… с элементом исключения" yes "$(has "$L" 'elements = { 10.10.1.0/24 }')"
check "… и проверка перед поиском" yes "$(has "$L" 'ip daddr != @vpn_ip_c0_e2_x ip daddr @vpn_ip_c0_e2')"
check "приложения на роутере — предупреждение" yes "$(has "$E" 'правила про приложения сняты')"
check "снятые правила набора названы" yes "$(has "$E" 'снято правил: 4')"
check "предупреждения с уровнем steer[warn]" 0 "$(grep -vc '^steer\[warn\]' "$tmp/logic.err")"

# ---- 8. IPv6 и пропавший файл ----------------------------------------------------------------
run v6 env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  v6: { srs: [FIX/v6.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: v6, to: [v6], out: vpn }
EOF
check "IPv6 в наборе: принят" 0 "$rc"
# С 1.9 подсети IPv6 набора — в парный набор группы, у правила — v6-двойник (docs/architecture.md, «4б»).
check "… IPv6 не пропущены" no "$(has "$(cat "$tmp/v6.err")" 'IPv6')"
check "… v4 на месте" yes "$(has "$(cat "$tmp/v6.nft")" 'elements = { 198.51.100.0/24 }')"
check "… v6 — в парном наборе" yes "$(has "$(cat "$tmp/v6.nft")" 'elements = { 2001:db8::/32, 2001:db9::1/128 }')"
check "… и v6-двойник правила" yes "$(has "$(cat "$tmp/v6.nft")" 'iifname "br-lan" ip6 daddr @vpn_ip6')"
run gone env <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  gone: { srs: [TMP/nope.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: gone, to: [gone], out: vpn }
EOF
check "набора нет: apply не отказывает" 0 "$rc"
check "… говорит о нём" yes "$(has "$(cat "$tmp/gone.err")" 'nope.srs')"
check "… и правило остаётся с пустым набором, а не «весь трафик»" yes "$(has "$(cat "$tmp/gone.nft")" 'ip daddr @vpn_ip')"

# ---- 9. телефон: package_name → UID приложения -----------------------------------------------
printf 'org.telegram.messenger 10123 0 /data/user/0/org.telegram.messenger default:targetSdkVersion=34 3003\ncom.example.app 10200 0 /data/x default 3003\n' > "$tmp/packages.list"
run phone env STEER_PLATFORM=android STEER_PACKAGES_LIST="$tmp/packages.list" STEER_NFT_CONCAT=1 <<EOF
version: 2

clients:
  me: { self: true }

lists:
  tg: { srs: [FIX/logic.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: tg, for: [me], to: [tg], out: vpn }
EOF
P="$(cat "$tmp/phone.nft")"
check "телефон: принят" 0 "$rc"
check "приложение набора — UID в правиле" yes "$(has "$P" 'meta skuid 10123 ct direction original ip daddr @vpn_ip_c0_e')"
check "«весь трафик приложения» — правило без набора" yes "$(has "$P" 'meta skuid 10200 ct direction original meta nfproto ipv4 ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } meta mark set')"
check "… и набора у него нет" no "$(has "$P" 'set vpn_all_c0_e')"
check "клиенты (source_ip_cidr) у канала на телефон сняты" yes "$(has "$(cat "$tmp/phone.err")" 'source_ip_cidr) сняты')"

# ---- 10. старая раскладка ядра ---------------------------------------------------------------
run legacy env STEER_NFT_COMPAT=legacy-min <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  mixed: { srs: [FIX/mixed.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: mixed, to: [mixed], out: vpn }
EOF
G="$(cat "$tmp/legacy.nft")"
check "старое ядро: принят" 0 "$rc"
check "… составного набора нет" no "$(has "$G" 'inet_proto')"
check "… деление по сужению" yes "$(has "$G" 'meta l4proto udp th dport 19000-20000 ip daddr @vpn_ip_c0_p2')"
check "… подсети набора — в статической половине доменного набора" yes "$(has "$G" 'set vpn_dom_n {')"

# ---- 11. таблица резолвера: выбор клауз и сужение -------------------------------------------
# Семейство «46»: у спеки v2 имена правил отвечают обоими семействами (docs/spec-v2.md, dns.mode).
tab="$(STEER_NFT_CONCAT=1 "$BIN" dnsd-table --spec "$tmp/mx_comp.yaml" 2>/dev/null)"
check "таблица резолвера: составной набор — клаузы с сужением" yes "$(has "$tab" "vpn_dom_c0_m|vpn|0|46|mixed|srs:0=-:$FIX/mixed.srs")"
tab="$(STEER_NFT_CONCAT=1 "$BIN" dnsd-table --spec "$tmp/mx_own.yaml" 2>/dev/null)"
check "… свои списки канала — с его сужением (cl:)" yes "$(has "$tab" "cl:-:$tmp/own.pfx")"
tab="$("$BIN" dnsd-table --spec "$tmp/tg_srs.yaml" 2>/dev/null)"
check "обычный набор — номера клауз имён" yes "$(has "$tab" "vpn_dom|vpn|0|46|tg|srs:0:$FIX/telegram.srs")"

# ---- 12. большой список со смешанным сужением — деление вместо составного набора -------------
if command -v python3 >/dev/null 2>&1; then
    cat > "$tmp/big.py" <<'PY'
import json, sys
r = [{"ip_cidr": ["10.%d.%d.%d/32" % (i >> 16 & 255, i >> 8 & 255, i & 255) for i in range(0, 34000, 2)]},
     {"network": ["udp"], "ip_cidr": ["192.0.2.0/24"], "port_range": ["50000:65535"]}]
json.dump({"rules": r}, open(sys.argv[1], "w"))
PY
    python3 "$tmp/big.py" "$tmp/big.json"
    python3 "$FIX/mksrs.py" "$tmp/big.json" "$tmp/big.srs"
    run big env STEER_NFT_CONCAT=1 <<EOF
version: 2

lan: { devices: [br-lan], addr: [192.168.1.0/24] }

lists:
  big: { srs: [TMP/big.srs] }

outputs:
  vpn: { kind: interface, device: wg0 }

rules:
  - { name: big, to: [big], out: vpn }
EOF
    check "большой смешанный список: принят" 0 "$rc"
    check "… составного набора нет" no "$(has "$(cat "$tmp/big.nft")" 'inet_proto')"
    check "… и сказано почему" yes "$(has "$(cat "$tmp/big.err")" 'элементов 17001 (больше 16384)')"
fi

printf '\nsrsgen: %d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\n'
