#!/bin/sh
# Сборка под Android (-DSTEER_DEFAULT_PLATFORM=android — умолчание выбора платформы при запуске):
# поле метки, пути по умолчанию и раскладка правил.
#
# Проверяется то, что сборка меняет, и ничего сверх: остальное у неё общее с роутерной и
# проверено её стендами. Раскладка правил одна (раскладку для Linux 4.9 убрали, I-541).
#
# Что проверяется.
#  1. Поле метки — биты 22-27: маска 0x0fc00000, запись `mark and 0xf03fffff`, и ни одного
#     следа роутерного поля 0x0ff00000 — в бит 20 и 21 пишет netd.
#  2. Пути по умолчанию — /data/misc/steer: /etc и /var на телефоне только для чтения.
#  5. Каналы на сам телефон (from: self / uid:N): правило на output, отказы разбора.
#  4. zapret на телефоне нет: бит пропуска zapret (0x40000000, в битах vendor netd) не ставится,
#     цепочки failopen, которая существует ради него, нет, а kind/on_fail zapret — отказ спеки.
# Что выбор платформы при запуске даёт то же самое, что сборка под Android, — tests/platmatch.sh
# (он гоняет этот стенд целиком через сверяющую обёртку).
set -u
BIN="${ANDROID:-./build/steer-android}"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

printf '203.0.113.0/24\n' > "$tmp/a.lst"
printf 'example.com\n' > "$tmp/d.lst"
cat > "$tmp/spec.json" <<EOF2
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "direct": { "kind": "direct" },
               "vpn": { "kind": "interface", "device": "wg0", "on_fail": "direct" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" },
                { "name": "d", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" } ] }
EOF2
S="--spec $tmp/spec.json --state-dir $tmp/state"

out="$("$BIN" apply --dry-run $S 2>/dev/null)"
check "современная раскладка собирается" "0" "$?"
# Правило IPv4 одно; второе — его v6-двойник (доменная группа выхода с IPv6 получает пару IPv6,
# fake-IP v6), с той же меткой.
check "метка пишется в биты 22-27, без бита zapret" "1" \
    "$(printf '%s\n' "$out" | grep 'meta mark set mark and 0xf03fffff or 0x00400000' | grep -vc 'ip6 daddr')"
check "  и у v6-двойника — та же" "1" \
    "$(printf '%s\n' "$out" | grep 'meta mark set mark and 0xf03fffff or 0x00400000' | grep -c 'ip6 daddr')"
check "бита zapret 0x40000000 нет нигде" "0" "$(printf '%s\n' "$out" | grep -ci '0x4[0-9a-f]\{7\}')"
# Цепочки снятия бита zapret нет (бита нет); набор failopen есть — его читает postrouting_guard
# (выход с on_fail=direct, упав, законно уходит в сеть телефона мимо своего устройства).
check "цепочки prerouting_failopen нет" "0" "$(printf '%s\n' "$out" | grep -c 'prerouting_failopen')"
check "  набор failopen есть, и guard его пропускает" "1 1" \
    "$(printf '%s\n' "$out" | grep -c 'set failopen {') $(printf '%s\n' "$out" | grep -c 'meta mark and 0x0fc00000 @failopen return')"
check "роутерного поля нет нигде" "0" "$(printf '%s\n' "$out" | grep -c '0x0ff00000\|0xf00fffff')"

help="$("$BIN" help apply 2>&1)"
check "спека по умолчанию — /data/misc/steer/spec.json" "1" \
    "$(printf '%s\n' "$help" | grep -c '/data/misc/steer/spec.json')"
check "состояние по умолчанию — /data/misc/steer/state" "1" \
    "$(printf '%s\n' "$help" | grep -c '/data/misc/steer/state')"
check "и ни слова про /etc/steer" "0" "$(printf '%s\n' "$help" | grep -c '/etc/steer')"

sed 's/"kind": "direct" }/"kind": "zapret" }/' "$tmp/spec.json" > "$tmp/z.json"
"$BIN" apply --dry-run --spec "$tmp/z.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/z.err"
check "kind zapret — отказ спеки" "2" "$?"
check "  и причина названа" "1" "$(grep -c 'recheck' "$tmp/z.err")"
sed 's/"on_fail": "direct"/"on_fail": "zapret"/' "$tmp/spec.json" > "$tmp/zf.json"
"$BIN" apply --dry-run --spec "$tmp/zf.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/zf.err"
check "on_fail zapret — отказ спеки" "2" "$?"

# Каналы на сам телефон (from: self / uid:N) — разбор спеки. Поведение в ядре проверяет
# tests/local49.sh на стенде vm49; здесь — что генератор ставит их на output, а спека
# отвергает то, чего быть не может.
cat > "$tmp/local.json" <<EOF2
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "a", "from": ["uid:10123"], "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF2
lo="$("$BIN" apply --dry-run --spec "$tmp/local.json" --state-dir "$tmp/state" 2>/dev/null)"
check "канал по UID: правило на output со skuid" "1" \
    "$(printf '%s\n' "$lo" | grep -c 'meta skuid 10123 ct direction original ip daddr @vpn_ip_c0 meta mark set')"
check "канал по UID: на prerouting его нет" "0" \
    "$(printf '%s\n' "$lo" | sed -n '/chain prerouting_mark/,/}/p' | grep -c skuid)"
bad() {   # bad ИМЯ FROM ТЕКСТ — спека с таким «кому» отвергается кодом 2 и называет причину
    sed "s|\"from\": \[\"uid:10123\"\]|\"from\": $2|" "$tmp/local.json" > "$tmp/bad.json"
    "$BIN" apply --dry-run --spec "$tmp/bad.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/bad.err"
    check "$1" "2" "$?"
    check "  причина: $3" "1" "$(grep -c "$3" "$tmp/bad.err")"
}
bad "смешаны телефон и клиенты — отказ" '["self", "192.168.43.5"]' 'смешаны сам телефон и клиенты'
bad "self вместе с uid — отказ" '["self", "uid:10123"]' 'уже включает все приложения'
bad "uid:0 (root) — отказ" '["uid:0"]' 'это root'
bad "не UID — отказ" '["uid:abc"]' 'не UID приложения'
bad "обратный диапазон — отказ" '["uid:10200-10100"]' 'не UID приложения'

# Вид правил на output. Спека с «self» + весь трафик и сужением, с приложениями списком и
# диапазоном, с доменным каналом телефона.
cat > "$tmp/loc2.json" <<EOF2
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "s", "from": ["self"], "match": { "any": true, "allow_all": true, "proto": "udp", "ports": ["50000-65535"] }, "out": "vpn" },
    { "name": "u", "from": ["uid:10123", "uid:1010200-1010300"], "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" },
    { "name": "d", "from": ["uid:10124"], "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" } ] }
EOF2
m2="$("$BIN" apply --dry-run --spec "$tmp/loc2.json" --state-dir "$tmp/state" 2>/dev/null)"
c() { printf '%s\n' "$1" | grep -c -- "$2"; }
check "self — приложения (UID от 10000), только исходящие соединения" "2" \
    "$(c "$m2" 'meta skuid >= 10000 ct direction original')"
check "приложения списком и диапазоном — в фигурных скобках" "1" \
    "$(c "$m2" 'meta skuid { 10123, 1010200-1010300 } ct direction original')"
check "современная раскладка: output_mark — цепочка route прямо в inet" "1" \
    "$(c "$m2" 'type route hook output priority mangle + 1')"
# Выход interface несёт IPv6 (1.9): IPv6 «весь трафик» не отвергается, а уводится двойником — с
# тем же сужением и мимо своей сети.
check "IPv6 «весь трафик» — двойник в выход с IPv6, с тем же сужением, мимо своей сети" "1" \
    "$(c "$m2" 'meta nfproto ipv6 meta l4proto udp th dport 50000-65535 oifname != "lo" ip6 daddr != { ::1, fe80::/10, fc00::/7, ff00::/8 } meta mark set')"
check "  отказа IPv6 у выхода с IPv6 нет" "0" "$(c "$m2" 'counter reject')"
check "«весь трафик» — не в свою сеть (RFC 1918, link-local, мультикаст)" "1" \
    "$(c "$m2" 'meta nfproto ipv4 ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }')"
# Метка пакета — в метку соединения (ct mark set mark): по ней резолвер переспрашивает с меткой
# сети исходного запроса. Оба семейства: одно правило в inet без nfproto.
dnsrule='meta mark and 0x0fc00000 != 0x0fc00000 udp dport 53 ct mark set mark counter redirect to :5300'
check "DNS телефона — все, кроме запроса самого резолвера (метка движка), оба семейства" "1" \
    "$(c "$m2" "$dnsrule")"
check "  без ограничения семейством" "0" "$(c "$m2" "nfproto ipv4 $dnsrule")"
# TCP/53 — рядом с UDP/53, тем же правилом (метка движка, ct mark set mark, оба семейства).
tcprule='meta mark and 0x0fc00000 != 0x0fc00000 tcp dport 53 ct mark set mark counter redirect to :5300'
check "DNS телефона по TCP/53 — рядом с UDP, с тем же исключением метки движка" "1" \
    "$(c "$m2" "$tcprule")"
# Раздача: TCP/53 заворачивается рядом с UDP/53.
check "раздача: TCP/53 к резолверу" "1" \
    "$(c "$m2" 'iifname "rndis0" tcp dport 53 counter redirect to :5300')"
check "раздача: TCP/53 стоит сразу за UDP/53" "1" \
    "$(printf '%s\n' "$m2" | grep -A1 'iifname "rndis0" udp dport 53' | grep -c 'tcp dport 53')"
check "поддельные адреса для соединений телефона переводятся на output" "1" \
    "$(c "$m2" 'ip daddr 198.18.0.0/15 counter dnat ip to ip daddr map @fakeip comment "steer-fakeip-local"')"
check "  и поддельные IPv6 — картой fakeip6" "1" \
    "$(c "$m2" 'ip6 daddr fdfe:dcba:9876::/96 counter dnat ip6 to ip6 daddr map @fakeip6 comment "steer-fakeip-local"')"
check "masquerade — не в nft (его ставит iptables при apply)" "0" "$(c "$m2" 'masquerade')"

spec_bad() {   # spec_bad ИМЯ ТЕКСТ — спека из stdin отвергается и называет причину
    cat > "$tmp/sb.json"
    "$BIN" apply --dry-run --spec "$tmp/sb.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/sb.err"
    check "$1" "2" "$?"
    check "  причина: $2" "1" "$(grep -c "$2" "$tmp/sb.err")"
}
spec_bad "канал телефона с выходом tgws — отказ" 'только для клиентов раздачи' <<EOF2
{ "schema": 2, "outputs": { "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [ { "name": "t", "from": ["uid:10123"], "match": { "prefixes_file": "$tmp/a.lst" }, "out": "tg" } ] }
EOF2
spec_bad "self в from_default — отказ, даже если у каналов свой from" 'сам телефон, а не клиенты' <<EOF2
{ "schema": 2, "from_default": ["self"], "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "a", "from": ["uid:10123"], "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF2
spec_bad "диапазон UID в правиле на устройство — отказ" 'одно приложение' <<EOF2
{ "schema": 2, "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "a", "scope": "device", "from": ["uid:10100-10200"], "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF2
# Туннель через via: его сокет несёт метку цели плюс бит «собственный трафик туннеля»
# (STEER_TUNNEL_BIT, 0x10000000), и заворот DNS приложений обязан его пропускать — иначе туннель
# с сервером на 53-м порту (UDP или TCP) уходил бы к нашему резолверу и не вставал. Условие
# пишется только в спеке с via: без via текст правил прежний побайтно (проверки выше).
sed 's|"outputs": { "vpn": { "kind": "interface", "device": "wg0" } }|"outputs": { "vpn": { "kind": "interface", "device": "wg0" }, "nl": { "kind": "awg", "conf": "/nonexistent/nl.conf", "via": "vpn" } }|' \
    "$tmp/loc2.json" > "$tmp/via.json"
mv3="$("$BIN" apply --dry-run --spec "$tmp/via.json" --state-dir "$tmp/state" 2>/dev/null)"
vdns='meta mark and 0x0fc00000 != 0x0fc00000 meta mark and 0x10000000 == 0x00000000 udp dport 53 ct mark set mark counter redirect to :5300'
vtcp='meta mark and 0x0fc00000 != 0x0fc00000 meta mark and 0x10000000 == 0x00000000 tcp dport 53 ct mark set mark counter redirect to :5300'
check "via: заворот UDP/53 пропускает туннель (бит 0x10000000)" "1" "$(c "$mv3" "$vdns")"
check "via: заворот TCP/53 пропускает туннель" "1" "$(c "$mv3" "$vtcp")"
check "без via бита туннеля в правилах нет" "0" "$(c "$m2" '0x10000000')"
# Ядро машины разработки принимает такое правило.
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null 2>&1 && unshare -n true 2>/dev/null; then
    printf '%s\n' "$mv3" > "$tmp/via.nft"
    unshare -n nft -c -f "$tmp/via.nft" >/dev/null 2>"$tmp/via.err"
    check "via: nft -c принимает правила с битом туннеля" "0" "$?"
fi

ROUTER="${ROUTER:-./build/steer}"
if [ -x "$ROUTER" ]; then
    "$ROUTER" apply --dry-run --spec "$tmp/local.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/r.err"
    check "роутерная сборка: каналы на себя — отказ" "2" "$?"
fi

# Разметка раздачи на ingress (compile/generate.c, «разметка на ingress») на телефоне не ставится:
# устройства раздачи появляются с включением раздачи (lan_devs_persist = 0). Даже когда ядро
# «принимает» inet ingress и устройство «есть» (STEER_NFT_INGRESS=all), текст — прежний.
ing="$(STEER_NFT_INGRESS=all "$BIN" apply --dry-run $S 2>/dev/null)"
check "раздача на телефоне — без ingress" "0" "$(printf '%s\n' "$ing" | grep -c 'hook ingress')"
check "  и текст тот же, что без него" "$out" "$ing"

# IPv6 от хоста (ключ ipv6 у выхода, шаг 8 выпуска 1.10): раздачей IPv6 на телефоне владеет
# Tethering Android. routed и nat разбираются (спека одна на обе платформы), но действуют как
# отсутствие ключа — набор правил тот же, что без него, — и apply говорит об этом; off действует.
printf '203.0.113.0/24\n2001:db8:a::/48\n' > "$tmp/h6.lst"
h6() {
    cat > "$tmp/h6.yaml" <<EOF
version: 2
lists:
  a: { prefixes_file: $tmp/h6.lst }
outputs:
  wg: { kind: interface, device: wg0$1 }
rules:
  - { to: a, out: wg }
EOF
    "$BIN" apply --dry-run --spec "$tmp/h6.yaml" --state-dir "$tmp/state" 2>"$tmp/h6.err"
}
h6_none="$(h6 '')"
h6_r="$(h6 ', ipv6: routed, prefix: "2001:db8:1::/56"')"
check "ipv6: routed на телефоне — набор правил как без ключа" "$h6_none" "$h6_r"
check "  и apply говорит, что ключ не действует" "1" \
    "$(grep -c 'ipv6: routed на этой платформе не действует' "$tmp/h6.err")"
h6_n="$(h6 ', ipv6: nat')"
check "ipv6: nat на телефоне — набор правил как без ключа" "$h6_none" "$h6_n"
h6_o="$(h6 ', ipv6: off')"
check "ipv6: off на телефоне действует — IPv6 выхода отвергается" "1" \
    "$(printf '%s\n' "$h6_o" | grep -c 'steer-v6drop:wg')"

printf '\nandroidmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
