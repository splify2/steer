#!/bin/sh
# Стенд плагина tgws — мост Telegram (plugins/tgws, src/modules/main_tgws.c, src/proto/tgws).
#
# Мост с 2.1 — плагин: вид `tgws` ядро берёт из манифеста, правило перехвата — из шаблона nft плагина
# (plugins/tgws/nft/tgws.nft, слот prerouting-dnat), порт моста — ресурс выхода (alloc.json), отказы
# общих ключей — хук check программы. Стенд проверяет всё это ядром стенда (build/steer) с каталогом
# плагинов дерева (tests/plugroot.sh) — без сети и без root:
#
#   1. правило перехвата: слот prerouting-dnat (nat, dstnat + 1), метка выхода, порты MTProto, порт моста;
#   2. порт — ресурс выхода: постоянный между запусками, у двух выходов разный, таблицы маршрутизации нет;
#   3. спека v1 (`"kind": "tgws"`) переводится в вид плагина с тем же правилом;
#   4. отказы: устройство, on_fail не drop, нет domain, domain у чужого вида; без плагина — понятный отказ;
#
# и программу плагина, если она собрана (TGWS_PROG; раскладку build/libs-host собирает make libs-test,
# стенд зовёт tests/libs-test.sh):
#
#   5. hello с API и id, хук check, разбор аргументов tgws-probe;
#   6. мост по {conf}: слушает порт из output.ports, говорит up, читает настройки плагина (settings.json:
#      пул, пути, адреса ДЦ, WARP) и перезапускается сам, когда их переписали.
#
# Мост целиком (перехват в ядре Linux, веб-сокет, поток) — tests/run-tgws.sh (root, сетевые пространства).
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "tgwsmatch: не собран $BIN (make)"; exit 2; }
PROG="${TGWS_PROG:-}"

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
has() {  # ИМЯ ТЕКСТ ПОДСТРОКА
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет: %s\n  в: %s\n' "$1" "$3" "$(printf '%s' "$2" | head -c 600)" ;; esac
}

sh tests/plugroot.sh "$tmp/plugins" "${BUILD:-build}" || { echo "tgwsmatch: каталог плагинов не собран"; exit 2; }
STEER_PLUGINS_ROOT="$tmp/plugins"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC
STEER_NFT_INGRESS=0; export STEER_NFT_INGRESS
printf '149.154.160.0/20\n91.108.4.0/22\n' > "$tmp/tg.lst"
dry() { "$BIN" apply --dry-run --spec "$1" --state-dir "$tmp/st" 2>&1; }

# ---- 1. правило перехвата ------------------------------------------------------------------------
cat > "$tmp/one.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
lists:
  tgl: { prefixes_file: $tmp/tg.lst }
outputs:
  tg: { kind: tgws, domain: ex.co.uk }
rules:
  - { name: tgr, to: [tgl], out: tg }
EOF
out="$(dry "$tmp/one.yaml")"; rc=$?
check "спека с выходом tgws компилируется" "0" "$rc"
# dstnat + 1, а не dstnat: сначала fake-IP ядра обязан вернуть настоящий адрес, и только потом решается,
# наш ли он. И не mangle: метку канала ставят раньше, на mangle + 1.
has "слот prerouting-dnat — после трансляции адресов" "$out" "chain plugin_prerouting-dnat {
        type nat hook prerouting priority dstnat + 1; policy accept;"
has "  и в нём переход в цепочку плагина" "$out" "jump plugin_tgws_prerouting-dnat"
port="$(sed -n 's/.*"tgws\/tg":{"ports":\[\([0-9]*\)\].*/\1/p' "$tmp/plugetc/alloc.json" 2>/dev/null)"
check "порт моста выдан ресурсом выхода (alloc.json)" "1" "$(printf '%s' "$port" | grep -c '^[0-9][0-9]*$')"
has "заворачивает по метке выхода на его порт" "$out" \
    "meta mark and 0x0ff00000 == 0x00100000 tcp dport { 443, 80, 5222 } counter redirect to :$port comment \"steer:plugin:tgws:tg\""
# Таблицы маршрутизации у такого выхода нет — маршрут не меняется, меняется адресат.
check "маршрута в таблицу у выхода tgws нет" "0" "$(printf '%s\n' "$out" | grep -c 'ip route .*table')"
check "метки соединения у tgws нет (ct mark выхода не ставится)" "0" \
    "$(printf '%s\n' "$out" | grep 'steer:tgl' | grep -c 'ct mark set')"

# ---- 2. порт — ресурс выхода ---------------------------------------------------------------------
out2="$(dry "$tmp/one.yaml")"
check "повторный запуск — тот же порт" "1" "$(printf '%s\n' "$out2" | grep -c "redirect to :$port comment")"
cat > "$tmp/two.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
clients:
  tv: { addr: [192.168.1.50] }
lists:
  tgl: { prefixes_file: $tmp/tg.lst }
outputs:
  tg:  { kind: tgws, domain: ex.co.uk }
  tg2: { kind: tgws, domain: other.example }
rules:
  - { name: tgr, to: [tgl], out: tg }
  - { name: tgr2, for: [tv], to: [tgl], out: tg2 }
EOF
out="$(dry "$tmp/two.yaml")"
port2="$(sed -n 's/.*"tgws\/tg2":{"ports":\[\([0-9]*\)\].*/\1/p' "$tmp/plugetc/alloc.json" 2>/dev/null)"
check "у второго выхода свой порт, первый прежний" "yes" \
    "$([ -n "$port2" ] && [ "$port2" != "$port" ] && echo yes || echo no)"
check "по правилу на выход, в одной цепочке плагина" "2" \
    "$(printf '%s\n' "$out" | grep -c 'tcp dport { 443, 80, 5222 } counter redirect to :')"
has "  второй — по своей метке на свой порт" "$out" "redirect to :$port2 comment \"steer:plugin:tgws:tg2\""
cat > "$tmp/none.yaml" <<EOF
version: 2
outputs:
  wg: { kind: interface, device: wg0 }
EOF
check "без выходов tgws слота и цепочки нет" "0" "$(dry "$tmp/none.yaml" | grep -c 'prerouting-dnat')"

# ---- 3. спека v1 ---------------------------------------------------------------------------------
cat > "$tmp/v1.json" <<EOF
{ "schema": 1, "lan_devices": ["br-lan"],
  "outputs": { "direct": { "kind": "direct" }, "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [ { "name": "тг", "match": { "prefixes_file": "$tmp/tg.lst" }, "out": "tg" } ] }
EOF
out="$(dry "$tmp/v1.json")"; rc=$?
check "спека v1 с kind tgws компилируется" "0" "$rc"
has "  тот же перехват на тот же порт" "$out" "redirect to :$port comment \"steer:plugin:tgws:tg\""
conv="$("$BIN" spec convert --spec "$tmp/v1.json" 2>&1)"
has "spec convert: выход переведён видом плагина с ключом domain" "$conv" "kind: tgws"
has "  domain на месте" "$conv" "domain: ex.co.uk"

# ---- 4. отказы -----------------------------------------------------------------------------------
refuse() {  # ИМЯ ВЫХОД-YAML ПОДСТРОКА-ПРИЧИНЫ
    printf 'version: 2\noutputs:\n  %s\n' "$2" > "$tmp/bad.yaml"
    o="$(dry "$tmp/bad.yaml")"; r=$?
    check "$1: код 2" "2" "$r"
    has "$1: причина названа" "$o" "$3"
}
# Устройство у такого выхода — почти наверняка описка, и молча принять её значит обещать маршрутизацию,
# которой не будет. on_fail не выражается ничем: правило перехвата стоит всегда.
refuse "устройство у tgws" "tg: { kind: tgws, domain: ex.co.uk, device: eth0 }" "нет устройства"
refuse "on_fail direct у tgws" "tg: { kind: tgws, domain: ex.co.uk, on_fail: direct }" "у kind tgws on_fail только drop"
refuse "tgws без domain" "tg: { kind: tgws }" "domain"
refuse "domain не имя хоста" "tg: { kind: tgws, domain: 'a b' }" "domain"
refuse "domain у чужого вида" "d: { kind: direct, domain: ex.co.uk }" "domain"
printf 'version: 2\noutputs:\n  tg: { kind: tgws, domain: ex.co.uk, on_fail: drop }\n' > "$tmp/drop.yaml"
dry "$tmp/drop.yaml" >/dev/null
check "on_fail drop у tgws законен" "0" "$?"
# Без плагина вид неизвестен: apply отказывает и называет вид.
o="$(STEER_PLUGINS_ROOT="$tmp/empty" STEER_PLUGIN_SEED="$tmp/empty" "$BIN" apply --dry-run --spec "$tmp/one.yaml" --state-dir "$tmp/st0" 2>&1)"
check "без плагина tgws apply отказывает" "2" "$?"
has "  и называет вид" "$o" "tgws"

# ---- 5–6. программа плагина ----------------------------------------------------------------------
if [ -z "$PROG" ] || [ ! -x "$PROG" ]; then
    echo "tgwsmatch: программа плагина не собрана (TGWS_PROG; её собирает make libs-test) — части 5–6 пропущены"
else
    h="$(STEER_EVENT_FD=3 "$PROG" tgws-probe --node 9 3>&1 >/dev/null 2>/dev/null | head -1)"
    check "первое сообщение программы — hello с API и id" '"api":"1.1"' "$(printf '%s' "$h" | grep -o '"api":"1.1"')"
    has "  id плагина" "$h" '"mod":"tgws"'
    o="$("$PROG" tgws-probe --node 9 2>&1)"; r=$?
    check "tgws-probe: номер ДЦ вне 1..5 и 203 — отказ" "2" "$r"
    o="$("$PROG" tgws-probe --node abc 2>&1)"; r=$?
    check "tgws-probe: не-число там, где ждали число — отказ разбора" "2" "$r"
    o="$("$PROG" tgws-probe medai 2>&1)"; r=$?
    check "tgws-probe: слово кроме media — отказ" "2" "$r"
    has "  и сказано, что понимается" "$o" "только «media»"
    o="$(printf '{"api":"1.1","output":{"name":"tg","kind":"tgws","keys":{"domain":"a.example"},"common":{"device":"eth0"}}}' | "$PROG" check 2>&1)"
    check "хук check: устройство — отказ" "2" "$?"
    o="$(printf '{"api":"1.1","output":{"name":"tg","kind":"tgws","keys":{"domain":"a.example"},"common":{"on_fail":"drop"}}}' | "$PROG" check 2>&1)"
    check "хук check: on_fail drop — годится" "0" "$?"
    o="$("$PROG" tgws tg 2>&1)"; r=$?
    check "мост без --conf — отказ" "2" "$r"

    # Мост по {conf}: порт — свободный на петле, настройки — свой каталог плагина.
    mp="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
    mkdir -p "$tmp/pconf" "$tmp/pstate"
    cat > "$tmp/pconf/settings.json" <<EOF
{"domains":["a.example","b.example"],"routes":["2 ws c.example","4 direct","x bad"],
 "dc_addresses":["149.154.167.220 2","1.2.3.4 9"],"warp":["nowarp0"],"verbose":false}
EOF
    cat > "$tmp/tg.conf" <<EOF
{"api":"1.1","plugin":{"id":"tgws","version":"t"},"output":{"name":"tg","kind":"tgws","keys":{"domain":"ex.example"},
 "device":"","mark":"0x00100000","mark_mask":"0x0ff00000","table":300,"ipv6":false,"on_fail":"drop","over":null,
 "sock_mark":"0x00000000","sock_mark_required":false,"tcp_port":0,"ports":[$mp],"queues":[]},
 "paths":{"etc":"$tmp","state":"$tmp","plugin":"$tmp","conf":"$tmp/pconf","plugin_state":"$tmp/pstate"},"platform":"openwrt"}
EOF
    STEER_EVENT_FD=3 "$PROG" tgws tg --conf "$tmp/tg.conf" 3>"$tmp/ev" 2>"$tmp/log" &
    bp=$!
    n=0
    while ! grep -q '"ev":"up"' "$tmp/ev" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    has "мост сказал up" "$(cat "$tmp/ev")" '"ev":"up"'
    log="$(cat "$tmp/log")"
    has "слушает порт из {conf} (output.ports)" "$log" "жду перехваченные соединения на :$mp, домен ex.example"
    has "пул из настроек" "$log" "запасных доменов: 2"
    has "пути ДЦ из настроек" "$log" "путей ДЦ из настроек: 2"
    has "  негодная строка пути названа" "$log" "путь ДЦ «x bad» не понят"
    has "адреса ДЦ из настроек" "$log" "адресов ДЦ из настроек: 1"
    has "  негодный адрес назван" "$log" "адрес ДЦ «1.2.3.4 9» не понят"
    has "туннели WARP из настроек" "$log" "WARP: туннелей для моста 1"
    has "ДЦ2 своим доменом по пути из настроек" "$log" "ДЦ2: web.telegram.org, запасной c.example и пул"
    has "ДЦ4 напрямую по пути из настроек" "$log" "ДЦ4: напрямую, не перехватывая"
    check "порт занят мостом" "1" "$(python3 -c "
import socket,sys
s=socket.socket()
try: s.connect(('127.0.0.1',$mp)); print(1)
except Exception: print(0)" 2>/dev/null)"
    # Настройки переписаны (так их пишет панель — plugin_settings_set): мост выходит сам, супервизор ядра
    # поднимает его заново уже с ними.
    sleep 0.2
    printf '{"domains":["z.example"]}\n' > "$tmp/pconf/settings.json.new" && mv "$tmp/pconf/settings.json.new" "$tmp/pconf/settings.json"
    n=0
    while kill -0 "$bp" 2>/dev/null && [ "$n" -lt 60 ]; do sleep 0.1; n=$((n + 1)); done
    check "настройки переписаны — мост вышел сам (перезапуск супервизором)" "no" "$(kill -0 "$bp" 2>/dev/null && echo yes || echo no)"
    has "  и сказал down с причиной" "$(cat "$tmp/ev")" '{"ev":"down","why":"'
    has "  в журнале — почему" "$(cat "$tmp/log")" "настройки изменились — перезапуск моста"
    kill "$bp" 2>/dev/null
    wait "$bp" 2>/dev/null
    # Негодный файл настроек мост не роняет: Telegram без пула лучше, чем без моста.
    printf 'не json' > "$tmp/pconf/settings.json"
    "$PROG" tgws tg --conf "$tmp/tg.conf" 2>"$tmp/log2" &
    bp=$!
    n=0
    while ! grep -q 'жду перехваченные' "$tmp/log2" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    has "негодные настройки: мост поднялся без них" "$(cat "$tmp/log2")" "жду перехваченные соединения на :$mp"
    has "  и назвал файл" "$(cat "$tmp/log2")" "settings.json не читаются"
    kill "$bp" 2>/dev/null
    wait "$bp" 2>/dev/null
fi

echo "tgwsmatch: $pass ok, $fail fail"
[ "$fail" -eq 0 ]
