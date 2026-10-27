#!/bin/sh
# Прогон моста tgws ЦЕЛИКОМ: перехват в ядре, разбор рукопожатия, веб-сокет, поток в обе
# стороны. Без интернета и без Telegram.
#
# ЗАЧЕМ СТЕНД НА ДВУХ СЕТЕВЫХ ПРОСТРАНСТВАХ, А НЕ НА ОДНОМ. Перехват стоит правилом nat в
# ЦЕПОЧКЕ PREROUTING, то есть ловит трафик КЛИЕНТОВ СЕТИ. Соединение, открытое процессом на
# том же хосте, через prerouting не проходит вовсе — оно идёт через output. Стенд на одном
# пространстве проверял бы что угодно, только не то правило, которое стоит на роутере, и был
# бы зелёным при полностью нерабочем перехвате.
#
# Устройство стенда:
#
#   пространство tgws-c (клиент)          пространство tgws-r (роутер)
#   veth-c 10.99.0.2  ──────────────────  veth-r 10.99.0.1   (маршрут по умолчанию туда)
#                                          dc0 149.154.167.51/32  ← «адрес дата-центра»
#                                          правила steer: перехват → :<порт выхода>
#                                          мост — программа плагина tgws
#                                          поддельная точка apiws на 127.0.0.1:8443
#
# Клиент соединяется с 149.154.167.51:443 (это ДЦ2 по встроенной таблице моста), пакет
# приходит на роутер в prerouting, правило заворачивает его на мост, мост узнаёт исходный
# адрес через SO_ORIGINAL_DST, вписывает в рукопожатие номер ДЦ и уводит соединение
# веб-сокетом на поддельную точку. Та проверяет, что рукопожатие расшифровывается сырыми
# ключами и что номер ДЦ верный, и работает эхом.
#
# TLS здесь нарочно выключен (STEER_TGWS_PLAIN=1): поднимать настоящий TLS означало бы
# проверять чужую библиотеку вместо своего моста, а сам обмен от этого не меняется.
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/libs-host/steerd}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (раскладку build/libs-host собирает make libs-test)"; exit 2; }
# Мост — плагин tgws: манифест и шаблон nft — каталог плагинов раскладки (libs-test кладёт туда манифесты
# дерева рядом с программами), программа — его bin/tgws.
PLUGROOT="${STEER_PLUGINS_ROOT:-$(dirname "$BIN")/plugins}"
PROG="$PLUGROOT/tgws/bin/tgws"
[ -x "$PROG" ] && [ -f "$PLUGROOT/tgws/plugin.json" ] || { echo "нет плагина tgws в $PLUGROOT (make libs-test)"; exit 2; }
# steerd динамический: libsteer.so и libsteer-wolfssl.so лежат рядом с ним, а не в системных путях.
LD_LIBRARY_PATH="$(cd "$(dirname "$BIN")" && pwd)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH
python3 -c "import cryptography" 2>/dev/null || { echo "нет python-cryptography — пропускаю"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "нужен root (сетевые пространства и nftables)"; exit 2; }

NSR=tgws-r
NSC=tgws-c
DCIP=149.154.167.51          # ДЦ2 по встроенной таблице моста
DCPORT=443
WSPORT=8443                  # поддельная точка apiws
tmp="$(mktemp -d /tmp/tgws-stand.XXXXXX)"
STEER_PLUGINS_ROOT="$PLUGROOT"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC
fail=0

check() {  # ЧТО ОЖИДАЛОСЬ ПОЛУЧЕНО
    if [ "$2" = "$3" ]; then
        printf '  %-58s ok\n' "$1"
    else
        printf '  %-58s ПРОВАЛ\n    ожидалось: %s\n    получено:  %s\n' "$1" "$2" "$3"
        fail=$((fail + 1))
    fi
}

cleanup() {
    for ns in "$NSR" "$NSC"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns delete "$ns" 2>/dev/null || true
    done
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

ip netns delete "$NSR" 2>/dev/null || true
ip netns delete "$NSC" 2>/dev/null || true
ip netns add "$NSR"
ip netns add "$NSC"
ip netns exec "$NSR" ip link set lo up
ip netns exec "$NSC" ip link set lo up

ip link add veth-r netns "$NSR" type veth peer name veth-c netns "$NSC"
ip netns exec "$NSR" ip addr add 10.99.0.1/24 dev veth-r
ip netns exec "$NSR" ip link set veth-r up
ip netns exec "$NSC" ip addr add 10.99.0.2/24 dev veth-c
ip netns exec "$NSC" ip link set veth-c up
ip netns exec "$NSC" ip route add default via 10.99.0.1
ip netns exec "$NSR" sysctl -qw net.ipv4.ip_forward=1
# «Дата-центр» — адрес на самом роутере: пакет клиента доходит до prerouting и дальше нас не
# волнует, потому что его забирает правило перехвата. Реальный маршрут в интернет стенду не
# нужен, а без адреса на устройстве роутер ответил бы клиенту недоступностью сети.
ip netns exec "$NSR" ip link add dc0 type dummy
ip netns exec "$NSR" ip addr add "$DCIP/32" dev dc0
ip netns exec "$NSR" ip link set dc0 up

printf '%s/32\n' "$DCIP" > "$tmp/tg.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 1, "lan_devices": ["veth-r"],
  "outputs": { "direct": { "kind": "direct" },
               "tg": { "kind": "tgws", "domain": "stand.invalid" } },
  "channels": [ { "name": "телеграм", "match": { "prefixes_file": "$tmp/tg.lst" },
                  "out": "tg" } ] }
EOF

# ---- правила перехвата ------------------------------------------------------------------
out="$(ip netns exec "$NSR" "$BIN" apply --spec "$tmp/spec.json" --state-dir "$tmp/state" 2>&1)" || {
    echo "apply не прошёл:"; echo "$out"; exit 1; }
rules="$(ip netns exec "$NSR" nft list table inet steer 2>/dev/null || true)"
PORT="$(sed -n 's/.*"tgws\/tg":{"ports":\[\([0-9]*\)\].*/\1/p' "$tmp/plugetc/alloc.json" 2>/dev/null)"
check "порт моста выдан ресурсом выхода" "1" "$(printf '%s' "$PORT" | grep -c '^[0-9][0-9]*$')"
check "цепочка перехвата плагина встала в ядро" "1" \
      "$(printf '%s\n' "$rules" | grep -c 'chain plugin_tgws_prerouting-dnat')"
check "слот висит после трансляции адресов" "1" \
      "$(printf '%s\n' "$rules" | grep -c 'hook prerouting priority dstnat + 1')"
check "заворачивает на порт выхода" "1" \
      "$(printf '%s\n' "$rules" | grep -c "redirect to :$PORT")"

# ---- поддельная точка apiws и мост -------------------------------------------------------
ip netns exec "$NSR" python3 tests/fake-apiws.py --port "$WSPORT" --report "$tmp/report" \
    > "$tmp/apiws.log" 2>&1 &
sleep 1

# STEER_TGWS_VERBOSE=1: строку «не наш дата-центр» мост пишет только в подробном журнале (по умолчанию в
# журнале одни параметры запуска и переключения путей), а проверка ниже ищет именно её.
# {conf} выхода — то, что кладёт ядро помощнику (steer-api.md, 1.4): ключ domain и порт выхода; настройки
# плагина — пусто (свой каталог). Демона стенд не поднимает — программа запускается так же, как её запустил
# бы супервизор.
mkdir -p "$tmp/pconf" "$tmp/pstate"
cat > "$tmp/tg.conf" <<CONF
{"api":"1.1","plugin":{"id":"tgws","version":"stand"},"output":{"name":"tg","kind":"tgws","keys":{"domain":"stand.invalid"},
 "device":"","mark":"0x00100000","mark_mask":"0x0ff00000","table":300,"ipv6":false,"on_fail":"drop","over":null,
 "sock_mark":"0x00000000","sock_mark_required":false,"tcp_port":0,"ports":[$PORT],"queues":[]},
 "paths":{"etc":"$tmp","state":"$tmp/state","plugin":"$PLUGROOT/tgws","conf":"$tmp/pconf","plugin_state":"$tmp/pstate"},"platform":"openwrt"}
CONF
ip netns exec "$NSR" env STEER_TGWS_VERBOSE=1 STEER_TGWS_PLAIN=1 STEER_TGWS_ENDPOINT="127.0.0.1:$WSPORT" \
    "$PROG" tgws tg --conf "$tmp/tg.conf" > "$tmp/tgws.log" 2>&1 &
sleep 1
check "мост поднялся и слушает" "1" \
      "$(grep -c "жду перехваченные соединения на :$PORT" "$tmp/tgws.log" || true)"

# ---- собственно перехват -----------------------------------------------------------------
cl="$(ip netns exec "$NSC" python3 tests/tgws-client.py --host "$DCIP" --port "$DCPORT" \
        --tag padded --word steer-tgws-1 2>&1 || true)"
check "поток прошёл в обе стороны через веб-сокет" "вернулось: steer-tgws-1" "$cl"

rep="$(cat "$tmp/report" 2>/dev/null || true)"
check "дата-центр опознан по адресу назначения" "yes" \
      "$(printf '%s' "$rep" | grep -q 'dc=2 ' && echo yes || echo no)"
check "медийным его не объявили" "yes" \
      "$(printf '%s' "$rep" | grep -q 'media=0' && echo yes || echo no)"
check "метка транспорта клиента сохранена" "yes" \
      "$(printf '%s' "$rep" | grep -q 'tag=dddddddd' && echo yes || echo no)"
check "точка увидела заголовки веб-клиента" "yes" \
      "$(printf '%s' "$rep" | grep -q 'origin=https://web.telegram.org proto=binary' && echo yes || echo no)"

# Второй транспорт: метка обязана доехать та, что выбрал клиент, а не наша любимая.
rm -f "$tmp/report"
cl2="$(ip netns exec "$NSC" python3 tests/tgws-client.py --host "$DCIP" --port "$DCPORT" \
        --tag intermediate --word steer-tgws-2 2>&1 || true)"
check "второе соединение тоже прошло" "вернулось: steer-tgws-2" "$cl2"
check "метка транспорта не подменяется" "yes" \
      "$(grep -q 'tag=eeeeeeee' "$tmp/report" 2>/dev/null && echo yes || echo no)"

# ---- неизвестный адрес не перехватывается ------------------------------------------------
# Единственный безопасный ответ: увести соединение не в тот дата-центр — значит сломать то,
# что работало. Проверяем, что мост говорит об этом и переливает как есть (точка apiws при
# этом ничего нового не видит).
rm -f "$tmp/report"
ip netns exec "$NSR" ip addr add 149.154.199.199/32 dev dc0
printf '149.154.199.199/32\n' >> "$tmp/tg.lst"
ip netns exec "$NSR" "$BIN" apply --spec "$tmp/spec.json" --state-dir "$tmp/state" >/dev/null 2>&1
ip netns exec "$NSC" timeout 8 python3 tests/tgws-client.py --host 149.154.199.199 \
    --port "$DCPORT" --word x >/dev/null 2>&1 || true
check "чужой адрес назван и не перехвачен" "yes" \
      "$(grep -q 'не наш дата-центр' "$tmp/tgws.log" && echo yes || echo no)"
check "точка apiws о нём не узнала" "yes" \
      "$([ ! -s "$tmp/report" ] && echo yes || echo no)"

if [ "$fail" -gt 0 ]; then
    echo
    echo "мост tgws: ПРОВАЛЕНО проверок: $fail"
    echo "--- журнал моста ---"; tail -20 "$tmp/tgws.log" || true
    echo "--- журнал точки ---"; tail -10 "$tmp/apiws.log" || true
    exit 1
fi
echo
echo "мост tgws: все проверки прошли"
