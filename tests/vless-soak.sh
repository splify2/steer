#!/bin/sh
# Долгий стенд выхода VLESS: «сначала работает, через минуты-часы трафик перестаёт идти, помогает
# перезапуск». Вне make test: идёт столько, сколько попросили (умолчание — час реального времени).
#
# Стенд: два сетевых пространства. В сервере — настоящий Xray (VLESS, по умолчанию без TLS; SEC=reality —
# Reality и Vision) и цели за ним (tests/vless-soak-srv.py: HTTP с keep-alive, эхо UDP, адреса пробы узла
# 1.1.1.1 и 8.8.8.8). В клиенте — туннель steer и нагрузка (tests/vless-soak.py). Узел в подписке — по
# имени, имя — в hosts пространства клиента: смена адреса узла — смена записи, прежний адрес исчезает
# молча. Беды по кругу: простой дольше connIdle Xray, kill -9 сервера, глухая потеря связи с узлом,
# смена адреса узла, падение WAN. После каждой трафик обязан вернуться сам за RECOVER секунд, дескрипторы
# процесса в покое после стенда — вернуться к стартовым.
#
# Использование (root):
#   STEER_VLESS=build/libs-host/plugins/vless/bin/vless sh tests/vless-soak.sh [минут]   — main (плагин)
#   STEER=<дерево 2.0.x>/build/libs-host/steerd sh tests/vless-soak.sh [минут]          — 2.0.x (steerd vless)
# Переменные: UDP_SPRAY (новых потоков UDP в секунду к разным адресам), NOFILE (предел fd туннеля), CROWD (устройств толпы: держат keep-alive и уходят без FIN, по одному в минуту), CROWD_CONNS
# (соединений на устройство, 8), TUN_STATS=1 (счёт соединений туннеля в журнал), SEC=none|reality, NETEM (tc netem до узла), CPUS (taskset туннеля), ONLY=беды,через,запятую, IDLE (с, 330), RECOVER (с, 180), STEADY (с, 120),
# SOAK_ID — суффикс имён пространств, KEEP=1 — не удалять рабочий каталог (журналы туннеля, Xray и стенда).
set -eu
cd "$(dirname "$0")/.."

MIN="${1:-60}"
SEC="${SEC:-none}"
XRAY="${XRAY:-$(command -v xray || true)}"
[ -x "$XRAY" ] || { echo "vless-soak: нет xray (XRAY=путь) — ПРОПУСК"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "vless-soak: нужен root — ПРОПУСК"; exit 2; }
if [ -n "${STEER_VLESS:-}" ]; then
    MODE=plugin; BIN="$STEER_VLESS"
elif [ -n "${STEER:-}" ]; then
    MODE=steerd; BIN="$STEER"
else
    MODE=plugin; BIN=./build/libs-host/plugins/vless/bin/vless
fi
[ -x "$BIN" ] || { echo "vless-soak: нет $BIN (раскладку собирает make libs-test)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
# steerd 2.0.x динамический: библиотеки рядом с ним.
[ "$MODE" = steerd ] && { LD_LIBRARY_PATH="$(dirname "$BIN")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH; }

# SOAK_ID — суффикс пространств: два стенда разом (скажем, SEC=none и SEC=reality) не мешают друг другу.
CL=soak-cl${SOAK_ID:-} SV=soak-sv${SOAK_ID:-}
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
IPA=10.77.1.1 IPB=10.77.1.2 GW=10.77.0.1 TARGET=203.0.113.7 NODE=node.soak.test PORT=443
W="$(mktemp -d /tmp/vless-soak.XXXXXX)"
chmod 755 "$W"

cleanup() {
    # Туннель — сначала TERM: сборка с ASan пишет отчёт об утечках только при штатном выходе.
    if [ -n "${TPID:-}" ] && kill -TERM "$TPID" 2>/dev/null; then
        for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$TPID" 2>/dev/null || break; sleep 0.5; done
    fi
    for ns in $CL $SV; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns delete "$ns" 2>/dev/null || true
    done
    rm -rf "/etc/netns/$CL"
    if [ "${KEEP:-0}" = 1 ]; then echo "vless-soak: журналы в $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM

for ns in $CL $SV; do ip netns delete "$ns" 2>/dev/null || true; done
ip netns add $CL
ip netns add $SV
mkdir -p "/etc/netns/$CL"
printf '127.0.0.1 localhost\n%s %s\n' "$IPA" "$NODE" > "/etc/netns/$CL/hosts"
ip -n $CL link set lo up
ip -n $SV link set lo up
ip link add cl0 netns $CL type veth peer name sv0 netns $SV
ip -n $CL addr add 10.77.0.2/24 dev cl0
ip -n $SV addr add $GW/24 dev sv0
ip -n $CL link set cl0 up
ip -n $SV link set sv0 up
ip -n $CL route add 10.77.1.0/24 via $GW dev cl0
# NETEM — сеть до узла как у провайдера («delay 40ms 10ms loss 0.5%»): обе стороны veth.
if [ -n "${NETEM:-}" ]; then
    ip netns exec $CL tc qdisc add dev cl0 root netem $NETEM
    ip netns exec $SV tc qdisc add dev sv0 root netem $NETEM
fi
# Узел — свой dummy (адрес узла меняется на нём), цели и адреса пробы — другой.
ip -n $SV link add node type dummy
ip -n $SV addr add $IPA/32 dev node
ip -n $SV link set node up
ip -n $SV link add net type dummy
for a in $TARGET 1.1.1.1 8.8.8.8; do ip -n $SV addr add $a/32 dev net; done
ip -n $SV link set net up
# Остальные адреса 203.0.113.0/24 — в dummy: датаграммы UDP_SPRAY уходят без ответа, как пинги DHT к мёртвым
# узлам (без маршрута Xray получил бы ENETUNREACH и закрывал поток сразу).
ip -n $SV route add 203.0.113.0/24 dev net

ip netns exec $SV python3 tests/vless-soak-srv.py 80 > "$W/srv.log" 2>&1 &

case "$SEC" in
none)
    STREAM='{"network":"tcp","security":"none"}'
    LINK="vless://$UUID@$NODE:$PORT?security=none&type=tcp#soak"
    FLOW="" ;;
reality)
    # Маскировочный сайт — свой TLS 1.3 рядом с целями: Reality проксирует ему чужих и берёт у него
    # рукопожатие. Ключи — у самого Xray.
    ip -n $SV addr add 203.0.113.9/32 dev net
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=mask.soak.test \
        -keyout "$W/mask.key" -out "$W/mask.crt" >/dev/null 2>&1
    if [ -n "${MASK_GROUPS:-}" ]; then
        # Маска с заданными группами (скажем, X25519MLKEM768:X25519) — openssl s_server, однопоточный: только
        # для коротких проверок рукопожатия, не для долгого стенда.
        ip netns exec $SV openssl s_server -accept 203.0.113.9:8443 -tls1_3 -groups "$MASK_GROUPS" \
            -alpn h2,http/1.1 -www -key "$W/mask.key" -cert "$W/mask.crt" -quiet > "$W/mask.log" 2>&1 &
    else
        ip netns exec $SV python3 tests/vless-soak-srv.py --mask 203.0.113.9:8443 "$W/mask.crt" "$W/mask.key" \
            > "$W/mask.log" 2>&1 &
    fi
    KP="$("$XRAY" x25519)"
    PRIV=$(printf '%s\n' "$KP" | awk -F': *' '/Private/{print $2}')
    PUB=$(printf '%s\n' "$KP" | awk -F': *' '/Public|Password/{print $2; exit}')
    SID=0123456789abcdef
    STREAM="{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"target\":\"203.0.113.9:8443\",\
\"serverNames\":[\"mask.soak.test\"],\"privateKey\":\"$PRIV\",\"shortIds\":[\"$SID\"]}}"
    LINK="vless://$UUID@$NODE:$PORT?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=mask.soak.test&pbk=$PUB&sid=$SID&fp=chrome#soak"
    FLOW=',"flow":"xtls-rprx-vision"' ;;
*) echo "vless-soak: SEC=$SEC не знаю"; exit 2 ;;
esac
# finalRules allow: freedom новых Xray молча глушит частные и тестовые адреса («blocked target»), а цели
# стенда — именно такие.
cat > "$W/xray.json" <<CFG
{"log":{"loglevel":"${XLOG:-warning}"},
 "inbounds":[{"listen":"0.0.0.0","port":$PORT,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID"$FLOW}],"decryption":"none"},"streamSettings":$STREAM}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}
CFG
printf '%s\n' "$LINK" > "$W/sub.txt"

mkdir -p "$W/state" "$W/pst"
if [ "$MODE" = plugin ]; then
    cat > "$W/vl.json" <<CONF
{"api":"1.1","plugin":{"id":"vless","version":"soak"},
 "output":{"name":"vl","kind":"tunnel:vless","keys":{"subscription":"$W/sub.txt"},"device":"vl","mark":"0x00300000",
           "mark_mask":"0x0ff00000","table":302,"ipv6":false,"on_fail":"drop","over":null,"sock_mark":"0x00000000",
           "sock_mark_required":false,"tcp_port":9480,"ports":[],"queues":[]},
 "paths":{"plugin_state":"$W/pst"},"platform":"openwrt"}
CONF
    set -- "$BIN" vless vl --conf "$W/vl.json"
else
    cat > "$W/spec.json" <<SPEC
{"schema":1,"outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$W/sub.txt","node":0}},"channels":[]}
SPEC
    set -- "$BIN" vless vl --spec "$W/spec.json" --state-dir "$W/state"
fi
# Сервер нужен до подъёма: туннель проверяет узел при старте. Дальше им управляет vless-soak.py.
ip netns exec $SV "$XRAY" run -c "$W/xray.json" > "$W/xray-boot.log" 2>&1 &
XB=$!
sleep 2
# CPUS — ядра туннеля (taskset): у роутера их одно-два, и гонки установщиков там видны, а на шестнадцати — нет.
[ -n "${CPUS:-}" ] && set -- taskset -c "$CPUS" "$@"
[ "${TUN_STATS:-0}" = 1 ] && set -- env STEER_TUN_STATS=1 "$@"
# NOFILE — предел дескрипторов туннеля, как у службы роутера (procd: 1024/4096; steerd поднимает до 4096).
[ -n "${NOFILE:-}" ] && set -- prlimit --nofile="$NOFILE:$NOFILE" "$@"
ip netns exec $CL "$@" > "$W/tun.log" 2>&1 &
TPID=$!     # ip netns exec заменяет себя программой: это pid туннеля
for _ in $(seq 100); do
    ip -n $CL link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
ip -n $CL link show vl >/dev/null 2>&1 || { echo "vless-soak: vl не поднялся:"; tail -20 "$W/tun.log"; exit 1; }
if [ "${HOLD:-0}" = 1 ]; then
    # Отладка: стенд поднят, сервер работает, нагрузки нет — до Ctrl-C (или kill этого sh).
    ip -n $CL route replace $TARGET/32 dev vl
    [ "$MODE" = plugin ] && { . tests/lib-redir.sh; redir_dev $CL vl; }
    echo "vless-soak: HOLD, pid $TPID, ip netns exec $CL ..., журналы $W"
    wait $XB
    exit 0
fi
kill $XB; wait $XB 2>/dev/null || true
ip -n $CL route replace $TARGET/32 dev vl
# Вся 203.0.113.0/24 — в туннель: UDP_SPRAY шлёт на разные её адреса.
ip -n $CL route replace 203.0.113.0/24 dev vl
if [ "$MODE" = plugin ]; then
    . tests/lib-redir.sh
    redir_dev $CL vl
fi
echo "vless-soak: $MODE $BIN, SEC=$SEC, $MIN мин, pid $TPID, журналы $W"

rc=0
ip netns exec $CL python3 tests/vless-soak.py --minutes "$MIN" --pid "$TPID" --work "$W" --sv $SV \
    --hosts "/etc/netns/$CL/hosts" --node $NODE --ip-a $IPA --ip-b $IPB --target $TARGET \
    --xray "ip netns exec $SV $XRAY run -c $W/xray.json" --wan cl0 --wan-gw $GW --node-net 10.77.1.0/24 \
    --port $PORT --idle "${IDLE:-330}" --recover "${RECOVER:-180}" --steady "${STEADY:-120}" \
    --only "${ONLY:-}" --crowd "${CROWD:-0}" --crowd-conns "${CROWD_CONNS:-8}" \
    --udp-spray "${UDP_SPRAY:-0}" || rc=$?
# Без бед (ONLY=none) узлу умирать не от чего: «узел не отвечает» в журнале — выход сам себя уронил (так
# выглядел EMFILE под UDP_SPRAY: getaddrinfo без дескриптора — «имя не разрешилось», узел мёртв, а демон
# роутера по этому down уводит выход в on_fail).
if [ "${ONLY:-}" = none ] && grep -q "не отвечает" "$W/tun.log"; then
    echo "vless-soak: ПРОВАЛ — без бед туннель признал узел мёртвым:"
    grep "не отвечает" "$W/tun.log" | sort | uniq -c | head -5 | sed 's/^/  /'
    rc=1
fi
echo "vless-soak: журнал туннеля (хвост):"
tail -15 "$W/tun.log" | sed 's/^/  /'
exit $rc
