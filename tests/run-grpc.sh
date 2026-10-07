#!/bin/sh
# VLESS против НАСТОЯЩЕГО Xray-core, по случаю на каждую настройку транспорта: проба узла и нагрузка в обе стороны
# (issue 39, «постоянно рвётся туннель Vless gRPC Reality»).
#
# Зачем, если есть tests/grpcmatch.c и tests/h2match.c. Те проверяют кадры и транспорт в памяти, с кадрами,
# написанными руками. Но поломка issue 39 живёт на сочетании, которое руками не придумать: что именно
# сервер gRPC кладёт в одну запись TLS, зависит от того, как grpc-go сбрасывает буфер, и от темпа ответа
# цели. h2_read терял данные, набранные в одном вызове с концом потока от Xray (RST_STREAM(NO_ERROR) после
# концевых HEADERS), и ломалось три вещи сразу:
#   - проба узла (запрос на 1.1.1.1:80 с «Connection: close») падала «ответа нет: поток закрыт сервером
#     (RST/GOAWAY)» на исправном узле — с Xray 26.3.27 14 проб из 30 в режиме gun и 21 из 30 в multi; при подъёме
#     без заданного узла перебор по пробе мог не найти ни одного;
#   - сторож после двух таких проб подряд (раз в `interval`, по умолчанию 60 с) объявлял узел мёртвым и
#     сбрасывал все соединения: «работает минуту, потом интернет рвётся полностью», узел в панели красный;
#   - около 20% коротких соединений (42 страницы из 200 по 30 КБ) теряли хвост ответа.
# Клиент Xray на том же узле отдаёт те же страницы без единого отказа: ломался именно разбор кадров в steer.
#
# Что проверяется (провал — код 1, причина в последней строке):
#   1. проба узла (`steer-vless vless-probe`) 30 раз подряд: отказов 0;
#   2. DUR секунд (умолчание 60) нагрузки через туннель: два долгих потока вниз, два
#      вверх и короткие «страницы» по 10 в секунду: ни одна страница не усечена и не повисла, долгие потоки
#      не оборваны и ни одно направление не встаёт на 15 секунд;
#   3. сторож: `interval: 10` у выхода — за прогон около 19 проверок каждого узла; в журнале steer не должно
#      быть «не отвечает», «ищу замену» и «не открылся» (то, что и видела панель: узел мёртв → трафик остановлен).
# KEEP=<каталог>: в конце скопировать туда рабочий каталог (журналы Xray и туннеля, конфиги).
# CASES — случаи через пробел (умолчание — все, см. case_cfg). Случай — это конфиг сервера (streamSettings
# Xray) и подходящая ему ссылка, так что настройка, которую клиент читает неверно, видна как провал пробы
# или нагрузки против настоящего сервера.
#
# Стороны РАЗВЕДЕНЫ по сетевым пространствам, как в run-reality.sh: клиент (steer-vless, его устройство vl и
# нагрузка) — в одном, Xray, маскировочный сайт Reality и цель — в другом. «Сайт» — адрес на lo сервера; там же
# 1.1.1.1 и 8.8.8.8 с HTTP на :80 — цели пробы узла.
#
# Нужны: root, ip netns, python3, openssl и Xray-core: XRAY=/путь/к/бинарнику (или xray в PATH). Нет Xray или прав
# — громкий пропуск (код 0), не молчание. Раскладка steer — LIBS (умолчание build/libs-host): её собирает
# `make libs-test`. В make test не входит — как run-reality.sh, run-tunnel.sh и run-udp.sh; идёт минуты.
set -eu
cd "$(dirname "$0")/.."

LIBS="${LIBS:-build/libs-host}"
DUR="${DUR:-60}"
ALL_CASES="grpc-gun grpc-multi xhttp-auto xhttp-stream-one xhttp-stream-up xhttp-packet-up xhttp-tls
           xhttp-auto-tls xhttp-auto-one xhttp-padding xhttp-host xhttp-path xhttp-up-secs
           xhttp-no-sse xhttp-post-max"
CASES="${CASES:-$ALL_CASES}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"

[ "$(id -u)" = 0 ] || { echo "run-grpc: ПРОПУСК — нужен root (ip netns). Это не падение."; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "run-grpc: ПРОПУСК — нет ip. Это не падение."; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "run-grpc: ПРОПУСК — нужен python3. Это не падение."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "run-grpc: ПРОПУСК — нужен openssl. Это не падение."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "run-grpc: ПРОПУСК — нет Xray-core (XRAY=/путь/к/бинарнику). Это не падение."; exit 0; }
[ -x "$LIBS/steer-vless" ] || { echo "run-grpc: нет $LIBS/steer-vless (его собирает make libs-test; LIBS=каталог)"; exit 2; }
LIBS="$(cd "$LIBS" && pwd)"
ip netns add "grpc-probe-$$" 2>/dev/null || { echo "run-grpc: ПРОПУСК — ip netns недоступен. Это не падение."; exit 0; }
ip netns delete "grpc-probe-$$"

NSC="grpcc$$"; NSS="grpcs$$"
S_IP=10.93.0.1; C_IP=10.93.0.2; TARGET=203.0.113.9
PORT=18443; MASK=mask.grpc.test; SVC=grpcsvc
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
SID=0123456789abcdef
W="$(mktemp -d)"
PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    done
    sleep 0.3
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill -9 "$p" 2>/dev/null || true; done
        ip netns delete "$n" 2>/dev/null || true
    done
    [ -n "${KEEP:-}" ] && cp -r "$W/." "$KEEP/" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

bg_in() { ns="$1"; log="$2"; shift 2; ip netns exec "$ns" "$@" > "$log" 2>&1 & PIDS="$PIDS $!"; }

echo "run-grpc: сервер — $("$XRAY" version 2>/dev/null | head -1)"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add grc0 netns "$NSC" type veth peer name grs0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev grc0
ip -n "$NSS" addr add "$S_IP/24" dev grs0
ip -n "$NSC" link set grc0 up; ip -n "$NSS" link set grs0 up
for a in "$TARGET" 1.1.1.1 8.8.8.8; do ip -n "$NSS" addr add "$a/32" dev lo; done

"$XRAY" x25519 > "$W/keys.txt" 2>&1
PRIV=$(awk '/^PrivateKey:/ {print $2}' "$W/keys.txt")
PUB=$(awk '/PublicKey/ {print $NF}' "$W/keys.txt")
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "run-grpc: xray x25519 не дал ключей:"; cat "$W/keys.txt"; exit 1; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$W/mask.key" -out "$W/mask.pem" -subj "/CN=$MASK" -addext "subjectAltName=DNS:$MASK" >/dev/null 2>&1

# Маскировочный сайт Reality: любой сервер TLS 1.3 с h2 в ALPN.
bg_in "$NSS" "$W/mask.log" openssl s_server -accept "$S_IP:8443" -cert "$W/mask.pem" -key "$W/mask.key" \
    -tls1_3 -alpn h2,http/1.1 -www -quiet
# Цель и цели пробы узла.
bg_in "$NSS" "$W/target.log" python3 tests/grpc-target.py "$TARGET" 8080
bg_in "$NSS" "$W/probe1.log" python3 tests/grpc-target.py 1.1.1.1 80
bg_in "$NSS" "$W/probe2.log" python3 tests/grpc-target.py 8.8.8.8 80
# Счётчик SYN к узлу — сколько соединений TCP открыто за прогон (только для печати; нет nft — без него).
if command -v nft >/dev/null 2>&1; then
    ip netns exec "$NSS" nft -f - >/dev/null 2>&1 <<NFT || true
table inet grpccnt { chain in { type filter hook input priority -300; policy accept;
    iifname "grs0" tcp dport $PORT tcp flags & (syn | ack) == syn counter comment "syn" } }
NFT
fi

FAIL=0
# Один случай: NET (streamSettings без security), SEC (reality | tls), Q (параметры транспорта ссылки).
# Умолчания — у самого Xray.
case_cfg() {
    SEC=reality
    XP='{"path":"/xp/"}'
    case "$1" in
    grpc-gun|grpc-multi)
        m=${1#grpc-}; multi=false; [ "$m" = multi ] && multi=true
        NET="\"network\":\"grpc\",\"grpcSettings\":{\"serviceName\":\"$SVC\",\"multiMode\":$multi}"
        Q="type=grpc&serviceName=$SVC&mode=$m" ;;
    xhttp-auto)        Q="type=xhttp&path=%2Fxp%2F" ;;
    xhttp-stream-one|xhttp-stream-up|xhttp-packet-up)
                       Q="type=xhttp&path=%2Fxp%2F&mode=${1#xhttp-}" ;;
    # TLS вместо Reality: клиент сверяет сертификат узла по отпечатку (pcs).
    xhttp-tls)         SEC=tls; Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    # auto решается как у клиента Xray: packet-up при TLS, stream-one при Reality. Сервер, настроенный
    # на один режим, отвечает на остальные 400 (hub.go), так что неверный выбор падает здесь.
    xhttp-auto-tls)    SEC=tls; XP='{"path":"/xp/","mode":"packet-up"}'
                       Q="type=xhttp&path=%2Fxp%2F" ;;
    xhttp-auto-one)    XP='{"path":"/xp/","mode":"stream-one"}'; Q="type=xhttp&path=%2Fxp%2F" ;;
    # Сервер сверяет длину набивки со своим диапазоном: ссылка несёт его в extra.
    xhttp-padding)     XP='{"path":"/xp/","xPaddingBytes":"20-40"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%2220-40%22%7D" ;;
    # host задан на сервере: запросы обязаны его называть.
    xhttp-host)        XP='{"path":"/xp/","host":"cdn.xhttp.test"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up&host=cdn.xhttp.test" ;;
    # Путь без завершающего слэша, как его пишут панели.
    xhttp-path)        XP='{"path":"/a/b"}'; Q="type=xhttp&path=%2Fa%2Fb&mode=packet-up" ;;
    # stream-up: сервер пишет набивку в ответ выгрузки раз в 1-2 с.
    xhttp-up-secs)     XP='{"path":"/xp/","scStreamUpServerSecs":"1-2"}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=stream-up" ;;
    xhttp-no-sse)      XP='{"path":"/xp/","noSSEHeader":true}'; Q="type=xhttp&path=%2Fxp%2F&mode=packet-up" ;;
    # packet-up: сервер ограничивает тело каждого POST; ссылка называет предел.
    xhttp-post-max)    XP='{"path":"/xp/","scMaxEachPostBytes":4096}'
                       Q="type=xhttp&path=%2Fxp%2F&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A4096%7D" ;;
    *) echo "run-grpc: неизвестный случай $1"; exit 2 ;;
    esac
    case "$1" in xhttp-*) NET="\"network\":\"xhttp\",\"xhttpSettings\":$XP" ;; esac
    if [ "$SEC" = reality ]; then
        SECJ="\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$S_IP:8443\",\"xver\":0,\"serverNames\":[\"$MASK\"],\"privateKey\":\"$PRIV\",\"shortIds\":[\"$SID\"]}"
        LSEC="security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome"
    else
        SECJ="\"security\":\"tls\",\"tlsSettings\":{\"alpn\":[\"h2\",\"http/1.1\"],\"certificates\":[{\"certificateFile\":\"$W/mask.pem\",\"keyFile\":\"$W/mask.key\"}]}"
        PCS=$(openssl x509 -in "$W/mask.pem" -noout -fingerprint -sha256 | cut -d= -f2)
        LSEC="security=tls&sni=$MASK&alpn=h2&fp=chrome&pcs=$PCS"
    fi
}

for MODE in $CASES; do
    case_cfg "$MODE"
    echo "run-grpc: ==== случай $MODE ===="
    cat > "$W/xray.json" <<JSON
{"log":{"loglevel":"warning","access":"$W/xray-access-$MODE.log"},
 "inbounds":[{"listen":"$S_IP","port":$PORT,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
   "streamSettings":{$NET,$SECJ}}],
 "outbounds":[{"protocol":"freedom","tag":"direct"}]}
JSON
    ip netns exec "$NSS" "$XRAY" run -c "$W/xray.json" > "$W/xray-$MODE.log" 2>&1 &
    XPID=$!; PIDS="$PIDS $XPID"
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
    ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " || { echo "run-grpc: Xray не поднялся:"; tail -5 "$W/xray-$MODE.log"; exit 1; }

    printf '%s\n' "vless://$UUID@$S_IP:$PORT?encryption=none&$Q&$LSEC#$MODE" > "$W/sub.txt"
    # interval: 10 — сторож проверяет узел каждые 10 секунд, а не раз в минуту: за прогон набирается около 19
    # проверок, и ложное «узел мёртв» (две неудачи подряд) не придётся ждать.
    cat > "$W/spec.yaml" <<SPEC
version: 2
outputs:
  vl: { kind: tunnel, protocol: vless, subscription: $W/sub.txt, interval: 10 }
SPEC

    # Прогрев: самое первое соединение с только что запущенным Xray у Reality бывает долгим (сервер при первом
    # рукопожатии ещё поднимает своё; у `openssl s_server` в роли маскировочного сайта — тем более), и проба на
    # нём молчит до срока. Это свойство стенда, а не клиента, поэтому ждём первого ответа (не дольше минуты),
    # и счёт отказов начинается только после него.
    warm=0
    for _ in $(seq 12); do
        out=$(LD_LIBRARY_PATH="$LIBS" ip netns exec "$NSC" "$LIBS/steer-vless" vless-probe "$W/sub.txt" --node 0 --timeout 5 2>&1 || true)
        if printf '%s' "$out" | grep -q '"ok":true'; then warm=1; break; fi
        sleep 1
    done
    [ "$warm" -eq 1 ] || { echo "run-grpc: ПРОВАЛ — узел не ответил на проверку за минуту: $(printf '%s' "$out" | grep -o '"why":"[^"]*"' | head -1)"; FAIL=1; kill "$XPID" 2>/dev/null || true; continue; }

    # 1. Проба узла: 30 раз. С прежним кодом отказывала большая часть.
    ok=0; bad=0
    for i in $(seq 30); do
        out=$(LD_LIBRARY_PATH="$LIBS" ip netns exec "$NSC" "$LIBS/steer-vless" vless-probe "$W/sub.txt" --node 0 --timeout 5 2>&1 || true)
        if printf '%s' "$out" | grep -q '"ok":true'; then ok=$((ok + 1)); else
            bad=$((bad + 1)); LAST="$out"
            echo "run-grpc:   проба $i: $(printf '%s' "$out" | grep -o '"why":"[^"]*"' | head -1)"
        fi
    done
    echo "run-grpc: проба узла: ok $ok, отказов $bad"
    if [ "$bad" -ne 0 ]; then
        echo "run-grpc: ПРОВАЛ — проба отказывает на исправном узле: $(printf '%s' "$LAST" | grep -o '"why":"[^"]*"' | head -1)"
        FAIL=1; kill "$XPID" 2>/dev/null || true; continue
    fi

    # 2-3. Туннель и нагрузка.
    mkdir -p "$W/state"
    LD_LIBRARY_PATH="$LIBS" ip netns exec "$NSC" "$LIBS/steer-vless" vless vl \
        --spec "$W/spec.yaml" --state-dir "$W/state" > "$W/steer-$MODE.log" 2>&1 &
    SPID=$!; PIDS="$PIDS $SPID"
    for _ in $(seq 60); do ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 && break; sleep 0.25; done
    ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 || {
        echo "run-grpc: ПРОВАЛ — туннель vl не поднялся:"; tail -8 "$W/steer-$MODE.log"; FAIL=1
        kill "$SPID" "$XPID" 2>/dev/null || true; continue; }
    ip netns exec "$NSC" ip route replace "$TARGET/32" dev vl
    echo "run-grpc: туннель поднят, нагрузка $DUR с (два потока вниз, два вверх, страницы по 10/с)"

    rc=0
    ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TARGET:8080" --dur "$DUR" \
        --down 2 --up 2 --rate 10 --report 10 || rc=$?

    # Что видела панель: узел объявлен мёртвым, соединения сброшены, поток к узлу не открылся.
    # ... или узел не принял выгруженные данные (xhttp: 413 сверх scMaxEachPostBytes, 400 на набивку).
    bad_log=$(grep -E "не отвечает|ищу замену|не открылся|снова отвечает|не принял данные" "$W/steer-$MODE.log" || true)
    if [ -n "$bad_log" ]; then
        echo "run-grpc: ПРОВАЛ — сторож объявлял узел мёртвым, поток не открывался или данные были отвергнуты:"
        printf '%s\n' "$bad_log" | head -5 | sed 's/^/    /'
        rc=1
    fi
    if command -v nft >/dev/null 2>&1; then
        syns=$(ip netns exec "$NSS" nft list chain inet grpccnt in 2>/dev/null | sed -n 's/.*packets \([0-9]*\) .*comment "syn".*/\1/p')
        [ -n "$syns" ] && echo "run-grpc: соединений TCP к узлу за случай: $syns"
    fi
    kill "$SPID" 2>/dev/null || true
    sleep 0.5
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
    kill "$XPID" 2>/dev/null || true
    sleep 0.5
    if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-grpc: случай $MODE — ПРОВАЛ"; else echo "run-grpc: случай $MODE — ok"; fi
done

[ "$FAIL" -eq 0 ] && echo "run-grpc: все проверки прошли" || echo "run-grpc: ЕСТЬ ПРОВАЛЫ"
exit "$FAIL"
