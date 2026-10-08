#!/bin/sh
# Сквозной стенд hysteria2: клиент steer-hysteria2 против НАСТОЯЩЕГО сервера apernet/hysteria
# (образ tobyxdd/hysteria:v2, бинарник берётся из него) — то есть независимой реализации
# протокола на quic-go. Этот же прогон — сверка нашей обёртки QUIC (ngtcp2 + wolfSSL + Brutal)
# с quic-go: рукопожатие, ALPN h3, датаграммы RFC 9221, потоки, окна, Brutal, Salamander.
#
# Что проверяется:
#   1. авторизация (233) и проба узла; неверный пароль — отказ С ПРИЧИНОЙ (HTTP 404 маскировки);
#   2. TCP через туннель (curl в сетевом пространстве клиента → цель за сервером): хеш файла
#      8 МиБ, загрузка на сервер (PUT), несколько соединений разом;
#   3. UDP: ответ DNS через туннель, эхо на 1 байт, 1200 и 3000 байт (фрагментация), крупные 4097, 20000 и 60000 байт к цели;
#   4. Salamander: совпавший пароль работает, несовпавший и «одна сторона без obfs» — нет;
#   5. pinSHA256: верный отпечаток проходит, неверный — отказ с причиной; без insecure и без
#      отпечатка самоподписанный сертификат отвергается;
#   6. прыжки по портам: сервер слушает один порт, диапазон заворачивает nft в его сетевом
#      пространстве; проверяется, что клиент ходит на несколько портов диапазона и трафик не рвётся;
#   7. режим перегрузки: ответ сервера «auto» (ignoreClientBandwidth) и предел сервера.
#   8. выгрузка на пределе (tests/hy2-flow.py): без останова и без провалов — стек подтверждает
#      данные клиента по готовности очереди к мультиплексору (DC_ACK_PACED);
#   9. скачивание медленным читателем: читатель идёт в своём темпе (обновление окна QUIC доходит до
#      сервера), память модуля ограничена окном, данные приходят без искажений;
# С параметром `bench` — ещё замер скорости на netem с потерями: BBR против Brutal.
#
# Всё в сетевых пространствах (клиент hy2c, сервер и цели hy2s, связаны veth): правил и маршрутов
# хоста стенд не трогает. Нужны: root, ip netns, /dev/net/tun, openssl, python3, curl и бинарник
# сервера (HY2_SERVER, иначе извлекается из образа tobyxdd/hysteria:v2 через docker create/cp).
# Клиент — раскладка libs (LIBS, по умолчанию build/libs-host; её собирает tests/libs-test.sh).
#
# Использование: tests/run-hy2.sh [bench]
set -u
cd "$(dirname "$0")/.."

LIBS="${LIBS:-build/libs-host}"
MOD="$LIBS/steer-hysteria2"
[ -x "$MOD" ] || { echo "run-hy2: нет $MOD (сначала tests/libs-test.sh) — ПРОПУСК"; exit 0; }
WORK="$(mktemp -d)"
NSC=hy2c
NSS=hy2s
SIP=10.66.0.1
CIP=10.66.0.2
TARGET=203.0.113.7
pass=0; fail=0
SRV_PID=""; CLI_PID=""; TGT_PID=""

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "  ok   $1"; else
        fail=$((fail + 1)); printf '  FAIL %s\n    ожидалось: %s\n    получено:  %s\n' "$1" "$2" "$3"
    fi
}
contains() {   # ИМЯ ТЕКСТ ОБРАЗЕЦ
    case "$2" in *"$3"*) pass=$((pass + 1)); echo "  ok   $1" ;; *)
        fail=$((fail + 1)); printf '  FAIL %s\n    в выводе нет «%s»:\n%s\n' "$1" "$3" "$(printf '%s' "$2" | sed 's/^/      /' | head -12)" ;; esac
}

cleanup() {
    stop_client
    stop_server
    [ -n "$TGT_PID" ] && kill "$TGT_PID" 2>/dev/null
    ip netns pids "$NSC" 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids "$NSS" 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns delete "$NSC" 2>/dev/null
    ip netns delete "$NSS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ---- бинарник сервера ------------------------------------------------------------------------
HY2="${HY2_SERVER:-}"
if [ -z "$HY2" ]; then
    HY2="$WORK/hysteria"
    if command -v docker >/dev/null 2>&1 && docker image inspect tobyxdd/hysteria:v2 >/dev/null 2>&1; then
        c="hy2-extract-$$"
        docker create --name "$c" tobyxdd/hysteria:v2 >/dev/null 2>&1 &&
            docker cp "$c:/usr/local/bin/hysteria" "$HY2" >/dev/null 2>&1
        docker rm "$c" >/dev/null 2>&1
    fi
fi
[ -x "$HY2" ] || { echo "run-hy2: нет бинарника сервера hysteria (HY2_SERVER или образ tobyxdd/hysteria:v2) — ПРОПУСК"; exit 0; }

# ---- сеть ------------------------------------------------------------------------------------
ip netns delete "$NSC" 2>/dev/null; ip netns delete "$NSS" 2>/dev/null
ip netns add "$NSC" && ip netns add "$NSS" || { echo "run-hy2: нет прав на ip netns — ПРОПУСК"; exit 0; }
ip netns exec "$NSC" ip link set lo up
ip netns exec "$NSS" ip link set lo up
ip link add hy2-c type veth peer name hy2-s
ip link set hy2-c netns "$NSC"; ip link set hy2-s netns "$NSS"
ip netns exec "$NSC" ip addr add "$CIP/24" dev hy2-c; ip netns exec "$NSC" ip link set hy2-c up
ip netns exec "$NSS" ip addr add "$SIP/24" dev hy2-s; ip netns exec "$NSS" ip link set hy2-s up
# Цель — адрес на lo сервера: у клиента маршрута к нему нет, кроме устройства туннеля.
ip netns exec "$NSS" ip addr add "$TARGET/32" dev lo

nsc() { ip netns exec "$NSC" "$@"; }
nss() { ip netns exec "$NSS" "$@"; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=hy2.test" \
    -addext "subjectAltName=DNS:hy2.test,IP:$SIP" >/dev/null 2>&1
PIN="$(openssl x509 -in "$WORK/cert.pem" -outform der | sha256sum | cut -d' ' -f1)"

mkdir -p "$WORK/www"
# Фоновые процессы — прямым `ip netns exec`, а не через функцию nss/nsc: функция в фоне порождает
# подоболочку, $! называет её, а не процесс, и kill убивал бы оболочку, оставляя сервер жить.
ip netns exec "$NSS" python3 tests/hy2-targets.py --ip "$TARGET" --dir "$WORK/www" --mb 8 > "$WORK/targets.log" 2>&1 &
TGT_PID=$!
for _ in $(seq 50); do grep -q ready "$WORK/targets.log" 2>/dev/null && break; sleep 0.2; done
WANT_SHA="$(cat "$WORK/www/big.sha256" 2>/dev/null)"

# ---- сервер ----------------------------------------------------------------------------------
# start_server ИМЯ [дополнительные строки yaml]: пароль hunter2.
start_server() {
    stop_server
    {
        echo "listen: $SIP:4433"
        echo "tls: { cert: $WORK/cert.pem, key: $WORK/key.pem${TLS_EXTRA:-} }"
        echo "auth: { type: password, password: hunter2 }"
        [ -n "${1:-}" ] && printf '%s\n' "$1"
    } > "$WORK/server.yaml"
    ip netns exec "$NSS" "$HY2" server -c "$WORK/server.yaml" > "$WORK/server.log" 2>&1 &
    SRV_PID=$!
    for _ in $(seq 50); do
        nss ss -ulnH 2>/dev/null | grep -q ":4433 " && return 0
        sleep 0.1
    done
    echo "  сервер не поднялся:"; sed 's/^/    /' "$WORK/server.log" | head -5
    return 1
}
stop_server() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
}

# ---- клиент ----------------------------------------------------------------------------------
# write_sub ССЫЛКА: подписка и спека v1 с выходом hy (kind hysteria2).
write_sub() {
    printf '%s\n' "$1" > "$WORK/sub.txt"
    cat > "$WORK/spec.json" <<SPEC
{"schema":1,
 "outputs":{"hy":{"name":"hy","kind":"hysteria2","sub_file":"$WORK/sub.txt","node":0}},
 "channels":[]}
SPEC
}
mod() { nsc env LD_LIBRARY_PATH="$LIBS" "$MOD" "$@"; }
start_client() {
    stop_client
    rm -rf "$WORK/state"
    ip netns exec "$NSC" env LD_LIBRARY_PATH="$LIBS" STEER_TUN_STATS=1 "$MOD" hysteria2 hy --spec "$WORK/spec.json" \
        --state-dir "$WORK/state" > "$WORK/client.log" 2>&1 &
    CLI_PID=$!
    for _ in $(seq 60); do
        nsc ip link show hy >/dev/null 2>&1 && break
        kill -0 "$CLI_PID" 2>/dev/null || break
        sleep 0.2
    done
    nsc ip link show hy >/dev/null 2>&1 || return 1
    nsc ip route replace "$TARGET/32" dev hy
    # Соединение с сервером поднимается сразу, но не мгновенно: ждём принятую авторизацию.
    for _ in $(seq 40); do grep -q "принял авторизацию" "$WORK/client.log" && return 0; sleep 0.1; done
    return 0
}
stop_client() {
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null && wait "$CLI_PID" 2>/dev/null
    CLI_PID=""
    nsc ip link del hy 2>/dev/null
}

URI="hysteria2://hunter2@$SIP:4433/?insecure=1"
echo "run-hy2: сервер $("$HY2" version 2>/dev/null | grep -i '^version' | head -1)"

# ---- 1. проба и авторизация -------------------------------------------------------------------
echo "1. авторизация"
start_server "" || exit 1
write_sub "$URI#ok"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "проба: узел принял" "$out" '"ok":true'
contains "  и назвал задержку" "$out" '"handshake_ms":'
write_sub "hysteria2://wrong@$SIP:4433/?insecure=1#bad"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "неверный пароль: отказ" "$out" '"ok":false'
contains "  с причиной (HTTP-ответ маскировки)" "$out" 'отказал в авторизации (HTTP 404)'

# ---- 2. TCP и UDP -----------------------------------------------------------------------------
echo "2. TCP и UDP"
write_sub "$URI#ok"
start_client || { echo "  клиент не поднялся:"; sed 's/^/    /' "$WORK/client.log" | head; }
got="$(nsc curl -s -m 60 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "TCP: файл 8 МиБ прошёл целиком (хеш)" "$WANT_SHA" "$got"
head -c 3000000 /dev/zero > "$WORK/up.bin"
check "TCP: загрузка на сервер (PUT) 3000000 байт" "3000000" "$(nsc curl -s -m 60 -T "$WORK/up.bin" "http://$TARGET/up")"
nsc sh -c "for i in 1 2 3 4 5 6; do curl -s -m 60 http://$TARGET/big.bin | sha256sum & done; wait" > "$WORK/par.txt"
check "TCP: шесть соединений разом, все хеши верны" "6" "$(grep -c "^$WANT_SHA" "$WORK/par.txt")"
dns="$(nsc dig +short +time=3 +tries=1 @"$TARGET" -p 53 x.test A 2>&1)"
check "UDP: DNS через туннель" "192.0.2.53" "$dns"
udp_echo() {  # размер
    nsc python3 - "$TARGET" "$1" <<'PY'
import socket, sys, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
d = os.urandom(int(sys.argv[2]))
s.sendto(d, (sys.argv[1], 7))
try:
    r, _ = s.recvfrom(65535)
    print("same" if r == d else "differ")
except Exception as e:
    print("none")
PY
}
check "UDP: эхо 1 байт" "same" "$(udp_echo 1)"
check "UDP: эхо 1200 байт" "same" "$(udp_echo 1200)"
check "UDP: эхо 3000 байт (фрагментация в обе стороны)" "same" "$(udp_echo 3000)"
# Крупные датаграммы ТУДА: цель на порту 9 отвечает суммой принятого. Эхо здесь не годится — эталонный
# сервер apernet ответа от 4096 байт клиенту не возвращает (проверено: 4000 байт эхо идёт, 4096 нет),
# хотя датаграмма до цели дошла.
udp_sum() {  # размер
    nsc python3 - "$TARGET" "$1" <<'PY'
import socket, sys, os, hashlib
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
d = os.urandom(int(sys.argv[2]))
s.sendto(d, (sys.argv[1], 9))
try:
    r, _ = s.recvfrom(65535)
    print("same" if r == hashlib.sha256(d).hexdigest().encode() + b" %d" % len(d) else "differ")
except Exception:
    print("none")
PY
}
check "UDP: 4097 байт к цели целиком (выше прежнего предела 4096)" "same" "$(udp_sum 4097)"
check "UDP: 20000 байт к цели целиком (первая датаграма нового потока)" "same" "$(udp_sum 20000)"
check "UDP: 60000 байт к цели целиком" "same" "$(udp_sum 60000)"
# Залп в новый поток: первые датаграммы приходят, пока поток к узлу ещё открывается, и стек их
# придерживает. Уйти серверу они обязаны по одной — склеенные, они приходили одной датаграммой
# (у QUIC — два Initial или Initial с 0-RTT одним куском больше 2400 байт).
burst="$(nsc python3 - "$TARGET" <<'PY'
import socket, sys, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
for n in (1000, 2300, 3000):
    s.sendto(os.urandom(n), (sys.argv[1], 7))
got = []
try:
    while len(got) < 3:
        r, _ = s.recvfrom(65535)
        got.append(len(r))
except Exception:
    pass
print(" ".join(map(str, sorted(got))))
PY
)"
check "UDP: залп 1000+2300+3000 в новый поток — три датаграммы, а не склейка" "1000 2300 3000" "$burst"
st="$(cat "$WORK/state/../state/hy2-hy" 2>/dev/null || true)"
sleep 3.5
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "файл состояния: соединение поднято" "$st" '"up":true'
contains "  режим перегрузки BBR (up в ссылке не задан)" "$st" '"cc":"bbr"'
contains "  UDP разрешён сервером" "$st" '"udp":true'
stop_client

# ---- 3. Salamander ----------------------------------------------------------------------------
echo "3. Salamander"
start_server "obfs: { type: salamander, salamander: { password: obfspass1 } }" || exit 1
write_sub "$URI&obfs=salamander&obfs-password=obfspass1#s"
start_client
got="$(nsc curl -s -m 30 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "salamander: файл прошёл" "$WANT_SHA" "$got"
contains "  и журнал называет обфускацию" "$(cat "$WORK/client.log")" "Salamander"
stop_client
write_sub "$URI&obfs=salamander&obfs-password=wrongpass#s"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --timeout 4 --state-dir "$WORK/state" 2>&1)"
contains "salamander: чужой пароль — отказ" "$out" '"ok":false'
write_sub "$URI#plain"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --timeout 4 --state-dir "$WORK/state" 2>&1)"
contains "salamander: сервер с obfs, клиент без — отказ" "$out" '"ok":false'
start_server "" || exit 1
write_sub "$URI&obfs=salamander&obfs-password=obfspass1#s"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --timeout 4 --state-dir "$WORK/state" 2>&1)"
contains "salamander: клиент с obfs, сервер без — отказ" "$out" '"ok":false'

# Gecko — Salamander плюс нарезка пакетов рукопожатия (extras/obfs эталона): рукопожатие, TCP и UDP
# через него; неверный пароль — отказ; Salamander против Gecko-сервера не срабатывает.
echo "3б. Gecko"
start_server "obfs: { type: gecko, gecko: { password: geckopass1 } }" || exit 1
write_sub "$URI&obfs=gecko&obfs-password=geckopass1#g"
start_client
got="$(nsc curl -s -m 30 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "gecko: файл прошёл" "$WANT_SHA" "$got"
check "  и UDP (эхо 3000 байт)" "same" "$(udp_echo 3000)"
contains "  журнал называет Gecko" "$(cat "$WORK/client.log")" "Gecko"
stop_client
write_sub "$URI&obfs=gecko&obfs-password=wrongpass#g"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --timeout 4 --state-dir "$WORK/state" 2>&1)"
contains "gecko: чужой пароль — отказ" "$out" '"ok":false'
write_sub "$URI&obfs=salamander&obfs-password=geckopass1#s"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --timeout 4 --state-dir "$WORK/state" 2>&1)"
contains "gecko-сервер, клиент с salamander — отказ" "$out" '"ok":false'
start_server "" || exit 1

# ---- 4. pinSHA256 и проверка сертификата ---------------------------------------------------------
echo "4. сертификат"
write_sub "hysteria2://hunter2@$SIP:4433/?pinSHA256=$PIN&sni=hy2.test#pin"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "pinSHA256 верный: узел принят" "$out" '"ok":true'
write_sub "hysteria2://hunter2@$SIP:4433/?pinSHA256=$(printf '%064d' 0)&sni=hy2.test#pin"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "pinSHA256 чужой: отказ" "$out" '"ok":false'
contains "  с причиной" "$out" 'не совпал с pinSHA256'
write_sub "hysteria2://hunter2@$SIP:4433/?sni=hy2.test#nocheck"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "самоподписанный без insecure и без отпечатка: отказ" "$out" '"ok":false'
# sni — адрес, а не имя (так Xray раздаёт узлы с сертификатом на IP): SNI не уходит, сертификат
# сверяется с SAN IP. Прежде клиент отказывал ещё до первого пакета («QUIC не открылся (-4)»), здесь
# рукопожатие обязано дойти до проверки сертификата — самоподписанный без insecure она не пропускает.
write_sub "hysteria2://hunter2@$SIP:4433/?sni=$SIP&alpn=h3#ipsni"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "sni=адрес: отказ проверкой сертификата" "$out" '"ok":false'
case "$out" in *"QUIC не открылся"*) fail=$((fail + 1)); echo "  FAIL sni=адрес: QUIC не открылся до первого пакета";;
    *) pass=$((pass + 1)); echo "  ok   sni=адрес: QUIC открылся, SNI-адрес не роняет TLS";; esac
write_sub "hysteria2://hunter2@$SIP:4433/?sni=$SIP&alpn=h3&pinSHA256=$PIN#ippin"
out="$(mod hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
contains "sni=адрес и pinSHA256: узел принят" "$out" '"ok":true'
# Хост — адрес, sni нет: имя сверяется с адресом (SAN IP), как у эталона (Go кладёт хост в ServerName,
# адрес в нём — проверка по SAN IP). Прежде без sni у адреса имени не проверял никто, и годился
# сертификат любого имени, подписанный признанным корнем. Корни — свой файл поверх системного в своём
# пространстве монтирования: иначе проверку имени не отличить от отказа цепочки.
modca() {  # ФАЙЛ_КОРНЕЙ АРГУМЕНТЫ...
    _ca="$1"; shift
    ip netns exec "$NSC" unshare -m sh -c 'mount --bind "$0" /etc/ssl/certs/ca-certificates.crt && shift && exec "$@"' \
        "$_ca" x env LD_LIBRARY_PATH="$LIBS" "$MOD" "$@"
}
if [ -f /etc/ssl/certs/ca-certificates.crt ] && command -v unshare >/dev/null 2>&1; then
    cp "$WORK/cert.pem" "$WORK/cert-ip.pem"; cp "$WORK/key.pem" "$WORK/key-ip.pem"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
        -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=hy2.test" \
        -addext "subjectAltName=DNS:hy2.test" >/dev/null 2>&1
    # sniGuard сервера apernet по умолчанию закрывает соединение без SNI к сертификату на одно имя, — и
    # отказ пришёл бы от сервера, а не от проверки клиента.
    TLS_EXTRA=", sniGuard: disable"
    start_server "" || exit 1
    write_sub "hysteria2://hunter2@$SIP:4433/#ipnosni"
    out="$(modca "$WORK/cert.pem" hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
    contains "адрес без sni, в сертификате только имя: отказ" "$out" '"ok":false'
    write_sub "hysteria2://hunter2@$SIP:4433/?sni=hy2.test#dnsni"
    out="$(modca "$WORK/cert.pem" hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
    contains "  тот же сервер с sni=hy2.test: принят (корни из своего файла)" "$out" '"ok":true'
    cp "$WORK/cert-ip.pem" "$WORK/cert.pem"; cp "$WORK/key-ip.pem" "$WORK/key.pem"
    start_server "" || exit 1
    TLS_EXTRA=""
    write_sub "hysteria2://hunter2@$SIP:4433/#ipsan"
    out="$(modca "$WORK/cert.pem" hysteria2-probe hy --spec "$WORK/spec.json" --state-dir "$WORK/state" 2>&1)"
    contains "адрес без sni, адрес в SAN IP: принят" "$out" '"ok":true'
else
    echo "  пропуск: нет /etc/ssl/certs/ca-certificates.crt или unshare — проверка имени по адресу"
fi

# ---- 5. режим перегрузки ------------------------------------------------------------------------
echo "5. режим перегрузки"
start_server "ignoreClientBandwidth: true" || exit 1
write_sub "$URI&up=100&down=100#brutal"
start_client
sleep 3.5
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "сервер ответил auto (ignoreClientBandwidth): клиент перешёл с Brutal на BBR" "$st" '"cc":"bbr"'
got="$(nsc curl -s -m 30 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "  файл прошёл" "$WANT_SHA" "$got"
stop_client
start_server "bandwidth: { up: 50 mbps, down: 50 mbps }" || exit 1
start_client
sleep 3.5
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "предел сервера 50 Мбит/с, up клиента 100: Brutal на 50 (6250000 байт/с)" "$st" '"brutal_bps":6250000'
got="$(nsc curl -s -m 30 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "  файл прошёл" "$WANT_SHA" "$got"
stop_client
start_server "" || exit 1
start_client
sleep 3.5
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "сервер без предела (0): Brutal на своём up (12500000 байт/с)" "$st" '"brutal_bps":12500000'
stop_client

# ---- 6. прыжки по портам --------------------------------------------------------------------------
echo "6. прыжки по портам"
start_server "" || exit 1
nss nft add table ip hop
nss nft add chain ip hop pre '{ type nat hook prerouting priority dstnat; }'
nss nft add rule ip hop pre iifname hy2-s udp dport 20000-20099 counter redirect to :4433
write_sub "hysteria2://hunter2@$SIP:20000/?insecure=1&mport=20000-20099&hop-interval=5#hop"
start_client
# Порты, на которые ходил клиент, — из conntrack нельзя (нет утилиты), поэтому считаем сегменты
# диапазона счётчиками nft: по одному правилу на каждые десять портов.
nss nft add chain ip hop pre2 '{ type filter hook prerouting priority -300; }'
for b in 0 1 2 3 4 5 6 7 8 9; do
    nss nft add rule ip hop pre2 iifname hy2-s udp dport "200${b}0-200${b}9" counter
done
# Период прыжка 5 с, порт выбирается из ста, участков десять: за полминуты смен набирается около
# пяти, и вероятность, что все они упали в один участок, — порядка 10^-4 (в четыре загрузки за 15 с
# стенд был флаковым).
nsc sh -c "for i in 1 2 3 4 5 6 7; do curl -s -m 40 http://$TARGET/big.bin | sha256sum; sleep 4; done" > "$WORK/hop.txt"
check "прыжки: 7 загрузок за ~30 с, все хеши верны" "7" "$(grep -c "^$WANT_SHA" "$WORK/hop.txt")"
seg="$(nss nft list chain ip hop pre2 | grep -c 'packets [1-9]')"
[ "$seg" -ge 2 ] && seg=">=2" || seg="$seg"
check "  клиент ходил на несколько участков диапазона" ">=2" "$seg"
stop_client

# ---- 7. соединение без потоков ------------------------------------------------------------------
# Туннель, через который сейчас ничего не идёт (группа выбрала другой выход, ночь), обязан держать
# соединение с узлом: прежде клиент закрывал его через 60 с без потоков, следующий поток платил
# рукопожатием, диагностика показывала «соединение не поднято», а замер задержки группы ловил то
# рукопожатие и прыгал втрое (живой роутер: переподключение раз в 1,5–3 минуты). И сервер со сроком
# простоя короче нашего PING (у apernet от 4 с) не должен ронять соединение: PING — чаще его срока.
echo "7. соединение без потоков"
auths() { grep -c "принял авторизацию" "$WORK/client.log"; }
start_server "" || exit 1
write_sub "$URI#idle"
start_client
sleep 75
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "75 с без потоков: соединение поднято" "$st" '"up":true'
check "  и не переподключалось (одна авторизация)" "1" "$(auths)"
got="$(nsc curl -s -m 30 "http://$TARGET/big.bin" | sha256sum | cut -d' ' -f1)"
check "  поток после простоя идёт по тому же соединению" "$WANT_SHA" "$got"
check "  без новой авторизации" "1" "$(auths)"
# Узел пропал и вернулся: соединение поднимается само, не дожидаясь потока клиента (иначе туннель
# без трафика так и показывал бы «не поднято», пока его не спросят).
stop_server
sleep 4
start_server "" || exit 1
for _ in $(seq 100); do [ "$(auths)" -ge 2 ] && break; sleep 0.5; done
sleep 3.5
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
check "сервер перезапущен: соединение поднялось само, без потока" "2" "$(auths)"
contains "  и файл состояния говорит «поднято»" "$st" '"up":true'
stop_client
start_server "quic: { maxIdleTimeout: 5s }" || exit 1
start_client
sleep 25
st="$(cat "$WORK/state/hy2-hy" 2>/dev/null)"
contains "сервер со сроком простоя 5 с, 25 с без потоков: соединение поднято" "$st" '"up":true'
check "  и не переподключалось" "1" "$(auths)"
stop_client

# ---- 8. обратное давление: выгрузка на пределе --------------------------------------------------
# Выгрузка в туннель быстрее, чем мультиплексор успевает шифровать и слать, прежде вставала: стек
# подтверждал данные клиента, едва они ложились в очередь пары, окно клиента не менялось, и клиент
# лил в очередь на порядок быстрее, чем её разбирали. Очередь переполнялась, send отвечал SEND_AGAIN,
# стек пакет не подтверждал — и ВСЕ следующие пакеты окна приходили не по порядку и отбрасывались
# (переупорядочивания нет, SACK мы не шлём, повторное подтверждение одно на порцию): клиент шёл по
# одному сегменту за таймаут — 200 мс, потом вдвое, до секунд. Выше ~300 Мбит/с выгрузка через
# 1–4 секунды вставала на нулях (на этом стенде — на сотнях КБ в секунду вместо сотни МБ).
# Теперь стек не подтверждает, пока очередь пары не опустеет до нижней отметки (DC_ACK_PACED), и
# клиент идёт со скоростью мультиплексора — ровно, без потерь.
# Источник — tests/hy2-flow.py send без предела скорости (быстрее мультиплексора), приёмник считает
# принятое по секундам. Проверяется не скорость, которая от машины зависит, а то, что выгрузка
# идёт ровно: медиана секунд не ниже 4 МиБ/с (останов даёт нули и сотни КБ), и ни одна секунда не
# проваливается ниже четверти медианы. Первые две секунды (разгон) и последняя (хвост) не в счёт.
echo "8. выгрузка на пределе: без останова и без провалов"
start_server "" || exit 1
write_sub "$URI#flow"
start_client || { echo "  клиент не поднялся:"; sed 's/^/    /' "$WORK/client.log" | head; }
flow_up() {  # ИМЯ ПОТОКОВ СЕКУНД ПЕРЕГРУЗКА
    rm -f "$WORK/sink.log"
    ip netns exec "$NSS" python3 tests/hy2-flow.py sink --ip "$TARGET" --port 5001 --log "$WORK/sink.log" > "$WORK/sink.out" 2>&1 &
    _sink=$!
    for _ in $(seq 50); do grep -q ready "$WORK/sink.out" 2>/dev/null && break; sleep 0.1; done
    nsc python3 tests/hy2-flow.py send --ip "$TARGET" --port 5001 --secs "$3" --conns "$2" ${4:+--cc "$4"} > "$WORK/send.out" 2>&1
    sleep 1.5
    kill "$_sink" 2>/dev/null; wait "$_sink" 2>/dev/null
    _n="$(wc -l < "$WORK/sink.log")"
    # КиБ в секунду по возрастанию: первый — минимум, средний — медиана.
    _v="$(awk -v n="$_n" 'NR > 2 && NR < n { printf "%d\n", $2 / 1024 }' "$WORK/sink.log" | sort -n)"
    _c="$(printf '%s\n' "$_v" | grep -c .)"
    _min="$(printf '%s\n' "$_v" | sed -n 1p)"
    _med="$(printf '%s\n' "$_v" | sed -n "$(( (_c + 1) / 2 ))p")"
    _min="${_min:-0}"; _med="${_med:-0}"
    [ "$_c" -ge 3 ] && [ "$_med" -ge 4096 ] && r=ok || r="медиана $(( _med / 1024 )) МиБ/с за $_c с"
    check "$1: идёт ровно, медиана не ниже 4 МиБ/с (медиана $(( _med / 1024 )) МиБ/с, $_c с)" "ok" "$r"
    [ "$_c" -ge 3 ] && [ $(( _min * 4 )) -ge "$_med" ] && r=ok || r="минимум $(( _min / 1024 )) МиБ/с при медиане $(( _med / 1024 )) МиБ/с"
    check "  и ни одна секунда не ниже четверти медианы (минимум $(( _min / 1024 )) МиБ/с)" "ok" "$r"
}
flow_up "выгрузка, 1 поток, 20 с" 1 20
flow_up "выгрузка, 8 потоков, 12 с" 8 12
if command -v sysctl >/dev/null 2>&1 && sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw cubic; then
    flow_up "выгрузка, 1 поток, CUBIC у клиента, 12 с" 1 12 cubic
fi
stop_client

# ---- 9. обратное давление: скачивание медленным читателем ------------------------------------
# Восемь потоков тянут из туннеля быстрее, чем клиент читает (темп чтения — --kbps на поток, сеть
# быстрее на порядки). Проверяется три вещи:
#   • читатель идёт в своём темпе. Обновление окна приёма QUIC (MAX_STREAM_DATA) прежде не уходило
#     к серверу, пока не случалось другое событие QUIC: сервер, остановленный окном, молчит, а
#     qc_stream_consumed пакета не писал, — и медленный клиент, прочитав восемь мегабайт, ждал
#     ближайшего PING (до десяти секунд): за 15 с он читал ~40 МБ из 480;
#   • память модуля ограничена окном QUIC, а не растёт с числом принятых байт. Очередь к клиенту
#     прежде была одним буфером, который возвращал отданное место, только пустея целиком, и под
#     непрерывной загрузкой раздувался с 14 до 700 МБ за двадцать секунд (роутеру с 128–256 МБ —
#     OOM). Предел: окно соединения 16 МиБ (RX_CONN_WIN в hy2conn.c) плюс 32 МиБ на всё остальное
#     (процесс, библиотеки, ngtcp2, фрагментация кучи) — 48 МиБ;
#   • данные приходят без искажений: образец сверяется побайтно, и перестановка, потеря или
#     двойная отдача куска очереди сбивают сверку.
echo "9. скачивание медленным читателем: темп, память, целостность"
start_server "" || exit 1
write_sub "$URI#slow"
start_client || { echo "  клиент не поднялся:"; sed 's/^/    /' "$WORK/client.log" | head; }
ip netns exec "$NSS" python3 tests/hy2-flow.py serve --ip "$TARGET" --port 5002 > "$WORK/serve.out" 2>&1 &
SRV2_PID=$!
for _ in $(seq 50); do grep -q ready "$WORK/serve.out" 2>/dev/null && break; sleep 0.1; done
rss_kb() { awk -v k="$2" '$1 == k ":" { print $2 }' "/proc/$1/status" 2>/dev/null; }
idle_kb="$(rss_kb "$CLI_PID" VmRSS)"
SLOW_KBPS=4000; SLOW_CONNS=8; SLOW_SECS=15
nsc python3 tests/hy2-flow.py slowread --ip "$TARGET" --port 5002 --secs "$SLOW_SECS" --conns "$SLOW_CONNS" --kbps "$SLOW_KBPS" > "$WORK/slow.out" 2>&1 &
RD_PID=$!
peak_kb=0
while kill -0 "$RD_PID" 2>/dev/null; do
    v="$(rss_kb "$CLI_PID" VmRSS)"
    [ -n "$v" ] && [ "$v" -gt "$peak_kb" ] && peak_kb="$v"
    sleep 0.5
done
wait "$RD_PID" 2>/dev/null
hwm_kb="$(rss_kb "$CLI_PID" VmHWM)"
kill "$SRV2_PID" 2>/dev/null; wait "$SRV2_PID" 2>/dev/null
read_b="$(sed -n 's/^read=\([0-9]*\) .*/\1/p' "$WORK/slow.out")"
bad="$(sed -n 's/.* bad=\([0-9]*\) .*/\1/p' "$WORK/slow.out")"
want_b=$(( SLOW_KBPS * 1000 * SLOW_CONNS * SLOW_SECS ))
# Не меньше 80% заданного темпа: читатель и был узким местом (иначе очередь не копилась бы).
[ "${read_b:-0}" -ge $(( want_b * 8 / 10 )) ] && r=ok || r="прочитано $(( ${read_b:-0} / 1000000 )) из $(( want_b / 1000000 )) МБ"
check "$SLOW_CONNS потоков, чтение $SLOW_KBPS КБ/с на поток: читатель идёт в своём темпе" "ok" "$r"
check "  данные пришли без искажений (сверка образца)" "0" "${bad:-нет вывода}"
[ "${hwm_kb:-999999999}" -le $(( 48 * 1024 )) ] && r=ok || r="пик ${hwm_kb:-?} КБ (покой ${idle_kb:-?} КБ)"
check "  пик памяти модуля не выше 48 МиБ (окно QUIC 16 МиБ и запас)" "ok" "$r"
echo "  память модуля: покой ${idle_kb:-?} КБ, VmHWM ${hwm_kb:-?} КБ (замеры раз в 0,5 с: ${peak_kb} КБ)"
stop_client

# ---- замер на потерях -------------------------------------------------------------------------
if [ "${1:-}" = bench ]; then
    echo "7. замер: 5% потерь, задержка 20 мс в каждую сторону"
    start_server "" || exit 1
    for ns in "$NSC" "$NSS"; do
        d=hy2-c; [ "$ns" = "$NSS" ] && d=hy2-s
        ip netns exec "$ns" tc qdisc replace dev "$d" root netem delay 20ms loss 5%
    done
    bench() {  # ИМЯ ССЫЛКА
        write_sub "$2"
        start_client
        d="$(nsc curl -s -m 120 -o /dev/null -w '%{speed_download}' "http://$TARGET/big.bin")"
        u="$(nsc curl -s -m 120 -o /dev/null -w '%{speed_upload}' -T "$WORK/up.bin" "http://$TARGET/up")"
        awk -v n="$1" -v d="$d" -v u="$u" 'BEGIN{printf "  %-34s загрузка %7.2f Мбит/с   выгрузка %7.2f Мбит/с\n", n, d*8/1e6, u*8/1e6}'
        stop_client
    }
    bench "BBR (up не задан)" "$URI#bbr"
    bench "Brutal up=down=100 Мбит/с" "$URI&up=100&down=100#br100"
    bench "Brutal up=down=20 Мбит/с" "$URI&up=20&down=20#br20"
    for ns in "$NSC" "$NSS"; do
        d=hy2-c; [ "$ns" = "$NSS" ] && d=hy2-s
        ip netns exec "$ns" tc qdisc del dev "$d" root 2>/dev/null
    done
fi

echo
echo "run-hy2: $pass проверок пройдено, провалено $fail"
[ "$fail" = 0 ]
