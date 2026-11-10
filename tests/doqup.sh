#!/bin/sh
# DoQ (DNS по QUIC, RFC 9250) в резолвере: настоящий QUIC, СЕРВЕР — НЕЗАВИСИМАЯ РЕАЛИЗАЦИЯ
# (AdGuard dnsproxy на quic-go), путь запроса через выход, bootstrap, кэш, обрыв соединения.
# Устройство проверяемого — src/dnsd/dup.c (раздел «DoQ»), кадры — src/dnsd/doq.h. Стенд не входит
# в `make test` (нужны root, пространства имён, nft, docker для получения сервера): запуск отдельный,
#
#     sh tests/doqup.sh                    проверки
#     DOQUP_BENCH=1 sh tests/doqup.sh      и замер (холодное/тёплое; потери — DOQUP_LOSS=3%)
#
# ЗАЧЕМ НЕЗАВИСИМЫЙ СЕРВЕР. Собственный сервер на той же обёртке QUIC проверил бы, что обёртка
# согласна сама с собой: одинаково понятая длина кадра, одинаково прочитанный ALPN. dnsproxy —
# чужая реализация протокола (quic-go, свой ngtcp2-независимый TLS 1.3 из стандартной библиотеки
# Go), и то, что она принимает наш запрос и мы принимаем её ответ, — сверка с RFC, а не с собой. Он
# же отдаёт по тому же сертификату DoT и DoH, поэтому замер честный: один сервер, три транспорта.
# Бинарник берётся из образа adguard/dnsproxy (тег steer-doqup-dnsproxy:v0.85.0) через
# `docker create`+`docker cp`: контейнер тут же удаляется, в систему ничего не ставится и сеть
# докера не участвует — запускается он в пространстве имён стенда. Готовый бинарник —
# DOQUP_DNSPROXY=/путь.
#
# Сеть — как у tests/dnsup.sh: роутер (сам стенд): wan0 (10.0.1.1) — «провайдер», tun0 (10.0.2.1) —
# устройство выхода `vpn`, настоящие правила из `steerd apply` со стражем postrouting_guard. Сервер S
# за ними: 192.0.2.53 (dnsproxy: обычный DNS 53, DoT 853/tcp, DoH 443, DoQ 853/udp) и 192.0.2.54
# (tests/dnsup-server.py — «настоящий» авторитетный сервер с зонами; dnsproxy пересылает ему).
# Клиента dnsproxy пишет в журнал (--verbose): по адресу клиента видно путь — 10.0.2.1 через выход,
# 10.0.1.1 напрямую; счётчики пакетов wan1 и tun1 в S — второе свидетельство.
#
# Что проверяется.
#  1. DoQ через выход: клиенту поддельный адрес, dnsproxy принял вопрос по QUIC с туннельного
#     адреса, в WAN ни пакета; bootstrap-имя сервера спрошено обычным DNS через выход.
#  2. Соединение одно и живёт: десятки вопросов подряд и сотня одновременных — все с ответом, в
#     dns-log conns=1 (потоки QUIC мультиплексируют, соединение на вопрос не заводится).
#  3. Без выхода — с адреса WAN. Кэш: повторный вопрос до сервера не доходит; fake-IP строгий.
#  4. Выход лёг: ни одного пакета в WAN, клиенту SERVFAIL; вернулся — работает.
#  5. Сервер перезапущен (соединение мертво: новый процесс не знает наших CID) — вопрос не пропал
#     насовсем, а дошёл на новом соединении; сервер лёг совсем — SERVFAIL за срок, не зависание, и
#     возврат после подъёма.
#  6. Имя в сертификате не то / корень не тот — рукопожатие отвергнуто, причина в dns-log, вопросов
#     на сервер нет (проверка сертификата не отключена).
#  7. ips в спеке — bootstrap не нужен; bootstrap молчит и адресов нет — SERVFAIL за срок.
#  8. dns-log: апстрим doq, состояние, счётчики.
#  Замер (DOQUP_BENCH=1): холодное и тёплое соединение, UDP/DoT/DoH/DoQ к одному dnsproxy.
#
# Нужны root, unshare, nsenter, ip, nft, openssl, python3, docker (или DOQUP_DNSPROXY), исходники
# wolfSSL и ngtcp2 (STEER_WOLFSSL, STEER_NGTCP2 или $BUILD/{wolfssl,ngtcp2}-host/src). Чего-то нет —
# пропуск вслух, с кодом 0.
set -u
BUILD=${BUILD:-build}
skip() { echo "doqup: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter openssl python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${DOQUP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
    [ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || skip "исходников wolfSSL нет ($WSRC)"
    NSRC="${STEER_NGTCP2:-$BUILD/ngtcp2-host/src}"
    [ -f "$NSRC/lib/includes/ngtcp2/ngtcp2.h" ] || skip "исходников ngtcp2 нет ($NSRC)"
    mkdir -p "$BUILD/doqup"
    # ---- сервер: dnsproxy из образа -----------------------------------------------------------------
    PROXY="${DOQUP_DNSPROXY:-}"
    if [ -z "$PROXY" ]; then
        command -v docker >/dev/null 2>&1 || skip "нет docker и DOQUP_DNSPROXY"
        IMG=steer-doqup-dnsproxy:v0.85.0
        docker image inspect "$IMG" >/dev/null 2>&1 || {
            docker pull adguard/dnsproxy:v0.85.0 >/dev/null 2>&1 || skip "образ dnsproxy не получить"
            docker tag adguard/dnsproxy:v0.85.0 "$IMG"; }
        if [ ! -x "$BUILD/doqup/dnsproxy" ]; then
            docker create --name steer-doqup-x "$IMG" >/dev/null 2>&1 || skip "docker create не удался"
            docker cp steer-doqup-x:/opt/dnsproxy/dnsproxy "$BUILD/doqup/dnsproxy" >/dev/null 2>&1
            docker rm steer-doqup-x >/dev/null 2>&1
        fi
        PROXY="$BUILD/doqup/dnsproxy"
    fi
    [ -x "$PROXY" ] || skip "нет исполняемого dnsproxy"
    # ---- сборка: движок с TLS и QUIC (то же, что кладёт в libsteer, но одним файлом) --------------------
    CC=${CC:-cc}
    . build/sources.sh
    INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done) $(profile_var THIRD_DEFS)"
    CCTAG=$(printf '%s' "$CC" | tr -c 'a-zA-Z0-9' '_')
    WLIB="$BUILD/wolfssl-host/libwolfssl-$CCTAG.a"
    NGLIB="$BUILD/ngtcp2-host/libngtcp2-$CCTAG.a"
    mkdir -p "$BUILD/wolfssl-host" "$BUILD/ngtcp2-host"
    if [ ! -f "$WLIB" ]; then
        CC="$CC" AR="${AR:-ar}" CFLAGS="-O2 -g" STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" \
            sh build/wolfssl/build.sh "$WSRC" "$WLIB" asm >/dev/null || skip "wolfSSL не собрался"
    fi
    if [ ! -f "$NGLIB" ]; then
        CC="$CC" AR="${AR:-ar}" CFLAGS="-O2 -g" sh build/ngtcp2/build.sh "$NSRC" "$WSRC" "$NGLIB" >/dev/null ||
            skip "ngtcp2 не собрался"
    fi
    WCF=$(cat "$WLIB.cflags")
    NGC=$(cat "$NGLIB.cflags")
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC $WCF -c src/lib/scrypto.c -o "$BUILD/doqup/scrypto.o" || skip "scrypto не собрался"
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC $NGC $WCF -DSTEER_VERSION='"doqup"' -o "$BUILD/doqup/steer" $(profile_var CORE_SRC) \
        src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/chello.c \
        src/proto/tls/h2.c src/proto/tls/roots.c src/proto/quic/quic.c src/proto/quic/qcssl.c src/proto/quic/qcdoq.c \
        "$BUILD/doqup/scrypto.o" "$NGLIB" "$WLIB" -lpthread -lm || skip "движок с QUIC не собрался"
    DOQUP_INNER=1 DOQUP_BIN="$(cd "$BUILD/doqup" && pwd)/steer" DOQUP_SRV="$(cd tests && pwd)/dnsup-server.py" \
        DOQUP_PROXY="$(cd "$(dirname "$PROXY")" && pwd)/$(basename "$PROXY")" \
        exec unshare -nm sh "$0" "$@"
fi
BIN="$DOQUP_BIN"
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up

tmp="$(mktemp -d)"
S="--state-dir $tmp/st"
cleanup() {
    kill $(cat "$tmp"/*.pid 2>/dev/null) ${SPID:-0} ${STUB:-0} 2>/dev/null
    pkill -f "$tmp/" 2>/dev/null
    pkill -9 -f "^$DOQUP_PROXY --verbose" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "doqup: журналы в $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

# ---- сеть --------------------------------------------------------------------------------------
unshare -n sh -c 'echo $$ > '"$tmp"'/srv.ns; exec sleep 3600' & SPID=$!
n=0; while [ ! -s "$tmp/srv.ns" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
NS="$(cat "$tmp/srv.ns")"
inS() { nsenter -t "$NS" -n "$@"; }
ip link add wan0 type veth peer name wan1 netns "$NS" || skip "veth недоступен"
ip link add tun0 type veth peer name tun1 netns "$NS"
ip addr add 10.0.1.1/24 dev wan0; ip addr add 10.0.2.1/24 dev tun0
ip link set wan0 up; ip link set tun0 up
inS ip link set lo up
inS ip addr add 10.0.1.2/24 dev wan1; inS ip addr add 10.0.2.2/24 dev tun1
inS ip link set wan1 up; inS ip link set tun1 up
inS ip addr add 192.0.2.53/32 dev lo; inS ip addr add 192.0.2.54/32 dev lo
ip route add default via 10.0.1.2 dev wan0
sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
inS sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
nft add table inet steer_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet steer_probe
if [ -n "${DOQUP_LOSS:-}" ] || [ -n "${DOQUP_DELAY:-}" ]; then
    # Потери и задержка на обоих концах пары: теряются и запросы, и ответы.
    for d in tun0 wan0; do tc qdisc add dev $d root netem delay "${DOQUP_DELAY:-0ms}" loss "${DOQUP_LOSS:-0%}" 2>/dev/null; done
    for d in tun1 wan1; do inS tc qdisc add dev $d root netem delay "${DOQUP_DELAY:-0ms}" loss "${DOQUP_LOSS:-0%}" 2>/dev/null; done
fi

# ---- сертификаты -------------------------------------------------------------------------------
c="$tmp/pki"; mkdir -p "$c"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/ca.key" \
    -out "$c/ca.pem" -days 3 -subj "/CN=doqup-test-ca" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/ca2.key" \
    -out "$c/ca2.pem" -days 3 -subj "/CN=doqup-other-ca" >/dev/null 2>&1
mkcert() {    # имя файла, имя в сертификате
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/$1.key" \
        -out "$c/$1.csr" -subj "/CN=$2" >/dev/null 2>&1
    printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' "$2" > "$c/$1.ext"
    openssl x509 -req -in "$c/$1.csr" -CA "$c/ca.pem" -CAkey "$c/ca.key" -CAcreateserial -out "$c/$1.pem" \
        -days 3 -extfile "$c/$1.ext" >/dev/null 2>&1
}
mkcert srv dns.test
mkcert wrong other.test

# ---- серверы -----------------------------------------------------------------------------------
LOG="$tmp/srv.log"; : > "$LOG"
inS python3 "$DOQUP_SRV" 192.0.2.54 "$LOG" "$c/srv.pem" "$c/srv.key" --zone svc.test=203.0.113.7 \
    --zone dns.test=192.0.2.53 --zone plain.test=203.0.113.9 --ttl 300 > "$tmp/auth.out" 2>&1 &
echo $! > "$tmp/auth.pid"
PLOG="$tmp/proxy.log"
proxy_start() {   # сертификат, ключ (по умолчанию — верный)
    inS "$DOQUP_PROXY" --verbose -l 192.0.2.53 -p 53 --tls-port=853 --https-port=443 --quic-port=853 \
        --tls-crt="${1:-$c/srv.pem}" --tls-key="${2:-$c/srv.key}" -u 192.0.2.54:53 --cache-size=0 \
        --ipv6-disabled >> "$PLOG" 2>&1 &
    echo $! > "$tmp/proxy.pid"
    n=0; while ! inS ss -lun 2>/dev/null | grep -q '192.0.2.53:853' && [ $n -lt 80 ]; do sleep 0.1; n=$((n + 1)); done
}
: > "$PLOG"
proxy_start
sleep 0.3
# SIGKILL, как падение: сервер не успевает закрыть соединения кодом, и новый процесс на том же порту не
# знает наших идентификаторов соединения. (pid из $! — оболочки, а не dnsproxy: убиваем по имени.)
proxy_stop() { pkill -9 -f "^$DOQUP_PROXY --verbose" 2>/dev/null; sleep 0.5; }

# ---- заглушка на петле: «dnsmasq» для имён вне правил -------------------------------------------
cat > "$tmp/stub.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(2048)
    e = 12
    while d[e]: e += 1 + d[e]
    e += 5
    s.sendto(d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x01\x00\x00\x00\x00" + d[12:e] +
             b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([198, 51, 100, 77]), a)
PY
python3 "$tmp/stub.py" 15353 & STUB=$!

# ---- клиент ------------------------------------------------------------------------------------
cat > "$tmp/ask.py" <<'PY'
import socket, struct, sys, time
port, name = int(sys.argv[1]), sys.argv[2]
qt = int(sys.argv[3]) if len(sys.argv) > 3 else 1
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', qt, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(7)
t = time.time()
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
ms = (time.time() - t) * 1000
rc = d[3] & 0x0f
if len(sys.argv) > 4: print("%.1f" % ms); sys.exit()
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(".".join(str(b) for b in d[-4:]))
PY
LPORT=15310
ask() { python3 "$tmp/ask.py" "$LPORT" "$@"; }
pq() { grep -c "$1" "$PLOG"; }              # строк журнала dnsproxy
cnt() { grep -c "$1" "$LOG"; }              # строк журнала авторитетного сервера
fake() { case "$1" in 198.18.*) echo fake ;; *) echo "$1" ;; esac; }
# Пакеты, принятые интерфейсом сервера (счётчик пространства сервера, не роутера).
rxs() { inS sed -n "s/^ *$1: *[0-9]* *\([0-9]*\).*/\1/p" /proc/net/dev; }
# Пакеты QUIC на порт 853 сервера по адресу отправителя: 10.0.2.1 — через выход, 10.0.1.1 — WAN. Клиента
# QUIC-соединения dnsproxy в журнал не пишет, поэтому путь показывает счётчик nft в пространстве сервера.
inS nft -f - <<'NFT'
table inet doqcnt {
  chain in {
    type filter hook input priority -300; policy accept;
    udp dport 853 ip saddr 10.0.2.1 counter comment "tun"
    udp dport 853 ip saddr 10.0.1.1 counter comment "wan"
  }
}
NFT
qpk() { inS nft list chain inet doqcnt in | sed -n "/comment \"$1\"/s/.*packets \([0-9]*\).*/\1/p"; }

# ---- спека --------------------------------------------------------------------------------------
mkdir -p "$tmp/st"
for l in doq doqd doqi doqw dot doh; do printf '%s.svc.test\n' "$l" > "$tmp/$l.lst"; done
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  ldoq:  { domains_file: $tmp/doq.lst }
  ldoqd: { domains_file: $tmp/doqd.lst }
  ldoqi: { domains_file: $tmp/doqi.lst }
  ldoqw: { domains_file: $tmp/doqw.lst }
  ldot:  { domains_file: $tmp/dot.lst }
  ldoh:  { domains_file: $tmp/doh.lst }
outputs:
  direct: { kind: direct }
  vpn: { kind: interface, device: tun0 }
dns:
  cache: 64
  bootstrap: [192.0.2.53]
  upstreams:
    doq:  { url: quic://dns.test, out: vpn }
    doqd: { url: quic://dns.test }
    doqi: { url: quic://dns.test, ips: [192.0.2.53], out: vpn }
    doqw: { url: quic://wrong.test, ips: [192.0.2.53], out: vpn }
    dot:  { url: tls://dns.test, out: vpn }
    doh:  { url: https://dns.test/dns-query, out: vpn }
rules:
  - { name: rdot,  to: [ldot],  out: vpn, dns: dot }
  - { name: rdoh,  to: [ldoh],  out: vpn, dns: doh }
  - { name: rdoq,  to: [ldoq],  out: vpn, dns: doq }
  - { name: rdoqd, to: [ldoqd], out: vpn, dns: doqd }
  - { name: rdoqi, to: [ldoqi], out: vpn, dns: doqi }
  - { name: rdoqw, to: [ldoqw], out: vpn, dns: doqw }
EOF
"$BIN" apply --spec "$tmp/spec.yaml" $S >"$tmp/apply.out" 2>&1 || { echo "FAIL apply:"; cat "$tmp/apply.out"; exit 1; }
"$BIN" daemon --supervise --socket "$tmp/s.sock" --spec "$tmp/spec.yaml" $S \
    --dnsd-flag --listen-port --dnsd-flag "$LPORT" --dnsd-flag --upstream-port --dnsd-flag 15353 \
    --dnsd-flag --ca-file --dnsd-flag "$c/ca.pem" 2>"$tmp/d.err" &
echo $! > "$tmp/d.pid"
n=0; while [ ! -S "$tmp/s.sock" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
n=0; while ! grep -q 'слушает\|listening on' "$tmp/d.err" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
sleep 0.5
TUNTX() { cat /sys/class/net/tun0/statistics/tx_packets; }
dnslog() { "$BIN" dns-log $S 2>/dev/null > "$tmp/dnslog.json"; python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
u = {x["name"]: x for x in d["upstreams"]}[sys.argv[2]]
print(u[sys.argv[3]])
' "$tmp/dnslog.json" "$1" "$2"; }

# ---- 1. DoQ через выход, bootstrap ------------------------------------------------------------------
t0=$(TUNTX); w0=$(rxs wan1)
check "DoQ: клиенту поддельный адрес" fake "$(fake "$(ask a.doq.svc.test)")"
check "  сервер (независимый) принял вопрос по QUIC" "1" "$([ "$(pq 'a.doq.svc.test')" -ge 1 ] && echo 1 || echo 0)"
check "  авторитетный сервер получил вопрос от dnsproxy" "1" "$(cnt 'a.doq.svc.test')"
check "  QUIC на порт сервера пришёл с адреса туннеля (10.0.2.1)" "1" "$([ "$(qpk tun)" -gt 0 ] && echo 1 || echo 0)"
check "  с адреса WAN (10.0.1.1) — ни одного пакета QUIC" "0" "$(qpk wan)"
check "  через tun0 прошли пакеты" "1" "$([ "$(TUNTX)" -gt "$t0" ] && echo 1 || echo 0)"
check "  в WAN (wan1 сервера) — ни пакета вообще" "0" "$(($(rxs wan1) - w0))"
check "bootstrap: имя сервера спрошено обычным DNS через выход" "1" \
    "$([ "$(pq 'dns.test')" -ge 1 ] && echo 1 || echo 0)"
check "dns-log: doq готов, соединение одно" "ready 1 doq vpn" "$(echo "$(dnslog doq state) $(dnslog doq conns) $(dnslog doq proto) $(dnslog doq via)")"

# Тот же сервер по DoT и DoH: сверка соседних транспортов с независимой реализацией.
check "DoT к dnsproxy: ответ" fake "$(fake "$(ask a.dot.svc.test)")"
check "DoH к dnsproxy: ответ" fake "$(fake "$(ask a.doh.svc.test)")"
sleep 1
# DoH по HTTP/2: dnsproxy (Go) выбирает h2, если он предложен; сто вопросов разом идут потоками одного
# соединения (у HTTP/1.1 это было бы соединение на вопрос).
check "  DoH: сервер выбрал HTTP/2" "h2" "$(dnslog doh http)"
: > "$tmp/h2par.res"
for i in $(seq 1 100); do ( fake "$(ask "q$i.doh.svc.test")" >> "$tmp/h2par.res" ) & done
n=0; while [ "$(wc -l < "$tmp/h2par.res")" -lt 100 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
sleep 1
check "  DoH/h2: сто одновременных вопросов — все с ответом" "100" "$(grep -c '^fake$' "$tmp/h2par.res")"
check "  и все дошли до авторитетного сервера" "100" "$(cnt 'q[0-9]*\.doh\.svc\.test')"
check "  соединение одно" "1" "$(dnslog doh conns)"
check "  отказов нет" "0" "$(dnslog doh failed)"
echo "     (dot: $(dnslog dot state) sent=$(dnslog dot sent) ok=$(dnslog dot ok) error=$(dnslog dot error); doh: $(dnslog doh state) sent=$(dnslog doh sent) ok=$(dnslog doh ok) error=$(dnslog doh error))"

# ---- 2. одно соединение, много вопросов ---------------------------------------------------------------
: > "$tmp/many.res"
for i in $(seq 1 40); do fake "$(ask "m$i.doq.svc.test")" >> "$tmp/many.res"; done
check "сорок вопросов подряд: все с ответом" "40" "$(grep -c '^fake$' "$tmp/many.res")"
: > "$tmp/par.res"
for i in $(seq 1 100); do ( fake "$(ask "p$i.doq.svc.test")" >> "$tmp/par.res" ) & done
n=0; while [ "$(wc -l < "$tmp/par.res")" -lt 100 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
check "сто одновременных вопросов: все с ответом" "100" "$(grep -c '^fake$' "$tmp/par.res")"
check "  соединение по-прежнему одно" "1" "$(dnslog doq conns)"

# ---- 2а. простой: PING держит соединение, мёртвый путь узнаётся до вопроса -----------------------------
# Пока соединение держится без вопросов, резолвер шлёт PING (раз в 15 с молчания, а при коротком
# сроке простоя сервера — чаще: у dnsproxy он 30 с, PING идёт раз в 10 с): пакеты QUIC на сервер
# идут и без вопросов, соединение остаётся тем же, и следующий вопрос уходит по нему сразу. Простой
# здесь — 25 с, не дольше: соединение без вопросов dnsproxy через 30 с закрывает сам, с PING или
# без (кодом DOQ_NO_ERROR; резолвер узнаёт об этом сразу и следующий вопрос ведёт на новом). Потом
# путь обрывается молча (сервер перестаёт видеть пакеты соединения, ответа нет): через 20 с тишины
# резолвер закрывает соединение сам, и вопрос после этого идёт на новом — без ожидания на мёртвом.
p0=$(qpk tun)
sleep 25
p1=$(qpk tun)
check "простой 25 с: PING шёл (пакеты QUIC на сервер без единого вопроса)" "1" \
    "$([ $((p1 - p0)) -ge 2 ] && echo 1 || echo "0 (пакетов: $((p1 - p0)))")"
check "  соединение то же, готово" "ready 1" "$(dnslog doq state) $(dnslog doq conns)"
ms="$(ask k1.doq.svc.test 1 ms)"
check "  вопрос после простоя — сразу, по готовому соединению" "1" \
    "$(python3 -c 'import sys; print(1 if float(sys.argv[1]) < 300 else "0 (%s мс)" % sys.argv[1])' "$ms" 2>&1)"
inS nft add rule inet doqcnt in udp dport 853 ip saddr 10.0.2.1 drop
sleep 23
check "путь пропал молча: через 20 с тишины соединение закрыто без вопроса клиента" "0" "$(dnslog doq conns)"
inS nft flush chain inet doqcnt in
inS nft add rule inet doqcnt in udp dport 853 ip saddr 10.0.2.1 counter comment '"tun"'
inS nft add rule inet doqcnt in udp dport 853 ip saddr 10.0.1.1 counter comment '"wan"'
ms="$(ask k2.doq.svc.test 1 ms)"
check "  путь вернулся: вопрос идёт на новом соединении без ожидания на мёртвом" "1" \
    "$(python3 -c 'import sys; print(1 if float(sys.argv[1]) < 600 else "0 (%s мс)" % sys.argv[1])' "$ms" 2>&1)"
check "  соединение одно" "1" "$(dnslog doq conns)"
check "  ни одного отказа" "0" "$(dnslog doq failed)"

# ---- 3. без выхода, кэш -------------------------------------------------------------------------------
check "DoQ без выхода: ответ" fake "$(fake "$(ask a.doqd.svc.test)")"
check "  QUIC пришёл с адреса WAN (10.0.1.1)" "1" "$([ "$(qpk wan)" -gt 0 ] && echo 1 || echo 0)"
n0=$(cnt 'b.doq.svc.test')
f1="$(ask b.doq.svc.test)"; sleep 0.3
f2="$(ask b.doq.svc.test)"
check "кэш: оба раза один поддельный адрес" "$f1" "$f2"
sleep 61   # быстрый путь fake-IP ходит наверх не чаще раза в минуту; дальше вопрос идёт через кэш апстрима
f3="$(ask b.doq.svc.test)"; sleep 0.3
check "кэш: до сервера дошёл один вопрос из трёх" "1" "$(($(cnt 'b.doq.svc.test') - n0))"
check "fake-IP строгий: элемент карты ядра стоит" "203.0.113.7" \
    "$(nft get element inet steer fakeip "{ $f1 }" 2>/dev/null | sed -n 's/.*elements = { [0-9.]* : \([0-9.]*\).*/\1/p')"

# ---- 4. выход лёг --------------------------------------------------------------------------------------
w0=$(rxs wan1)
ip link set tun0 down
sleep 0.5
r="$(ask c.doq.svc.test)"
sleep 0.3
check "выход лёг: клиенту не адрес" "1" "$([ "$r" = timeout ] || [ "$r" = rcode2 ] && echo 1 || echo 0)"
check "  в WAN за это время — ни пакета" "0" "$(($(rxs wan1) - w0))"
ip link set tun0 up; ip addr add 10.0.2.1/24 dev tun0 2>/dev/null
"$BIN" apply --spec "$tmp/spec.yaml" $S >/dev/null 2>&1
sleep 5
check "выход вернулся: DoQ работает" fake "$(fake "$(ask d.doq.svc.test)")"

# ---- 5. сервер перезапущен и сервер лёг ------------------------------------------------------------------
proxy_stop
proxy_start
r="$(ask e.doq.svc.test)"
check "сервер перезапущен: следующий вопрос дошёл на новом соединении" fake "$(fake "$r")"
check "  и сервер его получил" "1" "$([ "$(pq 'e.doq.svc.test')" -ge 1 ] && echo 1 || echo 0)"
r="$(ask e2.doq.svc.test)"
check "  дальше — как обычно" fake "$(fake "$r")"
r="$(ask e.doh.svc.test)"; sleep 1
check "  DoH/h2: новое соединение после перезапуска, вопрос дошёл" "1" "$([ "$(pq 'e.doh.svc.test')" -ge 1 ] && echo 1 || echo 0)"
proxy_stop
fl0=$(dnslog doq failed)
t0=$(date +%s)
r="$(ask g.doq.svc.test)"
t1=$(date +%s)
sleep 6
# Быстрый путь fake-IP отвечает клиенту поддельным адресом сразу, а вопрос к апстриму идёт следом; отказ
# виден в счётчиках апстрима и в его состоянии, зависшего вопроса нет.
check "сервер лёг совсем: клиенту ответ без зависания" "1" "$([ $((t1 - t0)) -le 2 ] && echo 1 || echo 0)"
check "  вопрос к апстриму получил отказ за срок (счётчик failed вырос)" "1" \
    "$([ "$(dnslog doq failed)" -gt "$fl0" ] && echo 1 || echo 0)"
check "  причина названа в dns-log" "1" "$([ "$(dnslog doq error)" != None ] && echo 1 || echo 0)"
echo "     (error: $(dnslog doq error))"
proxy_start
sleep 32   # пауза после неудачи растёт 1, 2, 4 ... 30 с
check "сервер поднялся: DoQ снова работает" fake "$(fake "$(ask h.doq.svc.test)")"

# ---- 6. проверка сертификата ------------------------------------------------------------------------
wl=$(wc -l < "$PLOG")
r="$(ask x.doqw.svc.test)"
check "имя в сертификате не то: вопрос не прошёл" "1" "$([ "$r" = timeout ] || [ "$r" = rcode2 ] && echo 1 || echo 0)"
check "  вопросов на сервер за это время нет" "0" "$(tail -n +$((wl + 1)) "$PLOG" | grep -c 'x.doqw.svc.test')"
check "  причина в dns-log (рукопожатие)" "1" "$(dnslog doqw error | grep -c 'рукопожатие')"

# ---- 7. ips и bootstrap -----------------------------------------------------------------------------
check "ips в спеке: имя не разрешается, ответ есть" fake "$(fake "$(ask a.doqi.svc.test)")"
cat > "$tmp/spec2.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  lb: { domains_file: $tmp/doq.lst }
  lc: { domains_file: $tmp/doqi.lst }
outputs:
  direct: { kind: direct }
rules:
  - { name: rb, to: [lb], out: direct, dns: { url: "quic://dns.test", bootstrap: [192.0.2.99] } }
  - { name: rc, to: [lc], out: direct, dns: { url: "quic://dns.test", ips: [192.0.2.53] } }
EOF
"$BIN" dnsd --spec "$tmp/spec2.yaml" --state-dir "$tmp/st2" --listen-port 15311 --upstream-port 15353 \
    --ca-file "$c/ca2.pem" 2>"$tmp/d2.err" &
echo $! > "$tmp/d2.pid"
sleep 1
LPORT=15311
t0=$(date +%s)
r="$(ask z.doq.svc.test)"
t1=$(date +%s)
check "bootstrap молчит: SERVFAIL или тишина, но не зависание" "1" \
    "$([ "$r" = rcode2 ] || [ "$r" = timeout ] && [ $((t1 - t0)) -le 8 ] && echo 1 || echo 0)"
wl=$(wc -l < "$PLOG")
r="$(ask z.doqi.svc.test)"
check "корень не тот (--ca-file чужой): рукопожатие отвергнуто, вопроса на сервере нет" "1" \
    "$([ "$r" != "" ] && { [ "$r" = timeout ] || [ "$r" = rcode2 ]; } && [ "$(tail -n +$((wl + 1)) "$PLOG" | grep -c 'z.doqi.svc.test')" = 0 ] && echo 1 || echo 0)"
LPORT=15310

# ---- 8. dns-log ------------------------------------------------------------------------------------------
check "dns-log: счётчики doq" "1" "$([ "$(dnslog doq sent)" -gt 100 ] && [ "$(dnslog doq ok)" -gt 100 ] && echo 1 || echo 0)"
check "dns-log: доп. апстрим без выхода — via None" "None" "$(dnslog doqd via)"

# ---- 9. 0-RTT: первый вопрос после переподключения ---------------------------------------------------------
# Отдельный резолвер на одном прямом апстриме DoQ; простой соединения сокращён до 1,5 с (STEER_DNSD_IDLE_MS —
# только для стендов), чтобы соединение закрылось само, а билет сессии остался в памяти процесса.
#   а) вопрос, пауза (соединение закрылось), вопрос: второй уходит в 0-RTT — счётчик early в dns-log,
#      отказов нет; время переподключения печатается рядом со временем без 0-RTT (STEER_DOQ_EARLY_DATA=0:
#      билетов нет, полное рукопожатие). Время — справка, не проверка: без задержки пути (DOQUP_DELAY) разница
#      в доли миллисекунды и тонет в шуме;
#   б) то же, но между вопросами сервер перезапущен: ключи билетов у нового процесса другие, 0-RTT отвергнут —
#      вопрос обязан дойти всё равно (возврат в очередь), счётчик early_rejected == 1.
printf 'e.early.test\nf.early.test\ng.early.test\n' > "$tmp/early.lst"
cat > "$tmp/spec4.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  le: { domains_file: $tmp/early.lst }
outputs:
  direct: { kind: direct }
rules:
  - { name: re, to: [le], out: direct, resolve: realip, dns: { url: "quic://dns.test", ips: [192.0.2.53] } }
EOF
early_dnsd() {   # каталог состояния, порт, переменные окружения…
    sd=$1; ep=$2; shift 2
    mkdir -p "$sd"
    env STEER_DNSD_IDLE_MS=1500 "$@" "$BIN" dnsd --spec "$tmp/spec4.yaml" --state-dir "$sd" --listen-port "$ep" \
        --upstream-port 15353 --ca-file "$c/ca.pem" 2>"$sd/err" &
    echo $! > "$sd/pid"
    sleep 1
}
early_log() {    # каталог состояния, поле
    "$BIN" dns-log --state-dir "$1" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["upstreams"][0].get(sys.argv[1], 0))' "$2"
}
early_stop() { kill "$(cat "$1/pid")" 2>/dev/null; sleep 0.3; }
askms() { python3 "$tmp/ask.py" "$1" "$2" 1 ms; }

early_dnsd "$tmp/st4" 15314
askms 15314 e.early.test >/dev/null
sleep 4
E_ON=$(askms 15314 f.early.test)
check "0-RTT: второй вопрос после закрытия соединения получил ответ" "1" "$([ "$E_ON" != timeout ] && echo 1 || echo 0)"
check "  вопрос ушёл в 0-RTT (early в dns-log)" "1" "$([ "$(early_log "$tmp/st4" early)" -ge 1 ] && echo 1 || echo 0)"
check "  сервер принял 0-RTT (отказов нет)" "0" "$(early_log "$tmp/st4" early_rejected)"
early_stop "$tmp/st4"

early_dnsd "$tmp/st5" 15315 STEER_DOQ_EARLY_DATA=0
askms 15315 e.early.test >/dev/null
sleep 4
E_OFF=$(askms 15315 f.early.test)
check "0-RTT выключен ключом: вопрос после переподключения получил ответ" "1" "$([ "$E_OFF" != timeout ] && echo 1 || echo 0)"
check "  в 0-RTT ничего не ушло" "0" "$(early_log "$tmp/st5" early)"
early_stop "$tmp/st5"
echo "  справка: вопрос после переподключения — с 0-RTT ${E_ON} мс, без ${E_OFF} мс (задержка пути DOQUP_DELAY=${DOQUP_DELAY:-0ms} в каждую сторону)"

early_dnsd "$tmp/st6" 15316
askms 15316 e.early.test >/dev/null
sleep 4
proxy_stop; proxy_start; sleep 0.5
E_REJ=$(askms 15316 g.early.test)
check "0-RTT отвергнут (сервер перезапущен): вопрос всё равно получил ответ" "1" "$([ "$E_REJ" != timeout ] && echo 1 || echo 0)"
check "  отказ 0-RTT засчитан" "1" "$(early_log "$tmp/st6" early_rejected)"
early_stop "$tmp/st6"

# ---- замер -----------------------------------------------------------------------------------------------
# Отдельный резолвер на четырёх прямых апстримах к одному dnsproxy (UDP, DoT, DoH, DoQ), кэша нет,
# имена каждый раз новые: «холодный» — первый вопрос (bootstrap, connect, рукопожатие), «тёплый» —
# медиана 30 следующих на том же соединении.
if [ "${DOQUP_BENCH:-0}" = 1 ]; then
    for k in u t h q; do printf '%s.bench.test\n' "$k" > "$tmp/b$k.lst"; done
    cat > "$tmp/spec3.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  bu: { domains_file: $tmp/bu.lst }
  bt: { domains_file: $tmp/bt.lst }
  bh: { domains_file: $tmp/bh.lst }
  bq: { domains_file: $tmp/bq.lst }
outputs:
  direct: { kind: direct }
rules:
  - { name: ru, to: [bu], out: direct, resolve: realip, dns: { url: "udp://192.0.2.53" } }
  - { name: rt, to: [bt], out: direct, resolve: realip, dns: { url: "tls://dns.test", bootstrap: [192.0.2.53] } }
  - { name: rh, to: [bh], out: direct, resolve: realip, dns: { url: "https://dns.test/dns-query", bootstrap: [192.0.2.53] } }
  - { name: rq, to: [bq], out: direct, resolve: realip, dns: { url: "quic://dns.test", bootstrap: [192.0.2.53] } }
EOF
    # Один процесс клиента на все вопросы: запуск python на вопрос вносил бы в «тёплое» столько же, сколько
    # сам транспорт. Вопросы идут по одному, последовательно; печатается p50/p95/максимум.
    cat > "$tmp/bench.py" <<'PY'
import socket, struct, sys, time
port, k, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(7)
bad = 0
def ask(name):
    global bad
    q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
    for l in name.split('.'): q += bytes([len(l)]) + l.encode()
    q += b'\x00' + struct.pack('>HH', 1, 1)
    t = time.time(); s.sendto(q, ('127.0.0.1', port))
    try: d, _ = s.recvfrom(2048)
    except socket.timeout:
        bad += 1
        return 7000.0
    if d[3] & 15 == 2: bad += 1              # SERVFAIL: апстрим не ответил
    return (time.time() - t) * 1000
cold = ask("c0.%s.bench.test" % k)
w = sorted(ask("w%d.%s.bench.test" % (i, k)) for i in range(n))
print("холодный %.1f мс, тёплый p50 %.2f p95 %.2f max %.2f мс (n=%d, отказов %d)" % (cold, w[n // 2], w[int(n * 0.95)], w[-1], n, bad))
PY
    "$BIN" dnsd --spec "$tmp/spec3.yaml" --state-dir "$tmp/st3" --listen-port 15312 --upstream-port 15353 \
        --ca-file "$c/ca.pem" 2>"$tmp/d3.err" &
    echo $! > "$tmp/d3.pid"
    sleep 1
    for k in u t h q; do
        echo "замер $k: $(python3 "$tmp/bench.py" 15312 $k "${DOQUP_N:-200}")"
    done
fi

echo "doqup: пройдено $pass, провалено $fail"
[ "$fail" = 0 ]
