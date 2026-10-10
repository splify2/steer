#!/bin/sh
# DoH по HTTP/3 (RFC 8484 + RFC 9114, QPACK RFC 9204) в резолвере: настоящий QUIC, сервер — НЕЗАВИСИМАЯ
# РЕАЛИЗАЦИЯ. Две: tests/doh3-server.py (aioquic с кодировщиком QPACK ls-qpack на C) ведёт себя по
# пути запроса — отказ кодом 500, сброс потока, ответ кусками с GREASE и трейлерами, молчание, закрытие
# соединения посреди работы, неверное имя в сертификате; AdGuard dnsproxy (quic-go, --http3) — обычная
# работа настоящего публичного сервера. Устройство проверяемого — src/dnsd/dup.c (раздел «DoQ», DoH3
# идёт тем же соединением QUIC), кадры и QPACK — src/dnsd/doh3.h. Стенд не входит в `make test`:
# нужны root, unshare, openssl, python3 с aioquic (DOH3_PYLIB=/путь к его модулям, если не установлен),
# исходники wolfSSL и ngtcp2 ($BUILD/{wolfssl,ngtcp2}-host/src или STEER_WOLFSSL, STEER_NGTCP2).
# Свой сетевой мир на петле: на хосте ничего не настраивается. dnsproxy — по желанию: DOH3UP_DNSPROXY=/путь
# или образ steer-doqup-dnsproxy:v0.85.0 (его кладёт tests/doqup.sh); нет — эти проверки пропускаются.
#
#     sh tests/doh3up.sh
#
# Что проверяется.
#  1. Вопрос идёт запросом HTTP/3: POST, :authority с портом, content-type и accept, номер в теле 0
#     (сервер видит их независимым разбором); клиент объявил таблицу QPACK 0 и блокированных потоков 0;
#     dns-log: proto doh3, http h3, соединение одно, сто одновременных вопросов — потоками одного.
#  2. Код не 200 — отказ вопроса с кодом в dns-log, соединение живёт и следующий вопрос отвечен.
#  3. Сброс потока сервером — отказ с причиной; ответ кусками (два DATA, GREASE, трейлеры) собран.
#  4. Тело короче заголовка DNS — отказ; молчание — отказ за срок, не зависание, дальше всё работает.
#  5. Сервер закрыл соединение после ответа — следующие вопросы идут на новом соединении.
#  6. Имя в сертификате не то — рукопожатие отвергнуто, вопросов на сервер нет.
#  7. dnsproxy: вопрос с ответом, сто одновременных; одно соединение.
set -u
BUILD=${BUILD:-build}
skip() { echo "doh3up: $1 — пропускаю"; exit 0; }
for t in ip unshare openssl python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${DOH3UP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    PYLIB="${DOH3_PYLIB:-}"
    PYTHONPATH="$PYLIB" python3 -c 'import aioquic.h3.connection' 2>/dev/null || skip "нет python-модуля aioquic (DOH3_PYLIB)"
    # ---- сервер dnsproxy (по желанию) ---------------------------------------------------------------
    mkdir -p "$BUILD/doh3up"
    PROXY="${DOH3UP_DNSPROXY:-}"
    if [ -z "$PROXY" ] && command -v docker >/dev/null 2>&1 && docker image inspect steer-doqup-dnsproxy:v0.85.0 >/dev/null 2>&1; then
        if [ ! -x "$BUILD/doh3up/dnsproxy" ]; then
            docker create --name steer-doh3up-x steer-doqup-dnsproxy:v0.85.0 >/dev/null 2>&1 &&
                docker cp steer-doh3up-x:/opt/dnsproxy/dnsproxy "$BUILD/doh3up/dnsproxy" >/dev/null 2>&1
            docker rm steer-doh3up-x >/dev/null 2>&1
        fi
        [ -x "$BUILD/doh3up/dnsproxy" ] && PROXY="$(cd "$BUILD/doh3up" && pwd)/dnsproxy"
    fi
    # ---- сборка: движок с TLS и QUIC (как у tests/doqup.sh) ------------------------------------------
    BIN="${DOH3UP_BIN:-}"
    if [ -z "$BIN" ]; then
        WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
        [ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || skip "исходников wolfSSL нет ($WSRC)"
        NSRC="${STEER_NGTCP2:-$BUILD/ngtcp2-host/src}"
        [ -f "$NSRC/lib/includes/ngtcp2/ngtcp2.h" ] || skip "исходников ngtcp2 нет ($NSRC)"
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
        $CC -O2 -g -w $INC $WCF -c src/lib/scrypto.c -o "$BUILD/doh3up/scrypto.o" || skip "scrypto не собрался"
        # shellcheck disable=SC2086
        $CC -O2 -g -w $INC $NGC $WCF -DSTEER_VERSION='"doh3up"' -o "$BUILD/doh3up/steer" $(profile_var CORE_SRC) \
            src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/chello.c \
            src/proto/tls/h2.c src/proto/tls/roots.c src/proto/quic/quic.c src/proto/quic/qcssl.c src/proto/quic/qcdoq.c \
            "$BUILD/doh3up/scrypto.o" "$NGLIB" "$WLIB" -lpthread -lm || skip "движок с QUIC не собрался"
        BIN="$BUILD/doh3up/steer"
    fi
    DOH3UP_INNER=1 DOH3UP_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" DOH3UP_PROXY="$PROXY" \
        DOH3UP_SRV="$(cd tests && pwd)/doh3-server.py" DOH3_PYLIB="$PYLIB" exec unshare -nm sh "$0" "$@"
fi
BIN="$DOH3UP_BIN"
ip link set lo up
tmp="$(mktemp -d)"
cleanup() {
    kill $(cat "$tmp"/*.pid 2>/dev/null) 2>/dev/null
    pkill -9 -f "^$DOH3UP_PROXY --verbose" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "doh3up: журналы в $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

c="$tmp/pki"; mkdir -p "$c"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/ca.key" \
    -out "$c/ca.pem" -days 3 -subj "/CN=doh3up-test-ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/srv.key" \
    -out "$c/srv.csr" -subj "/CN=dns.test" >/dev/null 2>&1
printf 'subjectAltName=DNS:dns.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$c/srv.ext"
openssl x509 -req -in "$c/srv.csr" -CA "$c/ca.pem" -CAkey "$c/ca.key" -CAcreateserial -out "$c/srv.pem" \
    -days 3 -extfile "$c/srv.ext" >/dev/null 2>&1

SLOG="$tmp/srv.log"; : > "$SLOG"
DOH3_PYLIB="${DOH3_PYLIB:-}" python3 "$DOH3UP_SRV" 127.0.0.1 8443 "$c/srv.pem" "$c/srv.key" "$SLOG" > "$tmp/srv.out" 2>&1 &
echo $! > "$tmp/srv.pid"

# Заглушка на петле: «dnsmasq» для имён вне правил и авторитетный сервер для dnsproxy.
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
python3 "$tmp/stub.py" 15353 & echo $! > "$tmp/stub.pid"
PLOG="$tmp/proxy.log"; : > "$PLOG"
if [ -n "$DOH3UP_PROXY" ]; then
    "$DOH3UP_PROXY" --verbose -l 127.0.0.1 -p 5399 --https-port=8453 --http3 --tls-crt="$c/srv.pem" --tls-key="$c/srv.key" \
        -u 127.0.0.1:15353 --cache-size=0 --ipv6-disabled >> "$PLOG" 2>&1 &
    echo $! > "$tmp/proxy.pid"
fi

cat > "$tmp/ask.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(9)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
rc = d[3] & 0x0f
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(".".join(str(b) for b in d[-4:]))
PY
LPORT=15330
ask() { python3 "$tmp/ask.py" "$LPORT" "$@"; }
good() { case "$1" in timeout|rcode*|empty) echo bad ;; *) echo ok ;; esac; }

mkdir -p "$tmp/st"
NAMES="ok st500 st404 rst split silent short close wrong px"
{
    printf 'version: 2\nlan: { devices: [lo] }\nlists:\n'
    for n in $NAMES; do
        printf '%s.svc.test\n' "$n" > "$tmp/$n.lst"
        printf '  l%s: { domains_file: %s/%s.lst }\n' "$n" "$tmp" "$n"
    done
    printf 'outputs:\n  direct: { kind: direct }\ndns:\n  cache: 0\n  upstreams:\n'
    for n in ok st500 st404 rst split silent short close; do
        printf '    %s: { url: "h3://dns.test:8443/%s", ips: [127.0.0.1] }\n' "$n" "$n"
    done
    printf '    wrong: { url: "h3://other.test:8443/ok", ips: [127.0.0.1] }\n'
    printf '    px:    { url: "h3://dns.test:8453/dns-query", ips: [127.0.0.1] }\n'
    printf 'rules:\n'
    for n in $NAMES; do printf '  - { name: r%s, to: [l%s], out: direct, dns: %s }\n' "$n" "$n" "$n"; done
} > "$tmp/spec.yaml"
# Правила ядра нужны быстрому пути fake-IP: без них клиенту отвечено SERVFAIL, и ответ апстрима не виден.
"$BIN" apply --spec "$tmp/spec.yaml" --state-dir "$tmp/st" >"$tmp/apply.out" 2>&1 || { echo "FAIL apply:"; cat "$tmp/apply.out"; exit 1; }
"$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st" --listen-port "$LPORT" --upstream-port 15353 \
    --ca-file "$c/ca.pem" 2>"$tmp/d.err" & echo $! > "$tmp/d.pid"
n=0; while ! grep -q 'слушает\|listening on' "$tmp/d.err" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
sleep 0.5
dnslog() { "$BIN" dns-log --state-dir "$tmp/st" 2>/dev/null > "$tmp/dnslog.json"; python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
u = {x["name"]: x for x in d["upstreams"]}[sys.argv[2]]
print(u.get(sys.argv[3]))
' "$tmp/dnslog.json" "$1" "$2"; }
nconns() { grep -c '^conn ' "$SLOG"; }

# ---- 1. запрос HTTP/3 и мультиплекс ---------------------------------------------------------------------
check "DoH3: вопрос с ответом" ok "$(good "$(ask a.ok.svc.test)")"
sleep 0.3
check "  сервер видит POST, :authority с портом, content-type, accept, номер в теле 0" \
    "req /ok POST dns.test:8443 ct=application/dns-message accept=application/dns-message id=0" "$(grep '^req /ok' "$SLOG" | head -1)"
check "  клиент объявил таблицу QPACK 0 и блокированных потоков 0" "settings cap=0 blocked=0" "$(grep '^settings' "$SLOG" | head -1)"
check "  dns-log: протокол doh3, http h3, готов" "doh3 h3 ready" "$(echo "$(dnslog ok proto) $(dnslog ok http) $(dnslog ok state)")"
: > "$tmp/par.res"
for i in $(seq 1 100); do ( good "$(ask "p$i.ok.svc.test")" >> "$tmp/par.res" ) & done
n=0; while [ "$(wc -l < "$tmp/par.res")" -lt 100 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
check "  сто одновременных: все с ответом" 100 "$(grep -c '^ok$' "$tmp/par.res")"
check "  на сервере одно соединение" 1 "$(nconns)"
check "  отказов нет, и на все вопросы ответил сервер" 1 \
    "$([ "$(dnslog ok failed)" = 0 ] && [ "$(dnslog ok ok)" -ge 101 ] && echo 1 || echo 0)"
check "  dns-log: соединение одно" 1 "$(dnslog ok conns)"

# ---- 2. код не 200 -------------------------------------------------------------------------------------------
check "HTTP 500: вопрос без ответа" bad "$(good "$(ask a.st500.svc.test)")"
check "  причина в dns-log" "DoH3: сервер ответил HTTP 500" "$(dnslog st500 error)"
check "  HTTP 404 — тоже" "DoH3: сервер ответил HTTP 404" "$(ask a.st404.svc.test >/dev/null; dnslog st404 error)"
n0=$(nconns)
check "  после отказа тот же апстрим отвечает на новом пути" ok "$(good "$(ask b.ok.svc.test)")"
check "  соединение не пересоздавалось" 0 "$(($(nconns) - n0))"

# ---- 3. сброс потока, ответ кусками --------------------------------------------------------------------------
ask a.rst.svc.test >/dev/null; sleep 0.3
check "сброс потока: причина в dns-log" "DoH3: сервер сбросил поток вопроса" "$(dnslog rst error)"
check "ответ кусками (два DATA, GREASE, трейлеры): собран" ok "$(good "$(ask a.split.svc.test)")"

# ---- 4. короткое тело, молчание ------------------------------------------------------------------------------
ask a.short.svc.test >/dev/null; sleep 0.3
check "тело короче заголовка DNS: отказ с причиной" "DoH3: тело ответа короче заголовка DNS (H3_MESSAGE_ERROR)" "$(dnslog short error)"
t0=$(date +%s)
r="$(ask a.silent.svc.test)"
t1=$(date +%s)
check "молчащий сервер: отказ за срок, не зависание" 1 "$([ "$(good "$r")" = bad ] && [ $((t1 - t0)) -le 8 ] && echo 1 || echo 0)"
check "  в dns-log причина" "нет ответа за 4000 мс" "$(dnslog silent error)"
check "  и другие вопросы потом идут" ok "$(good "$(ask c.ok.svc.test)")"

# ---- 5. сервер закрыл соединение --------------------------------------------------------------------------------
c0=$(nconns)
: > "$tmp/cl.res"
for i in 1 2 3 4; do good "$(ask "c$i.close.svc.test")" >> "$tmp/cl.res"; sleep 0.3; done
check "соединение закрыто сервером после каждого ответа: все четыре вопроса с ответом" 4 "$(grep -c '^ok$' "$tmp/cl.res")"
check "  и клиент пересоздавал соединение" 1 "$([ $(($(nconns) - c0)) -ge 3 ] && echo 1 || echo 0)"

# ---- 6. неверное имя в сертификате ---------------------------------------------------------------------------------
r0=$(grep -c '^req ' "$SLOG")
check "имя в сертификате не то: вопрос без ответа" bad "$(good "$(ask a.wrong.svc.test)")"
check "  причина — рукопожатие" 1 "$(dnslog wrong error | grep -c 'DoH3: рукопожатие с other.test не удалось')"
check "  вопросов на сервер нет" 0 "$(($(grep -c '^req ' "$SLOG") - r0))"

# ---- 7. dnsproxy ----------------------------------------------------------------------------------------------------
if [ -n "$DOH3UP_PROXY" ]; then
    n=0; while ! grep -q -i 'http3\|h3\|listening' "$PLOG" 2>/dev/null && [ $n -lt 30 ]; do sleep 0.1; n=$((n + 1)); done
    check "dnsproxy (quic-go): вопрос с ответом" ok "$(good "$(ask a.px.svc.test)")"
    check "  ответил именно сервер по h3 (счётчик апстрима, журнал dnsproxy)" 1 \
        "$([ "$(dnslog px ok)" -ge 1 ] && grep -q 'listening to h3' "$PLOG" && echo 1 || echo 0)"
    check "  dns-log: h3, готов" "h3 ready" "$(echo "$(dnslog px http) $(dnslog px state)")"
    : > "$tmp/pp.res"
    for i in $(seq 1 100); do ( good "$(ask "q$i.px.svc.test")" >> "$tmp/pp.res" ) & done
    n=0; while [ "$(wc -l < "$tmp/pp.res")" -lt 100 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
    check "  сто одновременных: все с ответом" 100 "$(grep -c '^ok$' "$tmp/pp.res")"
    check "  соединение одно, отказов нет" "1 0" "$(echo "$(dnslog px conns) $(dnslog px failed)")"
else
    echo "doh3up: dnsproxy нет (DOH3UP_DNSPROXY или образ steer-doqup-dnsproxy) — проверки 7 пропущены"
fi

printf '\nвсего: %d, провалов: %d\n' "$((pass + fail))" "$fail"
[ "$fail" = 0 ]
