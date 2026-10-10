#!/bin/sh
# ClientHello двумя записями TLS у апстрима DoH (`fragment: true`): рукопожатие с настоящим сервером
# (tests/doh2-server.py, TLS Python) проходит и с делением, и без него, а на проводе видно, что
# именно ушло: между клиентом и сервером стоит прокси, который пишет, из скольких записей TLS
# состояло всё, что клиент отправил до первого байта сервера. Разбор по байтам без сети —
# tests/dupfragmatch.c; устройство проверяемого — src/dnsd/dupdial.c, спека — docs/spec-v2.md.
#
#     sh tests/dnsfrag.sh
#
# Не входит в `make test`: нужны root и unshare (своя сеть на петле, на хосте ничего не трогается),
# openssl, python3 и исходники wolfSSL (STEER_WOLFSSL или $BUILD/wolfssl-host/src): TLS в резолвере —
# из библиотеки движка. Чего-то нет — пропуск вслух, код 0.
#
# Что проверяется.
#  1. fragment: true — вопрос с ответом, а до первого байта сервера клиент отправил ДВЕ записи TLS
#     (прокси разбирает заголовки), их тела вместе — один Hello (тип рукопожатия 1), разрез — внутри
#     имени сервера (SNI).
#  2. Без fragment — вопрос с ответом, запись одна.
set -u
BUILD=${BUILD:-build}
skip() { echo "dnsfrag: $1 — пропускаю"; exit 0; }
for t in ip unshare openssl python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${DNSFRAG_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
    [ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || skip "исходников wolfSSL нет ($WSRC)"
    # ---- сборка: движок с TLS для проверки (то же, что кладёт в пакет libsteer, но одним файлом) ----
    CC=${CC:-cc}
    . build/sources.sh
    INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done) $(profile_var THIRD_DEFS)"
    CCTAG=$(printf '%s' "$CC" | tr -c 'a-zA-Z0-9' '_')
    WLIB="$BUILD/wolfssl-host/libwolfssl-$CCTAG.a"
    mkdir -p "$BUILD/wolfssl-host" "$BUILD/dnsfrag"
    if [ ! -f "$WLIB" ]; then
        CC="$CC" AR="${AR:-ar}" CFLAGS="-O2 -g" STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" \
            sh build/wolfssl/build.sh "$WSRC" "$WLIB" asm >/dev/null || skip "wolfSSL не собрался"
    fi
    WCF=$(cat "$WLIB.cflags")
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC $WCF -c src/lib/scrypto.c -o "$BUILD/dnsfrag/scrypto.o" || skip "scrypto не собрался"
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC -DSTEER_VERSION='"dnsfrag"' -o "$BUILD/dnsfrag/steer" $(profile_var CORE_SRC) \
        src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/chello.c \
        src/proto/tls/h2.c src/proto/tls/roots.c "$BUILD/dnsfrag/scrypto.o" "$WLIB" -lpthread -lm ||
        skip "движок с TLS не собрался"
    DNSFRAG_INNER=1 DNSFRAG_BIN="$(cd "$BUILD/dnsfrag" && pwd)/steer" DNSFRAG_DIR="$(cd tests && pwd)" \
        exec unshare -nm sh "$0" "$@"
fi
BIN="$DNSFRAG_BIN"
ip link set lo up
tmp="$(mktemp -d)"
cleanup() {
    kill $(cat "$tmp"/*.pid 2>/dev/null) 2>/dev/null
    rm -rf "$tmp"
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
    -out "$c/ca.pem" -days 3 -subj "/CN=dnsfrag-test-ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/srv.key" \
    -out "$c/srv.csr" -subj "/CN=dns.test" >/dev/null 2>&1
printf 'subjectAltName=DNS:dns.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$c/srv.ext"
openssl x509 -req -in "$c/srv.csr" -CA "$c/ca.pem" -CAkey "$c/ca.key" -CAcreateserial -out "$c/srv.pem" \
    -days 3 -extfile "$c/srv.ext" >/dev/null 2>&1

SLOG="$tmp/srv.log"; : > "$SLOG"
python3 "$DNSFRAG_DIR/doh2-server.py" 127.0.0.1 8443 "$c/srv.pem" "$c/srv.key" "$SLOG" > "$tmp/srv.out" 2>&1 & echo $! > "$tmp/srv.pid"

# Прокси между клиентом и сервером: пишет в журнал по записям TLS, которые клиент отправил до первого
# байта сервера: сколько записей, тип рукопожатия в склеенном теле, лежит ли разрез внутри имени.
cat > "$tmp/proxy.py" <<'PY'
import select, socket, struct, sys, threading
lsn = socket.socket(); lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsn.bind(("127.0.0.1", 8450)); lsn.listen(8)
log = sys.argv[1]
def pump(c):
    s = socket.create_connection(("127.0.0.1", 8443))
    first = b""; seen_srv = False
    socks = [c, s]
    while socks:
        r, _, _ = select.select(socks, [], [], 20)
        if not r: break
        for x in r:
            d = x.recv(65536)
            if not d:
                socks = []; break
            if x is c:
                if not seen_srv: first += d
                s.sendall(d)
            else:
                if not seen_srv:
                    seen_srv = True
                    recs = []; o = 0; body = b""
                    while o + 5 <= len(first):
                        l = struct.unpack(">H", first[o+3:o+5])[0]
                        recs.append(l); body += first[o+5:o+5+l]; o += 5 + l
                    sni = b"dns.test"; at = body.find(sni) + 5
                    with open(log, "a") as f:
                        f.write("recs %d hs %d cut_in_sni %d\n" % (len(recs), body[0],
                                1 if len(recs) > 1 and at - 5 < recs[0] < at - 5 + len(sni) else 0))
                c.sendall(d)
    c.close(); s.close()
while True:
    c, _ = lsn.accept()
    threading.Thread(target=pump, args=(c,), daemon=True).start()
PY
PLOG="$tmp/proxy.log"; : > "$PLOG"
python3 "$tmp/proxy.py" "$PLOG" & echo $! > "$tmp/proxy.pid"

# Заглушка на петле для имён вне правил (движок требует, чтобы было к кому идти).
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
LPORT=15320
ask() { python3 "$tmp/ask.py" "$LPORT" "$@"; }
good() { case "$1" in timeout|rcode*|empty) echo bad ;; *) echo ok ;; esac; }

mkdir -p "$tmp/st"
printf 'fr.svc.test\n' > "$tmp/fr.lst"
printf 'nf.svc.test\n' > "$tmp/nf.lst"
cat > "$tmp/spec.yaml" <<SPEC
version: 2
lan: { devices: [lo] }
lists:
  lfr: { domains_file: $tmp/fr.lst }
  lnf: { domains_file: $tmp/nf.lst }
outputs:
  direct: { kind: direct }
dns:
  cache: 0
  upstreams:
    fr: { url: "https://dns.test:8450/ok", ips: [127.0.0.1], fragment: true }
    nf: { url: "https://dns.test:8450/ok", ips: [127.0.0.1] }
rules:
  - { name: rfr, to: [lfr], out: direct, dns: fr }
  - { name: rnf, to: [lnf], out: direct, dns: nf }
SPEC
"$BIN" apply --spec "$tmp/spec.yaml" --state-dir "$tmp/st" >"$tmp/apply.out" 2>&1 || { echo "FAIL apply:"; cat "$tmp/apply.out"; exit 1; }
"$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st" --listen-port "$LPORT" --upstream-port 15353 \
    --ca-file "$c/ca.pem" 2>"$tmp/d.err" & echo $! > "$tmp/d.pid"
n=0; while ! grep -q 'слушает\|listening on' "$tmp/d.err" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
sleep 0.5

check "fragment: true — вопрос с ответом" ok "$(good "$(ask a.fr.svc.test)")"
check "  до первого байта сервера — две записи TLS, в них один Hello, разрез внутри SNI" \
    "recs 2 hs 1 cut_in_sni 1" "$(sed -n 1p "$PLOG")"
check "без fragment — вопрос с ответом" ok "$(good "$(ask a.nf.svc.test)")"
check "  запись одна" "recs 1 hs 1 cut_in_sni 0" "$(sed -n 2p "$PLOG")"

echo "dnsfrag: $pass ok, $fail failed"
[ "$fail" = 0 ]
