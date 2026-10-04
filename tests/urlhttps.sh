#!/bin/sh
# Замер группы latency по HTTPS (src/proto/tls/urltls.c) — на настоящем демоне раскладки libs.
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Адрес проверки `https://…` меряет рабочий поток urltls.c: рукопожатие TLS 1.3
# с проверкой сертификата по хранилищу корней (ca-bundle), и ни один стенд `make test` его не
# доставал — в статической базовой сборке https:// отвергает разбор, а groupsmatch.sh собран на ней.
# Между тем это умолчание коннектора sing-box (https://www.gstatic.com/generate_204), и именно HTTPS
# чаще всего даёт «замера нет» без видимой причины: нет пакета ca-bundle, часы без NTP, страница
# плена, чужой сертификат — группа «самый быстрый» тихо идёт по порядку.
#
# Что проверяется. Два члена-интерфейса (veth, у ответчика netem: первый по порядку b — 100 мс, второй a
# — 5 мс) и группа `pick: latency` с адресом `https://probe.test:8443/generate_204`; ответчик — питоновский
# сервер TLS 1.3 со своим CA (openssl) на 10.2.0.1, имя — из hosts; хранилище корней демона —
# /etc/ssl/certs/ca-certificates.crt, подменённое в своём пространстве монтирования.
#   А. Хранилище, где нашего CA нет: замер не удался у обоих (сервер видит попытки с адресов обоих
#      членов — запрос шёл через каждого), группа идёт по порядку (b), status — why: no_measure,
#      latency_failed; в журнале у КАЖДОГО члена — причина: «сертификат не принят: сертификат не
#      сошёлся с корнями или выдан не на это …» (прежде строки о причине не было вовсе). Буфер причины
#      в tls13.c — 96 байт, и две самые длинные фразы certverify он режет (R-120, I-236): хвост
#      «имя» теряется, а недобитый байт буквы в журнал не пропускается — журнал остаётся валидным UTF-8.
#   Б. Хранилище с нашим CA: замер есть у обоих (b заметно медленнее a), группа на a — быстром, хотя он
#      второй по порядку; сервер видит запросы 204 с адресов обоих членов; в журнале строк «latency:»
#      нет.
#
# Нужны root, unshare -nm, ip, nft, tc (netem), nsenter, openssl, python3 с ssl и файл
# /etc/ssl/certs/ca-certificates.crt (его подменяют bind-монтированием) — иначе пропуск, а не падение.
# LIBS — раскладка libs (tests/libs-test.sh, build/libs-host).
set -u
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)"
skip() { echo "urlhttps: $1 — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] || skip "нет раскладки libs ($LIBS, tests/libs-test.sh)"
BIN="$LIBS/steerd"
LD_LIBRARY_PATH="$LIBS"; export LD_LIBRARY_PATH
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
for t in nft ip tc python3 nsenter unshare openssl awk; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
python3 -c 'import ssl; ssl.TLSVersion.TLSv1_3' 2>/dev/null || skip "у python3 нет ssl с TLS 1.3"
[ -f /etc/ssl/certs/ca-certificates.crt ] || skip "нет /etc/ssl/certs/ca-certificates.crt (подменять нечего)"
if [ "${URLHTTPS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    URLHTTPS_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "свой /sys не смонтировать"
ip link set lo up
nft add table inet urlhttps_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet urlhttps_probe
tc qdisc add dev lo root netem delay 1ms 2>/dev/null && tc qdisc del dev lo root 2>/dev/null ||
    skip "tc netem недоступен"
# Состояние демона и реестр таблиц — в памяти этого стенда, а не в файлах машины.
for d in /etc/steer /var/lib/steer /etc/iproute2/rt_tables.d; do
    [ -d "$d" ] && mount -t tmpfs tmpfs "$d" 2>/dev/null
done
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
D="" RPID="" HP="" MNT=""
stop_daemon() {
    [ -n "$D" ] && { kill "$D" 2>/dev/null; wait_for '! kill -0 $D 2>/dev/null' 15; D=""; }
    rm -f "$tmp/steer.sock"
}
cleanup() {
    stop_daemon
    kill $HP $RPID 2>/dev/null
    [ -n "$MNT" ] && umount /etc/ssl/certs/ca-certificates.crt 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- журнал демона, часть А (хвост)"; tail -n 12 "$tmp/d-a.err" 2>/dev/null
        echo "--- журнал демона (хвост)"; tail -n 12 "$tmp/d.err" 2>/dev/null
        echo "--- ответчик"; tail -n 8 "$tmp/http.log" 2>/dev/null
    fi
    [ -n "${URLHTTPS_KEEP:-}" ] && echo "каталог стенда: $tmp" || rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сертификаты: наш CA и сервер для probe.test; чужой CA — «хранилище без нашего корня» ----
mkca() {  # ИМЯ
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$tmp/$1.key" \
        -out "$tmp/$1.pem" -subj "/CN=urlhttps-$1" -days 30 -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}
mkca ca1 && mkca ca2 || skip "openssl не выпустил CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$tmp/srv.key" \
    -out "$tmp/srv.csr" -subj "/CN=probe.test" >/dev/null 2>&1 || skip "openssl не выпустил запрос"
printf 'subjectAltName=DNS:probe.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' \
    > "$tmp/srv.ext"
openssl x509 -req -in "$tmp/srv.csr" -CA "$tmp/ca1.pem" -CAkey "$tmp/ca1.key" -CAcreateserial \
    -out "$tmp/srv.pem" -days 30 -extfile "$tmp/srv.ext" >/dev/null 2>&1 || skip "openssl не выпустил сертификат"

# ---- сеть: ответчик R за двумя veth — членами a (sw1) и b (sw2) ----
unshare -n sleep 900 & RPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
R ip link set lo up
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo; R ip addr add 10.2.0.1/32 dev lo
for k in 1 2; do
    ip link add sw$k type veth peer name sw${k}p
    ip link set sw${k}p netns "$RPID"
    R ip link set sw${k}p up; R ip addr add 10.9.$k.2/24 dev sw${k}p
    ip link set sw$k addrgenmode none 2>/dev/null
    ip link set sw$k up; ip addr add 10.9.$k.1/24 dev sw$k
done
# Маршрут по умолчанию в WAN, как у роутера: ответ через члена приходит без метки, и проверка обратного
# пути ищет маршрут к ответчику в main.
ip link add wan0 type dummy; ip link set wan0 up; ip addr add 203.0.113.1/24 dev wan0
ip route add default via 203.0.113.254 dev wan0
nft -f - <<'EOF'
table ip urlhttps_nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname { "sw1", "sw2" } masquerade
    }
}
EOF
mkdir -p "$tmp/bin"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"; cp "$tmp/bin/ifdown" "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"; export PATH
printf '127.0.0.1 localhost\n10.2.0.1 probe.test\n' > "$tmp/hosts"
mount --bind "$tmp/hosts" /etc/hosts 2>/dev/null || skip "/etc/hosts не подменить"
# b — первый по порядку и медленный; a — второй и быстрый.
R tc qdisc add dev sw2p root netem delay 100ms
R tc qdisc add dev sw1p root netem delay 5ms

# Сервер TLS 1.3: 204 на любой путь; журнал — «путь адрес» и «TLSFAIL адрес причина».
cat > "$tmp/tls204.py" <<'PY'
import socket, ssl, sys, threading
log = open(sys.argv[1], 'a', buffering=1)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
ctx.set_alpn_protocols(['http/1.1'])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.2.0.1', 8443)); s.listen(64)
def serve(c, a):
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except Exception as e:
        log.write('TLSFAIL %s %r\n' % (a[0], e)); c.close(); return
    try:
        d = b''
        while b'\r\n\r\n' not in d:
            x = t.recv(4096)
            if not x: return
            d += x
        log.write('%s %s\n' % (d.split(b' ')[1].decode(), a[0]))
        t.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
    except Exception as e:
        log.write('ERR %s %r\n' % (a[0], e))
    finally:
        try: t.close()
        except Exception: pass
while True:
    c, a = s.accept()
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
PY
: > "$tmp/http.log"
nsenter -t "$RPID" -n python3 "$tmp/tls204.py" "$tmp/http.log" "$tmp/srv.pem" "$tmp/srv.key" \
    >"$tmp/http.err" 2>&1 & HP=$!
sleep 0.5

printf '10.2.0.0/24\n' > "$tmp/l.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
outputs:
  a:  { kind: interface, device: sw1 }
  b:  { kind: interface, device: sw2 }
  hs: { kind: group, pick: latency, members: [b, a], url: "https://probe.test:8443/generate_204", idle_timeout: 0 }
lists:
  l: { prefixes_file: $tmp/l.lst }
rules:
  - { name: r, to: [l], out: hs }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
export STEER_SOCKET="$tmp/steer.sock"
cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
if isinstance(d, list): print(','.join(str(x) for x in d))
elif isinstance(d, dict): print(','.join('%s=%s' % kv for kv in sorted(d.items())))
else: print('-' if d is None else d)
PY
st() { STEER_ENGINE=/bin/false "$BIN" status $S | python3 "$tmp/j.py" "$1"; }
lat() { st outputs.hs.group.latency | tr ',' '\n' | awk -F= -v m="$1" '$1 == m { print $2 }'; }
start_daemon() {
    "$BIN" daemon --watch --watch-period 3 --apply --socket "$tmp/steer.sock" $S >>"$tmp/d.out" 2>>"$tmp/d.err" &
    D=$!
    wait_for '[ -S "$tmp/steer.sock" ] && grep -q "watch: первый проход" "$tmp/d.err"' 15
}

# ---- А. хранилище корней без нашего CA ----
mount --bind "$tmp/ca2.pem" /etc/ssl/certs/ca-certificates.crt 2>/dev/null || skip "/etc/ssl/certs/ca-certificates.crt не подменить"
MNT=1
start_daemon
wait_for 'grep -q "группа hs: ни у одного живого члена нет замера" "$tmp/d.err"' 20
check "А. чужое хранилище: замера нет ни у кого — группа по порядку (b), status — no_measure" "b no_measure b,a" \
    "$(st outputs.hs.group.selected) $(st outputs.hs.group.why) $(st outputs.hs.group.latency_failed)"
check "  в журнале — строка, что группа идёт по порядку из-за замера" "1" \
    "$(grep -c 'группа hs: ни у одного живого члена нет замера' "$tmp/d.err")"
why="сертификат не принят: сертификат не сошёлся с корнями или выдан не на это"
check "  причина названа у каждого члена, с группой, членом и адресом" "yes yes" \
    "$(for m in b a; do grep -q "latency: группа hs, член $m: замер https://probe.test:8443/generate_204 не удался — $why" "$tmp/d.err" && echo yes || echo no; done | tr '\n' ' ' | sed 's/ $//')"
check "  журнал — валидный UTF-8: причина не обрезана посреди буквы" "yes" \
    "$(python3 -c 'import sys; sys.stdin.buffer.read().decode("utf-8")' < "$tmp/d.err" 2>/dev/null && echo yes || echo no)"
check "  сервер видел попытки TLS с адресов обоих членов (запрос шёл через каждого)" "2" \
    "$(grep '^TLSFAIL ' "$tmp/http.log" | awk '{ print $2 }' | sort -u | grep -c '^10\.9\.[12]\.1$')"
stop_daemon
umount /etc/ssl/certs/ca-certificates.crt && MNT=""

# ---- Б. хранилище с нашим CA ----
mount --bind "$tmp/ca1.pem" /etc/ssl/certs/ca-certificates.crt && MNT=1
cp "$tmp/d.err" "$tmp/d-a.err"
: > "$tmp/http.log"
: > "$tmp/d.err"
start_daemon
wait_for '[ -n "$(lat a)" ] && [ -n "$(lat b)" ]' 25
la="$(lat a)" lb="$(lat b)"
check "Б. своё хранилище: замеры обоих, b заметно медленнее a (рукопожатие TLS — лишние обороты пути)" "yes" \
    "$([ -n "$la" ] && [ -n "$lb" ] && [ "$lb" -gt $((la + 150)) ] && echo yes || echo "a=$la b=$lb")"
wait_for '[ "$(st outputs.hs.group.selected)" = a ]' 10
check "  группа на быстром a, хотя он второй по порядку; why — fastest" "a fastest" \
    "$(st outputs.hs.group.selected) $(st outputs.hs.group.why)"
check "  сервер отвечал 204 запросам с адресов обоих членов" "2" \
    "$(grep '^/generate_204 ' "$tmp/http.log" | awk '{ print $2 }' | sort -u | grep -c '^10\.9\.[12]\.1$')"
check "  в журнале строк о неудаче замера нет" "0" "$(grep -c 'latency: группа' "$tmp/d.err")"

echo "urlhttps: $pass ok, $fail fail"
[ "$fail" = 0 ]
