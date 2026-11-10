#!/bin/sh
# Мёртвое соединение TCP апстрима резолвера: путь к серверу пропал молча, без RST и без FIN.
# Устройство проверяемого — src/dnsd/dup.c, conn_tcp_watch.
#
# Так бывает после простоя: запись NAT о соединении истекла у провайдера, адрес PPPoE сменился —
# соединение у резолвера «готово», а пакеты в него уходят в никуда. Прежде вопрос, попавший в такое
# соединение, ждал весь срок (четыре секунды) и получал отказ: повторить его было уже некому.
#
# Сервер — обычный DNS по TCP на петле (tcp://): соединение держится между вопросами так же, как у
# DoT и DoH, и за ним следит тот же код. «Путь пропал» — правила nft, которые молча выбрасывают
# пакеты ОДНОГО соединения (по порту клиента) в обе стороны; новые соединения к тому же серверу
# проходят.
#
# Что проверяется.
#  1. Вопрос ушёл в мёртвое соединение: ядро рвёт его через полторы секунды (TCP_USER_TIMEOUT),
#     вопрос уходит на новом соединении — клиент получает ответ, а не SERVFAIL через четыре секунды.
#  2. Соединение умерло, пока простаивало: ядро находит это пробой (через 15 с тишины, ответа ждёт
#     5 с) и рвёт его до вопроса клиента — следующий вопрос отвечен сразу, на новом соединении.
#
# Нужны root (сетевое пространство и nf_tables), nft и python3. Без них стенд пропускается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "dnsdead: python3 нет — пропускаю"; exit 0; }
command -v nft >/dev/null 2>&1 || { echo "dnsdead: nft нет — пропускаю"; exit 0; }
if [ "${DNSDEAD_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "dnsdead: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "dnsdead: unshare -n недоступен — пропускаю"; exit 0; }
    DNSDEAD_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet bh 2>/dev/null || { echo "dnsdead: nf_tables недоступен — пропускаю"; exit 0; }
nft add chain inet bh out '{ type filter hook output priority 0; }'

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} 2>/dev/null; rm -rf "$tmp"' EXIT
sh tests/plugroot.sh "$tmp/plugins" "${BUILD:-build}" >/dev/null || { echo "dnsdead: каталог плагинов не собран"; exit 2; }
STEER_PLUGINS_ROOT="$tmp/plugins"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC

LPORT=15330
UPORT=15383
SPORT=15384

# Сервер: сообщения с длиной в два байта, ответ 10.0.0.1. Порт клиента каждого принятого соединения
# — строкой в файл: по нему стенд «обрывает путь» именно этого соединения.
cat > "$tmp/srv.py" <<'PY'
import socket, struct, sys, threading
def recvn(c, k):
    b = b''
    while len(b) < k:
        d = c.recv(k - len(b))
        if not d: return None
        b += d
    return b
def conn(c):
    try:
        while True:
            h = recvn(c, 2)
            if not h: break
            q = recvn(c, struct.unpack('>H', h)[0])
            if not q: break
            qend = 12
            while q[qend]: qend += 1 + q[qend]
            qend += 5
            r = q[:2] + b'\x81\x80' + q[4:6] + b'\x00\x01\x00\x00\x00\x00' + q[12:qend] + \
                b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([10, 0, 0, 1])
            c.sendall(struct.pack('>H', len(r)) + r)
    except Exception:
        pass
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("127.0.0.1", int(sys.argv[1]))); t.listen(16)
print("ready", flush=True)
while True:
    c, a = t.accept()
    with open(sys.argv[2], 'a') as f: f.write("%d\n" % a[1])
    threading.Thread(target=conn, args=(c,), daemon=True).start()
PY

cat > "$tmp/ask.py" <<'PY'
import socket, struct, sys, time
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
t = time.time()
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout 0"); sys.exit()
ms = int((time.time() - t) * 1000)
rc = d[3] & 0x0f
if rc: print("rcode%d %d" % (rc, ms))
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty %d" % ms)
else: print("%s %d" % (".".join(str(b) for b in d[-4:]), ms))
PY

: > "$tmp/conns"
python3 "$tmp/srv.py" "$SPORT" "$tmp/conns" > "$tmp/srv.out" 2>&1 & UPID=$!
n=0; while ! grep -q ready "$tmp/srv.out" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done

printf 'dead.test\n' > "$tmp/dead.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { addr: [127.0.0.0/8] }
lists:
  dead: { domains_file: $tmp/dead.lst }
outputs:
  vpn: { kind: interface, device: lo }
dns:
  mode: realip
rules:
  - { name: dead, to: [dead], out: vpn, dns: { url: "tcp://127.0.0.1:$SPORT" } }
EOF
mkdir -p "$tmp/st"
"$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st" --listen-port "$LPORT" \
    --upstream-port "$UPORT" > "$tmp/d.log" 2>&1 & DPID=$!
sleep 1
kill -0 "$DPID" 2>/dev/null || { echo "FAIL резолвер не поднялся:"; cat "$tmp/d.log"; exit 1; }

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
ask() { python3 "$tmp/ask.py" "$LPORT" "$1"; }
addr() { echo "${1% *}"; }
ms() { echo "${1#* }"; }
inr() { [ "$1" -ge "$2" ] && [ "$1" -le "$3" ] && echo yes || echo "нет ($1 мс)"; }
conns() { wc -l < "$tmp/conns" | tr -d ' '; }
# Путь соединения с портом клиента $1 пропал: пакеты в обе стороны выбрасываются молча.
blackhole() {
    nft add rule inet bh out tcp sport "$1" tcp dport "$SPORT" drop
    nft add rule inet bh out tcp sport "$SPORT" tcp dport "$1" drop
}

r="$(ask q1.dead.test)"
check "соединение живо: ответ сервера" "10.0.0.1" "$(addr "$r")"
check "  соединение одно" "1" "$(conns)"

# --- 1. Вопрос в мёртвое соединение --------------------------------------------------------
blackhole "$(tail -n 1 "$tmp/conns")"
r="$(ask q2.dead.test)"
check "путь соединения пропал: клиент всё равно получил ответ" "10.0.0.1" "$(addr "$r")"
check "  через 1,5 с (срок неподтверждённого), а не отказ через 4 с" "yes" "$(inr "$(ms "$r")" 1300 2800)"
check "  вопрос ушёл на новом соединении" "2" "$(conns)"

# --- 2. Соединение умерло, пока простаивало -------------------------------------------------
blackhole "$(tail -n 1 "$tmp/conns")"
sleep 23                      # 15 с тишины до пробы и 5 с ожидания её подтверждения
r="$(ask q3.dead.test)"
check "соединение умерло в простое: ответ есть" "10.0.0.1" "$(addr "$r")"
check "  сразу — мёртвое соединение закрыто до вопроса" "yes" "$(inr "$(ms "$r")" 0 500)"
check "  на новом соединении" "3" "$(conns)"

kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
nft delete table inet bh
if [ "$fail" -gt 0 ]; then echo "--- dnsd"; tail -n 20 "$tmp/d.log"; fi
echo "dnsdead: пройдено $pass, провалено $fail"
[ "$fail" = 0 ]
