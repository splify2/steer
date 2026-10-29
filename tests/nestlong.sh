#!/bin/sh
# Долгое соединение через вложенную группу (жалоба с живого роутера, 2026-10-02): правило ведёт в
# группу all = latency [hys, vpn], hys = latency [h1, h2] (члены — устройства туннелей hysteria2),
# all выбрала vpn. Соединение открытой страницы, которое молчит и потом получает данные от сервера
# (SSE, веб-сокет), обязано дожить, пока внутренняя группа переключается и её туннели живут своей
# жизнью, — ровно как при правиле прямо в vpn.
#
# Сеть — как у роутера владельца: наше пространство — роутер (демон `steerd daemon --watch
# --supervise --apply`, мост br-lan, разметка на ingress), клиент за портом моста (IPv4 и ULA IPv6),
# ответчик R за парами veth: sw3 — vpn (interface, ipv6: nat), sw0 и sw4 — «интернет» до двух узлов
# hysteria2 (сервер apernet, как у tests/run-hy2.sh). Правило — имя под fake-IP и префикс; клиент
# спрашивает DNS у роутера (заворот в резолвер steer). Masquerade IPv4 на sw3 — своей таблицей
# (дело фаервола), IPv6 — ядро steer (ipv6: nat).
#
# Долгие соединения — сервер пишет первым после молчания (как SSE): так видно и снятие записи
# conntrack (ответ сервера без записи не развернуть обратно), которое запрос клиента скрыл бы.
# Соединения открываются до первого прохода сторожа: его привязка «start» застаёт таблицу all уже на
# vpn (её поставил стартовый apply), и снимать соединения ей не за что. До правки bind_device
# снимал — и каждый ответ сервера после молчания пропадал на роутере (захват: до sw3 доходит, в
# br-lan нет). Дальше — переключения внутренней группы и переподключения её туннелей.
#
# NESTLONG_DIRECT=1 — правило прямо в vpn (сравнение). LIBS — раскладка libs (tests/libs-test.sh).
set -u
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)"
skip() { echo "nestlong: $1 — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] && [ -x "$LIBS/plugins/hysteria2/bin/hysteria2" ] || skip "нет раскладки libs ($LIBS, tests/libs-test.sh)"
BIN="$LIBS/steerd"
CLI="${STEER_CLIENT:-./build/steer}"
CLI="$(cd "$(dirname "$CLI")" 2>/dev/null && pwd)/$(basename "$CLI")"
[ -x "$CLI" ] || skip "нет клиента $CLI (make)"
LD_LIBRARY_PATH="$LIBS"; export LD_LIBRARY_PATH
# Протоколы — плагины раскладки (программы build-libs.sh, манифесты кладёт tests/libs-test.sh).
STEER_PLUGINS_ROOT="$LIBS/plugins"; export STEER_PLUGINS_ROOT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    # Приговор по фактическому состоянию, а не по счётчику кругов: условие, ставшее истинным в последнюю
    # десятую секунды, иначе объявлялось бы невыполненным.
    eval "$1" && return 0
    return 1
}
for t in nft ip tc python3 nsenter unshare openssl; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${NESTLONG_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    if [ -z "${HY2_SERVER:-}" ]; then
        d="$(mktemp -d)"
        HY2_SERVER="$d/hysteria"
        c="nestlong-hy2-$$"
        command -v docker >/dev/null 2>&1 && docker create --name "$c" tobyxdd/hysteria:v2 >/dev/null 2>&1 &&
            docker cp "$c:/usr/local/bin/hysteria" "$HY2_SERVER" >/dev/null 2>&1
        command -v docker >/dev/null 2>&1 && docker rm "$c" >/dev/null 2>&1
        [ -x "$HY2_SERVER" ] || skip "нет сервера hysteria (HY2_SERVER или образ tobyxdd/hysteria:v2)"
        export HY2_SERVER
    fi
    NESTLONG_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "свой /sys не смонтировать"
ip link set lo up
nft add table inet nestlong_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet nestlong_probe
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/bin"
D="" SUB="" RPID="" CPID="" BG="" LP="" FP=""
cleanup() {
    kill $SUB $BG $LP $FP $RPID $CPID 2>/dev/null
    [ -n "$D" ] && kill "$D" 2>/dev/null
    [ "$fail" != 0 ] && [ -f "$tmp/d.err" ] && { echo "--- журнал демона (хвост)"; grep -v 'внеочередной' "$tmp/d.err" | tail -n 40; }
    if [ "${NESTLONG_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; elif [ -n "$tmp" ]; then rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть ----
unshare -n sleep 1800 & RPID=$!
unshare -n sleep 1800 & CPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
C() { nsenter -t "$CPID" -n "$@"; }
R ip link set lo up
R ip addr add 10.2.0.1/32 dev lo
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo   # цели проб сторожа
for k in 0 3 4; do
    ip link add sw$k type veth peer name sw${k}p
    ip link set sw${k}p netns "$RPID"
    R ip link set sw${k}p up; R ip addr add 10.9.$k.2/24 dev sw${k}p
    ip link set sw$k up; ip addr add 10.9.$k.1/24 dev sw$k
done
# IPv6 vpn: свой адрес на паре и адрес цели fd02::1 на конце ответчика (маршрут — «default dev sw3»,
# соседа цели ответчик находит на том конце, куда пришёл пакет).
ip -6 addr add fd09:3::1/64 dev sw3 nodad
R ip -6 addr add fd09:3::2/64 dev sw3p nodad
R ip -6 addr add fd02::1/128 dev sw3p nodad
# «Интернет»: маршрут по умолчанию — к первому узлу hysteria2, второй узел — своей парой.
ip route add default via 10.9.0.2 dev sw0
R ip route add 192.168.7.0/24 via 10.9.0.1
# Мост br-lan, клиент за его портом.
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip link set p0 up
ip link add br-lan type bridge
ip link set br-lan type bridge stp_state 0 forward_delay 0 2>/dev/null
ip link set p0 master br-lan
ip addr add 192.168.7.1/24 dev br-lan
ip -6 addr add fd07::1/64 dev br-lan nodad
ip link set br-lan up
C ip link set lo up
C ip addr add 192.168.7.2/24 dev c0
C ip -6 addr add fd07::2/64 dev c0 nodad
C ip link set c0 up
C ip route add default via 192.168.7.1
C ip -6 route add default via fd07::1
nft -f - <<'EOF'
table ip nestlong_nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "sw3" masquerade
    }
}
EOF
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"
export PATH
# Имя адреса проверки групп (A и AAAA — замер по обоим семействам, как у cp.cloudflare.com).
printf '127.0.0.1 localhost\n10.2.0.1 probe.test\nfd02::1 probe.test\n' > "$tmp/hosts"
mount --bind "$tmp/hosts" /etc/hosts

# ---- ответчики ----
cat > "$tmp/srv.py" <<'PY'
import socket, sys, threading, time
def listen(fam, addr, port):
    s = socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(64)
    return s
def http(c, a):
    try:
        d = b''
        while b'\r\n\r\n' not in d:
            x = c.recv(4096)
            if not x: return
            d += x
        c.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
    finally:
        c.close()
# «Сервер пишет первым»: строка клиента «N» — через N секунд молчания сервер шлёт адрес
# собеседника; так по кругу, пока клиент не закроет.
def push(c, a):
    f = c.makefile('rwb', buffering=0)
    try:
        for line in f:
            time.sleep(int(line.strip() or b'0'))
            f.write(a[0].encode() + b'\n')
    except OSError:
        pass
def loop(s, fn):
    while True:
        c, a = s.accept()
        threading.Thread(target=fn, args=(c, a), daemon=True).start()
ts = []
for fam, addr in ((socket.AF_INET, '10.2.0.1'), (socket.AF_INET6, 'fd02::1')):
    for port, fn in ((8080, http), (9000, push)):
        ts.append(threading.Thread(target=loop, args=(listen(fam, addr, port), fn), daemon=True))
for t in ts: t.start()
print('ready', flush=True)
for t in ts: t.join()
PY
nsenter -t "$RPID" -n python3 "$tmp/srv.py" >"$tmp/srv.log" 2>&1 & BG="$BG $!"
# DNS выше резолвера steer (у роутера — dnsmasq на 127.0.0.1:53): claude.test — A и AAAA цели.
cat > "$tmp/dns.py" <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 53))
while True:
    q, a = s.recvfrom(1500)
    i = 12
    while q[i]: i += q[i] + 1
    qtype = struct.unpack('>H', q[i+1:i+3])[0]
    qsec = q[12:i+5]
    ans = b''
    if qtype == 1: ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('10.2.0.1')
    if qtype == 28: ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + socket.inet_pton(socket.AF_INET6, 'fd02::1')
    s.sendto(q[:2] + b'\x81\x80' + q[4:6] + (b'\x00\x01' if ans else b'\x00\x00') + b'\x00\x00\x00\x00' + qsec + ans, a)
PY
python3 "$tmp/dns.py" >"$tmp/dns.log" 2>&1 & BG="$BG $!"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -subj "/CN=hy2.test" >/dev/null 2>&1
for k in 0 4; do
    printf 'listen: 10.9.%s.2:4433\ntls: { cert: %s, key: %s }\nauth: { type: password, password: hunter2 }\n' \
        "$k" "$tmp/cert.pem" "$tmp/key.pem" > "$tmp/hy$k.yaml"
    nsenter -t "$RPID" -n "$HY2_SERVER" server -c "$tmp/hy$k.yaml" >"$tmp/hy$k.log" 2>&1 & BG="$BG $!"
done
printf 'hysteria2://hunter2@10.9.0.2:4433/?insecure=1#n1\n' > "$tmp/sub1"
printf 'hysteria2://hunter2@10.9.4.2:4433/?insecure=1#n2\n' > "$tmp/sub2"
wait_for 'grep -q ready "$tmp/srv.log"' 10

# ---- спека: как у владельца (splify2 пишет члены группы interface-выходами на устройства туннелей) ----
printf 'claude.test\n' > "$tmp/d.lst"
printf '10.2.0.0/24\nfd02::/64\n' > "$tmp/p.lst"
OUT=all
[ "${NESTLONG_DIRECT:-}" = 1 ] && OUT=vpn
# Интервал замера групп: 10 с — чтобы за прогон набралось переключений; NESTLONG_IV=0 — умолчание
# (180 с), как у владельца.
IV="interval: ${NESTLONG_IV:-10},"
[ "${NESTLONG_IV:-10}" = 0 ] && IV=""
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [br-lan] }
lists:
  l: { domains_file: $tmp/d.lst, prefixes_file: $tmp/p.lst }
outputs:
  hys2-1: { kind: tunnel, protocol: hysteria2, subscription: $tmp/sub1, on_fail: drop }
  hys2-2: { kind: tunnel, protocol: hysteria2, subscription: $tmp/sub2, on_fail: drop }
  hys2.hys2-1: { kind: interface, device: hys2-1, on_fail: drop }
  hys2.hys2-2: { kind: interface, device: hys2-2, on_fail: drop }
  hys2: { kind: group, pick: latency, members: [hys2.hys2-1, hys2.hys2-2], url: "http://probe.test:8080/generate_204", $IV idle_timeout: 0, on_fail: drop }
  vpn: { kind: interface, device: sw3, ipv6: nat, on_fail: drop }
  all: { kind: group, pick: latency, tolerance: 200, members: [hys2, vpn], url: "http://probe.test:8080/generate_204", $IV idle_timeout: 0, on_fail: drop }
rules:
  - { name: r, to: [l], out: $OUT, resolve: fakeip }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
STEER_SOCKET="$tmp/steer.sock"
export STEER_SOCKET
# Задержки как на живом роутере: vpn ~60 мс, туннели — 116…440: all выбирает vpn.
R tc qdisc add dev sw3p root netem delay 30ms
R tc qdisc add dev sw0p root netem delay 120ms
R tc qdisc add dev sw4p root netem delay 180ms
"$BIN" daemon --watch --watch-period 5 --supervise --apply --socket "$tmp/steer.sock" $S \
    >>"$tmp/d.out" 2>>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/steer.sock" ] && grep -q "watch: первый проход" "$tmp/d.err"' 20
# Строки подписчика — с отметкой времени (сверка с захватом пакетов).
"$CLI" subscribe $S 2>&1 | while IFS= read -r l; do echo "$(date +%T.%N | cut -c1-12) $l"; done > "$tmp/sub.out" &
SUB=$!
reg() { awk -v o="$1" '$1 == o { print $'"$2"' }' "$tmp/st/registry"; }
tdev() { ip route show table "$(reg "$1" 3)" | awk '$1 == "default" && $2 == "dev" { print $3 }' | head -n 1; }
# Таблицу all на vpn ставит уже стартовый apply (подхват записи сторожа), а первый проход сторожа
# придёт позже — после первых замеров и подъёма туннелей. Долгие соединения открываются в этом
# окне: привязка «start» первого прохода их застаёт (так же — после apply с новым выходом).
wait_for '[ "$(tdev all)" = sw3 ]' 60

# Внутренняя группа переключается: узлы меняются задержками (120 и 180 мс) каждые 15 с.
( d0=120 d4=180
  while :; do
      sleep 15
      t=$d0; d0=$d4; d4=$t
      R tc qdisc change dev sw0p root netem delay ${d0}ms
      R tc qdisc change dev sw4p root netem delay ${d4}ms
  done ) & FP=$!

# Долгие соединения клиента — к имени под fake-IP (IPv4 и IPv6) и к адресу из префикса: по одному
# на каждый промежуток молчания, ROUNDS кругов «сервер молчит N с и пишет».
cat > "$tmp/long.py" <<'PY'
import socket, struct, sys, threading, time
out = open(sys.argv[1], 'a', buffering=1)
gaps = [int(x) for x in sys.argv[2].split(',')]
rounds = int(sys.argv[3])
def resolve(name, qtype):
    q = struct.pack('>HHHHHH', 7, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00' + struct.pack('>HH', qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, ('192.168.7.1', 53)); r = s.recv(1500)
    if struct.unpack('>H', r[6:8])[0] == 0: return None
    return socket.inet_ntop(socket.AF_INET if qtype == 1 else socket.AF_INET6, r[-(4 if qtype == 1 else 16):])
targets = [('fake4', resolve('claude.test', 1)), ('fake6', resolve('claude.test', 28)), ('pfx4', '10.2.0.1')]
out.write('# %s\n' % ' '.join('%s=%s' % t for t in targets))
t0 = time.time()
def one(tag, addr, g):
    try:
        fam = socket.AF_INET6 if ':' in addr else socket.AF_INET
        s = socket.socket(fam); s.settimeout(5); s.connect((addr, 9000))
        f = s.makefile('rwb', buffering=0)
        for k in range(rounds):
            s.settimeout(g + 15)
            f.write(b'%d\n' % g)
            r = f.readline().decode().strip()
            out.write('%s %d %d %s\n' % (tag, g, k, r or 'нет'))
    except Exception as e:
        out.write('%s %d - ошибка:%s:%s через %.1f с\n' % (tag, g, type(e).__name__, e, time.time() - t0))
ts = [threading.Thread(target=one, args=(t, a, g)) for (t, a) in targets if a for g in gaps]
for t in ts: t.start()
for t in ts: t.join()
out.write('done\n')
PY
GAPS="${NESTLONG_GAPS:-20,50,100}"
ROUNDS="${NESTLONG_ROUNDS:-2}"
: > "$tmp/long.log"
if [ -n "${NESTLONG_DUMP:-}" ]; then
    nsenter -t "$RPID" -n tcpdump -ni sw3p -w "$tmp/sw3.pcap" >/dev/null 2>&1 & BG="$BG $!"
    tcpdump -ni br-lan -w "$tmp/lan.pcap" >/dev/null 2>&1 & BG="$BG $!"
    sleep 1
fi
pre="$(grep -c '"ev":"switched","out":"all"' "$tmp/sub.out")"
nsenter -t "$CPID" -n python3 "$tmp/long.py" "$tmp/long.log" "$GAPS" "$ROUNDS" >"$tmp/long.err" 2>&1 & LP=$!
wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"all\"" "$tmp/sub.out"' 60
check "all — на vpn (sw3), и первый проход привязал её уже при открытых соединениях" "sw3 0 1" \
    "$(tdev all) $pre $(grep -c '"ev":"switched","out":"all"' "$tmp/sub.out")"
maxg="$(echo "$GAPS" | tr ',' '\n' | sort -n | tail -1)"
wait_for 'grep -q "^done" "$tmp/long.log"' $(((maxg + 15) * ROUNDS + 30))
kill $FP 2>/dev/null; FP=""
echo "  hys2 переключилась $(grep -c '"ev":"switched","out":"hys2"' "$tmp/sub.out") раз, all — $(grep -c '"ev":"switched","out":"all"' "$tmp/sub.out"); авторизаций hysteria2: $(grep -c 'принял авторизацию' "$tmp/d.err")"
sed 's/^/  /' "$tmp/long.log"
total=$(( $(echo "$GAPS" | tr ',' '\n' | wc -l) * ROUNDS ))
check "fake-IP IPv4: все ответы сервера после молчания дошли, через vpn" "$total" \
    "$(grep -c '^fake4 .* 10\.9\.3\.1$' "$tmp/long.log")"
check "fake-IP IPv6: все ответы дошли, через vpn (NAT66)" "$total" \
    "$(grep -c '^fake6 .* fd09:3::1$' "$tmp/long.log")"
check "префикс IPv4: все ответы дошли, через vpn" "$total" \
    "$(grep -c '^pfx4 .* 10\.9\.3\.1$' "$tmp/long.log")"
echo "nestlong: $pass ok, $fail fail"
[ "$fail" = 0 ]
