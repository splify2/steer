#!/bin/sh
# Группы выходов спеки v2 в демоне с настоящими nft и ip (docs/architecture.md, «4в»).
#
# Сеть стенда: наше пространство (демон `steerd daemon --watch --apply`), клиент за устройством
# lanx (192.168.7.2 и 192.168.7.3) и ответчик за тремя парами veth — sw1 (член a), sw2 (член b) и
# sw3 (член c, только у групп by: site и site_client, 3а). На ответчике:
# 1.1.1.1 и 8.8.8.8 — цели проб сторожа, 10.2.0.1:8080 — HTTP-ответчик generate_204 (считает
# запросы по пути и отвечает, с какого адреса пришёл запрос: 10.9.1.1 — через a, 10.9.2.1 —
# через b) и эхо TCP на 10.2.0.1:9000 для долгого соединения. Задержка члена — tc netem на
# стороне ответчика.
#
# Что проверяется.
#  1. manual: `steer select man b` переключает таблицу группы на устройство b без apply (набор
#     правил в ядре не пересоздаётся), подписчику — switched с by: select и member; status — select
#     и selected; выбор переживает перезапуск демона и «перезагрузку» (чистый каталог состояния,
#     та же спека: файл select лежит рядом со спекой, а не в tmpfs); select мёртвого члена — отказ
#     группы по on_fail (blackhole), а не другой член; отказы команды (не член, не manual).
#  1а. До первого прохода — то же решение, что у прохода: демон без сторожа (стартовый apply и ни
#     одного прохода) после «перезагрузки» ставит таблицу группы на выбранный член, а не на первый;
#     выбранный член лежит — сразу on_fail (blackhole), и карта balance сразу без упавшего члена;
#     запись сторожа, устаревшая относительно файла select (файл сменили при остановленном
#     демоне), выбор не перебивает.
#  2. latency = urltest: через двух членов с разной задержкой выбирается быстрый, хотя он второй
#     по порядку; запрос идёт именно через члена (ответчик видит адрес его устройства); без `url` в
#     спеке — адрес по умолчанию (имя cp.cloudflare.com из hosts, порт 80); гистерезис: выигрыш меньше
#     tolerance — остаётся на текущем; больше — уходит.
#  2а. interval короче периода сторожа: группа с interval 10 при периоде 60 меряется каждые ~10 с
#     (по счётчику запросов у ответчика), а член, ставший медленным, теряет группу по замеру, не
#     дожидаясь прохода по периоду.
#  2б. IPv6: у группы, все члены которой несут IPv6, замер идёт и по IPv4, и по IPv6 (ответчик видит
#     запрос с адреса IPv6 каждого члена); status — latency4 и latency6; член, быстрый по IPv4, но
#     медленный по IPv6, не выигрывает (выбор — по худшему из двух).
#  2в. допуск: при разнице меньше допуска по умолчанию (50) остаётся первый по порядку, и status
#     объясняет это (fastest, why: in_tolerance, tolerance); tolerance: 0 — настоящий ноль: выбирается
#     строго самый быстрый, хотя он второй по порядку (прежде 0 читался как «не задан» и давал 50, и
#     «самый быстрый» превращался в первого живого). У группы из одного члена выбирать не из чего, и
#     why, fastest, latency_failed у неё нет.
#  2г. самый быстрый член упал: группа уходит на следующего по замеру (самого быстрого из живых), а не
#     на первого живого по порядку, и возвращается на него, когда он ожил.
#  2д. замер не удался ни у кого (проверочный адрес не ответил): группа идёт по порядку, status —
#     why: no_measure и latency_failed, в журнале — строка об этом; повтор замера — раньше срока
#     (interval группы — 90 с, а повтор — через ~15), и группа переходит на самого быстрого.
#  3. balance: новые соединения клиента расходятся по обоим членам; упавший член выпадает из карты
#     (карта в ядре — только цепочка живого, событие balance), новые идут на живого; установленное
#     соединение не перескакивает ни при уходе, ни при возврате другого члена.
#  3а. balance by: site — один сайт на одном члене (24 адреса, у каждого все соединения на одном
#     члене, а сайты — по всем трём членам); член a лёг — сайты b и c остались на своих членах, сайты a
#     разошлись по живым; a вернулся — каждый сайт снова там, где был. by: site_client — у каждого
#     из двух адресов клиента сайт на одном члене, но у разных клиентов один и тот же сайт может
#     быть на разных членах.
#  4. idle_timeout: без трафика через группу ни одного запроса проверки, status — why: idle (простой
#     не отказ: latency_failed нет, в журнале нет «замера нет»); трафик пошёл — замер есть.
#
# Нужны root, unshare, nsenter, nft, ip, tc и python3; без них — пропуск.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
skip() { echo "groupsmatch: $1 — пропуск"; exit 0; }
for t in nft ip tc python3 nsenter unshare; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${GROUPS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    GROUPS_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ip link set lo up
nft add table inet groupsmatch_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet groupsmatch_probe
unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null || skip "свой /sys не смонтировать"
tc qdisc add dev lo root netem delay 1ms 2>/dev/null && tc qdisc del dev lo root 2>/dev/null ||
    skip "tc netem недоступен"
sysctl -qw net.ipv4.ip_forward=1

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/bin"
D="" SUB="" RPID="" CPID="" HP="" EP="" SP="" LP=""
cleanup() {
    kill $SUB $HP $EP $SP $LP $RPID $CPID 2>/dev/null
    [ -n "$D" ] && kill "$D" 2>/dev/null
    # Провал — журнал демона в вывод стенда; GROUPS_KEEP=1 оставляет каталог стенда.
    [ "$fail" != 0 ] && [ -f "$tmp/d.err" ] && { echo "--- журнал демона (хвост)"; tail -n 40 "$tmp/d.err"; }
    if [ "${GROUPS_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; elif [ -n "$tmp" ]; then rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть ----
unshare -n sleep 900 & RPID=$!
unshare -n sleep 900 & CPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
C() { nsenter -t "$CPID" -n "$@"; }
R ip link set lo up
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo; R ip addr add 10.2.0.1/32 dev lo
# «Сайты» групп by (3а): 10.4.0.1-24 — by: site, 10.5.0.1-24 — by: site_client.
for i in $(seq 1 24); do R ip addr add 10.4.0.$i/32 dev lo; R ip addr add 10.5.0.$i/32 dev lo; done
for k in 1 2 3; do
    ip link add sw$k type veth peer name sw${k}p
    ip link set sw${k}p netns "$RPID"
    R ip link set sw${k}p up; R ip addr add 10.9.$k.2/24 dev sw${k}p
    ip link set sw$k addrgenmode none 2>/dev/null
    ip link set sw$k up; ip addr add 10.9.$k.1/24 dev sw$k
done
# IPv6 членов (2б): свой адрес у каждой пары и адрес ответчика fd02::1 на обоих его концах — маршрут
# члена IPv6 — «default dev swN», и соседа fd02::1 ответчик находит на том конце, куда пришёл запрос.
# Не встало (IPv6 в пространстве выключен) — часть 2б пропускается.
# keep_addr_on_down: стенд роняет устройства членов (ip link set down), а IPv6 без этого снимает
# адреса с упавшего устройства насовсем.
V6=1
for k in 1 2; do
    sysctl -qw "net.ipv6.conf.sw$k.keep_addr_on_down=1" 2>/dev/null
    ip -6 addr add fd09:$k::1/64 dev sw$k nodad 2>/dev/null || V6=0
    R ip -6 addr add fd09:$k::2/64 dev sw${k}p nodad 2>/dev/null || V6=0
    R ip -6 addr add fd02::1/128 dev sw${k}p nodad 2>/dev/null || V6=0
done
# Имя адреса проверки с A и AAAA — файлом hosts в пространстве имён монтирования демона.
printf '127.0.0.1 localhost\n10.2.0.1 probe.test\n10.2.0.1 cp.cloudflare.com\nfd02::1 probe.test\n' > "$tmp/hosts"
ip link add lanx type veth peer name lanxp
ip link set lanxp netns "$CPID"
ip link set lanx up; ip addr add 192.168.7.1/24 dev lanx
C ip link set lo up; C ip link set lanxp up; C ip addr add 192.168.7.2/24 dev lanxp
C ip addr add 192.168.7.3/24 dev lanxp
C ip route add default via 192.168.7.1
# Как у роутера — маршрут по умолчанию в WAN (здесь пустое устройство). Ответ на замер через члена
# приходит с его устройства без метки, и проверка обратного пути (rp_filter=2, loose) ищет маршрут к
# адресу ответчика в main: без маршрута по умолчанию ответ был бы выброшен.
ip link add wan0 type dummy; ip link set wan0 up; ip addr add 203.0.113.1/24 dev wan0
ip route add default via 203.0.113.254 dev wan0
# Masquerade — дело фаервола, а не движка: здесь своей таблицей, чтобы ответчик отвечал в ту же пару.
nft -f - <<'EOF'
table ip groupsmatch_nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname { "sw1", "sw2", "sw3" } masquerade
    }
}
EOF
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"
export PATH

# HTTP-ответчик: 204 на /generate_204 и /idle_204 (порты 8080 и 80), журнал «путь адрес» по строке; /who — адрес.
cat > "$tmp/http.py" <<'PY'
import os, socket, sys, threading
log = open(sys.argv[1], 'a', buffering=1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.2.0.1', 8080)); s.listen(64)
def serve(c, a):
    try:
        d = b''
        while b'\r\n\r\n' not in d:
            x = c.recv(4096)
            if not x: return
            d += x
        path = d.split(b' ')[1].decode()
        log.write('%s %s\n' % (path, a[0]))
        if path == '/who':
            body = a[0].encode()
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
        elif path.startswith('/rt_') and len(sys.argv) > 3 and os.path.exists(sys.argv[3]):
            # Отказ проверочного адреса (2д): пока лежит файл, путь /rt_… отвечает 503.
            c.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
        else:
            c.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
    finally:
        c.close()
def accept_loop(sock):
    while True:
        c, a = sock.accept()
        threading.Thread(target=serve, args=(c, a), daemon=True).start()
# Порт 80 — адрес проверки по умолчанию (http://cp.cloudflare.com/generate_204, имя — из hosts).
s80 = socket.socket(); s80.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s80.bind(('10.2.0.1', 80)); s80.listen(64)
threading.Thread(target=accept_loop, args=(s80,), daemon=True).start()
# IPv6 (2б): тот же ответчик на [fd02::1]:8080, журнал — с адресом IPv6 члена.
if len(sys.argv) > 2 and sys.argv[2] == '1':
    s6 = socket.socket(socket.AF_INET6); s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s6.bind(('fd02::1', 8080)); s6.listen(64)
    threading.Thread(target=accept_loop, args=(s6,), daemon=True).start()
accept_loop(s)
PY
# Эхо: на каждую строку отвечает адресом собеседника (через какого члена пришло соединение).
cat > "$tmp/echo.py" <<'PY'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.2.0.1', 9000)); s.listen(16)
def serve(c, a):
    f = c.makefile('rwb', buffering=0)
    for line in f:
        f.write(a[0].encode() + b'\n')
while True:
    c, a = s.accept()
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
PY
# «Кто я» на любом адресе ответчика, порт 8090: ответ — адрес собеседника, то есть член (3а).
cat > "$tmp/site.py" <<'PY'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8090)); s.listen(64)
def serve(c, a):
    try:
        c.sendall(a[0].encode())
    finally:
        c.close()
while True:
    c, a = s.accept()
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
PY
# Долгое соединение клиента: пишет строку по сигналу (файл-триггер), ответ — в журнал.
cat > "$tmp/long.py" <<'PY'
import socket, sys, time, os
s = socket.create_connection(('10.2.0.1', 9000), timeout=5)
f = s.makefile('rwb', buffering=0)
out = open(sys.argv[1], 'a', buffering=1)
n = 0
while True:
    if os.path.exists(sys.argv[2] + '.%d' % n):
        f.write(b'x\n')
        out.write('%d %s\n' % (n, f.readline().decode().strip()))
        n += 1
    time.sleep(0.05)
PY
: > "$tmp/http.log"
# nsenter напрямую, а не функцией R: у функции в фоне $! — подоболочка, и kill её не снял бы сервер.
nsenter -t "$RPID" -n python3 "$tmp/http.py" "$tmp/http.log" "$V6" "$tmp/rt.fail" >"$tmp/http.err" 2>&1 & HP=$!
nsenter -t "$RPID" -n python3 "$tmp/echo.py" >"$tmp/echo.err" 2>&1 & EP=$!
nsenter -t "$RPID" -n python3 "$tmp/site.py" >"$tmp/site.err" 2>&1 & SP=$!
sleep 0.5

cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    if isinstance(d, dict): d = d.get(k)
    elif isinstance(d, list) and k.isdigit(): d = d[int(k)] if int(k) < len(d) else None
    else: d = None
if isinstance(d, list): print(','.join(str(x) for x in d))
elif isinstance(d, dict): print(','.join('%s=%s' % kv for kv in sorted(d.items())))
else: print('-' if d is None else d)
PY
j() { python3 "$tmp/j.py" "$1"; }

printf '10.2.0.0/24\n' > "$tmp/bal.lst"
printf '10.3.0.0/24\n' > "$tmp/idl.lst"
printf '10.4.0.0/24\n' > "$tmp/sit.lst"
printf '10.5.0.0/24\n' > "$tmp/sic.lst"
V6G=""
[ "$V6" = 1 ] && V6G='  v6g: { kind: group, pick: latency, members: [b, a], url: "http://probe.test:8080/v6_204", tolerance: 60, idle_timeout: 0 }'
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lanx] }
lists:
  lb: { prefixes_file: $tmp/bal.lst }
  li: { prefixes_file: $tmp/idl.lst }
  ls: { prefixes_file: $tmp/sit.lst }
  lc: { prefixes_file: $tmp/sic.lst }
outputs:
  a:   { kind: interface, device: sw1 }
  b:   { kind: interface, device: sw2 }
  c:   { kind: interface, device: sw3 }
  man: { kind: group, pick: manual, members: [a, b], default: a }
  lat: { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/generate_204", tolerance: 60, idle_timeout: 0 }
  idl: { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/idle_204", idle_timeout: 3600 }
  iv:  { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/iv_204", tolerance: 60, interval: 10, idle_timeout: 0 }
$V6G
  dflt:  { kind: group, pick: latency, members: [b, a], idle_timeout: 0 }
  one:   { kind: group, pick: latency, members: [a], idle_timeout: 0 }
  tol:   { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/tol_204", idle_timeout: 0 }
  strict: { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/strict_204", tolerance: 0, idle_timeout: 0 }
  dead3: { kind: group, pick: latency, members: [b, c, a], url: "http://10.2.0.1:8080/dead3_204", idle_timeout: 0 }
  rt:    { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/rt_204", interval: 90, idle_timeout: 0 }
  bal: { kind: group, pick: balance, members: [a, b] }
  sit: { kind: group, pick: balance, by: site, members: [a, b, c] }
  sic: { kind: group, pick: balance, by: site_client, members: [a, b, c] }
rules:
  - { name: bal, to: [lb], out: bal }
  - { name: idl, to: [li], out: idl }
  - { name: sit, to: [ls], out: sit }
  - { name: sic, to: [lc], out: sic }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
STEER_SOCKET="$tmp/steer.sock"
export STEER_SOCKET
c() { "$BIN" "$@" $S; }
PERIOD=3
start_daemon() {
    unshare -m sh -c "mount -t sysfs sysfs /sys && mount --bind \"$tmp/hosts\" /etc/hosts && \
        exec \"$BIN\" daemon --watch --watch-period $PERIOD --apply \
        --socket \"$tmp/steer.sock\" $S" >>"$tmp/d.out" 2>>"$tmp/d.err" &
    D=$!
    wait_for '[ -S "$tmp/steer.sock" ] && [ "$(grep -c "watch: первый проход" "$tmp/d.err")" -gt "$starts" ]' 15
    starts=$((starts + 1))
    # Подписчик — заново у каждого экземпляра демона (соединение уходит вместе с прежним).
    [ -n "$SUB" ] && kill "$SUB" 2>/dev/null
    : > "$tmp/sub.out"
    "$BIN" subscribe $S > "$tmp/sub.out" 2>&1 &
    SUB=$!
    wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out"' 5
}
starts=0
stop_daemon() { kill "$D" 2>/dev/null; wait "$D" 2>/dev/null; D=""; rm -f "$tmp/steer.sock"; }
# Демон без сторожа (1а): стартовый apply и ни одного прохода — таблицы выходов ровно те, что
# поставил apply при старте, то есть то, что видит клиент в окно до первого прохода.
start_bare() {
    n0="$(grep -c 'спека применена при старте' "$tmp/d.err" 2>/dev/null)"
    unshare -m sh -c "mount -t sysfs sysfs /sys && mount --bind \"$tmp/hosts\" /etc/hosts && \
        exec \"$BIN\" daemon --apply --socket \"$tmp/steer.sock\" $S" >>"$tmp/d.out" 2>>"$tmp/d.err" &
    D=$!
    wait_for '[ -S "$tmp/steer.sock" ] && [ "$(grep -c "спека применена при старте" "$tmp/d.err")" -gt "${n0:-0}" ]' 15
}
# «Перезагрузка»: каталог состояния пуст (tmpfs), таблица группы в ядре пуста; спека и файл select
# рядом с ней — на месте.
reboot_state() {
    ts=""
    for g in "$@"; do ts="$ts $(reg "$g" 3)"; done
    [ -n "$tmp" ] && [ -d "$tmp/st" ] && rm -rf "$tmp/st" && mkdir -p "$tmp/st"
    for t in $ts; do ip route flush table "$t"; done
}
reg() { awk -v o="$1" '$1 == o { print $'"$2"' }' "$tmp/st/registry"; }
tdev() { ip route show table "$(reg "$1" 3)" | awk '$1 == "default" && $2 == "dev" { print $3 }' | head -n 1; }
tbh() { ip route show table "$(reg "$1" 3)" | grep -c '^blackhole default *$'; }
troutes() { ip route show table "$(reg "$1" 3)" | tr '\n' ';'; }
# status — только от демона (движок подменён отказом): память сторожа — у него.
st() { STEER_ENGINE=/bin/false "$BIN" status $S | j "$1"; }

start_daemon
wait_for '[ "$(tdev man)" = sw1 ]' 10
check "manual: до первой команды — default (a, sw1)" "sw1" "$(tdev man)"
wait_for '[ "$(st outputs.man.group.selected)" = a ]' 20
check "  status: pick, select, selected" "manual a a" \
    "$(st outputs.man.group.pick) $(st outputs.man.group.select) $(st outputs.man.group.selected)"

# ---- 1. manual ----
h0="$(nft -a list chain inet steer prerouting_mark | grep -o 'handle [0-9]*' | tr '\n' ' ')"
out="$(c select man b 2>&1)"; rc=$?
check "select man b: код 0 и ответ" "0 1" "$rc $(echo "$out" | grep -c 'выбран b (sw2)')"
check "  таблица группы — на устройство b сразу" "sw2" "$(tdev man)"
check "  без apply: правила в ядре те же (номера правил не сменились)" "$h0" \
    "$(nft -a list chain inet steer prerouting_mark | grep -o 'handle [0-9]*' | tr '\n' ' ')"
wait_for 'grep -q "\"by\":\"select\"" "$tmp/sub.out"' 3
check "  подписчику — switched by: select с членом" \
    '{"v":1,"ev":"switched","out":"man","from":"sw1","to":"sw2","why":"select","member":"b","by":"select"}' \
    "$(grep '"ev":"switched"' "$tmp/sub.out" | grep '"by":"select"' | head -n 1)"
check "  status: select b, selected b" "b b" "$(st outputs.man.group.select) $(st outputs.man.group.selected)"
check "  выбор — в файле select рядом со спекой, не в каталоге состояния" "man b -" \
    "$(cat "$tmp/select") $([ -e "$tmp/st/select" ] && echo есть || echo -)"
sleep 7
check "  проход сторожа выбор не отменяет" "sw2" "$(tdev man)"
out="$(c select man nope 2>&1)"; rc=$?
check "select не члена — отказ 2" "2 1" "$rc $(echo "$out" | grep -c 'не член группы man')"
out="$(c select lat a 2>&1)"; rc=$?
check "select у группы не manual — отказ 2" "2 1" "$rc $(echo "$out" | grep -c 'pick: latency')"

stop_daemon
check "перезапуск: таблица осталась на b" "sw2" "$(tdev man)"
start_daemon
sleep 1
check "  после перезапуска демона выбор тот же (status select и таблица)" "b sw2" \
    "$(st outputs.man.group.select) $(tdev man)"
# «Перезагрузка»: каталог состояния на роутере — tmpfs, после неё он пуст, а спека (и выбор рядом
# с ней) — на месте.
stop_daemon
[ -n "$tmp" ] && [ -d "$tmp/st" ] && rm -rf "$tmp/st" && mkdir -p "$tmp/st"
start_daemon
wait_for '[ "$(tdev man)" = sw2 ]' 10
check "  после «перезагрузки» (чистый каталог состояния) выбор тот же" "b sw2" \
    "$(st outputs.man.group.select) $(tdev man)"

# ---- 1а. до первого прохода ----
# Проверка выше смотрит после прохода; здесь — окно до него. Прежде подхват брал группе запись
# сторожа, а без неё — первого существующего члена: после перезагрузки таблица man несколько секунд
# вела в sw1 при выборе b, а при лежащем b — тоже в sw1 вместо on_fail.
bal_targets() { nft list map inet steer "balmap_$(reg bal 3)" 2>/dev/null | grep -o 'goto mark_[0-9]*' | sort -u | tr '\n' ' '; }
stop_daemon
reboot_state man
start_bare
check "до первого прохода после «перезагрузки»: таблица группы — на выбранном b, не на первом" "sw2" \
    "$(tdev man)$([ "$(tdev man)" = sw2 ] || troutes man)"
check "  status до прохода: select b, selected b, не в отказе" "b b -" \
    "$(st outputs.man.group.select) $(st outputs.man.group.selected) $(st outputs.man.failed)"
check "  balance до прохода: в карте оба живых члена" "4" "$(bal_targets | wc -w)"
# Запись сторожа устарела относительно select: файл выбора сменили, пока демон стоял (select через
# демон пишет запись active «man sw2» — она остаётся в каталоге состояния).
out="$(c select man b 2>&1)"
stop_daemon
printf 'man a\n' > "$tmp/select"
start_bare
check "запись active устарела (select сменён при остановленном демоне): таблица — на a по select" \
    "sw1 a a" "$(tdev man) $(st outputs.man.group.select) $(st outputs.man.group.selected)"
out="$(c select man b 2>&1)"
check "  select b обратно" "sw2" "$(tdev man)"
# Выбранный член лежит при старте — сразу on_fail группы (drop: blackhole), а не первый живой; карта
# balance — сразу без него.
stop_daemon
ip link set sw2 down
reboot_state man
start_bare
check "выбранный b лежит при старте: сразу on_fail (blackhole), не a" "1 " \
    "$(tbh man) $(tdev man)$([ "$(tbh man)" = 1 ] || troutes man)"
check "  status до прохода: selected null, select b, в отказе" "- b True" \
    "$(st outputs.man.group.selected) $(st outputs.man.group.select) $(st outputs.man.failed)"
check "  balance до прохода: в карте только живой a" "goto mark_$(reg a 3) " "$(bal_targets)"
check "  latency до прохода: первый живой по порядку (b лежит — a)" "sw1" "$(tdev lat)"
stop_daemon
ip link set sw2 up
start_daemon
wait_for '[ "$(tdev man)" = sw2 ]' 20
check "  член поднялся — проход возвращает группу на него" "sw2" "$(tdev man)"

ip link set sw2 down
wait_for '[ "$(tbh man)" = 1 ]' 40
check "выбранный член упал — группа по on_fail (drop: blackhole), не на a" "1 " \
    "$(tbh man) $(tdev man)$([ "$(tbh man)" = 1 ] || troutes man)"
wait_for 'grep "\"ev\":\"failed\"" "$tmp/sub.out" | grep -q "\"out\":\"man\""' 10
check "  подписчику — failed группы" "1" "$(grep '"ev":"failed"' "$tmp/sub.out" | grep -c '"out":"man"')"
check "  status: selected null, select по-прежнему b" "- b" \
    "$(st outputs.man.group.selected) $(st outputs.man.group.select)"
ip link set sw2 up
wait_for '[ "$(tdev man)" = sw2 ]' 30
check "член поднялся — группа снова на нём" "sw2" "$(tdev man)"

# ---- 2. latency = urltest ----
# b (первый по порядку) медленный: 200 мс на стороне ответчика; a — быстрый.
R tc qdisc add dev sw2p root netem delay 200ms
stop_daemon
start_daemon
# Замеры живут в памяти демона: после перезапуска их нет, пока первый проход не измерит обоих.
wait_for '[ "$(st outputs.lat.group.latency | tr "," "\n" | grep -c "^[ab]=")" = 2 ]' 20
check "latency: быстрый член выбран, хотя он второй по порядку" "sw1 a" "$(tdev lat) $(st outputs.lat.group.selected)"
lat_b="$(st outputs.lat.group.latency | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
lat_a="$(st outputs.lat.group.latency | tr ',' '\n' | awk -F= '$1 == "a" { print $2 }')"
check "  status: замеры обоих, b медленнее a на задержку netem" "yes" \
    "$([ -n "$lat_a" ] && [ -n "$lat_b" ] && [ "$lat_b" -ge 190 ] && [ "$lat_a" -lt 150 ] && echo yes || echo "a=$lat_a b=$lat_b")"
check "  запрос шёл через каждого члена (ответчик видел оба адреса)" "2" \
    "$(grep '^/generate_204 ' "$tmp/http.log" | awk '{ print $2 }' | sort -u | grep -c '^10\.9\.[12]\.1$')"
# Адрес проверки по умолчанию (в спеке группы dflt url нет): имя cp.cloudflare.com из hosts, порт 80.
wait_for '[ "$(st outputs.dflt.group.latency | tr "," "\n" | grep -c "^[ab]=")" = 2 ]' 20
check "url по умолчанию (имя из hosts, порт 80): быстрый член выбран, хотя он второй по порядку" "sw1 a" \
    "$(tdev dflt) $(st outputs.dflt.group.selected)"
check "  status: адрес проверки — умолчание" "http://cp.cloudflare.com/generate_204" "$(st outputs.dflt.group.url)"
# Гистерезис: теперь b быстрее, но меньше чем на tolerance 60 мс — остаёмся на a. Задержка netem
# на стороне ответчика ложится в замер дважды (SYN-ACK и ответ): 15 мс — около 30 мс разницы.
R tc qdisc del dev sw2p root
R tc qdisc add dev sw1p root netem delay 15ms
stop_daemon      # замеры живут в памяти демона: перезапуск — свежий замер на первом проходе
start_daemon
wait_for '[ -n "$(st outputs.lat.group.latency | grep "a=")" ]' 15
check "  гистерезис: выигрыш b меньше допуска — остаётся a" "sw1" \
    "$(tdev lat)$([ "$(tdev lat)" = sw1 ] || st outputs.lat.group.latency)"
R tc qdisc change dev sw1p root netem delay 250ms
stop_daemon
start_daemon
wait_for '[ "$(tdev lat) $(st outputs.lat.group.selected)" = "sw2 b" ]' 15
check "  выигрыш больше допуска — уходит на b" "sw2 b" "$(tdev lat) $(st outputs.lat.group.selected)"
R tc qdisc del dev sw1p root

# ---- 2а. interval короче периода сторожа ----
# Период 60 — проход по периоду за время проверки не наступает (события сети сторожа будят, но
# задержка netem на стороне ответчика — не событие в нашем пространстве). Первый замер — проходом,
# дальше — таймером группы раз в 10 с: по два запроса (член a и член b) на замер.
stop_daemon
PERIOD=60
ivs="$(grep -c '^/iv_204 ' "$tmp/http.log")"
kicks="$(grep -c 'iv: по замеру быстрее другой член' "$tmp/d.err")"
start_daemon
wait_for '[ "$(grep -c "^/iv_204 " "$tmp/http.log")" -ge $((ivs + 2)) ]' 20
check "interval 10 при периоде 60: первый замер — в первом проходе (запрос через каждого члена)" "yes" \
    "$([ "$(grep -c '^/iv_204 ' "$tmp/http.log")" -ge $((ivs + 2)) ] && echo yes || echo no)"
iv0="$(grep -c '^/iv_204 ' "$tmp/http.log")"
# Таймеры групп заводятся в конце первого прохода (он ещё меряет другие группы) — окно с запасом.
sleep 23
iv1="$(grep -c '^/iv_204 ' "$tmp/http.log")"
check "  за 23 с — два замера таймером группы (по запросу на члена), а не ноль до прохода" "yes" \
    "$([ $((iv1 - iv0)) -ge 4 ] && [ $((iv1 - iv0)) -le 6 ] && echo yes || echo "запросов: $((iv1 - iv0))")"
# Медленным становится тот член, что несёт группу сейчас (оба быстры — держится текущий).
case "$(tdev iv)" in sw1) slow=sw1p want="sw2 b" ;; *) slow=sw2p want="sw1 a" ;; esac
R tc qdisc add dev "$slow" root netem delay 200ms
wait_for '[ "$(tdev iv) $(st outputs.iv.group.selected)" = "$want" ]' 25
check "  несущий член стал медленным — группа на другом по замеру таймера, не дожидаясь прохода" \
    "$want" "$(tdev iv) $(st outputs.iv.group.selected)"
check "  внеочередной проход — по замеру" "yes" \
    "$([ "$(grep -c 'iv: по замеру быстрее другой член' "$tmp/d.err")" -gt "$kicks" ] && echo yes || echo no)"
R tc qdisc del dev "$slow" root
PERIOD=3

# ---- 2б. IPv6: замер по обоим семействам, выбор по худшему ----
if [ "$V6" = 1 ]; then
    # b медленный только по IPv6: netem в полосе prio, куда фильтр кладёт IPv6 с его стороны.
    R tc qdisc add dev sw2p root handle 1: prio
    R tc qdisc add dev sw2p parent 1:3 handle 30: netem delay 200ms
    R tc filter add dev sw2p parent 1: protocol ipv6 prio 1 u32 match u32 0 0 flowid 1:3
    stop_daemon
    start_daemon
    wait_for '[ "$(st outputs.v6g.group.latency6 | tr "," "\n" | grep -c "^[ab]=")" = 2 ] && [ "$(tdev v6g)" = sw1 ]' 20
    check "IPv6: status — latency4 и latency6 у обоих членов" "2 2" \
        "$(st outputs.v6g.group.latency4 | tr ',' '\n' | grep -c '^[ab]=') $(st outputs.v6g.group.latency6 | tr ',' '\n' | grep -c '^[ab]=')"
    check "  запрос по IPv6 шёл через каждого члена (ответчик видел оба адреса IPv6)" "2" \
        "$(grep '^/v6_204 fd09:' "$tmp/http.log" | awk '{ print $2 }' | sort -u | grep -c '^fd09:[12]::1$')"
    v4b="$(st outputs.v6g.group.latency4 | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
    v6b="$(st outputs.v6g.group.latency6 | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
    lb="$(st outputs.v6g.group.latency | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
    check "  b быстр по IPv4 и медлен по IPv6; latency у b — худший из двух" "yes" \
        "$([ -n "$v4b" ] && [ -n "$v6b" ] && [ "$v4b" -lt 150 ] && [ "$v6b" -ge 190 ] && [ "$lb" = "$v6b" ] && echo yes || echo "v4=$v4b v6=$v6b latency=$lb")"
    check "  выбор — a: b первый по порядку и быстр по IPv4, но медлен по IPv6" "sw1 a" \
        "$(tdev v6g) $(st outputs.v6g.group.selected)"
    R tc qdisc del dev sw2p root
else
    echo "groupsmatch: IPv6 в пространстве стенда не встал — часть 2б пропущена"
fi

# ---- 2в. допуск: умолчание 50 и tolerance: 0 ----
# b (первый по порядку) медленнее a ненамного: 15 мс на стороне ответчика против 5 — разница замера
# около 20-30 мс, меньше допуска по умолчанию (50), но заметна при допуске 0.
R tc qdisc add dev sw2p root netem delay 15ms
R tc qdisc add dev sw1p root netem delay 5ms
stop_daemon
reboot_state tol strict        # без памяти о прежнем выборе: у группы нет текущего члена
start_daemon
wait_for '[ "$(st outputs.tol.group.latency | tr "," "\n" | grep -c "^[ab]=")" = 2 ] && [ "$(st outputs.strict.group.latency | tr "," "\n" | grep -c "^[ab]=")" = 2 ]' 25
lt_a="$(st outputs.tol.group.latency | tr ',' '\n' | awk -F= '$1 == "a" { print $2 }')"
lt_b="$(st outputs.tol.group.latency | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
check "допуск: b медленнее a, но меньше чем на 50 мс (условие части)" "yes" \
    "$([ -n "$lt_a" ] && [ -n "$lt_b" ] && [ "$lt_b" -gt "$lt_a" ] && [ $((lt_b - lt_a)) -lt 50 ] && echo yes || echo "a=$lt_a b=$lt_b")"
check "допуск не задан (50): остаётся первый по порядку, не самый быстрый" "sw2 b" \
    "$(tdev tol) $(st outputs.tol.group.selected)"
check "  status объясняет: самый быстрый a, выбран в допуске" "a in_tolerance 50 180" \
    "$(st outputs.tol.group.fastest) $(st outputs.tol.group.why) $(st outputs.tol.group.tolerance) $(st outputs.tol.group.interval)"
check "tolerance: 0 — выбирается строго самый быстрый, хотя он второй по порядку" "sw1 a" \
    "$(tdev strict) $(st outputs.strict.group.selected)"
check "  status: допуск 0, самый быстрый — выбранный" "a fastest 0" \
    "$(st outputs.strict.group.fastest) $(st outputs.strict.group.why) $(st outputs.strict.group.tolerance)"
check "группа latency из одного члена: выбирать не из чего — why, fastest и latency_failed нет" "- - - 180" \
    "$(st outputs.one.group.why) $(st outputs.one.group.fastest) $(st outputs.one.group.latency_failed) $(st outputs.one.group.interval)"
R tc qdisc del dev sw2p root
R tc qdisc del dev sw1p root

# ---- 2г. самый быстрый член упал ----
# dead3: b (первый по порядку) медленный, c средний, a быстрый. Упал a — группа на c (самый быстрый из
# живых), а не на первом живом b: запись замеров ещё свежая и называет a лучшим, но он мёртв.
R tc qdisc add dev sw2p root netem delay 100ms
R tc qdisc add dev sw3p root netem delay 40ms
R tc qdisc add dev sw1p root netem delay 5ms
stop_daemon
reboot_state dead3
start_daemon
wait_for '[ "$(st outputs.dead3.group.latency | tr "," "\n" | grep -c "^[abc]=")" = 3 ] && [ "$(tdev dead3) $(st outputs.dead3.group.selected)" = "sw1 a" ]' 30
check "три члена: выбран самый быстрый (a — последний по порядку)" "sw1 a fastest" \
    "$(tdev dead3) $(st outputs.dead3.group.selected) $(st outputs.dead3.group.why)"
ip link set sw1 down
wait_for '[ -n "$(tdev dead3)" ] && [ "$(tdev dead3)" != sw1 ]' 30
sleep 7
check "a упал: группа на c (самый быстрый из живых), а не на первом живом b" "sw3 c c" \
    "$(tdev dead3) $(st outputs.dead3.group.selected) $(st outputs.dead3.group.fastest)"
check "  status: живые — b и c" "b,c" "$(st outputs.dead3.group.alive)"
# Причина смены — «упал», а не «по замеру»: замер лишь выбрал из оставшихся.
sw_why() {   # ВЫХОД УСТРОЙСТВО — «причина член» последнего switched в устройство
    grep '"ev":"switched"' "$tmp/sub.out" | grep "\"out\":\"$1\"" | grep "\"to\":\"$2\"" | tail -n 1 |
        sed -n 's/.*"why":"\([a-z]*\)".*"member":"\([a-z]*\)".*/\1 \2/p'
}
check "  подписчику — switched на c с причиной down (не latency)" "down c" "$(sw_why dead3 sw3)"
ip link set sw1 up
wait_for '[ "$(tdev dead3)" = sw1 ]' 40
check "a вернулся: группа снова на самом быстром" "sw1 a" "$(tdev dead3) $(st outputs.dead3.group.selected)"
wait_for '[ "$(sw_why dead3 sw1)" = "latency a" ]' 10
check "  возврат на a — switched с причиной latency" "latency a" "$(sw_why dead3 sw1)"
R tc qdisc del dev sw2p root
R tc qdisc del dev sw3p root
R tc qdisc del dev sw1p root

# ---- 2д. замер не удался: порядок, объяснение и повтор раньше срока ----
# Пока лежит файл rt.fail, ответчик отвечает на /rt_204 статусом 503 — замер не удаётся ни у кого.
# Группа идёт по порядку (b, самый медленный), и status с журналом говорят почему. interval группы —
# 90 с: без повтора раньше срока она оставалась бы на b все полторы минуты после того, как адрес
# проверки ожил; повтор — через ~15 с.
R tc qdisc add dev sw2p root netem delay 100ms
R tc qdisc add dev sw1p root netem delay 5ms
: > "$tmp/rt.fail"
stop_daemon
reboot_state rt
start_daemon
wait_for 'grep -q "группа rt: ни у одного живого члена нет замера" "$tmp/d.err"' 20
check "замера нет ни у кого: в журнале — строка, что группа идёт по порядку (не только под -v)" "yes" \
    "$(grep -q 'группа rt: ни у одного живого члена нет замера' "$tmp/d.err" && echo yes || echo no)"
check "  группа по порядку (b), status — no_measure и члены без замера" "sw2 b no_measure b,a" \
    "$(tdev rt) $(st outputs.rt.group.selected) $(st outputs.rt.group.why) $(st outputs.rt.group.latency_failed)"
check "  причина каждой неудачи — в журнале, с группой, членом и адресом: ответ 503 вместо 204/200" "yes yes" \
    "$(for m in b a; do grep -q "latency: группа rt, член $m: замер http://10.2.0.1:8080/rt_204 не удался — ответ 503 вместо 204/200" "$tmp/d.err" && echo yes || echo no; done | tr '\n' ' ' | sed 's/ $//')"
rm -f "$tmp/rt.fail"
t0="$(date +%s)"
wait_for '[ "$(tdev rt) $(st outputs.rt.group.selected) $(st outputs.rt.group.why)" = "sw1 a fastest" ]' 45
t1="$(date +%s)"
check "адрес проверки ожил: группа на самом быстром по повтору замера, раньше interval (90 с)" "sw1 a fastest yes" \
    "$(tdev rt) $(st outputs.rt.group.selected) $(st outputs.rt.group.why) $([ $((t1 - t0)) -lt 40 ] && echo yes || echo "$((t1 - t0)) с")"
check "  status: живых без замера нет" "-" "$(st outputs.rt.group.latency_failed)"
check "  в журнале — замеры снова есть" "yes" \
    "$(grep -q 'группа rt: замеры снова есть' "$tmp/d.err" && echo yes || echo no)"
R tc qdisc del dev sw2p root
R tc qdisc del dev sw1p root

# ---- 4. idle_timeout ----
check "idle_timeout: без трафика через группу — ни одного запроса проверки" "0" \
    "$(grep -c '^/idle_204 ' "$tmp/http.log")"
check "  status: замер на паузе — why idle (не отказ: latency_failed нет), idle_timeout 3600" "idle - 3600" \
    "$(st outputs.idl.group.why) $(st outputs.idl.group.latency_failed) $(st outputs.idl.group.idle_timeout)"
check "  в журнале нет «замера нет» для группы на паузе" "0" \
    "$(grep -c 'группа idl: ни у одного живого члена нет замера' "$tmp/d.err")"
# Трафик — после того как сторож хотя бы раз прошёл группу (первая встреча берёт отсчёт), и
# пачками, пока замер не появится.
sleep 5
for k in $(seq 1 15); do
    C python3 -c 'import socket
for i in range(5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x", ("10.3.0.1", 9))' 2>/dev/null
    [ "$(grep -c '^/idle_204 ' "$tmp/http.log")" -ge 1 ] && break
    sleep 2
done
check "  трафик пошёл — замер сделан" "yes" \
    "$([ "$(grep -c '^/idle_204 ' "$tmp/http.log")" -ge 1 ] && echo yes || echo no)"
wait_for '[ "$(st outputs.idl.group.why)" != idle ]' 10
check "  и why больше не idle" "no" "$([ "$(st outputs.idl.group.why)" = idle ] && echo yes || echo no)"

# ---- 3. balance ----
who() { C python3 -c 'import socket
s = socket.create_connection(("10.2.0.1", 8080), timeout=3)
s.sendall(b"GET /who HTTP/1.1\r\nHost: x\r\n\r\n")
d = b""
while True:
    x = s.recv(4096)
    if not x: break
    d += x
print(d.split(b"\r\n\r\n", 1)[1].decode())' 2>/dev/null; }
n1=0 n2=0
for i in $(seq 1 40); do
    case "$(who)" in 10.9.1.1) n1=$((n1 + 1)) ;; 10.9.2.1) n2=$((n2 + 1)) ;; esac
done
check "balance: соединения расходятся по обоим членам (40 соединений)" "yes" \
    "$([ $n1 -ge 5 ] && [ $n2 -ge 5 ] && [ $((n1 + n2)) = 40 ] && echo yes || echo "a=$n1 b=$n2")"
check "  status: живые — оба, веса" "a,b 1,1" "$(st outputs.bal.group.alive) $(st outputs.bal.group.weights)"
# Долгое соединение — на каком оно члене, скажет эхо.
nsenter -t "$CPID" -n python3 "$tmp/long.py" "$tmp/long.log" "$tmp/go" >"$tmp/long.err" 2>&1 & LP=$!
sleep 0.5
touch "$tmp/go.0"
wait_for '[ -s "$tmp/long.log" ]' 5
first="$(awk '$1 == 0 { print $2 }' "$tmp/long.log")"
case "$first" in 10.9.1.1) keep=sw1 other=sw2 om=b km=a ;; *) keep=sw2 other=sw1 om=a km=b ;; esac
map_targets() { nft list map inet steer "balmap_$(reg bal 3)" | grep -o 'goto mark_[0-9]*' | sort -u | tr '\n' ' '; }
ip link set "$other" down
wait_for '[ "$(map_targets)" = "goto mark_$(reg "$km" 3) " ]' 30
check "упал член $om — карта только с живым" "goto mark_$(reg "$km" 3) " "$(map_targets)"
# Событие — после прохода по всем группам balance (у sit и sic — свои): ждём строку группы bal.
wait_for 'grep -q "\"ev\":\"balance\",\"out\":\"bal\"" "$tmp/sub.out"' 5
check "  подписчику — balance с живыми" "{\"v\":1,\"ev\":\"balance\",\"out\":\"bal\",\"alive\":[\"$km\"]}" \
    "$(grep '"ev":"balance","out":"bal"' "$tmp/sub.out" | tail -n 1)"
touch "$tmp/go.1"
wait_for '[ "$(awk "\$1 == 1" "$tmp/long.log")" ]' 5
check "  установленное соединение на своём члене" "$first" "$(awk '$1 == 1 { print $2 }' "$tmp/long.log")"
m=0
for i in $(seq 1 10); do [ "$(who)" = "$first" ] && m=$((m + 1)); done
check "  новые соединения — все на живого" "10" "$m"
ip link set "$other" up
wait_for '[ "$(map_targets | wc -w)" = 4 ]' 30
check "член вернулся — карта снова на обоих" "4" "$(map_targets | wc -w)"
touch "$tmp/go.2"
wait_for '[ "$(awk "\$1 == 2" "$tmp/long.log")" ]' 5
check "  установленное соединение не перескочило на вернувшийся" "$first" "$(awk '$1 == 2 { print $2 }' "$tmp/long.log")"
kill $LP 2>/dev/null

# ---- 3а. balance by: site, site_client ----
# site АДРЕС [ИСТОЧНИК] — через какого члена ушло новое соединение к адресу (10.9.K.1 — член K).
site() { C python3 -c 'import socket, sys
s = socket.create_connection((sys.argv[1], 8090), timeout=3, source_address=(sys.argv[2], 0))
print(s.recv(64).decode())' "$1" "${2:-192.168.7.2}" 2>/dev/null; }
# sites ПРЕФИКС [ИСТОЧНИК] — «адрес:член» по 24 сайтам, по три соединения на сайт; сайт, чьи
# соединения разошлись по разным членам, — «адрес:разошлись».
sites() {
    for i in $(seq 1 24); do
        m1="$(site "$1.$i" "${2:-}")"; m2="$(site "$1.$i" "${2:-}")"; m3="$(site "$1.$i" "${2:-}")"
        if [ -n "$m1" ] && [ "$m1" = "$m2" ] && [ "$m1" = "$m3" ]; then echo "$i:$m1"; else echo "$i:разошлись"; fi
    done | tr '\n' ' '
}
s0="$(sites 10.4.0)"
check "by: site — все соединения сайта на одном члене" "" "$(echo "$s0" | tr ' ' '\n' | grep -v ':10\.9\.[123]\.1$' | grep .)"
check "  сайты — по всем трём членам" "3" "$(echo "$s0" | tr ' ' '\n' | cut -d: -f2 | grep . | sort -u | wc -l)"
check "  в цепочке группы — jhash адреса назначения, numgen нет" "1 0" \
    "$(nft list chain inet steer "bal_$(reg sit 3)" | grep -c 'jhash ip daddr mod 120 seed') $(nft list chain inet steer "bal_$(reg sit 3)" | grep -c numgen)"
sit_targets() { nft list map inet steer "balmap_$(reg sit 3)" | grep -o 'goto mark_[0-9]*' | sort -u | tr '\n' ' '; }
ip link set sw1 down
wait_for '[ "$(sit_targets | wc -w)" = 4 ]' 30
check "a лёг — в карте by: site только b и c" "$(printf 'goto mark_%s\ngoto mark_%s\n' "$(reg b 3)" "$(reg c 3)" | sort | tr '\n' ' ')" "$(sit_targets)"
s1="$(sites 10.4.0)"
# Сайты b и c — на прежних членах; сайты a — на живых.
moved="" lost=""
for e in $s0; do
    i="${e%%:*}" m="${e#*:}"
    now="$(echo "$s1" | tr ' ' '\n' | awk -F: -v i="$i" '$1 == i { print $2 }')"
    if [ "$m" = 10.9.1.1 ]; then case "$now" in 10.9.2.1|10.9.3.1) ;; *) lost="$lost $i:$now" ;; esac
    elif [ "$now" != "$m" ]; then moved="$moved $i:$m>$now"; fi
done
check "  сайты b и c остались на своих членах" "" "$moved"
check "  сайты a — на живых членах" "" "$lost"
ip link set sw1 up
wait_for '[ "$(sit_targets | wc -w)" = 6 ]' 30
check "a вернулся — каждый сайт снова на прежнем члене" "$s0" "$(sites 10.4.0)"

c2="$(sites 10.5.0 192.168.7.2)"
c3="$(sites 10.5.0 192.168.7.3)"
check "by: site_client — у клиента .2 сайт на одном члене" "" "$(echo "$c2" | tr ' ' '\n' | grep 'разошлись')"
check "  у клиента .3 — тоже" "" "$(echo "$c3" | tr ' ' '\n' | grep 'разошлись')"
check "  у разных клиентов один сайт бывает на разных членах" "yes" "$([ "$c2" != "$c3" ] && echo yes || echo no)"
check "  в цепочке группы — jhash пары адресов" "1" \
    "$(nft list chain inet steer "bal_$(reg sic 3)" | grep -c 'jhash ip saddr . ip daddr mod 120 seed')"

stop_daemon
echo "groupsmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
