#!/bin/sh
# Apply-сверка демона (src/daemon/recon.c, docs/ctl.md, поле changed): apply и reload трогают
# только изменившиеся части.
#
# Демон — `steer daemon --supervise` в своём сетевом пространстве (и со своим /sys, если его
# удаётся смонтировать) с настоящим nft; помощники —
# заглушка через шов STEER_SUPERVISE_EXE (пишет «obfs выход pid»), резолвер — настоящий, на
# таблице от демона. nft и ip — обёртки в PATH, которые записывают каждый запуск.
#
# Что проверяется.
#  1. Первый apply применяет всё: набор правил и маршрутизацию обоих выходов.
#  2. apply той же спеки: nft не запускается ни разу, ip не меняет ни маршрутов, ни правил;
#     таблица в ядре та же (номер таблицы), элементы, положенные в доменный набор со стороны так,
#     как кладёт резолвер (поддельный адрес без срока, настоящий со сроком), на месте; помощники
#     и резолвер — те же процессы, таблица резолверу не отправлялась; changed — пустой. То же —
#     reload.
# 2а. Сверка с ядром (recon.c, «СВЕРКА С ЯДРОМ»): снятые снаружи правило канала или цепочка, чужой
#     набор в нашей таблице — apply (reload) той же спеки ставит набор правил заново, в журнале
#     демона — почему, а элементы резолвера после замены снова на месте: fake-IP (карта и набор
#     канала) и real-ip со сроком; помощники и резолвер те же. Снятые маршрут и правило таблицы
#     выхода, правило IPv6, один маршрут — выход привязывается заново, набор правил не трогается.
#     Без расхождения apply и reload в ядро не идут, как в п. 2 — в том числе после того, как
#     резолвер выдал новый поддельный адрес (он в файле состояния, из которого generate засевает
#     карту fake-IP) и после правки этого файла в обход резолвера: набор правил не заменяется
#     (changed.ruleset false, nft не запускался, номер таблицы прежний), элементы fake-IP на месте.
# 2б. Сверка элементов статических наборов (recon.c, «СВЕРКА ЭЛЕМЕНТОВ»): снятая руками подсеть
#     адресного списка — apply той же спеки ставит набор правил заново, подсеть на месте, в
#     журнале почему, элементы fake-IP и real-ip снова на месте; чужая подсеть в адресном наборе
#     — reload убирает её; адрес без срока вне пула fake-IP в доменном наборе (так выглядят
#     подсети списка, которые генератор кладёт в доменный набор) — тоже расхождение. После
#     сверки apply той же спеки в ядро не идёт.
#  3. Изменился только канал: набор правил новой транзакцией, маршруты, помощники и резолвер не
#     тронуты; резолверу — та же таблица ещё раз (вернуть элементы fake-IP в новые наборы); адрес
#     из ответа DNS канала real-ip, лежавший в наборе со сроком, снова в новом наборе — со сроком.
#  4. Изменился режим отказа одного выхода: привязан заново только он.
#  5. Изменился сервер обфускации одного выхода: перезапущен только его помощник, маршруты не
#     тронуты.
#  6. Изменился состав доменного канала: резолверу — новая таблица, процесс тот же.
#  7. Отказ ядра (адрес, который форму проходит, а ядро отвергает): прежняя спека возвращена,
#     прежняя таблица в ядре на месте; следующий apply применяет всё заново.
#  8. Пока идёт компиляция (план читает список из именованного канала, который стенд долго не
#     наполняет), status отвечает сразу: компиляция — в ребёнке, цикл демона свободен.
#
# Нужны root, unshare -n, nft, ip и python3; без них стенд пропускается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
for t in nft ip python3; do
    command -v $t >/dev/null 2>&1 || { echo "reconmatch: $t нет — пропускаю"; exit 0; }
done
if [ "${RECON_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "reconmatch: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "reconmatch: unshare -n недоступен — пропускаю"; exit 0; }
    RECON_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ip link set lo up
real_nft="$(command -v nft)"
real_ip="$(command -v ip)"
"$real_nft" add table inet reconmatch_probe 2>/dev/null ||
    { echo "reconmatch: nf_tables недоступен — пропускаю"; exit 0; }
"$real_nft" delete table inet reconmatch_probe
for d in wga wgb; do "$real_ip" link add $d type dummy && "$real_ip" link set $d up; done

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/st2" "$tmp/bin"
D="" D2="" W="" AP="" UPR=""
trap 'kill $D $D2 $W $AP $UPR 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
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

for t in nft ip; do
    real="$(command -v $t)"
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/%s.log"\nexec "%s" "$@"\n' "$tmp" "$t" "$real" \
        > "$tmp/bin/$t"
    chmod +x "$tmp/bin/$t"
done
PATH="$tmp/bin:$PATH"
export PATH

cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
trap 'exit 0' TERM
while :; do sleep 1; done
H
chmod +x "$tmp/helper"

# j ПУТЬ — поле ответа (через точку); список — через запятую.
cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
if d is None: print('-')
elif isinstance(d, bool): print('true' if d else 'false')
elif isinstance(d, list): print(','.join(d))
else: print(d)
PY
j() { python3 "$tmp/j.py" "$1"; }
ch() { printf '%s' "$1" | python3 "$tmp/j.py" changed.ruleset | tr -d '\n'; printf ' ['
       printf '%s' "$1" | python3 "$tmp/j.py" changed.routing | tr -d '\n'; printf '] ['
       printf '%s' "$1" | python3 "$tmp/j.py" changed.helpers | tr -d '\n'; printf '] '
       printf '%s' "$1" | python3 "$tmp/j.py" changed.dnsd; }
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

printf '10.1.0.0/16\n' > "$tmp/p1.lst"
printf '10.2.0.0/16\n' > "$tmp/p2.lst"
printf 'example.com\n' > "$tmp/d1.lst"
printf 'example.org\n' > "$tmp/d2.lst"
printf 'rip.test\n' > "$tmp/r.lst"
# Апстрим резолвера: на A — 203.0.113.9 со сроком 300 с (канал real-ip кладёт его в набор).
cat > "$tmp/up.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04' + bytes([203, 0, 113, 9])
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/qa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(".".join(str(b) for b in d[-4:]))
except socket.timeout:
    print("timeout")
PY
python3 "$tmp/up.py" 15475 &
UPR=$!
# spec ФАЙЛ СПИСОК_P ON_FAIL_A СЕРВЕР_B ДОМЕННЫЕ_ФАЙЛЫ
spec() {
    cat > "$tmp/$1" <<EOF
{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{
 "a":{"kind":"interface","device":"wga","on_fail":"$3",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5101"}},
 "b":{"kind":"interface","device":"wgb",
      "obfs":{"mode":"wg-over-tcp","server":"$4","listen":"127.0.0.1:5102"}}},
 "channels":[{"name":"p","match":{"prefixes_file":"$tmp/$2"},"out":"a"},
             {"name":"d","match":{"domains_files":[$5]},"out":"b"},
             {"name":"r","match":{"domains_files":["$tmp/r.lst"],"mode":"realip"},"out":"b"}]}
EOF
}
D1="\"$tmp/d1.lst\"" D12="\"$tmp/d1.lst\",\"$tmp/d2.lst\""
spec S1.json p1.lst direct 10.99.0.3:4443 "$D1"
spec S2.json p2.lst direct 10.99.0.3:4443 "$D1"
spec S3.json p2.lst drop 10.99.0.3:4443 "$D1"
spec S4.json p2.lst drop 10.99.0.4:4443 "$D1"
spec S5.json p2.lst drop 10.99.0.4:4443 "$D12"
spec S6.json p3.lst drop 10.99.0.4:4443 "$D12"
cp "$tmp/S1.json" "$tmp/spec.json"

pid_of() { grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3; }
handle() { "$real_nft" -a list table inet steer 2>/dev/null | sed -n '1s/.*# handle \([0-9]*\).*/\1/p'; }
dnsd_pid() { grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | tail -1 | grep -o '[0-9]*$'; }
tabs() { grep -c "channel b_dom: .*rule(s)" "$tmp/d.err"; }
nft_runs() { [ -f "$tmp/nft.log" ] && wc -l < "$tmp/nft.log" | tr -d ' ' || echo 0; }
nft_loads() { [ -f "$tmp/nft.log" ] && { grep -c '^-f ' "$tmp/nft.log" || true; } || echo 0; }
ip_changes() { [ -f "$tmp/ip.log" ] && grep -E 'route (replace|add|flush|del)|rule (add|del)' "$tmp/ip.log" |
               sed -n 's/.* table \([0-9]*\).*/\1/p' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
fresh() { : > "$tmp/nft.log"; : > "$tmp/ip.log"; }

DARGS="daemon --supervise --socket $tmp/s.sock --spec $tmp/spec.json --state-dir $tmp/st
    --dnsd-flag --listen-port --dnsd-flag 15411 --dnsd-flag --upstream-port --dnsd-flag 15475"
# Свой /sys, как у daemonmatch: сверка маршрутов с ядром (шаг 2а) спрашивает, есть ли устройство
# выхода (/sys/class/net), а /sys хоста о dummy этого сетевого пространства не знает. Не
# смонтировать — демон как прежде, а проверка, которой нужно устройство, пропускается.
SYSFS=0
if unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null; then
    SYSFS=1
    STEER_SUPERVISE_EXE="$tmp/helper" unshare -m sh -c \
        "mount -t sysfs sysfs /sys && exec \"$BIN\" $(echo $DARGS)" 2>"$tmp/d.err" &
else
    STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" $DARGS 2>"$tmp/d.err" &
fi
D=$!
wait_for '[ -S "$tmp/s.sock" ] && [ -n "$(pid_of a)" ] && [ -n "$(pid_of b)" ] && [ -n "$(dnsd_pid)" ]' 5
wait_for '[ "$(tabs)" -ge 1 ]' 5
TA=$(awk '$1 == "a" { print $3 }' "$tmp/st/registry")
TB=$(awk '$1 == "b" { print $3 }' "$tmp/st/registry")

# ---- 1. первый apply — всё ---------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "первый apply: применён, набор правил и оба выхода" "0 true true [a,b] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(ch "$r")"
check "  одна транзакция nft" "1" "$(nft_loads)"
H1="$(handle)"
check "  таблица в ядре" "yes" "$([ -n "$H1" ] && echo yes || echo no)"
SET="$("$real_nft" list table inet steer | awk '/^\tset /{s=$2} /10\.1\.0\.0\/16/{print s; exit}')"
# Элементы, какие кладёт резолвер, — в доменный набор канала d: поддельный адрес без срока (из
# пула fake-IP) и настоящий со сроком. Сверка элементов (recon.c, «СВЕРКА ЭЛЕМЕНТОВ») их не
# считает, и apply той же спеки из-за них в ядро не идёт. Элемент в адресном наборе $SET —
# другое дело: его целиком задаёт nft -f (шаг 2б).
"$real_nft" add element inet steer b_dom "{ 198.18.77.1, 10.77.0.1 timeout 1h }"
# Канал real-ip: имя из его списка — настоящий адрес клиенту и в набор канала со сроком.
RSET="$("$real_nft" list table inet steer | awk '/^\tset .*_c[0-9]*r /{ print $2; exit }')"
check "  real-ip: клиенту — настоящий адрес" "203.0.113.9" "$(python3 "$tmp/qa.py" 15411 rip.test)"
rip_in() { "$real_nft" list set inet steer "$RSET" 2>/dev/null | grep -c '203\.0\.113\.9 timeout'; }
wait_for '[ "$(rip_in)" = 1 ]' 3
check "  real-ip: адрес — в наборе канала со сроком" "1" "$(rip_in)"
PA="$(pid_of a)" PB="$(pid_of b)" DN="$(dnsd_pid)" T0="$(tabs)"

# ---- 2. та же спека — ничего ---------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "apply той же спеки: применён, changed пустой" "0 true false [] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(ch "$r")"
check "  nft не запускался ни разу" "0" "$(nft_runs)"
check "  маршруты и правила не тронуты" "" "$(ip_changes)"
check "  таблица в ядре та же" "$H1" "$(handle)"
side_n() { "$real_nft" list set inet steer b_dom 2>/dev/null |
           grep -o '198\.18\.77\.1\|10\.77\.0\.1 timeout' | wc -l | tr -d ' '; }
check "  элементы резолвера, положенные в доменный набор со стороны, на месте" "2" "$(side_n)"
check "  помощники и резолвер — те же процессы" "$PA $PB $DN" "$(pid_of a) $(pid_of b) $(dnsd_pid)"
check "  таблица резолверу не отправлялась" "$T0" "$(tabs)"
check "  stdout — прежняя строка итога" "steer: applied 3 channel(s), 2 output(s)" \
    "$(printf '%s' "$r" | j stdout | head -n 1)"

fresh
r="$(ctl reload)"
check "reload без изменений: changed пустой, nft не запускался" "0 false [] [] false 0" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs)"
check "  маршруты не тронуты, таблица та же" " $H1" "$(ip_changes) $(handle)"

# ---- 2а. сверка с ядром: изменённое снаружи возвращает apply той же спеки ---------------------
# Правило канала, цепочка, чужой набор в нашей таблице — набор правил ставится заново (номер
# таблицы тот же, отличие видно только по отпечатку содержимого), и элементы, которые кладёт
# резолвер, после замены снова на месте: fake-IP (адрес в карте и в наборе канала) и real-ip (со
# сроком). Снятые правило и маршрут таблицы выхода — выход привязывается заново, набор правил не
# трогается. После сверки apply той же спеки снова не идёт в ядро.
FAKE="$(python3 "$tmp/qa.py" 15411 example.com)"
fk_map() { "$real_nft" list map inet steer fakeip 2>/dev/null | grep -cF "$FAKE : 203.0.113.9"; }
fk_set() { "$real_nft" list set inet steer b_dom 2>/dev/null | grep -cF "$FAKE"; }
wait_for '[ "$(fk_map)" = 1 ] && [ "$(fk_set)" = 1 ]' 3
check "сверка: fake-IP — адрес в карте и в наборе доменного канала" "1 1" "$(fk_map) $(fk_set)"
# Новый поддельный адрес резолвер записал в файл состояния, а generate засевает из него карту
# fake-IP. В отпечаток плана засев не входит (print.c, у print_elements): элемент в карте уже
# положил сам резолвер, и apply той же спеки не должен из-за него заменять таблицу. Прежде
# здесь стоял предварительный apply, который эту замену и принимал.
fk_file() { awk -F '\t' -v f="$FAKE" '$2 == f && $3 == "203.0.113.9" { n++ } END { print n + 0 }' \
                "$tmp/st/fakeip.state" 2>/dev/null; }
wait_for '[ "$(fk_file)" -ge 1 ]' 3
check "  адрес — и в файле состояния резолвера" "yes" "$([ "$(fk_file)" -ge 1 ] && echo yes || echo no)"
fresh
T0="$(tabs)"
r="$(ctl apply < "$tmp/S1.json")"
check "новый fake-IP в файле состояния: apply той же спеки не заменяет набор правил" \
    "0 false [] [] false 0 $H1" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs) $(handle)"
check "  fake-IP на месте, таблица резолверу не отправлялась" "1 1 $T0" \
    "$(fk_map) $(fk_set) $(tabs)"
# Файл состояния изменён в обход резолвера (строка, которой в карте нет): то же самое — засев
# в таблицу ядра попадёт при следующей замене набора, а не станет её причиной.
cp "$tmp/st/fakeip.state" "$tmp/fakeip.state.bak"
printf 'seed.test\t198.18.200.7\t203.0.113.77\n' >> "$tmp/st/fakeip.state"
fresh
r="$(ctl reload)"
check "изменённый файл состояния: reload не заменяет набор правил" "0 false [] [] false 0 $H1" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs) $(handle)"
cp "$tmp/fakeip.state.bak" "$tmp/st/fakeip.state"
drift_n() { grep -c 'набор правил в ядре изменён снаружи' "$tmp/d.err"; }
DR0="$(drift_n)"
elems_back() {
    wait_for '[ "$(fk_map)" = 1 ] && [ "$(fk_set)" = 1 ] && [ "$(rip_in)" = 1 ]' 5
    echo "$(fk_map) $(fk_set) $(rip_in)"
}
has_rule() { "$real_nft" list chain inet steer prerouting_mark 2>/dev/null | grep -c 'comment "steer:a_ip"'; }
rh="$("$real_nft" -a list chain inet steer prerouting_mark |
      sed -n 's/.*comment "steer:a_ip" # handle \([0-9]*\).*/\1/p')"
"$real_nft" delete rule inet steer prerouting_mark handle "$rh"
check "  правило канала снято снаружи" "0" "$(has_rule)"
fresh
T0="$(tabs)"
r="$(ctl apply < "$tmp/S1.json")"
check "снятое правило канала: apply той же спеки ставит набор правил заново" "0 true [] [] false 1" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_loads)"
check "  правило канала на месте, маршруты не тронуты" "1 " "$(has_rule) $(ip_changes)"
check "  в журнале демона — почему" "$((DR0 + 1))" "$(drift_n)"
wait_for '[ "$(tabs)" -gt "$T0" ]' 5
check "  резолверу — таблица ещё раз" "yes" "$([ "$(tabs)" -gt "$T0" ] && echo yes || echo no)"
check "  fake-IP (карта и набор) и real-ip — снова на месте" "1 1 1" "$(elems_back)"
check "  помощники и резолвер — те же процессы" "$PA $PB $DN" "$(pid_of a) $(pid_of b) $(dnsd_pid)"

"$real_nft" flush chain inet steer postrouting_down
"$real_nft" delete chain inet steer postrouting_down
fresh
r="$(ctl reload)"
check "снятая цепочка: reload ставит набор правил заново" "0 true 1 1 $((DR0 + 2))" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r" | awk '{print $1}') $(nft_loads) \
$("$real_nft" list chain inet steer postrouting_down 2>/dev/null | grep -c 'steer-down:a_ip') $(drift_n)"
check "  fake-IP и real-ip — на месте" "1 1 1" "$(elems_back)"

"$real_nft" add set inet steer junk '{ type ipv4_addr; }'
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "чужой набор в нашей таблице: набор правил заново, чужого нет" "true 1 0 $((DR0 + 3))" \
    "$(ch "$r" | awk '{print $1}') $(nft_loads) \
$("$real_nft" list sets inet 2>/dev/null | grep -c 'set junk') $(drift_n)"

fresh
r="$(ctl apply < "$tmp/S1.json")"
check "после сверки apply той же спеки — снова ничего" "0 false [] [] false 0" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs)"
check "  маршруты не тронуты" "" "$(ip_changes)"

# ---- 2б. сверка элементов статических наборов ---------------------------------------------------
# Отпечаток элементов не видит — их сверяет сводка, снятая сразу после нашего nft -f, против
# сводки ядра, которую снимает план (recon.c, «СВЕРКА ЭЛЕМЕНТОВ»).
del_n() { grep -c 'элементы статических наборов в ядре не те' "$tmp/d.err"; }
in_set() { "$real_nft" list set inet steer "$1" 2>/dev/null | grep -c "$2"; }
DE0="$(del_n)"
"$real_nft" delete element inet steer "$SET" "{ 10.1.0.0/16 }"
check "элементы: подсеть адресного списка снята руками" "0" "$(in_set "$SET" '10\.1\.0\.0/16')"
fresh
T0="$(tabs)"
r="$(ctl apply < "$tmp/S1.json")"
check "  apply той же спеки ставит набор правил заново, подсеть на месте" "0 true [] [] false 1 1" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_loads) $(in_set "$SET" '10\.1\.0\.0/16')"
check "  в журнале демона — почему" "$((DE0 + 1))" "$(del_n)"
wait_for '[ "$(tabs)" -gt "$T0" ]' 5
check "  fake-IP (карта и набор) и real-ip — снова на месте" "1 1 1" "$(elems_back)"
check "  помощники и резолвер — те же процессы" "$PA $PB $DN" "$(pid_of a) $(pid_of b) $(dnsd_pid)"
"$real_nft" add element inet steer "$SET" "{ 10.66.0.0/16 }"
fresh
r="$(ctl reload)"
check "чужая подсеть в адресном наборе: reload ставит набор правил заново, её нет" \
    "true 1 0 $((DE0 + 2))" \
    "$(ch "$r" | awk '{print $1}') $(nft_loads) $(in_set "$SET" '10\.66\.') $(del_n)"
check "  fake-IP и real-ip — на месте" "1 1 1" "$(elems_back)"
# Подсети списка, которые генератор кладёт в доменный набор (адресный и доменный каналы в один
# выход), выглядят в ядре так: без срока и вне пула fake-IP. Такой элемент, положенный руками, —
# расхождение; элементы резолвера (выше, шаг 2) — нет.
"$real_nft" add element inet steer b_dom "{ 10.88.0.1 }"
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "адрес без срока вне пула в доменном наборе: набор правил заново, адреса нет" \
    "true 1 0 $((DE0 + 3))" \
    "$(ch "$r" | awk '{print $1}') $(nft_loads) $(in_set b_dom '10\.88\.0\.1') $(del_n)"
check "  fake-IP и real-ip — на месте" "1 1 1" "$(elems_back)"
# Резолвер вернул свои элементы после замены — это не расхождение: apply той же спеки — ничего.
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "после сверки элементов apply той же спеки — снова ничего" "0 false [] [] false 0 $((DE0 + 3))" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs) $(del_n)"

rule_n() { "$real_ip" $1 rule show table "$2" 2>/dev/null | grep -c fwmark; }
route_n() { "$real_ip" $1 route show table "$2" 2>/dev/null | grep -c "^default dev $3"; }
"$real_ip" route del default dev wga table "$TA"
"$real_ip" rule del table "$TA"
check "  маршрут и правило выхода a сняты снаружи" "0 0" "$(route_n -4 "$TA" wga) $(rule_n -4 "$TA")"
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "снятые маршрут и правило выхода: привязан заново только a, набор правил не тронут" \
    "0 false [a] [] false 0" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_loads)"
check "  маршрут и правило a — на месте" "1 1" "$(route_n -4 "$TA" wga) $(rule_n -4 "$TA")"
check "  в журнале демона — почему" "1" \
    "$(grep -c 'выход a: правила fwmark нет — привязываю заново' "$tmp/d.err")"

"$real_ip" -6 rule del table "$TB"
fresh
r="$(ctl reload)"
check "снятое правило IPv6 выхода b: reload привязывает заново только b" "false [b] 1" \
    "$(ch "$r" | awk '{print $1, $2}') $(rule_n -6 "$TB")"

if [ "$SYSFS" = 1 ]; then
    "$real_ip" route del default dev wga table "$TA"
    fresh
    r="$(ctl apply < "$tmp/S1.json")"
    check "снятый маршрут выхода (правило на месте): привязан заново a" "false [a] 1" \
        "$(ch "$r" | awk '{print $1, $2}') $(route_n -4 "$TA" wga)"
fi
fresh
r="$(ctl reload)"
check "после сверки маршрутов reload — ничего" "0 false [] [] false 0" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs)"
T0="$(tabs)"

# ---- 3. только канал ---------------------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S2.json")"
check "сменился только канал: набор правил, маршруты и помощники нет" "0 true [] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r")"
check "  одна транзакция nft, таблица новая" "1 yes" \
    "$(nft_loads) $([ "$(handle)" != "$H1" ] && echo yes || echo no)"
check "  новый список в наборе" "1" "$("$real_nft" list table inet steer | grep -c '10\.2\.0\.0/16')"
check "  маршруты и правила не тронуты" "" "$(ip_changes)"
check "  помощники и резолвер — те же" "$PA $PB $DN" "$(pid_of a) $(pid_of b) $(dnsd_pid)"
# Набор правил заменён — таблица резолверу уходит и неизменной (supd_spec_changed): по ней он
# возвращает в пересозданные наборы постоянные элементы fake-IP. changed.dnsd при этом false.
wait_for '[ "$(tabs)" -gt "$T0" ]' 5
check "  резолверу — та же таблица ещё раз, changed.dnsd — нет" "$((T0 + 1)) false" \
    "$(tabs) $(ch "$r" | awk '{print $4}')"
wait_for '[ "$(rip_in)" = 1 ]' 3
check "  real-ip: адрес из ответа снова в новом наборе со сроком, без нового запроса" "1" "$(rip_in)"

# ---- 4. режим отказа выхода a ----------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S3.json")"
check "сменился on_fail выхода a: привязан заново только a" "[a] []" \
    "$(ch "$r" | awk '{print $2, $3}')"
check "  в ядре тронута только таблица a" "$TA" "$(ip_changes)"
check "  помощники — те же" "$PA $PB" "$(pid_of a) $(pid_of b)"

# ---- 5. сервер обфускации выхода b ----------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S4.json")"
check "сменился сервер обфускации b: перезапущен только его помощник" "[] [b]" \
    "$(ch "$r" | awk '{print $2, $3}')"
wait_for '[ "$(pid_of b)" != "$PB" ]' 5
check "  помощник b — новый процесс, a — прежний" "yes $PA" \
    "$([ "$(pid_of b)" != "$PB" ] && echo yes || echo no) $(pid_of a)"
check "  маршруты не тронуты" "" "$(ip_changes)"
PB="$(pid_of b)"

# ---- 6. состав доменного канала ----------------------------------------------------------------
fresh
sleep 0.3
T0="$(tabs)"
r="$(ctl apply < "$tmp/S5.json")"
check "сменился состав доменного канала: резолверу новая таблица" "true" \
    "$(ch "$r" | awk '{print $4}')"
wait_for '[ "$(tabs)" -gt "$T0" ]' 5
check "  резолвер — тот же процесс, таблицу получил" "$DN yes" \
    "$(dnsd_pid) $([ "$(tabs)" -gt "$T0" ] && echo yes || echo no)"

# ---- 7. отказ ядра -------------------------------------------------------------------------------
H5="$(handle)"
printf '999.1.1.1\n' > "$tmp/p3.lst"
before="$(cksum < "$tmp/spec.json")"
fresh
r="$(ctl apply < "$tmp/S6.json")"
check "отказ ядра: не применено, прежняя спека возвращена" "false false true" \
    "$(printf '%s' "$r" | j saved | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(printf '%s' "$r" | j rolled_back)"
check "  spec.json — прежний" "$before" "$(cksum < "$tmp/spec.json")"
check "  прежняя таблица в ядре на месте" "$H5 1" \
    "$(handle) $("$real_nft" list table inet steer | grep -c '10\.2\.0\.0/16')"
kept="$(printf '%s' "$r" | j stderr | sed -n 's/.*(kept: \(.*\))$/\1/p')"
[ -n "$kept" ] && rm -f "$kept"
fresh
r="$(ctl apply < "$tmp/S5.json")"
check "  после отказа применённое забыто: следующий apply — всё" "true [a,b]" \
    "$(ch "$r" | awk '{print $1, $2}')"

# ---- 8. status во время компиляции --------------------------------------------------------------
# Список канала — именованный канал: план открывает его и ждёт данных, пока стенд не разрешит
# писать. Второй демон — без супервизора и с выключенным движком: нужен только план.
mkfifo "$tmp/big.fifo"
python3 - "$tmp/big.lst" <<'PY'
import sys
with open(sys.argv[1], 'w') as f:
    for i in range(50000):
        f.write('11.%d.%d.%d/32\n' % (i // 65536, (i // 256) % 256, i % 256))
PY
cat > "$tmp/feed.py" <<'PY'
import os, sys, time, errno
fifo, src, go = sys.argv[1:4]
while not os.path.exists(go): time.sleep(0.05)
data = open(src, 'rb').read()
while True:
    fd = os.open(fifo, os.O_WRONLY)
    try: os.write(fd, data)
    except OSError as e:
        if e.errno != errno.EPIPE: raise
    os.close(fd)
    time.sleep(0.2)          # читатель закрывает свой конец раньше, чем откроется следующий
PY
python3 "$tmp/feed.py" "$tmp/big.fifo" "$tmp/big.lst" "$tmp/go" &
W=$!
printf '{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{"a":{"kind":"interface","device":"wga"}},"channels":[{"name":"p","match":{"prefixes_file":"%s"},"out":"a"}]}\n' \
    "$tmp/big.fifo" > "$tmp/big.json"
cp "$tmp/S1.json" "$tmp/spec2.json"
STEER_CTL_ENABLED=0 "$BIN" daemon --socket "$tmp/s2.sock" --spec "$tmp/spec2.json" \
    --state-dir "$tmp/st2" 2>"$tmp/d2.err" &
D2=$!
wait_for '[ -S "$tmp/s2.sock" ]' 5
"$BIN" ctl --socket "$tmp/s2.sock" apply < "$tmp/big.json" > "$tmp/big.out" 2>&1 &
AP=$!
sleep 0.5
t="$(python3 -c '
import subprocess, sys, time
t = time.monotonic()
r = subprocess.run([sys.argv[1], "ctl", "--socket", sys.argv[2], "status"], capture_output=True)
print("%s %s" % ("fast" if time.monotonic() - t < 1.0 else "slow", r.returncode))
' "$BIN" "$tmp/s2.sock")"
check "status во время компиляции — сразу, apply ещё идёт" "fast 0 running" \
    "$t $(kill -0 $AP 2>/dev/null && [ ! -s "$tmp/big.out" ] && echo running || echo done)"
touch "$tmp/go"
wait_for '! kill -0 $AP 2>/dev/null' 30
check "  компиляция дошла до конца: спека сохранена" "0 true" \
    "$(j code < "$tmp/big.out" | tr -d '\n') $(j saved < "$tmp/big.out")"
AP=""

printf '\nreconmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
