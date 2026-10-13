#!/bin/sh
# Резолвер и ядро: DNAT-карта fakeip через настоящий netlink, в отдельном сетевом пространстве.
#
# Всё прочее в резолвере проверяется без ядра, а путь «ответ апстрима -> элемент карты» — нет,
# и именно в нём жили две ошибки, которые снаружи выглядят одинаково: клиент с поддельным
# адресом идёт без подмены. Поэтому здесь поднимается настоящий dnsd в `unshare -n`, с таблицей
# `inet steer` и картой `fakeip` такими, какими их ждёт резолвер, поддельным апстримом на петле
# и `nft monitor` рядом — он считает, сколькими транзакциями ядро приняло переезд домена.
#
# Что проверяется.
#  1. Переезд (апстрим ответил другим адресом) — ОДНА транзакция: удаление старого значения и
#     добавление нового идут одним батчем. Двумя транзакциями между ними есть поколение ядра,
#     в котором поддельного адреса в карте нет, а при отказе второй — карта теряет элемент
#     насовсем, хотя резолвер продолжает раздавать этот адрес из быстрого пути.
#  2. После переезда в карте новый адрес.
#  3. Элемент удалён снаружи (перезагрузка fw4 снесла карту), затем переезд: удаление отвечает
#     ENOENT, батч откатывается целиком — и резолвер обязан повторить одно добавление.
#  4. Ядро отвергло добавление нового значения — прежнее отображение остаётся в карте (батч
#     откатывается целиком), а не пропадает вместе с удалением.
#  5. HUP при исчезнувшем файле правил не оставляет канал без правил, а вернувшийся файл
#     следующим HUP подхватывается.
#  6. Стойкий отказ ядра (карта не того типа) — настоящий адрес, а не SERVFAIL; окно
#     пересборки (таблицы нет) — SERVFAIL, но не дольше MAP_WINDOW_SEC (15 с) подряд, после —
#     тоже настоящий адрес; первое принятое отображение окно обнуляет.
#
# Нужны root (сетевое пространство и nf_tables), nft и python3. Без них стенд пропускается,
# а не проваливается: остальной набор обязан проходить на голой машине.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "dnsnft: python3 нет — пропускаю"; exit 0; }
command -v nft >/dev/null 2>&1 || { echo "dnsnft: nft нет — пропускаю"; exit 0; }
if [ "${DNSNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "dnsnft: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "dnsnft: unshare -n недоступен — пропускаю"; exit 0; }
    DNSNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet steer 2>/dev/null || { echo "dnsnft: nf_tables недоступен — пропускаю"; exit 0; }
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} ${MPID:-0} ${DPID6:-0} ${UPID6:-0} 2>/dev/null; rm -rf "$tmp"' EXIT

LPORT=15310
UPORT=15363

# Апстрим отвечает на A тем адресом, что лежит в файле сейчас: переезд домена — это запись
# в файл между запросами.
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    ip = bytes(int(x) for x in open(sys.argv[2]).read().split("."))
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip
    s.sendto(hdr + data[12:qend] + ans, addr)
PY

cat > "$tmp/client.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
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

printf 'example.com\nmoved.net\nfail.io\nstay.org\nperm.io\nwin.io\nwin2.io\n' > "$tmp/d.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { addr: [127.0.0.0/8] }
lists:
  c: { domains_file: $tmp/d.lst }
outputs:
  direct: { kind: direct }
  vpn: { kind: interface, device: lo }
rules:
  - { name: c, to: c, out: vpn }
EOF

echo 203.0.113.1 > "$tmp/ip"
python3 "$tmp/upstream.py" "$UPORT" "$tmp/ip" & UPID=$!
nft monitor > "$tmp/mon" 2>&1 & MPID=$!
sleep 1
"$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/state" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/log" 2>&1 & DPID=$!
sleep 1
kill -0 "$DPID" 2>/dev/null || { echo "FAIL резолвер не поднялся:"; cat "$tmp/log"; exit 1; }

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
ask() { python3 "$tmp/client.py" "$LPORT" "$1"; }
# Значение карты для поддельного адреса: пусто, если элемента нет.
mapval() { nft get element inet steer fakeip "{ $1 }" 2>/dev/null |
           sed -n 's/.*elements = { [0-9.]* : \([0-9.]*\).*/\1/p'; }
gens() { grep -c 'new generation' "$tmp/mon"; }
# Переезд идёт из быстрого пути: клиенту сразу уходит поддельный адрес, а карту обновляет
# фоновый ответ апстрима. Его и ждём.
settle() { sleep 0.5; }

# Каждый сценарий — своё имя. Быстрый путь ходит наверх за свежестью карты не чаще раза в
# FAKEIP_ANSWER_TTL (60 с), и первый такой поход случается на ВТОРОМ запросе имени: первый
# идёт наверх обычным путём и ставит карту, второй отвечает поддельным сразу и обновляет карту
# фоновым ответом. То есть на имя в стенде ровно один переезд.
first() {   # имя адрес -> поддельный адрес; карта должна встать с этим адресом
    echo "$2" > "$tmp/ip"
    f="$(ask "$1")"
    settle
    check "$1: первый ответ — поддельный адрес" "198.18" "$(echo "$f" | cut -d. -f1-2)"
    check "$1: в карте первый адрес" "$2" "$(mapval "$f")"
}
move() {    # имя новый-адрес: переезд через быстрый путь
    echo "$2" > "$tmp/ip"
    ask "$1" >/dev/null
    settle
}

# --- 1-2. Переезд ---------------------------------------------------------------------------
first example.com 203.0.113.1
fake="$f"
g0="$(gens)"
move example.com 203.0.113.2
g1="$(gens)"
check "переезд — одна транзакция ядра" "1" "$((g1 - g0))"
check "после переезда в карте новый адрес" "203.0.113.2" "$(mapval "$fake")"

# --- 3. Элемент удалён снаружи, затем переезд ------------------------------------------------
first moved.net 203.0.113.11
fake="$f"
nft delete element inet steer fakeip "{ $fake }"
move moved.net 203.0.113.12
check "после внешнего удаления переезд восстановил элемент" "203.0.113.12" "$(mapval "$fake")"

# --- 4. Добавление отвергнуто — прежнее отображение остаётся ---------------------------------
# Карта того же имени, но со значением IPv6: удаление по ключу проходит, а добавление
# четырёхбайтного значения ядро отвергает. Двумя транзакциями удаление успевало
# зафиксироваться и элемент пропадал; одним батчем откатывается всё, и прежнее значение цело.
first fail.io 203.0.113.21
fake="$f"
nft delete map inet steer fakeip
nft add map inet steer fakeip '{ type ipv4_addr : ipv6_addr; }'
nft add element inet steer fakeip "{ $fake : 2001:db8::21 }"
move fail.io 203.0.113.22
check "отказ добавления не снёс прежний элемент" "1" \
    "$(nft list map inet steer fakeip | grep -c "$fake : 2001:db8::21")"
nft delete map inet steer fakeip
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'

# --- 5. HUP при исчезнувшем файле правил ----------------------------------------------------
mv "$tmp/d.lst" "$tmp/d.lst.gone"
kill -HUP "$DPID"
sleep 0.5
stay="$(ask stay.org)"
check "HUP без файла правил: домен из прежних правил всё ещё подменяется" "198.18" \
    "$(echo "$stay" | cut -d. -f1-2)"
# Файл вернулся с новым именем — следующий HUP его берёт: подмена не застыла на старом.
{ cat "$tmp/d.lst.gone"; echo new.dev; } > "$tmp/d.lst"
rm -f "$tmp/d.lst.gone"
kill -HUP "$DPID"
sleep 0.5
check "HUP с вернувшимся файлом берёт новые правила" "198.18" \
    "$(ask new.dev | cut -d. -f1-2)"

# --- 6. Стойкий отказ против окна пересборки ------------------------------------------------
nft delete map inet steer fakeip
nft add map inet steer fakeip '{ type ipv4_addr : ipv6_addr; }'
echo 203.0.113.31 > "$tmp/ip"
check "стойкий отказ (карта не того типа): настоящий адрес, не SERVFAIL" "203.0.113.31" \
    "$(ask perm.io)"
nft delete table inet steer
echo 203.0.113.41 > "$tmp/ip"
check "окно пересборки (таблицы нет): SERVFAIL" "rcode2" "$(ask win.io)"
sleep 16
check "таблицы нет дольше окна: настоящий адрес" "203.0.113.41" "$(ask win.io)"
nft add table inet steer
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'
check "таблица вернулась: снова поддельный адрес" "198.18" "$(ask win.io | cut -d. -f1-2)"
nft delete table inet steer
check "после принятого отображения окно началось заново: SERVFAIL" "rcode2" "$(ask win2.io)"

kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null

# --- 7. fake-IP v6 и real-ip v6 (docs/architecture.md, «4б») ------------------------------
# Свой резолвер со своим каталогом состояния: первая запись файла состояния случается сразу, а
# следующие — не чаще раза в минуту, и проверять восстановление по чужому, уже записанному
# файлу нельзя. Апстрим отвечает на A адресом из ip, на AAAA — из ip6.
#  a. AAAA имени fake-IP-правила в выход с IPv6 — поддельный IPv6 из пула, пара поддельного IPv4
#     той же записи; в карте fakeip6 — настоящий IPv6; поддельный — постоянным элементом набора
#     «<канал>6»; в файле состояния — четвёртое поле.
#  b. Правило в выход без IPv6 — пустой AAAA; имя вне правил — настоящий AAAA.
#  c. real-ip: настоящий AAAA клиенту и в набор «<канал>6» со сроком.
#  d. Перезапуск: карта и набор восстановлены из файла, AAAA отвечается сразу тем же адресом.
#  e. Карта fakeip6 не того типа — пустой AAAA, а не настоящий.
#  f. Набор правил заменён, затем HUP — поддельные адреса обоих семейств снова в наборах каналов.
#  g. То же для real-ip: настоящие адреса обоих семейств снова в наборах канала — со сроком, и срок
#     — оставшийся, а не TTL ответа заново (память резолвера, src/dnsd/realip.c).
#  h. Та же спека записью v1 — на AAAA имён правил пустой ответ (всё выше — спека v2).
nft add table inet steer
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'
nft add map inet steer fakeip6 '{ type ipv6_addr : ipv6_addr; }'
cat > "$tmp/upstream6.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qtype = data[qend + 1] << 8 | data[qend + 2]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    if qtype == 28:
        ip = socket.inet_pton(socket.AF_INET6, open(sys.argv[3]).read().strip())
        ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + ip
    else:
        ip = bytes(int(x) for x in open(sys.argv[2]).read().split("."))
        ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/client6.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4343, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 28, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
rc = d[3] & 0x0f
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(socket.inet_ntop(socket.AF_INET6, d[-16:]))
PY
printf 'v6.io\nv6b.io\n' > "$tmp/d6.lst"
printf 'r6.io\n' > "$tmp/r6.lst"
printf 't4.io\n' > "$tmp/t4.lst"
# Спека v2: поддельный и настоящий IPv6 на AAAA.
printf '{"version":2,"lan":{"addr":["127.0.0.0/8"]},'\
'"lists":{"c6":{"domains_file":"%s/d6.lst"},"r6":{"domains_file":"%s/r6.lst"},'\
'"t4":{"domains_file":"%s/t4.lst"}},'\
'"outputs":{"vpn":{"kind":"interface","device":"lo"},"tg":{"kind":"tgws","domain":"example.com"}},'\
'"rules":[{"name":"c6","to":"c6","out":"vpn"},'\
'{"name":"r6","to":"r6","out":"vpn","resolve":"realip"},'\
'{"name":"t4","to":"t4","out":"tg"}]}' \
    "$tmp" "$tmp" "$tmp" > "$tmp/spec6.json"
tab6="$("$BIN" dnsd-table --spec "$tmp/spec6.json" 2>/dev/null)"
set_c6="$(printf '%s\n' "$tab6" | awk -F'|' '$5 == "c6" { print $1 }')"
set_r6="$(printf '%s\n' "$tab6" | awk -F'|' '$5 == "r6" { print $1 }')"
check "таблица: fake-IP и real-ip в выход с IPv6 — «46», в выход без IPv6 — «4»" "46 46 4" \
    "$(printf '%s\n' "$tab6" | awk -F'|' 'NF > 4 { printf "%s%s", s, $4; s = " " }')"
nft add set inet steer "${set_c6}6" '{ type ipv6_addr; flags interval,timeout; }'
nft add set inet steer "${set_r6}6" '{ type ipv6_addr; flags interval,timeout; }'
LPORT6=15320
UPORT6=15373
echo 203.0.113.61 > "$tmp/ip4"
echo 2001:db8:77::1 > "$tmp/ip6"
python3 "$tmp/upstream6.py" "$UPORT6" "$tmp/ip4" "$tmp/ip6" & UPID6=$!
mkdir -p "$tmp/state6"
sleep 1
start6() {
    "$BIN" dnsd --spec "$tmp/spec6.json" --state-dir "$tmp/state6" \
        --listen-port "$LPORT6" --upstream-port "$UPORT6" >> "$tmp/log6" 2>&1 & DPID6=$!
    sleep 1
}
start6
ask6() { python3 "$tmp/client6.py" "$LPORT6" "$1"; }
map6() { nft get element inet steer fakeip6 "{ $1 }" 2>/dev/null |
         sed -n 's/.*elements = { [0-9a-f:]* : \([0-9a-f:]*\).*/\1/p'; }
in6() { nft list set inet steer "$1" 2>/dev/null | grep -c "$2"; }

f6="$(ask6 v6.io)"
settle
check "a. AAAA fake-IP-правила — адрес из пула fake-IP v6" "fdfe:dcba:9876::c612" \
    "$(echo "$f6" | sed 's/:[0-9a-f]*$//')"
check "a. в карте fakeip6 — настоящий IPv6" "2001:db8:77::1" "$(map6 "$f6")"
check "a. поддельный IPv6 — в наборе канала" "1" "$(in6 "${set_c6}6" "$f6")"
check "a. и без срока (постоянный элемент)" "0" \
    "$(nft list set inet steer "${set_c6}6" | grep "$f6" | grep -c timeout)"
check "a. в файле состояния — четвёртое поле" "1" \
    "$(grep -c "^v6.io	198\.1[89]\.[0-9.]*	-	2001:db8:77::1\$" "$tmp/state6/fakeip.state")"
f4="$(python3 "$tmp/client.py" "$LPORT6" v6.io)"
pair="$(python3 -c "import ipaddress,sys; a=int(ipaddress.IPv4Address(sys.argv[1])); print(ipaddress.IPv6Address((0xfdfedcba9876 << 80) | a))" "$f4" 2>/dev/null)"
check "a. поддельный IPv6 — пара поддельного IPv4 той же записи" "$pair" "$f6"
check "b. правило в выход без IPv6 — пустой AAAA" "empty" "$(ask6 t4.io)"
check "b. имя вне правил — настоящий AAAA" "2001:db8:77::1" "$(ask6 out.io)"
echo 2001:db8:77::2 > "$tmp/ip6"
check "c. real-ip: клиенту — настоящий AAAA" "2001:db8:77::2" "$(ask6 r6.io)"
check "c. real-ip: адрес — в наборе «<канал>6» со сроком" "1" \
    "$(nft list set inet steer "${set_r6}6" | grep '2001:db8:77::2' | grep -c timeout)"

kill "$DPID6" 2>/dev/null; wait "$DPID6" 2>/dev/null
nft delete element inet steer fakeip6 "{ $f6 }"
nft flush set inet steer "${set_c6}6"
echo 2001:db8:77::3 > "$tmp/ip6"
start6
check "d. перезапуск: элемент карты fakeip6 восстановлен из файла" "2001:db8:77::1" "$(map6 "$f6")"
check "d. и поддельный IPv6 — снова в наборе канала" "1" "$(in6 "${set_c6}6" "$f6")"
check "d. AAAA — тот же поддельный адрес" "$f6" "$(ask6 v6.io)"

# f. Набор правил заменён (apply пересоздаёт таблицу — наборы каналов приходят пустыми), затем
#    HUP, как после reload: постоянные элементы поддельных адресов обоих семейств снова в наборах
#    сразу, без запроса имени. Прежде они возвращались только запросом после дросселя (60 с), а
#    клиент с поддельным адресом в кэше всё это время шёл напрямую. Набор IPv4 канала заводится
#    только здесь — элемента поддельного IPv4 в нём не было, и его появление — работа прохода.
nft add set inet steer "$set_c6" '{ type ipv4_addr; flags interval,timeout; }'
nft flush set inet steer "${set_c6}6"
kill -HUP "$DPID6"
sleep 0.5
check "f. после замены набора и HUP поддельный IPv6 снова в наборе канала" "1" "$(in6 "${set_c6}6" "$f6")"
check "f. и поддельный IPv4 — в наборе канала IPv4" "1" "$(in6 "$set_c6" "$f4")"

# g. real-ip: адреса из ответов (A и AAAA) лежат в наборах канала со сроком ответа (60 с). Набор
#    правил заменён — наборы пусты; HUP (как и таблица от демона) возвращает их из памяти с
#    оставшимся сроком: через 2 с после ответа — меньше минуты, в секундах.
nft add set inet steer "$set_r6" '{ type ipv4_addr; flags interval,timeout; }'
echo 203.0.113.71 > "$tmp/ip4"
echo 2001:db8:77::7 > "$tmp/ip6"
r4="$(python3 "$tmp/client.py" "$LPORT6" r6.io)"
r6="$(ask6 r6.io)"
check "g. real-ip: клиенту — настоящие адреса обоих семейств" "203.0.113.71 2001:db8:77::7" "$r4 $r6"
sleep 2
nft flush set inet steer "$set_r6"
nft flush set inet steer "${set_r6}6"
check "g. набор правил заменён — наборы real-ip пусты" "0 0" \
    "$(in6 "$set_r6" 203.0.113.71) $(in6 "${set_r6}6" 2001:db8:77::7)"
kill -HUP "$DPID6"
sleep 0.5
left_of() { nft list set inet steer "$1" | grep -o "$2 timeout [0-9a-z]*" | awk '{ print $3 }'; }
check "g. после HUP адрес IPv4 снова в наборе, срок оставшийся (меньше минуты)" "yes" \
    "$(left_of "$set_r6" 203.0.113.71 | grep -qx '[1-5]\{0,1\}[0-9]s' && echo yes || echo "no:$(left_of "$set_r6" 203.0.113.71)")"
check "g. и адрес IPv6 — в наборе «<канал>6», срок оставшийся" "yes" \
    "$(left_of "${set_r6}6" 2001:db8:77::7 | grep -qx '[1-5]\{0,1\}[0-9]s' && echo yes || echo "no:$(left_of "${set_r6}6" 2001:db8:77::7)")"

nft delete map inet steer fakeip6
nft add map inet steer fakeip6 '{ type ipv6_addr : ipv4_addr; }'
check "e. карта fakeip6 не того типа — пустой AAAA, не настоящий" "empty" "$(ask6 v6b.io)"
kill "$DPID6" "$UPID6" 2>/dev/null; wait "$DPID6" 2>/dev/null
nft delete table inet steer

if [ "$fail" -gt 0 ]; then
    echo "--- nft monitor"; cat "$tmp/mon"; echo "--- dnsd"; tail -n 20 "$tmp/log"
    echo "--- dnsd (IPv6)"; tail -n 20 "$tmp/log6"
fi
printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
