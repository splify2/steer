#!/bin/sh
# Группы серверов DNS и сервер для имён вне правил (`dns.other`): живой резолвер, поддельные
# апстримы на петле, без root и без сети наружу. Устройство — src/dnsd/dupgrp.c, спека —
# docs/spec-v2.md, раздел `dns`.
#
# Поддельные серверы (обычный DNS по UDP, каждый на своём порту, каждый вопрос — строкой журнала):
#   silent   — молчит;            servfail — SERVFAIL сразу;    slow — ответ 10.0.0.4 через 700 мс;
#   oka      — 10.0.0.1 сразу;    okb      — 10.0.0.5 сразу;
#   flaky    — 10.0.0.6, а пока лежит файл flaky.down — молчит;
#   oth      — 10.0.0.7, а пока лежит файл oth.down — молчит;   sf — SERVFAIL (dns.other второго резолвера);
#   заглушка на порту «наверх» — прежний путь (dnsmasq): 10.0.0.9.
#
# Что проверяется.
#  1. race: вопрос уходит всем сразу; SERVFAIL и молчание не ответ — клиенту первый годный (медленный).
#  2. race: годный быстрый сервер отвечает за всех, хотя SERVFAIL пришёл раньше.
#  3. failover: SERVFAIL основного — сразу следующий.
#  4. failover: основной молчит — через 1,5 с спрошен следующий, ответ его; молчавший после срока
#     ответа уходит на паузу, и следующий вопрос его не спрашивает (ответ сразу).
#  5. failover возвращается: сервер ожил, пауза кончилась — снова отвечает он.
#  6. Группа, где годного ответа нет ни у кого, — SERVFAIL клиенту за срок.
#  7. dns.other: имя вне правил — его сервер, не прежний путь; имена своей сети (без точки, .lan) —
#     прежний путь; сервер молчит — запасной путь (ответ DNS роутера), следующие имена сразу им
#     (пауза); ожил — снова он.
#  8. dns.other ответил SERVFAIL — ответ DNS роутера, без паузы.
#  9. dns-log: группы (режим, члены, кто первый), сервер каждого имени, состояние dns.other.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "dnsgroups: python3 нет — пропускаю"; exit 0; }
# Под root — в своём сетевом пространстве: резолвер с real-ip кладёт адреса в наборы nft, и
# набор правил хоста стенду трогать незачем.
if [ "$(id -u)" = 0 ] && [ "${DNSGROUPS_INNER:-}" != 1 ] && unshare -n true 2>/dev/null; then
    DNSGROUPS_INNER=1 exec unshare -n sh -c 'ip link set lo up 2>/dev/null; exec sh "$0" "$@"' "$0" "$@"
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

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

cat > "$tmp/srv.py" <<'PY'
import os, socket, struct, sys, threading, time
log = sys.argv[1]
lock = threading.Lock()
def note(tag, name):
    with lock:
        open(log, "a").write("%s %s\n" % (tag, name))
def answer(q, ip=None, rcode=0):
    e = 12
    while q[e]: e += 1 + q[e]
    e += 5
    if ip is None:
        return q[:2] + bytes([0x81, 0x80 | rcode]) + q[4:6] + b"\x00\x00\x00\x00\x00\x00" + q[12:e]
    return (q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:e] +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(int(x) for x in ip.split(".")))
def qname(q):
    e, parts = 12, []
    while q[e]:
        parts.append(q[e + 1:e + 1 + q[e]].decode()); e += 1 + q[e]
    return ".".join(parts)
def serve(spec):
    tag, port, how = spec.split(":", 2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(port)))
    while True:
        q, a = s.recvfrom(2048)
        note(tag, qname(q))
        kind, _, arg = how.partition(":")
        if kind == "silent": continue
        if kind == "servfail": s.sendto(answer(q, None, 2), a); continue
        if kind == "ok": s.sendto(answer(q, arg), a); continue
        if kind == "slow":
            ms, ip = arg.split(":")
            threading.Timer(int(ms) / 1000.0, lambda q=q, a=a, ip=ip: s.sendto(answer(q, ip), a)).start()
            continue
        if kind == "flag":
            f, ip = arg.split(":")
            if os.path.exists(f): continue
            s.sendto(answer(q, ip), a)
for sp in sys.argv[2:]:
    threading.Thread(target=serve, args=(sp,), daemon=True).start()
print("ready", flush=True)
while True: time.sleep(3600)
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

P=154
LOG="$tmp/srv.log"; : > "$LOG"
python3 "$tmp/srv.py" "$LOG" silent:${P}21:silent servfail:${P}22:servfail slow:${P}23:slow:700:10.0.0.4 \
    oka:${P}24:ok:10.0.0.1 okb:${P}25:ok:10.0.0.5 flaky:${P}26:flag:$tmp/flaky.down:10.0.0.6 \
    oth:${P}27:flag:$tmp/oth.down:10.0.0.7 sf:${P}28:servfail stub:${P}29:ok:10.0.0.9 \
    sfa:${P}30:servfail sfb:${P}31:servfail sfd:${P}32:servfail sfe:${P}33:servfail sfc:${P}34:servfail \
    okc:${P}35:ok:10.0.0.8 > "$tmp/srv.out" 2>&1 &
echo $! > "$tmp/srv.pid"
n=0; while ! grep -q ready "$tmp/srv.out" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done

for l in race1 race2 fo1 fo2 fo3 fail sv rs rv; do printf '%s.test\n' "$l" > "$tmp/$l.lst"; done
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { addr: [127.0.0.0/8] }
lists:
  race1: { domains_file: $tmp/race1.lst }
  race2: { domains_file: $tmp/race2.lst }
  fo1:   { domains_file: $tmp/fo1.lst }
  fo2:   { domains_file: $tmp/fo2.lst }
  fo3:   { domains_file: $tmp/fo3.lst }
  fail:  { domains_file: $tmp/fail.lst }
  sv:    { domains_file: $tmp/sv.lst }
  rs:    { domains_file: $tmp/rs.lst }
  rv:    { domains_file: $tmp/rv.lst }
outputs:
  vpn: { kind: interface, device: lo }
dns:
  mode: realip
  other: oth
  upstreams:
    silent:   { url: "udp://127.0.0.1:${P}21" }
    servfail: { url: "udp://127.0.0.1:${P}22" }
    slow:     { url: "udp://127.0.0.1:${P}23" }
    oka:      { url: "udp://127.0.0.1:${P}24" }
    okb:      { url: "udp://127.0.0.1:${P}25" }
    flaky:    { url: "udp://127.0.0.1:${P}26" }
    oth:      { url: "udp://127.0.0.1:${P}27" }
    sfa:      { url: "udp://127.0.0.1:${P}30" }
    sfb:      { url: "udp://127.0.0.1:${P}31" }
    sfd:      { url: "udp://127.0.0.1:${P}32" }
    sfe:      { url: "udp://127.0.0.1:${P}33" }
    sfc:      { url: "udp://127.0.0.1:${P}34" }
    okc:      { url: "udp://127.0.0.1:${P}35" }
    sv: { servers: [sfa, sfb], mode: failover }
    rs: { servers: [sfc, okc], mode: race }
    rv: { servers: [sfd, sfe], mode: race }
    race1: { servers: [silent, servfail, slow], mode: race }
    race2: { servers: [servfail, oka, slow], mode: race }
    fo1:   { servers: [silent, oka], mode: failover }
    fo2:   { servers: [servfail, okb] }
    fo3:   { servers: [flaky, okb], mode: failover }
rules:
  - { name: race1, to: [race1], out: vpn, dns: race1 }
  - { name: race2, to: [race2], out: vpn, dns: race2 }
  - { name: fo1,   to: [fo1],   out: vpn, dns: fo1 }
  - { name: fo2,   to: [fo2],   out: vpn, dns: fo2 }
  - { name: fo3,   to: [fo3],   out: vpn, dns: fo3 }
  - { name: sv,    to: [sv],    out: vpn, dns: sv }
  - { name: rs,    to: [rs],    out: vpn, dns: rs }
  - { name: rv,    to: [rv],    out: vpn, dns: rv }
  - { name: fail,  to: [fail],  out: vpn, dns: { servers: [silent, servfail], mode: race } }
EOF
L=${P}10
mkdir -p "$tmp/st" "$tmp/st2"
STEER_DNSD_PAUSE_MS=3000 "$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st" --listen-port "$L" \
    --upstream-port ${P}29 > "$tmp/d.log" 2>&1 &
echo $! > "$tmp/d.pid"
sleep 1
kill -0 "$(cat "$tmp/d.pid")" 2>/dev/null || { echo "FAIL резолвер не поднялся:"; cat "$tmp/d.log"; exit 1; }

ask() { python3 "$tmp/ask.py" "$L" "$1"; }
addr() { echo "${1% *}"; }
ms() { echo "${1#* }"; }
inr() { [ "$1" -ge "$2" ] && [ "$1" -le "$3" ] && echo yes || echo "нет ($1 мс)"; }
asked() { grep -c "^$1 $2\$" "$LOG"; }           # спрошен ли сервер $1 об имени $2

tab="$("$BIN" dnsd-table --spec "$tmp/spec.yaml" 2>&1)"
check "таблица: седьмое число заголовка — dns.other" "1" \
    "$(printf '%s\n' "$tab" | head -1 | awk 'NF == 7 { print 1 }')"
check "таблица: строка группы race1" "1" "$(printf '%s\n' "$tab" | grep -c '^race1|group:race|-|0|[0-9,]*|-$')"

# ---- 1-3 ----------------------------------------------------------------------------------------
r="$(ask q1.race1.test)"
check "race: SERVFAIL и молчание пропущены — ответ медленного" "10.0.0.4" "$(addr "$r")"
check "  через ~700 мс, а не через срок молчащего" "yes" "$(inr "$(ms "$r")" 550 1500)"
check "  вопрос ушёл всем трём" "1 1 1" \
    "$(asked silent q1.race1.test) $(asked servfail q1.race1.test) $(asked slow q1.race1.test)"
r="$(ask q1.race2.test)"
check "race: быстрый годный отвечает за группу" "10.0.0.1" "$(addr "$r")"
check "  сразу" "yes" "$(inr "$(ms "$r")" 0 400)"
r="$(ask q1.fo2.test)"
check "failover: SERVFAIL основного — сразу следующий" "10.0.0.5" "$(addr "$r")"
check "  без ожидания срока" "yes" "$(inr "$(ms "$r")" 0 400)"
check "  основной спрошен один раз, следующий — один" "1 1" \
    "$(asked servfail q1.fo2.test) $(asked okb q1.fo2.test)"

# ---- 3б. память отказов: выживание и пропуск плохих в race --------------------------------------
# Все члены на паузе — ровно ОДНА попытка через наименее плохого, а не обход всех (failover) и не
# веер (race). Пауза 3 с (STEER_DNSD_PAUSE_MS), все вопросы — подряд, внутри неё.
r="$(ask q1.sv.test)"
check "failover, оба отказывают: первый вопрос — обоим по очереди, SERVFAIL" "rcode2 1 1" \
    "$(addr "$r") $(asked sfa q1.sv.test) $(asked sfb q1.sv.test)"
r="$(ask q2.sv.test)"
check "failover, все на паузе: ровно одна попытка (не обход всех)" "rcode2 1" \
    "$(addr "$r") $(( $(asked sfa q2.sv.test) + $(asked sfb q2.sv.test) ))"
r="$(ask q3.sv.test)"
check "  следующий вопрос — снова одна попытка" "1" "$(( $(asked sfa q3.sv.test) + $(asked sfb q3.sv.test) ))"
who() { if [ "$(asked sfa "$1")" = 1 ]; then echo sfa; else echo sfb; fi; }
check "  и другому серверу: наименее плохой сменился (отказавший ушёл на более долгую паузу)" "sfa sfb" \
    "$(who q2.sv.test) $(who q3.sv.test)"
r="$(ask q1.rs.test)"
check "race: первый вопрос — обоим, ответ годного" "10.0.0.8 1 1" \
    "$(addr "$r") $(asked sfc q1.rs.test) $(asked okc q1.rs.test)"
r="$(ask q2.rs.test)"
check "race: отказавший на паузе не спрашивается, годный отвечает" "10.0.0.8 0 1" \
    "$(addr "$r") $(asked sfc q2.rs.test) $(asked okc q2.rs.test)"
r="$(ask q1.rv.test)"
check "race, оба отказывают: первый вопрос — обоим, SERVFAIL" "rcode2 1 1" \
    "$(addr "$r") $(asked sfd q1.rv.test) $(asked sfe q1.rv.test)"
r="$(ask q2.rv.test)"
check "race, все на паузе: ровно одна попытка (не веер)" "rcode2 1" \
    "$(addr "$r") $(( $(asked sfd q2.rv.test) + $(asked sfe q2.rv.test) ))"

# ---- 4-6: молчание, пауза, возвращение — параллельно, по одной шкале времени ---------------------
: > "$tmp/flaky.down"
ask q1.fo1.test > "$tmp/fo1.1" & A1=$!
ask q1.fo3.test > "$tmp/fo3.1" & A2=$!
ask q1.fail.test > "$tmp/fail.1" & A3=$!
sleep 4.5                     # молчащие отвечают отказом через 4 с — пауза 3 с
wait $A1 $A2 $A3
r="$(cat "$tmp/fo1.1")"
check "failover: основной молчит — ответ следующего" "10.0.0.1" "$(addr "$r")"
check "  через 1,5 с (не через срок основного)" "yes" "$(inr "$(ms "$r")" 1400 2600)"
check "  основной был спрошен первым" "1" "$([ "$(asked silent q1.fo1.test)" -ge 1 ] && echo 1)"
r="$(cat "$tmp/fail.1")"
check "годного ответа нет ни у кого — SERVFAIL клиенту" "rcode2" "$(addr "$r")"
check "  за срок вопроса" "yes" "$(inr "$(ms "$r")" 3500 5500)"
rm -f "$tmp/flaky.down"
r="$(ask q2.fo1.test)"
check "failover: молчавший на паузе — ответ сразу от следующего" "10.0.0.1 yes" \
    "$(addr "$r") $(inr "$(ms "$r")" 0 400)"
check "  молчавшего не спрашивали" "0" "$(asked silent q2.fo1.test)"
r="$(ask q2.fo3.test)"
check "failover: ожившего на паузе ещё не спрашивают" "10.0.0.5 0" "$(addr "$r") $(asked flaky q2.fo3.test)"
sleep 3                       # пауза кончилась
r="$(ask q3.fo3.test)"
check "failover возвращается: пауза кончилась, ответ снова основного" "10.0.0.6" "$(addr "$r")"
check "  сразу" "yes" "$(inr "$(ms "$r")" 0 400)"
check "  следующего не спрашивали" "0" "$(asked okb q3.fo3.test)"

# ---- 7. dns.other ---------------------------------------------------------------------------------
r="$(ask www.example.org)"
check "dns.other: имя вне правил — его сервер" "10.0.0.7" "$(addr "$r")"
check "  прежний путь не спрошен" "0" "$(asked stub www.example.org)"
check "имя без точки — DNS роутера" "10.0.0.9 0" "$(addr "$(ask router)") $(asked oth router)"
check "имя .lan — DNS роутера" "10.0.0.9 0" "$(addr "$(ask nas.lan)") $(asked oth nas.lan)"
check "обратная зона — DNS роутера" "1 0" \
    "$(ask 1.1.168.192.in-addr.arpa > /dev/null; asked stub 1.1.168.192.in-addr.arpa) $(asked oth 1.1.168.192.in-addr.arpa)"
: > "$tmp/oth.down"
r="$(ask a.example.org)"
check "dns.other молчит — ответ DNS роутера (запасной путь)" "10.0.0.9" "$(addr "$r")"
check "  после срока вопроса к серверу" "yes" "$(inr "$(ms "$r")" 3500 5500)"
r="$(ask b.example.org)"
check "  следующее имя — сразу DNS роутера (пауза)" "10.0.0.9 yes" "$(addr "$r") $(inr "$(ms "$r")" 0 400)"
check "  сервер на паузе не спрошен" "0" "$(asked oth b.example.org)"
rm -f "$tmp/oth.down"
sleep 3.2
r="$(ask c.example.org)"
check "dns.other ожил, пауза кончилась — снова он" "10.0.0.7" "$(addr "$r")"

# ---- 9. dns-log -----------------------------------------------------------------------------------
"$BIN" dns-log --state-dir "$tmp/st" > "$tmp/dnslog.json" 2>/dev/null
dl() { python3 - "$tmp/dnslog.json" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
u = {x["name"]: x for x in d["upstreams"]}
nm = {x["name"]: x for x in d["names"]}
k = sys.argv[2]
if k == "grp": print(u["race1"]["proto"], u["race1"]["mode"], ",".join(s["name"] for s in u["race1"]["servers"]))
if k == "fo3": print(u["fo3"]["mode"], u["fo3"]["active"], u["fo3"]["state"])
if k == "fo1": print(u["fo1"]["active"], int(u["fo1"]["servers"][0]["failed"] >= 1))
if k == "dns": print(nm["q1.race1.test"]["dns"], nm["www.example.org"]["dns"], nm["router"]["dns"])
if k == "other": o = d["other"]; print(o["name"], int(o["fallback"] >= 2), int(o["failed"] >= 1), o["pause"])
PY
}
check "dns-log: группа race1 — режим и члены" "group race silent,servfail,slow" "$(dl grp)"
check "dns-log: fo3 — первым снова flaky" "failover flaky ready" "$(dl fo3)"
check "dns-log: fo1 — молчавший на паузе, первым oka" "oka 1" "$(dl fo1)"
check "dns-log: сервер каждого имени (null — DNS роутера)" "race1 oth None" "$(dl dns)"
check "dns-log: dns.other — запасной путь был, пауза снята" "oth 1 1 0" "$(dl other)"
kill "$(cat "$tmp/d.pid")" 2>/dev/null

# ---- 8. dns.other с SERVFAIL ----------------------------------------------------------------------
cat > "$tmp/spec2.yaml" <<EOF
version: 2
lan: { addr: [127.0.0.0/8] }
outputs:
  vpn: { kind: interface, device: lo }
dns:
  other: sf
  upstreams:
    sf: { url: "udp://127.0.0.1:${P}28" }
EOF
L=${P}12
"$BIN" dnsd --spec "$tmp/spec2.yaml" --state-dir "$tmp/st2" --listen-port "$L" --upstream-port ${P}29 \
    > "$tmp/d2.log" 2>&1 &
echo $! > "$tmp/d2.pid"
sleep 1
r="$(ask x.example.net)"
check "dns.other SERVFAIL — ответ DNS роутера, сразу" "10.0.0.9 yes" "$(addr "$r") $(inr "$(ms "$r")" 0 400)"
r="$(ask y.example.net)"
check "  без паузы: следующее имя снова спрошено у сервера" "1" "$(asked sf y.example.net)"
"$BIN" dns-log --state-dir "$tmp/st2" > "$tmp/dnslog.json" 2>/dev/null
check "  dns-log: пауза 0, запасной путь дважды" "sf 1 1 0" "$(dl other)"

# ---- 10. steer explain называет сервер имени ------------------------------------------------------
# explain спрашивает резолвер на его постоянном порту (DNS_PORT, 5300) — только в своём пространстве.
if [ "${DNSGROUPS_INNER:-}" = 1 ]; then
    mkdir -p "$tmp/st3"
    "$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st3" --listen-port 5300 --upstream-port ${P}29 \
        > "$tmp/d3.log" 2>&1 &
    echo $! > "$tmp/d3.pid"
    sleep 1
    ex() { "$BIN" explain --spec "$tmp/spec.yaml" --state-dir "$tmp/st3" "$1" 2>&1 | grep 'DNS:\|вне правил:'; }
    check "explain: имя под правилом — группа, режим, члены" \
        "      DNS: группа «race1» (все сразу, первый годный ответ): silent, servfail, slow" "$(ex e.race1.test)"
    check "explain: имя вне правил — сервер dns.other и запасной путь" \
        "$(printf '      DNS: сервер «oth» (udp://127.0.0.1:%s27)\n      имя вне правил: не ответит — спросится DNS роутера' $P)" \
        "$(ex e.example.org)"
    check "explain: имя своей сети — DNS роутера" "      DNS: DNS роутера (прежний путь)" "$(ex router)"
fi

# ---- 11. под демоном: таблица по трубе (группа и dns.other в заголовке), status ------------------
if [ "${DNSGROUPS_INNER:-}" = 1 ] && command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1; then
    kill "$(cat "$tmp/d3.pid")" 2>/dev/null
    cat > "$tmp/spec4.yaml" <<EOF
version: 2
lan: { addr: [127.0.0.0/8] }
lists:
  race1: { domains_file: $tmp/race1.lst }
outputs:
  vpn: { kind: interface, device: lo }
dns:
  mode: realip
  other: fo
  upstreams:
    silent:   { url: "udp://127.0.0.1:${P}21" }
    servfail: { url: "udp://127.0.0.1:${P}22" }
    oka:      { url: "udp://127.0.0.1:${P}24" }
    okb:      { url: "udp://127.0.0.1:${P}25" }
    fo:       { servers: [servfail, okb] }
rules:
  - { name: race1, to: [race1], out: vpn, dns: { servers: [silent, oka], mode: race } }
EOF
    mkdir -p "$tmp/st4"
    "$BIN" apply --spec "$tmp/spec4.yaml" --state-dir "$tmp/st4" > "$tmp/apply4.out" 2>&1
    "$BIN" daemon --supervise --socket "$tmp/s4.sock" --spec "$tmp/spec4.yaml" --state-dir "$tmp/st4" \
        --dnsd-flag --listen-port --dnsd-flag ${P}13 --dnsd-flag --upstream-port --dnsd-flag ${P}29 \
        > "$tmp/d4.log" 2>&1 &
    echo $! > "$tmp/d4.pid"
    n=0; while ! grep -q 'слушает\|listening on' "$tmp/d4.log" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    L=${P}13
    check "демон: имя под правилом — своя группа правила (race)" "10.0.0.1" "$(addr "$(ask d.race1.test)")"
    check "демон: имя вне правил — группа dns.other (SERVFAIL — следующий)" "10.0.0.5" "$(addr "$(ask d.example.com)")"
    check "демон: в status названы умения dns_groups и dns_other" "2" \
        "$("$BIN" status --spec "$tmp/spec4.yaml" --state-dir "$tmp/st4" 2>/dev/null | grep -o '"dns_groups"\|"dns_other"' | wc -l | tr -d ' ')"
    "$BIN" dns-log --state-dir "$tmp/st4" > "$tmp/dnslog.json" 2>/dev/null
    check "демон: dns-log — dns.other и сервер имени" "fo race1" "$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1])); nm = {x["name"]: x for x in d["names"]}
print(d["other"]["name"], nm["d.race1.test"]["dns"])' "$tmp/dnslog.json" 2>&1)"
    kill "$(cat "$tmp/d4.pid")" 2>/dev/null
    sleep 0.5
    "$BIN" down --spec "$tmp/spec4.yaml" --state-dir "$tmp/st4" > /dev/null 2>&1
fi

echo "dnsgroups: пройдено $pass, провалено $fail"
[ "$fail" = 0 ]
