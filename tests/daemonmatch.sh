#!/bin/sh
# Демон целиком, как его держит один сервис (docs/architecture.md, раздел 4а): `steerd
# daemon --watch --supervise --apply` в своём сетевом пространстве с настоящим nft, и клиент
# `steer` (src/client/main.c) — тот, которым пользуются rpcd, init.d и человек.
#
# Что проверяется.
#  1. init.d (files/etc/init.d/steer): procd держит ровно один экземпляр — steerd daemon с
#     --watch --supervise --apply и respawn; reload и reapply идут в сокет клиентом.
#  2. Демон при старте применяет спеку сам (--apply): набор правил в ядре, без отдельного apply.
#  3. Помощники-заглушки подняты демоном (helper-up у подписчика), резолвер отвечает.
#  4. status через клиент — ответ демона, и он тот же, что у движка без демона (прежний формат);
#     клиент без демона отдаёт status движку с тем же выводом; чужая спека — движку.
#  5. apply через клиент — через демон (сверка), вывод и код подкоманды.
#  6. Падение устройства — сторож переключает выход (switched у подписчика `steer subscribe`),
#     status через клиент — новое устройство.
#  7. reload через клиент: сменился сервер обфускации — перезапущен только тот помощник.
#  8. SIGTERM демону: помощников и резолвера не остаётся; `steer down` (движком) снимает всё.
#  9. Без демона reload отвечает отказом с кодом 3; steer-tools отвечает только на инструменты.
# 10. Порядок при старте: первый проход сторожа — после стартового apply, и строк «разъехалась» при
#     штатном старте нет — ни при первом, ни при перезапуске после `steer down` (выбор устройств
#     остался в active, правил в ядре нет — проход до apply назвал бы это расхождением).
# 11. Страж правил: `ip rule del` нашего правила и `ip rule flush` (как netd при перезапуске) —
#     через ≤ 3 с правила снова на месте, подписчику repaired с перечнем выходов, на пачку — одна
#     починка; собственные apply (выход убран — его правило снято) и `steer down` repaired не
#     порождают.
# 12. Выключенный движок (шов STEER_CTL_ENABLED_FILE вместо свойства телефона): демон с --watch
#     --supervise за 20 с тишины переключается не больше одного раза (ни таймера сторожа, ни
#     снимка status, ни стража правил); reload после включения — проход сторожа сразу, дальше не
#     чаще периода; выключили и reload — снова тишина и ни одной пробы.
# 13. Сверка набора правил на проходе сторожа (recon.c, «СВЕРКА НА ПРОХОДЕ СТОРОЖА»; демон в своём
#     пространстве PID, период 3 с): проходы по здоровому ядру — ни одного процесса; снятое снаружи
#     правило канала возвращает проход сам, без apply, не позже периода (+ время починки), — в
#     журнале почему, подписчику applied с by: watch, элементы, которые клал резолвер, на месте;
#     таблица, заменённая мимо демона (`steerd apply` без сокета), — тоже возвращается; свои
#     замены набора (apply новой спеки, пока идут проходы) расхождением не считаются. Элементы
#     статических наборов проход не сверяет: снятую подсеть списка из доменного набора выхода
#     возвращает apply той же спеки.
#
# Нужны root, unshare, nsenter, nft, ip и python3; без них сетевая часть пропускается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# ---- 1. init.d: один экземпляр ---------------------------------------------------------------
# Скрипт читается как есть, без rc.common: функции procd подменены записью того, что им сказали.
if [ "${DAEMON_INNER:-}" != 1 ]; then
    it="$(mktemp -d)"
    cat > "$it/run.sh" <<EOF
procd_open_instance() { echo "instance \$1"; }
procd_set_param() { echo "param \$*"; }
procd_close_instance() { echo "close"; }
procd_open_trigger() { :; }
procd_close_trigger() { :; }
procd_add_config_trigger() { echo "trigger \$*"; }
. "$ROOT/files/etc/init.d/steer"
SPEC="$it/spec.json"
STEER="$it/steer"
STEERD="$it/steerd"
start() { echo "start" >> "$it/calls"; }
[ -n "\${NODAEMON:-}" ] && STEER="$it/steer3"
[ -n "\${REFUSED:-}" ] && STEER="$it/steer1"
[ -n "\${AUTOSTART_OFF:-}" ] && steer_autostart_off() { return 0; }
[ -n "\${AUTOSTART_ON:-}" ] && steer_autostart_off() { return 1; }
case "\$1" in
  start) start_service ;;
  triggers) service_triggers ;;
  reload) reload_service ;;
  reapply) reapply ;;
  reload_dnsd) reload_dnsd ;;
  reload_zapret) reload_zapret ;;
esac
EOF
    printf '#!/bin/sh\necho "steer $*" >> "%s/calls"\n' "$it" > "$it/steer"
    printf '#!/bin/sh\necho "steerd $*" >> "%s/calls"\n' "$it" > "$it/steerd"
    chmod +x "$it/steer" "$it/steerd"
    out="$(sh "$it/run.sh" start)"
    check "init.d: ровно один экземпляр" "1" "$(printf '%s\n' "$out" | grep -c '^instance ')"
    check "  это демон со сторожем, супервизором и применением при старте" \
        "param command $it/steerd daemon --watch --supervise --apply --spec $it/spec.json" \
        "$(printf '%s\n' "$out" | grep '^param command')"
    check "  с respawn" "1" "$(printf '%s\n' "$out" | grep -c '^param respawn')"
    check "  без спеки тоже поднимается (apply через сокет её и заведёт)" "no 1" \
        "$([ -f "$it/spec.json" ] && echo yes || echo no) $(printf '%s\n' "$out" | grep -c '^instance steerd$')"
    check "  start ничего не применяет сам" "" "$(cat "$it/calls" 2>/dev/null)"
    check "init.d: триггер сети — reapply" "trigger config.change network /etc/init.d/steer reapply" \
        "$(sh "$it/run.sh" triggers)"
    : > "$it/spec.json"
    for c in reload reapply reload_zapret; do
        : > "$it/calls"
        sh "$it/run.sh" "$c" >/dev/null 2>&1
        check "init.d: $c — запрос reload демону клиентом" "steer reload --spec $it/spec.json" \
            "$(head -n 1 "$it/calls")"
    done
    # Демона нет (код 3 клиента): служба включена и её поднимают — тревоги в stderr нет; выключена
    # и не поднимут — строка клиента в stderr. Отказ самого reload (код 1) виден всегда.
    printf '#!/bin/sh\necho "steer $*" >> "%s/calls"\necho "steer: reload: демон ядра не отвечает" >&2\nexit 3\n' "$it" > "$it/steer3"
    printf '#!/bin/sh\necho "steer: reload: спека не прошла проверку" >&2\nexit 1\n' > "$it/steer1"
    chmod +x "$it/steer3" "$it/steer1"
    # quiet РЕЖИМ КОМАНДА — «stderr-строк старт-вызовов»
    quiet() { : > "$it/calls"
        e="$(env $1 sh "$it/run.sh" "$2" 2>&1 >/dev/null)"
        echo "$(printf '%s' "$e" | grep -c .) $(grep -c '^start$' "$it/calls")"; }
    check "init.d без демона, служба включена: reload_dnsd поднимает её молча" "0 1" \
        "$(quiet "NODAEMON=1 AUTOSTART_ON=1" reload_dnsd)"
    check "  reload — тоже" "0 1" "$(quiet "NODAEMON=1 AUTOSTART_ON=1" reload)"
    check "  reload_zapret не поднимает и молчит" "0 0" "$(quiet "NODAEMON=1 AUTOSTART_ON=1" reload_zapret)"
    check "  reapply применяет движком и молчит" "0 steerd apply --spec $it/spec.json" \
        "$(: > "$it/calls"; e="$(NODAEMON=1 sh "$it/run.sh" reapply 2>&1 >/dev/null)"
           echo "$(printf '%s' "$e" | grep -c .) $(grep '^steerd' "$it/calls")")"
    check "init.d без демона, автозапуск снят: reload_dnsd не поднимает и говорит почему" "1 0" \
        "$(quiet "NODAEMON=1 AUTOSTART_OFF=1" reload_dnsd)"
    check "  reload_zapret — тоже говорит" "1 0" "$(quiet "NODAEMON=1 AUTOSTART_OFF=1" reload_zapret)"
    check "отказ reload демоном — в stderr всегда" "1 0" "$(quiet "REFUSED=1 AUTOSTART_ON=1" reload_dnsd)"
    rm -rf "$it"
fi

# ---- сетевая часть --------------------------------------------------------------------------
skip() { echo "daemonmatch: $1 — сетевая часть пропущена"; echo "daemonmatch: $pass passed, $fail failed"; [ "$fail" = 0 ]; exit $?; }
for t in nft ip python3 nsenter unshare; do
    command -v $t >/dev/null 2>&1 || skip "$t нет"
done
if [ "${DAEMON_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    DAEMON_INNER=1 STEER="$BIN" PASS0="$pass" FAIL0="$fail" exec unshare -n sh "$0" "$@"
fi
pass="${PASS0:-0}" fail="${FAIL0:-0}"
ip link set lo up
real_nft="$(command -v nft)"
"$real_nft" add table inet daemonmatch_probe 2>/dev/null || skip "nf_tables недоступен"
"$real_nft" delete table inet daemonmatch_probe
unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null || skip "свой /sys не смонтировать"

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/bin"
D="" DU="" SUB="" UP="" RPID=""
trap 'kill $SUB $UP $RPID 2>/dev/null; [ -n "$D" ] && kill $D 2>/dev/null; rm -rf "$tmp"' EXIT

# Ответчик: соседнее сетевое пространство, на lo — цели пробы сторожа (1.1.1.1, 8.8.8.8), к нему
# три пары veth. sw1/sw2 — пул выхода vpn, sw3 — устройство выхода o с обфускацией.
unshare -n sleep 600 & RPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
R ip link set lo up
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo
for k in 1 2 3; do
    ip link add sw$k type veth peer name sw${k}p
    ip link set sw${k}p netns "$RPID"
    R ip link set sw${k}p up; R ip addr add 10.9.$k.2/24 dev sw${k}p
    ip link set sw$k addrgenmode none 2>/dev/null
    ip link set sw$k up; ip addr add 10.9.$k.1/24 dev sw$k
done
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"
export PATH

cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
[ -n "\${STEER_EVENT_FD:-}" ] && eval "exec 9>&\$STEER_EVENT_FD" && printf '{"ev":"up"}\n' >&9
trap 'exit 0' TERM
while :; do sleep 0.2; done
H
chmod +x "$tmp/helper"

cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
print('-' if d is None else d)
PY
j() { python3 "$tmp/j.py" "$1"; }
# status без полей времени — то, что между двумя вызовами меняется само.
nostamp() { python3 -c 'import json,sys
d = json.loads(sys.stdin.read())
def strip(x):
    if isinstance(x, dict): return {k: strip(v) for k, v in x.items() if k not in ("at", "age", "ago", "cached")}
    if isinstance(x, list): return [strip(v) for v in x]
    return x
print(json.dumps(strip(d), sort_keys=True))'; }

UPORT=15575 LPORT=15511
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + b'\x20\x01\x0d\xb8' + b'\x00' * 12
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/qaaaa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x7a7a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
# Тип 65 (HTTPS): имя под правилом резолвер гасит в любом случае. AAAA годится сигналом только у
# спеки v1 — у спеки v2 на AAAA имени под правилом в выход с IPv6 резолвер отвечает адресом, а
# HTTPS не зависит от формата спеки.
q += b'\x00' + struct.pack('>HH', 65, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(struct.unpack('>H', d[6:8])[0])
except socket.timeout:
    print('timeout')
PY
python3 "$tmp/upstream.py" "$UPORT" & UP=$!

printf '10.1.0.0/16\n' > "$tmp/p1.lst"
printf '10.2.0.0/16\n' > "$tmp/p2.lst"
printf 'swap.test\n' > "$tmp/d1.lst"
# spec СЕРВЕР_O [ВТОРОЙ_КАНАЛ]
spec() {
    {
        printf 'version: 2\nlan: { addr: [192.168.1.0/24] }\nlists:\n  p: { prefixes_file: %s/p1.lst }\n' "$tmp"
        printf '  d: { domains_file: %s/d1.lst }\n' "$tmp"
        [ -n "${2:-}" ] && printf '  q: { prefixes_file: %s/p2.lst }\n'  "$tmp"
        printf 'outputs:\n  vpn: { kind: group, pick: order, members: [vpn.sw1, vpn.sw2] }\n'
        printf '  o: { kind: interface, device: sw3, obfs: { server: %s, listen: 127.0.0.1:5101 } }\n' "$1"
        printf '  vpn.sw1: { kind: interface, device: sw1 }\n  vpn.sw2: { kind: interface, device: sw2 }\n'
        printf 'rules:\n  - { name: p, to: p, out: vpn }\n  - { name: d, to: d, out: o }\n'
        [ -n "${2:-}" ] && printf '  - { name: q, to: q, out: vpn }\n'
        return 0
    } > "$tmp/spec.yaml"
}
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
STEER_SOCKET="$tmp/steer.sock"
export STEER_SOCKET
c() { "$BIN" "$@" $S; }                                  # клиент к демону стенда
# Движок без демона — в своём /sys, как демон: иначе /sys/class/net показывал бы устройства хоста.
local_status() { STEER_SOCKET="$tmp/nobody.sock" unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" status $S"; }
runs() { grep -c "^obfs $1 " "$tmp/log" 2>/dev/null; }
pid_of() { grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3; }
dev() { c status | j outputs.vpn.device; }

spec 10.99.0.3:4443
# Демон — через клиент: `steer daemon` клиент отдаёт движку execv'ом, и pid тот же.
STEER_SUPERVISE_EXE="$tmp/helper" unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" \
    daemon --watch --supervise --apply --socket \"$tmp/steer.sock\" $S \
    --dnsd-flag --listen-port --dnsd-flag $LPORT --dnsd-flag --upstream-port --dnsd-flag $UPORT" \
    >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/steer.sock" ] && grep -q "спека применена при старте" "$tmp/d.err"' 10
check "демон при старте применил спеку сам (--apply)" "1" "$(grep -c 'спека применена при старте' "$tmp/d.err")"
check "  набор правил в ядре" "0" "$("$real_nft" list table inet steer >/dev/null 2>&1; echo $?)"
check "  демон — это steerd (клиент отдал ему себя execv'ом)" "steerd" \
    "$(basename "$(readlink "/proc/$D/exe" 2>/dev/null)")"
# Строка номер N журнала, где впервые встретилось слово (0 — нет).
line_of() { grep -n "$1" "$2" | head -n 1 | cut -d: -f1 | grep . || echo 0; }
order_ok() {
    a=$(line_of 'спека применена при старте' "$1") w=$(line_of 'watch: первый проход' "$1")
    [ "$a" -gt 0 ] && [ "$w" -gt "$a" ] && echo ok || echo "apply:$a pass:$w"
}
wait_for 'grep -q "watch: первый проход" "$tmp/d.err"' 5
check "старт: первый проход сторожа — после стартового apply" "ok" "$(order_ok "$tmp/d.err")"

"$BIN" subscribe $S > "$tmp/sub.out" 2>&1 &
SUB=$!
wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out" 2>/dev/null' 5
check "steer subscribe — поток событий демона" "0" "$(head -n 1 "$tmp/sub.out" | j code)"

wait_for '[ "$(runs o)" = 1 ]' 5
check "помощник-заглушка поднят демоном" "1" "$(runs o)"
DN="$(grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | grep -o '[0-9]*$')"
check "  резолвер — ребёнок демона, argv[0] прежний (…/steer dnsd)" "1" \
    "$(tr '\0' ' ' < "/proc/$DN/cmdline" 2>/dev/null | grep -c '/steer dnsd --table-fd ')"
wait_for '[ "$(python3 "$tmp/qaaaa.py" "$LPORT" other.test)" = 1 ]' 5
check "резолвер отвечает: канал swap.test — из таблицы, чужое имя — наверх" "0 1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT" swap.test) $(python3 "$tmp/qaaaa.py" "$LPORT" other.test)"

wait_for 'grep -q "^vpn sw1 0$" "$tmp/st/active" 2>/dev/null' 10
check "сторож: выход на первом устройстве пула" "sw1" "$(dev)"

# status: к демону (движок подменён отказом — ответ мог дать только демон) и движком без демона.
r1="$(STEER_ENGINE=/bin/false "$BIN" status $S)"; rc1=$?
check "status через клиент — ответ демона (движок не запускался)" "0" "$rc1"
r2="$(local_status)"
check "  тот же ответ, что у движка без демона (прежний формат)" \
    "$(printf '%s' "$r2" | nostamp)" "$(printf '%s' "$r1" | nostamp)"
check "  explain через демон — тот же вывод" "$(STEER_SOCKET=/nonexistent "$BIN" explain 10.1.2.3 $S)" \
    "$(STEER_ENGINE=/bin/false "$BIN" explain 10.1.2.3 $S)"
cp "$tmp/spec.yaml" "$tmp/other.yaml"
STEER_ENGINE=/bin/false "$BIN" status --spec "$tmp/other.yaml" --state-dir "$tmp/st" >/dev/null 2>&1
check "  чужая спека — движку, не демону" "1" "$?"
STEER_ENGINE=/bin/false "$BIN" status --spec "$tmp/spec.yaml" >/dev/null 2>&1
check "  чужой каталог состояния — движку" "1" "$?"

# apply через клиент: новый канал — через демон (сверка), вывод и код подкоманды.
spec 10.99.0.3:4443 q
out="$(STEER_ENGINE=/bin/false "$BIN" apply $S 2>"$tmp/a.err")"; rc=$?
check "apply через клиент: код 0, вывод подкоманды" "0 steer: applied 3 channel(s), 4 output(s)" "$rc $out"
check "  применил демон" "1" "$(grep -c 'ctl: спека применена$' "$tmp/d.err")"
# Соседние подсети в наборе склеены в интервал: 10.1.0.0/16 и 10.2.0.0/16 — 10.1.0.0-10.2.255.255.
check "  подсеть нового канала — в наборе выхода в ядре" "1" \
    "$("$real_nft" list set inet steer vpn_ip 2>/dev/null | grep -c '10\.2\.255\.255')"
check "  помощник не тронут" "1" "$(runs o)"
check "  подписчику — applied" "1" "$(grep -c '"ev":"applied","by":"apply"' "$tmp/sub.out")"
bad="$(STEER_ENGINE=/bin/false "$BIN" apply --dry-run $S 2>&1 >/dev/null)"; rc=$?
check "apply --dry-run — движку (компилятор), не демону" "1" "$rc"

# Падение устройства — сторож переключает выход.
ip link set sw1 down
wait_for 'grep "\"ev\":\"switched\"" "$tmp/sub.out" | grep -q "\"why\":\"down\""' 15
check "устройство упало — switched у подписчика" \
    '{"v":1,"ev":"switched","out":"vpn","from":"sw1","to":"sw2","why":"down","member":"vpn.sw2"}' \
    "$(grep '"ev":"switched"' "$tmp/sub.out" | grep '"why":"down"')"
check "  status через клиент — новое устройство" "sw2" "$(dev)"

# reload через клиент: сменился сервер обфускации o — перезапущен только его помощник.
po="$(pid_of o)"
out="$(STEER_ENGINE=/bin/false "$BIN" reload $S 2>&1)"; rc=$?
check "reload без изменений: код 0, вывода нет" "0 " "$rc $out"
check "  помощник тот же" "$po" "$(pid_of o)"
spec 10.99.0.4:4443 q
out="$(STEER_ENGINE=/bin/false "$BIN" reload $S 2>&1)"; rc=$?
check "reload со сменой сервера обфускации: код 0" "0 " "$rc $out"
wait_for '[ "$(runs o)" = 2 ]' 5
check "  помощник o перезапущен" "2" "$(runs o)"

# ---- страж правил ----
# Проход сторожа после reload (через 5 с) — пусть кончится: он и сам возвращает недостающее
# правило, и стенд тогда не отличил бы починку стража от его прохода.
sleep 6
# Наши правила: метка с маской движка. ours — сколько их; rule_of ВЫХОД — «метка/маска» его правила
# (таблица в выводе ip может быть и именем из rt_tables.d хоста — метка из реестра надёжнее).
ours() { ip rule show | grep -c 'fwmark .*/'; }
rule_of() { m=$(awk -v o="$1" '$1 == o { print $2 }' "$tmp/st/registry"); ip rule show | grep -o "fwmark 0x$m/[^ ]*" | head -n 1 | cut -d' ' -f2; }
reps() { grep -c '"ev":"repaired"' "$tmp/sub.out"; }
tvpn=$(awk '$1 == "vpn" { print $3 }' "$tmp/st/registry")
n0=$(ours)
check "страж правил: у выходов vpn, o и членов группы vpn по правилу" "4" "$n0"
ip rule del fwmark "$(rule_of vpn)" table "$tvpn"
check "  ip rule del — правила vpn нет" "3" "$(ours)"
t0=$(date +%s%N)
wait_for '[ "$(ours)" = "$n0" ]' 5
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "  через ≤ 3 с правило на месте" "yes" "$([ "$(ours)" = "$n0" ] && [ $ms -le 3000 ] && echo yes || echo "no:$ms ms, $(ours)")"
wait_for '[ "$(reps)" = 1 ]' 3
check "  подписчику repaired с перечнем" '{"v":1,"ev":"repaired","outputs":["vpn"],"masq":false}' \
    "$(grep '"ev":"repaired"' "$tmp/sub.out")"
check "  в журнале демона — строка о починке" "1" "$(grep -c 'сняты снаружи — возвращены: vpn' "$tmp/d.err")"
# Как netd при (пере)запуске: все правила, кроме приоритета 0. Свои (main, default) netd ставит
# сам — здесь их возвращает стенд.
ip rule flush
ip rule add priority 32766 table main; ip rule add priority 32767 table default
check "  ip rule flush — наших правил нет" "0" "$(ours)"
t0=$(date +%s%N)
wait_for '[ "$(ours)" = "$n0" ]' 5
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "  через ≤ 3 с оба на месте" "yes" "$([ "$(ours)" = "$n0" ] && [ $ms -le 3000 ] && echo yes || echo "no:$ms ms, $(ours)")"
wait_for '[ "$(reps)" = 2 ]' 3
sleep 2
check "  на пачку — одна починка, с обоими выходами" '{"v":1,"ev":"repaired","outputs":["vpn","o","vpn.sw1","vpn.sw2"],"masq":false}' \
    "$(grep '"ev":"repaired"' "$tmp/sub.out" | tail -n +2)"
check "  таблица vpn не перепривязана (устройство то же)" "sw2" "$(dev)"
# Свой apply: выход o убран — его правило и таблицу снимает сверка (--drop). Не починка.
cp "$tmp/spec.yaml" "$tmp/spec-o.yaml"
sed -i '/^  o: /d; /^  d: /d; /name: d,/d' "$tmp/spec.yaml"
out="$(STEER_ENGINE=/bin/false "$BIN" apply $S 2>&1)"; rc=$?
check "свой apply (выход o убран): код 0, правило o снято" "0 3" "$rc $(ours)"
sleep 3
check "  repaired не пришло" "2" "$(reps)"
cp "$tmp/spec-o.yaml" "$tmp/spec.yaml"
STEER_ENGINE=/bin/false "$BIN" apply $S >/dev/null 2>&1
check "  выход o вернули apply — правило снова стоит" "4" "$(ours)"
sleep 6   # проход сторожа после apply (выходы изменились) — до steer down, а не посреди него

# Строки «разъехалась» до steer down — их быть не должно (проверка у перезапуска ниже); после down
# проход сторожа возвращает снятое сам (ctl.c, srv_table_flushed), и они законны.
raz0="$(grep -c 'разъехал' "$tmp/d.err")"
# steer down движком при живом демоне (так снимает правила init): таблиц и правил нет — не починка.
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1
check "steer down при живом демоне: наших правил нет" "0" "$(ours)"
sleep 3
# Правила вернёт ближайший проход сторожа (так задумано: ручной down при живом демоне — не
# остановка службы), и когда — зависит от его срока; здесь проверяется только, что это не починка.
check "  repaired не пришло" "2" "$(reps)"

# SIGTERM: демон гасит помощников и резолвер; правила остаются до steer down.
kill $SUB 2>/dev/null; wait $SUB 2>/dev/null; SUB=""
kill "$D"
wait $D 2>/dev/null
D=""
po="$(pid_of o)"
check "SIGTERM: помощника нет" "no" "$(kill -0 "$po" 2>/dev/null && echo yes || echo no)"
check "  резолвера нет" "no" "$(kill -0 "$DN" 2>/dev/null && echo yes || echo no)"
check "  сокет убран" "no" "$([ -S "$tmp/steer.sock" ] && echo yes || echo no)"
out="$("$BIN" reload $S 2>&1)"; rc=$?
check "без демона reload — отказ с кодом 3 (демона нет)" "3" "$rc"
r3="$("$BIN" status $S)"; rc=$?
check "без демона status — движком, тот же формат" "0 $(printf '%s' "$r2" | nostamp | python3 -c 'import json,sys; print(sorted(json.loads(sys.stdin.read()).keys()))')" \
    "$rc $(printf '%s' "$r3" | nostamp | python3 -c 'import json,sys; print(sorted(json.loads(sys.stdin.read()).keys()))')"
"$BIN" down --state-dir "$tmp/st"
check "steer down: таблиц движка нет" "1" "$("$real_nft" list table inet steer >/dev/null 2>&1; echo $?)"
check "  правил выходов нет" "0" "$(ip rule show | grep -c 'fwmark')"

# Перезапуск после steer down: выбор устройств остался в active, правил в ядре нет. Первый проход
# — после стартового apply, и «разъехалась» он не говорит.
check "старт: при первом запуске строк «разъехалась» нет" "0" "$raz0"
check "  в active остался выбор прежнего демона" "1" "$(grep -c '^vpn sw' "$tmp/st/active")"
STEER_SUPERVISE_EXE="$tmp/helper" unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" \
    daemon --watch --supervise --apply --socket \"$tmp/steer.sock\" $S \
    --dnsd-flag --listen-port --dnsd-flag $LPORT --dnsd-flag --upstream-port --dnsd-flag $UPORT" \
    >"$tmp/d2.out" 2>"$tmp/d2.err" &
D=$!
wait_for 'grep -q "watch: первый проход" "$tmp/d2.err"' 10
sleep 1
check "перезапуск: первый проход — после стартового apply" "ok" "$(order_ok "$tmp/d2.err")"
check "  строк «разъехалась» нет" "0" "$(grep -c 'разъехал' "$tmp/d2.err")"
kill "$D"; wait $D 2>/dev/null; D=""
"$BIN" down --state-dir "$tmp/st" >/dev/null 2>&1

# steer-tools: ссылка на steerd, роль по argv[0].
ln -s "$(dirname "$BIN")/steerd" "$tmp/steer-tools"
"$tmp/steer-tools" status $S >/dev/null 2>&1
check "steer-tools: команда движка — отказ" "2" "$?"
check "steer-tools fit — инструмент работает" "10.0.0.0/23" \
    "$(printf '10.0.0.0/24\n10.0.1.0/24\n' | "$tmp/steer-tools" fit 2>/dev/null)"

# ---- status и diag без процессов; выход в отказе ----
# Демон со сторожем, супервизором (резолвер — его ребёнок) и чужим фаерволом в ядре — в своём
# пространстве PID: номера процессов там идут подряд, и по ним видно, запускал ли он кого-нибудь,
# пока отвечал на status и diag. Раньше status стоил двух `sh -c nft …` (≈7 процессов), diag —
# ребёнка `steerd diag` и ещё около двадцати (nft, pgrep, ip, пробы `nft -c`).
mkdir -p "$tmp/st4"
ip link set sw1 up
cat > "$tmp/spec4.yaml" <<EOF
version: 2
lan: { addr: [192.168.1.0/24] }
lists:
  p: { prefixes_file: $tmp/p1.lst }
  d: { domains_file: $tmp/d1.lst }
outputs:
  vpn: { kind: interface, device: sw1, on_fail: drop }
rules:
  - { name: p, to: p, out: vpn }
  - { name: d, to: d, out: vpn }
EOF
"$real_nft" add table inet fw4
"$real_nft" add chain inet fw4 srcnat '{ type nat hook postrouting priority srcnat; policy accept; }'
"$real_nft" add chain inet fw4 srcnat_vpn
"$real_nft" add rule inet fw4 srcnat oifname '"sw1"' jump srcnat_vpn
"$real_nft" add rule inet fw4 srcnat_vpn meta nfproto ipv4 masquerade
S4="--spec $tmp/spec4.yaml --state-dir $tmp/st4"
STEER_SUPERVISE_EXE="$tmp/helper" unshare -m -p -f sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" \
    daemon --watch --watch-period 3 --supervise --apply --socket \"$tmp/s4.sock\" $S4 \
    --dnsd-flag --listen-port --dnsd-flag $LPORT --dnsd-flag --upstream-port --dnsd-flag $UPORT" \
    >"$tmp/d4.out" 2>"$tmp/d4.err" &
DU=$!
wait_for '[ -S "$tmp/s4.sock" ] && grep -q "watch: первый проход" "$tmp/d4.err" && grep -q "supervise: dnsd запущен" "$tmp/d4.err"' 10
D="$(cat "/proc/$DU/task/$DU/children" 2>/dev/null | tr -d ' ')"
[ -n "$D" ] || D="$(pgrep -P "$DU" | head -n 1)"
c4() { STEER_SOCKET="$tmp/s4.sock" STEER_ENGINE=/bin/false "$BIN" "$@" $S4; }
nspid() { nsenter -t "$D" -p sh -c 'echo $$'; }
wait_for 'grep -q "^vpn sw1 0$" "$tmp/st4/active" 2>/dev/null' 10
sleep 1
p0=$(nspid)
i=0
while [ $i -lt 10 ]; do c4 status >/dev/null 2>&1; i=$((i + 1)); done
c4 diag > "$tmp/diag4.d" 2>/dev/null
p1=$(nspid)
check "демон: 10 status и diag — ни одного процесса (новых PID в его пространстве, кроме своих)" "0" \
    "$((p1 - p0 - 1))"
check "  status демона видит чужой фаервол: sw1 в зоне, masquerade есть" "True True" \
    "$(c4 status | j outputs.vpn.in_firewall) $(c4 status | j outputs.vpn.nat)"
check "  и счётчик канала — из ядра (правило канала на месте)" "True" \
    "$(c4 status | python3 -c 'import json,sys; print(all(c["live"] for c in json.loads(sys.stdin.read())["channels"]))')"
local4() { STEER_SOCKET="$tmp/nobody.sock" unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" $1 $S4"; }
check "  diag демона — тот же, что у движка без демона" "$(local4 diag 2>/dev/null)" "$(cat "$tmp/diag4.d")"
check "  status демона — тот же, что у движка без демона" \
    "$(local4 status 2>/dev/null | nostamp)" "$(c4 status | nostamp)"
check "  резолвер жив (обход /proc), таблица на месте" "ok ok" \
    "$(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
v = {c["id"]: c["verdict"] for c in d["checks"]}
print(v.get("dnsd"), v.get("table"))' "$tmp/diag4.d")"

# ---- сверка набора правил на проходе сторожа ----
# Перед каждым проходом демон сверяет номер и отпечаток своей таблицы с ядром — netlink в его
# процессе. Проходы по здоровому ядру не запускают никого: PID в пространстве демона те же, а
# эхо-пробы сторожа у ответчика показывают, что проходы за это время были.
echos() { R awk '/^Icmp:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "InEchos") c = i; h = 1 } else print $c }' /proc/net/snmp; }
p0=$(nspid); e0=$(echos)
sleep 7
p1=$(nspid); e1=$(echos)
check "сверка на проходе: за 7 с (период 3) проходы были, новых процессов нет" "yes 0" \
    "$([ $((e1 - e0)) -ge 2 ] && echo yes || echo "no:$((e1 - e0))") $((p1 - p0 - 1))"
check "  расхождений на здоровом ядре нет" "0" "$(grep -c 'разошёлся с поставленным' "$tmp/d4.err")"
c4 subscribe > "$tmp/sub4.out" 2>&1 &
SUB=$!
wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub4.out" 2>/dev/null' 5
# Правило канала по комментарию, в какой бы цепочке оно ни стояло: «цепочка номер» первого;
# chan_n — сколько их (у канала их два: IPv4 и IPv6).
chan_rule() { "$real_nft" -a list table inet steer 2>/dev/null |
    awk '/^\tchain /{ c = $2 } /comment "steer:vpn_dom"/ { sub(/.*# handle /, ""); print c, $1; exit }'; }
chan_n() { "$real_nft" list table inet steer 2>/dev/null | grep -c 'comment "steer:vpn_dom"'; }
drift4() { grep -c "проход сторожа: набор правил в ядре разошёлся с поставленным ($1)" "$tmp/d4.err"; }
fixed4() { grep -c 'набор правил сверен с ядром проходом сторожа — поставлен заново' "$tmp/d4.err"; }
handle4() { "$real_nft" -a list table inet steer 2>/dev/null | sed -n '1s/.*# handle \([0-9]*\).*/\1/p'; }
cn="$(chan_n)"
cr="$(chan_rule)"
"$real_nft" delete rule inet steer "${cr% *}" handle "${cr#* }"
check "  правило канала снято снаружи" "$((cn - 1))" "$(chan_n)"
t0=$(date +%s%N)
wait_for '[ "$(chan_n)" = "$cn" ]' 10
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
# Не позже периода прохода (3 с) — плюс сама починка: план и nft -f ребёнком.
check "снятое правило канала: проход сторожа вернул его сам, без apply, ≤ периода + 2 с" "yes" \
    "$([ "$(chan_n)" = "$cn" ] && [ $ms -le 5000 ] && echo yes || echo "no:$ms ms")"
wait_for '[ "$(fixed4)" = 1 ]' 3
check "  в журнале — почему, одной строкой; и итог починки" "1 1" \
    "$(drift4 'цепочки, правила или наборы не те, что ставило ядро steer') $(fixed4)"
wait_for 'grep -q "\"by\":\"watch\"" "$tmp/sub4.out"' 3
check "  подписчику — applied с by: watch, набор правил поставлен" "1" \
    "$(grep '"ev":"applied","by":"watch"' "$tmp/sub4.out" | grep -c '"ruleset":true')"
# Таблицу заменили мимо демона — движком без сокета (как `steerd apply` из скрипта): номер другой.
H0="$(handle4)"
local4 apply >/dev/null 2>&1
H1="$(handle4)"
check "таблица заменена мимо демона: номер другой" "yes" \
    "$([ -n "$H1" ] && [ "$H1" != "$H0" ] && echo yes || echo no)"
wait_for '[ "$(fixed4)" = 2 ]' 10
check "  проход ставит набор правил демона заново" "1 2 yes" \
    "$(drift4 'таблицу ядра steer заменили мимо демона') $(fixed4) \
$([ "$(handle4)" != "$H1" ] && echo yes || echo no)"
# Свои замены набора правил — не расхождение: apply новой спеки (канал прибавился и убавился)
# шесть раз подряд, пока идут проходы по периоду 3 с.
cp "$tmp/spec4.yaml" "$tmp/spec4.bak"
sed -e "/^lists:/a\\  q: { prefixes_file: $tmp/p2.lst }" "$tmp/spec4.yaml" > "$tmp/spec4.yaml.q"
echo '  - { name: q, to: q, out: vpn }' >> "$tmp/spec4.yaml.q"
n0=$(grep -c 'разошёлся с поставленным' "$tmp/d4.err")
i=0 ok=0
while [ $i -lt 6 ]; do
    if [ $((i % 2)) = 0 ]; then cp "$tmp/spec4.yaml.q" "$tmp/spec4.yaml"; else cp "$tmp/spec4.bak" "$tmp/spec4.yaml"; fi
    c4 apply >/dev/null 2>&1 && ok=$((ok + 1))
    sleep 1.3
    i=$((i + 1))
done
sleep 4
check "свои замены набора правил (6 apply, пока идут проходы): не расхождение" "6 $n0 2" \
    "$ok $(grep -c 'разошёлся с поставленным' "$tmp/d4.err") $(fixed4)"
# Элементы статических наборов проход не сверяет (дорого) — их сверяет apply. У выхода vpn и
# адресный, и доменный канал: подсеть списка генератор кладёт в доменный набор vpn_dom, рядом с
# элементами резолвера.
in_dom() { "$real_nft" list set inet steer vpn_dom 2>/dev/null | grep -c '10\.1\.0\.0/16'; }
"$real_nft" delete element inet steer vpn_dom "{ 10.1.0.0/16 }"
sleep 4
check "подсеть списка в доменном наборе снята: проход её не сверяет" "0 2" "$(in_dom) $(fixed4)"
c4 apply >/dev/null 2>&1
check "  apply той же спеки возвращает её, в журнале почему" "1 1" \
    "$(in_dom) $(grep -c 'элементы статических наборов в ядре не те' "$tmp/d4.err")"
# `/etc/init.d/firewall stop` — это `fw4 flush`: он снимает ВСЕ таблицы nftables, и наши тоже,
# а `firewall start` ставит только fw4 (steer#4). Правила выходов при этом стоят — это не
# `steer down`, и проход сторожа обязан вернуть таблицу сам, не позже периода + починка.
"$real_nft" list tables | while read -r _ fam tab; do "$real_nft" delete table "$fam" "$tab"; done
"$real_nft" add table inet fw4
check "fw4 flush: таблицы движка нет, правило выхода стоит" "0 yes" \
    "$("$real_nft" list tables | grep -c 'inet steer$') $([ "$(ip rule | grep -c fwmark)" -ge 1 ] && echo yes || echo no)"
t0=$(date +%s%N)
wait_for '[ "$(chan_n)" = "$cn" ]' 10
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
# Срок — два периода и секунда: снятие приходится на случайное место периода (до 3 с до прохода),
# а сама починка — полная замена набора правил. Без возврата таблица не появляется вовсе.
check "  проход сторожа вернул таблицу движка сам, ≤ 2 периодов + 1 с" "yes" \
    "$([ "$(chan_n)" = "$cn" ] && [ $ms -le 7000 ] && echo yes || echo "no:$ms ms")"
check "  в журнале — почему" "1" \
    "$(drift4 'таблицы ядра steer нет в ядре Linux, а правила выходов стоят — её снял кто-то другой')"
kill $SUB 2>/dev/null; wait $SUB 2>/dev/null; SUB=""

# Выход в отказе: устройство поднято (operstate up), но трафик не несёт — адреса у него нет, и
# проба отвечает «нет» сразу (молчащий адресат стоил бы шесть секунд на каждый из десяти шагов
# ожидания подъёма). Сторож ставит on_fail=drop. До правки status отдавал здесь `up: true`, и
# интерфейс рисовал живым выход, чей трафик стоит.
ip addr flush dev sw1
wait_for 'grep -q "^vpn - " "$tmp/st4/active" 2>/dev/null' 40
check "отказ: сторож поставил on_fail (запись «-»)" "1" "$(grep -c '^vpn - ' "$tmp/st4/active")"
check "  устройство при этом поднято" "1" "$(ip -o link show sw1 | grep -c 'state UP')"
check "  status: устройство то же, up false, failed true" "sw1 False True" \
    "$(c4 status | j outputs.vpn.device) $(c4 status | j outputs.vpn.up) $(c4 status | j outputs.vpn.failed)"
check "  diag: выход — fail, трафик канала остановлен" "1" \
    "$(c4 diag 2>/dev/null | grep -c '"verdict":"fail","what":"выход vpn: sw1 не отвечает, трафик канала остановлен"')"
ip addr add 10.9.1.1/24 dev sw1
wait_for 'grep -q "^vpn sw1 " "$tmp/st4/active" 2>/dev/null' 20
check "  адрес вернули, проба ответила — failed снят, up true" "- True" \
    "$(c4 status | j outputs.vpn.failed) $(c4 status | j outputs.vpn.up)"
kill "$D"; wait "$DU" 2>/dev/null; D=""
"$BIN" down --state-dir "$tmp/st4" >/dev/null 2>&1
"$real_nft" delete table inet fw4

# ---- выключенный движок: ноль пробуждений ----
# Свой выход на sw1 и своё состояние; выключатель — файл (шов стенда вместо свойства телефона).
mkdir -p "$tmp/st3"
cat > "$tmp/spec3.yaml" <<EOF
version: 2
lists:
  p: { prefixes_file: $tmp/p1.lst }
outputs:
  vpn: { kind: interface, device: sw1, on_fail: drop }
rules:
  - { name: p, to: p, out: vpn }
EOF
ip link set sw1 up
S3="--spec $tmp/spec3.yaml --state-dir $tmp/st3"
echo 0 > "$tmp/enabled"
csw() { awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$D/status"; }
c3() { "$BIN" ctl --socket "$tmp/s3.sock" "$@"; }
STEER_CTL_ENABLED_FILE="$tmp/enabled" unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" \
    daemon --watch --watch-period 3 --supervise --apply --socket \"$tmp/s3.sock\" $S3 \
    --dnsd-flag --listen-port --dnsd-flag $LPORT --dnsd-flag --upstream-port --dnsd-flag $UPORT" \
    >"$tmp/d3.out" 2>"$tmp/d3.err" &
D=$!
wait_for '[ -S "$tmp/s3.sock" ]' 5
sleep 1
cs0=$(csw); e0=$(echos)
sleep 20
cs1=$(csw); e1=$(echos)
check "выключенный движок: за 20 с тишины демон переключается не больше раза" "ok" \
    "$([ $((cs1 - cs0)) -le 1 ] && echo ok || echo "$((cs1 - cs0))")"
check "  проб нет, проходов нет, правил нет" "0 0 0" \
    "$((e1 - e0)) $(grep -c 'watch: первый проход' "$tmp/d3.err") $(ip rule show | grep -c fwmark)"
check "  детей у демона нет (резолвер не поднят)" "" "$(cat "/proc/$D/task/$D/children" 2>/dev/null | tr -d ' ')"
echo 1 > "$tmp/enabled"
r="$(c3 reload)"
check "включили и reload: код 0, движок включён" "0 True" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j enabled)"
wait_for 'grep -q "^vpn sw1 0$" "$tmp/st3/active" 2>/dev/null' 5
check "  проход сторожа сразу после reload" "1" "$(grep -c 'watch: первый проход' "$tmp/d3.err")"
sleep 1
e0=$(echos)
sleep 10
e1=$(echos)
n=$((e1 - e0))
check "  дальше проходы не чаще периода (эхо-проб за 10 с при периоде 3)" "ok" \
    "$([ "$n" -ge 2 ] && [ "$n" -le 4 ] && echo ok || echo "n=$n")"
echo 0 > "$tmp/enabled"
"$BIN" down --state-dir "$tmp/st3" >/dev/null 2>&1
r="$(c3 reload)"
check "выключили и reload: движок выключен" "False" "$(printf '%s' "$r" | j enabled)"
sleep 1
cs0=$(csw); e0=$(echos)
sleep 10
cs1=$(csw); e1=$(echos)
check "  снова тишина: переключений не больше одного, проб нет" "ok 0" \
    "$([ $((cs1 - cs0)) -le 1 ] && echo ok || echo "$((cs1 - cs0))") $((e1 - e0))"
check "  выключение не порождает починку правил" "0" "$(grep -c 'сняты снаружи' "$tmp/d3.err")"
kill "$D"; wait $D 2>/dev/null; D=""

echo "daemonmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
