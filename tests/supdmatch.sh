#!/bin/sh
# steer daemon --supervise: помощники выходов и резолвер — дети демона (src/daemon/supd.c).
#
# Помощники не настоящие: шов STEER_SUPERVISE_EXE (тот же, что у tests/supervisematch.sh)
# подставляет скрипт, который записывает «команда выход pid», по файлу go пишет в трубу
# STEER_EVENT_FD события (up, у выхода a ещё node), по файлу crash.<выход> — down и выходит с
# кодом 3, а по SIGTERM записывает «stop выход» и гаснет через полсекунды. Резолвер настоящий:
# `steer dnsd --table-fd`, поднятый демоном, с апстримом-заглушкой на петле.
#
# Что проверяется: помощники поднимаются в порядке via (цель раньше того, кто через неё идёт);
# каждый получает свою трубу событий; up, node и down из трубы приходят подписчику как helper-up,
# node и helper-down; помощник, убитый молча после up, — тоже helper-down с причиной; упавший
# перезапускается через 5 с, а упавший снова сразу — через 10; reload со сменой параметров одного
# выхода перезапускает только его, без смены — никого; резолвер поднят на таблице от демона и
# после смены спеки (reload) ведёт себя по новой таблице тем же процессом; SIGTERM демону гасит
# помощников по одному в обратном порядке подъёма и резолвер — детей после демона не остаётся;
# резолвер переживает kill -9 демона, а `steerd down` после него (stop в окне до respawn) гасит его
# сразу, при живом же демоне не трогает. Строки резолвера, оставшегося без читателя stderr (труба
# журнала закрыта), приходят в syslog — в приёмник стенда вместо /dev/log (шов STEER_SYSLOG_SOCK) —
# с заголовком syslog(3): уровень по началу строки, метка времени, тег steer[pid], текст целиком, и
# разбирается этот заголовок по правилам logd OpenWrt и journald; забравший резолвер демон получает
# строки снова в свой stderr; последняя строка перед выходом (срок ожидания, `steerd down`) доходит.
#
# Сторож и супервизор вместе (--watch --supervise; root, своё сетевое пространство и свой /sys,
# демон build/steer-xk — базовая сборка с видами vless и xsteer): здоровье выходов xsteer сторож
# берёт из событий помощников — помощник пишет down, и выход-пул переключается на следующее
# устройство (switched у подписчика), пишет up — возвращается, и всё это без файлов probe-* и
# xsteer-*.json в каталоге состояния; клиент vless, следящий за узлом сам (up с watch), — приговор
# без пробы TCP (через его устройство-заглушку она бы не прошла), его down переключает выход-пул
# внеочередным проходом (период сторожа — 600 с), status показывает node_down с причиной, diag —
# «узел перестал отвечать», а up возвращает пул; ход перебора узлов vless status берёт из памяти демона;
# оживление обфускатора — перезапуск помощника демоном (helper-down с причиной, helper-up), ubus
# не зовётся.
#
# Под root стенд уходит в своё сетевое пространство (unshare -n); без root — петля хоста и
# высокие порты. Без python3 — пропуск (заглушка апстрима и запросы DNS).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "supdmatch: python3 нет — пропускаю"; exit 0; }
if [ "${SUPD_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    SUPD_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
[ "${SUPD_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

tmp="$(mktemp -d)"
# Помощника obfs выходу interface даёт плагин obfs (вид interface, helper.when obfs): каталог плагинов стенда.
sh tests/plugroot.sh "$tmp/plugins" "$(dirname "$BIN")" || { echo "supdmatch: каталог плагинов не собран"; exit 2; }
STEER_PLUGINS_ROOT="$tmp/plugins"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC
mkdir -p "$tmp/st"
D="" SUB="" UP="" WD="" DN5="" Q5="" SL="" CAT="" DO6=""
trap 'kill $D $SUB $UP $WD $DN5 $Q5 $SL $CAT $DO6 2>/dev/null; rm -rf "$tmp"' EXIT
# Резолвер без читателя stderr пишет в syslog (src/dnsd/adopt.c, stderr_rescue) — у стенда это
# свой приёмник, а не /dev/log машины: в системный журнал стенд не пишет ни строки. Шов — на весь
# стенд, чтобы ни один резолвер отсюда, даже там, где проверка его не ждёт, до /dev/log не дошёл
# (приёмника нет — резолвер пишет в /dev/null).
export STEER_SYSLOG_SOCK="$tmp/log.sock"
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

cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$ \${STEER_EVENT_FD:--}" >> "$tmp/log"
[ -n "\${STEER_EVENT_FD:-}" ] && eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; sleep 0.5; exit 0' TERM
while [ ! -e "$tmp/go" ]; do sleep 0.1; done
printf '{"ev":"up"}\n' >&9
[ "\$2" = a ] && printf '{"ev":"node","n":2,"total":5}\n' >&9
while :; do
    if [ -e "$tmp/crash.\$2" ]; then
        rm -f "$tmp/crash.\$2"
        printf '{"ev":"down","why":"стенд: отказ"}\n' >&9
        exit 3
    fi
    if [ -e "$tmp/active.\$2" ]; then
        rm -f "$tmp/active.\$2"
        # Тысяча узлов — событие в ~3,9 КиБ: прежний предел был 160 символов списка и 480 байт на запись.
        printf '{"ev":"active","nodes":"%s"}\n' "\$(seq -s, 1 1000)" >&9
    fi
    if [ -e "$tmp/health.\$2" ]; then
        rm -f "$tmp/health.\$2"
        printf '{"ev":"health","dc":2,"media":1,"domain":"kws2.example","cool":300}\n' >&9
    fi
    sleep 0.1
done
H
chmod +x "$tmp/helper"

LPORT=15311 UPORT=15375
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
# AAAA на имя, которое забрал доменный канал, резолвер гасит NODATA из самого вопроса (ANCOUNT 0),
# не спрашивая апстрим; чужое имя уходит наверх и получает запись (ANCOUNT 1) — см. dnsproxy.sh.
cat > "$tmp/qaaaa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x7a7a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 28, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(struct.unpack('>H', d[6:8])[0])
except socket.timeout:
    print('timeout')
PY
python3 "$tmp/upstream.py" "$UPORT" & UP=$!

printf 'swap.test\n' > "$tmp/swap.lst"
# spec [chan] — выходы с obfs: a идёт через t (via), b сам по себе; порядок в спеке — a, t, b.
# $BSRV — сервер обфускации выхода b. chan=1 — доменный канал swap.test → t.
spec() {
    chans='[]'
    [ -n "${1:-}" ] && chans="[{\"name\":\"c\",\"match\":{\"domains_files\":[\"$tmp/swap.lst\"]},\"out\":\"t\"}]"
    cat > "$tmp/spec.json" <<EOF
{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{
 "a":{"kind":"interface","device":"wga","via":"t",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5101"}},
 "t":{"kind":"interface","device":"wgt",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5102"}},
 "b":{"kind":"interface","device":"wgb",
      "obfs":{"mode":"wg-over-tcp","server":"${BSRV:-10.99.0.3:4443}","listen":"127.0.0.1:5103"}}},
 "channels":$chans}
EOF
}
pid_of() { grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3; }
runs() { grep -c "^obfs $1 " "$tmp/log" 2>/dev/null; }
alive() { p="$(pid_of "$1")"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo yes || echo no; }
self_uid="--allow-uid $(id -u)"
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

spec 1
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" daemon --supervise $self_uid --socket "$tmp/s.sock" \
    --spec "$tmp/spec.json" --state-dir "$tmp/st" \
    --dnsd-flag --listen-port --dnsd-flag "$LPORT" --dnsd-flag --upstream-port --dnsd-flag "$UPORT" \
    2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ] && [ "$(runs a)" = 1 ] && [ "$(runs b)" = 1 ]' 5
check "поднято по помощнику на выход" "1 1 1" "$(runs a) $(runs t) $(runs b)"
check "  в порядке via: цель t раньше a, идущего через неё (b — в порядке спеки)" "t b a" \
    "$(grep -o 'supervise: obfs [a-z]* запущен' "$tmp/d.err" | awk '{print $3}' | tr '\n' ' ' | sed 's/ $//')"
check "  каждому — своя труба событий (STEER_EVENT_FD)" "3" \
    "$(grep '^obfs ' "$tmp/log" | awk '$4 != "-"' | wc -l | tr -d ' ')"
DN="$(grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | grep -o '[0-9]*$')"
check "резолвер поднят демоном — на таблице" "1" \
    "$(tr '\0' ' ' < "/proc/$DN/cmdline" 2>/dev/null | grep -c -- ' dnsd --table-fd ')"

ctl subscribe > "$tmp/sub.out" 2>&1 &
SUB=$!
wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out" 2>/dev/null' 5
touch "$tmp/go"
wait_for '[ "$(grep -c "\"ev\":\"helper-up\"" "$tmp/sub.out")" = 3 ] && grep -q "\"ev\":\"node\"" "$tmp/sub.out"' 5
check "up из трубы — подписчику helper-up по каждому выходу" \
'{"v":1,"ev":"helper-up","out":"a","helper":"obfs"}
{"v":1,"ev":"helper-up","out":"b","helper":"obfs"}
{"v":1,"ev":"helper-up","out":"t","helper":"obfs"}' "$(grep '"ev":"helper-up"' "$tmp/sub.out" | sort)"
check "node из трубы — подписчику node" '{"v":1,"ev":"node","out":"a","n":2,"total":5}' \
    "$(grep '"ev":"node"' "$tmp/sub.out")"

# health (мост отставил путь до ДЦ; у стенда его пишет заглушка обфускатора — моста в сборке нет):
# подписчику — событие health, в status выхода и в ответе helper — paths_down до конца срока.
touch "$tmp/health.b"
wait_for 'grep -q "\"ev\":\"health\"" "$tmp/sub.out"' 5
check "health из трубы — подписчику health" \
    '{"v":1,"ev":"health","out":"b","helper":"obfs","dc":2,"media":true,"domain":"kws2.example","cool":300}' \
    "$(grep '"ev":"health"' "$tmp/sub.out")"
pdown() { python3 -c 'import json,sys
d = json.loads(sys.stdin.read())
d = json.loads(d["stdout"]) if "stdout" in d else d
p = d["outputs"]["b"].get("paths_down") if "outputs" in d else d.get("paths_down")
print("-" if p is None else " ".join("%s %s %s %s" % (x["dc"], x["media"], x["domain"], x["until"] - x["at"]) for x in p))'; }
check "  status выхода — paths_down (ДЦ, медийный, домен, срок)" "2 True kws2.example 300" \
    "$(ctl status | pdown)"
check "  helper b — живое состояние из памяти демона" "True True 2 True kws2.example 300" \
    "$(ctl helper b | python3 -c 'import json,sys
d = json.loads(json.load(sys.stdin)["stdout"])
p = d["paths_down"][0]
print(d["running"], d["up"], p["dc"], p["media"], p["domain"], p["until"] - p["at"])')"
check "  helper у выхода без помощника — код 1" "1" "$(ctl helper nope | python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])')"
# steerd status мимо клиента при живом демоне этой спеки — ответ демона (paths_down знает только он);
# клиент, уже спросивший демон (STEER_DAEMON_ASKED), получает ответ самого движка.
ENG="$(dirname "$BIN")/steerd"
check "steerd status при живом демоне — его ответ, а не подкоманды" "2 True kws2.example 300" \
    "$(STEER_SOCKET="$tmp/s.sock" "$ENG" status --spec "$tmp/spec.json" --state-dir "$tmp/st" | pdown)"
check "  после клиента (STEER_DAEMON_ASKED) — считает сам" "-" \
    "$(STEER_DAEMON_ASKED=1 STEER_SOCKET="$tmp/s.sock" "$ENG" status --spec "$tmp/spec.json" --state-dir "$tmp/st" | pdown)"
check "  чужая спека — считает сам" "-" \
    "$(cp "$tmp/spec.json" "$tmp/other.json"; STEER_SOCKET="$tmp/s.sock" "$ENG" status --spec "$tmp/other.json" --state-dir "$tmp/st" | pdown)"

# active со списком в тысячу узлов (больше прежних 160 символов): список доходит до status целиком.
touch "$tmp/active.b"
wait_for 'ctl helper b | grep -q "active"' 5
check "  active на 1000 узлов — в ответе helper без обрезки (3892 знака списка)" "1000 3892" \
    "$(ctl helper b | python3 -c 'import json,sys
d = json.loads(json.load(sys.stdin)["stdout"])
print(len(d["active"]), len(",".join(map(str, d["active"]))))')"

# Резолвер на таблице: канал swap.test есть — AAAA погашен; чужое имя — ответ апстрима.
wait_for '[ "$(python3 "$tmp/qaaaa.py" "$LPORT" other.test)" = 1 ]' 5
check "резолвер: канал из таблицы демона забрал swap.test, чужое имя — наверх" "0 1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT" swap.test) $(python3 "$tmp/qaaaa.py" "$LPORT" other.test)"

# reload без изменений — никого не трогать; со сменой сервера обфускации b — только b.
pa="$(pid_of a)" pt="$(pid_of t)" pb="$(pid_of b)"
r="$(ctl reload)"
check "reload с --supervise: резолверу таблица, помощников сверяет демон" "table daemon" \
    "$(printf '%s' "$r" | python3 -c 'import json,sys; d=json.load(sys.stdin)["reload"]; print(d["dnsd"], d["outputs"])')"
sleep 1
check "  без изменений спеки — никто не перезапущен" "$pa $pt $pb" "$(pid_of a) $(pid_of t) $(pid_of b)"
BSRV=10.99.0.4:4443 spec 1
ctl reload >/dev/null
wait_for '[ "$(runs b)" = 2 ] && [ "$(alive b)" = yes ]' 5
check "reload со сменой параметров b: b поднят заново" "2 yes" "$(runs b) $(alive b)"
check "  прежний b погашен" "no" "$(kill -0 "$pb" 2>/dev/null && echo yes || echo no)"
check "  a и t не тронуты" "$pa $pt" "$(pid_of a) $(pid_of t)"
check "  и о причине сказано" "1" "$(grep -c 'supervise: obfs b — параметры выхода изменились' "$tmp/d.err")"

check "  подписчику — helper-down с нашей причиной" \
    '{"v":1,"ev":"helper-down","out":"b","helper":"obfs","why":"перезапуск: параметры выхода изменились"}' \
    "$(grep '"ev":"helper-down"' "$tmp/sub.out")"

# Смена спеки меняет поведение резолвера без перезапуска: канала больше нет.
BSRV=10.99.0.4:4443 spec ""
ctl reload >/dev/null
sleep 1
check "резолвер: после reload без канала swap.test уходит наверх" "1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT" swap.test)"
check "  тем же процессом" "$DN yes" "$DN $(kill -0 "$DN" 2>/dev/null && echo yes || echo no)"
check "  и новую таблицу он принял" "1" "$(grep -c 'таблица от демона: 0 доменных' "$tmp/d.err")"

# Отказ: помощник пишет down и выходит с кодом 3 — helper-down с причиной, перезапуск через 5 с.
touch "$tmp/crash.b"
wait_for 'grep -q "стенд: отказ" "$tmp/sub.out"' 5
check "down из трубы — подписчику helper-down с причиной" \
    '{"v":1,"ev":"helper-down","out":"b","helper":"obfs","why":"стенд: отказ"}' \
    "$(grep '"ev":"helper-down"' "$tmp/sub.out" | grep 'стенд')"
check "  в журнале — выход и пауза 5 с" "1" "$(grep -c 'supervise: obfs b вышел (код 3) — перезапуск через 5 с' "$tmp/d.err")"
sleep 4
check "  за 4 с ещё не перезапущен" "2" "$(runs b)"
wait_for '[ "$(runs b)" = 3 ]' 4
check "  через 5 с перезапущен" "3" "$(runs b)"
wait_for '[ "$(grep -c "\"ev\":\"helper-up\"" "$tmp/sub.out")" -ge 5 ]' 3
touch "$tmp/crash.b"
wait_for 'grep -q "supervise: obfs b вышел (код 3) — перезапуск через 10 с" "$tmp/d.err"' 5
check "  упал снова сразу — пауза растёт до 10 с" "1" \
    "$(grep -c 'supervise: obfs b вышел (код 3) — перезапуск через 10 с' "$tmp/d.err")"

# Молча убитый после up — тоже helper-down: причина — сигнал.
kill -KILL "$(pid_of t)"
wait_for 'grep -q "\"out\":\"t\",\"helper\":\"obfs\",\"why\"" "$tmp/sub.out"' 5
check "помощник убит молча после up — helper-down с причиной" \
    '{"v":1,"ev":"helper-down","out":"t","helper":"obfs","why":"процесс убит (сигнал 9)"}' \
    "$(grep '"out":"t","helper":"obfs","why"' "$tmp/sub.out")"
wait_for '[ "$(runs t)" = 2 ] && [ "$(alive t)" = yes ]' 8
wait_for '[ "$(runs b)" -ge 4 ] && [ "$(alive b)" = yes ]' 12

# Тишина: помощники и резолвер живы и молчат — демон не просыпается.
sleep 1
cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$D/status")
sleep 3
cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$D/status")
q=$(( cs1 - cs0 )); [ "$q" -le 1 ] && q=ok
check "в тишине демон с детьми не просыпается" "ok" "$q"

# SIGTERM: по одному в обратном порядке подъёма (a раньше t), резолвер — тоже; детей не остаётся.
kill $SUB 2>/dev/null; wait $SUB 2>/dev/null; SUB=""
pa="$(pid_of a)" pt="$(pid_of t)" pb="$(pid_of b)"
before=$(wc -l < "$tmp/log")
kill -TERM $D
wait_for '! kill -0 $D 2>/dev/null' 15
check "SIGTERM: демон вышел" "no" "$(kill -0 $D 2>/dev/null && echo yes || echo no)"
live=""
for p in $pa $pt $pb $DN; do kill -0 "$p" 2>/dev/null && live="$live $p"; done
check "  помощники и резолвер погашены" "" "$live"
check "  помощники — по одному, в обратном порядке подъёма" "a b t" \
    "$(tail -n +$((before + 1)) "$tmp/log" | awk '$1 == "stop" {print $2}' | tr '\n' ' ' | sed 's/ $//')"
check "  журнал демона — с уровнем" "0" \
    "$(grep -v '^steer\[\(warn\|info\)\]' "$tmp/d.err" | grep -v '^steer dnsd: ' | grep -c .)"
D=""

# ---- резолвер переживает демона (src/dnsd/adopt.c) ------------------------------------------
# kill -9 демона: резолвер отвечает дальше по последней таблице — запросы каждые 100 мс, ни
# одного без ответа; новый демон на том же каталоге состояния забирает тот же процесс (pid тот
# же), и его таблица до резолвера доходит; SIGTERM новому гасит резолвер; без нового демона
# резолвер выходит сам через --orphan-timeout; демон, которому резолвер не нужен (спеки нет),
# гасит оставшийся сразу. Спека без помощников: после kill -9 они остались бы сиротами.
mkdir -p "$tmp/st5"
LPORT5=15312
printf 'swap.test\n' > "$tmp/l5a.lst"
printf 'swap.test\nnew.test\n' > "$tmp/l5b.lst"
spec5() {
    printf '{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{"t":{"kind":"interface","device":"wgt"}},'\
'"channels":[{"name":"c","match":{"domains_files":["%s"]},"out":"t"}]}\n' "$1" > "$tmp/spec5.json"
}
d5() {   # d5 ЖУРНАЛ [СПЕКА] — демон стенда в фоне, pid — в $!
    "$BIN" daemon --supervise $self_uid --socket "$tmp/s5.sock" --spec "${2:-$tmp/spec5.json}" \
        --state-dir "$tmp/st5" \
        --dnsd-flag --listen-port --dnsd-flag "$LPORT5" --dnsd-flag --upstream-port --dnsd-flag "$UPORT" \
        --dnsd-flag --orphan-timeout --dnsd-flag 4 2>"$tmp/$1" &
}
dn5() { grep -o "supervise: dnsd $2 (pid [0-9]*" "$tmp/$1" | tail -1 | grep -o '[0-9]*$'; }
gone() { kill -0 "$1" 2>/dev/null && echo alive || echo gone; }
cat > "$tmp/q5.py" <<'PY'
import socket, struct, sys, time
port, dur = int(sys.argv[1]), float(sys.argv[2])
ok = bad = 0
end = time.time() + dur
i = 0
while time.time() < end:
    i += 1
    q = struct.pack('>HHHHHH', i & 0xffff, 0x0100, 1, 0, 0, 0) + b'\x05other\x04test\x00' + \
        struct.pack('>HH', 28, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
    try:
        s.sendto(q, ('127.0.0.1', port))
        d, _ = s.recvfrom(2048)
        if d[:2] == q[:2]: ok += 1
        else: bad += 1
    except Exception:
        bad += 1
    s.close()
    time.sleep(0.1)
print(ok, bad)
PY
spec5 "$tmp/l5a.lst"
d5 d5a.err; D=$!
wait_for '[ -n "$(dn5 d5a.err запущен)" ] && [ "$(python3 "$tmp/qaaaa.py" "$LPORT5" other.test)" = 1 ]' 5
DN5="$(dn5 d5a.err запущен)"
check "переживание: резолвер поднят, канал из таблицы — swap.test, new.test ещё нет" "0 1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT5" swap.test) $(python3 "$tmp/qaaaa.py" "$LPORT5" new.test)"
python3 "$tmp/q5.py" "$LPORT5" 6 > "$tmp/q5.out" & Q5=$!
sleep 1
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
sleep 1
check "  kill -9 демона: резолвер жив и сказал, что ждёт нового" "alive 1" \
    "$(gone "$DN5") $(grep -c 'steer\[warn\] dnsd: демон пропал' "$tmp/d5a.err")"
check "  и отвечает по последней таблице" "0 1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT5" swap.test) $(python3 "$tmp/qaaaa.py" "$LPORT5" new.test)"
spec5 "$tmp/l5b.lst"
d5 d5b.err; D=$!
wait_for '[ -n "$(dn5 d5b.err подхвачен)" ]' 5
check "  новый демон забрал тот же резолвер" "$DN5" "$(dn5 d5b.err подхвачен)"
check "  своего не запускал" "" "$(dn5 d5b.err запущен)"
wait_for '[ "$(python3 "$tmp/qaaaa.py" "$LPORT5" new.test)" = 0 ]' 5
check "  таблица нового демона дошла: new.test теперь в канале" "0" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT5" new.test)"
check "  журнал резолвера — в stderr нового демона" "1" \
    "$(grep -c 'steer\[info\] dnsd: новый демон забрал резолвер' "$tmp/d5b.err")"
wait "$Q5"; Q5=""
check "  DNS без перерыва: ни одного запроса без ответа (запрос каждые 100 мс)" "ok 0" \
    "$(awk '{ print ($1 >= 40 ? "ok" : "мало:" $1), $2 }' "$tmp/q5.out")"
kill -TERM "$D"; wait "$D" 2>/dev/null; D=""
# Забранный резолвер — не ребёнок демона: демон ждёт его выхода по закрытию соединения, а
# вышедший процесс ещё мгновение виден kill -0, пока его не приберёт init. Поэтому — ожидание.
wait_for '[ "$(gone "$DN5")" = gone ]' 2
check "  SIGTERM новому демону гасит и забранный резолвер" "gone no" \
    "$(gone "$DN5") $([ -S "$tmp/st5/dnsd-ctl.sock" ] && echo yes || echo no)"

d5 d5c.err; D=$!
wait_for '[ -n "$(dn5 d5c.err запущен)" ]' 5
DN5="$(dn5 d5c.err запущен)"
wait_for '[ "$(python3 "$tmp/qaaaa.py" "$LPORT5" other.test)" = 1 ]' 5
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
sleep 2
check "без нового демона: через 2 с резолвер ещё жив" "alive" "$(gone "$DN5")"
wait_for '[ "$(gone "$DN5")" = gone ]' 6
check "  через срок (--orphan-timeout 4) вышел сам" "gone 1" \
    "$(gone "$DN5") $(grep -c 'нового демона нет 4 с — выхожу' "$tmp/d5c.err")"

d5 d5d.err; D=$!
wait_for '[ -n "$(dn5 d5d.err запущен)" ]' 5
DN5="$(dn5 d5d.err запущен)"
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
sleep 0.5
d5 d5e.err "$tmp/nospec.json"; D=$!
wait_for '[ "$(gone "$DN5")" = gone ]' 5
check "демон без спеки гасит оставшийся резолвер сразу" "gone 1" \
    "$(gone "$DN5") $(grep -c "резолвер прежнего демона (pid $DN5) погашен" "$tmp/d5e.err")"
kill -TERM "$D"; wait "$D" 2>/dev/null; D="" DN5=""

# ---- помощники не переживают демона (src/daemon/supd.c, «Помощники демона не переживают») -------
# kill -9 демона: помощник выходит сам не позже чем через секунду (PR_SET_PDEATHSIG, SIGTERM) и
# нового демона не ждёт. Помощник, который SIGTERM не слышит (trap '' TERM — сирота, которого
# сигнал не взял), гасит новый демон при старте, SIGTERM и по сроку SIGKILL, — раньше, чем
# поднимает своего: иначе своему не встать на занятое «устройство». Устройство здесь — flock на
# файл по имени выхода: как TUNSETIFF на имя vr, второй экземпляр получает отказ («busy») и
# выходит с кодом 1. Помощник другого, живого демона (свой каталог состояния) не тронут ни
# смертью соседа, ни уборкой нового.
cat > "$tmp/h6" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log6"
exec 8>"$tmp/tun6.\$2"
flock -n 8 || { echo "busy \$2 \$\$" >> "$tmp/log6"; exit 1; }
if [ -e "$tmp/deaf6.\$2" ]; then trap '' TERM
else trap 'echo "stop \$2 \$\$" >> "$tmp/log6"; exit 0' TERM; fi
[ -n "\${STEER_EVENT_FD:-}" ] && eval "exec 9>&\$STEER_EVENT_FD" && printf '{"ev":"up"}\n' >&9
while :; do sleep 0.1 8>&- 9>&-; done
H
chmod +x "$tmp/h6"
mkdir -p "$tmp/st6" "$tmp/st6o"
spec6() {   # spec6 ФАЙЛ ВЫХОД ПОРТ — один выход с обфускатором
    printf '{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{"%s":{"kind":"interface",'\
'"device":"wg%s","obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:%s"}}}}\n' \
        "$2" "$2" "$3" > "$1"
}
d6() {   # d6 ЖУРНАЛ СПЕКА КАТАЛОГ ПОРТ-РЕЗОЛВЕРА — демон стенда в фоне, pid — в $!
    STEER_SUPERVISE_EXE="$tmp/h6" "$BIN" daemon --supervise $self_uid --socket "$3/s.sock" --spec "$2" \
        --state-dir "$3" \
        --dnsd-flag --listen-port --dnsd-flag "$4" --dnsd-flag --upstream-port --dnsd-flag "$UPORT" \
        --dnsd-flag --orphan-timeout --dnsd-flag 2 2>"$tmp/$1" &
}
pid6() { grep "^obfs $1 " "$tmp/log6" | tail -1 | cut -d' ' -f3; }
runs6() { grep -c "^obfs $1 " "$tmp/log6" 2>/dev/null; }
spec6 "$tmp/spec6.json" v 5106
spec6 "$tmp/spec6o.json" w 5107
d6 d6o.err "$tmp/spec6o.json" "$tmp/st6o" 15314; DO6=$!
d6 d6a.err "$tmp/spec6.json" "$tmp/st6" 15313; D=$!
wait_for '[ "$(runs6 v)" = 1 ] && [ "$(runs6 w)" = 1 ]' 5
PV="$(pid6 v)" PW="$(pid6 w)"
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
wait_for '! kill -0 "$PV" 2>/dev/null' 1
check "kill -9 демона: помощник вышел сам за секунду, по SIGTERM" "gone 1" \
    "$(gone "$PV") $(grep -c "^stop v $PV\$" "$tmp/log6")"
check "  помощник соседнего живого демона жив" "alive" "$(gone "$PW")"
touch "$tmp/deaf6.v"
d6 d6b.err "$tmp/spec6.json" "$tmp/st6" 15313; D=$!
wait_for '[ "$(runs6 v)" = 2 ]' 5
check "  новый демон поднял своего без отказа «занято»" "2 0" "$(runs6 v) $(grep -c '^busy' "$tmp/log6")"
PV="$(pid6 v)"
sleep 0.3
rm -f "$tmp/deaf6.v"
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
sleep 1.5
check "глухой к SIGTERM помощник пережил kill -9 демона" "alive" "$(gone "$PV")"
d6 d6c.err "$tmp/spec6.json" "$tmp/st6" 15313; D=$!
wait_for '[ "$(runs6 v)" = 3 ]' 8
check "  новый демон погасил его до запуска своего: SIGTERM, по сроку SIGKILL" "gone 1 1" \
    "$(gone "$PV") $(grep -c "помощник прежнего демона (pid $PV, .*) остался без него — гашу" \
        "$tmp/d6c.err") $(grep -c "помощник прежнего демона (pid $PV) не вышел по SIGTERM за 3 с — SIGKILL" \
        "$tmp/d6c.err")"
check "  свой поднят без отказа «занято», помощника соседа уборка не тронула" "0 alive 0" \
    "$(grep -c '^busy' "$tmp/log6") $(gone "$PW") $(grep -c "pid $PW" "$tmp/d6c.err")"
check "  журнал демона — с уровнем" "0" \
    "$(grep -v '^steer\[\(warn\|info\)\]' "$tmp/d6c.err" | grep -v '^steer dnsd: ' | grep -c .)"
kill -TERM "$D" "$DO6"; wait "$D" "$DO6" 2>/dev/null; D="" DO6=""

# ---- stderr резолвера без демона — в syslog с заголовком (src/dnsd/adopt.c, stderr_rescue) -------
# На роутере stderr резолвера — труба журнала procd, и после остановки службы её читателя нет.
# Здесь это FIFO, чей читатель (cat) убит до kill -9 демона: пропажу демона резолвер замечает уже
# без читателя stderr, и строки идут в приёмник syslog стенда. Приёмник пишет по датаграмме на
# строку (перевод строки внутри — как \n). Проверка разбирает заголовок трижды: как RFC 3164
# (syslog(3) glibc/musl: `<PRI>Mmm dd hh:mm:ss ТЕГ[pid]: `, время — местное, сейчас), как logd
# OpenWrt (ubox, logd/syslog.c: число после '<' до '>' — приоритет, без него 0, то есть
# kern.emerg; метка снимается, если на [3] и [6] пробел, на [9] и [12] двоеточие, на [15] пробел)
# и как journald (syslog_parse_priority, syslog_skip_timestamp — буква, буква, буква, пробел,
# пробел-или-цифра, цифра, …; syslog_parse_identifier — тег и pid до «: »). Итог — «PRI ok ok ok ok»
# или, вместо ok, чем не сошлось.
cat > "$tmp/slog.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
with open(sys.argv[2], 'ab', buffering=0) as f:
    while True:
        d = s.recv(65536)
        f.write(d.replace(b'\\', b'\\\\').replace(b'\n', b'\\n') + b'\n')
PY
cat > "$tmp/slogchk.py" <<'PY'
import re, sys, time
path, pid, text = sys.argv[1], sys.argv[2], sys.argv[3]
MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
grams = [l.rstrip(b'\n').replace(b'\\n', b'\n').replace(b'\\\\', b'\\')
         for l in open(path, 'rb')]
got = [g for g in grams if text.encode() in g]
if len(got) != 1:
    print('датаграмм с этим текстом: %d' % len(got)); sys.exit()
d = got[0]
want = ('steer[%s]: %s' % (pid, text)).encode()

def rfc(d):
    m = re.fullmatch(rb'<(\d{1,3})>(' + '|'.join(MON).encode() + rb') ( [1-9]|[12]\d|3[01]) '
                     rb'([01]\d|2[0-3]):([0-5]\d):([0-5]\d) (.*)', d, re.S)
    if not m: return 'не RFC 3164'
    return 'ok' if m.group(7) == want else 'текст: %r' % m.group(7)

def stamp(d):
    if b'>' not in d: return 'метки нет'
    stamp = d[d.index(b'>') + 1:][:15].decode(errors='replace')
    now = time.time()
    for t in range(int(now) - 60, int(now) + 2):
        tm = time.localtime(t)
        if '%s %2d %02d:%02d:%02d' % (MON[tm.tm_mon - 1], tm.tm_mday, tm.tm_hour, tm.tm_min,
                                      tm.tm_sec) == stamp: return 'ok'
    return 'время не местное-сейчас: %s' % stamp

def logd(d):                   # ubox logd/syslog.c, syslog_handle_log
    p, pri = d.rstrip(b'\0\n'), 0
    if p[:1] == b'<':
        i = 1
        while i < len(p) and p[i:i + 1].isdigit():
            pri = pri * 10 + p[i] - 48; i += 1
        if p[i:i + 1] == b'>': i += 1
        p = p[i:]
    if len(p) > 16 and p[3:4] == b' ' and p[6:7] == b' ' and p[9:10] == b':' and \
       p[12:13] == b':' and p[15:16] == b' ':
        p = p[16:]
    if pri >> 3 != 1: return 'facility %d (pri %d)' % (pri >> 3, pri)
    return 'ok' if p == want else 'logread: %r' % p

def journald(d):               # systemd, journald-syslog.c
    p = d
    if p[:1] != b'<' or b'>' not in p: return 'нет <PRI>'
    k = next((k for k in (2, 3, 4) if p[k:k + 1] == b'>'), 0)
    if not k or not p[1:k].isdigit(): return 'PRI не разобран'
    pri, p = int(p[1:k]), p[k + 1:]
    if pri >> 3 != 1: return 'facility %d' % (pri >> 3)
    seq = 'LLLSsNSsN:sN:sNS'
    if len(p) < len(seq): return 'коротко'
    for c, want_c in zip(p[:len(seq)], seq):
        ch = bytes([c])
        ok = {'L': ch.isalpha(), 'S': ch == b' ', 'N': ch.isdigit(),
              's': ch == b' ' or ch.isdigit(), ':': ch == b':'}[want_c]
        if not ok: return 'метка времени не снята'
    p = p[len(seq):]
    p = p.lstrip(b' \t\n\r')
    l = len(re.match(rb'[^ \t\n\r]*', p).group(0))
    if l <= 0 or p[l - 1:l] != b':': return 'тега нет'
    e, l = l, l - 1
    ident, jpid = p[:l], None
    if l > 0 and p[l - 1:l] == b']':
        k = p.rfind(b'[', 0, l - 1)
        if k >= 0: jpid, ident = p[k + 1:l - 1], p[:k]
    if p[e:e + 1] in (b' ', b'\t', b'\n', b'\r'): e += 1
    msg = p[e:]
    if (ident, jpid, msg) != (b'steer', pid.encode(), text.encode()):
        return 'тег %r pid %r текст %r' % (ident, jpid, msg)
    return 'ok'

pri = re.match(rb'<(\d+)>', d)
print(pri.group(1).decode() if pri else '-', rfc(d), stamp(d), logd(d), journald(d))
PY
slogchk() { python3 "$tmp/slogchk.py" "$tmp/log.out" "$@"; }
mkfifo "$tmp/err.fifo"
: > "$tmp/log.out"
python3 "$tmp/slog.py" "$tmp/log.sock" "$tmp/log.out" & SL=$!
wait_for '[ -S "$tmp/log.sock" ]' 5
d5fifo() {   # d5fifo ЖУРНАЛ — демон, чей stderr — FIFO с читателем cat в ЖУРНАЛ (pid — $CAT)
    cat "$tmp/err.fifo" > "$tmp/$1" & CAT=$!
    d5 err.fifo
}
cutlog() { kill "$CAT"; wait "$CAT" 2>/dev/null; CAT=""; }

# Демон пропал уже без читателя stderr: «демон пропал» — в syslog, warn (12); новый демон забрал
# резолвер — строки снова в его stderr, и в syslog больше ничего не приходит.
d5fifo d5h.err; D=$!
wait_for '[ -n "$(dn5 d5h.err запущен)" ] && [ -S "$tmp/st5/dnsd-ctl.sock" ]' 5
DN5="$(dn5 d5h.err запущен)"
cutlog
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
wait_for 'grep -q . "$tmp/log.out"' 3
# Эту строку и glibc, и musl пишут двумя write (кусок до %d и остаток) — приходит она одной
# датаграммой и целой.
lost="steer[warn] dnsd: демон пропал (труба таблицы закрыта) — отвечаю по последней таблице"
lost="$lost и жду нового демона 4 с"
check "stderr без читателя: строка резолвера — в syslog, warn, заголовок разбирается" \
    "12 ok ok ok ok" "$(slogchk "$DN5" "$lost")"
d5 d5i.err; D=$!
wait_for '[ -n "$(dn5 d5i.err подхвачен)" ]' 5
sleep 0.3
check "  забравший демон получает строки резолвера в свой stderr, в syslog — больше ничего" \
    "$DN5 1 1" "$(dn5 d5i.err подхвачен) \
$(grep -c 'steer\[info\] dnsd: новый демон забрал резолвер' "$tmp/d5i.err") $(grep -c . "$tmp/log.out")"
kill -TERM "$D"; wait "$D" 2>/dev/null; D=""
wait_for '[ "$(gone "$DN5")" = gone ]' 2

# Срок ожидания нового демона вышел: последняя строка перед выходом дочитана и дошла.
: > "$tmp/log.out"
d5fifo d5j.err; D=$!
wait_for '[ -n "$(dn5 d5j.err запущен)" ] && [ -S "$tmp/st5/dnsd-ctl.sock" ]' 5
DN5="$(dn5 d5j.err запущен)"
cutlog
kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
wait_for '[ "$(gone "$DN5")" = gone ]' 8
check "  срок ожидания вышел: последняя строка перед выходом — в syslog" "gone 12 ok ok ok ok" \
    "$(gone "$DN5") $(slogchk "$DN5" "steer[warn] dnsd: нового демона нет 4 с — выхожу")"
DN5=""

# stop в окне после падения демона: kill -9 и сразу `steerd down` (его зовёт service_stopped
# init.d), пока procd не поднял демон, — резолвер, ждущий нового демона, гаснет сразу, а не через
# --orphan-timeout: сокета нет, и новому демону забирать нечего (свой резолвер он запускает). При
# живом демоне `steer down` резолвер не трогает: хозяин жив, и резолвер просьбу отклоняет.
# Только в своём сетевом пространстве: down снимает таблицы nft и правила маршрутизации.
if [ "${SUPD_INNER:-}" = 1 ]; then
    d5 d5f.err; D=$!
    wait_for '[ -n "$(dn5 d5f.err запущен)" ] && [ -S "$tmp/st5/dnsd-ctl.sock" ]' 5
    DN5="$(dn5 d5f.err запущен)"
    "$BIN" down --state-dir "$tmp/st5" 2>"$tmp/down1.err"
    check "живой демон: steer down резолвер не трогает" "alive 0" \
        "$(gone "$DN5") $(grep -c 'погашен' "$tmp/down1.err")"
    kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
    sleep 0.5
    t0="$(date +%s)"
    "$BIN" down --state-dir "$tmp/st5" 2>"$tmp/down2.err"
    wait_for '[ "$(gone "$DN5")" = gone ]' 3
    check "kill -9 демона и сразу steerd down: резолвер погашен сразу, сокета нет" "gone no yes" \
        "$(gone "$DN5") $([ -S "$tmp/st5/dnsd-ctl.sock" ] && echo yes || echo no) \
$([ $(($(date +%s) - t0)) -lt 3 ] && echo yes || echo no)"
    check "  down сказал, кого погасил; резолвер — почему вышел" "1 1" \
        "$(grep -c "резолвер, оставшийся без демона (pid $DN5), погашен" "$tmp/down2.err") \
$(grep -c 'служба остановлена без демона (steerd down) — выхожу' "$tmp/d5f.err")"
    d5 d5g.err; D=$!
    wait_for '[ -n "$(dn5 d5g.err запущен)" ]' 5
    check "  новому демону забирать нечего: свой резолвер" "yes " \
        "$([ -n "$(dn5 d5g.err запущен)" ] && echo yes || echo no) $(dn5 d5g.err подхвачен)"
    kill -TERM "$D"; wait "$D" 2>/dev/null; D="" DN5=""

    # То же без читателя stderr (на роутере так и есть: stop закрыл трубу журнала procd) —
    # последняя строка резолвера, info (14), дочитана перед выходом и дошла до syslog.
    : > "$tmp/log.out"
    d5fifo d5k.err; D=$!
    wait_for '[ -n "$(dn5 d5k.err запущен)" ] && [ -S "$tmp/st5/dnsd-ctl.sock" ]' 5
    DN5="$(dn5 d5k.err запущен)"
    cutlog
    kill -KILL "$D"; wait "$D" 2>/dev/null; D=""
    sleep 0.5
    "$BIN" down --state-dir "$tmp/st5" 2>"$tmp/down3.err"
    wait_for '[ "$(gone "$DN5")" = gone ]' 3
    check "  без читателя stderr: строка о выходе по steerd down — в syslog, info" \
        "gone 14 ok ok ok ok" \
        "$(gone "$DN5") $(slogchk "$DN5" \
            "steer[info] dnsd: служба остановлена без демона (steerd down) — выхожу")"
    DN5=""
fi

# ---- сторож и супервизор вместе (--watch --supervise) --------------------------------------
# Выход-пул vpn из устройств xa и xb — устройств выходов kind=xsteer, чьи помощники (заглушки) пишут
# up или down по файлу down.<выход>. Устройства — dummy: их наличие сторож видит в своём /sys, а
# живость решает событие помощника. vl — выход vless, чей помощник застрял на переборе узлов (node
# 2 из 5). wo — interface с обфускатором;
# у его устройства нет адреса, проба ICMP его не находит, и сторож его оживляет. ubus, ifdown и
# ifup — заглушки в PATH демона: ubus записывает вызов, ifdown/ifup отказывают.
XK="${STEER_XK:-$(dirname "$BIN")/steer-xk}"
if [ "${SUPD_INNER:-}" = 1 ] && [ -x "$XK" ] && command -v unshare >/dev/null 2>&1 &&
   unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null &&
   ip link add xa type dummy 2>/dev/null && ip link add xb type dummy 2>/dev/null &&
   ip link add wo type dummy 2>/dev/null && ip link add va type dummy 2>/dev/null &&
   ip link add vb type dummy 2>/dev/null; then
    for dv in xa xb wo va vb; do ip link set "$dv" addrgenmode none 2>/dev/null; ip link set "$dv" up; done
    W="$tmp/w"
    mkdir -p "$W/st" "$W/bin"
    printf '#!/bin/sh\necho "ubus $*" >> "%s/ubus.log"\nexit 0\n' "$W" > "$W/bin/ubus"
    printf '#!/bin/sh\nexit 1\n' > "$W/bin/ifdown"
    printf '#!/bin/sh\nexit 1\n' > "$W/bin/ifup"
    chmod +x "$W/bin/ubus" "$W/bin/ifdown" "$W/bin/ifup"
    cat > "$W/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$W/log"
[ -n "\${STEER_EVENT_FD:-}" ] && eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$1 \$2 \$\$" >> "$W/log"; exit 0' TERM
upline='{"ev":"up"}' downline='{"ev":"down","why":"стенд: отказ"}'
case "\$1 \$2" in
"vless vl") printf '{"ev":"node","n":2,"total":5}\n' >&9; while :; do sleep 0.1; done ;;
"vless vx") printf '{"ev":"excluded","total":3}\n{"ev":"down","why":"все узлы-кандидаты исключены exclude"}\n' >&9; while :; do sleep 0.1; done ;;
vless*) upline="{\"ev\":\"up\",\"watch\":1,\"dev\":\"\$2\"}" downline='{"ev":"down","why":"стенд: узел молчит"}' ;;
xsteer*) upline="{\"ev\":\"up\",\"dev\":\"\$2\"}" ;;
esac
last=""
while :; do
    cur=up; [ -e "$W/down.\$2" ] && cur=down
    if [ "\$cur" != "\$last" ]; then
        if [ "\$cur" = up ]; then printf '%s\n' "\$upline" >&9
        else printf '%s\n' "\$downline" >&9; fi
        last=\$cur
    fi
    sleep 0.1
done
H
    chmod +x "$W/helper"
    : > "$W/sub.txt"
    # wspec [wo] — с «wo» ещё и выход с обфускатором.
    wspec() {
        wo=""
        [ -n "${1:-}" ] && wo=',"wo":{"kind":"interface","device":"wo","obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5111"}}'
        cat > "$W/spec.json" <<EOF
{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{
 "xa":{"kind":"xsteer","conf":"/etc/xa.conf","on_fail":"direct"},
 "xb":{"kind":"xsteer","conf":"/etc/xb.conf","on_fail":"direct"},
 "vpn":{"kind":"interface","devices":["xa","xb"],"on_fail":"drop"},
 "vl":{"kind":"vless","sub_file":"$W/sub.txt","on_fail":"direct"},
 "vx":{"kind":"vless","sub_file":"$W/sub.txt","on_fail":"direct"},
 "va":{"kind":"vless","sub_file":"$W/sub.txt","on_fail":"direct"},
 "vb":{"kind":"vless","sub_file":"$W/sub.txt","on_fail":"direct"},
 "vv":{"kind":"interface","devices":["va","vb"],"on_fail":"drop"}$wo},
 "channels":[]}
EOF
    }
    wruns() { grep -c "^$1 $2 " "$W/log" 2>/dev/null; }
    wctl() { "$XK" ctl --socket "$W/s.sock" "$@"; }
    wst() { wctl status | python3 -c 'import json,sys; d=json.loads(json.load(sys.stdin)["stdout"]); print(json.dumps(eval("d"+sys.argv[1]), separators=(",", ":")))' "$1" 2>/dev/null; }
    nofiles() { ls "$W/st" | grep '^probe-\|^xsteer-' | tr '\n' ' '; }
    wspec
    WD=""
    # STEER_FAILOVER_HYST=0 — возврат на ожившее предпочтительное устройство без выдержки в три
    # прохода: стенд смотрит на то, откуда сторож берёт здоровье, а не на гистерезис. Период —
    # 600 с: всё, что стенд ждёт от сторожа, обязано прийти внеочередным проходом по событию.
    unshare -m sh -c "mount -t sysfs sysfs /sys && PATH=\"$W/bin:\$PATH\" STEER_FAILOVER_HYST=0 \
        STEER_SUPERVISE_EXE=\"$W/helper\" exec \"$XK\" daemon --watch --watch-period 600 --supervise $self_uid \
        --socket \"$W/s.sock\" --spec \"$W/spec.json\" --state-dir \"$W/st\" \
        --dnsd-flag --listen-port --dnsd-flag 15411 --dnsd-flag --upstream-port --dnsd-flag 15475" \
        >"$W/d.out" 2>"$W/d.err" &
    WD=$!
    wait_for '[ -S "$W/s.sock" ]' 5
    wctl subscribe > "$W/sub.out" 2>&1 &
    SUB=$!
    wait_for 'grep -q "\"cmd\":\"subscribe\"" "$W/sub.out" 2>/dev/null' 5
    # Первый проход: помощники ещё не сказали up — сторож ждёт их, как ждал бы туннель, и выход-пул
    # встаёт на первое устройство, когда его помощник поднялся (vl ждётся до конца — перебор).
    wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"vpn\"" "$W/sub.out"' 40
    check "сторож с супервизором: помощник поднялся — выход-пул на первом устройстве" \
        '{"v":1,"ev":"switched","out":"vpn","from":null,"to":"xa","why":"start"}' \
        "$(grep '"ev":"switched","out":"vpn"' "$W/sub.out")"
    check "  status из памяти — оно же" '"xa"' "$(wst '["outputs"]["vpn"]["device"]')"
    check "  status: перебор узлов vless — из памяти демона" \
        '{"state":"probing","node":2,"total":5}' "$(wst '["outputs"]["vl"]["probe"]')"
    # Мимо клиента (так status зовёт rpcd): подкоманда при живом демоне отвечает его ответом —
    # файлов probe-* нет, и сама она хода перебора не знала бы.
    check "  steerd status мимо клиента — тот же ход перебора, от демона" \
        '{"state":"probing","node":2,"total":5}' \
        "$(STEER_SOCKET="$W/s.sock" "$XK" status --spec "$W/spec.json" --state-dir "$W/st" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["outputs"]["vl"].get("probe"), separators=(",", ":")))' 2>&1)"
    # Все кандидаты исключены exclude (событие excluded клиента): своё состояние, а не failed —
    # «в подписке нет пригодных узлов» было бы неправдой, узлы есть, их не велено брать.
    check "  status: все кандидаты исключены — состояние excluded, не failed" \
        '{"state":"excluded","total":3}' "$(wst '["outputs"]["vx"]["probe"]')"
    check "  и в steerd status мимо клиента" \
        '{"state":"excluded","total":3}' \
        "$(STEER_SOCKET="$W/s.sock" "$XK" status --spec "$W/spec.json" --state-dir "$W/st" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["outputs"]["vx"].get("probe"), separators=(",", ":")))' 2>&1)"
    check "  helper xa — живое состояние клиента xsteer из памяти демона (xsteer-peers)" \
        "xsteer True True" \
        "$(wctl helper xa | python3 -c 'import json,sys; d=json.loads(json.load(sys.stdin)["stdout"]); print(d["helper"], d["running"], d["up"])' 2>&1)"

    # Маршрут выхода помощника ставит демон по его up с устройством (1.10, шаг 3; src/daemon/supd.c,
    # route_up): помощник-заглушка маршрута не трогает вовсе, а таблица выхода xa смотрит в xa и
    # правило по метке стоит. Номер таблицы — из строки демона о привязке.
    xat() { sed -n 's/.*supervise: xsteer xa — xa поднят, маршрут выхода привязан (таблица \([0-9]*\)).*/\1/p' "$W/d.err" | head -1; }
    wait_for '[ -n "$(xat)" ]' 10
    XT="$(xat)"
    check "up с устройством: демон привязал маршрут выхода xa (строка в журнале)" "yes" \
        "$([ -n "$XT" ] && echo yes)"
    check "  таблица выхода xa — в устройство xa" "default dev xa" \
        "$(ip route show table "${XT:-0}" 2>/dev/null | grep -o '^default dev xa')"
    # Правило — фильтром по таблице, а не разбором вывода: ip печатает имя таблицы из rt_tables
    # машины (steer_xa), если оно там есть.
    xrule() { ip rule show table "${XT:-0}" 2>/dev/null | grep -c fwmark; }
    check "  правило по метке выхода xa стоит" "1" "$(xrule)"
    check "  и у vless va — тем же путём" "1" \
        "$(grep -c 'supervise: vless va — va поднят, маршрут выхода привязан' "$W/d.err")"

    touch "$W/down.xa"
    wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"vpn\",\"from\":\"xa\"" "$W/sub.out"' 40
    check "помощник xa пишет down — выход переключён на следующее устройство" \
        '{"v":1,"ev":"switched","out":"vpn","from":"xa","to":"xb","why":"down"}' \
        "$(grep '"ev":"switched","out":"vpn","from":"xa"' "$W/sub.out")"
    check "  status — новое устройство" '"xb"' "$(wst '["outputs"]["vpn"]["device"]')"
    # down помощника — решает сторож, как прежде: у xa on_fail=direct, правило снято, таблица
    # пуста (трафик выхода — напрямую). Второго пути решения у демона нет.
    wait_for '[ -z "$(ip route show table "${XT:-0}" 2>/dev/null)" ]' 10
    check "  down: сторож снял маршрут выхода xa (on_fail=direct)" "" \
        "$(ip route show table "${XT:-0}" 2>/dev/null)"
    check "  и правило по его метке" "0" "$(xrule)"
    rm -f "$W/down.xa"
    wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"vpn\",\"from\":\"xb\"" "$W/sub.out"' 40
    check "помощник xa пишет up — возврат на него" \
        '{"v":1,"ev":"switched","out":"vpn","from":"xb","to":"xa","why":"preferred"}' \
        "$(grep '"ev":"switched","out":"vpn","from":"xb"' "$W/sub.out")"
    # Снова up того же процесса: маршрут возвращает проход сторожа (was «-» → устройство), а
    # демон по up второй раз не привязывает — привязка одна на подъём устройства.
    wait_for '[ -n "$(ip route show table "${XT:-0}" 2>/dev/null | grep "^default dev xa")" ]' 10
    check "  маршрут выхода xa вернулся (сторож)" "default dev xa" \
        "$(ip route show table "${XT:-0}" 2>/dev/null | grep -o '^default dev xa')"
    check "  демон по второму up того же процесса не привязывал" "1" \
        "$(grep -c 'supervise: xsteer xa — xa поднят, маршрут выхода привязан' "$W/d.err")"
    check "  файлов probe-* и xsteer-*.json в каталоге состояния нет" "" "$(nofiles)"

    # Клиент vless, следящий за узлом сам (up с watch): его слово — приговор, пробы TCP нет. Через
    # устройства va и vb (dummy без адреса в пространстве без маршрутов) соединение TCP не уходит
    # вовсе — проба сторожа признала бы их мёртвыми, а выход-пул vv стоит на va.
    check "клиент vless с watch: пул на первом устройстве, хотя проба TCP через него не прошла бы" \
        '{"v":1,"ev":"switched","out":"vv","from":null,"to":"va","why":"start"}' \
        "$(grep '"ev":"switched","out":"vv"' "$W/sub.out" | head -1)"
    check "  соединение TCP через va и правда не уходит" "no" \
        "$(python3 -c 'import socket
s = socket.socket(); s.settimeout(2)
s.setsockopt(socket.SOL_SOCKET, 25, b"va\0")
try: s.connect(("1.1.1.1", 80)); print("yes")
except OSError: print("no")' 2>&1)"
    # vast — «в отказе|причина node_down|время есть» у выхода va по status.
    vast() { wctl status | python3 -c 'import json,sys
d = json.loads(json.load(sys.stdin)["stdout"])["outputs"]["va"]; n = d.get("node_down") or {}
print(d.get("failed", False), n.get("why", "-"), n.get("since", 0) > 0, sep="|")' 2>&1; }
    check "  status va — в строю, без node_down" "False|-|False" "$(vast)"
    # Узел потерян: клиент пишет down с причиной — демон переключает пул тем же внеочередным
    # проходом (период сторожа у стенда — 600 с, дождаться его нельзя), va — в отказе.
    t0=$(date +%s)
    touch "$W/down.va"
    wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"vv\",\"from\":\"va\"" "$W/sub.out"' 40
    check "клиент vless пишет down — пул переключён без прохода по периоду" \
        '{"v":1,"ev":"switched","out":"vv","from":"va","to":"vb","why":"down"}' \
        "$(grep '"ev":"switched","out":"vv","from":"va"' "$W/sub.out")"
    check "  за секунды, а не за период" "yes" "$([ $(($(date +%s) - t0)) -lt 60 ] && echo yes)"
    check "  подписчику — helper-down с причиной клиента" \
        '{"v":1,"ev":"helper-down","out":"va","helper":"vless","why":"стенд: узел молчит"}' \
        "$(grep '"ev":"helper-down","out":"va"' "$W/sub.out")"
    wait_for '[ "$(vast)" = "True|стенд: узел молчит|True" ]' 10
    check "  status va — отказ и причина от клиента (node_down)" "True|стенд: узел молчит|True" \
        "$(vast)"
    check "  diag va — узел перестал отвечать, с причиной клиента" \
        "fail|выход va: узел перестал отвечать, трафик канала идёт напрямую|стенд: узел молчит; выход вернётся сам, когда узел ответит" \
        "$(wctl diag | python3 -c 'import json,sys
d = json.loads(json.load(sys.stdin)["stdout"])
for c in d["checks"]:
    if c["id"] == "output" and c["what"].startswith("выход va:"): print(c["verdict"], c["what"], c["why"], sep="|")' 2>&1)"
    check "  оживлять нечего — в журнале, что клиент ищет узел сам" "yes" \
        "$(grep -q 'va: узел не отвечает — клиент ищет узел сам; жду его сообщения' "$W/d.err" && echo yes)"
    # Узел нашёлся: up с watch — возврат, и никаких следов отказа.
    rm -f "$W/down.va"
    wait_for 'grep -q "\"ev\":\"switched\",\"out\":\"vv\",\"from\":\"vb\"" "$W/sub.out"' 40
    check "клиент vless пишет up — пул вернулся на va" \
        '{"v":1,"ev":"switched","out":"vv","from":"vb","to":"va","why":"preferred"}' \
        "$(grep '"ev":"switched","out":"vv","from":"vb"' "$W/sub.out")"
    wait_for '[ "$(vast)" = "False|-|False" ]' 10
    check "  status va — снова в строю, node_down нет" "False|-|False" "$(vast)"
    check "  файлов probe-* по-прежнему нет" "" "$(nofiles)"

    # Выход с обфускатором: его устройство не отвечает — оживление перезапуском помощника в демоне.
    wspec wo
    wctl reload >/dev/null
    wait_for '[ "$(wruns obfs wo)" = 2 ] && grep -q "\"ev\":\"helper-up\",\"out\":\"wo\"" "$W/sub.out" &&
              [ "$(grep -c "\"ev\":\"helper-up\",\"out\":\"wo\"" "$W/sub.out")" = 2 ]' 40
    check "оживление обфускатора: помощник перезапущен демоном" "2" "$(wruns obfs wo)"
    check "  подписчику — helper-down с причиной" \
        '{"v":1,"ev":"helper-down","out":"wo","helper":"obfs","why":"перезапуск: выход не отвечает"}' \
        "$(grep '"ev":"helper-down","out":"wo"' "$W/sub.out")"
    check "  и helper-up после подъёма" "2" "$(grep -c '"ev":"helper-up","out":"wo"' "$W/sub.out")"
    check "  в журнале — почему" "1" "$(grep -c 'supervise: obfs wo — выход не отвечает, поднимаю заново' "$W/d.err")"
    check "  ubus не звался" "" "$(cat "$W/ubus.log" 2>/dev/null)"
    check "  файлов probe-* и xsteer-*.json по-прежнему нет" "" "$(nofiles)"
    check "  журнал демона — с уровнем" "0" \
        "$(grep -v '^steer\[\(warn\|info\)\]' "$W/d.err" | grep -v '^steer dnsd: ' | grep -c .)"

    kill $SUB 2>/dev/null; wait $SUB 2>/dev/null; SUB=""
    kill -TERM $WD 2>/dev/null
    wait_for '! kill -0 $WD 2>/dev/null' 15
    WD=""
    ip link del xa; ip link del xb; ip link del wo; ip link del va; ip link del vb
else
    echo "supdmatch: нет root, своего сетевого пространства, своего /sys или $XK — сторож с супервизором пропущен"
fi

printf '\nsupdmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
