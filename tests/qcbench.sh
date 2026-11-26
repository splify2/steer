#!/bin/sh
# Замер: Brutal против CUBIC на канале с потерями и задержкой (шаг 7 выпуска 1.10).
#
#     sh tests/qcbench.sh                                 умолчания ниже
#     SECS=10 DELAY=25ms LOSS=5% BPS=6250000 sh tests/qcbench.sh
#     sh tests/qcbench.sh check                           для ext-test: коротко, тихо, с проверкой
#
# СТЕНД. Два сетевых пространства имён, между ними veth, на обоих концах netem (задержка и потери
# на выходе, то есть в обе стороны — теряются и подтверждения). Сервер (tests/qcserver.c) в одном,
# клиент (tests/qcbench.c) в другом: не loopback, а настоящее ядерное соединение с очередью, — и, что
# важно для соседних прогонов на той же машине, netem НЕ на общем интерфейсе lo: qdisc висит на
# паре veth, которую видит только этот скрипт. Пространства и пара удаляются при любом выходе.
#
# Что меряется. Клиент льёт данные в один поток SECS секунд; сервер считает принятые байты и
# печатает скорость (goodput — то, что дошло и было принято приложением). CUBIC режет окно на каждую
# потерю и на канале с 5% потерь и RTT 40 мс проседает до нескольких мегабит; Brutal держит заданное
# BPS (БАЙТ/с) и поправляет отправку на потери.
#
# Нужно: root, ip(8) с netns, tc(8) с netem, собранные build/qcserver и build/qcbench (tests/ext-test.sh
# собирает их вместе с остальным). Нет чего-то — явный пропуск; PM_STRICT=1 делает его ошибкой.
set -u
BUILD=${BUILD:-build}
SECS=${SECS:-8}
DELAY=${DELAY:-20ms}
LOSS=${LOSS:-5%}
BPS=${BPS:-6250000}
MODE=${1:-report}
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
[ "$MODE" = check ] && SECS=${SECS_CHECK:-4}

skip() { echo "qcbench: ПРОПУСК — $1"; [ "${PM_STRICT:-0}" != 1 ] || exit 1; exit 0; }
[ "$(id -u)" = 0 ] || skip "нужен root (ip netns)"
command -v ip >/dev/null 2>&1 || skip "нет ip(8)"
command -v tc >/dev/null 2>&1 || skip "нет tc(8)"
command -v setsid >/dev/null 2>&1 || skip "нет setsid(1)"
[ -x "$BUILD/qcserver" ] && [ -x "$BUILD/qcbench" ] || skip "нет $BUILD/qcserver и $BUILD/qcbench (make ext-test)"
case "$SECS" in ''|*[!0-9]*) echo "qcbench: неверное время" >&2; exit 1;; esac
case "$BPS" in ''|*[!0-9]*) echo "qcbench: неверный BPS" >&2; exit 1;; esac
[ "$SECS" -gt 0 ] && [ "$SECS" -le 86400 ] && [ "$BPS" -gt 0 ] || {
    echo "qcbench: неверные параметры" >&2; exit 1;
}

ID=$$
NS_S=qcb-s-$ID
NS_C=qcb-c-$ID
LOG=$(mktemp -d) || exit 1
HAVE_S=0 HAVE_C=0 SPID= CPID= SGID= CGID= SWATCH= CWATCH= START_PID= START_FILE= WATCH_PENDING= WATCH_READY=
stop_group() {
    [ -n "$1" ] || return 0
    kill -TERM "-$1" 2>/dev/null || :
    kill -KILL "-$1" 2>/dev/null || :
}
stop_watch() {
    [ -n "$1" ] || return 0
    kill "$1" 2>/dev/null || :
    wait "$1" 2>/dev/null || :
}
# Функция запускается в фоне: тело без дополнительного subshell, чтобы $!
# обозначал именно процесс с trap, который владеет sleep и дожидается его.
watch_group() {
    timer=
    trap '[ -z "$timer" ] || { kill "$timer" 2>/dev/null || :; wait "$timer" 2>/dev/null || :; }; exit 0' TERM INT
    sleep "$1" & timer=$!
    : > "$4"
    wait "$timer" || exit 0
    : > "$3"
    kill -TERM "-$2" 2>/dev/null || :
    sleep 2 & timer=$!
    wait "$timer" || exit 0
    kill -KILL "-$2" 2>/dev/null || :
}
start_watch() {
    WATCH_READY=$3.ready
    watch_group "$1" "$2" "$3" "$WATCH_READY" & WATCH_PID=$!
    WATCH_PENDING=$WATCH_PID
    tries=0
    while [ ! -e "$3.ready" ] && [ "$tries" -lt 50 ]; do
        kill -0 "$WATCH_PID" 2>/dev/null || break
        sleep 0.1; tries=$((tries + 1))
    done
    [ -e "$3.ready" ]
}
start_group() {
    group_file=$1; START_FILE=$1; shift
    # Wrapper сообщает собственный PGID; fork у setsid не даёт надёжного wait status.
    setsid sh -c 'echo "$$" > "$1"; shift; exec "$@"' sh "$group_file" "$@" &
    START_PID=$!
    tries=0
    while [ ! -s "$group_file" ] && [ "$tries" -lt 50 ]; do
        sleep 0.1; tries=$((tries + 1))
    done
    START_GID=$(cat "$group_file" 2>/dev/null || :)
    case "$START_GID" in ''|*[!0-9]*|0|1) return 1;; esac
    [ "$START_GID" = "$START_PID" ]
}
cleanup() {
    if [ -n "$WATCH_PENDING" ]; then
        tries=0
        while [ ! -e "$WATCH_READY" ] && [ "$tries" -lt 50 ]; do
            kill -0 "$WATCH_PENDING" 2>/dev/null || break
            sleep 0.1; tries=$((tries + 1))
        done
        stop_watch "$WATCH_PENDING"
    fi
    stop_watch "$CWATCH"; stop_watch "$SWATCH"
    if [ -n "$START_PID" ]; then
        pending=$(cat "$START_FILE" 2>/dev/null || :)
        case "$pending" in ''|*[!0-9]*|0|1) :;; *) stop_group "$pending";; esac
        kill "$START_PID" 2>/dev/null || :
        wait "$START_PID" 2>/dev/null || :
    fi
    stop_group "$CGID"; stop_group "$SGID"
    [ -z "$CPID" ] || { kill "$CPID" 2>/dev/null || :; wait "$CPID" 2>/dev/null || :; }
    [ -z "$SPID" ] || { kill "$SPID" 2>/dev/null || :; wait "$SPID" 2>/dev/null || :; }
    [ "$HAVE_S" = 0 ] || ip netns del "$NS_S" 2>/dev/null || :
    [ "$HAVE_C" = 0 ] || ip netns del "$NS_C" 2>/dev/null || :
    # KEEP=1 — оставить журналы сервера и клиента (разбор отказа): путь напечатан ниже.
    if [ -n "${KEEP:-}" ]; then echo "qcbench: журналы в $LOG"; else rm -rf "$LOG"; fi
}
trap cleanup EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

ip netns add "$NS_S" 2>/dev/null || skip "не создать пространство имён сервера"
HAVE_S=1
ip netns add "$NS_C" 2>/dev/null || skip "не создать пространство имён клиента"
HAVE_C=1
V1=qcs$ID
V2=qcc$ID
ip netns exec "$NS_S" ip link add "$V1" type veth peer name "$V2" 2>/dev/null || skip "не создать veth"
ip -n "$NS_S" link set "$V2" netns "$NS_C" || exit 1
ip -n "$NS_S" addr add 10.77.0.1/24 dev "$V1" || exit 1
ip -n "$NS_C" addr add 10.77.0.2/24 dev "$V2" || exit 1
ip -n "$NS_S" link set "$V1" up || exit 1
ip -n "$NS_C" link set "$V2" up || exit 1
ip -n "$NS_S" link set lo up || exit 1
ip -n "$NS_C" link set lo up || exit 1
for pair in "$NS_S:$V1" "$NS_C:$V2"; do
    ip netns exec "${pair%%:*}" tc qdisc add dev "${pair#*:}" root netem delay "$DELAY" loss "$LOSS" limit 20000 2>/dev/null \
        || skip "нет netem в ядре (tc qdisc add ... netem)"
done
# net.core buffer maxima могут быть общими между namespace: стенд их не меняет.

run_one() {  # ИМЯ АРГУМЕНТЫ-КЛИЕНТА…
    name=$1; shift
    start_group "$LOG/srv.$name.pgid" ip netns exec "$NS_S" "$BUILD/qcserver" --bind 10.77.0.1 --port 4433 --idle 20 > "$LOG/srv.$name" 2>"$LOG/srv.$name.err"
    started=$?; SPID=$START_PID; SGID=$START_GID; START_PID= START_FILE=
    if [ "$started" = 0 ]; then
        start_watch "$((SECS + 45))" "$SGID" "$LOG/srv.$name.timeout"
        watch_started=$?; SWATCH=$WATCH_PID; WATCH_PENDING= WATCH_READY=
        [ "$watch_started" = 0 ] || started=1
    fi
    n=0
    while [ "$started" = 0 ] && ! grep -q '^listening [0-9][0-9]*$' "$LOG/srv.$name" 2>/dev/null && [ $n -lt 50 ]; do
        kill -0 "$SPID" 2>/dev/null || break
        sleep 0.1; n=$((n + 1))
    done
    if [ "$started" = 0 ] && grep -q '^listening [0-9][0-9]*$' "$LOG/srv.$name"; then
        start_group "$LOG/cli.$name.pgid" ip netns exec "$NS_C" "$BUILD/qcbench" 10.77.0.1 4433 "$SECS" "$@" > "$LOG/cli.$name" 2>"$LOG/cli.$name.err"
        client_started=$?; CPID=$START_PID; CGID=$START_GID; START_PID= START_FILE=
        if [ "$client_started" = 0 ]; then
            start_watch "$((SECS + 35))" "$CGID" "$LOG/cli.$name.timeout"
            watch_started=$?; CWATCH=$WATCH_PID; WATCH_PENDING= WATCH_READY=
            if [ "$watch_started" = 0 ]; then
                wait "$CPID"; client_rc=$?
            else
                client_rc=125
                stop_group "$CGID"; wait "$CPID" 2>/dev/null || :
            fi
        else
            client_rc=125
        fi
        stop_group "$CGID"
        if [ "$client_started" != 0 ]; then
            kill "$CPID" 2>/dev/null || :; wait "$CPID" 2>/dev/null || :
        fi
        CPID= CGID=
        stop_watch "$CWATCH"; CWATCH=
        [ ! -e "$LOG/cli.$name.timeout" ] || client_rc=124
    else
        client_rc=125
        echo "qcbench: $name сервер не готов" >&2
        stop_group "$SGID"
        kill "$SPID" 2>/dev/null || :
    fi
    wait "$SPID"; server_rc=$?
    stop_group "$SGID"
    SPID= SGID=
    stop_watch "$SWATCH"; SWATCH=
    [ ! -e "$LOG/srv.$name.timeout" ] || server_rc=124
    printf '%s\n' "$client_rc" > "$LOG/cli.$name.rc"
    printf '%s\n' "$server_rc" > "$LOG/srv.$name.rc"
    if [ "$client_rc" -ne 0 ] || [ "$server_rc" -ne 0 ]; then
        echo "qcbench: $name клиент=$client_rc сервер=$server_rc — ПРОВАЛ" >&2
        for file in "$LOG/cli.$name" "$LOG/cli.$name.err" "$LOG/srv.$name" "$LOG/srv.$name.err"; do
            [ ! -f "$file" ] || sed "s/^/  $name: /" "$file" >&2
        done
        return 1
    fi
    if ! awk -v mode="$name" -f "$SCRIPT_DIR/qcbench-verdict.awk" "$LOG/cli.$name" "$LOG/srv.$name" > "$LOG/mbit.$name"; then
        echo "qcbench: $name неполные или некорректные итоги — ПРОВАЛ" >&2
        sed "s/^/  $name: /" "$LOG/cli.$name" "$LOG/srv.$name" >&2
        return 1
    fi
}

[ "$MODE" = check ] || echo "qcbench: RTT ${DELAY}x2, потери ${LOSS} в каждую сторону, ${SECS} с, Brutal ${BPS} байт/с ($((BPS * 8 / 1000000)) Мбит/с)"
failed=0
run_one cubic cubic || failed=1
run_one brutal brutal "$BPS" || failed=1
[ "$failed" = 0 ] || { echo "qcbench: ПРОВАЛ — результаты недостоверны"; exit 1; }
cubic=$(cat "$LOG/mbit.cubic")
brutal=$(cat "$LOG/mbit.brutal")
target=$((BPS * 8 / 1000000))
if [ "$MODE" != check ]; then
    echo "  CUBIC    goodput ${cubic} Мбит/с   ($(sed 's/^client //' "$LOG/cli.cubic"))"
    echo "  Brutal   goodput ${brutal} Мбит/с   ($(sed 's/^client //' "$LOG/cli.brutal"))  цель ${target} Мбит/с"
    exit 0
fi
# Проверка для ext-test: Brutal держит заданное (не ниже 60% цели — часть уходит на потери и разгон
# за короткий прогон), и заметно быстрее CUBIC на том же канале.
ok=$(awk -v b="$brutal" -v c="$cubic" -v t="$target" 'BEGIN { print (b >= 0.6 * t && b >= 2 * c) ? 1 : 0 }')
echo "qcbench: CUBIC ${cubic} Мбит/с, Brutal ${brutal} Мбит/с (цель ${target}): $([ "$ok" = 1 ] && echo ok || echo ПРОВАЛ)"
[ "$ok" = 1 ]
