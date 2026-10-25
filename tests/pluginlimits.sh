#!/bin/sh
# Пределы, которые мешали бы плагинам (PLUGINS.md, этап 2): число подписчиков сокета, число
# помощников, флагов резолверу и uid в --allow-uid не ограничено ничем, кроме памяти и
# RLIMIT_NOFILE (src/daemon/ctl.c, supd.c, helpers.c).
#
# Помощники не настоящие: шов STEER_SUPERVISE_EXE (как у tests/supdmatch.sh) подставляет
# скрипт, который записывает «команда выход pid» и ждёт SIGTERM. Выходов — сорок, подписчиков —
# сорок (прежние пределы: восемь подписчиков, а помощников масса была ограничена массивами),
# --allow-uid и --dnsd-flag — по двадцать. Все подписчики получают ответ с кодом 0 и событие
# applied от reload; ни один не получает busy.
#
# Без python3 (подписчики держатся его сокетами) — пропуск.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "pluginlimits: python3 нет — пропускаю"; exit 0; }
if [ "${PL_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    PL_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
[ "${PL_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
D="" SUBS=""
trap 'kill $D $SUBS 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    eval "$1" && return 0
    return 1
}

N=40
cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
trap 'exit 0' TERM
while :; do sleep 0.1; done
H
chmod +x "$tmp/helper"

python3 - "$tmp/spec.json" "$N" <<'PY'
import json, sys
n = int(sys.argv[2])
out = {}
for i in range(n):
    out["o%d" % i] = {"kind": "interface", "device": "wgp%d" % i,
        "obfs": {"mode": "wg-over-tcp", "server": "10.99.0.3:4443", "listen": "127.0.0.1:%d" % (5200 + i)}}
json.dump({"schema": 2, "from_default": ["127.0.0.0/8"], "outputs": out, "channels": []}, open(sys.argv[1], "w"))
PY

ARGS=""
i=0
while [ $i -lt 20 ]; do
    ARGS="$ARGS --allow-uid $((60000 + i)) --dnsd-flag --listen-port --dnsd-flag $((15400 + i))"
    i=$((i + 1))
done
ARGS="$ARGS --allow-uid $(id -u)"
# shellcheck disable=SC2086
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" daemon --supervise $ARGS --socket "$tmp/s.sock" \
    --spec "$tmp/spec.json" --state-dir "$tmp/st" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ] && [ "$(grep -c "^obfs " "$tmp/log" 2>/dev/null)" = '$N' ]' 20
check "помощников поднято по числу выходов ($N)" "$N" "$(grep -c '^obfs ' "$tmp/log" 2>/dev/null)"
check "  и все разные" "$N" "$(grep '^obfs ' "$tmp/log" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')"
check "  демон принял сорок флагов и двадцать uid (не отказал при разборе)" "yes" \
    "$(kill -0 $D 2>/dev/null && echo yes || echo no)"
DN="$(grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | grep -o '[0-9]*$')"
if [ -n "$DN" ]; then
    check "  резолвер получил все двадцать флагов --listen-port" "20" \
        "$(tr '\0' '\n' < "/proc/$DN/cmdline" 2>/dev/null | grep -c -- '^--listen-port$')"
fi

# Сорок подписчиков держатся одним процессом: каждый шлёт subscribe и читает до закрытия.
cat > "$tmp/subs.py" <<'PY'
import socket, sys, time
path, n, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
socks = []
for i in range(n):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    s.sendall(b"subscribe\n")
    socks.append(s)
ok = 0
for s in socks:
    s.settimeout(5)
    if b'"code":0' in s.recv(4096): ok += 1
open(out + ".ok", "w").write("%d\n" % ok)
deadline = time.time() + 20
got = 0
for s in socks:
    s.settimeout(max(0.1, deadline - time.time()))
    try:
        if b'"ev":"applied"' in s.recv(4096): got += 1
    except Exception:
        pass
open(out + ".ev", "w").write("%d\n" % got)
PY
python3 "$tmp/subs.py" "$tmp/s.sock" 40 "$tmp/subs" & SUBS=$!
wait_for '[ -e "$tmp/subs.ok" ]' 10
check "сорок подписчиков одновременно: у всех ответ с кодом 0 (прежде девятому — busy)" "40" \
    "$(cat "$tmp/subs.ok" 2>/dev/null)"
"$BIN" ctl --socket "$tmp/s.sock" reload >/dev/null 2>&1
wait_for '[ -e "$tmp/subs.ev" ]' 20
check "  и каждый получает событие applied от reload" "40" "$(cat "$tmp/subs.ev" 2>/dev/null)"
check "  демон жив и помощники не перезапускались" "$N" "$(grep -c '^obfs ' "$tmp/log")"

printf '\npluginlimits: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
