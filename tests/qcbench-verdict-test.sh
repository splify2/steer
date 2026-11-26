#!/bin/sh
# Replay через настоящий qcbench.sh, но без сетевых привилегий.
set -eu
PM_STRICT=0; export PM_STRICT
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/build" "$tmp/case"
cat > "$tmp/bin/ip" <<'EOF'
#!/bin/sh
if [ "$1" = netns ] && [ "$2" = exec ]; then shift 3; exec "$@"; fi
exit 0
EOF
cat > "$tmp/bin/tc" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$tmp/bin/id" <<'EOF'
#!/bin/sh
echo 0
EOF
cat > "$tmp/build/qcserver" <<'EOF'
#!/bin/sh
if [ -e "$CASE/first" ]; then mode=brutal; else mode=cubic; : > "$CASE/first"; fi
if [ -e "$CASE/unready" ]; then exit 7; fi
if [ -e "$CASE/hang" ]; then echo "$$" >> "$CASE/pids"; trap '' TERM; while :; do sleep 1; done; fi
echo 'listening 4433'
cat "$CASE/$mode.server"
exit "$(cat "$CASE/$mode.sr")"
EOF
cat > "$tmp/build/qcbench" <<'EOF'
#!/bin/sh
if [ -e "$CASE/hangclient" ]; then echo "$$" >> "$CASE/pids"; trap '' TERM; while :; do sleep 1; done; fi
cat "$CASE/$4.client"
exit "$(cat "$CASE/$4.cr")"
EOF
chmod +x "$tmp/bin/"* "$tmp/build/"*
PATH="$tmp/bin:$PATH"; export PATH
CASE="$tmp/case"; export CASE
BUILD="$tmp/build"; export BUILD
# Сам монитор должен обнаружить и прибрать усыновлённый живой процесс,
# а усыновлённый zombie — собрать, не объявляя живой утечкой.
if python3 tests/qcbench-process-test.py sh -c 'sleep 60 & exit 0' > "$tmp/monitor" 2>&1; then
    echo 'монитор пропустил живого потомка' >&2; exit 1
fi
grep -q 'живой процесс после возврата' "$tmp/monitor"
python3 tests/qcbench-process-test.py python3 -c \
    'import os,time; p=os.fork(); os._exit(0) if p==0 else time.sleep(.2)' > "$tmp/monitor"
reset_case() {
    rm -f "$CASE/first" "$CASE/unready" "$CASE/hang" "$CASE/hangclient" "$CASE/pids"
    printf '%s\n' 'client queued=10959138 sent=11308848 lost=504 pkts=8078 cwnd=21036 rtt_us=40204 brutal=0 replied=1' > "$CASE/cubic.client"
    printf '%s\n' 'total bytes=10959138 secs=23.99 mbit=3.5' > "$CASE/cubic.server"
    printf '%s\n' 'client queued=32883330 sent=35844454 lost=1633 pkts=24986 cwnd=527113 rtt_us=40145 brutal=1 replied=1' > "$CASE/brutal.client"
    printf '%s\n' 'total bytes=32883330 secs=5.18 mbit=50.7' > "$CASE/brutal.server"
    for f in cubic.cr cubic.sr brutal.cr brutal.sr; do echo 0 > "$CASE/$f"; done
}
pass() {
    rm -f "$CASE/first"
    if ! python3 tests/qcbench-process-test.py sh tests/qcbench.sh "$@" > "$tmp/output" 2>&1; then cat "$tmp/output"; exit 1; fi
}
fail() {
    rm -f "$CASE/first"
    if python3 tests/qcbench-process-test.py sh tests/qcbench.sh "$@" > "$tmp/output" 2>&1; then cat "$tmp/output"; echo "ошибочно прошёл: $*" >&2; exit 1; fi
    if grep -q 'живой процесс после возврата' "$tmp/output"; then cat "$tmp/output"; exit 1; fi
    grep -q 'ПРОВАЛ' "$tmp/output"
}
reset_case
pass check
grep -q 'ok' "$tmp/output"
pass report
grep -q 'goodput 50.7' "$tmp/output"
# Исходный loss5.3.v214: клиент недополучил ответ и вышел с ошибкой.
sed 's/replied=1/replied=0/' "$CASE/cubic.client" > "$CASE/cubic.tmp"
mv "$CASE/cubic.tmp" "$CASE/cubic.client"
echo 'total bytes=10348614 secs=23.99 mbit=3.5' > "$CASE/cubic.server"
echo 1 > "$CASE/cubic.cr"
fail check
fail report
# Каждый признак проверяется отдельно, даже если другой выглядит успешным.
reset_case; echo 1 > "$CASE/cubic.cr"; fail check
reset_case; echo 1 > "$CASE/brutal.sr"; fail check
reset_case; sed -i 's/replied=1/replied=0/' "$CASE/cubic.client"; fail check
reset_case; sed -i 's/bytes=10959138/bytes=10348614/' "$CASE/cubic.server"; fail check
reset_case
sed -i 's/queued=10959138/queued=9007199254740993/' "$CASE/cubic.client"
sed -i 's/bytes=10959138/bytes=9007199254740992/' "$CASE/cubic.server"
fail check
reset_case; sed -i 's/bytes=10959138/bytes=0/' "$CASE/cubic.server"; fail check
reset_case; : > "$CASE/cubic.client"; fail check
reset_case; : > "$CASE/cubic.server"; fail check
reset_case; cat "$CASE/cubic.client" >> "$CASE/cubic.client.copy"; cat "$CASE/cubic.client.copy" >> "$CASE/cubic.client"; fail check
reset_case; cat "$CASE/cubic.server" >> "$CASE/cubic.server.copy"; cat "$CASE/cubic.server.copy" >> "$CASE/cubic.server"; fail check
reset_case; sed -i 's/lost=504/lost=bad/' "$CASE/cubic.client"; fail check
reset_case; sed -i 's/mbit=3.5/mbit=3.5broken/' "$CASE/cubic.server"; fail check
reset_case; : > "$CASE/unready"; fail check
no_children() {
    [ -s "$CASE/pids" ] || { echo "нет PID тестового процесса" >&2; exit 1; }
    while read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "остался тестовый процесс $pid" >&2; exit 1
        fi
    done < "$CASE/pids"
}
reset_case; : > "$CASE/hang"
if timeout -k 2 15 python3 tests/qcbench-process-test.py sh tests/qcbench.sh check > "$tmp/output" 2>&1; then exit 1; else rc=$?; fi
no_children
[ "$rc" -ne 124 ] && [ "$rc" -ne 137 ]
if grep -q 'живой процесс после возврата' "$tmp/output"; then cat "$tmp/output"; exit 1; fi
grep -q 'ПРОВАЛ' "$tmp/output"
# SIGTERM во время старта сервера и ожидания клиента; проверяем PID вне shell стенда.
for which in hang hangclient; do
    reset_case; : > "$CASE/$which"
    python3 tests/qcbench-process-test.py sh tests/qcbench.sh check > "$tmp/output" 2>&1 & gate=$!
    tries=0
    while [ ! -s "$CASE/pids" ] && [ "$tries" -lt 100 ]; do sleep 0.1; tries=$((tries+1)); done
    [ -s "$CASE/pids" ] || { kill "$gate" 2>/dev/null || :; wait "$gate" || :; exit 1; }
    kill -TERM "$gate"
    if wait "$gate"; then echo "SIGTERM вернул успех" >&2; exit 1; fi
    no_children
    if grep -q 'живой процесс после возврата' "$tmp/output"; then cat "$tmp/output"; exit 1; fi
done
reset_case
if ! BUILD="$tmp/missing" python3 tests/qcbench-process-test.py sh tests/qcbench.sh check > "$tmp/output" 2>&1; then exit 1; fi
grep -q 'ПРОПУСК' "$tmp/output"
if PM_STRICT=1 BUILD="$tmp/missing" python3 tests/qcbench-process-test.py sh tests/qcbench.sh check > "$tmp/output" 2>&1; then exit 1; fi
grep -q 'ПРОПУСК' "$tmp/output"
echo 'qcbench verdict replay: PASS'
