#!/bin/sh
# Публичный контракт вывода fit; только временные файлы и локальные устройства.
set -eu
BIN="${STEER:-./build/steer}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
printf '%s\n' 192.0.2.1 192.0.2.3 > "$T/input"
printf '%s\n' 192.0.2.200 > "$T/exclude"

run_fit() { "$BIN" fit "$T/input" --budget 1 --exclude "$T/exclude" "$@"; }
fail() { printf 'fit-output: %s\n' "$*" >&2; exit 1; }

touch "$T/punch"
chmod 0640 "$T/punch"
run_fit --punch-out "$T/punch" --report "$T/report" > "$T/out"
[ "$(cat "$T/out")" = 192.0.2.0/24 ] || fail "неверный fitted"
cmp "$T/punch" "$T/exclude"
[ "$(stat -c %a "$T/punch")" = 640 ] || fail "изменился режим прежнего файла"
grep -q '"fits":true,"punched":1' "$T/report" || fail "неверный JSON"

if [ -c /dev/full ]; then
    rc=0
    run_fit --punch-out /dev/full --report "$T/no-report" > "$T/out" 2>"$T/err" || rc=$?
    [ "$rc" -eq 2 ] || fail "сбой записи punch: код $rc вместо 2"
    [ ! -s "$T/out" ] || fail "опубликован fitted без punch"
    [ ! -e "$T/no-report" ] || fail "опубликован отчёт без punch"
    grep -q '/dev/full' "$T/err" || fail "не назван путь punch"

    rc=0
    run_fit --punch-out "$T/punch" --report "$T/no-report" > /dev/full 2>"$T/err" || rc=$?
    [ "$rc" -eq 2 ] || fail "сбой stdout: код $rc вместо 2"
    [ ! -e "$T/no-report" ] || fail "опубликован отчёт при сбое stdout"
    grep -q 'stdout' "$T/err" || fail "не назван stdout"

    rc=0
    run_fit --punch-out "$T/punch" --report /dev/full > "$T/out" 2>"$T/err" || rc=$?
    [ "$rc" -eq 2 ] || fail "сбой отчёта: код $rc вместо 2"
    grep -q '/dev/full' "$T/err" || fail "не назван путь отчёта"
fi

rc=0
run_fit --punch-out "$T/no-dir/x" > "$T/out" 2>"$T/err" || rc=$?
[ "$rc" -eq 2 ] || fail "сбой открытия punch: код $rc вместо 2"
[ ! -s "$T/out" ] || fail "опубликован fitted после отказа открытия punch"

rc=0
"$BIN" fit "$T/input" --budget 1 --levels 32 --report "$T/report" > "$T/out" || rc=$?
[ "$rc" -eq 1 ] || fail "недостаточный бюджет: код $rc вместо 1"
cmp "$T/input" "$T/out"
grep -q '"fits":false,"punched":0' "$T/report" || fail "неверный отчёт о бюджете"
echo "fit-output: все проверки прошли"
