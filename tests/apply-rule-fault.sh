#!/bin/sh
# Тестовая сборка make build/steerd-rule-fault; настоящее ядро, отказ только RTM_NEWRULE.
set -u
if [ "${RULE_FAULT_INNER:-}" != 1 ]; then
    bin="${STEERD_FAULT:-build/steerd-rule-fault}"
    [ -x "$bin" ] || { echo "rule-fault: нет $bin"; exit 2; }
    bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
    script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    if [ -z "${RULE_TEST_MODE:-}" ]; then
        RULE_TEST_MODE=cli STEERD_FAULT="$bin" sh "$script" || exit 1
        RULE_TEST_MODE=ctl STEERD_FAULT="$bin" sh "$script" || exit 1
        exit 0
    fi
    [ "$(id -u)" = 0 ] || exit 2
    OLDNET="$(readlink /proc/self/ns/net)" OLDMNT="$(readlink /proc/self/ns/mnt)" \
        RULE_FAULT_INNER=1 BIN="$bin" exec unshare -nm sh "$script"
fi
[ -n "${OLDNET:-}" ] && [ -n "${OLDMNT:-}" ] &&
    [ "$(readlink /proc/self/ns/net)" != "$OLDNET" ] &&
    [ "$(readlink /proc/self/ns/mnt)" != "$OLDMNT" ] || exit 2
mount --make-rprivate / || exit 2
awk_path="$(readlink -f "$(command -v awk)")" || { echo "rule-fault: нет awk"; exit 2; }
mount -t tmpfs tmpfs /run || exit 2
mkdir -p /run/fixture
cp "$BIN" /run/fixture/steerd || exit 2
cp "$awk_path" /run/fixture/awk || exit 2
mount -t tmpfs tmpfs /tmp || exit 2
mount -t tmpfs tmpfs /etc || exit 2
mount -t tmpfs tmpfs /var || exit 2
mount -t sysfs sysfs /sys || exit 2
mkdir -p /etc/steer /tmp/state
ip link set lo up || exit 2
ip link add vpn0 type dummy || exit 2
ip link set vpn0 up || exit 2
cat >/tmp/spec.json <<'EOF'
{"schema":2,"from_default":["192.168.1.0/24"],
 "outputs":{"vpn":{"kind":"interface","device":"vpn0","on_fail":"drop","ipv6":"off"}},
 "channels":[{"name":"all","match":{"any":true,"allow_all":true},"out":"vpn"}]}
EOF
export STEER_NFT_TABLE=steer_fixture STEER_TEST_RULE_FAULT=/tmp/fault
STEER_RULE_PREF=200 /run/fixture/steerd apply --spec /tmp/spec.json --state-dir /tmp/state \
    >/tmp/initial.log 2>&1 || { cat /tmp/initial.log; exit 2; }
mark="$(/run/fixture/awk '$1=="vpn"{print $2}' /tmp/state/registry)"
table="$(/run/fixture/awk '$1=="vpn"{print $3}' /tmp/state/registry)"
old="$(ip -4 rule show | grep "^200:.*fwmark 0x$mark/.*lookup ")"
[ -n "$old" ] || { echo "rule-fault: старое правило не установлено ($mark $table)"; ip -4 rule show; cat /tmp/initial.log; exit 2; }
old_nft="$(nft list table inet steer_fixture | cksum)"
fail=0
check() {
    if [ "$2" = "$3" ]; then echo "ok   $1"
    else echo "FAIL $1: expected $2, got $3"; fail=$((fail+1)); fi
}
ctl_code() {
    python3 -c 'import json,sys
try:
    obj = json.load(sys.stdin)
    code = obj.get("code") if isinstance(obj, dict) else None
    print(code if type(code) is int else "invalid")
except (ValueError, TypeError):
    print("invalid")'
}
if [ "$RULE_TEST_MODE" = cli ]; then
touch /tmp/fault
STEER_RULE_PREF=100 /run/fixture/steerd apply --spec /tmp/spec.json --state-dir /tmp/state \
    >/tmp/fault.log 2>&1
rc=$?
check "отказ действительно внедрён" 1 "$([ -s /tmp/rule-fault-hit ] && echo 1 || echo 0)"
check "Apply сообщает отказ" 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
check "старое правило сохранилось" 1 \
    "$(ip -4 rule show | grep -Fxc "$old")"
check "старый маршрут работает" 1 \
    "$(ip -4 route get 203.0.113.7 mark "0x$mark" 2>/dev/null | grep -c 'dev vpn0')"
check "прежняя nft таблица сохранилась" 0 \
    "$(nft list table inet steer_fixture >/dev/null 2>&1; echo $?)"
check "содержимое nft не заменено" "$old_nft" "$(nft list table inet steer_fixture | cksum)"
rm /tmp/fault
STEER_RULE_PREF=100 /run/fixture/steerd apply --spec /tmp/spec.json --state-dir /tmp/state \
    >/tmp/retry.log 2>&1
check "повтор без отказа успешен" 0 "$?"
check "новое правило появилось" 1 \
    "$(ip -4 rule show | grep -c "^100:.*fwmark 0x$mark/.*lookup ")"
check "старое правило удалено после успеха" 0 "$(ip -4 rule show | grep -Fxc "$old")"
fi
# Независимый запуск ctl-serve: та же ошибка должна дойти через apply-commit до ответа ctl.
if [ "$RULE_TEST_MODE" = ctl ]; then
STEER_RULE_PREF=100 STEER_CTL_ENABLED=1 /run/fixture/steerd ctl-serve \
    --socket /tmp/ctl.sock --spec /tmp/spec.json --state-dir /tmp/state \
    --lists-dir /tmp/lists >/tmp/daemon.log 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null; wait "$daemon" 2>/dev/null' EXIT
for i in $(seq 1 100); do [ -S /tmp/ctl.sock ] && break; sleep 0.1; done
[ -S /tmp/ctl.sock ] || { cat /tmp/daemon.log; exit 2; }
sed 's/"name":"all"/"name":"changed"/' /tmp/spec.json >/tmp/candidate.json
: >/tmp/rule-fault-hit
touch /tmp/fault
response="$(/run/fixture/steerd ctl --socket /tmp/ctl.sock apply </tmp/candidate.json)"
code="$(printf '%s' "$response" | ctl_code)" || code=invalid
check "ctl: отказ действительно внедрён" 1 "$([ -s /tmp/rule-fault-hit ] && echo 1 || echo 0)"
check "ctl: корректный JSON с числовым code=1" 1 "$code"
check "ctl: пустой ответ не считается отказом" invalid "$(printf '' | ctl_code)"
check "ctl: битый JSON не считается отказом" invalid "$(printf '{' | ctl_code)"
check "ctl: строковый code не считается числом" invalid "$(printf '{\"code\":\"1\"}' | ctl_code)"
check "ctl: логический code не считается числом" invalid "$(printf '{\"code\":true}' | ctl_code)"
check "ctl: старое правило сохранилось" 1 "$(ip -4 rule show | grep -Fxc "$old")"
check "ctl: старый маршрут работает" 1 \
    "$(ip -4 route get 203.0.113.7 mark "0x$mark" 2>/dev/null | grep -c 'dev vpn0')"
check "ctl: прежняя nft таблица сохранилась" 0 \
    "$(nft list table inet steer_fixture >/dev/null 2>&1; echo $?)"
check "ctl: содержимое nft не заменено" "$old_nft" "$(nft list table inet steer_fixture | cksum)"
rm /tmp/fault
fi
[ "$fail" = 0 ] || { cat /tmp/fault.log /tmp/retry.log /tmp/daemon.log 2>/dev/null || :; }
echo "rule-fault: $fail fail"
[ "$fail" = 0 ]
