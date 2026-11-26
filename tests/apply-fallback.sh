#!/bin/sh
# Реальный Apply на отсутствующее устройство. Только disposable mount/net namespaces.
# STEERD=/путь/к/steerd sh tests/apply-fallback.sh
set -u
if [ "${APPLY_FALLBACK_INNER:-}" != 1 ]; then
    bin="${STEERD:-build/steerd}"
    [ -x "$bin" ] || { echo "apply-fallback: нет $bin"; exit 2; }
    bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
    script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    for t in ip nft unshare mount; do command -v "$t" >/dev/null || exit 2; done
    [ "$(id -u)" = 0 ] || { echo "apply-fallback: нужен root"; exit 2; }
    oldnet="$(readlink /proc/self/ns/net)" || exit 2
    oldmnt="$(readlink /proc/self/ns/mnt)" || exit 2
    APPLY_FALLBACK_INNER=1 OLDNET="$oldnet" OLDMNT="$oldmnt" BIN="$bin" SCRIPT="$script" \
        exec unshare -nm sh "$script"
fi
[ "$(readlink /proc/self/ns/net)" != "${OLDNET:-}" ] &&
    [ "$(readlink /proc/self/ns/mnt)" != "${OLDMNT:-}" ] &&
    [ -n "${OLDNET:-}" ] && [ -n "${OLDMNT:-}" ] || exit 2
mount --make-rprivate / || exit 2
awk_path="$(readlink -f "$(command -v awk)")" || { echo "apply-fallback: нет awk"; exit 2; }
mount -t tmpfs tmpfs /run || exit 2
mkdir -p /run/apply-fixture
cp "$BIN" /run/apply-fixture/steerd || exit 2
cp "$awk_path" /run/apply-fixture/awk || exit 2
mount -t tmpfs tmpfs /tmp || exit 2
mount -t tmpfs tmpfs /etc || exit 2
mount -t tmpfs tmpfs /var || exit 2
mount -t sysfs sysfs /sys || exit 2
mount -t proc proc /proc || exit 2
ip link set lo up || exit 2
ip link add wan0 type dummy || exit 2
ip link set wan0 up || exit 2
ip addr add 192.0.2.1/24 dev wan0 || exit 2
ip route add default dev wan0 || exit 2
mkdir -p /tmp/state /etc/steer
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "ok   $1"
    else fail=$((fail+1)); printf 'FAIL %s: expected %s, got %s\n' "$1" "$2" "$3"; fi
}
for policy in drop direct; do
    rm -rf /tmp/state
    mkdir -p /tmp/state
    nft delete table inet steer_fixture 2>/dev/null || :
    cat > /tmp/spec.json <<EOF
{"schema":2,"from_default":["192.168.1.0/24"],
 "outputs":{"vpn":{"kind":"interface","device":"missing0","on_fail":"$policy"}},
 "channels":[{"name":"all","match":{"any":true,"allow_all":true},"out":"vpn"}]}
EOF
    STEER_NFT_TABLE=steer_fixture /run/apply-fixture/steerd apply --spec /tmp/spec.json \
        --state-dir /tmp/state >"/tmp/$policy.log" 2>&1
    rc=$?
    check "$policy: код Apply" 0 "$rc"
    check "$policy: nft загружена" 0 "$(nft list table inet steer_fixture >/dev/null 2>&1; echo $?)"
    mark="$(/run/apply-fixture/awk '$1=="vpn"{print $2}' /tmp/state/registry 2>/dev/null)"
    table="$(/run/apply-fixture/awk '$1=="vpn"{print $3}' /tmp/state/registry 2>/dev/null)"
    if [ -z "$mark" ] || [ -z "$table" ]; then
        check "$policy: реестр выхода" present missing
        cat "/tmp/$policy.log"
        continue
    fi
    route="$(ip -4 route get 203.0.113.7 mark "0x$mark" 2>&1)"
    if [ "$policy" = drop ]; then
        check "drop: фактический маршрут запрещён" 1 \
            "$(printf '%s\n' "$route" | grep -Ec 'Invalid argument|unreachable|prohibit|blackhole')"
        check "drop: blackhole в таблице" 1 \
            "$(ip -4 route show table "$table" | grep -q '^blackhole default' && echo 1 || echo 0)"
    else
        check "direct: фактический маршрут через wan0" 1 \
            "$(printf '%s\n' "$route" | grep -c 'dev wan0')"
        check "direct: нет маршрута через missing0" 0 \
            "$(ip -4 route show table "$table" 2>/dev/null | grep -c 'dev missing0')"
    fi
    [ "$rc" = 0 ] || cat "/tmp/$policy.log"
done
# Живой IPv4 при выключенном IPv6 устройства — не отказ политики on_fail.
rm -rf /tmp/state
mkdir -p /tmp/state
nft delete table inet steer_fixture 2>/dev/null || :
ip link add v4only type dummy || exit 2
ip link set v4only up || exit 2
printf 1 > /proc/sys/net/ipv6/conf/v4only/disable_ipv6 || exit 2
cat >/tmp/spec.json <<'EOF'
{"schema":2,"from_default":["192.168.1.0/24"],
 "outputs":{"vpn":{"kind":"interface","device":"v4only","on_fail":"drop"}},
 "channels":[{"name":"all","match":{"any":true,"allow_all":true},"out":"vpn"}]}
EOF
STEER_NFT_TABLE=steer_fixture /run/apply-fixture/steerd apply --spec /tmp/spec.json \
    --state-dir /tmp/state >/tmp/v4only.log 2>&1
rc=$?
check "IPv4 без IPv6: код Apply" 0 "$rc"
check "IPv4 без IPv6: nft загружена" 0 "$(nft list table inet steer_fixture >/dev/null 2>&1; echo $?)"
mark="$(/run/apply-fixture/awk '$1=="vpn"{print $2}' /tmp/state/registry 2>/dev/null)"
table="$(/run/apply-fixture/awk '$1=="vpn"{print $3}' /tmp/state/registry 2>/dev/null)"
if [ -n "$mark" ] && [ -n "$table" ]; then
    check "IPv4 без IPv6: маршрут IPv4 в устройство" 1 \
        "$(ip -4 route get 203.0.113.7 mark "0x$mark" 2>/dev/null | grep -c 'dev v4only')"
    check "IPv4 без IPv6: маршрут IPv6 запрещён" 1 \
        "$(ip -6 route show table "$table" | grep -q '^prohibit default' && echo 1 || echo 0)"
else
    check "IPv4 без IPv6: реестр выхода" present missing
fi
[ "$rc" = 0 ] || cat /tmp/v4only.log
echo "apply-fallback: $pass ok, $fail fail"
[ "$fail" = 0 ]
