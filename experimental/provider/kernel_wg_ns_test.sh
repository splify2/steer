#!/bin/sh
# Experimental adapter lifecycle + independent kernel WireGuard interoperability.
set -eu
BIN=$(realpath "${STEER_KERNEL_WG_TEST:-/tmp/steer-kernel-wg-test}")
for tool in unshare nsenter ip wg ping; do command -v "$tool" >/dev/null || { echo "SKIP missing $tool"; exit 77; }; done
[ -x "$BIN" ] || { echo 'Missing kernel WG test runner'; exit 2; }
if [ "${STEER_KERNEL_WG_NS:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo 'SKIP root required'; exit 77; }
    export STEER_KERNEL_WG_NS=1 STEER_KERNEL_WG_TEST="$BIN"
    exec unshare -nm sh "$0"
fi
mount --make-rprivate /
mount -t sysfs sysfs /sys
umask 077
work=$(mktemp -d)
peer=''; server=''; stage=setup
cleanup() {
    code=$?
    if [ "$code" != 0 ]; then
        echo "FAIL kernel WG adapter stage: $stage" >&2
        [ ! -f "$work/server.log" ] || sed -E 's/[A-Za-z0-9+\/]{43}=/[redacted-key]/g' "$work/server.log" >&2
    fi
    if [ -n "$server" ]; then kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :; fi
    if [ -n "$peer" ]; then kill "$peer" 2>/dev/null || :; wait "$peer" 2>/dev/null || :; fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
mkdir "$work/state"
export STEER_TEST_STATE="$work/state"
ip link set lo up
wg genkey > "$work/server.key"
wg pubkey < "$work/server.key" > "$work/server.pub"
wg genkey > "$work/client.key"
wg pubkey < "$work/client.key" > "$work/client.pub"
STEER_TEST_PRIVATE=$(cat "$work/server.key")
export STEER_TEST_PRIVATE
client_pub=$(cat "$work/client.pub")
for mode in zero-private zero-public prepare-abort rollback activation-race namespace; do
    stage=$mode
    "$BIN" "$mode" srvwg 51821 10.80.0.1/24 "$client_pub" 10.80.0.2/32
    if ip link show srvwg >/dev/null 2>&1; then exit 1; fi
done
stage=existing
ip link add foreign0 type wireguard
"$BIN" existing foreign0 51821 10.80.0.1/24 "$client_pub" 10.80.0.2/32
ip link delete foreign0
start_server() {
    "$BIN" "$1" srvwg 51821 10.80.0.1/24 "$client_pub" 10.80.0.2/32 > "$work/server.log" 2>&1 &
    server=$!
    tries=0
    until grep -q '^ACTIVE$' "$work/server.log"; do
        kill -0 "$server" 2>/dev/null || return 1
        tries=$((tries+1)); [ "$tries" -lt 30 ] || return 1
        sleep 0.1
    done
}
stage=replacement
start_server replacement
ip link delete srvwg
ip link add srvwg type dummy
kill "$server"; wait "$server"; server=''
ip -details link show srvwg | grep -q dummy
ip link delete srvwg
echo 'PASS foreign replacement kind/index is preserved'
stage=traffic-setup
unshare -n sleep 120 &
peer=$!
sleep 0.2
ip link add srvnet type veth peer name clinet
ip link set clinet netns "$peer"
ip addr add 192.0.2.1/24 dev srvnet
ip link set srvnet up
nsenter -t "$peer" -n ip link set lo up
nsenter -t "$peer" -n ip addr add 192.0.2.2/24 dev clinet
nsenter -t "$peer" -n ip link set clinet up
start_server serve
[ "$(wg show srvwg listen-port)" = 51821 ]
[ "$(wg show srvwg endpoints | cut -f2)" = '(none)' ]
nsenter -t "$peer" -n ip link add wgclient type wireguard
nsenter -t "$peer" -n wg set wgclient private-key "$work/client.key" peer "$(cat "$work/server.pub")" endpoint 192.0.2.1:51821 allowed-ips 10.80.0.1/32
nsenter -t "$peer" -n ip addr add 10.80.0.2/24 dev wgclient
nsenter -t "$peer" -n ip link set wgclient up
stage=traffic
nsenter -t "$peer" -n ping -q -c 3 -W 2 -I 10.80.0.2 10.80.0.1 > "$work/ping.log" 2>&1
[ "$(wg show srvwg latest-handshakes | cut -f2)" -gt 0 ]
case $(wg show srvwg endpoints | cut -f2) in 192.0.2.2:*) ;; *) exit 1;; esac
echo 'PASS adapter-owned endpointless kernel WG accepts independent wg traffic'
stage=retire
kill "$server"; wait "$server"; server=''
if ip link show srvwg >/dev/null 2>&1; then exit 1; fi
nsenter -t "$peer" -n ip link show wgclient >/dev/null
echo 'PASS adapter retire removes only owned interface and preserves peer'
