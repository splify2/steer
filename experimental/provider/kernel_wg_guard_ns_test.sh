#!/bin/sh
# Experimental adapter lifecycle + independent kernel WireGuard interoperability.
set -eu
BIN=$(realpath "${STEER_KERNEL_WG_TEST:-/tmp/steer-kernel-wg-guard-test}")
for tool in unshare nsenter ip nft wg ping python3; do command -v "$tool" >/dev/null || { echo "SKIP missing $tool"; exit 77; }; done
[ -x "$BIN" ] || { echo 'Missing kernel WG test runner'; exit 2; }
if [ "${STEER_KERNEL_WG_GUARD_NS:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo 'SKIP root required'; exit 77; }
    export STEER_KERNEL_WG_GUARD_NS=1 STEER_KERNEL_WG_TEST="$BIN"
    exec unshare -nm sh "$0"
fi
mount --make-rprivate /
mount -t sysfs sysfs /sys
umask 077
server_ip=${STEER_WG_SERVER_IP:-10.80.0.1}
client_ip=${STEER_WG_CLIENT_IP:-10.80.0.2}
network_bits=${STEER_WG_NETWORK_BITS:-24}
host_bits=${STEER_WG_HOST_BITS:-32}
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
for mode in retire-index unknown-echo race replace-exit replace-unknown; do
    stage=$mode
    "$BIN" "$mode" srvwg 51821 "$server_ip/$network_bits" "$client_pub" "$client_ip/$host_bits"
    if ip link show srvwg >/dev/null 2>&1; then exit 1; fi
done
start_server() {
    "$BIN" "$1" srvwg 51821 "$server_ip/$network_bits" "$client_pub" "$client_ip/$host_bits" > "$work/server.log" 2>&1 &
    server=$!
    tries=0
    until grep -q '^ACTIVE_DROP$' "$work/server.log"; do
        kill -0 "$server" 2>/dev/null || return 1
        tries=$((tries+1)); [ "$tries" -lt 30 ] || return 1
        sleep 0.1
    done
}
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
nsenter -t "$peer" -n wg set wgclient private-key "$work/client.key" peer "$(cat "$work/server.pub")" endpoint 192.0.2.1:51821 allowed-ips "$server_ip/$host_bits"
nsenter -t "$peer" -n ip addr add "$client_ip/$network_bits" dev wgclient
nsenter -t "$peer" -n ip link set wgclient up
stage=guard-drop
if nsenter -t "$peer" -n ping -q -c 1 -W 1 -I "$client_ip" "$server_ip" > "$work/drop.log" 2>&1; then exit 1; fi
[ "$(wg show srvwg latest-handshakes | cut -f2)" -gt 0 ]
kill -USR1 "$server"
tries=0
until grep -q '^POLICY_DIRECT$' "$work/server.log"; do tries=$((tries+1)); [ "$tries" -lt 30 ] || exit 1; sleep 0.1; done
stage=traffic
nsenter -t "$peer" -n ping -q -c 3 -W 2 -I "$client_ip" "$server_ip" > "$work/ping.log" 2>&1
[ "$(wg show srvwg latest-handshakes | cut -f2)" -gt 0 ]
case $(wg show srvwg endpoints | cut -f2) in 192.0.2.2:*) ;; *) exit 1;; esac
echo 'PASS DROP before publish, verified-peer DIRECT accepts independent WG packets'
nsenter -t "$peer" -n python3 - "$server_ip" <<'PY'
import socket,sys
host=sys.argv[1]
family=socket.AF_INET6 if ':' in host else socket.AF_INET
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
    for port,blocked in ((15353,True),(15355,False)):
        with socket.socket(family,kind) as peer:
            peer.settimeout(.6)
            try:
                peer.connect((host,port))
                if kind==socket.SOCK_DGRAM:
                    peer.send(b'guard-port-gate')
                    peer.recv(64)
                raise AssertionError('unexpected open fixture port')
            except TimeoutError:
                assert blocked,'DIRECT port was dropped'
            except ConnectionRefusedError:
                assert not blocked,'BLOCK port reached host'
print('PASS TCP/UDP port rules while portless ICMP follows shared default')
PY

stage=policy-block
kill -USR2 "$server"
tries=0
until grep -q '^POLICY_BLOCK$' "$work/server.log"; do tries=$((tries+1)); [ "$tries" -lt 30 ] || exit 1; sleep 0.1; done
if nsenter -t "$peer" -n ping -q -c 1 -W 1 -I "$client_ip" "$server_ip" > "$work/drop.log" 2>&1; then exit 1; fi
stage=policy-restore
kill -USR1 "$server"
tries=0
until [ "$(grep -c '^POLICY_DIRECT$' "$work/server.log")" -ge 2 ]; do tries=$((tries+1)); [ "$tries" -lt 30 ] || exit 1; sleep 0.1; done
nsenter -t "$peer" -n ping -q -c 1 -W 2 -I "$client_ip" "$server_ip" > "$work/ping.log" 2>&1
echo 'PASS atomic per-packet BLOCK and DIRECT reload on same WG interface'
stage=retire
kill "$server"; wait "$server"; server=''
if ip link show srvwg >/dev/null 2>&1; then exit 1; fi
nsenter -t "$peer" -n ip link show wgclient >/dev/null
echo 'PASS adapter retire removes only owned interface and preserves peer'
