#!/bin/sh
# Kernel WireGuard server-role baseline: Steer owns the listening device,
# independent wg configures an initiating peer. Not the new provider API.
set -eu
BIN=${STEER:-./build/steer}
BIN=$(realpath "$BIN")
for tool in unshare nsenter ip nft wg ping; do
    command -v "$tool" >/dev/null || { echo "SKIP missing $tool"; exit 77; }
done
[ -x "$BIN" ] || { echo 'Steer binary missing'; exit 2; }
if [ "${STEER_WG_INBOUND_NS:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo 'SKIP root required'; exit 77; }
    export STEER_WG_INBOUND_NS=1 STEER="$BIN"
    exec unshare -nm sh "$0"
fi
mount --make-rprivate /
mount -t sysfs sysfs /sys
umask 077
work=$(mktemp -d)
peer=''
stage=setup
# Explicit tunnel-device names must not use the reserved wg/awg/tun prefixes.
server_device=srvwg
cleanup() {
    result=$?
    if [ "$result" != 0 ]; then echo "FAIL WireGuard inbound stage: $stage" >&2; fi
    if [ -n "$peer" ]; then kill "$peer" 2>/dev/null || :; wait "$peer" 2>/dev/null || :; fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
ip link set lo up
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
wg genkey > "$work/server.key"
wg pubkey < "$work/server.key" > "$work/server.pub"
wg genkey > "$work/client.key"
wg pubkey < "$work/client.key" > "$work/client.pub"
{
    printf '[Interface]\nPrivateKey = %s\nAddress = 10.79.0.1/24\nListenPort = 51821\n' "$(cat "$work/server.key")"
    printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.79.0.2/32\n' "$(cat "$work/client.pub")"
} > "$work/server.conf"
printf '10.79.0.2/32\n' > "$work/clients.lst"
cat > "$work/spec.json" <<EOF
{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{"server":{"kind":"awg","device":"$server_device","conf":"$work/server.conf","on_fail":"drop"}},"channels":[{"name":"clients","match":{"prefixes_file":"$work/clients.lst"},"out":"server"}]}
EOF
stage=apply
"$BIN" apply --spec "$work/spec.json" --state-dir "$work/state" > "$work/apply.log" 2>&1
stage=listen-port
[ "$(wg show "$server_device" listen-port)" = 51821 ]
stage=endpointless
[ "$(wg show "$server_device" endpoints | cut -f2)" = '(none)' ]
nsenter -t "$peer" -n ip link add wgclient type wireguard
nsenter -t "$peer" -n wg set wgclient private-key "$work/client.key" \
    peer "$(cat "$work/server.pub")" endpoint 192.0.2.1:51821 allowed-ips 10.79.0.1/32
nsenter -t "$peer" -n ip addr add 10.79.0.2/24 dev wgclient
nsenter -t "$peer" -n ip link set wgclient up
stage=traffic
nsenter -t "$peer" -n ping -q -c 3 -W 2 -I 10.79.0.2 10.79.0.1 > "$work/ping.log" 2>&1
[ "$(wg show "$server_device" latest-handshakes | cut -f2)" -gt 0 ]
stage=learned-endpoint
case $(wg show "$server_device" endpoints | cut -f2) in 192.0.2.2:*) ;; *) exit 1;; esac
echo 'PASS Steer-configured endpointless WireGuard server accepts initiating wg peer and packet traffic'
"$BIN" down --state-dir "$work/state" > "$work/down.log" 2>&1
if ip link show "$server_device" >/dev/null 2>&1; then exit 1; fi
nsenter -t "$peer" -n ip link show wgclient >/dev/null
echo 'PASS server cleanup preserves independent peer'
