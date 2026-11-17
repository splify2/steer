#!/bin/sh
# Source-only _ex lifecycle backend, real kernel redirect; never touches host routes.
set -eu
cd "$(dirname "$0")/.."
BIN="${STEER_FLOW_HOST:?set STEER_FLOW_HOST to the tunnel-flow-host test binary}"
BIN="$(realpath "$BIN")"
NS="steer-flow-test-$$"
WORK="$(mktemp -d)"
cleanup() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
for workers in 1 4; do
    rm -f "$WORK/fakeip.state"
    printf 'file.invalid\t198.18.0.2\t203.0.113.81\t2001:db8::81\n' > "$WORK/fakeip.state"
    ip netns add "$NS"
    ip -n "$NS" link set lo up
    ip netns exec "$NS" env STEER_TUN_THREADS="$workers" STEER_TUN_CONNECTORS=4 \
        STEER_FLOW_FAKEIP_PATH="$WORK/fakeip.state" STEER_TUN_SPARES=0 STEER_TUN_TCPPORT=9480 "$BIN" >"$WORK/host.log" 2>&1 &
    host=$!
    ready=0
    for n in $(seq 100); do
        if ip -n "$NS" link show flowtest >/dev/null 2>&1 && \
           ip netns exec "$NS" ss -ltn | grep -q ':9480'; then ready=1; break; fi
        kill -0 "$host" 2>/dev/null || break
        sleep .05
    done
    if [ "$ready" != 1 ]; then cat "$WORK/host.log"; exit 1; fi
    grep -q "потоков $workers из $workers" "$WORK/host.log" || { cat "$WORK/host.log"; exit 1; }
    ip -n "$NS" route add 203.0.113.81/32 dev flowtest
    ip -n "$NS" route add 198.18.0.0/15 dev flowtest
    ip -n "$NS" -6 route add fdfe:dcba:9876::/96 dev flowtest
    ip netns exec "$NS" nft -f - <<'NFT'
table inet steer {
 map fakeip { type ipv4_addr : ipv4_addr; elements = { 198.18.0.1 : 203.0.113.81 }; }
 map fakeip6 { type ipv6_addr : ipv6_addr; elements = { fdfe:dcba:9876::c612:1 : 2001:db8::81 }; }
}
table inet flowtest {
 chain output { type nat hook output priority -101; policy accept;
  ip daddr 203.0.113.81 tcp dport 19001-19006 redirect to :9480
  ip daddr 198.18.0.0/15 tcp dport 19001-19006 redirect to :9480
  ip6 daddr fdfe:dcba:9876::/96 tcp dport 19001-19006 redirect to :9480
 }
}
NFT
    ip netns exec "$NS" timeout 35 python3 tests/tunnel-flow-io.py "$WORK/fakeip.state" || { cat "$WORK/host.log"; exit 1; }
    # Same finite workload must not leak sockets or spawn unbounded connectors.
    fds=$(ls "/proc/$host/fd" | wc -l)
    [ "$fds" -lt 192 ] || { echo "unbounded retained descriptors: $fds"; exit 1; }
    echo "workers=$workers PASS retained_fds=$fds"
    ip netns exec "$NS" timeout 8 python3 tests/tunnel-flow-stop.py "$WORK/stop-ready" &
    stop_client=$!
    for n in $(seq 100); do [ -f "$WORK/stop-ready" ] && break; sleep .01; done
    [ -f "$WORK/stop-ready" ] || { echo "shutdown admissions did not connect"; exit 1; }
    ip -n "$NS" link delete flowtest
    stopped=0
    for n in $(seq 100); do
        if ! kill -0 "$host" 2>/dev/null; then stopped=1; break; fi
        sleep .03
    done
    [ "$stopped" = 1 ] || { echo "worker shutdown stalled"; cat "$WORK/host.log"; exit 1; }
    host_status=0
    wait "$host" 2>/dev/null || host_status=$?
    [ "$host_status" = 1 ] || { echo "unexpected host exit: $host_status"; cat "$WORK/host.log"; exit 1; }
    if grep -Eq 'ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|DEADLYSIGNAL' "$WORK/host.log"; then
        cat "$WORK/host.log"; exit 1
    fi
    touch "$WORK/stop-ready.stopped"
    wait "$stop_client"
    rm -f "$WORK/stop-ready" "$WORK/stop-ready.stopped"
    ip netns delete "$NS"
done
