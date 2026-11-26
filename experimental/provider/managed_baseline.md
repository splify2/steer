# Managed SOCKS loopback baseline

Run the bounded black-box baseline against a disposable managed core binary:

```sh
python3 -B experimental/provider/managed_baseline.py \
  --core /absolute/path/to/steer-nano
```

Defaults are eight concurrent SOCKS5 CONNECT streams and 128 KiB per stream
(1 MiB total echoed payload). Limits are 12 clients, 512 KiB/client, 6 MiB
total and a 5–45 second load deadline. The script creates only IPv4 loopback
listeners: a local TCP echo target, a separate local HTTP GET target, the core's
private Unix control socket and managed SOCKS listener. It applies block then
direct policy generations while streams are active. Echo contents and the
expected count of 4 KiB round trips are checked; Unix GET/STATUS are checked.
Core termination is bounded and escalates to kill only after a shutdown timeout.

Output includes load-window aggregate payload throughput, per-echo-round-trip
p50/p95 latency, child FD/RSS before and after, and errors. Percentiles use the
nearest lower observed sample (`floor((n-1)*p)`). RSS is `/proc/<pid>/status`
VmRSS in KiB; FD is the number of entries in `/proc/<pid>/fd`.

This is a small, single-host Linux smoke baseline, not a capacity or release
benchmark. It measures loopback TCP plus Python scheduling and local echo,
includes generation control operations in the transfer window, and cannot
separate core CPU from kernel/client overhead. One run does not establish
repeatability, tail behavior at scale, external-network performance, other
builds/platforms, or production readiness.

## Opt-in longer Linux profiles

`managed_long_budget.py` is a separate 601–900 second, loopback-only
managed-v3 TCP profile. It refuses the initial network namespace, probes
the actual SOCKS session admission limit, then uses four clients, each
reconnecting and checking a 4096-byte echo every 200 ms. A control thread
applies a label-only revision every 20 seconds while traffic is active.
The optional `--ui-reads` adds HTTP runtime reads at two per second;
the UI is otherwise started but idle. This is offered load, not saturation
throughput. `--check --seconds 30` is only a short harness check.

`hy2_long_budget.py` separately exercises one independent Hysteria2 client
against the full core: verified TLS/QUIC, TCP 4096-byte echo, UDP 512-byte
echo, repeated client reconnect and the same label-only revision churn.
It does not make Nano support HY2. Both scripts emit exclusive-create JSONL
with hashes, startup, idle/active `/proc` RSS/PSS, FD counts, CPU ticks,
payload counts, failures and p50/p95/p99 round-trip/connect/apply latencies.
Convert CPU ticks to one-core percent as `100 * delta_ticks / CLK_TCK /
elapsed_seconds`; PSS and RSS are per process, not system totals. Percentiles
use the lower observed sample. Payload throughput counts one direction only.
JSONL is the raw instrument output, not individual per-request traces.

Example (run full and Nano with the same offered TCP load; all paths are
operator-selected task-owned files):

```sh
unshare -n sh -ec 'ip link set lo up; exec python3 -B experimental/provider/managed_long_budget.py \
  --core "$1" --ui "$2" --assets "$3" --output "$4" --seconds 620 --ui-reads' \
  sh /path/to/core /path/to/ui /path/to/assets /tmp/opencode/tcp.jsonl
unshare -n sh -ec 'ip link set lo up; exec python3 -B experimental/provider/hy2_long_budget.py \
  --core "$1" --client "$2" --output "$3" --seconds 620' \
  sh /path/to/hy2-core /path/to/independent-client /tmp/opencode/hy2.jsonl
```

`legacy_ctl_budget.py` measures an identical local `version` request on
the v2.1.4 engine and the later legacy engine, using private state and no
apply. This is a **control-plane** comparison, not a comparison of managed
SOCKS execution:

```sh
unshare -n sh -ec 'ip link set lo up; exec python3 -B experimental/provider/legacy_ctl_budget.py \
  --engine "$1" --output "$2" --requests 500' \
  sh /path/to/legacy-steerd /tmp/opencode/ctl.jsonl
```

The short `managed_baseline.py` can additionally measure a
bounded burst, but neither it nor the offered-load rate establishes line
capacity. Run profiles on a quiet machine for comparable budgets; overlapping
profiles, loopback, client scheduling, builds and shared libraries affect
results. Keep raw outputs and record exact source commits, binary hashes,
build flags, dependency provenance and namespace isolation. There are no
release thresholds in these scripts; candidate budgets require repeated
measurements on representative hardware and explicit owner approval.

For a candidate acceptance profile, record and compare: zero payload
mismatches and unexpected disconnects, completed requested churn, observed
reconnects, final/periodic FD and PSS trends after warm-up, and p50/p95/p99
for the same operation and offered rate. Report full/Nano side by side only
for common TCP work; keep full-only HY2 UDP/QUIC separate. Establish any
numeric limits only after repeated baseline runs on the target class of
machine; one isolated run is evidence for that run, not a release threshold.
