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
The session probe records FD and memory while admitted sockets are still
held; this is an admission check, not 32 simultaneous transferring clients.

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
  --core "$1" --client "$2" --output "$3" --seconds 620 --windows 1' \
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

`startup_budget.py` runs 5–50 fresh managed core/UI startups and applies one
label-only revision to each fresh private state directory. It emits every
sample and p50/p95/p99; a small number of samples cannot characterize a tail.
These fresh-state timings are distinct from long-lived churn and from package
installation time.

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

### One observed Linux TCP run

On Linux x86-64 with eight CPUs in the process affinity, Core `ebe2d8e`
and Nano from the same sources ran concurrently in distinct namespaces with
UI `a687901`. Each completed 620 seconds at four reconnecting clients and
30 label-only Apply operations; every 4096-byte echo matched. The session
probe held 32 connections and the 33rd was refused on both binaries. This
does not mean 32 concurrent clients sustained data at that rate.

| Managed TCP | Full | Nano |
|---|---:|---:|
| completed reconnect/echo operations | 12,316 | 12,314 |
| offered payload bytes/s, one direction | 81,365 | 81,352 |
| echo p50/p95/p99, ms | 0.239 / 1.042 / 3.452 | 0.243 / 1.094 / 3.507 |
| Apply p50/p95/p99, ms (30 samples) | 2.647 / 6.328 / 6.936 | 2.411 / 4.184 / 4.193 |
| core PSS after warm-up, KiB, sampled after 70 s | 4,631–4,985 | 4,575–4,680 |

The PSS rose from the post-probe idle sample (1,575 / 1,267 KiB) during
warm-up; subsequent samples alone do not establish absence of leaks.
The output and companion short checks are stored under `/tmp/opencode` in
the producing environment. Run again on the actual target before proposing
numeric budgets.

The separately run full-only HY2 profile completed 620.44 seconds, 1,234
TCP and 1,234 UDP verified exchanges, 62 client connections and 31 measured
Apply calls without reported errors. The historical harness did not propagate
unexpected churn-thread exceptions, so its Apply success must not be inferred
solely from a successful process exit. TCP echo p50/p95/p99 was
1.176/2.298/5.054 ms; UDP echo was 0.360/0.724/1.736 ms. Core RSS/PSS
started at 4,024/1,976 KiB and ended at 8,224/6,448 KiB; sampled FD was
23–24 during activity. PSS grew in steps even after 70 seconds. This
observation neither proves a leak nor demonstrates a long-term plateau.
The configured pacing was about two exchanges per second; the observed
payload rate is not a saturation result. UI was not active in this
HY2-specific profile.

For the separate common legacy-control workload, the first 500 sequential
`version` requests measured p50/p95/p99 of 0.083/0.143/0.253 ms on tagged
v2.1.4 and 0.086/0.161/0.246 ms on the `ebe2d8e` legacy engine. Two short
additional runs are retained alongside it; these measurements do not
compare either dataplane with managed v3. The logical sums of stripped
core + full UI host + UI assets were 2,232,572 bytes for full and 480,172
bytes for Nano in this build. These are file sums, not installed package
sizes, and exclude shared system libraries and packaging overhead.
The 480,172-byte sum used **Nano core with the full UI host and full UI
assets**, not the Nano UI; it must not be called a Nano/Nano installation.

For separately rebuilt Core `f907c01` and UI `a687901`, the actual stripped
full/core + full/UI + full asset tree totals **2,311,028 logical bytes**
(2,033,888 + 133,256 + 143,884). The stripped Nano core + `steer-ui-nano`
+ generated `nano-assets` totals **402,418 logical bytes**
(203,032 + 92,360 + 107,026). The full asset tree includes the bundled font
licence; the Nano Makefile produces four files without fonts. The manifest
`/tmp/opencode/steer-f907-ui-a687-logical-sizes.json` records every file,
size and SHA-256. These are logical file sums, not a packaged or installed
image and not dependency-inclusive.

The revised HY2 harness propagates exceptions from its churn thread, counts
only Apply replies that advance the revision, and requires time, TCP, UDP,
reconnect and successful Apply progress in every long window. `--check`
can finish before the first 20-second Apply interval. `--windows 2 --seconds
900` runs two consecutive windows in one core process; `--no-churn` provides
an independently started, otherwise equivalent control. Churn changes only
the listener label and revision, not network topology or secret values.

```sh
python3 -B experimental/provider/hy2_long_budget_test.py
unshare -n sh -ec 'ip link set lo up; exec python3 -B experimental/provider/hy2_long_budget.py \
  --core "$1" --client "$2" --output "$3" --seconds 900 --windows 2' \
  sh /path/to/f907-core /path/to/independent-client /tmp/opencode/churn.jsonl
# Same invocation with --no-churn and a different output file for the control.
```

### Follow-up on `f907c01`: two consecutive windows

Two independent processes used the same full executable and equivalent HY2
TCP/UDP topology in separate loopback netns, concurrently on the same host.
Their generated credentials and ports differed. Each process stayed alive for
two consecutive 900-second windows; the churn process applied only label
changes, while the control did not Apply. Raw output is indexed at
`/tmp/opencode/steer-f907-budget-index.md` in the producing environment.

| Measurement | Churn, window 1 / 2 | No churn, window 1 / 2 |
|---|---:|---:|
| elapsed, seconds | 900.372 / 900.294 | 900.372 / 900.292 |
| verified TCP echoes | 1,792 / 1,792 | 1,792 / 1,792 |
| verified UDP echoes | 1,792 / 1,792 | 1,792 / 1,792 |
| client connections | 90 / 90 | 90 / 90 |
| successful Apply replies | 44 / 45 | 0 / 0 |
| PSS at window end, KiB | 5,695 / 5,705 | 2,287 / 2,308 |
| RSS at window end, KiB | 8,352 / 8,360 | 4,944 / 4,964 |
| FD at window end | 22 / 22 | 22 / 22 |

Each second window has 89 active snapshots. Sampled PSS ranged 5,690–5,703
KiB with churn and 2,286–2,308 KiB without; both had 23 active FDs in every
sample. PSS grew during the first window and the second-window samples were
nearly flat. This is an observed association, not proof of a memory leak,
allocator cause or long-term bound. The final `complete` record in the churn
file reads PSS 6,583 KiB as the concurrent control was completing, while RSS
remained 8,360 KiB: shared-page attribution can change and the exact cause
was not investigated. Both workloads were paced, not saturation tests.
