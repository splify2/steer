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
