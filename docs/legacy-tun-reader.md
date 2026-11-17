# Legacy TUN reader overload isolation

The fallback shared TUN reader now never waits for a full worker SPSC ring. It
counts/drops that owner's excess packet and immediately continues reading other
owners. The old20ms wait happened once per full-ring packet, so64packets for one
stalled owner delayed an unrelated owner by about1.286seconds. Redirected TCP
listener benchmarks did not exercise this reader and cannot justify that wait.

No queue, allocation, slot count, worker count or protocol window was added or
increased. The per-owner accepted packet order is unchanged. Overload is not
lossless: the full owner's excess UDP packets are explicitly dropped/accounted.
The existing oversized-packet mailbox is a different path and is not validated
by this small-packet SPSC gate.

`make test` includes `tunreadermatch` in unprivileged fd-fed mode. The standalone
script supports instrumented builds:

```sh
TSAN_OPTIONS=halt_on_error=1 SANITIZE=thread sh tests/tun-reader-build.sh /tmp/reader-tsan
unshare -n -- env STEER_TEST_READER_NETNS=1 TSAN_OPTIONS=halt_on_error=1 /tmp/reader-tsan/reader --tun
```

For ASan/UBSan use `SANITIZE=address` and the corresponding halt/leak options.
Kernel mode refuses the initial namespace and creates a temporary TUN interface
inside the disposable namespace. It disables automatic IPv6 DAD/RS only on that
fixture interface, then injects real IPv4 UDP through kernel routing/TUN. It does
not change the live host network. GSO is disabled for this44byte packet test.

Three scenarios use the actual production reader/hash and SPSC implementation:
a short paced healthy baseline, a stopped owner with256retained slots followed by
64excess packets, and a recovering owner accepting64new packets after that loss.
Healthy32/64packets and recovered64packets retain exact per-flow order. The test
checks exact64drop accounting and fixed786432bytes of ring storage for two owners;
this is not a whole-process or kernel-queue RSS ceiling. Its300ms bound detects
the deterministic old1.286second head-of-line delay, not a product latency SLA.

On2026-11-17 the unchanged old reader failed both fd and actual isolated TUN modes
at about1286ms. The no-wait version passed both modes under TSan and
ASan/UBSan/LSan: actual TUN healthy worst delay was0.835–1.361ms across the three
short scenarios,64drops remained confined to the stalled owner, and64recovered
packets were ordered. These are reproducible regression snapshots, not a
throughput benchmark, full-stack soak or proof about the oversized mailbox.
