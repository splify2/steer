# TCP flow control extension candidate

`stack_run_ex`, `stack_run_fd_ex`, and `pool_run_ex` accept an immutable,
size/version checked `stack_flow_extensions` table. The old entrypoints and old
`dialer_ops`, `dialer`, and `pool_cfg` layouts remain unchanged. The candidate exports these entrypoints as ABI 1.5 in package 1.6.0. New protocol
manifests require package `^1.6.0`; ABI numbering is not a package version.
Published symbols remain in `build/net1/exports.lst` after caller migration.
This candidate has not been deployed or released.

Each owning worker latches `can_halfclose` once after its session is ready.
Only a supported session uses the new lifecycle. Unsupported providers retain
the legacy lifecycle and are not described as half-close correct. The pool
adapter passes the selected node and inner session explicitly, with the original
extension context; it uses no callback registry.

Client EOF causes an empty protocol-opening send when no request has been sent,
then an ordered `shutdown_write` after all accepted application bytes. AGAIN is
retried with existing writable/room progress; OK is accepted once. Server EOF
shuts down the client write half after its complete queued tail, while client
upload remains active. Unknown/error terminal reads reset supported TCP flows.
Both EOFs and empty provider output queues are required before final teardown.
The provider must keep accepted FIN/control state alive through its documented
close-safe teardown. A half-closed flow still obeys the normal idle/resource
policy; receiver EOF alone does not make active uploads cheap eviction victims.

Pool audit classification: the pinned pre-change source already distinguishes
node death (`dead_at`) from a latency-driven slot replacement. `pl_stale` does
not invalidate established flows merely because their live node leaves a slot;
latency measurement also has its own worker thread. Existing `tunnelmatch`
cases check old-flow survival, new-flow selection and parallel candidate probes.
These are retained baseline behaviors, not fixes introduced by this extension.

The legacy drain budget measures lack of write progress, rather than total
transfer duration. A timed-out unsent tail resets TCP instead of reporting clean
truncated EOF. A new UDP packet cannot reuse a terminal provider session.

## Verification

For a short isolated client shared-profile check, run
`LIBS=/path/to/layout RCVWND_MODE=smoke RCVWND_SECS=2 RCVWND_MAX_BYTES=4194304 sh tests/rcvwnd.sh`
inside a disposable root environment with TUN, netem and separate mount/network
namespaces. It uses the packaged `plugins/vless/bin/vless` helper and checks
window scaling, an advertised window above 64 KiB, acknowledged data and bytes
received by the test node. This bounded smoke check does not replace the full
loss/throughput fixture.

`tests/net1-compat.sh` takes separately built `OLD_LIBS` and `NEW_LIBS`
distributions. With immediate dynamic binding, the frozen VLESS, Hysteria2,
proxy, xsteer and warpbox programs pass the library probe against both providers;
their executable hashes remain unchanged. Candidate programs accept the new
provider and reject the old one. The actual VLESS/Hysteria2 modules import the
new flow-extension entrypoints. This is a binary loading/ABI gate, not a traffic
interoperability test. The export ledger retains all 142 baseline symbols and
adds seven; no published symbol was removed.

The package-manager regression separately checks that package 1.5.0 cannot
satisfy `^1.6.0`, and that the planner upgrades the dependency before installing
its new consumer. The full manager suite still has two daemon-reload fixture
failures, reproduced with both the pinned baseline and candidate in the same
environment; that suite is not reported as passing.

`make build/tunnelmatch && ./build/tunnelmatch` includes retry/order, immediate
empty request, independent directions, idle cleanup, unknown-terminal reset,
UDP reopen, and real slow-reader checks. ASan/UBSan runs use leak detection off
because the older harness keeps process-lifetime connector threads.

`make build/tunnel-flow-host` builds a test-only native TCP backend over the real
stack worker loop. As root, run:

```
STEER_FLOW_HOST=./build/tunnel-flow-host sh tests/run-tunnel-halfclose.sh
```

This creates and removes its own network namespace, TUN, and nft redirect. The
same workload runs with one and four workers: delayed response after client FIN,
server FIN followed by upload, slow exact-checksum download, immediate empty
request, reset distinction, and unrelated concurrent flows. This establishes the
stack lifecycle, not protocol interoperability or production deployment.

## Nonblocking Fake-IP admission

Only TCP redirect creates the shared refresh service. Each worker has a
nonblocking netlink socket on its existing epoll loop and at most 64 pending
accepted sockets. The cross-worker mailbox holds at most 64 queued sockets;
at most 64 more can temporarily be detached for processing. No protocol session
or policy publication exists before resolution. The original acceptance time
survives mailbox handoff: the 200 ms budget never restarts. Full queues and
unresolved deadlines fail closed; numeric destinations bypass this stage.

Replies require a kernel sender, matching sequence and original key, valid
message/attribute lengths, and no truncation. Positive IPv4/IPv6 mappings resume
the unchanged `conn_accept` policy path. Missing kernel results may use the
immutable cached file map and await a demand refresh within that same deadline.
Late replies cannot transfer an fd again. Worker teardown cancels admissions;
shared wake fds and remaining mailboxes close after all producers join.

One refresh thread reads a regular file off the dataplane: at most 131072 records
and 67108864 bytes. Invalid/incomplete/duplicate-key snapshots retain the last
complete map. Readers perform a bounded lookup/copy under a short lock; at most
current and replacement maps coexist. Loop callbacks perform no filesystem IO
or blocking netlink receive. Shutdown joins the loader before freeing state;
an unresponsive filesystem may delay that join, rather than permit early free.

`fakeipadmissionmatch` checks malformed replies, deadline and descriptor ownership,
refresh and saturation. The real worker test additionally checks actual nft and
file mappings in both IP families, numeric-flow fairness during 64 unresolved
admissions with a FIFO state path, and interface failure with open admissions.
It requires expected exit 1 and rejects sanitizer diagnostics.

The admission fixture also passes a separate ThreadSanitizer build in WSL
(`-O1 -g -fsanitize=thread -fno-omit-frame-pointer`,
`TSAN_OPTIONS=halt_on_error=1`). This covers the refresh thread interacting with
admission, snapshot replacement and service shutdown in that fixture. It is not
a race-freedom claim for the entire stack or pool, nor a sustained traffic test.

`tests/net1-compat.sh` accepts separately built `OLD_LIBS` and `NEW_LIBS`. Frozen
old protocol binaries run unchanged against both providers with `LD_BIND_NOW`;
candidate consumers must reject the older provider. `PM_FLOOR_ONLY=1` selects
the actual dependency-planner package-floor regression in `pluginmgrmatch.sh`.
