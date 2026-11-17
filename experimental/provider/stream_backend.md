# Origin-owned stream companion

`plugin-sdk/include/steer/draft/stream_backend_v1.h` is a new draft companion.
The existing `stream_v1.h` remains the native socket service. A generic stream
is an opaque handle plus its origin API; it is never adopted/cast as an fd.
Operations likewise use their own origin operation API. This is source-only
prototype code, with no stable ABI/provider discovery claim.

`stream_backend.c` wraps a valid exclusively owned native stream on the same
serialized owner loop. It delegates all IO to `stream.c`, adds no sockets or
payload copies, and bounds streams, operations and submitted bytes. Completed
unreleased operations count against admission. An optional retained generation
lease transfers only on successful wrapping and is released after stream close
and all operation releases.

Finish rejects a pending write, including its queued callback, without changing
write state. Callers first consume partial byte counts and resubmit suffixes.
Completed write operation references do not otherwise block finish. Accepted
finish installs a permanent write barrier, runs asynchronously, and preserves
reads. Cancelling unresolved finish aborts the stream; queued terminal success
may win. Close is idempotent; release inside callbacks is refused.

Both native IO and wrapper completion pumps dispatch at most32 results per turn.
The wrapper also progresses at most32 finishes per turn. Its intrusive finish
queue unlinks in constant time on resolution/cancel before any callback can
release the operation. Remaining work rearms eventfd; there are no sleeps.

From this directory:

```
make BUILD=/tmp/steer-origin-stream-check \
  /tmp/steer-origin-stream-check/stream-backend-test \
  /tmp/steer-origin-stream-check/stream-backend-fairness-test
```

Strict C11/pedantic + ASan/UBSan/leak checks pass: lifecycle/admission/ownership,
partial-write finish rejection, unreleased write references, bidirectional EOF,
cancel/close and generation leases on one plus four concurrent owner loops.
The bounded owner-loop soak runs257 scenarios/771 stream leases; TSan passes
with halt_on_error enabled in the current WSL environment. This covers separate
owner loops and real socketpair IO, not shared stack/pool lifecycle, external
multi-listener traffic or future provider/backend races.
The97-operation regression cancels/releases a queued finish tail before later
pumps and verifies unrelated readiness within two bounded batches; a separate
97-native-write queue checks the same fairness guarantee.

`route_stream.c` now selects an immutable prepared binding through an ordered
policy callback before resolution. It checks exact generation, owner and actual
prepared capabilities. The native TCP binding delegates connect/DNS to the
existing route service, then returns an origin stream; it never exposes an fd
for a foreign provider. Registry, open operations and returned stream guards
retain separate binding references through their exported releases.

Public release consumes a closed handle once exported operations are released.
A layered provider's private jobs retain independent context and generation
references. A provider that violates this rule is retained in a bounded
quarantine, blocks reuse/destruction and requires explicit recovery; no automatic
release retry or premature unpin is permitted. The layered regression exercises
both proper private-job retention and a deliberately rejecting provider.

The lab host TCP relay now uses these origin refs for accepted and routed
streams, including deferred finish operations, partial-write suffixes and
separate read lifetime after FIN. Old accepted flows pin their generation;
retired generation storage is freed only after binding finalizer notification.
HY2 retains its separate legacy native route path during this migration.
Incremental VLESS outbound and spec-v3 binding execution remain subsequent work.
The wrapper/table alone does not make a provider runtime-ready.

Host migration checks pass with strict C11/pedantic, ASan/UBSan/leak detection
and TSan: configured SOCKS/VLESS TCP, original-domain policy, pinned old flows,
apply rollback and durable restart. The managed HY2 TCP/TLS suite also passes
against the shared host while retaining HY2's legacy route adapter. This does
not establish a generic HY2/VLESS outbound backend or production plugin loading.

`prototype_startup_signal_test.py` uses the separately linked
`steer-prototype-startup-signal` test binary. An occupied control socket forces
startup rollback after control allocation; `--wrap=loop_run` raises SIGTERM
before deferred binding retirement dispatch. The fixed host exits1 cleanly and
preserves the other socket. A temporary pre-fix variant reproduces ASan
heap-use-after-free, confirming this exercises the partial-cleanup signal path.
The production host has no test hook.
