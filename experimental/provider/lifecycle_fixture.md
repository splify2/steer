# Source-only lifecycle integration fixture

`lifecycle_fixture.c` connects the real experimental host/buffer table, operation
queue and post-query admission utility with a fake C provider table. No primitive
queue/buffer implementation is copied. It is a manually pumped, single-environment
mock, not a production orchestrator, native IO cancellation implementation, event
loop, upstream protocol, loader or server.

The mock query checks host prefix/layout/major and required function pointers,
then returns an immutable static descriptor/table. Trusted expected metadata and
the synthetic target tuple are explicitly fixture data; they do not describe or
detect the executing machine. `fixture-api` equality is a test expectation, not
semver negotiation. The fixture calls the actual admission validator after query.

Prepare starts an actual deferred queue operation but reserves resources only in
an explicit manual work step. A single bounded wrapper slot exposes its own opaque
operation API and holds the separate inner queue handle. Only that API interprets
the wrapper pointer; queue functions receive only the inner pointer. Cancel records
intent until the work pump cleans partial instance/buffer allocations, then selects
CANCELLED. Once resolved, the outcome is frozen and later cancellation cannot
change it. This models provider-specific cleanup before completion; blindly using
the generic queue cancel would not provide that cleanup. Wrapper release clears
the slot only after the inner checked release succeeds, after callback return.

Scenarios in source: success prepare/activate; activate failure followed by cleanup;
quiesce/drain deferred completion and explicit op release before instance destroy;
drain REJECTED not treated as a barrier; cancellation after instance/buffer reserve
unwinds before selecting completion; buffer-allocation failure unwinds the instance.
Final assertions require zero buffer accounting, queue live/queued operations and
mock instances. Fixture safe-destroy checks prevent early destroy; the mock provider
destroy also asserts its barrier preconditions. No general host enforcement exists.

The single work slot permits only one outstanding provider operation. Instance
allocation uses calloc; host buffers are bounded and only one instance is prepared
at a time. Deadlines, real IO cancellation, data-plane flows, provider isolation,
crash recovery and multi-instance scheduling are not exercised. Synthetic callbacks
perform no IO. Query/prepare inputs beyond the explicit fixture setup are not a
general production validation interface.

Strict C11 and ASan/UBSan execution passed on WSL Ubuntu x86_64 Linux,
GCC 15.2.0, on 2026-11-17. See [commands and scope](README.md#executed-validation).
These standalone checks do not establish production integration or concurrency safety.
No production source list or installed build target was added.
