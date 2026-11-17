# Draft operation completion queue

Source-only implementation of operation handle cancel/release semantics from
the draft SDK. Isolated in `experimental/provider`; not in production lists,
exports, net1, or a host service table. No IO, workers, timers, provider loading,
data payload ownership, actual IO cancellation or provider destruction barrier
is implemented. An external IO adapter must stop its work and release resources
before choosing a terminal result; this queue does not do that for it.

One queue belongs to one serialized owning shard. The same-shard/no-reentry rule
applies to allocator callbacks; completion callbacks may enqueue/start/resolve/
cancel operations and release previously completed operations, but may not
recursively dispatch. There is no locking or thread identity enforcement.
Handles must remain valid/live: forged pointers, double release, use after
successful release, exceptions/longjmp out of callbacks and destroying callback
userdata early violate the contract. No buffer host internals are reused.

Start allocates one fixed-size node and returns PENDING plus the draft API ref,
or REJECTED with non-OK error and NULL handle/API. Rejection never calls back.
The live-operation ceiling includes unresolved, queued, callback-running and
completed-unreleased nodes. Storage is bounded by one queue and at most that
many nodes; queued nodes are intrusive, so resolving/cancelling/dispatching
allocates no memory. A zero ceiling creates a queue rejecting every start.
Allocator bookkeeping overhead is outside this fixed-node accounting.

States: unresolved → queued → calling → completed → released. The first valid
resolve selects a terminal error/success and appends once in O(1). Cancel selects
CANCELLED only while unresolved; later cancellation is a no-op. Results already
queued or delivered cannot change. Terminal status and transient fields are
validated; invalid results leave unresolved state unchanged. Duplicate resolve
returns POLICY_DENIED. Neither resolve nor cancel invokes inline completion.

Dispatch snapshots queued count at entry and invokes at most the smaller of
that count and max_count. New callbacks enqueued during dispatch wait for a
later call; FIFO preserves the entry snapshot ahead of them. Recursive dispatch
is rejected and processes nothing. Callback-running nodes cannot be released;
void ABI release safely does nothing, and the checked helper reports
POLICY_DENIED. After callback returns, release consumes the handle and decrements
live count in O(1). Destroy refuses while any operation is live, including a
completed unreleased operation, or dispatch is active. Pending operations must
be resolved/cancelled, dispatched and explicitly released before destruction.

`operations_test.c` contains meaningful source tests for allocation failures,
rejected starts, table prefix, invalid results, no inline callback, first-result
wins in both cancel/success orders, repeated cancellation/resolve, early release
before/during callback, recursive dispatch/destroy refusal, callback-enqueued
work deferred to the next dispatch, count budgets, completion-unreleased limits,
explicit IO error delivery, no duplicate callback and complete allocator cleanup.
It does not test real IO, multithreading, real cancellation races, payload
ownership or production integration.

Strict C11 and ASan/UBSan execution passed on WSL Ubuntu x86_64 Linux,
GCC 15.2.0, on 2026-11-17. See [commands and scope](README.md#executed-validation).
These standalone checks do not establish production integration or concurrency safety.
No production source list or installed build target was added.
