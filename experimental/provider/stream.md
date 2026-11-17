# Experimental Linux stream transport

`stream.c` implements the separate SDK `draft/stream_v1.h` table over the
existing `src/daemon/loop.c`; it creates no second event loop or worker process.
It is not connected to provider discovery or the production dataplane. No
listener, SOCKS parsing, authentication, route selection, TLS or DNS is supplied.
Legacy net1 and `provider_v1.h` layouts are unchanged. Rust support for this
extension is not implemented.

The internal adoption function consumes a connected Linux stream fd on success.
All calls and callbacks run serialized on the owning loop shard. The caller
keeps the loop and buffer host alive through runtime destruction. Host owns the
fd until close; release requires close and all operation references released.
Runtime destruction refuses live streams, operations or callback dispatch.

Read/write submissions require a sole-reference host buffer and nonzero bounded
offset/length. PENDING transfers that reference until terminal callback entry;
REJECTED leaves ownership unchanged. Submission invalidates caller views.
Never resubmit, retain, release, or request writable access during transfer.
The completion returns the submitted buffer on every outcome. Lengths charge
the runtime byte budget until IO is detached, independent of kernel buffers.
Operation count also bounds completed unreleased operations; stream count is
bounded separately. No payload copies or unlimited write queues are created.

One operation per direction remains pending until its terminal callback starts.
Writes report partial success; caller resubmits remaining bytes if needed.
Read success with zero bytes means EOF and does not close the write direction.
`shutdown_write` refuses pending writes and otherwise closes only that direction.
Cancel detaches readiness and IO before enqueueing cancellation. Close removes
readiness and closes fd before cancellation callbacks. Already queued success
may win over cancel/close. Terminal callbacks use the existing operation queue,
pumped by a nonblocking CLOEXEC eventfd on the existing loop; none run inline
on submission. Each readiness callback drains its wake counter once and
dispatches only the queue snapshot. Completions queued during dispatch wake a
later epoll iteration, so a ready stream cannot form an unbounded zero-delay
timer chain. Submission attempts IO before registering readiness; immediate
success adds no per-operation fd registration. Existing pending opposite-direction
readiness is preserved or updated when detaching the completed direction.
Operation wrappers use their own origin-owned cancel/release table. Release
inside the corresponding terminal callback is refused; release after return
is required before stream destruction. Handles are trusted same-shard objects,
not a defense against stale/forged pointers or violating buffer ownership.

Validated in WSL Ubuntu x86_64 Linux on 2026-11-17:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -Iplugin-sdk/include -Isteer/src/daemon \
  steer/experimental/provider/stream_test.c \
  steer/experimental/provider/stream.c \
  steer/experimental/provider/buffers.c \
  steer/experimental/provider/operations.c steer/src/daemon/loop.c \
  -o /tmp/steer-stream-test
/tmp/steer-stream-test
```

The same build with `-fsanitize=address,undefined -fno-omit-frame-pointer -g`
and `ASAN_OPTIONS=detect_leaks=1` passed without diagnostics. Socketpair coverage
includes delayed real reads, offset delivery, concurrent-direction limits, EOF
followed by response write, partial writes, byte-budget pressure, cancellation
of blocked writes, close of pending reads, and refusal to destroy live handles.
An always-ready stream/host-work-timer chain signals an unrelated eventfd at
completion 100; its callback must run by completion 102. The chain is capped at
10000 operations plus a 3s timeout. A temporary negative-control build restoring
timer-only completion dispatch failed that fairness assertion; the eventfd build
passed. It demonstrates bounded completion
work between epoll batches and avoidance of per-immediate-IO registration churn.
Network TCP clients, routing, threaded misuse, fault-injected allocation/epoll
failures, Windows/mobile and Rust FFI remain unverified.
