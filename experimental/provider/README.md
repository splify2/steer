# Experimental provider host foundations

Experimental drafts using the sibling SDK's
`include/steer/draft/provider_v1.h`. This is not a complete provider host, runtime discovery,
loader, transport service, production integration, or stable ABI.

- `buffers.c`: bounded host-owned buffers, described below.
- [stream.h](stream.h): experimental Linux stream IO using the existing daemon
  loop, buffers and operations; [ownership, tests and limits](stream.md).
- [policy.h](policy.h): immutable ordered direct/block rules for accepted flows;
  [matching semantics and current limits](policy.md).
- [host.h](host.h): base SDK table over the same buffer host, with injected
  clock/log callbacks; [lifetime and service limits](host.md).
- [operations.c](operations.c): deferred completion and cancellation of synthetic
  operations; [contract and limitations](operations.md).
- [admission.c](admission.c): post-query table/metadata checks;
  [preconditions and limitations](admission.md). It does not verify or load packages.
- [lifecycle_fixture.c](lifecycle_fixture.c): source-only integration of these
  primitives with a mock C provider; [scenarios and limitations](lifecycle_fixture.md).

These services are not yet wired into the production dataplane. Standalone
fixtures and loopback protocol hosts exercise the experimental implementations.

This directory is outside `src/` and is absent from the explicit source lists
in `build/sources.mk`, `Makefile`, and Android profiles. No production source
list, export map, net1 ABI, default, or SDK header was changed by this slice.

The host tracks live buffer capacities plus allocation metadata against a
byte ceiling, and live buffers against a count ceiling. Zero-capacity buffers
still consume metadata and one slot. Host metadata and allocator overhead are
outside the byte ceiling; an allocator must impose any additional physical RAM
budget. Buffer contents are uninitialized, never secret storage. Allocation
failure clears the output and does not change accounting. Writable views require
one reference; sharing invalidates existing writable views by caller contract.

All operations and allocator callbacks must run serialized on the same owning
shard without reentry. This is an explicit precondition, not enforced thread
detection or a thread-safe implementation. The buffer primitives have no native
IO calls; the stream service and loopback hosts do use real sockets.
Foreign live buffer handles are rejected; foreign release is a no-op. Arbitrary
or forged pointers and use-after-release remain caller violations. Pointer
reuse cannot identify stale handles. Owner checks and doubly linked list unlink
are O(1); this foundation does not claim measured hot-path performance.

The architect changed draft `retain` to return `steer_pv1_error`. Retain at the
configured reference ceiling fails with RESOURCE_EXHAUSTED and leaves the count
unchanged; the ceiling may be UINT32_MAX and is checked before increment. Failed
retain transfers no reference. Release frees only the final reference. Destroy
refuses while buffers remain; it never forcibly invalidates live references.

`buffers_test.c` covers allocation and host allocation failure injection,
accounting preservation, exact byte/count ceilings, zero capacity, ceiling reuse,
foreign-host rejection, sole-owner views, retain ceiling and unchanged count,
live-buffer destroy refusal, invalid arguments and complete allocator cleanup.
Intrusive list tests cover middle, tail and head unlink while another live
buffer remains usable.
The small configured reference ceiling exercises the same preincrement guard
used for UINT32_MAX without billions of calls. Tests do not exercise shard misuse,
real integer-maximum repeated retains, async lifetimes, secrecy, transport, or
production integration.

## Executed validation

On 2026-11-17 all five standalone fixtures passed strict C11 and ASan/UBSan
execution in WSL Ubuntu x86_64 Linux (64-bit), GCC 15.2.0
(Ubuntu 15.2.0-16ubuntu1), target x86_64-linux-gnu. Each exit code was 0;
no sanitizer diagnostics occurred. From the hub root:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -Iplugin-sdk/include SOURCES -o /tmp/TEST
/tmp/TEST
```

Sources under `steer/experimental/provider/`:

- buffers: `buffers.c buffers_test.c`
- operations: `operations.c operations_test.c`
- admission: `admission.c admission_test.c`
- host: `buffers.c host_test.c`
- lifecycle: `buffers.c operations.c admission.c lifecycle_fixture.c`

Each was also compiled with `-fsanitize=address,undefined
-fno-omit-frame-pointer -g` and run with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1`.
Outputs stayed outside the checkout at `/tmp/steer-provider-validation`.
These synthetic serialized fixtures do not validate real IO, concurrency,
production integration or other platforms. Production build targets are unchanged.

## Reproducible Linux lab build

This directory now has an isolated Makefile. From this directory, with the
`plugin-sdk` and `steer-protocols` sibling checkouts present:

```sh
make unit-test BUILD=/tmp/steer-provider-build
make integration-test BUILD=/tmp/steer-provider-build
```

`unit-test` includes the five foundation fixtures plus the real socketpair
stream test. `integration-test` builds the disposable loopback-only SOCKS host
and runs its TCP tests. It does not install anything or modify routing/firewall
configuration. Neither target makes this code a production provider runtime.
The upstream client harness lives in `steer-protocols/tests/xray_socks_inbound.py`
and takes explicit host/Xray binary paths; it never downloads executables.
