# Accepted flow to shared stream runtime

`route_dial.{c,h}` is an executable source-only Linux seam between a protocol
handshake and the existing stream runtime. It creates no relay, process or
event loop. The caller supplies authenticated accepted-flow metadata, an
immutable generation-bound policy callback, and an absolute monotonic deadline.
The service validates input, evaluates policy before opening any socket, and
performs a real nonblocking direct TCP connect on the existing loop. Success
returns an adopted `stream_v1` stream, usable by the same relay as other protocols.

The policy callback sees the original requested endpoint, inbound ID, generation
and host-verified stable principal ID. It must not substitute socket destination
for the requested domain or silently downgrade an authenticated user to anonymous.
NULL opaque principal plus empty principal ID explicitly represents anonymous;
the prototype's principal-ID bridge is not a central authentication service.
Non-NULL opaque handles remain unsupported until that service exists.

Metadata spans are borrowed only through the synchronous start/evaluation call.
All pending work uses an owned socket address or owned numeric bound endpoint;
no asynchronous callback borrows caller flow storage. The service independently
rejects generation mismatch. A policy error, BLOCK, unsupported action, unsupported
flow type or unimplemented domain resolution never falls back to direct connect.
Domain policy can therefore block before DNS. A domain DIRECT result uses the
optional host-shared bounded resolver when attached; otherwise it returns
UNSUPPORTED before any socket. Selectable existing protocol outbounds,
device flows and v3 configuration application remain separate implementation work.
The legacy nft/kernel routing compiler is not an in-process v3 evaluator.

Operation count bounds live pending and completed-unreleased work. Each operation
owns at most one connecting fd and one deadline timer. Cancel and timeout remove
readiness, close fd and free timer before queueing a deferred terminal callback.
Expired deadlines are also checked before ready success so event ordering cannot
turn a late connection into success. Queued success can win cancellation; success
transfers a stream reference to the caller. The caller must close/release streams
and release operations after callback return. Service destruction refuses live
operations and callback dispatch. The loop, stream runtime, policy callback and
its context must outlive the service. Quiesce/drain generation orchestration is
the host's responsibility; this service does not unload native modules.

The optional `routes_use_resolver` retains one shared pool across generations.
Policy evaluates the original requested domain, then NSS runs only on the fixed
workers. Up to eight numeric answers are tried sequentially under the same
absolute deadline; scoped IPv6 remains unsupported. Cancellation/deadline detaches
the resolver callback before freeing route state. An in-flight NSS job remains
pool-owned, so route operation release does not free memory used by a worker.
See [resolver.md](resolver.md) for pool/shutdown limits and test coverage.

Completions reuse `operations.c` and a nonblocking CLOEXEC eventfd on the existing
loop. Dispatch consumes one queue snapshot, so callbacks starting new dials yield
to another epoll iteration. Connect failure has a protocol-neutral classification
for refused/network-unreachable/host-unreachable; SOCKS can retain REP5/3/4 without
exposing native errno. TIMEOUT and CANCELLED remain common error codes.

WSL Ubuntu x86_64 Linux validation, 2026-11-17:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread \
  -Iplugin-sdk/include -Isteer/src/daemon \
  steer/experimental/provider/route_dial_test.c \
  steer/experimental/provider/route_dial.c \
  steer/experimental/provider/resolver.c \
  steer/experimental/provider/stream.c \
  steer/experimental/provider/buffers.c \
  steer/experimental/provider/operations.c steer/src/daemon/loop.c \
  -o /tmp/steer-route-test
/tmp/steer-route-test
```

Strict C11 and the same command with
`-fsanitize=address,undefined -fno-omit-frame-pointer -g` and
`ASAN_OPTIONS=detect_leaks=1` passed. Tests connect to an ephemeral local TCP
listener, read through the shared stream API, mutate caller metadata after start,
exercise pending cancellation, deadline expiry before ready dispatch, refusal
classification, generation mismatch, principal bounds, operation limits,
deferred completion/lifetime guards and fail-closed BLOCK/domain/unknown actions.
No production integration or new stable SDK compatibility is claimed. Native
allocation/epoll fault injection, route pressure fairness and non-Linux platforms
remain unverified.
