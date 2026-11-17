# Bounded host resolver

`resolver.c` is a Linux source-only host service, shared by route generations on
the existing loop. It creates 1..4 fixed workers and 1..256 fixed job slots;
the recommended host profile is two workers and 64 jobs. No thread is created
per flow. Thread startup failure unwinds and returns an error; it never invokes
blocking resolution on the loop. Unlike legacy `gaiw`, there is no synchronous
fallback and no detached worker owning pointers into caller state.

Submission copies a validated ASCII DNS name and port into one bounded slot.
Default workers call NSS `getaddrinfo`, preserving system hosts/resolver behavior,
and return at most eight deduplicated numeric addresses. An injected worker
backend supports deterministic tests without network DNS. Backend/context must
remain alive and safe for concurrent worker calls through pool destruction.
Worker results wake an eventfd registered on the existing loop; callbacks run
only there, never inline. Callback result storage is borrowed until return.

Cancellation consumes the job handle and synchronously detaches its callback and
userdata. Queued jobs can release their slot immediately. An already running
NSS call cannot be interrupted portably: its bounded slot remains occupied until
the worker returns. Cancelled slots still count toward the limit; overload fails
instead of spawning more threads or growing a queue. Route cancellation and
deadline can therefore return terminal callbacks immediately without retaining
or later dereferencing freed route-operation state.

Each attached route generation retains the pool. Destroy refuses retained users,
active/queued/completed-unprocessed jobs and callback dispatch. Once idle it
signals worker shutdown and joins the idle workers before closing eventfd or
freeing locks/storage. The host must keep the loop and pool alive until cancelled
NSS work finishes, then destroy. No abort or early free is permitted on shutdown.
An arbitrarily stuck third-party NSS module can delay graceful shutdown; this
implementation does not claim forced cancellation or an absolute NSS shutdown
deadline. That needs process isolation or a different resolver backend.

`route_dial` evaluates the original requested domain before DNS. BLOCK never
submits a resolver job. Direct results use numeric addresses sequentially under
the original absolute dial deadline, so a failed first address can fall back to
the next. Destination port stays the requested port; scoped IPv6 is unsupported.
This service supplies default system resolution, not complete v3 DNS routing,
per-route DNS servers, cache policy, IDNA, Happy Eyeballs or DNS loop prevention.

WSL Ubuntu x86_64 Linux, 2026-11-17: strict C11 and ASan/UBSan with leak detection
passed for `resolver_test.c` and `route_domain_test.c`. Build with `-pthread`, SDK
and daemon include paths, `resolver.c` and existing `loop.c`; the route test also
links route_dial, stream, buffers and operations. Coverage:

- Fixed-slot exhaustion, queued/running cancellation and retained-pool refusal.
- Injected stuck backend while another loop fd remains responsive.
- Safe shutdown refusal until the worker returns; no cancelled callback.
- Real NSS `localhost`, without external DNS/network dependencies.
- Domain policy before DNS, multi-address fallback and actual local TCP connect.
- Route cancellation/release and deadline while DNS worker remains blocked.

The last two tests free route state before unblocking the worker and pass
sanitizers, exercising the callback-detachment lifetime boundary. Other platforms,
allocator/thread/epoll fault injection and hostile NSS implementations remain
unverified. Legacy net1/gaiw behavior is unchanged.
