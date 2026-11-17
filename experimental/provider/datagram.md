# Experimental datagram runtime

The C draft uses `flow_v1.h`, `datagram_v1.h` and `datagram_route_v1.h`.
These are source experiments, not a released ABI; there is no Rust mirror.
The native backend runs connected UDP on the existing daemon loop with the
shared buffer, operation and bounded resolver services. A UDP connect is local
socket preparation, not remote reachability. Messages are never replayed across
DNS addresses as an implicit failover mechanism.

References and operation references carry their origin API. Callers must use
that pair, including close/release, and must not reinterpret provider handles.
PENDING transfers one buffer reference until its own callback entry; accessing,
retaining, releasing or submitting it again before then is forbidden. Sends
are atomic, including valid zero-length messages. Oversize receives discard
one whole message and report an error; there is no truncated success or EOF.

`datagram_routes.h` provides an immutable copied registry of at most 512 prepared
bindings. Each entry identifies an owner loop, backend API/context and exact
generation/class/provider-instance lease. Duplicate `(provider_id,
instance_token)` tuples are rejected. Pure policy selects an index before DNS
or backend open; invalid selection, missing domain capability and unavailable
bindings fail without a direct fallback. Native UDP is an ordinary registry
entry. The older constructor retains its single-backend DIRECT/BLOCK behavior.
Mixed-class detours and execution of an entire spec graph remain separate work.

Create a routing association for each actual protocol UDP session lifetime.
Matching inbound, principal and source identities do not merge associations.
Within it, the destination and selected binding identify a cached target.
Selection is evaluated on every new open, while an exported reference keeps
its selected origin. New destinations after a configuration reload need the
current generation's context; admitted old targets can drain their generation.

Limits bound associations, the global target count, targets per association,
completed-unreleased operations and submitted buffer bytes. Private cleanup
and quarantined origins retain admission budget. Active references and
unreleased operations prevent idle/budget eviction. The submitted-byte limit
does not include kernel socket buffers or a foreign backend's private queues;
their bounds belong to that prepared backend. Callback and cleanup dispatch
are bounded to 32 items per loop turn. Success is checked against the absolute
deadline again at publication, including cached results.
The native backend follows that open-publication boundary as well. Message IO
has a separate side-effect boundary: an already sent message or consumed
receive retains its completed result even if callback dispatch runs late.

Close cancels pending operations. After all exported references/operations
have been released, association release consumes its public handle. Independent
private context and provider/configuration pins survive until backend cleanup
returns and all callbacks quiesce. A failed provider release preserves the
opaque origin and pins in bounded quarantine; destruction refuses. Explicit
owner `retry_cleanup` examines at most 32 entries per call after provider
recovery. Malformed handles/operation tables cannot be recovered this way.
There is no automatic retry or forced module unload.
An optional pre-publication `on_drained` hook wakes the owner exactly once after
quiescence and all public/private cleanup. Notification is deferred on the
existing eventfd; destruction is refused until it returns. The host schedules
its own later collection turn, avoiding timer polling and parent-pin cycles.

Verification includes actual UDP atomic/zero/truncated-message handling,
spoof filtering, deadline/cancel ownership, idle eviction versus unreleased
operations, two identical protocol identities with isolated stale replies,
cancel versus queued native success, a running blocked resolver and shutdown
barrier, and provider release refusal/recovery. The registry test runs one and
four independent owner shards with two provider identities opening the same
destination through different reply sockets, then drains after retirement.
Selected backend immediate rejection and deferred failure never invoke another
entry, and independent provider retirement leaves configuration admission and
already exported origin IO correctly separated.
ASan/UBSan/LSan and TSan checks cover these fixtures, not a full protocol or
production multiworker soak. HY2 adapter/host integration has its own gates.
