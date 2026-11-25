# Isolated WireGuard coordinator checkpoint

`experimental/provider/kernel_wg_coordinator.{h,c}` runs the staged fixture's
ordering on a serialized worker with explicit backend callbacks. It reuses the
existing owned-link and guard payloads in `execution_journal`; no keys or
configuration text are journaled.

1. Sync the owned link intent, then create DOWN and stage the lowered config.
2. Sync the guard intent, install DROP, and sync the exact captured handle
   before permitting the owned-link UP callback.
3. Sync the policy replacement intent and capture the replacement handle in
   its outcome. Only then return a ready candidate. Promotion and durable
   selection of the active config remain separate host operations.

Failed build/apply does not mutate the previous generation. The profile
requires disjoint staging resources, including listen ports; same-port handover
is unsupported. Recovery is explicit per transaction and validates the whole
journal before effects. It retires the owned link first, then removes only the
exact proven guard. If an outcome was lost and a table with the marker remains,
the coordinator leaves that table for reconciliation. Errors and deadlines may
leave work to recover; an apply error is not proof of cleanup.

The new standalone test uses a real temporary journal and an injected backend.
Run `sh tests/wg-coordinator-build.sh /absolute/isolated/build`. It does not
touch networking.

## Real link adapter

`kernel_wg_linux_link.{h,c}` connects the coordinator's create/stage/retire
callbacks to the composite owned WireGuard operations. It pins the worker's
network namespace and rejects the caller's outer namespace and PID 1's
namespace. It has no UP callback and is not a complete backend.

`sh tests/wg-linux-link-build.sh /absolute/isolated/build --netns` launches a
disposable namespace and exercises the new coordinator with a real link and
journal. Its guard stub deliberately fails before UP; it never calls nft.
The fixture checks the staged peer and address on the DOWN link, normal
rollback, and exact recovery after SIGKILL leaves a staged link and a durable
guard intent. Without `--netns` it only builds and checks namespace refusal.

## Guard API still needed

The current guard accessor exposes only the table name. The random marker is
private until creation, bind discards the transaction phase, and the captured
handle is private. Publication exports its phase but not the handle. The
current `nfd_inet_table_identity()` is a useful exact lookup, not a substitute
for the pre-bind identity or the transaction's captured handle.

Proposed source-only additions (keep the legacy bind hook):

```c
int steer_draft_kernel_wg_guard_plan(
    const struct steer_draft_kernel_wg_guard *, char table[26], char marker[42]);
struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_apply_owned(
    struct steer_draft_kernel_wg_guard *, const struct steer_draft_wg_guard_record *,
    int pinned_netns_fd, int publish, uint64_t deadline_ns, uint64_t *captured_handle);
int steer_draft_kernel_wg_guard_retire_record(
    const struct steer_draft_wg_guard_record *, int pinned_netns_fd, uint64_t deadline_ns);
int nfd_inet_table_identity_until(
    const char *, struct nfd_table_identity *, uint64_t deadline_ns);
```

`plan` is read-only, before bind. `apply_owned` reuses the current transaction
and echo path with `run_output_until`, validates namespace/boot and exact
name/kind/index/group, and returns the captured handle on CHANGED even when
the command errors. The managed uncertainty path must also use the group-aware
owned DOWN helper; the legacy name/kind/index check is not enough here. A fresh
lookup cannot promote UNCERTAIN to CHANGED. Before UP the host checks the
durably captured DROP handle and marker with an exact lookup, then uses the
existing owned UP primitive. `retire_record` rechecks the worker/pinned
namespace, boot, captured index absence, and table marker+handle before the
existing delete-by-handle transaction. No name-only delete or re-adoption.
All these steps must share the supplied absolute deadline.

No live guard backend, managed WG Apply, or WireGuard inbound/outbound
interoperability is claimed by this checkpoint.
