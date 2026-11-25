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
touch networking. The concrete backend is not yet wired: it needs a guard
identity snapshot before bind, the captured handle after mutation, and precise
boot/namespace/index checks for restart cleanup. This is not managed WG Apply
in the host, nor a new WireGuard inbound/outbound support claim.
