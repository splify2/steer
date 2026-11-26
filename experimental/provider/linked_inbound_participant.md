# Internal linked inbound participant experiment

This is an isolated worker-side transaction participant, **not wired into the
host**, not an external schema or capability, and not an end-to-end WG ingress.
It does not open a store, decide its revision, or start a service. The owner must
open a role-scoped inbound journal with `steer_draft_wg_selection_open_inbound`;
existing role-ambiguous selection records are not adopted. See
`linked_inbound_recovery.md` for the narrow checked Linux recovery entry point.
For a first inbound device that must remain closed until the durable store
receipt, use the separate two-phase API described in
`linked_inbound_two_phase.md`; the older participant path is eager.
The owner must
first recover the common store and pass its validated exact revision/digest to
`recover`, then supply a verified inbound-only config/peer mapping and policy.
The backend and its prepared-guard slot must belong to the same serialized owner.
The caller must supply a fresh recovery verifier that verifies the exact owned
link, current netns/boot, exact guard identity and inbound policy role, and live
peer/key identity against that validated committed document. A marker or a
return-only egress guard alone is not such verification. These obligations are
not implemented by the fake verifier in the test.

Prepare compiles a real non-return-only inbound guard, plans its durable marker
and calls the existing selection journal stage. A failure fences until recovery
against the owner's durable revision. NOT_RENAMED reconciles the previous
selection. RENAMED without sync fences without deleting either side.
`steer_linked_inbound_live_commit` accepts a SYNCED success only if the
externally selected generation and digest equal the staged transaction and
`without_wg` is false. It updates memory only: no journal scan, kernel IO,
cleanup, startup recovery or interruption of bindings. Mismatch or uncertainty
fences and consumes the staged attempt; restart recovery must then use the
actual durable store selection. The serialized host is responsible for associating
the receipt and selection with the *same* store transaction and computing the
digest from its exact validated document; the store result is not a signed or
document-bound receipt. The older `finish` path does not perform this live
promotion. This experiment does not implement live host publication or
draining; startup recovery remains safe only when the owner has stopped and
joined other generation bindings.

Run independently of CI, with no privileges or network modifications:

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/linked-inbound-participant-build.sh /tmp/opencode/linked-inbound-test
```

The executable uses the real policy/guard compiler and selection journal with a
fake kernel backend. It tests return-only rejection, journaled guard ordering,
precommit failure and recovery, NOT_RENAMED cleanup, RENAMED fencing, and
restart with injected identity refusal. Additional tests use a real
`prototype_store` and journal: synced live promotion, wrong generation, digest
and `without_wg` flag, and an injected directory-fsync failure after rename. They check that
no fake-backend recovery or cleanup occurred and that the journal accepts the
new selection. Kernel operations remain simulated. This does not prove nft rules,
peer handshake, kernel identity attestation, socket traffic, crash durability of
an actual common store, or concurrent WG/SOCKS operation. Those require further
integration and isolated real-kernel tests before any capability is advertised.
