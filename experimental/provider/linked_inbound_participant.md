# Internal linked inbound participant experiment

This is an isolated worker-side transaction participant, **not wired into the
host**, not an external schema or capability, and not an end-to-end WG ingress.
It does not open a store, decide its revision, or start a service. The owner must
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
selection. RENAMED without sync fences without deleting either side. SYNCED also
fences: the owner must recover the exact selected durable document before this
experimental participant can be used again. This conservative boundary does not
implement live host publication or draining; recovery is only safe when the
owner has stopped and joined other generation bindings.

Run independently of CI, with no privileges or network modifications:

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/linked-inbound-participant-build.sh /tmp/opencode/linked-inbound-test
```

The executable uses the real policy/guard compiler and selection journal with a
fake kernel backend. It tests return-only rejection, journaled guard ordering,
precommit failure and recovery, NOT_RENAMED cleanup, RENAMED fencing, and
restart with injected identity refusal. It does not prove actual nft rules,
peer handshake, kernel identity attestation, socket traffic, crash durability of
an actual common store, or concurrent WG/SOCKS operation. Those require further
integration and isolated real-kernel tests before any capability is advertised.
