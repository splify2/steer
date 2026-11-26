# Experimental two-phase inbound DEVICE

This is an internal participant operation, not connected to linked host Apply,
not a product capability, and not a replacement for the existing eager
standalone/outbound operations. It supports only the first inbound device when
the previously committed selection has no WG. The serialized owner supplies
validated configuration, the exact previous store selection and the pending
transaction's generation/digest, and must associate the eventual receipt with
that same prepared `prototype_store` transaction. A store receipt does not
cryptographically identify a document.

`steer_linked_inbound_prepare_closed` retains its prepared guard and durably
journals the owned link and guard intent. It stages the link while DOWN, binds
the owned DROP guard, then brings the link UP under DROP. It does **not** publish
the allowing policy. The old eager APIs remain unchanged; callers must use the
closed API for this protocol and cannot use `live_commit` to promote its slot.

`steer_linked_inbound_finish_closed` has these boundaries:

* `NOT_RENAMED`: reconcile and retire the confirmed owned candidate against the
  previous selection; even successful rollback returns EIO rather than Apply
  success. A cleanup failure remains fenced for explicit recovery.
* `RENAMED` without successful sync, or a receipt/selection mismatch: retain
  resources under DROP, set `fenced` and `durable_unknown`, return EIO. A caller
  must not expose the cached previous generation as the durable revision while
  `durable_unknown` is set.
* Matching `SYNCED`: record the new durable selection in memory **before** the
  journaled allowing-policy publication. Success returns zero. Failure leaves
  the participant fenced with the new committed generation; it is not Apply
  success and must not be reported as the old durable generation.

The publication backend may report a confirmed changed kernel policy together
with an error. In that case the allowing policy can already pass traffic even
though the call returns failure and the participant remains fenced. The caller
must not mistake fencing of participant operations for kernel traffic fencing;
additional admission/quiescence handling is required before host integration.
Unknown effects and post-commit journal failures likewise require reconciliation.

The existing inbound journal's `BOUND` without `PUBLISHED` is a valid
unselected preparation. If the process exits after SYNCED but before PUBLISH,
the current selection scanner refuses the committed but unpublished generation
with EPROTO and performs no cleanup. This is a deliberate fail-closed limitation,
not automatic resumption or complete crash recovery. It does not change the
existing eager journal format or permit adoption of role-ambiguous old records.

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/linked-inbound-two-phase-ns.sh /tmp/opencode/inbound-two-phase
```

Each test case uses its own disposable Linux netns, real selection journal,
real `prototype_store`, real kernel WireGuard and nft guard, plus an independent
peer in a second disposable namespace. It asserts backend event order
`create, stage, DROP, UP, SYNCED receipt, publish`; peer handshake succeeds but
payload is blocked before receipt. It tests successful traffic after publish,
NOT_RENAMED cleanup preserving an unrelated link, RENAMED-unsynced fencing,
unchanged and confirmed-changed publication errors after sync, revision/digest
mismatch, and a separate process restart at the SYNCED-before-PUBLISH window.
The test uses fixed synthetic local key material and logs no private key or PSK.
