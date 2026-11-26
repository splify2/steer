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
  journaled allowing-policy publication. First bring the verified owned link
  DOWN and freshly confirm that state. Publish the policy while it remains DOWN;
  only after the journaled outcome is synced can the link be brought UP and
  freshly verified. Success returns zero. Failure leaves the participant fenced
  with the new committed generation; it is not Apply success and must not be
  reported as the old durable generation.

`publication_state` distinguishes NONE, CONFIRMED and UNKNOWN; a confirmed
changed policy can accompany an error. `barrier_state` distinguishes freshly
confirmed link CLOSED, confirmed OPEN and UNKNOWN. After a post-sync error the
participant attempts to close and re-observe the owned link even when policy
has changed. It must not claim a closed dataplane when that observation fails.
If the deadline expires, an ACK is lost, or ownership/state cannot be proved,
UNKNOWN requires explicit reconciliation and resources are retained; no
unconditional claim of blocked traffic is made. These are fresh checks, not
an atomic CAS against another privileged namespace actor. A DOWN/UP transition
can invalidate the WG session, so seamless peer reconnection is not claimed.

The serialized owner may instead call `steer_linked_inbound_finish_closed_shutdown`
with the same prepared slot, matching selection and store receipt, independently
of whether the requesting control socket still exists. This path never calls
allow-policy publication or barrier open. For matching SYNCED it records the
new durable selection, attempts to close and freshly confirm the owned link,
retains fencing and returns ECANCELED on confirmed closure, not Apply success.
If closure fails, its error and barrier state must be examined: UNKNOWN is not
proof of closed traffic. NOT_RENAMED reconciles only confirmed owned resources
and retains the shutdown fence; RENAMED-unsynced or a mismatch retains resources
and marks the durable selection unknown. The existing journal still refuses a
restart of a selected but unpublished generation rather than silently adopting
or cleaning it. This operation is not yet connected to the common host.

The existing inbound journal's `BOUND` without `PUBLISHED` is a valid
unselected preparation. If the process exits after SYNCED but before PUBLISH,
the current selection scanner refuses the committed but unpublished generation
with EPROTO and performs no cleanup. This is a deliberate fail-closed limitation,
not automatic resumption or complete crash recovery. It does not change the
existing eager journal format or permit adoption of role-ambiguous old records.
If the process dies after changing nft but before recording its outcome, the
same EPROTO refusal retains the independent owned-link DOWN barrier and resources.

```sh
SDK=/absolute/path/to/plugin-sdk PROTOCOLS=/absolute/path/to/steer-protocols \
  sh tests/linked-inbound-two-phase-ns.sh /tmp/opencode/inbound-two-phase
```

Each test case uses its own disposable Linux netns, real selection journal,
real `prototype_store`, real kernel WireGuard and nft guard, plus an independent
peer in a second disposable namespace. It asserts backend event order
`create, stage, DROP, UP, SYNCED receipt, DOWN, publish, journal sync, UP`;
peer handshake succeeds but payload is blocked before receipt. It tests a new
peer handshake after successful publication, NOT_RENAMED cleanup preserving an
unrelated link/table, RENAMED-unsynced fencing, confirmed-changed publication
error, lost outcome, uncertain ownership/state and an error after actual UP.
In the confirmed-closed cases the real peer cannot transfer payload. It also
checks a separately started real SOCKS lab host and pinned stream stay usable;
that is not a claim of common-host integration. Separate process restarts are
tested both before publication and after nft change but before outcome.
Shutdown cases separately exercise SYNCED, NOT_RENAMED, RENAMED-unsynced and
unconfirmed ownership: they verify no allow publication, the actual peer's
payload, on-disk document and unrelated link/table.
The test uses fixed synthetic local key material and logs no private key or PSK.
