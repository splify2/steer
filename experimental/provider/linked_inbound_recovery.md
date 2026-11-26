# Experimental checked inbound selection recovery

`steer_linked_inbound_recover_checked` connects the existing participant's
`selection_startup` callback to owned-link reconciliation and the bounded
C guard snapshot verifier. This is an internal inbound-only experiment, not
registered with linked host, UI or runtime capabilities. The caller passes a
typed plan and revision derived from the same fully validated committed store
document; the selection journal must match that exact generation and digest.
The kernel listing is never the source of expected peer source or policy.

The supported plan is one peer/source IPv4 `/32`, empty ordered policy and
DIRECT default. A return-only guard, other policy, or other source geometry is
rejected. Before and after guard capture, recovery reconciles the journaled
owned WireGuard identity against pinned and current network namespace and boot,
and compares the observed effective ifindex with the record. The capture then
compares table name, recorded handle and marker, and the actual guard rules.
An inbound-specific generic-netlink check requires exactly one complete device
message, one peer with the expected public key and one expected IPv4 `/32`
AllowedIPs entry; split or ambiguous replies are refused. The expected key and
AllowedIPs come from the same caller-validated config as the revision digest;
the AllowedIPs must also match the guard source. The authenticated peer's
roaming endpoint is deliberately ignored. The local interface address is not
forced to `/32` and is not attested by this check.
Verification must succeed before selection startup cleans any other journal
entry. Private key, PSK, address, remaining device settings and packet flow are
not attested. This is not atomic against another privileged actor mutating the
namespace during or after verification.
Successful return must not be used to advertise production readiness or
authorize traffic before the remaining device verification is in place.

Inbound records use the role-specific journal provider
`wireguard-inbound-selected`. The existing role-ambiguous
`wireguard-isolated-selected` format remains unchanged for existing users and
is rejected by the inbound selection reader; there is no silent adoption or
migration. The current bounded selection reader cannot mix the two provider
roles in one journal; combined inbound/outbound ownership remains future work.
This role tag does not add a store or select a revision: `prototype_store`
remains the external authority. Existing experimental inbound-only participant
callers must open their new empty journal with `steer_draft_wg_selection_open_inbound`.

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/linked-inbound-recovery-ns.sh /tmp/opencode/inbound-recovery
SDK=/absolute/path/to/plugin-sdk sh tests/linked-inbound-participant-build.sh /tmp/opencode/inbound-participant
sh tests/wg-coordinator-build.sh /tmp/opencode/wg-coordinator
```

The netns test uses real prototype_store, participant, selected journal and
Linux backend. Its small fixed test document embeds the expected public key
and source; the fixture supplies the corresponding fixed typed config rather
than parsing a production spec. It starts separate processes against one journal/store, performs
a successful restart, then prepares a second unselected owned resource. Wrong
generation/digest, return-only role, nonempty policy, expired deadline, nft failure and renamed
owned link must fail without changing any journal file or deleting the other
link/table. Separately, changed public key, changed AllowedIPs, extra peer and
extra AllowedIPs fail closed; a changed roaming endpoint remains accepted.
Finally a real verdict mutation preserves selected table identity;
restart must return ESTALE and preserve that other resource and the journal.
The fake-backend participant test also verifies that a legacy-provider record
is rejected as inbound without cleanup. These tests do not implement complete
device attestation or combined managed host configuration.
