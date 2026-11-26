# C snapshot comparator for the narrow inbound guard

`steer_inbound_guard_verify` is a read-only comparison of a supplied nft JSON
snapshot against an independently supplied plan: exact table name, marker,
table handle, ifindex and canonical IPv4 source address. The sole supported
policy is one IPv4 `/32` peer, default DIRECT and no user rules. The caller must
only construct this plan after validating that exact policy and binding the
identity to the committed document. Unsupported configurations must never be
mapped to this plan. The API does not itself inspect a policy object or infer
that an address in a packet listing came from a verified WireGuard peer.

The comparator bounds input to 64 KiB and nesting to 64, requires JSON syntax,
uses the bounded `ynode` parser with duplicate-key rejection and distinguishes
quoted strings from JSON scalars. It accepts exactly nft JSON schema version 1
and the tested ordering/shape of the eight objects, known chain fields and
ordered expressions. Unknown fields, objects and expressions fail closed.
Only positive rule/chain handles, numeric packet/byte counters and nft version
strings may vary; table handle and marker must match. Counter values must fit
uint64. Ifindex is resolved against the caller's current namespace. A different
nft representation or version may be rejected intentionally.

This function does not capture a snapshot or impose an I/O deadline. A future
caller must do bounded capture under an absolute deadline (e.g. existing
`run_output_until`), validate the owned link and peer, and handle concurrent
mutation and snapshot consistency; this comparison is not an atomic netlink
proof. It is not connected to participant recovery or host Apply and advertises
no capability. Python is only used by the netns test driver, not the verifier.

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/inbound-guard-verify.sh /tmp/opencode/c-guard-verify
```

The test uses the previously accepted actual managed-guard fixture in a fresh
netns. It verifies the real snapshot, counters, changed verdict with unchanged
table identity, and invalid extra fields/expressions, duplicate keys, wrong
scalar types, invalid JSON and mismatched ifindex. No peer handshake is claimed.
