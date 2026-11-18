# Universal v3 intent compiler

This is the implementation contract for the next core slice. The current
`steer-linux-v1` foreground host remains an executable checkpoint, not the
universal spec or the final acceptance target. Architecture follows
`universal-core.md` §§4–6 and the SDK's `spec-v3-draft.md` and provider draft.
Existing v1/v2 readers, package IDs and runtime ABI are preserved.

The owner requires general mechanisms. A reference client configuration is an
acceptance fixture, never a schema ceiling: no named-node special cases, fixed
group cardinalities or reference-specific routing branches. Arbitrary allowed
topologies must work within explicit resource bounds. Compiler-only acceptance
is intermediate; the final gate requires executing the reference and unrelated
topologies, including reload, rollback and restart behavior.

## Intent, typed IR and evidence

The C compiler reads bounded YAML/JSON through the existing `ynode` parser.
Duplicate keys, aliases, unknown common fields, invalid types and resource
overflows are errors. Provider `options` remain an owned subtree until an exact
provider schema validates them; an unknown provider is an explicit unavailable
dependency, not permission to ignore options. Secret values never appear in
diagnostics or compiled-plan summaries. Only typed secret references are allowed
in common fields.

Compilation reports three independent outcomes:

- `syntax_valid`: the complete document follows the accepted v3 intent contract.
- `topology_valid`: symbols, typed edges, action order and dependency phases are valid.
- `runtime_ready`: every required provider tuple, option schema, host capability,
  authorization and local lock dependency is actually satisfied.

A valid plan can be unavailable on the current host. It must then list bounded,
machine-readable diagnostic codes and field paths; it cannot silently downgrade
TLS/flow, drop a rule or choose direct. The existing minimal SDK schema does not
already implement the extended DNS/profile/secrets contract described here;
extensions must be made explicit in the SDK and checked against both consumers.

IR nodes cover inbounds, outbounds, device resources, groups, DNS servers,
rule sets, secrets, users and network profiles. IDs are namespace-qualified;
display labels do not become identity. Stream, datagram and device are distinct
port types matching the SDK flow classes. Conversion requires an explicit
adapter requirement: TUN packet classification/IP-stack and device-backed
stream/datagram dialing are not fabricated stream listeners. Transport and
security are part of provider tuples, independently from flow type.

Edges carry semantic phases:

| Edge | Check |
|---|---|
| detour, group member | construction dependency; reject cycles and type mismatch |
| DNS bootstrap, outbound server resolution, DNS transport detour | resolution/construction dependency; reject recursive bootstrap loops |
| route/default/DNS-rule target | referential and type check; not itself a construction dependency |
| health observation | probe a specific member; do not recursively select the containing group |
| secret, rule set, user, profile selection | namespace/type/reference check and capability requirement |

A single blind DAG of every reference is incorrect. The compiler builds the
construction/resolution dependency graph separately from policy and observation
graphs. URL-test probes use the selected member's dial path and explicit DNS
bootstrap context; they never route through their own group selection.

## Common contract extension

Keep the existing `version:3`, `plugin_remotes`, `plugins`, `inbounds`,
`outbounds` and `routing` structure and `provider:alias` references. Add explicit
definitions for `secrets`, `users`, `dns`, `rule_sets` and `profiles` instead of
embedding unrelated behavior inside provider options. Outbound groups retain
`type:group`, `strategy` and `members`; health policy adds interval/tolerance,
probe transport and existing-flow interruption policy. Generic detour and DNS
bootstrap references are visible dependencies.

Routing preserves ordered nonterminal sniff/resolve actions and terminal
route/reject/hijack-DNS decisions, with domain/CIDR/rule-set/network-profile
classifiers. DNS servers have explicit local/UDP/TCP/HTTPS transports, outbound
detours, bootstrap resolver and cache/strategy policy. Network profiles select
named routing/DNS defaults through platform capabilities rather than replacing
unknown chunks of configuration. Inline and remote rule sets retain format,
fetch/verification policy and offline readiness separately from rule matching.

The sanitized representative fixture uses mock nodes, example domains and env
secret references. It preserves the reference's categories: TUN mixed stack,
VLESS over WS/TLS with explicit uTLS and XUDP requirements, independent latency
groups, device-backed WireGuard paths with detours, routed DoH, profile branches
and ordered DNS/routing/rule-set behavior. Tests additionally use different
counts, nesting and protocols; passing one fixture cannot complete this work.

## Capability and execution gates

Requirements use exact inbound/outbound × stream/datagram/device ×
transport/security variants and host features. `built`, `supported`, `available`
and `authorized` are separate evidence bits. Existing legacy outbound code or a
standalone interop fixture does not establish a loaded native provider, a secret
service, a TUN capture adapter or a generation-ready backend.

The managed Linux prototype can apply the
[linked v3 subset for SOCKS5, plain VLESS TCP and optional Hysteria2 TCP/UDP](../experimental/provider/prototype_core.md#managed-spec-v3-linked-socks-v1).
It compiles the intent on a bounded worker and lowers listeners and ordered
direct/block policy into the existing generation transaction. GET and durable
recovery retain the v3 intent and revision. The full provider catalogue,
generic groups, generic datagram/device providers, network-profile activation and
routed DNS are still unavailable in the managed v3 path.

The generic compiler now represents plugin device inbounds with
`flow: [device]` and `device: {name: …}` instead of a socket `listen`.
Mixed socket and device flows are rejected. The device name is logical;
the host must mint and persist a separate physical ownership identity.
The inventory tuple for `wireguard:alias` is
`provider.wireguard:alias/inbound/device/device/none/default`. A valid
device plan is still unavailable for managed Apply until a deployed host
binds that tuple and coordinates the device and its admission guard.

Next gates: strict C compiler/reference fixtures → typed dependency tests and
capability inventory → adapters from ready IR to the existing generation/store
transaction → groups/health, routed DNS, datagram/device and platform capture →
full reference plus unrelated end-to-end topologies. No active router/server
network defaults change during compiler validation.

## Source-only executor checkpoint

`experimental/spec/execution` prepares typed construction dependencies on a
worker and binds each owner in bounded steps. Factory guards span foreign calls
and reverse cleanup; failed preparation or partial binding cannot publish a
partial generation. Rule decisions remain ordered separately from construction.

The native execution fixture routes real TCP and UDP through ordered rules,
holds old origin references across failed replacement preparation/partial bind
and a new blocked generation, and verifies their exact payload after retirement.
It runs one and four independent owners with sanitizer gates. Its worker joins
are a fixture synchronization shortcut, not the final host's async apply path.
The managed linked subset uses the prototype's listener transaction. The
general executor still needs its transaction coordinator before it can replace
that path.
Devices remain rejected until durable intent authorizes their fallible effects;
memory-only publication does not perform kernel or file operations.

The shared source-only worker and async preparation adapter now cover queued
success followed by cancellation before owner handoff, and discard on another
fixed worker after synchronized transfer. The returned cancelled execution is
retired before callback delivery; cleanup ownership is still returned. Journal
primitives preserve immutable intent/outcome/reconcile records and report
post-rename uncertainty, with bounded validated restart scans and owned orphan
temporary reporting. They are not yet a device authorization coordinator:
persisted teardown reservations, config-commit reconciliation and host v3
apply/admission integration remain required.

The bounded ownership ledger now retains durable cleanup/reconcile credits for
ACTIVE and uncertain resources. Operation intents reference an exact provider/
instance anchor across transactions; fresh grants consume physical space too.
Only a current-operation fact proving RETIRED releases unused credits. Whole
restart validation rejects missing/cross-provider anchors, duplicate grants and
stale historical reconciliation. Exhaustion refuses new effects while preserving
ownership; safe history compaction remains pending. Normal `make test` includes
the reservation regressions. The experimental device authority service matches
one exact transaction, instance and intent sequence. After an uncertain journal
write, successful storage recovery closes claims only for exact intents with a
validated durable outcome or reconciliation record. It preserves issued permits
until release and never re-enables blocked claims. A missing fact still requires
explicit reconciliation, and a durable UNKNOWN fact does not prove that the
device was retired. The host apply coordinator and managed kernel device factory
are not wired into the prototype yet.

The startup worker can now take a bounded snapshot of all non-retired anchors,
including unused anchors and ones whose last result was ACTIVE. The inventory
contains the exact keys of the current intent and its latest fact (if present),
the last sequence including grants, and remaining cleanup credits. Once the host
excludes live operations, it can spend the pending intent's reserved outcome slot
to record a lost result as UNCERTAIN. This persists the original recovery payload
and does not start device work. The configuration store also has a recovery read:
it returns the visible typed envelope, or confirms its absence, only after a
successful directory sync. `execution_startup` combines these reads for a worker
that holds both stores. It requires the host's v3 verifier and compares generation
and plan identity for the anchor and current intent separately. A later retire
intent may belong to a different generation than the anchored resource. The
production host still needs to supply its catalogue/lock verifier and reconcile
device ownership before making any publication or cleanup decision.
