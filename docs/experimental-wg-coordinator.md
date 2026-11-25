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

## Guard identity and recovery

`guard_plan` mints a managed marker before bind; the legacy bind hook is
unchanged for standalone callers. The managed transaction attaches the marker
at creation and validates it together with the name, family and new handle
in the transaction echo. A subsequent lookup alone cannot promote an unknown
result to CHANGED. Before UP the host checks the durably captured DROP handle
and marker using exact `inet` GETTABLE. `guard_retire_record` rechecks the
worker/pinned namespace, boot, and captured index absence through RTM_GETLINK,
then deletes only the exact observed marker+handle. These calls reuse the
existing bounded netlink and nft transaction paths under one deadline.

## Core Apply: privileged isolated profile

The optional `steer-prototype-wg-netns` binary accepts `--wg-netns-profile
--control PATH --state-dir DIR`; fd 3 must pin the outer network namespace.
The profile requires Linux root with CAP_NET_ADMIN, a different namespace
from the outer namespace and PID 1, disabled IPv4 forwarding, and an owned private state directory
containing a pre-existing owned private `wg-journal` directory. The default
prototype binary and ordinary server arguments never register this profile.
There is no fallback to existing host interfaces or services.

This uses the same Core control `STATUS`, `GET`, `VALIDATE`, and revision-CAS
`APPLY`. The frozen spec-v3 subset is one enabled builtin `wireguard:main`
inbound `vpn`, one IPv4 /24 with host-only peer AllowedIPs, env key refs, and
one `direct` or `block` device default. No arbitrary plugin fetch/lock
resolution is implied by this exact local tuple. Stage separate port/subnet
resources; no same-port or overlapping-prefix replacement. The profile
only claims device inbound in its own namespace and LAN-local testing,
not WireGuard outbound, generic routing, or production use.

`prototype_store`'s config rename and directory sync are the only commit
decision. The bounded device journal stores link and guard identities keyed by
revision and profile-domain digest of exact canonical JSON. Startup
recompiles and cross-checks the committed document, then freshly verifies
its exact UP device and guard before any cleanup. Missing or ambiguous live
state blocks startup, not fallback/adoption. Before rename, only the failed
candidate can be cleaned; at RENAMED with uncertain durability, fence further
Apply and leave both generations for the next validated startup. After
SYNCED, retire the superseded generation using its reserved cleanup records.
The retained selected link and firewall remain in the disposable netns across
Core exit; neither production shutdown nor machine reboot is modeled.

Build directly from a clean source archive, with sibling source archives of
`plugin-sdk` at `fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd` and
`steer-protocols` at `cb6d369022300b8b26275d000b76021e1267f62b`. No local
guard/nft overlays or patches are required. The test starts two independent
WireGuard peers, initiates ICMP and UDP traffic from both directions, injects
a real occupied listen port, and checks live peer traffic after recovery on
both sides of the config commit. Server-initiated traffic on this inbound
device is not a spec-configured outbound; see the separate TCP profile below.

```sh
# From the workspace containing the three repositories; choose the WG Apply
# commit explicitly rather than archiving the working tree.
scratch=$(mktemp -d /tmp/opencode/wg-sources.XXXXXX)
mkdir "$scratch/steer" "$scratch/plugin-sdk" "$scratch/steer-protocols"
git -C steer archive "$STEER_WG_COMMIT" | tar -xf - -C "$scratch/steer"
git -C plugin-sdk archive fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd | tar -xf - -C "$scratch/plugin-sdk"
git -C steer-protocols archive cb6d369022300b8b26275d000b76021e1267f62b | tar -xf - -C "$scratch/steer-protocols"
cd "$scratch/steer"
out=$(mktemp -d /tmp/opencode/wg-core.XXXXXX)
make -C experimental/provider BUILD="$out" "$out/steer-prototype" \
    "$out/steer-prototype-wg-netns" "$out/wg-commit-fault.so"
unshare -n -- env TMPDIR="$out" PYTHONDONTWRITEBYTECODE=1 \
    python3 experimental/provider/prototype_wg_apply_test.py \
    "$out/steer-prototype-wg-netns" "$out/steer-prototype" "$out/wg-commit-fault.so" \
    3</proc/self/ns/net
```

For cross-protocol acceptance, the additional explicit make target
`"$out/steer-prototype-hy2-wg-netns"` takes `NGTCP2_LIB` and `WOLFSSL_SERVER_LIB`
from the optional HY2 build. Use that executable as the **first** binary in the
WG test above and as `CORE_BINARY` for Steer UI's `spec-v3-matrix-test`.
Ordinary `--config` runs the proxy profile; only `--wg-netns-profile` enters
the WG device profile, under the same namespace and fd checks described above.
These are separate invocations. To test the specific SOCKS-to-WG route, use
the outbound acceptance below with the same executable.

## Core-selected WireGuard TCP outbound

The same opt-in binary can take `--socks-port PORT` after `--state-dir DIR`.
It opens only `127.0.0.1:PORT`, uses the regular Core SOCKS CONNECT implementation
and stream router, and requires Linux `SO_BINDTOIFINDEX`. Until an outbound
document is committed, the listener rejects every CONNECT. The router has
only a WG-constrained binding in this mode; no direct or DNS binding.

For UI discovery, require `capabilities.wg_stream_outbound_netns: true` and
`capabilities.wg_stream_outbound_netns_schema: "wireguard-tcp-netns-outbound-v1"`.
[`schemas/wireguard-tcp-netns-outbound-v1.json`](schemas/wireguard-tcp-netns-outbound-v1.json)
describes `outbounds.tunnel`, not a general-purpose provider schema. The v3
document uses the same builtin plugin alias and typed env refs as inbound,
one `socks-entry` inbound with `plugin: socks:main`, `flow: [stream]`, the
matching loopback `listen` and empty `options`, and
`routing: {default: tunnel, rules: []}`. A real document is in
`experimental/provider/prototype_wg_outbound_test.py`. The schema is for form
construction; Core `VALIDATE` also enforces the cross-field invariants.
`runtimeReady` is false until an exact selected link, guard and route exist;
the capability is not a health signal. `wg_device_outbound` remains false.

The outbound needs one passive peer, a numeric IPv4 UDP endpoint outside the
route, a distinct IPv4 `/32` local source, and one explicit `/24`–`/32` route
equal to its sole AllowedIPs prefix. The route is exclusive, in the
disposable namespace's main table, and attached to the journal-owned link.
Linux requires the nexthop UP to add it, so stage it only after the durable DROP
guard and before publishing a return-traffic-only policy. STARTUP verifies the
exact route with the link and guard before cleanup. The router admits only
numeric TCP targets in the prefix, then the connector verifies the live objects
under a short deadline and binds both the owned ifindex and source address
before connect. A missing route or link never falls back to direct. Removing
the owned link also removes its attached route; no delete or
replace by prefix is used. Staging a new revision requires disjoint source,
route and listen port; role changes are not supported.

After building clean sources as above, run the outbound acceptance in a
separate disposable netns (`python3-jsonschema` is needed for the UI schema
check):

```sh
unshare -n -- env TMPDIR="$out" PYTHONDONTWRITEBYTECODE=1 \
    python3 experimental/provider/prototype_wg_outbound_test.py \
    "$out/steer-prototype-wg-netns" 3</proc/self/ns/net
```

This is IPv4 TCP through the isolated SOCKS entry, not packet forwarding,
UDP egress, general WireGuard Device ABI, namespace management, or a production
dataplane/UI integration. Short kernel checks still run on the opt-in control
owner; the general host needs a bounded worker and common device authority.
The isolated journal has no compaction or deliberate disable transition;
multi-device Apply, same-resource handover and machine-reboot recovery remain
out of scope.

## Linked spec v3 integration boundary

`kernel_wg_stream` is a generation-local native TCP socket constraint, not a
second router or configuration store. It owns a copy of the exact journal
guard identity, source and prefix and a duplicate of the pinned namespace FD.
It has no `current` pointer and no authority to retire the device. In the
isolated profile the candidate constraint is allocated and verified after
journaled staging but **before** committing the document. Failure here is
pre-commit rollback. Startup builds a new constraint only after the committed
revision has been verified. No new linked capability is registered.

The next linked profile should extend the existing Core, not dispatch into
`steer_prototype_wg_request`:

1. The opt-in namespace gate controls WG capability inventory in the ordinary
   v3 compiler. Lower one `wireguard:main/.../kernel` outbound into a normal
   `stream_outbounds` slot. SOCKS5, VLESS and Hysteria2 streams already share
   `select_stream`; use the existing ordered route action and binding index
   instead of a protocol-specific branch. WG gets its own native binding and
   no resolver. Keep the separate direct binding unchanged for flows explicitly
   routed there; use the scoped route binding below rather than the old
   namespace `main`-table route.
2. The prepare worker lowers intent and resolves keys. The serialized durable
   writer reserves lifecycle credits and stages owned link, DROP, route and
   binding; only a verified immutable candidate may enter the owner registry.
   Reserve a cleanup path even when stream preparation or listener bind fails.
   One canonical linked `prototype_store` revision is the commit decision.
   NOT_RENAMED retires only the candidate, RENAMED-but-unsynced fences cleanup
   and admission, SYNCED publishes the already allocated generation.
3. Pin the binding to the accepted flow's generation and keep the previous
   WG resource while its admitted streams drain. Never retarget a pending
   connect to the newer interface. For startup, the journal now distinguishes
   a validated committed document that intentionally has no WG (`without_wg`)
   from a missing required WG outcome. It rejects a WG record at the same
   committed generation when the document omits WG, and the next revision
   is above both the committed generation and all journal attempts. Verify a
   selected WG before retiring other identities, or fence. Test disjoint updates, no-WG
   transitions, unavailable WG without direct fallback, and ambiguous storage
   on both sides of commit. Do not advertise mixed profile support until
   independent SOCKS5/VLESS/HY2 TCP clients and a passive WG peer pass that
   test on the same committed revision.

The hook points are the ordinary `prototype_config` v3 outbound lowering,
`prototype_prepare`, `prepare_configuration`/`prepare_stream_routes` on the
owner, and `store_worker`/`writer_ready`. In particular, the current
ordinary `writer_ready` publishes on RENAMED even when not SYNCED. A future
WG-enabled generation cannot use that branch unchanged: keep both sets of
owned resources on uncertainty and fence new admissions until validated
restart. The startup-only journal sweeper is not a drain-time retirement
API. The existing staged WG path still admits only one selected WG and
rejects unreconciled candidates; it has not been connected to those hooks.

### Scoped route prerequisite

In the existing isolated outbound profile only, append `--scoped-route`
after `--socks-port PORT` and use a fresh state directory with a private
`wg-scoped-journal` instead of `wg-journal`. These state directories are
intentionally not interchangeable. The old invocation and ordinary build
are unchanged. This flag does not enable WG in linked Apply or add a
capability.

The bounded IPv4 route lives in a private table keyed by the journaled
random link group. RPDB priority 1 selects that table only for `oif` equal
to the owned interface; priority 2 terminates that lookup path with
`unreachable` rather than continuing to `main`. The connector pins the
socket to the exact ifindex and source, so this needs no shared packet mark,
does not select the encrypted UDP underlay, and does not affect unbound
direct sockets. A Linux bound-interface lookup can synthesize a link route
after a FIB failure; the connector never relies on the stop rule alone.
Before connecting it verifies the namespace, link identity and UP state,
guard, both rules, the sole exact route, and the effective TCP FIB result.
Any mismatch denies the connection. There is no unbound retry.

Staging rejects nonempty private tables and RPDB selectors that can
intercept the early lookup or reference the private table, without
replacing them. Rules for a different non-inverted `oif` may coexist at the
reserved priorities. Route and rule protocol 242 is private to this
disposable profile; this is not protection against an administrator racing
or forging kernel state. Retirement requires an exact owned link and its
private route as evidence before deleting rules. If evidence has vanished
or changed, leave ambiguous rules alone and fail closed. Deleting the link
removes the route; restart verifies the committed generation before cleanup.

After building both binaries, run:

```sh
unshare -n -- env TMPDIR="$out" PYTHONDONTWRITEBYTECODE=1 \
    python3 experimental/provider/prototype_wg_outbound_test.py \
    "$out/steer-prototype-wg-netns" --scoped-route "$out/steer-prototype" \
    3</proc/self/ns/net
```

The fixture uses an ordinary Core for the direct path (before the passive
peer's first handshake) and the opt-in Core for WG, both reaching the same
IP and TCP port with different source addresses. This checks the kernel
isolation prerequisite, not a mixed configuration in one active revision.
