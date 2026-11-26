# Configured Linux foreground prototype

`steer-prototype` runs configured SOCKS5 and VLESS plain TCP listeners in one
foreground process, on one existing Steer loop, stream service and routing
runtime. This is an executable prototype format, not full v3 configuration, a
production daemon integration, a loaded provider package or a release.

Build and verify from the hub:

```sh
make -C steer/experimental/provider BUILD=/tmp/steer-provider-build test
```

Run with `steer-prototype --config FILE --control /private/directory/core.sock`
and optional `--state-dir /private/state-directory`.

### Experimental selected/runtime divergence

`--experimental-durable-split` opts the standalone configured host into an
experimental control contract and requires a state directory. It cannot be
combined with the existing WG netns modes. It does not enable a DEVICE, WG
inbound, or a UI capability. In this mode STATUS additionally reports
`selectedRevision`, `runtimeGeneration`, and `splitFenced`; GET returns the
selected document and revision together with the runtime generation and fence.
On a post-SYNCED runtime-publication failure the host keeps the selected
document from the same prepared transaction, retains the previous runtime,
returns an Apply error, fences subsequent Apply and sets `runtimeReady` false.
Existing SOCKS admission is not globally fenced. If durability is uncertain,
selected revision is null in STATUS and GET refuses instead of returning a
document with an unproven revision. Ordinary non-opt-in responses are unchanged.
GET is framed directly into the control output buffer; its serializer unit test
covers a maximum-size document, maximum-width revision numbers and exact-fit
and insufficient-capacity buffers. The existing `store-fault-test` also checks
split-mode directory-fsync failure and continued old SOCKS traffic.

The separate `steer-prototype-split-fault` build provides the test-only
`--test-fail-after-sync` switch; the ordinary build has no fault switch or
environment hook. The fault is injected after the real store receipt, before
runtime publication. It does not test DEVICE, peer traffic, or DEVICE restart.
For the executable control/store and pinned/new SOCKS regression, build
`steer-prototype` and `steer-prototype-split-fault` using this directory's
Makefile, and pass both paths plus a separately built pre-change baseline to
`prototype_split_test.py`. Run it in a disposable network namespace with its
loopback up. The test compares ordinary STATUS/GET against the baseline.

```sh
make -C experimental/provider BUILD=/tmp/opencode/split-build \
  SDK=/absolute/path/to/plugin-sdk PROTOCOLS=/absolute/path/to/steer-protocols \
  /tmp/opencode/split-build/steer-prototype /tmp/opencode/split-build/steer-prototype-split-fault
unshare -n sh -c 'ip link set lo up && python3 -B experimental/provider/prototype_split_test.py \
  /tmp/opencode/split-build/steer-prototype /tmp/opencode/split-build/steer-prototype-split-fault \
  /absolute/path/to/pre-change/steer-prototype'
```

The control parent directory must belong to the effective UID and have no group
or other permissions (normally mode 0700). The socket is mode 0600 and accepts
only the same effective UID through `SO_PEERCRED`. An existing socket path is
never unlinked to take ownership. SIGTERM/SIGINT close admission and drain active
IO/cancellation callbacks before releasing services and removing the owned
socket. Stdout emits one `READY <status-JSON>` line only after all initial
listeners and the control socket are prepared.

The parser accepts the explicit `prototype: steer-linux-v1` schema and the
linked SOCKS v3 profile below, and produces canonical JSON for reads.
Generation/revision is host-issued, starting at 1.
Credentials are environment references; values are neither stored in the
document nor returned by control. Enabled listeners resolve and validate their
references before publication. Disabled listeners retain configuration without
reading credentials. A minimal JSON document is:

```json
{"prototype":"steer-linux-v1","listeners":[{"id":"local-socks","protocol":"socks","enabled":true,"listen":{"address":"127.0.0.1","port":1080},"auth":{"type":"none"}}],"routing":{"default":"direct","rules":[]}}
```

VLESS requires `auth.type: uuid`, a host-configured `principal_id` and `uuid_ref:
env:NAME`. SOCKS USERPASS uses `type: userpass`, `principal_id`, `username_ref`
and `password_ref`. Successful credential verification supplies that trusted
principal ID to policy; anonymous SOCKS explicitly supplies no principal.
The runtime never treats a peer-provided UUID/username as a trusted policy ID.
Enabled numeric IPv4/IPv6 listeners have ports 1..65535. Loopback remains the
sample/default; wildcard or other unicast binds require an explicit configured
address. IPv6 uses `IPV6_V6ONLY=1`, allowing deterministic separate IPv4/IPv6
listeners on one port. Multicast, broadcast/reserved IPv4 and mapped IPv6 are
rejected. Management HTTP stays on loopback and Unix control stays private.
Numeric outbound TCP targets may be outside loopback; use a controlled lab.

Each accepted flow pins its immutable generation and listener credential scope.
Policy sees inbound ID, verified principal ID and the original destination;
the shared `route_dial` service performs direct dialing after evaluation.
SOCKS/VLESS responses indicate success only after an actual successful dial.
Numeric IPv4/IPv6 and validated ASCII domain TCP targets work. Original domain
policy is evaluated before resolution. One shared pool of two fixed NSS workers
and 64 jobs serves all generations; up to eight resolved addresses are tried
in order under the route deadline. There is no thread per flow and no blocking
resolver fallback on the event loop. This does not configure DNS servers or
provide the full DNS management subsystem. UDP and nonempty VLESS flows remain denied.
Existing two-buffer relay, pipelining, backpressure, half-close and deadlines
are shared with the standalone [SOCKS](socks_loopback.md) and
[VLESS](vless_loopback.md) fixtures; their CLI remains available.

Applying configuration prepares every new listener before publication, reuses
identical live listener specifications and closes removed/disabled admission
sockets only at commit. Bind, parse, credential or policy failures close all
newly prepared sockets and leave the old revision and traffic intact. Changing
an occupied endpoint's protocol, identity or auth configuration requires disable
then create; the prototype rejects that direct replacement with 422. A label
change does not reopen a socket. `SO_REUSEADDR` supports re-enabling an endpoint
after established connections; `SO_REUSEPORT` is never used. Accepted old flows
continue on their pinned generation when new flows switch to new policy.

Bounds: 16 configured listeners, 32 concurrent flows, two 16 KiB buffers per
flow, 64 streams/stream operations, 32 route operations per generation, eight
live generations including the active one, 64 shared resolver jobs, eight control connections, a 128-byte
command header and 64 KiB documents. Old generations are destroyed after their
flows drain. Applying at the retained-generation ceiling returns 503. A control
request has an absolute five-second read/write deadline. Resource metadata and
the fixed bounded control buffers are additional to relay payload capacities.
On shutdown, cancelled in-progress NSS jobs retain their pool slots until the
backend returns. The host drains route-generation references and continues the
loop until those jobs finish before joining workers. An arbitrarily stuck NSS
backend cannot be forcibly cancelled safely, so shutdown may wait for it.

## Managed spec v3: `linked-socks-v1`

### Experimental inbound DEVICE validation only

The HY2+WG netns build has a separate `--validate-wg-inbound-netns` option for
testing the common parser and control socket, **not a working WG inbound**.
It requires a private `--state-dir`, CAP_NET_ADMIN, disabled IPv4 forwarding,
and fd 3 pinned to the outer network namespace; the current namespace must be
different from both that fd and the initial namespace. It cannot be combined
with `--allow-wg-stream-netns`. It never creates a device, journal or guard.

With that option, `VALIDATE` accepts only one DEVICE WireGuard inbound and
one independent SOCKS TCP inbound, a single direct outbound explicitly carrying
both `device` and `stream` flow classes, no routing rules, and one IPv4 peer
`/32` on the same `/24` as the single device address. Private-key and optional
PSK are typed env references under `STEER_WG_`; values must resolve and parse.
DEVICE stays separate from a proxy stream. The reply explicitly includes
`validationOnly: true` and `candidateRuntimeReady: false`. **APPLY always
rejects this candidate**, leaves the existing revision/store untouched, and no
runtime capability is advertised. This is not a kernel device, peer exchange,
private-key/PSK attestation, forwarding guarantee or 4×4 protocol matrix.
Normal profiles and Nano reject this DEVICE configuration.

The separate experimental
`--experimental-wg-inbound-netns` switch in the WG
netns build is a narrow first-Apply path, not the validation-only switch or
a production capability declaration. It requires the same private namespace gate and
a state directory. It accepts the first transition from one existing SOCKS
listener to the same SOCKS listener plus the supported DEVICE, and removal
back to the same SOCKS listener with direct routing and no rules. Other live
DEVICE changes and DEVICE startup from a source file are refused. On restart from the actual
store snapshot, only a role-tagged journal selection with a confirmed DOWN
owned device and matching guard is considered. Before reopening, the host
checks the current private key, PSK, peer key and AllowedIPs, listen port,
fwmark, MTU and IPv4 address against the validated stored document and local
secret references. The authenticated peer endpoint is not fixed. It cannot be
combined with the existing outbound-WG or validation-only modes.

For the common control bridge, STATUS exposes the explicitly experimental
`spec_v3_wg_inbound_netns` capability with `mode`, `add`, `remove`, and
`replace`. In validation-only mode both mutations are false; in runtime mode
add/remove reflect the selected slot, the journal's re-add restriction,
runtime health, fencing, durability and pending operations. Replace is always
false. An active slot is read-only checked against its link, guard and peer
before reporting it ready. This is not a production WG capability or a protocol
matrix claim. In runtime mode VALIDATE checks the same supported transition
constraints as APPLY; it never prepares the device. The validation-only mode
continues to return `validationOnly: true` for its DEVICE candidate.

An already UP or otherwise unconfirmed device is refused, including after
SIGKILL; a selected but unpublished journal entry is also refused. A DOWN
device after a crash is not automatically trusted: the same checks apply.
This is a narrow recovery path, not general restart/reuse, and is not atomic
against a concurrently mutating privileged actor in the namespace.

The common host keeps the closed participant slot with `prepared` and passes
the receipt from its store writer to normal finish or shutdown finish according
to the host's stopping state, not the control socket. STATUS/GET expose selected
revision separately from the live generation; `inboundBarrier` is `closed`,
`open`, `absent`, or `unknown`. A post-sync publication failure does not return Apply
success and leaves the old SOCKS generation serving while the selected document
is rev2. UNKNOWN does not prove traffic is blocked.

For removal, the serialized owner closes and confirms the exact owned DEVICE
before it hands the candidate no-WG document to the store writer. The previous
selected revision and SOCKS remain in place until the receipt. A NOT_RENAMED
failure retains the old revision and fences the host; while the write is
pending STATUS already reports `runtimeReady: false` and a closed barrier.
The DEVICE is not
automatically reopened. Checked recovery may reopen it after restart. A
RENAMED-unsynced outcome retains the closed candidate and reports unknown
durability; GET refuses and no cleanup is attempted. After matching SYNCED the
new no-WG document is selected and the owned link is closed and checked again
before journaled retirement of the exact old owned link and guard. Only
completed cleanup permits Apply success. If closure or cleanup
fails or ownership is ambiguous, the selected new revision is still reported,
the old runtime is fenced, the barrier is UNKNOWN, and no success is returned.
The participant and journal remain a single serialized slot; this does not
introduce live DEVICE replacement, re-add after removal or general reuse; the
published journal history preserves that restriction across restart. A restarted rev3 can
reconcile interrupted cleanup only where existing ownership checks prove it.

`tests/linked-inbound-host-ns.sh` builds the explicit WG host and a separate
test-only backend fault binary, then exercises same-host control/store, a real
peer TCP echo and SOCKS echo, confirmed policy-change failure, control
disconnect, shutdown while store fsync is paused, shutdown during publication,
active-link shutdown and refusal of mismatched ownership. It uses disposable netns;
it is not a release, UI capability, full recovery or protocol-matrix claim.

Shutdown is accepted when the serialized loop handles its signal callback and
sets `h->stopping`, not when the asynchronous signal is sent or queued. Before
that point an in-progress publication can complete and traffic can pass.
After accepted shutdown a still-prepared slot takes shutdown finish when its
receipt arrives; an already committed DEVICE is closed using a fresh
exact-ownership check before the host exits. If closure or ownership cannot be
confirmed, the link and guard are retained and the host exits nonzero; an
unconfirmed state is UNKNOWN, not a claim that packets are blocked. A process kill,
crash, external privileged mutation and the period before the loop accepts a
signal are not covered by that guarantee. Pause hooks are compiled only into
the separate test binary. This gate remains subject to independent acceptance.

Given separately built full HY2+WG and Nano binaries, run the real control test:

```sh
unshare -n python3 -B experimental/provider/linked_inbound_validate_test.py \
  /absolute/path/to/steer-prototype-hy2-wg-netns /absolute/path/to/steer-nano \
  3</proc/self/ns/net
```

The test disables forwarding only inside that newly created namespace and
checks that rejected Apply preserves the common store and SOCKS echo.

The separate `tests/linked-inbound-remove-ns.sh` exercises removal immediately
after Apply and after a checked restart, the next rev3 restart, real peer and
SOCKS traffic, store and ownership failures, cleanup ambiguity, disconnected
control, and shutdown with an outstanding receipt. The tests do not operate
on the host network.

This is an experimental subset, accepted by `--config` and by the same
validate/apply control commands. For example:

```yaml
version: 3
plugin_remotes:
  local:
    url: https://github.com/splify2/steer-protocols
    trust: steer-linked-prototype-v1
plugins:
  proxy: {remote: local, package: steer-protocols, version: "0.0.0"}
secrets:
  client-id: {source: env, kind: uuid, name: STEER_VLESS_UUID}
inbounds:
  socks-local:
    plugin: socks:proxy
    options: {}
    listen: {address: 127.0.0.1, port: 1080}
  vless-local:
    plugin: vless:proxy
    options: {principal_id: local-client, uuid: {secret: client-id}}
    listen: {address: 127.0.0.1, port: 18443}
outbounds:
  internet: {type: direct}
  deny: {type: block}
routing:
  default: deny
  rules:
    - {name: local-route, match: {inbound: [socks-local]}, outbound: internet}
    - {name: vless-route, match: {inbound: [vless-local]}, outbound: internet}
```

The fixed remote, trust, package and `0.0.0` prototype marker select code
already linked into this build. They do not grant trust, read a remote index,
install a package, or represent a signed lock. Aliases and object IDs are
user-defined. By default the profile accepts numeric loopback only (`127/8`,
`::1`). SOCKS5 CONNECT supports NOAUTH (`options: {}`) or USERPASS;
only the latter can use an [operator-approved VPN address](#managed-socks5-tcp-on-a-vpn-address).
Plain VLESS TCP (UUID auth) stays loopback-only. For these two providers explicit
`flow` is limited to `[stream]`. VLESS requires one typed `uuid` reference to an inherited
environment variable. Supply the UUID in the core process's private environment,
never in the intent. Validate/apply and startup reject an enabled VLESS listener
if its value is absent or malformed. The intent, snapshots and status never
include the resolved value. TLS, REALITY, Vision and UDP are not part of this
VLESS variant. Routing supports ordered `route` and `reject`, named
direct/block outbounds, and an explicit default. Match fields are `inbound`
and either `domain` or `domain_suffix`, each with one list entry; an empty map
matches all. Other variants and settings are rejected, even on disabled
objects. The general v3 provider executor and signed lock are not wired in.

### Managed SOCKS5 TCP on a VPN address

The VPN address must already be set up by the operator. Add the following
**startup option** to the core process, not to the UI or v3 intent:

```text
--allow-socks-vpn-bind 10.8.0.1 STEER_VPN_SOCKS_USER STEER_VPN_SOCKS_PASSWORD
```

The last two arguments are names of **distinct** process environment variables,
not their values. Provision dedicated credentials privately in the core
environment; enabled entries require 1–255 bytes in each value. The repeatable
option allows up to 16 unique numeric addresses, each with one approved pair of
environment names. The core compares canonical addresses and the exact resolved
reference names; a v3 document cannot use another environment variable in their
place. Wildcards, hostnames, CIDR ranges, mapped IPv6, multicast, IPv6
link-local addresses and loopback are not allowlist entries. Without the option
there is no non-loopback exception. The port and principal ID are intent fields;
the option does not bind a socket by itself.

For the example above, merge these entries into the v3 document (add a
routing rule selecting `socks-vpn` only if you want it to reach the chosen
outbound):

```yaml
secrets:
  vpn-user: {source: env, name: STEER_VPN_SOCKS_USER, kind: username}
  vpn-pass: {source: env, name: STEER_VPN_SOCKS_PASSWORD, kind: password}
inbounds:
  socks-vpn:
    plugin: socks:proxy
    listen: {address: 10.8.0.1, port: 11080}
    options:
      principal_id: vpn-client
      username: {secret: vpn-user}
      password: {secret: vpn-pass}
```

The SOCKS5 TCP listener accepts only USERPASS at this endpoint; failed
negotiation or authentication never reaches the route or target. The core
supplies `principal_id` to the runtime after authentication. This profile
does not add v3 principal-based route filters, SOCKS UDP, a secret store or
multi-user authentication. Validate checks configuration and enabled credentials
without binds; Apply can still fail if the address cannot be bound or the port
is occupied. On recovery the operator must supply the same approval and
credentials again; they are not saved in the durable envelope. Removing the
approval for a saved non-loopback entry makes startup refuse that snapshot
(including disabled entries), rather than silently fall back or expose it.
Remove or relocate the entry first if intentionally retiring that approval.

To prevent a format downgrade from bypassing the bind policy, a managed v3
core refuses `steer-linux-v1` over control; the startup option also refuses
legacy files and snapshots. A standalone legacy fixture started without the
option keeps its existing behavior and must not be offered as managed v3.

**UI form contract:** `STATUS.capabilities.spec_v3_socks_tcp_userpass: true`
advertises SOCKS5 USERPASS. `spec_v3_socks_vpn_bind` is
`{"auth":"userpass","addresses":["10.8.0.1"]}` with a read-only array of
canonical startup-approved addresses (empty by default). If absent, or if no
addresses are advertised, do not offer a VPN address selector. For a managed
SOCKS5 TCP row, offer numeric loopback by default and choose a non-loopback
address from this array. Require port 1–65535; for a VPN address lock auth to
USERPASS and require a principal matching `[A-Za-z0-9_.-]{1,64}` and two
typed `{secret: ID}` refs matching the example. Collect or select env **names**
only (syntax `[A-Za-z_][A-Za-z0-9_]{0,94}`), not credential values. The actual
pair approval is checked by Validate/Apply; STATUS does not advertise the names.
For loopback, serialize NOAUTH as `{}` or use the same USERPASS options when
supported. Treat capabilities as guidance, not as a substitute for core
validation, and never generate a wildcard or fall back to legacy to bypass it.
The existing UI bridge/form is not changed by this core contract.

Binding by destination address is not binding to the WireGuard interface and
does not install firewall rules. Ensure only intended VPN peers can reach that
address/port and limit outbound access in routing and firewall policy as needed.
SOCKS5 USERPASS is not encrypted by SOCKS; the fixture relies on the WireGuard
tunnel. The managed UI and existing WireGuard configuration are not changed.
To reproduce using two disposable network namespaces with real WireGuard peers
and `curl` (requires namespace privileges, kernel WireGuard, iproute2, `wg` and
`ping`), run:

```sh
make -C steer/experimental/provider BUILD=/tmp/steer-provider-build socks-vpn-netns-test
```

### Managed plain VLESS TCP outbound

Build from `experimental/provider/Makefile` to include the source-linked stream
backend. The separate top-level lab build does not include this outbound.
For example, merge these entries and replace the `socks-local` rule above
(use the numeric address/port of your own upstream):

```yaml
secrets:
  upstream-id: {source: env, kind: uuid, name: STEER_VLESS_UPSTREAM_UUID}
outbounds:
  via-vless:
    plugin: vless:proxy
    endpoint: {address: 127.0.0.1, port: 24443}
    options: {uuid: {secret: upstream-id}}
routing:
  default: deny
  rules:
    - {name: local-route, match: {inbound: [socks-local]}, outbound: via-vless}
    - {name: vless-route, match: {inbound: [vless-local]}, outbound: internet}
```

Validate and startup check the inherited UUID without contacting the peer.
Apply prepares the VLESS binding over the native TCP binding before publication.
Each selected session sends the original target to the VLESS peer, not to local
direct dial; a failed peer connection never falls back. Old sessions keep their
original bindings across Apply. VLESS provides no target-connect ACK, so a
SOCKS success reply means the VLESS request was sent, not that the far target
connected; its unknown bind address is reported as `0.0.0.0:0`.

This slice allows enabled plain VLESS v0 TCP outbounds with a numeric upstream
and no explicit detour, transport, security or resolver settings. The UUID travels unencrypted
in this variant. TLS, REALITY, Vision, UDP and VLESS routing for HY2 ingress
are not supported by this binding. A VLESS default is valid only with TCP
inbounds. The local alias check uses the same linked profile and spec graph,
not a dynamic provider loader or a stable ABI.

`integration-test` uses a separate Steer VLESS fixture; the independent
loopback interoperability test takes an existing Xray executable:

```sh
python3 steer/experimental/provider/prototype_vless_outbound_test.py \
  --core /tmp/steer-provider-build/steer-prototype --xray /path/to/xray
```

### Managed SOCKS5 TCP outbound

The local provider Makefile also builds a source-linked SOCKS5 CONNECT backend.
For an unauthenticated upstream, use an empty `options: {}`. For USERPASS use
two typed environment references:

```yaml
secrets:
  proxy-user: {source: env, kind: username, name: STEER_SOCKS_USER}
  proxy-pass: {source: env, kind: password, name: STEER_SOCKS_PASSWORD}
outbounds:
  via-socks:
    plugin: socks:proxy
    endpoint: {address: 127.0.0.1, port: 1081}
    options:
      username: {secret: proxy-user}
      password: {secret: proxy-pass}
```

Select `via-socks` in a TCP routing rule or as the TCP-only default.
The upstream endpoint is numeric; the requested target can be IPv4, IPv6, or
a domain forwarded unchanged to the peer. The backend waits for the complete
CONNECT reply under one absolute deadline, then transfers the same stream to
the host relay without reading ahead. An upstream error never falls back to
`direct`. Credential values are not stored in the intent or status. The wire
authentication exchange is plaintext and cannot downgrade to NOAUTH. BIND,
UDP ASSOCIATE, TLS, detours and dynamic provider loading are not supported.

`integration-test` runs a separate Steer SOCKS5 fixture plus wire-level edge
cases. For the independent upstream, run from the hub:

```sh
python3 steer/experimental/provider/prototype_socks_outbound_test.py \
  --core /tmp/steer-provider-build/steer-prototype --xray /path/to/xray --wire-cases
```

### Managed Hysteria2 TCP outbound (optional HY2 build)

`hy2_stream_backend.c` adds a TCP stream binding to the same table as SOCKS
and VLESS. `hy2_tcp_client.c` reuses Steer's ngtcp2/wolfSSL client and the legacy HY2
HTTP/3 and TCP codecs, without the global node, worker, or TUN callbacks of
`hy2conn.c`. It connects only to a numeric upstream, strictly checks the
certificate against prepared PEM roots and an explicit DNS/IP identity, and
sends the password only after verified TLS. It does not expose a stream until
both HTTP 233 and a positive HY2 TCP response arrive. There is no direct
fallback, DNS lookup on the owner, UDP relay, 0-RTT, obfuscation or port hopping.
DNS targets are forwarded as wire names for server-side resolution.

Validate/Apply prepare the password, a regular PEM file (up to 1 MiB), and
its TLS context on the prepare worker without contacting the peer. Bootstrap
prepares the same material from persisted references before accepting traffic.
Name/trust matching against the peer and password authentication happen
at TCP open, not at Validate/Apply. One absolute open deadline covers TLS,
auth and the upstream TCP response; the owner drives nonblocking QUIC with
fd/timer readiness. The binding uses one QUIC connection per TCP flow,
up to 16 per outbound per generation, with 64 KiB send/receive flow bounds and
the shared host TCP admission cap. Apply retires old HY2 bindings: new opens
cannot select them, admitted opens and established streams drain on the
old profile for up to 30 seconds, then outstanding transport is closed. The
binding is reclaimed after its stream and operation references release.

Spec-v3 fields for the UI form. Only offer it when STATUS advertises
`capabilities.spec_v3_hysteria2_tcp_outbound`. The plugin alias `proxy` is
the alias declared by the existing linked profile:

```yaml
secrets:
  hy2-out-password: {source: env, kind: password, name: STEER_HY2_OUT_PASSWORD}
  hy2-out-roots: {source: env, kind: certificate, name: STEER_HY2_OUT_CA}
outbounds:
  hy2-exit:
    plugin: hysteria2:proxy
    flow: [stream]
    endpoint: {address: 192.0.2.10, port: 443}
    transport: {type: quic}
    security: {type: tls, server_name: relay.example, verify: true}
    options: {password: {secret: hy2-out-password}, ca_bundle: {secret: hy2-out-roots}}
```

The form takes a numeric IPv4/IPv6 endpoint and port 1–65535, a required
ASCII DNS name (IDNA A-labels only) or IP SAN identity, and references to
the password and trusted CA bundle. `STEER_HY2_OUT_CA` is a path to a regular
PEM file in the core's environment, not a URL or a leaf-certificate bypass.
The password is 1–256 visible ASCII bytes; the form and intent must not return
resolved values or paths. TLS verification and ALPN `h3` are fixed, not UI
switches. Omitted `verify` is `true`; `false` is rejected. Select `hy2-exit`
in a TCP routing rule or as the TCP-only default. Do not expose UDP.
The independent server test below exercises this outbound from SOCKS ingress.
The stream-only HY2 ingress profile is separately tested with SOCKS and VLESS
egress. Neither test establishes HY2-to-HY2 interoperability or UDP egress.

To reproduce the isolated test, build
`experimental/provider` target `$BUILD/hy2-tcp-client-test` with the same
`NGTCP2_LIB` and `WOLFSSL_SERVER_LIB` archives and `.cflags` as the optional
server profile. Build `tests/hy2_outbound_oracle.go` via `go build -o
$ORACLE_SERVER /absolute/path/to/tests/hy2_outbound_oracle.go` from the pinned
upstream Hysteria Go workspace (its `core` directory). Then run:

```sh
python3 experimental/provider/hy2_tcp_client_test.py \
  --client "$BUILD/hy2-tcp-client-test" --server "$ORACLE_SERVER" \
  --oracle-client /tmp/opencode/steer-hy2-oracle-bin
python3 experimental/provider/prototype_hy2_outbound_test.py \
  --core "$BUILD/steer-prototype-hy2" --server "$ORACLE_SERVER" \
  --minimal "$BUILD/steer-prototype"
```

The supplied oracle binary is an independent **client**; it verifies the
upstream server fixture before the Steer client runs. All test addresses are
loopback; the fixture explicitly maps `target.test` to a local echo service
without DNS and rejects other targets. The managed fixture accepts
`--fault-core "$BUILD/steer-prototype-hy2-fault"` to verify that a deliberately
blocked outbound CA read does not interrupt Relay or STATUS/GET.

### Optional Hysteria2 server build

On the optional HY2 server build, merge the following entries into the
same intent to enable Hysteria2 TCP/UDP over QUIC/TLS:

```yaml
secrets:
  hy2-password: {source: env, kind: password, name: STEER_HY2_PASSWORD}
  hy2-cert: {source: env, kind: certificate, name: STEER_HY2_CERT}
  hy2-key: {source: env, kind: private_key, name: STEER_HY2_KEY}
inbounds:
  hy2-local:
    plugin: hysteria2:proxy
    flow: [stream, datagram]
    listen: {address: 127.0.0.1, port: 8443}
    transport: {type: quic}
    security: {type: tls, certificate: {secret: hy2-cert}, private_key: {secret: hy2-key}}
    options: {principal_id: local-client, password: {secret: hy2-password}}
```

Add `flow: [stream, datagram]` to both `internet` and `deny` in the example and
add an ordered route for `hy2-local` to `internet`. For a TCP-only SOCKS5 or
plain VLESS proxy default, explicitly use `flow: [stream]` on the HY2 inbound:
new UDP associations are denied even if the policy selects direct. Existing
UDP associations remain pinned to their admitted generation and drain normally.
The compiler rejects the two-class HY2 document when its default or a matching
route targets a stream-only proxy; it does not infer compatibility from
component capabilities. A datagram-only HY2 inbound is unsupported. With the
two-class profile TCP and UDP share the same ordered routing policy. The
certificate and key variables contain paths in the core's environment; the
password variable contains the password. No values or resolved paths are stored
in the intent. A minimal build rejects HY2 documents. The prototype caps typed
secret declarations at 16.

For the inbound flow selector, STATUS advertises
`capabilities.spec_v3_hysteria2_stream_only_inbound: true` when the core
accepts an explicit `flow: [stream]`. This is independent of outbound support.
On older cores without this flag, keep the existing TCP+UDP choice when
advertised; do not generate the stream-only profile from a form.

GET returns the whole accepted v3 intent, not its lowered listener/policy
representation. The durable envelope records `format: "steer-spec-v3"`;
recovery syncs the store and recompiles the saved intent with the same
catalogue and revision. A format mismatch refuses startup without fallback.
To bootstrap a different configuration, use a fresh private state directory;
the source file never replaces an existing committed snapshot.

## Local control protocol

One request per Unix stream connection. After sending the entire request a client
may shut down its write half and still read the reply, including while validation
or persistent apply is pending. Lengths count UTF-8 bytes. Commands are
case-sensitive ASCII followed by LF; document bytes follow immediately:

```text
STATUS\n
GET\n
VALIDATE <length>\n<document>
APPLY <expected-revision> <length>\n<document>
```

Responses are `OK <length>\n<JSON>` or `ERR <code> <length>\n<JSON>`, then EOF.
The error body is generic and contains no document excerpts or credentials.
400 means malformed framing, 409 stale revision, 422 rejected configuration or
listener preparation, and 503 exhausted resources. Validation does not bind
sockets or mutate state. Apply compares the expected revision, assigns the next
revision internally, then prepares/commits atomically on the loop shard.

- `STATUS`: `prototype`, `generation`, `revision`, `runtimeReady`,
  actual `persistence`, `durability_uncertain`, `activeClients`, and active `listeners` with
  `id`, `protocol`, `address`, `port`. `capabilities.spec_v3_profile` advertises
  `linked-socks-v1` for compatibility; `capabilities.spec_v3_vless_tcp: true`
   advertises plain VLESS inbound; `capabilities.spec_v3_vless_tcp_outbound: true`
   indicates the linked VLESS outbound above. `capabilities.spec_v3_socks_tcp_outbound: true`
   indicates the linked SOCKS5 outbound. `capabilities.spec_v3_hysteria2: true`
  advertises the QUIC/TLS TCP+UDP HY2 tuple, not general v3 execution.
- `GET`: one atomic `{revision,persistence,durability_uncertain,document}` envelope with the
  canonical configuration, including environment references only.
- `VALIDATE`: `{valid:true,persistence}` on success.
- `APPLY`: `{applied:true,revision,generation,persistence,durability_uncertain}` on success.

Without `--state-dir`, apply changes memory and reports `persistence:false`;
restart reloads the startup file. With the option, the existing private directory
must belong to the effective UID, have no group/other permissions and permit an
exclusive writer lock. The core seeds an absent committed snapshot at startup.
Subsequent boots load its `config.json` document and revision before considering
the source file. A corrupt or unsafe snapshot fails closed, even if the source
file is valid; a missing snapshot alone allows source bootstrap. Secret values
are never persisted, only validated environment references. The source file is
never overwritten.

One bounded prepare worker parses configuration and compiles policy. Apply
rechecks revision on the owner loop, then prepares routes and listener sockets;
a single bounded writer thread writes an exclusive 0600 temporary snapshot,
fsyncs it, renames it atomically and fsyncs the directory. Disk IO does not block
packet processing. Prepared listeners are inactive and omitted from runtime
until publication; precommit connections to a newly bound port are rejected.
Only one durable apply is in flight; another apply receives 503. Writer
completion returns through eventfd. All fallible runtime preparation precedes
rename; publication afterwards performs no allocation or new socket registration.
Before-rename failure rolls back new listeners and preserves the old runtime
and committed revision. Once rename succeeds, the new runtime is published even
if directory fsync fails: the response is 503 with `applied:true`, actual revision
and `durability_uncertain:true`. GET and runtime report that actual state; the
UI reconciles it and warns rather than claiming either rollback or confirmed
durability. Shutdown waits for the bounded writer transaction before service
cleanup. HTTP and UI remain in the separate management bridge.

The black-box `prototype_test.py` exercises both protocols simultaneously,
atomic reads, fragmented control requests, validate/apply/stale revisions,
new-flow block with old-flow continuity, rollback after one prepared listener
and a second occupied port, listener creation/disable/re-enable, and graceful
cleanup. Native epoll/allocation failure injection, cross-UID control testing, production loading,
full v3 migration and non-Linux platforms remain unverified.
The configured fixture also verifies localhost through SOCKS and VLESS, address
fallback to an IPv4 echo target, and original-domain blocking while numeric
requests remain direct. Standalone lab CLIs retain their explicit numeric-only
profile and do not attach this resolver pool.

`prototype_persistence_test.py` verifies snapshot priority/revision across
restarts, stale revision handling, real disk-create failure rollback and corrupt
state rejection. The independent UI HTTP crash/restart gate also verifies a
SIGKILL/restart retaining committed routing. `server_bind_test.py` passed actual
IPv4 and IPv6 wildcard ingress on the same port from a separate Linux network
namespace, with exact binary echo and half-close. These are prototype Linux
checks, not production deployment or a release.

`make store-fault-test` adds a test-only `LD_PRELOAD` fsync interposer, never
linked into runtime binaries. Strict and ASan/UBSan executions passed: paused
file fsync keeps old packet traffic and STATUS responsive, hides prepared
listeners and rejects a second apply; file fsync failure rolls back, directory
fsync failure publishes the visible revision with explicit uncertainty, and an
abandoned caller's apply response cannot leak into a reused control slot.
