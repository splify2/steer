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
user-defined. SOCKS5 CONNECT (no auth) and plain VLESS TCP (UUID auth) are
supported on numeric loopback only (`127/8`, `::1`); explicit `flow` is
limited to `[stream]`. VLESS requires one typed `uuid` reference to an inherited
environment variable. Supply the UUID in the core process's private environment,
never in the intent. Validate/apply and startup reject an enabled VLESS listener
if its value is absent or malformed. The intent, snapshots and status never
include the resolved value. TLS, REALITY, Vision and UDP are not part of this
VLESS variant. Routing supports ordered `route` and `reject`, named
direct/block outbounds, and an explicit default. Match fields are `inbound`
and either `domain` or `domain_suffix`, each with one list entry; an empty map
matches all. Other variants and settings are rejected, even on disabled
objects. The general v3 provider executor and signed lock are not wired in.

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
add an ordered route for `hy2-local` to `internet`. The HY2 tuple requires both
flow classes, and the compiler rejects a default or route that cannot handle
the selected traffic. TCP and UDP share the same ordered routing policy. The
certificate and key variables contain paths in the core's environment; the
password variable contains the password. No values or resolved paths are stored
in the intent. A minimal build rejects HY2 documents. The prototype caps typed
secret declarations at 16.

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
