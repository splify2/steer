# Prototype configuration boundary

`prototype_config.{c,h}` parses the explicitly marked `prototype: steer-linux-v1`
format using Steer's existing bounded `ynode` parser and libyaml. This is not a
v3 specification parser: `version: 3`, plugin/remotes, arbitrary provider options,
DNS, outbound groups and unknown fields are rejected. Legacy parsing is unchanged.
The generation is supplied by the core, not accepted from the document.

Top-level fields are exactly `prototype`, `listeners`, `routing`. JSON and YAML
are accepted; duplicate keys, tags, aliases, anchors and embedded NUL fail closed.
Input and canonical output are limited to 64 KiB. There are at most 16 declared
listeners and 128 declared rules. An empty listener list is valid. All returned
strings, canonical JSON and compiled policy are owned by the config; destroy
frees all of them. No asynchronous reader borrows parser storage.

A listener has `id`, `protocol` (`socks` or `vless`), `listen` (`address`, `port`),
`auth`, optional `label` and optional `enabled` (default true). Binds must be
explicit numeric IPv4/IPv6, including wildcard `0.0.0.0` and `::`, ports
1..65535. Multicast, reserved IPv4, mapped IPv6 and hostname bindings are
rejected. Samples remain loopback-only; changing a listener address is an
explicit configuration action. IDs are 1..64 ASCII letters/digits or
underscore, dot, hyphen. Labels are at most 128 UTF-8 bytes without controls.
Active duplicate binds and duplicate IDs are rejected; normalized numeric bind
addresses are returned to the host.

`server_bind_test.py <core-binary>` runs as root inside disposable network
namespaces and verifies real traffic from a separate client namespace to
IPv4/IPv6 wildcard listeners sharing one port. It passed on the WSL test kernel;
the host uses `IPV6_V6ONLY` so IPv6 does not silently claim the IPv4 listener.
Management HTTP remains loopback-only. No production network is changed by
this test.

SOCKS auth is `{type: none}` or
`{type: userpass, principal_id: alice, username_ref: env:USER, password_ref: env:PASS}`.
VLESS auth is `{type: uuid, principal_id: alice, uuid_ref: env:UUID}`. References
are strictly `env:NAME`, with an ASCII environment-variable name. The parser never
resolves, prints or stores credential values. The host must resolve and validate
refs before publishing listeners. Principal IDs are routing identities, not
credentials. Inline password/UUID fields are unsupported and rejected.

Routing requires an explicit `default: direct|block` and ordered `rules` array.
Each rule requires `id` and `action: direct|block`. Optional AND conditions are
`inbound` (one declared listener ID), `principal` (stable verified ID), `domain`
(ASCII DNS name), `domain_suffix` boolean, `cidr` (canonical IPv4/IPv6 prefix),
`ports: [first,last]`. Domain and CIDR are mutually exclusive. Empty conditions
require `match_all: true`; conditioned rules cannot set it. `label` and `enabled`
are optional. Disabled rules are fully validated, including duplicate IDs, but
omitted from the active compiled policy. Disabled listeners remain in the owned
configuration; the host must not bind them. References can name disabled declared
listeners. Canonical JSON preserves disabled entries and labels for UI editing.
String fields reject unquoted booleans/null/numbers; quote numeric-looking IDs.

The existing policy compiler validates canonical CIDR, domain labels, port ranges,
AND conditions and explicit default. Configuration validity does not prove bind
success, credential availability, upstream protocol support or a successful apply.
Those checks and atomic publication belong to the core host, never the UI parser.

The sample `prototype.sample.yaml` keeps VLESS disabled until the owner supplies
an environment UUID. It exposes loopback only and contains no credential values.

`prototype_config_test.c` passed strict C11 and ASan/UBSan with leak detection in
WSL Ubuntu x86_64 Linux on 2026-11-17. It checks YAML/canonical-JSON roundtrip,
labels, disabled listeners/rules, compiled first-match behavior, env refs, empty
listeners, unknown/duplicate fields and IDs, malformed references, external
binds, noncanonical CIDR, invalid scalar types, tags/aliases and v3 rejection.
Build with `-D_POSIX_C_SOURCE=200809L -DHAVE_CONFIG_H`, include SDK headers,
`src/lib`, `src/third_party/libyaml`; link the test, `prototype_config.c`, `policy.c`,
`ynode.c`, `jsonw.c`, `err.c`, and libyaml api/reader/scanner/parser sources.
No production release, complete v3 migration or multi-platform parser gate is claimed.
