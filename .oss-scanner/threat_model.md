# Threat model — steer

## What this project does and where untrusted input enters
steer is a policy-routing core for Linux routers (OpenWrt) and Android: it compiles a routing
specification into nftables rules and routing tables, runs a DNS resolver with fake-IP
(`src/dnsd`), and runs tunnel clients (VLESS/Reality, Hysteria2, Trojan/Shadowsocks/SOCKS/HTTP/VMess,
xsteer, WireGuard-over-fake-TCP obfuscation, Telegram bridge, Cloudflare WARP) as separate module
processes (`src/proto/*`, `src/tunnel`). It runs as root on the router.

Untrusted input (attacker-controlled), most important first:
1. **Network data from remote servers/peers** — everything parsed by tunnel clients and transports:
   TLS 1.3 / Reality / ECH handshakes (`src/proto/tls`), HTTP/2, gRPC, WebSocket, HTTP upgrade, xhttp
   (`src/proto/transport`), QUIC (`src/proto/quic`), protocol framing of VLESS/Vision, Hysteria2 (incl.
   Salamander/Gecko obfuscation), proxy protocols, xsteer hub/client (`src/proto/xsteer`), WARP API
   responses. A malicious or compromised node/server is in scope.
2. **DNS traffic** — queries from LAN clients and answers from upstream resolvers (UDP/TCP/DoT/DoH/DoQ/DoH3)
   in `src/dnsd`.
3. **Packets from LAN clients** entering the userspace TUN stack (`src/tunnel`: IP/UDP parsing,
   fragment reassembly).
4. **Subscription content** fetched over the network (lists of node links, base64, Clash YAML,
   Xray/sing-box JSON) — `src/proto/vless/sub*.c`, `src/proto/hysteria2/hy2sub.c`, `src/proto/proxy/pxsub.c`.
5. **Domain/IP list files and `.srs` rule sets** downloaded from third parties (`src/model/srs.c`,
   `src/tools/aggregate.c`).
6. Less important: the spec (`spec.yaml`/`spec.json`, `src/model`) and the local control socket
   (`src/daemon/ctl.c`) — written by the local admin/panel; parsing bugs matter, privilege escalation
   from root-only callers does not.

## Components that matter most / least
- Most: `src/proto/*`, `src/tunnel`, `src/dnsd`, `src/model/srs.c`, subscription parsers.
- Less: `src/daemon` (local control), `src/cli`, `build/`, `tests/`.
- Out of scope: `src/third_party/` (vendored libyaml), wolfSSL/ngtcp2 themselves (fetched by
  `build/*/fetch.sh`), `tools/`.

## How to exercise it
- `make` builds the host binaries into `build/` (`build/steerd`, `build/steer`).
- `make test` runs the unit and integration stands (`tests/*match.c`, `tests/*.sh`); many parser stands
  are standalone binaries in `build/` (e.g. `submatch`, `hy2match`, `pxsubmatch`, `dnsmatch`, `srsunit`,
  `h2match`, `xhupmatch`, `tls13readmatch`, `xswirematch`) and accept crafted input easily.
- Specs: `steer apply --dry-run --spec <file>` compiles a spec without touching the system.

## How you rate severity
- Memory corruption (overflow, UAF, double free) reachable from a remote server/peer or from DNS
  traffic: critical if controlled, high otherwise.
- Same from subscription/list content: high.
- Remote DoS of the resolver or a tunnel process (crash, unbounded memory, busy loop): medium.
- Traffic leaking outside the configured tunnel (routing/DNS leaks) without memory corruption: high.
- Bugs reachable only via the spec or the root-only control socket: low, unless they corrupt memory.

## Anything to leave alone
- Fixed limits that produce an explicit, named refusal are intentional (the project is removing silent
  truncations; silent ones are worth reporting).
- Test stands under `tests/` and build scripts are not production code.
