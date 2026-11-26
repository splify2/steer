# Experimental outgoing SOCKS5 UDP backend

This Full-only SDK datagram backend is also constructed by the narrow managed
SOCKS profile in [prototype_core.md](prototype_core.md#experimental-managed-socks5-udp-outbound).
It is experimental, not a released service. Nano and the existing SOCKS TCP
CONNECT backend are unchanged.

The first slice accepts a numeric IPv4 target and an IPv4 upstream bound at
`127.0.0.1` only. It negotiates SOCKS5 NOAUTH and UDP ASSOCIATE over a retained
nonblocking TCP control connection. The reported relay must be non-wildcard
`127.0.0.1` with a nonzero port. It connects its local UDP socket to that relay,
rejects invalid RSV/FRAG and unexpected original target addresses on replies,
and caps both sent and received application payloads at 65000 bytes. An
oversized reply is consumed and completes receive with resource exhaustion and
zero bytes; subsequent replies remain eligible. UDP readiness is watched only
while an operation needs it, leaving early replies in the bounded kernel socket
queue; the TCP control socket remains watched independently. Domain targets, IPv6, USERPASS,
remote upstreams and fallback to direct are not implemented.

The SDK binding has bounded references, operations and transferred bytes. Open,
send and receive use mandatory deadlines and cancellable deferred completions.
TCP EOF or protocol error fails the association and pending operations.
Retirement stops admission and applies a bounded drain deadline. Callers must
close and release references and operations before destroying the binding.

`socks-outbound-udp-test` requires `XRAY=/path/to/xray` and runs in a disposable
network namespace. It routes through the real SDK router to an independent
Xray SOCKS server, checks that the echo sees a UDP socket owned by Xray, checks
control loss, disabled UDP and absent server, and verifies zero backend budget
after drain. It does not demonstrate managed v3 routing or a UI contract.
`socks-outbound-udp-contract-test` uses a separate controlled SOCKS server to
exercise deferred receive without a busy loop and exact 65000/65001 byte replies,
independent of upstream implementation limits.
