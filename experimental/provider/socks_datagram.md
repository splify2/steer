# SOCKS UDP adapter — intermediate Full-only source

`socks_datagram.c` is an internal, owner-loop adapter, not a managed listener
or a capability. Full `HY2_HOSTS` build it with `STEER_PROTOTYPE_SOCKS_UDP`
and the existing datagram router; Nano and ordinary builds do not.

The owner supplies the already authenticated control peer, requested UDP peer,
admitted generation, an immutable-policy authorization callback and the
router's acquire/release services. The owner pins that generation until
`destroy` succeeds. Each structurally valid message is independently passed to
the authorization callback before a target can be opened **or reused**; the
router also evaluates each new target open. Unexpected acquired generations are
released and denied. Router and provider failures never fall back to direct.

This first adapter accepts only an IPv4 `127.0.0.1` control peer and binds a
non-wildcard IPv4 loopback UDP socket. An explicit request address must match
that peer; zero address is allowed. A nonzero requested port is enforced;
otherwise the first valid permitted datagram binds the UDP source port.
Foreign sources, nonzero RSV/FRAG, malformed addresses and oversized payloads
are dropped. Payloads are bounded at 65000 bytes. The internal dispatcher
limits associations, targets, packets, memory and asynchronous operations.
Domain-typed numeric IPv4 strings and bracket-prefixed domain strings are
rejected rather than reclassified while crossing the internal address format.

The TCP owner **must** call `stop` on control EOF, successful replacement of
the admitted generation, or shutdown. Stop removes and closes the relay fd
before cancelling dispatcher work. An idle timer also stops it. `destroy`
returns busy until callbacks and provider references drain; the caller must
keep its generation pin, callback context and adapter alive until it succeeds.
The Full host connects this adapter to the opt-in v3 handshake and retires it
on successful generation replacement. VPN-bind and Nano remain unsupported;
see `prototype_core.md` for the managed contract.

The source-only `socks-datagram-test` target uses a real SDK router and native
UDP echo in a private network namespace. It exercises different direct/block
targets selected by a fixture policy callback, repeated permitted traffic,
malformed/source filtering, a TCP-owner EOF calling stop, generation mismatch
and idle expiry. This does not claim that managed v3 supports a port-match
syntax. It is not the managed or independent-client acceptance gate.
