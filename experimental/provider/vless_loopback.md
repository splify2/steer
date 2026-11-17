# VLESS plain TCP loopback lab host

`vless_loopback.c` selects VLESS v0 parsing in the same `loopback_host.c` used by
[the SOCKS5 fixture](socks_loopback.md). Listener admission, nonblocking dial,
stream buffers, deferred operation release, backpressure, half-close, deadlines
and shutdown have one shared implementation. VLESS framing and UUID callback
come from the sibling `steer-protocols/src/vless/inbound.{c,h}` codec. This is an
executable Linux lab path, not production Steer integration, a stable provider
ABI, a provider loader, or a supported server package.

From the hub root:

```sh
make -C steer lab-loopback
# Set STEER_LAB_UUID in the child environment to a disposable lab UUID first.
steer/build/vless-loopback direct 127.0.0.1 0
make -C steer lab-loopback-test
```

CLI: `vless-loopback direct|block [127.0.0.1|::1] [port]`. Bind addresses are
restricted to those two numeric loopbacks. Port defaults to zero; stdout emits
one flushed `PORT <actual-port>` line. `direct` may dial any numeric target a
local client supplies, so use a controlled disposable lab. `block` denies all
requests before dialing. Both modes now compile immutable policy and use the
shared `route_dial` service; the host no longer implements a second connect path.
Generation 1 and inbound `lab-vless` are host-issued. UUID verification maps to
trusted principal ID `lab-vless-user`, never a raw UUID or client-provided ID.
The UUID is required in `STEER_LAB_UUID`, in canonical
36-character hexadecimal form with hyphens at the usual positions; uppercase
and lowercase hex are accepted. Missing or malformed UUID exits 2 before any
listener or runtime allocation. No UUID or credential is logged. This is a
single plaintext lab identity with a simple comparison, not a production
identity store, TLS profile or constant-time authenticator.

Only TCP command 1, numeric IPv4 and numeric IPv6, with no flow or explicitly
empty Flow, are admitted. Domains fail closed without calling a resolver.
UDP, mux/unknown commands, nonempty flows, unsupported extensions, wrong UUID,
invalid headers, block policy and failed dial close the connection without a
success header. VLESS has no SOCKS-style failure reply. The host emits `00 00`
only after actual successful TCP connection and stream adoption, before relaying
target bytes. Parsed header bytes are consumed exactly; fragmented headers and
pipelined payload reuse the same bounded direction buffer.

The shared host allows 32 concurrent clients, two 16 KiB buffers per client,
64 streams/stream operations, 32 independent route operations and a 1 MiB
submitted-byte ceiling, plus bounded metadata.
Handshake and connect deadlines are five seconds each; relay idle deadline is
30 seconds. SIGTERM/SIGINT close active IO and drain deferred callbacks and
releases before destroying services. Opposite-direction reads continue after
one direction's EOF; writes resume partial completion and backpressure through
the stream service. There is no separate VLESS relay or second epoll engine.

Strict GCC C11 and ASan/UBSan with leak detection passed both shared-host suites
in WSL Ubuntu Linux. `vless_loopback_test.py` covers a 1 MiB binary transfer,
fragmented headers/pipelined payload, 16 concurrent relays, half-close, valid and
wrong UUID, malformed version/addon bound, explicit empty Flow, nonempty flow,
UDP/mux rejection, domain rejection, block/refused dial without an optimistic
response, truncated EOF cleanup, IPv6 loopback, absolute handshake timeout,
32-client admission, SIGTERM with pending reads, malformed/missing UUID startup,
and occupied-port cleanup. The sibling SOCKS suite continues to pass unchanged
in behavior, including its independent curl check.

To reproduce sanitizer checks:

```sh
make -C steer -B lab-loopback \
  LAB_CFLAGS='-O1 -g -std=c11 -pedantic -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer'
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  make -C steer lab-loopback-test
```

Synthetic wire tests alone do not establish upstream compatibility. Independent
Xray checks and exact artifact evidence belong to the sibling protocols repo's
upstream matrix. Domain resolution, UDP, negotiated Vision/REALITY/TLS, full
routing, production loading, generation lifecycle, deterministic connect/idle
timeouts, injected platform failures and performance remain outside this slice.
