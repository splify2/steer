# SOCKS5 loopback lab host

`socks_loopback.c` is the SOCKS5 entry point of an executable Linux integration
fixture; `loopback_host.c` supplies the shared listener, dial and relay machinery
also used by [the VLESS entry point](vless_loopback.md). It joins the
bounded SOCKS5 handshake codec in the sibling `steer-protocols` checkout to the
experimental host buffers, operations and stream service, using Steer's existing
`src/daemon/loop.c`. It is not production Steer integration, a loaded provider,
a stable ABI or a supported SOCKS server package.

The host owns loopback accept. The shared `route_dial` service owns nonblocking
TCP connect after `steer_policy_route` evaluates immutable policy. All application
reads/writes, including negotiation responses, go through `stream_v1` and its
buffer ownership rules. There is one process and one existing event loop, with
no worker threads or additional epoll/relay engine. The codec never sees a
socket. The host's `direct`/`block` argument compiles one lab rule with explicit
default block; it does not import Steer's legacy routing configuration.
Generation 1 and inbound `lab-socks` are supplied by the host. Successful
USERPASS verification maps to host-issued `lab-socks-user`; NOAUTH has an empty
principal. Raw credentials and peer-supplied identity never enter route metadata.
The route service sees the original destination before denying unresolved domains.

## Source-linked instance lifecycle

The standalone fixture and the managed prototype now use a separate in-process
SOCKS instance per listener and generation. Preparation snapshots listener
identity and auth policy into generation-owned storage without opening sockets.
The host activates it at publication and quiesces the old instance even when
the listener socket is reused. A TCP session keeps its instance from accept
through the final IO/route operation release, including a handshake already in
progress at publication. The host destroys the retired generation only after
its sessions release those pins. Existing handshake/connect/idle timeouts and
shutdown cancellation are unchanged.

After a valid CONNECT the host takes a `steer_pv1_flow_metadata` record built
from the instance to the existing route service. The instance supplies immutable
generation and inbound identity; the host verifier determines principal, and
the requested destination reaches policy before resolution or dial. Neither
the host nor the relay is duplicated. This is an internal, source-linked
lifecycle, not the draft async provider entrypoint or a separate package.

The managed loopback test checks simultaneous anonymous and authenticated
instances, listener reuse with reordered config, a pending old handshake and
half-close across direct-to-block Apply, and retirement over more commits than
there are generation slots.

## Run

From the hub root in Linux, with the sibling SDK and protocols checkouts:

```sh
make -C steer lab-loopback
steer/build/socks-loopback direct 127.0.0.1 0
```

Syntax: `socks-loopback direct|block [127.0.0.1|::1] [port]`. The default address
is `127.0.0.1`, default port is zero. Stdout prints `PORT <actual-port>` after
successful binding. Other bind addresses are rejected. `direct` may connect to
any numeric IPv4/IPv6 target supplied by the local client; it is not restricted
to loopback destinations. Only use this disposable fixture in a controlled lab.
SIGTERM/SIGINT stop admission, close active streams and pending connects, drain
deferred terminal callbacks, release operation handles, then destroy the stream
and buffer services before exiting.

NOAUTH is the default. Set both `STEER_LAB_USER` and `STEER_LAB_PASSWORD` in the
child environment to require USERPASS. Both must be 1..255 bytes; missing/empty
partners fail startup. There is no fallback to NOAUTH. Credentials are never
printed; these are plaintext SOCKS lab credentials, not an authentication
database or constant-time production verifier. Environment credentials remain
owned by the process; the codec clears its parsed credential storage.

## Bounds and behavior

- At most 32 clients, 64 adopted streams, 64 live stream operations and 32
  independent route operations, including terminal unreleased handles.
- Exactly two host buffers of 16 KiB per admitted client. One direction alternates
  read/write on one buffer, preserving backpressure. Handshake input and pipelined
  payload reuse the downstream-to-upstream buffer. Responses reuse the opposite
  buffer. Fixed codec/host metadata and allocator overhead are additional.
- Full submitted lengths are charged to the stream service's 1 MiB queued-byte
  ceiling. The buffer host separately bounds capacities plus metadata.
- One absolute five-second handshake deadline, a new five-second connect
  deadline and a 30-second relay idle deadline refreshed on IO completion.
  Timeouts close the session; no promise of a timeout reply is made.
- CONNECT handles numeric IPv4 and IPv6. Domain targets fail with REP 4 without
  invoking a resolver. Block policy fails with REP 2; connection refusal uses
  REP 5. BIND and UDP ASSOCIATE fail with REP 7 in the codec.
- Success is emitted only after a successful dial and stream adoption; the
  response contains the actual numeric local bound address and port.
- Fragmented handshakes and coalesced request/payload bytes retain exact consumed
  boundaries. Partial stream writes are resumed. EOF shuts down the destination
  write direction after queued bytes drain, while the opposite direction remains
  readable. Both EOFs finish the session.
- Stream callbacks only record completion and schedule a loop timer. Operation
  handles are released from that timer, after callback return, before resubmission
  or stream release. Shutdown uses the same deferred cleanup path.

There is no UDP, domain resolver, TLS, full routing, or config reload in the
standalone fixture. The managed lifecycle above does not implement a provider
drain deadline, provider discovery/loader or production daemon integration.
Admission is fixed and has no fairness or tenant quota model. Connect readiness
uses the existing loop through `route_dial`; listener readiness uses that loop
directly and payload IO uses the stream service.

## Executed checks

In WSL Ubuntu Linux, strict C11 GCC compilation and the following real TCP
fixture passed:

```sh
python3 steer/experimental/provider/socks_loopback_test.py steer/build/socks-loopback
```

The suite covers a 1 MiB binary transfer, fragmentation, coalesced handshake and
payload, 16 concurrent relays, half-close, refusal/block/domain/unsupported
commands, USERPASS success/failure and downgrade rejection, IPv6 loopback,
handshake timeout, the 32-client ceiling, SIGTERM with pending IO, and occupied
listen-port startup cleanup. If available, the system `curl` independently uses
SOCKS5 to fetch a real loopback HTTP response; that check passed in this run.
The Python fixtures alone are not independent upstream interoperability.

The same suite also passed with `-O1 -g -fsanitize=address,undefined
-fno-omit-frame-pointer` and
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1`.
These results establish the bounded Linux lab path only. Deterministic connect
timeout, idle timeout, injected allocation/epoll failures, production loading,
performance, other platforms and external upstream compatibility matrices remain
outside this check.

The optional `lab-loopback` and `lab-loopback-test` Make targets build/check both
entry points; neither belongs to production `all` or `test`. They require Linux
and sibling SDK/protocols checkouts. `LAB_CFLAGS` controls their flags separately
from production flags. The default includes strict C11/pedantic warnings as
errors. Rebuild with `make -C steer -B lab-loopback LAB_CFLAGS='...'` when changing
flags; Make does not track compiler flag changes automatically.
