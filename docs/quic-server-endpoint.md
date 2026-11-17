# Bounded Linux QUIC server endpoint

`QC_WITH_ENDPOINT` adds the reusable `qc_endpoint_*` API to the existing C
ngtcp2/wolfSSL wrapper. It does not copy another QUIC or TLS stack. It is not
yet enabled in production net1 builds, exported as stable ABI or advertised as
an installed Hysteria2 server. The existing client API and the legacy
`QC_WITH_SERVER` single-peer test listener remain available unchanged.

One endpoint owns one unconnected nonblocking UDP descriptor, one shared TLS
server context, and at most 64 independently timed connections. The configured
limit must be 1..64. Each connection has at most eight CID slots: original
Initial DCID, server SCID and subsequently issued CIDs. Original DCID survives
retirement of server-issued IDs so retransmitted Initial packets keep routing.
All aliases are removed with their connection. CID collision/capacity failure
fails that admission/connection rather than silently routing across peers.
CID lookup is bounded linear search; performance under load is not certified.

Packets are demultiplexed by clear destination CID and fixed peer address.
Migration/rebinding is unsupported and a known CID from another address is
dropped. Unknown short headers and non-Initial long headers do not allocate.
New Initial packets require at least 1200 bytes, version 1 and an available
slot; excess connections are silently dropped. Processing consumes at most
64 UDP datagrams per readiness callback. There is no Retry/token service yet;
ngtcp2 owns QUIC address validation/anti-amplification. No response is sent for
an unknown unsupported packet or a full endpoint.

The endpoint owns all child objects and TLS/UDP lifetime. `on_connection`
allocates application context and provides per-connection callbacks before the
first Initial enters ngtcp2; no QUIC application API may be called from that
admission callback. It is not authentication. Only `on_handshake` establishes
transport readiness; applications still must perform their own authentication.
Stream/datagram callbacks before handshake or marked 0-RTT are rejected before
reaching application code. wolfSSL server context explicitly sets maximum early
data to zero. Standalone/coalesced 0-RTT cannot enable application auth.

Event-loop owner calls endpoint fd/readable/timeout/timer methods. These are
serialized and non-reentrant. Connection stream/datagram APIs remain usable;
child qc_run/qc_on_readable must not read the shared descriptor. `qc_free` on a
child requests closure and defers freeing to endpoint post-callback reaping,
never closing the shared descriptor. Never use a child after its on_closed
callback. Callback-owned context may be destroyed then; callbacks can be nested
by operations that close a connection. `qc_endpoint_free` is prohibited inside
callbacks/processing; call it only after the processing function returns.
Destroy closes/notifies all children before releasing the TLS context/socket.

The endpoint caps configuration values: send buffer <=16 MiB, receive window
<=64 MiB, stream receive window <=8 MiB, initial bidi stream count <=256,
datagram frame limit <=65535. Existing per-stream send and datagram queue caps
still apply; application queues and their aggregate memory budgets remain the
protocol/host's responsibility. The endpoint is bounded, not a claim that the
maximum simultaneous configuration meets OpenWrt memory/performance budgets.
Incoming datagrams use a single 64 KiB endpoint buffer, with no GRO; existing
per-connection GSO send/fallback is reused. Children discard unused standalone
RX workspaces. ALPN and certificate/key data are consumed/copied on open;
callers may release them after success. Endpoint callback tables are copied;
user context must live until endpoint destruction.

## Executed checks

Pinned Hysteria commit `c2b181e0b0e72b077e4b0b7297735af14d1f9929` supplies the
independent apernet/quic-go version from core/go.mod. Lab client source is
`tests/qcendpoint_client.go`, compiled in a disposable cmd directory of that
pinned module; it is never a runtime dependency. Its TLS certificate verification
is intentionally disabled for the public disposable qccert fixture; certificate
verification is checked separately by the existing qcloop suite.

`tests/qcendpoint_test.py` checks two concurrent connections with binary streams,
FIN and QUIC DATAGRAM echoes, rejection of a third connection while both remain
usable, capacity reuse after peer close, replay of a known Initial from another
UDP peer, and timer-based idle close/reaping. It checks endpoint counters:
three admitted/handshaken/closed, zero remaining, at least two idle expiries and
zero application callback errors. It then admits a fourth independent client,
requests qc_free on its endpoint-owned child, and verifies closure/reaping with
the shared socket still alive. Malformed/unknown UDP packets are sent before
the healthy clients and must not alter admission counts. The client also appends a syntactically
complete synthetic 0-RTT packet to its valid first Initial; no early-data keys
are provisioned and no pre-handshake application callback is permitted. This
is not a resumed-session 0-RTT acceptance test.

Strict endpoint checks passed in Ubuntu WSL2. Existing qcloop passed 135 checks
and qcbatch passed 33 without defining QC_WITH_ENDPOINT. All three checks also
passed with the wrapper/test code built using ASan/UBSan, leak detection and
halt-on-error. Dependency static archives used normal builds, so this does not
claim instrumented coverage inside wolfSSL/ngtcp2. This is QUIC
transport evidence, not Hysteria2 authentication/TCP/UDP server interoperability.

Build against server-enabled dependency archives generated by the repository
recipes (exact source versions/checksums are in build/*/fetch.sh):

```sh
sh tests/qcendpoint_build.sh /path/libngtcp2.a /path/libwolfssl-server.a /tmp/endpoint-check
python3 tests/qcendpoint_test.py --server /tmp/endpoint-check/server --client /path/pinned-quic-client
```

The wolfSSL recipe requires `STEER_WOLFSSL_DEFS=-DSTEER_WOLFSSL_SERVER` and
automatically adds `WOLFSSL_VALIDATE_ECC_IMPORT` for private/public EC key
correspondence validation. Server profile gates require both in `.cflags`; default
client/minimal builds define NO_WOLFSSL_SERVER. Consequently a new endpoint
object cannot be linked against the existing client-only wolfSSL artifact.
Shipping a Linux server profile requires explicit server capability and size
verification; it must not silently replace a minimal client/OpenWrt profile.

## Optional profile and size baseline

`build/linux-quic-profile.sh client|server OUT WOLFSSL_ARCHIVE NGTCP2_ARCHIVE`
builds an explicit optional Linux transport archive from the same core-owned
sources. Server mode requires server-enabled wolfSSL metadata and defines
QC_WITH_ENDPOINT. Minimal client mode requires client-only wolfSSL metadata.
Neither modifies existing shipping default builds, exports, manifests or
OpenWrt packages. This archive is a build ingredient, not an installed server.

Measured in Ubuntu WSL2 x86_64, GCC 15.2.0, identical `-O2 -g0` transport
optimization and repository-pinned dependencies built without assembly:

| Artifact | Client | Server | Increase |
|---|---:|---:|---:|
| wolfSSL static archive | 1,809,940 | 1,867,940 | 58,000 bytes |
| QUIC transport archive | 58,524 | 75,744 | 17,220 bytes |
| Comparable stripped link probe | 1,463,872 | 1,508,928 | 45,056 bytes |
| Transport object text total | 22,944 | 30,748 | 7,804 bytes |

The link probe is the same `tests/qcprofile_size.c` source, with an additive
server branch enabled only in the server build and dead-section elimination.
It is not executed, installed or advertised as a product. Archives include
object/container overhead; these numbers are neither a compressed package nor
RSS/throughput measurement, and do not establish a native Linux performance
gate. An eventual shared net1/server package needs its own export-map, build
compatibility, rollout and performance verification.
