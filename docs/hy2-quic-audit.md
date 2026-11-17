# HY2 / QUIC correctness audit tranche

This is an isolated source/test milestone. It does not establish a production
HY2 inbound server, end-to-end HY2 interoperability, throughput, low-RAM sizing,
or a soak result. The HY2 module entry now explicitly uses the versioned
half-close companion through `stack_run_ex`; the additive net1 export gate is
coordinated separately from experimental inbound host registration.

## Reproduced and corrected

* The real HY2 response callback rejected a valid three-byte response coalesced
  with 65536 application bytes. It now incrementally retains only bounded header
  state and leaves payload bytes for the receive queue. Every incomplete header
  prefix followed by EOF fails promptly, including an empty FIN callback.
* UDP assembly matched an expired packet ID before TTL checking, had no entry
  limit, and allocated fragments before checking the 65507-byte packet limit.
  Tests reproduced all four failures before the fix. TTL now precedes identity
  lookup; the worker also expires assemblies each second without new fragments,
  and connection teardown frees them immediately.
* Sending on an unopened local QUIC stream returned success and closed the
  entire established connection. Live-stream tracking now rejects missing or
  retired handles with `QC_ENOSTREAM`; peer streams are registered before the
  application callback. Healthy neighboring streams remain usable.
* The datagram size promise used our four-byte source CID rather than the
  peer's destination CID. A pinned independent client with a 20-byte CID could
  not receive the C endpoint's own advertised maximum datagram before the fix.
  The cap now conservatively reserves QUIC's maximum 20-byte destination CID,
  including rotations, without adding a dependency export.
* Source-only HY2 `hy2_flow_extensions()` provides per-session TCP half-close.
  FIN follows pending uplink bytes exactly once; normal half-close does not
  STOP_SENDING. After both EOFs the application detaches without RESET while
  QUIC retains chunks/FIN until ACK or stream close. A real loopback loss test
  drops outgoing traffic for 150ms after peer EOF and application detachment,
  verifies retransmitted exact final data/FIN, then a healthy neighbor stream.
* Regular peer stream closure did not return MAX_STREAMS credit. A real QUIC
  test stopped at exactly 16 of 40 sequential fully closed streams without closing
  the connection. The close callback now returns one peer-initiated bidi/uni
  slot, never a local slot. Two generated ngtcp2 exports require additive
  `steer-crypto 1.1`; no existing export was removed.
* HY2 engine cancellation discarded delivered-but-unconsumed bytes without
  returning connection credit. Per-stream uncredited-byte accounting now
  covers queued payload, parsing prefixes and rejected callback remainder;
  cancellation returns the remainder once, and late write completions cannot
  double-credit it. The real pinned client cancels 25 streams with 50000 queued
  bytes each, exceeding the 1MiB connection window, while neighbors continue.
* HY2 transport closure no longer synthesizes clean EOF without observed
  STREAM FIN. RESET code 0/nonzero is terminal failure when no FIN was received;
  nonzero transmit-side errors are preserved by the QUIC close callback.

## Assembly accounting scope

Each UDP flow retains at most 16 incomplete packets for five seconds. The oldest
is evicted when full. Module-wide atomic safety ceilings are 1024 assemblies
and 16MiB of allocated assembly metadata plus fragment buffers, reserved before
allocation and released on all allocation failures, completion and expiry.
These conservative legacy safety defaults are not a measured Steer resource
budget. The byte ceiling roughly matches the existing legacy connection receive
window; it is not per-instance and must become an explicitly runtime-owned
shared budget in the new core. A single flow can still approach 1MiB.

Completed caller-owned packets (at most 65507 bytes plus caller prefix per call),
malloc overhead, completed UDP queues, QUIC/TLS state and receive windows are
outside this accounting. Therefore 16MiB is not an RSS ceiling. Concurrent tests
exercise eight workers, allocation rollback, entry/byte admission and return to
zero; they do not establish low-memory deployment suitability.

## Pinned evidence and limits

Dependency sources used in the disposable WSL lab:

* ngtcp2 v1.25.0, source archive SHA256
  `2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb`,
  with this repository's two Brutal patches. Build: `NGTCP2_STATICLIB`.
* wolfSSL v5.9.4, source archive SHA256
  `7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57`,
  repository `build/wolfssl/user_settings.h`, Linux pthread profile, noasm lab
  build, `WOLFSSL_USER_SETTINGS` and explicit `STEER_WOLFSSL_SERVER`.
  Server builds additionally require `WOLFSSL_VALIDATE_ECC_IMPORT`: pinned
  wolfSSL otherwise accepts an unrelated valid EC private key in
  `wolfSSL_CTX_check_private_key`. The server recipe adds this flag and records
  it in `.cflags`; client/minimal flags remain unchanged. The old lab server
  archive is not a validated server profile.
* Independent client: Hysteria commit
  `c2b181e0b0e72b077e4b0b7297735af14d1f9929` core module's pinned
  `github.com/apernet/quic-go v0.65.1-0.20261109005002-2895f039137a`.
  The oracle uses a disposable certificate and loopback UDP only.

The proposed MAX_DATA callback deadlock assumes that ngtcp2 sets
`STREAM_DATA_BLOCKED` on connection-level exhaustion. In pinned
`lib/ngtcp2_conn.c` around lines 4449–4492 that error is conditional on remaining
connection credit; zero connection credit returns without setting our stream
blocked flag. A small-connection-credit / large-stream-credit regression guards
progress. No speculative callback was added.

The proposed Linux first-init mutex corruption also has a false premise for
this profile: wolfSSL's static `inits_count_mutex` expands to a pthread static
initializer and initialization holds it. This source finding does not establish
correctness for every wolfSSL platform/profile; no scrypto change was made.

## Reproduction

Use already verified static archives and their generated `.cflags` files:

```sh
SANITIZE=1 sh tests/hy2-audit-build.sh /path/libngtcp2.a /path/libwolfssl-server.a /tmp/hy2-audit
```

The script runs allocation/concurrency accounting, real callback response
framing, real QUIC FIN-loss lifetime and legacy QUIC regressions. With a CRLF
Windows checkout, run an LF-normalized temporary copy and set
`STEER_SOURCE_ROOT` to the checkout's Linux path. Dependency archives themselves
are not sanitizer-instrumented. Build/run `qcendpoint_client.go` inside the
pinned Hysteria core module and use `qcendpoint_test.py` with the separately
built `QC_WITH_ENDPOINT` server for the independent 20-byte-CID regression and
multi-connection/capacity/idle/peer-isolation gate.

Pending, not established by this tranche: GSO EMSGSIZE fallback, sustained
datagram/stream fairness, cached timer precision, oversized auth probe response,
Brutal rate-update timing, and worker reconnect/soak behavior. Do not describe
these audit items as fixed or tune windows/worker counts without measurements.

## Isolated core-service adapter gate

`experimental/provider/hy2_inbound.c` connects the protocol engine to the
existing core route, resolver, stream, buffer and loop services. Its isolated
fixture is not shared-host/config registration. `tests/hy2_adapter_build.sh`
builds the fixture with verified dependency archives; build
`tests/hy2_adapter_client.go` in the pinned Hysteria core module, then run
`experimental/provider/hy2_adapter_test.py --host ... --client ...`.

The gate verifies binary TCP echo and localhost routing, auth refusal,
CURRENT listener/auth-epoch admission, existing-flow preservation, negotiated
capacity and recovery, and 40 sequential flows after draining. Backend EOF and
resolver barriers prove pending IO/route cancellation. A lab-only linker
wrapper delays forwarding a real connected-success callback until after
protocol cancellation; it exercises queued-success cleanup without replacing
core routing or sockets. Stop requires lease/operation/buffer counts to drain
to zero. Invalid protocol config fails before bind; optional web body is owned
after open and checked through an independent HTTP3 request after caller input
is overwritten/freed. This is TCP-only lab evidence, not full HY2 support,
production, all-core integration or a soak result.
