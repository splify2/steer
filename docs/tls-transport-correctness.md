# TLS/Vision/HTTP2 correctness checkpoint

Prepared trust uses an owned, bounded PEM snapshot for the incremental TLS path.
`tests/certprepared.py` checks chain/name/expiry/signature failures, explicit pin
and insecure policies, input lifetime and concurrent verification without file
fallback. The existing crypto root store serializes verification with a mutex;
concurrent safety does not make a shared store nonblocking for owner loops.
The new runtime must use bounded per-owner preparation or an admitted verifier
worker with explicit cancellation and lifetime ownership.

This test reproduced a race in the previous wolfSSL POSIX profile:
`wc_ValidateDateWithTime` used libc `gmtime` across different root stores.
The Linux/Apple profile now selects `gmtime_r`; the build recipe probes the
effective macro and records `STEER_WOLFSSL_POSIX_TIME_SAFE=1` in archive flags.
The explicit Linux HY2 recipe rejects an archive without that marker. Rebuild
the dependency itself: recompiling a consumer with a changed header is not a fix.
The old archive fails the concurrent TSan test; the corrected server archive
passes TSan and ASan/UBSan/leak checks. The 13-value crypto ABI vectors agree
between the old and corrected client/server profiles. This verifies the date
race and prepared trust checkpoint, not a completed asynchronous TLS backend
or race freedom throughout wolfSSL.

The source changes delay Vision DIRECT until its complete payload and padding
have been consumed. TLS1.3 retains directional application traffic secrets in
the old handshake-transcript footprint and processes fragmented post-handshake
messages. Requested KeyUpdate responses precede later application records;
previously encoded ciphertext keeps its original epoch. Secrets are wiped on
rotation, terminal failure and free. No struct size or original field offset
changes are required. TLS1.2 does not inspect the post-handshake overlay.

HTTP2 scans bounded header blocks across transport reads and contiguous
CONTINUATION frames using the existing 64-byte control scratch. Static indices,
split HPACK integers, literal strings and exact plain/Huffman `:status` and
`grpc-status` names/values are supported. Unrelated literal strings are skipped
by their declared length; this is not a general Huffman/dynamic-table decoder.
Header blocks are limited to 64 KiB and the initial status prefix to 64 bytes.
The advertised dynamic header-table size is zero; illegal dynamic references
and table updates fail closed. DATA needs a final HTTP 200, and END_STREAM waits
for END_HEADERS. gRPC clean EOF requires complete message framing and a verified
terminal HEADERS block with grpc-status zero. Missing/nonzero status and resets
are errors. Stream-up auxiliary failures reach the next write.

Verification in WSL:

* `tests/tls13abi.py` compares size, alignment and every legacy TLS offset with
  pinned pre-change commit `05742cc0f87a00f84dd43bd441cdcaa1fd10151c`.
* `tests/tls13post.py --wolfssl-library PATH/libwolfssl.a --sanitize` uses the
  matching `PATH/libwolfssl.a.cflags`. Three real AEAD suites cover fragmented
  KeyUpdate, old/new epochs, invalid requests, repeated free, encrypted Vision
  boundary splits/raw tail and coalesced replies under socket backpressure.
  It also runs an old-header executable against a newly compiled TLS DSO.
  The test-only initializer enters the post-Finished phase; it is absent from
  production builds. The pinned lab archive lacks PIC, so the old consumer
  exports its real crypto backend to the test DSO. ASan/UBSan/leak checks pass.
* `h2match`, `tls13readmatch`, `visionmatch`, `xhupmatch` and `trdialmatch` pass.
  H2 also passes strict C11 warnings and ASan/UBSan.
* `tests/transport_interop.py --xray BINARY --probe PROBE` passes stream-one,
  stream-up and packet-up TLS echo against Xray commit
  `f781c68715cda8a896dde7a19966980a15e53071`. The existing `application/grpc`
  header remains: pinned Xray sets it for stream-up/one unless NoGRPCHeader.
  Temporary certificates, public lab UUID and an exact loopback echo allow-rule
  are generated only inside the test. Management/live processes are untouched.
  The self-signed lab certificate is explicitly insecure: this checks record and
  transport interoperability, not certificate trust/name verification.
* `tests/transport_oracle.go` independently reads the request to EOF before
  responding. The same runner with `--oracle BINARY --halfclose` passes TCP/TLS,
  XHTTP stream-one/stream-up and gRPC; `--network tcp|grpc` selects those modes.
  The probe transfers ownership through `transport_moved` after its handshake.
* `tests/tls_keyupdate_oracle.go` uses a standard Go TLS handshake, captures keys
  privately, then emits RFC8446 KeyUpdate and authenticates the reply under the
  old client epoch before sending new-server-key application data. Run with
  `--oracle BINARY --network tcp` (without `--halfclose`). This gate passes.
  Neither Go oracle logs traffic secrets.

The explicit per-session companion admits raw TCP (plain/TLS1.3), gRPC and XHTTP
stream-one/stream-up without Vision or VLESS encryption. TLS close_notify is
ordered after queued ciphertext; shutdown retries drain and preserves reads.
Peer-requested KeyUpdate after local close still rotates the receive epoch
without writing after close_notify. TLS EOF without close_notify is truncation.
H2 sends exactly one END_STREAM and keeps the reverse stream available. VLESS
passes the companion explicitly to pool_run_ex; old dialer/transport layouts
remain unchanged. WS, HTTP upgrade, packet-up, raw TLS1.2, Vision and VLESS
encryption do not advertise half-close support in this companion.

The Xray `--halfclose` echo-after-EOF gate currently fails: pinned freedom's
request copy returns without target CloseWrite, so an EOF-dependent target
responds only when the complete connection times out/closes. Basic Xray echo
and the independent EOF-response oracles are separate evidence. Full net1 old
plugin/new library compatibility and real worker concurrency tests are separate
acceptance gates. These changes are not a release or universal provider runtime.

Protocol references: [RFC8446](https://www.rfc-editor.org/rfc/rfc8446.html),
[gRPC HTTP2 response/trailers](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md),
and pinned Xray [XHTTP configuration](https://github.com/XTLS/Xray-core/blob/f781c68715cda8a896dde7a19966980a15e53071/transport/internet/splithttp/config.go).

REALITY completion must include a real pinned-server handshake with
CertificateVerify. Xray pins REALITY `4bb46b2afd8b`, whose
[server handshake](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/handshake_server_tls13.go)
emits Ed25519 CV after the authenticated temporary certificate. The old minimal
synthetic fixture omitted CV and does not define wire compatibility. The new
CV unit uses actual test-only Ed25519 signing and checks signature/transcript/
wrong-key rejection; production keeps verification-only Ed25519 support.

That pinned server also conditionally emits a one-byte NewSessionTicket
handshake payload after Finished for target-length padding. Its interaction
with strict post-handshake parsing still needs a real server gate. No generic
TLS parser relaxation is implemented or justified by this source observation;
any proven interoperability accommodation must be scoped to explicit REALITY
and that exact behavior. Verified TLS and the new incremental engine cannot
inherit a no-CV or incomplete-handshake acceptance exception.

The shared handshake-message parser now enforces the EE → Certificate →
CertificateVerify → Finished order, exact EE/ALPN vector boundaries, duplicate
extension rejection and an explicit handshake-record boundary at Finished.
`vlessmatch` exercises sixteen malformed variants under real record encryption,
with the fixture signing its actual transcript and producing a correct Finished.
A borrowed view of the exact prepared ClientHello binds the echoed session ID,
cipher, key-share group, signature scheme and ALPN (length plus bytes). ECH uses
its expanded inner transcript. Embedded-NUL/unoffered ALPN and unoffered TLS
signature schemes fail closed. The pinned REALITY profile is deliberately
separate: upstream [4bb46b2afd8b](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b/handshake_server_tls13.go)
forces Ed25519 independently of the mimicked browser offer. Only authenticated
REALITY permits that mandatory0807 proof; ordinary TLS rejects the identical
unoffered scheme. Its HMAC/public-key authentication and actual CV signature
remain mandatory. Browser fingerprints are unchanged.

The offered-view sanitizer fixture, signed encrypted legacy handshake fixture,
old-header/new-DSO IO, pinned Xray TLS XHTTP three modes and independent Go TLS
EOF/KU fixtures pass this extraction checkpoint. The interop probe still uses
explicit insecure lab policy; prepared-trust tests separately cover trust/name
verification. A temporary source with only the duplicate-EE guard disabled makes
the real-crypto fixture fail, proving that guard is exercised. No runtime
TLS-layer capability follows: `tls13_engine.h` is a source-only draft, and its
bounded incremental owner-loop implementation/lifecycle gates remain work.
