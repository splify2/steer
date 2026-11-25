# Plain VLESS origin stream backend

`vless_stream_backend.c` layers plain VLESS v0 TCP over a host-selected prepared
stream binding on the same serialized owner loop. It never owns sockets, DNS
or an fd representation of the lower stream. Its immutable context copies the
upstream endpoint and UUID, retains the lower binding and issues its own copied
provider/instance/generation identity. Original target and trusted inbound/
principal IDs remain separate flow metadata. The protocol request uses the
shared socket-free codec from steer-protocols.

Open handles partial request-header writes before returning its origin stream.
Success means ordered lower output acceptance; VLESS has no final-target connect
acknowledgement. Reads incrementally remove response headers and preserve
coalesced payload. EOF before a complete valid response is an error. Half-close
is advertised only when the actual lower handle supports it; accepted finish
rejects later writes and leaves reads usable. Pending write/queued callback
rejects finish without changing the write barrier. Completed but unreleased
operation references count against admission.

Streams, operations, submitted bytes and header buffers are bounded. Continuation
and completion pumps process at most32 each per owner turn. Absolute monotonic
deadlines are checked at lower/header progress, completion and public delivery;
timer conversion uses quotient/remainder rounding, LONG_MAX capping and rearm.
UUID wire headers are wiped before buffer release and immutable UUID is wiped
on destruction. There is no credential logging.

Public release consumes independently of private lower cleanup. If a lower
provider refuses release, a bounded private context retains budget and binding
pin; its quarantine count is exposed. Explicit max32-item recovery after lower
quiescence replaces automatic retries. Retirement prevents new admissions;
existing streams/operations retain exact generation lifetime through releases
and deferred finalizer return.

From this directory:

```
make BUILD=/tmp/steer-vless-origin-check \
  /tmp/steer-vless-origin-check/vless-stream-test \
  /tmp/steer-vless-origin-check/vless-stream-deadline-test
/tmp/steer-vless-origin-check/vless-stream-test
/tmp/steer-vless-origin-check/vless-stream-deadline-test
python3 vless_stream_xray_test.py \
  --xray /tmp/steer-upstream-lab/xray-f781c68715cda8a896dde7a19966980a15e53071 \
  --probe /tmp/steer-vless-origin-check/vless-stream-test
```

Strict C11/pedantic and ASan/UBSan/leak checks pass for forced one-byte header/body
writes and reads, coalesced bounded addons/payload, response only after FIN,
bad version/truncated header, cancel and retired-generation drain. TSan passes
the network and fake-lower deadline/private-release fixtures. The deadline
fixture suppresses only initial open timers through a test-only linker wrapper,
proving late lower/header/publication checks independently. UINT64_MAX uses a real
timer. A temporary copy without absolute checks fails late-publication assertion.
No production timer/clock test hook exists.

Pinned Xray SHA256 `b02576a30eb713471a91f7407d76a0b035ebf262986a36cb5e06a38d91a16c35`
passes plain-TCP echo with explicit loopback-only freedom allow. This target
answers before FIN: the gate does not establish Xray forwarding request FIN,
TLS/certificate verification or response addons. The local test separately
checks EOF-dependent reverse response.

The [managed linked profile](prototype_core.md#managed-plain-vless-tcp-outbound)
can prepare this backend as a named spec v3 TCP outbound. It uses the same
source-linked provider and generation leases, not the general v3 executor,
plugin loader or stable ABI. TLS/WS/H2/gRPC/XHTTP composition, Vision/REALITY and
UDP remain unsupported.
