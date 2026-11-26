# Experimental HY2 inbound runtime

The optional Linux server profile joins the shared managed host, QUIC endpoint, HY2 engine and route/buffer/operation/resolver services. TCP uses shared stream routing; UDP uses origin-owned datagram refs. No independent default-direct socket path exists in the adapter. The [linked v3 profile](../experimental/provider/prototype_core.md#managed-spec-v3-linked-socks-v1) also accepts the explicit QUIC/TLS stream+datagram tuple; it reuses this adapter and transaction. This is a local prototype, not a production release.

New TCP streams and UDP destinations check CURRENT listener/auth admission and generation. Existing destinations retain their generation; a new destination in the same actual UDP session acquires current policy in a separate context. Contexts never merge across actual sessions. Principal IDs are authenticated/copied; source endpoints come from the real QUIC peer.

Disable/remove retires admission and drains old flows until a host-owned monotonic30s deadline. Stop/expiry cancels operations and waits for callbacks before releasing guards. Retired UDP binds remain occupied until drain, without SO_REUSEPORT. IPv6 uses V6ONLY. Deferred router drain notification schedules separate host GC; destruction inside notification is prohibited. Foreign release failure is quarantined, not retried automatically.

## Resource envelope

One host-owned, same-loop UDP budget spans all connections and generations: eight receive slots(capacity65507),64 queued/in-flight upload packets and256KiB upload allocations. Partial metadata/fragments, completed assembly overlap and assembled-to-buffer overlap reserve budget before allocation. Receive slots reserve before target open.

The common buffer host adds UDP allowance to its prior TCP reserve. A test occupies eight UDP receive plus64 upload buffers, then allocates all64 original TCP16KiB buffers. Kernel/socket memory, QUIC/TLS queues and session metadata have separate bounds; this is not an RSS/low-RAM guarantee. Only the owning loop mutates counters.

A poll handles at most32 targets and32 output fragments with round-robin continuation. Replies retain buffers across continuation. UDP is atomic messages with overload/loss drops. Assemblies expire without new traffic. Module-wide16MiB/1024 reassembly caps are additional safety limits, not the service budget.

## Profiles and evidence

The explicit server build requires recipe-generated `-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1` plus server/ECC validation flags. The recipe proves effective gmtime_r settings and compiles the archive with the marker. A changed consumer header cannot fix an already built archive: rebuild the dependency. Old unmarked archives remain negative-controls only.

Official oracle pin: apernet/hysteria`c2b181e0b0e72b077e4b0b7297735af14d1f9929` with pinned quic-go. Dependencies: ngtcp2v1.25.0 plus repository Brutal patches; wolfSSLv5.9.4. Source archive hashes are in[the audit](hy2-quic-audit.md). No Go runtime is linked into Steer.

`SANITIZE=1 sh tests/hy2_datagram_build.sh OUT` covers native65507-byte echo, fragmentation, empty messages, exact packet quota, shared two-adapter budget, queued callbacks after cancel, healthy neighbor recovery, policy/reload/retire and zero final resources.

`prototype_hy2_udp_test.py --host HOST --client PINNED_CLIENT` covers real trusted-TLS3000-byte binary numeric/domain messages, two peers and old/new generations sharing eight RX slots, ninth-target rejection/recovery and listener drain. Near256KiB retained upload and eight RX slots remain present while ten extra SOCKS TCP roundtrips finish. The pinned client rejects zero data and limits its serialization buffer to4096; its gate does not prove zero/65507-byte interop. Those boundaries have independent native tests.

The WSL host routes127.0.0.1 through Windows-facing table127/loopback0(MTU1500). Plain Python UDP1500+ may drop despite send success. Large-message gates run in disposable unshare network namespaces with their own loopback, not the live WSL route. No live network settings change. Host sanitizer gates do not automatically instrument dependency archives or establish throughput/soak.

### D2: first stream on a reduced-MTU path

Run from the repository root with the Full host and pinned adapter client:

```sh
unshare -n sh -ec 'ip link set lo mtu 1380 up; exec python3 experimental/provider/prototype_hy2_mtu_test.py --host "$1" --client "$2"' sh "$HOST" "$PINNED_CLIENT"
```

The gate checks the first 8192-byte echo at the stock 3-second deadline, another
stream, HY2 UDP and 32768 more bytes on the held stream, over both IPv4 and IPv6.
IPv4 controls on `6607986` used the same client and payload:

| Path | Managed before fix | Upstream HY2 server | Managed after fix |
| --- | --- | --- | --- |
| Ordinary loopback | pass | pass | pass |
| Loopback MTU 1380, GSO/GRO on | timeout | pass | pass |
| Server veth MTU 1380, interface GSO/GRO off | timeout | pass | pass |
| Server egress 1500, router egress 1380, ICMP allowed | pass | pass | pass |

On reduced loopback the target received and wrote all 8192 bytes. Single UDP
probes (1406, 1444 bytes) fragmented and were acknowledged after reassembly;
Linux then rejected `UDP_SEGMENT` sends with 1444-byte segments (`EMSGSIZE`).
In a diagnostic 12-second run the client read only 1421 matching bytes while
another peer exchanged a small stream and UDP. In contrast, the routed 1500→1380
control returned ICMP *fragmentation needed* for the 1406-byte probe. The shared
endpoint now forbids IP fragmentation so a probe cannot validate a segment
larger than the path can carry. This gate tests a reduced MTU at connection
start; it does not establish recovery from an MTU decrease on an established path.

### D2: live 1500 → 1380 downshift on an established stream

**Server transmit recovery and client transmit recovery are independent.** To
exercise the former with the stock client and its 3-second deadline:

```sh
unshare -n sh -ec 'ip link set lo mtu 1500 up; exec python3 experimental/provider/prototype_hy2_mtu_test.py --live-reply --host "$1" --client "$2"' sh "$HOST" "$PINNED_CLIENT"
```

After five verified 32768-byte exchanges, the target reads all 32768 bytes of
the next request on the **same TCP socket**, lowers MTU and only then echoes
them. On `1a72adf` the managed server repeatedly sends 1444-byte UDP payloads;
even a diagnostic 12-second deadline yielded 0/32768 bytes. The regression now
passes for IPv4 and IPv6, including a 512-byte message on the pre-existing HY2
UDP session both before and after restoring MTU 1500. An IPv4 three-namespace
veth control changed only the **return route's** MTU at the forwarding router
(both NICs still 1500, interface GSO/GRO off). ICMP reported MTU 1380; all
32768 request bytes sent *after* the change reached the target. The response
timed out before the fix and arrived intact after it.

The pinned ngtcp2 v1.25 public API reports the discovered transmit size but
has no same-path setter; its migration API is client-only. Single-packet
stream/datagram writers accept a smaller destination buffer (minimum 1200).
The aggregate writer still requires a buffer at least as large as the discovered
size. On a single-datagram `EMSGSIZE` at an already validated size, limit only
the affected child's single-packet writer and datagram admission. A failed GSO
batch is first retried as individual datagrams; an oversized discovery probe
does not lower the limit. The first step halves the headroom above 1200
(1444 → 1322 in this test); a second size failure can reach 1200. Loss recovery
repacketizes stream data. This requires a local size error, not just silent loss.

The conservative limit lasts for that connection. Other connections keep their
normal probing and batching. The reduced size can cost throughput: below the
library's discovered size the aggregate helper produces one packet at a time.
In one local 128 × 32768-byte exact echo sample, goodput was 35.1 MiB/s before
and 31.3 MiB/s after the return-path cut. This is a fixture measurement, not
a link-rate benchmark.

**Remaining interop boundary:** if `lo` shrinks *before* the next request, the
stock upstream client keeps sending oversized packets (e.g. 1439-byte segments)
on that unchanged path. The target saw no new request bytes, with either the
managed or the upstream IPv4 server. Disabling client GSO did not cure it.
Pinned quic-go's `send_queue.go` ignores `EMSGSIZE`; its initial-size fallback
does not reset the established path's MTU. Widening the client deadline alone
to 12 seconds did not deliver data. With that diagnostic deadline, restoring
MTU 1500 after four seconds let the outstanding exchange finish without a
reconnect (7.2 s managed, 7.4 s upstream, from request start). That is recovery
after **restoration**, not adaptation of the upstream sender to MTU 1380.
