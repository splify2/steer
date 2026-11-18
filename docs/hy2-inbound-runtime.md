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
