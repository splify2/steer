# Test oracle: single-peer inbound guard

This is a regression fixture, not a production verifier, not connected to
recovery, and not an advertised capability. It implements exactly one profile:
IPv4 peer source `/32`, one principal, empty policy and DIRECT default. Other
policies, IPv6, extra nft objects/fields or unsupported JSON schema are rejected.
It uses no fingerprint and does not derive an expected ruleset from a prior
snapshot. Expectations are independently assembled from the documented
`kernel_wg_guard.c` structure and the fixture's table identity, ifindex and peer.

The oracle checks the exact two chains, base-chain filter/prerouting hook,
priority -160 and accept policy, every rule and expression in chain order,
interface match, source, goto and verdict. The table handle and marker must
match the supplied identity. Rule/chain handles and counter values are not
policy: counter values must still have the expected numeric structure. Because
`nft -j -n` on the tested version resolves `meta iif` to an interface name,
the oracle resolves the independently supplied ifindex to the current name
and checks the reverse lookup. It is not an atomic kernel snapshot or proof
against a concurrent CAP_NET_ADMIN actor. The fixture does not verify WG peer
keys or device ownership during recovery.

Run independently of `make test`; root/CAP_NET_ADMIN, Linux WireGuard, nft,
Python 3, compiler and `unshare` are required. Only a newly created netns is
mutated. The C fixture refuses to run unless fd 3 identifies a different outer
namespace and uses the actual managed `kernel_wg_guard` prepare/bind/publish
operations with an owned disposable link and planned table marker.

```sh
SDK=/absolute/path/to/plugin-sdk sh tests/inbound-guard-oracle.sh /tmp/opencode/inbound-guard-oracle
```

The test confirms the real table, injects invalid JSON geometry, seeds and
resets counters while checking every other field and handle remains unchanged,
then replaces the peer chain's `accept` with `drop` while retaining the table
name, marker and table handle. The last listing must be rejected. The fixture
retires its owned link and table; the namespace is disposable even on failure.
The oracle deliberately supports the exact JSON schema observed in this test;
another nft version may be rejected until explicitly understood and tested.
