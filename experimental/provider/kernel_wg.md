# Experimental kernel WireGuard lifecycle and ingress guard

`kernel_wg` is a Linux source-only owned-device adapter. Prepare resolves bounded
host secret refs into wiped buffers and a sealed anonymous 0600 memfd, then uses
existing `awg_conf_parse`. No Endpoint is required/emitted for server peers.
Activation exclusively creates ordinary kernel WireGuard, captures ifindex and
uses existing `awg_dev_configure`; it verifies UP/addresses/peers. No ip helper,
new netlink stack or userspace WireGuard implementation is introduced.

Rollback/retire check namespace, name, kind and captured index and delete by index.
Existing devices are never adopted. Same-name replacements are preserved. Destroy
refuses an owned active interface; after identity loss it can release only
userspace resources. The initial bounds are 8 peers, 8 interface prefixes and
8 AllowedIPs per peer. Key/PSK values stay out of config/logs; zero private/public
keys, zero explicit PSKs and duplicate peer keys are rejected. The adapter is
serialized, not a sandbox against another CAP_NET_ADMIN actor.

`kernel_wg_guard` compiles the same immutable policy visitor into existing nft IR
and chain printer. The guarded activation hook installs DROP for captured iif
while the fresh interface is DOWN, before configuring keys/listening. Only then
can selected policy be published. Verified kernel AllowedIPs map to principal
IDs; overlapping source prefixes are rejected. Rules preserve order, inbound,
principal, CIDR and explicit default. TCP/UDP port rules are split by protocol;
portless ICMP/other IP skip those conditions. Applicable domain rules fail prepare;
unrelated inbound/principal domain rules do not block this provider. A shared
packet evaluation entry preserves the existing stream nonzero-port invariant.
Each peer admits at most 128 applicable rules. Scoped guard table names are random.

Nft mutation uses existing C argv execution/deadline transport and existing parser
for `nft --echo --json --handle`. Deletes address the captured table handle inside
an atomic delete/create transaction, so a foreign same-name replacement between
check and apply is never mutated. Echo captures the newly created kernel handle;
there is no unsafe postcommit lookup/adoption by name.

Publish/replace returns error plus UNCHANGED/CHANGED/UNCERTAIN. A confirmed new
handle transfers ownership even if the command later errors. Unknown postcommit
state retains both contexts and takes only the captured owned WG interface DOWN
before returning. It must not be reported as unchanged runtime or successful
rollback. Destroy refuses uncertain contexts. Explicit recovery requires device
retirement and external table reconciliation, then read-only absence verification;
the adapter never guesses ownership or deletes a table observed only by name.

Policy-only replacement uses a prepared snapshot with identical peer/device
identity mapping, atomic per packet. Existing WG flows can be affected; these are
not pinned stream generations. Peer/device replacement needs separate resource
preparation; same-port atomic handover is not claimed. On normal teardown remove
the device before its guard. Wrong namespace and foreign table/interface identity
are rejected. An existing source file and runtime core configuration are untouched
by these standalone adapters.

Strict C11 and ASan/UBSan+leak namespace suites passed in WSL Linux, 2026-11-17:
prepare-without-mutation, rollback, raced device refusal, namespace identity,
foreign replacement preservation, missing echo recovery, raced table replacement
between check and apply, confirmed postcommit tool failure and unknown replacement
with fail-closed DOWN. Independent wireguard-tools initiates a real handshake and
IP traffic through the adapter. IPv4 and unrelated IPv6 tunnel topologies verify
DROP before publish, principal DIRECT, TCP/UDP port BLOCK, portless ICMP and
BLOCK/DIRECT reload on the same interface. All disposable keys/namespaces clean up.
Legacy `awgmatch` rebuilt: 153 passed, 0 failed. Existing endpointless legacy
`tests/awg-inbound-ns.sh` also passed independently.

Build the adapter runner from kernel_wg_test.c, kernel_wg.c and existing awgdev.c
with SDK and core includes. The guard runner additionally links kernel_wg_guard.c,
policy.c, ir.c, print.c, nftdump.c, run.c, ynode.c, err.c and existing libyaml
sources. Use function/data sections and linker GC for the chain-only printer;
the guard test wraps run_output for deterministic failure/race injection.
Run kernel_wg_ns_test.sh or kernel_wg_guard_ns_test.sh in an isolated root WSL
namespace with nft/ip/wg/ping tools. Normalize CRLF copies into /tmp first.

This is not yet configured prototype/UI support, a stable SDK device API or the
full product gate. Kernel WG UDP ListenPort binds all addresses; loopback-only
listen semantics cannot be fabricated. Outer UDP exposure needs an explicit
kernel policy. Durable disk+kernel apply also needs a coordinated journal because
nft publication remains fallible. WG detours over protocol groups require an
actual shared outbound datagram service/relay and independent interoperability;
a socket fwmark alone does not turn WG UDP into VLESS XUDP. Legacy host-TUN
currently carries UDP only and resets TCP; protocol egress requires a preserved
identity source into the shared net1 runtime. These are subsequent integration
work, not capabilities claimed by this device/guard gate.
