# Isolated WireGuard coordinator checkpoint

`experimental/provider/kernel_wg_coordinator.{h,c}` runs the staged fixture's
ordering on a serialized worker with explicit backend callbacks. It reuses the
existing owned-link and guard payloads in `execution_journal`; no keys or
configuration text are journaled.

1. Sync the owned link intent, then create DOWN and stage the lowered config.
2. Sync the guard intent, install DROP, and sync the exact captured handle
   before permitting the owned-link UP callback.
3. Sync the policy replacement intent and capture the replacement handle in
   its outcome. Only then return a ready candidate. Promotion and durable
   selection of the active config remain separate host operations.

Failed build/apply does not mutate the previous generation. The profile
requires disjoint staging resources, including listen ports; same-port handover
is unsupported. Recovery is explicit per transaction and validates the whole
journal before effects. It retires the owned link first, then removes only the
exact proven guard. If an outcome was lost and a table with the marker remains,
the coordinator leaves that table for reconciliation. Errors and deadlines may
leave work to recover; an apply error is not proof of cleanup.

The new standalone test uses a real temporary journal and an injected backend.
Run `sh tests/wg-coordinator-build.sh /absolute/isolated/build`. It does not
touch networking.

## Real link adapter

`kernel_wg_linux_link.{h,c}` connects the coordinator's create/stage/retire
callbacks to the composite owned WireGuard operations. It pins the worker's
network namespace and rejects the caller's outer namespace and PID 1's
namespace. It has no UP callback and is not a complete backend.

`sh tests/wg-linux-link-build.sh /absolute/isolated/build --netns` launches a
disposable namespace and exercises the new coordinator with a real link and
journal. Its guard stub deliberately fails before UP; it never calls nft.
The fixture checks the staged peer and address on the DOWN link, normal
rollback, and exact recovery after SIGKILL leaves a staged link and a durable
guard intent. Without `--netns` it only builds and checks namespace refusal.

## Guard identity and recovery

`guard_plan` mints a managed marker before bind; the legacy bind hook is
unchanged for standalone callers. The managed transaction attaches the marker
at creation and validates it together with the name, family and new handle
in the transaction echo. A subsequent lookup alone cannot promote an unknown
result to CHANGED. Before UP the host checks the durably captured DROP handle
and marker using exact `inet` GETTABLE. `guard_retire_record` rechecks the
worker/pinned namespace, boot, and captured index absence through RTM_GETLINK,
then deletes only the exact observed marker+handle. These calls reuse the
existing bounded netlink and nft transaction paths under one deadline.

## Core Apply: privileged isolated profile

The optional `steer-prototype-wg-netns` binary accepts `--wg-netns-profile
--control PATH --state-dir DIR`; fd 3 must pin the outer network namespace.
The profile requires Linux root with CAP_NET_ADMIN, a different namespace
from the outer namespace and PID 1, disabled IPv4 forwarding, and an owned private state directory
containing a pre-existing owned private `wg-journal` directory. The default
prototype binary and ordinary server arguments never register this profile.
There is no fallback to existing host interfaces or services.

This uses the same Core control `STATUS`, `GET`, `VALIDATE`, and revision-CAS
`APPLY`. The frozen spec-v3 subset is one enabled builtin `wireguard:main`
inbound `vpn`, one IPv4 /24 with host-only peer AllowedIPs, env key refs, and
one `direct` or `block` device default. No arbitrary plugin fetch/lock
resolution is implied by this exact local tuple. Stage separate port/subnet
resources; no same-port or overlapping-prefix replacement. The profile
only claims device inbound in its own namespace and LAN-local testing,
not WireGuard outbound, generic routing, or production use.

`prototype_store`'s config rename and directory sync are the only commit
decision. The bounded device journal stores link and guard identities keyed by
revision and profile-domain digest of exact canonical JSON. Startup
recompiles and cross-checks the committed document, then freshly verifies
its exact UP device and guard before any cleanup. Missing or ambiguous live
state blocks startup, not fallback/adoption. Before rename, only the failed
candidate can be cleaned; at RENAMED with uncertain durability, fence further
Apply and leave both generations for the next validated startup. After
SYNCED, retire the superseded generation using its reserved cleanup records.
The retained selected link and firewall remain in the disposable netns across
Core exit; neither production shutdown nor machine reboot is modeled.

Build directly from a clean source archive, with sibling source archives of
`plugin-sdk` at `fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd` and
`steer-protocols` at `cb6d369022300b8b26275d000b76021e1267f62b`. No local
guard/nft overlays or patches are required. The test starts two independent
WireGuard peers, initiates ICMP and UDP traffic from both directions, injects
a real occupied listen port, and checks live peer traffic after recovery on
both sides of the config commit. Server-initiated traffic on this inbound
device is not a spec-configured outbound.

```sh
# From the workspace containing the three repositories; choose the WG Apply
# commit explicitly rather than archiving the working tree.
scratch=$(mktemp -d /tmp/opencode/wg-sources.XXXXXX)
mkdir "$scratch/steer" "$scratch/plugin-sdk" "$scratch/steer-protocols"
git -C steer archive "$STEER_WG_COMMIT" | tar -xf - -C "$scratch/steer"
git -C plugin-sdk archive fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd | tar -xf - -C "$scratch/plugin-sdk"
git -C steer-protocols archive cb6d369022300b8b26275d000b76021e1267f62b | tar -xf - -C "$scratch/steer-protocols"
cd "$scratch/steer"
out=$(mktemp -d /tmp/opencode/wg-core.XXXXXX)
make -C experimental/provider BUILD="$out" "$out/steer-prototype" \
    "$out/steer-prototype-wg-netns" "$out/wg-commit-fault.so"
unshare -n -- env TMPDIR="$out" PYTHONDONTWRITEBYTECODE=1 \
    python3 experimental/provider/prototype_wg_apply_test.py \
    "$out/steer-prototype-wg-netns" "$out/steer-prototype" "$out/wg-commit-fault.so" \
    3</proc/self/ns/net
```

This does not wire WG into the general host executor or UI. Before doing that,
move serialized control work to the bounded host worker, replace the isolated
reservation with common `execution_reservations`/`device_authority_service`,
add a normal deliberate retire/disable transition, and specify endpoint,
route, transport and secret ownership for outbound and bidirectional
configuration. The isolated journal has no compaction; accumulated orphans can
fence admission. Real host work also needs machine-reboot and multi-device
recovery, and an explicitly scoped privileged network integration contract.
