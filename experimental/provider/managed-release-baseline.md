# Steer 2.1.4 vs managed Nano: bounded idle baseline

## Scope and compatibility boundary

The latest 2.x release tag present in this checkout is `v2.1.4`
(`70d11ebb6ab7b618508e1bbb593a3d28a9cf4d08`, `VERSION` = `2.1.4`).
There is no v3 release tag here. The comparison target is therefore the
experimental source-linked managed Nano profile at Steer commit
`2d189f9ae0463cf6ef44a9f6e524c473e8e8f46c`, not a released Steer 3.x build.
Measurements were built from clean worktree `e0a2eff4ad7ea55b3dd2297c7cd5a37717c0228a`;
that commit adds only the prior loopback baseline test/docs to the product
source at `2d189f9`. This measurement harness is another test-only change.

Steer 2.1.4's `proxy` plugin supports SOCKS as an **outbound client**. It does
not expose a managed SOCKS5 server/inbound comparable to Nano's SOCKS5 CONNECT
listener. The existing TCP path test `tests/run-tcp-redir.sh` is present in both
trees and exercises the legacy v2 VLESS outbound/module path with
`tests/mtclient.py` and a local fake VLESS peer. It requires the legacy daemon,
VLESS module and nftables redirection; those are not in the Nano profile.
Consequently it is a useful legacy TCP regression scenario, but not a workload
that can be run unchanged against managed Nano. No throughput, latency, CPU or
`perf` comparison is reported; comparing unlike functions would not establish a
performance win.

## Reproduction

Builds were made in clean detached/source worktrees using host GCC 13.3.0,
x86_64 Linux, glibc, and `strip` from the same host:

```sh
git worktree add --detach /tmp/opencode/steer-v214 v2.1.4
make -C /tmp/opencode/steer-v214 -j2 CFLAGS=-Os build/steerd build/steer
strip --strip-unneeded /tmp/opencode/steer-v214/build/steerd \
  /tmp/opencode/steer-v214/build/steer

make -C /tmp/opencode/steer-managed-baseline NANO=1 \
  NANO_BUILD=/tmp/opencode/steer-nano-build \
  NANO_SDK=/root/splicicd/plugin-sdk \
  NANO_PROTOCOLS=/root/splicicd/steer-protocols STRIP=strip nano

python3 -B /tmp/opencode/steer-managed-baseline/tests/managed-profile-idle-baseline.py \
  --legacy-steerd /tmp/opencode/steer-v214/build/steerd \
  --managed-core /tmp/opencode/steer-nano-build/steer-nano --repeat 3
```

The v2 tree was clean at the release tag and the Nano tree was clean at
`e0a2eff` before adding this harness; Nano product code matches `2d189f9`.
The SDK and protocol dependency checkouts used for Nano
were clean at `fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd` and
`cb6d369022300b8b26275d000b76021e1267f62b`, respectively. Both profiles use
`-Os`; Nano additionally uses function/data sections and linker GC as defined
by its profile. Steer 2.1.4's package build uses split optimization for some
hot sources; this uniform `-Os` host rebuild is not the official 2.1.4 binary
or OpenWrt release package, and is not bit-for-bit representative of that
artifact.

The idle harness starts each process with a minimal local configuration (v2
daemon without `--apply`; Nano with one loopback SOCKS listener),
waits for its Unix control socket/READY state, settles 750 ms, reads the
process's `smaps_rollup` PSS and `/proc/<pid>/fd` count, and terminates it
within five seconds. It samples each profile three times. The Nano listener
binds only `127.0.0.1`; no traffic is sent and no external destination is
contacted.

## Recorded result

| Process/profile | Stripped executable bytes | Idle PSS median | FD median |
|---|---:|---:|---:|
| Steer 2.1.4 `steerd` | 1,154,120 | 1,130 KiB | 8 |
| Managed Nano core | 190,744 | 799 KiB | 16 |

The legacy companion CLI `steer` is another 30,936 stripped bytes; the legacy
two-binary total is 1,185,056 bytes. Nano is one binary. The measured binaries
were dynamically linked against the host glibc; these byte counts are not
package/flash sizes and do not include shared libraries.

The output supports only these narrow observations: in this host build, the
Nano executable is smaller and its configured idle process has lower PSS, but
it uses more file descriptors. It does not show functional parity: the legacy
daemon is a broad routing/plugin manager started with an empty v2 spec, while
Nano is a smaller experimental managed host started with one SOCKS listener.
The measurements do not support a release-wide size, memory, or performance
claim, nor extrapolation to OpenWrt, other architectures, or active traffic.
