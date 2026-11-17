[English](README.md) | [Русский](README.ru.md) | [简体中文](README.zh-CN.md)

<div align="center">

<img src="https://splify2.github.io/assets/img/logo.svg" width="104" alt="">

# steer

**Rule-based routing core for OpenWrt: choose which traffic uses a tunnel and which goes directly**

[![Release](https://img.shields.io/github/v/release/splify2/steer?label=release&color=6d5ce7)](https://github.com/splify2/steer/releases)
[![License](https://img.shields.io/github/license/splify2/steer?label=license&color=6d5ce7)](LICENSE)
[![Documentation](https://img.shields.io/badge/documentation-splify2.github.io-a897ff)](https://splify2.github.io/docs/steer/)
[![Telegram](https://img.shields.io/badge/Telegram-chat-2CA5E0?logo=telegram&logoColor=white)](https://t.me/ssplify)
[![Support the project](https://img.shields.io/badge/❤️_Support-Cloudtips-FF3355)](https://pay.cloudtips.ru/p/fb925110)

</div>

Define rules in one specification (YAML or JSON). The steer core turns it into `nftables` rules,
routing tables and address sets in a single atomic transaction. Written in C; protocols are
plugins bundled with the core package and installed offline. The management panel with a
service catalog is [splify2](https://github.com/splify2/splify2); the sing-box replacement for
podkop and forkop is [steer-box-connector](https://github.com/splify2/steer-box-connector).

## Features

- **Rules evaluated from top to bottom**: select which clients' traffic uses which outbound; the first match wins
- **Domains through fake-IP**: the resolver returns a synthetic address; the Linux kernel restores the real address through DNAT
- **DNS per rule**: DoT, DoH (HTTP/1.1, HTTP/2, HTTP/3), DoQ, UDP/TCP, directly or through an outbound, with caching; server groups (parallel or sequential) and a separate server for other sites
- **Outbounds and groups**: interface, AmneziaWG, subscription tunnel, block; `order`, `latency`, `manual`, `balance` groups; `on_fail` when all members fail
- **Native protocol clients as plugins**: VLESS/Reality (Vision, tcp/grpc/xhttp/ws/httpupgrade), hysteria2, trojan, shadowsocks, socks, http, vmess, xsteer, Cloudflare WARP — TCP and UDP, IPv4 and IPv6
- **IPv6 routing rules**: `family: 4 | 6 | both` on a rule, without leaks outside the outbound
- **WireGuard over simulated TCP** where UDP is blocked
- **`steer fit`** compresses a blocklist of hundreds of thousands of prefixes to fit the router
- **CLI and control socket**: `apply`, `status`, `diag`, `explain`, `plugin`, and events for management panels

## Installation

Download the package for your architecture (`DISTRIB_ARCH` in `/etc/openwrt_release`) from
[releases](https://github.com/splify2/steer/releases) or the mirror's
[dist](https://gitlab.com/xyzmean/steer/-/tree/dist) branch. There is one package per architecture,
`steer-core`; protocol plugins (`vless`, `hysteria2`, `proxy`, `xsteer`, `obfs`, `warpbox`, `awg`)
are bundled and can be installed offline:

```sh
apk add --allow-untrusted ./steer-core-<version>-1_<arch>.apk   # OpenWrt with apk
opkg install ./steer-core-<version>-1_<arch>.ipk               # OpenWrt with opkg
steer plugin list                                          # installed plugins
steer plugin install vless                                 # add a missing protocol
```

Upgrading from 2.0.x removes the old module packages (`steer-vless` and others, `steer-extended`)
and installs the plugins needed by the specification's outbounds. The Telegram bridge is the
`tgws` plugin from `splify2-extended-plugins`. See [docs/guide.md](docs/guide.md#установка).

## Quick start

`/etc/steer/spec.yaml`: domains from the list use WireGuard; everything else goes directly:

```yaml
version: 2
lan: { devices: [br-lan] }
lists:
  blocked: { domains_file: lists/blocked.dom }
outputs:
  vpn: { kind: interface, device: wg0, on_fail: drop }
rules:
  - { name: блоклист, to: [blocked], out: vpn }
```

```sh
steer apply --dry-run && steer apply
steer status
steer explain example.org
```

## Documentation

[splify2.github.io/docs/steer](https://splify2.github.io/docs/steer/): [guide](docs/guide.md),
[specification v2](docs/spec-v2.md), [control and events](docs/ctl.md), [core architecture](docs/architecture.md),
protocols: [VLESS](docs/vless.md), [hysteria2](docs/hysteria2.md), [trojan and others](docs/proxy.md),
[xsteer](docs/xsteer.md), [WARP](docs/warp.md), [server and hub](server/README.md).

## Building

```sh
./build.sh                          # packages for all 11 architectures (STEER_ARCH=<arch> for one); requires Docker
make && make test                   # build and run tests on the development machine
```

## License

[GPL-3.0](LICENSE). Third-party code: libyaml (MIT), wolfSSL (GPL-3.0), and ngtcp2 (MIT, with the
Brutal patch). Versions and checksums are in `build/wolfssl/fetch.sh` and `build/ngtcp2/fetch.sh`.
