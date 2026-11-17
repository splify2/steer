[English](README.md) | [Русский](README.ru.md) | [简体中文](README.zh-CN.md)

<div align="center">

<img src="https://splify2.github.io/assets/img/logo.svg" width="104" alt="">

# steer

**面向 OpenWrt 的规则路由核心：决定哪些流量走隧道，哪些流量直连**

[![版本](https://img.shields.io/github/v/release/splify2/steer?label=release&color=6d5ce7)](https://github.com/splify2/steer/releases)
[![许可证](https://img.shields.io/github/license/splify2/steer?label=license&color=6d5ce7)](LICENSE)
[![文档](https://img.shields.io/badge/documentation-splify2.github.io-a897ff)](https://splify2.github.io/docs/steer/)
[![Telegram](https://img.shields.io/badge/Telegram-chat-2CA5E0?logo=telegram&logoColor=white)](https://t.me/ssplify)
[![支持项目](https://img.shields.io/badge/❤️_Support-Cloudtips-FF3355)](https://pay.cloudtips.ru/p/fb925110)

</div>

通过一份配置规范（YAML 或 JSON）定义规则，steer 核心将其转换为 `nftables` 规则、
路由表和地址集合，并通过单次原子事务应用。核心使用 C 编写；协议以插件形式随核心包提供，
可离线安装。提供服务目录的管理面板是 [splify2](https://github.com/splify2/splify2)，
用于替代 podkop 和 forkop 中 sing-box 的组件是
[steer-box-connector](https://github.com/splify2/steer-box-connector)。

## 功能

- **从上到下匹配规则**：指定各客户端的流量使用哪个出口，首条匹配规则生效
- **通过 fake-IP 处理域名**：解析器返回合成地址，Linux 内核通过 DNAT 恢复真实地址
- **按规则选择 DNS**：支持 DoT、DoH（HTTP/1.1、HTTP/2、HTTP/3）、DoQ、UDP/TCP，可直连或经出口访问，并提供缓存；支持并行或顺序查询的服务器组，以及供其他网站使用的独立服务器
- **出口和分组**：接口、AmneziaWG、订阅隧道、阻断；支持 `order`、`latency`、`manual`、`balance` 分组，以及所有成员失效时的 `on_fail`
- **以插件提供的原生协议客户端**：VLESS/Reality（Vision、tcp/grpc/xhttp/ws/httpupgrade）、hysteria2、trojan、shadowsocks、socks、http、vmess、xsteer、Cloudflare WARP，支持 TCP、UDP、IPv4 和 IPv6
- **IPv6 规则路由**：规则中可设置 `family: 4 | 6 | both`，避免流量绕过指定出口泄漏
- **在 UDP 受限时通过模拟 TCP 传输 WireGuard**
- **`steer fit`**：将包含数十万前缀的阻断列表压缩到路由器可容纳的大小
- **CLI 和控制套接字**：提供 `apply`、`status`、`diag`、`explain`、`plugin`，以及供管理面板使用的事件

## 安装

从[发布页面](https://github.com/splify2/steer/releases)或镜像的
[dist](https://gitlab.com/xyzmean/steer/-/tree/dist) 分支下载适合设备架构的包
（架构见 `/etc/openwrt_release` 中的 `DISTRIB_ARCH`）。每种架构只有一个 `steer-core` 包；
其中包含协议插件（`vless`、`hysteria2`、`proxy`、`xsteer`、`obfs`、`warpbox`、`awg`），可离线安装：

```sh
apk add --allow-untrusted ./steer-core-<version>-1_<arch>.apk   # 使用 apk 的 OpenWrt
opkg install ./steer-core-<version>-1_<arch>.ipk               # 使用 opkg 的 OpenWrt
steer plugin list                                          # 已安装的插件
steer plugin install vless                                 # 安装缺少的协议
```

从 2.0.x 升级时会移除旧模块包（`steer-vless` 等，以及 `steer-extended`），
并根据配置规范中的出口安装所需插件。Telegram 桥接由 `splify2-extended-plugins` 仓库中的
`tgws` 插件提供。详见 [docs/guide.md](docs/guide.md#установка)。

## 快速开始

`/etc/steer/spec.yaml`：列表中的域名通过 WireGuard 访问，其余流量直连：

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

## 文档

[splify2.github.io/docs/steer](https://splify2.github.io/docs/steer/)：
[使用指南](docs/guide.md)、[配置规范 v2](docs/spec-v2.md)、[控制与事件](docs/ctl.md)、
[核心架构](docs/architecture.md)，以及协议文档：
[VLESS](docs/vless.md)、[hysteria2](docs/hysteria2.md)、[trojan 等](docs/proxy.md)、
[xsteer](docs/xsteer.md)、[WARP](docs/warp.md)、[服务器与枢纽](server/README.md)。

## 构建

```sh
./build.sh                          # 构建全部 11 种架构的包（STEER_ARCH=<arch> 指定一种）；需要 Docker
make && make test                   # 在开发机器上构建并运行测试
```

## 许可证

[GPL-3.0](LICENSE)。第三方代码：libyaml（MIT）、wolfSSL（GPL-3.0）和 ngtcp2
（MIT，含 Brutal 补丁）。版本和校验和见 `build/wolfssl/fetch.sh` 与 `build/ngtcp2/fetch.sh`。
