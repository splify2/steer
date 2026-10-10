<div align="center">

<img src="https://splify2.github.io/assets/img/logo.svg" width="104" alt="">

# steer

**Ядро маршрутизации по правилам для OpenWrt: какой трафик — в туннель, какой — напрямую**

[![Выпуск](https://img.shields.io/github/v/release/splify2/steer?label=выпуск&color=6d5ce7)](https://github.com/splify2/steer/releases)
[![Лицензия](https://img.shields.io/github/license/splify2/steer?label=лицензия&color=6d5ce7)](LICENSE)
[![Документация](https://img.shields.io/badge/документация-splify2.github.io-a897ff)](https://splify2.github.io/docs/steer/)
[![Telegram](https://img.shields.io/badge/Telegram-чат-2CA5E0?logo=telegram&logoColor=white)](https://t.me/ssplify)
[![Поддержать проект](https://img.shields.io/badge/❤️_Поддержать-Cloudtips-FF3355)](https://pay.cloudtips.ru/p/fb925110)

</div>

Правила описываются одной спекой (YAML или JSON), ядро steer превращает её в правила `nftables`,
таблицы маршрутизации и наборы адресов одной атомарной транзакцией. Написано на C под слабые
роутеры: одно процессорное ядро, десятки мегабайт памяти, 6–7 МБ на разделе overlay. Панель с
каталогом сервисов поверх ядра — [splify2](https://github.com/splify2/splify2), замена sing-box для
podkop и forkop — [steer-box-connector](https://github.com/splify2/steer-box-connector).

## Возможности

- **Правила сверху вниз**: какой трафик каких клиентов в какой выход; побеждает первое совпадение
- **Домены через fake-IP**: резолвер отвечает служебным адресом, ядро Linux возвращает настоящий через DNAT
- **DNS под правило**: DoT, DoH (HTTP/1.1, HTTP/2, HTTP/3), DoQ, UDP/TCP — напрямую или через выход, с кэшем; группы серверов (все сразу или по очереди) и свой сервер для остальных сайтов
- **Выходы и группы**: интерфейс, туннель по подписке, zapret; группы `order`, `latency`, `manual`, `balance`; `on_fail` при отказе всех
- **Свои клиенты протоколов** модулями: VLESS/Reality (Vision, tcp/grpc/xhttp/ws/httpupgrade), hysteria2, trojan, shadowsocks, socks, http, vmess, xsteer
- **WireGuard поверх поддельного TCP** там, где режут UDP
- **`steer fit`** ужимает блок-лист в сотни тысяч префиксов до размера, который влезает в роутер
- **CLI и управляющий сокет**: `apply`, `status`, `diag`, `explain`, события для панелей

## Установка

Пакеты своей архитектуры (`DISTRIB_ARCH` в `/etc/openwrt_release`) — со страницы
[выпусков](https://github.com/splify2/steer/releases) или из ветки
[dist](https://gitlab.com/xyzmean/steer/-/tree/dist) зеркала. Ядро `steer-core` нужно всегда, модули —
по нужде, всё одной командой:

```sh
apk add --allow-untrusted ./steer-core-<версия>-1_<арх>.apk ./steer-vless-<версия>-1_<арх>.apk   # OpenWrt на apk
opkg install ./steer-core-<версия>-1_<арх>.ipk ./steer-vless-<версия>-1_<арх>.ipk               # OpenWrt на opkg
```

| Пакет | Что это |
|---|---|
| `steer-core` | ядро: маршрутизация, сторож, резолвер, `steerd`, `steer`, библиотеки `libsteer` |
| `steer-vless` | клиент VLESS/Reality |
| `steer-hysteria2` | клиент hysteria2 (QUIC, Brutal, Salamander) |
| `steer-proxy` | клиенты trojan, shadowsocks, socks, http, vmess |
| `steer-xsteer` | клиент звезды xsteer |
| `steer-obfs` | WireGuard поверх поддельного TCP |
| `steer-tgws` | мост Telegram |

## Быстрый старт

`/etc/steer/spec.yaml` — домены из списка через WireGuard, остальное напрямую:

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

## Документация

[splify2.github.io/docs/steer](https://splify2.github.io/docs/steer/): [подробное описание](docs/guide.md),
[спека v2](docs/spec-v2.md), [управление и события](docs/ctl.md), [устройство ядра](docs/architecture.md),
протоколы [VLESS](docs/vless.md), [hysteria2](docs/hysteria2.md), [trojan и другие](docs/proxy.md),
[xsteer](docs/xsteer.md), [сервер и хаб](server/README.md).

## Сборка

```sh
./build.sh                          # пакеты под все архитектуры (STEER_ARCH=<арх> — одну), нужен docker
make && make test                   # сборка и стенды на машине разработки
```

## Лицензия

[GPL-3.0](LICENSE). Сторонний код: libyaml (MIT), wolfSSL (GPL-3.0) и ngtcp2 (MIT, с патчем Brutal) —
версии и суммы в `build/wolfssl/fetch.sh` и `build/ngtcp2/fetch.sh`.
