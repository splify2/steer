# Steer Nano

`steer-nano` и `steer-ui-nano` — экспериментальные варианты из тех же
исходников. Они используют тот же локальный сокет управления, формат v3 и
браузерные формы. Первый проверяемый профиль — Linux x86_64; это **не**
пакеты OpenWrt, не firmware и не замена штатному Steer 2.x на роутере.

Из хаба с соседними `plugin-sdk`, `steer-protocols` и `steer-ui`:

```sh
make -C steer NANO=1 nano-test
make -C steer-ui NANO=1 test
```

Ядро лежит в `steer/build/nano/steer-nano`. Оно собрано с `-Os`,
удалением неиспользуемых секций и символов. Включены Linux loopback,
управляемые вход и выход SOCKS5 CONNECT TCP и plain VLESS TCP, правила и
revisioned Apply. `nano-test` проверяет входы, оба прокси-выхода и
восстановление конфигурации. Профиль не включает QUIC/TLS Hysteria2, управляемый WireGuard и захват
трафика. Отсутствующие возможности не обещаются конфигурацией или UI.

Бинарник панели — `steer-ui/build/steer-ui-nano`. Передайте
`--assets` с абсолютным путём к `steer-ui/build/nano-assets` или к каталогу
`assets` из архива. Используйте `--core-control` с приватным Unix-сокетом
ядра; без сокета Apply недоступен. Nano не включает файлы шрифтов и
использует восемь HTTP-слотов вместо шестнадцати. Лимиты документа и
проверки API остаются прежними. Management HTTP — только loopback.

В ручном workflow `Релиз` флаг `nano` работает только с `prerelease`.
Передайте полные SHA `nano_ui_ref`, `nano_protocols_ref` и настройте
`PLUGIN_SDK_REF` на полный SHA. Сборка и loopback-тесты обязательны до
публикации; архивы содержат `SOURCE-REVISIONS`. Обычный workflow без флага
собирает прежние пакеты без изменений.

Для поставки на IoT ещё нужны сборка musl на целевые ARM/MIPS, установка и
upgrade/rollback через пакетный менеджер, измерения flash/PSS под нагрузкой и
проверка отдельных опциональных функций на устройствах.
