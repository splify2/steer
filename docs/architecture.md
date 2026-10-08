# Устройство steer

Документ для тех, кто правит ядро steer: как устроен код и как он работает. Внешние обещания описаны
отдельно: спека v1, вывод `status` и `diag`, командная строка и инварианты набора правил —
[docs/contract-v1.md](contract-v1.md); управляющий сокет демона — [docs/ctl.md](ctl.md); формат
спеки v2 — [docs/spec-v2.md](spec-v2.md); клиент VLESS — [docs/vless.md](vless.md); протокол
xsteer — [docs/xsteer.md](xsteer.md).

## 1. Сборки

Одно дерево на C, несколько сборок. Какие файлы входят в сборку, решает профиль в
`build/sources.mk` — единственном списке исходников: `Makefile` его включает, `build.sh` и
`build/build-ext.sh` читают через `build/sources.sh`, а список в `Android.bp` с ним сверяет
`tests/buildmatch.sh`.

| Профиль | Состав | Что в сборке |
|---|---|---|
| `base` | `CORE_SRC` | ядро: модель спеки, компилятор, демон, резолвер, виды `direct`, `interface`, `zapret`, `tgws` (правила перехвата), `awg` и группы, обфускатор; криптографии нет |
| `extended` | ядро, `XS_COMMON_SRC`, `EXT_ROUTER_SRC`, `KINDS_EXT_SRC` | статическая полная сборка (телефон, стенды): ещё клиент VLESS/Reality со стеком туннеля, клиент xsteer, мост tgws, подписка, TLS на wolfSSL; на роутере те же файлы разложены по пакетам (ниже) |
| `server` | ядро, `XS_COMMON_SRC`, `EXT_SERVER_SRC` | хаб xsteer |
| `tgws` | ядро, `EXT_TGWS_SRC` | мини-сборка моста Telegram: своё поле метки, свой ряд таблиц и портов моста (docs/contract-v1.md, §7), без резолвера |
| `android` | как `extended` | та же сборка с умолчанием платформы «телефон» (`-DSTEER_DEFAULT_PLATFORM=android`) |

Код обеих платформ, роутера и телефона, есть в каждой сборке: платформа выбирается при запуске
(раздел 2, правило 2).

**Пакет роутера — разделяемая раскладка**, а не один статический файл. Профили выше остаются для
статических сборок (телефон, стенды, микропакет tgws, хаб на VPS); роутер получает те же файлы,
разложенные по бинарникам и библиотекам (списки — те же `build/sources.mk`, рецепт —
`build/build-libs.sh`):

| Файл | Список | Что в нём |
|---|---|---|
| `libsteer-wolfssl.so.<версия wolfSSL>` | `build/wolfssl/build.sh` | наша сборка wolfSSL (`build/wolfssl/user_settings.h`, QUIC включён) — только достижимое от экспорта; в `libsteer.so` — ещё ngtcp2 с патчем Brutal и обёртка `src/proto/quic` |
| `libsteer.so.<версия ядра steer>` | `LIBSTEER_SRC` | модель спеки с libyaml, платформа, реестр и файлы видов, разбор командной строки, линия событий, обфускатор (`obfs.c`), слой примитивов, TLS 1.3, REALITY, h2, транспорты, стек TUN и `tun.c` |
| `steerd` | `STEERD_DYN_SRC` = `DAEMON_SRC` + `urltls.c` | демон, компилятор правил, apply, сторож, супервизор, резолвер, заглушки команд модулей (`src/cli/modcmd.c`) |
| `steer-vless` | `VLESS_MODULE_SRC` | клиент VLESS: `vlmain`, `vldial`, `client`, `vless_proto`, `vision`, разбор и скачивание подписки, проба TLS; пул узлов и слежка (`src/tunnel/pool.c`) — в `libsteer`, со стеком |
| `steer-xsteer` | `XSTEER_MODULE_SRC` | клиент звезды: `xsclient` и общая часть формата (`xswire`, `xsconf`, `xslink`, `xsroute`, `xsconn`, `xsstream`, `xsepoch`, `xshake`), служебные команды `xsadmin` |
| `steer-obfs` | `OBFS_MODULE_SRC` | точка входа обфускатора (`obfsmain.c`); сам `obfs.c` — в `libsteer`, его зовёт и xsteer |
| `steer-tgws` | `TGWS_MODULE_SRC` | мост Telegram (`tgws.c`); правила перехвата пишет ядро (`kinds/tgws.c`) |
| `steer-hysteria2` | `HY2_MODULE_SRC` | клиент hysteria2 ([docs/hysteria2.md](hysteria2.md)): провод (`hy2wire`), узлы и подписка (`hy2sub`), соединение QUIC и мультиплексор потоков (`hy2conn`), дайлер стека (`hy2dial`), команды и слежка (`hy2main`); запись вида — `kinds/hysteria2.c` в `libsteer` (`KINDS_HY2_SRC`); в статические профили и в телефон не входит |
| `steer-proxy` | `PROXY_MODULE_SRC` | клиенты прокси ([docs/proxy.md](proxy.md)): trojan, shadowsocks, socks, http, vmess одним бинарником — провод и вывод ключей (`pxwire`), узлы и подписка (`pxsub`), общее дайлеров (`pxdial`), по файлу на протокол (`pxtrojan`, `pxss`, `pxsocks`, `pxhttp`, `pxvmess`), команды (`pxmain`), слежка — пул узлов `src/tunnel/pool.c`; дайлеры — поверх стека `src/tunnel` и транспорта `src/proto/transport`, как vless; записи пяти видов — `kinds/proxy.c` в `libsteer` (`KINDS_PROXY_SRC`); в статические профили и в телефон не входит (как hysteria2) |

Каждый модуль — свой `main` (`src/modules/main_<имя>.c`) и `src/cli/modcmd.c`; линкуется он с
`libsteer.so`, thread-local таблицы туннеля живут в куче потока (раздел «Туннели»). В модуле нет
`failover.c` и модели: маршрут выхода ставит демон по событию `up` (раздел 4а). Списки
непересекающиеся, `modcmd.c` — общий; это сверяет `tests/buildmatch.sh`.

Экспорт `libsteer.so` — version-script `build/libsteer.map` (только то, что берут `steerd` и
модули; порождён из кода `build/libs-exports.sh`, проверка — `make libs-test`), SONAME
`libsteer.so.<версия ядра steer>`; ABI между версиями не обещается, поэтому модуль той же версии, что
ядро (зависимость пакета `steer-core (= версия)`; демон дополнительно проверяет версию из `hello`
модуля, `docs/ctl.md`). Экспорт `libsteer-wolfssl.so` — `build/wolfssl/libsteer-wolfssl.map`:
символы wolfSSL, которые зовёт слой примитивов, и отпечаток сборки. Библиотеки собираются `-fPIC` и
`-ftls-model=initial-exec`; видимость задаёт version-script, а не `-fvisibility=hidden` (пометка
`visibility("default")` на каждом экспортируемом определении — второй список в исходниках рядом с
первым). Загрузчик musl задаётся на каждую архитектуру (`-Wl,--dynamic-linker`, `interp_of` в
`build.sh`): `ld-musl-mipsel-sf.so.1`, `ld-musl-mips-sf.so.1`, `ld-musl-aarch64.so.1`,
`ld-musl-armhf.so.1`, `ld-musl-arm.so.1`, `ld-musl-x86_64.so.1`; RPATH нет — библиотеки в
`/usr/lib`.

Пакеты (`build.sh`, функция `pack`; оба формата — `.apk` и `.ipk` — из одного дерева файлов):
`steer-core` (`steerd`, `steer`, `steer-tools` — ссылка на `steerd`, `steer-nfqws`, обе библиотеки
в `/usr/lib`, init-скрипт, hotplug, `keep.d`; зависит только от чужих `nftables`, `ip-full`,
`conntrack`, `kmod-nft-queue`), `steer-vless`, `steer-xsteer`, `steer-obfs`, `steer-tgws`,
`steer-hysteria2`, `steer-proxy` (по одному бинарнику `usr/sbin/steer-<имя>`; зависят от `steer-core (= версия)`,
модули с собственным TUN — ещё от `kmod-tun`) и мета-пакет `steer-extended` (устаревший: ядро и
первые четыре модуля; `steer-hysteria2` и `steer-proxy` в него не входят). Библиотеки лежат внутри `steer-core`, а
не в своих пакетах: `steerd` сам ходит по HTTPS (замер групп, `urltls.c`) и по DoH, DoT и DoQ (резолвер),
поэтому криптография нужна ядру и без модулей. Модули файлов ядра не повторяют — у каждого файла
один владелец.

`steer-core` заменяет пакеты прежней раскладки — `steer`, `libsteer`, `libsteer-wolfssl`: он
объявляет `provides steer`, `replaces` и конфликт с ними (apk: `provides`, `replaces` и `!имя` в
`depends`; opkg: поля `Provides`, `Replaces`, `Conflicts`), поэтому установка и обновление снимают
старые пакеты, а `/usr/sbin/steerd` принадлежит одному пакету. Проверка на настоящем менеджере apk —
`tests/pkglayout.sh`; для opkg проверяются только поля метаданных.

Модуль, которого нет в системе, — не отсутствие команды. Вид выхода `vless` или `xsteer` при
разборе спеки отвечает «kind vless требует пакет steer-vless (входит в steer-extended)» —
единственное место текста, `src/kinds/kind.c`; команда модуля (`steer vless …`, `sub-fetch`,
`tls-probe`, `xsteer-key`…) без модуля отвечает так же, с кодом 2, а при установленном модуле
`steerd` запускает его с той же командной строкой (`src/cli/modcmd.c`). Есть ли модуль, решает
файл `steer-<имя>` рядом с исполняемым файлом (`src/lib/module.c`; каталог подменяет
`STEER_MODULE_DIR`).

## 2. Устройство

**Ядро — компилятор.** Спека превращается в дерево набора правил (`src/lib/ir.h`), дерево — в
текст, а текст применяется одной транзакцией `nft -f`. Поэтому генератор проверяется без роутера:
`tests/gen.sh` и снимок генератора (раздел 4).

**Ядерная форма.** Выход выбирают метки nftables, policy routing и наборы адресов; доменные
правила идут через свой резолвер (fake-IP или real-ip); туннели — устройства TUN или устройства
ядра. tproxy, перехвата потоков в пользовательский процесс и сниффинга нет. Пользовательский
процесс стоит только там, где без него нельзя: туннели с протоколами и DNS как плоскость
управления.

**Чем ближе к L2, тем лучше — когда это даёт пользу.** Пакет классифицируется и получает выход
как можно ниже по стеку и как можно раньше на своём пути, если это даёт хотя бы одно из
следующего:
- меньше обработки трафика;
- выше скорость, меньше задержки и расход ресурсов;
- меньше возможности другому софту вмешаться в наш трафик без нашего ведома;
- удобнее.

Перенос ниже, который ничего из этого не даёт или стоит памяти (например, вторая копия наборов в
таблице `netdev`), не делается. По этому правилу правила каналов раздачи стоят на хуке ingress
(«Набор правил» ниже).

**Чужие пакеты — настройка человека.** `dnsmasq`, `https-dns-proxy`, `netifd`, `odhcpd` и зоны
fw4 ядро не настраивает: оно маршрутизирует само и говорит в `diag`, чего не хватает. Исключение
одно — masquerade IPv6 по ключу `ipv6: nat` у выхода (раздел 4б), и то в своей таблице.

**Один разбор спеки.** Спеку читает одна функция `load_spec` (`src/model/parse.c`), а таблицу
доменных каналов для резолвера строит код модели (`dch_build`, `src/dnsd/table.c`); имя набора
у компилятора и резолвера считает одна функция (docs/contract-v1.md, §7).

### Правила устройства

1. **Вид выхода — модуль.** Всё, что знает о виде, лежит в `src/kinds/<вид>.c` и отдаётся одной
   таблицей `struct kind_ops` («Вид выхода» ниже). Общий код спрашивает свойства и функции вида, а
   не сравнивает, какой он: сравнение вида вне `src/kinds` ловит `tests/buildmatch.sh`.
2. **Платформа — модуль, выбираемый при запуске.** Отличия телефона от роутера лежат в
   `src/platform/openwrt.c` и `src/platform/android.c` за таблицей `struct platform_ops`
   (`platform.h`): пути, поле метки, NAT, цепочки на сам телефон. Порядок выбора
   (`platform.c`): `--platform` или `STEER_PLATFORM`, затем умолчание сборки
   (`-DSTEER_DEFAULT_PLATFORM`), затем признаки среды, последним — роутер. Условной компиляции по
   `STEER_ANDROID` вне `src/platform` нет (buildmatch).
3. **Сборка — набор модулей, а не набор макросов.** Профиль в `build/sources.mk` — это список
   файлов, и больше ничего. Команды модулей, которых в сборке может не быть (клиенты VLESS и
   xsteer, подписка, мост, хаб), — слабые ссылки в `src/daemon/main.c`, виды — слабые ссылки
   реестра `src/kinds/kind.c`: файла нет в профиле — на его месте штатный отказ «нужен пакет …».
   То, что файлом модуля не выражается, лежит в файле профиля `src/profile/<профиль>.c`
   (`profile.h`): имя варианта сборки, признак полного пакета, у мини-сборки tgws — поле метки, ряд
   таблиц, файл имён таблиц, порты моста и «без резолвера». У `base` своего файла нет, действуют
   умолчания `src/profile/profile.c`. Макросов `STEER_EXTENDED`, `STEER_SERVER`, `STEER_TGWS` нет ни
   в `src`, ни в путях сборки (buildmatch).
4. **Слои зависят только вниз.** buildmatch проверяет это частями: сборочные списки замкнуты по
   `#include`, ядро не включает заголовков протоколов, а `src/tunnel` и `src/proto` не зовут
   маршрутизацию демона.
5. **Ошибки возвращаются.** Модели и компилятору `die()` не нужен: они возвращают код и заполняют
   `struct err` (`src/lib/err.h`), а процесс завершает только точка входа бинарника (`err_die`). В
   `src/model`, `src/compile` и `src/lib`, кроме `err.c`, нет ни `die()`, ни `exit()` (buildmatch).
6. **Спека — значение, а не глобалы.** Всё прочитанное лежит в `struct spec` (`src/model/spec.h`),
   и функции получают её параметром. Прежних глобалов спеки (`g_out`, `g_ch`, `g_lan_dev` и
   соседних) в `src` нет (buildmatch).

### Процессы

На роутере:

```
procd
  └─ steerd daemon --watch --supervise --apply    один экземпляр, respawn
       ├─ сокет управления, протокол v1            <каталог спеки>/steer.sock
       ├─ apply-сверка                             дети apply-plan, apply-commit на команду
       ├─ сторож                                   на цикле событий, без fork на проход
       ├─ супервизор детей
       ├─ steer dnsd --table-fd 3                  ребёнок: файл steerd, argv[0] «…/steer»
       ├─ steer vless|xsteer|obfs|tgws <выход>     ребёнок: бинарник модуля (steer-vless,
       │                                            steer-xsteer, steer-obfs, steer-tgws),
       │                                            argv[0] «…/steer»
       └─ steer-nfqws <очередь> <файл ключей>      ребёнок: обёртка nfqws
steer <команда>          клиент: команды демона — в сокет; остальное и всё без демона — execv steerd
steer-tools <команда>    ссылка на steerd: отвечает только на инструменты
```

- **Три имени в пакете.** `steerd` — всё ядро одним файлом: демон, компилятор, apply, помощники
  выходов, резолвер, инструменты; `steerd <подкоманда>` — то же, что подкоманда ядра. `steer` —
  отдельный маленький клиент сокета (`src/client/main.c`). `steer-tools` — ссылка на `steerd`, под
  этим именем ядро отвечает только на инструменты (раздел 4а, «Бинарники»).
- **Помощники: резолвер — подкоманда `steerd`, туннели, обфускатор и мост — модули.** Резолвер
  демон запускает тем же файлом `steerd`, помощников выходов — бинарником модуля из каталога
  ядра (`kind_helper.prog`, `helpers_plan` в `src/daemon/helpers.c`): `steer-vless`,
  `steer-xsteer`, `steer-obfs`, `steer-tgws`, `steer-hysteria2`. Слова у них те же, что у подкоманды
  (`<команда> <выход> --spec … [--state-dir …]`), окружение — `STEER_EVENT_FD` и `STEER_SUPD`, как
  у прежних помощников. argv[0] у всех «…/steer» (`helper_argv0`): в списке процессов они
  выглядят как `steer dnsd`, `steer vless <выход>`, и поиск по командной строке (diag — обходом
  /proc) их находит. В статической сборке (телефон, стенды) модули слинкованы в `steerd`
  (`modcmd_builtin`), и помощник — подкоманда, как раньше. Обработчик zapret — своя программа рядом
  с ядром (`files/usr/sbin/steer-nfqws`).
- **У модулей SIGPIPE выключен** (`modcmd_run`, для всех модульных команд). Запись в сокет узла,
  который узел уже закрыл, — ошибка EPIPE, как ECONNRESET: стек закрывает ровно это соединение
  (RST клиенту) и освобождает его, а процесс продолжает нести остальные. С SIGPIPE по умолчанию такая
  запись убивала модуль целиком: выгрузка в несколько потоков на высокой скорости (iperf3 -P 8
  через steer-vless) делала это в большинстве запусков, и туннель стоял, пока демон не поднимал
  помощника заново (через 5, 10, 20 с). Закрытая труба событий по-прежнему гасит помощника, но
  теперь через EPIPE и SIGTERM (`evline_emit`).
- **Первое сообщение модуля — `hello`** с версией его сборки (`docs/ctl.md`). Демон сверяет её со
  своей: модуль другой версии, как и модуль, начавший не с `hello`, он гасит (SIGTERM) и не верит
  ни одному его событию; причина — в журнале и в `last_down` ответа `helper` (поле `rejected`).
  Бинарника модуля нет — в журнале один раз «модуля нет: нужен пакет steer-<имя>», в `last_down` то
  же, повтор запуска по обычной паузе.
- **Службу держит `/etc/init.d/steer`:** один экземпляр procd с respawn. `reload`, `reload_dnsd`,
  `reload_zapret` и `reapply` — запрос `reload` демону клиентом; `stop` ждёт выхода демона и зовёт
  `steerd down`; hotplug (`files/etc/hotplug.d/iface/95-steer`) шлёт экземпляру SIGHUP. На телефоне
  демона держит init (`init/steerd.rc` в дереве прошивки `vendor/der`, вне этого репозитория).

### Слои и каталоги

Каталоги слоёв — `INC_DIRS` в `build/sources.mk`; их же ровно перечисляет `Android.bp`, и сверяет
это `tests/buildmatch.sh`. Имена заголовков в дереве уникальны: заголовки подключаются по имени из
любого слоя.

```
src/
  lib/        общие кирпичи: run.c (run, run_quiet), err.c, tmpfile.c (шаблон временного файла),
              jsonw.c, jsonr.c, ynode.c (обёртка libyaml), nlbuf.h, nftnl.c (nf_tables по
              netlink), nftdump.c, nftvmap.c, ctnl.c (conntrack), rtnl.c, procscan.c, sindex.c,
              puff.c, ir.c (дерево набора правил: его строят и compile, и виды через emit),
              evline.c (линия событий помощник → демон, hello), ctlcall.c (вызов сокета демона),
              module.c (какая команда чья, установлен ли модуль),
              scrypto.c (слой криптографических примитивов — только в сборках с TLS)
  model/      spec.h (struct spec, struct output с union видов, правила, клиенты, списки),
              parse.c (выбор формата), v2.c и v2print.c (спека v2), v1.c (перевод спеки v1),
              check.c (сквозные проверки), registry.c (реестр меток и таблиц), marks.h, probe.c,
              srs.c, srsplan.c (наборы sing-box)
  kinds/      kind.h и kind.c (struct kind_ops, биты свойств, реестр),
              direct.c interface.c awg.c vless.c xsteer.c zapret.c tgws.c group.c grpurl.c
              hysteria2.c proxy.c (записи видов модулей steer-hysteria2 и steer-proxy)
  platform/   platform.h, platform.c, openwrt.c, android.c
  profile/    profile.h, profile.c (умолчания), extended.c, server.c, tgws.c — данные профиля
  compile/    groups.c, balance.c, generate.c, print.c, legacy.c (раскладка ядра 4.9),
              nftcompat.c (что умеет nft этого ядра)
  daemon/     main.c, ctl.c (сокет, протокол), apply.c, recon.c (сверка), watch.c и watchd.c
              (сторож), supervise.c и supd.c (супервизор), helpers.c, status.c, diag.c,
              explain.c, fwcheck.c, failover.c, fogroup.c, folat.c, foprobe.c, urltest.c, gaiw.c,
              conns.c, loop.c, state.c, rulewd.c, nftquery.c
  dnsd/       main.c, proxy.c, wire.c, rules.c, fakeip.c, realip.c, origdst.c, table.c, tabfmt.c,
              fpseed.c, adopt.c, dlog.c
  client/     main.c — steer, клиент сокета
  cli/        cli.c — таблица команд и разбор командной строки; modcmd.c — команды модулей
              (заглушки в steerd, настоящие ветки в модуле) и main модуля (steer_module_main)
  modules/    main_vless.c, main_xsteer.c, main_obfs.c, main_tgws.c, main_hysteria2.c, main_proxy.c
              — main бинарников модулей (только разделяемая раскладка)
  tools/      aggregate.c (fit), srsread.c, hwid.c
  tunnel/     стек туннеля без протокола: tun.c (TUN: очереди, разгрузка, запись пакетов),
              rtx.c (кольцо повтора), stack.c и stack.h (TCP/UDP ↔ потоки к узлу, таблица
              соединений, пул установщиков, запасные сессии), dialer.h (struct dialer_ops),
              pool.c и pool.h (пул узлов выхода: N активных узлов, раздача соединений, слежка
              за каждым и замена мёртвого без перезапуска — обёртка дайлера)
  proto/      tls/ (tls13, certverify, reality, chello, h2, roots — корни проверки сертификата,
              tlsprobe, urltls)
              transport/ (transport.h — struct transport_ops и security_ops; transport.c —
              сборка ярусов и транспорт tcp; trdial.c — сокет до узла; trsec.c — none, tls,
              reality; trgrpc.c; trxhttp.c; trupgrade.c — запрос Upgrade по HTTP/1.1 и
              httpupgrade; trws.c — кадры WebSocket; trpath.c — путь запроса Upgrade)
              vless/ (vlmain.c — подкоманды vless*, vldial.c — дайлер стека, client.c —
              vless_connect и проверка узла, vless_proto, vision, sub,
              subfetch; sublink.c — ссылка узла и поля транспорта, общие с модулем steer-proxy)
              proxy/ (trojan, shadowsocks, socks, http, vmess: pxwire, pxsub, pxdial, pxtrojan,
              pxss, pxsocks, pxhttp, pxvmess, pxmain — модуль steer-proxy, docs/proxy.md)
              hysteria2/ (клиент hysteria2 на QUIC — модуль steer-hysteria2, docs/hysteria2.md)
              xsteer/ (xswire, xshake, xsepoch, xsconf, xslink, xsconn, xsroute, xsstream,
              xsclient, xshub, xsadmin)   tgws/   obfs/ (WG поверх поддельного TCP: помощник и
              obfs-server)
  third_party/libyaml (разбор YAML; файлы не правятся — суммы в UPSTREAM сверяет buildmatch)
```

Отдельной точки входа туннеля в `src/tunnel` нет: она у модуля протокола
(`src/proto/vless/vlmain.c`), а стек — библиотека, которую модуль зовёт (`stack_run`).

Куда файлы уходят в разделяемой раскладке (раздел 1): `src/tunnel`, `src/proto/tls` (кроме
`tlsprobe.c` и `urltls.c`), `src/proto/transport`, `src/proto/obfs/obfs.c`, `src/lib`, `src/model`,
`src/kinds`, `src/platform`, `cli/cli.c`, `tools/hwid.c` — в `libsteer.so`; `src/daemon`, `src/dnsd`,
`src/compile`, `tools/aggregate.c`, `tools/srsread.c`, `tls/urltls.c` — в `steerd`; `proto/vless`
(с `tls/tlsprobe.c`), `proto/xsteer` (без `xshub.c`), `proto/tgws`, `proto/obfs/obfsmain.c` —
в модули; `xshub.c` — только в хаб на VPS.

Файлы `reality.c`, `tls13.c`, `vision.c`, `vless_proto.c`, `xswire.c`, `xshake.c`, `xsepoch.c`,
`certverify.c` держат байты на проводе: ошибка в них не ломается явно, поэтому их правка
проверяется `make ext-test` и стендами протокола (раздел 4).

### Вид выхода

Вид выхода — файл `src/kinds/<вид>.c` с записью `struct kind_ops` (`src/kinds/kind.h`, полностью
и с доводами — там же):

```c
enum kind_cap {
    KC_DEVICE = 1 << 0,  KC_MARK = 1 << 1,        KC_CTMARK = 1 << 2,   KC_ENGINE_OWNED = 1 << 3,
    KC_SELF_NAT = 1 << 4, KC_OVER = 1 << 5,       KC_SKIP_ZAPRET = 1 << 6,
    KC_TCP_PROBE = 1 << 7, KC_FLOW_UDP = 1 << 8,  KC_IPV6 = 1 << 9,
};

struct kind_ops {
    const char *name;           /* как пишется в спеке */
    unsigned caps;              /* enum kind_cap */
    unsigned keys;              /* enum kind_key: чьи ключи спеки */
    const char *absent;         /* не NULL — вида в этой сборке нет, строка отказа */
    unsigned (*caps_of)(const struct output *);        /* свойства, зависящие от настройки */
    const char *novia, *selfnat_why, *lan_only;       /* тексты о виде для общего кода */

    int  (*parse)(struct output *, const struct out_keys *, struct err *);  /* один разбор на v1 и v2 */
    void (*keys_of)(const struct output *, struct out_keys *);             /* обратное parse */
    int  (*check)(const struct spec *, const struct output *, struct err *);
    void (*emit)(struct nft_rs *, const struct spec *, const struct output *);
    int  (*health)(const struct spec *, const struct output *, const char *dev);
    int  (*revive)(const struct spec *, const struct output *, const char *dev,
                   const struct kind_name *names, size_t n);
    size_t (*revive_names)(const struct spec *, const struct output *, struct kind_name *, size_t);
    int  (*latency)(const struct spec *, const struct output *, const char *dev);
    void (*status)(FILE *, const struct spec *, const struct output *);
    void (*diag)(kind_diag_fn *, const struct spec *, const struct output *);
    int  (*helper)(const struct spec *, const struct output *, struct kind_helper *);
};
```

- **Свойства — биты `caps`.** Предикаты `out_*` в `spec.h` (`out_has_device`, `out_needs_mark`,
  `out_engine_managed`, `out_self_natting` и соседи) — тонкие обёртки над битами, и у каждого
  записано, чем он отличается от соседнего.
- **Любая функция может быть `NULL`**: общий код проверяет это явно и идёт общим путём (общая
  проба ICMP или TCP по `KC_TCP_PROBE`, общий замер соединением TCP, правила по свойствам).
- **Настройки видов — `union`** внутри `struct output`: у каждого вида своя структура
  (`struct vless_cfg`, `struct xsteer_cfg`, …), и заполняет её только разбор его модуля.
  Помощники спрашивают свою настройку у вида (`out_vless`, `out_xsteer`, `out_tgws`).
- **Реестр** (`kind.c`): `direct`, `interface`, `vless`, `xsteer`, `zapret`, `tgws`, `awg` — в этом
  порядке идут правила видов в дереве (`kind_emit_all`) и проверки diag. На записи вида, файла
  которого в сборке нет, стоит запись отказа с `absent`; её текст о VLESS и xsteer содержит
  подстроку `steer-extended` — её читает splify2.
- **Группа** (`kind: group`, `src/kinds/group.c`) — вид модели v2 и в реестр не входит: спека v1
  её не знает, разбор v2 находит её через `kind_by_name_v2`, а пул `devices` спеки v1 собирает в
  группу перевод v1 (раздел 4в).

### Набор правил

Всё, что ставит ядро steer, лежит в своих таблицах (`table inet steer`, в раскладке старого ядра Linux — ещё
`ip steer` и `ip6 steer`), и каждая замена идёт одной транзакцией: файл начинается со снятия
таблицы, за ним новая, поэтому момента без таблицы нет (docs/contract-v1.md, §7). Раскладку под
ядро выбирает `src/compile/nftcompat.c`; печать под ядро 4.9 — `src/compile/legacy.c`. Основные
цепочки (`src/compile/generate.c`):

| Цепочка | Хук | Что делает |
|---|---|---|
| `ingress_mark` | ingress устройств раздачи | правила каналов раздачи: метка выхода пакету до conntrack и до чужих цепочек prerouting |
| `prerouting_mark` | prerouting, `mangle + 1` | метка соединения и выбор члена `balance` по готовой метке; те же правила каналов — запасные, для пакета, который ingress не разобрал |
| `prerouting_failopen` | prerouting, `mangle + 2` | снимает бит обхода DPI с трафика выхода, пущенного сторожем напрямую |
| `prerouting_dns` | nat prerouting | заворот DNS клиентов на порт резолвера |
| `prerouting_dnat` | nat prerouting | подмена поддельного адреса fake-IP на настоящий по карте; поддельный адрес без подмены отбрасывает правило `steer-fakeip-nomap` |
| `forward_v6` | forward | отвергает IPv6 правил, ведущих в выход без IPv6, и адрес из префикса хоста мимо донора (раздел 4б) |
| `postrouting_guard` | postrouting, `filter` | пакет с меткой выхода с устройством уходит только в устройства этого выхода — или отбрасывается |
| `postrouting_down` | postrouting | счётчики входящего трафика каналов |
| `postrouting_nat6` | nat postrouting | masquerade IPv6 у выхода с `ipv6: nat` |
| `output_mark`, `output_dns` | output | каналы на сам телефон и заворот его DNS; в раскладке 4.9 — ещё `output_reroute` и `output_nat` |
| `zapret_*`, `tgws_redirect` | — | правила видов `zapret` и `tgws` (`kind_ops.emit`) |

**Разметка на ingress.** Цепочка `ingress_mark` стоит на тех устройствах из `lan_devices`, что есть
при `apply`, с приоритетом `filter + 10` — после flowtable fw4 на том же хуке. Первое правило даёт
пакету с пустым полем метки значение «разобран, выхода нет» (`STEER_INGRESS_SEEN`, `0x0f000000`,
`src/model/marks.h`), дальше идут правила каналов с меткой пакета. Записи conntrack на ingress ещё
нет, поэтому метку соединения и выбор члена `balance` ставит первое правило `prerouting_mark`
(цепочки `ingress_seen` и `ingress_ct`). Остальные правила `prerouting_mark` ловят пакет, который
ingress не разбирал: устройство без хука, клиент с другого устройства, метка, переписанная чужой
цепочкой между ingress и нами. Цепочку ingress ядро принимает только на существующие устройства и
вынимает из неё исчезнувшее; устройство, созданное заново, возвращает в неё следующая замена набора
правил (демон со `--watch` ставит её сам, раздел 4а). Разметка остаётся целиком в prerouting на
ядре без inet ingress (проба `nft -c`), в раскладке 4.9, на телефоне, в мини-сборке tgws, у спеки
без правил раздачи и при `STEER_NFT_INGRESS=0` в окружении `apply`.

**Порядок применения** (docs/ctl.md, «Порядок применения»): устройства `awg` и привязка выходов —
раньше набора правил, чтобы метка ни мгновения не жила без своего правила `fwmark`; набор правил —
одной транзакцией, с картой fake-IP и наборами каналов fake-IP, засеянными из файла состояния
резолвера (`src/dnsd/fpseed.c`, `print_elements` в `src/compile/print.c`); сразу после загрузки —
возврат элементов real-ip резолвером, отметки «пущен напрямую», карта `balance` к живым членам;
снятие прежних меток — только после удачной загрузки.

### Туннели: стек, дайлер, транспорт

Туннель с протоколом поверх потоков — три слоя (раскладка по файлам — «Слои и каталоги»):

- **стек** (`src/tunnel`): TUN ↔ потоки TCP/UDP клиента — SYN-ACK сразу, окно (с масштабом по
  RFC 7323, потолок — из `tcp_rmem` и `tcp_wmem`, `docs/vless.md`) и кольцо повтора,
  ранние данные, сборка фрагментов, таблица соединений, пул установщиков, запасные сессии. Про
  протокол он не знает ничего: на каждое соединение у него непрозрачная сессия дайлера; вход —
  `stack_run(выход, дайлер, ready, arg)` (`stack.h`), а обратный вызов `ready` получает имя
  поднятого устройства;
- **дайлер** — протокол поверх транспорта: заголовок запроса, обёртки, разбор ответа, обрамление
  датаграмм. Дайлеры — VLESS (`src/proto/vless/vldial.c`: заголовок VLESS, Vision, UDP командой 2) и
  протоколы прокси (`src/proto/proxy`: trojan, shadowsocks, socks, http, vmess — по файлу на
  протокол; docs/proxy.md), а hysteria2 ходит своим путём (QUIC, `src/proto/hysteria2`). Подкоманды
  `steer vless*` / `steer proxy*` и выбор первого узла — в модуле протокола (`vlmain.c`/`pxmain.c`),
  а N активных узлов, раздача соединений и слежка — у пула узлов (`src/tunnel/pool.c`): он обёртка
  дайлера, ctx протокола у него по-прежнему узел, только узел свой у каждого соединения;
- **транспорт** (`src/proto/transport`): как поток дайлера едет до узла — сокет по всем адресам
  имени с меткой `over` (`trdial.c`), безопасность `security=` — none, tls, reality (`trsec.c`) —
  и транспорт `type=` — tcp, grpc, xhttp, ws, httpupgrade (`transport.c`, `trgrpc.c`, `trxhttp.c`,
  `trws.c`, `trupgrade.c`).

Интерфейсы — сокращённо, полностью с доводами в заголовках:

```c
struct dialer_ops {              /* src/tunnel/dialer.h */
    const char *name;
    unsigned caps;               /* DC_PRECONNECT: связь открывается до адреса — пул запасных */
    size_t sess_size;            /* сессия на соединение клиента; память выделяет стек */
    int  (*connect)(const void *ctx, void *sess, int timeout_s);   /* в потоке установщика */
    void (*take)(void *dst, void *src);      /* связь из запасной сессии — в сессию соединения */
    int  (*flow_open)(const void *ctx, void *sess, const struct flow_key *k, int udp);
    int  (*send)(const void *ctx, void *sess, const struct flow_key *k, int udp,
                 const unsigned char *d, size_t n);
    size_t (*dgram_frame)(const unsigned char *p, size_t n, unsigned char *out, size_t cap);
    int  (*read)(void *sess, unsigned char *buf, size_t cap,
                 const unsigned char **data, size_t *got);
    int  (*deliver)(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                    dialer_emit_fn emit, void *arg);   /* кусками потока или датаграммами */
    /* служебные: peer, describe, strerror, close, clear, fd, has_data */
    /* вторая связь (NULL — нет): aux_fd — дескриптор, который стек ставит в epoll, aux_drain — слить
     * пришедшее; у xhttp это связь выгрузки, ответы на которую освобождают место (room) */
    /* узлов несколько (пул, pool.c; NULL — узел один): peer_of, match — годится ли запасная,
     * stale — узел соединения больше не активен (RST), lost — связь оборвана ядром или узлом */
};

struct transport_ops {           /* src/proto/transport/transport.h — tcp, grpc, xhttp, ws, httpupgrade */
    const char *name;
    const char *alpn;            /* что просить в ALPN; NULL у tcp, http/1.1 у ws и httpupgrade */
    int zc;                      /* данные лежат в записях TLS как есть — чтение без копии */
    int  (*open)(struct transport *, const struct tr_node *, int timeout_s);
    int  (*write)(struct transport *, const unsigned char *, size_t);
    int  (*read)(struct transport *, unsigned char *, size_t cap, size_t *got);
    void (*moved)(struct transport *);       /* структура переехала — поправить самоуказатели */
    void (*close)(struct transport *);       /* своё сверх основной связи: вторая связь xhttp */
    int  (*pending)(const struct transport *); /* своё непрочитанное: остаток за ответом 101 */
    int  (*aux_fd)(const struct transport *);  /* вторая связь для epoll цикла (xhttp: выгрузка), -1 — нет */
    int  (*aux_drain)(struct transport *);     /* слить её по событию; не 0 — слушать больше нечего */
};
struct security_ops {            /* none, tls, reality */
    const char *name;
    int (*handshake)(struct tr_link *, const struct tr_node *, const char *alpn);
};
```

- **Безопасность и транспорт — две таблицы, а не одна цепочка.** В ссылке узла это два независимых
  поля, `security=` и `type=`, и сочетаются они любые. Слои безопасности различаются только
  рукопожатием — после него у tls и reality одни и те же записи TLS 1.3, — поэтому у
  `security_ops` одна функция, а поток после рукопожатия общий. Вторая связь xhttp (stream-up,
  packet-up) поднимается тем же `tr_link_open`, что и основная.
- **У дайлера нет своих `open_tcp`/`open_udp`.** Узел у протокола один на соединение (у пула узлов —
  свой у каждого соединения, без пула — один на процесс), связь — одна на поток
  клиента, и открывает её установщик стека (`connect`); TCP и UDP различаются флагом в
  `flow_open`, `send` и `deliver` — у VLESS это одна связь с другой командой в заголовке.
  Датаграммы едут байтами потока (`dgram_frame`).
- **Сессия одна на соединение клиента — и связь, и состояние потока.** Граница между ними — дело
  дайлера: `take` переселяет из запасной сессии только связь, не затирая UUID и Vision потока.
- **Таблицы потока — в куче, а не в `__thread`.** У потока цикла одно отображение (`mmap`) под
  таблицу соединений, списки, корзины и сессии; страницы берутся по факту обращения, а установщики
  и поток слежки этого адресного пространства не получают. Статический TLS разделяемой библиотеки
  заводился бы каждому потоку каждого слинкованного с ней процесса.
- **Буферы на поток в `libsteer.so` остаются `__thread`.** `.tbss` объектов библиотеки (mipsel,
  `size -A`): `tls13.c` — три по 40 КБ (рукопожатие, сертификаты) и 16 КБ записей, `stack.c` — 18 КБ
  и три по 4 КБ, `trgrpc.c` и `trxhttp.c` — по 16–32 КБ, `h2.c` — около 40 КБ, `tun.c` и
  `reality.c` — по 4 КБ; в заголовке TLS-сегмента `libsteer.so` итого около 282 КБ, у `steerd` —
  16 КБ (`urltls.c`), у `steer-vless` — около 52 КБ (дайлер, проверка узла). Библиотека загружается
  при запуске процесса (DT_NEEDED, не `dlopen`) и собирается с `-ftls-model=initial-exec`, поэтому
  обращение — одна загрузка из GOT. На musl TLS потока лежит в его же отображении, нулевые страницы
  не трогаются, пока буфер не использован; резидентной остаётся только используемая часть.

Новый протокол поверх потоков — это файл дайлера, стек не трогается (так добавлены trojan, vmess и
http модуля steer-proxy). UDP самим протоколом по датаграммам (shadowsocks, socks5 UDP ASSOCIATE)
ложится в ту же таблицу без правки стека: бит `DC_UDP_OWN` говорит, что у потока UDP своя связь —
сокет UDP к узлу, а не поток, и стек не берёт для него запасную связь пула (dialer.h). Бит
`DC_ACK_PACED` — у дайлера с ограниченной очередью к узлу (hysteria2: пара SEQPACKET к
мультиплексору): стек не подтверждает данные клиента, пока дескриптор сессии не готов к записи
(`flush_acks`, `ack_must_wait`), и ждёт этой готовности в epoll (`EPOLLOUT`, `ARM_OUT`) — окно клиента
становится местом в очереди, и она не переполняется; окно, объявляемое такому клиенту, не больше
предела дайлера (`dialer_ops.rcv_wnd_max`: потолок стека выбран по памяти машины и измеряется
мегабайтами, очередь пары их не вместит). Новый
транспорт — таблица `transport_ops` без правки дайлера и стека (так устроены `ws` и `httpupgrade`:
`tr_ws` в `trws.c`, `tr_httpupgrade` в `trupgrade.c`).

**xsteer** на этот стек не ложится: он везёт IP-пакеты, а не потоки — TUN ↔ записи своего
протокола (Noise IK в облике TLS, `xshake.c`) поверх UDP или своего TCP (`xsstream.c`), без
терминатора TCP/UDP, окон и повтора. Транспорты `src/proto/transport` ему тоже ни к чему: его
рукопожатие — не TLS-клиент к серверу, а своё. Общее со стеком у него — слой TUN (`tun.c`:
очереди, чтение, склейка сегментов при записи); подъём устройства и потоки — свои.

### Криптография

Криптобиблиотека — wolfSSL, собранная из исходников выпуска со своими опциями: версия и сумма
архива — `build/wolfssl/fetch.sh`, опции — `build/wolfssl/user_settings.h`, список файлов —
`build/wolfssl/build.sh` (с ним сверяется `build/wolfssl/Android.bp`). Код протоколов и транспортов
библиотеку не зовёт: между ними тонкий слой примитивов `src/lib/scrypto.h` — хэши, HMAC, HKDF,
AES-GCM, ChaCha20-Poly1305, AES-CTR, X25519, проверка подписей и цепочки X.509. В заголовке слоя нет
ни одного типа wolfSSL, контексты — непрозрачные буферы фиксированного размера, а заголовки
wolfSSL включает один `src/lib/scrypto.c` (buildmatch). Свои TLS 1.3 и REALITY (`src/proto/tls`),
рукопожатие и ратчет xsteer и мост tgws стоят на этом слое. В статической базовой сборке
криптографии нет.

**Постквантовая часть.** Слой отдаёт ML-KEM-768 (`sc_mlkem768_*`: ключ и закрытый ключ — байтами, не
контекстами; случайность даёт вызывающий), проверку ML-DSA-65 (`sc_mldsa65_verify`, пустой контекст
FIPS 204) и BLAKE3 (`sc_blake3_*`). Первые два стоят на wolfSSL (`WOLFSSL_WC_MLKEM`, `WOLFSSL_WC_MLDSA` в
режиме `VERIFY_ONLY`, SHA-3 — все три в `user_settings.h`; ключи wolfSSL создаются в куче на время
вызова, поэтому их размер не входит в ABI между `libsteer` и `libsteer-wolfssl`). BLAKE3 в wolfSSL нет:
это `src/lib/blake3.h`, переносимый C без библиотеки, включаемый в `scrypto.c`. Потребители: гибрид
X25519MLKEM768 в TLS 1.3 и REALITY (`src/proto/tls`), подпись ML-DSA-65 у REALITY
(`certverify.c`) и VLESS encryption (`src/proto/transport/trvenc.c`), см. [vless.md](vless.md).

**В пакете роутера** библиотека — `libsteer-wolfssl.so.<версия wolfSSL>`, слой `scrypto.c` — в
`libsteer.so`, и `libsteer.so` зависит от неё (DT_NEEDED). Наружу из `libsteer-wolfssl.so` выходят
символы `wc_*` и `wolfSSL_*`, которые зовёт слой (`build/wolfssl/libsteer-wolfssl.map`), и
`steer_wolfssl_abi`; остальное код wolfSSL — включая TLS-стек и QUIC, включённые опциями, — в
файл попадает, только если достижим от экспорта (`--gc-sections`). Размеры `SC_HASH_CTX_SIZE`,
`SC_AEAD_CTX_SIZE`, `SC_AESCTR_CTX_SIZE` слоя — часть ABI между двумя файлами: контексты
размещает `libsteer`, а заполняет `libsteer-wolfssl`. Их держат две проверки: при сборке библиотеки
(`build/wolfssl/abi.c`: те же `_Static_assert`, что в `scrypto.c`) и при загрузке (`sc_abi_check`
в `scrypto.c` сверяет версию wolfSSL, размеры структур и смещение поля `cm` хранилища корней с
массивом `steer_wolfssl_abi` загруженной библиотеки; расхождение — строка в stderr и выход с кодом
3). На роутере wolfSSL пакета `libwolfssl` не используется: в нём нет QUIC, а его SONAME несёт
хеш опций.

**QUIC как слой.** QUIC-соединение для DoQ и hysteria2 даёт `src/proto/quic` — тонкая обёртка над
ngtcp2, целиком в `libsteer.so`. Сама ngtcp2 — выпуск с закреплёнными версией и суммой
(`build/ngtcp2/fetch.sh`, лицензия MIT), в дереве не лежит: скрипт скачивает архив, сверяет sha256 и
накладывает наши патчи (`build/ngtcp2/patches`). Собирается она своим рецептом `build/ngtcp2/build.sh`
(все файлы `lib/` и криптобэкенд `crypto/wolfssl`, `build/ngtcp2/config.h` вместо порождаемого
configure) в статический архив с `-fPIC`; nghttp3 не берётся. Криптобэкенд зовёт TLS-стек и
`wolfSSL_quic_*` из `libsteer-wolfssl.so`, поэтому опции wolfSSL включают QUIC, слой EVP и AES-ECB
(защита заголовка пакета). Заголовки wolfSSL видят два файла: `scrypto.c` и `src/proto/quic/qcssl.c`
(ngtcp2 нужен сам TLS-стек, а не примитивы); `quic.c` держит сокет, потоки, датаграммы RFC 9221 и
таймер и wolfSSL не видит. Модель выполнения — внешняя линия событий: соединение отдаёт дескриптор
UDP-сокета и срок таймера (`qc_fd`, `qc_timeout_ms`), потребитель зовёт `qc_on_readable` и
`qc_on_timer`. Перегрузка по умолчанию — CUBIC; при `bbr` — BBR; при `brutal_bps` — Brutal из
hysteria2, патч к ngtcp2: заданная скорость в байтах в секунду, окно `bps × RTT × 2 / доля
подтверждённых пакетов`, без снижения при потерях. Второй патч (`0002`) даёт смену перегрузки на
установленном соединении (`qc_set_cc`: Brutal с другой скоростью или BBR).

Швы для hysteria2, не меняющие остальное поведение слоя: фильтр датаграмм сокета (`qc_filter`,
Salamander; `tx_multi` — один пакет в несколько датаграмм, Gecko), прыжки по портам сервера (`hop_*`: отправка на порт диапазона, приём с любого порта
диапазона, для ngtcp2 путь остаётся один), метка сокета (`sock_mark`), проверка отпечатка
сертификата (`pin_sha256`, вместо цепочки), однонаправленный поток (`qc_stream_open_uni` — управляющий
поток HTTP/3), PING по молчанию (`keepalive_ms`) и ручное продление окон приёма (`flow_manual`,
`qc_stream_consumed`) — обратное давление на сервер. Длина идентификатора соединения — четыре байта.
Потребители — модуль `steer-hysteria2` и стенд `tests/qcbench.c` (`build/libs-exports.sh`).

**Клиент hysteria2 в стеке туннеля.** Стек (`stack.c`) держит на каждое соединение клиента
дескриптор, а QUIC-соединение у hysteria2 одно. Между ними — поток-мультиплексор модуля
(`hy2conn.c`): владеет QUIC и для каждого соединения клиента держит пару сокетов `SOCK_SEQPACKET`,
один конец которой стек опрашивает как обычный дескриптор (`hy2dial.c`, `caps = DC_ACK_PACED`, без
пула запасных сессий). Запись в SEQPACKET принимается целиком либо не принимается — то, что требует
`dialer_ops.send`; для UDP границы датаграмм сохраняются сокетом.

Обратное давление идёт в обе стороны. Вниз (скачивание): окно приёма QUIC продлевается только за
байты, ушедшие в сокет клиента (`qc_stream_consumed`; пакет с обновлением окна уходит из линии
событий мультиплексора — `qc_flush_credit`), а очередь к медленному клиенту — цепочка блоков по
16000 байт, память которых возвращается по мере отдачи, и не больше окна потока: 8 МиБ на поток и
16 МиБ на соединение (`RX_STREAM_WIN`, `RX_CONN_WIN` в `hy2conn.c`; окно обязано вмещать
«скорость × задержка» с запасом вдвое, а при медленном клиенте оно же — наихудший расход памяти на
очереди туннеля). Вверх (выгрузка): стек не подтверждает данные клиента, пока очередь пары выше
нижней отметки (четверть буфера отправки, 128 КиБ), и клиент идёт со скоростью мультиплексора; а
мультиплексор, чей буфер потока QUIC (`send_buf`, 1 МиБ) полон, придерживает остаток и не читает
пару, так что та же придержка доходит до клиента. Очередь пары вмещает окно клиента сверх нижней
отметки, а окно у hysteria2 не больше 128 КиБ (`HY2_CLIENT_WND`, `rcv_wnd_max` дайлера; связь с
буфером пары — проверка сборки в `hy2conn.h`); буфер отправки пары задаётся `SO_SNDBUFFORCE` и от
`net.core.wmem_max` не зависит.

### DNS

Резолвер `steer dnsd` (`src/dnsd`) — ребёнок демона. Он слушает порт 5300 (`DNS_PORT`), и набор
правил заворачивает на него DNS клиентов (`prerouting_dns`; в мини-сборке tgws резолвера нет).
Спеку резолвер под демоном не читает: таблицу доменных каналов — набор, режим, семейства, файлы
списков (`src/dnsd/tabfmt.h`) — демон пишет ему в трубу (`--table-fd`) при старте и после каждого
изменения, и резолвер меняет её без перезапуска. Без трубы резолвер читает спеку сам.

- **Имя вне правил** уходит к апстриму как есть: на роутере — `127.0.0.1:53` (dnsmasq), на
  телефоне — туда, куда шёл запрос клиента (адрес из conntrack, `--upstream-origdst`). С
  `dns.other` — к его серверу или группе тем же `dup_ask`, что у канала; имена своей сети
  (`name_local` в `src/dnsd/proxy.c`: без точки, `lan`, `local`, `home.arpa`, обратные зоны …)
  остаются на прежнем пути. Нет ответа или SERVFAIL/REFUSED — вопрос уходит прежним путём
  (`forward_old`, тот же код, что у обычного имени вне правил); отказ без ответа ставит паузу
  (`struct dpause`, `src/dnsd/dup.h`), и на её время имена вне правил идут прежним путём сразу.
- **Имя под правилом** в режиме fake-IP получает поддельный адрес из `198.18.0.0/15` (IPv6 —
  `fdfe:dcba:9876::/96`, раздел 4б); подмена ставится в карту ядра раньше ответа клиенту, а адрес —
  в набор канала. Раздача хранится в `<каталог состояния>/fakeip.state`. В режиме real-ip клиент
  получает настоящий ответ, а адрес ложится в набор канала со сроком ответа; эти элементы резолвер
  помнит в памяти (`src/dnsd/realip.c`) и возвращает после каждой замены набора правил.
- **Сокеты резолвера** в каталоге состояния: `dnsd.sock` — журнал имён для `dns-log`;
  `dnsd-ctl.sock` — просьбы демона и загрузчика набора правил: подхват нового демона, `down`,
  `reassert` (вернуть элементы real-ip), `flush` (записать `fakeip.state` перед засевом)
  (`src/dnsd/adopt.c`).
- **Апстрим канала** (`dns.upstreams`, `dns` у правила, `dns.upstream`, `dns.other`; ключи —
  docs/spec-v2.md). Канал — это набор nft, режим и апстрим; демон кладёт апстримы, которыми
  пользуются каналы и `dns.other`, в ту же таблицу: заголовок `N U кэш min max neg [other]`, после
  строк каналов U строк `имя|адрес|выход|метка|адреса|bootstrap`, у канала последнее поле
  `dns:<номер>`; седьмое число заголовка — номер строки апстрима `dns.other` (только когда он задан).
  Группа серверов — строка `имя|group:race|-|0|1,2,3|-` (или `group:failover`): члены — номера строк
  апстримов, они стоят в таблице раньше группы. Без апстримов и кэша таблица — прежняя, `N` и
  строки каналов, байт в байт.
- **Группа серверов** (`src/dnsd/dupgrp.c`) — для резолвера один апстрим: `dup_ask` по её номеру
  даёт ровно один обратный вызов — первый годный ответ члена (не SERVFAIL и не REFUSED) или отказ.
  race спрашивает всех сразу; failover — по порядку, с паузой отказавшего члена и вопросом
  следующему по отказу или через 1,5 с молчания. Следующий член спрашивается из `dup_tick`, а не из
  обратного вызова прежнего: тот приходит изнутри разбора соединения. Вопрос группы живёт в куче,
  пока не вернутся все принятые вопросы членов. Имя под правилом с апстримом уходит
  только туда (`src/dnsd/dup.c`): UDP, TCP, DoT (кадры с длиной в два байта по одному соединению,
  вопросы вперемешку, номер транзакции свой на апстрим), DoH (POST `application/dns-message`; в ALPN «h2, http/1.1», протокол выбирает сервер. HTTP/2:
  одно соединение на апстрим, вопрос — поток, число одновременных потоков — то, что объявил сервер
  (`SETTINGS_MAX_CONCURRENT_STREAMS`, до его SETTINGS — 100), ответ на GOAWAY — потоки за
  `last_stream_id` уходят на новое соединение; кадры и HPACK — `src/dnsd/doh2.c`, таблица заголовков
  у сервера нулевая. HTTP/1.1: keep-alive, соединение на каждый ожидающий вопрос, пока хватает
  дескрипторов — четверть RLIMIT_NOFILE, на каждом один вопрос за раз; ALPS из ClientHello DoH
  убран) и DoQ (RFC 9250, `quic://`: одно соединение QUIC на апстрим, вопрос — свой двунаправленный
  поток с кадром «длина, сообщение с номером 0» и FIN, ответ сопоставляется по потоку; кадры и коды
  — `src/dnsd/doq.c`). Сокеты — в epoll резолвера, неблокирующие, срок вопроса 4 с,
  простаивающее соединение закрывается через 5 минут; обрыв соединения под вопросом — один повтор
  на новом, дальше SERVFAIL; после неудачи следующая попытка — через 1, 2, 4 … 30 с, всё это время
  вопросы получают SERVFAIL сразу. Рукопожатие TLS блокирующее, поэтому соединение устанавливает
  короткий поток (`dupdial.c`: bootstrap, connect, `tls13_handshake_auth`) и отдаёт циклу готовый
  сокет; поток заводится на соединение, не на вопрос. Рукопожатие QUIC неблокирующее: поток `dupdial.c`
  только находит адреса сервера, а `qc_open`, события сокета и таймер обёртки `src/proto/quic` ведёт
  цикл резолвера (`dup_wait_ms` учитывает `qc_timeout_ms`); контекст TLS с корнями — один на процесс.
  Соединение DoQ, не подавшее ни пакета за 1,5 с после отправленного вопроса, считается мёртвым:
  оно пересоздаётся, вопрос уходит на новом. Билеты сессии (кэш `qc_tls` в `src/proto/quic/quic.c`, по
  записи на сервер, память процесса) дают рукопожатие по PSK и 0-RTT: пока рукопожатие идёт, `pick_conn`
  берёт соединение с `dupq_early_ready` и вопрос уходит в early data; отвергнутый 0-RTT
  (`on_early_rejected`) возвращает вопросы в очередь, попытка не тратится; счётчики `early` и
  `early_rejected` — в `dns-log`. TLS и обёртка QUIC
  берутся из библиотек ядра слабыми ссылками: сборка без них работает, а DoT/DoH (без TLS) и
  DoQ (без QUIC) в ней отказывают.
- **Путь запроса.** Сокет апстрима «через выход» метится меткой выхода (та же, что у сокета туннеля
  `over`, `marks.h`, плюс на телефоне бит собственного трафика туннеля), «напрямую» — без метки на
  роутере и меткой «само ядро steer» на телефоне. Метку в таблицу кладёт демон из реестра; у резолвера
  без демона её нет, и апстрим «через выход» не используется. Правило ip rule ведёт помеченный пакет
  в таблицу выхода, `postrouting_guard` (в него попадают и выходы, названные в `dns`) не пускает его
  в другое устройство. Bootstrap идёт с той же меткой.
- **Кэш** (`dns.cache`, `src/dnsd/dcache.c`): только ответы на имена под правилами и, с
  `dns.other`, на имена вне правил (ответы его сервера), NOERROR и
  NXDOMAIN, ключ — апстрим, имя без регистра, тип. Срок — наименьший TTL, зажатый пределами
  `cache_ttl`; TTL в самом ответе зажат так же и уменьшается на возраст, поэтому адрес real-ip
  в наборе и у клиента кончается одновременно. Ответ из кэша идёт через тот же `upstream_answer`, что
  ответ по сети: подмена fake-IP ставится в ядро раньше ответа клиенту, ответа «из пула сразу» нет.
  Кэш сбрасывается при каждой новой таблице.
- `steer dns-log` кроме имён (у каждого — сервер, которым оно спрашивается, `dns`) отдаёт
  `upstreams` (состояние, счётчики, последняя ошибка; у группы — режим, члены и их паузы), `cache`
  и `other` (docs/ctl.md).

### Команды и файлы состояния

Команда описана строкой таблицы `CMDS[]` в `src/cli/cli.c` (флаги, справка, проверка аргументов), а
вызывается цепочкой сравнений в `main()` (`src/daemon/main.c`). Команды модулей, которых в сборке
может не быть, объявлены там же слабыми ссылками и отвечают отказом «нужен пакет …» (правило 3).
Инструменты, на которые отвечает `steer-tools`, перечислены в `TOOLS[]` того же файла.

Файлы ядра (пути платформы — `src/platform/openwrt.c` и `android.c`):

| Где | Файл | Что |
|---|---|---|
| каталог спеки (`/etc/steer`, телефон — `/data/misc/steer`) | `spec.json` или `spec.yaml` | спека |
| | `select` | выбор групп `pick: manual`; пишется только при смене выбора |
| | `steer.sock` | управляющий сокет демона |
| каталог состояния (`/var/lib/steer`, на роутере tmpfs; телефон — `/data/misc/steer/state`) | `registry` | реестр меток и таблиц выходов |
| | `fakeip.state` | раздача fake-IP резолвера |
| | `active`, `latency`, `restart-*` | память сторожа между проходами у `steer failover`; демон держит её в памяти, `active` пишет при изменении |
| | `status.json` | снимок `status` для `status --fast` |
| | `probe-<выход>`, `xsteer-<имя>.json` | ход перебора узлов и состояние клиента xsteer — только у помощника без трубы событий демона |
| | `awg-devices`, `awg-<устройство>.hs`, `awg-<устройство>.sig`, `dnsd.sig` | устройства awg, которые завело ядро; замер awg одиночного прохода; подписи, по которым решается, перенастроить ли устройство awg и хватит ли резолверу SIGHUP |
| | `dnsd.sock`, `dnsd-ctl.sock` | сокеты резолвера |

Что из каталога спеки переживает sysupgrade, перечисляет `files/lib/upgrade/keep.d/steer`.

## 3. Спека v2

Свой формат под ядерную модель steer, а не разделы sing-box. YAML читается через libyaml из
дерева (`src/third_party/libyaml`); JSON — тоже YAML, и спеку v2 можно записать JSON-объектом с
`"version": 2`. Ключ `version: 2` отличает формат от спеки v1 — JSON со `schema: 1` или
`schema: 2` (docs/contract-v1.md), которую переводит `src/model/v1.c`.

Полная форма формата — ниже. Всё, что в ней есть, разбор принимает и проверяет; то, чего ядро
ещё не выполняет (здесь — `app` клиента, встроенные `domains`/`prefixes` списка), отвергается отказом «ещё не поддерживается в этой версии
ядра steer: …» после всех настоящих проверок. Что ядро принимает целиком, показывает пример
[docs/spec-v2.md](spec-v2.md); там же все ключи, умолчания и отказы.

```yaml
version: 2

lan: { devices: [br-lan] }            # кто наши клиенты по умолчанию

clients:                              # именованные группы клиентов
  kids: { mac: [aa:bb:cc:dd:ee:01] }
  tv:   { addr: [192.168.1.50] }
  tg:   { app: [org.telegram.messenger] }      # только на телефоне

lists:                                # что: назначения
  youtube: { srs: lists/youtube.srs }
  work:    { domains: [corp.example], prefixes: [10.20.0.0/16] }
  voice:   { prefixes_file: lists/dc.lst, proto: udp, ports: [50000-65535] }

outputs:                              # куда
  wg0:  { kind: interface, device: wg0 }
  wg1:  { kind: interface, device: wg1 }
  nl:   { kind: tunnel, protocol: vless, subscription: sub/nl, nodes: [3, 5],
          transport: ws, over: wg0 }
  dpi:  { kind: zapret, strategy: zapret/yt.opts }
  res:  { kind: group, pick: order,   members: [wg0, wg1], on_fail: drop }
  eu:   { kind: group, pick: manual,  members: [nl, res], default: nl }
  bal:  { kind: group, pick: balance, members: [nl, wg1] }

dns:
  mode: fakeip                        # умолчание
  cache: 2048
  upstreams:
    nl-doh: { url: https://1.1.1.1/dns-query, out: nl }

rules:                                # сверху вниз, выше — сильнее
  - { name: yt,   for: [kids, tv], to: [youtube], out: dpi, resolve: realip }
  - { name: work, to: [work, voice], out: eu, dns: nl-doh }
```

- Правило только ссылается на имена: `for` — клиенты (по умолчанию `lan`), `to` — списки, `out` —
  выход или группа. При пересечении правил побеждает то, что выше, а нижнее не отбрасывается.
- `over` — подложка туннеля, выход, через который идёт трафик самого туннеля (в спеке v1 — `via`).
- У `interface` в v2 одно устройство: резерв из нескольких устройств — группа `pick: order`.
- **Формат — по содержимому, а не по имени файла.** Текст с `{` — JSON: `version` наверху — v2,
  иначе v1 с отказами v1; остальное — YAML, то есть v2. Файл по умолчанию — `{etc}/spec.json` или
  `{etc}/spec.yaml`; лежат оба — отказ «две спеки».
- **Неизвестный ключ и ключ чужого вида — отказ**, каждый отказ — `файл:строка:столбец`. Ссылки по
  именам проверяются, круг в группах и в `over` — отказ.
- **Ключи видов** разбирает сам вид (`kind_ops.parse` над `struct out_keys` — один разбор на оба
  формата): `kind: tunnel, protocol: vless` (`kind: vless` — отказ с подсказкой) с `subscription`
  (v1 `sub_file`), `nodes` и `transport`; `strategy` у zapret (v1 `opts_file`); `conf`, `stream`,
  `stream_port` у xsteer; `conf` у awg; `obfs: { mode, server, listen }` у interface; `domain` у
  tgws; `ipv6` и `prefix` у выходов с IPv6 (раздел 4б).
- **Относительный путь — от каталога файла спеки** (`lists/youtube.srs` рядом со спекой в
  `{etc}`), а не от рабочего каталога процесса.
- `steer spec convert` печатает спеку v2 из спеки v1 (`src/model/v2print.c`); напечатанное даёт тот
  же набор правил до байта.

Во что спека разбирается — раздел 4в.

## 4. Проверка изменений

- **Юнит-стенды.** Модуль линкуется со стендом сам, без `#include` чужого `.c` и `setjmp`; общий
  каркас — `tests/unit.h`. Стенды не включают `.c` из `src/model`, `src/compile`, `src/lib`,
  `src/daemon`, `src/dnsd`; число стендов, которые включают исходники из `src` (протоколы, туннель,
  `awgmatch`), не растёт — это держит храповик `tests/buildmatch.sh`.
- **Снимок генератора** (`tests/snapshot.sh`, `tests/golden/ruleset`, входит в `make test`) — вывод
  `apply --dry-run` со stderr и кодом выхода по всем спекам `tests/gen.sh`, для обеих раскладок nft
  и обеих платформ. Изменение, которое не должно менять набор правил, обязано совпасть с ним байт в
  байт; перезапись — `make snapshot-record`, только вместе с намеренным изменением набора правил.
  Спека v1 и её перевод в v2 дают один набор правил (`tests/v2match.sh`).
- **Интеграция в сетевых пространствах** (стенды `*.sh` с root): демон, резолвер, туннель и сторож
  на хосте, пакет клиента реально уходит в нужный выход, упавший выход переключается.
- **`make ext-test`** — стенды расширенной части на настоящем wolfSSL той же версии и с теми же
  опциями, что в сборке (`tests/ext-test.sh`).
- **`tests/buildmatch.sh`** — согласие сборочных списков, правила раздела 2, контракт журнала,
  упаковка, `keep.d` и идентификаторы проверок diag против `docs/contract-v1.md`.
- **Стенд роутера в QEMU** — поведение на настоящих procd, fw4 и netifd.

## 4а. Демон steerd

Демон — хозяин состояния ядра: спека и группы в памяти, сторож выходов, дети-помощники и
резолвер, сокет управления с событиями. Флаги: `--watch` (сторож), `--supervise` (дети),
`--apply` (применить спеку при старте). Устройство сокета, команд и событий — [docs/ctl.md](ctl.md).

**Сокет и протокол.** Протокол управляющего сокета v1: строка запроса с телом по длине, ответ —
один объект JSON одной строкой; `subscribe` оставляет соединение открытым и шлёт события строками
JSON (`src/daemon/ctl.c`). `status`, `diag`, `explain`, `conns`, `dns-log` демон отвечает из памяти
и по ядру в своём процессе: nf_tables и маршруты — по netlink (`src/lib/nftdump.c`,
`src/lib/rtnl.c`), резолвер и обфускатор — обходом /proc (`src/lib/procscan.c`). Изменяющие команды
(`apply`, `check`, `reload`, `rm-file`) идут по одной, в очереди; проверка и компиляция — в детях
демона, поэтому остальные команды отвечают и во время `apply`.

**Цикл событий** (`src/daemon/loop.c`). Один `epoll`: слушающий сокет и соединения, `signalfd`
(SIGCHLD, SIGHUP, SIGTERM), таймеры (`timerfd`, `CLOCK_MONOTONIC`), сокет rtnetlink событий сети
(ссылки и адреса) — они будят сторожа, сокет стража правил и трубы событий от детей. Опроса по кругу
нет.

**Проход без fork.** Проход сторожа (`src/daemon/failover.c`) — конечный автомат на цикле событий:
пробы (неблокирующий TCP connect и эхо ICMP, привязанные к устройству), ожидание подъёма устройства
(таймер шага и события netlink), команды оживления (ifdown/ifup, ubus — ребёнок на действие) и
разрешение имён (рабочий поток `src/daemon/gaiw.c`) ждутся шагами автомата, а не синхронно. Тот же
автомат крутят демон (`watchd.c`), `steer failover --loop` и одиночный `steer failover`. Сверка
маршрутизации читает ядро по rtnetlink, поэтому проход по исправной спеке не запускает ни одного
процесса; процесс появляется только на действие. Во время прохода демон отвечает на запросы.

**Состояние в памяти** (`src/daemon/state.c`, `watchd.c`): спека и группы, отпечатки применённого,
по выходу — активное устройство, серия, задержка, здоровье, время оживления; дети; подписчики. Где
та же память лежит файлами (у `steer failover` и помощников без демона), — «Команды и файлы
состояния» в разделе 2; шов между файлами и памятью — `src/daemon/fostate.h`.

**Дети и здоровье** (`src/daemon/supd.c`, `helpers.c`). Помощник получает дескриптор трубы
(`STEER_EVENT_FD`) и пишет в неё события строками JSON (`src/lib/evline.h`): `up` (с полем `dev` —
устройство, которое поднял этот процесс), `down` с причиной, `node`, `health`. Без дескриптора
(ручной запуск, стенды) помощник работает сам по себе и пишет свои файлы состояния. Порядок подъёма
по `over`, перезапуск с растущей паузой, подпись параметров «надо ли перезапускать» — одним кодом
для демона и `steer supervise`. Маршрут выхода к устройству помощника ставит демон: по первому `up`
с `dev` за жизнь процесса он привязывает таблицу выхода к устройству (`bind_device`) в своём
процессе; следующие `up` маршрут не трогают, после `down` и выхода процесса решает сторож
(`on_fail`). Без демона маршрут выхода к устройству помощника не привязывает никто. Клиент VLESS (и
протоколов прокси) сам следит за своими активными узлами (`src/tunnel/pool.c`), и сторож принимает
его `up` и `down` без своей пробы.

**Apply-сверка** (`src/daemon/recon.c`). `apply` и `reload` строят план новой спеки в ребёнке
(`apply-plan`: проверки dry-run и отпечатки частей) и применяют только изменившиеся части
(`apply-commit`): набор правил, маршрутизацию выходов, помощников, таблицу резолвера. Отпечаток
набора правил считается по тексту без засева из файла состояния резолвера. Неизменная спека не
запускает ни `nft`, ни `ip`.

**Сверка с ядром.** То же `apply` и `reload` сверяют с ядром и применённое: номер и отпечаток наших
таблиц (`nfd_table_fp`: цепочки, правила по порядку, заголовки наборов — без счётчиков и элементов),
сводку элементов статических наборов (сумма перемешанных хэшей, снимает ребёнок-план), правило
`fwmark` и таблицу каждого выхода. Ожидаемое снимает сам ребёнок `apply-commit` сразу после своего
`nft -f`. Демон с `--watch` сверяет номер и отпечаток таблиц ещё и перед каждым проходом сторожа —
без процессов и без элементов; расхождение ставит в очередь `reload`, не больше трёх за пять минут
(docs/ctl.md, «Сверка с ядром»).

**Страж правил** (`src/daemon/rulewd.c`, с `--watch`). Правила `fwmark` выходов живут вне нашей
таблицы, и их снимают чужие (netifd на своём старте, netd на телефоне, `ip rule flush`). Страж слушает
снятие правил IPv4 и IPv6 и запасного запрета в таблицах IPv6 выходов и возвращает их сам, одним
сообщением rtnetlink; своё снятие он отличает по таблице IPv4 выхода. Сторож ещё и замечает
пересозданное устройство раздачи и ставит сверку набора правил, возвращая на него цепочку
`ingress_mark` (docs/ctl.md, «Страж правил выходов»). Пока правила нет, помеченный пакет не уйдёт в
чужое устройство: его отбросит `postrouting_guard`.

**dnsd** — ребёнок демона на таблице от него (раздел 2, «DNS»). Демона резолвер переживает:
закрытая труба — «демона нет», он отвечает по последней таблице и ждёт нового демона
(`--orphan-timeout`, по умолчанию 60 с); новый демон на том же каталоге состояния забирает его через
`dnsd-ctl.sock` новой трубой (`src/dnsd/adopt.c`). `steerd down` без демона просит его выйти тем же
сокетом. Если stderr резолвера сломан (читателя нет), строки журнала уходят в `/dev/log` с
заголовком syslog.

**Бинарники.** `steerd` — всё ядро одним файлом. `steer` (`src/client/main.c`, `CLIENT_SRC` в
`build/sources.mk`) — клиент: команды демона (`status`, `diag`, `explain`, `conns`, `dns-log`,
`select`, `apply` без `--dry-run`, `reload`, `subscribe`) шлёт в сокет и печатает stdout, stderr и
код из ответа; всё остальное — и любую команду, когда демона нет или он обслуживает другую спеку
(сверка по `version`), — отдаёт `steerd` через execv с теми же аргументами. `steerd` клиент берёт
из `STEER_ENGINE` или рядом с собой. `steer-tools` — ссылка на `steerd`: под этим именем (argv[0])
ядро отвечает только на инструменты. Подробно — docs/ctl.md, «Клиент steer».

**Выключенное ядро** (телефон, свойство `persist.der.steer.enabled`): ни таймеров сторожа и стража
правил, ни снимка `status`, ни сокетов событий сети — демон не просыпается сам. Положение
выключателя ему сообщают `apply`, `reload` и SIGHUP. wakelock демон не берёт.

## 4б. IPv6

Семейство — свойство строки списка и адреса клиента; у выхода и группы — бит `KC_IPV6`. Его несут
`interface`, `awg` и `zapret` (и группа, все члены которой его несут); у `vless`, `xsteer` и `tgws`
его нет.

- **Списки.** Строка списка классифицируется по семейству (`spec_line_family`: 4, 6 или 0 — имя).
  Строки IPv6 из файлов и подсети IPv6 из `.srs` идут в парный набор группы `<имя>6` (`ipv6_addr`; у
  составной группы — `ipv6_addr . inet_proto . inet_service`). Набор заводится, только когда у
  группы есть элементы IPv6 или у доменной группы есть половина IPv6 (`dom6`). `steer fit`
  пропускает строки IPv6 как есть: не сливает и в бюджет не считает.
- **Правила.** У правила группы — v6-двойник в той же цепочке: то же «кто», сужение, поиск в `<имя>6`
  (или «весь трафик»), та же метка и тот же комментарий, поэтому счётчик канала остаётся одним
  числом (`counters_load` складывает правила с одним именем). «Кто» по устройству и по MAC — одно
  выражение на оба семейства; адреса — `ip saddr` для записей IPv4 и `ip6 saddr` для записей IPv6.
  Клиенты по умолчанию из одних подсетей IPv4 узнаются для IPv6 по устройствам. Клиент правила из
  одних адресов IPv4 по IPv6 не узнаётся (diag: `ipv6_clients`).
- **Маршрутизация.** Выход с устройством и `KC_IPV6` получает `ip -6 rule fwmark <метка>/<маска>
  table <таблица>` с той же меткой и тем же номером таблицы и маршрут в устройство в таблице IPv6. В
  таблице IPv6 всегда лежит запасной запрет `prohibit` (`table_bh_type`, `src/daemon/failover.c`):
  ядро сразу отвечает клиенту «administratively prohibited», и клиент переходит на IPv4, а не ждёт
  таймаута; у IPv4 запрет — `blackhole`. Сторож и страж правил сверяют и возвращают оба семейства.
  masquerade IPv6 на роутере — дело зоны fw4 (`masq6`), на телефоне его ставит ядро steer
  (`ip6tables`).
- **Проба сторожа** — по IPv4: здоровье туннеля — здоровье его транспорта и пира, у семейств оно
  общее.
- **Выход без IPv6.** IPv6 его правил метится, но правила `ip -6 rule` у метки нет, и цепочка
  `forward_v6` отвергает такой пакет (`reject with icmpx type admin-prohibited`): клиент с двумя
  стеками сразу переходит на IPv4. В prerouting reject ядро не принимает, а drop задел бы трафик к
  самому роутеру. На телефоне для каналов на само устройство — reject в `output_mark`. diag:
  `ipv6_output`.
- **Старое ядро (4.9).** Разметка IPv6 остаётся в `inet`; nat IPv6 — только при `NFTC_IP6NAT`.

**Резолвер.**
- **Есть ли у доменного правила IPv6** — одно решение на компилятор и резолвер, `dom6_ok`
  (`src/model/parse.c`): выход несёт IPv6 или метки не ставит (direct), «кто» выражается для IPv6, а
  для fake-IP ещё и есть nat в ip6. Резолвер получает решение полем семейства в таблице каналов.
- **Ответ на AAAA.** Имя под правилом получает адрес, только если IPv6 есть у всех совпавших каналов
  (`dch_all_v6`); иначе — пустой ответ. У спеки v1 ответ на AAAA имени под правилом пустой всегда:
  перевод v1 ставит модели `dns.names_v4`, и таблица даёт её каналам семейство «4». Набор правил
  спеки v1 от этого не меняется. HTTPS и SVCB для имён под правилом гасятся.
- **fake-IP v6.** Пул `fdfe:dcba:9876::/96` (`FAKEIP6_NET`); поддельный IPv6 — пара поддельного IPv4
  той же записи в младших 32 битах (`fakeip6_of`), поэтому выдача одна на оба семейства и хранить
  поддельный IPv6 не нужно. Карта `fakeip6` и правило `dnat ip6 to ip6 daddr map @fakeip6` в
  `prerouting_dnat`; отказ карты — пустой AAAA.
- **real-ip v6.** Настоящие AAAA — в `<имя>6` каналов real-ip со сроком ответа.
- **`fakeip.state`** — строка «домен, поддельный, настоящий, настоящий IPv6»; на месте настоящего
  IPv4 — «-», если его нет; запись без IPv6 пишется формой из трёх полей.
- **`explain`** принимает адрес IPv6 и у поддельного адреса обоих семейств называет имя.

**IPv6 от хоста** (ключ `ipv6: routed | nat | off` у выхода спеки v2, docs/spec-v2.md). Хост —
сервер на том конце туннеля WireGuard, у которого IPv6 есть; роутер получает IPv6 внутри туннеля.
- *Модель.* `enum out_ipv6`, `struct v6pfx` и `v6_denied` у `struct output` (`spec.h`). Кому снять
  IPv6, решает `spec_v6_resolve` один раз после разбора: `off` и все выходы рядом с донором, кроме
  донора и `nat`; у них снимается `KC_IPV6`, и всё, что спрашивает «несёт ли выход IPv6», видит один
  ответ. На телефоне `routed` и `nat` действуют как отсутствие ключа (`out_ipv6_mode`), `off`
  действует.
- *Набор правил.* Набор `v6donor` с префиксом хоста; последнее правило разметки — всё несовпавшее из
  префикса, кроме назначений в самом префиксе, ULA, link-local и multicast, — в донора; в
  `forward_v6` — запрет источника из префикса мимо устройств донора и раздачи и ULA-источника в
  донора; донор — и в `postrouting_guard`. `nat` — цепочка `postrouting_nat6` с masquerade IPv6 на
  устройство выхода.
- *Префикс без `prefix:`* (`v6donor_derive`, `failover.c`) выводится по ядру: нуль-маршрут
  `unreachable P`, который netifd ставит на раздаваемый префикс, над глобальным адресом устройства
  раздачи; префикс провайдера отличает маршрут `default from P` через чужое устройство. Кандидат
  ровно один — префикс донора, иначе не угадывается. Сторож в конце каждого прохода сверяет набор
  `v6donor` с ядром и переписывает элементы одной транзакцией (`nfv_ranges6_write`,
  `src/lib/nftvmap.c`).
- *diag* (`ipv6_host`): чего не хватает в `/etc/config/network` и `/etc/config/dhcp` (только
  чтение) и проба эхом ICMPv6 через выход.

## 4в. Модель v2 и группы

**Одна внутренняя модель — модель v2** (`src/model/spec.h`). Компилятор, резолвер, сторож и status
работают с ней. Спека v2 разбирается в неё напрямую (`src/model/v2.c`), спека v1 — переводчиком
`src/model/v1.c`; `load_spec` (`parse.c`) выбирает формат по содержимому, сквозные проверки обоих
форматов — `src/model/check.c`. Сущности:
- `struct spec_client` — кто: адреса, MAC, `self`/`uid` на телефоне; `sp->lan` — клиенты по
  умолчанию;
- `struct spec_list` — что: файлы префиксов и доменов, `.srs`, сужение proto/ports, `all` — весь
  трафик;
- выходы — `struct output` с видами из `src/kinds`, в том числе `group`;
- `struct spec_rule` — «кто → что → куда»: клиенты и списки номерами, выход по номеру, режим DNS,
  область `device`, выключенность. Порядок правил — приоритет.

Несколько клиентов или списков у правила разбор сводит в одного клиента или один список, когда смысл
не меняется: компилятор берёт у правила одного клиента и один список.

**Перевод v1.** Канал становится правилом с безымянными клиентом и списком; выход `interface` с
`devices` из нескольких устройств — группой `pick: order` (или `latency`) из безымянных
членов-интерфейсов по одному на устройство. Безымянные члены лежат в `sp->out` за именованными,
поэтому реестр, status, помощники и правила видов их не видят; группа видна снаружи прежним видом и
именем, с прежними меткой и таблицей. `via` становится `over`. У `steer spec convert` члены пула
получают имена `<пул>.<устройство>` и становятся обычными выходами со своими метками и таблицами.

**Группы** (`src/kinds/group.c`, `struct group_cfg`): у группы свои метка и таблица, члены — любые
выходы с устройством, в том числе группы. Ключи и умолчания — docs/spec-v2.md.
- **Члены спеки v2 — выходы со своим приговором.** Группа своих устройств не пробует: жив ли член —
  приговор его прохода в том же обходе, лист — выбранное им устройство. Обход — по зависимостям
  (`over` и члены раньше группы, `fog_order` в `src/daemon/fogroup.c`). Безымянные члены пула v1
  пробуются, как устройства пула.
- **До первого прохода** (после старта и перезагрузки) apply и status решают за группу так же, как
  решил бы проход, только без проб: `fog_pick_known` — последний приговор члена и наличие устройства.
- **`order`** — первый живой член; возврат на предпочтительный — после нескольких проходов подряд.
- **`latency`** — замер как urltest sing-box (`src/daemon/urltest.c`): `GET` к `url` через члена, время
  до первого байта ответа 204 или 200. Через именованного члена — сокет с его меткой (`SO_MARK`),
  то есть ровно путь трафика группы; безымянному члену пула — `SO_BINDTODEVICE`. HTTP — неблокирующий
  сокет в цикле демона, HTTPS — рабочим потоком `src/proto/tls/urltls.c`, только в полном пакете
  (профили `extended` и `android`; в остальных `https://` отвергает разбор). Замер — по IPv4, а у
  группы спеки v2, все живые члены которой несут IPv6, ещё и по IPv6; выбор один на оба
  семейства — по худшему из двух (`src/daemon/folat.c`). У демона замер идёт своим таймером группы на
  её `interval` и зовёт внеочередной проход, только если выбор меняется. Без трафика через группу
  дольше `idle_timeout` (по счётчикам правил каналов) запросов нет. Выбор — `group_latency_pick`:
  самый быстрый из ЖИВЫХ, а из не хуже него на `tolerance` — первый по порядку (допуск 0 —
  настоящий ноль, `group_tolerance_ms`); у члена, которого нет в живых, замер в счёт не идёт. Замер,
  не давший ответа ни у кого, оставляет группу «по порядку» — ядро говорит это строкой в журнале и
  в status (`why`), а повтор замера у члена без ответа идёт раньше срока (`FOLAT_RETRY_S`).
- **`manual`** — член, выбранный командой `select <группа> <член>` без apply: маршрут таблицы группы
  сразу на лист члена. Выбор хранится в файле `select` рядом со спекой (`steer_keep_dir`). Выбранный
  член не работает — `on_fail` группы, другой член не берётся.
- **`balance`** (`src/compile/balance.c`) — правило канала переходит в цепочку `bal_<таблица>`: там
  восстановление по метке соединения (соединение остаётся на своём члене), затем
  `numgen random mod 120 vmap @balmap_<таблица>` и запасной переход в метку самой группы. 120 слотов
  (`GROUP_BAL_SLOTS`), а не `mod <живых>`: уход члена меняет только элементы карты, которые сторож
  переписывает одной транзакцией nf_tables (`src/lib/nftvmap.c`); веса — доли слотов. `numgen
  random`, а не `jhash` по кортежу: постоянство соединения держит метка соединения, а хэш по
  кортежу при смене карты переносил бы установленные соединения. Если хоть один член не несёт IPv6,
  IPv6 группы уходит в метку самой группы, и `forward_v6` его отвергает.
- **`balance` с `by: site` / `site_client`** — вместо `numgen` по правилу на семейство:
  `meta nfproto ipv4 jhash ip daddr mod 120 seed 0x<таблица> vmap @balmap_<таблица>` и то же с
  `ip6 daddr` (у `site_client` — `ip saddr . ip daddr`). Карта, метка соединения и сторож — те же;
  хеш выбирает слот, то есть член, для сайта, а не для соединения. Семя — номер таблицы группы:
  без семени ядро берёт случайное на каждое правило (сайты тасовались бы с каждым apply), и у каждой
  группы оно своё (вложенная `balance` с тем же семенем получала бы только «свои» слоты внешней и
  отдавала бы их одному члену). Раскладка слотов (`group_balance_slots`) — основная при всех живых;
  когда член лёг, живые сохраняют свои слоты основной раскладки и добирают долю только слотами
  ушедших, поэтому сайты живых не переезжают от чужого отказа, а вернувшийся получает свои назад.
- **Вложенность.** `order`, `latency` и `manual` разворачивают выбор до листа; у `balance` вложенная
  группа — один член со своей меткой и весом, а вложенная `balance` — переход в её цепочку.
  `balance` членом группы `order`, `latency` или `manual` — отказ разбора.
- **status** — объект `group` у выхода-группы спеки v2 и умение `groups` (docs/contract-v1.md, §2);
  события `switched` у групп — с полем `member` (docs/ctl.md).
