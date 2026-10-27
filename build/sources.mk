# Сборочные списки исходников — ЕДИНСТВЕННЫЕ.
#
# Раньше один и тот же список ядра был переписан руками у пяти целей Makefile, в build.sh,
# в build/build-ext.sh и в Android.bp, и расходились они молча: новый файл проходил make test
# и ломался только в релизной сборке, на чужой машине, неопределённой ссылкой (I-024, I-032).
# Теперь списки живут здесь, а остальные их читают:
#
#   Makefile             include build/sources.mk
#   build.sh, build-ext.sh   . build/sources.sh; profile_src <профиль>
#   Android.bp           сверяется с профилем android стендом tests/buildmatch.sh (Soong не
#                        умеет читать чужие файлы, поэтому список там остаётся, но проверяемым)
#
# Формат нарочно простой, чтобы его читал и make, и build/sources.sh без make: строки
# `ИМЯ := значение`, продолжение строки обратной косой чертой, ссылки `$(ИМЯ)` на имена,
# объявленные ВЫШЕ. Ничего другого из make здесь не использовать.
#
# Профиль — это набор файлов одной сборки, и больше ничего (docs/architecture.md, раздел 2,
# правило 3): какие команды и виды есть в бинарнике, решает наличие их файлов (слабые ссылки в
# src/daemon/main.c и src/kinds/kind.c), а то, что файлом модуля не выражается (имя варианта
# сборки, раскладка меток и таблиц мини-сборки tgws, резолвер), — файл профиля src/profile/
# <профиль>.c. Прежние ключи -DSTEER_EXTENDED/-DSTEER_SERVER/-DSTEER_TGWS сняты; PROFILE_DEFS_*
# остались ради умолчания платформы телефона и читаются сценариями сборки по-прежнему.

# Каталоги слоёв (docs/architecture.md). Заголовки подключаются по имени (`#include "spec.h"`)
# из любого слоя, поэтому каждая сборка получает -I на все каталоги сразу; имена заголовков
# в дереве уникальны, и стенд tests/buildmatch.sh за этим следит.
CORE_DIRS := src/lib src/model src/platform src/compile src/daemon src/kinds src/cli src/dnsd src/tools
# Файлы профилей (src/profile, profile.h): profile.c — умолчания, в каждой сборке (с платформой,
# PLATFORM_SRC); остальные — по одному на профиль, у base своего файла нет. Отдельно от ядра и
# от расширенной части, потому что файл профиля не входит ни в одну сборку, кроме своей.
PROFILE_DIRS := src/profile
EXT_DIRS  := src/plugkit src/proto/obfs src/net1 src/tunnel src/proto/tls src/proto/transport src/proto/vless src/proto/xsteer src/proto/tgws src/proto/quic src/proto/hysteria2 src/proto/proxy src/proto/warp src/modules
# Клиент сокета `steer` (src/client) — отдельный бинарник, не профиль движка: CLIENT_SRC ниже.
CLIENT_DIRS := src/client
# Сторонний код (src/third_party) — не слой движка: файлы в нём не правятся (см. UPSTREAM в
# каталоге библиотеки), а собираются вместе с ядром. libyaml подключает свой заголовок как
# <yaml.h>, поэтому её каталог — в -I у всех; обёртка движка над ней называется ynode.h, а не
# yaml.h, ровно чтобы имена заголовков оставались уникальными (tests/buildmatch.sh).
THIRD_DIRS := src/third_party/libyaml
# Менеджер плагинов (src/pluginmgr, `steer plugin …`): только в steerd пакета steer-core (PLUGMGR_SRC ниже) —
# ему нужны HTTPS и проверка подписи из libsteer. В статических сборках его нет (команда отвечает отказом,
# src/daemon/main.c), на телефоне плагинов в 2.1 нет вовсе (plugin-sdk, open.md, О-13).
PLUGMGR_DIRS := src/pluginmgr
INC_DIRS  := $(CORE_DIRS) $(PROFILE_DIRS) $(EXT_DIRS) $(CLIENT_DIRS) $(THIRD_DIRS) $(PLUGMGR_DIRS)
# Каталоги, которых нет в сборке телефона (Android.bp их не подключает: hysteria2 и протоколы прокси
# в профиль android не входят, телефон не собирает ни QUIC-клиента, ни модули steer-hysteria2 и
# steer-proxy). tests/buildmatch.sh сверяет
# Android.bp с INC_DIRS за вычетом этого списка.
PHONE_SKIP_DIRS := src/net1 src/proto/hysteria2 src/proto/proxy src/proto/warp src/pluginmgr
# Определения, которых ждёт сторонний код: yaml_private.h подключает config.h (номер версии
# libyaml) только при HAVE_CONFIG_H. Ключ идёт во ВСЕ пути сборки движка — Makefile, build.sh,
# build/build-ext*.sh (там он читается отсюда), в Android.bp — флагом библиотеки libsteer_yaml;
# забытый в одном из них, он роняет компиляцию api.c, а не тихо меняет поведение, и всё равно
# сверяется стендом tests/buildmatch.sh. Движку ключ ничего не значит.
THIRD_DEFS := -DHAVE_CONFIG_H

# Модель спеки — то, во что нарезан прежний src/model/spec.c (docs/architecture.md, «Слои и
# каталоги»): JSON-ридер, сам разбор спеки, реестр меток/таблиц, ход перебора узлов подписки и
# вопросы о возможностях nftables ядра (nftcompat). Порядок — тот, в котором они шли в
# неразрезанном файле.
#
# lib/err.c — тоже сюда: правило 5 (раздел 2) требует, чтобы модель и компилятор возвращали
# отказ, а не звали die() сами, а err_set/err_prop/err_die и сам die() (для точек входа) живут
# в этом файле. Стенды, собирающие модель отдельным списком (dnsmatch, specmatch, obfsmatch,
# awgmatch — см. Makefile), берут его отсюда же, а не include'ом err.c по одному разу на файл.
# Платформа (src/platform, docs/architecture.md, раздел 2, правило 2): роутер или телефон,
# выбирается при запуске, и код обеих есть в каждой сборке. Идёт вместе с моделью, потому что
# модель её и спрашивает первой: разбор (zapret и каналы на само устройство), реестр (поле
# метки), пути состояния. Стенды, компонующие модель, получают платформу тем же списком.
# С ней же — умолчания профиля (src/profile/profile.c): поле метки мини-сборки tgws подменяет
# поле роутера в plat(), так что платформа без профиля не компонуется.
PLATFORM_SRC := src/platform/platform.c src/platform/openwrt.c src/platform/android.c src/profile/profile.c

# Чтение YAML (docs/architecture.md, «3. Спека v2»): событийный парсер libyaml 0.2.5
# (src/third_party/libyaml, MIT; только разбор — без загрузчика и эмиттера) и обёртка движка
# src/lib/ynode.c, которая строит из событий дерево с пределами и отказом на алиасах. В ядре, а
# не в полном пакете: спеку v2 читает и мини-движок, и полный. JSON спеки v1 читается тем же
# парсером (стенд tests/yamlmatch.c). В модели, а не рядом с ней: load_spec сам выбирает формат
# и зовёт разбор v2 (src/model/v2.c), так что всякий, кто компонует модель, компонует и YAML.
LIBYAML_SRC := src/third_party/libyaml/api.c src/third_party/libyaml/reader.c \
               src/third_party/libyaml/scanner.c src/third_party/libyaml/parser.c
YAML_SRC := src/lib/ynode.c $(LIBYAML_SRC)

# Разбор спеки: parse.c (общее и выбор формата), v1.c (перевод v1), v2.c и v2print.c (спека v2 и
# её печать — `steer spec convert`), check.c (сквозные проверки, общие для обоих форматов).
#
# lib/nftdump.c, lib/rtnl.c, lib/procscan.c — вопросы к ядру (nf_tables и rtnetlink) и обход /proc
# без процессов: их задают status и diag, но и виды (interface — маршрут к серверу обфускации и
# живость обфускатора) и nftcompat (возможности nftables ядра), а
# виды идут со всякой моделью. Поэтому здесь, а не в CORE_SRC.
#
# lib/ir.c — дерево набора правил (lib/ir.h) — здесь по той же причине: его строят не только
# компилятор (src/compile), но и виды (kind_ops.emit у tgws), а о спеке и видах дерево
# не знает ничего (только libc), то есть это кирпич lib, а не часть компилятора.
#
# lib/module.c — какая команда чья и установлен ли модуль (шаг 4 выпуска 1.10, src/lib/module.h):
# его зовут реестр видов (kinds/kind.c, kinds/tgws.c) и справка (cli/cli.c), а они идут со всякой
# моделью, поэтому файл здесь же.
#
# MODEL_SPEC_SRC — модель без платформы, lib/err.c и lib/jsonr.c (их net1 берёт себе отдельно,
# NET1_BASE_SRC ниже). Программам плагинов модель спеки не нужна вовсе: о выходе им говорит {conf}.
MODEL_SPEC_SRC := src/lib/module.c src/lib/tmpfile.c src/lib/ir.c src/model/parse.c src/model/v1.c \
                  src/model/check.c src/model/v2.c src/model/v2keys.c src/model/v2schema.c src/model/v2print.c src/model/registry.c \
                  src/model/probe.c src/model/plugprep.c src/compile/nftcompat.c src/lib/puff.c src/lib/gz.c src/model/srs.c src/model/srsplan.c \
                  src/lib/nftdump.c src/lib/rtnl.c src/lib/procscan.c $(YAML_SRC)
MODEL_SRC := $(PLATFORM_SRC) src/lib/err.c src/lib/jsonr.c $(MODEL_SPEC_SRC)

# Резолвер: src/dnsd/dnsd.c был один файл, теперь — DNSD_SRC. lib/sindex.c, lib/nftnl.c,
# lib/ctnl.c родились из того же файла (хеш-индекс строк, транзакции nf_tables по netlink,
# разговор с conntrack) и собираются только вместе с резолвером — CORE_SRC берёт весь список.
# dnsd/origdst.c (исходное назначение запроса) родился позже, разделением ctnl.c: он работает
# на типах резолвера, а общий разговор с ctnetlink (ct_attr, ctnl_dump…) остался в lib/ctnl.c —
# им пользуется и origdst.c, и список соединений `steer conns` (src/daemon/conns.c, CORE_SRC
# ниже), а resolver-типов ctnl.h больше не подключает.
#
# DNSD_TABLE_SRC — сборка и разбор таблицы доменных каналов (src/dnsd/tabfmt.h, docs/
# architecture.md, раздел 4а, «dnsd»): table.c (dch_build — то же построение, что и раньше) и
# tabfmt.c (текст ↔ g_dch). Отдельной переменной, а не прямо в DNSD_SRC, потому что демону 1.8
# они понадобятся БЕЗ остального резолвера (сети, epoll, fake-IP) — он таблицу только собирает
# и шлёт в трубу, обслуживать LAN не обслуживает сам. Сегодня это подмножество DNSD_SRC (один
# бинарник несёт всё сразу); шаг 6 (раздельные бинарники) сможет собрать steerd этим списком, не
# трогая DNSD_SRC вовсе.
DNSD_TABLE_SRC := src/dnsd/table.c src/dnsd/tabfmt.c

# dnsd/fpseed.c — засев наборов каналов fake-IP в тексте набора правил (src/dnsd/fpseed.h): код
# резолвера, но зовёт его apply, а не резолвер, — поэтому он в любой сборке, где есть и apply, и
# резолвер (то есть в DNSD_SRC, как и всё сопоставление имён).
DNSD_SRC := src/lib/sindex.c src/lib/nftnl.c src/lib/ctnl.c \
            src/dnsd/rules.c src/dnsd/wire.c src/dnsd/origdst.c src/dnsd/fakeip.c $(DNSD_TABLE_SRC) \
            src/dnsd/dlog.c src/dnsd/realip.c src/dnsd/adopt.c src/dnsd/proxy.c src/dnsd/main.c \
            src/dnsd/fpseed.c src/dnsd/dcache.c src/dnsd/dup.c src/dnsd/dupgrp.c src/dnsd/dupdial.c \
            src/dnsd/doq.c src/dnsd/doh2.c src/dnsd/doh3.c src/dnsd/dprobe.c

# Виды выхода ядра (src/kinds, docs/architecture.md, раздел 2, правило 1): вид — это файл. Протоколов
# среди них нет: виды протоколов (tunnel:vless и соседи, xsteer, warp) приходят только из манифестов
# плагинов (kinds/plugin.c) — без плагина такой выход недоступен (unavail), остальное работает
# (plugin-sdk/docs/steer-api.md, 3.5). tgws — пока вид ядра (его вынос в плагин — отдельная работа).
# Состав проверяет tests/buildmatch.sh.
KINDS_BASE_SRC := src/kinds/kind.c src/kinds/direct.c src/kinds/block.c src/kinds/group.c src/kinds/grpurl.c src/kinds/interface.c \
                  src/kinds/tgws.c src/kinds/awg.c src/kinds/awgdev.c src/kinds/plugin.c src/kinds/plugalloc.c

# src/daemon/steer.c нарезан на модули (docs/architecture.md, раздел 2, «Слои и каталоги»):
# компиляция спеки в правила — в src/compile, остальное ядро — в src/daemon, порядок ниже
# такой же, как был в steer.c (lib/run.c раньше всех — на него ссылаются и compile, и daemon).
#
# С ВЫПУСКА 1.10 (ШАГ 4) ЯДРО РАЗРЕЗАНО НА ДВА СПИСКА, а CORE_SRC — их сумма:
#   DAEMON_SRC        то, что остаётся в бинарнике steerd, когда он линкуется с libsteer.so:
#                     компилятор правил, apply, сторож, супервизор, демон, резолвер, точка входа;
#   LIBSTEER_BASE_SRC то, что нужно и демону, и модулям: модель спеки (с libyaml), платформа,
#                     реестр и файлы видов, разбор командной строки, линия событий,
#                     идентификатор роутера. Уходит в libsteer.so (LIBSTEER_SRC ниже);
# Статические сборки (телефон, стенды, мини-сборка tgws, хаб) по-прежнему берут CORE_SRC целиком:
# один бинарник без разделяемых библиотек, и снимок генератора, стенды и телефон проверяют ровно
# ту логику, что едет в пакет; отличается только компоновка. Обфускатор (`steer obfs`,
# `obfs-server`) — программа плагина obfs (OBFS_MOD_SRC), в ядре его подкоманд нет.
# cli/modcmd.c — команды модулей (заглушки steerd и настоящие ветки модулей) и main модуля;
# входит и в steerd, и в каждый бинарник модуля.
MODCMD_SRC := src/cli/modcmd.c
DAEMON_SRC := src/compile/groups.c src/compile/generate.c src/compile/balance.c src/compile/print.c src/daemon/fwcheck.c \
              src/daemon/apply.c src/daemon/status.c src/daemon/nftquery.c src/daemon/diag.c \
              src/daemon/explain.c src/daemon/helpers.c src/daemon/supervise.c src/daemon/supd.c src/daemon/watch.c src/daemon/main.c \
              $(DNSD_SRC) src/daemon/failover.c src/tools/aggregate.c \
              src/tools/srsread.c src/daemon/ctl.c \
              src/daemon/conns.c src/daemon/loop.c src/daemon/state.c src/daemon/watchd.c src/daemon/recon.c src/daemon/rulewd.c \
              src/daemon/foprobe.c src/daemon/gaiw.c src/daemon/urltest.c src/daemon/fogroup.c src/lib/nftvmap.c \
              src/daemon/folat.c src/daemon/plugso.c $(MODCMD_SRC)
LIBSTEER_BASE_SRC := src/lib/run.c src/lib/jsonw.c src/lib/evline.c $(MODEL_SRC) \
                     src/cli/cli.c src/tools/hwid.c src/lib/ctlcall.c $(KINDS_BASE_SRC)
OBFS_MOD_SRC := src/proto/obfs/obfsmain.c
CORE_SRC := $(DAEMON_SRC) $(LIBSTEER_BASE_SRC)

# Слой криптографических примитивов (src/lib/scrypto.h, docs/architecture.md, «Криптография»):
# единственный файл движка, который видит wolfSSL. Лежит в src/lib, потому
# что это кирпич библиотеки (в 1.10 он уходит в libsteer.so вместе с TLS и стеком), но в профиль
# base не входит: базовому движку криптография не нужна, и библиотеки в его сборке нет. Поэтому
# отдельной переменной — как KINDS_EXT_SRC, у которых тот же расклад: каталог ядра, профили
# полного пакета (tests/buildmatch.sh сверяет каталоги ядра с base вместе с обеими). Собирается
# с опциями wolfSSL (-DWOLFSSL_USER_SETTINGS, -I на build/wolfssl и исходники библиотеки) —
# остальным файлам движка они ничего не значат.
CRYPTO_SRC := src/lib/scrypto.c

# Общее для обеих ролей: формат кадра, конфигурация, маршрутизация, рукопожатие, соединение
# и то, на чём они стоят (TLS-записи, примитивы Reality, TUN). Расходиться на проводе этим
# половинам негде — кода формата ровно один экземпляр, и это ровно та гарантия, которая
# заменила прежнюю «один бинарник на две стороны» (см. server/README.md).
# xsstream.c и xsepoch.c лежат в ОБЩЕЙ половине, а не в клиентской: рамка записей по
# настоящему TCP и ратчет эпох нужны обеим сторонам звезды, и держать их у одной значило бы,
# что вторую придётся писать заново — то есть двумя способами ошибиться в формате, который
# обязан совпадать до байта.
# certverify.c лежит в ОБЩЕЙ половине, хотя проверка цепочки нужна только клиенту: её зовёт
# tls13.c, и зовёт безусловно, а не под #ifdef. Значит файл обязан быть везде, где
# компилируется tls13.c, — то есть во всех трёх ролях. Внесённый только в EXT_ROUTER_SRC, он
# оставил роли server и tgws с неопределёнными ссылками на cert_verify_server: сборка
# роутерного пакета при этом шла как обычно, и заметить это было нечем, кроме релиза.
XS_COMMON_SRC := src/proto/xsteer/xswire.c src/proto/xsteer/xsconf.c src/proto/xsteer/xslink.c src/proto/xsteer/xsroute.c \
                 src/proto/tls/chello.c src/proto/xsteer/xshake.c src/proto/xsteer/xsconn.c \
                 src/proto/xsteer/xsstream.c src/proto/xsteer/xsepoch.c \
                 src/proto/tls/tls13.c src/proto/tls/certverify.c \
                 src/proto/tls/reality.c src/tunnel/tun.c src/proto/tls/h2.c \
                 src/proto/xsteer/xsadmin.c src/proto/obfs/obfs.c $(CRYPTO_SRC)
# Туннель VLESS — стек отдельно от протокола (шаг 2 выпуска 1.10, docs/architecture.md, «Туннели:
# стек, дайлер, транспорт»). Три списка — по тому, куда файлы уйдут на шаге 4, когда появятся
# libsteer.so и бинарники модулей; пока все три входят в расширенный профиль целиком:
#   STACK_SRC      стек TUN ↔ потоки TCP/UDP (tun.c — в XS_COMMON_SRC: на нём стоит и xsteer) —
#                  в libsteer;
#   TRANSPORT_SRC  транспорты до узла (сокет, security, tcp/grpc/xhttp/ws/httpupgrade) и корни
#                  проверки сертификата — в libsteer, вместе с TLS; trpath.c (путь запроса
#                  Upgrade — чистые строки) зовёт и разбор подписки sub.c;
#   VLESS_MOD_SRC  протокол: подкоманды vless*, дайлер, слежка за узлом, проверка узла,
#                  заголовок и Vision — в бинарник модуля steer-vless.
# sub.c (разбор подписки) — не в модуле: его зовёт и `steer-tools sub-fetch` (subfetch.c).
#   SUBLINK_SRC    ссылка узла в форме Xray (строки ссылки, поля транспорта и безопасности, их
#                  годность): половина разбора sub.c, которую с ним делит модуль steer-proxy
#                  (trojan://, vmess://), — в libsteer, как и сам транспорт.
SUBLINK_SRC := src/proto/vless/sublink.c
STACK_SRC := src/tunnel/stack.c src/tunnel/rtx.c src/tunnel/pool.c src/tunnel/geo.c \
             src/proto/warp/wbhttps.c src/proto/warp/wbjson.c src/proto/tls/httpc.c src/proto/tls/plughttp.c
TRANSPORT_SRC := src/proto/transport/transport.c src/proto/transport/trdial.c \
                 src/proto/transport/trsec.c src/proto/tls/ech.c src/proto/transport/trgrpc.c \
                 src/proto/transport/trxhttp.c src/proto/transport/trupgrade.c \
                 src/proto/transport/trws.c src/proto/transport/trpath.c src/proto/tls/roots.c \
                 src/proto/transport/trvenc.c
# Примитивы менеджера плагинов (PLUGINS.md, раздел 3), каждый отдельно от формата плагина:
#   httpc.c    HTTP/1.1-клиент (GET/HEAD, https, переадресации, поток, сроки, ETag) — в STACK_SRC выше;
#   sigverify.c проверка подписи Ed25519 в формате usign/signify (слой scrypto.h);
#   untar.c    распаковка ustar+gzip в каталог с защитой путей и SHA-256 файлов (gz.c, scrypto.h).
# Два последних — каталог src/lib, но им нужна криптобиблиотека, поэтому не в базовом профиле.
PLUGIN_PRIM_SRC := src/lib/sigverify.c src/lib/untar.c
VLESS_MOD_SRC := src/proto/vless/vlmain.c src/proto/vless/vldial.c \
                 src/proto/vless/client.c src/proto/vless/vless_proto.c src/proto/vless/vision.c
EXT_ROUTER_SRC := src/proto/vless/sub.c $(SUBLINK_SRC) $(VLESS_MOD_SRC) $(STACK_SRC) $(TRANSPORT_SRC) $(PLUGIN_PRIM_SRC) \
                  src/proto/xsteer/xsclient.c src/proto/vless/subfetch.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c \
                  src/proto/tls/urltls.c
EXT_SERVER_SRC := src/proto/xsteer/xshub.c
EXT_TGWS_SRC := src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c \
                src/proto/tls/chello.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c $(CRYPTO_SRC)

# PLUGKIT_SRC — сторона плагина в API ядра (src/plugkit): точка входа, {conf}, файл состояния, ключи
# туннеля по подписке. Модели спеки ядра в программах протоколов нет: всё о выходе — в {conf}. Каждая
# программа плагина — таблица подкоманд (PK_PROGRAM в src/modules/main_<id>.c); main даёт PKMAIN_SRC
# (своя программа плагина), а статический бинарник ядра зовёт её сам по имени argv[0] (PK_STATIC_SRC).
PLUGKIT_SRC := src/plugkit/plugkit.c src/plugkit/pkjson.c src/plugkit/pktun.c
PKMAIN_SRC := src/plugkit/pkmain.c
# PLUGINS_EMBED — плагины, вкомпилированные в бинарник телефона вместе с манифестами (PKEMBED_SRC — его
# пишет build/pkembed.sh из plugins/<id>/): реестр ядра видит их и без каталога плагинов (О-13).
PLUGINS_EMBED := vless xsteer obfs
PK_STATIC_SRC := $(PLUGKIT_SRC) src/modules/main_vless.c src/modules/main_xsteer.c src/proto/xsteer/xshook.c $(OBFS_MOD_SRC) src/modules/main_obfs.c

PROFILE_base     := $(CORE_SRC)
# Полный статический профиль (телефон): протоколы vless и xsteer вкомпилированы программами плагинов
# (PK_STATIC_SRC выше, PK_PROGRAM в src/plugkit/plugkit.h): виды их — из манифестов, как у роутера, а программа
# плагина — этот же бинарник под именем <id> (bin/<id> в каталоге плагина — ссылка на него).
PROFILE_extended := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_ROUTER_SRC) $(PK_STATIC_SRC) src/profile/extended.c
PROFILE_server   := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_SERVER_SRC) src/profile/server.c
PROFILE_tgws     := $(CORE_SRC) $(EXT_TGWS_SRC) src/profile/tgws.c
# Телефон: тот же состав, что расширенный роутерный (Android.bp, цель steer), и манифесты вкомпилированных
# плагинов: каталога плагинов на телефоне в 2.1 нет.
PKEMBED_SRC := src/plugkit/pkembed.c
PROFILE_android  := $(PROFILE_extended) $(PKEMBED_SRC)

# ---- РАЗДЕЛЯЕМАЯ СБОРКА РОУТЕРА (шаг 4 выпуска 1.10, docs/architecture.md, «Сборки») ----------
#
# Пакет роутера — не один статический бинарник, а steerd, четыре модуля и две разделяемые
# библиотеки. Списки ниже — то, что линкуется в каждый из этих файлов; статические профили выше
# остаются для телефона (шаг 6), стендов и микропакетов и собирают то же самое одним файлом.
#
#   libsteer.so         LIBSTEER_SRC: модель, платформа, виды, разбор команд, линия событий, слой
#                       криптографии, TLS и REALITY, транспорты, стек TUN — всё, что нужно и
#                       steerd, и модулям. Собирается -fPIC -fvisibility=hidden с version-script
#                       build/libsteer.map (наружу — только нужное), SONAME libsteer.so.<версия>;
#                       ABI между версиями не обещается, модуль той же версии, что движок.
#   libsteer-wolfssl.so наша сборка wolfSSL (build/wolfssl): список файлов — build/wolfssl/
#                       build.sh, не здесь.
#   steerd              PROFILE_steerd = DAEMON_SRC + urltls.c (замер групп по HTTPS — ему нужен
#                       TLS из libsteer; вслед за ним в 1.11 dnsd для DoH/DoT). Поэтому ядро
#                       зависит от обеих библиотек.
#   steer-vless         клиент VLESS: дайлер, слежка за узлом, проверка узла, Vision, разбор
#                       подписки, скачивание подписки, проба TLS. Свой main — modmain.c.
#   steer-xsteer        клиент звезды xsteer: рукопожатие, конфигурация, маршрутизация, поток,
#                       служебные команды (ключ, проверка, ссылка).
#   steer-obfs          помощник обфускатора; сам код obfs.c — в libsteer (его зовёт и xsteer).
#   steer-tgws          мост Telegram; правила перехвата пишет ядро (kinds/tgws.c в libsteer).
#
# modcmd.c входит и в steerd (заглушки команд модулей), и в каждый модуль (настоящие ветки): один
# разбор команд, тот же вывод и код выхода, `steer vless-nodes` для splify2 не меняется.
# Состав двух бинарных половин сверяет tests/buildmatch.sh: в модуле нет failover.c и модели —
# они в libsteer/steerd; маршрут выхода ставит демон по up (шаг 3).
#
# QUIC (шаг 7 выпуска 1.10, docs/architecture.md, «Туннели»): обёртка над ngtcp2 — в libsteer, чтобы
# её взяли и DoQ в dnsd (1.11), и модуль hysteria2 без второй копии библиотеки. Сама ngtcp2 (с патчем
# Brutal) собирается отдельным рецептом (build/ngtcp2/build.sh) в статический архив и линкуется в
# libsteer.so; wolfSSL для неё — та же libsteer-wolfssl.so. Обёртка — два файла:
#   quic.c   сокет, потоки, датаграммы, таймер; видит только заголовки ngtcp2;
#   qcssl.c  единственный, кроме слоя примитивов (CRYPTO_SRC), файл с заголовками wolfSSL.
# Ключи сборки им нужны разные (build/build-libs.sh): ngtcp2 — обоим, wolfSSL — только qcssl.c,
# поэтому списки два. Потребителей у слоя пока нет: в steerd и модули он не идёт. Единственный
# «потребитель» — стенд QUIC_STAND_SRC (клиент замера; tests/libs-test.sh линкует его с
# библиотекой и гоняет против сервера): его неопределённые символы попадают в список экспорта
# (build/libs-exports.sh), поэтому программный интерфейс qc_* торчит из libsteer.so, а код ngtcp2
# и QUIC-часть wolfSSL остаются в обеих библиотеках и собираются, слинковываются и проверяются на
# каждой архитектуре. Без стенда сборщик выбросил бы их как недостижимые. Когда придёт настоящий
# потребитель (DoQ, hysteria2), стенд из списка экспорта уйдёт, а символы останутся его же.
# qcdoq.c — сторона QUIC шва резолвера (src/dnsd/dupq.h): DoQ в dnsd берёт обёртку через него, а не
# заголовком, чтобы статические сборки без QUIC не тянули quic.c по замыканию #include.
QUIC_SRC := src/proto/quic/quic.c src/proto/quic/qcssl.c src/proto/quic/qcdoq.c
QUIC_SSL_SRC := src/proto/quic/qcssl.c
QUIC_STAND_SRC := tests/qcbench.c
# hysteria2 (плагин hysteria2, docs/hysteria2.md): провод и подписка — hy2wire.c, hy2sub.c; соединение
# QUIC в цикле рабочего и потоки клиента поверх него — hy2conn.c; дайлер стека — hy2dial.c; команды и
# слежка — hy2main.c. В статических профилях его нет (телефон отложен).
HY2_MOD_SRC := src/proto/hysteria2/hy2wire.c src/proto/hysteria2/hy2sub.c src/proto/hysteria2/hy2conn.c \
               src/proto/hysteria2/hy2dial.c src/proto/hysteria2/hy2main.c
# Протоколы прокси (плагин proxy, docs/proxy.md): trojan, shadowsocks, socks, http, vmess — пять видов
# `kind: tunnel` одного манифеста и одна программа. По тому же доводу, что hysteria2, — НЕ в
# статических профилях (extended, android): это ответ на вопрос роутера (коннектор sing-box для
# podkop), и в прошивку телефона без потребителя он лёг бы мёртвым весом.
# Дайлеры — по файлу на протокол поверх стека и транспорта (src/tunnel, src/proto/transport):
# pxtrojan.c, pxss.c, pxsocks.c, pxhttp.c, pxvmess.c; узлы — pxsub.c (ссылки, общие поля
# транспорта — sublink.c); общее дайлеров (сокет UDP, проба узла, слежка) — pxdial.c; команды —
# pxmain.c.
PROXY_MOD_SRC := src/proto/proxy/pxwire.c src/proto/proxy/pxsub.c src/proto/proxy/pxdial.c src/proto/proxy/pxtrojan.c \
                 src/proto/proxy/pxss.c src/proto/proxy/pxsocks.c src/proto/proxy/pxhttp.c \
                 src/proto/proxy/pxvmess.c src/proto/proxy/pxmain.c
# WARP (плагин warpbox, docs/warp.md): регистрация, подбор точек и замена для выхода `kind: warp`.
# Вид warp — из манифеста плагина, его хук expand разворачивает выход в группу и членов awg; не в
# статических профилях: телефону — позже, вместе с MASQUE.
# HTTPS — wbhttps.c (TLS 1.3 libsteer) и JSON по пути — wbjson.c живут в libsteer (STACK_SRC): их же зовёт
# проверка страны выхода туннелей (src/tunnel/geo.c); модуль берёт их оттуда. Регистрация — wbreg.c, файл туннеля и
# маски I1 — wbconf.c, пространство сети подбора — wbns.c, эхо-запросы — wbping.c, подбор — wbscan.c,
# сертификат клиента MASQUE и ключ сервера — wbx509.c, туннель MASQUE (QUIC, HTTP/3 CONNECT-IP, TUN) —
# wbmq.c, команды и сторож — wbmain.c.
WARP_MOD_SRC := src/proto/warp/wbreg.c src/proto/warp/wbconf.c \
                src/proto/warp/wbns.c src/proto/warp/wbping.c src/proto/warp/wbscan.c src/proto/warp/wbx509.c \
                src/proto/warp/wbmq.c src/proto/warp/wbmain.c src/proto/warp/wbexpand.c
# Менеджер плагинов: команда `steer plugin …` в steerd (src/pluginmgr/pm.h). Стоит на libsteer: HTTP-клиент
# (httpc.c), подпись (sigverify.c), распаковка (untar.c), хеши (scrypto.c), разбор JSON (ynode.c).
PLUGMGR_SRC := src/pluginmgr/pmutil.c src/pluginmgr/pmver.c src/pluginmgr/pmstate.c src/pluginmgr/pmindex.c \
               src/pluginmgr/pminst.c src/pluginmgr/pmmain.c
STEERD_DYN_SRC := $(DAEMON_SRC) src/proto/tls/urltls.c $(PLUGMGR_SRC)
# Перевод --conf {conf} в прежние --spec/--state-dir (src/modules/plugconf.h) — только у модуля моста
# steer-tgws, пока он не плагин. Протоколы-плагины читают {conf} сами (src/plugkit).
PLUGCONF_SRC := src/modules/plugconf.c
VLESS_MODULE_SRC := $(VLESS_MOD_SRC) src/proto/vless/sub.c src/proto/vless/subfetch.c \
                    src/proto/tls/tlsprobe.c src/modules/main_vless.c
XSTEER_MODULE_SRC := src/proto/xsteer/xsclient.c src/proto/xsteer/xswire.c src/proto/xsteer/xsconf.c \
                     src/proto/xsteer/xslink.c src/proto/xsteer/xsroute.c src/proto/xsteer/xsconn.c \
                     src/proto/xsteer/xsstream.c src/proto/xsteer/xsepoch.c src/proto/xsteer/xshake.c \
                     src/proto/xsteer/xsadmin.c src/proto/xsteer/xshook.c src/modules/main_xsteer.c
OBFS_MODULE_SRC := $(OBFS_MOD_SRC) src/modules/main_obfs.c
TGWS_MODULE_SRC := src/proto/tgws/tgws.c $(MODCMD_SRC) $(PLUGCONF_SRC) src/modules/main_tgws.c
HY2_MODULE_SRC := $(HY2_MOD_SRC) src/modules/main_hysteria2.c
PROXY_MODULE_SRC := $(PROXY_MOD_SRC) src/modules/main_proxy.c
WARP_MODULE_SRC := $(WARP_MOD_SRC) src/modules/main_warpbox.c

PROFILE_steerd     := $(STEERD_DYN_SRC)
PROFILE_mod_tgws   := $(TGWS_MODULE_SRC)

# ---- РАСКЛАДКА 2.1: ЯДРО, БИБЛИОТЕКА-ПЛАГИН net1 И ПРОТОКОЛЫ-ПЛАГИНЫ ------------------------------
#
# Решения владельца (plugin-sdk/docs/steer-abi.md, «Сервисы протоколам»; open.md, О-1): протоколы —
# плагины, обновляются отдельно от ядра; общий для них сетевой стек — один плагин-библиотека `net1`
# с одной libs2p-net.so.1, а не копия в каждом. Ядро держит свою копию TLS/QUIC и wolfSSL: резолвер
# (DoH, DoH3, DoQ), замер групп (urltls.c), менеджер плагинов (httpc.c, wbhttps.c, подпись, untar) и
# коннектор (exports-ext.lst) работают и без единого плагина, а обновление net1 в фоне не должно
# ронять DNS роутера.
#
#   libsteer.so.<версия>  PROFILE_libsteer: модель, виды, разбор команд, линия событий, TLS 1.3,
#                         REALITY, HTTP/2, ECH, корни, HTTP-клиент, слой примитивов, QUIC (+DoQ).
#                         Стека TUN, транспортов и разбора ссылок узлов в ядре больше нет;
#   libs2p-net.so.1       PROFILE_net1: стек TUN, пул узлов, гео, транспорты, разбор ссылок, та же
#                         TLS/REALITY/HTTP/2/QUIC (второй экземпляр тех же исходников) и wolfSSL с
#                         ngtcp2 внутри, скрытые. Наружу — только имена s2p_* (build/net1/
#                         libs2p-net.map, LIBS2P_NET_1): имена исходников переименовывает заголовок,
#                         порождённый из карты (build/build-libs.sh), так что ни один символ net1
#                         не совпадает с libsteer и libsteer-wolfssl в процессе steerd;
#   plugins/<id>/bin/<id> протоколы: код протокола + сторона плагина в API ядра (PLUGKIT_SRC:
#                         {conf}, точка входа, файл состояния) статически + DT_NEEDED libs2p-net.so.1
#                         с RUNPATH $ORIGIN/../../net1/lib. Модели спеки ядра и libsteer в них нет.
#                         obfs стека не берёт и собирается целиком статически.
#
# NET1_BASE_SRC — то немногое из основы, что нужно самому стеку: платформа (пути, устройство TUN,
# каталоги корней), профиль, линия событий, запуск ip, JSON и отказ (err.c). Оно живёт в net1 в ОДНОМ экземпляре
# на процесс помощника и отдаётся наружу (s2p_plat, s2p_evline_emit…): иначе у плагина и у net1 было
# бы по своей платформе, и выбор --platform или каталог состояния расходились бы между ними.
NET1_BASE_SRC := $(PLATFORM_SRC) src/lib/err.c src/lib/jsonr.c src/lib/run.c src/lib/jsonw.c src/lib/evline.c
TUNNEL_SRC := src/tunnel/stack.c src/tunnel/rtx.c src/tunnel/pool.c src/tunnel/geo.c src/tunnel/tun.c
TRANSPORT_ONLY_SRC := src/proto/transport/transport.c src/proto/transport/trdial.c \
                      src/proto/transport/trsec.c src/proto/transport/trgrpc.c \
                      src/proto/transport/trxhttp.c src/proto/transport/trupgrade.c \
                      src/proto/transport/trws.c src/proto/transport/trpath.c src/proto/transport/trvenc.c
# TLS и всё, на чём он стоит, — ДВАЖДЫ: в ядре (для себя) и в net1 (для протоколов). Исходник один.
TLS_CORE_SRC := src/proto/tls/chello.c src/proto/tls/tls13.c src/proto/tls/certverify.c \
                src/proto/tls/reality.c src/proto/tls/h2.c src/proto/tls/ech.c src/proto/tls/roots.c \
                src/proto/tls/httpc.c src/proto/warp/wbhttps.c src/proto/warp/wbjson.c $(CRYPTO_SRC)
NET1_QUIC_SRC := src/proto/quic/quic.c src/proto/quic/qcssl.c
# Свой файл net1: версия ABI и отпечаток раскладки (src/net1/s2pnet.h).
NET1_OWN_SRC := src/net1/s2pnet.c
PROFILE_net1 := $(TUNNEL_SRC) $(TRANSPORT_ONLY_SRC) $(SUBLINK_SRC) $(TLS_CORE_SRC) $(NET1_QUIC_SRC) \
                $(NET1_BASE_SRC) $(NET1_OWN_SRC)
# Ядро 2.1. Множество — прежний LIBSTEER_SRC без стека, транспортов и sublink.c (tests/buildmatch.sh).
PROFILE_libsteer := $(LIBSTEER_BASE_SRC) \
                    $(TLS_CORE_SRC) src/proto/tls/plughttp.c $(PLUGIN_PRIM_SRC) $(QUIC_SRC)
# Проверка ABI net1 при запуске помощника (src/net1/s2pcheck.c) — в каждом плагине на net1.
NET1_CHECK_SRC := src/net1/s2pcheck.c
PROFILE_plug_vless     := $(VLESS_MODULE_SRC) $(PLUGKIT_SRC) $(PKMAIN_SRC) src/tools/hwid.c src/lib/gz.c src/lib/puff.c $(NET1_CHECK_SRC)
PROFILE_plug_hysteria2 := $(HY2_MODULE_SRC) $(PLUGKIT_SRC) $(PKMAIN_SRC) $(NET1_CHECK_SRC)
PROFILE_plug_proxy     := $(PROXY_MODULE_SRC) $(PLUGKIT_SRC) $(PKMAIN_SRC) $(NET1_CHECK_SRC)
PROFILE_plug_xsteer    := $(XSTEER_MODULE_SRC) $(PLUGKIT_SRC) $(PKMAIN_SRC) src/proto/obfs/obfs.c src/lib/ctlcall.c $(NET1_CHECK_SRC)
# warpbox: устройства подбора — слой устройства AmneziaWG без модели спеки (src/kinds/awgdev.c, общий с видом
# awg ядра) и его запросы ядру по netlink (nlbuf).
PROFILE_plug_warpbox   := $(WARP_MODULE_SRC) $(PLUGKIT_SRC) $(PKMAIN_SRC) src/kinds/awgdev.c $(NET1_CHECK_SRC)
# obfs: стек ему не нужен — статическая программа, основа net1 вкомпилирована своя.
PROFILE_plug_obfs      := $(OBFS_MODULE_SRC) src/plugkit/plugkit.c src/plugkit/pkjson.c $(PKMAIN_SRC) src/proto/obfs/obfs.c \
                          $(NET1_BASE_SRC)
# Плагины протоколов на net1 и без него (build/build-libs.sh, build.sh, tests/buildmatch.sh).
PLUGINS_NET1 := vless hysteria2 proxy xsteer warpbox
PLUGINS_STATIC := obfs

# steer-box-connector (sing-box для podkop и forkop) живёт в своём репозитории
# (github.com/splify2/steer-box-connector) и собирается build/ext-build.sh; нужные ему символы
# libsteer — в build/exports-ext.lst.

# Два бинарника на пакет (docs/architecture.md, раздел 4а, «Бинарники»): профиль — это движок
# steerd (демон, компилятор, apply, помощники, инструменты; ссылка steer-tools на него же), а
# `steer` — маленький клиент сокета, один на все профили: в нём нет ни спеки, ни компилятора,
# только разбор команды, протокол v1 и exec движка. Платформа — ради путей по умолчанию (спека,
# сокет, каталог состояния): клиент выбирает их так же, как движок (src/platform).
CLIENT_SRC := src/client/main.c src/lib/ctlcall.c $(PLATFORM_SRC)

# Ключей профилей нет (шапка файла): всё, чем профили различаются, — их списки выше.
PROFILE_DEFS_base     :=
PROFILE_DEFS_extended :=
PROFILE_DEFS_server   :=
PROFILE_DEFS_tgws     :=
# Телефон — не профиль, а платформа (src/platform): код обеих платформ есть в любой сборке, а
# ключ задаёт только умолчание выбора при запуске — прошивка ведёт себя как телефон, где бы ни
# запустилась. --platform и STEER_PLATFORM его переопределяют.
PROFILE_DEFS_android  := -DSTEER_DEFAULT_PLATFORM=android
