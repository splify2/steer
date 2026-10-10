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
CORE_DIRS := src/lib src/model src/platform src/compile src/daemon src/kinds src/cli src/dnsd src/tools src/proto/obfs
# Файлы профилей (src/profile, profile.h): profile.c — умолчания, в каждой сборке (с платформой,
# PLATFORM_SRC); остальные — по одному на профиль, у base своего файла нет. Отдельно от ядра и
# от расширенной части, потому что файл профиля не входит ни в одну сборку, кроме своей.
PROFILE_DIRS := src/profile
EXT_DIRS  := src/tunnel src/proto/tls src/proto/transport src/proto/vless src/proto/xsteer src/proto/tgws src/proto/quic src/proto/hysteria2 src/proto/proxy src/modules
# Клиент сокета `steer` (src/client) — отдельный бинарник, не профиль движка: CLIENT_SRC ниже.
CLIENT_DIRS := src/client
# Сторонний код (src/third_party) — не слой движка: файлы в нём не правятся (см. UPSTREAM в
# каталоге библиотеки), а собираются вместе с ядром. libyaml подключает свой заголовок как
# <yaml.h>, поэтому её каталог — в -I у всех; обёртка движка над ней называется ynode.h, а не
# yaml.h, ровно чтобы имена заголовков оставались уникальными (tests/buildmatch.sh).
THIRD_DIRS := src/third_party/libyaml
INC_DIRS  := $(CORE_DIRS) $(PROFILE_DIRS) $(EXT_DIRS) $(CLIENT_DIRS) $(THIRD_DIRS)
# Каталоги, которых нет в сборке телефона (Android.bp их не подключает: hysteria2 и протоколы прокси
# в профиль android не входят, телефон не собирает ни QUIC-клиента, ни модули steer-hysteria2 и
# steer-proxy). tests/buildmatch.sh сверяет
# Android.bp с INC_DIRS за вычетом этого списка.
PHONE_SKIP_DIRS := src/proto/hysteria2 src/proto/proxy
# Определения, которых ждёт сторонний код: yaml_private.h подключает config.h (номер версии
# libyaml) только при HAVE_CONFIG_H. Ключ идёт во ВСЕ пути сборки движка — Makefile, build.sh,
# build/build-ext*.sh (там он читается отсюда), в Android.bp — флагом библиотеки libsteer_yaml;
# забытый в одном из них, он роняет компиляцию api.c, а не тихо меняет поведение, и всё равно
# сверяется стендом tests/buildmatch.sh. Движку ключ ничего не значит.
THIRD_DEFS := -DHAVE_CONFIG_H

# Модель спеки — то, во что нарезан прежний src/model/spec.c (docs/architecture.md, «Слои и
# каталоги»): JSON-ридер, сам разбор спеки, реестр меток/таблиц, ход перебора узлов подписки и
# раскладка правил старого ядра. Порядок — тот, в котором они шли в неразрезанном файле.
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
# живость обфускатора, zapret — живость обработчика очереди) и nftcompat (раскладка по ядру), а
# виды идут со всякой моделью. Поэтому здесь, а не в CORE_SRC.
#
# lib/ir.c — дерево набора правил (lib/ir.h) — здесь по той же причине: его строят не только
# компилятор (src/compile), но и виды (kind_ops.emit у zapret и tgws), а о спеке и видах дерево
# не знает ничего (только libc), то есть это кирпич lib, а не часть компилятора.
#
# lib/module.c — какая команда чья и установлен ли модуль (шаг 4 выпуска 1.10, src/lib/module.h):
# его зовут реестр видов (kinds/kind.c, kinds/tgws.c) и справка (cli/cli.c), а они идут со всякой
# моделью, поэтому файл здесь же.
MODEL_SRC := $(PLATFORM_SRC) src/lib/module.c src/lib/err.c src/lib/jsonr.c src/lib/tmpfile.c src/lib/ir.c src/model/parse.c src/model/v1.c \
             src/model/check.c src/model/v2.c src/model/v2print.c src/model/registry.c \
             src/model/probe.c src/compile/nftcompat.c src/lib/puff.c src/model/srs.c src/model/srsplan.c \
             src/lib/nftdump.c src/lib/rtnl.c src/lib/procscan.c $(YAML_SRC)

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
            src/dnsd/doq.c src/dnsd/doh2.c src/dnsd/doh3.c

# Виды выхода (src/kinds, docs/architecture.md, раздел 2, правило 1): вид — это файл, и какие виды
# есть в сборке, решает профиль. Реестр (kind.c) ссылается на записи видов слабо, поэтому вид,
# файла которого в профиле нет, у движка есть — одной строкой отказа («kind vless требует пакет
# steer-extended»), без #ifdef в разборе. Базовые виды — в каждом профиле (через CORE_SRC); виды,
# которым нужны TLS и клиенты туннелей, — только в полном пакете (PROFILE_extended и android).
# tgws — базовый: правила перехвата пишет любой движок, мост живёт своей программой (полный
# пакет, микропакет stgws). Состав проверяет tests/buildmatch.sh.
KINDS_BASE_SRC := src/kinds/kind.c src/kinds/direct.c src/kinds/group.c src/kinds/grpurl.c src/kinds/interface.c \
                  src/kinds/zapret.c src/kinds/tgws.c src/kinds/awg.c
KINDS_EXT_SRC  := src/kinds/vless.c src/kinds/xsteer.c

# src/daemon/steer.c нарезан на модули (docs/architecture.md, раздел 2, «Слои и каталоги»):
# компиляция спеки в правила — в src/compile, остальное ядро — в src/daemon, порядок ниже
# такой же, как был в steer.c (lib/run.c раньше всех — на него ссылаются и compile, и daemon).
#
# С ВЫПУСКА 1.10 (ШАГ 4) ЯДРО РАЗРЕЗАНО НА ТРИ СПИСКА, а CORE_SRC — их сумма:
#   DAEMON_SRC        то, что остаётся в бинарнике steerd, когда он линкуется с libsteer.so:
#                     компилятор правил, apply, сторож, супервизор, демон, резолвер, точка входа;
#   LIBSTEER_BASE_SRC то, что нужно и демону, и модулям: модель спеки (с libyaml), платформа,
#                     реестр и файлы видов, разбор командной строки, линия событий, обфускатор,
#                     идентификатор роутера. Уходит в libsteer.so (LIBSTEER_SRC ниже);
#   OBFS_MOD_SRC      точка входа обфускатора (`steer obfs`, `steer obfs-server`) — в пакете
#                     модуль steer-obfs, а в статических сборках часть ядра, как была.
# Статические сборки (телефон, стенды, мини-сборка tgws, хаб) по-прежнему берут CORE_SRC целиком:
# один бинарник без разделяемых библиотек, и снимок генератора, стенды и телефон проверяют ровно
# ту логику, что едет в пакет; отличается только компоновка. Что список DAEMON + LIBSTEER_BASE +
# OBFS_MOD даёт то же множество файлов, что прежний CORE_SRC, сверяет tests/buildmatch.sh.
# cli/modcmd.c — команды модулей (заглушки steerd и настоящие ветки модулей) и main модуля;
# входит и в steerd, и в каждый бинарник модуля.
MODCMD_SRC := src/cli/modcmd.c
DAEMON_SRC := src/compile/groups.c src/compile/generate.c src/compile/balance.c src/compile/print.c src/compile/legacy.c src/daemon/fwcheck.c \
              src/daemon/apply.c src/daemon/status.c src/daemon/nftquery.c src/daemon/diag.c \
              src/daemon/explain.c src/daemon/helpers.c src/daemon/supervise.c src/daemon/supd.c src/daemon/watch.c src/daemon/main.c \
              $(DNSD_SRC) src/daemon/failover.c src/tools/aggregate.c \
              src/tools/srsread.c src/daemon/ctl.c \
              src/daemon/conns.c src/daemon/loop.c src/daemon/state.c src/daemon/watchd.c src/daemon/recon.c src/daemon/rulewd.c \
              src/daemon/foprobe.c src/daemon/gaiw.c src/daemon/urltest.c src/daemon/fogroup.c src/lib/nftvmap.c \
              src/daemon/folat.c $(MODCMD_SRC)
LIBSTEER_BASE_SRC := src/lib/run.c src/lib/jsonw.c src/lib/evline.c $(MODEL_SRC) src/proto/obfs/obfs.c \
                     src/cli/cli.c src/tools/hwid.c src/lib/ctlcall.c $(KINDS_BASE_SRC)
OBFS_MOD_SRC := src/proto/obfs/obfsmain.c
CORE_SRC := $(DAEMON_SRC) $(LIBSTEER_BASE_SRC) $(OBFS_MOD_SRC)

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
                 src/proto/xsteer/xsadmin.c $(CRYPTO_SRC)
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
STACK_SRC := src/tunnel/stack.c src/tunnel/rtx.c src/tunnel/pool.c
TRANSPORT_SRC := src/proto/transport/transport.c src/proto/transport/trdial.c \
                 src/proto/transport/trsec.c src/proto/tls/ech.c src/proto/transport/trgrpc.c \
                 src/proto/transport/trxhttp.c src/proto/transport/trupgrade.c \
                 src/proto/transport/trws.c src/proto/transport/trpath.c src/proto/tls/roots.c \
                 src/proto/transport/trvenc.c
VLESS_MOD_SRC := src/proto/vless/vlmain.c src/proto/vless/vldial.c \
                 src/proto/vless/client.c src/proto/vless/vless_proto.c src/proto/vless/vision.c
EXT_ROUTER_SRC := src/proto/vless/sub.c $(SUBLINK_SRC) $(VLESS_MOD_SRC) $(STACK_SRC) $(TRANSPORT_SRC) \
                  src/proto/xsteer/xsclient.c src/proto/vless/subfetch.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c \
                  src/proto/tls/urltls.c
EXT_SERVER_SRC := src/proto/xsteer/xshub.c
EXT_TGWS_SRC := src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c \
                src/proto/tls/chello.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c $(CRYPTO_SRC)

PROFILE_base     := $(CORE_SRC)
PROFILE_extended := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_ROUTER_SRC) $(KINDS_EXT_SRC) src/profile/extended.c
PROFILE_server   := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_SERVER_SRC) src/profile/server.c
PROFILE_tgws     := $(CORE_SRC) $(EXT_TGWS_SRC) src/profile/tgws.c
# Телефон: тот же состав, что расширенный роутерный (Android.bp, цель steer).
PROFILE_android  := $(PROFILE_extended)

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
# hysteria2 (модуль steer-hysteria2, docs/hysteria2.md). Запись вида — в libsteer, как у vless и
# xsteer, но НЕ в KINDS_EXT_SRC: тот список входит в статические профили (extended, android), а
# hysteria2 в них нет — телефон отложен, и вид там отвечает записью отказа (kind.c). Модуль — свой
# бинарник на libsteer.so: провод и подписка — hy2wire.c, hy2sub.c; соединение QUIC и мультиплексор
# потоков — hy2conn.c; дайлер стека — hy2dial.c; команды и слежка — hy2main.c.
KINDS_HY2_SRC := src/kinds/hysteria2.c
HY2_MOD_SRC := src/proto/hysteria2/hy2wire.c src/proto/hysteria2/hy2sub.c src/proto/hysteria2/hy2conn.c \
               src/proto/hysteria2/hy2dial.c src/proto/hysteria2/hy2main.c
# Протоколы прокси (модуль steer-proxy, docs/proxy.md): trojan, shadowsocks, socks, http, vmess —
# пять видов `kind: tunnel` одной записью вида (kinds/proxy.c) и один бинарник. По тому же доводу,
# что hysteria2, — НЕ в статических профилях (extended, android): телефон и стенды несут модули
# в себе, а этот модуль — ответ на вопрос роутера (коннектор sing-box для podkop), и в прошивку
# телефона без потребителя он лёг бы мёртвым весом; вид там отвечает записью отказа (kind.c).
# Дайлеры — по файлу на протокол поверх стека и транспорта (src/tunnel, src/proto/transport):
# pxtrojan.c, pxss.c, pxsocks.c, pxhttp.c, pxvmess.c; узлы — pxsub.c (ссылки, общие поля
# транспорта — sublink.c); общее дайлеров (сокет UDP, проба узла, слежка) — pxdial.c; команды —
# pxmain.c.
KINDS_PROXY_SRC := src/kinds/proxy.c
PROXY_MOD_SRC := src/proto/proxy/pxwire.c src/proto/proxy/pxsub.c src/proto/proxy/pxdial.c src/proto/proxy/pxtrojan.c \
                 src/proto/proxy/pxss.c src/proto/proxy/pxsocks.c src/proto/proxy/pxhttp.c \
                 src/proto/proxy/pxvmess.c src/proto/proxy/pxmain.c
LIBSTEER_SRC := $(LIBSTEER_BASE_SRC) $(KINDS_EXT_SRC) $(KINDS_HY2_SRC) $(KINDS_PROXY_SRC) $(SUBLINK_SRC) \
                $(STACK_SRC) $(TRANSPORT_SRC) \
                src/tunnel/tun.c src/proto/tls/chello.c src/proto/tls/tls13.c \
                src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/h2.c $(CRYPTO_SRC) \
                $(QUIC_SRC)
STEERD_DYN_SRC := $(DAEMON_SRC) src/proto/tls/urltls.c
VLESS_MODULE_SRC := $(VLESS_MOD_SRC) src/proto/vless/sub.c src/proto/vless/subfetch.c \
                    src/proto/tls/tlsprobe.c $(MODCMD_SRC) src/modules/main_vless.c
XSTEER_MODULE_SRC := src/proto/xsteer/xsclient.c src/proto/xsteer/xswire.c src/proto/xsteer/xsconf.c \
                     src/proto/xsteer/xslink.c src/proto/xsteer/xsroute.c src/proto/xsteer/xsconn.c \
                     src/proto/xsteer/xsstream.c src/proto/xsteer/xsepoch.c src/proto/xsteer/xshake.c \
                     src/proto/xsteer/xsadmin.c $(MODCMD_SRC) src/modules/main_xsteer.c
OBFS_MODULE_SRC := $(OBFS_MOD_SRC) $(MODCMD_SRC) src/modules/main_obfs.c
TGWS_MODULE_SRC := src/proto/tgws/tgws.c $(MODCMD_SRC) src/modules/main_tgws.c
HY2_MODULE_SRC := $(HY2_MOD_SRC) $(MODCMD_SRC) src/modules/main_hysteria2.c
PROXY_MODULE_SRC := $(PROXY_MOD_SRC) $(MODCMD_SRC) src/modules/main_proxy.c

PROFILE_libsteer   := $(LIBSTEER_SRC)
PROFILE_steerd     := $(STEERD_DYN_SRC)
PROFILE_mod_vless  := $(VLESS_MODULE_SRC)
PROFILE_mod_xsteer := $(XSTEER_MODULE_SRC)
PROFILE_mod_obfs   := $(OBFS_MODULE_SRC)
PROFILE_mod_tgws   := $(TGWS_MODULE_SRC)
PROFILE_mod_hysteria2 := $(HY2_MODULE_SRC)
PROFILE_mod_proxy  := $(PROXY_MODULE_SRC)
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
