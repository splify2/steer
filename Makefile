# Native build for development and tests. Router builds are static musl via the
# same zig cross-toolchain splify already uses for its 29 architectures — added
# when there is something to ship, not before.
CFLAGS ?= -O2 -Wall -Wextra
BUILD  := build

# Версия — из того же файла, что читает build.sh: `steer --version` на собранном руками
# движке должен называть то же число, что окажется в имени пакета.
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
# Ревизия: чем эта сборка отличается от релиза с тем же номером версии. Версия между
# релизами не меняется, поэтому движок из релиза и движок из main через два коммита после
# него назывались одним числом — на стенде два разных бинарника отчитывались как
# «0.9.6-r1» (R-045/I-054). `--dirty` здесь, а не в build.sh: локальная сборка идёт по
# рабочему дереву с правками, релизная — по коммиту (см. комментарий там).
# Пустое значение, когда git недоступен: тогда define не даётся вовсе и работает честное
# умолчание из src/cli/cli.c, а не подставленное число.
REV     := $(shell git describe --tags --always --dirty 2>/dev/null)
DEFS    := -DSTEER_VERSION='"$(VERSION)"' $(if $(REV),-DSTEER_REV='"$(REV)"',)

# Списки исходников — из build/sources.mk, единственного места, где они перечислены
# (его же читают build.sh и build/build-ext.sh). Заголовки ядра — зависимостью целиком:
# список файлов сборки они не меняют, а пересобрать движок при их правке нужно всегда.
include build/sources.mk
CORE_HDR := $(wildcard $(addsuffix /*.h,$(CORE_DIRS) $(PROFILE_DIRS) $(THIRD_DIRS)))
# Точки входа модулей (src/modules, шаг 4 выпуска 1.10) — тоже расширенная часть: их main живёт
# только в разделяемой раскладке, и ни один статический профиль их не компилирует.
EXT_ALL_SRC := $(sort $(XS_COMMON_SRC) $(EXT_ROUTER_SRC) $(EXT_SERVER_SRC) $(EXT_TGWS_SRC) $(HY2_MOD_SRC) $(KINDS_HY2_SRC) $(PROXY_MOD_SRC) $(KINDS_PROXY_SRC) $(wildcard src/modules/*.c))
# Модель для стендов, которые компонуют её отдельным списком: разбор спрашивает вид у реестра, поэтому
# вместе с моделью идут виды (src/kinds). Без awg.c: он тянет run_quiet из lib/run.c, а стенды
# подменяют run_quiet своим — awg.c берут только те, кому нужен сам вид awg (specmatch, awgmatch).
# Вид, которого в списке нет, у реестра остаётся записью отказа (см. src/kinds/kind.c).
# Дерево ruleset (src/lib/ir.c), которое kind_ops.emit видов zapret и tgws строит напрямую, уже
# в MODEL_SRC (build/sources.mk): без него компоновка падала бы на ir_rule/ir_x и соседях, даже
# если стенд emit не зовёт вовсе, — символ нужен компоновщику.
MODEL_KINDS := $(MODEL_SRC) $(filter-out src/kinds/awg.c,$(KINDS_BASE_SRC))
# -I на все каталоги слоёв — через override, чтобы `make CFLAGS=...` его не терял. Там же
# THIRD_DEFS — определения стороннего кода (libyaml, см. build/sources.mk).
#
# Сторонние файлы собираются ТЕМИ ЖЕ флагами и той же командой, что движок, без отдельных
# правил с приглушёнными предупреждениями: libyaml 0.2.5 чиста под -Wall -Wextra и у gcc 13, и
# у clang из NDK с глобальными флагами Soong и -Werror (проверено при переносе). Появится шум у
# новой версии компилятора — глушить его здесь флагами для LIBYAML_SRC, а не правкой upstream.
override CFLAGS += $(addprefix -I,$(INC_DIRS)) $(THIRD_DEFS)

.PHONY: all test clean ext-syntax ext-test libs-test libs-exports snapshot-record print-inc ndk-check
all: $(BUILD)/steerd $(BUILD)/steer

# Два бинарника, как в пакете (docs/architecture.md, раздел 4а, «Бинарники»): build/steerd — весь
# движок, build/steer — клиент сокета. Стенды зовут ./build/steer, как звали всегда: команды,
# которые не к демону (а без демона — любые), клиент отдаёт движку execv'ом, и steerd он берёт
# рядом с собой. Так каждый стенд заодно проверяет и путь «клиент → движок» с тем же выводом
# и кодом (снимок генератора — 118 вызовов apply --dry-run через клиент), а не только движок.
$(BUILD)/steerd: $(CORE_SRC) $(CORE_HDR) VERSION
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -o $@ $(CORE_SRC)

# Клиенту без steerd рядом делать нечего: зависимость порядка, чтобы `make build/steer` давал
# рабочую пару.
$(BUILD)/steer: $(CLIENT_SRC) src/platform/platform.h | $(BUILD)/steerd
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC)

# Демон базовой сборки с видами vless и xsteer — только для стенда tests/supdmatch.sh: сторож демона
# берёт здоровье выходов, чьё устройство создаёт наш процесс, у супервизора (--watch вместе с
# --supervise), а такие виды есть только в расширенной сборке, которая собирается docker'ом с
# wolfSSL. Помощников стенд подменяет швом STEER_SUPERVISE_EXE, поэтому клиенты туннелей (и
# криптобиблиотека) демону не нужны: хватает файлов видов — реестр видов (kind.c) ссылается на них слабо.
# Не пакет и не профиль: в build/sources.mk его нет нарочно.
$(BUILD)/steer-xk: $(CORE_SRC) $(KINDS_EXT_SRC) $(KINDS_HY2_SRC) $(KINDS_PROXY_SRC) $(CORE_HDR) VERSION
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -o $@ $(CORE_SRC) $(KINDS_EXT_SRC) $(KINDS_HY2_SRC) $(KINDS_PROXY_SRC)

# Сборка под Android — тот же движок и те же исходники, у которого только умолчание выбора
# платформы при запуске — телефон (-DSTEER_DEFAULT_PLATFORM=android, src/platform/platform.c):
# своё поле метки (биты 22-27, в 0-21 пишет netd), свои каталоги (/data/misc/steer) и
# приоритет ip rule ниже лестницы netd. Здесь она собирается хостовым компилятором ради стенда
# androidmatch и снимка; тот же вывод обязан давать и обычный build/steer с STEER_PLATFORM=android
# или --platform android — это сверяет tests/platmatch.sh. Настоящая сборка под телефон — не
# здесь (Android.bp).
$(BUILD)/steer-android: $(CORE_SRC) $(CORE_HDR) VERSION
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -DSTEER_DEFAULT_PLATFORM=android -o $@ $(CORE_SRC)

test: all ext-syntax $(BUILD)/steer-android $(BUILD)/tgwssim $(BUILD)/dnsmatch $(BUILD)/dupmatch $(BUILD)/dupconnmatch $(BUILD)/dupfragmatch $(BUILD)/specmatch $(BUILD)/specmatch-ext $(BUILD)/xswirematch $(BUILD)/xsconnmatch $(BUILD)/xsstreammatch $(BUILD)/tungromatch $(BUILD)/tunnelmatch $(BUILD)/tunnamematch $(BUILD)/xsconfmatch $(BUILD)/xslinkmatch $(BUILD)/xsroutematch $(BUILD)/chellomatch $(BUILD)/failovermatch $(BUILD)/helpersmatch $(BUILD)/rrkeepmatch $(BUILD)/runmatch $(BUILD)/irmatch $(BUILD)/irmatch-android $(BUILD)/dcmatch $(BUILD)/msgsplitmatch $(BUILD)/warmmatch $(BUILD)/upmatch $(BUILD)/tgwsfailmatch $(BUILD)/h2match $(BUILD)/grpcmatch $(BUILD)/xhupmatch $(BUILD)/wsmatch $(BUILD)/tls13readmatch $(BUILD)/pqfallbackmatch $(BUILD)/submatch $(BUILD)/subfetchmatch $(BUILD)/hy2match $(BUILD)/pxsubmatch $(BUILD)/pxdialmatch $(BUILD)/fwmatch $(BUILD)/obfsmatch $(BUILD)/visionmatch $(BUILD)/tlsprobematch $(BUILD)/diagsim $(BUILD)/hwidsum $(BUILD)/awgmatch $(BUILD)/awgmatch-android $(BUILD)/evmatch $(BUILD)/srsunit $(BUILD)/modelmatch $(BUILD)/steer-xk $(BUILD)/yamlmatch $(BUILD)/urltestmatch $(BUILD)/nftvmap-tool $(BUILD)/b3match $(BUILD)/subpq
	@sh tests/run.sh
	@sh tests/gen.sh
	@sh tests/snapshot.sh
	@sh tests/v2match.sh
	@sh tests/tgwsmark.sh
	@BUILD=$(BUILD) sh tests/noforward.sh
	@BUILD=$(BUILD) sh tests/boxenv.sh
	@sh tests/climatch.sh
	@sh tests/dnsproxy.sh
	@sh tests/dnsgroups.sh
	@sh tests/dnsnft.sh
	@sh tests/applynft.sh
	@sh tests/applynft-legacy.sh
	@sh tests/v6ns.sh
	@sh tests/v6host.sh
	@sh tests/ingressns.sh
	@sh tests/androidmatch.sh
	@sh tests/platmatch.sh
	@sh tests/supervisematch.sh
	@sh tests/ctlmatch.sh
	@sh tests/reroutematch.sh
	@sh tests/supdmatch.sh
	@sh tests/modhello.sh
	@sh tests/reconmatch.sh
	@sh tests/swapmatch.sh
	@sh tests/netrestart.sh
	@sh tests/daemonmatch.sh
	@sh tests/diagmatch.sh
	@sh tests/statusmatch.sh
	@sh tests/buildmatch.sh
	@sh tests/srsmatch.sh
	@$(BUILD)/srsunit
	@$(BUILD)/modelmatch
	@sh tests/srsgen.sh
	@sh tests/srsnft.sh
	@sh tests/vpsfetch.sh
	@$(BUILD)/dnsmatch
	@$(BUILD)/dupmatch
	@$(BUILD)/dupconnmatch
	@$(BUILD)/dupfragmatch
	@$(BUILD)/specmatch
	@$(BUILD)/specmatch-ext
	@$(BUILD)/failovermatch
	@$(BUILD)/helpersmatch
	@$(BUILD)/rrkeepmatch
	@$(BUILD)/runmatch
	@$(BUILD)/dcmatch
	@$(BUILD)/msgsplitmatch
	@$(BUILD)/warmmatch
	@$(BUILD)/upmatch
	@$(BUILD)/tgwsfailmatch
	@$(BUILD)/h2match
	@$(BUILD)/grpcmatch
	@$(BUILD)/xhupmatch
	@$(BUILD)/wsmatch
	@$(BUILD)/tls13readmatch
	@$(BUILD)/pqfallbackmatch
	@$(BUILD)/b3match
	@$(BUILD)/subpq
	@$(BUILD)/submatch
	@$(BUILD)/subfetchmatch
	@$(BUILD)/hy2match
	@$(BUILD)/pxsubmatch
	@$(BUILD)/pxdialmatch
	@$(BUILD)/fwmatch
	@$(BUILD)/obfsmatch
	@$(BUILD)/visionmatch
	@$(BUILD)/tlsprobematch
	@$(BUILD)/xswirematch
	@$(BUILD)/xsconnmatch
	@$(BUILD)/xsstreammatch
	@$(BUILD)/tungromatch
	@$(BUILD)/tunnelmatch
	@$(BUILD)/tunnamematch
	@$(BUILD)/xsconfmatch
	@$(BUILD)/xslinkmatch
	@$(BUILD)/xsroutematch
	@$(BUILD)/chellomatch
	@sh tests/hwidmatch.sh
	@$(BUILD)/awgmatch
	@$(BUILD)/awgmatch-android
	@sh tests/awgns.sh
	@$(BUILD)/irmatch
	@$(BUILD)/irmatch-android
	@$(BUILD)/evmatch
	@$(BUILD)/yamlmatch
	@$(BUILD)/urltestmatch
	@sh tests/nftvmapmatch.sh
	@sh tests/groupsmatch.sh

# Перезапись снимка генератора (tests/snapshot.sh). Только когда ruleset меняется
# намеренно, и в том же коммите, что и изменение: иначе снимок перестаёт что-либо сторожить.
# Флаги -I для ручной сборки стенда (так их зовут шапки tests/*.c): cc $(make -s print-inc) ...
print-inc:
	@echo $(addprefix -I,$(INC_DIRS))

snapshot-record: all $(BUILD)/steer-android $(BUILD)/tgwssim
	@sh tests/snapshot.sh record

# Сборка под Android тем же NDK, что прошивка (Android.bp, bionic): ни стенды на хосте, ни
# QEMU-роутер (musl) не видят, чего нет в bionic, — так в origin/main однажды ушёл fopencookie.
# Гонять перед пушем. Скрипт живёт в дереве работы над Android-портом; нет его на машине — цель
# пропускается, а не падает.
#
# wolfSSL для телефона. В дереве прошивки она будет своим репозиторием (external/der-wolfssl, форк
# в der-exp — шаг 6 выпуска 1.10) с Android.bp из build/wolfssl/Android.bp.
# Пока форка нет, цель собирает ровно его: исходники того же выпуска, что у роутера (скачивание со
# сверкой суммы — build/wolfssl/fetch.sh, NDK_WOLFSSL переопределяет каталог готовых исходников),
# и тот Android.bp рядом с ними. Так проверяется то, что потом соберёт Soong, а не заменитель.
NDK_BPBUILD ?= /root/der-exp/android_vendor_der/tools/ndk-check/bpbuild.py
NDK_WOLFSSL ?= $(BUILD)/ndk/wolfssl-src
ndk-check:
	@if [ ! -f "$(NDK_BPBUILD)" ]; then echo "ndk-check: нет $(NDK_BPBUILD) — пропуск"; exit 0; fi; \
	if [ ! -f "$(NDK_WOLFSSL)/wolfssl/wolfcrypt/settings.h" ] && ! sh build/wolfssl/fetch.sh "$(NDK_WOLFSSL)"; then \
		echo "ndk-check: нет исходников wolfSSL (не скачались, см. выше) — пропуск"; exit 0; fi; \
	cp build/wolfssl/Android.bp "$(NDK_WOLFSSL)/Android.bp"; \
	for a in aarch64 x86_64; do \
		python3 "$(NDK_BPBUILD)" --static --arch $$a --out $(BUILD)/ndk/$$a . "$(NDK_WOLFSSL)" \
			-- steerd steer > $(BUILD)/ndk-$$a.log 2>&1 || \
			{ echo "ndk-check: $$a не собирается:"; grep -m5 'error:' $(BUILD)/ndk-$$a.log; exit 1; }; \
		echo "ndk-check: $$a — steerd и steer собираются"; \
	done

# Мини-сборка микропакета tgws на хосте — для стенда tgwsmark: ядро движка с файлом профиля
# tgws (src/profile/tgws.c), мост заменён заглушкой (tests/tgws-stub.c), потому что настоящий
# тянет TLS и docker. Проверяется не мост, а ruleset рядом с полным движком: свой бит метки,
# свой порт, свой ряд таблиц, чужой реестр.
$(BUILD)/tgwssim: $(CORE_SRC) $(CORE_HDR) src/profile/tgws.c tests/tgws-stub.c VERSION
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -o $@ $(CORE_SRC) src/profile/tgws.c tests/tgws-stub.c

# Движок, собранный как расширенный (виды и файл профиля extended), но без самой расширенной
# части: нужен стенду diagmatch, потому что спеку с `kind: vless` базовая сборка отвергает
# реестром видов, а проверять диагностику интереснее всего именно на VLESS-выходе. Подкоманды
# расширенной сборки заменены заглушками — см. tests/vless-stub.c.
$(BUILD)/diagsim: $(CORE_SRC) $(KINDS_EXT_SRC) $(CORE_HDR) src/profile/extended.c tests/vless-stub.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -o $@ $(CORE_SRC) $(KINDS_EXT_SRC) src/profile/extended.c tests/vless-stub.c

# SHA-256 движка против sha256sum оболочки. Отдельная цель, потому что стенду нужен ПОЛНЫЙ
# хеш: в самом идентификаторе он обрезан до двадцати знаков, и расхождение в старших байтах
# такой проверкой не поймать. Ни сети, ни криптобиблиотеки — файл вложенный и самодостаточный.
$(BUILD)/hwidsum: tests/hwidsum.c src/tools/hwid.c src/tools/hwid.h src/lib/jsonw.c src/lib/jsonw.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/hwidsum.c src/tools/hwid.c src/lib/jsonw.c $(PLATFORM_SRC)

# Синтаксическая проверка расширенного движка (R-014/I-024). Полная сборка расширенной части идёт
# только в build.sh через docker с wolfSSL, поэтому локальный make test оставался зелёным,
# даже когда ext не компилировался вовсе — так в main пролез 654e4e6. -fsyntax-only ловит
# ровно тот класс ошибок (несуществующее имя, снесённое объявление). Заглушки заголовков
# библиотеки больше не нужны: протоколы видят только src/lib/scrypto.h, где её типов нет.
# Сам scrypto.c — единственный файл, который включает заголовки wolfSSL, — отсюда исключён:
# в `make test` библиотеки нет по построению, а компилирует его ext-test вместе с ней.
# Компоновку по-прежнему проверяет build.sh.
ext-syntax:
	@for f in $(filter-out $(CRYPTO_SRC),$(EXT_ALL_SRC)); do \
		$(CC) $(CFLAGS) -fsyntax-only $$f || exit 1; \
	done
	@echo "ext-syntax: расширенная часть компилируется"

# Стенды расширенной части, которым нужна НАСТОЯЩАЯ криптобиблиотека: векторы слоя примитивов
# (scryptomatch), xsloop (рукопожатие целиком), spokematch (освобождение ключей под ASan),
# hubmatch (арифметика записи в хабе, I-070) и остальные — список в tests/ext-test.sh. В `make
# test` они не входят — там библиотеки нет по построению (R-014, см. ext-syntax), а роутерная
# сборка ext идёт только docker'ом (build.sh), поэтому первые до запуска 42 не прогонялись ни
# разу и дали I-066/I-067 первым же прогоном. Цель закрывает разрыв (R-058): wolfSSL собирается
# из исходников той же версии и с теми же опциями, что у роутера (build/wolfssl), исходники —
# STEER_WOLFSSL или скачивание со сверкой суммы; не нашлись — ГРОМКИЙ пропуск, а не падение.
# Вся логика — в tests/ext-test.sh, как у прочих *.sh-стендов.
ext-test:
	@BUILD=$(BUILD) CC="$(CC)" sh tests/ext-test.sh

# Разделяемая раскладка роутера (шаг 4 выпуска 1.10: libsteer.so, libsteer-wolfssl.so, steerd и
# модули) на хосте — тем же build/build-libs.sh, что кладёт файлы в пакеты, и с теми же исходниками
# wolfSSL, что ext-test. В `make test` не входит по той же причине, что ext-test (нужна
# библиотека); ext-test зовёт этот стенд последним шагом. Вся логика — в tests/libs-test.sh.
libs-test: all $(BUILD)/steer-android $(BUILD)/tgwssim
	@BUILD=$(BUILD) CC="$(CC)" sh tests/libs-test.sh

# Переписать списки экспорта libsteer.so и libsteer-wolfssl.so по коду (build/libs-exports.sh).
# Нужен, когда модуль или steerd начал брать из libsteer новый символ: сборка раскладки скажет
# неопределённой ссылкой, `sh build/libs-exports.sh check` (его зовёт libs-test) — словами.
libs-exports:
	@BUILD=$(BUILD) CC="$(CC)" sh build/libs-exports.sh gen

# Подбор доменного правила проверяется отдельной программой, а не через движок: подбор
# сам — публичная функция резолвера (ruleset_match), а дотянуться до него иначе значило бы
# добавить в движок подкоманду ради теста. Резолвер (DNSD_SRC) линкуется отдельными
# объектами, как и модель (MODEL_SRC) — см. tests/dnsmatch.c.
$(BUILD)/dnsmatch: tests/dnsmatch.c $(DNSD_SRC) src/lib/sindex.h src/lib/nftnl.h src/lib/ctnl.h \
                   src/lib/jsonw.c src/dnsd/dnsd_int.h src/dnsd/tabfmt.h $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dnsmatch.c $(DNSD_SRC) src/lib/jsonw.c $(MODEL_KINDS)

# Апстримы резолвера без сети (разбор адреса, спека, таблица, кэш): tests/dupmatch.c.
$(BUILD)/dupmatch: tests/dupmatch.c $(DNSD_SRC) src/dnsd/dup.h src/dnsd/dnsd_int.h src/dnsd/tabfmt.h \
                   src/lib/jsonw.c $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dupmatch.c $(DNSD_SRC) src/lib/jsonw.c $(MODEL_KINDS) -lpthread

# Соединения апстримов в цикле событий (DoT, DoH/1.1, DoH/2, TCP) без сети: стенд линкуется с dup.c
# (объекты цикла — dupint.h) и подменяет слой TLS очередью записей — tests/dupconnmatch.c.
$(BUILD)/dupconnmatch: tests/dupconnmatch.c tests/unit.h $(DNSD_SRC) src/dnsd/dup.h src/dnsd/dupint.h src/dnsd/dnsd_int.h \
                       src/dnsd/doh2.h src/lib/jsonw.c $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dupconnmatch.c $(DNSD_SRC) src/lib/jsonw.c $(MODEL_KINDS) -lpthread

# ClientHello DoT/DoH двумя записями TLS (`fragment: true`): разрез, заголовки, пауза, ключ спеки и
# седьмое поле таблицы без сети — tests/dupfragmatch.c.
$(BUILD)/dupfragmatch: tests/dupfragmatch.c tests/unit.h $(DNSD_SRC) src/dnsd/dup.h src/dnsd/dupint.h src/dnsd/tabfmt.h \
                       src/lib/jsonw.c $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dupfragmatch.c $(DNSD_SRC) src/lib/jsonw.c $(MODEL_KINDS) -lpthread

# Парсер конфигурации проверяется отдельной программой по той же причине: load_spec
# читает файл и зовёт die()/exit(2) на неверной спеке — перехватить это через подкоманду
# движка нельзя. load_spec ошибку возвращает (правило 5, docs/architecture.md, раздел 2), и
# стенд линкуется с парсером отдельным объектом (MODEL_SRC) — см. tests/specmatch.c.
# Таблица дата-центров Telegram — см. пояснение в самом стенде. Криптографию моста (гамму
# AES-CTR через src/lib/scrypto.h) стенд подменяет своими функциями sc_aesctr_*: настоящей
# библиотеки в `make test` нет по построению (см. ext-syntax).
$(BUILD)/dcmatch: tests/dcmatch.c src/proto/tgws/tgws.c src/lib/jsonw.c src/lib/evline.c src/lib/scrypto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dcmatch.c src/lib/jsonw.c src/lib/evline.c $(PLATFORM_SRC)

$(BUILD)/msgsplitmatch: tests/msgsplitmatch.c src/proto/tgws/tgws.c src/lib/jsonw.c src/lib/evline.c src/lib/scrypto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/msgsplitmatch.c src/lib/jsonw.c src/lib/evline.c $(PLATFORM_SRC)

# Запас поднятых соединений — там же и по той же причине: warm_* статические.
$(BUILD)/warmmatch: tests/warmmatch.c src/proto/tgws/tgws.c src/lib/jsonw.c src/lib/evline.c src/lib/scrypto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/warmmatch.c src/lib/jsonw.c src/lib/evline.c $(PLATFORM_SRC)

# Исходы пробы браузерным рукопожатием и то, как она их называет (I-272). Там же и по той же
# причине: bind_local и hello12_build статические. Срок пробы подменён секундой — с шестью
# настоящими прогон стоял бы полминуты на ожиданиях, а стенд смотрит не на длительность
# срока, а на то, чем он кончается.
$(BUILD)/tlsprobematch: tests/tlsprobematch.c src/proto/tls/tlsprobe.c src/proto/tls/reality.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DPROBE_TIMEOUT_S=1 -o $@ tests/tlsprobematch.c

# Освобождение соединения наверх: чем обозначено «дескриптора нет» (I-204). Там же и по той
# же причине: up_drop статическая.
$(BUILD)/upmatch: tests/upmatch.c src/proto/tgws/tgws.c src/lib/jsonw.c src/lib/evline.c src/lib/scrypto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/upmatch.c src/lib/jsonw.c src/lib/evline.c $(PLATFORM_SRC)

# Пути отказа моста, которых прогон настоящего бинаря не достаёт: длинная строка списка
# запасных доменов, отказ источника случайности, отказ рукопожатия после разворота ключа
# (I-155, I-196, I-197), срок затишья сессии через веб-сокет и причины её конца. Там же и по
# той же причине: alt_init, ws_upgrade, tls_start и pump статические.
$(BUILD)/tgwsfailmatch: tests/tgwsfailmatch.c src/proto/tgws/tgws.c src/lib/jsonw.c src/lib/evline.c src/lib/scrypto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/tgwsfailmatch.c src/lib/jsonw.c src/lib/evline.c $(PLATFORM_SRC)

$(BUILD)/specmatch: tests/specmatch.c $(MODEL_KINDS) src/kinds/awg.c src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/specmatch.c $(MODEL_KINDS) src/kinds/awg.c

# Тот же исходник, собранный КАК РАСШИРЕННЫЙ. Нужен потому, что виды выходов vless и
# xsteer в базовой сборке отвергаются реестром видов (и обязаны отвергаться — см.
# src/kinds/kind.c), а значит их положительные случаи в build/specmatch недостижимы: до
# появления этого бинарника kind=vless не проверялся здесь ни одной строкой, только комментарием.
# Один исходник, два бинарника, ветки стенда под его собственным ключом -DSPECMATCH_EXT — так
# «базовая отказывает» и «расширенная разбирает» проверяются одним файлом. Отказ базовой сборки
# даёт реестр видов, а не #ifdef в разборе: здесь виды расширенной части (KINDS_EXT_SRC)
# скомпонованы, в build/specmatch — нет.
$(BUILD)/specmatch-ext: tests/specmatch.c $(MODEL_KINDS) src/kinds/awg.c $(KINDS_EXT_SRC) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DSPECMATCH_EXT -o $@ tests/specmatch.c $(MODEL_KINDS) src/kinds/awg.c $(KINDS_EXT_SRC)

# Поддельный TCP проверяется в памяти: сборка и разбор сегмента, контрольные суммы и
# арифметика номеров — чистые функции без сокетов, поэтому стенд не требует ни сети, ни
# прав root. Циклы клиента и сервера сюда не входят намеренно — см. заголовок файла.
$(BUILD)/obfsmatch: tests/obfsmatch.c src/proto/obfs/obfs.c src/proto/obfs/obfs.h src/lib/jsonw.c src/lib/evline.c $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/obfsmatch.c src/lib/jsonw.c src/lib/evline.c $(MODEL_KINDS)

# Выход kind=awg без ядра: разбор файла awg-quick, спека, побайтная сборка сообщений netlink.
# Модель (MODEL_SRC) линкуется отдельным объектом, src/kinds/awg.c — по-прежнему #include
# (вне пяти каталогов правила юнит-стендов, docs/architecture.md, раздел 4) — см. шапку
# tests/awgmatch.c.
# Дважды — роутерная и Android-сборка: у них разная метка сокета туннеля без via (0 против
# STEER_SELF_MARK). С ядром — tests/awgns.sh.
$(BUILD)/awgmatch: tests/awgmatch.c src/kinds/awg.c src/kinds/awg.h src/lib/nlbuf.h $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/awgmatch.c $(MODEL_KINDS)

$(BUILD)/awgmatch-android: tests/awgmatch.c src/kinds/awg.c src/kinds/awg.h src/lib/nlbuf.h $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DSTEER_DEFAULT_PLATFORM=android -o $@ tests/awgmatch.c $(MODEL_KINDS)

# Виды — объектами (без awg.c и без парсера: стенд подменяет load_spec своей спекой). С
# src/lib/ir.c — тем же доводом, что у MODEL_KINDS: zapret_emit/tgws_emit зовут ir_* на
# компоновке, даже когда стенд их не вызывает (модели стенд не компонует, поэтому отдельно). И с
# src/lib/module.c: kinds/tgws.c спрашивает, установлен ли модуль моста (шаг 4 выпуска 1.10).
FAILOVERMATCH_KINDS := $(filter-out src/kinds/awg.c,$(KINDS_BASE_SRC)) $(KINDS_EXT_SRC) src/lib/ir.c src/lib/module.c

# Модель v2 и перевод спеки v1 (src/model/v1.c, src/kinds/group.c): каналы → правила, списки,
# клиенты; пул devices → группа — модулями модели, без движка: см. шапку tests/modelmatch.c. С
# awg.c — как у specmatch: перевод отвечает и за отказ пула у kind=awg.
$(BUILD)/modelmatch: tests/modelmatch.c tests/unit.h $(MODEL_KINDS) src/kinds/awg.c $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/modelmatch.c $(MODEL_KINDS) src/kinds/awg.c

# Читатель наборов sing-box (src/model/srs.c) и раскладка канала с ними (srsplan.c) — модулями
# модели, без движка: см. шапку tests/srsunit.c.
$(BUILD)/srsunit: tests/srsunit.c tests/unit.h $(MODEL_KINDS) $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/srsunit.c $(MODEL_KINDS)

# Дерево набора правил (src/lib/ir.h): генератор и раскладка старого ядра проверяются
# запросами к дереву, а не текстом — см. шапку tests/irmatch.c. Модули компилятора линкуются
# с моделью отдельными объектами (само дерево приходит с моделью, MODEL_SRC). Дважды — роутер
# и телефон (цепочки на output).
COMPILE_SRC := $(filter-out $(MODEL_SRC),$(filter src/compile/%,$(CORE_SRC)))
$(BUILD)/irmatch: tests/irmatch.c tests/unit.h $(COMPILE_SRC) $(MODEL_KINDS) $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/irmatch.c $(COMPILE_SRC) $(MODEL_KINDS)

$(BUILD)/irmatch-android: tests/irmatch.c tests/unit.h $(COMPILE_SRC) $(MODEL_KINDS) $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DSTEER_DEFAULT_PLATFORM=android -o $@ tests/irmatch.c $(COMPILE_SRC) $(MODEL_KINDS)

# Проход сторожа — автомат на цикле событий: с ним компонуются цикл (loop.c), ожидания
# (foprobe.c), рабочий поток имён (gaiw.c) и rtnetlink (rtnl.c). Всё, что из них полезло бы в
# ядро или в сеть, стенд подменяет швами failover_int.h.
FAILOVERMATCH_SRC := src/daemon/failover.c src/daemon/loop.c src/daemon/foprobe.c src/daemon/gaiw.c src/lib/rtnl.c \
                     src/lib/nftdump.c src/lib/procscan.c src/daemon/fogroup.c src/daemon/urltest.c src/lib/nftvmap.c \
                     src/daemon/folat.c
$(BUILD)/failovermatch: tests/failovermatch.c $(FAILOVERMATCH_SRC) src/daemon/daemon.h src/daemon/fogroup.h \
                        src/daemon/failover_int.h src/daemon/fostate.h src/daemon/foprobe.h src/daemon/gaiw.h \
                        src/daemon/loop.h src/lib/rtnl.h src/model/spec.h src/lib/err.c $(FAILOVERMATCH_KINDS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/failovermatch.c $(FAILOVERMATCH_SRC) src/lib/err.c $(FAILOVERMATCH_KINDS) $(PLATFORM_SRC) -lpthread

# Пауза перезапуска помощника (helpers_exited) — без процессов и ожидания, tests/helpersmatch.c.
$(BUILD)/helpersmatch: tests/helpersmatch.c src/daemon/helpers.c src/daemon/helpers.h $(MODEL_KINDS) src/model/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/helpersmatch.c src/daemon/helpers.c $(MODEL_KINDS)

# Выбор записей conntrack по интервалам наборов (src/daemon/conns.c, rr_keep) — conns.c целиком.
$(BUILD)/rrkeepmatch: tests/rrkeepmatch.c src/daemon/conns.c src/daemon/rrkeep.h src/lib/ctnl.c src/lib/jsonw.c src/lib/nftdump.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/rrkeepmatch.c src/daemon/conns.c src/lib/ctnl.c src/lib/jsonw.c src/lib/nftdump.c $(PLATFORM_SRC) -lpthread

# run()/run_quiet() — run.c целиком.
$(BUILD)/runmatch: tests/runmatch.c src/lib/run.c src/lib/run.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/runmatch.c src/lib/run.c -lpthread

# Замер urltest (src/daemon/urltest.c): свой цикл и ответчики на 127.0.0.1 — см. шапку стенда.
$(BUILD)/urltestmatch: tests/urltestmatch.c src/daemon/urltest.c src/daemon/urltest.h src/kinds/grpurl.c \
                       src/kinds/grpurl.h src/daemon/loop.c src/daemon/gaiw.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/urltestmatch.c src/daemon/urltest.c src/kinds/grpurl.c src/daemon/loop.c \
		src/daemon/gaiw.c -lpthread

# Карта вердиктов balance по netlink (src/lib/nftvmap.c) — инструмент стенда tests/nftvmapmatch.sh.
$(BUILD)/nftvmap-tool: tests/nftvmap-tool.c src/lib/nftvmap.c src/lib/nftvmap.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/nftvmap-tool.c src/lib/nftvmap.c

# Зависимость выхода от чужого firewall: fw_check судит о конфигурации по тексту дампа
# nft, и проверить эвристику можно только примерами. Стенд включает исходник движка и
# подменяет popen на чтение из памяти — см. tests/fwmatch.c.
$(BUILD)/fwmatch: tests/fwmatch.c $(CORE_SRC) $(CORE_HDR)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/fwmatch.c \
		$(filter-out src/daemon/main.c,$(CORE_SRC))

# Управление потоком HTTP/2 проверяется в памяти: h2.c общается с сетью только через
# struct h2_io, поэтому стенд подменяет его целиком. tls13.h, который h2.c тянет ради одной
# константы, криптобиблиотеки не требует: её типов в нём нет (src/lib/scrypto.h).
$(BUILD)/h2match: tests/h2match.c src/proto/tls/h2.c src/proto/tls/h2.h src/proto/tls/tls13.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/h2match.c

# Отказ сервера на выгрузку xhttp (stream-up, packet-up) обязан дойти до отправки (I-219):
# транспорт xhttp (trxhttp.c) включается целиком (up_drain статическая), остальные ярусы
# транспорта и h2.c настоящие и компонуются отдельно, TLS и Reality подменены — связь
# выгрузки голая, на сокетной паре. Подробности — в шапке стенда.
XHUPMATCH_SRC = src/proto/tls/h2.c src/proto/transport/transport.c src/proto/transport/trsec.c \
                src/proto/transport/trdial.c src/proto/transport/trgrpc.c src/proto/tls/roots.c \
                src/proto/transport/trws.c src/proto/transport/trupgrade.c src/proto/transport/trpath.c
$(BUILD)/xhupmatch: tests/xhupmatch.c src/proto/transport/trxhttp.c src/proto/transport/transport.h \
                    src/proto/tls/h2.h $(XHUPMATCH_SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xhupmatch.c tests/trvenc-stub.c \
		$(XHUPMATCH_SRC) $(PLATFORM_SRC) -lpthread

# Конец потока grpc от сервера (issue 39): данные, отданные вместе с концевыми HEADERS и RST_STREAM одной
# записью, не теряются, а конец виден через transport_has_data. Тот же приём, что у xhupmatch: транспорт
# и h2.c настоящие и компонуются объектами (а не include .c: храповик tests/buildmatch.sh), связь голая на сокетной
# паре, TLS и Reality заглушены.
$(BUILD)/grpcmatch: tests/grpcmatch.c src/proto/transport/trgrpc.c src/proto/transport/transport.h \
                    src/proto/tls/h2.h $(XHUPMATCH_SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/grpcmatch.c tests/trvenc-stub.c \
		$(XHUPMATCH_SRC) src/proto/transport/trxhttp.c $(PLATFORM_SRC) -lpthread

# Транспорты ws и httpupgrade (trws.c, trupgrade.c, trpath.c; шаг 5 выпуска 1.10): кадры WebSocket
# в памяти, запрос Upgrade байт в байт против перехвата Xray, путь против net/url Go, ответ 101 и
# отказы, остаток за ответом — на настоящем сокете с security=none и сервером-стендом в потоке.
# Все ярусы транспорта компонуются настоящими, отдельными объектами (без #include .c), TLS и
# Reality подменены заглушками в самом стенде. Поверх tls и reality с настоящей библиотекой —
# vlessmatch в ext-test.
WSMATCH_SRC = src/proto/transport/trws.c src/proto/transport/trupgrade.c src/proto/transport/trpath.c \
              src/proto/transport/transport.c src/proto/transport/trsec.c src/proto/transport/trdial.c \
              src/proto/transport/trgrpc.c src/proto/transport/trxhttp.c src/proto/tls/h2.c \
              src/proto/tls/roots.c
# BLAKE3 против Go (lukechampine.com/blake3, как у Xray): src/lib/blake3.h самодостаточен, библиотеки нет.
$(BUILD)/b3match: tests/b3match.c src/lib/blake3.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/b3match.c

$(BUILD)/wsmatch: tests/wsmatch.c tests/trvenc-stub.c src/proto/transport/transport.h src/proto/transport/trpath.h \
                  src/proto/tls/h2.h $(WSMATCH_SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/wsmatch.c tests/trvenc-stub.c $(WSMATCH_SRC) $(PLATFORM_SRC) -lpthread

# Чтение потока TLS не ждёт и не спрашивает poll (tls13.c, rbuf_fill). Стенд линкует настоящий tls13.c,
# а не заглушку, как прочие транспортные стенды; криптографию он не зовёт — служебные записи пропускаются без
# расшифровки, — и её ссылки оставлены неразрешёнными, чтобы не тянуть шифры ради стенда чтения.
$(BUILD)/tls13readmatch: tests/tls13readmatch.c tests/unit.h src/proto/tls/tls13.c src/proto/tls/tls13.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc/lib -Isrc/proto/tls -o $@ tests/tls13readmatch.c src/proto/tls/tls13.c \
	      -Wl,--unresolved-symbols=ignore-all -ldl

# Запасной путь при потере длинного ClientHello (tr_link_open): TLS и Reality — заглушки стенда, трогается
# только выбор Hello; tr_dial подменён самим стендом.
$(BUILD)/pqfallbackmatch: tests/pqfallbackmatch.c src/proto/transport/trsec.c src/proto/transport/transport.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/pqfallbackmatch.c src/proto/transport/trsec.c $(PLATFORM_SRC) -lpthread

# Разбор подписки — единственное место, куда в движок попадает чужой текст из интернета.
# Ни сети, ни криптобиблиотеки он не требует, поэтому стенд включает исходник напрямую и входит
# в обычный make test, в отличие от остальной расширенной части (см. ext-syntax).
# Разбор потока Vision — вторая точка, куда в движок попадают недоверенные байты от
# сервера. Ни сети, ни криптобиблиотеки он не требует, поэтому входит в обычный make test, как и
# разбор подписки; остальная расширенная часть доходит только до ext-syntax.
$(BUILD)/visionmatch: tests/visionmatch.c src/proto/vless/vision.c src/proto/vless/vision.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/visionmatch.c src/proto/vless/vision.c

# vless_proto.c — в предпосылках и в стенде: разбор подписки решает, ПРИГОДЕН ли
# идентификатор, а превращает его в 16 байт vless_proto.c, и правило у них одно (правило
# Xray по длине строки). Без этой строки правка вывода UUID не пересобирала стенд, то есть
# зелёный прогон ничего не значил бы. Библиотек файл не тянет — криптобиблиотеки здесь нет
# по построению (см. ext-syntax).
#
# trpath.c — отдельным объектом: путь ws и httpupgrade подписка отбраковывает тем же правилом, по
# которому транспорт собирает запрос (src/proto/transport/trpath.h), а сам файл — чистые строки.
$(BUILD)/submatch: tests/submatch.c src/proto/vless/sub.c src/proto/vless/sublink.c src/proto/vless/sublink.h \
                  src/model/nodesel.h \
                  src/proto/vless/vless.h src/proto/transport/vencp.h \
                  src/proto/vless/vless_proto.c src/proto/vless/vless_proto.h \
                  src/proto/transport/trpath.c src/proto/transport/trpath.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/submatch.c src/proto/vless/sublink.c src/proto/transport/trpath.c

# Постквантовые поля подписки (encryption, pqv / mldsa65Verify): tests/subpq.c, образцы значений Xray-core
# 26.9.9 — tests/sub-pq-samples.h. Библиотеки нет; sub.c линкуется объектом, а не включается (предел на
# стенды с #include .c из src — buildmatch).
$(BUILD)/subpq: tests/subpq.c tests/sub-pq-samples.h src/proto/vless/sub.c src/proto/vless/sublink.c src/proto/vless/vless.h \
                src/proto/transport/vencp.h src/proto/vless/vless_proto.c src/proto/transport/trpath.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests -o $@ tests/subpq.c src/proto/vless/sub.c src/proto/vless/sublink.c src/proto/vless/vless_proto.c \
		src/proto/transport/trpath.c

# Скачивание и обработка подписки. Стенд включает исходник и подставляет две вещи: свой
# run_quiet и поддельный curl в PATH (SHA-256 идентификатора устройства — свой, в hwid.c).
# Поэтому ни сети, ни криптобиблиотеки, ни docker он не требует и входит в обычный make test —
# при том что до переноса вся эта работа жила в оболочке объекта rpcd и не проверялась ничем.
$(BUILD)/subfetchmatch: tests/subfetchmatch.c src/proto/vless/subfetch.c src/proto/vless/subfetch.h \
                  src/tools/hwid.c src/tools/hwid.h src/lib/jsonw.c src/lib/jsonw.h \
                  src/proto/vless/sub.c src/proto/vless/sublink.c src/proto/vless/vless.h src/proto/vless/vless_proto.c src/proto/vless/vless_proto.h \
                  src/proto/transport/trpath.c src/proto/transport/trpath.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/subfetchmatch.c src/lib/jsonw.c src/proto/vless/sublink.c src/proto/transport/trpath.c $(PLATFORM_SRC)

# Провод hysteria2 и узлы (src/proto/hysteria2/hy2wire.c, hy2sub.c): целые QUIC, запрос
# авторизации QPACK и разбор ответа, TCPRequest/Response, UDPMessage, Salamander и BLAKE2b на
# векторах — ни сети, ни QUIC, ни криптобиблиотеки, поэтому входит в обычный make test.
$(BUILD)/hy2match: tests/hy2match.c src/proto/hysteria2/hy2wire.c src/proto/hysteria2/hy2wire.h \
                   src/proto/hysteria2/hy2sub.c src/proto/hysteria2/hy2.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/hy2match.c src/proto/hysteria2/hy2wire.c src/proto/hysteria2/hy2sub.c

# Разбор ссылок и подписки прокси (src/proto/proxy/pxsub.c) — без сети и криптографии, как submatch.
# sublink.c, sub.c, vless_proto.c и trpath.c — те же общие части, что у разбора vless.
$(BUILD)/pxsubmatch: tests/pxsubmatch.c src/proto/proxy/pxsub.c src/proto/proxy/proxy.h src/proto/proxy/pxwire.h \
                   src/proto/vless/sublink.c src/proto/vless/sub.c src/proto/vless/vless_proto.c src/proto/transport/trpath.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests -o $@ tests/pxsubmatch.c src/proto/proxy/pxsub.c src/proto/vless/sublink.c \
		src/proto/vless/sub.c src/proto/vless/vless_proto.c src/proto/transport/trpath.c

# Дайлеры прокси (src/proto/proxy: trojan, http) через таблицы dialer_ops — транспорт и хеш подменены
# заглушками в стенде, поэтому без сети и криптобиблиотеки.
$(BUILD)/pxdialmatch: tests/pxdialmatch.c src/proto/proxy/pxtrojan.c src/proto/proxy/pxhttp.c src/proto/proxy/pxvmess.c src/proto/proxy/pxss.c \
                    src/proto/proxy/proxy.h src/proto/proxy/pxdial.h src/proto/proxy/pxwire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests -o $@ tests/pxdialmatch.c src/proto/proxy/pxtrojan.c src/proto/proxy/pxhttp.c src/proto/proxy/pxvmess.c src/proto/proxy/pxss.c

# Арифметика провода xsteer: заголовок записи, вывод nonce, окно приёма, пределы
# соединения. Всё, что она считает, ломается МОЛЧА — пакет отбрасывается стеком той
# стороны, или не расшифровывается, или отвергается как повтор, и ни одного сообщения об
# этом нет. Ни сети, ни криптобиблиотеки стенд не требует (xswire.c намеренно без неё),
# поэтому он входит в обычный make test, как submatch и visionmatch.
$(BUILD)/xswirematch: tests/xswirematch.c src/proto/xsteer/xswire.c src/proto/xsteer/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xswirematch.c

# Стенд поддельного соединения: порог мёртвого пути и учёт своей незанятости. Входит в обычный
# make test по той же причине, что xswirematch: ни сети, ни криптобиблиотеки — время приходит аргументом,
# а сокета у соединения в стенде нет вовсе.
$(BUILD)/xsconnmatch: tests/xsconnmatch.c src/proto/xsteer/xsconn.c src/proto/xsteer/xsconn.h src/proto/obfs/obfs.c src/proto/obfs/obfs.h src/lib/jsonw.c src/lib/evline.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsconnmatch.c src/proto/obfs/obfs.c src/lib/jsonw.c src/lib/evline.c $(MODEL_KINDS)

# Рамка записей по настоящему потоку TCP: границы записей, смещения (они же nonce) и досылка
# недописанного хвоста. Стенд входит в обычный make test по той же причине, что xswirematch:
# xsstream.c не требует ни криптобиблиотеки, ни сети — обстановка делается из socketpair. Проверять это
# на живом туннеле пришлось бы гигабайтом трафика, а ломается всё здесь молча.
$(BUILD)/xsstreammatch: tests/xsstreammatch.c src/proto/xsteer/xsstream.c src/proto/xsteer/xsstream.h src/proto/xsteer/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsstreammatch.c

# Склейка соседних сегментов в одну запись в устройство: что склеивается, что нет и какими
# байтами уезжает. В make test входит потому, что tun.c не требует ни криптобиблиотеки, ни сети, а
# обстановка делается из socketpair датаграммами — по одной на writev, поэтому видно и число
# записей, и их содержимое. Ошибка здесь либо портит поток клиента (склеили лишнее), либо тихо
# отключает выигрыш (не склеили ничего) — второе тут и случилось на живом прогоне.
$(BUILD)/tungromatch: tests/tungromatch.c src/tunnel/tun.c src/tunnel/tun.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/tungromatch.c $(PLATFORM_SRC)

# Разбор пакетов туннеля VLESS на подменённом транспорте (I-320, I-321, I-322): стек
# (stack.c) включается целиком, дайлер VLESS (vldial.c) настоящий и компонуется отдельно, а
# соединение с узлом (vless_connect и transport_*) подменено, поэтому криптобиблиотека не нужна —
# её типов в заголовках нет (src/lib/scrypto.h), как у ext-syntax. Подробности — в шапке стенда.
# Второй половиной стенд включает пул узлов выхода (src/tunnel/pool.c) с поддельным протоколом под
# ним: обрыв связи с узлом — RST клиенту, порог молчания на сокете, замена мёртвого узла без
# перезапуска, раздача by. Молчание узла в сети — tests/run-silence.sh (root).
TUNNELMATCH_SRC = src/tunnel/tun.c src/tunnel/rtx.c src/proto/vless/vless_proto.c src/proto/vless/vision.c \
                  src/proto/vless/vldial.c \
                  src/lib/jsonw.c src/lib/evline.c $(MODEL_KINDS) $(KINDS_EXT_SRC)
$(BUILD)/tunnelmatch: tests/tunnelmatch.c src/tunnel/stack.c src/tunnel/pool.c src/tunnel/pool.h src/tunnel/dialer.h $(TUNNELMATCH_SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/tunnelmatch.c \
		$(TUNNELMATCH_SRC) -lpthread -ldl

# Имя устройства: движок работает ровно с тем именем, о котором просил, — иначе отказ. Ядро
# усекает имя длиннее 15 символов молча, и разошедшееся имя не видно ниоткуда: очереди
# открыты, туннель жив, а адрес и зона firewall уезжают на несуществующее устройство (I-107).
# Здесь нужно НАСТОЯЩЕЕ устройство (TUNSETIFF — единственный источник выбранного имени),
# поэтому стенд требует CAP_NET_ADMIN и без него пропускается вслух с кодом 0. В make test он
# всё равно входит: стенд, который надо позвать руками, не запускается никогда.
$(BUILD)/tunnamematch: tests/tunnamematch.c src/tunnel/tun.c src/tunnel/tun.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/tunnamematch.c src/tunnel/tun.c $(PLATFORM_SRC)

# Разбор конфигурации xsteer — единственное место, куда в движок попадает текст, который
# человек написал руками, поэтому разбор строгий, а стенд перечисляет каждый отказ.
# Отдельно проверяется, что приватный ключ не попадает в вывод: обещание держится на том,
# что печатающая функция не имеет к нему доступа по построению. Без криптобиблиотеки — это же
# требуется для build/diagsim, который линкует этот файл ради проверок diag.
$(BUILD)/xsconfmatch: tests/xsconfmatch.c src/proto/xsteer/xsconf.c src/proto/xsteer/xsconf.h src/proto/xsteer/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsconfmatch.c

# Ссылка xs:// — второе представление той же настройки, и оно ПЕРЕДАЁТСЯ между людьми и между
# половинами звезды. Расхождение здесь не падает: ссылка «принялась», а туннель молчит, потому что
# маска оказалась другой или keepalive включился сам. Поэтому стенд держит те же векторы, что
# xsteer/conf/link_cross_test.go на стороне Go, и сверяет печать ПОБАЙТОВО.
$(BUILD)/xslinkmatch: tests/xslinkmatch.c src/proto/xsteer/xslink.c src/proto/xsteer/xslink.h \
                  src/proto/xsteer/xsconf.c src/proto/xsteer/xsconf.h src/proto/xsteer/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xslinkmatch.c

# Куда отдать пакет. Ошибка здесь не видна снаружи: канал работает, счётчик растёт, а
# пакеты приходят не тому пиру. Три утверждения, без которых звезда небезопасна, стоят
# именно тут — самое длинное совпадение, «нет пира — отбросить» (а не «отдать первому»,
# что было бы утечкой между спицами) и запрет отправлять от чужого имени.
$(BUILD)/xsroutematch: tests/xsroutematch.c src/proto/xsteer/xsroute.c src/proto/xsteer/xsroute.h src/proto/xsteer/xsconf.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsroutematch.c

# Разбор ClientHello — граница доверия хаба: это первый код, который смотрит на байты от
# кого угодно из интернета, и ошибка здесь означает чтение за буфером по длине, которой
# доверились. Разбирается НАСТОЯЩИЙ Hello из заморозки (tests/chello-frozen.h), поэтому
# криптобиблиотека не нужна. Байтовую неизменность самого сборщика проверяет tests/hellofreeze.c,
# которому библиотека нужна и который поэтому идёт в make ext-test.
$(BUILD)/chellomatch: tests/chellomatch.c tests/chello-frozen.h src/proto/tls/chello.c src/proto/tls/chello.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/chellomatch.c

# Формат событий помощников (src/lib/evline.h): запись в трубу, разбор обратно, выключенность
# без STEER_EVENT_FD, неблокирующая потеря на полной трубе, экранирование why. Каждый сценарий —
# отдельный дочерний процесс (см. шапку tests/evmatch.c): fork()/waitpid() из libc, без -lpthread.
$(BUILD)/evmatch: tests/evmatch.c src/lib/evline.c src/lib/evline.h src/lib/jsonw.c src/lib/jsonw.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/evmatch.c src/lib/evline.c src/lib/jsonw.c

# Дерево YAML (src/lib/ynode.c) поверх libyaml: модуль и библиотека — отдельными объектами, со
# стендом tests/yamlmatch.c (пример спеки v2, JSON спек v1, отказы и пределы). err.c — ради
# err_set; больше модулю ничего не нужно.
$(BUILD)/yamlmatch: tests/yamlmatch.c tests/unit.h $(YAML_SRC) src/lib/ynode.h src/lib/err.c src/lib/err.h \
                    $(wildcard src/third_party/libyaml/*.h)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/yamlmatch.c $(YAML_SRC) src/lib/err.c

# НЕ rm -rf $(BUILD): в build/ живут отслеживаемые Dockerfile, build-ext.sh и
# лабораторные исходники, без которых ./build.sh из свежего клона не работает —
# .gitignore об этом прямо предупреждает, а clean их сносил (I-023). Удаляются
# только артефакты: то, что здесь же и собирается, плюс упаковка из build.sh.
clean:
	rm -rf $(BUILD)/steer $(BUILD)/steerd $(BUILD)/steer-* $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/specmatch-ext \
	       $(BUILD)/failovermatch $(BUILD)/helpersmatch $(BUILD)/rrkeepmatch $(BUILD)/runmatch $(BUILD)/dcmatch $(BUILD)/msgsplitmatch $(BUILD)/warmmatch $(BUILD)/upmatch $(BUILD)/tgwsfailmatch $(BUILD)/h2match $(BUILD)/grpcmatch $(BUILD)/xhupmatch $(BUILD)/wsmatch $(BUILD)/tls13readmatch $(BUILD)/pqfallbackmatch $(BUILD)/submatch $(BUILD)/subfetchmatch $(BUILD)/hy2match $(BUILD)/pxsubmatch $(BUILD)/pxdialmatch $(BUILD)/fwmatch $(BUILD)/obfsmatch $(BUILD)/b3match $(BUILD)/subpq \
	       $(BUILD)/visionmatch $(BUILD)/xswirematch $(BUILD)/xsconnmatch $(BUILD)/xsstreammatch $(BUILD)/xsepochmatch $(BUILD)/tungromatch $(BUILD)/tunnamematch $(BUILD)/xsconfmatch $(BUILD)/xslinkmatch $(BUILD)/xsroutematch $(BUILD)/chellomatch $(BUILD)/hellofreeze $(BUILD)/xsloop $(BUILD)/xsbench \
	       $(BUILD)/steer-hub $(BUILD)/steer-ext \
	       $(BUILD)/diagsim $(BUILD)/evmatch $(BUILD)/srsunit $(BUILD)/yamlmatch $(BUILD)/wolfssl-host \
	       $(BUILD)/scryptomatch $(BUILD)/vlessmatch $(BUILD)/androidroots $(BUILD)/hubmatch $(BUILD)/spokematch \
	       $(BUILD)/devupmatch $(BUILD)/ndk \
	       $(BUILD)/urltestmatch $(BUILD)/nftvmap-tool \
	       $(BUILD)/*.err $(BUILD)/pkg $(BUILD)/scripts out
