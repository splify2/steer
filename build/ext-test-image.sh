#!/bin/sh
# Прогон стендов расширенной части ВНУТРИ образа сборщика — там, где wolfSSL та самая.
#
# Зачем отдельный скрипт. Стенды xsloop, spokematch, vlessmatch, hubmatch и векторы слоя
# (scryptomatch) требуют НАСТОЯЩЕЙ криптобиблиотеки (tests/ext-test.sh, там же объяснено почему).
# На runner'е её нет, а собирать на нём свою значило бы проверять не то, чем собран релиз. Прогон
# здесь идёт на исходниках из образа (build/Dockerfile, /opt/wolfssl — версия и сумма из
# build/wolfssl/fetch.sh) тем же zig, которым собирается расширенный пакет (R-058, R-063).
#
# Логика здесь, а не строкой в `docker run -c`: там всё это жило бы внутри двойных кавычек с
# экранированием, и на этом класс ошибок уже стоил сборки — флаги -I терялись при подстановке,
# а выглядело как «заголовок не найден» (см. шапку build/build-ext.sh).
#
# ЧТО СОБИРАЕТСЯ И ЧЕМ. Библиотеку собирает сам tests/ext-test.sh — рецептом build/wolfssl/build.sh
# и с опциями build/wolfssl/user_settings.h, то есть теми же, что у пакета (прежде, при mbedtls,
# стенды здесь шли на конфигурации по умолчанию, а не на steer_mbedtls_config.h, — расхождение,
# которого больше нет). Добавка у стендов одна — выпуск сертификатов (WOLFSSL_CERT_GEN).
#
# AddressSanitizer в этом окружении недоступен (zig не везёт с собой его рантайм, а на musl нет
# и LeakSanitizer). tests/ext-test.sh это проверяет пробой и говорит об этом ГРОМКО, собирая
# spokematch и vlessmatch без санитайзера: функциональная половина стендов прогоняется, утечка — нет.
set -eu

WSRC=${WOLFSSL_DIR:-/opt/wolfssl}
SRC=${SRC:-/src}

if [ ! -f "$WSRC/wolfssl/wolfcrypt/settings.h" ]; then
	echo "ext-test-image: в образе нет исходников wolfSSL ($WSRC) — прогон невозможен" >&2
	exit 2
fi
command -v zig >/dev/null 2>&1 || {
	echo "ext-test-image: в образе нет zig — это не образ сборщика steer" >&2; exit 2; }

cd "$SRC"
# Стенд пишет в build/ от root (образ). Владелец на выходе возвращается тому, кому принадлежит
# смонтированное дерево (OWNER=uid:gid задаёт его явно); иначе следующая сборка на машине без
# root не снимет build/libs-host и соседей. Дерево root-а — ничего не меняем.
[ -n "${OWNER:-}" ] || OWNER="$(stat -c %u:%g "$SRC")"
if [ "$OWNER" != "0:0" ]; then
	trap 'chown -R "$OWNER" "$SRC/${BUILD:-build}" 2>/dev/null || true' EXIT
fi
STEER_WOLFSSL="$WSRC" CC="zig cc" BUILD="${BUILD:-build}" sh tests/ext-test.sh
