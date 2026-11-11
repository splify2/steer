#!/bin/sh
# Собрать ngtcp2 (с нашим патчем Brutal) и её криптобэкенд для wolfSSL в статический архив —
# одним и тем же рецептом для всех целей, как build/wolfssl/build.sh.
#
#     sh build/ngtcp2/build.sh <исходники ngtcp2 (fetch.sh)> <исходники wolfSSL> <выход .a>
#     sh build/ngtcp2/build.sh list                   список файлов (для сверки с Android.bp)
#
# Компилятор и флаги — из окружения: CC (по умолчанию cc; zig — «zig cc -target …»), CFLAGS (цель,
# оптимизация, -fPIC для общей библиотеки), AR (у zig — «zig ar»). STEER_NGTCP2_DEFS — добавочные
# ключи (стенды: отладочный журнал), сборки движка — никогда.
#
# Рядом с архивом кладётся <выход>.cflags — ровно те ключи и -I, с которыми обязаны
# компилироваться файлы, включающие заголовки ngtcp2 (src/proto/quic/*.c): как у wolfSSL, не
# «примерно те же»: NGTCP2_STATICLIB меняет объявления, а -I на исходники — путь к ngtcp2.h.
#
# СПИСОК ФАЙЛОВ — все .c из lib/ (46 штук; ядро QUIC не делится на нужное и лишнее) и два
# файла криптобэкенда: crypto/shared.c (общий для всех библиотек: обёртки над колбэками, токены,
# помощники) и crypto/wolfssl/wolfssl.c. Библиотеки HTTP/3 (nghttp3) нет и не берётся — запрос
# авторизации hysteria2 собирается вручную (решение владельца, шаг 7).
#
# ПОЧЕМУ БЕЗ configure. Та же причина, что у wolfSSL: все архитектуры build/arches.sh из одного образа с zig и
# NDK под телефон; конфигурация одна — build/ngtcp2/config.h.
#
# ОШИБКА КОМПИЛЯЦИИ ФАЙЛА НЕ ГЛУШИТСЯ и называется словами «не удалась» — их читает барьер релиза
# (как у wolfSSL). Предупреждения библиотеки не прячутся: новое предупреждение после обновления
# ngtcp2 видно здесь, а не в релизе.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ngtcp2_c_files() {  # $1 — исходники
    for f in "$1"/lib/*.c; do echo "lib/$(basename "$f")"; done
    echo crypto/shared.c
    echo crypto/wolfssl/wolfssl.c
}
if [ "${1:-}" = list ]; then
    ngtcp2_c_files "${2:?нужны исходники ngtcp2}"
    exit 0
fi

SRC="${1:?нужен каталог исходников ngtcp2}"
WSRC="${2:?нужен каталог исходников wolfSSL}"
OUT="${3:?нужен путь выходного архива}"
CC="${CC:-cc}"
AR="${AR:-ar}"
CFLAGS="${CFLAGS:--O2}"
[ -f "$SRC/lib/includes/ngtcp2/ngtcp2.h" ] || { echo "ngtcp2: в $SRC нет исходников" >&2; exit 2; }
[ -f "$SRC/lib/ngtcp2_brutal.c" ] || { echo "ngtcp2: в $SRC нет патча Brutal (fetch.sh накладывает его)" >&2; exit 2; }
[ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || { echo "ngtcp2: в $WSRC нет исходников wolfSSL" >&2; exit 2; }
SRC=$(cd "$SRC" && pwd)
WSRC=$(cd "$WSRC" && pwd)
mkdir -p "$(dirname "$OUT")"

# Ключи. NGTCP2_STATICLIB — без него заголовок помечает функции dllimport/visibility по-своему;
# HAVE_CONFIG_H — заголовки ngtcp2 подключают <config.h> (наш, из $HERE). wolfSSL-ключи нужны
# только файлу криптобэкенда, но даются всем: заголовки wolfSSL раскладывают структуры по
# user_settings.h, и файл, видевший их без него, расходился бы с библиотекой (см. шапку
# build/wolfssl/user_settings.h).
DEFS="-DHAVE_CONFIG_H -DNGTCP2_STATICLIB -DWOLFSSL_USER_SETTINGS ${STEER_NGTCP2_DEFS:-}"
INCS="-I$HERE -I$HERE/include -I$SRC/lib -I$SRC/lib/includes -I$SRC/crypto -I$SRC/crypto/includes -I$HERE/../wolfssl -I$WSRC"
OBJ="$OUT.obj"
TRIPLE=$($CC -dumpmachine 2>/dev/null || echo unknown)
# Отпечаток сборки: флаги, компилятор, наши файлы и сумма исходников (метка fetch.sh).
STAMP="$(cat "$HERE/config.h" "$0" "$HERE/../wolfssl/user_settings.h"; echo "$CC|$CFLAGS|$DEFS|$TRIPLE"; cat "$SRC/.steer-ngtcp2" 2>/dev/null)"
if [ -f "$OUT" ] && [ -f "$OUT.stamp" ] && [ "$(cat "$OUT.stamp")" = "$STAMP" ]; then
    exit 0
fi
rm -rf "$OBJ"
mkdir -p "$OBJ"

failed=
for f in $(ngtcp2_c_files "$SRC"); do
    o="$OBJ/$(echo "$f" | tr '/' '_').o"
    # shellcheck disable=SC2086
    if ! $CC $CFLAGS $DEFS $INCS -c "$SRC/$f" -o "$o" 2>"$o.err"; then
        failed="$failed $f"
        echo "ngtcp2: сборка файла $f не удалась ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    elif [ -s "$o.err" ]; then
        echo "ngtcp2: предупреждения в $f ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    fi
    rm -f "$o.err"
done
[ -z "$failed" ] || { echo "ngtcp2: сборка не удалась у файлов:$failed" >&2; exit 1; }

rm -f "$OUT"
$AR rcs "$OUT" "$OBJ"/*.o
# Ключи для потребителей (src/proto/quic): заголовки ngtcp2 и заглушка wolfssl/options.h, которую
# подключает ngtcp2_crypto_wolfssl.h. Ключей wolfSSL здесь нет — они у файла, включающего wolfSSL,
# свои, из build/wolfssl (.cflags его архива). HAVE_CONFIG_H не дан: он нужен только внутренним
# заголовкам самой библиотеки, публичные его не читают.
printf '%s\n' "-DNGTCP2_STATICLIB -I$HERE/include -I$SRC/lib/includes -I$SRC/crypto/includes" > "$OUT.cflags"
printf '%s' "$STAMP" > "$OUT.stamp"
rm -rf "$OBJ"
