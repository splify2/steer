#!/bin/sh
# Собрать wolfSSL из исходников в статический архив — одним и тем же рецептом для всех целей.
#
#     sh build/wolfssl/build.sh <исходники wolfSSL> <выход .a> [asm|noasm]
#
# Компилятор и флаги — из окружения: CC (по умолчанию cc; zig — «zig cc -target …»), CFLAGS (цель,
# оптимизация), AR (по умолчанию «ar»; у zig — «zig ar», busybox ar архив создавать не умеет).
# STEER_WOLFSSL_DEFS — добавочные ключи библиотеки, которых нет в user_settings.h: их даёт только
# tests/ext-test.sh (выпуск сертификатов для стендов, WOLFSSL_CERT_GEN), сборки движка — никогда.
#
# Рядом с архивом кладётся <выход>.cflags — ровно те ключи, с которыми обязан компилироваться
# src/lib/scrypto.c против этого архива (определения и -I). Не «примерно те же»: ключ
# STEER_WOLFSSL_ASM меняет раскладку Aes (поля AES-NI), и scrypto.c, собранный без него рядом с
# библиотекой, собранной с ним, писал бы мимо полей. Поэтому вызывающий берёт ключи из файла, а не
# выводит их сам.
#
# ПОЧЕМУ СВОЙ РЕЦЕПТ, А НЕ configure. Движок собирается zig под девять архитектур из одного образа
# и NDK под телефон; configure wolfSSL на каждую цель — это autotools в образе, проба компилятора
# под чужую архитектуру и опции, размазанные по командной строке. Официальный путь wolfSSL для
# встраиваемых сборок — ровно такой: список .c, ключ -DWOLFSSL_USER_SETTINGS и один заголовок
# опций (build/wolfssl/user_settings.h — там же, почему опции именно такие). Этим же заголовком
# и этим же списком собирает Android.bp (сверяет tests/buildmatch.sh), а шаг 4 (пакет
# libsteer-wolfssl) — .so из того же набора.
#
# СПИСОК ФАЙЛОВ — ЯВНЫЙ, а не «всё из wolfcrypt/src»: там больше сотни файлов, из которых нам
# нужна треть, и лишний файл под нашими опциями компилируется в пустоту — то есть ничего не
# стоит на флеше, но стоит времени сборки на девяти архитектурах. Забытый нужный файл виден сразу:
# неопределённая ссылка при компоновке движка или стенда.
#
# ОШИБКА КОМПИЛЯЦИИ ФАЙЛА НЕ ГЛУШИТСЯ и называется словами «не удалась» — их читает барьер
# релиза (.github/workflows/release.yml грепает build.log), ровно как прежде у цикла mbedtls.
set -eu

SRC="${1:?нужен каталог исходников wolfSSL}"
OUT="${2:-}"
[ "$SRC" = list ] || [ -n "$OUT" ] || { echo "wolfssl: нужен путь выходного архива" >&2; exit 2; }
ASM="${3:-asm}"
CC="${CC:-cc}"
AR="${AR:-ar}"
CFLAGS="${CFLAGS:--O2}"
HERE=$(cd "$(dirname "$0")" && pwd)

# Сам список — функцией, чтобы его же печатал вызов `build.sh list` для сверки с Android.bp.
wolfssl_c_files() {
    for f in internal keys ssl tls tls13 quic wolfio; do echo "src/$f.c"; done
    # ge_operations.c — групповая математика Ed25519: проверка подписи плагинов (ed25519.c) стоит на
    # ней, а X25519 берёт её для открытого ключа там, где у кривой свой ассемблер (aarch64).
    for f in aes asn chacha chacha20_poly1305 coding cpuid curve25519 ecc ed25519 error fe_operations \
             ge_operations hash hmac kdf logging md5 memory poly1305 random rsa sha sha256 sha3 sha512 \
             sp_int wc_encrypt wc_mldsa wc_mlkem wc_mlkem_poly wc_port wolfmath; do
        echo "wolfcrypt/src/$f.c"
    done
    # Встроенный ассемблер aarch64 (WOLFSSL_ARMASM_INLINE в user_settings.h). Файлы в каждом
    # списке, а не только у aarch64: вне его они компилируются в пустоту (#ifdef __aarch64__
    # внутри), и список остаётся одним на все цели и на Android.bp.
    for f in aes-asm_c chacha-asm_c poly1305-asm_c sha256-asm_c sha512-asm_c curve25519_c sha3-asm_c; do
        echo "wolfcrypt/src/port/arm/armv8-$f.c"
    done
}
[ "$SRC" = list ] && { wolfssl_c_files; exit 0; }
[ -f "$SRC/wolfssl/wolfcrypt/settings.h" ] || {
    echo "wolfssl: в $SRC нет исходников wolfSSL (wolfssl/wolfcrypt/settings.h)" >&2; exit 2; }
# Пути — абсолютные: они уходят в <выход>.cflags, а читают его из другого рабочего каталога.
SRC=$(cd "$SRC" && pwd)
mkdir -p "$(dirname "$OUT")"

TRIPLE=$($CC -dumpmachine 2>/dev/null || echo unknown)
ASMFILES=
ASMDEF=
case "$ASM:$TRIPLE" in
    asm:x86_64-*)
        ASMDEF=-DSTEER_WOLFSSL_ASM
        for f in aes_x86_64_asm aes_gcm_asm; do
            ASMFILES="$ASMFILES wolfcrypt/src/$f.S"
        done ;;
esac

DEFS="-DWOLFSSL_USER_SETTINGS $ASMDEF ${STEER_WOLFSSL_DEFS:-}"
OBJ="$OUT.obj"
# Отпечаток сборки: опции, флаги, компилятор. Архив с тем же отпечатком не пересобирается — у
# девяти архитектур это минуты, — а любая правка user_settings.h или флагов пересобирает его.
STAMP="$(cat "$HERE/user_settings.h" "$0"; echo "$CC|$CFLAGS|$DEFS|$TRIPLE")"
if [ -f "$OUT" ] && [ -f "$OUT.stamp" ] && [ "$(cat "$OUT.stamp")" = "$STAMP" ]; then
    exit 0
fi
rm -rf "$OBJ"
mkdir -p "$OBJ"

failed=
for f in $(wolfssl_c_files) $ASMFILES; do
    o="$OBJ/$(echo "$f" | tr '/' '_').o"
    extra=
    # Интринсики AES-NI в aes.c (AES_set_decrypt_key) требуют -maes у компилятора. Ключ — ОДНОМУ
    # файлу: команды AES компилятор сам не выпускает никогда, а весь путь AES-NI в aes.c стоит за
    # проверкой CPUID (Check_CPU_support_AES), так что бинарник по-прежнему запускается там, где
    # AES-NI нет. SSE4.1 не даётся нарочно: её команды компилятор ВЫПУСКАЕТ сам, векторизуя
    # обычный код, и тогда файл упал бы на процессоре без неё.
    [ -n "$ASMDEF" ] && [ "$f" = wolfcrypt/src/aes.c ] && extra=-maes
    # shellcheck disable=SC2086
    if ! $CC $CFLAGS $extra $DEFS -I"$HERE" -I"$SRC" \
            -c "$SRC/$f" -o "$o" 2>"$o.err"; then
        failed="$failed $f"
        echo "wolfssl: сборка файла $f не удалась ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    elif [ -s "$o.err" ]; then
        # Предупреждения не прячутся: сборка движка идёт без них, и у библиотеки их тоже быть
        # не должно — новое предупреждение после обновления wolfSSL видно здесь, а не в релизе.
        echo "wolfssl: предупреждения в $f ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    fi
    rm -f "$o.err"
done
[ -z "$failed" ] || { echo "wolfssl: сборка не удалась у файлов:$failed" >&2; exit 1; }

rm -f "$OUT"
# shellcheck disable=SC2086
$AR rcs "$OUT" "$OBJ"/*.o
printf '%s\n' "$DEFS -I$HERE -I$SRC" > "$OUT.cflags"
printf '%s' "$STAMP" > "$OUT.stamp"
rm -rf "$OBJ"
