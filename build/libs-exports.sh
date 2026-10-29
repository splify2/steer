#!/bin/sh
# Списки экспорта разделяемых библиотек (шаг 4 выпуска 1.10): что libsteer.so отдаёт steerd и
# модулям, а libsteer-wolfssl.so — libsteer.
#
#     sh build/libs-exports.sh gen     переписать build/libsteer.map, build/wolfssl/libsteer-wolfssl.map
#                                      и build/net1/libs2p-net.map (экспорт плагина net1)
#     sh build/libs-exports.sh check   сверить файлы с кодом (выход 1 — расходятся)
#
# ЗАЧЕМ СПИСКИ, А НЕ «ВСЁ ВИДИМОЕ». Без version-script библиотека отдаёт наружу каждый глобальный
# символ — модель, YAML, всё, что не static, — и любой из них становится ABI, который потом
# приходится помнить. С -fvisibility=hidden и списком наружу торчит ровно то, что кто-то снаружи
# (steerd, модуль) действительно зовёт. Список — не ручной: он вычисляется как пересечение
# неопределённых символов потребителей (steerd и всех модулей) с определёнными в libsteer, так что
# ни забыть нужный, ни оставить лишний нельзя — `check` падает, если файл разошёлся с кодом.
# Забытый символ ловит и сама сборка (-Wl,-z,defs у библиотеки; у потребителя — неопределённая
# ссылка), но `check` показывает разницу словами, а не строкой линковщика.
#
# СИМВОЛЫ НЕ ЗАВИСЯТ ОТ АРХИТЕКТУРЫ, поэтому считаются один раз на хосте (nm образа сборщика нет:
# там только zig) и лежат в дереве; кросс-сборка (build/build-libs.sh) их только читает.
#
# Нужны исходники wolfSSL (слой scrypto.c включает её заголовки): STEER_WOLFSSL или
# $BUILD/wolfssl-host/src, и исходники ngtcp2 с патчем (обёртка QUIC): STEER_NGTCP2 или
# $BUILD/ngtcp2-host/src (их кладёт tests/ext-test.sh).
set -eu
MODE="${1:-check}"
BUILD="${BUILD:-build}"
CC="${CC:-cc}"
. build/sources.sh
STEER_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
THIRD_DEFS="$(profile_var THIRD_DEFS)"
WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
[ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || {
    echo "libs-exports: нет исходников wolfSSL ($WSRC) — STEER_WOLFSSL=/путь" >&2; exit 2; }
NSRC="${STEER_NGTCP2:-$BUILD/ngtcp2-host/src}"
[ -f "$NSRC/lib/includes/ngtcp2/ngtcp2.h" ] || {
    echo "libs-exports: нет исходников ngtcp2 ($NSRC) — STEER_NGTCP2=/путь (build/ngtcp2/fetch.sh)" >&2; exit 2; }
W="$BUILD/libs-exports"
rm -rf "$W"
mkdir -p "$W/lib" "$W/app"
F="-O0 -w -fPIC -DSTEER_LIBSTEER -DWOLFSSL_USER_SETTINGS -Ibuild/wolfssl -I$WSRC $STEER_INC $THIRD_DEFS"
CRYPTO="$(profile_var CRYPTO_SRC)"
QUIC_ALL="$(profile_var QUIC_SRC)"
QUIC_STAND="$(profile_var QUIC_STAND_SRC)"
# ngtcp2 нужна ради двух вещей: заголовков (обёртка QUIC и стенд-потребитель) и списка функций
# wolfSSL, которые зовёт её криптобэкенд (crypto/wolfssl) — libsteer-wolfssl обязана их отдавать.
# Архив собирается тем же рецептом, что и в build-libs.sh, но без оптимизаций: нужны только символы.
CC="$CC" AR="${AR:-ar}" CFLAGS="-O0 -w -fPIC" sh build/ngtcp2/build.sh "$NSRC" "$WSRC" "$W/libngtcp2.a"
NGCFLAGS="$(cat "$W/libngtcp2.a.cflags")"
comp() {  # ДЕЛО КАТАЛОГ ФАЙЛЫ…
    d="$1"; shift
    printf '%s\n' "$@" | OD="$d" CCF="$F" xargs -P "$(nproc 2>/dev/null || echo 4)" -I{} \
        sh -c '$CC $CCF -c "$1" -o "$OD/$(echo "$1" | tr / _).o"' _ {}
}
export CC
LIB_SRC=""
for f in $(profile_var PROFILE_libsteer); do
    case " $QUIC_ALL " in *" $f "*) ;; *) LIB_SRC="$LIB_SRC $f" ;; esac
done
comp "$W/lib" $LIB_SRC
for f in $QUIC_ALL; do
    # shellcheck disable=SC2086
    $CC $F $NGCFLAGS -c "$f" -o "$W/lib/$(echo "$f" | tr / _).o"
done
# Стенд-потребитель QUIC: см. QUIC_STAND_SRC в sources.mk.
for f in $QUIC_STAND; do
    # shellcheck disable=SC2086
    $CC $F $NGCFLAGS -Itests -c "$f" -o "$W/app/$(echo "$f" | tr / _).o"
done
{
    # Раскладка 2.1: из libsteer берёт только steerd; протоколы и мост Telegram — плагины (на net1 или
    # статические) и с libsteer не связаны (нужды плагинов на net1 — карта net1 ниже).
    for p in PROFILE_steerd; do
        profile_var "$p"
    done
} | tr ' ' '\n' | sort -u | grep -v '^$' > "$W/app.lst"
comp "$W/app" $(cat "$W/app.lst")

nm -g --defined-only "$W"/lib/*.o | awk 'NF==3 {print $3}' | sort -u > "$W/defs"
# Слабые ссылки (w) считаются такими же нуждами, как обычные (U): слабая ссылка на скрытый символ
# не падает при сборке, а молча становится NULL, и возможность («в сборке есть QUIC», dup_have_quic)
# пропадает без единого сообщения. Именно так DoQ мог бы «работать» в стенде и отказывать на роутере.
nm -u "$W"/app/*.o | awk '$1=="U" || $1=="w" {print $2}' | sort -u > "$W/undef"
comm -12 "$W/defs" "$W/undef" > "$W/need"
# Все, что определено в libsteer, а снаружи не зовётся, остаётся скрытым.
# wolfSSL, нужная libsteer: слой примитивов, обёртка QUIC (qcssl.c) и криптобэкенд ngtcp2. Из
# архива берутся все члены, а не достижимые: сборщик выбросит лишнее, а список экспорта от этого
# зависеть не должен (nm на образе сборщика нет — список считается здесь, один на все архитектуры).
# Слой примитивов на 32-битном MIPS идёт своей веткой ChaCha20-Poly1305 (SC_CP_OWN в scrypto.c) и зовёт
# другие функции wolfSSL (wc_Chacha_SetIV, wc_Chacha_Process), чем на остальных целях
# (wc_ChaCha20Poly1305_*_ex): символы «не зависят от архитектуры» только если взять оба набора.
# shellcheck disable=SC2086
$CC $F -DSTEER_CP_OWN -c $CRYPTO -o "$W/scrypto-own.o"
{
    nm -u "$W/lib/$(echo "$CRYPTO" | tr / _).o" "$W/scrypto-own.o" "$W/lib/$(echo "$(profile_var QUIC_SSL_SRC)" | tr / _).o"
    nm -u "$W/libngtcp2.a"
} | awk '$1=="U" && ($2 ~ /^(wc_|wolf)/) {print $2}' | sort -u > "$W/wneed"

# ---- net1: libs2p-net.so.1 -------------------------------------------------------------------
# Экспорт net1 — то, что плагины протоколов на ней (PLUGINS_NET1) берут из её исходников; имена — с
# приставкой s2p_ (build/build-libs.sh переименовывает их заголовком из этой же карты). Плюс родная
# s2p_net_abi. Объекты — без переименования: считаются исходные имена, приставка ставится здесь.
mkdir -p "$W/net1" "$W/plug"
N1_SRC=""
for f in $(profile_var PROFILE_net1); do
    case " $QUIC_ALL " in *" $f "*) ;; *) N1_SRC="$N1_SRC $f" ;; esac
done
comp "$W/net1" $N1_SRC
for f in $(profile_var NET1_QUIC_SRC); do
    # shellcheck disable=SC2086
    $CC $F $NGCFLAGS -c "$f" -o "$W/net1/$(echo "$f" | tr / _).o"
done
for _pl in $(profile_var PLUGINS_NET1); do profile_var "PROFILE_plug_$_pl"; done | tr ' ' '\n' | sort -u | grep -v '^$' > "$W/plug.lst"
comp "$W/plug" $(cat "$W/plug.lst")
nm -g --defined-only "$W"/net1/*.o | awk 'NF==3 {print $3}' | sort -u > "$W/n1defs"
nm -u "$W"/plug/*.o | awk '$1=="U" || $1=="w" {print $2}' | sort -u > "$W/n1undef"
comm -12 "$W/n1defs" "$W/n1undef" | grep -v '^s2p_' > "$W/n1need" || true

emit_net1() {
    echo "/* Экспорт libs2p-net.so.1 (плагин net1) — ЭТОТ ФАЙЛ ПОРОЖДАЕТ build/libs-exports.sh (gen), руками"
    echo " * не правится. Имена исходников стека, которые берут плагины протоколов ($(profile_var PLUGINS_NET1 | sed 's/ /, /g')),"
    echo " * с приставкой s2p_; из той же карты сборка порождает заголовок переименования (src/net1/s2pnet.h)."
    echo " * Остальное, вместе с wolfSSL и ngtcp2, скрыто. Удалить или изменить имя — major net1. */"
    echo "LIBS2P_NET_1 {"
    echo "  global:"
    echo "    s2p_net_abi;"
    sed 's/^/    s2p_/; s/$/;/' "$W/n1need"
    echo "  local:"
    echo "    *;"
    echo "};"
}

emit_libsteer() {
    echo "/* Экспорт libsteer.so — ЭТОТ ФАЙЛ ПОРОЖДАЕТ build/libs-exports.sh (gen), руками не правится."
    echo " * Символы, которые steerd берёт"
    echo " * из библиотеки, и программный интерфейс QUIC (qc_*), который берёт стенд QUIC_STAND_SRC, пока"
    echo " * настоящих потребителей нет; остальное скрыто (local: *). Проверка: check. */"
    echo "LIBSTEER_1 {"
    echo "  global:"
    sed 's/$/;/; s/^/    /' "$W/need"
    echo "  local:"
    echo "    *;"
    echo "};"
}
emit_wolfssl() {
    echo "/* Экспорт libsteer-wolfssl.so — ЭТОТ ФАЙЛ ПОРОЖДАЕТ build/libs-exports.sh (gen), руками не правится."
    echo " * Символы wolfSSL, которые зовут слой src/lib/scrypto.c, обёртка QUIC src/proto/quic/qcssl.c и"
    echo " * криптобэкенд ngtcp2 (crypto/wolfssl), и отпечаток сборки steer_wolfssl_abi (build/wolfssl/"
    echo " * abi.c). Остальное скрыто: наружу торчит не библиотека, а нужное. */"
    echo "{"
    echo "  global:"
    echo "    steer_wolfssl_abi;"
    sed 's/$/;/; s/^/    /' "$W/wneed"
    echo "  local:"
    echo "    *;"
    echo "};"
}
emit_libsteer > "$W/libsteer.map"
emit_wolfssl > "$W/libsteer-wolfssl.map"
emit_net1 > "$W/libs2p-net.map"

case "$MODE" in
gen)
    cp "$W/libsteer.map" build/libsteer.map
    cp "$W/libsteer-wolfssl.map" build/wolfssl/libsteer-wolfssl.map
    mkdir -p build/net1
    cp "$W/libs2p-net.map" build/net1/libs2p-net.map
    echo "libs-exports: libsteer.map — $(wc -l < "$W/need") символов, libsteer-wolfssl.map — $(wc -l < "$W/wneed"), libs2p-net.map — $(($(wc -l < "$W/n1need") + 1))"
    ;;
check)
    bad=0
    for pair in libsteer.map:build/libsteer.map libsteer-wolfssl.map:build/wolfssl/libsteer-wolfssl.map libs2p-net.map:build/net1/libs2p-net.map; do
        gen="$W/${pair%%:*}"; have="${pair#*:}"
        if ! diff -u "$have" "$gen" > "$W/diff" 2>&1; then
            echo "libs-exports: $have разошёлся с кодом (sh build/libs-exports.sh gen):"
            sed 's/^/    /' "$W/diff" | head -30
            bad=1
        fi
    done
    [ "$bad" = 0 ] || exit 1
    echo "libs-exports: списки экспорта сходятся с кодом"
    ;;
*) echo "libs-exports: gen или check" >&2; exit 2 ;;
esac
