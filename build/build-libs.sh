#!/bin/sh
# Разделяемая раскладка роутера под ОДНУ архитектуру (шаг 4 выпуска 1.10, docs/architecture.md,
# «Сборки»): libsteer-wolfssl.so, libsteer.so, steerd, плагин-библиотека net1 и программы плагинов.
#
#     sh build/build-libs.sh ВЫХОДНОЙ_КАТАЛОГ ВЕРСИЯ [РЕВИЗИЯ]
#
# Компилятор и цель — из окружения: CC (по умолчанию cc; zig — «zig cc -target … -mcpu=…»), AR
# (у zig — «zig ar»), INTERP (путь загрузчика musl этой архитектуры, см. ниже; пусто — как у
# компилятора: хостовая сборка стендов), LIBS (добавочные системные библиотеки: на glibc хоста
# нужен -lpthread -ldl -lm, на musl — ничего), WOLFSSL_DIR (исходники wolfSSL; в образе сборщика —
# /opt/wolfssl), JOBS (параллельность). Зовут этот скрипт build.sh (внутри образа сборщика, по разу
# на архитектуру) и tests/libs-test.sh (на хосте, gcc).
#
# ЧТО В КАКОМ ФАЙЛЕ — build/sources.mk (PROFILE_libsteer, PROFILE_steerd, PROFILE_net1, PROFILE_plug_*);
# здесь
# только рецепт. Файлы на выходе называются по SONAME, а не по «libсteer.so»: у libsteer версия
# движка (ABI между версиями не обещается, и бинарник, слинкованный с чужой версией, должен не
# запуститься с понятной ошибкой загрузчика, а не молча взять несовместимую), у libsteer-wolfssl —
# версия wolfSSL (пакет обновляется отдельно, а совместимость раскладки при этом сторожит сверка
# размеров при загрузке — build/wolfssl/abi.c).
#
# ИНТЕРПРЕТАТОР. У статического бинарника загрузчика нет, у динамического он вшит по абсолютному
# пути, и умолчание zig для musl — путь без поправок на мягкую плавающую точку и разные ABI ARM,
# то есть не тот файл, что лежит на роутере. Поэтому build.sh задаёт INTERP на каждую
# архитектуру по имени загрузчика musl (ld-musl-mipsel-sf.so.1 для mipsel soft-float,
# ld-musl-armhf.so.1 для hard-float ARM, и т. д.). RPATH не нужен: библиотеки лежат в /usr/lib,
# где musl ищет по умолчанию.
#
# РАСКЛАДКА 2.1 (единственная; build/sources.mk, «РАСКЛАДКА 2.1»): libsteer без стека протоколов,
# steerd, плагин-библиотека net1 и программы плагинов (модулей ядра больше нет):
#
#     ВЫХОД/libsteer.so.<версия> libsteer-wolfssl.so.<версия> steerd
#     ВЫХОД/plugins/net1/lib/libs2p-net.so.1
#     ВЫХОД/plugins/<id>/bin/<id>          vless hysteria2 proxy xsteer warpbox obfs tgws
#
# tgws — плагин репозитория splify2-extended-plugins (PLUGINS_EXTENDED): программу собирает это дерево,
# архив .s2p — тот репозиторий.
#
# Плагины ищут net1 по RUNPATH $ORIGIN/../../net1/lib — раскладка каталога плагинов на роутере
# (/usr/lib/steer/plugins/<id>/bin) та же, что здесь. Прежней раскладки 2.0 (модули steer-<m> на
# libsteer со стеком) больше нет: виды и подкоманды протоколов ядро берёт только у плагинов.
set -eu

OUT="${1:?нужен выходной каталог}"
VERSION="${2:?нужна версия}"
REV="${3:-неизвестна}"
CC="${CC:-cc}"
AR="${AR:-ar}"
INTERP="${INTERP:-}"
LIBS="${LIBS:-}"
WOLFSSL_DIR="${WOLFSSL_DIR:-/opt/wolfssl}"
J="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
export CC

. build/sources.sh
STEER_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
THIRD_DEFS="$(profile_var THIRD_DEFS)"
WVER="$(sh build/wolfssl/fetch.sh version)"
NGTAG="$(sh build/ngtcp2/fetch.sh soname)"

# РАЗМЕР И СКОРОСТЬ (2.1.4). Горячий путь — шифры, TLS и QUIC, стек туннеля, транспорты, данные протоколов,
# резолвер (HOT_SRC в build/sources.mk) — собирается -O2; всё остальное (компилятор спеки, разбор YAML и JSON,
# команды, менеджер плагинов, подписки, doctor и diag) — -Os: там важен размер, а не такты. STEER_OPT=O2 — всё
# -O2 (сравнительный замер), STEER_OPT=Os — всё -Os.
HOT=" $(profile_var HOT_SRC) "
OPT="${STEER_OPT:-split}"
# Символы в файлах — только для разбора размера (STEER_NOSTRIP=1: «что сколько весит» по llvm-nm -S); в пакет не идёт.
STRIPF="-s"
[ -z "${STEER_NOSTRIP:-}" ] || STRIPF=""
# MIPS: clang кладёт в каждый объект .pdr (описатели процедур для отладчика) — секцию без SHF_ALLOC, которую -s
# не снимает: 0,64 МБ во всех файлах 2.1.3 на mipsel (net1 158 КБ, tgws 131 КБ, wolfSSL 112 КБ, libsteer 75 КБ…),
# и роутеру она не нужна.
# Отбрасывает её скрипт компоновщика (INSERT — дополнение к стандартной раскладке, а не замена).
case "$CC" in *mips*) LDX="-Wl,-T,build/nopdr.ld" ;; *) LDX="" ;; esac
# Таблицы раскрутки стека (.eh_frame, .eh_frame_hdr) коду на C без исключений не нужны: ни backtrace, ни отмены
# потоков с раскруткой у musl нет. На aarch64 2.1.3 — 0,38 МБ во всех файлах (net1 108 КБ из 1,27 МБ).
NOUNW="-fno-asynchronous-unwind-tables -fno-unwind-tables"
# Страница 4 КБ. lld по умолчанию выравнивает сегменты под 64 КБ на MIPS, ARM и aarch64 (ядра со страницами 64 КБ), и
# смещение сегмента в ФАЙЛЕ обязано совпадать с адресом по модулю этой страницы: где TLS и RELRO сдвигают адрес, файл
# получал до 64 КБ нулей (libsteer и tgws 2.1.3 на mipsel — по 66 КБ). Ядра OpenWrt всех архитектур пакета
# (build/arches.sh) — со страницей 4 КБ, и загрузчик musl требует совпадения только по ней. Ко всем компоновкам файла.
PAGE="-Wl,-z,max-page-size=4096"
LDX="$LDX $PAGE"

mkdir -p "$OUT"
OBJ="$OUT/obj"
rm -rf "$OBJ"
mkdir -p "$OBJ/lib" "$OBJ/steerd" "$OBJ/mod"

# Версия и ревизия — заголовком, а не -D: значение со строкой в кавычках через переменную оболочки
# не передать (кавычки не переразбираются), а прежний приём — литерал в самой командной строке — не
# годится для общей переменной флагов.
{
    printf '#define STEER_VERSION "%s"\n' "$VERSION"
    printf '#define STEER_REV "%s"\n' "$REV"
} > "$OBJ/steer_version.h"

# ---- wolfSSL: статический архив С -fPIC и общая библиотека ---------------------------------------
# Архив собирает тот же рецепт, что для статических бинарников (build/wolfssl/build.sh), но -fPIC
# и в свой каталог: объекты без PIC в общую библиотеку не влезают. -ffunction-sections и
# --gc-sections оставляют в .so только достижимое от экспортируемых символов: TLS-стек и QUIC
# wolfSSL, включённые опциями заранее, весят там ровно столько, сколько их зовут (с шага 7 — обёртка
# QUIC и ngtcp2, ниже).
WTAG="$(echo "$CC" | tr -c 'a-zA-Z0-9' '_')"
WLIB="$OUT/wolfssl-pic/$WTAG/libwolfssl.a"
env CC="$CC" AR="$AR" CFLAGS="-O2 -fPIC -ffunction-sections -fdata-sections $NOUNW" \
    sh build/wolfssl/build.sh "$WOLFSSL_DIR" "$WLIB" asm
WCFLAGS="$(cat "$WLIB.cflags")"

# shellcheck disable=SC2086
$CC -O2 -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections $NOUNW -Wall -Wextra \
    -Isrc/lib $WCFLAGS -c build/wolfssl/abi.c -o "$OBJ/abi.o"
# Экспортируется из библиотеки ровно то, что зовёт слой src/lib/scrypto.c (и отпечаток сборки):
# список лежит в дереве (build/wolfssl/libsteer-wolfssl.map), а `sh build/libs-exports.sh check`
# сверяет его с неопределёнными символами объекта слоя. Забытый символ ловит и сама сборка:
# libsteer.so не слинкуется (-z defs). Список — файлом, а не вычисляется здесь, потому что nm в
# образе сборщика нет (там только zig), а состав символов от архитектуры не зависит.
WMAP="build/wolfssl/libsteer-wolfssl.map"

# ---- ngtcp2: статический архив с -fPIC (шаг 7) и общая библиотека (2.1.4) ------------------------
# Исходники — с нашим патчем Brutal (build/ngtcp2/fetch.sh; в образе сборщика — /opt/ngtcp2), рецепт —
# build/ngtcp2/build.sh: те же флаги, что у архива wolfSSL. С 2.1.4 архив — не в libsteer.so и не в net1 по
# копии, а одна общая библиотека ядра libsteer-ngtcp2.so.<версия>-<серия патчей> (ниже): потребителей два —
# резолвер ядра (DoQ, DoH3) и net1 (hysteria2, MASQUE), и вторая копия стоила 0,3 МБ на mipsel.
# Криптобэкенд ngtcp2 зовёт wolfSSL_*, они берутся из libsteer-wolfssl.so (список экспорта —
# build/libs-exports.sh).
NGTCP2_DIR="${NGTCP2_DIR:-/opt/ngtcp2}"
NGLIB="$OUT/ngtcp2-pic/$WTAG/libngtcp2.a"
env CC="$CC" AR="$AR" CFLAGS="-Os -fPIC -ffunction-sections -fdata-sections $NOUNW" \
    sh build/ngtcp2/build.sh "$NGTCP2_DIR" "$WOLFSSL_DIR" "$NGLIB"
NGCFLAGS="$(cat "$NGLIB.cflags")"

# ---- libsteer.so ---------------------------------------------------------------------------------
# Оптимизация — по файлу (optf, HOT_SRC выше): через TLS, QUIC и шифры этой библиотеки идёт резолвер (DoH, DoQ),
# а модель спеки, виды и команды — холодный код.
# -ftls-model=initial-exec: __thread в библиотеке без него ходят через __tls_get_addr на каждое
# обращение — на mipsel это заметно, а библиотека всегда грузится при запуске процесса (DT_NEEDED,
# не dlopen), где initial-exec допустим и стоит одну загрузку из GOT.
# -DSTEER_LIBSTEER: реестр видов (kinds/kind.c) отвечает по наличию модулей.
#
# ВИДИМОСТЬ. Экспорт задаёт version-script (build/libsteer.map), порождённый из того, что
# действительно берут потребители (build/libs-exports.sh): всё, чего в нём нет, компоновщик
# делает локальным, и в .dynsym остаётся ровно список. -fvisibility=hidden поверх него дал бы
# ту же таблицу, но потребовал бы пометить `visibility("default")` каждое из 240 определений
# (иначе скрытое нельзя экспортировать даже из version-script), то есть второй список в
# исходниках, который разъезжается с первым. Потеря — только в том, что компилятор не знает
# заранее о локальности символов; её возвращают -fno-semantic-interposition (вызовы внутри
# библиотеки не идут через PLT) и -Bsymbolic-functions при компоновке.
LIBF="$NOUNW -fPIC -fno-semantic-interposition -ftls-model=initial-exec -ffunction-sections -fdata-sections \
      -DSTEER_LIBSTEER -Wall -Wextra -include $OBJ/steer_version.h $STEER_INC $THIRD_DEFS"
APPF="$NOUNW -Wall -Wextra -include $OBJ/steer_version.h $STEER_INC $THIRD_DEFS -ffunction-sections -fdata-sections"

# optf ФАЙЛ — ключ оптимизации файла: -O2 горячему пути (HOT_SRC), -Os остальному (STEER_OPT — выше).
optf() {
    case "$OPT" in
        O2) echo -O2 ;;
        Os) echo -Os ;;
        *) case "$HOT" in *" $1 "*) echo -O2 ;; *) echo -Os ;; esac ;;
    esac
}

# compile ФЛАГИ КАТАЛОГ ФАЙЛЫ… — параллельно; отказ любого файла — отказ сборки. Ключ оптимизации — по файлу
# (optf); -O во ФЛАГАХ стоит после него и побеждает (внешние модули — как прежде, -O2).
compile() {
    _f="$1"; _d="$2"; shift 2
    printf '%s\n' "$@" | CCF="$_f" OD="$_d" HOT="$HOT" OPT="$OPT" xargs -P "$J" -I{} sh -c '
        case "$OPT" in O2) o=-O2 ;; Os) o=-Os ;; *) case "$HOT" in *" $1 "*) o=-O2 ;; *) o=-Os ;; esac ;; esac
        $CC $o $CCF -c "$1" -o "$OD/$(echo "$1" | tr / _).o"' _ {}
}

# ---- memcpy, memmove, memset musl в каждом файле (zig) ---------------------------------------------
# Второй изъян compiler_rt zig: в том же единственном объекте лежат слабые memcpy, memmove и memset — побайтовые
# циклы. Где compiler_rt подтягивается (на mipsel — в каждый файл: деление 64-битных чисел, мягкая плавающая
# точка), его слабое определение побеждает memcpy из libc.so (определение в самой компоновке сильнее чужой .so), и
# весь горячий путь — буферы стека, записи TLS, датаграммы QUIC — копировал по байту (2.1.3: libsteer, wolfSSL,
# net1 и плагины на mipsel). Здесь те же функции из исходников musl, которые zig несёт с собой (на aarch64, arm и
# x86_64 — ассемблер musl, на mips — его C пословно), собираются в каждый файл: сильные определения побеждают
# compiler_rt, а в .so они локальны (version-script). Код — тот же, что в libc.so роутера.
MEMOPS=""
if [ -n "${ZIG:-}" ]; then
    _ms="$(zig env | sed -n 's/.*"lib_dir": *"\([^"]*\)".*/\1/p')/libc/musl/src/string"
    case "$CC" in *aarch64*) _ma=aarch64 ;; *x86_64*) _ma=x86_64 ;; *" arm"*) _ma=arm ;; *) _ma="" ;; esac
    mkdir -p "$OBJ/memops"
    _mf="memcpy memmove memset"
    [ "$_ma" = arm ] && _mf="$_mf __aeabi_memcpy __aeabi_memset"
    for _f in $_mf; do
        _src="$_ms/$_f.c"
        for _e in S s; do [ -n "$_ma" ] && [ -f "$_ms/$_ma/$_f.$_e" ] && _src="$_ms/$_ma/$_f.$_e"; done
        [ -f "$_src" ] || { echo "build-libs: нет $_src (исходники musl в zig)" >&2; exit 1; }
        # shellcheck disable=SC2086
        $CC -O2 -fPIC -ffreestanding -fno-builtin $NOUNW -c "$_src" -o "$OBJ/memops/$_f.o"
        MEMOPS="$MEMOPS $OBJ/memops/$_f.o"
    done
fi

CRYPTO="$(profile_var CRYPTO_SRC)"
QUIC_ALL="$(profile_var QUIC_SRC)"
QUIC_SSL="$(profile_var QUIC_SSL_SRC)"
LAYOUT="${STEER_LAYOUT:-2.1}"
case "$LAYOUT" in
    2.1) LIB_PROFILE=PROFILE_libsteer; LIB_MAP=build/libsteer.map ;;
    *) echo "build-libs: STEER_LAYOUT — только 2.1 (раскладка 2.0 с модулями протоколов снята), а не «$LAYOUT»" >&2; exit 2 ;;
esac
LIB_SRC=""
for f in $(profile_var "$LIB_PROFILE"); do
    case " $CRYPTO $QUIC_ALL " in *" $f "*) ;; *) LIB_SRC="$LIB_SRC $f" ;; esac
done
# shellcheck disable=SC2086
compile "$LIBF" "$OBJ/lib" $LIB_SRC
# Слой примитивов — с ключами wolfSSL, остальным они ничего не значат.
# shellcheck disable=SC2086
$CC $(optf "$CRYPTO") $LIBF $WCFLAGS -c "$CRYPTO" -o "$OBJ/lib/$(echo "$CRYPTO" | tr / _).o"
# Обёртка QUIC: заголовки ngtcp2 — обоим файлам, wolfSSL — только тому, что ему положено (QUIC_SSL_SRC).
for f in $QUIC_ALL; do
    case " $QUIC_SSL " in *" $f "*) _wc="$WCFLAGS" ;; *) _wc="" ;; esac
    # shellcheck disable=SC2086
    $CC $(optf "$f") $LIBF $NGCFLAGS $_wc -c "$f" -o "$OBJ/lib/$(echo "$f" | tr / _).o"
done

# -z defs (библиотека не оставляет неопределённых символов) по умолчанию включён: он превращает
# забытый экспорт или файл, выпавший из списка, в ошибку сборки, а не в падение на роутере. Но
# libc, с которой zig линкует общие библиотеки под musl, — заглушка, собранная из перечня
# «стабильных» символов, и в ней нет служебных __time64 и __gmtime64, которые заголовки musl
# подставляют вместо time() и gmtime() на 32-битных архитектурах (в настоящем libc.so на роутере они
# есть — любая динамическая программа под 32-битный musl зовёт их же). Поэтому кросс-сборка
# отключает проверку переменной ZIG=1, а замену ей даёт запуск на самих архитектурах
# (qemu-user, ВМ): неопределённый символ там — отказ загрузчика при первом запуске. ZIG=1 же
# убирает -rpath-link, которого драйвер zig не знает (зависимости библиотек lld ищет сам).
if [ -n "${ZIG:-}" ]; then
    ZDEFS=""
    RPL=""
else
    ZDEFS="-Wl,-z,defs"
    RPL="-Wl,-rpath-link,$OUT"
fi

WSO="$OUT/libsteer-wolfssl.so.$WVER"
# --whole-archive: символы экспортируются, но никто внутри библиотеки их не «требует», и обычная
# компоновка архива не вытянула бы ни одного члена; --gc-sections потом выбрасывает все секции,
# недостижимые от экспортов.
# shellcheck disable=SC2086
$CC -shared -o "$WSO" "$OBJ/abi.o" $MEMOPS -Wl,--whole-archive "$WLIB" -Wl,--no-whole-archive \
    -Wl,-soname,"libsteer-wolfssl.so.$WVER" -Wl,--version-script="$WMAP" -Wl,--gc-sections \
    $ZDEFS -Wl,-z,relro $LDX $STRIPF $LIBS

# libsteer-ngtcp2.so — ngtcp2 с криптобэкендом одним файлом на ядро и net1 (выше). Экспорт —
# build/ngtcp2/libsteer-ngtcp2.map: то, что зовут обёртка src/proto/quic (quic.c, qcssl.c), сверяет
# `sh build/libs-exports.sh check`. SONAME несёт версию ngtcp2 и серию наших патчей: структуры ngtcp2
# (настройки, Brutal) — часть границы с quic.c, и net1 другой серии с этой библиотекой не загрузится.
NGSO="$OUT/libsteer-ngtcp2.so.$NGTAG"
# shellcheck disable=SC2086
$CC -shared -o "$NGSO" $MEMOPS -Wl,--whole-archive "$NGLIB" -Wl,--no-whole-archive "$WSO" \
    -Wl,-soname,"libsteer-ngtcp2.so.$NGTAG" -Wl,--version-script=build/ngtcp2/libsteer-ngtcp2.map \
    -Wl,-Bsymbolic -Wl,--gc-sections $ZDEFS -Wl,-z,relro $LDX $STRIPF $LIBS

SO="$OUT/libsteer.so.$VERSION"
# shellcheck disable=SC2086
$CC -shared -o "$SO" "$OBJ"/lib/*.o $MEMOPS "$NGSO" "$WSO" \
    -Wl,-soname,"libsteer.so.$VERSION" -Wl,--version-script="$LIB_MAP" \
    -Wl,-Bsymbolic -Wl,--gc-sections $ZDEFS -Wl,-z,relro $LDX $STRIPF $LIBS

# ---- программы: компоновка без чужих экспортов ----------------------------------------------------
# link_exe ВЫХОД АРГУМЕНТЫ… — программа (steerd, плагины). У zig есть изъян, который стоил каждой программе
# под mipsel 60–90 КБ: compiler_rt (деление 64-битных чисел, мягкая плавающая точка) — ОДИН объект, и вместе с
# __udivdi3 в программу попадают его слабые memcpy, sin, cos, log, fma… lld экспортирует из программы всякий
# символ, который определяет и подключённая .so (libc.so их определяет), а экспорт — корень для --gc-sections:
# ни одна из этих функций не выбрасывалась. Ключа --exclude-libs драйвер zig 0.13 не знает, поэтому программа
# компонуется дважды: `zig cc -v` печатает команду ld.lld, и она повторяется с --exclude-libs ALL — символы
# архивов (compiler_rt) локальны, лишнее уходит. Программам экспортировать нечего: .so-плагины steerd берут
# всё таблицей (steer-abi), net1 — только libc и библиотеки ядра. Не zig (стенды, gcc) — как прежде.
link_exe() {
    _xo="$1"; shift
    if [ -z "${ZIG:-}" ]; then
        # shellcheck disable=SC2086
        $CC -o "$_xo" "$@" $LDX $STRIPF $LIBS
        return
    fi
    # shellcheck disable=SC2086
    if ! $CC -o "$_xo" "$@" $LDX $STRIPF $LIBS -v >"$_xo.ldv" 2>&1; then
        cat "$_xo.ldv" >&2; rm -f "$_xo.ldv"; return 1
    fi
    _ll="$(grep '^ld.lld ' "$_xo.ldv" | grep -F -- " -o $_xo " | tail -1 || true)"
    rm -f "$_xo.ldv"
    if [ -z "$_ll" ]; then
        # Статическую программу (нет ни одной .so — obfs) zig компонует без внешнего ld.lld, и экспортов у неё нет:
        # оставляем как есть. С .so строки быть обязано — иначе громко, но сборку не роняем: программа рабочая.
        case " $* " in *.so*) echo "build-libs: нет строки ld.lld для $_xo в выводе zig cc -v — оставлена без --exclude-libs" >&2 ;; esac
        return 0
    fi
    # Слова строки — как есть: без eval, чтобы $ORIGIN в -rpath остался буквальным; без подстановки имён файлов.
    ( set -f; IFS=' '; set -- $_ll; zig "$@" --exclude-libs ALL )
}

# ---- steerd и модули ------------------------------------------------------------------------------
# steerd: оптимизация по файлу (optf) — резолвер (src/dnsd) -O2, компилятор спеки, сторож, менеджер плагинов -Os.
link_app() {  # ИМЯ КЛАСС-ФЛАГИ СПИСОК-ПРОФИЛЯ
    _n="$1"; _f="$2"; _p="$3"
    _od="$OBJ/$_n"
    mkdir -p "$_od"
    _files=""
    for f in $(profile_var "$_p"); do
        # modcmd.c общий: собирается один раз с флагами steerd и берётся всеми.
        [ "$f" = "$MODCMD" ] && continue
        _files="$_files $f"
    done
    # shellcheck disable=SC2086
    compile "$_f" "$_od" $_files
    _ldi=""
    [ -z "$INTERP" ] || _ldi="-Wl,--dynamic-linker=$INTERP"
    # shellcheck disable=SC2086
    link_exe "$OUT/$_n" "$_od"/*.o "$OBJ/modcmd.o" $MEMOPS "$SO" $_ldi $RPL -Wl,--gc-sections -Wl,--as-needed
}

# shellcheck disable=SC2086
MODCMD="$(profile_var MODCMD_SRC)"
$CC $(optf "$MODCMD") $APPF -c "$MODCMD" -o "$OBJ/modcmd.o"
# STEER_EXT_ONLY=1 (build/ext-build.sh) — только библиотеки и внешние модули: steerd и модули steer
# внешнему модулю не нужны, их пакеты собирает build.sh steer.
if [ -z "${STEER_EXT_ONLY:-}" ]; then
link_app steerd "$APPF" PROFILE_steerd
fi

# ---- net1 и плагины протоколов (раскладка 2.1) ----------------------------------------------------
if [ -z "${STEER_EXT_ONLY:-}" ]; then
    N1MAP=build/net1/libs2p-net.map
    # Заголовок переименования: по строке `#define имя s2p_имя` на каждое имя карты, кроме родных
    # s2p_net_* (src/net1/s2pnet.h). Подключается ключом -include и к net1, и к плагинам на ней: те и
    # другие видят одни и те же имена, а исходники не меняются.
    N1H="$OBJ/s2p-names.h"
    {
        echo "/* Порождён build/build-libs.sh из $N1MAP — не править. */"
        sed -n 's/^ *s2p_\([A-Za-z0-9_]*\);$/\1/p' "$N1MAP" | grep -v '^net_' |
            awk '{print "#define " $1 " s2p_" $1}'
    } > "$N1H"
    N1DIR="$OUT/plugins/net1/lib"
    mkdir -p "$N1DIR" "$OBJ/net1"
    # Флаги — как у libsteer (тот же стек, тот же горячий путь), без STEER_LIBSTEER: реестра видов в
    # net1 нет. Видимость задаёт карта (local: *). wolfSSL и ngtcp2 с 2.1.4 — не копией внутри, а общие
    # библиотеки ядра (libsteer-wolfssl.so, libsteer-ngtcp2.so, DT_NEEDED): net1 их имён не экспортирует и
    # не переименовывает — в процессе steerd это те же самые библиотеки, что у libsteer. Какая сборка ядра
    # годится, net1 объявляет осью compat.steer-crypto (plugins/net1/plugin.json, build/wolfssl/crypto.lst);
    # SC_ABI_NET1 — строка отказа сверки размеров (scrypto.c, sc_abi_check) называет net1.
    # -Wno-address: src/lib/sockmark.h спрашивает слабую `plat` (стенды без платформы), а под
    # переименованием это уже сильная s2p_plat — проверка верна, но gcc предупреждает о ней.
    # TLS — модель по умолчанию (global-dynamic), а НЕ initial-exec, как у libsteer: net1 грузят не
    # только программы протоколов при запуске (DT_NEEDED), но и steerd dlopen'ом — вместе с .so-плагином
    # ядра, которому net1 нужен (steer-abi). У библиотеки, загруженной dlopen, места в статическом блоке
    # TLS процесса нет (__thread net1 — десятки КиБ: буферы рукопожатия TLS), и initial-exec там — отказ
    # загрузчика «cannot allocate memory in static TLS block» (glibc) или порча (musl). Цена невелика:
    # __thread в net1 — static, и для них компилятор берёт local-dynamic (одна база модуля на функцию,
    # дальше смещения), а таблицы потока стека и без того — указатели в куче (src/tunnel/stack.c).
    # Проверка — tests/libs-test.sh, «net1 в процессе steerd».
    N1F="-Wno-address -DSC_ABI_NET1 $NOUNW -fPIC -fno-semantic-interposition -ffunction-sections -fdata-sections \
         -Wall -Wextra -include $OBJ/steer_version.h -include $N1H $STEER_INC $THIRD_DEFS"
    N1_PLAIN=""
    for f in $(profile_var PROFILE_net1); do
        case " $CRYPTO $QUIC_ALL " in *" $f "*) ;; *) N1_PLAIN="$N1_PLAIN $f" ;; esac
    done
    # shellcheck disable=SC2086
    compile "$N1F" "$OBJ/net1" $N1_PLAIN
    # shellcheck disable=SC2086
    $CC $(optf "$CRYPTO") $N1F $WCFLAGS -c "$CRYPTO" -o "$OBJ/net1/$(echo "$CRYPTO" | tr / _).o"
    for f in $(profile_var NET1_QUIC_SRC); do
        case " $QUIC_SSL " in *" $f "*) _wc="$WCFLAGS" ;; *) _wc="" ;; esac
        # shellcheck disable=SC2086
        $CC $(optf "$f") $N1F $NGCFLAGS $_wc -c "$f" -o "$OBJ/net1/$(echo "$f" | tr / _).o"
    done
    N1SO="$N1DIR/libs2p-net.so.1"
    # wolfSSL и ngtcp2 — общими библиотеками ядра (DT_NEEDED, ищутся в /usr/lib). -z defs: ссылки наружу —
    # только libc и они.
    # shellcheck disable=SC2086
    $CC -shared -o "$N1SO" "$OBJ"/net1/*.o $MEMOPS "$NGSO" "$WSO" \
        -Wl,-soname,libs2p-net.so.1 -Wl,--version-script="$N1MAP" \
        -Wl,-Bsymbolic -Wl,--gc-sections $ZDEFS -Wl,-z,relro $LDX $STRIPF $LIBS

    # plug ИМЯ — плагин протокола: код протокола и разбор спеки статически, стек — из net1.
    # RUNPATH ставит компоновщик ($ORIGIN/../../net1/lib, plugin-sdk/docs/manifest.md, «libs»).
    _ldi=""
    [ -z "$INTERP" ] || _ldi="-Wl,--dynamic-linker=$INTERP"
    # Вид: 1 — на net1; 0 — статически без TLS; tls — свой TLS статически, wolfSSL — общая библиотека ядра
    # libsteer-wolfssl.so (как у net1, ось compat.steer-crypto; до 2.1.4 — своя копия, 0,7 МБ на mipsel).
    plug() {
        _n="$1"; _net="$2"
        _od="$OBJ/plug-$_n"; _pd="$OUT/plugins/$_n/bin"
        mkdir -p "$_od" "$_pd"
        if [ "$_net" = 1 ]; then _pf="$APPF -Wno-address -include $N1H"; else _pf="$APPF"; fi
        _ps=""
        for f in $(profile_var "PROFILE_plug_$_n"); do
            [ "$_net" = tls ] && [ "$f" = "$CRYPTO" ] && continue
            _ps="$_ps $f"
        done
        # shellcheck disable=SC2086
        compile "$_pf" "$_od" $_ps
        if [ "$_net" = tls ]; then
            # shellcheck disable=SC2086
            $CC $(optf "$CRYPTO") $_pf -DSC_ABI_TGWS $WCFLAGS -c "$CRYPTO" -o "$_od/$(echo "$CRYPTO" | tr / _).o"
            # shellcheck disable=SC2086
            link_exe "$_pd/$_n" "$_od"/*.o $MEMOPS "$WSO" $_ldi $RPL -Wl,--gc-sections -Wl,--as-needed
        elif [ "$_net" = 1 ]; then
            # shellcheck disable=SC2086
            link_exe "$_pd/$_n" "$_od"/*.o $MEMOPS "$N1SO" '-Wl,-rpath,$ORIGIN/../../net1/lib' $_ldi $RPL \
                -Wl,--gc-sections -Wl,--as-needed
        else
            # shellcheck disable=SC2086
            link_exe "$_pd/$_n" "$_od"/*.o $MEMOPS $_ldi -Wl,--gc-sections
        fi
    }
    for _p in $(profile_var PLUGINS_NET1); do plug "$_p" 1; done
    for _p in $(profile_var PLUGINS_STATIC); do plug "$_p" 0; done
    for _p in $(profile_var PLUGINS_TLS); do plug "$_p" tls; done
fi

# Внешние модули (STEER_EXT_APPS="имя:каталог …"): бинарники из исходников ВНЕ этого дерева.
# Собираются теми же флагами и с той же libsteer, что модули steer, и берут у неё только то, что
# она экспортирует модулям дерева. Зовёт их сборка build/ext-build.sh.
_eldi=""
[ -z "$INTERP" ] || _eldi="-Wl,--dynamic-linker=$INTERP"
# STEER_EXT_STATIC=1 (ext-build.sh --static) — программа плагина без libsteer: свои исходники, EXT_TLS_SRC
# дерева steer и wolfSSL статически (как tgws, PLUGINS_TLS), от системы — только libc. Так собирается плагин
# box-connector: связь с libsteer.so.<версия> привязала бы его к одной версии ядра.
if [ -n "${STEER_EXT_STATIC:-}" ] && [ -n "${STEER_EXT_APPS:-}" ]; then
    _xod="$OBJ/ext-tls"
    mkdir -p "$_xod"
    _xs=""
    for f in $(profile_var EXT_TLS_SRC); do [ "$f" = "$CRYPTO" ] || _xs="$_xs $f"; done
    # shellcheck disable=SC2086
    compile "-O2 $APPF" "$_xod" $_xs
    # shellcheck disable=SC2086
    $CC -O2 $APPF $WCFLAGS -c "$CRYPTO" -o "$_xod/$(echo "$CRYPTO" | tr / _).o"
fi
for _ea in ${STEER_EXT_APPS:-}; do
    _en="${_ea%%:*}"; _ed="${_ea#*:}"
    _eod="$OBJ/ext-$_en"
    mkdir -p "$_eod"
    # shellcheck disable=SC2046,SC2086
    compile "-O2 $APPF -I$_ed" "$_eod" $(ls "$_ed"/*.c)
    if [ -n "${STEER_EXT_STATIC:-}" ]; then
        # shellcheck disable=SC2086
        $CC -o "$OUT/$_en" "$_eod"/*.o "$_xod"/*.o "$WLIB" $_eldi -Wl,--gc-sections -s $LIBS
        continue
    fi
    # shellcheck disable=SC2086
    $CC -o "$OUT/$_en" "$_eod"/*.o "$OBJ/modcmd.o" "$SO" $_eldi $RPL \
        -Wl,--gc-sections -Wl,--as-needed -s $LIBS
done

# Клиент сокета `steer` — по-прежнему статический (build.sh собирает его сам).
echo "libs: готово в $OUT (раскладка 2.1: libsteer.so.$VERSION, libsteer-wolfssl.so.$WVER, libsteer-ngtcp2.so.$NGTAG, steerd, net1, плагины $(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC) $(profile_var PLUGINS_TLS)${STEER_EXT_APPS:+, внешние: $STEER_EXT_APPS})"
