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
env CC="$CC" AR="$AR" CFLAGS="-O2 -fPIC -ffunction-sections -fdata-sections" \
    sh build/wolfssl/build.sh "$WOLFSSL_DIR" "$WLIB" asm
WCFLAGS="$(cat "$WLIB.cflags")"

# shellcheck disable=SC2086
$CC -O2 -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -Wall -Wextra \
    -Isrc/lib $WCFLAGS -c build/wolfssl/abi.c -o "$OBJ/abi.o"
# Экспортируется из библиотеки ровно то, что зовёт слой src/lib/scrypto.c (и отпечаток сборки):
# список лежит в дереве (build/wolfssl/libsteer-wolfssl.map), а `sh build/libs-exports.sh check`
# сверяет его с неопределёнными символами объекта слоя. Забытый символ ловит и сама сборка:
# libsteer.so не слинкуется (-z defs). Список — файлом, а не вычисляется здесь, потому что nm в
# образе сборщика нет (там только zig), а состав символов от архитектуры не зависит.
WMAP="build/wolfssl/libsteer-wolfssl.map"

# ---- ngtcp2: статический архив с -fPIC (шаг 7) ----------------------------------------------------
# Исходники — с нашим патчем Brutal (build/ngtcp2/fetch.sh; в образе сборщика — /opt/ngtcp2), рецепт —
# build/ngtcp2/build.sh: те же флаги, что у архива wolfSSL. Архив идёт в libsteer.so, а не в
# отдельную библиотеку: у неё один потребитель за раз, а пакет с ещё одной .so на флеше 7 МБ —
# лишний (docs/architecture.md, «Туннели»). Криптобэкенд ngtcp2 зовёт wolfSSL_*, они берутся из
# libsteer-wolfssl.so (список экспорта — build/libs-exports.sh).
NGTCP2_DIR="${NGTCP2_DIR:-/opt/ngtcp2}"
NGLIB="$OUT/ngtcp2-pic/$WTAG/libngtcp2.a"
env CC="$CC" AR="$AR" CFLAGS="-Os -fPIC -ffunction-sections -fdata-sections" \
    sh build/ngtcp2/build.sh "$NGTCP2_DIR" "$WOLFSSL_DIR" "$NGLIB"
NGCFLAGS="$(cat "$NGLIB.cflags")"

# ---- libsteer.so ---------------------------------------------------------------------------------
# -O2: через эти файлы идёт весь трафик туннеля (шифр, стек, транспорты), и -Os тут стоил бы
# скорости (тот же довод, что у прежней расширенной сборки, build/build-ext.sh).
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
LIBF="-O2 -fPIC -fno-semantic-interposition -ftls-model=initial-exec -ffunction-sections -fdata-sections \
      -DSTEER_LIBSTEER -Wall -Wextra -include $OBJ/steer_version.h $STEER_INC $THIRD_DEFS"
APPF="-Wall -Wextra -include $OBJ/steer_version.h $STEER_INC $THIRD_DEFS -ffunction-sections -fdata-sections"

# compile КЛАСС ФЛАГИ КАТАЛОГ ФАЙЛЫ… — параллельно; отказ любого файла — отказ сборки.
compile() {
    _f="$1"; _d="$2"; shift 2
    printf '%s\n' "$@" | CCF="$_f" OD="$_d" xargs -P "$J" -I{} \
        sh -c '$CC $CCF -c "$1" -o "$OD/$(echo "$1" | tr / _).o"' _ {}
}

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
$CC $LIBF $WCFLAGS -c "$CRYPTO" -o "$OBJ/lib/$(echo "$CRYPTO" | tr / _).o"
# Обёртка QUIC: заголовки ngtcp2 — обоим файлам, wolfSSL — только тому, что ему положено (QUIC_SSL_SRC).
for f in $QUIC_ALL; do
    case " $QUIC_SSL " in *" $f "*) _wc="$WCFLAGS" ;; *) _wc="" ;; esac
    # shellcheck disable=SC2086
    $CC $LIBF $NGCFLAGS $_wc -c "$f" -o "$OBJ/lib/$(echo "$f" | tr / _).o"
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
$CC -shared -o "$WSO" "$OBJ/abi.o" -Wl,--whole-archive "$WLIB" -Wl,--no-whole-archive \
    -Wl,-soname,"libsteer-wolfssl.so.$WVER" -Wl,--version-script="$WMAP" -Wl,--gc-sections \
    $ZDEFS -Wl,-z,relro -s $LIBS

SO="$OUT/libsteer.so.$VERSION"
# shellcheck disable=SC2086
$CC -shared -o "$SO" "$OBJ"/lib/*.o "$NGLIB" "$WSO" \
    -Wl,-soname,"libsteer.so.$VERSION" -Wl,--version-script="$LIB_MAP" \
    -Wl,-Bsymbolic -Wl,--gc-sections $ZDEFS -Wl,-z,relro -s $LIBS

# ---- steerd и модули ------------------------------------------------------------------------------
# steerd и модули: -O2 (I-540) — размер пакета больше не главная цель, а в steerd работают разбор
# спеки, сторож и резолвер; в xsteer через xsclient.c идёт поток пакетов звезды.
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
    $CC -o "$OUT/$_n" "$_od"/*.o "$OBJ/modcmd.o" "$SO" $_ldi $RPL \
        -Wl,--gc-sections -Wl,--as-needed -s $LIBS
}

# shellcheck disable=SC2086
MODCMD="$(profile_var MODCMD_SRC)"
$CC -O2 $APPF -c "$MODCMD" -o "$OBJ/modcmd.o"
# STEER_EXT_ONLY=1 (build/ext-build.sh) — только библиотеки и внешние модули: steerd и модули steer
# внешнему модулю не нужны, их пакеты собирает build.sh steer.
if [ -z "${STEER_EXT_ONLY:-}" ]; then
link_app steerd "-O2 $APPF" PROFILE_steerd
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
    # net1 нет. Видимость задаёт карта (local: *), поэтому и wolfSSL, и ngtcp2 из архивов остаются
    # внутри библиотеки.
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
    N1F="-Wno-address -O2 -fPIC -fno-semantic-interposition -ffunction-sections -fdata-sections \
         -Wall -Wextra -include $OBJ/steer_version.h -include $N1H $STEER_INC $THIRD_DEFS"
    N1_PLAIN=""
    for f in $(profile_var PROFILE_net1); do
        case " $CRYPTO $QUIC_ALL " in *" $f "*) ;; *) N1_PLAIN="$N1_PLAIN $f" ;; esac
    done
    # shellcheck disable=SC2086
    compile "$N1F" "$OBJ/net1" $N1_PLAIN
    # shellcheck disable=SC2086
    $CC $N1F $WCFLAGS -c "$CRYPTO" -o "$OBJ/net1/$(echo "$CRYPTO" | tr / _).o"
    for f in $(profile_var NET1_QUIC_SRC); do
        case " $QUIC_SSL " in *" $f "*) _wc="$WCFLAGS" ;; *) _wc="" ;; esac
        # shellcheck disable=SC2086
        $CC $N1F $NGCFLAGS $_wc -c "$f" -o "$OBJ/net1/$(echo "$f" | tr / _).o"
    done
    N1SO="$N1DIR/libs2p-net.so.1"
    # wolfSSL — архивом целиком (--whole-archive не нужен: тянется только то, что зовут scrypto.c,
    # qcssl.c и ngtcp2), ngtcp2 — тоже архивом. -z defs: у net1 нет ни одной ссылки наружу, кроме libc.
    # shellcheck disable=SC2086
    $CC -shared -o "$N1SO" "$OBJ"/net1/*.o "$NGLIB" "$WLIB" \
        -Wl,-soname,libs2p-net.so.1 -Wl,--version-script="$N1MAP" \
        -Wl,-Bsymbolic -Wl,--gc-sections $ZDEFS -Wl,-z,relro -s $LIBS

    # plug ИМЯ — плагин протокола: код протокола и разбор спеки статически, стек — из net1.
    # RUNPATH ставит компоновщик ($ORIGIN/../../net1/lib, plugin-sdk/docs/manifest.md, «libs»).
    _ldi=""
    [ -z "$INTERP" ] || _ldi="-Wl,--dynamic-linker=$INTERP"
    # Вид: 1 — на net1; 0 — статически без TLS; tls — статически со своим TLS и wolfSSL (архив с -fPIC тот
    # же, что у библиотек: лишнего в программу не попадает, --gc-sections).
    plug() {
        _n="$1"; _net="$2"
        _od="$OBJ/plug-$_n"; _pd="$OUT/plugins/$_n/bin"
        mkdir -p "$_od" "$_pd"
        if [ "$_net" = 1 ]; then _pf="-O2 $APPF -Wno-address -include $N1H"; else _pf="-O2 $APPF"; fi
        _ps=""
        for f in $(profile_var "PROFILE_plug_$_n"); do
            [ "$_net" = tls ] && [ "$f" = "$CRYPTO" ] && continue
            _ps="$_ps $f"
        done
        # shellcheck disable=SC2086
        compile "$_pf" "$_od" $_ps
        if [ "$_net" = tls ]; then
            # shellcheck disable=SC2086
            $CC $_pf $WCFLAGS -c "$CRYPTO" -o "$_od/$(echo "$CRYPTO" | tr / _).o"
            # shellcheck disable=SC2086
            $CC -o "$_pd/$_n" "$_od"/*.o "$WLIB" $_ldi -Wl,--gc-sections -s $LIBS
        elif [ "$_net" = 1 ]; then
            # shellcheck disable=SC2086
            $CC -o "$_pd/$_n" "$_od"/*.o "$N1SO" '-Wl,-rpath,$ORIGIN/../../net1/lib' $_ldi \
                -Wl,--gc-sections -Wl,--as-needed -s $LIBS
        else
            # shellcheck disable=SC2086
            $CC -o "$_pd/$_n" "$_od"/*.o $_ldi -Wl,--gc-sections -s $LIBS
        fi
    }
    for _p in $(profile_var PLUGINS_NET1); do plug "$_p" 1; done
    for _p in $(profile_var PLUGINS_STATIC); do plug "$_p" 0; done
    for _p in $(profile_var PLUGINS_TLS); do plug "$_p" tls; done
fi

# Внешние модули (STEER_EXT_APPS="имя:каталог …"): бинарники из исходников ВНЕ этого дерева —
# steer-box-connector (sing-box). Собираются теми же флагами и с той же libsteer, что модули
# steer, а нужные им символы библиотека экспортирует по build/exports-ext.lst. Зовёт их сборка
# build/ext-build.sh.
_eldi=""
[ -z "$INTERP" ] || _eldi="-Wl,--dynamic-linker=$INTERP"
for _ea in ${STEER_EXT_APPS:-}; do
    _en="${_ea%%:*}"; _ed="${_ea#*:}"
    _eod="$OBJ/ext-$_en"
    mkdir -p "$_eod"
    # shellcheck disable=SC2046,SC2086
    compile "-O2 $APPF -I$_ed" "$_eod" $(ls "$_ed"/*.c)
    # shellcheck disable=SC2086
    $CC -o "$OUT/$_en" "$_eod"/*.o "$OBJ/modcmd.o" "$SO" $_eldi $RPL \
        -Wl,--gc-sections -Wl,--as-needed -s $LIBS
done

# Клиент сокета `steer` — по-прежнему статический (build.sh собирает его сам).
echo "libs: готово в $OUT (раскладка 2.1: libsteer.so.$VERSION, libsteer-wolfssl.so.$WVER, steerd, net1, плагины $(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC) $(profile_var PLUGINS_TLS)${STEER_EXT_APPS:+, внешние: $STEER_EXT_APPS})"
