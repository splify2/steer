#!/bin/sh
# Builds one static musl binary per OpenWrt architecture and packages it.
#
# Same zig cross-toolchain splify uses: a static binary means no libc version to
# match against the router's, and one build serves every OpenWrt release for that
# ISA.
set -eu

VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0)"

# В VERSION только цифры и точки. Этой строкой собираются имя файла пакета
# (`steer-extended-26.9-1_<арх>.apk`), версия для apk/opkg и тег релиза — пробелу и буквам там
# места нет ни в одном из трёх мест. Заодно её читает интерфейс splify2 через менеджер пакетов и
# сравнивает с релизами; версия с буквами в этом сравнении оказалась бы несравнимой.
#
# Кодовое имя выпуска («26.9 Andromeda») живёт в ЗАГОЛОВКЕ релиза на GitHub: оттуда его читает
# splify2 и показывает человеку. В имени пакета ему места нет.
#
# Число составляющих НЕ проверяется: «26.9» — такая же законная версия, как «1.2.0», и требовать
# три части значило бы отвергать собственный выпуск.
case "$VERSION" in
    ''|*[!0-9.]*)
        echo "в VERSION только цифры и точки, а там: «$VERSION»" >&2
        echo "кодовое имя выпуска задаётся заголовком релиза на GitHub, а не файлом VERSION" >&2
        exit 1 ;;
esac
# Ревизия сборки: чем этот бинарник отличается от релиза с тем же номером версии. Версия
# между релизами не меняется, поэтому релизный движок и движок из main через два коммита
# после него назывались одним числом, и на стенде два РАЗНЫХ бинарника отчитывались как
# «0.9.6-r1» (R-045/I-054). Печатает её `steer --version`; имена пакетов и версия пакета не
# затронуты намеренно — интерфейс версию берёт от менеджера пакетов.
#
# Считается ЗДЕСЬ, а не внутри docker: в образе нет ни git, ни каталога .git — смонтирован
# только рабочий каталог, — и describe там вернул бы пустоту при любом состоянии дерева.
#
# Без `--dirty`, в отличие от Makefile: релизный workflow сам записывает номер в VERSION
# ПЕРЕД сборкой и коммитит его после (см. .github/workflows/release.yml), поэтому дерево во
# время релизной сборки грязное всегда, и флаг помечал бы «-dirty» каждый релиз — то есть
# перестал бы что-либо значить.
#
# Не на теге — номер из VERSION и коммит («2.0.0-g32b3a4b»), а не describe от последнего тега:
# тот давал «v1.5.9-239-g…» у сборки 2.0.0, ещё не помеченной тегом, и читался как 1.5.9.
REV="$(git describe --tags --exact-match 2>/dev/null ||
      { _h="$(git rev-parse --short HEAD 2>/dev/null)" && echo "$VERSION-g$_h"; } || true)"
[ -n "$REV" ] || REV="неизвестна"
OUT=out
# Сколько частей сборки не собралось (FAILED в выводе) — код возврата в конце.
fails=0
# Предупреждения компилятора (-Wall -Wextra) удачных сборок — для итоговой строки.
warns=0
# Свой образ, а не образ сборщика splify: в том нет исходников криптобиблиотеки, и расширенная
# сборка в нём падает на ненайденном заголовке, тогда как базовая проходит. Незаметная поломка:
# `./build.sh` печатает архитектуры, пакеты появляются, и только extended молча отсутствует.
# Тег — по библиотеке: steer-builder:wolfssl (build/Dockerfile); прежний steer-builder:mbedtls
# с mbedtls 3.6.2 этой сборке не годится — в нём нет исходников wolfSSL.
IMAGE="${STEER_BUILDER_IMAGE:-steer-builder:wolfssl}"

# Снять каталог выхода libs. Его создаёт docker (от root), и на машине без root (GitHub Actions)
# `rm -rf` снаружи падал «Permission denied» — а при set -e это роняло всю сборку. Снимаем внутри
# контейнера; обычный rm — для каталога, который и так наш. Не вышло — возврат 1, решает вызывающий.
rm_libs() {
    rm -rf "$1" 2>/dev/null || true
    [ -e "$1" ] || return 0
    docker run --rm -v "$PWD:/src" --entrypoint rm "$IMAGE" -rf "/src/$1" >/dev/null 2>&1 || true
    [ ! -e "$1" ]
}

# Предупреждения удачной сборки. Файл stderr компилятора раньше читали только при провале
# (grep error), и на успехе -Wall -Wextra не видел никто: предупреждение жило, пока его не
# превращали в ошибку. Здесь — число и первые три строки, остальное лежит в самом файле; ничего
# не печатается, если предупреждений нет, чтобы тихий вывод по строке на архитектуру остался тихим.
warn_report() {  # ФАЙЛ_STDERR
    _wn="$(grep -c 'warning:' "$1" 2>/dev/null || true)"
    [ "${_wn:-0}" -gt 0 ] || return 0
    warns=$((warns + _wn))
    printf '    предупреждений: %s (подробно — %s)\n' "$_wn" "$1"
    grep -m3 'warning:' "$1" | sed 's/^/      /'
}

# Собрать образ, если его нет. Иначе первая же сборка на чужой машине упирается в
# «Unable to find image», и человек ищет, откуда его взять, — а он описан прямо здесь,
# в build/Dockerfile.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "образ $IMAGE отсутствует — собираю из build/Dockerfile"
    docker build -t "$IMAGE" build/ || { echo "не удалось собрать образ"; exit 1; }
fi

# id:target:mcpu — the ISAs OpenWrt actually ships. Package arch names below map
# several OpenWrt targets onto one ISA build, which is why the two lists differ.
# Два варианта одного движка, как dnsmasq и dnsmasq-full: базовый и с клиентом
# VLESS/Reality. Базовому VLESS не нужен, а весит он вместе с TLS-стеком больше самого
# движка — и на 4C с 6.9 МБ overlay это решает, влезет ли пакет.
#
# Собираются из ОДНИХ исходников: extended это те же файлы плюс src/tunnel, src/proto и wolfSSL.
# Разные бинарники из разного набора файлов означали бы два места, где чинить одну ошибку.
# Списки файлов всех сборок — в build/sources.mk и только там; build/build-ext.sh читает тот же
# манифест сам (он запускается отдельным процессом и отсюда ничего не наследует).
. ./build/sources.sh
BASE_SRC="$(profile_src base)" || exit 2
BASE_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
# Определения стороннего кода в ядре (libyaml: -DHAVE_CONFIG_H) — см. THIRD_DEFS в sources.mk.
THIRD_DEFS="$(profile_var THIRD_DEFS)" || exit 2
# Клиент сокета `steer` — второй бинарник пакета (docs/architecture.md, раздел 4а, «Бинарники»):
# движок — steerd, а под именем steer его зовут rpcd splify2, init-скрипт и человек. Клиент один
# на оба пакета (в нём нет ни видов, ни протоколов), собирается один раз на архитектуру.
CLIENT_SRC="$(profile_var CLIENT_SRC)" || exit 2

. ./build/arches.sh

# ТРИ РАЗНОВИДНОСТИ CORTEX-A9, А НЕ ОДНА, и выбирать из них нельзя: OpenWrt публикует именно
# три, и пакет под чужую роутер не поставит — apk и opkg сверяют архитектуру по имени.
#
#   arm_cortex-a9            без блока с плавающей точкой, отсюда musleabi (мягкая ABI);
#                            так собран bcm53xx — Netgear R7000, Asus RT-AC68U и родня;
#   arm_cortex-a9_neon       NEON и жёсткая ABI: imx6, oxnas, zynq;
#   arm_cortex-a9_vfpv3-d16  VFPv3-D16 и жёсткая ABI: mvebu — Linksys WRT1200/1900,
#                            Turris Omnia.
#
# Мягкость ABI задаёт ТРИПЛЕТ (musleabi против musleabihf), а не ключ -mcpu: `cortex_a9+soft_float`
# zig не принимает вовсе (проверено сборкой), и пытаться выразить её признаком процессора
# значило бы получить пакет с чужой ABI, который встанет и упадёт на первом же вызове.

# Во время отладки собирать все шесть архитектур незачем: это три бинарника на каждую и около
# десяти минут ожидания. STEER_ARCH сужает список до нужной — полная сборка нужна только перед
# выкладкой пакетов.
if [ -n "${STEER_ARCH:-}" ]; then
    ISAS="$(printf '%s\n' "$ISAS" | grep "^${STEER_ARCH}:")"
    [ -n "$ISAS" ] || { echo "неизвестная архитектура: $STEER_ARCH" >&2; exit 1; }
fi

mkdir -p "$OUT" build/pkg

# ---- загрузчик musl для динамических бинарников (steerd, модули) -----------------------------
#
# Статическому бинарнику загрузчик не нужен, динамическому он вшит в файл ПУТЁМ, и путь обязан
# совпасть с тем, что лежит на роутере: musl называет загрузчик по архитектуре и по ABI —
# ld-musl-<арх>[hf|-sf].so.1. Умолчание zig этого не различает (мягкая плавающая точка MIPS и
# hard-float ARM получили бы имя без суффикса), поэтому задаём явно по тройке цели; тот же
# суффикс определяет, какая из трёх сборок Cortex-A9 у нас (musleabi против musleabihf, см. выше).
# RPATH не нужен: библиотеки лежат в /usr/lib, где musl ищет сам.
# interp_of — в build/arches.sh (его берут и внешние модули).

# ---- две упаковки одного пакета: apk и opkg ----------------------------------
#
# OpenWrt перешёл на apk в 24.10, но 23.05 и 22.03 живут на роутерах и будут жить: на
# 4/32 их никто не обновит, а именно там движок и нужнее всего. Собирать пакет только в
# новом формате значит отрезать половину устройств, ради которых он написан.
#
# Оба формата делаются из ОДНОГО дерева файлов ($root / $eroot), а не из двух: разные
# деревья означали бы пакет, который на одном формате работает, а на другом нет, и
# заметить это можно было бы только на роутере. Отличаются они только метаданными.
#
# ipkg-build — родной скрипт OpenWrt, тот же, что собирает пакеты в их SDK. Берётся из
# сети один раз, закреплённой версией (коммит и sha256 ниже), и кладётся в build/ (см. .gitignore): переписывать его своими руками
# значило бы получить .ipk, который opkg принимает не везде, — ровно та ошибка, на
# которой в splify обжигались с po2lmo.
IPKG=build/ipkg-build
if [ ! -x "$IPKG" ]; then
    echo "качаю ipkg-build из OpenWrt"
    # ДВА ИСТОЧНИКА, а не один, и по той же причине, по которой пакеты выкладываются в
    # ветку dist (splify2#15): `raw.githubusercontent.com` у части провайдеров закрыт
    # целиком, а хосты самого GitHub — другая сеть и работают. `api.github.com` с
    # заголовком `Accept: application/vnd.github.raw` отдаёт тот же файл байтами, никуда не
    # перенаправляя. Это машина сборщика, а не роутер, но человек с закрытым доменом не мог
    # собрать пакеты вовсе, и сообщение об этом ничем не отличалось от «сеть отвалилась».
    # ВЕРСИЯ ЗАКРЕПЛЕНА (I-540): коммит openwrt/openwrt и сумма файла. Скрипт из ветки master
    # менялся бы под сборкой без нашего ведома, а чужой код в цепочке выпуска без суммы — дыра:
    # сумма проверяется ПОСЛЕ скачивания, и несошедшийся файл не кладётся в build/.
    IPKG_COMMIT=e36c2946b7b574504335ff517b19b7c1eedf1bd8
    IPKG_SHA256=5a85d59b6656074015bc20add788993143f7b51f371f977b5286af9ed5f22f5b
    RAW=https://raw.githubusercontent.com/openwrt/openwrt/$IPKG_COMMIT/scripts/ipkg-build
    API="https://api.github.com/repos/openwrt/openwrt/contents/scripts/ipkg-build?ref=$IPKG_COMMIT"
    ACCEPT='Accept: application/vnd.github.raw'
    IPKG_TMP="$IPKG.part"
    # curl или wget: на машине сборщика бывает любой из двух, а требовать конкретный
    # значит уронить сборку там, где всё для неё есть.
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$RAW" -o "$IPKG_TMP" ||
        curl -fsSL -H "$ACCEPT" "$API" -o "$IPKG_TMP" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$IPKG_TMP" "$RAW" ||
        wget -qO "$IPKG_TMP" --header="$ACCEPT" "$API" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    else
        echo "нужен curl или wget, чтобы взять ipkg-build"; exit 1
    fi
    got="$(sha256sum "$IPKG_TMP" | cut -d' ' -f1)"
    if [ "$got" != "$IPKG_SHA256" ]; then
        rm -f "$IPKG_TMP"
        echo "ipkg-build: сумма $got, ожидалась $IPKG_SHA256 (коммит $IPKG_COMMIT)"; exit 1
    fi
    mv "$IPKG_TMP" "$IPKG"
    chmod +x "$IPKG"
fi

# ---- зависимости пакета: не список в голове, а свойство собранного файла ------
#
# Три вещи, которых движку не хватает самому по себе, и все три до сих пор не были
# объявлены — то есть проверить их было нечем, а узнавал о них человек по молчаливо
# неработающей половине.
#
#   nftables, ip-full  — правила и `ip rule`; объявлены с самого начала.
#   kmod-nft-queue     — выражение `queue` в наборе правил: им модуль DPI (recheck)
#                        отдаёт помеченный трафик своему обработчику. Без модуля ядро
#                        отвергает правило, а `nft -f` атомарен — то есть один такой выход
#                        снимает маршрутизацию ЦЕЛИКОМ, сообщением «No such file or
#                        directory» с указателем на слово queue (проверено на роутере,
#                        OpenWrt 25.12 / nftables 1.1.6). Модуль весит единицы килобайт;
#                        цена объявить его всем несравнимо меньше цены такого отказа.
#   conntrack          — снятие установленных соединений выхода при смене маршрута
#                        (src/daemon/failover.c, conntrack_evict). Снимает их сам движок, через
#                        ctnetlink, а инструмент — запасной путь на случай, когда ядро по
#                        ctnetlink не отвечает (нет модуля nf_conntrack_netlink). Без
#                        обоих движок предупреждает и работает дальше, но при включённой выгрузке
#                        потоков это значит, что уже установленное соединение маршрут
#                        больше не пересматривает — и запрет on_fail=drop до него не
#                        доходит (H-110, R-096). Предупреждение в журнале читают редко,
#                        а зависимость проверяет менеджер пакетов при установке.
#   kmod-tun           — модулям, которые сами создают TUN (steer-vless, steer-xsteer, steer-hysteria2, steer-proxy).
#
# Библиотек среди зависимостей нет: libsteer.so и libsteer-wolfssl.so лежат ВНУТРИ пакета
# steer-core (у них один владелец и один срок жизни с движком), а модули, связанные с ними по
# DT_NEEDED, получают их зависимостью от steer-core. Системный libwolfssl OpenWrt тут не
# подходит нарочно: его SONAME несёт хеш опций и меняется с каждым обновлением, а QUIC в нём нет.
pkg_deps() {  # ФАЙЛ_БИНАРНИКА ВИД (core|mod|tun) -> "nftables ip-full ..." через пробел
    case "$2" in
        core) _pd="nftables ip-full conntrack kmod-nft-queue" ;;
        tun)  _pd="kmod-tun" ;;
        *)    _pd="" ;;
    esac
    printf '%s' "$_pd"
}

# ---- зависимости между НАШИМИ пакетами: точная версия --------------------------------
#
# Формат событий между движком и модулями, ABI libsteer и раскладка libsteer-wolfssl между
# выпусками не обещаются, поэтому модуль той же версии, что движок, — не
# пожелание, а условие: `steer-vless` зависит от `steer-core (= версия)`. Менеджер пакетов не даст
# обновить один, оставив другой (apk — `имя=версия`, opkg — `имя (= версия)`). Чужие пакеты
# (nftables, kmod-…) остаются без версии. Демон дополнительно проверяет версию при запуске модуля
# (hello, docs/ctl.md) — на случай установки файлами мимо менеджера.
OURS=" steer-core steer-vless steer-xsteer steer-obfs steer-hysteria2 steer-proxy steer-warpbox steer-extended "
dep_apk() {  # ИМЕНА через пробел -> "имя=версия ..." для наших
    for _d in $1; do
        case "$OURS" in *" $_d "*) printf '%s=%s-r1 ' "$_d" "$VERSION" ;; *) printf '%s ' "$_d" ;; esac
    done
}
dep_ipk() {  # ИМЕНА через пробел -> "имя (= версия), ..." для наших
    _sep=""
    for _d in $1; do
        case "$OURS" in
            *" $_d "*) printf '%s%s (= %s-1)' "$_sep" "$_d" "$VERSION" ;;
            *)         printf '%s%s' "$_sep" "$_d" ;;
        esac
        _sep=", "
    done
}

# mk_ipk КОРЕНЬ ИМЯ АРХ ЗАВИСИМОСТИ ОПИСАНИЕ [ДОПОЛНИТЕЛЬНЫЕ ПОЛЯ CONTROL] [СКРИПТЫ]
#
# СКРИПТЫ — префикс файлов build/scripts (умолчание «steer»: steer.postinst, steer.prerm).
# Каталог CONTROL создаётся ВНУТРИ дерева пакета, поэтому зовётся строго ПОСЛЕ apk mkpkg
# по тому же дереву: иначе служебные файлы уехали бы в полезную нагрузку apk.
mk_ipk() {
    ipk_root="$1"; ipk_name="$2"; ipk_arch="$3"; ipk_dep="$4"; ipk_desc="$5"; ipk_extra="${6:-}"
    ipk_scr="${7:-steer}"
    mkdir -p "$ipk_root/CONTROL"
    {
        echo "Package: $ipk_name"
        echo "Version: $VERSION-1"
        [ -n "$ipk_dep" ] && echo "Depends: $ipk_dep"
        echo "Architecture: $ipk_arch"
        echo "Maintainer: xyzmean"
        echo "Section: net"
        [ -n "$ipk_extra" ] && printf '%s\n' "$ipk_extra"
        echo "Description: $ipk_desc"
    } > "$ipk_root/CONTROL/control"
    cp "build/scripts/$ipk_scr.postinst" "$ipk_root/CONTROL/postinst"
    # preinst — только у ядра: запомнить пакеты модулей до того, как менеджер их снимет.
    if [ -f "build/scripts/$ipk_scr.preinst" ]; then
        cp "build/scripts/$ipk_scr.preinst" "$ipk_root/CONTROL/preinst"
        chmod 0755 "$ipk_root/CONTROL/preinst"
    fi
    cp "build/scripts/$ipk_scr.prerm" "$ipk_root/CONTROL/prerm"
    cp "build/scripts/$ipk_scr.postrm" "$ipk_root/CONTROL/postrm"
    chmod 0755 "$ipk_root/CONTROL/postinst" "$ipk_root/CONTROL/prerm" "$ipk_root/CONTROL/postrm"
    # Без -o/-g: нынешний ipkg-build их не понимает (они были в старых версиях), а
    # молчаливый отказ здесь означал бы релиз без половины пакетов.
    if "$PWD/$IPKG" "$ipk_root" "$PWD/$OUT" >/dev/null 2>&1; then
        # ipkg-build называет файл через подчёркивания; приводим к тому же виду, что у
        # apk, чтобы в релизе оба формата одного пакета лежали рядом и читались одинаково.
        mv "$OUT/${ipk_name}_${VERSION}-1_${ipk_arch}.ipk" \
           "$OUT/${ipk_name}-${VERSION}-1_${ipk_arch}.ipk" 2>/dev/null || true
    else
        echo "    (ipk packaging failed for $ipk_name $ipk_arch)"
    fi
    rm -rf "$ipk_root/CONTROL"
}

# Раскладка роутера: 2.1 (умолчание) — ядро без стека протоколов, net1 и протоколы плагинами (.s2p и семя
# в steer-core, build/pack-s2p.sh); 2.0 — прежние пакеты steer-<m> на libsteer (STEER_LAYOUT=2.0).
LAYOUT="${STEER_LAYOUT:-2.1}"
PLUGS="$(profile_var PLUGINS_NET1) $(profile_var PLUGINS_STATIC) $(profile_var PLUGINS_TLS)"
echo "steer $VERSION (раскладка $LAYOUT)"
for spec in $ISAS; do
    arch=${spec%%:*}; rest=${spec#*:}
    target=${rest%%:*}; mcpu=${rest#*:}
    printf '  %-26s ' "$arch"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -DSTEER_VERSION="\"$VERSION\"" -DSTEER_REV="\"$REV\"" \
               -o "build/steerd-$arch" $BASE_INC $THIRD_DEFS $BASE_SRC \
               2>"build/$arch.err"; then
        echo "$(stat -c %s "build/steerd-$arch") bytes"
        warn_report "build/$arch.err"
    else
        # Старый бинарник обязан исчезнуть: иначе упаковка молча положит в пакет
        # сборку от прошлого раза, и ошибка компиляции превратится в «версия
        # обновилась, а поведение прежнее» — самый дорогой вид тихого сбоя.
        rm -f "build/steerd-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch.err" || head -1 "build/$arch.err")"
        fails=$((fails + 1))
        continue
    fi

    # Клиент. Без него пакета нет: /usr/sbin/steer зовут все, кто был до демона, — пакет с одним
    # steerd выглядел бы установленным, а splify2 получал бы «команда не найдена».
    printf '  %-26s ' "$arch (клиент steer)"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -o "build/steer-client-$arch" $BASE_INC $CLIENT_SRC \
               2>"build/$arch-client.err"; then
        echo "$(stat -c %s "build/steer-client-$arch") bytes"
        warn_report "build/$arch-client.err"
    else
        rm -f "build/steer-client-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-client.err" || head -1 "build/$arch-client.err")"
        fails=$((fails + 1))
        continue
    fi

    # Разделяемая раскладка роутера (шаг 4 выпуска 1.10): libsteer-wolfssl.so, libsteer.so, steerd, net1 и
    # программы плагинов (с 2.1 — и мост tgws, плагин репозитория splify2-extended-plugins). Логика — build/build-libs.sh (одна
    # для этого цикла и для tests/libs-test.sh), списки файлов — build/sources.mk. Статического
    # расширенного бинарника роутера больше нет: его место — steerd + модули на общих библиотеках
    # (статическая сборка расширенной части остаётся у телефона, шаг 6, и у стендов).
    #
    # Загрузчик задаётся на каждую архитектуру (interp_of): у динамического бинарника он вшит по
    # абсолютному пути и обязан совпасть с файлом musl на роутере.
    printf '  %-26s ' "$arch (libs)"
    libs="build/libs/$arch"
    if ! rm_libs "$libs"; then
        echo "FAILED — не удалось снять $libs (владелец root?)"
        fails=$((fails + 1))
        rm -f "$OUT"/steer-*_"$arch".apk "$OUT"/steer-*_"$arch".ipk
        continue
    fi
    # Объектные файлы снимаются и владелец выхода возвращается ВНУТРИ контейнера: docker пишет от
    # root, и на машине без root (GitHub Actions) `rm -rf obj` снаружи падал «Permission denied».
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh \
            -e CC="zig cc -target $target -mcpu=$mcpu" -e AR="zig ar" -e ZIG=1 \
            -e INTERP="$(interp_of "$target" "$mcpu")" -e STEER_LAYOUT="$LAYOUT" "$IMAGE" -c \
            'sh /src/build/build-libs.sh "$1" "$2" "$3"; rc=$?; rm -rf "$1/obj"; chown -R "$4" "$1"; exit $rc' _ \
            "/src/$libs" "$VERSION" "$REV" "$(id -u):$(id -g)" \
            >"build/$arch-libs.log" 2>"build/$arch-libs.err"; then
        echo "libsteer $(stat -c %s "$libs"/libsteer.so.*) + wolfssl $(stat -c %s "$libs"/libsteer-wolfssl.so.*)" \
             "+ steerd $(stat -c %s "$libs/steerd") bytes"
        if [ "$LAYOUT" = 2.1 ]; then
            printf '  %-26s net1 %s' "" "$(stat -c %s "$libs/plugins/net1/lib/libs2p-net.so.1")"
            for _p in $PLUGS; do printf ' + %s %s' "$_p" "$(stat -L -c %s "$libs/plugins/$_p/bin/$_p")"; done
            echo " bytes"
        fi
        warn_report "build/$arch-libs.err"
    else
        rm_libs "$libs" || echo "    (не удалось снять $libs)"
        echo "FAILED — $(grep -m1 error "build/$arch-libs.err" || head -1 "build/$arch-libs.err")"
        fails=$((fails + 1))
        # Пакеты этой архитектуры от прошлой сборки — не этой: оставь их в $OUT, и список «packages»
        # в конце выдал бы их за свежие (так и было: libsteer не собралась, а в out/ лежали пакеты
        # часовой давности, и сборка отвечала кодом 0).
        rm -f "$OUT"/steer-*_"$arch".apk "$OUT"/steer-*_"$arch".ipk
        continue
    fi

    # ---- пакеты ---------------------------------------------------------------------------
    #
    # Раскладка 2.1 — один пакет на архитектуру (docs/architecture.md, «Сборки»):
    #
    #   steer-core         ядро и общая крипта: steerd на общих библиотеках, клиент steer,
    #                      libsteer.so.<версия> (модель, виды, TLS, слой криптографии),
    #                      libsteer-wolfssl.so.<версия wolfSSL> (наша wolfSSL, QUIC включён заранее,
    #                      см. build/wolfssl), init-скрипт, обработчик обхода, hotplug, keep.d, семя
    #                      плагинов протоколов. dnsd — подкоманда steerd, своего файла у него нет.
    #
    # Протоколы и мост Telegram — плагины (.s2p), пакетов steer-<модуль> больше нет: steer-core 2.1
    # заменяет их все (steer-tgws в том числе). Прежняя раскладка 2.0 (пакеты модулей и мета-пакет
    # steer-extended) ниже осталась под LAYOUT=2.0, но build/build-libs.sh её уже не собирает.
    #
    # Библиотеки лежат в steer-core, отдельных пакетов libsteer и libsteer-wolfssl нет. Довод:
    # ядру крипта нужна и без модулей — steerd сам ходит по HTTPS (замер групп, urltls) и
    # по DoH/DoT (dnsd), — а значит, «ядра без TLS» не бывает, и пакеты библиотек были бы лишь
    # двумя лишними именами, которые надо держать в одной версии с ядром. Цена — 0,6 МБ
    # библиотек на флеше и в памяти, выигрыш — один набор файлов, ни одной веточки «есть ли TLS»
    # и один владелец у каждого файла.
    #
    # МИГРАЦИЯ со старой раскладки (пакеты steer, libsteer, libsteer-wolfssl). steer-core
    # объявляет себя provides steer (кто зависит от имени `steer`, продолжает его находить),
    # replaces steer, libsteer, libsteer-wolfssl (может занять их файлы) и конфликтует с ними:
    # без конфликта старые пакеты остались бы в базе и владели бы /usr/sbin/steerd вместе с
    # новым. В apk конфликт пишется как `!имя` в depends, в opkg — поле Conflicts.
    # Версия у конфликта не проверяется: старое ядро того же номера (промежуточные сборки одного
    # выпуска) заменяется точно так же, как ядро прежнего выпуска.
    root="build/pkg/$arch"
    rm -rf "$root"
    mkdir -p "$root/usr/sbin" "$root/usr/lib" "$root/etc/init.d" "$root/etc/steer/lists" \
             "$root/lib/upgrade/keep.d" "$root/etc/hotplug.d/iface"
    # Обе библиотеки — часть ядра (см. комментарий к раскладке выше): steerd и каждый модуль
    # находят их по SONAME в /usr/lib.
    cp "$libs"/libsteer.so.* "$libs"/libsteer-wolfssl.so.* "$root/usr/lib/"
    # Три имени (docs/architecture.md, раздел 4а): steerd — движок целиком, steer — клиент сокета,
    # steer-tools — ссылка на steerd, под этим именем движок отвечает только на инструменты.
    cp "$libs/steerd" "$root/usr/sbin/steerd"
    cp "build/steer-client-$arch" "$root/usr/sbin/steer"
    ln -sf steerd "$root/usr/sbin/steer-tools"
    cp files/etc/init.d/steer "$root/etc/init.d/steer"
    # Реакция на события сети: подъём и падение интерфейса доходят до сторожа сразу, а не
    # через минуту опроса. Файл невелик, но без него правка I-137 существует только в дереве.
    cp files/etc/hotplug.d/iface/95-steer "$root/etc/hotplug.d/iface/95-steer"
    # Настройки объявляются системе, иначе их не существует для sysupgrade и для «Создать
    # архив» в LuCI: список файлов там собирается из /etc/sysupgrade.conf и
    # /lib/upgrade/keep.d/*, и всё, чего в нём нет, обновление прошивки «с сохранением
    # настроек» просто теряет — молча (I-037: на стенде sysupgrade -l не знал ни spec.json,
    # ни sub.txt, то есть переживал обновление только URL подписки в /etc/config, без узлов).
    # Файл кладётся В ПОЛЕЗНУЮ НАГРУЗКУ, а не в скрипт установки: он обязан исчезнуть вместе
    # с пакетом и принадлежать ему, как init-скрипт.
    cp files/lib/upgrade/keep.d/steer "$root/lib/upgrade/keep.d/steer"
    # Плагины (src/pluginmgr): каталог, официальный репозиторий и что из них переживает sysupgrade.
    # keep.d/steer-plugins менеджер переписывает при каждой установке и снятии (дописывает keep
    # плагинов); в пакете — основа: оба каталога целиком (plugin-sdk, s2p.md, «sysupgrade»).
    # Ключи официального репозитория (/usr/share/steer/keys/<роль>/) и семя (/usr/share/steer/seed)
    # кладёт конвейер выпуска, когда они есть; без ключа индекс официального репозитория не принимается.
    mkdir -p "$root/usr/lib/steer/plugins" "$root/etc/steer/plugins/repos.d"
    cp files/lib/upgrade/keep.d/steer-plugins "$root/lib/upgrade/keep.d/steer-plugins"
    cp files/etc/steer/plugins/repos.d/splify2.json "$root/etc/steer/plugins/repos.d/splify2.json"
    chmod 0644 "$root/lib/upgrade/keep.d/steer-plugins" "$root/etc/steer/plugins/repos.d/splify2.json"
    # Вход fw4 для перенаправленных к службам steer соединений (гостевые зоны с input REJECT) —
    # почему, в самом файле. fw4 подхватывает его при перечитывании; postinst перечитывает.
    mkdir -p "$root/usr/share/nftables.d/chain-pre/input"
    cp files/usr/share/nftables.d/chain-pre/input/30-steer.nft \
       "$root/usr/share/nftables.d/chain-pre/input/30-steer.nft"
    chmod 0644 "$root/usr/share/nftables.d/chain-pre/input/30-steer.nft"
    # Версия steer-abi ядра — для .so-плагинов (steerd динамический и грузит их сам: src/daemon/plugso.c). Загрузчик внутри
    # steerd, отдельной libsteer-plugin.so в пакете нет; файл — то, что читает менеджер плагинов
    # (compat.steer-abi), не запуская steerd.
    mkdir -p "$root/usr/share/steer"
    printf 'steer-abi %s\n' "$(sh build/abi.sh)" > "$root/usr/share/steer/steer-abi"
    chmod 0644 "$root/usr/share/steer/steer-abi"
    # Открытые ключи официальных репозиториев (/usr/share/steer/keys/<роль>/<номер>.pub и revoked; роль — index,
    # protocols, plugins; plugin-sdk/docs/s2p.md, «Ключи и ротация»). Два источника: дерево (files/usr/share/steer/keys —
    # прежние ключи на время ротации и revoked) и конвейер выпуска ($STEER_KEYS_DIR — ключи, выведенные из секретов
    # build/release-keys.sh). Без ключа роли index менеджер не примет индекс официального репозитория.
    for _kd in files/usr/share/steer/keys "${STEER_KEYS_DIR:-}"; do
        [ -n "$_kd" ] && [ -d "$_kd" ] || continue
        mkdir -p "$root/usr/share/steer/keys"
        cp -R "$_kd/." "$root/usr/share/steer/keys/"
    done
    if [ -d "$root/usr/share/steer/keys" ]; then
        find "$root/usr/share/steer/keys" -type d -exec chmod 0755 {} +
        find "$root/usr/share/steer/keys" -type f -exec chmod 0644 {} +
    fi
    # Семя (раскладка 2.1, plugin-sdk/docs/migration-2.1.md, раздел 5): подписанные .s2p протоколов и net1
    # под эту архитектуру и index.json с подписью — переход и первая установка без сети. Архивы же
    # кладутся в $OUT рядом с пакетами (их публикует репозиторий плагинов).
    if [ "$LAYOUT" = 2.1 ]; then
        _seedrc=0
        sh build/pack-s2p.sh "$libs" "$arch" "$VERSION" "$OUT" "$root/usr/share/steer/seed" \
            > "build/$arch-s2p.log" 2>&1 || _seedrc=$?
        case "$_seedrc" in
            0) printf '  %-26s семя %s байт (%s архивов)\n' "" "$(du -sb "$root/usr/share/steer/seed" | cut -f1)" \
                   "$(find "$root/usr/share/steer/seed" -name '*.s2p' | wc -l)"
               grep -h 'ТЕСТОВЫМ' "build/$arch-s2p.log" | sed 's/^/    /' || true ;;
            3) echo "    семя пропущено: $(tail -1 "build/$arch-s2p.log")" ;;
            *) echo "    FAILED — .s2p: $(grep -m1 -i 'error\|ошиб\|отказ' "build/$arch-s2p.log" || tail -1 "build/$arch-s2p.log")"
               fails=$((fails + 1)) ;;
        esac
    fi
    chmod 0755 "$root/usr/sbin/steerd" "$root/usr/sbin/steer" \
               "$root/etc/init.d/steer" "$root/etc/hotplug.d/iface/95-steer"
    chmod 0644 "$root/lib/upgrade/keep.d/steer"

    # OUTSIDE the package root: anything inside it ships as a FILE, so a
    # .post-install written there arrives on the router as /.post-install and
    # collides with every other package doing the same — apk refused the install of a
    # second package with "trying to overwrite .post-install owned by steer". The
    # script belongs to --script, not to the payload.
    #
    # Скрипты пакетов — три вида (файлы build/scripts/<вид>.<хук>, apk и opkg берут их же):
    #   steer  ядро: включить и перезапустить службу при установке, остановить и выключить при
    #          удалении;
    #   mod    модуль: перезапустить службу при установке и после удаления — реестр видов и
    #          состав помощников зависят от того, какие модули лежат рядом с движком, и демон
    #          видит их, только стартуя заново; службу не включает и не выключает — это дело ядра;
    #   noop   библиотеки и мета-пакет: делать нечего.
    #
    # При steer-box-connector движок ведёт коннектор (sing-box) своим экземпляром, и служба steer
    # рядом с ним делила бы таблицы маршрутизации и поле метки. Поэтому ядро и модули проверяют,
    # чья служба /etc/init.d/sing-box: при коннекторе службу steer не включают и не запускают, а
    # перезапускают запущенный sing-box. Без этой проверки обновление ядра на роутере с
    # коннектором поднимало службу steer по оставшейся спеке (так было 2026-10-01 на 10.8.1.1:
    # около минуты по спеке splify2). Скрипты пишутся здесь, а не лежат файлами: правка файла в
    # build/scripts затирается первой же сборкой. Метка /var/run/steer-box-installing — для первой
    # установки: в одной транзакции ядро встаёт раньше коннектора, и /etc/init.d/sing-box ещё
    # чужой; метку ставит install.sh тестового набора на время установки.
    mkdir -p build/scripts
    # preinst/pre-upgrade ядра: какие модули стояли пакетами (steer-vless…, раскладка 2.0). Решатель
    # apk снимает их РАНЬШЕ, чем зовёт pre-upgrade нового ядра (проверено на 3.0.5: «Purging steer-vless»
    # идёт первым), так что бинарников уже нет — остаётся /etc/apk/world: имена пакетов в нём стоят,
    # их закрывает provides ядра. У opkg preinst идёт до снятия, там виден и бинарник. Список отдаёт
    # `steer plugin migrate` в postinst (migration-2.1.md, 3.1), и тот ставит плагины из семени. tgws в
    # список не входит: плагин моста — из репозитория splify2-extended-plugins, в семени его нет. После первого перехода (есть migrate.done.json) имена в
    # world остаются навсегда и решать ими уже нельзя: человек мог снять плагин. Пишется в
    # /etc/steer/plugins: keep.d переносит его через sysupgrade.
    cat > build/scripts/steer.preinst <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ -e /etc/steer/plugins/migrate.done.json ] && exit 0
_pk=""
for _m in vless hysteria2 proxy xsteer obfs warpbox; do
	if [ -e "/usr/sbin/steer-$_m" ] || grep -Eq "^steer-$_m(><.*)?\$" /etc/apk/world 2>/dev/null; then
		_pk="$_pk${_pk:+,}\"steer-$_m\""
	fi
done
[ -n "$_pk" ] || exit 0
mkdir -p /etc/steer/plugins
printf '{"packages":[%s]}\n' "$_pk" > /etc/steer/plugins/migrate.json
exit 0
EOF
    cat > build/scripts/steer.postinst <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ -x /sbin/fw4 ] && fw4 -q reload 2>/dev/null
# Плагины протоколов — по спеке и по прежним пакетам модулей, из семени без сети (раскладка 2.1);
# в прежней раскладке команды нет — отказ молчит. До перезапуска службы: демон встаёт с плагинами.
/usr/sbin/steer plugin migrate 2>&1 | sed 's/^/steer: /'
if grep -q steer-box-connector /etc/init.d/sing-box 2>/dev/null || [ -e /var/run/steer-box-installing ]; then
	/etc/init.d/steer stop 2>/dev/null
	/etc/init.d/steer disable 2>/dev/null
	/etc/init.d/sing-box running 2>/dev/null && /etc/init.d/sing-box restart 2>/dev/null
	exit 0
fi
/etc/init.d/steer enable 2>/dev/null
/etc/init.d/steer restart 2>/dev/null
exit 0
EOF
    {
        printf '#!/bin/sh\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n'
        printf '/etc/init.d/steer stop 2>/dev/null\n/etc/init.d/steer disable 2>/dev/null\nexit 0\n'
    } > build/scripts/steer.prerm
    # Модуль: при коннекторе — перезапуск запущенного sing-box; иначе — службы steer, только если
    # она включена (restart поднимает и выключенную).
    cat > build/scripts/mod.postinst <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
if grep -q steer-box-connector /etc/init.d/sing-box 2>/dev/null || [ -e /var/run/steer-box-installing ]; then
	/etc/init.d/sing-box running 2>/dev/null && /etc/init.d/sing-box restart 2>/dev/null
elif [ -x /etc/init.d/steer ] && /etc/init.d/steer enabled 2>/dev/null; then
	/etc/init.d/steer restart 2>/dev/null
fi
exit 0
EOF
    cp build/scripts/mod.postinst build/scripts/mod.postrm
    printf '#!/bin/sh\nexit 0\n' > build/scripts/mod.prerm
    printf '#!/bin/sh\nexit 0\n' > build/scripts/noop.postinst
    cp build/scripts/noop.postinst build/scripts/noop.prerm
    cp build/scripts/noop.postinst build/scripts/noop.postrm
    # Включение входа fw4 (usr/share/nftables.d) уходит с пакетом — fw4 перечитывает набор без него.
    printf '#!/bin/sh\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n[ -x /sbin/fw4 ] && fw4 -q reload 2>/dev/null\nexit 0\n' > build/scripts/steer.postrm
    chmod +x build/scripts/*

    # pack ИМЯ КОРЕНЬ ЗАВИСИМОСТИ ОПИСАНИЕ ВИД-СКРИПТОВ [КОНФЛИКТЫ] [ЗАМЕНЯЕТ] — оба формата из одного
    # дерева. Зависимости пишутся один раз (имена через пробел), версии нашим пакетам ставят
    # dep_apk и dep_ipk. КОНФЛИКТЫ — имена пакетов, с которыми этот несовместим (apk: `!имя`
    # в depends; opkg: Conflicts). ЗАМЕНЯЕТ — пакеты, чьи файлы этот вправе занять и чьё имя он
    # берёт на себя (apk: replaces + provides имя=версия; opkg: Replaces + Provides).
    pack() {
        _n="$1"; _r="$2"; _dp="$3"; _ds="$4"; _sk="$5"; _cf="${6:-}"; _rp="${7:-}"; _cfi="${8:-}"
        _dinfo=""
        _dall="$(dep_apk "$_dp")"
        for _c in $_cf; do _dall="$_dall !$_c"; done
        [ -n "$_dall" ] && _dinfo="--info depends:'$_dall'"
        _ipkx=""
        # opkg снимает установленный пакет только при Conflicts вместе с Replaces (проверено на opkg 24.10:
        # одних Provides/Replaces мало — модули 2.0.5 остаются стоять); для apk то же делает provides.
        [ -n "$_cf$_cfi" ] && _ipkx="$(printf 'Conflicts: %s' "$(echo $_cf $_cfi | sed 's/ /, /g')")"
        if [ -n "$_rp" ]; then
            # provides — на КАЖДОЕ имя «заменяет», а не на первое (plugin-sdk/docs/open.md, О-23):
            # steer-core 2.1 закрывает собой все прежние пакеты модулей (migration-2.1.md, раздел 2).
            _pv=""
            for _n1 in $_rp; do _pv="$_pv${_pv:+ }$_n1=$VERSION-r1"; done
            _dinfo="$_dinfo --info replaces:'$_rp' --info provides:'$_pv'"
            _ipkx="$(printf '%s\nReplaces: %s\nProvides: %s' "$_ipkx" "$(echo $_rp | sed 's/ /, /g')" "$(echo $_rp | sed 's/ /, /g')")"
            _ipkx="$(printf '%s' "$_ipkx" | sed '/^$/d')"
        fi
        # apk: скрипты — четыре хука. post-deinstall нужен модулям (перезапуск после удаления).
        # post-upgrade нужен всем, у кого post-install что-то делает: apk при обновлении пакета
        # на другую версию зовёт pre-upgrade/post-upgrade, а НЕ pre-deinstall/post-install
        # (на OpenWrt 25.12.5 старый steerd с бинарником `(deleted)` работал после
        # `apk add`, пока службу не перезапускали руками). Тело то же, что у post-install:
        # ядро включает и перезапускает службу, модуль перезапускает; остановка при обновлении
        # не нужна (pre-deinstall при нём не вызывается), а при удалении остаётся как было.
        # opkg зовёт postinst и при обновлении, поэтому ipk остаётся с одним файлом.
        # Компромисс: apk не даёт хука «конец транзакции», так что обновление ядра вместе с
        # модулями перезапускает службу по разу на пакет (ядро, затем каждый модуль); перезапуск
        # идемпотентен, а модули ставятся после ядра (зависимость), так что последний из них
        # застаёт демон с уже полным составом.
        docker run --rm -v "$PWD":/w -w /w alpine:latest sh -c \
            "apk add --no-cache apk-tools >/dev/null 2>&1; apk mkpkg \
               --info name:$_n --info version:$VERSION-r1 \
               --info description:'$_ds' \
               --info arch:$arch $_dinfo \
               $( [ -f build/scripts/$_sk.preinst ] && echo "--script pre-install:build/scripts/$_sk.preinst --script pre-upgrade:build/scripts/$_sk.preinst") \
               --script post-install:build/scripts/$_sk.postinst \
               --script post-upgrade:build/scripts/$_sk.postinst \
               --script pre-deinstall:build/scripts/$_sk.prerm \
               --script post-deinstall:build/scripts/$_sk.postrm \
               -F $_r -o $OUT/$_n-$VERSION-1_$arch.apk" >/dev/null 2>&1 \
            || echo "    (apk packaging failed for $_n $arch)"
        mk_ipk "$_r" "$_n" "$arch" "$(dep_ipk "$_dp")" "$_ds" "$_ipkx" "$_sk"
    }

    # Ядро вместе с библиотеками. Своих зависимостей от наших пакетов нет; предыдущие пакеты
    # steer, libsteer и libsteer-wolfssl — конфликтуют и заменяются (миграция, см. выше). Имя
    # `steer` идёт первым в ЗАМЕНЯЕТ: pack берёт первое как provides.
    deps="$(pkg_deps "$root/usr/sbin/steerd" core)"
    # kmod-tun держит само ядро: протоколы-плагины (vless, hysteria2, xsteer) создают TUN, а прежние пакеты
    # модулей тянули kmod-tun и при переходе снимаются в той же транзакции — apk тут же удаляет и
    # осиротевший kmod-tun (проверено на apk 3.0.5), а менеджер плагинов из postinst пакет поставить не
    # может: база заперта. Без этой зависимости плагины встали бы без TUN (migration-2.1.md, раздел 4).
    [ "$LAYOUT" = 2.0 ] || deps="$deps $(pkg_deps "" tun)"
    # Раскладка 2.1: протоколы и мост Telegram — плагины, steer-core берёт на себя имена всех прежних пакетов
    # модулей (с steer-tgws: мост — плагин tgws) и мета-пакета (migration-2.1.md, раздел 2) — конфликтует с
    # ними и заменяет, так что установка ядра 2.1 снимает их в той же транзакции.
    _old="steer libsteer libsteer-wolfssl"
    _mods=""
    [ "$LAYOUT" = 2.0 ] || _mods="steer-vless steer-hysteria2 steer-proxy steer-xsteer steer-obfs steer-warpbox steer-tgws steer-extended"
    pack steer-core "$root" "$deps" "steer-core: ядро маршрутизации по политике (каналы на входе, nftables на выходе) и общая крипта" \
        steer "$_old" "$_old $_mods" "$_mods"

    # Модули: по одному бинарнику в usr/sbin рядом со steerd, где их находит движок (src/lib/
    # module.c). Зависимость от steer-core — точной версии: ядро и модуль общаются линией событий,
    # формат которой между выпусками не обещан (hello в docs/ctl.md).
    # steer-hysteria2, steer-proxy и steer-warpbox — тоже модули, но в steer-extended они НЕ входят:
    # отдельные пакеты, которые ставят сознательно (см. мета-пакет ниже). У steer-warpbox нет
    # зависимости от модуля ядра: туннели WARP — выходы awg ядра steer, а им годится и kmod-amneziawg
    # (сторонний, с обфускацией), и kmod-wireguard из фидов OpenWrt — выбор за человеком.
    _modlist=""
    [ "$LAYOUT" = 2.0 ] && _modlist="vless xsteer obfs hysteria2 proxy warpbox"
    for m in $_modlist; do
        mroot="build/pkg/$arch-$m"
        rm -rf "$mroot"
        mkdir -p "$mroot/usr/sbin"
        cp "$libs/steer-$m" "$mroot/usr/sbin/steer-$m"
        chmod 0755 "$mroot/usr/sbin/steer-$m"
        case "$m" in
            vless)  md="steer-vless: клиент VLESS/Reality для steer (модуль)"; mk=tun ;;
            xsteer) md="steer-xsteer: клиент звезды xsteer для steer (модуль)"; mk=tun ;;
            obfs)   md="steer-obfs: обфускатор WireGuard для steer (модуль)"; mk=mod ;;
            hysteria2) md="steer-hysteria2: клиент hysteria2 (QUIC, Brutal) для steer (модуль)"; mk=tun ;;
            proxy)  md="steer-proxy: клиенты trojan, shadowsocks, socks, http, vmess для steer (модуль)"; mk=tun ;;
            warpbox) md="steer-warpbox: Cloudflare WARP для steer — регистрация, подбор точек, замена (модуль)"; mk=mod ;;
        esac
        mdeps="steer-core $(pkg_deps "$mroot/usr/sbin/steer-$m" "$mk")"
        pack "steer-$m" "$mroot" "$mdeps" "$md" mod
    done

    # steer-box-connector — свой репозиторий (github.com/splify2/steer-box-connector).

    # Мета-пакет steer-extended (устарел, оставлен на переход): ядро и модули vless, xsteer, obfs;
    # hysteria2 не входит. Пустой пакет менеджеры не любят, поэтому в нём один маленький
    # файл-метка. Имя сохранено ради splify2, который ставит его по имени.
    [ "$LAYOUT" = 2.0 ] || continue
    xroot="build/pkg/$arch-extended"
    rm -rf "$xroot"
    mkdir -p "$xroot/usr/lib/steer"
    printf 'steer-extended %s: мета-пакет — steer-core, steer-vless, steer-xsteer, steer-obfs\n' \
        "$VERSION" > "$xroot/usr/lib/steer/extended"
    # Системные зависимости 1.5.x (nftables ip-full conntrack kmod-nft-queue kmod-tun) мета-пакет
    # повторяет нарочно. opkg (OpenWrt 24.10 и старше) при обновлении steer-extended 1.5.x до этого
    # мета-пакета считает их осиротевшими раньше, чем доходит до зависимостей steer-core и модулей,
    # и снимает: после `opkg install ./*-2.0.0-1_<арх>.ipk` на роутере не оставалось ip-full,
    # conntrack, kmod-nft-queue и (без hysteria2) kmod-tun. apk решает транзакцию целиком и этого
    # не делает, но зависимости общие для обоих форматов.
    pack steer-extended "$xroot" "steer-core steer-vless steer-xsteer steer-obfs $(pkg_deps "" core) $(pkg_deps "" tun)" \
        "steer-extended (устарел, взамен — steer-core и нужные модули): ядро, VLESS/Reality, xsteer, обфускатор" noop
done

# ---- серверная половина обфускации: архив для VPS -----------------------------
#
# steer obfs-server живёт не на роутере, а на VPS рядом с WireGuard, и пакетом OpenWrt
# туда не поставишь: там обычный Linux с systemd. До сих пор единственным путём была
# сборка из исходников (server/install.sh), то есть на голой VPS установка начиналась с
# apt install build-essential ради одного файла — и упиралась в него же на образах, где
# компилятора нет и ставить его нельзя.
#
# Архив содержит ровно то, что нужно на той стороне: статический бинарник, установщик и
# краткую справку. Код тот же, что у модуля steer-obfs в пакете для роутера (obfs.c и obfsmain.c
# входят в статическую базовую сборку, а в пакете — в libsteer и модуль), — отдельной обфускации
# для сервера нет и быть не должно: две реализации означали бы две обфускации, расходящиеся в
# мелочах на проводе. Сборка здесь статическая, без библиотек: на VPS нет пакетов OpenWrt.
#
# Архитектуры только те, на которых VPS реально бывают. Собирать архив под mips значило
# бы предлагать людям то, чего не существует.
echo "серверная половина:"
for arch in x86_64 aarch64_generic; do
    # Движок, а не клиент: на VPS нет ни демона, ни сокета — obfs-server подкомандой самого
    # движка. Имя внутри архива прежнее (steer): его зовут server/install.sh и человек.
    bin="build/steerd-$arch"
    if [ ! -f "$bin" ]; then
        printf '  %-26s пропуск (ядро не собралось)\n' "$arch"
        continue
    fi
    # Имя внутри архива — привычное человеку, а не имя цели OpenWrt: на VPS про
    # aarch64_generic никто не знает, там знают uname -m.
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    stage="build/obfs-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$bin" "$stage/steer"
    cp server/install.sh "$stage/install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer" "$stage/install.sh"
    tar -C build -czf "$OUT/steer-obfs-$VERSION-$uarch.tar.gz" "obfs-$uarch"
    printf '  %-26s %s bytes\n' "$uarch" "$(stat -c %s "$OUT/steer-obfs-$VERSION-$uarch.tar.gz")"
done

# ---- хаб xsteer: архив для VPS -----------------------------------------------
#
# Клиент xsteer живёт на роутере (роль router, уже собран выше в extended), а хаб звезды —
# на VPS. Хабу нужна подкоманда xsteer-hub, поднимающая слушателя на публичном порту, и
# ради безопасности её нет в сборке для роутера: это отдельная РОЛЬ server сборки ext
# (см. build/build-ext.sh — там объяснено, почему гейт стоит на списках файлов).
#
# Отсюда отдельный бинарник steer-hub и отдельный архив: смешивать его с обфускацией из
# steer-obfs нельзя — там другая половина и другой протокол. Архитектуры те же, что у VPS
# вообще (см. серверную половину выше): собирать хаб под mips значило бы предлагать
# несуществующее.
#
# Имя архива БЕЗ версии — steer-hub-$uarch.tar.gz: установщик server/xs_install.sh тянет его
# по фиксированному пути releases/latest/download/steer-hub-$arch.tar.gz, где имя не должно
# зависеть от версии. Внутри — бинарник, установщик и справка: распаковал и запустил, даже
# без сети (xs_install.sh берёт steer-hub рядом с собой, если он есть).
echo "хаб xsteer:"
for arch in x86_64 aarch64_generic; do
    # Цель и mcpu берём из того же ISAS, что и основную сборку: одна таблица архитектур,
    # чтобы хаб и движок не разошлись в флагах компилятора.
    spec=""
    for s in $ISAS; do [ "${s%%:*}" = "$arch" ] && spec="$s" && break; done
    if [ -z "$spec" ]; then
        printf '  %-26s пропуск (нет в ISAS)\n' "$arch"
        continue
    fi
    rest=${spec#*:}; target=${rest%%:*}; mcpu=${rest#*:}
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    printf '  %-26s ' "$uarch"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/steer-hub-$arch" \
            "$VERSION" server "$REV" \
            2>"build/$arch-hub.err"; then
        :
    else
        rm -f "build/steer-hub-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-hub.err" || head -1 "build/$arch-hub.err")"
        fails=$((fails + 1))
        continue
    fi
    stage="build/hub-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "build/steer-hub-$arch" "$stage/steer-hub"
    cp server/xs_install.sh "$stage/xs_install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer-hub" "$stage/xs_install.sh"
    tar -C "$stage" -czf "$OUT/steer-hub-$uarch.tar.gz" .
    printf '%s bytes\n' "$(stat -c %s "$OUT/steer-hub-$uarch.tar.gz")"
    warn_report "build/$arch-hub.err"
done

# Владелец всего, что писал docker (от root): бинарники и архивы wolfSSL в build/, пакеты apk в
# out/, каталоги, которые контейнер создал сам (build/libs, build/wolfssl-obj). Не от root (GitHub
# Actions, сборка руками под своим пользователем) следующая сборка в том же дереве не могла бы их
# снять или переписать снаружи контейнера, — отдаём пользователю хоста одним проходом в конце.
if [ "$(id -u)" != 0 ]; then
    docker run --rm -v "$PWD:/src" --entrypoint chown "$IMAGE" -R "$(id -u):$(id -g)" \
        /src/build /src/"$OUT" >/dev/null 2>&1 ||
        echo "    (не удалось вернуть владельца build/ и $OUT/ — часть файлов принадлежит root)"
fi

echo "packages:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
[ "$warns" = 0 ] || echo "build.sh: предупреждений компилятора за сборку — $warns (строки выше, полный текст — build/*.err)"
# Что-то не собралось — код отказа: прежде сборка с FAILED в выводе отвечала 0, и вызывающий (руками,
# release.yml) узнавал об этом, только читая вывод.
if [ "$fails" != 0 ]; then
    echo "build.sh: не собралось частей — $fails (FAILED выше)" >&2
    exit 1
fi
