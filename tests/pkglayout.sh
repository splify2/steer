#!/bin/sh
# Раскладка собранных пакетов роутера: состав, зависимости, миграция со старых пакетов.
#
# Зачем. tests/buildmatch.sh сверяет ТЕКСТ build.sh с ожиданиями, но пакет — это файл, и
# правда о нём в самом файле: что лежит внутри, чему принадлежит и как менеджер пакетов ведёт себя
# при установке поверх прежнего. Раскладка «ядро с библиотеками внутри + модули отдельно» ломается
# молча именно там: модуль, унёсший копию libsteer.so, отказывается ставиться рядом с ядром
# сообщением о владельце файла; ядро без provides/replaces оставляет старые пакеты steer, libsteer и
# libsteer-wolfssl в базе, и /usr/sbin/steerd числится за двумя. Ни то ни другое не видно, пока
# пакет не поставишь поверх старого.
#
# Что проверяется (для одной архитектуры, по готовым out/*.apk и out/*.ipk):
#   1. состав: steer-core несёт обе библиотеки, бинарники, init.d, hotplug и keep.d; модуль — ровно
#      свой бинарник; файлы разных пакетов не пересекаются; состав .apk и .ipk одного пакета совпадает;
#   2. зависимости: модули — от steer-core точной версии; steer-extended — ядро и четыре модуля,
#      без hysteria2; steer-core объявляет provides/replaces и конфликты со старыми пакетами
#      в обоих форматах (apk — depends с `!имя`, opkg — поля Conflicts/Replaces/Provides);
#   3. размеры (таблица) и предел на сумму установленных файлов без hysteria2;
#   4. миграция apk на настоящем менеджере (apk-tools в контейнере alpine, корень во временном
#      каталоге, репозитории — каталоги с индексом): чистая установка и обновление поверх старых
#      steer, libsteer, libsteer-wolfssl, steer-vless и steer-extended (той же версии и старой) —
#      у каждого файла один владелец, старых пакетов в базе не осталось, служба после обновления
#      включена (старый prerm выключает её, новый postinst включает — порядок сверяется по журналу).
#      Старые пакеты изготавливаются из файлов нового: важны имена, версии, зависимости и
#      скрипты, а не байты. Отдельно — обновление на БОЛЕЕ НОВУЮ версию тех же пакетов (post-upgrade
#      перезапускает службу, остановки и выключения нет). opkg в контейнере нет: для .ipk проверяется только состав метаданных
#      (пункт 2); порядок его действий здесь не воспроизведён.
#
# Нужны docker и собранные пакеты (`STEER_ARCH=<арх> sh build.sh`); нет — громкий пропуск (это не
# падение), как у стендов, которым не хватает образа. Запуск: sh tests/pkglayout.sh [архитектура]
set -u

ARCH="${1:-mipsel_24kc}"
case "$ARCH" in
    --inside) ARCH="${2:-mipsel_24kc}"; INSIDE=1 ;;
    *) INSIDE=0 ;;
esac

if [ "$INSIDE" = 0 ]; then
    if ! ls out/steer-core-*_"$ARCH".apk >/dev/null 2>&1; then
        echo "pkglayout: пакетов для $ARCH в out/ нет (STEER_ARCH=$ARCH sh build.sh) — ПРОПУСК (это не падение)."
        exit 0
    fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "pkglayout: docker нет — ПРОПУСК (это не падение)."
        exit 0
    fi
    exec docker run --rm -v "$PWD:/w:ro" -w /w alpine:latest sh tests/pkglayout.sh --inside "$ARCH"
fi

# ---- дальше — внутри контейнера ------------------------------------------------------------
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

A="$ARCH"
T=/tmp/pl
rm -rf "$T"; mkdir -p "$T"
core_apk="$(ls out/steer-core-*_"$A".apk | head -1)"
V="${core_apk#out/steer-core-}"; V="${V%%-1_*}"     # версия без ревизии сборки
# Раскладка 2.1 (умолчание build.sh): протоколы — плагины (.s2p и семя в steer-core), пакетом остаётся
# только мост steer-tgws; 2.0 (STEER_LAYOUT=2.0) — прежние пакеты модулей и мета-пакет.
if ls out/steer-vless-"$V"-1_"$A".apk >/dev/null 2>&1; then LAYOUT=2.0; else LAYOUT=2.1; fi
if [ "$LAYOUT" = 2.0 ]; then
    MODS="vless xsteer obfs tgws hysteria2"
    PKGS="steer-core steer-vless steer-xsteer steer-obfs steer-tgws steer-hysteria2 steer-extended"
else
    MODS="tgws"
    PKGS="steer-core steer-tgws"
fi
echo "pkglayout: раскладка $LAYOUT"

# Разворачиваем каждый пакет в обоих форматах.
for p in $PKGS; do
    mkdir -p "$T/apk/$p" "$T/ipk/$p" "$T/ctl/$p"
    apk extract --allow-untrusted --destination "$T/apk/$p" "out/$p-$V-1_$A.apk" >/dev/null 2>&1
    tar -xzf "out/$p-$V-1_$A.ipk" -C "$T/ctl/$p"
    tar -xzf "$T/ctl/$p/data.tar.gz" -C "$T/ipk/$p"
    tar -xzf "$T/ctl/$p/control.tar.gz" -C "$T/ctl/$p"
done
files_of() { (cd "$1" && find . -mindepth 1 \( -type f -o -type l \) | sed 's|^\.||' | sort); }

# ---- 1. состав ----------------------------------------------------------------------------
core_files="$(files_of "$T/apk/steer-core")"
# steer-nfqws ушёл из ядра вместе с zapret (2.1.0, docs/spec-v2.md: kind zapret убран).
for want in /usr/sbin/steerd /usr/sbin/steer /usr/sbin/steer-tools \
            /etc/init.d/steer /etc/hotplug.d/iface/95-steer /lib/upgrade/keep.d/steer; do
    check "steer-core содержит $want (всё, что было в прежнем пакете steer)" "1" \
        "$(printf '%s\n' "$core_files" | grep -cx "$want")"
done
check "steer-core содержит libsteer.so.<версия>" "1" \
    "$(printf '%s\n' "$core_files" | grep -c '^/usr/lib/libsteer\.so\.[0-9.]*$')"
check "steer-core содержит libsteer-wolfssl.so.<версия wolfSSL>" "1" \
    "$(printf '%s\n' "$core_files" | grep -c '^/usr/lib/libsteer-wolfssl\.so\.[0-9.]*$')"
check "steer-tools — ссылка на steerd" "steerd" "$(readlink "$T/apk/steer-core/usr/sbin/steer-tools")"
check "у steer-core нет других файлов" "0" \
    "$(printf '%s\n' "$core_files" | grep -vcE '^/(usr/sbin/(steerd|steer|steer-tools|steer-nfqws)|usr/lib/libsteer(-wolfssl)?\.so\.[0-9.]+|etc/init\.d/steer|etc/hotplug\.d/iface/95-steer|lib/upgrade/keep\.d/steer|usr/share/steer/steer-abi|usr/share/nftables\.d/chain-pre/input/30-steer\.nft|usr/share/steer/seed/.*|usr/share/steer/keys/.*|etc/steer/plugins/.*|lib/upgrade/keep\.d/steer-plugins|etc/init\.d/steer-plugins)$')"
if [ "$LAYOUT" = 2.1 ]; then
    # Семя (plugin-sdk/docs/migration-2.1.md, раздел 5): подписанный индекс и архивы протоколов и net1.
    check "steer-core 2.1: семя — index.json и подпись" "1 1" \
        "$(printf '%s\n' "$core_files" | grep -c '^/usr/share/steer/seed/index\.json$') $(printf '%s\n' "$core_files" | grep -c '^/usr/share/steer/seed/index\.json\.sig$')"
    for q in net1 vless hysteria2 proxy xsteer warpbox obfs; do
        check "  в семени архив $q под $A" "1" \
            "$(printf '%s\n' "$core_files" | grep -c "^/usr/share/steer/seed/$q/[0-9.]*/$q-[0-9.]*-$A\.s2p$")"
    done
    # awg — плагин без файлов (impl: core), нужен warpbox по requires.plugins: без него WARP из семени не встанет.
    check "  в семени архив awg (all)" "1" \
        "$(printf '%s\n' "$core_files" | grep -c "^/usr/share/steer/seed/awg/[0-9.]*/awg-[0-9.]*-all\.s2p$")"
fi
for m in $MODS; do
    check "steer-$m — ровно свой бинарник" "/usr/sbin/steer-$m" "$(files_of "$T/apk/steer-$m" | tr '\n' ' ' | sed 's/ $//')"
done
[ "$LAYOUT" = 2.1 ] ||
check "steer-extended — только метка" "/usr/lib/steer/extended" "$(files_of "$T/apk/steer-extended" | tr '\n' ' ' | sed 's/ $//')"
allf=""
for p in $PKGS; do allf="$allf$(files_of "$T/apk/$p")
"; done
check "файлы разных пакетов не пересекаются" "" "$(printf '%s' "$allf" | sort | uniq -d | tr '\n' ' ')"
check "библиотеки есть только в steer-core" "2" "$(printf '%s' "$allf" | grep -c 'libsteer')"
for p in $PKGS; do
    check "$p: состав .apk и .ipk одинаков" "$(files_of "$T/apk/$p")" "$(files_of "$T/ipk/$p")"
done
check "steer-core: init.d, hotplug и бинарники исполняемы" "" \
    "$(for f in usr/sbin/steerd usr/sbin/steer etc/init.d/steer etc/hotplug.d/iface/95-steer; do [ -x "$T/apk/steer-core/$f" ] || printf '%s ' "$f"; done)"

# ---- 2. зависимости и миграция: метаданные ----------------------------------------------------
dump() { apk adbdump --allow-untrusted "out/$1-$V-1_$A.apk"; }
has() { grep -cFx -- "$2" "$T/dump.$1" | tr -d ' '; }   # ИМЯ СТРОКА -> число совпадений
for p in $PKGS; do dump "$p" > "$T/dump.$p"; done
ctl() { sed -n "s/^$2: //p" "$T/ctl/$1/control"; }

for m in $MODS; do
    check "steer-$m (apk) зависит от steer-core точной версии" "1" "$(has steer-$m "    - steer-core=$V-r1")"
    check "steer-$m (ipk) зависит от steer-core точной версии" "1" \
        "$(ctl steer-$m Depends | tr ',' '\n' | grep -c "^ *steer-core (= $V-1)\$")"
    check "steer-$m не зависит от libsteer и libsteer-wolfssl" "0" \
        "$(grep -c 'libsteer' "$T/dump.steer-$m")"
done
if [ "$LAYOUT" = 2.0 ]; then
for m in vless xsteer hysteria2; do
    check "steer-$m требует kmod-tun (создаёт TUN сам)" "1" "$(has steer-$m "    - kmod-tun")"
done
check "steer-extended (apk): ядро и четыре модуля" "5" \
    "$(grep -cE -- "^    - steer-(core|vless|xsteer|obfs|tgws)=$V-r1$" "$T/dump.steer-extended")"
check "steer-extended (ipk): ядро и четыре модуля" "5" \
    "$(ctl steer-extended Depends | tr ',' '\n' | grep -cE "^ *steer-(core|vless|xsteer|obfs|tgws) \(= $V-1\)\$")"
check "steer-extended не тянет steer-hysteria2 (apk и ipk)" "0 0" \
    "$(grep -c hysteria2 "$T/dump.steer-extended") $(ctl steer-extended Depends | grep -c hysteria2)"
check "steer-extended помечен устаревшим" "1" "$(ctl steer-extended Description | grep -c 'устарел')"
fi
if [ "$LAYOUT" = 2.1 ]; then
    # kmod-tun держит ядро: прежние пакеты модулей тянули его, а apk снимает осиротевшую зависимость в той же
    # транзакции перехода; плагины протоколов создают TUN, и поставить пакет из postinst менеджер не может.
    check "steer-core 2.1 (apk) зависит от kmod-tun" "1" "$(has steer-core "    - kmod-tun")"
    check "steer-core 2.1 (ipk) зависит от kmod-tun" "1" "$(ctl steer-core Depends | tr ',' '\n' | grep -c '^ *kmod-tun$')"
    # preinst запоминает пакеты модулей; postinst отдаёт их `steer plugin migrate` (apk: pre-install и pre-upgrade).
    check "steer-core 2.1 (apk) несёт pre-install и pre-upgrade" "2" "$(grep -cE '^  pre-(install|upgrade):' "$T/dump.steer-core")"
    check "steer-core 2.1 (ipk) несёт preinst" "1" "$([ -x "$T/ctl/steer-core/preinst" ] && echo 1 || echo 0)"
    check "steer-core 2.1 (ipk): postinst зовёт steer plugin migrate до перезапуска службы" "yes" \
        "$(awk '/plugin migrate/ { m = NR } /init.d\/steer (enable|restart)/ { if (!r) r = NR } END { print (m && r && m < r) ? "yes" : "no" }' "$T/ctl/steer-core/postinst")"
fi
check "steer-core не зависит от наших пакетов (только конфликты со старыми)" "0" \
    "$(sed -n '/^  depends:/,/^  [a-z]*:/p' "$T/dump.steer-core" | grep -E -- '^    - .?(steer|libsteer)' | grep -vcE "^    - '!(steer|libsteer|libsteer-wolfssl)'$")"
# Миграция, метаданные. apk: provides + replaces и `!имя` в depends.
check "steer-core (apk) provides steer=$V-r1" "1" "$(has steer-core "    - steer=$V-r1")"
for old in steer libsteer libsteer-wolfssl; do
    check "steer-core (apk) replaces $old" "1" "$(has steer-core "    - $old")"
    check "steer-core (apk) конфликтует с $old" "1" "$(has steer-core "    - '!$old'")"
    check "steer-core (ipk) Replaces/Conflicts $old" "1 1" \
        "$(ctl steer-core Replaces | tr ',' '\n' | grep -c "^ *$old\$") $(ctl steer-core Conflicts | tr ',' '\n' | grep -c "^ *$old\$")"
done
# provides — на каждое имя «заменяет» (plugin-sdk/docs/open.md, О-23); в 2.1 — и на пакеты протоколов и
# steer-extended (migration-2.1.md, раздел 2), кроме steer-tgws: он пакетом остаётся.
OLDN="steer libsteer libsteer-wolfssl"
[ "$LAYOUT" = 2.1 ] && OLDN="$OLDN steer-vless steer-hysteria2 steer-proxy steer-xsteer steer-obfs steer-warpbox steer-extended"
for old in $OLDN; do
    check "steer-core (apk) provides $old=$V-r1 и replaces $old" "1 1" "$(has steer-core "    - $old=$V-r1") $(has steer-core "    - $old")"
    check "steer-core (ipk) Provides и Replaces $old" "1 1" \
        "$(ctl steer-core Provides | tr ',' '\n' | grep -c "^ *$old\$") $(ctl steer-core Replaces | tr ',' '\n' | grep -c "^ *$old\$")"
done
if [ "$LAYOUT" = 2.1 ]; then
    # opkg 24.10 снимает установленные модули только при Conflicts (с Replaces и Provides): без него после
    # `opkg install steer-core` модули 2.0.x стоят дальше с нарушенной зависимостью от ядра. apk обходится
    # provides/replaces: `!имя` в depends ему здесь не нужен, и steer-tgws не трогается.
    for old in steer-vless steer-hysteria2 steer-proxy steer-xsteer steer-obfs steer-warpbox steer-extended; do
        check "steer-core (ipk) конфликтует с прежним пакетом $old" "1" \
            "$(ctl steer-core Conflicts | tr ',' '\n' | grep -c "^ *$old\$")"
        check "steer-core (apk) не пишет !$old (его снимает provides)" "0" "$(has steer-core "    - '!$old'")"
    done
    check "steer-core (ipk) не конфликтует с steer-tgws" "0" "$(ctl steer-core Conflicts | grep -c tgws)"
fi
check "steer-core не берёт имя steer-tgws (мост — свой пакет)" "0" "$(grep -c 'steer-tgws' "$T/dump.steer-core")"
# Скрипты ядра: прежнее поведение — включить и перезапустить при установке, остановить и выключить при удалении.
check "steer-core (ipk): postinst включает и перезапускает службу" "2" \
    "$(grep -cE '/etc/init\.d/steer (enable|restart)' "$T/ctl/steer-core/postinst")"
check "steer-core (ipk): prerm останавливает и выключает службу" "2" \
    "$(grep -cE '/etc/init\.d/steer (stop|disable)' "$T/ctl/steer-core/prerm")"

# ---- 3. размеры ----------------------------------------------------------------------------
inst_size() { (cd "$1" && find . -type f | while read -r f; do wc -c < "$f"; done | awk '{ t += $1 } END { print t + 0 }'); }
echo "pkglayout: размеры ($A, версия $V), байт"
printf '  %-18s %10s %10s %12s\n' пакет ipk apk установлено
tot_ipk=0 tot_apk=0 tot_inst=0 nohy_inst=0
for p in $PKGS; do
    si="$(wc -c < "out/$p-$V-1_$A.ipk" | tr -d ' ')"; sa="$(wc -c < "out/$p-$V-1_$A.apk" | tr -d ' ')"
    sd="$(inst_size "$T/apk/$p")"
    printf '  %-18s %10s %10s %12s\n' "$p" "$si" "$sa" "$sd"
    tot_ipk=$((tot_ipk + si)); tot_apk=$((tot_apk + sa)); tot_inst=$((tot_inst + sd))
    [ "$p" = steer-hysteria2 ] || nohy_inst=$((nohy_inst + sd))
done
printf '  %-18s %10s %10s %12s\n' "итого" "$tot_ipk" "$tot_apk" "$tot_inst"
printf '  без hysteria2: установлено %s\n' "$nohy_inst"
check "сумма установленных файлов без hysteria2 — не больше 5 МБ" "yes" \
    "$([ "$nohy_inst" -le 5242880 ] && echo yes || echo "no ($nohy_inst)")"

# ---- 4. миграция apk на настоящем менеджере ---------------------------------------------------
if [ "$LAYOUT" = 2.1 ]; then
    # 2.0.x → steer-core 2.1 (migration-2.1.md, раздел 2). Прежние пакеты модулей требуют steer-core ТОЧНОЙ
    # версии 2.0.x, новый steer-core закрывает их имена provides/replaces и должен снять их сам. Что
    # решает исход на настоящем apk, а прежняя редакция стенда не проверяла:
    #   - как ПОСТАВЛЕНЫ прежние пакеты. `apk add ФАЙЛ` пишет в /etc/apk/world «имя><хеш файла»: решатель
    #     обязан держать в базе именно тот файл, и никакие provides нового ядра его не снимают;
    #     `apk add имя` из фида пишет просто имя, и тогда provides работает. Поэтому сценарии идут
    #     в двух видах — «фид» и «файлы»; в мире стоят ВСЕ модули (в прежней редакции — только steer-core
    #     и пара модулей, мета-пакет — без модулей);
    #   - steer-tgws остаётся пакетом: прежний 2.0.x требует ядро 2.0.x, так что вместе с ядром идёт
    #     steer-tgws 2.1 (из фида — сам, файлом — рядом в команде);
    #   - kmod-tun: прежние модули тянули его, и apk снимает осиротевшую зависимость в той же транзакции —
    #     плагины vless/hysteria2/xsteer остались бы без TUN, а менеджер плагинов из postinst пакеты
    #     поставить не может (база заперта). Ядро 2.1 держит kmod-tun само.
    R0="$T/repo21"; mkdir -p "$R0/old/$A" "$R0/new/$A" "$R0/sys/$A" "$T/empty" "$T/nokeys" "$T/o21"
    for d in nftables ip-full conntrack kmod-nft-queue kmod-tun; do
        apk mkpkg --info "name:$d" --info "version:1-r0" --info "arch:$A" -F "$T/empty" \
            -o "$R0/sys/$A/$d-1-r0.apk" >/dev/null 2>&1
    done
    for f in out/*_"$A".apk; do b="${f##*/}"; cp "$f" "$R0/new/$A/${b%%-$V-1_*}-$V-r1.apk"; done
    OV=2.0.5-r1   # прежний выпуск
    mko() {  # ИМЯ ЗАВИСИМОСТИ — пустой пакет прежней версии
        mkdir -p "$T/o21/$1/usr/lib/o21"; echo "$1" > "$T/o21/$1/usr/lib/o21/$1"
        apk mkpkg --info "name:$1" --info "version:$OV" --info "arch:$A" ${2:+--info "depends:$2"} \
            -F "$T/o21/$1" -o "$R0/old/$A/$1-$OV.apk" >/dev/null 2>&1
    }
    mko steer-core "nftables ip-full conntrack kmod-nft-queue"
    for m in vless xsteer obfs tgws hysteria2 proxy warpbox; do mko "steer-$m" "steer-core=$OV kmod-tun"; done
    mko steer-extended "steer-core=$OV steer-vless=$OV steer-xsteer=$OV steer-obfs=$OV steer-tgws=$OV"
    for r in old new sys; do apk mkndx --allow-untrusted -o "$R0/$r/$A/APKINDEX.tar.gz" "$R0/$r/$A"/*.apk >/dev/null 2>&1; done
    MODW="steer-core steer-vless steer-hysteria2 steer-proxy steer-xsteer steer-obfs steer-warpbox steer-tgws"
    NEWF="$R0/new/$A/steer-core-$V-r1.apk $R0/new/$A/steer-tgws-$V-r1.apk"
    apkr21() { _root="$1"; shift; apk --root "$_root" --arch "$A" --allow-untrusted --no-network --no-cache \
        --keys-dir "$T/nokeys" --repositories-file /dev/null -X "$R0/sys" "$@"; }
    mkr21() {  # КОРЕНЬ — корень с оболочкой для скриптов пакетов; init.d — заглушкой (как mkroot ниже)
        rm -rf "$1"; mkdir -p "$1/bin" "$1/lib" "$1/etc"
        cp /bin/busybox "$1/bin/"; ln -s busybox "$1/bin/sh"; cp /lib/ld-musl-*.so.1 "$1/lib/"
        printf 'echo "RC $2" >> /order.log\n' > "$1/etc/rc.common"
    }
    # старые ставятся «из фида» (world — имена) или «файлами» (world — имя><хеш)
    old21() {  # КОРЕНЬ feed|files
        mkr21 "$1"
        if [ "$2" = feed ]; then
            apkr21 "$1" -X "$R0/old" --initdb add $MODW kmod-tun >/dev/null 2>&1
        else
            apkr21 "$1" --initdb add "$R0"/old/"$A"/steer-*"$OV.apk" "$R0/sys/$A/kmod-tun-1-r0.apk" >/dev/null 2>&1
        fi
    }
    heal21() { sed -i 's/><.*//' "$1/etc/apk/world"; }
    # сценарий: ИМЯ ВИД ПОДГОТОВКА КОМАНДА...  (ОЖИДАНИЕ: прошла, ядро 2.1, tgws 2.1, нет прежних модулей, kmod-tun цел)
    sc21() {
        _n="$1"; _k="$2"; _pre="$3"; shift 3
        _r="$T/r21-$_n"
        old21 "$_r" "$_k"
        check "[2.1 $_n] прежние пакеты встали (steer-vless $OV)" "1" \
            "$(apk --root "$_r" list -I 2>/dev/null | grep -c "^steer-vless-$OV ")"
        [ "$_pre" = heal ] && heal21 "$_r"
        # shellcheck disable=SC2086
        apkr21 "$_r" -X "$R0/old" "$@" > "$T/out21-$_n" 2>&1; _rc=$?
        _inst="$(apk --root "$_r" list -I 2>/dev/null | sed 's/ .*//' | sort | tr '\n' ' ')"
        printf '  [2.1 %s] %s → %s\n' "$_n" "$*" "$_inst"
        check "[2.1 $_n] команда менеджера прошла" "0" "$_rc"
        [ "$_rc" = 0 ] || sed 's/^/    /' "$T/out21-$_n" | head -8
        check "[2.1 $_n] steer-core и steer-tgws новой версии" "2" \
            "$(printf '%s\n' $_inst | grep -cE "^steer-(core|tgws)-$V-r1\$")"
        check "[2.1 $_n] прежних пакетов (модулей, мета-пакета, старого ядра) не осталось" "" \
            "$(printf '%s\n' $_inst | grep -E "^steer-[a-z0-9]+-$OV\$|^steer-[a-z0-9]+-[0-9.]+-r[0-9]+\$" | grep -vE "^steer-(core|tgws)-$V-r1\$" | tr '\n' ' ')"
        check "[2.1 $_n] kmod-tun не снят как осиротевший" "1" "$(printf '%s\n' $_inst | grep -c '^kmod-tun-')"
    }
    # 1. из фида с индексом: `apk upgrade` и `apk add` файла ядра — оба
    sc21 feed-upgrade feed none  -X "$R0/new" upgrade
    sc21 feed-addfile feed none  add $NEWF
    # 2. файлами (как ставит splify2 и описывает docs/guide.md); закрепления снимает pkg_world_heal splify2 —
    #    здесь sed по world, тот же смысл
    sc21 file-healed files heal  add $NEWF
    # 3. закрепления остались, но имена модулей названы в той же команде (снимают закрепление транзакции)
    sc21 file-pinned-named files none add $NEWF steer-vless steer-hysteria2 steer-proxy steer-xsteer steer-obfs steer-warpbox steer-extended
    # Информационно: что НЕ работает, чтобы изменение раскладки не прошло молча (ответ — в migration-2.1.md).
    for sc in "pinned-bare:files:none:add $NEWF" "core-only:feed:none:add $R0/new/$A/steer-core-$V-r1.apk"; do
        _n="${sc%%:*}"; _rest="${sc#*:}"; _k="${_rest%%:*}"; _rest="${_rest#*:}"; _pre="${_rest%%:*}"; _cmd="${_rest#*:}"
        _r="$T/r21-$_n"; old21 "$_r" "$_k"
        # shellcheck disable=SC2086
        apkr21 "$_r" -X "$R0/old" $_cmd > "$T/out21-$_n" 2>&1; _rc=$?
        printf '  [2.1 %s, информационно] %s → код %s (%s)\n' "$_n" "$_cmd" "$_rc" \
            "$(sed -n 's/^ *breaks: *//p' "$T/out21-$_n" | head -1)"
    done
    printf '\n%d проверок пройдено' "$pass"
    if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
    printf '\nвсе проверки прошли\n'
    exit 0
fi
R0="$T/repo"
mkdir -p "$R0/old/$A" "$R0/new/$A" "$R0/sys/$A" "$T/oldroot/steer" "$T/oldroot/libsteer" "$T/oldroot/wolf" \
         "$T/oldroot/vless" "$T/oldroot/ext" "$T/empty" "$T/nokeys"
cp -a "$T/apk/steer-core/." "$T/oldroot/steer/"
rm -rf "$T/oldroot/steer/usr/lib"
mkdir -p "$T/oldroot/libsteer/usr/lib" "$T/oldroot/wolf/usr/lib"
cp -a "$T"/apk/steer-core/usr/lib/libsteer.so.* "$T/oldroot/libsteer/usr/lib/"
cp -a "$T"/apk/steer-core/usr/lib/libsteer-wolfssl.so.* "$T/oldroot/wolf/usr/lib/"
cp -a "$T/apk/steer-vless/." "$T/oldroot/vless/"
cp -a "$T/apk/steer-extended/." "$T/oldroot/ext/"
# Скрипты старых пакетов пишут в журнал: порядок их вызова относительно новых — часть проверки.
for h in post pre postrm; do
    printf '#!/bin/sh\necho "OLD-%s" >> /order.log\nexit 0\n' "$h" > "$T/old.$h"
done
chmod +x "$T"/old.post "$T"/old.pre "$T"/old.postrm
mk_old() {  # ИМЯ ВЕРСИЯ ЗАВИСИМОСТИ КОРЕНЬ
    apk mkpkg --info "name:$1" --info "version:$2" --info "arch:$A" ${3:+--info "depends:$3"} \
        --script "post-install:$T/old.post" --script "pre-deinstall:$T/old.pre" \
        --script "post-deinstall:$T/old.postrm" -F "$4" -o "$R0/old/$A/$1-$2.apk" >/dev/null 2>&1
}
for d in nftables ip-full conntrack kmod-nft-queue kmod-tun; do
    apk mkpkg --info "name:$d" --info "version:1-r0" --info "arch:$A" -F "$T/empty" \
        -o "$R0/sys/$A/$d-1-r0.apk" >/dev/null 2>&1
done
for f in out/*_"$A".apk; do
    b="${f##*/}"; cp "$f" "$R0/new/$A/${b%%-$V-1_*}-$V-r1.apk"
done
mkrepos() {  # ВЕРСИЯ_СТАРЫХ (с ревизией): собрать старые пакеты и индексы всех репозиториев
    rm -f "$R0/old/$A"/*.apk
    mk_old steer "$1" "libsteer=$1 nftables ip-full conntrack kmod-nft-queue" "$T/oldroot/steer"
    mk_old libsteer "$1" "libsteer-wolfssl=$1" "$T/oldroot/libsteer"
    mk_old libsteer-wolfssl "$1" "" "$T/oldroot/wolf"
    mk_old steer-vless "$1" "steer=$1 libsteer=$1 kmod-tun" "$T/oldroot/vless"
    mk_old steer-extended "$1" "steer=$1 steer-vless=$1" "$T/oldroot/ext"
    for r in old new sys; do
        apk mkndx --allow-untrusted -o "$R0/$r/$A/APKINDEX.tar.gz" "$R0/$r/$A"/*.apk >/dev/null 2>&1
    done
}
mkroot() {
    rm -rf "$1"; mkdir -p "$1/bin" "$1/lib" "$1/etc"
    cp /bin/busybox "$1/bin/"; ln -s busybox "$1/bin/sh"
    cp /lib/ld-musl-*.so.1 "$1/lib/"
    # Заглушка rc.common: init.d/steer запускается как `/bin/sh /etc/rc.common /etc/init.d/steer ДЕЙСТВИЕ`.
    printf 'echo "RC $2" >> /order.log\n' > "$1/etc/rc.common"
    : > "$1/order.log"
}
apkr() {  # КОРЕНЬ РЕПОЗИТОРИИ... -- аргументы
    _root="$1"; _repos="$2"; shift 2
    _x=""; for _q in $_repos; do _x="$_x -X $R0/$_q"; done
    apk --root "$_root" --arch "$A" --allow-untrusted --no-network --no-cache --keys-dir "$T/nokeys" \
        --repositories-file /dev/null $_x "$@"
}
scenario() {  # ИМЯ ВЕРСИЯ_СТАРЫХ МИР_СТАРЫЙ ОЖИДАЕМЫЙ_МИР_ПОСЛЕ КОМАНДА...
    _n="$1"; _ov="$2"; _ow="$3"; shift 3
    _want="$(printf '%s\n' $1 | sort | tr '\n' ' ')"; shift
    _r="$T/r-$_n-$_ov"
    mkrepos "$_ov"
    mkroot "$_r"
    if [ -n "$_ow" ]; then apkr "$_r" "sys old" --initdb add $_ow >/dev/null 2>&1
    else apk --root "$_r" --arch "$A" --initdb add >/dev/null 2>&1; fi
    : > "$_r/order.log"
    apkr "$_r" "sys old new" "$@" >"$T/out-$_n" 2>&1
    check "[$_n, старые $_ov] команда завершилась успешно" "0" "$?"
    _inst="$(apk --root "$_r" info 2>/dev/null | sort | tr '\n' ' ')"
    check "[$_n, старые $_ov] установлено" "$_want" "$_inst"
    check "[$_n, старые $_ov] steerd, обе библиотеки и клиент у одного владельца — steer-core" \
        "steer-core steer-core steer-core steer-core" \
        "$(for f in usr/sbin/steerd usr/lib/libsteer.so.$V usr/lib/$WSO usr/sbin/steer; do
               apk --root "$_r" info -W "$f" 2>/dev/null | sed 's/.*is owned by //; s/-[0-9][0-9.]*-r[0-9]*$//'
           done | tr '\n' ' ' | sed 's/ $//')"
    # Служба: старый prerm выключил её, новый postinst обязан включить ПОСЛЕ — иначе роутер остаётся без движка после перезагрузки.
    _ord="$(cat "$_r/order.log")"
    _lastold="$(printf '%s\n' "$_ord" | grep -n '^OLD-' | tail -1 | cut -d: -f1)"
    _lastenable="$(printf '%s\n' "$_ord" | grep -n '^RC enable$' | tail -1 | cut -d: -f1)"
    if [ -n "$_lastold" ]; then
        check "[$_n, старые $_ov] служба включена после скриптов старых пакетов" "yes" \
            "$([ -n "$_lastenable" ] && [ "$_lastenable" -gt "$_lastold" ] && echo yes || echo "no")"
    else
        check "[$_n, старые $_ov] служба включена" "yes" "$([ -n "$_lastenable" ] && echo yes || echo no)"
    fi
    check "[$_n, старые $_ov] служба не выключалась новым пакетом" "0" "$(printf '%s\n' "$_ord" | grep -c '^RC disable$')"
}
WSO="$(ls "$T/apk/steer-core/usr/lib" | grep wolfssl)"
SYS="conntrack ip-full kmod-nft-queue nftables"
# Старые: заведомо меньшая версия и та же версия с меньшей ревизией (сборка того же выпуска раньше).
OVS="0.9-r1 $V-r0"
scenario clean "$V-r0" "" "$SYS kmod-tun steer-core steer-vless" add steer-core steer-vless
for ov in $OVS; do
    scenario ext "$ov" "steer-extended" \
        "$SYS kmod-tun steer-core steer-extended steer-obfs steer-tgws steer-vless steer-xsteer" upgrade
    scenario ext-add "$ov" "steer-extended" \
        "$SYS kmod-tun steer-core steer-extended steer-obfs steer-tgws steer-vless steer-xsteer" add steer-core
    scenario steer-only "$ov" "steer" "$SYS steer-core" upgrade
    scenario steer-add "$ov" "steer" "$SYS steer-core" add steer-core
    scenario vless "$ov" "steer-vless" "$SYS kmod-tun steer-core steer-vless" upgrade
done
# Удаление: пакет ядра убирает всё своё, службу выключает.
_r="$T/r-del"
mkrepos "$V-r0"; mkroot "$_r"
apkr "$_r" "sys old new" --initdb add steer-core steer-vless >/dev/null 2>&1
: > "$_r/order.log"
apkr "$_r" "sys old new" del steer-vless steer-core >/dev/null 2>&1
check "удаление: файлов движка в корне не осталось" "" \
    "$(ls "$_r"/usr/sbin "$_r"/usr/lib "$_r"/etc/init.d 2>/dev/null | tr '\n' ' ' | sed 's/^ *//')"
check "удаление: служба остановлена и выключена" "1 1" \
    "$(grep -c '^RC stop$' "$_r/order.log") $(grep -c '^RC disable$' "$_r/order.log")"

# Обновление на БОЛЕЕ НОВУЮ версию того же пакета: apk зовёт не post-install, а post-upgrade. Раньше у
# пакетов был только post-install — на OpenWrt 25.12.5 после `apk add` работал старый steerd с
# бинарником `(deleted)`, пока службу не перезапускали руками. Старые пакеты — те же имена
# (steer-core, steer-vless) заведомо меньшей версии; скрипты новых берутся из настоящих .apk.
check "steer-core (apk) несёт post-upgrade" "1" "$(grep -c 'post-upgrade' "$T/dump.steer-core")"
for m in $MODS; do
    check "steer-$m (apk) несёт post-upgrade" "1" "$(grep -c 'post-upgrade' "$T/dump.steer-$m")"
done
_r="$T/r-upg"
rm -f "$R0/old/$A"/*.apk
mk_old steer-core "0.9-r1" "" "$T/oldroot/steer"
mk_old steer-vless "0.9-r1" "steer-core=0.9-r1 kmod-tun" "$T/oldroot/vless"
for r in old new sys; do
    apk mkndx --allow-untrusted -o "$R0/$r/$A/APKINDEX.tar.gz" "$R0/$r/$A"/*.apk >/dev/null 2>&1
done
mkroot "$_r"
apkr "$_r" "sys old" --initdb add steer-core steer-vless kmod-tun >/dev/null 2>&1
check "[upgrade] старые версии встали" "0.9-r1 0.9-r1" \
    "$(apk --root "$_r" list -I 2>/dev/null | sed -n 's/^steer-\(core\|vless\)-\(0\.9-r1\) .*/\2/p' | tr '\n' ' ' | sed 's/ $//')"
: > "$_r/order.log"
apkr "$_r" "sys new" upgrade >"$T/out-upg" 2>&1
check "[upgrade] команда завершилась успешно" "0" "$?"
check "[upgrade] версии обновились" "$V-r1 $V-r1" \
    "$(apk --root "$_r" list -I 2>/dev/null | sed -n "s/^steer-\(core\|vless\)-\($V-r1\) .*/\2/p" | tr '\n' ' ' | sed 's/ $//')"
check "[upgrade] post-upgrade перезапустил службу (не меньше одного раза)" "yes" \
    "$([ "$(grep -c '^RC restart$' "$_r/order.log")" -ge 1 ] && echo yes || echo no)"
check "[upgrade] последним действием со службой был restart" "RC restart" "$(tail -1 "$_r/order.log")"
check "[upgrade] обновление не останавливает и не выключает службу" "0" \
    "$(grep -cE '^RC (stop|disable)$' "$_r/order.log")"
printf '  [upgrade] журнал служб: %s\n' "$(tr '\n' ' ' < "$_r/order.log")"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
