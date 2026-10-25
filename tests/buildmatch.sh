#!/bin/sh
# Сборочные списки против каталога с исходниками: без docker, без сети, без zig.
#
# Зачем. Релизная сборка перечисляла файлы руками в трёх местах — BASE_SRC в build.sh,
# базовый и расширенный списки в build/build-ext.sh, — а `make test` компилировал свой набор
# и про эти списки ничего не знал. Новый файл расширенной части поэтому проходил ext-syntax
# (там была маска src/ext/*.c) и весь набор тестов, а ломался только в `./build.sh`, на
# чужой машине с docker, сообщением про неопределённую ссылку (I-024). Теперь списки живут в
# одном манифесте, build/sources.mk, и стенд сверяет его с каталогами слоёв, с Android.bp и
# с тем, что сценарии сборки не завели себе копию списка.
#
# Проверять сам docker-путь нечем: образа здесь нет. Но список файлов — это текст, и
# текст сверяется текстом.
set -u
pass=0 fail=0

check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  в скрипте: %s\n' "$1" "$2" "$3"
    fi
}

names() { sed 's|.*/||' | sort -u | tr '\n' ' '; }

# ---- что лежит на диске ----------------------------------------------------
# Ядро и расширенная часть различаются каталогами слоёв (CORE_DIRS и EXT_DIRS в
# build/sources.mk): в каталоге ядра не может лежать файл, которого нет в профиле base.
. build/sources.sh
in_dirs() { for _d in $1; do ls "$_d"/*.c 2>/dev/null; done; }
# Сторонний код (THIRD_DIRS, сейчас libyaml) собирается в ядре целиком: из библиотеки в дерево
# взято только то, что входит в сборку, — поэтому его каталоги сверяются вместе с каталогами
# ядра, и лишний .c, положенный туда «на всякий случай», не пройдёт так же, как в src/lib.
# Умолчания профиля (src/profile/profile.c) — тоже ядро: они в каждой сборке; остальные файлы
# src/profile принадлежат своим профилям и сверяются ниже, у правила 3.
disk_base="$( { in_dirs "$(profile_var CORE_DIRS) $(profile_var THIRD_DIRS)"; echo src/profile/profile.c; } | names)"
disk_ext="$(in_dirs "$(profile_var EXT_DIRS)" | names)"

# ---- что перечислено в манифесте -------------------------------------------
# Сборочные списки живут в одном месте — build/sources.mk (см. его шапку); Makefile, build.sh,
# build/build-ext.sh и рецепты SDK его читают. Сверяется ОБЪЕДИНЕНИЕ профилей с каталогом:
# файл, не попавший ни в один профиль, не соберётся в релизе — и только в релизе, на чужой
# машине. Снять проверку нельзя, она стоит на этой поломке.
words() { tr ' ' '\n' | grep -v '^$'; }
# Виды выхода расширенной части (KINDS_EXT_SRC) лежат в src/kinds рядом с базовыми, но в профиль
# base не входят — их отсутствие и есть отказ «требует пакет steer-extended» (src/kinds/kind.c).
# Поэтому с каталогами ядра сверяется base вместе с ними, а их место — ниже, отдельной проверкой.
# Тот же расклад у слоя примитивов (CRYPTO_SRC, src/lib/scrypto.c): лежит в каталоге ядра, в base не
# входит — базовой сборке криптография не нужна, и wolfSSL в ней нет.
# Вид hysteria2 (KINDS_HY2_SRC) — того же рода, но только для раскладки с libsteer.so: в статические
# профили он не входит (телефон отложен), запись вида есть в libsteer, а модуль — steer-hysteria2.
m_base="$( { profile_src base; echo; profile_var KINDS_EXT_SRC; echo; profile_var KINDS_HY2_SRC; echo; profile_var KINDS_PROXY_SRC; echo; profile_var CRYPTO_SRC; } | words | names)"
# Профили разделяемой раскладки (шаг 4 выпуска 1.10: libsteer, steerd, четыре модуля) — тоже
# профили: точки входа модулей (src/modules/main_*.c) существуют только в них.
m_ext="$( { profile_src extended; echo; profile_src server; echo; profile_src tgws; echo
            for p in libsteer steerd mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox; do profile_src "$p"; echo; done; } |
          words | grep -E "^($(profile_var EXT_DIRS | tr ' ' '|'))/" | names)"
check "sources.mk: профиль base (с видами расширенной части) — это все каталоги ядра"  "$disk_base" "$m_base"
check "sources.mk: профили покрывают всю расширенную часть" "$disk_ext" "$m_ext"

# Каталог вне манифеста: файл в нём не попадёт ни в одну сборку и ни в одну проверку выше.
stray="$(for d in $(find src -type d); do
    case " $(profile_var INC_DIRS) src src/proto src/third_party " in *" $d "*) ;; *) printf '%s ' "$d" ;; esac
done)"
check "каждый каталог src описан в INC_DIRS" "" "$stray"
# Имена заголовков ниже сверяются по ВСЕМУ src, включая src/third_party: libyaml подключает свой
# yaml.h как <yaml.h> по -I, и заголовок движка с тем же именем подменил бы его молча. Поэтому
# исключения для стороннего каталога нет, а обёртка движка названа ynode.h.
# Заголовки подключаются по имени из любого слоя (-I на все каталоги), поэтому два заголовка
# с одним именем в разных каталогах молча подменяли бы друг друга порядком флагов.
check "имена заголовков в src уникальны" "" \
    "$(find src -name '*.h' | sed 's|.*/||' | sort | uniq -d | tr '\n' ' ')"
bp_inc="$(sed -n '/cc_defaults/,/^}/p' Android.bp | grep -oE '"src/[a-z_/]+"' | tr -d '"' | tr '\n' ' ')"
# За вычетом каталогов, которых нет в сборке телефона (PHONE_SKIP_DIRS, build/sources.mk).
inc_phone="$(for d in $(profile_var INC_DIRS); do
    case " $(profile_var PHONE_SKIP_DIRS) " in *" $d "*) ;; *) printf '%s ' "$d" ;; esac
done)"
check "Android.bp подключает ровно каталоги INC_DIRS (кроме PHONE_SKIP_DIRS)" "$inc_phone" "$bp_inc"

# ---- сторонний код: не правится и собирается везде одинаково -------------------------------
# libyaml лежит в дереве байт в байт как в теге upstream (суммы — в UPSTREAM рядом): правка «на
# месте» потерялась бы при первом же обновлении библиотеки, и узнали бы об этом по поведению.
check "src/third_party/libyaml совпадает с суммами UPSTREAM" "" \
    "$(cd src/third_party/libyaml && sed -n '/^sha256:/,/^$/p' UPSTREAM | grep -E '^[0-9a-f]{64}  ' |
       sha256sum -c --quiet 2>&1 | tr '\n' ' ')"
# Определения стороннего кода (THIRD_DEFS) обязаны дойти до каждой сборки, в которую входит ядро:
# без -DHAVE_CONFIG_H api.c не компилируется — громко, но только на той машине, где собирают этот
# путь (релиз, SDK, образ). Android.bp держит их во флагах libsteer_yaml, а исходники библиотеки
# там — ровно LIBYAML_SRC, и движок с ней компонуется (static_libs в steer_defaults).
for f in Makefile build.sh build/build-ext.sh build/build-ext-sdk.sh tests/ext-test.sh; do
    check "$f передаёт THIRD_DEFS" "1" \
        "$([ "$(grep -v '^[[:space:]]*#' "$f" | grep -c 'THIRD_DEFS')" -ge 1 ] && echo 1 || echo 0)"
done
bp_yaml="$(awk '/^cc_library_static \{/ { blk = "" } { blk = blk $0 "\n" } /^\}/ { if (blk ~ /name: "libsteer_yaml",/) print blk }' Android.bp)"
check "Android.bp: libsteer_yaml собирается ровно из LIBYAML_SRC" \
    "$(profile_var LIBYAML_SRC | words | sort -u | tr '\n' ' ')" \
    "$(printf '%s' "$bp_yaml" | grep -oE '"src/[a-z0-9_/]+\.c"' | tr -d '"' | sort -u | tr '\n' ' ')"
check "Android.bp: libsteer_yaml получает THIRD_DEFS" "1" \
    "$(printf '%s' "$bp_yaml" | grep -c "cflags: \[\"$(profile_var THIRD_DEFS)\"\]")"
check "Android.bp: движок компонуется с libsteer_yaml" "1" \
    "$(sed -n '/^cc_defaults/,/^}/p' Android.bp | grep -c 'static_libs: \["libsteer_yaml"\]')"

# Ядро входит в КАЖДЫЙ профиль, а общая половина xsteer — в обе роли звезды: иначе хаб (или
# пир) собрался бы без формата кадра — то есть не собрался бы вовсе.
missing_in() {  # ПРОФИЛЬ СПИСОК -> файлы списка, которых в профиле нет
    _mi_have=" $(profile_src "$1") "
    for _mi_f in $2; do
        case "$_mi_have" in *" $_mi_f "*) ;; *) printf '%s ' "$_mi_f" ;; esac
    done
}
for p in extended server tgws android; do
    check "sources.mk: профиль $p несёт всё ядро" "" "$(missing_in "$p" "$(profile_src base)")"
done
for p in extended server; do
    check "sources.mk: общая часть xsteer входит в профиль $p" "" \
        "$(missing_in "$p" "$(profile_var XS_COMMON_SRC)")"
done
# Виды выхода — файлы, и реестр ссылается на них слабо (src/kinds/kind.c): вид, выпавший из
# профиля, не ломает компоновку, а тихо становится отказом разбора. Поэтому состав сверяется
# здесь. Базовые виды входят в CORE_SRC (то есть в каждый профиль — проверка «несёт всё ядро»
# выше), виды расширенной части — в полный пакет и в прошивку телефона, и ни в какой другой.
for p in extended android; do
    check "sources.mk: виды расширенной части входят в профиль $p" "" \
        "$(missing_in "$p" "$(profile_var KINDS_EXT_SRC)")"
done
for p in base server tgws; do
    check "sources.mk: видов расширенной части нет в профиле $p" "$(profile_var KINDS_EXT_SRC)" \
        "$(missing_in "$p" "$(profile_var KINDS_EXT_SRC)" | sed 's/ $//')"
done

# ---- правило 3 (docs/architecture.md, раздел 2): сборка — набор модулей, а не набор макросов ----
#
# Профиль решает всё составом файлов: команды и виды — наличием их файлов (слабые ссылки), а
# данные профиля — файлом src/profile/<профиль>.c (src/profile/profile.h). Файл профиля обязан
# быть ровно у своего профиля: чужой дал бы бинарнику чужое имя, а мини-сборке — раскладку
# полного движка (или наоборот), и компоновка этого не заметила бы — у base файла нет вовсе, и
# его отсутствие законно. Умолчания (profile.c) идут с платформой в каждую сборку.
prof_files() { profile_src "$1" | words | grep '^src/profile/' | grep -v '^src/profile/profile\.c$' | tr '\n' ' '; }
for p in base extended server tgws android; do
    case "$p" in base) want="" ;; android) want="src/profile/extended.c " ;; *) want="src/profile/$p.c " ;; esac
    check "sources.mk: файл профиля $p — ровно свой" "$want" "$(prof_files "$p")"
done
check "sources.mk: умолчания профиля — в PLATFORM_SRC" "1" \
    "$(profile_var PLATFORM_SRC | words | grep -c '^src/profile/profile\.c$')"
check "каждый файл src/profile — в каком-то профиле" "" \
    "$(for f in src/profile/*.c; do
         case " $(profile_src base) $(profile_src extended) $(profile_src server) $(profile_src tgws) " in
           *" $f "*) ;; *) printf '%s ' "$f" ;; esac
       done)"
# Прежние ключи профилей сняты: ни кода под ними в src (комментарии не в счёт — в прозе история
# упоминается законно), ни -D в путях сборки. Появись такой ключ снова, путь, который его
# забыл, собрал бы бинарник соседнего профиля — ровно то, от чего избавлял переход.
profbad=""
for f in $(find src \( -name '*.c' -o -name '*.h' \)); do
    n=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" | grep -cE '\<STEER_(EXTENDED|SERVER|TGWS)\>')
    [ "$n" -gt 0 ] && profbad="$profbad$f:$n "
done
check "в src нет макросов профилей STEER_EXTENDED/SERVER/TGWS (правило 3)" "" "$profbad"
check "пути сборки не передают ключей профилей -DSTEER_EXTENDED/SERVER/TGWS" "0" \
    "$(grep -hvE '^[[:space:]]*(#|//)' Makefile Android.bp build/sources.mk build.sh build/build-ext.sh \
         build/build-ext-sdk.sh tests/ext-test.sh |
       grep -cE -- '-DSTEER_(EXTENDED|SERVER|TGWS)\>'; true)"

# Сценарии сборки не перечисляют исходники сами: копия списка — ровно то, что расходилось
# молча (у рецептов SDK и нативного к моменту перевода на манифест не хватало шести файлов).
# Строки комментариев не считаются: в прозе пути упоминаются законно.
for f in build.sh build/build-ext.sh build/build-ext-sdk.sh; do
    check "$f: исходники берёт из манифеста, а не перечисляет сам" "" \
        "$(grep -v '^[[:space:]]*#' "$f" | grep -oE 'src/[a-z0-9_/]+\.c' | tr '\n' ' ')"
done
check "Makefile: сборки движка берут ядро из манифеста" "0" \
    "$(grep -c 'src/dnsd\.c src/failover\.c' Makefile; true)"

# Android.bp: Soong чужих файлов не читает, поэтому список там остаётся — но сверяется с
# профилем android, чтобы новый файл не собрался везде, кроме прошивки телефона.
# Модулей три: движок (steer_defaults + steerd) и клиент steer — его список (CLIENT_SRC) сверяется
# отдельно, по блоку модуля.
bp="$(grep -oE '"src/[a-z0-9_/]+\.c"' Android.bp | tr -d '"' | sort -u | tr '\n' ' ')"
check "Android.bp перечисляет ровно профиль android и клиент" \
    "$( { profile_src android; echo; profile_var CLIENT_SRC; } | words | sort -u | tr '\n' ' ')" "$bp"
bp_client="$(awk '/^cc_binary \{/ { blk = "" } { blk = blk $0 "\n" } /^\}/ { if (blk ~ /name: "steer",/) print blk }' Android.bp |
             grep -oE '"src/[a-z0-9_/]+\.c"' | tr -d '"' | sort -u | tr '\n' ' ')"
check "Android.bp: клиент steer собирается ровно из CLIENT_SRC" \
    "$(profile_var CLIENT_SRC | words | sort -u | tr '\n' ' ')" "$bp_client"
check "Android.bp: движок ставится как steerd со ссылкой steer-tools" "1 1" \
    "$(grep -c 'stem: "steerd"' Android.bp) $(grep -c 'symlinks: \["steer-tools"\]' Android.bp)"

# ---- переменная, которую никто не читает -----------------------------------
# Присвоенная и ни разу не использованная переменная в сборочном скрипте — это список,
# который выглядит действующим и не действует. Так в build.sh жили BASE_SRC_ABS и
# EXT_SRC_ABS: build-ext.sh запускается отдельным процессом с тремя аргументами, ничего
# не экспортируется, и правка этих строк не меняла в сборке ничего (I-032).
for f in build.sh build/build-ext.sh build/bench.sh; do
    dead=""
    for v in $(grep -oE '^[A-Z_][A-Z0-9_]*=' "$f" | tr -d '='); do
        # Присвоение не считается использованием, поэтому строки `V=` отбрасываются.
        if [ "$(grep -v "^$v=" "$f" | grep -c "\\\$$v\|\${$v")" -eq 0 ]; then
            dead="$dead$v "
        fi
    done
    check "$f: нет переменных, которые никто не читает" "" "$dead"
done

# ---- контракт журнала: у каждой строки есть уровень ---------------------------
# Контракт (docs/contract-v1.md §5) обещает управляющему слою, что всякая строка, которую
# движок пишет ВО ВРЕМЯ РАБОТЫ, начинается с steer[warn] или steer[info]. Обещание жило
# только на бумаге: префикс ставили обфускатор и расширенная часть, а базовый движок писал
# голое «steer: », и интерфейс splify2 подписывал свежие строки как «от более старого
# движка». Сверяется здесь, потому что расхождение это текстовое и молчаливое.
#
# Голое «steer: » законно ровно в двух случаях: die() — отказ вызывающему, и разбор
# аргументов. Оба заканчиваются кодом 2 и до журнала не доходят, о чём сказано в контракте.
bare=""
for f in src/daemon/main.c src/cli/modcmd.c src/daemon/failover.c src/lib/sindex.c src/lib/nftnl.c src/lib/ctnl.c src/dnsd/rules.c src/dnsd/wire.c src/dnsd/origdst.c src/dnsd/fakeip.c src/dnsd/table.c src/dnsd/dlog.c src/dnsd/realip.c src/dnsd/adopt.c src/dnsd/proxy.c src/dnsd/main.c src/proto/obfs/obfs.c src/tools/srsread.c src/model/srs.c src/model/srsplan.c; do
    # grep -c печатает 0 и выходит с кодом 1, когда совпадений нет, — поэтому «|| echo 0»
    # добавлял бы вторую строку и ломал сравнение числа.
    n=$(grep -c 'fprintf(stderr, "steer: ' "$f" 2>/dev/null); [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && bare="$bare$f:$n "
done
# main.c: три законные строки — отказ «хаб xsteer этой сборки нет» (хаб — архив для VPS, а не
# модуль), «флаги идут после команды» и отказ reload/subscribe движком (их исполняет демон, а
# посылает клиент steer). Остальные шесть строк, что были здесь до 1.10, переехали вместе с
# командами модулей в cli/modcmd.c.
#
# modcmd.c: шесть законных строк — «команды модуля нет в этой сборке, нужен пакет» (одна, общая
# для всех модулей: текст с контрактной подстрокой steer-extended живёт в одном месте), «не
# удалось запустить модуль», неизвестное слово у tgws-probe (I-316), --insecure у *-nodes и
# *-probe с именем выхода вместо файла подписки и два отказа флага --platform (без значения,
# нет такой платформы) — разбор аргументов. Все они
# заканчиваются кодом 2 и до журнала не доходят, о чём сказано в контракте §5. Больше ни в
# одном файле голых быть не должно.
#
# srsread.c: десять строк, и все десять — отказы команды `srs-read`: набор не разобран (текст
# отказа — от читателя, src/model/srs.c), не выразим тремя файлами, сужение есть, а печатать
# его некуда, файл вывода не создался или не записался до конца. Команда в этих случаях
# заканчивается кодом 1 или 2, а напечатанный список объявлен негодным к применению (см. шапку
# srsread.h), то есть до журнала эти строки не доходят так же, как die(). Сам читатель
# (src/model/srs.c, srsplan.c) в stderr не пишет вовсе — он возвращает отказ и текст снятого.
# Две строки srsread.c печатаются при УДАВШЕМСЯ разборе — снятые правила и пропущенные подсети
# IPv6, — и у них уровень есть; проверка ниже сторожит именно это различие.
check "голых «steer: » ровно столько, сколько отказов вызывающему" "src/daemon/main.c:3 src/cli/modcmd.c:6 src/tools/srsread.c:10 " "$bare"
# Строки, которые печатаются при успехе, обязаны иметь уровень: разбор удался, значит это
# журнал во время работы, а не отказ вызывающему.
check "предупреждения srs-read при удавшемся разборе идут с уровнем" "2" \
    "$(grep -c 'steer\[warn\] srs' src/tools/srsread.c)"
check "и голым «steer: » про IPv6 не пишется" "0" \
    "$(grep -c 'fprintf(stderr, "steer: srs: в наборе' src/tools/srsread.c)"

# ---- правило 5 (docs/architecture.md, раздел 2): модель и компилятор не умирают сами -------
# Решение владельца: ошибки возвращаются. Модели (src/model) и компилятору (src/compile) die()
# не нужен — они возвращают код и заполняют struct err (err_set/err_prop), а завершает процесс
# только точка входа (err_die), которой к этому моменту уже известно, что случилось. lib
# (src/lib) — туда же, кроме самого src/lib/err.c: там die()/err_die() и живут, ради точек
# входа.
#
# Зачем это стенду, а не только код-ревью. Модуль, который может позвать exit() сам, нельзя
# собрать в стенд без перехвата exit — то есть без setjmp/longjmp поверх макроса, как раньше
# было в specmatch.c и awgmatch.c (до перехода на struct err отказ разбора проверялся только
# кодом завершения процесса, а не кодом возврата функции). Одной строкой die()/exit() в
# src/model или src/compile этот путь возвращается тихо — стенд не упадёт сразу, просто
# перестанет видеть отказы, которые раньше ловил кодом возврата.
#
# Комментарии и сам err.c — не в счёт: `*` и `//` в начале строки после обрезки пробелов
# считаются прозой, а не кодом (тот же приём, что и у прочих текстовых проверок этого файла).
diebad=""
for d in src/model src/compile src/lib; do
    for f in "$d"/*.c; do
        [ -f "$f" ] || continue
        case "$f" in src/lib/err.c) continue ;; esac
        n=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" | grep -cE '\<(die|exit)\(')
        [ -n "$n" ] || n=0
        [ "$n" -gt 0 ] && diebad="$diebad$f:$n "
    done
done
check "в src/model, src/compile и src/lib (кроме err.c) нет die()/exit()" "" "$diebad"

# Старое имя проекта в журнале: строка с ним не содержит подстроки steer, а rpcd собирает
# журнал как `logread | grep steer` — значит в интерфейс она не попадала никогда. Резолвер —
# теперь несколько файлов src/dnsd (дьявол раньше жил в одном dnsd.c), проверяются все.
# ---- правило 1 (docs/architecture.md, раздел 2): общий код спрашивает вид, а не сравнивает его ----
# Всё, что знает о виде выхода, лежит в src/kinds/<вид>.c и отдаётся таблицей struct kind_ops;
# общий код спрашивает её биты (out_has_device и соседи в spec.h) и функции. Сравнение с
# конкретным видом вне src/kinds — это знание о виде, размазанное по движку: новый вид требует
# найти все такие места, а забытое место — выход, который настроен и молча не работает.
#
# Что считается сравнением: прежние имена видов (OUT_DIRECT… — в kind.h они оставлены только
# для стендов, которые собирают выход конкретного вида в обход разбора спеки), записи видов по
# имени (kind_direct… — сравнение указателя с ними и есть сравнение вида) и сравнение поля kind
# с адресом (`->kind == &…`). Имя вида строкой в strcmp рядом с kind_of — та же проверка в
# другой одежде. Группа (kind_group, OUT_GROUP) — тоже вид: «это группа?» спрашивают out_group
# (src/kinds/group.c), а перевод v1 собирает её group_of_devices. Комментарии не в счёт.
#
# src/compile здесь наравне с остальным движком: построители видов (tgws) переехали в
# kind_ops.emit (src/kinds), а has_tgws — в tgws_present там же;
# генератор зовёт их через kind_emit_all, не зная имён видов.
kindbad=""
for f in $(find src -name '*.c' -o -name '*.h' | sort); do
    case "$f" in src/kinds/*) continue ;; esac
    n=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" |
        grep -cE '\<OUT_(DIRECT|INTERFACE|VLESS|XSTEER|TGWS|AWG|GROUP)\>|\<kind_(direct|interface|vless|xsteer|tgws|awg|group)\>|(->|\.)kind *[!=]= *&|kind_of\([^)]*\)->name *, *"|"(direct|interface|vless|xsteer|tgws|awg|group)" *, *kind_of')
    [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && kindbad="$kindbad$f:$n "
done
check "вне src/kinds вид выхода не сравнивается" "" "$kindbad"

check "имени splify-dnsd в сообщениях журнала нет" "0" \
    "$(grep -c 'fprintf(stderr, "splify-dnsd' src/dnsd/*.c | awk -F: '{s+=$2} END{print s+0}')"

# ---- барьер релиза ловит все виды отказа сборки ------------------------------
# build.sh печатает про отказ и ИДЁТ ДАЛЬШЕ — это верно для локальной работы, а в релизе
# барьер в .github/workflows/release.yml обязан такой прогон завалить. Барьер искал одно
# слово FAILED, а его печатает только компиляция: упаковка сообщает о себе другими
# словами, и релиз уходил с неполным набором пакетов молча.
#
# Сверяется не текст с текстом, а СОСТАВ: каждая строка, которой build.sh сообщает об
# отказе, обязана попадать под образец в барьере. Новый вид отказа с новой формулировкой
# стенд поймает здесь, а не пользователь — в релизе без своей архитектуры.
wf=.github/workflows/release.yml
# Берётся образец ИМЕННО того grep, который читает журнал сборки: в файле есть и другие
# (например, проверка формата версии), и «первый попавшийся» брал не тот.
pat="$(grep 'build\.log' "$wf" | grep -o "grep -qE '[^']*'" | head -1 | sed "s/grep -qE '//;s/'$//")"
check "барьер релиза задан образцом" "1" "$([ -n "$pat" ] && echo 1 || echo 0)"
missed=""
for msg in "FAILED" "не удалась" "packaging failed"; do
    grep -q "$msg" build.sh || continue
    printf '%s\n' "$msg" | grep -qE "$pat" || missed="$missed[$msg] "
done
check "барьер релиза ловит все отказы build.sh" "" "$missed"

# Ожидаемое число пакетов барьер считает из build.sh. Сверяем, что счёт вообще работает:
# ноль архитектур означал бы барьер, требующий ноль пакетов, то есть отключённый.
arch_n=$(sed -n '/^ISAS="/,/^"$/p' build/arches.sh | grep -c '^[a-z0-9_.-]*:')
check "архитектуры в build/arches.sh считаются" "1" "$([ "$arch_n" -ge 1 ] && echo 1 || echo 0)"
check "барьер релиза считает архитектуры тем же образцом" "1" \
    "$(grep -c "sed -n '/\^ISAS=\"/,/\^\"\$/p' build/arches.sh | grep -c '\^\[a-z0-9_.-\]\*:'" "$wf")"
# И число пакетов на архитектуру — из OURS в build.sh, а не константой: steer-warpbox добавил
# девятый пакет, барьер ждал восемь, и выпуск 2.1.0 падал на собранном полном наборе.
pkg_n=$(sed -n 's/^OURS="\(.*\)"$/\1/p' build.sh | wc -w)
check "пакеты в OURS build.sh считаются" "1" "$([ "$pkg_n" -ge 1 ] && echo 1 || echo 0)"
check "барьер релиза считает пакеты из OURS, а не числом" "1" "$(grep -c 'want=\$((arch_n \* pkg_n))' "$wf")"

# ---- два формата пакета и архив для VPS --------------------------------------
# OpenWrt 24.10 перешёл на apk, но 23.05 и 22.03 живут на роутерах и будут жить: на 4/32
# их никто не обновит. Пакет собирается в обоих форматах из одного дерева файлов, и
# забыть один формат легко — он ничего не ломает в сборке, просто половина устройств
# остаётся без пакета. Поэтому оба вида упаковки сверяются здесь по составу.
# Пакетов на архитектуру семь (steer-core, пять модулей и мета-пакет steer-extended), и обе
# упаковки для всех идут через ОДНУ функцию pack в build.sh (apk mkpkg и mk_ipk из одного
# дерева): забыть формат у одного пакета из семи нельзя, не забыв его у всех. Поэтому
# сверяется, что каждый пакет упаковывается и что функция зовёт оба формата.
for pkg in steer-core steer-extended; do
    check "build.sh упаковывает $pkg" "1" "$(grep -c "^ *pack $pkg " build.sh)"
done
# Раскладка: библиотеки — внутри steer-core, отдельных пакетов libsteer и libsteer-wolfssl нет
# (иначе у ядра и у библиотек снова было бы по имени, которое надо держать в одной версии).
check "отдельных пакетов библиотек нет" "0" \
    "$(grep -c '^ *pack libsteer' build.sh)"
check "обе библиотеки кладутся в корень steer-core" "1" \
    "$(grep -c 'cp "\$libs"/libsteer.so.\* "\$libs"/libsteer-wolfssl.so.\* "\$root/usr/lib/"' build.sh)"
check "модуль не несёт библиотек ядра" "0" \
    "$(sed -n '/^    for m in vless xsteer/,/^    done/p' build.sh | grep -c 'libsteer')"
# Миграция со старых пакетов: provides и replaces имени steer, конфликт с steer, libsteer и
# libsteer-wolfssl — в обоих форматах (apk: `!имя` в depends, opkg: Conflicts).
check "steer-core заменяет и вытесняет steer, libsteer, libsteer-wolfssl" "1" \
    "$(grep -c 'steer "steer libsteer libsteer-wolfssl" "steer libsteer libsteer-wolfssl"$' build.sh)"
check "pack пишет конфликты как !имя (apk) и Conflicts (opkg)" "1 1" \
    "$(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c '_dall="\$_dall !\$_c"') $(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c "Conflicts: ")"
check "pack пишет Replaces и Provides в обоих форматах" "1 1 1 1" \
    "$(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c -- '--info replaces:') $(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c -- '--info provides:') $(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c 'Replaces: ') $(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c 'Provides: ')"
check "build.sh упаковывает модули по кругу vless xsteer obfs tgws hysteria2 proxy warpbox" "1 1" \
    "$(grep -c '^ *pack "steer-\$m" ' build.sh) $(grep -c '^    for m in vless xsteer obfs tgws hysteria2 proxy warpbox; do' build.sh)"
check "pack зовёт apk mkpkg и mk_ipk из одного дерева" "1 1" \
    "$(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c 'apk mkpkg') $(sed -n '/^    pack() {/,/^    }/p' build.sh | grep -c 'mk_ipk ')"
# Мета-пакет steer-extended ставит ядро и четыре модуля (имя ждёт splify2, пакет устарел), а
# модули зависят от ядра. Системные зависимости 1.5.x он повторяет, иначе opkg при переходе с
# steer-extended 1.5.x снимает ip-full, conntrack, kmod-nft-queue и kmod-tun как осиротевшие.
check "steer-extended зависит от ядра и четырёх модулей" "1" \
    "$(grep -c 'pack steer-extended "\$xroot" "steer-core steer-vless steer-xsteer steer-obfs steer-tgws ' build.sh)"
check "steer-extended повторяет системные зависимости ядра и модуля с TUN" "1" \
    "$(grep 'pack steer-extended' build.sh | grep -c 'pkg_deps "" core) $(pkg_deps "" tun)')"
check "steer-extended помечен устаревшим в описании" "1" \
    "$(grep -A1 'pack steer-extended' build.sh | grep -c 'steer-extended (устарел')"
# steer-hysteria2 — отдельный пакет: мета-пакет его не ставит (решение владельца), и вид без модуля
# отвечает «требует пакет steer-hysteria2», а не отсылкой к steer-extended.
check "steer-extended не включает steer-hysteria2" "0" \
    "$(grep 'pack steer-extended' build.sh | grep -c hysteria2)"
check "steer-extended не включает steer-proxy" "0" \
    "$(grep 'pack steer-extended' build.sh | grep -c steer-proxy)"
check "модули зависят от steer-core" "1" "$(grep -c 'mdeps="steer-core \$(pkg_deps' build.sh)"
check "список наших пакетов — новая раскладка (steer-core, модули, мета)" "1" \
    "$(grep -c '^OURS=" steer-core steer-vless steer-xsteer steer-obfs steer-tgws steer-hysteria2 steer-proxy steer-warpbox steer-extended "$' build.sh)"
# Зависимости между нашими пакетами — точной версии (формат линии событий и ABI libsteer между
# выпусками не обещаны).
check "наши пакеты зависят друг от друга точной версией (apk и opkg)" "1 1" \
    "$(grep -c '%s=%s-r1' build.sh) $(grep -c '(= %s-1)' build.sh)"

# ---- стенды расширенной части прогоняются в релизе --------------------------------------
# `make test` в релизе стендов расширенной части не касается: криптобиблиотеки там нет по построению. Они идут
# отдельным шагом ВНУТРИ образа сборки, где библиотека та самая, которой собирается
# расширенный пакет (R-063). Забыть этот шаг легко и тихо: релиз от этого не краснеет,
# просто рукопожатие, освобождение ключей и арифметика хаба перестают кем-либо стеречься.
check "обвязка прогона в образе есть и исполняема" "yes" \
    "$([ -x build/ext-test-image.sh ] && echo yes || echo no)"
check "релиз зовёт стенды расширенной части в образе" "1" \
    "$(grep -c 'build/ext-test-image.sh' "$wf")"
check "обвязка в образе зовёт tests/ext-test.sh" "1" \
    "$(grep -c 'BUILD=.*sh tests/ext-test.sh' build/ext-test-image.sh)"
# Громкий пропуск ext-test.sh выходит НУЛЁМ (так задумано), поэтому шаг обязан проверять
# признак прохода отдельно — иначе он зелёный, не прогнав ни одного стенда.
check "релиз отличает пропуск от прохода" "1" \
    "$(grep -c "grep -q 'ext-test: все стенды прошли'" "$wf")"
check "признак прохода печатает сам ext-test.sh" "1" \
    "$(grep -c 'ext-test: все стенды прошли' tests/ext-test.sh)"
# Комментарий про «ext-test сознательно оставлен за барьером» стоял в шаге `make test` и
# после появления отдельного шага стал неправдой. Проверка стоит на том, чтобы вранье не
# вернулось: старая формулировка объясняла ОТСУТСТВИЕ прогона.
check "в релизе нет комментария об отсутствии ext-test" "0" \
    "$(grep -c 'Чего в барьере НЕТ' "$wf")"

# ---- сборочные списки ЗАМКНУТЫ по #include ------------------------------------
# Проверки выше сверяют списки с КАТАЛОГОМ: файл, не попавший ни в одну роль и ни в один
# стенд, здесь уже не пройдёт. Но объединение ролей ничего не говорит про каждую роль
# отдельно, а списки стендов ext-test.sh вообще не сверялись ни с чем — и именно там дважды
# подряд сломалась сборка.
#
# Как это выглядело. src/tools/srs.c появился 5 сентября: серверный список стенда его не получил, и
# `make ext-test` перестал собираться вовсе — падал на `undefined reference to srs_dump`.
# Урок записали в шапку ext-test.sh («барьер, который нужно ЗАПУСТИТЬ РУКАМИ, не барьер») и на
# том остановились. Через три дня то же с src/proto/tls/certverify.c: tls13.c стал звать проверку
# сертификата, файл внесли в EXT_ROUTER — а tls13.c лежит в XS_COMMON, то есть компилируется
# ВСЕМИ тремя ролями. Роли server и tgws перестали компоноваться, и ни один стенд ext-test —
# включая spokematch, единственный барьер против утечки контекстов шифра (I-067), — тоже.
#
# Сверяется ЗАМЫКАНИЕ: если список компонует файл, который включает чужой заголовок, а рядом
# с этим заголовком лежит .c, — этот .c обязан быть в том же списке. Файлы каталогов ядра
# считаются присутствующими всегда: они входят в каждую роль и в каждый стенд, а полноту их
# перечня держат проверки выше.
#
# Замыкание, а не один шаг: файл, притянутый включением, тянет за собой свои включения.
# Файлы профилей (src/profile) включением не притягиваются: заголовок у них общий (profile.h), а
# какой файл взять, решает профиль — это сверено выше («файл профиля — ровно свой»). Умолчания
# (profile.c) идут с платформой в каждую сборку и считаются присутствующими, как ядро.
closure_missing() {  # СПИСОК ФАЙЛОВ -> те, которых в нём нет, а включают их те, что есть
    _cm_core="$(in_dirs "$(profile_var CORE_DIRS)" | tr '\n' ' ') src/profile/profile.c"
    _cm_have=" $(printf '%s' "$1" | tr '\n' ' ') $_cm_core "
    _cm_work="$1 $_cm_core"
    _cm_seen=" "
    _cm_need=""
    while [ -n "$(printf '%s' "$_cm_work" | tr -d ' \n')" ]; do
        _cm_next=""
        for _cm_f in $_cm_work; do
            case "$_cm_seen" in *" $_cm_f "*) continue ;; esac
            _cm_seen="$_cm_seen$_cm_f "
            [ -f "$_cm_f" ] || continue
            for _cm_h in $(grep -oE '#include "[a-z0-9_]+\.h"' "$_cm_f" |
                           sed 's/.*"\(.*\)"/\1/'); do
                _cm_b="${_cm_h%.h}"
                for _cm_c in $(for _cm_d in $(profile_var INC_DIRS); do echo "$_cm_d/$_cm_b.c"; done); do
                    [ -f "$_cm_c" ] || continue
                    case "$_cm_c" in src/profile/*) continue ;; esac
                    case "$_cm_have" in *" $_cm_c "*) continue ;; esac
                    case " $_cm_need" in *" $_cm_c "*) continue ;; esac
                    _cm_need="$_cm_need$_cm_c "
                    _cm_next="$_cm_next $_cm_c"
                done
            done
        done
        _cm_work="$_cm_next"
    done
    printf '%s' "$_cm_need"
}

# Списки стендов ext-test.sh — проверяются ОБЪЕДИНЕНИЕМ: расписывать, какому стенду что
# нужно, значило бы завести здесь третью копию тех же списков. Строки комментариев
# отбрасываются: в шапке ext-test.sh пути упоминаются прозой («Включает src/proto/xsteer/xshub.c»), а
# упоминание в комментарии — не компоновка.
et_list="$(grep -v '^[[:space:]]*#' tests/ext-test.sh |
           grep -oE 'src/[a-z0-9_/]+\.c' | sort -u)"
check "стенды ext-test.sh компонуют всё, что включают" "" "$(closure_missing "$et_list")"

# Профили — каждый отдельно. Общая половина проверяется вместе с тем профилем, в который
# входит, а не сама по себе: файл, нужный только клиентской половине, законно лежит в
# EXT_ROUTER_SRC, и требовать его от профиля server было бы неверно.
for p in extended server tgws android; do
    check "sources.mk: профиль $p замкнут" "" "$(closure_missing "$(profile_src "$p" | words)")"
done

# ---- ревизия попадает во ВСЕ пути сборки --------------------------------------
# Пути сборки движка три: Makefile (локально и стенды), build.sh (базовый пакет) и
# build/build-ext.sh (расширенный пакет и хаб). Забыть define в одном из них не ломает
# ничего заметного — просто ровно тот бинарник начинает отвечать «ревизия неизвестна», и
# именно он окажется тем, который надо было отличить от релиза (R-045).
for f in Makefile build.sh build/build-ext.sh; do
    check "$f подставляет STEER_REV" "1" "$(grep -c 'STEER_REV' "$f")"
done
# Считается ВНЕ docker: в образе нет ни git, ни каталога .git, и describe там вернул бы
# пустоту при любом состоянии дерева — то есть «неизвестна» на каждой релизной сборке.
check "build.sh берёт ревизию до docker" "1" \
    "$(grep -c '^REV="\$(git describe' build.sh)"
# Умолчание обязано быть честным: подставленное число, ничему не соответствующее, хуже
# отсутствующего — по нему нельзя отличить сборку, а выглядит оно как можно.
check "у ревизии честное умолчание в движке" "1" \
    "$(grep -c '#define STEER_REV "неизвестна"' src/cli/cli.c)"

# ---- настройки объявлены системе ---------------------------------------------
# sysupgrade и «Создать архив» в LuCI собирают список файлов из /etc/sysupgrade.conf и
# /lib/upgrade/keep.d/*, и всё, чего в этом списке нет, обновление прошивки теряет молча
# (I-037). Проверяется и сам файл, и то, что он попадает в ОБА дерева пакета: забыть его в
# расширенном — это вернуть потерю настроек ровно тому пакету, который ставят чаще.
# ---- версия пакета -----------------------------------------------------------
# Этой строкой собираются имя файла пакета, версия для apk/opkg и тег релиза, а интерфейс
# splify2 читает её через менеджер пакетов и сравнивает с релизами. Кодовое имя выпуска
# («26.9 Andromeda») живёт в заголовке релиза на GitHub, а не здесь: пробел в имени файла
# пакета не переживёт ни apk, ни URL.
check "в build.sh есть барьер на форму VERSION" "1" \
    "$(grep -c "''|\*\[!0-9.\]\*)" build.sh)"
check "VERSION в дереве проходит свой же барьер" "yes" \
    "$(V="$(cat VERSION)"; case "$V" in ''|*[!0-9.]*) echo no ;; *) echo yes ;; esac)"
# Версия из двух частей законна: «26.9» — такой же выпуск, как «1.2.0». Барьер обязан её
# пропускать, иначе он отвергнет собственный релиз проекта.
check "версия из двух частей барьером не отвергается" "yes" \
    "$(V=26.9; case "$V" in ''|*[!0-9.]*) echo no ;; *) echo yes ;; esac)"
check "кодовое имя в VERSION барьер отвергает" "no" \
    "$(V='26.9 Andromeda'; case "$V" in ''|*[!0-9.]*) echo no ;; *) echo yes ;; esac)"

KEEP=files/lib/upgrade/keep.d/steer
check "файл keep.d есть в репозитории" "yes" "$([ -f "$KEEP" ] && echo yes || echo no)"
# sub.userinfo — остаток трафика подписки, названный панелью в заголовке ответа. Пишет его
# управляющий слой (splify2), а объявлен он здесь потому, что лежит в каталоге движка и
# теряется тем же молчанием, что и подписка: обзор после обновления прошивки говорил бы
# «панель не сообщает остаток» о панели, которая сообщает.
#
# Каталог подписок и каталог СВОИХ списков объявлены с запуска 65. Оба заводит splify2, и оба
# невосстановимы: несколько подписок со своим учётом остатка живут в /etc/steer/subs, а
# /etc/steer/lists/custom человек набивает руками — перекачать его неоткуда.
#
# spec.yaml — спека v2 в YAML рядом со spec.json (1.9, docs/spec-v2.md): без неё в списке
# обновление прошивки «с сохранением настроек» оставляло роутер без спеки.
#
# select — выбор члена группы pick: manual командой select (1.9): лежит рядом со спекой, чтобы
# пережить перезагрузку (каталог состояния — tmpfs), и обязан пережить и обновление прошивки.
#
# awg — файлы выходов kind: awg по умолчанию (<etc>/awg/<выход>.conf, src/kinds/awg.c): ключи
# туннеля, которые человек положил сам; без каталога в списке обновление прошивки оставляло выход
# без конфига.
for f in /etc/steer/spec.json /etc/steer/spec.yaml /etc/steer/select /etc/steer/sub.txt /etc/steer/sub.userinfo \
         /etc/steer/subs /etc/steer/lists/custom /etc/steer/awg /etc/steer/xsteer; do
    check "keep.d объявляет $f" "1" "$(grep -cx "$f" "$KEEP")"
done
# Ни комментариев, ни пустых строк, ни относительных путей: файл читает не человек, а
# sysupgrade, и строка, не являющаяся путём, в лучшем случае бесполезна, а в худшем уносит
# в архив не то, что задумано. Считается число строк, НЕ начинающихся со слэша.
check "в keep.d только абсолютные пути" "0" "$(grep -cv '^/' "$KEEP")"
# Каталог списков в keep.d НЕ берётся намеренно: это десятки файлов и сотни килобайт в
# архиве, а списки восстанавливаются по расписанию. Решение владельца — splicicd#6;
# проверка стоит на том, чтобы каталог не попал туда «заодно», без этого решения.
#
# Вторая половина обоснования — «отсутствующий список не мешает применению» — до запуска 57
# ссылалась на H-012 и была НЕВЕРНА: H-012 про интерфейс, а apply умирал на первом же
# непрочитанном файле (проверено опытом: код возврата 2, таблицы нет вовсе, весь роутер
# напрямую — I-136). Теперь она верна по-настоящему: пропавший список уносит свои адреса, его
# канал остаётся в наборе правил пустым, остальные каналы работают. Стенд на это —
# в tests/gen.sh, «пропавший список канала не рушит ВЕСЬ набор правил».
# Строка стояла как `grep -c '/etc/steer/lists'` = 0 и была верна, пока в каталоге лежали
# только списки издателя. Со появлением своих списков (list_put) она стала запрещать И ИХ:
# решение splicicd#6 обосновано тем, что «списки восстанавливаются по расписанию», а свой
# список не восстанавливается ниоткуда — его набивал человек. Поэтому проверка разделена на
# две: сам каталог издателя по-прежнему запрещён, подкаталог custom обязателен.
#
# `find` в sysupgrade рекурсивен по каталогу из keep.d, поэтому одна строка `.../lists/custom`
# берёт свои списки и НЕ берёт лежащие рядом файлы издателя — исключений выражать не нужно.
check "keep.d не тащит каталог списков издателя" "0" \
    "$(grep -cx '/etc/steer/lists' "$KEEP")"
check "и не тащит его файлы поимённо" "0" \
    "$(grep -c '^/etc/steer/lists/[^c]' "$KEEP")"
check "но свои списки объявлены" "1" \
    "$(grep -cx '/etc/steer/lists/custom' "$KEEP")"
check "build.sh кладёт keep.d в пакет ядра" "1" \
    "$(grep -c 'cp files/lib/upgrade/keep.d/steer' build.sh)"

# Серверная половина. Установщик обязан уметь работать БЕЗ компилятора — ради этого архив
# и собирается; проверка ловит откат к «всегда собираем из исходников».
check "install.sh берёт готовый бинарник, если он рядом" "1" \
    "$(grep -c 'if \[ -x "\$here/steer" \]' server/install.sh)"
check "build.sh кладёт архив steer-obfs в out" "1" \
    "$(grep -c 'tar -C build -czf "\$OUT/steer-obfs' build.sh)"

# Каждое слово в профилях обязано быть существующим файлом .c.
#
# Проверка ловит класс, который уже сломал релиз: строка списка кончалась ДВУМЯ обратными
# слэшами, а в двойных кавычках это литеральный слэш — он уехал в линковщик отдельным
# аргументом, и сборка падала с «ld.lld: error: cannot open \». Локально это не видно вовсе:
# локально собирают прямыми командами cc, а не сценарием релиза, поэтому первым узнаёт релиз.
# Проверяется обратное полноте: что в списке нет ничего, кроме имён существующих файлов.
junk=''
for p in base extended server tgws android; do
    for w in $(profile_src "$p"); do
        case "$w" in
            src/*.c) [ -f "$w" ] || junk="$junk $p:$w" ;;
            *) junk="$junk $p:$w" ;;
        esac
    done
done
check "в профилях sources.mk только существующие файлы .c" "" "$junk"

# ---- установщик хаба xsteer ----------------------------------------------------
# Хаб — вторая серверная половина, и у неё свой установщик с меню (пира приходят и уходят).
# Проверяется не текст, а решения, каждое из которых уже стоило отдельного разбора.
check "xs_install.sh исполняемый" "yes" \
    "$([ -x server/xs_install.sh ] && echo yes || echo no)"
# Компилятора в нём нет НАМЕРЕННО: системная wolfSSL собрана с чужими опциями, а раскладка её
# структур от них зависит (build/wolfssl/user_settings.h), то есть собралась бы тихо не та
# криптография. Проверка ловит откат к «соберём на месте».
check "xs_install.sh не собирает хаб на месте" "0" \
    "$(grep -cE '^[^#]*\b(cc|gcc|clang|make)\b' server/xs_install.sh)"
check "xs_install.sh берёт готовый бинарник, если он рядом" "1" \
    "$(grep -c 'if \[ -x "\$here/steer-hub" \]' server/xs_install.sh)"
# /dev/net/tun проверяется ДО вопросов: без него хаб не может отдать трафик наружу вовсе, и
# узнать об этом надо до того, как человек ответит на десять вопросов.
check "xs_install.sh проверяет /dev/net/tun" "1" \
    "$(grep -c 'if \[ ! -c /dev/net/tun \]' server/xs_install.sh)"
# Конфигурация проверяется движком ПЕРЕД запуском и перед перезапуском при правке пиров:
# испорченный файл иначе уронил бы работающий хаб вместе со всеми остальными пирами.
# Дважды: перед первым запуском и внутри hubApply, то есть перед каждым перезапуском после
# правки пиров. Одного раза мало — правка пиров происходит чаще установки.
check "xs_install.sh проверяет конфигурацию движком" "2" \
    "$(grep -c 'xsteer-check --config' server/xs_install.sh)"
# Приватный ключ хаба пишется под umask 077: файл не должен даже на мгновение быть читаемым
# всем — chmod после создания этого не даёт.
check "xs_install.sh пишет конфигурацию под umask 077" "2" \
    "$(grep -c 'umask 077' server/xs_install.sh)"
# Все вопросы идут через ask/anykey. Прямой `read` в цикле `until` при конце ввода крутится
# ВЕЧНО — установщик, запущенный не с терминала, вис вместо отказа; это уже случилось.
check "в xs_install.sh нет прямых read вне помощников" "2" \
    "$(grep -cE '^[^#]*\bread -' server/xs_install.sh)"

# Барьер релиза обязан считать ВСЕ три вида артефактов и все три выкладывать. Раньше он
# смотрел только на apk, и добавление формата прошло бы мимо него молча.
check "барьер релиза считает apk и ipk" "1" "$(grep -c 'for ext in apk ipk' "$wf")"
# Ищется САМ ПЕРЕСЧЁТ (`ls ... | wc -l`), а не образец имени. Это второй раз, когда здесь
# ловится одна и та же ловушка: образец `out/steer-*.tar.gz` законно встречается и в шагах
# ВЫКЛАДКИ (в ветки dist и dist-vps), и проверка «ровно одно вхождение» падала на добавлении
# такого шага, обвиняя его в том, чего он не делает. Проверка обязана стоять на том, что
# сторожит, а не на подстроке, которая рядом.
check "барьер релиза считает архивы steer-obfs" "1" \
    "$(grep -c 'ls out/steer-obfs-\*.tar.gz' "$wf")"
# Хаб xsteer — отдельный артефакт со своей ролью сборки; забыть его так же легко, как формат
# пакета, и так же тихо: установщик просто не найдёт архив. Поэтому build.sh обязан его
# собирать, а барьер релиза — считать.
check "build.sh собирает архив steer-hub" "1" \
    "$(grep -c 'czf ".*OUT/steer-hub' build.sh)"
check "build.sh зовёт роль server для хаба" "1" \
    "$(grep -c 'VERSION" server' build.sh)"
check "барьер релиза считает архивы steer-hub" "1" \
    "$(grep -c 'ls out/steer-hub-\*.tar.gz' "$wf")"
# Считается СТРОКА ЦЕЛИКОМ, а не вхождение: у `files:` каждый образец стоит на своей строке,
# а те же образцы законно встречаются и в других шагах — выкладка пакетов роутера в ветку dist
# копирует их одной командой. Пока проверка считала вхождения, добавление такого шага роняло
# релиз на ровном месте, обвиняя выкладку в том, чего она не делала.
check "релиз выкладывает out/*.apk" "1" "$(grep -c '^ *out/\*\.apk$' "$wf")"
check "релиз выкладывает out/*.ipk" "1" "$(grep -c '^ *out/\*\.ipk$' "$wf")"
check "релиз выкладывает out/*.tar.gz" "1" "$(grep -c '^ *out/\*\.tar\.gz$' "$wf")"


# ---- документация не разошлась с кодом ----------------------------------------
# docs/contract-v1.md — то, на что опирается управляющий слой, и разойтись с кодом он может
# только молча: документ не исполняется. Самое живое место — список идентификаторов проверок
# diag: он может и расти, и сокращаться (проверка `udp` однажды исчезла), а потребитель
# читает документ.
API=docs/contract-v1.md
# Проверки видов выхода (обфускация, zapret) живут в src/kinds/<вид>.c (kind_ops.diag).
code_ids="$(grep -oh 'diag("[a-z_]*"' src/daemon/diag.c src/kinds/*.c | sed 's/diag("//;s/"//' | sort -u | tr '\n' ' ')"
doc_ids="$(sed -n '/Идентификаторы проверок/,/^$/p' "$API" |
           grep -o '`[a-z_]*`' | tr -d '`' | sort -u | tr '\n' ' ')"
check "идентификаторы проверок diag совпадают с кодом" "$code_ids" "$doc_ids"

# Документация на русском — проект для русскоязычных пользователей. Проверяется наличие
# кириллицы, а не отсутствие латиницы: имена команд, полей и флагов остаются как есть.
for d in README.md docs/guide.md docs/contract-v1.md docs/vless.md docs/proxy.md docs/hysteria2.md server/README.md; do
    check "$d написан по-русски" "yes" \
        "$(grep -qP '[А-Яа-я]' "$d" && echo yes || echo no)"
done

# Номер версии в документации устаревает молча к следующему же релизу: примеры команд
# обязаны быть с подстановкой, а не с числом.
stale=""
for d in README.md docs/guide.md docs/contract-v1.md docs/vless.md docs/proxy.md docs/hysteria2.md server/README.md; do
    grep -qE 'steer(-extended|-obfs)?-[0-9]+\.[0-9]+\.[0-9]+' "$d" && stale="$stale$d "
done
check "в документации нет зашитых номеров версии" "" "$stale"

# Таблица пакетов docs/guide.md — по составу build.sh (OURS): пакет, которого в таблице нет,
# человек не найдёт вовсе (так из неё однажды выпал steer-proxy).
no_pkg=""
for p in $(sed -n 's/^OURS="\(.*\)"$/\1/p' build.sh); do
    grep -q "^| \`$p\` |" docs/guide.md || no_pkg="$no_pkg$p "
done
check "все пакеты build.sh есть в таблице docs/guide.md" "" "$no_pkg"

# Команды, обещанные в README и docs/guide.md (таблица команд живёт там), обязаны существовать в
# ядре: их читают раньше, чем `steer help`, и несуществующая команда там — отказ на первом же шаге.
if [ -x ./build/steer ]; then
    bad_cmd=""
    for c in apply status diag explain outputs needs-dnsd dnsd failover fit vless \
             vless-nodes vless-probe obfs obfs-server; do
        cat README.md docs/guide.md | grep -q "\`$c" || continue
        ./build/steer help "$c" >/dev/null 2>&1 || bad_cmd="$bad_cmd$c "
    done
    check "все команды из README существуют" "" "$bad_cmd"
fi

# ---- workflow вообще пригоден к запуску ---------------------------------------
# Разбор вынесен в tests/wfcheck.py — там же объяснено, почему это нельзя проверить
# глазами. Коротко: GitHub раскрывает выражения и внутри комментариев оболочки, и
# пример выражения, написанный ради пояснения, роняет весь релиз ещё до первой команды.
if command -v python3 >/dev/null 2>&1; then
    check "release.yml пригоден к запуску" "" "$(python3 tests/wfcheck.py "$wf" 2>&1)"
fi

# ---- files/ против упаковки ---------------------------------------------------
# Тот же класс, что списки файлов выше, и та же цена. Файлы системной обвязки
# (init-скрипт, keep.d, hotplug) build.sh копирует ПОИМЁННО — раньше в два корня (базовый и
# расширенный пакеты), с шага 4 выпуска 1.10 в один: ядро, у которого теперь единственный
# владелец файлов. Новый файл в files/ поэтому существует в репозитории, приезжает в git,
# проходит все стенды и просто не попадает в пакет: на роутере его нет, а в дереве он есть.
# Молчаливее не бывает — ни ошибки сборки, ни предупреждения. Поэтому: каждый файл из files/
# обязан быть упомянут в build.sh — ровно один раз, в пакете ядра (второе упоминание
# означало бы, что файл едет в два пакета и менеджер откажет второму: конфликт владельцев).
missing=""
twice=""
for f in $(find files -type f | sort); do
    n=$(grep -c -- "$f" build.sh)
    if [ "$n" -eq 0 ]; then missing="$missing$f "
    elif [ "$n" -gt 1 ]; then twice="$twice$f "
    fi
done
check "каждый файл из files/ упакован" "" "$missing"
check "и ровно в один пакет (ядро)" "" "$twice"

# ---- зависимости пакета: считаются по файлу, а не по памяти -------------------
#
# pkg_deps в build.sh отвечает на вопрос «чего этому бинарнику не хватает в системе», и
# отвечает ЧТЕНИЕМ ФАЙЛА. Проверять это стендом нужно потому, что ошибиться здесь можно
# в обе стороны и обе молчат: недостающая зависимость — это половина движка, которая не
# работает на стоковом роутере (conntrack, H-110), а лишняя — пакет, который менеджер
# отказывается ставить там, где всё для него есть (библиотека у статической сборки).
#
# Функция берётся из build.sh как есть: копия здесь разошлась бы с оригиналом, а стенд
# на копии проверяет копию.
eval "$(sed -n '/^pkg_deps() {/,/^}/p' build.sh)"
dtmp="$(mktemp -d)"
printf 'static binary without any SONAME\n' > "$dtmp/static"
# Строка ровно того вида, что пишет линковщик в DT_NEEDED. Нулевые байты вокруг — чтобы
# файл не был текстовым: grep без -a такой файл пропускает, и проверка стояла бы на том,
# что бинарник — это текст. Имя — пакета libsteer (шаг 4 выпуска 1.10).
printf 'x\000libsteer.so.1.10.0\000x\n' > "$dtmp/shared"
# Системная libwolfssl OpenWrt (SONAME с хешем опций) пакетом движка НЕ считается: связываться
# с ней нельзя (SONAME меняется с каждым обновлением), и зависимость на неё — ошибка.
printf 'x\000libwolfssl.so.5.9.1.e624513f\000x\n' > "$dtmp/system"

check "ядро требует conntrack и kmod-nft-queue" \
    "nftables ip-full conntrack kmod-nft-queue" "$(pkg_deps "$dtmp/static" core)"
check "модуль с TUN добавляет kmod-tun" "kmod-tun" "$(pkg_deps "$dtmp/static" tun)"
check "обычный модуль системных зависимостей не имеет" "" "$(pkg_deps "$dtmp/static" mod)"
check "статическая сборка НЕ требует пакета библиотеки" \
    "" "$(pkg_deps "$dtmp/static" tun | grep -o 'libsteer\|libwolfssl')"
# Библиотеки лежат в steer-core, отдельного пакета нет: связанный с libsteer.so бинарник (в
# каком бы виде) отдельной зависимости от библиотеки не получает — её даёт steer-core.
check "связанная с libsteer сборка отдельной зависимости от библиотеки не имеет" \
    "nftables ip-full conntrack kmod-nft-queue" "$(pkg_deps "$dtmp/shared" core)"
check "  и модуль с TUN — тоже" "kmod-tun" "$(pkg_deps "$dtmp/shared" tun)"
check "системная libwolfssl зависимостью не становится" \
    "nftables ip-full conntrack kmod-nft-queue" "$(pkg_deps "$dtmp/system" core)"
rm -rf "$dtmp"

# Оба формата пакета обязаны получить ОДИН список, и это не педантизм: apk берёт его через
# пробел, opkg через запятую, и разойтись они могут молча — .ipk с прежним списком выглядит
# собранным ровно так же, как .apk с новым. Поэтому проверяется, что и там и там подставлена
# ОДНА переменная (`$_dp` в pack), которую преобразуют dep_apk и dep_ipk, а не литерал.
check "apk берёт зависимости через dep_apk из одной переменной" "1" \
    "$(grep -c '_dall="\$(dep_apk "\$_dp")"' build.sh)"
check "opkg берёт зависимости через dep_ipk из той же переменной" "1" \
    "$(grep -c 'mk_ipk "\$_r" "\$_n" "\$arch" "\$(dep_ipk "\$_dp")"' build.sh)"
check "литералов зависимостей в упаковке не осталось" "" \
    "$(grep -n "depends:'nftables\|mk_ipk .*\"nftables" build.sh)"

# ---- сборка криптобиблиотеки не глушит ошибки компиляции ------------------------
#
# Сборочные сценарии прежде компилировали mbedtls скопированным циклом, и во всех строка
# кончалась на `2>/dev/null || true`: провал модуля и его отсутствие в наборе становились
# неразличимы, а компоновка ниже сообщала о нём неопределённой ссылкой на символ — без строки,
# объясняющей причину, потому что её стёрли шагом раньше (I-034). Теперь цикл один на всех —
# build/wolfssl/build.sh, — и сценарии обязаны звать его, а не заводить свою копию.
#
# Проверяется текстом по той же причине, что и списки исходников выше: docker, zig и тулчейна
# SDK здесь нет, а форма строки — это текст. Заодно закреплено, что отказ назван словом,
# которое читает барьер релиза: иначе релиз с недособранной криптографией уйдёт молча.
W=build/wolfssl/build.sh
check "$W: компиляция файла wolfSSL не уходит в /dev/null" "0" \
    "$(grep -v '^[[:space:]]*#' "$W" | grep -c '\.o" 2>/dev/null'; true)"
check "$W: отказ файла назван словом барьера релиза" "1" \
    "$([ "$(grep -c 'сборка файла \$f не удалась' "$W"; true)" -ge 1 ] && echo 1 || echo 0)"
check "$W: провал любого файла роняет сборку" "1" \
    "$(grep -c 'сборка не удалась у файлов:\$failed" >&2; exit 1' "$W")"
for f in build/build-ext.sh build/build-ext-sdk.sh build/bench.sh tests/ext-test.sh; do
    check "$f: wolfSSL собирает общим рецептом build/wolfssl/build.sh" "1" \
        "$([ "$(grep -v '^[[:space:]]*#' "$f" | grep -c 'build/wolfssl/build\.sh')" -ge 1 ] && echo 1 || echo 0)"
    check "$f: своей копии списка файлов wolfSSL нет" "" \
        "$(grep -v '^[[:space:]]*#' "$f" | grep -oE 'wolfcrypt/src/[a-z0-9_]+\.c' | tr '\n' ' ')"
done

# ---- список файлов wolfSSL и опции — одни на все сборки -------------------------
#
# Android.bp будущего форка (build/wolfssl/Android.bp) не умеет читать build.sh, поэтому список
# там свой — и сверяется здесь. Файл, забытый в одном из двух, собрался бы на роутере и не
# собрался на телефоне (или наоборот) неопределённой ссылкой.
wl_sh="$(sh build/wolfssl/build.sh list | sort -u | tr '\n' ' ')"
wl_bp="$(grep -oE '"(src|wolfcrypt)/[a-z0-9_/.-]+\.c"' build/wolfssl/Android.bp | tr -d '"' | sort -u | tr '\n' ' ')"
check "build/wolfssl/Android.bp: те же файлы wolfSSL, что build/wolfssl/build.sh" "$wl_sh" "$wl_bp"
bp_wolf="$(awk '/^cc_library_static \{/ { blk = "" } { blk = blk $0 "\n" } /^\}/ { if (blk ~ /name: "libsteer_wolfssl",/) print blk; blk = "" }' Android.bp)"
# build/wolfssl — дважды: local_include_dirs (опции для самих .c wolfSSL) и export_include_dirs
# (они же для src/lib/scrypto.c в steerd).
check "Android.bp: libsteer_wolfssl — из filegroup форка, с опциями build/wolfssl" "1 2 1" \
    "$(printf '%s' "$bp_wolf" | grep -c ':libwolfssl_der_srcs') $(printf '%s' "$bp_wolf" | grep -c '"build/wolfssl"') $(printf '%s' "$bp_wolf" | grep -c 'DWOLFSSL_USER_SETTINGS')"
check "Android.bp: движок компонуется с libsteer_wolfssl" "1" \
    "$(grep -c 'static_libs: \["libsteer_wolfssl"\]' Android.bp)"

# ---- wolfSSL видит один файл движка --------------------------------------------
#
# Слой примитивов (src/lib/scrypto.h) обещает: код протоколов криптобиблиотеку не зовёт, её типов в
# заголовках нет, и сменить её — правка одного файла. Обещание держится только проверкой: один
# #include <wolfssl/...> в tls13.c вернул бы и зависимость стендов `make test` от библиотеки, и
# второе место, где живёт её API.
# Второй файл — src/proto/quic/qcssl.c: ngtcp2 берёт не примитивы, а сам TLS-стек (см. шапку qcssl.h).
check "заголовки wolfSSL включают только scrypto.c и qcssl.c" "src/lib/scrypto.c src/proto/quic/qcssl.c " \
    "$(grep -rlE '#include [<"]wolfssl/' src | sort | tr '\n' ' ')"
check "в src не осталось вызовов mbedtls" "" \
    "$(grep -rhoE '\<mbedtls_[a-z0-9_]+\(' src | sort -u | tr '\n' ' ')"
check "в src не осталось заголовков mbedtls" "" \
    "$(grep -rlE '#include [<"]mbedtls/' src tests | tr '\n' ' ')"

# ---- маршрут модуля ставит демон (1.10, шаг 3) ---------------------------------
#
# Клиенты VLESS и xsteer звали bind_device сами — код маршрутизации демона (таблица, ip rule,
# conntrack, набор failopen; src/daemon/failover.c) в процессе помощника. С шага 3 помощник говорит
# демону up с именем устройства (src/lib/evline.h, поле dev), а привязывает демон
# (src/daemon/supd.c, route_up). На шаге 4 модули — свои бинарники на libsteer, и failover.c в них
# быть не должно: один вызов из src/tunnel или src/proto потянул бы его обратно, а с ним и
# модельные зависимости маршрутизации. Комментарии не в счёт — тот же приём, что у правила 5.
modroute=""
for f in $(find src/tunnel src/proto \( -name '*.c' -o -name '*.h' \)); do
    hit=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" | grep -oE '\<(bind_device|table_bind|rule_ensure6?|rule_drop6?|route6_bind|route6_flush|conntrack_evict|failopen_mark|apply_failed|fo_fail_apply)\(' | sort -u | tr -d '(' | tr '\n' ' ')
    [ -n "$hit" ] && modroute="$modroute$f: $hit"
done
check "src/tunnel и src/proto не зовут маршрутизацию демона (шаг 3 выпуска 1.10)" "" "$modroute"

# ---- разделяемая раскладка роутера (1.10, шаг 4) -------------------------------
#
# libsteer.so, steerd и четыре модуля собираются из непересекающихся списков (build/sources.mk),
# и вместе они дают те же файлы, что статический расширенный профиль: файл, выпавший из всех, не
# соберётся только в релизе, а файл в двух местах дал бы два экземпляра одного кода в разных
# процессах (глобальные таблицы модели, реестр меток) и молчаливое расхождение. Общее у steerd и
# модулей одно — cli/modcmd.c: он входит в каждый бинарник, потому что слабые ссылки на cmd_*
# решаются компоновкой, а не загрузчиком.
sd="$(mktemp -d)"
for p in libsteer steerd mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox extended; do
    profile_src "$p" | words | sort -u > "$sd/$p"
done
modcmd="$(profile_var MODCMD_SRC)"
for a in steerd mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox; do
    check "раскладка: в libsteer и $a нет общих файлов" "" \
        "$(comm -12 "$sd/libsteer" "$sd/$a" | tr '\n' ' ')"
done
for a in mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox; do
    check "раскладка: у steerd и $a общий один файл — modcmd.c" "$modcmd " \
        "$(comm -12 "$sd/steerd" "$sd/$a" | tr '\n' ' ')"
done
set -- mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox
while [ $# -gt 1 ]; do
    a="$1"; shift
    for b in "$@"; do
        check "раскладка: у модулей $a и $b общий один файл — modcmd.c" "$modcmd " \
            "$(comm -12 "$sd/$a" "$sd/$b" | tr '\n' ' ')"
    done
done
# Модуль не несёт ни демона, ни модели: демон (failover.c, supd.c, dnsd…) — в steerd, модель и виды —
# в libsteer. В списках модулей нет ничего из каталогов демона, резолвера, компилятора и моделей.
for a in mod_vless mod_xsteer mod_obfs mod_tgws mod_hysteria2 mod_proxy mod_warpbox; do
    check "раскладка: в $a нет файлов демона, компилятора, резолвера и модели" "" \
        "$(grep -E '^src/(daemon|dnsd|compile|model|kinds|platform)/' "$sd/$a" | tr '\n' ' ')"
done
# (compile/nftcompat.c — раскладка по ядру, часть модели, а не компилятора: его зовёт реестр видов.)
check "раскладка: libsteer не несёт демона, компилятора и резолвера" "" \
    "$(grep -E '^src/(daemon|dnsd|compile)/' "$sd/libsteer" | grep -v 'src/compile/nftcompat.c' | tr '\n' ' ')"
# Всё, что было в статическом расширенном профиле, есть в раскладке (кроме файла профиля), а лишнее —
# только четыре точки входа модулей.
cat "$sd/libsteer" "$sd/steerd" "$sd/mod_vless" "$sd/mod_xsteer" "$sd/mod_obfs" "$sd/mod_tgws" "$sd/mod_hysteria2" "$sd/mod_proxy" "$sd/mod_warpbox" | sort -u > "$sd/all"
check "раскладка покрывает расширенный профиль (кроме файла профиля)" "src/profile/extended.c " \
    "$(comm -23 "$sd/extended" "$sd/all" | tr '\n' ' ')"
# (Обёртка QUIC src/proto/quic — в libsteer, в статическом профиле её нет: потребителя нет, телефону — шаг 6.)
check "  и добавляет только точки входа модулей, обёртку QUIC и модули hysteria2, proxy (с их видами) и warpbox" "src/kinds/hysteria2.c src/kinds/proxy.c src/modules/main_hysteria2.c src/modules/main_obfs.c src/modules/main_proxy.c src/modules/main_tgws.c src/modules/main_vless.c src/modules/main_warpbox.c src/modules/main_xsteer.c src/proto/hysteria2/hy2conn.c src/proto/hysteria2/hy2dial.c src/proto/hysteria2/hy2main.c src/proto/hysteria2/hy2sub.c src/proto/hysteria2/hy2wire.c src/proto/proxy/pxdial.c src/proto/proxy/pxhttp.c src/proto/proxy/pxmain.c src/proto/proxy/pxsocks.c src/proto/proxy/pxss.c src/proto/proxy/pxsub.c src/proto/proxy/pxtrojan.c src/proto/proxy/pxvmess.c src/proto/proxy/pxwire.c src/proto/quic/qcdoq.c src/proto/quic/qcssl.c src/proto/quic/quic.c src/proto/warp/wbconf.c src/proto/warp/wbmain.c src/proto/warp/wbmq.c src/proto/warp/wbns.c src/proto/warp/wbping.c src/proto/warp/wbreg.c src/proto/warp/wbscan.c src/proto/warp/wbx509.c " \
    "$(comm -13 "$sd/extended" "$sd/all" | tr '\n' ' ')"
# Точка входа — единственный main() модуля; steerd свой main держит в daemon/main.c.
for a in vless xsteer obfs tgws hysteria2 proxy; do
    check "src/modules/main_$a.c зовёт steer_module_main с именем модуля" "1" \
        "$(grep -c "steer_module_main(argc, argv, \"$a\", STEER_VERSION)" src/modules/main_$a.c)"
done
rm -rf "$sd"
# Экспорт libsteer — version-script (не «всё видимое»): список порождён из кода, сверяет его
# build/libs-exports.sh check (в tests/libs-test.sh), а здесь сторожится форма и то, что сборка его
# читает. То же для libsteer-wolfssl.
check "libsteer.map: экспорт списком, остальное локально" "1" \
    "$(grep -c '^  local:$' build/libsteer.map)"
check "libsteer-wolfssl.map: экспорт списком, остальное локально" "1" \
    "$(grep -c '^  local:$' build/wolfssl/libsteer-wolfssl.map)"
check "build-libs.sh линкует libsteer с version-script и SONAME по версии движка" "1 1" \
    "$(grep -v '^[[:space:]]*#' build/build-libs.sh | grep -c 'version-script=build/libsteer.map') \
$(grep -v '^[[:space:]]*#' build/build-libs.sh | grep -c -- '-soname,"libsteer.so.$VERSION"')"
check "build-libs.sh берёт списки файлов из манифеста, а не перечисляет сам" "" \
    "$(grep -v '^[[:space:]]*#' build/build-libs.sh | grep -oE 'src/[a-z0-9_/]+\.c' | tr '\n' ' ')"
# Размеры хранилищ слоя — ABI между libsteer и libsteer-wolfssl: и в сборке (abi.c), и при загрузке
# (scrypto.c, sc_abi_check) они сверяются с настоящими sizeof.
check "abi.c сверяет хранилища слоя со структурами wolfSSL при сборке библиотеки" "8" \
    "$(grep -c '^_Static_assert' build/wolfssl/abi.c)"
check "отпечаток библиотеки и его сверка при загрузке — одного размера" "1" \
    "$([ "$(grep -c '^#define SC_ABI_N' src/lib/scrypto.h)" = 1 ] && grep -q 'steer_wolfssl_abi\[SC_ABI_N\]' src/lib/scrypto.c build/wolfssl/abi.c && echo 1 || echo 0)"

# ---- каждый тарбол в образе сверяется по контрольной сумме ---------------------
#
# Тарбол zig сверялся с самого начала, тарбол mbedtls — нет: он распаковывался ровно тем, что
# отдал сервер в момент сборки (I-033). Проверялся компилятор, не проверялась криптография —
# при том что это та половина, где живут X25519, HKDF, ChaCha20-Poly1305 и AES-GCM для
# Reality, и подмена в ней не ломается заметно.
#
# Проверяется СООТНОШЕНИЕ, а не два известных имени: сколько в образе скачиваний тарбола,
# столько и сверок. Новый источник, добавленный без суммы, стенд поймает здесь. wolfSSL образ
# берёт скриптом build/wolfssl/fetch.sh (версия и сумма — там, одни на образ, стенды и ndk-check):
# образ обязан звать его, а скрипт — сверять сумму до распаковки.
dl=$(grep -cE 'curl -fsSL -o /tmp/' build/Dockerfile; true)
sums=$(grep -c 'sha256sum -c -' build/Dockerfile; true)
check "у каждого тарбола образа есть сверка суммы" "$dl" "$sums"
check "образ берёт wolfSSL через build/wolfssl/fetch.sh" "2" \
    "$(grep -v '^[[:space:]]*#' build/Dockerfile | grep -c 'wolfssl/fetch.sh\|steer-wolfssl-fetch.sh /opt/wolfssl'; true)"
check "сумма wolfSSL задана в fetch.sh" "1" \
    "$(grep -c '^WOLFSSL_SHA256=[0-9a-f]\{64\}$' build/wolfssl/fetch.sh; true)"
check "fetch.sh сверяет сумму до распаковки" "1" \
    "$(awk '/sha256sum -c/ { s = NR } /tar xzf/ { t = NR } END { print (s && t && s < t) ? 1 : 0 }' build/wolfssl/fetch.sh)"

# ---- MTU из конфигурации нигде не берётся без потолка --------------------------
#
# Разбор конфигурации принимает MTU до XS_LINK_MAX (1500) — это предел КАНАЛА, — а в клиенте
# то же число означает MTU ТУННЕЛЯ, у которого потолок XS_MTU_DEF (1439). По нему считается
# предельный сегмент (mtu + XS_OVERHEAD - 40), и при 1500 в файле он выходил 1521 байт: больше
# кадра канала, большие пакеты пропадали молча (I-094). Потолок ставит xs_mtu_clamp, и весь
# смысл в том, что она ОДНА на все входы; проверяется поэтому не одно место, а отсутствие
# присваиваний MTU из конфигурации в обход неё.
for f in src/proto/xsteer/xsclient.c src/proto/xsteer/xshub.c; do
    check "$f: MTU из конфигурации только через потолок" "" \
        "$(grep -nE '(\.|->)mtu = ' "$f" | grep -E 'g_cf|g_conf|conf->' | grep -v xs_mtu_clamp; true)"
done

# Оба SYN обфускатора — первый и повтор — уходят с одним набором опций (OBFS_SYN_OPTS): повтор
# шёл с одним MSS, и потеря первого SYN оставляла сессию без масштаба окна (I-292).
check "src/proto/obfs/obfs.c: оба SYN с OBFS_SYN_OPTS" "2" "$(grep -c 'TH_SYN, NULL, 0, OBFS_SYN_OPTS)' src/proto/obfs/obfs.c)"
check "src/proto/obfs/obfs.c: SYN с голым MSS не осталось" "0" "$(grep -c 'TH_SYN, NULL, 0, 1)' src/proto/obfs/obfs.c)"

# ---- правило 2 (docs/architecture.md, раздел 2): платформа — модуль, выбираемый при запуске ----
#
# Решение владельца: «Отличия телефона от роутера лежат в platform/android.c и platform/openwrt.c
# за одной таблицей struct platform_ops. Один бинарник сам определяет, где он запущен, а
# --platform переопределяет выбор для стендов. #ifdef STEER_ANDROID в общем коде нет.» До этого
# шага развилка по STEER_ANDROID стояла в двух десятках файлов, и третья платформа превратила бы
# каждую в развилку на три ветки. Теперь общий код спрашивает признак у plat(), а умолчание
# выбора задаёт ключ -DSTEER_DEFAULT_PLATFORM (Makefile, Android.bp). Условная компиляция по
# STEER_ANDROID — в любом виде (#ifdef, #ifndef, defined(…)) — законна разве что в src/platform.
# Комментарии не в счёт — тот же приём, что у правил 5 и 6.
platbad=""
for f in $(find src \( -name '*.c' -o -name '*.h' \) ! -path 'src/platform/*'); do
    n=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" | \
        grep -cE '^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef|elif)\>.*\<STEER_ANDROID\>')
    [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && platbad="$platbad$f:$n "
done
check "в src нет условной компиляции по STEER_ANDROID вне src/platform (правило 2)" "" "$platbad"
# Сборки задают платформу умолчанием, а не старым ключом, который больше никто не читает (и на
# который src/platform/platform.c отвечает #error).
# Два места: общие флаги движка (steer_defaults) и клиент — пути по умолчанию у него те же.
check "Android.bp: умолчание платформы — телефон" "2" \
    "$(grep -c '"-DSTEER_DEFAULT_PLATFORM=android"' Android.bp)"
check "Android.bp и Makefile не передают снятый ключ -DSTEER_ANDROID" "0" \
    "$(grep -hvE '^[[:space:]]*(#|//)' Android.bp Makefile build/sources.mk | grep -cE -- '-DSTEER_ANDROID\>'; true)"
check "Makefile: build/steer-android — та же сборка с умолчанием android" "1" \
    "$(grep -c -- '-DSTEER_DEFAULT_PLATFORM=android -o \$@ \$(CORE_SRC)$' Makefile)"

# ---- правило 6 (docs/architecture.md, раздел 2): спека — значение, а не глобалы ------------
#
# Решение владельца: разобранная спека передаётся параметром (struct spec *), а не лежит в
# глобальных массивах. До этого шага пять групп полей были глобалами g_out/g_ch/g_from_default/
# g_lan_dev/g_traceroute_hops (жили в src/model/parse.c), и читало их полтора десятка файлов без
# единого объявления в сигнатуре — то есть без способа увидеть по одной функции, что она вообще
# трогает спеку, не читая её тело. Теперь это поля struct spec, а функции получают её
# параметром; новое упоминание старых имён в src — знак, что кто-то завёл глобал заново (или
# скопировал старый пример вместо того, чтобы протащить параметр).
#
# Комментарии не в счёт — тот же приём, что у правила 5 выше: `*`/`//`/`/*` в начале строки
# после обрезки пробелов считаются прозой. Совпадения по слову, а не по подстроке: иначе
# g_outbuf в src/tools/aggregate.c (буфер печати диапазонов, к спеке отношения не имеющий) тоже
# попал бы в список — этим же заходом он и переименован из g_out, чтобы имя не путало.
rule6bad=""
for f in $(find src \( -name '*.c' -o -name '*.h' \)); do
    n=$(grep -vE '^[[:space:]]*(\*|//|/\*)' "$f" | \
        grep -cE '\<(g_out|g_ch|g_from_default|g_lan_dev|g_traceroute_hops)\>')
    [ -n "$n" ] || n=0
    [ "$n" -gt 0 ] && rule6bad="$rule6bad$f:$n "
done
check "в src нет g_out/g_ch/g_from_default/g_lan_dev/g_traceroute_hops (правило 6)" "" "$rule6bad"

# ---- юнит-стенды (docs/architecture.md, раздел 4): юнит-стенд линкуется с модулем, а не
# включает его .c -----------------------------------------------------------------------
#
# «Юнит-стенды на модуль: модуль линкуется со стендом сам, без #include чужого .c и setjmp».
# Пять каталогов — model, compile, lib, daemon, dnsd — под этим правилом с шага, который
# завёл tests/unit.h; протокольные и туннельные стенды (src/proto, src/tunnel) сюда пока не
# входят — это отдельная работа. #include исходника сваривает две единицы трансляции в одну:
# static одного файла тихо становится виден другому, а настоящая сборка линкует их отдельными
# объектами и может не найти неопределённую ссылку, которую такой стенд не ловит вовсе — до
# релиза (тот же класс беды, что у buildmatch.sh в целом, см. шапку файла).
badinc=""
for f in tests/*.c; do
    hit=$(grep -oE '#include "\.\./src/(model|compile|lib|daemon|dnsd)/[^"]*\.c"' "$f")
    [ -n "$hit" ] && badinc="$badinc$f: $(printf '%s' "$hit" | tr '\n' ' ') "
done
check "ни один стенд не включает .c из model/compile/lib/daemon/dnsd" "" "$badinc"

# Храповик на число стендов, включающих ЛЮБОЙ .c из src (в т.ч. src/proto, src/tunnel — им
# ещё предстоит тот же переход, отдельным шагом). Было 34 до unit.h, стало 30; шаг 2 выпуска 1.10
# (стек туннеля отдельно от протокола) перевёл на линковку ещё три: devupmatch компонуется со
# стеком и дайлером вместо включения tunnel.c, visionmatch и tunnamematch — с vision.c и tun.c,
# статического в которых им и не было нужно. Стало 27. Число уменьшать можно по мере перевода
# очередных стендов, увеличивать — нельзя: новый стенд, который решил проблему include'ом
# вместо линковки модуля, стенд обязан поймать здесь, а не оставить как молчаливый прецедент
# для следующего.
c_inc_n=$(grep -lE '#include "\.\./src/[^"]*\.c"' tests/*.c | wc -l | tr -d ' ')
check "стендов с #include .c из src не больше 27 (было 34 до unit.h/линковки, 30 до стека 1.10)" "1" \
    "$([ "$c_inc_n" -le 27 ] && echo 1 || echo 0)"

# ---- ngtcp2 (шаг 7 выпуска 1.10) ---------------------------------------------------------------
# Версия и сумма записаны только в build/ngtcp2/fetch.sh; образ берёт исходники им же вместе с патчами,
# а список файлов рецепта не должен расходиться с тем, что собирают build-libs.sh и libs-exports.sh.
check "ngtcp2: сумма sha256 записана в fetch.sh" "1" \
    "$(grep -cE '^NGTCP2_SHA256=[0-9a-f]{64}$' build/ngtcp2/fetch.sh)"
check "ngtcp2: образ сборщика берёт исходники через fetch.sh с патчами" "1 1" \
    "$(grep -c 'COPY ngtcp2/patches' build/Dockerfile) $(grep -c 'ngtcp2/fetch.sh /opt/ngtcp2' build/Dockerfile)"
check "ngtcp2: build-libs.sh и libs-exports.sh собирают её рецептом build/ngtcp2/build.sh" "2" \
    "$(grep -l 'build/ngtcp2/build.sh' build/build-libs.sh build/libs-exports.sh | wc -l | tr -d ' ')"
check "ngtcp2: патчи (Brutal и смена перегрузки на ходу) — в build/ngtcp2/patches" "2" \
    "$(ls build/ngtcp2/patches/*.patch | wc -l | tr -d ' ')"

# ---- слабые символы разбора спеки (модуль читает ту же спеку, что steerd) ------------------------
# «https:// доступен для замера группы» — свойство системы, а не бинарника, где идёт разбор: символ
# steer_urltls_present живёт в urltls.c, который есть только у steerd (замер ведёт он), и в бинарнике
# модуля слабая ссылка всегда нулевая. Поэтому разбор в модуле отказа не выносит: steer_module_main
# объявляет процесс читателем, а urltest_reader_only отдаёт libsteer (иначе модуль не слинкуется).
# Остальные слабые ссылки в model/kinds/compile — виды (kind.c: в libsteer есть всегда) и профиль
# (profile.c: умолчания совпадают с полным движком) — разбор спеки модулем не портят.
check "разбор спеки: steer_module_main объявляет модуль читателем до разбора" "1" \
    "$(grep -c 'urltest_reader_only();' src/cli/modcmd.c)"
check "разбор спеки: urltest_reader_only отдаёт libsteer (модуль берёт её оттуда)" "1" \
    "$(grep -c '^    urltest_reader_only;' build/libsteer.map)"
check "разбор спеки: единственная слабая ссылка model/kinds на символ urltls — в grpurl.c" "1" \
    "$(grep -rl 'steer_urltls_present' src/model src/kinds src/compile src/cli | wc -l | tr -d ' ')"

# ---- экспорт для модулей вне дерева ----------------------------------------------------------------
# Символы build/exports-ext.lst (нужды steer-box-connector и других внешних модулей) обязаны стоять в
# libsteer.map: gen кладёт их туда сам, но правка карты руками или gen без списка молча убрали бы
# символ, которым ядро само не пользуется, — и внешний модуль перестал бы компоноваться.
ext_missing=""
for sym in $(grep -v '^#' build/exports-ext.lst | grep -v '^$'); do
    grep -qx "    $sym;" build/libsteer.map || ext_missing="$ext_missing $sym"
done
check "exports-ext.lst: каждый символ экспортируется libsteer.map" "" "$ext_missing"

# ---- список изменений выпуска ---------------------------------------------------------------
# release.yml берёт текст «что нового» из раздела «## <VERSION>» файла CHANGELOG.md, и стабильный
# выпуск без него не выходит. Поднятая VERSION без раздела ловится здесь, а не на кнопке выпуска.
check "CHANGELOG.md: есть раздел текущей VERSION" "1" \
    "$(grep -cx "## $(cat VERSION)" CHANGELOG.md 2>/dev/null)"

# ---- владелец каталогов, которые пишет docker (STEER-CORE-895) -------------------------------
check "build.sh: build/libs/<арх> снимается через docker, а не голым rm -rf \$libs" "0" \
    "$(grep -c '^ *rm -rf "\$libs"' build.sh)"
check "build.sh: rm_libs вызывает docker run ... rm" "1" \
    "$(grep -c 'docker run --rm -v "\$PWD:/src" --entrypoint rm' build.sh)"
check "ext-test-image.sh: trap EXIT возвращает владельца build" "1" \
    "$(grep -c "trap 'chown -R \"\$OWNER\"" build/ext-test-image.sh)"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
