#!/bin/sh
# Обвязка командной строки: справка, коды возврата и отказы на кривых аргументах.
#
# Зачем стенд. Разбор аргументов — единственная часть движка, с которой человек
# сталкивается раньше всего остального, и ошибка в нём молчалива по своей природе:
# неизвестный флаг, попавший в позиционный аргумент, не ломает ничего видимого — он
# просто делает не то, о чём просили. Именно так `steer apply --dryrun` применял
# правила по-настоящему. Проверяется поэтому не текст справки (он меняется), а
# контракт: что печатается в stdout, что в stderr и с каким кодом.
#
# Спека здесь нужна не всегда: почти все проверки падают на разборе аргументов раньше,
# чем движок доберётся до файла.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

# code ИМЯ ОЖИДАЕМЫЙ_КОД -- команда...
code() {
    name="$1"; want="$2"; shift 3
    "$@" >/dev/null 2>&1
    check "$name" "$want" "$?"
}

# Каталог плагинов стенда (tests/plugroot.sh): манифесты официальных плагинов дерева и программа хуков
# build/pkhooks под именем bin/<id>. Подкоманды протоколов ядро берёт только из манифестов: с ним они
# есть и доходят до программы плагина, без него — их нет вовсе.
PR="$tmp/plugins"
sh tests/plugroot.sh "$PR" "$(dirname "$BIN")" || { echo "climatch: каталог плагинов не собран"; exit 2; }
WITHP="env STEER_PLUGINS_ROOT=$PR STEER_PLUGINS_ETC=$tmp/plugetc"

# ---- справка отвечает нулём и печатает в stdout -----------------------------
# Код 2 и вывод в stderr — это поведение ОШИБКИ. Справка, запрошенная явно, ошибкой
# не является: `steer --help | less` на прежнем движке показывал пустую страницу,
# потому что весь текст уходил в stderr.
for form in --help -h help; do
    out="$("$BIN" $form 2>/dev/null)"
    code "$form: код 0" 0 -- "$BIN" $form
    check "$form: список команд в stdout" "1" "$(printf '%s' "$out" | grep -c '^  apply ')"
done

# Справка по команде — тремя способами, и все три дают один текст.
a="$("$BIN" help explain 2>/dev/null)"
b="$("$BIN" explain --help 2>/dev/null)"
c="$("$BIN" explain -h 2>/dev/null)"
check "help КОМАНДА и КОМАНДА --help совпадают" "$a" "$b"
# Разделы справки идут подряд: «Диагностика:» печатается один раз, а не трижды (три команды
# лежали среди VLESS и Telegram). И у --kind перечислены ВСЕ виды выходов, которые знает спека.
check "help: раздел «Диагностика» один" "1" "$("$BIN" help 2>/dev/null | grep -c '^Диагностика:')"
for k in direct interface tgws awg плагина; do
    check "help outputs: --kind знает вид $k" "1" \
        "$("$BIN" help outputs 2>/dev/null | grep -c "только выходы этого вида:.*\b$k\b")"
done
check "help tgws-probe: срок по умолчанию назван верно" "1" \
    "$("$BIN" help tgws-probe 2>/dev/null | grep -c 'по умолчанию 5 секунд')"
check "КОМАНДА -h — то же самое" "$a" "$c"
check "справка по команде показывает синопсис" "1" \
    "$(printf '%s' "$a" | grep -c 'steer explain <адрес|имя>')"

# --help перехватывается и у команд со своим разбором аргументов, иначе они успели бы
# принять его за флаг и ответить своей ошибкой.
code "fit --help: код 0" 0 -- "$BIN" fit --help
check "fit --help: свои флаги на месте" "1" \
    "$("$BIN" fit --help 2>/dev/null | grep -c '^  --budget ')"
code "dnsd --help: код 0" 0 -- "$BIN" dnsd --help
check "dnsd --help: свои флаги на месте" "1" \
    "$("$BIN" dnsd --help 2>/dev/null | grep -c '^  --listen-port ')"

# ---- версия -----------------------------------------------------------------
check "version: называет версию из файла VERSION" "1" \
    "$("$BIN" --version 2>/dev/null | grep -c "^steer $(cat VERSION) ")"
check "version: словом и флагом одинаково" \
    "$("$BIN" version 2>/dev/null)" "$("$BIN" --version 2>/dev/null)"
# Ревизия рядом с вариантом сборки: номер версии между релизами не меняется, и без неё два
# РАЗНЫХ бинарника (релиз и сборка из main после него) отчитывались одним числом — так и
# было на стенде, оба назывались «0.9.6-r1» (R-045/I-054). Проверяется наличие слова и
# непустое значение после него, а не формат: формат задаёт git describe, не контракт.
check "version: называет ревизию сборки" "1" \
    "$("$BIN" --version 2>/dev/null | grep -cE 'ревизия [^)]+\)$')"

# ---- ошибки: всё в stderr и код 2 -------------------------------------------
code "без команды — код 2" 2 -- "$BIN"
check "без команды — ни слова в stdout" "" "$("$BIN" 2>/dev/null)"
code "неизвестная команда — код 2" 2 -- "$BIN" nosuchthing
check "опечатка получает подсказку" "1" \
    "$("$BIN" aply 2>&1 >/dev/null | grep -c 'steer apply')"
# Порог подсказки: далёкое слово не должно уверенно советовать случайную команду.
check "далёкое слово подсказки не получает" "0" \
    "$("$BIN" nosuchthing 2>&1 >/dev/null | grep -c 'имелось в виду')"

# Главное, ради чего всё затевалось: опечатка во флаге — это отказ, а не тихое
# согласие. Прежний разбор клал --dryrun в позиционный аргумент, apply его не читал, и
# правила применялись НА САМОМ ДЕЛЕ вместо обещанного показа.
code "опечатка во флаге — отказ" 2 -- "$BIN" apply --dryrun
code "чужой флаг команде — отказ" 2 -- "$BIN" status --dry-run
code "флаг без значения — отказ" 2 -- "$BIN" apply --spec
code "значение, съеденное флагом, — отказ" 2 -- "$BIN" apply --spec --dry-run
code "лишний позиционный — отказ" 2 -- "$BIN" apply лишнее
code "не-число там, где ждали число" 2 -- "$BIN" tgws-probe --node abc
code "флаг вместо команды — отказ" 2 -- "$BIN" --spec /etc/steer/spec.json apply
code "обязательный аргумент пропущен" 2 -- "$BIN" explain

# ---- разобранные значения доходят до команды --------------------------------
# Спека нарочно несуществующая: если --spec дошёл, движок жалуется именно на этот путь,
# а не на /etc/steer/spec.json. Так проверяется, что значение флага не потерялось.
check "--spec доходит до команды" "1" \
    "$("$BIN" apply --spec "$tmp/нет.json" 2>&1 >/dev/null | grep -c "$tmp/нет.json")"

cat > "$tmp/spec.json" <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" }, "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "c", "match": { "any": true, "allow_all": true }, "out": "vpn" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"
check "outputs без отбора" "direct
vpn" "$("$BIN" outputs $S 2>/dev/null)"
check "outputs --kind отбирает" "vpn" "$("$BIN" outputs $S --kind interface 2>/dev/null)"
# --state-dir принимается всеми командами, которые читают спеку: init-скрипт и стенды
# передают его не глядя, и «не понимает флаг» тут был бы регрессией.
for cmd in status diag outputs needs-dnsd; do
    "$BIN" $cmd $S >/dev/null 2>"$tmp/err"
    check "$cmd понимает --state-dir" "0" "$(grep -c 'не понимает флаг' "$tmp/err")"
done

# ---- таблица и диспетчер не разошлись ---------------------------------------
# Команда, объявленная в таблице и забытая в диспетчере, попадает в справку и не
# работает — самый обидный вид расхождения, ради устранения которого таблица и
# заводилась. Движок отвечает на такое отдельной строкой; здесь проверяется, что её
# не печатает ни одна команда из списка. Спека нарочно несуществующая: до неё доходят
# только те команды, которые действительно подключены.
# Имена берутся из разделов справки, а не из списка в этом файле: список пришлось бы
# дописывать руками при каждой новой команде, то есть ровно тогда, когда проверка
# нужнее всего. Строка под «Использование:» и раздел про саму справку пропускаются —
# steer, help и version командами таблицы не являются.
cmd_names() {
    "$BIN" help 2>/dev/null | awk '
        /^Использование:/       { skip = 1; next }
        /^Справка и версия:/    { exit }
        /^[^ ]/                 { skip = 0; next }
        skip                    { next }
        /^  [a-z]/              { print $1 }'
}
for name in $(cmd_names); do
    code "help $name отвечает нулём" 0 -- "$BIN" help "$name"
    out="$("$BIN" "$name" x --spec "$tmp/нет.json" 2>&1)"
    check "$name подключена к диспетчеру" "0" \
        "$(printf '%s' "$out" | grep -c 'не подключена')"
done

# ---- вызовы, которыми движок зовёт splify2 ----------------------------------
# Разбор аргументов — граница между двумя репозиториями, и ужесточать её можно только
# зная, что через неё ходит. Строки ниже взяты из splify2/files/usr/libexec/rpcd/splify2
# и splify2-update-lists; проверяется не результат, а то, что ни один из них не
# отвергнут разбором. Так уже ловилось `--node -1` — часовой «первый рабочий», который
# диапазон «с нуля» отверг бы, и проверка выхода в интерфейсе молча перестала бы
# работать.
# Проверяется КОД ВОЗВРАТА, а не текст ошибки. Первая версия считала вхождения четырёх
# русских фраз в stderr — то есть любая переформулировка сообщения в cli.c делала все
# проверки границы вечнозелёными, а именно они и стерегут совместимость с splify2.
# Разбор аргументов отвечает кодом 2; всё остальное (нет спеки, нет выхода, движок без
# VLESS) — это уже работа команды, и такие коды здесь законны.
accepted() { # ИМЯ -- команда...
    name="$1"; shift 2
    "$@" >/dev/null 2>&1
    rc=$?
    check "$name" "принят" "$([ "$rc" = 2 ] && echo "ОТВЕРГНУТ разбором" || echo "принят")"
}
accepted "splify2: apply --dry-run --spec" -- "$BIN" apply --dry-run --spec "$tmp/spec.json"
accepted "splify2: outputs --kind vless --spec (вид плагина)" -- $WITHP "$BIN" outputs --kind vless --spec "$tmp/spec.json"
code "outputs --kind vless без плагина — нет такого вида" 2 -- "$BIN" outputs --kind vless --spec "$tmp/spec.json"
accepted "splify2: outputs --obfs --spec" -- "$BIN" outputs --obfs --spec "$tmp/spec.json"
accepted "splify2: status --spec" -- "$BIN" status --spec "$tmp/spec.json"
accepted "splify2: diag --spec" -- "$BIN" diag --spec "$tmp/spec.json"
accepted "splify2: explain АДРЕС --spec" -- "$BIN" explain 1.2.3.4 --spec "$tmp/spec.json"
# ПОДКОМАНДЫ ПРОТОКОЛОВ — ИЗ МАНИФЕСТОВ ПЛАГИНОВ (steer-api.md, 4.3). Ядро их имён не знает: без плагинов
# `steer vless-nodes` — неизвестная команда, с плагином — программа плагина bin/<id> с теми же словами.
# Здесь программа — build/pkhooks (tests/plugroot.sh): она называет себя и первое слово, и по этой строке
# видно, что вызов дошёл до программы плагина. Свой разбор флагов (--insecure только с файлом, --node
# числом, противоречия --stream) — у самой программы плагина: tests/libs-test.sh гоняет настоящие.
reach() { # ИМЯ ПЛАГИН КОМАНДА -- команда...
    name="$1"; pl="$2"; cmdw="$3"; shift 4
    out="$("$@" 2>&1 >/dev/null)"
    check "$name" "1" "$(printf '%s' "$out" | grep -c "pkhooks ($pl): «$cmdw»")"
}
code "vless-nodes без плагина — неизвестная команда" 2 -- "$BIN" vless-nodes /tmp/x
check "  и словами «нет такой команды», а не «нужен пакет»" "1 0" \
    "$("$BIN" vless-nodes /tmp/x 2>&1 | grep -c 'нет такой команды') $("$BIN" vless-nodes /tmp/x 2>&1 | grep -c 'нужен пакет')"
printf 'vless://x@h.example:443#n\n' > "$tmp/sub.txt"
for c in vless-nodes vless-probe hysteria2-nodes hysteria2-probe proxy-nodes proxy-probe; do
    pl="${c%%-*}"
    reach "$c /файл --insecure доходит до программы плагина" "$pl" "$c" -- $WITHP "$BIN" $c "$tmp/sub.txt" --insecure
    # Слово — имя выхода (conf: true в манифесте): ядро ищет выход в спеке, чтобы дать программе его {conf}.
    out="$($WITHP "$BIN" $c v --spec "$tmp/spec.json" 2>&1 >/dev/null)"; rc=$?
    check "$c выход: ядро ищет выход для {conf} — нет его, отказ кодом 2" "2 1" \
        "$rc $(printf '%s' "$out" | grep -c 'выхода v нет в спеке')"
done
reach "splify2: sub-fetch <ссылка> --out --info доходит до программы плагина" vless sub-fetch -- \
    $WITHP "$BIN" sub-fetch https://p.example/s --out "$tmp/sub.txt" --info "$tmp/sub.userinfo"
reach "splify2: sub-quota <ссылка> --info доходит до программы плагина" vless sub-quota -- \
    $WITHP "$BIN" sub-quota https://p.example/s --info "$tmp/sub.userinfo"
reach "xsteer-link доходит до программы плагина" xsteer xsteer-link -- $WITHP "$BIN" xsteer-link -
reach "warp-reg доходит до программы плагина" warpbox warp-reg -- $WITHP "$BIN" warp-reg "$tmp/w.reg"
check "help vless-nodes с плагином — справка из манифеста" "1" \
    "$($WITHP "$BIN" help vless-nodes 2>/dev/null | grep -c 'Команда плагина vless')"
code "--insecure у команды ядра — отказ разбора" 2 -- "$BIN" status --insecure
# sub-hwid И dev-id ОТВЕЧАЮТ В БАЗОВОЙ СБОРКЕ, а не отказывают «нужен steer-extended», — и
# это ровно то свойство, ради которого идентификатор переехал в src/tools/hwid.c. Прежде здесь
# стояла проверка на отказ, и она была верна, пока читатель был один: панель подписки.
# Телеметрии он нужен как раз на роутере, где расширенной части нет.
out="$("$BIN" sub-hwid 2>/dev/null)"
check "sub-hwid отвечает и в базовой сборке" "1" \
    "$(printf '%s' "$out" | grep -c '"hwid":')"
check "и отказа про steer-extended в нём нет" "0" \
    "$("$BIN" sub-hwid 2>&1 >/dev/null | grep -c 'steer-extended')"
check "dev-id отвечает и в базовой сборке" "1" \
    "$(STEER_DEVID_ITERS=1000 "$BIN" dev-id 2>/dev/null | grep -c '"tid":')"
check "и это ДРУГОЙ идентификатор, а не тот же" "0" \
    "$(STEER_DEVID_ITERS=1000 "$BIN" dev-id 2>/dev/null | grep -c 'splify2-')"
# Флаги чужим командам не даются: список флагов команды — это данные, по которым растут и справка,
# и разбор, и разойтись им негде.
code "status не принимает --out" 2 -- "$BIN" status --out /dev/null
accepted "splify2: fit --budget --report ФАЙЛ" -- \
    "$BIN" fit --budget 100 --report "$tmp/rep.json" /dev/null

# tgws-probe понимает одно слово — media. Любое другое молча проверяло ОБЫЧНУЮ точку, и
# «steer tgws-probe medai» отвечал «ок» про другую (I-316). Опечатка — отказ разбора с
# названием того, что есть, раньше, чем команда куда-либо пойдёт.
# Мост tgws — пока модуль ядра (steer-tgws рядом со steerd): без него отказ называет пакет.
ext_marker() { # ИМЯ -- команда...
    name="$1"; shift 2
    out="$("$@" 2>&1 >/dev/null)"
    check "$name" "1" "$(printf '%s' "$out" | grep -c 'steer-tgws')"
}
ext_marker "tgws-probe media доходит до команды" -- "$BIN" tgws-probe media
code "tgws-probe medai: отказ" 2 -- "$BIN" tgws-probe medai
check "tgws-probe medai: отказ разбора, а не команды" "0" \
    "$("$BIN" tgws-probe medai 2>&1 >/dev/null | grep -c 'steer-extended')"
check "tgws-probe medai: названо, что есть" "1" \
    "$("$BIN" tgws-probe medai 2>&1 >/dev/null | grep -c '«media»')"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
