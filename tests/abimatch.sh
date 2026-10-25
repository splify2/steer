#!/bin/sh
# ABI .so-плагинов steerd (steer-abi v1, src/daemon/plugso.c, plugabi.h): загрузчик, таблица функций ядра,
# журнал виновного, отключение по падениям, сторож и отказ в статической сборке.
#
# Плагины стенда — варианты tests/abi/plugin.c, собранные тем же способом, каким их собирает `s2p cc --kind so`
# (-fPIC -fvisibility=hidden -Wl,-z,defs, один экспорт), но хостовым cc: zig на стенде нет. Хост — build/abihost
# (tests/abihost.c: настоящий загрузчик, цикл и модель спеки без демона) и настоящий build/steerd.
#
#  1. Плагин не связан ни с какой libsteer*: readelf -d (NEEDED) и один экспорт steer_plugin_v1_entry.
#  2. Загрузка: сверка ABI, init с таблицей, каталоги плагина.
#  3. Вызовы хоста: out_*, журнал, alloc/free, nft_rule (только из emit), emit, set_status, status.
#  4. Цикл: таймеры (с отменой), дескриптор, разрешение имён, HTTPS потоком.
#  5. Отказы: чужой major и minor, отпечаток, NULL из точки входа, чужой id и версия, init с отказом,
#     .so, связанный с libsteer*.
#  6. Падение плагина (SIGSEGV в вызове, в таймере, в on_event, в init, abort): запись в so.crash с именем
#     плагина и функции; три падения за десять минут — плагин OFF и не грузится; включение человеком.
#  7. Зависание: сторож через 5 с пишет WATCHDOG и роняет процесс.
#  8. steerd целиком: плагин из so.load, status с plugins_so, падение демона и отключение на третьем старте.
#  9. Статическая сборка (steerd-static, abihost-static): честный отказ, а не падение.
# 10. Копия заголовка plugabi.h равна include/steer/plugin.h SDK (если SDK рядом), шаблон SDK собирается и грузится.
set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
HOST="${ABIHOST:-./build/abihost}"
[ -x "$HOST" ] || { echo "not built: $HOST (make build/abihost)"; exit 2; }
command -v readelf >/dev/null 2>&1 || { echo "abimatch: нет readelf — пропускаю"; exit 0; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
has() {   # has ИМЯ ТЕКСТ ОБРАЗЕЦ — текст содержит образец как подстроку
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет: %s\n  в:   %s\n' "$1" "$3" "$2" ;; esac
}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
SRC=tests/abi/plugin.c
CF="-shared -fPIC -fvisibility=hidden -O2 -Isrc/daemon"
LF="-Wl,-z,defs"
mk() {   # mk ВЫХОД ОПЦИИ… — собрать вариант плагина
    out="$1"; shift
    # shellcheck disable=SC2086
    cc $CF "$@" -o "$out" $SRC $LF -Wl,-soname,"$(basename "$out")" || { echo "не собралось: $out"; exit 2; }
}
st() { rm -rf "$tmp/st"; mkdir -p "$tmp/st"; STEER_STATE_DIR="$tmp/st"; export STEER_STATE_DIR; }

# Моды plugin.c: 0 ok, 1 крах в init, 2 отказ init, 3 крах таймера, 4 зависание таймера, 5 крах health,
# 6 зависание health, 7 крах on_event, 8 abort в health.
mk "$tmp/ok.so"
mk "$tmp/major2.so" -DABI_MAJOR=2
mk "$tmp/minor5.so" -DABI_MINOR=5
mk "$tmp/fp.so" -DFP_XOR=0x100
mk "$tmp/refuse.so" -DREFUSE_ENTRY
mk "$tmp/otherid.so" -DPLUGIN_ID='"otherid"'
mk "$tmp/failinit.so" -DMODE=2
mk "$tmp/crashinit.so" -DMODE=1
mk "$tmp/crashtimer.so" -DMODE=3
mk "$tmp/crashhealth.so" -DMODE=5
mk "$tmp/hanghealth.so" -DMODE=6
mk "$tmp/crashevent.so" -DMODE=7
mk "$tmp/aborthealth.so" -DMODE=8
cc -shared -fPIC -o "$tmp/libsteer-stub.so" tests/abi/stub-libsteer.c -Wl,-soname,libsteer-stub.so
cc $CF -DPLUGIN_ID='"linked"' -o "$tmp/linked.so" $SRC -Wl,--no-as-needed "$tmp/libsteer-stub.so" -Wl,-rpath,"$tmp" -Wl,-soname,linked.so

# ---- 1. связей нет, экспорт один ---------------------------------------------------------------
needed="$(readelf -d "$tmp/ok.so" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')"
case "$needed" in *libsteer*) check "плагин без DT_NEEDED на libsteer*" "" "$needed" ;; *) check "плагин без DT_NEEDED на libsteer*" 1 1 ;; esac
exports="$(nm -D --defined-only "$tmp/ok.so" | awk '$2 ~ /^[TDBR]$/ {print $3}' | tr '\n' ' ')"
check "плагин экспортирует один символ" "steer_plugin_v1_entry " "$exports"

# ---- 2-3. загрузка и вызовы хоста --------------------------------------------------------------
st
out="$("$HOST" "$tmp/ok.so" abitest calls 2>&1)"
has "init: ABI и версия ядра" "$out" "INIT abi=1.0 size_ok=1 core="
has "init: каталог плагина" "$out" "plugin_dir=$tmp "
has "init: каталог настроек" "$out" "conf=/etc/steer/plugins/conf/abitest"
has "init: каталог состояния" "$out" "state=$tmp/st/plugin/abitest"
has "загружен" "$out" "LOAD rc=0 state=1"
has "вид найден, чужого нет" "$out" "KIND found=1 absent=1"
has "out_*: имя, вид, устройство, метка, таблица, число, поиск, первый, владелец, ключи, настройка" "$out" \
    "CHECK out=wan kind=direct dev=wg0 mark=256 table=100 count=2 byname=1 at0=wan owner=abitest/wan keys={\"k\":1} conf={\"c\":2}"
has "check: отказ с причиной" "$out" "CHECK1 -1 why=выход bad не годится"
has "check: годный" "$out" "CHECK0 0"
has "nft_rule из emit: первое правило" "$out" "NFT abitest forward: counter accept (ctx)"
has "nft_rule из emit: второе правило" "$out" "NFT abitest forward: meta mark 0x1 drop (ctx)"
has "nft_rule вернул 0 внутри emit" "$out" "EMIT nft rc=0,0"
has "health живо и нет" "$out" "HEALTH 1 0"
has "revive" "$out" "REVIVE 7"
has "apply_all видит спеку" "$out" "APPLY_ALL 0"
has "down_all" "$out" "DOWN_ALL 3"
has "status вида — JSON из host->alloc" "$out" 'STATUS_CALL {"up":true,"out":"wan"}'
has "expand" "$out" 'EXPAND 0 {"echo":{"a":1}}'
has "pre_apply" "$out" 'PRE_APPLY 0 {"spec":1}'
has "ctl: неизвестная команда" "$out" "CTL-UNKNOWN -1"
has "nft_rule вне emit — отказ" "$out" "NFT-OUTSIDE rc=-1"
has "emit: событие дошло подписчику с полями" "$out" 'SUB {"v":1,"ev":"abievent","a":1,"b":"x"}'
has "emit: пустые поля" "$out" 'SUB {"v":1,"ev":"abiempty"}'
has "emit: NULL вместо полей" "$out" 'SUB {"v":1,"ev":"abinull"}'
has "emit: плохое имя и перевод строки — отказ" "$out" "EMIT-EV 0 -1 0 0 -1"
has "on_event получил событие подписки" "$out" 'EVENT {"v":1,"ev":"abievent","a":1,"b":"x"}'
has "set_status → status выхода" "$out" 'STATUS_OUT ,"plugin":{"up":true,"out":"wan"}'
has "fini при остановке" "$out" "FINI"
has "журнал плагина с приставкой steer[id]" "$out" "steer[abitest] INIT"

# ---- 4. цикл: таймеры, дескрипторы, имена, HTTPS -----------------------------------------------
st
out="$("$HOST" "$tmp/ok.so" abitest async 2>&1)"
has "таймер сработал" "$out" "TIMER fired arg=one"
case "$out" in *"cancelled but fired"*) check "отменённый таймер молчит" "" "сработал" ;; *) check "отменённый таймер молчит" 1 1 ;; esac
has "дескриптор: событие чтения" "$out" "FD ready ev=0x1 n=1 arg=pipe"
has "разрешение имени" "$out" "RESOLVE rc=0 n=1 arg=lo"
has "HTTPS рабочим потоком" "$out" "HTTP status=200 len=4 body=pong why=- arg=h"
has "вызовы вернули 0" "$out" "ASYNC started t1>0=1 resolve=0 http=0"

# ---- 5. отказы ------------------------------------------------------------------------------------
load() {   # load ФАЙЛ ID [ВЕРСИЯ]
    st
    ABI_VERSION="${3:-}" "$HOST" "$1" "$2" load 2>&1 | grep -E '^(LOAD|STATUS)' | tr '\n' ' '
}
r="$(load "$tmp/major2.so" abitest)"
has "чужой major" "$r" "major2.so собран для steer-abi 2.0, у ядра 1.0"
has "чужой major: плагин failed" "$r" "state=2"
r="$(load "$tmp/minor5.so" abitest)"
has "minor новее ядра" "$r" "minor5.so собран для steer-abi 1.5, у ядра 1.0"
r="$(load "$tmp/fp.so" abitest)"
has "другой отпечаток" "$r" "fp.so собран с другим отпечатком"
r="$(load "$tmp/refuse.so" abitest)"
has "NULL из точки входа" "$r" "refuse.so не принял steer-abi 1.0 ядра"
r="$(load "$tmp/otherid.so" abitest)"
has "id плагина не тот" "$r" "называет себя «otherid», а в манифесте «abitest»"
r="$(load "$tmp/ok.so" abitest 9.9.9)"
has "версия не та" "$r" "версии «1.0.0», а в манифесте «9.9.9»"
r="$(load "$tmp/failinit.so" abitest)"
has "init отказал с причиной" "$r" "abitest: отказ из init"
has "отказ init виден в status" "$r" '"state":"failed"'
r="$(load "$tmp/linked.so" linked)"
has "связан с libsteer* — отказ" "$r" "linked.so связан с libsteer-stub.so"
r="$(load "$tmp/нет.so" abitest)"
has "нет файла" "$r" "нет файла"
r="$(load "$tmp/ok.so" abitest 1.0.0)"
has "годный: loaded в status" "$r" '"plugins_so":[{"id":"abitest","state":"loaded","crashes":0,"version":"1.0.0"}]'

# ---- 6. падения, журнал, отключение ------------------------------------------------------------------
crash_of() {   # crash_of ФАЙЛ СЦЕНАРИЙ — одна жизнь процесса; код выхода в $rc, вывод в $out
    out="$("$HOST" "$1" abitest "$2" 2>&1)"
    rc=$?
}
st
crash_of "$tmp/crashhealth.so" health 2>/dev/null
check "падение в вызове — процесс умер от SIGSEGV" 139 "$rc"
has "запись: плагин, функция, сигнал, где" "$(cat "$tmp/st/plugin/so.crash")" "abitest health SIGSEGV "
has "запись: падение в коде .so" "$(cat "$tmp/st/plugin/so.crash")" " so"
has "человеку в журнал" "$out" "steer[err] plugin: abitest упал: health SIGSEGV"
crash_of "$tmp/crashhealth.so" health 2>/dev/null
crash_of "$tmp/crashhealth.so" health 2>/dev/null
check "три записи за окно" 3 "$(grep -c '^abitest ' "$tmp/st/plugin/so.crash")"
r="$("$HOST" "$tmp/crashhealth.so" abitest load 2>&1 | grep -E '^(LOAD|STATUS)' | tr '\n' ' ')"
has "после третьего падения плагин OFF" "$r" "LOAD rc=-1 state=3 why=steerd падал в crashhealth.so (health, SIGSEGV) — плагин отключён"
has "OFF виден в status" "$r" '"state":"off","crashes":3'
has "OFF: причина в status" "$r" "плагин отключён"
check "отметка отключения лежит файлом" 1 "$([ -f "$tmp/st/plugin/abitest.off" ] && echo 1 || echo 0)"
# Вылечили .so (обновление плагина) — без включения человеком он по-прежнему не грузится.
cp "$tmp/ok.so" "$tmp/crashhealth.so"
r="$("$HOST" "$tmp/crashhealth.so" abitest load 2>&1 | grep -E '^LOAD')"
has "обновлённый .so не грузится без включения" "$r" "state=3"
r="$("$HOST" "$tmp/crashhealth.so" abitest enable 2>&1 | grep -E '^(BEFORE|AFTER)' | tr '\n' ' ')"
has "до включения — OFF" "$r" "BEFORE rc=-1 state=3"
has "после включения — загружен, счётчик сброшен" "$r" "AFTER state=1 crashes=0"
check "записи плагина вычищены" 0 "$(grep -c '^abitest ' "$tmp/st/plugin/so.crash")"
check "отметка снята" 0 "$([ -f "$tmp/st/plugin/abitest.off" ] && echo 1 || echo 0)"
r="$("$HOST" "$tmp/crashhealth.so" abitest load 2>&1 | grep -E '^LOAD')"
has "после включения грузится и следующим запуском" "$r" "LOAD rc=0 state=1"

# Падение в таймере, в on_event, в init, abort — функции в записи называются правильно.
st
crash_of "$tmp/crashtimer.so" timer 2>/dev/null
check "падение в таймере" 139 "$rc"
has "запись: функция timer" "$(cat "$tmp/st/plugin/so.crash")" "abitest timer SIGSEGV "
st
crash_of "$tmp/crashevent.so" event 2>/dev/null
check "падение в on_event" 139 "$rc"
has "запись: функция on_event" "$(cat "$tmp/st/plugin/so.crash")" "abitest on_event SIGSEGV "
st
crash_of "$tmp/crashinit.so" load 2>/dev/null
check "падение в init" 139 "$rc"
has "запись: функция init" "$(cat "$tmp/st/plugin/so.crash")" "abitest init SIGSEGV "
crash_of "$tmp/crashinit.so" load 2>/dev/null
crash_of "$tmp/crashinit.so" load 2>/dev/null
r="$("$HOST" "$tmp/crashinit.so" abitest load 2>&1 | grep -E '^LOAD')"
has "init, упавший трижды, — OFF на четвёртом старте" "$r" "(init, SIGSEGV) — плагин отключён"
st
crash_of "$tmp/aborthealth.so" health 2>/dev/null
check "abort в плагине — SIGABRT" 134 "$rc"
has "запись: SIGABRT в health" "$(cat "$tmp/st/plugin/so.crash")" "abitest health SIGABRT "
check "abort: одна запись, а не две" 1 "$(grep -c . "$tmp/st/plugin/so.crash")"
# Падения старше окна не считаются и вычищаются при загрузке.
st
mkdir -p "$tmp/st/plugin"
old=$(( $(date +%s) - 700 ))
printf 'abitest health SIGSEGV %s so\nabitest health SIGSEGV %s so\nabitest health SIGSEGV %s so\n' "$old" "$old" "$old" > "$tmp/st/plugin/so.crash"
r="$("$HOST" "$tmp/ok.so" abitest load 2>&1 | grep -E '^LOAD')"
has "падения старше десяти минут не считаются" "$r" "LOAD rc=0 state=1"
check "старые записи вычищены" 0 "$(grep -c . "$tmp/st/plugin/so.crash")"
# Чужой плагин падений не наследует.
st
crash_of "$tmp/crashhealth.so" health 2>/dev/null
cp "$tmp/ok.so" "$tmp/other.so"
for i in 1 2; do
    printf 'abitest health SIGSEGV %s so\n' "$(date +%s)" >> "$tmp/st/plugin/so.crash"
done
r="$("$HOST" "$tmp/other.so" otherplug load 2>&1 | grep -E '^LOAD')"
has "записи одного плагина не отключают другого" "$r" "otherplug"

# ---- 7. зависание — сторож --------------------------------------------------------------------------------
st
t0="$(date +%s)"
crash_of "$tmp/hanghealth.so" health 2>/dev/null
t1="$(date +%s)"
check "зависание: процесс убит abort()" 134 "$rc"
has "запись WATCHDOG с функцией" "$(cat "$tmp/st/plugin/so.crash")" "abitest health WATCHDOG "
check "сторож сработал за 5-7 с" 1 "$([ $((t1 - t0)) -ge 5 ] && [ $((t1 - t0)) -le 8 ] && echo 1 || echo 0)"
check "WATCHDOG: одна запись" 1 "$(grep -c . "$tmp/st/plugin/so.crash")"

# ---- 8. steerd целиком ----------------------------------------------------------------------------------------
STEERD="${STEER:-./build/steer}"
STEERD="$(cd "$(dirname "$STEERD")" && pwd)/$(basename "$STEERD")"
if [ -x "$STEERD" ]; then
    mkdir -p "$tmp/bin" "$tmp/d"
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/nft"
    chmod +x "$tmp/bin/nft"
    printf '{"schema":1,"from_default":["127.0.0.0/8"],"outputs":{"direct":{"kind":"direct"}},"channels":[]}\n' > "$tmp/d/spec.json"
    uid_flag="--allow-uid $(id -u)"
    daemon() {   # daemon ФАЙЛ-.so — поднять steerd с плагином в so.load, ждать сокет; $SRVPID
        rm -rf "$tmp/d/state"
        mkdir -p "$tmp/d/state/plugin"
        printf 'abitest\t1.0.0\t%s\t%s\n' "$(dirname "$1")" "$(basename "$1")" > "$tmp/d/state/plugin/so.load"
        rm -f "$tmp/d/s.sock"
        PATH="$tmp/bin:$PATH" "$STEERD" daemon --socket "$tmp/d/s.sock" --spec "$tmp/d/spec.json" \
            --state-dir "$tmp/d/state" --lists-dir "$tmp/d/lists" $uid_flag 2>"$tmp/d/err" &
        SRVPID=$!
        i=0
        while [ $i -lt 50 ] && [ ! -S "$tmp/d/s.sock" ] && kill -0 "$SRVPID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    }
    daemon "$tmp/ok.so"
    sleep 0.3
    s="$(PATH="$tmp/bin:$PATH" "$STEERD" ctl --socket "$tmp/d/s.sock" status 2>&1 | sed 's/\\"/"/g')"
    has "steerd: плагин загружен из so.load" "$(cat "$tmp/d/err")" "abitest 1.0.0 загружен (.so)"
    has "steerd: status показывает плагин" "$s" '"plugins_so":[{"id":"abitest","state":"loaded","crashes":0,"version":"1.0.0"}]'
    has "steerd: каталог состояния плагина создан" "$([ -d "$tmp/d/state/plugin/abitest" ] && echo yes)" "yes"
    kill -TERM "$SRVPID" 2>/dev/null; wait "$SRVPID" 2>/dev/null
    has "steerd: fini при остановке" "$(cat "$tmp/d/err")" "steer[abitest] FINI"
    # Падение демона из таймера плагина — три раза, на четвёртом старте плагин OFF, демон живёт.
    daemon "$tmp/crashtimer.so"
    for n in 1 2; do
        wait "$SRVPID" 2>/dev/null
        check "steerd упал от плагина (запуск $n)" 139 "$?"
        rm -f "$tmp/d/s.sock"
        PATH="$tmp/bin:$PATH" "$STEERD" daemon --socket "$tmp/d/s.sock" --spec "$tmp/d/spec.json" \
            --state-dir "$tmp/d/state" --lists-dir "$tmp/d/lists" $uid_flag 2>>"$tmp/d/err" &
        SRVPID=$!
        sleep 0.2
    done
    wait "$SRVPID" 2>/dev/null
    check "steerd упал от плагина (запуск 3)" 139 "$?"
    check "в so.crash три записи" 3 "$(grep -c '^abitest timer SIGSEGV' "$tmp/d/state/plugin/so.crash")"
    rm -f "$tmp/d/s.sock"
    PATH="$tmp/bin:$PATH" "$STEERD" daemon --socket "$tmp/d/s.sock" --spec "$tmp/d/spec.json" \
        --state-dir "$tmp/d/state" --lists-dir "$tmp/d/lists" $uid_flag 2>>"$tmp/d/err" &
    SRVPID=$!
    i=0
    while [ $i -lt 50 ] && [ ! -S "$tmp/d/s.sock" ]; do sleep 0.1; i=$((i + 1)); done
    sleep 1
    s="$(PATH="$tmp/bin:$PATH" "$STEERD" ctl --socket "$tmp/d/s.sock" status 2>&1 | sed 's/\\"/"/g')"
    has "steerd: четвёртый старт жив, плагин отключён по падениям" "$s" '"state":"off","crashes":3'
    has "steerd: причина отключения в status" "$s" "steerd падал в crashtimer.so (timer, SIGSEGV) — плагин отключён"
    check "steerd: демон не упал" 1 "$(kill -0 "$SRVPID" 2>/dev/null && echo 1 || echo 0)"
    kill -TERM "$SRVPID" 2>/dev/null; wait "$SRVPID" 2>/dev/null
else
    echo "abimatch: нет $STEERD — часть про steerd пропущена"
fi

# ---- 9. статическая сборка ----------------------------------------------------------------------------------------
if [ -x ./build/abihost-static ]; then
    st
    r="$(./build/abihost-static "$tmp/ok.so" abitest load 2>&1 | grep -E '^(LOAD|STATUS)' | tr '\n' ' ')"
    has "статическая сборка: честный отказ" "$r" "эта сборка steerd статическая: загрузить .so нечем"
    has "статическая сборка: плагин failed, не загружен" "$r" '"state":"failed"'
else
    echo "abimatch: нет build/abihost-static (make build/abihost-static) — пропущено"
fi
if [ -x ./build/steerd-static ]; then
    mkdir -p "$tmp/s"
    printf 'abitest\t1.0.0\t%s\tok.so\n' "$tmp" > "$tmp/s/so.load"
    mkdir -p "$tmp/ss/plugin" && cp "$tmp/s/so.load" "$tmp/ss/plugin/so.load"
    rm -f "$tmp/ss.sock"
    PATH="$tmp/bin:$PATH" ./build/steerd-static daemon --socket "$tmp/ss.sock" --spec "$tmp/d/spec.json" \
        --state-dir "$tmp/ss" $uid_flag 2>"$tmp/ss.err" &
    SP=$!
    i=0
    while [ $i -lt 50 ] && [ ! -S "$tmp/ss.sock" ]; do sleep 0.1; i=$((i + 1)); done
    sleep 0.3
    has "steerd-static: отказ в журнале" "$(cat "$tmp/ss.err")" "эта сборка steerd статическая"
    check "steerd-static: демон жив" 1 "$(kill -0 "$SP" 2>/dev/null && echo 1 || echo 0)"
    kill -TERM "$SP" 2>/dev/null; wait "$SP" 2>/dev/null
fi

# ---- 10. заголовок и шаблон SDK -------------------------------------------------------------------------------------------
SDK="${PLUGIN_SDK:-$ROOT/../plugin-sdk}"
[ -d "$SDK/include/steer" ] || SDK=/home/yo1nk/splicicd/plugin-sdk
if [ -f "$SDK/include/steer/plugin.h" ]; then
    # Копия отличается шапкой и охранным макросом — остальное байт в байт.
    a="$(sed '1,/^#define STEER_PLUGABI_H/d' src/daemon/plugabi.h)"
    b="$(sed '1,/^#define STEER_PLUGIN_H/d' "$SDK/include/steer/plugin.h")"
    check "plugabi.h равен include/steer/plugin.h SDK (кроме шапки)" "$b" "$a"
    if [ -f "$SDK/templates/so/src/example.c" ]; then
        mkdir -p "$tmp/inc/steer"
        cp "$SDK/include/steer/plugin.h" "$tmp/inc/steer/plugin.h"
        # shellcheck disable=SC2086
        cc -shared -fPIC -fvisibility=hidden -O2 -I"$tmp/inc" -DPLUGIN_ID='"example-so"' -DPLUGIN_VERSION='"0.0.0"' \
            -o "$tmp/example-so.so" "$SDK/templates/so/src/example.c" $LF -Wl,-soname,example-so.so
        st
        r="$("$HOST" "$tmp/example-so.so" example-so load 2>&1 | grep -E '^LOAD|steer\[example-so\]' | tr '\n' ' ')"
        has "шаблон SDK грузится" "$r" "LOAD rc=0 state=1"
        has "шаблон SDK: init с таблицей ядра" "$r" "example-so 0.0.0 загружен, ядро "
    fi
else
    echo "abimatch: нет plugin-sdk — сверка заголовка и шаблона пропущена"
fi

printf '\nabimatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
