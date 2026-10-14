#!/bin/sh
# Модуль и линия событий (шаг 4 выпуска 1.10, src/daemon/supd.c: mod_hello; docs/ctl.md, hello).
#
# Демон запускает помощника vless/xsteer БИНАРНИКОМ МОДУЛЯ (steer-vless, steer-xsteer) из каталога
# модулей рядом с движком — здесь это STEER_MODULE_DIR со скриптами-заглушками, а не шов
# STEER_SUPERVISE_EXE (шов подменяет ВСЕ помощники сразу и hello не проверяет). Каждая заглушка
# пишет в трубу событий (STEER_EVENT_FD) то, что ей велено, и стенд смотрит, что решил демон:
#
#   vl  модуль называет версию движка — принят: helper показывает module и module_ver, up виден;
#   vf  модуль чужой версии — отвергнут: процесс погашен, в last_down — «версии 0.0.1, а движок …»,
#       rejected, в журнале демона — та же причина, up (который заглушка пишет следом) не принят;
#   vn  модуль не сказал hello, а сразу up — отвергнут («не назвал версию»);
#   xm  бинарника модуля нет (steer-xsteer в каталоге не лежит) — не запуск вслепую, а last_down
#       «нужен пакет steer-xsteer» и ОДНА строка в журнале, сколько бы раз демон ни пробовал.
#
# Демон — build/steer-xk (база с видами vless и xsteer: файлы видов есть, модулей в бинарнике нет),
# то есть modcmd_builtin говорит «модуля в самом движке нет» и помощник идёт бинарником. Резолвер
# демона (детей) стенду не нужен и мешает: порты ему даются свободные. Под root стенд уходит в своё
# сетевое пространство; без root — петля хоста. Без python3 — пропуск (разбор ответа демона).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
# Без root стенд сам — чужой uid для демона: пускаем его явно, как в tests/ctlmatch.sh.
self_uid=""
[ "$(id -u)" = 0 ] || self_uid="--allow-uid $(id -u)"
XK="${STEER_XK:-$(dirname "$BIN")/steer-xk}"
[ -x "$XK" ] || { echo "modhello: не собран $XK (make build/steer-xk)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "modhello: python3 нет — пропускаю"; exit 0; }
if [ "${MODHELLO_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    MODHELLO_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
[ "${MODHELLO_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

tmp="$(mktemp -d)"
D=""
trap 'kill $D 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}

VER="$("$XK" version | awk '{print $2}')"
mkdir -p "$tmp/mods" "$tmp/st"

# Заглушка модуля: $1 — команда, $2 — выход (те же слова, что у настоящего модуля); первая строка
# в трубу — по имени выхода. Живёт, пока не убьют: SIGTERM демона — выход.
cat > "$tmp/mods/steer-vless" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; exit 0' TERM
case "\$2" in
vl) printf '{"ev":"hello","ver":"$VER","mod":"vless"}\n' >&9; printf '{"ev":"up"}\n' >&9 ;;
vf) printf '{"ev":"hello","ver":"0.0.1","mod":"vless"}\n' >&9; printf '{"ev":"up"}\n' >&9 ;;
vn|xm) printf '{"ev":"up"}\n' >&9 ;;
esac
while :; do sleep 0.1; done
H
chmod +x "$tmp/mods/steer-vless"

: > "$tmp/sub.txt"
cat > "$tmp/spec.json" <<EOF
{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{
 "vl":{"kind":"vless","sub_file":"$tmp/sub.txt","on_fail":"direct"},
 "vf":{"kind":"vless","sub_file":"$tmp/sub.txt","on_fail":"direct"},
 "vn":{"kind":"vless","sub_file":"$tmp/sub.txt","on_fail":"direct"},
 "xm":{"kind":"xsteer","conf":"/etc/xm.conf","on_fail":"direct"}},
 "channels":[]}
EOF

STEER_MODULE_DIR="$tmp/mods" "$XK" daemon $self_uid --supervise --socket "$tmp/s.sock" \
    --spec "$tmp/spec.json" --state-dir "$tmp/st" \
    --dnsd-flag --listen-port --dnsd-flag 15511 --dnsd-flag --upstream-port --dnsd-flag 15575 \
    >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ]' 5
wctl() { "$XK" ctl --socket "$tmp/s.sock" "$@"; }
# helper ВЫХОД → одно поле ответа демона.
hf() {  # выход поле
    wctl helper "$1" | python3 -c 'import json,sys
d=json.loads(json.load(sys.stdin)["stdout"]); print(d.get(sys.argv[1], "-"))' "$2" 2>&1
}
wait_for '[ "$(hf vl up)" = True ]' 10
wait_for '[ "$(hf vf rejected)" = True ]' 10
wait_for '[ "$(hf vn rejected)" = True ]' 10

check "модуль с верной версией: принят, up виден" "True" "$(hf vl up)"
check "  helper называет модуль" "steer-vless" "$(hf vl module)"
check "  и его версию из hello" "$VER" "$(hf vl module_ver)"
check "  запущен бинарником модуля тем же словами, что подкоманда (vless vl)" "1" \
    "$(grep -c '^vless vl ' "$tmp/log")"

check "модуль чужой версии: отвергнут" "True" "$(hf vf rejected)"
check "  причина в last_down называет обе версии" \
    "модуль steer-vless версии 0.0.1, а ядро $VER — обновите пакеты steer вместе" \
    "$(hf vf last_down)"
check "  helper показывает версию, которой модуль представился" "0.0.1" "$(hf vf module_ver)"
check "  up после hello чужой версии не принят" "False" "$(hf vf up)"
check "  в журнале демона — та же причина" "1" \
    "$(grep -c "vless vf — модуль steer-vless версии 0.0.1, а ядро $VER — обновите пакеты steer вместе: отвергнут" "$tmp/d.err")"
check "  процесс погашен (SIGTERM демона)" "1" "$(grep -c '^stop vf ' "$tmp/log")"

check "модуль без hello (сразу up): отвергнут" "True" "$(hf vn rejected)"
check "  причина — не назвал версию" \
    "модуль steer-vless не назвал версию (первое сообщение — не hello): нужен модуль того же выпуска, что ядро" \
    "$(hf vn last_down)"

# Бинарника нет вовсе: steer-xsteer в каталоге не лежит.
wait_for 'grep -q "xsteer xm — модуля нет" "$tmp/d.err"' 10
check "нет бинарника модуля: last_down — нужен пакет" "нужен пакет steer-xsteer" "$(hf xm last_down)"
sleep 12
check "  в журнал строка о нём одна, сколько бы раз демон ни пробовал" "1" \
    "$(grep -c 'xsteer xm — модуля нет' "$tmp/d.err")"
check "  и строка называет контрактное имя пакета" "1" \
    "$(grep -c 'xsteer xm — модуля нет: нужен пакет steer-xsteer (входит в steer-extended)' "$tmp/d.err")"

# Поставили пакет — следующая попытка запускает модуль (заглушка того же steer-vless годится:
# она просто держит процесс; версию не называет, и модуль отвергнется за отсутствие hello).
cp "$tmp/mods/steer-vless" "$tmp/mods/steer-xsteer"
wait_for '[ "$(hf xm rejected)" = True ]' 15
check "пакет появился: демон запустил модуль без перезапуска" "True" "$(hf xm rejected)"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
