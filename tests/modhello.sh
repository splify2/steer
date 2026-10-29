#!/bin/sh
# Программа плагина и линия событий (src/daemon/supd.c: plug_hello; steer-api.md, 2.1; docs/ctl.md, hello).
#
# Демон запускает помощника выхода вида плагина ПРОГРАММОЙ ПЛАГИНА (plugins/<id>/bin/<id>, helper.prog
# манифеста). Здесь каталог плагинов стенда (tests/plugroot.sh), а программа vless — скрипт-заглушка;
# шов STEER_SUPERVISE_EXE не годится (он подменяет все помощники сразу и hello не проверяет). Заглушка
# пишет в трубу событий (STEER_EVENT_FD) то, что ей велено, и стенд смотрит, что решил демон:
#
#   vl  hello с api ядра и id своего плагина — принят: helper показывает plugin и plugin_ver, up виден;
#   vf  hello с чужим major steer-api — отвергнут: процесс погашен, в last_down — обе версии API,
#       rejected, в журнале демона — та же причина, up (который заглушка пишет следом) не принят;
#   vn  не сказал hello, а сразу up — отвергнут («не назвал версию»);
#   vm  hello от имени другого плагина — отвергнут («представился плагином …»);
#   xm  программы плагина xsteer нет (снята после старта) — не запуск вслепую, а last_down «нет
#       программы плагина» и ОДНА строка в журнале, сколько бы раз демон ни пробовал; вернули —
#       следующая попытка запускает.
#
# Версию плагина (ver) с версией ядра демон не сверяет: плагины обновляются отдельно. Резолвер демона
# стенду не нужен и мешает: порты ему даются свободные. Под root стенд уходит в своё сетевое
# пространство; без root — петля хоста. Без python3 — пропуск (разбор ответа демона).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "modhello: не собран $BIN"; exit 2; }
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
    # Приговор по фактическому состоянию, а не по счётчику кругов: условие, ставшее истинным в последнюю
    # десятую секунды, иначе объявлялось бы невыполненным.
    eval "$1" && return 0
    return 1
}

sh tests/plugroot.sh "$tmp/plugins" "$(dirname "$BIN")" || { echo "modhello: каталог плагинов не собран"; exit 2; }
STEER_PLUGINS_ROOT="$tmp/plugins"; STEER_PLUGINS_ETC="$tmp/plugetc"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC
API="$("$BIN" version --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["api"])')"
mkdir -p "$tmp/st"

# Заглушка программы плагина: хук check — годится всё; помощник: $1 — команда, $2 — выход (слова
# helper.argv манифеста); первая строка в трубу — по имени выхода. Живёт, пока не убьют.
cat > "$tmp/stub" <<H
#!/bin/sh
[ "\$1" = check ] && { cat >/dev/null; exit 0; }
echo "\$1 \$2 \$\$" >> "$tmp/log"
eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; exit 0' TERM
case "\$2" in
vl) printf '{"ev":"hello","api":"$API","ver":"9.9.9","mod":"vless"}\n' >&9; printf '{"ev":"up"}\n' >&9 ;;
vf) printf '{"ev":"hello","api":"2.0","ver":"9.9.9","mod":"vless"}\n' >&9; printf '{"ev":"up"}\n' >&9 ;;
vm) printf '{"ev":"hello","api":"$API","ver":"9.9.9","mod":"proxy"}\n' >&9; printf '{"ev":"up"}\n' >&9 ;;
*) printf '{"ev":"up"}\n' >&9 ;;
esac
while :; do sleep 0.1; done
H
chmod +x "$tmp/stub"
for id in vless xsteer; do rm -f "$tmp/plugins/$id/bin/$id"; cp "$tmp/stub" "$tmp/plugins/$id/bin/$id"; done

: > "$tmp/sub.txt"
printf 'xsteer://k@127.0.0.1:1\n' > "$tmp/xm.conf"
cat > "$tmp/spec.yaml" <<EOF
version: 2
outputs:
  vl: { kind: tunnel, protocol: vless, subscription: $tmp/sub.txt, on_fail: direct }
  vf: { kind: tunnel, protocol: vless, subscription: $tmp/sub.txt, on_fail: direct }
  vn: { kind: tunnel, protocol: vless, subscription: $tmp/sub.txt, on_fail: direct }
  vm: { kind: tunnel, protocol: vless, subscription: $tmp/sub.txt, on_fail: direct }
  xm: { kind: xsteer, conf: $tmp/xm.conf, on_fail: direct }
EOF

"$BIN" daemon --supervise --allow-uid "$(id -u)" --socket "$tmp/s.sock" \
    --spec "$tmp/spec.yaml" --state-dir "$tmp/st" \
    --dnsd-flag --listen-port --dnsd-flag 15511 --dnsd-flag --upstream-port --dnsd-flag 15575 \
    >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ]' 5
wctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }
# helper ВЫХОД → одно поле ответа демона.
hf() {  # выход поле
    wctl helper "$1" | python3 -c 'import json,sys
d=json.loads(json.load(sys.stdin)["stdout"]); print(d.get(sys.argv[1], "-"))' "$2" 2>&1
}
wait_for '[ "$(hf vl up)" = True ]' 10
wait_for '[ "$(hf vf rejected)" = True ]' 10
wait_for '[ "$(hf vn rejected)" = True ]' 10
wait_for '[ "$(hf vm rejected)" = True ]' 10

check "программа плагина с верным api: принята, up виден" "True" "$(hf vl up)"
check "  helper называет плагин" "vless" "$(hf vl plugin)"
check "  и его версию из hello" "9.9.9" "$(hf vl plugin_ver)"
check "  запущена программой плагина словами helper.argv (vless vl)" "1" "$(grep -c '^vless vl ' "$tmp/log")"

check "чужой major steer-api: отвергнута" "True" "$(hf vf rejected)"
check "  причина в last_down называет обе версии API" \
    "плагин vless говорит steer-api 2.0, ядро — $API" "$(hf vf last_down)"
check "  up после hello чужого api не принят" "False" "$(hf vf up)"
check "  в журнале демона — та же причина" "1" \
    "$(grep -c "vless vf — плагин vless говорит steer-api 2.0, ядро — $API: отвергнут" "$tmp/d.err")"
check "  процесс погашен (SIGTERM демона)" "1" "$(grep -c '^stop vf ' "$tmp/log")"

check "без hello (сразу up): отвергнута" "True" "$(hf vn rejected)"
check "  причина — не назвала версию" \
    "плагин vless не назвал версию (первое сообщение — не hello, steer-api.md 2.1)" "$(hf vn last_down)"
check "hello от имени другого плагина: отвергнута" \
    "плагин vless представился плагином proxy, а запущен как vless" "$(hf vm last_down)"

# Программы нет: сняли после старта; следующая попытка (после паузы) её не находит.
wait_for '[ "$(hf xm rejected)" = True ]' 10
rm -f "$tmp/plugins/xsteer/bin/xsteer"
kill "$(grep '^xsteer xm ' "$tmp/log" | tail -1 | cut -d' ' -f3)" 2>/dev/null
wait_for 'grep -q "xsteer xm — нет программы плагина" "$tmp/d.err"' 15
check "нет программы плагина: last_down — переставить плагин" "нет программы плагина xsteer — переставить плагин" \
    "$(hf xm last_down)"
sleep 12
check "  в журнал строка о ней одна, сколько бы раз демон ни пробовал" "1" \
    "$(grep -c 'xsteer xm — нет программы плагина' "$tmp/d.err")"
n="$(grep -c '^xsteer xm ' "$tmp/log")"
cp "$tmp/stub" "$tmp/plugins/xsteer/bin/xsteer"
wait_for '[ "$(grep -c "^xsteer xm " "$tmp/log")" -gt "$n" ]' 15
check "программу вернули: демон запустил её без перезапуска" "1" \
    "$([ "$(grep -c '^xsteer xm ' "$tmp/log")" -gt "$n" ] && echo 1 || echo 0)"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
