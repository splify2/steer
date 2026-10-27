#!/bin/sh
# Службы плагинов (steer.services[], manifest.md): помощник на весь роутер под супервизором демона
# (src/daemon/helpers.c: helpers_plan, supd.c) и слот nft рядом с ним (рецепт recheck: служба + правила).
#
# Плагин svcplug — заглушки в каталоге плагинов стенда (STEER_PLUGINS_ROOT). Манифест просит очередь и бит
# метки (resources), даёт две службы и файл nft со слотами postrouting-post и output-raw. Проверяется:
#   s1  hello с api ядра, ready — служба принята, helper показывает up, plugin и plugin_ver; слова argv
#       получили выданные ресурсы ({queue0}, {mark}), в окружении — STEER_PLUGIN_STATE;
#   s2  не сказала hello, сразу up — отвергнута, как помощник выхода;
#   правила слотов встают в набор правил вместе с номерами тех же ресурсов.
# Под root стенд уходит в своё сетевое пространство. Без python3 — пропуск (разбор ответа демона).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "plugsvc: не собран $BIN"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "plugsvc: python3 нет — пропускаю"; exit 0; }
if [ "${PLUGSVC_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    PLUGSVC_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
[ "${PLUGSVC_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

tmp="$(mktemp -d)"
D=""
trap 'kill $D 2>/dev/null; wait $D 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
has() {
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет подстроки: %s\n  в тексте: %s\n' "$1" "$3" "$2" ;; esac
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    eval "$1" && return 0
    return 1
}

ROOT="$tmp/plugins" ETC="$tmp/etc" ST="$tmp/st"
mkdir -p "$ROOT/svcplug/bin" "$ROOT/svcplug/nft" "$ETC" "$ST"
STEER_PLUGINS_ROOT="$ROOT"; STEER_PLUGINS_ETC="$ETC"; export STEER_PLUGINS_ROOT STEER_PLUGINS_ETC
API="$("$BIN" version --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["api"])')"

cat > "$ROOT/svcplug/plugin.json" <<'J'
{
  "schema": 1, "id": "svcplug", "version": "1.0.0", "name": "Служба",
  "compat": { "steer-api": "^1.2" }, "arch": "all", "permissions": ["nft"],
  "resources": { "queues": 1, "mark_bits": 1 },
  "steer": {
    "services": [
      { "name": "s1", "prog": "bin/svc", "argv": ["s1", "{queue0}", "{mark}"], "env": { "SVC_ENV": "yes" } },
      { "name": "s2", "prog": "bin/svc" }
    ],
    "nft": ["nft/svc.nft"]
  }
}
J
cat > "$ROOT/svcplug/nft/svc.nft" <<'N'
chain postrouting-post {
  iifname @lan_dev oifname @wan_dev meta l4proto tcp counter queue flags bypass to {queue0}
}
chain output-raw {
  meta mark & {mark} == {mark} notrack
}
N
# Заглушка службы: $1 — имя службы (у s2 слов нет — по умолчанию argv = [имя]); пишет, с чем запущена, и события.
cat > "$ROOT/svcplug/bin/svc" <<H
#!/bin/sh
echo "\$* env=\$SVC_ENV state=\$STEER_PLUGIN_STATE id=\$STEER_PLUGIN_ID" >> "$tmp/log"
eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$1 \$\$" >> "$tmp/log"; exit 0' TERM
case "\$1" in
s1) printf '{"ev":"hello","api":"$API","ver":"9.9.9","mod":"svcplug"}\n' >&9; printf '{"ev":"ready"}\n' >&9
    printf '{"ev":"state"}\n' >&9 ;;
*) printf '{"ev":"up"}\n' >&9 ;;
esac
while :; do sleep 0.1; done
H
chmod +x "$ROOT/svcplug/bin/svc"

printf 'version: 2\noutputs:\n  d: { kind: direct }\nrules: []\n' > "$tmp/spec.yaml"
# Подготовка спеки выдаёт ресурсы плагина (alloc.json); набор правил печатает apply --dry-run.
rs="$("$BIN" apply --dry-run --spec "$tmp/spec.yaml" 2>&1)"
QN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outputs"]["plugin:svcplug"]["queues"][0])' "$ETC/alloc.json" 2>/dev/null)"
has "слот postrouting-post: очередь выданного номера" "$rs" "queue flags bypass to $QN"
has "слот output-raw: notrack по выданному биту" "$rs" "notrack"
has "слот output-raw встал цепочкой ядра" "$rs" "chain plugin_output-raw {"

"$BIN" daemon --supervise --allow-uid "$(id -u)" --socket "$tmp/s.sock" \
    --spec "$tmp/spec.yaml" --state-dir "$ST" \
    --dnsd-flag --listen-port --dnsd-flag 15521 --dnsd-flag --upstream-port --dnsd-flag 15585 \
    >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ]' 5
wctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }
hf() {  # служба поле
    wctl helper "$1" | python3 -c 'import json,sys
d=json.loads(json.load(sys.stdin)["stdout"]); print(d.get(sys.argv[1], "-"))' "$2" 2>&1
}
wait_for '[ "$(hf s1 up)" = True ]' 10
wait_for '[ "$(hf s2 rejected)" = True ]' 10

check "служба с верным api: принята, up виден (ready)" "True" "$(hf s1 up)"
check "  helper называет её плагин" "svcplug" "$(hf s1 plugin)"
check "  и версию из hello" "9.9.9" "$(hf s1 plugin_ver)"
check "  ответ называет службу полем service" "s1" "$(hf s1 service)"
check "  слова argv: имя, выданная очередь и бит метки" "1" \
    "$(grep -c "^s1 $QN 0x[0-9a-f]\{8\} env=yes " "$tmp/log")"
check "  окружение плагина: id и рабочий каталог" "1" \
    "$(grep -c "^s1 .* state=.*/plugin/svcplug id=svcplug" "$tmp/log")"
check "служба без hello: отвергнута" "True" "$(hf s2 rejected)"
check "  причина — не назвала версию" \
    "плагин svcplug не назвал версию (первое сообщение — не hello, steer-api.md 2.1)" "$(hf s2 last_down)"
check "  слова по умолчанию — имя службы" "1" "$(grep -c '^s2 env= ' "$tmp/log")"

# Reload: служба та же, второго экземпляра нет.
kill -HUP "$D"
sleep 1
check "после reload служба та же: второго экземпляра нет" "1" "$(grep -c '^s1 ' "$tmp/log")"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
