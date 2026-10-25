#!/bin/sh
# Плагины в ядре: виды, схема ключей, подкоманды, хуки, слоты nft (src/kinds/plugin.c, plugprep.c).
#
# Плагины не настоящие: манифесты и программы-заглушки лежат во временном каталоге, который ядру
# называют STEER_PLUGINS_ROOT (манифесты) и STEER_PLUGINS_ETC (state.json, кэш хуков, alloc.json).
# Проверяется то, что ядро решает само, без роутера и без root: набор правил печатает
# `steer apply --dry-run`, спеку читают `steer outputs`, `status` и `spec convert`.
#
#   fakeplug — вид fakekind со схемой ключей, шаблоном nft и подкомандой fake-hello;
#   xpplug   — вид xp с check, expand (группа и два члена), pre_apply (правило) и ресурсами.
#
# Проверяется: разбор вида; отказ при неизвестном ключе и при нарушении схемы; unavail при
# отсутствующем и при отключённом плагине (при старте — остальное работает, при apply — отказ с
# причиной) и прежний отказ там, где плагинной раскладки нет; подкоманда из манифеста; хуки check
# и expand, их кэш по входу; pre_apply и owner; подготовка спеки; слоты nft и карта `nft-map`.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
has() {     # has "имя" "текст" "подстрока"
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет подстроки: %s\n  в тексте: %s\n' "$1" "$3" "$2" ;; esac
}
hasnt() {
    case "$2" in *"$3"*)
        fail=$((fail + 1)); printf 'FAIL %s\n  лишняя подстрока: %s\n  в тексте: %s\n' "$1" "$3" "$2" ;; *) pass=$((pass + 1)) ;; esac
}

ROOT="$tmp/plugins" ETC="$tmp/etc" ST="$tmp/st"
mkdir -p "$ROOT/fakeplug/bin" "$ROOT/fakeplug/kinds" "$ROOT/fakeplug/nft" \
         "$ROOT/xpplug/bin" "$ROOT/xpplug/kinds" "$ETC" "$ST"
export STEER_PLUGINS_ROOT="$ROOT" STEER_PLUGINS_ETC="$ETC"

# ---- fakeplug: вид со схемой, шаблон nft, подкоманда ---------------------------------------------
cat > "$ROOT/fakeplug/plugin.json" <<'EOF'
{
  "schema": 1, "id": "fakeplug", "version": "1.0.0", "name": "Фальшивый",
  "compat": { "steer-api": "^1.0" }, "arch": "all",
  "steer": {
    "kinds": [{
      "name": "fakekind", "keys": "kinds/fakekind.schema.json",
      "caps": ["device", "mark"],
      "helper": { "prog": "bin/helper", "cmd": "fakehelper", "argv": ["fake", "{out}", "--conf", "{conf}"] },
      "nft": ["nft/out.nft"]
    }],
    "commands": [{ "name": "fake-hello", "prog": "bin/hello", "argv": ["hello"], "help": "приветствие плагина" }],
    "nft": ["nft/plugin.nft"]
  }
}
EOF
cat > "$ROOT/fakeplug/kinds/fakekind.schema.json" <<'EOF'
{ "type": "object",
  "properties": {
    "token": { "type": "string", "minLength": 2 },
    "nodes": { "type": "array", "items": { "type": "integer", "minimum": 1 }, "uniqueItems": true },
    "file":  { "type": "string", "x-path": "etc" },
    "mode":  { "enum": ["a", "b"], "default": "a" }
  },
  "required": ["token"], "additionalProperties": false }
EOF
cat > "$ROOT/fakeplug/nft/out.nft" <<'EOF'
# шаблон вида: правила всех выходов одного вида ложатся в одну цепочку подряд
chain prerouting-dnat {
  meta mark and {steer_mask} == {out_mark} tcp dport { 443, 80 } counter redirect to :9999
}
EOF
cat > "$ROOT/fakeplug/nft/plugin.nft" <<'EOF'
set private4 {
  type ipv4_addr; flags interval
  elements = { 10.0.0.0/8, 192.168.0.0/16 }
}
chain postrouting-post {
  ip daddr @private4 return
  iifname @lan_dev counter
}
EOF
printf '#!/bin/sh\necho "hello from plugin: $*"\n' > "$ROOT/fakeplug/bin/hello"
printf '#!/bin/sh\nexit 0\n' > "$ROOT/fakeplug/bin/helper"
chmod +x "$ROOT/fakeplug/bin/hello" "$ROOT/fakeplug/bin/helper"

# ---- xpplug: check, expand, pre_apply, ресурсы -----------------------------------------------------
cat > "$ROOT/xpplug/plugin.json" <<'EOF'
{
  "schema": 1, "id": "xpplug", "version": "1.0.0", "name": "Разворот",
  "compat": { "steer-api": "^1.0" }, "arch": "all",
  "steer": {
    "kinds": [{
      "name": "xp", "keys": "kinds/xp.schema.json", "caps": ["mark"],
      "check":  { "prog": "bin/check",  "argv": ["{out}"] },
      "expand": { "prog": "bin/expand", "argv": ["{out}"] },
      "resources": { "ports": 2, "queues": 1 }
    }],
    "hooks": { "pre_apply": { "prog": "bin/pre", "argv": [] } }
  }
}
EOF
cat > "$ROOT/xpplug/kinds/xp.schema.json" <<'EOF'
{ "type": "object", "properties": { "count": { "type": "integer", "minimum": 1, "default": 2 } },
  "additionalProperties": false }
EOF
cat > "$ROOT/xpplug/bin/check" <<EOF
#!/bin/sh
echo check >> "$tmp/hooklog"
in=\$(cat)
case "\$in" in *'"count":9'*) echo "count 9 нельзя" >&2; exit 2;; esac
echo '{"warnings":["проверка прошла"]}'
EOF
cat > "$ROOT/xpplug/bin/expand" <<EOF
#!/bin/sh
echo expand >> "$tmp/hooklog"
cat >/dev/null
n="\$1"
printf '{"self":{"kind":"group","pick":"order","members":["%s.1","%s.2"],"on_fail":"drop"},"outputs":{"%s.1":{"kind":"interface","device":"dev1"},"%s.2":{"kind":"interface","device":"dev2"}},"helper":false}\n' "\$n" "\$n" "\$n" "\$n"
EOF
cat > "$ROOT/xpplug/bin/pre" <<EOF
#!/bin/sh
echo pre >> "$tmp/hooklog"
in=\$(cat)
case "\$in" in
    *'"x1"'*) printf '%s\n' "\$in" | sed 's/"rules": *\[\]/"rules":[{"name":"added-by-hook","for":"lan","to":"all","out":"x1"}]/' ;;
    *) printf '%s\n' "\$in" ;;
esac
EOF
chmod +x "$ROOT/xpplug/bin/"*

spec() { printf 'version: 2\noutputs:\n%s\nrules: []\n' "$2" > "$tmp/$1.yaml"; }
dry() { "$BIN" apply --dry-run --spec "$tmp/$1.yaml" 2>&1; }
outs() { "$BIN" outputs --spec "$tmp/$1.yaml" 2>&1; }
stat() { "$BIN" status --spec "$tmp/$1.yaml" --state-dir "$ST" 2>&1; }

# ================= 1. разбор вида ======================================================================
spec ok '  f1: { kind: fakekind, token: abc, nodes: [1, 2], file: sub/x, on_fail: drop }'
check "вид плагина: выход разобран" "f1" "$(outs ok)"
conv="$("$BIN" spec convert --spec "$tmp/ok.yaml" 2>&1)"
has "convert: вид назван манифестным именем" "$conv" "kind: fakekind"
has "convert: ключ из схемы" "$conv" "token: abc"
has "convert: список ключа" "$conv" "nodes: [1, 2]"
has "convert: путь x-path: etc стал абсолютным (от каталога спеки)" "$conv" "file: $tmp/sub/x"
has "convert: умолчание схемы (mode) записано" "$conv" "mode: a"
st="$(stat ok)"
has "status: выход вида плагина с его именем вида" "$st" '"f1":{"kind":"fakekind"'
has "status: плагин назван в выходе" "$st" '"plugin":{"id":"fakeplug","version":"1.0.0"}'
has "status: сводка плагинов" "$st" '"plugins":[{"id":"fakeplug","version":"1.0.0","state":"enabled","why":null}'

# ================= 2. отказы по схеме ==================================================================
spec bad1 '  f1: { kind: fakekind, token: abc, bogus: 1 }'
out="$(dry bad1)"
has "неизвестный ключ — отказ" "$out" "неизвестный ключ «bogus»"
has "  с перечнем ключей вида" "$out" "(есть: token, nodes, file, mode)"
has "  и местом в спеке" "$out" "bad1.yaml:3:"
spec bad2 '  f1: { kind: fakekind, token: abc, nodes: [1, 1] }'
has "повтор в uniqueItems — отказ" "$(dry bad2)" "nodes[1]: «1» уже есть в списке"
spec bad3 '  f1: { kind: fakekind, token: a }'
has "minLength — отказ" "$(dry bad3)" "token: короче 2 знаков"
spec bad4 '  f1: { kind: fakekind }'
has "нет обязательного ключа — отказ" "$(dry bad4)" "нет обязательного ключа token"
spec bad5 '  f1: { kind: fakekind, token: abc, mode: z }'
has "enum — отказ" "$(dry bad5)" "нужно одно из: a, b"
spec bad6 '  f1: { kind: fakekind, token: abc, nodes: [0] }'
has "minimum — отказ" "$(dry bad6)" "0 — меньше допустимого 1"
spec bad7 '  f1: { kind: fakekind, token: abc, nodes: [x] }'
has "тип — отказ" "$(dry bad7)" "нужно: целое число"

# ================= 3. слоты и шаблоны nft ================================================================
rs="$(dry ok)"
has "слот: базовая цепочка ядра" "$rs" "chain plugin_prerouting-dnat {"
has "  с хуком и приоритетом слота" "$rs" "type nat hook prerouting priority dstnat + 1"
has "  jump на цепочку плагина" "$rs" "jump plugin_fakeplug_prerouting-dnat"
has "  правило вида с подстановкой {out_mark} и {steer_mask}" "$rs" \
    "meta mark and 0x0ff00000 == 0x00100000 tcp dport { 443, 80 } counter redirect to :9999"
has "  скобки множества nft не приняты за подстановку" "$rs" "tcp dport { 443, 80 }"
has "файл плагина: набор переименован" "$rs" "set p_fakeplug_private4 {"
has "  ссылка @набор переименована" "$rs" "ip daddr @p_fakeplug_private4 return"
has "  набор ядра lan_dev заведён" "$rs" "set lan_dev {"
has "  слот postrouting-post — после NAT" "$rs" "chain plugin_postrouting-post {"
has "  с приоритетом srcnat + 20" "$rs" "priority srcnat + 20"
if command -v unshare >/dev/null 2>&1 && command -v nft >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
    printf '%s\n' "$rs" > "$tmp/rules.nft"
    nout="$(unshare -rn nft -c -f "$tmp/rules.nft" 2>&1)"
    check "набор правил со слотами принимает настоящий nft (-c)" "" "$nout"
else
    echo "nft -c недоступен — проверка набора пропущена"
fi

# ================= 4. карта nft ==========================================================================
map="$("$BIN" nft-map --json 2>&1)"
has "nft-map: таблица" "$map" '"table":"steer","family":"inet"'
has "nft-map: поле метки" "$map" '"mask":"0x0ff00000"'
has "nft-map: цепочка ядра с приоритетом числом" "$map" '{"name":"prerouting_mark","type":"filter","hook":"prerouting","priority":-149}'
has "nft-map: слот" "$map" '{"name":"prerouting-pre","chain":"plugin_prerouting-pre","type":"filter","hook":"prerouting","priority":-150}'
has "nft-map: слот после NAT" "$map" '"name":"postrouting-post","chain":"plugin_postrouting-post","type":"filter","hook":"postrouting","priority":120'
# Карта не должна расходиться с настоящим набором правил: приоритет каждой цепочки, которую печатает
# компилятор, равен числу из карты.
spec mapchk '  f1: { kind: fakekind, token: abc }
  w:  { kind: tunnel, protocol: hysteria2 }'
nums() {    # имя цепочки и приоритет числом из текста nft
    awk '/^ *chain [a-z_0-9]+ \{/ { name = $2 }
         /priority/ && name != "" {
             p = $0; sub(/.*priority /, "", p); sub(/;.*/, "", p)
             n = split(p, a, " ")
             base = a[1]
             v = (base == "raw") ? -300 : (base == "mangle") ? -150 : (base == "dstnat") ? -100 : (base == "filter") ? 0 : (base == "srcnat") ? 100 : base + 0
             if (n == 3) v = (a[2] == "-") ? v - a[3] : v + a[3]
             print name, v; name = "" }'
}
dry ok | nums | sort > "$tmp/real.txt"
printf '%s' "$map" | tr '{' '\n' | sed -n 's/.*"name":"\([a-z_]*\)","type":"[a-z]*","hook":"[a-z]*","priority":\(-\{0,1\}[0-9]*\).*/\1 \2/p' | sort > "$tmp/map.txt"
miss=""
while read -r n p; do
    q="$(awk -v n="$n" '$1 == n { print $2 }' "$tmp/map.txt")"
    [ -z "$q" ] && continue
    [ "$q" = "$p" ] || miss="$miss $n(набор=$p,карта=$q)"
done < "$tmp/real.txt"
check "nft-map: приоритеты цепочек ядра совпадают с набором правил" "" "$miss"

has "version --json: версия steer-api, по которой плагины сверяют compat" "$("$BIN" version --json 2>&1)" '"api":"1.0","abi":"1.0"'

# ================= 5. подкоманда из манифеста ===========================================================
check "подкоманда плагина исполняется" "hello from plugin: hello a b" "$("$BIN" fake-hello a b 2>&1)"
has "справка называет подкоманду плагина" "$("$BIN" help 2>&1)" "fake-hello"
has "  и плагин" "$("$BIN" help 2>&1)" "[fakeplug]"
has "help <подкоманда>" "$("$BIN" help fake-hello 2>&1)" "приветствие плагина"

# ================= 6. вид без плагина ====================================================================
spec nov '  f1: { kind: fakekind, token: abc }
  v:  { kind: tunnel, protocol: vless, subscription: sub/x, nodes: [1], on_fail: direct }'
spec novonly '  v:  { kind: tunnel, protocol: vless, subscription: sub/x, nodes: [1], on_fail: direct }'
out="$(outs nov)"
has "unavail: оба выхода разобраны (при старте остальное работает)" "$out" "f1"
has "  недоступный тоже в перечне" "$out" "v"
st="$(stat nov)"
has "status: недоступный вид — прежним именем" "$st" '"v":{"kind":"vless"'
has "status: unavail с причиной" "$st" '"unavail":{"why":"нужен плагин vless — поставить","plugin":"vless"}'
has "status: он failed (on_fail живёт)" "$st" '"failed":true'
has "status: остальные выходы без unavail" "$st" '"f1":{"kind":"fakekind"'
out="$(dry nov)"
has "apply/check: отказ с причиной" "$out" "outputs.v: нужен плагин vless — поставить"
spec nov2 '  v:  { kind: tunnel, protocol: nosuch, subscription: sub/x }'
has "неизвестный протокол — прежний отказ" "$(dry nov2)" "протокол «nosuch» не знаю"
spec nov3 '  v:  { kind: nosuchkind }'
has "неизвестный kind — отказ, а не unavail" "$(dry nov3)" "неизвестный kind «nosuchkind»"
# отключённый плагин: state.json менеджера
printf '{"schema":1,"plugins":{"fakeplug":{"enabled":false,"why":"отключён человеком"},"xpplug":{"enabled":true}}}\n' > "$ETC/state.json"
st="$(stat ok)"
has "отключённый плагин: выход недоступен" "$st" '"unavail":{"why":"плагин fakeplug отключён: отключён человеком","plugin":"fakeplug"}'
has "  плагин в сводке с причиной" "$st" '{"id":"fakeplug","version":"1.0.0","state":"failed","why":"отключён человеком"}'
has "  apply — отказ с причиной" "$(dry ok)" "плагин fakeplug отключён: отключён человеком"
check "  подкоманда отключённого плагина не регистрируется" "1" "$("$BIN" fake-hello >/dev/null 2>&1; echo $(( $? > 0 )))"
rm -f "$ETC/state.json"
# без плагинной раскладки (нет каталога плагинов) ядро ведёт себя, как до плагинов
out="$(STEER_PLUGINS_ROOT="$tmp/none" "$BIN" apply --dry-run --spec "$tmp/novonly.yaml" 2>&1)"
has "без раскладки плагинов: вид без модуля — прежний отказ" "$out" "kind vless требует пакет steer-vless"
out="$(STEER_PLUGINS_ROOT="$tmp/none" "$BIN" apply --dry-run --spec "$tmp/ok.yaml" 2>&1)"
has "без раскладки плагинов: вид плагина неизвестен" "$out" "неизвестный kind «fakekind»"

# ================= 7. несовместимый и конфликтный плагины ==========================================
mkdir -p "$ROOT/oldapi" "$ROOT/clash/bin"
cat > "$ROOT/oldapi/plugin.json" <<'EOF'
{ "schema": 1, "id": "oldapi", "version": "1.0.0", "compat": { "steer-api": "^2.0" },
  "steer": { "kinds": [{ "name": "oldkind", "caps": ["mark"] }] } }
EOF
cat > "$ROOT/clash/plugin.json" <<'EOF'
{ "schema": 1, "id": "clash", "version": "1.0.0", "compat": { "steer-api": "^1.0" },
  "steer": { "commands": [{ "name": "apply", "prog": "bin/x" }, { "name": "fake-hello", "prog": "bin/x" }] } }
EOF
st="$(stat ok)"
has "несовместимый steer-api: плагин выключен с числами" "$st" 'oldapi 1.0.0 требует steer-api ^2.0, у ядра 1.0'
has "имя команды ядра плагину не даётся" "$st" 'подкоманда apply — команда ядра'
check "  команда ядра осталась ядру" "table" "$("$BIN" apply --dry-run --spec "$tmp/ok.yaml" 2>&1 | head -1 | cut -d' ' -f1)"
rm -rf "$ROOT/oldapi" "$ROOT/clash"

# ================= 8. хуки check и expand, подготовка ===================================================
: > "$tmp/hooklog"
spec xp '  x1: { kind: xp, count: 2 }'
out="$(dry xp)"
has "check: предупреждение хука дошло до человека" "$out" "steer[warn] плагин xpplug: x1: проверка прошла"
has "expand: члены разворота в наборе правил" "$out" 'steer-mark:x1.1'
has "  и второй" "$out" 'steer-mark:x1.2'
has "  выход под прежним именем стал группой" "$out" 'steer-mark:x1"'
has "pre_apply: правило, добавленное хуком, в наборе" "$out" 'steer:x1_all'
check "хуки исполнены по разу (check, expand, pre_apply)" "check expand pre" "$(tr '\n' ' ' < "$tmp/hooklog" | sed 's/ $//')"
key=""
for f in "$ETC/cache/prepared/"*.json; do
    case "$f" in *.report.json) continue ;; esac
    grep -q '"x1"' "$f" 2>/dev/null && key="$f"
done
[ -f "$key" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL подготовленная спека не записана"; }
prep="$(cat "$key" 2>/dev/null)"
has "подготовленная спека: self под прежним именем" "$prep" '"x1":{"kind":"group"'
has "  члены с owner = {плагин, выход}" "$prep" '"x1.1":{"owner":{"plugin":"xpplug","out":"x1"}'
has "  правило хука с owner = {плагин}" "$prep" '{"owner":{"plugin":"xpplug"},"name":"added-by-hook"'
has "отчёт подготовки: что изменили хуки" "$(cat "${key%.json}.report.json")" '"pre_apply":[{"id":"xpplug","added":["rules[0]"],"changed":[]}]'
has "  развороты" "$(cat "${key%.json}.report.json")" '"expand":[{"id":"xpplug","out":"x1","outputs":["x1.1","x1.2"]}]'
check "ресурсы выданы (alloc.json): два порта и очередь" '"xpplug/x1":{"ports":[10480,10481],"queues":[4300]}' "$(grep xpplug "$ETC/alloc.json")"
# спеку читает load_spec из подготовленной: и status, и перечень выходов
check "outputs читает подготовленную спеку" "x1 x1.1 x1.2" "$(outs xp | tr '\n' ' ' | sed 's/ $//')"
st="$(stat xp)"
has "status: член с владельцем" "$st" '"x1.1":{"kind":"interface","owner":{"plugin":"xpplug","out":"x1"}'
has "status: у выхода человека владельца нет" "$st" '"x1":{"kind":"group","device"'
# кэш: та же спека — хуки не запускаются; спека с другим текстом, но тем же выходом — check и expand из кэша
: > "$tmp/hooklog"
dry xp > /dev/null
check "кэш подготовки: повтор без запуска хуков" "" "$(cat "$tmp/hooklog")"
printf '# комментарий меняет байты спеки\n' >> "$tmp/xp.yaml"
dry xp > /dev/null
check "кэш хуков по входу: комментарий не меняет вход хуков — ни один не запущен" "" "$(cat "$tmp/hooklog")"
spec xp2 '  x1: { kind: xp, count: 2 }
  d:  { kind: direct }'
dry xp2 > /dev/null
check "новый выход меняет вход хуков (перечень выходов) — запущены все три" "check expand pre" "$(tr '\n' ' ' < "$tmp/hooklog" | sed 's/ $//')"
# отказ check
spec xp9 '  x1: { kind: xp, count: 9 }'
out="$(dry xp9)"
has "check: отказ плагина — отказ спеки с выходом и причиной" "$out" "outputs.x1: count 9 нельзя"
has "  и местом в спеке" "$out" "xp9.yaml:3:"
# не подготовлена: кэша нет — при чтении (status) выход недоступен, а не отказ спеки
rm -rf "$ETC/cache"
st="$(stat xp)"
has "спека не подготовлена: выход недоступен" "$st" '"unavail":{"why":"спека не подготовлена — нужен reload","plugin":"xpplug"}'
has "  вид — прежним именем" "$st" '"x1":{"kind":"xp"'
# сам человек owner написать не вправе
spec own '  x1: { kind: direct, owner: { plugin: xpplug } }'
has "owner в спеке человека — отказ" "$(dry own)" "owner пишет только плагин"
spec dev '  x1: { kind: plugin-device }'
has "plugin-device руками — отказ" "$(dry dev)" "заводит только плагин"
# spec convert читает спеку человека: выходы, заведённые хуками, не печатаются
conv="$("$BIN" spec convert --spec "$tmp/xp.yaml" 2>&1)"
has "convert: выход человека на месте" "$conv" "x1: { kind: xp, count: 2 }"
hasnt "  выходы хука не печатаются" "$conv" "x1.1"

# ================= 9. ресурсы плагина целиком (resources манифеста) ====================================
# Как у recheck: очереди и биты метки выдаёт ядро, а плагин пишет в nft и argv только подстановки.
mkdir -p "$ROOT/svcplug/nft"
cat > "$ROOT/svcplug/plugin.json" <<'EOF'
{ "schema": 1, "id": "svcplug", "version": "1.0.0", "compat": { "steer-api": "^1.0" },
  "resources": { "queues": 2, "mark_bits": 3, "ports": 1 },
  "steer": { "nft": ["nft/svc.nft"] } }
EOF
cat > "$ROOT/svcplug/nft/svc.nft" <<'EOF'
chain postrouting-post {
  meta mark & {mark} == {mark} return
  meta mark & {steer_mask} != 0 return
  iifname @lan_dev counter queue flags bypass to {queue0}
  udp dport {port0} counter queue to {queue1}
}
EOF
rm -rf "$ETC/cache" "$ETC/alloc.json"
rs="$(dry ok)"
al="$(grep 'plugin:svcplug' "$ETC/alloc.json" | sed 's/,$//')"
check "ресурсы плагина: порт, две очереди, три бита метки вне поля steer и соседей" \
    '"plugin:svcplug":{"ports":[10480],"queues":[4300,4301],"mark_bits":[31,15,14]}' "$al"
has "{mark} — маска выданных битов" "$rs" "meta mark & 0x8000c000 == 0x8000c000 return"
has "{queue0}" "$rs" "queue flags bypass to 4300"
has "{port0} и {queue1}" "$rs" "udp dport 10480 counter queue to 4301"
# соседний плагин не получает те же номера
spec xp3 '  x1: { kind: xp, count: 2 }'
dry xp3 > /dev/null
check "ресурсы выхода другого плагина — другие номера" '"xpplug/x1":{"ports":[10481,10482],"queues":[4302]}' "$(grep xpplug "$ETC/alloc.json" | sed 's/,$//')"
check "  выданное svcplug осталось прежним (номера постоянны)" "$al" "$(grep 'plugin:svcplug' "$ETC/alloc.json" | sed 's/,$//')"
# {mark} без resources — отказ с причиной
mkdir -p "$ROOT/nores/nft"
cat > "$ROOT/nores/plugin.json" <<'EOF'
{ "schema": 1, "id": "nores", "version": "1.0.0", "compat": { "steer-api": "^1.0" },
  "steer": { "nft": ["nft/n.nft"] } }
EOF
printf 'chain forward {\n  meta mark & {mark} != 0 return\n}\n' > "$ROOT/nores/nft/n.nft"
has "{mark} у плагина без resources — отказ с именем плагина и строкой файла" "$(dry ok)" "плагин nores: $ROOT/nores/nft/n.nft:2:"
rm -rf "$ROOT/nores"

# ================= 5. слова схемы спеки в схеме ключей вида ===============================================
# refplug — вид refkind со словами x-ref, x-one-or-list, x-needs, x-when, x-when-set, x-example (как у
# схемы спеки ядра, docs/spec-schema.md): разбор ссылок, одно значение вместо списка, соседи, подсказки.
mkdir -p "$ROOT/refplug/kinds"
cat > "$ROOT/refplug/plugin.json" <<'EOF'
{ "schema": 1, "id": "refplug", "version": "1.0.0", "compat": { "steer-api": "^1.0" }, "arch": "all",
  "steer": { "kinds": [{ "name": "refkind", "keys": "kinds/refkind.schema.json", "caps": ["mark"] }] } }
EOF
cat > "$ROOT/refplug/kinds/refkind.schema.json" <<'EOF'
{ "type": "object",
  "properties": {
    "via":   { "type": "string", "x-ref": { "section": "outputs", "also": ["direct"] }, "x-example": "wg0" },
    "to":    { "type": "array", "items": { "type": "string", "x-ref": { "section": "lists", "also": ["all"] } },
               "minItems": 1, "x-one-or-list": true, "x-example": ["work"] },
    "who":   { "type": "array", "items": { "type": "string", "x-ref": { "section": "clients", "also": ["lan"] } },
               "x-one-or-list": true },
    "dns":   { "type": "string", "x-ref": { "section": "dns.upstreams" } },
    "scope": { "enum": ["device", "global"], "default": "global", "x-needs": { "device": ["for"] } },
    "for":   { "type": "string", "x-when": { "scope": ["device"] } },
    "pick":  { "enum": ["order", "latency"], "x-example": "order" },
    "tol":   { "type": "integer", "minimum": 0, "x-when": { "pick": ["latency"] }, "x-when-set": ["pick"] },
    "by":    { "type": "string", "x-needs": { "*": ["pick"] } }
  },
  "additionalProperties": false }
EOF
rspec() {   # rspec имя "ключи выхода r1" — спека с выходом wg0, списком work, клиентом kid и апстримом dns1
    cat > "$tmp/$1.yaml" <<EOS
version: 2
clients:
  kid: { addr: 192.168.1.50 }
lists:
  work: { domains_file: work.txt }
dns:
  upstreams:
    dns1: { url: "udp://1.1.1.1" }
outputs:
  wg0: { kind: interface, device: wg0 }
  r1: { kind: refkind, $2 }
rules: []
EOS
}
printf "example.org\n" > "$tmp/work.txt"
oneline() { printf '%s' "$1" | tr '\n' ' ' | sed 's/ $//'; }
rspec rok 'via: wg0, to: work'
check "x-ref: имя из раздела — разбор принял" "wg0 r1" "$(oneline "$(outs rok)")"
rspec rone 'to: work'
has "x-one-or-list: одно значение стало списком" "$("$BIN" spec convert --spec "$tmp/rone.yaml" 2>&1)" 'to: [work]'
rspec rlist 'to: [work, all]'
has "x-one-or-list: список с also принят как есть" "$("$BIN" spec convert --spec "$tmp/rlist.yaml" 2>&1)" 'to: [work, all]'
rspec ralso 'via: direct, who: [lan, kid], dns: dns1'
check "x-ref.also и остальные разделы — принято" "wg0 r1" "$(oneline "$(outs ralso)")"
rspec rbad1 'via: nope'
out="$(dry rbad1)"
has "x-ref: чужое имя — отказ" "$out" "via: «nope» — в разделе outputs такой записи нет (и это не direct)"
has "  с выходом и местом в спеке" "$out" "outputs.r1:"
has "  и строкой спеки" "$out" "rbad1.yaml:"
rspec rbad2 'to: [work, ghost]'
has "x-ref у items: ключ с номером и имя" "$(dry rbad2)" "to[1]: «ghost» — в разделе lists такой записи нет (и это не all)"
rspec rbad3 'to: ghost'
has "x-ref при одном значении вместо списка" "$(dry rbad3)" "to: «ghost»"
rspec rbad4 'who: wg0'
has "x-ref: раздел clients" "$(dry rbad4)" "who: «wg0» — в разделе clients такой записи нет (и это не lan)"
rspec rbad5 'dns: wg0'
has "x-ref: раздел dns.upstreams" "$(dry rbad5)" "dns: «wg0» — в разделе dns.upstreams такой записи нет"
rspec rbad6 'to: []'
has "minItems при x-one-or-list держится" "$(dry rbad6)" "нужно не меньше 1"
rspec rn1 'scope: device'
has "x-needs: значение без соседа — отказ" "$(dry rn1)" "scope: device — без ключа for он не разобран"
rspec rn2 'scope: device, for: kid'
check "x-needs: с соседом принято" "wg0 r1" "$(oneline "$(outs rn2)")"
rspec rn3 'scope: global'
check "x-needs: другое значение соседа не требует" "wg0 r1" "$(oneline "$(outs rn3)")"
rspec rn4 'by: x'
has "x-needs «*»: при любом значении" "$(dry rn4)" "by: при любом значении — без ключа pick он не разобран"
rspec rw1 'tol: 5'
check "x-when и x-when-set — подсказки: ключ вне условия законен" "wg0 r1" "$(oneline "$(outs rw1)")"
rspec rw2 'for: kid'
check "x-when: сосед не записан — разбор не отказывает" "wg0 r1" "$(oneline "$(outs rw2)")"
# слова схемы спеки доходят до `steer spec-schema` как есть
sch="$("$BIN" spec-schema --json 2>&1 | tr -d ' \n')"
for w in '"x-ref":{"section":"outputs","also":["direct"]}' '"x-one-or-list":true' '"x-needs":{"device":["for"]}' \
         '"x-when":{"pick":["latency"]}' '"x-when-set":["pick"]'; do
    has "spec-schema: ключ плагина со словом $w" "$sch" "$w"
done
# схема с неверным видом слова отвергается при разборе
cat > "$ROOT/refplug/kinds/refkind.schema.json" <<'EOF'
{ "type": "object", "properties": { "via": { "type": "string", "x-ref": { "section": "nowhere" } } } }
EOF
has "x-ref с чужим разделом — ошибка схемы" "$(dry rok)" "x-ref — {section: outputs, lists, clients или dns.upstreams}"
cat > "$ROOT/refplug/kinds/refkind.schema.json" <<'EOF'
{ "type": "object", "properties": { "via": { "type": "string", "x-one-or-list": true } } }
EOF
has "x-one-or-list у не-массива — ошибка схемы" "$(dry rok)" "x-one-or-list — у массива"
rm -rf "$ROOT/refplug"

printf '\npluginkindmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
