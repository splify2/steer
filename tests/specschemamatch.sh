#!/bin/sh
# Схема спеки v2: `steer spec-schema` (src/model/v2keys.c, v2schema.c; docs/spec-schema.md).
#
# Схему строят таблицы ключей, которыми пользуется и разбор спеки, реестр видов и реестр плагинов.
# Стенд сверяет её с настоящим разбором (tests/specschemamatch.py): каждый ключ схемы разбор
# принимает, значения enum и границы чисел — тоже, неизвестный ключ и ключ чужого вида — нет, а
# всё, что разбор принимает, есть в схеме. Прогоны:
#
#   1. роутер  — виды ядра сборки; виды, которых в сборке нет, названы в схеме как недоступные;
#   2. телефон — STEER_PLATFORM=android: ключи uid, self и app принимаются;
#   3. плагины — вид и протокол плагина вливаются с пометкой x-plugin, их ключи принимает разбор,
#                выключенный плагин назван в x-plugins с причиной;
#   4. расширенная сборка — если задан STEERD_EXT (steerd раскладки с модулями vless, xsteer, hysteria2,
#                proxy: tests/libs-test.sh собирает её и зовёт этот стенд с SPECSCHEMA_ONLY_EXT=1):
#                тот же прогон по её видам, на обеих платформах.
# Кроме того: справка называет команду, таблица для человека печатается, JSON разбирается.
set -u
BIN="${STEERD:-./build/steerd}"
CLI="${STEER:-./build/steer}"
for b in "$BIN" "$CLI"; do
    [ -x "$b" ] || { echo "specschemamatch: не собран $b (make)"; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "specschemamatch: нужен python3"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
rc=0
pass=0
fail=0
has() {     # has "имя" "текст" "подстрока"
    case "$2" in *"$3"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL specschemamatch: %s\n  нет подстроки: %s\n' "$1" "$3" ;; esac
}

# ---- справка, таблица и JSON -------------------------------------------------------------------
has "справка называет spec-schema" "$("$CLI" help 2>&1)" "spec-schema"
has "справка команды" "$("$CLI" help spec-schema 2>&1)" "docs/spec-schema.md"
txt="$("$CLI" spec-schema 2>&1)"
has "таблица: раздел" "$txt" "lan.devices"
has "таблица: ключ вида" "$txt" "outputs.<имя>.members"
"$BIN" spec-schema --json > "$tmp/schema.json" 2>&1 || { echo "FAIL specschemamatch: spec-schema --json не отработал"; rc=1; }
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp/schema.json" 2>/dev/null &&
    pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL specschemamatch: spec-schema --json — не JSON"; }
"$CLI" spec-schema --bogus > /dev/null 2>&1 && { fail=$((fail + 1)); echo "FAIL specschemamatch: чужой флаг принят"; } || pass=$((pass + 1))

# ---- 1-2. роутер и телефон ------------------------------------------------------------------------
if [ -z "${SPECSCHEMA_ONLY_EXT:-}" ]; then
    python3 tests/specschemamatch.py "$BIN" router docs/spec-v2.md || rc=1
    python3 tests/specschemamatch.py "$BIN" android docs/spec-v2.md || rc=1
fi

# ---- 3. плагины -----------------------------------------------------------------------------------
if [ -z "${SPECSCHEMA_ONLY_EXT:-}" ]; then
ROOT="$tmp/plugins" ETC="$tmp/etc"
mkdir -p "$ROOT/fakeplug/kinds" "$ROOT/offplug/kinds" "$ETC"
cat > "$ROOT/fakeplug/plugin.json" <<'EOP'
{
  "schema": 1, "id": "fakeplug", "version": "1.2.3", "name": "Фальшивый",
  "compat": { "steer-api": "^1.0" }, "arch": "all",
  "steer": {
    "kinds": [
      { "name": "fakekind", "keys": "kinds/fakekind.schema.json", "caps": ["device", "mark"] },
      { "name": "tunnel:fakeproto", "keys": "kinds/fakeproto.schema.json", "caps": ["device", "mark", "ipv6"] }
    ]
  }
}
EOP
cat > "$ROOT/fakeplug/kinds/fakekind.schema.json" <<'EOP'
{ "type": "object",
  "properties": {
    "token": { "type": "string", "minLength": 2 },
    "nodes": { "type": "array", "items": { "type": "integer", "minimum": 1 }, "uniqueItems": true },
    "file":  { "type": "string", "x-path": "etc" },
    "mode":  { "enum": ["a", "b"], "default": "a" },
    "level": { "type": "integer", "minimum": 0, "maximum": 9 },
    "flag":  { "type": "boolean" },
    "via":   { "type": "string", "x-ref": { "section": "outputs", "also": ["direct"] }, "x-example": "wg0" },
    "feeds": { "type": "array", "items": { "type": "string", "x-ref": { "section": "lists", "also": ["all"] } },
               "minItems": 1, "x-one-or-list": true, "x-example": ["work"] },
    "scope": { "enum": ["device", "global"], "default": "global", "x-needs": { "device": ["flag"] } },
    "tol":   { "type": "integer", "minimum": 0, "x-when": { "mode": ["b"] }, "x-when-set": ["level"] }
  },
  "required": ["token"], "additionalProperties": false }
EOP
cat > "$ROOT/fakeplug/kinds/fakeproto.schema.json" <<'EOP'
{ "type": "object",
  "properties": {
    "subscription": { "type": "string", "x-path": "etc" },
    "interval": { "type": "integer", "minimum": 1, "maximum": 100 }
  },
  "required": ["subscription"], "additionalProperties": false }
EOP
cat > "$ROOT/offplug/plugin.json" <<'EOP'
{
  "schema": 1, "id": "offplug", "version": "0.1.0", "name": "Выключенный",
  "compat": { "steer-api": "^1.0" }, "arch": "all",
  "steer": { "kinds": [ { "name": "offkind", "keys": "kinds/offkind.schema.json", "caps": ["mark"] } ] }
}
EOP
printf '{ "type": "object", "properties": { "x": { "type": "string" } }, "additionalProperties": false }\n' > "$ROOT/offplug/kinds/offkind.schema.json"
printf '{"schema":1,"plugins":{"fakeplug":{"enabled":true},"offplug":{"enabled":false,"why":"отключён человеком"}}}\n' > "$ETC/state.json"
STEER_PLUGINS_ROOT="$ROOT" STEER_PLUGINS_ETC="$ETC" SPECSCHEMA_LABEL=plugins \
SPECSCHEMA_PLUGINS="fakeplug|fakekind,fakeplug|tunnel:fakeproto" SPECSCHEMA_PLUGINS_OFF="offplug|offkind" \
    python3 tests/specschemamatch.py "$BIN" router docs/spec-v2.md || rc=1
fi

# ---- 4. расширенная сборка ------------------------------------------------------------------------
if [ -n "${STEERD_EXT:-}" ]; then
    EXT="$(cd "$(dirname "$STEERD_EXT")" && pwd)/$(basename "$STEERD_EXT")"
    SPECSCHEMA_LABEL=ext-router python3 tests/specschemamatch.py "$EXT" router docs/spec-v2.md || rc=1
    SPECSCHEMA_LABEL=ext-android python3 tests/specschemamatch.py "$EXT" android docs/spec-v2.md || rc=1
fi

echo "specschemamatch: справка и вывод — $pass проверок прошли"
if [ "$fail" -gt 0 ]; then echo "specschemamatch: ПРОВАЛЕНО $fail"; rc=1; fi
exit "$rc"
