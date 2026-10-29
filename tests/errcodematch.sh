#!/bin/sh
# Коды отказов ядра (docs/errors.md): code и args рядом с текстом error.
#
#   1. Отказ спеки при STEER_ERR_JSON=1: после текста — строка JSON с code, args и местом (at, line, col); без переменной
#      вывод прежний, строки JSON нет.
#   2. Подстановки: по порядку подстановок текста, слова-виды узла — английскими.
#   3. Чтение YAML (табуляция, повтор ключа) и сквозные проверки (круг подложек) несут свои коды.
#   4. Отказ, у которого слова нет, остаётся текстом без code.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "errcodematch: python3 нет — ПРОПУСК"; exit 0; }
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
# err ФАЙЛ -> последняя строка stderr (JSON отказа) под STEER_ERR_JSON=1
js() { STEER_ERR_JSON=1 "$BIN" apply --dry-run --spec "$1" 2>&1 >/dev/null | tail -n 1; }
pj() { python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(eval(sys.argv[1]))' "$1"; }

printf 'version: 2\noutputs:\n  a:\n    kind: bogus\nrules: []\n' > "$T/s1.yaml"
o="$(js "$T/s1.yaml")"
check "неизвестный kind: code" "spec.unknown_kind" "$(printf '%s' "$o" | pj 'd["code"]')"
check "  подстановки 1 и 2 — выход и слово" "outputs.a bogus" "$(printf '%s' "$o" | pj 'd["args"]["1"]+" "+d["args"]["2"]')"
check "  место: строка и столбец" "4 11" "$(printf '%s' "$o" | pj 'd["args"]["line"]+" "+d["args"]["col"]')"
check "  at — файл:строка:столбец, как в тексте" "yes" "$(printf '%s' "$o" | pj '"yes" if d["args"]["at"].endswith("s1.yaml:4:11") and d["args"]["at"] in d["error"] else "no"')"
check "  ok:false и русский текст error" "False" "$(printf '%s' "$o" | pj 'd["ok"]')"
plain="$("$BIN" apply --dry-run --spec "$T/s1.yaml" 2>&1 >/dev/null)"
check "без STEER_ERR_JSON — одна строка текста, без JSON" "1" "$(printf '%s\n' "$plain" | wc -l | tr -d ' ')"

printf 'version: 2\noutputs:\n  a: { kind: direct }\nrules: 5\n' > "$T/s2.yaml"
o="$(js "$T/s2.yaml")"
check "rules не список: code и английское слово вида" "spec.rules_shape a string" "$(printf '%s' "$o" | pj 'd["code"]+" "+d["args"]["1"]')"

printf 'version: 2\noutputs:\n\ta: { kind: direct }\n' > "$T/s3.yaml"
check "табуляция в отступе: yaml.tab" "yaml.tab" "$(js "$T/s3.yaml" | pj 'd["code"]')"
printf 'version: 2\noutputs:\n  a: { kind: direct }\n  a: { kind: block }\n' > "$T/s4.yaml"
o="$(js "$T/s4.yaml")"
check "повтор ключа: yaml.duplicate_key, ключ и строка" "yaml.duplicate_key a 3" "$(printf '%s' "$o" | pj 'd["code"]+" "+d["args"]["1"]+" "+d["args"]["2"]')"

printf 'version: 2\nlan: { devices: [br-lan] }\noutputs:\n  a: { kind: interface, device: br-lan }\nrules: []\n' > "$T/s5.yaml"
check "выход в локальное устройство: spec.device_is_lan" "spec.device_is_lan a br-lan" \
    "$(js "$T/s5.yaml" | pj 'd["code"]+" "+d["args"]["1"]+" "+d["args"]["2"]')"

printf 'version: 2\noutputs:\n  a: { kind: direct, bogus_key: 1 }\nrules: []\n' > "$T/s6.yaml"
check "лишний ключ: spec.unknown_key" "spec.unknown_key bogus_key" "$(js "$T/s6.yaml" | pj 'd["code"]+" "+d["args"]["1"]')"

# Спека v1 (JSON schema: 1): отказ без своего слова — spec.v1_error, текст в подстановке 1.
printf '{"schema": 1, "outputs": {"a": {"kind": "bogus"}}}\n' > "$T/v1.json"
o="$(js "$T/v1.json")"
check "спека v1: spec.v1_error, текст отказа в подстановке 1" "spec.v1_error yes" \
    "$(printf '%s' "$o" | pj 'd["code"]+" "+("yes" if d["args"]["1"] and d["args"]["1"] in d["error"] else "no")')"

# Нет файла: у отказа слова нет — JSON без code, error есть.
o="$(STEER_ERR_JSON=1 "$BIN" apply --dry-run --spec "$T/нет.yaml" 2>&1 >/dev/null | tail -n 1)"
check "нет файла спеки: слова нет, JSON без code" "no-code" "$(printf '%s' "$o" | pj '"no-code" if "code" not in d and d["error"] else "has-code"' 2>/dev/null || echo not-json)"

printf '\nerrcodematch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
