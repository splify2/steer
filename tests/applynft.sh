#!/bin/sh
# apply и настоящий nft: замена таблицы одной транзакцией и набор «пущен напрямую».
#
# Остальные стенды компилятора смотрят на текст --dry-run, а здесь нужно именно ядро: текст
# не скажет, примет ли nft файл целиком и что останется в ядре, если не примет.
#
# Что проверяется.
#  1. apply на машине без таблицы проходит: файл начинается с `table inet steer` (добавить,
#     если нет) и `delete table inet steer`, и без первой строки удаление отказало бы — а с
#     ним весь файл.
#  2. Повторный apply проходит, и отдельного `nft delete table` при этом не зовётся: прежде
#     таблица удалялась одним запуском nft, а новая грузилась другим, и между ними DNS
#     клиентов шёл мимо резолвера. Запуски nft считает обёртка в PATH.
#  3. Отвергнутый набор оставляет в ядре ПРЕЖНЮЮ таблицу, а не пустоту; файл отвергнутого набора —
#     один на все отказы. Испорченные адресные строки списка набор не роняют: пропускаются со
#     счётом. Отказ стартового применения демон повторяет сам.
#  4. Выход с on_fail=direct без устройства: apply ставит его метку в набор failopen, то есть
#     его трафик, ушедший напрямую, общий обход снова видит как свой. Отметка засевается в
#     тот же файл, что и таблица (элемент набора failopen в загружаемом тексте), чтобы между
#     `nft -f` и failopen_after_load трафик выхода не отбрасывался.
#
# Нужны root (сетевое пространство и nf_tables), nft и ip. Без них стенд пропускается, а не
# проваливается — как dnsnft.sh.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v nft >/dev/null 2>&1 || { echo "applynft: nft нет — пропускаю"; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "applynft: ip нет — пропускаю"; exit 0; }
if [ "${APPLYNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "applynft: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "applynft: unshare -n недоступен — пропускаю"; exit 0; }
    APPLYNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet applynft_probe 2>/dev/null || { echo "applynft: nf_tables недоступен — пропускаю"; exit 0; }
nft delete table inet applynft_probe

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# Обёртка: пишет каждый запуск nft строкой и передаёт настоящему.
real_nft="$(command -v nft)"
mkdir -p "$tmp/bin"
cat > "$tmp/bin/nft" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$tmp/nft.log"
[ "\$1" = -f ] && cp "\$2" "$tmp/loaded.nft"
# Отказ ядра по заказу стенда: файл-признак — и nft -f отвергает набор, как отверг бы ядро.
if [ -e "$tmp/reject" ] && { [ "\$1" = -f ] || [ "\$1" = -c ]; }; then
    echo "Error: стенд: набор отвергнут" >&2
    exit 1
fi
exec "$real_nft" "\$@"
EOF
chmod +x "$tmp/bin/nft"
PATH="$tmp/bin:$PATH"; export PATH

printf '203.0.113.0/24\n' > "$tmp/a.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"

"$BIN" apply $S >/dev/null 2>&1
check "первый apply (таблицы нет) проходит" "0" "$?"
check "набор канала в ядре" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"

: > "$tmp/nft.log"
"$BIN" apply $S >/dev/null 2>&1
check "повторный apply проходит" "0" "$?"
check "таблица не удаляется отдельным запуском nft" "0" "$(grep -c '^delete table' "$tmp/nft.log")"
check "набор канала на месте" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"

# Испорченные адресные строки в чужом списке: форма адреса, а адресом не являются (октет больше
# 255, длина префикса 33, пустая длина, обрыв загрузки, диапазон задом наперёд). Раньше такая
# строка уходила в текст набора, и nft отвергал его целиком; теперь набор собирается без неё, а о
# пропуске — одна строка на список со счётом и первой строкой.
printf '203.0.113.0/24\n999.1.1.1\n10.0.0.0/33\n1.2.3.4/\n1...2\n104.16.0.\n10.0.0.9-10.0.0.1\n198.51.100.7\n2001:db8::/129\n' > "$tmp/a.lst"
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "список с испорченными строками: apply проходит" "0" "$?"
check "  годные адреса списка в ядре" "2" \
    "$(nft list set inet steer vpn_ip 2>/dev/null | grep -oE '203\.0\.113\.0/24|198\.51\.100\.7' | grep -c .)"
check "  о пропуске — одна строка на список, со счётом и первой строкой" "1" \
    "$(printf '%s\n' "$err" | grep -c "a.lst: испорченных адресных строк 7 из 9, пропускаю их (первая — 2: «999.1.1.1»)")"
check "  в загруженный текст испорченные не попали" "0" \
    "$(grep -cE '999\.1\.1\.1|/33|1\.\.\.2|104\.16\.0\.[, ]|10\.0\.0\.9-|/129' "$tmp/loaded.nft")"
printf '203.0.113.0/24\n' > "$tmp/a.lst"
"$BIN" apply $S >/dev/null 2>&1

# Отвергнутый ядром набор оставляет прежнюю таблицу. Файл набора остаётся для разбора — один, с
# постоянным именем: второй отказ его перезаписывает, а не кладёт рядом ещё один.
printf '203.0.113.0/24\n192.0.2.0/24\n' > "$tmp/a.lst"
: > "$tmp/reject"
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "отвергнутый набор — отказ" "1" "$?"
check "и прежняя таблица стоит" "1 0" \
    "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24') $(nft list set inet steer vpn_ip 2>/dev/null | grep -c '192.0.2.0/24')"
kept="$(printf '%s\n' "$err" | sed -n 's/.*(файл набора: \(.*\))$/\1/p')"
check "отвергнутый файл назван и лежит" "yes" "$([ -n "$kept" ] && [ -f "$kept" ] && echo yes || echo no)"
check "  имя постоянное" "steer-ruleset.rejected" "$(basename "$kept")"
# Каталог временных файлов у ядра steer общий на машину: считается прирост после первого отказа.
rj1="$(ls "$(dirname "$kept")" | grep -c 'steer-ruleset')"
"$BIN" apply $S >/dev/null 2>&1
"$BIN" apply $S >/dev/null 2>&1
check "ещё два отказа файлов набора не прибавили" "$rj1" "$(ls "$(dirname "$kept")" | grep -c 'steer-ruleset')"
rm -f "$tmp/reject" "$kept"
printf '203.0.113.0/24\n' > "$tmp/a.lst"

"$BIN" apply $S >/dev/null 2>&1
# Отметка стоит в самом файле транзакции: окна между `nft -f` и failopen_after_load нет.
check "отметка выхода засеяна в набор failopen загружаемого файла" "1" \
    "$(sed -n '/set failopen {/,/^    }/p' "$tmp/loaded.nft" | grep -c 'elements = { 0x00100000 }')"
check "отметка стоит в новой таблице файла (после delete старой)" "1" \
    "$(awk '/^delete table inet steer/ {d=1} /elements = \{ 0x00100000 \}/ && d {print "x"; exit}' "$tmp/loaded.nft" | grep -c x)"
check "выход без устройства при on_fail=direct отмечен «пущен напрямую»" "1" \
    "$(nft list set inet steer failopen 2>/dev/null | grep -c 'elements = { 0x00100000 }')"
check "цепочка снятия бита стоит" "1" \
    "$(nft list chain inet steer prerouting_failopen 2>/dev/null | grep -c '@failopen')"

# ---- стартовое применение демона не прошло: повтор, а не тишина до ручного reload ----
# После перезагрузки прежнего набора правил нет: отказ стартового применения оставлял роутер без
# маршрутизации. Демон повторяет его с растущей паузой (здесь первая — 1 с, шов стенда).
"$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1
: > "$tmp/reject"
STEER_BOOT_RETRY_MS=1000 "$BIN" daemon --apply --socket "$tmp/steer.sock" $S >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
i=0; while [ $i -lt 100 ] && ! grep -q 'применение при старте не прошло' "$tmp/d.err"; do sleep 0.1; i=$((i + 1)); done
check "демон: стартовое применение отвергнуто — сказано, и назначен повтор" "1 1" \
    "$(grep -c 'применение при старте не прошло' "$tmp/d.err") $(grep -c 'стартовое применение: попытка 2 через 1 с' "$tmp/d.err")"
check "  таблицы в ядре нет" "1" "$(nft list table inet steer >/dev/null 2>&1; echo $?)"
rm -f "$tmp/reject"
i=0; while [ $i -lt 100 ] && ! grep -q 'спека применена при старте' "$tmp/d.err"; do sleep 0.1; i=$((i + 1)); done
check "  причина ушла — повтор применил спеку сам" "1" "$(grep -c 'спека применена при старте — с попытки 2' "$tmp/d.err")"
check "  набор правил в ядре" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"
sleep 2
check "  после удачи повторов больше нет" "1" "$(grep -c 'стартовое применение: попытка' "$tmp/d.err")"
kill "$D" 2>/dev/null; wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1

# То же глазами сторожа: до повтора далеко (пауза 10 минут), а проход видит «движок включён, спека
# есть, правила выходов стоят, набора правил нет» — и чинит сам, как снятую мимо него таблицу.
ip link add applynft0 type dummy 2>/dev/null && ip link set applynft0 up && ip addr add 10.77.7.1/24 dev applynft0
: > "$tmp/reject"
STEER_BOOT_RETRY_MS=600000 "$BIN" daemon --apply --watch --watch-period 2 --socket "$tmp/steer.sock" $S \
    >"$tmp/d.out" 2>"$tmp/d2.err" &
D=$!
i=0; while [ $i -lt 100 ] && ! grep -q 'применение при старте не прошло' "$tmp/d2.err"; do sleep 0.1; i=$((i + 1)); done
check "демон со сторожем: стартовое применение отвергнуто, правила выхода стоят" "1 1" \
    "$(grep -c 'применение при старте не прошло' "$tmp/d2.err") $(ip rule show | grep -c 'fwmark 0x100000/')"
rm -f "$tmp/reject"
i=0; while [ $i -lt 150 ] && ! nft list table inet steer >/dev/null 2>&1; do sleep 0.1; i=$((i + 1)); done
check "  проход сторожа счёл это расхождением" "yes" \
    "$(grep -q 'а набора правил в ядре Linux нет' "$tmp/d2.err" && echo yes || echo no)"
check "  и поставил набор правил" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"
kill "$D" 2>/dev/null; wait "$D" 2>/dev/null
"$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1
rm -f "$(dirname "$kept")"/steer-ruleset.rejected

printf '\napplynft: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
