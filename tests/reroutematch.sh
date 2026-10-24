#!/bin/sh
# Смена выхода правила снимает соединения прежнего выхода (docs/ctl.md, «apply»).
#
# Живой роутер, 2026-10-03: правило перевели с vpn2 на группу balance [vpn, vpn2], apply прошёл,
# а через 25 минут 29 установленных соединений правила всё ещё шли через vpn2 — липкость balance
# (`ct mark … == метка члена goto` в цепочке группы) держала их на прежнем выходе, новые уходили
# по раздаче, и один сеанс сайта шёл с разных внешних адресов. Здесь — то же в своём сетевом
# пространстве: демон (ctl-serve) с настоящим nft, выходы — dummy-устройства, записи conntrack —
# свой исходящий UDP, метку им ставит своя таблица (как в tests/ctlmatch.sh), а смотрим их
# командой conns того же демона.
#
# Нужны root, unshare, nft и python3; без них стенд пропускается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
if [ "${REROUTE_INNER:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ] && command -v nft >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 &&
       unshare -n true 2>/dev/null; then
        REROUTE_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
    fi
    echo "reroutematch: нет root, nft, python3 или своих пространств имён — пропущен"
    exit 0
fi
ip link set lo up
ip link add r1 type dummy && ip link add r2 type dummy && ip link set r1 up && ip link set r2 up ||
    { echo "reroutematch: dummy-устройств нет — пропущен"; exit 0; }
# Маршруты к назначениям стенда — чтобы исходящий UDP было куда отправить (и завелась запись).
ip route add 10.0.0.0/8 dev r1

tmp="$(mktemp -d)"
mkdir -p "$tmp/state"
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$tmp"' EXIT
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
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

echo '10.1.2.0/24' > "$tmp/p.lst"
echo '10.9.0.0/24' > "$tmp/q.lst"
echo '10.5.0.0/24' > "$tmp/r.lst"
# spec ФАЙЛ ВЫХОД_P ВЫХОД_Q [ВЫХОД_R] — правила p, q (и r) на свои списки.
spec() {
    r=""
    [ -n "${4:-}" ] && r=',{"name":"r","to":["r"],"out":"'"$4"'"}'
    cat > "$tmp/$1" <<EOF
{"version":2,
 "outputs":{"direct":{"kind":"direct"},
            "vpn":{"kind":"interface","device":"r1"},
            "vpn2":{"kind":"interface","device":"r2"},
            "all":{"kind":"group","pick":"balance","members":["vpn","vpn2"]}},
 "lists":{"p":{"prefixes_file":["$tmp/p.lst"]},"q":{"prefixes_file":["$tmp/q.lst"]},
          "r":{"prefixes_file":["$tmp/r.lst"]}},
 "rules":[{"name":"p","to":["p"],"out":"$2"},{"name":"q","to":["q"],"out":"$3"}$r]}
EOF
}
apply() {
    r="$(ctl apply < "$tmp/$1")"
    printf '%s' "$r" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("code")==0 and d.get("applied") else 1)' ||
        { echo "reroutematch: apply $1 не прошёл: $r"; exit 1; }
}
mark() { awk -v n="$1" '$1 == n { print $2 }' "$tmp/state/registry"; }
# ct ПОРТ АДРЕС ВЫХОД — одна запись conntrack: UDP на адрес и порт с меткой выхода.
ct() {
    nft add rule inet rr o udp dport "$1" ct mark set "0x$(mark "$3")"
    python3 -c 'import socket,sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", (sys.argv[1], int(sys.argv[2])))' "$2" "$1"
}
# alive — порты записей стенда (41000..41100), что сейчас есть, по возрастанию, с выходом.
alive() {
    ctl conns | python3 -c '
import json, sys
d = json.loads(json.load(sys.stdin)["stdout"])
print(" ".join("%d:%s" % (c["dport"], c["out"]) for c in sorted(d["conns"], key=lambda c: c.get("dport", 0))
               if 41000 <= c.get("dport", 0) <= 41100))'
}

spec S1.json vpn2 vpn
cp "$tmp/S1.json" "$tmp/spec.json"
STEER_CTL_ENABLED=1 "$BIN" ctl-serve --socket "$tmp/s.sock" --spec "$tmp/spec.json" \
    --state-dir "$tmp/state" --lists-dir "$tmp/lists" 2>>"$tmp/serve.err" &
SRV=$!
wait_for '[ -S "$tmp/s.sock" ]' 5 || { echo "reroutematch: сервер не поднялся"; cat "$tmp/serve.err"; exit 1; }
apply S1.json
nft add table inet rr
nft add chain inet rr o '{ type filter hook output priority 0; }'

# ---- 1. правило перевели на balance, где прежний выход — член (случай роутера) -------------------
ct 41001 10.1.2.3 vpn2
ct 41002 10.9.0.5 vpn
ct 41003 10.1.2.4 vpn2
check "до apply: три записи" "41001:vpn2 41002:vpn 41003:vpn2" "$(alive)"
spec S2.json all vpn
apply S2.json
check "p: vpn2 → all — записи vpn2 сняты, у q (vpn) — остались" "41002:vpn" "$(alive)"
check "  в журнале демона — строка о снятии" "1" \
    "$(grep -c 'смена выхода правил (p → all): снято соединений метки 0x.* — 2 (целиком)' "$tmp/serve.err")"

# ---- 2. прежний выход держит и другое правило: снимаются только чужие его наборам -----------------
spec S3.json vpn vpn
apply S3.json
nft flush chain inet rr o
ct 41011 10.1.2.3 vpn
ct 41012 10.9.0.5 vpn
ct 41013 10.7.7.7 vpn
check "p и q на vpn: записи vpn" "41002:vpn 41011:vpn 41012:vpn 41013:vpn" "$(alive)"
spec S4.json vpn2 vpn
apply S4.json
check "p: vpn → vpn2, q остался на vpn — сняты записи вне наборов q" "41002:vpn 41012:vpn" "$(alive)"
check "  в журнале — снятие по наборам" "1" \
    "$(grep -c 'смена выхода правил (p → vpn2): снято соединений метки 0x.* — 2 (по наборам)' "$tmp/serve.err")"

# ---- 3. выход правил не менялся — ничего не снимается -------------------------------------------
nft flush chain inet rr o
ct 41021 10.1.2.3 vpn2
spec S5.json vpn2 vpn vpn
apply S5.json
check "добавили правило r, у p и q выход прежний — записи на месте" "41002:vpn 41012:vpn 41021:vpn2" "$(alive)"

# ---- 4. правило сняли: его выход больше никто не держит — снимается целиком ----------------------
spec S6.json vpn vpn vpn
sed -i 's/{"name":"p","to":\["p"\],"out":"vpn"},//' "$tmp/S6.json"
apply S6.json
check "правило p снято — записи vpn2 сняты" "41002:vpn 41012:vpn" "$(alive)"

printf '\nreroutematch: %d ok, %d fail\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
