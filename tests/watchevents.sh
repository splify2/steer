#!/bin/sh
# События сети за время прохода сторожа демона (src/daemon/watchd.c, «СОБЫТИЯ ВО ВРЕМЯ ПРОХОДА»).
#
# Что было. На роутере (netifd) всё, что приходило по сокету событий за время прохода, считалось
# следом его же ifdown/ifup и выбрасывалось. Проход с оживлением идёт до ≈70 с, и настоящее событие
# за это время — вернулся WAN, поднялось устройство другого выхода — оставалось незамеченным:
# выход, которому проход только что поставил on_fail, лежал до следующего периода. Теперь
# выбрасываются только события об устройствах, которые проход сам оживляет (fo_pass_on_revive), а
# чужое зовёт ещё один проход через WATCH_SETTLE_S после этого.
#
# Сеть: наше пространство (демон `steerd daemon --watch`, период 120 с) и ответчик (1.1.1.1 и
# 8.8.8.8) за парами veth va (выход a) и vb (выход b). ifdown/ifup — подменные: ifup устройства va
# спит 8 с, так что проход с оживлением a длится ≈18 с (ifup и десять шагов ожидания подъёма).
#
# Проверяется.
#  1. Первый проход: устройства vb нет — b в отказе (запрет в его таблице), a на va.
#  2. va пропало — проход оживляет a (долго). Пока он идёт, появляется vb: b возвращается на vb
#     вскоре после прохода (через WATCH_SETTLE_S), а не через период. Прежде — только через период.
# Нужны root, unshare -n, nsenter, ip и nft.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    eval "$1" && return 0
    return 1
}
skip() { echo "watchevents: $1 — пропуск"; exit 0; }
for t in nft ip nsenter unshare; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${WATCHEV_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    WATCHEV_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ip link set lo up
nft add table inet watchev_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet watchev_probe
unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null || skip "свой /sys не смонтировать"

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/bin"
D="" RPID=""
cleanup() {
    kill $RPID 2>/dev/null
    [ -n "$D" ] && kill "$D" 2>/dev/null
    [ "$fail" != 0 ] && [ -f "$tmp/d.err" ] && { echo "--- журнал демона (хвост)"; tail -n 40 "$tmp/d.err"; }
    if [ "${WATCHEV_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

unshare -n sleep 600 & RPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
R ip link set lo up
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo
# pair N ИМЯ — пара veth к ответчику: ИМЯ у нас (10.9.N.1), ИМЯp у ответчика (10.9.N.2).
pair() {
    ip link add "$2" type veth peer name "$2p"
    ip link set "$2p" netns "$RPID"
    R ip link set "$2p" up; R ip addr add "10.9.$1.2/24" dev "$2p"
    ip link set "$2" addrgenmode none 2>/dev/null
    ip link set "$2" up; ip addr add "10.9.$1.1/24" dev "$2"
}
pair 1 va
ip link add lanx type dummy; ip link set lanx up; ip addr add 192.168.7.1/24 dev lanx
ip link add wan0 type dummy; ip link set wan0 up; ip addr add 203.0.113.1/24 dev wan0
ip route add default via 203.0.113.254 dev wan0
# Подменные ifdown/ifup: каждая попытка — строка в журнал стенда; ifup va спит 8 с.
cat > "$tmp/bin/ifdown" <<EOF
#!/bin/sh
echo "ifdown \$*" >> "$tmp/if.log"
exit 0
EOF
cat > "$tmp/bin/ifup" <<EOF
#!/bin/sh
echo "ifup \$*" >> "$tmp/if.log"
case " \$* " in *" va "*) sleep 8 ;; esac
exit 0
EOF
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
: > "$tmp/if.log"
PATH="$tmp/bin:$PATH"
export PATH

printf '10.6.0.0/24\n' > "$tmp/la.lst"
printf '10.7.0.0/24\n' > "$tmp/lb.lst"
# b — раньше a: проход судит b до того, как возьмётся оживлять a, и появление vb приходится на
# оживление a, а не на пробу b.
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lanx] }
lists:
  la: { prefixes_file: $tmp/la.lst }
  lb: { prefixes_file: $tmp/lb.lst }
outputs:
  b: { kind: interface, device: vb }
  a: { kind: interface, device: va }
rules:
  - { name: rb, to: [lb], out: b }
  - { name: ra, to: [la], out: a }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
STEER_SOCKET="$tmp/steer.sock"
export STEER_SOCKET
unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" daemon --watch --watch-period 120 \
    --apply --socket \"$tmp/steer.sock\" $S" >>"$tmp/d.out" 2>>"$tmp/d.err" &
D=$!
reg() { awk -v o="$1" '$1 == o { print $'"$2"' }' "$tmp/st/registry"; }
tdev() { ip route show table "$(reg "$1" 3)" 2>/dev/null | awk '$1 == "default" && $2 == "dev" { print $3 }' | head -n 1; }
tbh() { ip route show table "$(reg "$1" 3)" 2>/dev/null | grep -c '^blackhole default *$'; }
ifups() { grep -c "^ifup .*$1" "$tmp/if.log"; }

# 1. Первый проход: b без устройства (оживление vb — один раз, дальше его не пустит
#    RESTART_COOLDOWN), a на va.
wait_for '[ -f "$tmp/st/registry" ] && [ "$(tbh b)" = 1 ] && [ "$(tdev a)" = va ]' 40
check "первый проход: b в отказе, a на va" "1 va" "$(tbh b) $(tdev a)"
wait_for '[ "$(ifups vb)" -ge 1 ]' 5
sleep 12       # первый проход ждёт подъёма vb десять шагов — дать ему кончиться

# 2. va пропало: проход оживляет a (ifup va спит 8 с). В его середине появляется vb.
ip link del va
wait_for '[ "$(ifups va)" -ge 1 ]' 20
check "va пропало — проход взялся оживлять a" "1" "$(ifups va)"
sleep 2
t0=$(date +%s)
pair 2 vb
wait_for '[ "$(tdev b)" = vb ]' 45
t1=$(date +%s)
check "vb появилось во время прохода — b вернулся, не дожидаясь периода (120 с)" "vb" "$(tdev b)"
check "  b вернулся быстрее 40 с после появления vb" "1" "$([ $((t1 - t0)) -lt 40 ] && echo 1 || echo 0)"

kill "$D" 2>/dev/null; wait "$D" 2>/dev/null; D=""
echo "watchevents: $pass passed, $fail failed"
[ "$fail" = 0 ]
