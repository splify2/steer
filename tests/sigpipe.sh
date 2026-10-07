#!/bin/sh
# Модуль туннеля переживает закрытие соединений узлом на скорости: запись в закрытый сокет узла — отказ
# записи, а не смерть процесса от SIGPIPE.
#
# ЧТО НАШЛИ. Сравнительный замер (iperf3 -P 8 вверх через steer-vless против Xray) убивал модуль в большинстве
# запусков (три из пяти на релизном пакете): узел закрывает соединение, пока стек ещё дописывает в него пакеты
# клиента, запись TLS (tls13_write — write() без MSG_NOSIGNAL) получает EPIPE, а у модуля SIGPIPE по
# умолчанию — демон возвращает его детям нарочно (loop_child_reset). Демон писал «vless tun вышел (сигнал 13) —
# перезапуск через 5 с» (дальше 10 и 20: пауза удваивается), и всё это время туннель стоял. Правка — в
# cli/modcmd.c: у модульных команд SIGPIPE выключен, запись возвращает EPIPE, стек закрывает ТО соединение
# RST'ом клиенту.
#
# ЧТО ПРОВЕРЯЕТ СТЕНД. Настоящий демон (`steerd daemon --watch --supervise --apply`) поднимает два выхода
# vless — по TLS 1.3 и без шифрования, потому что запись идёт разными путями: TLS — tls13_write (защищённый
# файл, спасает только выключенный SIGPIPE), без шифрования — tr_link_write (там ещё и MSG_NOSIGNAL). За
# каждым — поддельный узел (tests/sigpipe-node.py), который закрывает соединения так, как закрывает
# занятый сервер: FIN, а следом RST. Клиент локальной сети (tests/sigpipe-client.py) 12 с гонит через оба
# туннеля десятки соединений: выгрузку, которую узел обрывает рано, выгрузку и скачивание, которые
# обрывает сам клиент — RST посреди передачи. После этого:
#   * у каждого модуля тот же pid, и он жив; в журнале демона нет «вышел» (и «сигнал 13» тоже);
#   * у модулей и у резолвера SIGPIPE выключен (SigIgn в /proc/<pid>/status);
#   * туннель сразу отвечает (эхо строки), а не через 5–20 с перезапуска;
#   * дескрипторов у модуля после затишья не больше, чем было до нагрузки (закрытие по EPIPE ничего
#     не оставляет открытым);
#   * нагрузка была настоящей: узел закрыл рано десятки соединений.
# До правки стенд падает на первой же проверке pid (модуль убит и перезапущен).
#
# Нагрузка на выход без шифрования легче (4+2+2 рабочих против 12+6+6): наблюдалось, что у него главный
# поток модуля подолгу стоит в read() на пустом соединении с узлом (SO_RCVTIMEO — восемь секунд),
# и числа скорости в этом стенде ни о чём не говорят — проверяется только, что модуль жив.
#
# Нужны root, unshare -nm, ip, nft, nsenter, pgrep, ss, openssl и python3 с ssl — иначе пропуск, а не
# падение. LIBS — раскладка libs (tests/libs-test.sh, build/libs-host). SIGPIPE_SECS — срок нагрузки, с (12).
set -u
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)"
skip() { echo "sigpipe: $1 — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] && [ -x "$LIBS/steer-vless" ] || skip "нет раскладки libs ($LIBS, tests/libs-test.sh)"
BIN="$LIBS/steerd"
HERE="$(cd "$(dirname "$0")" && pwd)"
LD_LIBRARY_PATH="$LIBS"; export LD_LIBRARY_PATH
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
for t in nft ip python3 nsenter unshare openssl pgrep awk ss; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
python3 -c 'import ssl' 2>/dev/null || skip "у python3 нет ssl"
if [ "${SIGPIPE_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    SIGPIPE_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "свой /sys не смонтировать"
ip link set lo up
nft add table inet sigpipe_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet sigpipe_probe
# Состояние демона и реестр таблиц — в памяти этого стенда, а не в файлах машины.
for d in /etc/steer /var/lib/steer /etc/iproute2/rt_tables.d; do
    [ -d "$d" ] && mount -t tmpfs tmpfs "$d" 2>/dev/null
done
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

SECS="${SIGPIPE_SECS:-12}"
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
D="" CPID="" NT="" NP=""
cleanup() {
    kill $NT $NP $CPID 2>/dev/null
    [ -n "$D" ] && { kill "$D" 2>/dev/null; wait_for '! kill -0 $D 2>/dev/null' 15; }
    if [ "$fail" != 0 ]; then
        echo "--- журнал демона (хвост)"; tail -n 30 "$tmp/d.err" 2>/dev/null
        echo "--- узел TLS"; tail -n 3 "$tmp/node-tls.err" 2>/dev/null
        echo "--- узел без шифрования"; tail -n 3 "$tmp/node-none.err" 2>/dev/null
    fi
    if [ "${SIGPIPE_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть: роутер (это пространство), клиент за veth, узлы на dummy роутера --------------------------
unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.77.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.77.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.77.1.1
# Адрес узла — на dummy: ядро steer отвергает узел на петле 127.0.0.0/8 как «отвечать некому», а наружу
# этот адрес не виден (то же, что у tests/run-tunnel.sh).
ip link add node0 type dummy
ip addr add 10.77.0.1/32 dev node0
ip link set node0 up
# Цели клиента: TLS-выход — .7, выход без шифрования — .8; адреса — из префикса списка правила.
printf '203.0.113.0/24\n' > "$tmp/p.lst"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -subj "/CN=node.test" >/dev/null 2>&1
python3 "$HERE/sigpipe-node.py" --bind 10.77.0.1 --port 10443 --uuid "$UUID" --tls "$tmp/cert.pem" "$tmp/key.pem" \
    >"$tmp/node-tls.out" 2>"$tmp/node-tls.err" & NT=$!
python3 "$HERE/sigpipe-node.py" --bind 10.77.0.1 --port 10444 --uuid "$UUID" \
    >"$tmp/node-none.out" 2>"$tmp/node-none.err" & NP=$!
wait_for 'grep -q ready "$tmp/node-tls.out" && grep -q ready "$tmp/node-none.out"' 10

printf 'vless://%s@10.77.0.1:10443?encryption=none&type=tcp&security=tls&sni=node.test&allowInsecure=1#tls\n' "$UUID" > "$tmp/sub-tls"
printf 'vless://%s@10.77.0.1:10444?encryption=none&type=tcp&security=none#none\n' "$UUID" > "$tmp/sub-none"
printf '203.0.113.7/32\n' > "$tmp/p-tls.lst"
printf '203.0.113.8/32\n' > "$tmp/p-none.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [p0] }
lists:
  lt: { prefixes_file: $tmp/p-tls.lst }
  ln: { prefixes_file: $tmp/p-none.lst }
outputs:
  vlt: { kind: tunnel, protocol: vless, subscription: $tmp/sub-tls, insecure: true, on_fail: drop }
  vln: { kind: tunnel, protocol: vless, subscription: $tmp/sub-none, on_fail: drop }
rules:
  - { name: rt, to: [lt], out: vlt }
  - { name: rn, to: [ln], out: vln }
EOF
"$BIN" daemon --watch --supervise --apply --socket "$tmp/steer.sock" --spec "$tmp/spec.yaml" --state-dir "$tmp/st" \
    >"$tmp/d.out" 2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/steer.sock" ]' 20

TLS=203.0.113.7 NONE=203.0.113.8
ping_tunnel() { C python3 "$HERE/sigpipe-client.py" "$1" --ping >"$tmp/ping.$1" 2>&1; }
ping_tunnel $TLS; check "туннель TLS отвечает до нагрузки" "0" "$?"
ping_tunnel $NONE; check "туннель без шифрования отвечает до нагрузки" "0" "$?"

# Модули — дети демона по имени бинарника; резолвер — тоже ребёнок, `steerd dnsd`.
kids() { pgrep -P "$D" -x "$1" | sort -n | tr '\n' ' ' | sed 's/ $//'; }
mods="$(kids steer-vless)"
check "демон поднял два модуля vless" "2" "$(printf '%s\n' $mods | wc -l)"
set -- $mods; M1="$1"; M2="${2:-0}"
dnsd="$(pgrep -P "$D" -x steerd | head -n 1)"
fds() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
# SIGPIPE — сигнал 13, бит 12 маски SigIgn (0x1000).
pipe_ignored() { m="$(awk '/^SigIgn:/ { print $2 }' "/proc/$1/status" 2>/dev/null)"; [ -n "$m" ] && echo $(( (0x$m >> 12) & 1 )) || echo "?"; }
check "у модулей vless SIGPIPE выключен" "1 1" "$(pipe_ignored $M1) $(pipe_ignored $M2)"
check "  и у резолвера" "1" "$(pipe_ignored "${dnsd:-0}")"
f1="$(fds $M1)"; f2="$(fds $M2)"
err0="$(wc -l < "$tmp/d.err")"

# ---- нагрузка ------------------------------------------------------------------------------------
C python3 "$HERE/sigpipe-client.py" $TLS --storm "$SECS" >"$tmp/cl-tls.out" 2>&1 & P1=$!
C python3 "$HERE/sigpipe-client.py" $NONE --storm "$SECS" --up 4 --abort-up 2 --abort-down 2 >"$tmp/cl-none.out" 2>&1 & P2=$!
wait $P1 $P2
echo "  $(cat "$tmp/cl-tls.out")"
echo "  $(cat "$tmp/cl-none.out")"
echo "  узел TLS:  $(grep '^узел:' "$tmp/node-tls.err" | tail -n 1)"
echo "  узел none: $(grep '^узел:' "$tmp/node-none.err" | tail -n 1)"

now="$(kids steer-vless)"
check "после нагрузки у демона те же модули: pid не менялись" "$mods" "$now"
check "  и оба живы" "1 1" "$(kill -0 $M1 2>/dev/null && echo 1 || echo 0) $(kill -0 $M2 2>/dev/null && echo 1 || echo 0)"
check "в журнале демона нет «вышел» (и «сигнал 13»)" "0" \
    "$(tail -n +$((err0 + 1)) "$tmp/d.err" | grep -c 'вышел\|сигнал 13\|перезапуск через')"
ping_tunnel $TLS; check "туннель TLS отвечает сразу после нагрузки" "0" "$?"
ping_tunnel $NONE; check "туннель без шифрования отвечает сразу после нагрузки" "0" "$?"
early() { grep '^узел:' "$1" | tail -n 1 | grep -o 'рано закрыто=[0-9]*' | sed 's/.*=//'; }
e1="$(early "$tmp/node-tls.err")"; e2="$(early "$tmp/node-none.err")"
check "нагрузка дошла до узла TLS: рано закрыто не меньше 20 соединений" "1" "$([ "${e1:-0}" -ge 20 ] && echo 1 || echo 0)"
check "  и до узла без шифрования — не меньше 10" "1" "$([ "${e2:-0}" -ge 10 ] && echo 1 || echo 0)"
# Порт 81 говорит первым: клиент ничего не шлёт, и узел узнаёт назначение только из заголовка,
# который стек отправляет сам через SERVER_FIRST_MS. Без него каждое скачивание получало ноль байт.
bin_() { grep -o 'байт принято=[0-9]*' "$1" | sed 's/.*=//'; }
b1="$(bin_ "$tmp/cl-tls.out")"; b2="$(bin_ "$tmp/cl-none.out")"
check "скачивания с сервера, говорящего первым, получили данные (TLS, без шифрования)" "1 1" \
    "$([ "${b1:-0}" -gt 0 ] && echo 1 || echo 0) $([ "${b2:-0}" -gt 0 ] && echo 1 || echo 0)"
check "ни одна выгрузка не застряла на записи (тайм-аут сокета 10 с)" "0" \
    "$(cat "$tmp/cl-tls.out" "$tmp/cl-none.out" | grep -o 'up:застряло=[0-9]*' | sed 's/.*=//' | awk '{ n += $1 } END { print n + 0 }')"

# Затишье: стек освобождает закрытые соединения за витки цикла, а закрытое узлом, но не подтверждённое
# клиентом — через CLOSE_DRAIN_MS (5 с); запас — несколько запасных связей пула и сокет проверки узла.
sleep 7
g1="$(fds $M1)"; g2="$(fds $M2)"
check "дескрипторов у модулей не больше, чем до нагрузки (+8: запасные связи пула)" "1 1" \
    "$([ "$g1" -le $((f1 + 8)) ] && echo 1 || echo 0) $([ "$g2" -le $((f2 + 8)) ] && echo 1 || echo 0)"
echo "  дескрипторов у модулей: TLS $f1 -> $g1, без шифрования $f2 -> $g2"
# Сокеты к узлам, закрытые узлом, а нашей стороной нет (CLOSE-WAIT), — след соединения, закрытого по
# EPIPE не до конца.
check "закрытых узлом и не закрытых модулем сокетов (CLOSE-WAIT) нет" "0" \
    "$(ss -tnp state close-wait 2>/dev/null | grep -c "pid=$M1,\|pid=$M2,")"

echo "sigpipe: $pass ok, $fail fail"
[ "$fail" = 0 ]
