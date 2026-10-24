#!/bin/sh
# Линия клиента с задержкой и потерями: выгрузка через туннель не упирается в «окно на круг» (R-152).
#
# ЧТО БЫЛО. Свой TCP-стек туннеля держал у клиента не больше 64 КБ в пути (сначала окно 65535 без масштаба,
# потом кольцо повтора RTX_CAP), а скорость соединения — это окно, делённое на круг: при круге 6 мс выгрузка
# одним потоком шла 83 Мбит/с, в настоящей сети с Wi-Fi (круг 2-5 мс) — 100-250 Мбит/с, сколько бы ни давали
# узел и процессор; с потерей 0,5 % — десятки Мбит/с (SACK не было, повтор по таймеру). Замер в хабе
# (STEER_REBUILD.md, «Ход R-152»): на линии «2 мс + 0,5 %» скачивание через TUN — 49 Мбит/с, через слушатель — 5092.
#
# ЧТО ПРОВЕРЯЕТ СТЕНД. TCP клиента завершает ядро: правило nat перенаправляет его к слушателю модуля (здесь
# правило ставит стенд по адресу цели, на роутере — демон по метке выхода). Модуль steer-vless (прямой запуск,
# без демона) принимает выгрузку настоящего клиента ядра; между клиентом и роутером — netem в обе стороны
# (круг 6 мс), узел — приёмник без шифрования (tests/sigpipe-node.py, порт 82). Прогоны:
#   * линия с задержкой — клиент видит у роутера масштаб окна (wscale:<наш>,<его>) и окно выше 64 КБ, и
#     выгрузка быстрее потолка «64 КБ на круг» больше чем втрое;
#   * задержка и потеря 0,5 % — выгрузка всё равно быстрее этого потолка больше чем втрое;
#   * клиент без опции масштаба (net.ipv4.tcp_window_scaling=0) — выгрузка идёт и не рвётся.
#
# Нужны root, unshare -nm, ip, tc (netem), ss, nsenter и python3 — иначе пропуск, а не падение.
# LIBS — раскладка libs (tests/libs-test.sh, build/libs-host).
set -u
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)"
skip() { echo "rcvwnd: $1 — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] && [ -x "$LIBS/steer-vless" ] || skip "нет раскладки libs ($LIBS, tests/libs-test.sh)"
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
    # Приговор по фактическому состоянию, а не по счётчику кругов: условие, ставшее истинным в последнюю
    # десятую секунды, иначе объявлялось бы невыполненным.
    eval "$1" && return 0
    return 1
}
for t in ip tc ss python3 nsenter unshare awk; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${RCVWND_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    RCVWND_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "свой /sys не смонтировать"
ip link set lo up
ip link add nemprobe type dummy 2>/dev/null && tc qdisc add dev nemprobe root netem delay 1ms 2>/dev/null \
    || skip "netem недоступен (sch_netem)"
ip link del nemprobe
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
TARGET=203.0.113.7
SECS="${RCVWND_SECS:-4}"
DELAY="${RCVWND_DELAY:-3}"       # мс в каждую сторону: круг вдвое больше
tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
CPID="" NP="" MP="" CL=""
cleanup() {
    kill $CL $MP $NP $CPID 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- журнал модуля (хвост)"; tail -n 12 "$tmp/mod.log" 2>/dev/null
    fi
    if [ "${RCVWND_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть: роутер (это пространство), клиент за veth, узел на dummy роутера ---------------------------
unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.78.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.78.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.78.1.1
ip link add node0 type dummy
ip addr add 10.78.0.1/32 dev node0
ip link set node0 up
# Круг в LAN: задержка в каждую сторону (исходящее клиента и исходящее роутера клиенту). limit — с запасом:
# netem держит в очереди всё, что «в полёте» по задержке, и со штатным 1000 пакетов терял бы сам.
C tc qdisc add dev c0 root netem delay "${DELAY}ms" limit 100000
tc qdisc add dev p0 root netem delay "${DELAY}ms" limit 100000

python3 "$HERE/sigpipe-node.py" --bind 10.78.0.1 --port 10444 --uuid "$UUID" >"$tmp/node.out" 2>"$tmp/node.err" & NP=$!
wait_for 'grep -q ready "$tmp/node.out"' 10
printf 'vless://%s@10.78.0.1:10444?security=none&type=tcp#node\n' "$UUID" > "$tmp/sub.txt"
cat > "$tmp/spec.json" <<EOF
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$tmp/sub.txt","node":0}},
 "channels":[]}
EOF

# Клиент: выгрузка на порт 82 узла (приёмник, который не закрывается) SECS секунд; соединение держится
# открытым, пока стенд не снимет ss.
cat > "$tmp/up.py" <<'PY'
import socket, sys, time
target, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket()
s.settimeout(10)
s.connect((target, 82))
blob = b"\xa5" * (1 << 20)
end = time.time() + secs
try:
    while time.time() < end:
        s.send(blob)
except OSError as e:
    print("клиент: запись оборвалась:", e, flush=True)
print("клиент: послал", flush=True)
time.sleep(30)
PY

# Один прогон: модуль (env — «К=З» или пусто), выгрузка, ss клиента в середине и в конце. Печатает в $tmp/run.*
run() {
    name="$1"; shift
    env "$@" "$LIBS/steerd" vless vl --spec "$tmp/spec.json" --state-dir "$tmp/st" >"$tmp/mod.log" 2>&1 &
    MP=$!
    wait_for 'ip link show vl >/dev/null 2>&1' 20
    wait_for 'grep -q "запасных сессий" "$tmp/mod.log"' 20
    ip route replace "$TARGET/32" dev vl
    # TCP клиента — к слушателю модуля (порт 9480: единственный выход стенда, место 0).
    nft list table inet rcvwnd_redir >/dev/null 2>&1 || nft -f - <<NFT
table inet rcvwnd_redir {
    chain pre { type nat hook prerouting priority -101; policy accept;
        ip daddr $TARGET ip protocol tcp counter redirect to :9480; }
}
NFT
    # nsenter напрямую, а не функцией C: у функции $! — подоболочка, и kill её не убил бы сам python.
    nsenter -t "$CPID" -n python3 "$tmp/up.py" "$TARGET" "$SECS" >"$tmp/cl.$name" 2>&1 & CL=$!
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.mid.$name" 2>&1
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 + 0.5 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.end.$name" 2>&1
    kill $CL 2>/dev/null; wait $CL 2>/dev/null; CL=""
    kill $MP 2>/dev/null; wait $MP 2>/dev/null; MP=""
    ip link del vl 2>/dev/null
    sleep 1
}
# Поле ss: tok<имя>:<значение> из строки с данными соединения.
field() { tr ' ' '\n' < "$1" | sed -n "s/^$2://p" | head -n 1; }
# Мбит/с по bytes_acked клиента за срок выгрузки.
mbit() { awk -v b="$(field "$1" bytes_acked)" -v s="$SECS" 'BEGIN { printf "%d", b * 8 / s / 1e6 }'; }
# Потолок «окно 64 КБ на круг» в Мбит/с: 65535 байт на (круг + то, что стоит сам модуль — берём один пакет).
CEIL="$(awk -v d="$DELAY" 'BEGIN { printf "%d", 65535 * 8 / (2 * d / 1000) / 1e6 }')"

run scaled STEER_X=1
C tc qdisc change dev c0 root netem delay "${DELAY}ms" loss 0.5% limit 100000
tc qdisc change dev p0 root netem delay "${DELAY}ms" loss 0.5% limit 100000
run lossy STEER_X=1
C tc qdisc change dev c0 root netem delay "${DELAY}ms" limit 100000
tc qdisc change dev p0 root netem delay "${DELAY}ms" limit 100000
C sysctl -qw net.ipv4.tcp_window_scaling=0
run nows STEER_X=1
C sysctl -qw net.ipv4.tcp_window_scaling=1

echo "  круг ${DELAY}x2 мс; потолок «64 КБ на круг» — $CEIL Мбит/с"
for v in scaled lossy nows; do
    echo "  $v: $(mbit "$tmp/ss.end.$v") Мбит/с, snd_wnd $(field "$tmp/ss.mid.$v" snd_wnd), wscale $(field "$tmp/ss.mid.$v" wscale), rtt $(field "$tmp/ss.mid.$v" rtt)"
done

check "через слушатель: перенаправление сработало (счётчик правила)" "1" \
    "$([ "$(nft list table inet rcvwnd_redir | grep -o 'packets [0-9]*' | grep -o '[0-9]*')" -ge 3 ] 2>/dev/null && echo 1 || echo 0)"
# Масштаб — по ss клиента: wscale:<масштаб роутера>,<его собственный>.
check "клиент видит масштаб окна роутера (wscale:N,... с N > 0)" "1" \
    "$([ "$(field "$tmp/ss.mid.scaled" wscale | cut -d, -f1)" -gt 0 ] 2>/dev/null && echo 1 || echo 0)"
check "  и окно выше 64 КБ (snd_wnd)" "1" "$([ "$(field "$tmp/ss.mid.scaled" snd_wnd)" -gt 65535 ] 2>/dev/null && echo 1 || echo 0)"
check "  и выгрузка быстрее потолка «64 КБ на круг» больше чем втрое" "1" \
    "$([ "$(mbit "$tmp/ss.end.scaled")" -gt $((CEIL * 3)) ] && echo 1 || echo 0)"
check "потеря 0,5 %: выгрузка быстрее того же потолка больше чем втрое" "1" \
    "$([ "$(mbit "$tmp/ss.end.lossy")" -gt $((CEIL * 3)) ] && echo 1 || echo 0)"
check "клиент без масштаба окна: выгрузка идёт, масштаба нет" "1" \
    "$([ "$(mbit "$tmp/ss.end.nows")" -gt 10 ] && [ -z "$(field "$tmp/ss.mid.nows" wscale)" ] && echo 1 || echo 0)"

echo "rcvwnd: $pass ok, $fail fail"
