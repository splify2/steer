#!/bin/sh
# Сквозные проверки клиента против НАСТОЯЩЕГО Xray-core: VLESS encryption и постквантовая часть.
#
#   1. VLESS encryption (mlkem768x25519plus): режимы native / xorpub / random × ключ X25519 / ML-KEM ×
#      1rtt / 0rtt. Три соединения в одном процессе (со второго — по билету 0-RTT, это видно по трассе) и
#      4 МБ данных туда и обратно через эхо-сервер: записи случайной длины, сверка побайтно.
#   2. Несколько реле цепочкой (X25519 → ML-KEM → X25519) и своя набивка (padding из строки).
#   3. REALITY: клиент предлагает гибрид X25519MLKEM768, сервер Xray выбирает его; с mldsa65Seed на
#      сервере и pqv у узла клиент проверяет подпись ML-DSA-65, с чужим pqv — отказывает. Нужен маскировочный
#      сайт с большим сертификатом (VENC_DEST, умолчание www.apple.com: у www.microsoft.com цепочка на 8 КБ, и Xray 26.3.27 рвёт с ней рукопожатие даже для собственного клиента) и сеть: нет — этот раздел
#      ПРОПУСКАЕТСЯ громко, остальное идёт.
#
# Почему стенд, а не сверка байтов с эталоном: у VLESS encryption нет вектора «вход → выход» — каждое
# рукопожатие случайно. Единственная проверка, что мы говорим на том же протоколе, — живой сервер,
# который отвергает всё, что не сошлось до бита (AEAD с контекстом из BLAKE3 по всем сообщениям).
#
# Xray: XRAY=/путь/к/бинарнику либо docker с образом XRAY_IMAGE (умолчание ghcr.io/xtls/xray-core:latest);
# нет ни того, ни другого — громкий пропуск (код 0), не молчание. Клиент — $BUILD/vencprobe (его собирает
# tests/ext-test.sh на настоящей wolfSSL). Контейнеры и временные файлы убираются при любом выходе.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/vencprobe"
[ -x "$PROBE" ] || { echo "venc: нет $PROBE (собирает tests/ext-test.sh)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "venc: ПРОПУСК — нужен python3"; exit 0; }

IMG=${XRAY_IMAGE:-ghcr.io/xtls/xray-core:latest}
if [ -n "${XRAY:-}" ] && [ -x "$XRAY" ]; then
	MODE=bin
elif command -v docker >/dev/null 2>&1 && docker image inspect "$IMG" >/dev/null 2>&1; then
	MODE=docker
else
	echo "venc: ПРОПУСК — нет Xray-core (XRAY=/путь либо образ $IMG в docker). Это не падение."
	exit 0
fi

W=$(mktemp -d)
# Контейнер читает конфиги под другим пользователем: каталог mktemp по умолчанию 0700.
chmod 755 "$W"
PIDS=""
CONTS=""
cleanup() {
	for p in $PIDS; do kill "$p" 2>/dev/null || true; done
	for c in $CONTS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	rm -rf "$W"
}
trap cleanup EXIT INT TERM

xray_cmd() {
	if [ "$MODE" = bin ]; then "$XRAY" "$@"; else docker run --rm "$IMG" "$@"; fi
}
XVER=$(xray_cmd version 2>/dev/null | head -1)
echo "venc: сервер — $XVER ($MODE)"

BASE=$((20000 + $$ % 20000))
NEXT=$BASE
# Не через $(…): подоболочка не сохранила бы счётчик, и все серверы получили бы один порт.
port() { NEXT=$((NEXT + 1)); PORT=$NEXT; }

# Эхо-сервер для обмена данными: одно место назначения, куда сервер Xray (freedom) пускает трафик.
port; ECHO=$PORT
python3 - "$ECHO" <<'PY' &
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    finally: c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PY
PIDS="$PIDS $!"

wait_port() {
	python3 - "$1" <<'PY'
import socket, sys, time
for _ in range(60):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close(); sys.exit(0)
    except OSError: time.sleep(0.2)
# Приговор по состоянию, а не по счётчику кругов: сервер, поднявшийся в последние 0,2 с, — поднялся.
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close(); sys.exit(0)
except OSError: sys.exit(1)
PY
}

# xray_start ИМЯ ПОРТ — конфиг $W/ИМЯ.json уже лежит.
xray_start() {
	if [ "$MODE" = bin ]; then
		"$XRAY" run -c "$W/$1.json" >"$W/$1.log" 2>&1 &
		PIDS="$PIDS $!"
		LAST_PID=$!
	else
		c="steer-venc-$$-$1"
		docker run -d --rm --name "$c" --network host -v "$W:/cfg:ro" "$IMG" run -c "/cfg/$1.json" >/dev/null
		CONTS="$CONTS $c"
		LAST_CONT=$c
	fi
	wait_port "$2" || { echo "venc: сервер $1 не поднялся"; [ -f "$W/$1.log" ] && tail -5 "$W/$1.log"; return 1; }
}
# Хвост журнала сервера — при первом же провале имени: без него «не расшифровалось» не отличить от
# «сервер отказал по своей причине».
srvlog() {
	if [ "$MODE" = bin ]; then tail -8 "$W/$1.log" 2>/dev/null | sed 's/^/      xray: /'
	else docker logs "steer-venc-$$-$1" 2>&1 | tail -8 | sed 's/^/      xray: /'; fi
}
xray_stop() {
	if [ "$MODE" = bin ]; then kill "$LAST_PID" 2>/dev/null || true; wait "$LAST_PID" 2>/dev/null || true
	else docker rm -f "$LAST_CONT" >/dev/null 2>&1 || true; fi
}

UUID=b831381d-6324-4d53-ad4f-8cda48b30811
OK=0
BAD=0
result() { # ИМЯ КОД
	if [ "$2" -eq 0 ]; then OK=$((OK + 1)); printf '  %-58s ok\n' "$1"
	else BAD=$((BAD + 1)); printf '  %-58s ПРОВАЛ\n' "$1"; fi
}

# ---- ключи VLESS encryption --------------------------------------------------------------------
xray_cmd vlessenc >"$W/vlessenc.txt"
python3 - "$W" <<'PY'
import re, sys
t = open(sys.argv[1] + "/vlessenc.txt").read()
dec = re.findall(r'"decryption": "([^"]+)"', t)
enc = re.findall(r'"encryption": "([^"]+)"', t)
assert len(dec) == 2 and len(enc) == 2, t
for name, i in (("x", 0), ("m", 1)):
    open(sys.argv[1] + "/dec-" + name, "w").write(dec[i])
    open(sys.argv[1] + "/enc-" + name, "w").write(enc[i])
PY

# gen_enc ИМЯ ПОРТ ДЕКОДИРОВАНИЕ → $W/ИМЯ.json
gen_server() {
	python3 - "$W" "$1" "$2" "$3" "$4" <<'PY'
import json, os, sys
w, name, port, dec, uuid = sys.argv[1:6]
srv = {"log": {"loglevel": "warning"},
       "inbounds": [{"port": int(port), "listen": "127.0.0.1", "protocol": "vless",
                     "settings": {"clients": [{"id": uuid}], "decryption": dec},
                     "streamSettings": {"network": "tcp"}}],
       "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
json.dump(srv, open("%s/%s.json" % (w, name), "w"))
os.chmod("%s/%s.json" % (w, name), 0o644)
PY
}

echo "venc: VLESS encryption — режимы × ключи × 1rtt/0rtt"
[ "${VENC_ONLY:-}" = reality ] && modes="" || modes="native xorpub random"
for mode in $modes; do
	for kind in x m; do
		for rtt in 1rtt 0rtt; do
			name="e-$mode-$kind-$rtt"
			port; p=$PORT
			dec=$(sed "s/\.native\./.$mode./" "$W/dec-$kind")
			enc=$(sed "s/\.native\.0rtt\./.$mode.$rtt./" "$W/enc-$kind")
			gen_server "$name" "$p" "$dec" "$UUID"
			xray_start "$name" "$p" || { result "$name: сервер" 1; continue; }
			url="vless://$UUID@localhost:$p?encryption=$enc&type=tcp&security=none#$name"
			STEER_VENC_TRACE=1 "$PROBE" bulk "$url" "$ECHO" 1 3 >"$W/$name.probe" 2>&1 && rc=0 || rc=$?
			result "$name: три соединения подряд" $rc
			if [ "$rtt" = 0rtt ]; then
				n0=$(grep -c "0-RTT по билету" "$W/$name.probe" || true)
				[ "$n0" -eq 2 ] && rc=0 || rc=1
				result "$name: соединения 2 и 3 — по билету" $rc
			fi
			"$PROBE" bulk "$url" "$ECHO" 4 >"$W/$name.bulk" 2>&1 && rc=0 || rc=$?
			[ $rc -eq 0 ] || { sed 's/^/      /' "$W/$name.bulk"; srvlog "$name"; }
			result "$name: 4 МБ туда и обратно" $rc
			xray_stop
		done
	done
done

echo "venc: цепочка реле и своя набивка"
if [ "${VENC_ONLY:-}" != reality ]; then
port; p=$PORT
xk_d=$(sed 's/.*\.//' "$W/dec-x"); mk_d=$(sed 's/.*\.//' "$W/dec-m")
xk_e=$(sed 's/.*\.//' "$W/enc-x"); mk_e=$(sed 's/.*\.//' "$W/enc-m")
gen_server chain "$p" "mlkem768x25519plus.xorpub.600s.$xk_d.$mk_d.$xk_d" "$UUID"
xray_start chain "$p" && {
	url="vless://$UUID@localhost:$p?encryption=mlkem768x25519plus.xorpub.0rtt.$xk_e.$mk_e.$xk_e&type=tcp&security=none#chain"
	"$PROBE" bulk "$url" "$ECHO" 1 2 >"$W/chain.probe" 2>&1 && rc=0 || rc=$?
	result "три реле X25519 → ML-KEM → X25519, два соединения" $rc
	"$PROBE" bulk "$url" "$ECHO" 2 >/dev/null 2>&1 && rc=0 || rc=$?
	result "три реле: 2 МБ туда и обратно" $rc
	xray_stop
}
port; p=$PORT
pad="100-100-200.60-10-30.50-0-100"
gen_server pad "$p" "$(sed "s/\.native\.600s\./.random.600s.$pad./" "$W/dec-m")" "$UUID"
xray_start pad "$p" && {
	url="vless://$UUID@localhost:$p?encryption=$(sed "s/\.native\.0rtt\./.random.1rtt.$pad./" "$W/enc-m")&type=tcp&security=none#pad"
	"$PROBE" bulk "$url" "$ECHO" 1 2 >/dev/null 2>&1 && rc=0 || rc=$?
	result "своя набивка из строки, два соединения" $rc
	xray_stop
}

fi

# Билет, который сервер забыл (перезапуск): соединение по билету отклоняется, клиент выбрасывает билет,
# следующее соединение идёт по полному рукопожатию и работает.
echo "venc: забытый сервером билет 0-RTT"
if [ "${VENC_ONLY:-}" != reality ]; then
port; p=$PORT
gen_server stale "$p" "$(sed 's/\.native\./.random./' "$W/dec-m")" "$UUID"
xray_start stale "$p" && {
	url="vless://$UUID@localhost:$p?encryption=$(sed 's/\.native\.0rtt\./.random.0rtt./' "$W/enc-m")&type=tcp&security=none#stale"
	mkdir -p "$W/sync"
	VENC_SYNC="$W/sync" STEER_VENC_TRACE=1 "$PROBE" bulk "$url" "$ECHO" 1 4 >"$W/stale.out" 2>&1 &
	PROBE_PID=$!
	PIDS="$PIDS $PROBE_PID"
	n=1
	while [ "$n" -le 3 ]; do
		i=0
		while [ ! -f "$W/sync/ready.$n" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
		# после первого соединения — перезапуск сервера, дальше просто продолжаем
		if [ "$n" -eq 2 ]; then xray_stop; xray_start stale "$p" || break; fi
		: > "$W/sync/go.$n"
		n=$((n + 1))
	done
	wait "$PROBE_PID" && rc=0 || rc=$?
	result "после перезапуска сервера последнее соединение работает" $rc
	grep -q "отклонил билет" "$W/stale.out" && rc=0 || rc=1
	result "отклонённый билет назван" $rc
	[ "$(grep -c 'полное рукопожатие' "$W/stale.out")" -ge 2 ] && rc=0 || rc=1
	result "после отказа — полное рукопожатие" $rc
	xray_stop
}
fi

echo "venc: REALITY с гибридом X25519MLKEM768 и подписью ML-DSA-65"
DEST=${VENC_DEST:-www.apple.com}
if python3 -c "import socket,sys; socket.create_connection(('$DEST',443),3).close()" 2>/dev/null; then
	xray_cmd x25519 >"$W/x25519.txt"
	PRIV=$(awk '/PrivateKey/{print $2}' "$W/x25519.txt")
	PUB=$(awk '/Password|PublicKey/{print $NF}' "$W/x25519.txt" | head -1)
	xray_cmd mldsa65 >"$W/mldsa.txt"
	SEED=$(awk '/Seed/{print $2}' "$W/mldsa.txt")
	VERIFY=$(awk '/Verify/{print $2}' "$W/mldsa.txt")
	xray_cmd mldsa65 >"$W/mldsa2.txt"
	OTHER=$(awk '/Verify/{print $2}' "$W/mldsa2.txt")
	SID=0123456789abcdef
	for variant in plain mldsa; do
		port; p=$PORT
		python3 - "$W" "reality-$variant" "$p" "$UUID" "$DEST" "$PRIV" "$SID" "$variant" "$SEED" <<'PY'
import json, os, sys
w, name, port, uuid, dest, priv, sid, variant, seed = sys.argv[1:10]
rs = {"show": False, "dest": dest + ":443", "serverNames": [dest], "privateKey": priv, "shortIds": [sid]}
if variant == "mldsa": rs["mldsa65Seed"] = seed
srv = {"log": {"loglevel": "warning"},
       "inbounds": [{"port": int(port), "listen": "127.0.0.1", "protocol": "vless",
                     "settings": {"clients": [{"id": uuid}], "decryption": "none"},
                     "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": rs}}],
       "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
json.dump(srv, open("%s/%s.json" % (w, name), "w"))
os.chmod("%s/%s.json" % (w, name), 0o644)
PY
		xray_start "reality-$variant" "$p" || { result "reality-$variant: сервер" 1; continue; }
		# Первое соединение с только что запущенным сервером REALITY теряет запрос (сервер принял рукопожатие и
		# молчит; снято тем же клиентом против Xray 26.9.9: 7 из 10 запусков, при паузе 0,5 с — ни одного).
		# Порт уже открыт, а сервер ещё нет, поэтому пауза здесь, а не в wait_port.
		sleep 1
		base="vless://$UUID@localhost:$p?encryption=none&type=tcp&security=reality&sni=$DEST&pbk=$PUB&sid=$SID&fp=chrome"
		STEER_PQ_TRACE=1 "$PROBE" bulk "$base#r" "$ECHO" 1 >"$W/r-$variant.probe" 2>&1 && rc=0 || rc=$?
		[ $rc -eq 0 ] || { sed 's/^/      /' "$W/r-$variant.probe"; srvlog "reality-$variant"; }
		result "reality ($variant): 1 МБ туда и обратно" $rc
		grep -q "X25519MLKEM768" "$W/r-$variant.probe" && rc=0 || rc=1
		result "reality ($variant): сервер выбрал гибрид" $rc
		if [ "$variant" = mldsa ]; then
			"$PROBE" bulk "$base&pqv=$VERIFY#r" "$ECHO" 1 >/dev/null 2>&1 && rc=0 || rc=$?
			result "reality (mldsa): верный pqv — проходит" $rc
			"$PROBE" bulk "$base&pqv=$OTHER#r" "$ECHO" 1 >/dev/null 2>&1 && rc=1 || rc=0
			result "reality (mldsa): чужой pqv — отказ" $rc
		fi
		xray_stop
	done
else
	echo "  ПРОПУЩЕНО: маскировочный сайт $DEST:443 недоступен (VENC_DEST=…). Это не падение."
fi

echo
if [ "$BAD" -eq 0 ]; then echo "venc: все проверки прошли ($OK)"; else echo "venc: ПРОВАЛОВ $BAD из $((OK + BAD))"; exit 1; fi
