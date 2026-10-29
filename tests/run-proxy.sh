#!/bin/sh
# Протоколы steer-proxy (trojan, shadowsocks, socks, http, vmess) против НАСТОЯЩЕГО Xray-core
# (XRAY=/путь/к/xray). Провод — дайлеры src/proto/proxy, драйвятся напрямую (tests/pxprobe.c), как
# у tests/xudp.sh: клиент тот же, что в работе, сервер настоящий, за ним эхо и HTTP.
#
# Проверяется то, что ломается молча: вывод ключей (ss EVP/HKDF/BLAKE3, vmess KDF/AuthID),
# заголовки запроса и разбор ответа, обрамление UDP. Рукопожатие сошлось — ключи и байты верны.
#
# Пропуск ГРОМКИЙ (echo + выход 0), как у xudp.sh: нет Xray, python3 или openssl — это не падение.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/pxprobe"
[ -x "$PROBE" ] || { echo "proxy: нет $PROBE (собирает tests/ext-test.sh)"; exit 2; }
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
	echo "proxy: ПРОПУСК — нужны python3 и openssl. Это не падение."; exit 0; }
if [ -z "${XRAY:-}" ] || [ ! -x "${XRAY:-}" ]; then
	echo "proxy: ПРОПУСК — нет сервера (XRAY=/путь/к/xray). Это не падение."
	exit 0
fi

W=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT INT TERM

BASE=$((26000 + $$ % 20000))
HP=$BASE; UP=$((BASE+1))
TR=$((BASE+2)); SS=$((BASE+3)); SS22=$((BASE+4)); SK=$((BASE+5)); HT=$((BASE+6)); VM=$((BASE+7))
VMC=$((BASE+8)); SS22C=$((BASE+9)); SSN=$((BASE+10)); SK4=$((BASE+11)); VMWS=$((BASE+12)); SSMU=$((BASE+13))
SINK=$((BASE+14))
U=00000000-0000-0000-0000-000000000abc

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/k.pem" -out "$W/c.pem" \
	-subj "/CN=test.example" -days 2 -addext "subjectAltName=DNS:test.example" 2>/dev/null
PCS=$(openssl x509 -in "$W/c.pem" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')

python3 - "$HP" <<'PY' &
import http.server, sys, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.send_header("Content-Length","7"); s.end_headers(); s.wfile.write(b"OK-PXY\n")
    def log_message(s,*a): pass
socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
PIDS="$PIDS $!"
python3 - "$UP" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535); s.sendto(b"echo:" + d, a)
PY
PIDS="$PIDS $!"

# Медленный приёмник: читает понемногу (буферы по дороге заполняются — отправка клиента упирается
# в полный сокет), счёт байт — в ответ «GOT n», когда пришло 4 МБ. Начало «05 01 00» — он же сам
# сервер socks5 без авторизации: Xray перед ним вычитывал бы поток в свою память, и полного
# сокета у клиента socks не случалось бы.
python3 - "$SINK" <<'PY' &
import socket, sys, threading, time
def serve(c):
    n = 0
    try:
        d = c.recv(3)
        if d == b"\x05\x01\x00":
            c.sendall(b"\x05\x00"); c.recv(10)
            c.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        else:
            n = len(d)
        while True:
            d = c.recv(16384)
            if not d: break
            n += len(d)
            time.sleep(0.01)
            if n >= 4000000: c.sendall(b"GOT %d\n" % n); break
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
PIDS="$PIDS $!"

PSK16=$(head -c16 /dev/urandom | base64)
PSK32=$(head -c32 /dev/urandom | base64)
IPSK=$(head -c16 /dev/urandom | base64)
UPSK=$(head -c16 /dev/urandom | base64)

# Шифр «none» у сервера ss: живёт не во всякой сборке Xray (в 26.9.9 и 26.10.21 его нет — конфиг не
# грузится целиком: «unknown cipher method: none», и тогда падает ВЕСЬ стенд, а не один случай).
# Спрашиваем у самого сервера минимальным конфигом `run -test`: принял — вход ставим, нет — вход
# выпускаем из конфига, а случай пропускаем громко (ниже). Клиент не трогаем: провал других
# протоколов от этого не глушится.
SSN_IN=""; SSN_OK=0
cat > "$W/n.json" <<EOF
{"inbounds":[{"listen":"127.0.0.1","port":$SSN,"protocol":"shadowsocks","settings":{"method":"none","password":"x","network":"tcp,udp"}}],
 "outbounds":[{"protocol":"freedom"}]}
EOF
if "$XRAY" run -test -c "$W/n.json" >"$W/n.log" 2>&1; then
	SSN_OK=1
	SSN_IN=' {"listen":"127.0.0.1","port":'$SSN',"protocol":"shadowsocks","settings":{"method":"none","password":"x","network":"tcp,udp"}},'
fi

cat > "$W/x.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[
 {"listen":"127.0.0.1","port":$TR,"protocol":"trojan","settings":{"clients":[{"password":"tp"}]},
  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$W/c.pem","keyFile":"$W/k.pem"}]}}},
 {"listen":"127.0.0.1","port":$SS,"protocol":"shadowsocks","settings":{"method":"aes-256-gcm","password":"sspass","network":"tcp,udp"}},
 {"listen":"127.0.0.1","port":$SS22,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"$PSK16","network":"tcp,udp"}},
 {"listen":"127.0.0.1","port":$SS22C,"protocol":"shadowsocks","settings":{"method":"2022-blake3-chacha20-poly1305","password":"$PSK32","network":"tcp,udp"}},
 {"listen":"127.0.0.1","port":$SSMU,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"$IPSK","clients":[{"password":"$UPSK","email":"u@x"}],"network":"tcp,udp"}},
$SSN_IN
 {"listen":"127.0.0.1","port":$SK,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"su","pass":"sp"}],"udp":true,"ip":"127.0.0.1"}},
 {"listen":"127.0.0.1","port":$SK4,"protocol":"socks","settings":{"auth":"noauth","udp":false}},
 {"listen":"127.0.0.1","port":$HT,"protocol":"http","settings":{"accounts":[{"user":"hu","pass":"hp"}]}},
 {"listen":"127.0.0.1","port":$VM,"protocol":"vmess","settings":{"clients":[{"id":"$U","alterId":0}]},"streamSettings":{"network":"tcp"}},
 {"listen":"127.0.0.1","port":$VMC,"protocol":"vmess","settings":{"clients":[{"id":"$U","alterId":0}]},"streamSettings":{"network":"tcp"}},
 {"listen":"127.0.0.1","port":$VMWS,"protocol":"vmess","settings":{"clients":[{"id":"$U","alterId":0}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vm"}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}
EOF
"$XRAY" run -c "$W/x.json" >"$W/x.log" 2>&1 &
PIDS="$PIDS $!"
sleep 2
XVER=$("$XRAY" version 2>/dev/null | awk 'NR==1{print $2}')
echo "proxy: сервер — $("$XRAY" version 2>/dev/null | head -1)"

vmess_url() { # порт net path scy
	json=$(printf '{"v":"2","ps":"t","add":"localhost","port":"%s","id":"%s","aid":"0","scy":"%s","net":"%s","path":"%s","tls":""}' \
		"$1" "$U" "$4" "$2" "$3")
	printf 'vmess://%s' "$(printf '%s' "$json" | base64 | tr -d '\n')"
}

FAILS=0; SKIPS=0
run() { # название ссылка tcp|udp порт
	if out=$(timeout 30 "$PROBE" "$2" "$3" 127.0.0.1 "$4" 3 2>&1); then
		echo "  ok   $1"
	else
		echo "  FAIL $1"; echo "$out" | sed 's/^/       /'; FAILS=$((FAILS + 1))
	fi
}

run "trojan tcp"            "trojan://tp@localhost:$TR?security=tls&sni=test.example&pcs=$PCS" tcp $HP
run "trojan udp"            "trojan://tp@localhost:$TR?security=tls&sni=test.example&pcs=$PCS" udp $UP
run "ss aes-256-gcm tcp"    "ss://aes-256-gcm:sspass@localhost:$SS" tcp $HP
run "ss aes-256-gcm udp"    "ss://aes-256-gcm:sspass@localhost:$SS" udp $UP
run "ss 2022-aes-128 tcp"   "ss://2022-blake3-aes-128-gcm:$PSK16@localhost:$SS22" tcp $HP
# 2022 UDP не поддержан (сессии/AES-ECB, docs/proxy.md) — узел обязан ОТКЛОНИТЬ датаграммы.
if timeout 30 "$PROBE" "ss://2022-blake3-aes-128-gcm:$PSK16@localhost:$SS22" udp 127.0.0.1 $UP 2 >/dev/null 2>&1; then
	echo "  FAIL ss 2022 udp должен отклоняться, а прошёл"; FAILS=$((FAILS + 1))
else
	echo "  ok   ss 2022 udp отклонён (как задумано)"
fi
run "ss 2022-chacha tcp"    "ss://2022-blake3-chacha20-poly1305:$PSK32@localhost:$SS22C" tcp $HP
run "ss 2022 multiuser tcp" "ss://2022-blake3-aes-128-gcm:$IPSK:$UPSK@localhost:$SSMU" tcp $HP
if [ $SSN_OK = 1 ]; then
	run "ss none tcp"           "ss://none:x@localhost:$SSN" tcp $HP
	run "ss none udp"           "ss://none:x@localhost:$SSN" udp $UP
else
	echo "  пропуск: Xray $XVER не умеет ss none (сервер не принимает шифр; остальные случаи идут)"
	SKIPS=$((SKIPS + 1))
fi
run "socks5 tcp"            "socks5://su:sp@localhost:$SK" tcp $HP
run "socks5 udp"            "socks5://su:sp@localhost:$SK" udp $UP
run "socks4 tcp"            "socks4://localhost:$SK4" tcp $HP
run "http tcp"              "http://hu:hp@localhost:$HT" tcp $HP
run "vmess aes-128-gcm tcp" "$(vmess_url $VM tcp '' aes-128-gcm)" tcp $HP
run "vmess aes-128-gcm udp" "$(vmess_url $VM tcp '' aes-128-gcm)" udp $UP
run "vmess chacha tcp"      "$(vmess_url $VMC tcp '' chacha20-poly1305)" tcp $HP
run "vmess over ws tcp"     "$(vmess_url $VMWS ws /vm aes-128-gcm)" tcp $HP

# Отправка под давлением: 4 МБ в медленный приёмник. Полный буфер сокета — не отказ: кусок либо
# уходит целиком, либо SEND_AGAIN и повтор, но не SEND_FATAL посреди потока.
run_up() { # название ссылка
	if out=$(UPLOAD=4000000 timeout 60 "$PROBE" "$2" tcp 127.0.0.1 "$SINK" 2>&1); then
		echo "  ok   $1"
	else
		echo "  FAIL $1"; echo "$out" | tail -3 | sed 's/^/       /'; FAILS=$((FAILS + 1))
	fi
}
run_up "socks5 tcp: 4 МБ под давлением" "socks5://localhost:$SINK"
run_up "ss aes-256-gcm tcp: 4 МБ под давлением" "ss://aes-256-gcm:sspass@localhost:$SS"
run_up "http tcp: 4 МБ под давлением" "http://hu:hp@localhost:$HT"

[ "$SKIPS" = 0 ] || echo "proxy: пропущено случаев: $SKIPS (см. «пропуск» выше — это не падение, но и не зелёное)"
[ $FAILS = 0 ] && echo "proxy: все проверки прошли" || { echo "proxy: провалов: $FAILS"; sed -n '1,30p' "$W/x.log"; exit 1; }
