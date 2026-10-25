#!/bin/sh
# HTTPS клиента libsteer (src/proto/tls/httpc.c) с настоящим TLS 1.3 и проверкой цепочки: python-сервер
# (tests/httpsserver.py) со своим корнем, клиент — tests/httpsget.c на настоящих tls13/reality/scrypto.
# Зовётся из tests/ext-test.sh, который собрал $HTTPSGET; сам ничего не собирает.
#   sh tests/httpsmatch.sh <httpsget>
set -e
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
SRC=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d /tmp/httpsmatch.XXXXXX)
trap 'kill $SP 2>/dev/null; rm -rf "$W"' EXIT
fail=0
ck() { # описание, ожидаемая подстрока, вывод
    case "$3" in *"$2"*) echo "$1 ok" ;; *) echo "$1 ПРОВАЛ"; echo "   хочу: $2"; echo "   есть: $3"; fail=1 ;; esac
}
cd "$W"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=steer test ca" -days 2 >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca2.key -out ca2.pem -subj "/CN=other ca" -days 2 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n' > ext.cnf
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 2 -extfile ext.cnf >/dev/null 2>&1
python3 "$SRC/httpsserver.py" srv.pem srv.key > port.txt &
SP=$!
i=0; while [ ! -s port.txt ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
PORT=$(cat port.txt)
U="https://localhost:$PORT"

o=$("$BIN" "$U/ok" ca.pem body)
ck "GET по HTTPS с проверкой цепочки" "rc=0 status=200 body=14" "$o"
ck "  тело" "hello over tls" "$(cat body)"
o=$("$BIN" "$U/redir" ca.pem body)
ck "переадресация внутри HTTPS" "rc=0 status=200 body=14 redirects=1" "$o"
o=$("$BIN" "$U/big" ca.pem body)
ck "5 МиБ по TLS потоком" "rc=0 status=200 body=5242880" "$o"
python3 - body <<'P' || { echo "  содержимое 5 МиБ ПРОВАЛ"; fail=1; }
import sys
d = open(sys.argv[1], "rb").read()
assert d == bytes((i * 7) & 0xff for i in range(5 * 1024 * 1024))
P
o=$("$BIN" "$U/etag" ca.pem body '"t1"')
ck "If-None-Match по HTTPS: 304" "rc=0 status=304 body=0 redirects=0 etag=\"t1\"" "$o"
o=$("$BIN" "$U/etag" ca.pem body)
ck "без If-None-Match: 200 и ETag" "status=200 body=6 redirects=0 etag=\"t1\"" "$o"
o=$("$BIN" "$U/downgrade" ca.pem body)
ck "переадресация https -> http отвергнута" "rc=-8" "$o"
o=$("$BIN" "$U/ok" ca2.pem body)
ck "чужой корень: сертификат не принят" "rc=-4" "$o"
o=$("$BIN" "https://127.0.0.1:$PORT/ok" ca.pem body)
ck "имя не из сертификата (127.0.0.1): отказ" "rc=-4" "$o"
o=$("$BIN" "$U/ok" /нет/корней.pem body)
ck "хранилища корней нет: отказ, не принятие" "rc=-4" "$o"
[ $fail = 0 ] && echo "httpsmatch: все проверки прошли" || { echo "httpsmatch: ПРОВАЛ"; exit 1; }
