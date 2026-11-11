#!/bin/sh
# Включение fw4 ядра steer (files/usr/share/nftables.d/chain-pre/input/30-steer.nft): перенаправленное
# правилом nat steer к слушателю на роутере проходит через зону с input REJECT (гостевая сеть), прямое —
# нет.
#
# Зачем. Плагины получают порты от PLUGIN_PORT_FIRST (10480) и выше (src/kinds/plugalloc.c), а включение
# принимало только 8480-8744 и 9480-9734: TCP гостя, завёрнутый к слушателю плагина, fw4 отвергал. Стенд —
# два сетевых пространства в контейнере: «роутер» с цепочкой input как у fw4 (включение, затем REJECT зоны)
# и правилом redirect, «клиент» за veth.
#
# Проверяется:
#   1. перенаправленный TCP к порту плагина 10480 и к слушателю туннеля 9480 — принят, ответ пришёл;
#   2. перенаправленный UDP к порту плагина — принят;
#   3. прямое подключение к тем же портам — отвергнуто правилом зоны;
#   4. включение проходит `nft -c`.
# Нужен docker с --privileged (сетевые пространства); нет — громкий пропуск, это не падение.
set -u
cd "$(dirname "$0")/.."
INC=files/usr/share/nftables.d/chain-pre/input/30-steer.nft

if [ "${1:-}" != --inside ]; then
    command -v docker >/dev/null 2>&1 || { echo "fwinclude: docker нет — ПРОПУСК (это не падение)"; exit 0; }
    exec docker run --rm --privileged -v "$PWD:/w:ro" -w /w alpine:latest sh -c \
        'apk add -q nftables iproute2 python3 >/dev/null 2>&1 || { echo "fwinclude: пакеты alpine не встали — ПРОПУСК"; exit 0; }
         sh tests/fwinclude.sh --inside'
fi

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
R=fwr C=fwc
ip netns add $R && ip netns add $C || { echo "fwinclude: ip netns недоступен — ПРОПУСК"; exit 0; }
trap 'ip netns del $R; ip netns del $C' EXIT
ip link add vr netns $R type veth peer name vc netns $C
ip -n $R addr add 10.88.0.1/24 dev vr; ip -n $R link set vr up; ip -n $R link set lo up
ip -n $C addr add 10.88.0.2/24 dev vc; ip -n $C link set vc up; ip -n $C link set lo up

# «fw4»: цепочка input роутера — включение steer (chain-pre), затем зона гостя с input REJECT.
cat > /tmp/fw.nft <<EOF
table inet fw4 {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "lo" accept
    include "/w/$INC"
    iifname "vr" reject
  }
}
table inet steer {
  chain dstnat {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "vr" tcp dport 443 redirect to :10480
    iifname "vr" tcp dport 444 redirect to :9480
    iifname "vr" udp dport 4443 redirect to :10481
  }
}
EOF
ip netns exec $R nft -c -f /tmp/fw.nft
check "включение проходит nft -c" "0" "$?"
ip netns exec $R nft -f /tmp/fw.nft || { echo "fwinclude: набор не встал"; exit 1; }

# Слушатели «плагина» и «туннеля» на роутере: TCP отвечает строкой, UDP — эхом.
cat > /tmp/srv.py <<'EOF'
import socket, threading
def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(8)
    while True:
        c, _ = s.accept(); c.sendall(b"ok%d" % port); c.close()
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(100); s.sendto(b"ok" + d, a)
for f, p in ((tcp, 10480), (tcp, 9480), (udp, 10481)):
    threading.Thread(target=f, args=(p,), daemon=True).start()
threading.Event().wait()
EOF
ip netns exec $R python3 /tmp/srv.py & SRV=$!
sleep 0.5
cat > /tmp/cli.py <<'EOF'
import socket, sys
proto, port = sys.argv[1], int(sys.argv[2])
try:
    if proto == "tcp":
        s = socket.create_connection(("10.88.0.1", port), timeout=2); print(s.recv(100).decode())
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        s.sendto(b"u", ("10.88.0.1", port)); print(s.recvfrom(100)[0].decode())
except Exception as e:
    print("отказ:", type(e).__name__)
EOF
cli() { ip netns exec $C python3 /tmp/cli.py "$@"; }
check "перенаправленный TCP к порту плагина 10480 — принят" "ok10480" "$(cli tcp 443)"
check "перенаправленный TCP к слушателю туннеля 9480 — принят" "ok9480" "$(cli tcp 444)"
check "перенаправленный UDP к порту плагина 10481 — принят" "oku" "$(cli udp 4443)"
check "прямой TCP к 10480 — отвергнут зоной" "отказ: ConnectionRefusedError" "$(cli tcp 10480)"
check "прямой TCP к 9480 — отвергнут зоной" "отказ: ConnectionRefusedError" "$(cli tcp 9480)"
kill $SRV 2>/dev/null

echo "fwinclude: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
