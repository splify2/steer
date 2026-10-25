#!/bin/sh
# Протокол-плагин поднимается из каталога плагинов (раскладка 2.1, build/sources.mk, «РАСКЛАДКА 2.1»).
#
# Ядро — каталог, в котором ТОЛЬКО steerd и его библиотеки (ни steer-vless, ни ссылок рядом), плагины —
# отдельный каталог в раскладке роутера (<корень>/<id>/bin/<id>, <корень>/net1/lib/libs2p-net.so.1),
# STEER_PLUGIN_DIR указывает на него (src/lib/module.c). Проверяется:
#   • без плагина команда протокола и вид в спеке отвечают отказом «нужен пакет», с плагином — работают,
#     и steerd отдаёт команду программе плагина (hello называет её);
#   • программа плагина находит net1 сама (RUNPATH $ORIGIN/../../net1/lib, без LD_LIBRARY_PATH) и не
#     связана с libsteer;
#   • `--conf {conf}` помощника (src/modules/plugconf.h) даёт то же, что `--spec`;
#   • под root — настоящий туннель VLESS (tests/run-tunnel.sh) с ядром из этого каталога и плагином
#     из каталога плагинов;
#   • QEMU=1 — то же на стенде OpenWrt (tools/vmrouter хаба: VMR=путь к vmrouter.sh) сборкой musl
#     (MUSL_LIBS, по умолчанию build/libs/x86_64 — её кладёт `STEER_ARCH=x86_64 ./build.sh`).
#
#     LIBS=build/libs-host sh tests/plugnet1.sh
set -u
cd "$(dirname "$0")/.."
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)" || { echo "plugnet1: нет раскладки (tests/libs-test.sh) — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] && [ -f "$LIBS/plugins/net1/lib/libs2p-net.so.1" ] ||
    { echo "plugnet1: в $LIBS нет раскладки 2.1 — пропуск"; exit 0; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  вышло:     %s\n' "$1" "$2" "$3"
    fi
}
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/core" "$W/plugins" "$W/none"
cp "$LIBS/steerd" "$LIBS"/libsteer.so.* "$LIBS"/libsteer-wolfssl.so.* "$W/core/"
cp -R "$LIBS/plugins/." "$W/plugins/"
# Манифесты и схемы ключей — те, что едут в .s2p (plugins/<id>/ дерева, build/pack-s2p.sh): ядро читает их
# реестром (src/kinds/plugin.c), и виды протоколов на стенде — виды плагинов, а не встроенные записи.
VER="$(cat VERSION)"
for d in plugins/*/; do
    q="$(basename "$d")"
    [ -d "$W/plugins/$q" ] || continue
    cp -R "$d." "$W/plugins/$q/"
    sed -i "s/\"@VERSION@\"/\"$VER\"/" "$W/plugins/$q/plugin.json"
done
CORE="$W/core/steerd"
P="$W/plugins"
run_core() { _d="$1"; shift; env -u STEER_MODULE_DIR LD_LIBRARY_PATH="$W/core" STEER_PLUGIN_DIR="$_d" STEER_PLUGINS_ROOT="$_d" STEER_PLUGINS_ETC="$W/petc" "$CORE" "$@"; }

U=11111111-2222-3333-4444-555555555555
printf 'vless://%s@192.0.2.1:443?security=tls&sni=a.test#A\nvless://%s@192.0.2.2:443?security=none&type=tcp#B\n' "$U" "$U" > "$W/sub.txt"
printf 'hysteria2://p@192.0.2.4:443/?sni=h.test#H\n' > "$W/hy.txt"
mkdir -p "$W/etc"
cat > "$W/etc/spec.yaml" <<SPEC
version: 2
outputs:
  vl: { kind: tunnel, protocol: vless, subscription: $W/sub.txt }
  hy: { kind: tunnel, protocol: hysteria2, subscription: $W/hy.txt }
SPEC

# ---- без плагина -------------------------------------------------------------------------------
o="$(run_core "$W/none" vless-nodes "$W/sub.txt" 2>&1)"; r=$?
check "без плагина: steerd vless-nodes — код 2 и «нужен пакет steer-vless»" "2 1" \
    "$r $(printf '%s' "$o" | grep -c 'нужен пакет steer-vless')"
o="$(run_core "$W/none" apply --dry-run --spec "$W/etc/spec.yaml" --state-dir "$W/st0" 2>&1)"
# Раскладка плагинов есть, плагина нет — apply отказывает словами «нужен плагин» (реестр видов,
# src/kinds/plugin.c; при старте демона такой выход живёт по on_fail).
check "  спека с vless — отказ «нужен плагин vless»" "1" \
    "$(printf '%s' "$o" | grep -c 'нужен плагин vless')"

# ---- с плагином ----------------------------------------------------------------------------------
a="$(run_core "$P" vless-nodes "$W/sub.txt" 2>&1; echo "rc=$?")"
b="$(env -u LD_LIBRARY_PATH "$P/vless/bin/vless" vless-nodes "$W/sub.txt" 2>&1; echo "rc=$?")"
check "с плагином: steerd vless-nodes отвечает как программа плагина (вывод и код)" "$b" "$a"
check "  и это перечень узлов, а не отказ" "1 0" \
    "$(printf '%s' "$a" | grep -c '"name":"B"') $(printf '%s' "$a" | grep -c 'нужен пакет')"
h="$(STEER_EVENT_FD=3 env -u STEER_MODULE_DIR LD_LIBRARY_PATH="$W/core" STEER_PLUGIN_DIR="$P" STEER_PLUGINS_ROOT="$P" STEER_PLUGINS_ETC="$W/petc" \
    "$CORE" hysteria2 x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "steerd hysteria2 исполняет плагин: hello от программы плагина" "1" \
    "$(printf '%s' "$h" | grep -c '"ev":"hello".*"mod":"hysteria2"')"
o="$(run_core "$P" apply --dry-run --spec "$W/etc/spec.yaml" --state-dir "$W/st1" 2>&1)"
check "  спека с vless и hysteria2 принимается: виды плагинов, без «нужен плагин»" "0 0" \
    "$(printf '%s' "$o" | grep -c 'требует пакет') $(printf '%s' "$o" | grep -c 'нужен плагин')"

# ---- программа плагина сама по себе ---------------------------------------------------------------
if command -v readelf >/dev/null 2>&1; then
    for m in vless hysteria2; do
        check "плагин $m: NEEDED из нашего — только libs2p-net.so.1" "libs2p-net.so.1" \
            "$(readelf -d "$P/$m/bin/$m" | sed -n 's/.*Shared library: \[\(lib\(steer\|s2p\)[^]]*\)\]/\1/p' | tr '\n' ' ' | sed 's/ $//')"
    done
fi
if command -v ldd >/dev/null 2>&1; then
    check "net1 находится по RUNPATH из каталога плагинов, без LD_LIBRARY_PATH" "$P/vless/bin/../../net1/lib/libs2p-net.so.1" \
        "$(env -u LD_LIBRARY_PATH ldd "$P/vless/bin/vless" | sed -n 's/.*libs2p-net.so.1 => \([^ ]*\) .*/\1/p')"
fi
mv "$P/net1" "$W/net1.away"
o="$(env -u LD_LIBRARY_PATH "$P/vless/bin/vless" vless-nodes "$W/sub.txt" 2>&1)"; r=$?
check "без net1 плагин не стартует, загрузчик называет libs2p-net.so.1" "1" \
    "$([ "$r" != 0 ] && printf '%s' "$o" | grep -c 'libs2p-net.so.1' || echo 0)"
mv "$W/net1.away" "$P/net1"

# ---- --conf {conf} -------------------------------------------------------------------------------
mkdir -p "$W/pst"
cat > "$W/vl.json" <<CONF
{"api":"1.0","plugin":{"id":"vless","version":"x"},
 "output":{"name":"vl","kind":"tunnel:vless","keys":{"subscription":"$W/sub.txt"},"device":"","mark":"0x00300000",
           "mark_mask":"0x0ff00000","table":302,"ipv6":true,"on_fail":"drop","over":null,"sock_mark":"0x00000000",
           "sock_mark_required":false,"tcp_port":0,"ports":[],"queues":[]},
 "paths":{"etc":"$W/nonexistent-etc","state":"$W/nonexistent-state","plugin":"$P/vless","plugin_state":"$W/pst"},
 "platform":"openwrt"}
CONF
a="$(env -u LD_LIBRARY_PATH "$P/vless/bin/vless" vless-nodes vl --conf "$W/vl.json" 2>&1; echo "rc=$?")"
b="$(env -u LD_LIBRARY_PATH "$P/vless/bin/vless" vless-nodes vl --spec "$W/etc/spec.yaml" --state-dir "$W/st2" 2>&1; echo "rc=$?")"
# Помощник знает о выходе только {conf}: спеки человека и каталогов ядра (их в {conf} нарочно нет на
# диске) он не читает — перечень тот же, что по спеке.
check "--conf {conf}: выход только из {conf}, без спеки человека — то же, что --spec" "$b" "$a"
check "  и это перечень узлов выхода" "1" "$(printf '%s' "$a" | grep -c '"name":"A"')"
o="$(env -u LD_LIBRARY_PATH "$P/vless/bin/vless" vless-nodes vl --conf "$W/nope.json" 2>&1)"; r=$?
check "--conf без файла — код 2 со словами" "2 1" "$r $(printf '%s' "$o" | grep -c 'файл настройки выхода не читается')"

# hysteria2 по {conf}: ключи пула (silence) и снятый IPv6 доходят до разбора, узел честно не отвечает.
cat > "$W/pst/hy.json" <<CONF
{"api":"1.0","plugin":{"id":"hysteria2","version":"x"},
 "output":{"name":"hy","kind":"tunnel:hysteria2","keys":{"subscription":"$W/hy.txt","silence":30},"device":"",
           "mark":"0x00300000","table":302,"ipv6":false,"sock_mark":"0x00000000","sock_mark_required":false,"tcp_port":0},
 "paths":{"plugin_state":"$W/pst"},"platform":"openwrt"}
CONF
o="$(timeout 30 env -u LD_LIBRARY_PATH "$P/hysteria2/bin/hysteria2" hysteria2 hy --conf "$W/pst/hy.json" 2>&1)"
check "hysteria2 --conf: выход из {conf} разобран, узлы подписки перебраны" "1 1" \
    "$(printf '%s' "$o" | grep -c 'узлов 1 (пропущено 0') $(printf '%s' "$o" | grep -c 'ни один узел подписки не отвечает')"
check "  спека из одного выхода — в каталоге плагина, с ipv6: off и ключами вида" "1" \
    "$(grep -c '"protocol":"hysteria2","ipv6":"off","subscription":"[^"]*","silence":30' "$W/pst/hy.spec.json")"

# ---- настоящий туннель под root -------------------------------------------------------------------
if [ "$(id -u)" = 0 ] && command -v python3 >/dev/null 2>&1; then
    o="$(STEER="$CORE" LD_LIBRARY_PATH="$W/core" STEER_PLUGIN_DIR="$P" STEER_PLUGINS_ROOT="$P" STEER_PLUGINS_ETC="$W/petc" sh tests/run-tunnel.sh 2>&1)"; r=$?
    check "туннель VLESS: ядро без модулей рядом, плагин из каталога плагинов (tests/run-tunnel.sh)" "0" "$r"
    [ "$r" = 0 ] || printf '%s\n' "$o" | tail -15 | sed 's/^/    /'
    # Демон с супервизором: виды tunnel:vless — из манифеста плагина (реестр, src/kinds/plugin.c),
    # помощник — программа плагина с --conf {conf}, файл кладёт демон (helpers.c). Стенд tests/sigpipe.sh
    # (два выхода vless, закрытие соединений узлом на скорости) — на ядре без модулей рядом.
    mkdir -p "$W/sp"
    cp "$W/core/"* "$W/sp/"
    ln -s "$P/vless/bin/vless" "$W/sp/steer-vless"      # sigpipe.sh проверяет, что раскладка есть
    o="$(LIBS="$W/sp" STEER_PLUGINS_ROOT="$P" STEER_PLUGIN_DIR="$P" STEER_PLUGINS_ETC="$W/petc" sh tests/sigpipe.sh 2>&1)"; r=$?
    check "демон: выходы вида плагина vless, помощник по манифесту с {conf} (tests/sigpipe.sh)" "0 1" \
        "$r $(printf '%s\n' "$o" | tail -1 | grep -c ', 0 fail$')"
    [ "$r" = 0 ] || printf '%s\n' "$o" | grep -v '^ *ok\|^узел' | tail -15 | sed 's/^/    /'
else
    echo "plugnet1: туннель — нужен root и python3 (пропуск этой части)"
fi

# ---- QEMU (OpenWrt 25.12.5 x86-64, musl) ----------------------------------------------------------
if [ "${QEMU:-0}" = 1 ]; then
    VMR="${VMR:-../tools/vmrouter/vmrouter.sh}"
    ML="$(cd "${MUSL_LIBS:-build/libs/x86_64}" 2>/dev/null && pwd)" || ML=""
    if [ -z "$ML" ] || [ ! -f "$ML/plugins/net1/lib/libs2p-net.so.1" ] || [ ! -f "$VMR" ]; then
        echo "plugnet1: QEMU — нет сборки musl 2.1 ($ML) или $VMR (пропуск)"
    else
        mkdir -p "$W/q/core" "$W/q/plugins"
        cp "$ML/steerd" "$ML"/libsteer.so.* "$ML"/libsteer-wolfssl.so.* "$W/q/core/"
        cp -R "$ML/plugins/." "$W/q/plugins/"
        cp "$W/sub.txt" "$W/hy.txt" "$W/q/"
        sed "s#$W/#/tmp/plugnet1/#g" "$W/etc/spec.yaml" > "$W/q/spec.yaml"
        tar -C "$W/q" -czf "$W/q.tgz" .
        sh "$VMR" ssh 'rm -rf /tmp/plugnet1; mkdir -p /tmp/plugnet1' >/dev/null 2>&1
        sh "$VMR" put "$W/q.tgz" /tmp/plugnet1/q.tgz >/dev/null 2>&1
        R="$(sh "$VMR" ssh 'cd /tmp/plugnet1 && tar -xzf q.tgz && Q=/tmp/plugnet1 &&
            echo "direct:$(plugins/vless/bin/vless vless-nodes $Q/sub.txt 2>&1 | grep -c "\"name\":\"B\"")" &&
            echo "core:$(LD_LIBRARY_PATH=$Q/core STEER_PLUGIN_DIR=$Q/plugins core/steerd vless-nodes $Q/sub.txt 2>&1 | grep -c "\"name\":\"B\"")" &&
            echo "none:$(LD_LIBRARY_PATH=$Q/core STEER_PLUGIN_DIR=/nonexistent core/steerd vless-nodes $Q/sub.txt 2>&1 | grep -c "нужен пакет steer-vless")" &&
            echo "apply:$(LD_LIBRARY_PATH=$Q/core STEER_PLUGIN_DIR=$Q/plugins core/steerd apply --dry-run --spec $Q/spec.yaml --state-dir $Q/st 2>&1 | grep -c "требует пакет\|нужен плагин")" &&
            echo "hy2:$(plugins/hysteria2/bin/hysteria2 hysteria2-nodes $Q/hy.txt 2>&1 | grep -c "\"name\":\"H\"")" &&
            echo "ldd:$(ldd plugins/vless/bin/vless 2>&1 | grep -c "net1/lib/libs2p-net.so.1")"' 2>&1)"
        for k in "direct:1:плагин vless на OpenWrt: перечень узлов, net1 по RUNPATH (musl \$ORIGIN)" \
                 "core:1:steerd на OpenWrt исполняет плагин из каталога плагинов" \
                 "none:1:без каталога плагинов — «нужен пакет steer-vless»" \
                 "apply:0:спека с vless и hysteria2 принимается ядром с плагинами (без «нужен плагин»)" \
                 "hy2:1:плагин hysteria2 на OpenWrt: перечень узлов" \
                 "ldd:1:загрузчик musl берёт net1 из каталога плагинов"; do
            _k="${k%%:*}"; _r="${k#*:}"; _v="${_r%%:*}"; _t="${_r#*:}"
            check "QEMU: $_t" "$_v" "$(printf '%s\n' "$R" | sed -n "s/^$_k://p")"
        done
        sh "$VMR" ssh 'rm -rf /tmp/plugnet1' >/dev/null 2>&1
    fi
fi

echo "plugnet1: $pass ok, $fail fail"
[ "$fail" = 0 ]
