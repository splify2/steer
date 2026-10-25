#!/bin/sh
# Стенд спеки v2 (src/model/v2.c, v2print.c; docs/spec-v2.md).
#
# 1. ПЕРЕВОД v1 → v2 ДАЁТ ТОТ ЖЕ RULESET. Спеки v1 берутся не из своего набора, а из всех
#    вызовов `apply --dry-run`, которые делают стенды генератора (gen.sh, androidmatch.sh,
#    tgwsmark.sh), — тем же приёмом, что у снимка (tests/snapshot.sh): вместо бинарника стендам
#    подставлена обёртка. На каждый такой вызов обёртка делает `spec convert` той же спеки и
#    `apply --dry-run` по напечатанному v2 с теми же флагами и окружением, и ruleset (stdout) и
#    код обязаны совпасть до байта. Спеку, которую v1 отвергает, convert обязан отвергнуть тоже.
#    stderr не сравнивается: у v1 свои предупреждения, у v2 их нет.
# 2. РАЗБОР v2: примеры (в том числе пример из docs/spec-v2.md), отказы с файлом, строкой и
#    столбцом, неизвестный ключ, чужой ключ вида, битые ссылки, круги, «ещё не поддерживается»,
#    выбор файла спеки по умолчанию.
set -u
STEER_BIN="${STEER:-./build/steer}"
ANDROID_BIN="${ANDROID:-./build/steer-android}"
TGWSSIM_BIN="${TGWSSIM:-./build/tgwssim}"
for b in "$STEER_BIN" "$ANDROID_BIN" "$TGWSSIM_BIN"; do
    [ -x "$b" ] || { echo "v2match: не собран $b (make)"; exit 2; }
done

abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
res="$tmp/res"
mkdir -p "$res" "$tmp/wrap"

# ---- 1. перевод ------------------------------------------------------------------------------
wrap() {
    real="$(abs "$1")"
    cat > "$tmp/wrap/$2" <<EOF
#!/bin/sh
real='$real'
dry=0 spec=''
if [ "\${1:-}" = apply ]; then
    prev=''
    for a in "\$@"; do
        [ "\$a" = --dry-run ] && dry=1
        [ "\$prev" = --spec ] && spec="\$a"
        prev="\$a"
    done
fi
[ \$dry = 1 ] && [ -n "\$spec" ] || exec "\$real" "\$@"
cnt="$res/.n"
n=\$(cat "\$cnt" 2>/dev/null || echo 0); n=\$((n + 1)); echo \$n > "\$cnt"
d="$res/\$n"
mkdir -p "\$d"
"\$real" "\$@" > "\$d/v1.out" 2> "\$d/v1.err"
rc=\$?
echo "\$rc" > "\$d/v1.rc"
printf '%s\n' "$2 \$*" > "\$d/args"
cp "\$spec" "\$d/v1.spec" 2>/dev/null
if "\$real" spec convert --spec "\$spec" > "\$d/v2.yaml" 2> "\$d/conv.err"; then
    # Те же аргументы, спека — напечатанный v2.
    set -- "\$@" __end__
    while [ "\$1" != __end__ ]; do
        a="\$1"; shift
        if [ "\$a" = --spec ]; then set -- "\$@" --spec "\$d/v2.yaml"; shift; else set -- "\$@" "\$a"; fi
    done
    shift
    "\$real" "\$@" > "\$d/v2.out" 2> "\$d/v2.err"
    echo \$? > "\$d/v2.rc"
fi
cat "\$d/v1.out"
cat "\$d/v1.err" >&2
exit \$rc
EOF
    chmod +x "$tmp/wrap/$2"
}
wrap "$STEER_BIN" router
wrap "$ANDROID_BIN" android
wrap "$TGWSSIM_BIN" tgws

STEER="$tmp/wrap/router" sh tests/gen.sh >/dev/null 2>&1
ANDROID="$tmp/wrap/android" sh tests/androidmatch.sh >/dev/null 2>&1
STEER="$tmp/wrap/router" TGWSSIM="$tmp/wrap/tgws" sh tests/tgwsmark.sh >/dev/null 2>&1

same=0 refused=0 pinned=0 fail=0 total=0
for d in "$res"/*/; do
    [ -f "$d/v1.rc" ] || continue
    total=$((total + 1))
    rc1="$(cat "$d/v1.rc")"
    if [ ! -f "$d/v2.rc" ]; then
        # convert отказал: законно, только если v1 отказал тоже (та же спека не разбирается).
        if [ "$rc1" != 0 ]; then refused=$((refused + 1)); continue; fi
        fail=$((fail + 1))
        echo "FAIL v2match: convert отказал на спеке, которую v1 принял ($(cat "$d/args"))"
        head -n 3 "$d/conv.err"
        continue
    fi
    if [ "$rc1" != 0 ]; then
        # v1 разобрался, но apply отказал дальше (проверки компилятора): v2 обязан отказать так же.
        if [ "$(cat "$d/v2.rc")" = "$rc1" ]; then refused=$((refused + 1)); continue; fi
    fi
    if [ "$(cat "$d/v2.rc")" = "$rc1" ] && cmp -s "$d/v1.out" "$d/v2.out"; then
        same=$((same + 1))
    elif [ "$(cat "$d/v2.rc")" = "$rc1" ] && grep -q 'comment "steer-pin:' "$d/v2.out" &&
         ! grep -q 'steer-pin:' "$d/v1.out"; then
        # Пул v1 (`devices`) переводится группой с именованными членами, а у неё в v2 соединения
        # закреплены за членом (compile/balance.c, group_carded): v1 так не умеет — у членов пула
        # нет своих меток. Расхождение намеренное; набор правил такой группы сверяют gen.sh и снимок.
        pinned=$((pinned + 1))
    else
        fail=$((fail + 1))
        echo "FAIL v2match: ruleset v1 и перевода разошёлся ($(cat "$d/args")), коды $rc1/$(cat "$d/v2.rc")"
        diff -u "$d/v1.out" "$d/v2.out" | head -n 20
        head -n 5 "$d/v2.err"
        echo "--- v2:"; head -n 40 "$d/v2.yaml"
    fi
done
[ "$total" -gt 100 ] || { fail=$((fail + 1)); echo "FAIL v2match: вызовов apply --dry-run всего $total (ждали >100)"; }
echo "v2match: перевод v1 → v2 — $same спек дали тот же ruleset, $pinned — тот же, но с закреплением соединений группы (v2), $refused отвергнуты обеими, из $total"

# ---- 2. разбор v2 ----------------------------------------------------------------------------
pass=0
BIN="$STEER_BIN"
S="--state-dir $tmp/state"
printf '203.0.113.0/24\n' > "$tmp/a.lst"
printf 'example.com\n' > "$tmp/d.lst"

ok()   { pass=$((pass + 1)); }
bad()  { fail=$((fail + 1)); printf 'FAIL v2match: %s\n' "$1"; [ -n "${2:-}" ] && printf '  %s\n' "$2"; }

y() { sed "s|TMP|$tmp|g" > "$tmp/s.yaml"; }

# warp: count печатается всегда, кроме умолчания 1 — прежде пропускалось 3 (старое умолчание), и выбор
# «3 туннеля» после круга записи и чтения становился 1.
for n in 1 2 3 5; do
    printf 'version: 2\noutputs:\n  w: { kind: warp, count: %s }\n' "$n" > "$tmp/w1.yaml"
    "$BIN" spec convert --spec "$tmp/w1.yaml" > "$tmp/w2.yaml" 2>&1
    "$BIN" spec convert --spec "$tmp/w2.yaml" > "$tmp/w3.yaml" 2>&1
    want="count: $n"; [ "$n" = 1 ] && want=""
    got="$(grep -o 'count: [0-9]*' "$tmp/w3.yaml")"
    if [ "$got" = "$want" ]; then ok; else bad "warp count: $n — после двух кругов convert «$got»"; fi
done

# Принято: код 0.
accepted() {
    if out="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"; then ok; else bad "$1" "$(echo "$out" | head -n 3)"; fi
}
# Отвергнуто: код 2 и в сообщении — строка (и место «s.yaml:СТРОКА:СТОЛБЕЦ», если задано).
refused() {
    out="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
    rc=$?
    if [ "$rc" = 2 ] && echo "$out" | grep -qF -- "$2" && { [ -z "${3:-}" ] || echo "$out" | grep -qF "s.yaml:$3:"; }; then
        ok
    else
        bad "$1" "код $rc: $out"
    fi
}

# Примеры из документов — движком с видами расширенной части (vless, xsteer): build/steer-xk,
# базовая сборка с файлами видов (Makefile). Пути в примерах относительные — от каталога стенда.
XK="${XK:-./build/steer-xk}"
if [ -x "$XK" ]; then
    XKA="$(abs "$XK")"
    mkdir -p "$tmp/lists" "$tmp/sub"
    printf '10.20.0.0/16\n' > "$tmp/lists/work.lst"
    printf 'corp.example\n' > "$tmp/lists/work.dom"
    printf '10.30.0.0/16\n' > "$tmp/lists/dc.lst"
    : > "$tmp/sub/nl"
    # Пример из docs/spec-v2.md — то, что движок принимает сегодня.
    sed -n '/^<!-- v2match:example -->/,/^```$/p' docs/spec-v2.md | sed '1,2d;$d' > "$tmp/ex.yaml"
    [ -s "$tmp/ex.yaml" ] || bad "пример в docs/spec-v2.md не найден (метка v2match:example)"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec ex.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "пример docs/spec-v2.md принят" "$(echo "$out" | head -n 3)"; fi
    # Пример раздела 3 docs/architecture.md — весь формат, включая то, чего движок ещё не умеет:
    # отказ «ещё не поддерживается», а не синтаксическая ошибка и не молчание. На роутере в нём
    # есть и настоящая ошибка — клиент-приложение (только на телефоне), — её отказ проверяется
    # первым, а дальше пример без этой строки.
    sed -n '/^## 3\. Спека v2/,/^## 4/p' docs/architecture.md | sed -n '/^```yaml$/,/^```$/p' |
        sed '1d;$d' > "$tmp/arch.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec arch.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "arch.yaml:8:16: clients.tg.app: приложения — только на телефоне"; then ok; else
        bad "пример раздела 3 на роутере — отказ «только на телефоне» с местом" "$out"; fi
    grep -v '^  tg:' "$tmp/arch.yaml" > "$tmp/arch2.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec arch2.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ещё не поддерживается в этой версии ядра steer"; then ok; else
        bad "пример раздела 3 — отказ «ещё не поддерживается»" "$out"; fi
    # balance и IPv6: член без IPv6 (VLESS с `ipv6: off`; сам VLESS IPv6 несёт) — группа без IPv6; её IPv6
    # первым правилом цепочки уходит в метку группы, а forward_v6 его отвергает (отказ, а не часть
    # соединений мимо туннеля).
    printf 'version: 2\noutputs:\n  a: { kind: interface, device: wg0 }\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, ipv6: off }\n  bal: { kind: group, pick: balance, members: [a, nl] }\nrules:\n  - { to: all, out: bal }\n' > "$tmp/bal6.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec bal6.yaml --state-dir "$tmp/state" 2>&1)"
    bm="$(echo "$out" | grep -o 'goto bal_[0-9]*' | head -n 1 | cut -d_ -f2)"
    if [ -n "$bm" ] && echo "$out" | grep -q "meta nfproto ipv6 goto mark_$bm comment \"steer-balance-v6:bal\"" &&
       echo "$out" | grep -q 'reject with icmpx type admin-prohibited comment "steer-v6drop:bal"'; then ok; else
        bad "balance с членом без IPv6 — IPv6 группы в отказ" "$(echo "$out" | grep -E 'bal_|v6' | head -n 8)"; fi
    # by: site с членом без IPv6 — хеш только по IPv4, IPv6 группы — тот же отказ.
    printf 'version: 2\noutputs:\n  a: { kind: interface, device: wg0 }\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, ipv6: off }\n  bal: { kind: group, pick: balance, by: site, members: [a, nl] }\nrules:\n  - { to: all, out: bal }\n' > "$tmp/bal6s.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec bal6s.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -q 'steer-balance-v6:bal' && echo "$out" | grep -q 'jhash ip daddr mod 120' &&
       ! echo "$out" | grep -q 'jhash ip6'; then ok; else
        bad "by: site с членом без IPv6 — jhash только IPv4" "$(echo "$out" | grep -E 'bal_|jhash|v6' | head -n 8)"; fi
    # IPv6 через туннель (I-566): VLESS несёт IPv6 — группа balance из интерфейса и VLESS раздаёт и IPv6
    # (карта v6, без отказа), jhash по ip6 daddr; TCP IPv6 перенаправляется своим правилом.
    printf 'version: 2\noutputs:\n  a: { kind: interface, device: wg0 }\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl }\n  bal: { kind: group, pick: balance, by: site, members: [a, nl] }\nrules:\n  - { to: all, out: bal }\n' > "$tmp/bal6t.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec bal6t.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -q 'jhash ip6 daddr mod 120' && ! echo "$out" | grep -q 'steer-v6drop:bal'; then ok; else
        bad "balance из интерфейса и VLESS (оба несут IPv6): IPv6 раздаётся картой, отказа нет" "$(echo "$out" | grep -E 'bal_|jhash|v6' | head -n 8)"; fi
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl }\nlists:\n  p: { prefixes_file: [lists/dc.lst] }\nrules:\n  - { to: [p], out: nl }\n' > "$tmp/redir6.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec redir6.yaml --state-dir "$tmp/state" 2>&1)"
    n4="$(echo "$out" | grep 'steer-tcp-redir' | grep -c 'ip protocol tcp meta mark and 0x0ff00000 @tcp_redir fib daddr type != local counter redirect to :meta mark and 0x0ff00000 map @tcp_redir')"
    n6="$(echo "$out" | grep 'steer-tcp-redir' | grep -c 'meta nfproto ipv6 meta l4proto tcp meta mark and 0x0ff00000 @tcp_redir fib daddr type != local counter redirect to :meta mark and 0x0ff00000 map @tcp_redir')"
    if [ "$n4 $n6" = "2 2" ]; then ok; else
        bad "VLESS: перенаправление TCP — правило IPv4 и правило IPv6 на prerouting и output" "$n4 $n6"; fi
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, ipv6: off }\nlists:\n  p: { prefixes_file: [lists/dc.lst] }\nrules:\n  - { to: [p], out: nl }\n' > "$tmp/redir6off.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec redir6off.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -q 'steer-tcp-redir' && ! echo "$out" | grep 'steer-tcp-redir' | grep -q 'nfproto ipv6'; then ok; else
        bad "VLESS с ipv6: off: правила перенаправления IPv6 нет" "$(echo "$out" | grep 'steer-tcp-redir' | head -n 4)"; fi
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, ipv6: nat }\n' > "$tmp/s.yaml"
    out="$("$XKA" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"; rc=$?
    if [ "$rc" = 2 ] && echo "$out" | grep -qF "у kind: vless есть только off"; then ok; else
        bad "ipv6: nat у туннеля — отказ «есть только off»" "код $rc: $out"; fi
    # hysteria2 (модуль steer-hysteria2): туннель по подписке, ключи как у vless, но без transport;
    # convert — неподвижная точка; `kind: hysteria2` в v2 — отказ с подсказкой.
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, nodes: [1, 0] }\n' > "$tmp/hy1.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec hy1.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "protocol: hysteria2 — принят" "$(echo "$out" | head -n 3)"; fi
    (cd "$tmp" && "$XKA" spec convert --spec hy1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'protocol: hysteria2' "$tmp/c1.yaml" && grep -q 'nodes: \[1, 0\]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает hysteria2 с nodes (неподвижная точка)" "$(grep -n hy "$tmp/c1.yaml")"; fi
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, transport: ws }\n' > "$tmp/hy2.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec hy2.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "у kind hysteria2 нет transport"; then ok; else bad "hysteria2 с transport — отказ" "$out"; fi
    printf 'version: 2\noutputs:\n  hy: { kind: hysteria2, subscription: sub/hy }\n' > "$tmp/hy3.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec hy3.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "туннель пишется kind: tunnel, protocol: hysteria2"; then ok; else bad "kind: hysteria2 в v2 — отказ с подсказкой" "$out"; fi
    # I-543: тысяча клиентов с длинным общим началом имени — печать v2 даёт каждому своё имя и кончается
    # (суффикс считался как k % 1000: остаток возвращался к занятым, и цикл не завершался).
    {
        printf '10.1.0.0/16\n' > "$tmp/many.lst"
        {
            printf 'version: 2\noutputs:\n  vpn: { kind: interface, device: wg0 }\nclients:\n'
            i=0
            while [ $i -lt 1005 ]; do
                printf '  cccccccccccccccccccccccccc%04d: { addr: [192.168.%d.%d] }\n' $i $((i / 250)) $((i % 250 + 1))
                i=$((i + 1))
            done
            printf 'lists:\n  work: { prefixes_file: %s/many.lst }\nrules:\n  - { to: work, out: vpn }\n' "$tmp"
        } > "$tmp/many.yaml"
        timeout 30 "$XKA" spec convert --spec "$tmp/many.yaml" > "$tmp/many.out" 2>&1
        mrc=$?
        mu=$(sed -n '/^clients:/,/^[a-z]/p' "$tmp/many.out" | grep -c '^  c')
        if [ "$mrc" = 0 ] && [ "$mu" = 1005 ] &&
           [ "$(sed -n '/^clients:/,/^[a-z]/p' "$tmp/many.out" | grep '^  c' | sed 's/:.*//' | sort -u | wc -l)" = 1005 ]; then ok; else
            bad "1005 клиентов с общим началом имени — печать кончается, имена различны" "rc=$mrc клиентов=$mu"; fi
    }
    # transport: у туннеля (шаг 5 выпуска 1.10) — фильтр транспортов узлов подписки: одно имя или
    # список; convert печатает его обратно (одно — строкой, несколько — списком в порядке имён) и
    # остаётся неподвижной точкой; отказы — с местом.
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, transport: ws }\n' > "$tmp/tr1.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec tr1.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "transport: ws — принят" "$(echo "$out" | head -n 3)"; fi
    (cd "$tmp" && "$XKA" spec convert --spec tr1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'transport: ws[,} ]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает transport: ws (неподвижная точка)" "$(grep -n transport "$tmp/c1.yaml")"; fi
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, transport: [httpupgrade, ws] }\n' > "$tmp/tr2.yaml"
    (cd "$tmp" && "$XKA" spec convert --spec tr2.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'transport: \[ws, httpupgrade\]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает список транспортов в порядке имён" "$(grep -n transport "$tmp/c1.yaml")"; fi
    trref() {   # имя, значение transport, строка отказа, место
        printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, transport: %s }\n' "$2" > "$tmp/tr3.yaml"
        out="$(cd "$tmp" && "$XKA" apply --dry-run --spec tr3.yaml --state-dir "$tmp/state" 2>&1)"
        rc=$?
        if [ "$rc" = 2 ] && echo "$out" | grep -qF -- "$3" && echo "$out" | grep -qF "tr3.yaml:$4:"; then ok; else
            bad "$1" "код $rc: $out"; fi
    }
    trref "transport: kcp — отказ с местом" kcp "«kcp» — нужен tcp, grpc, xhttp, ws или httpupgrade" 3:73
    trref "transport: [ws, ws] — отказ" "[ws, ws]" "ws указан дважды" 3:78
    trref "transport: [] — отказ" "[]" "пустой список" 3:73
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, transport: ws }\n' > "$tmp/tr4.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec tr4.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ключ transport есть только у kind: tunnel"; then ok; else
        bad "transport у interface — отказ «только у kind: tunnel»" "$out"; fi
    # insecure: у туннеля vless — явный отказ от проверки сертификата узлов TLS; convert печатает его
    # обратно и остаётся неподвижной точкой; у hysteria2 (там insecure — параметр ссылки) и у прочих
    # видов — отказ.
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, insecure: true }\n' > "$tmp/in1.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec in1.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "insecure: true у vless — принят" "$(echo "$out" | head -n 3)"; fi
    (cd "$tmp" && "$XKA" spec convert --spec in1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'insecure: true' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает insecure: true (неподвижная точка)" "$(grep -n insecure "$tmp/c1.yaml")"; fi
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, insecure: true }\n' > "$tmp/in2.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec in2.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "у kind hysteria2 нет insecure"; then ok; else bad "insecure у hysteria2 — отказ" "$out"; fi
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, insecure: true }\n' > "$tmp/in3.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec in3.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ключ insecure есть только у kind: tunnel"; then ok; else
        bad "insecure у interface — отказ «только у kind: tunnel»" "$out"; fi
    # exclude и exclude_name: у туннеля любого протокола — исключение узлов по стране (флаг в имени) и
    # по куску имени. convert печатает их обратно и остаётся неподвижной точкой; отказы — с местом.
    for p in "protocol: vless" "protocol: hysteria2" "protocol: trojan"; do
        printf 'version: 2\noutputs:\n  t: { kind: tunnel, %s, subscription: sub/t, exclude: [RU, NO], exclude_name: ["Мобильный", lte] }\n' "$p" > "$tmp/ex1.yaml"
        out="$(cd "$tmp" && "$XKA" apply --dry-run --spec ex1.yaml --state-dir "$tmp/state" 2>&1)"
        if [ $? = 0 ]; then ok; else bad "exclude, exclude_name у $p — приняты" "$(echo "$out" | head -n 3)"; fi
        (cd "$tmp" && "$XKA" spec convert --spec ex1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
        if grep -q 'exclude: \[RU, "NO"\], exclude_name: \["Мобильный", lte\]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
            bad "convert печатает exclude и exclude_name у $p (неподвижная точка)" "$(grep -n exclude "$tmp/c1.yaml")"; fi
    done
    printf 'version: 2\noutputs:\n  t: { kind: tunnel, protocol: vless, subscription: sub/t, exclude: DE }\n' > "$tmp/ex2.yaml"
    (cd "$tmp" && "$XKA" spec convert --spec ex2.yaml > c1.yaml 2>&1)
    if grep -q 'exclude: \[DE\]' "$tmp/c1.yaml"; then ok; else
        bad "exclude: DE — одно значение как список из одного" "$(grep -n exclude "$tmp/c1.yaml")"; fi
    exref() {   # имя, ключ: значение, строка отказа, место
        printf 'version: 2\noutputs:\n  t: { kind: tunnel, protocol: vless, subscription: sub/t, %s }\n' "$2" > "$tmp/ex3.yaml"
        out="$(cd "$tmp" && "$XKA" apply --dry-run --spec ex3.yaml --state-dir "$tmp/state" 2>&1)"
        rc=$?
        if [ "$rc" = 2 ] && echo "$out" | grep -qF -- "$3" && echo "$out" | grep -qF "ex3.yaml:$4:"; then ok; else
            bad "$1" "код $rc: $out"; fi
    }
    exref "exclude: ru — отказ с местом" "exclude: ru" "«ru» — код страны: две заглавные латинские буквы" 3:69
    exref "exclude: RUS — отказ" "exclude: [RUS]" "«RUS» — код страны: две заглавные латинские буквы" 3:70
    exref "exclude: [RU, RU] — отказ" "exclude: [RU, RU]" "RU указан дважды" 3:74
    exref "exclude_name: [a, a] — отказ" "exclude_name: [a, a]" "«a» указано дважды" 3:78
    exref "exclude_name: \"\" — отказ" 'exclude_name: [""]' "непустая строка" 3:75
    # only — узлы только этих стран: тот же разбор, печать и неподвижная точка; спор с exclude — отказ.
    printf 'version: 2\noutputs:\n  t: { kind: tunnel, protocol: vless, subscription: sub/t, only: [NL, DE], exclude_name: lte }\n' > "$tmp/on1.yaml"
    (cd "$tmp" && "$XKA" spec convert --spec on1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'only: \[NL, DE\], exclude_name: \[lte\]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает only (неподвижная точка)" "$(grep -n only "$tmp/c1.yaml")"; fi
    exref "only: nl — отказ с местом" "only: nl" "«nl» — код страны: две заглавные латинские буквы" 3:66
    exref "only: [NL, NL] — отказ" "only: [NL, NL]" "NL указан дважды" 3:71
    exref "only и exclude по одной стране — отказ" "only: [NL, DE], exclude: DE" "DE — и в only, и в exclude" 3:66
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, only: [RU] }\n' > "$tmp/on4.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec on4.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ключ only есть только у kind: tunnel"; then ok; else
        bad "only у interface — отказ «только у kind: tunnel»" "$out"; fi
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, exclude: [RU] }\n' > "$tmp/ex4.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec ex4.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ключ exclude есть только у kind: tunnel"; then ok; else
        bad "exclude у interface — отказ «только у kind: tunnel»" "$out"; fi
    # only и exclude у группы (pick: latency, order): страна живого узла члена. convert печатает их
    # обратно неподвижной точкой; у manual и balance, при споре и у не-группы — отказ с местом.
    gy() {   # имя, pick, лишние ключи
        printf 'version: 2\noutputs:\n  a: { kind: tunnel, protocol: vless, subscription: sub/a }\n  b: { kind: tunnel, protocol: vless, subscription: sub/b }\n  g: { kind: group, pick: %s, members: [a, b]%s }\nrules:\n  - { to: all, out: g }\n' "$2" "$3" > "$tmp/$1.yaml"
    }
    gy gc1 latency ', only: [NL, DE], exclude: RU'
    (cd "$tmp" && "$XKA" spec convert --spec gc1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'only: \[NL, DE\], exclude: \[RU\]' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает only и exclude группы (неподвижная точка)" "$(cat "$tmp/c1.yaml")"; fi
    gy gc2 order ', exclude: US'
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec gc2.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "exclude у группы order — принят" "$out"; fi
    gy gc3 manual ', only: NL'
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec gc3.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "выбор члена по стране, он есть только у pick: latency и order"; then ok; else
        bad "only у группы manual — отказ" "$out"; fi
    gy gc4 balance ', exclude: RU'
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec gc4.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "выбор члена по стране"; then ok; else bad "exclude у группы balance — отказ" "$out"; fi
    gy gc5 latency ', only: [NL, DE], exclude: DE'
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec gc5.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "DE — и в only, и в exclude"; then ok; else bad "only и exclude группы по одной стране — отказ" "$out"; fi
    gy gc6 latency ', only: nl'
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec gc6.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "«nl» — код страны"; then ok; else bad "only: nl у группы — отказ" "$out"; fi
    # Пул узлов туннеля (src/tunnel/pool.c): active, by, interval, silence — у vless и протоколов
    # прокси; convert печатает отличное от умолчания и остаётся неподвижной точкой; у hysteria2 — только
    # interval и silence; отказы — с местом.
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, active: 3, by: site, interval: 30, silence: 0 }\n' > "$tmp/pl1.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl1.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "active/by/interval/silence у vless — приняты" "$(echo "$out" | head -n 3)"; fi
    (cd "$tmp" && "$XKA" spec convert --spec pl1.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'active: 3, by: site, interval: 30, silence: 0' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает ключи пула (неподвижная точка)" "$(grep -n nl "$tmp/c1.yaml")"; fi
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, active: 1, by: connection, silence: 20 }\n' > "$tmp/pl2.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl2.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "by — раздача соединений между активными узлами, она есть только при active больше 1"; then ok; else
        bad "by при active: 1 — отказ" "$out"; fi
    plref() {   # имя, ключи, строка отказа, место
        printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, %s }\n' "$2" > "$tmp/pl3.yaml"
        out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl3.yaml --state-dir "$tmp/state" 2>&1)"
        rc=$?
        if [ "$rc" = 2 ] && echo "$out" | grep -qF -- "$3" && { [ -z "$4" ] || echo "$out" | grep -qF "pl3.yaml:$4:"; }; then ok; else
            bad "$1" "код $rc: $out"; fi
    }
    plref "active: 0 — отказ с местом" "active: 0" "active" 3:70
    plref "by: random — отказ с местом" "active: 2, by: random" "«random» — нужен connection, site или site_client" 3:77
    plref "interval: 2 — отказ" "interval: 2" "interval" 3:72
    plref "silence: 3 — отказ с причиной" "silence: 3" "меньше 5 с" 3:71
    plref "silence: 40000 — отказ" "silence: 40000" "silence" 3:71
    plref "active больше узлов в nodes — отказ" "nodes: [0, 1], active: 3" "active 3, а узлов в nodes 2" ""
    printf 'version: 2\noutputs:\n  tj: { kind: tunnel, protocol: trojan, subscription: sub/tj, active: 2, by: site_client }\n' > "$tmp/pl4.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl4.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "требует пакет steer-proxy" || [ "$(echo "$out" | grep -c 'active\|by')" = 0 ]; then ok; else
        bad "active/by у trojan — разбирает вид прокси (или отказ «нужен пакет»)" "$out"; fi
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, interval: 30, silence: 15 }\n' > "$tmp/pl5.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl5.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "interval/silence у hysteria2 — приняты" "$(echo "$out" | head -n 3)"; fi
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, active: 2 }\n' > "$tmp/pl6.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl6.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "у kind hysteria2 нет active больше 1"; then ok; else bad "active у hysteria2 — отказ" "$out"; fi
    # pick: latency и tolerance — самые быстрые узлы подписки (пул туннеля): convert печатает их, у
    # hysteria2 — отказ, tolerance без pick: latency — отказ; pick и tolerance у прочих видов — ключи группы.
    printf 'version: 2\noutputs:\n  nl: { kind: tunnel, protocol: vless, subscription: sub/nl, pick: latency, tolerance: 0 }\n' > "$tmp/pl8.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl8.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ]; then ok; else bad "pick: latency, tolerance: 0 у vless — приняты" "$(echo "$out" | head -n 3)"; fi
    (cd "$tmp" && "$XKA" spec convert --spec pl8.yaml > c1.yaml 2>&1 && "$XKA" spec convert --spec c1.yaml > c2.yaml 2>&1)
    if grep -q 'pick: latency, tolerance: 0' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
        bad "convert печатает pick и tolerance туннеля (неподвижная точка)" "$(grep -n nl "$tmp/c1.yaml")"; fi
    plref "pick: balance у туннеля — отказ с местом" "pick: balance" "«balance» — у туннеля нужен order или latency" 3:68
    plref "tolerance без pick: latency — отказ" "tolerance: 20" "tolerance — допуск смены узла по замеру, он есть только у pick: latency" ""
    plref "tolerance: 70000 — отказ" "pick: latency, tolerance: 70000" "tolerance — от 0 до 60000" 3:88
    printf 'version: 2\noutputs:\n  hy: { kind: tunnel, protocol: hysteria2, subscription: sub/hy, pick: latency }\n' > "$tmp/pl9.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl9.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "у kind hysteria2 пока нет pick: latency"; then ok; else bad "pick: latency у hysteria2 — отказ" "$out"; fi
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, pick: latency }\n' > "$tmp/pl10.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl10.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "pick есть только у kind: group"; then ok; else
        bad "pick у interface — прежний отказ «только у kind: group»" "$out"; fi
    printf 'version: 2\noutputs:\n  wg: { kind: interface, device: wg0, active: 2 }\n' > "$tmp/pl7.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec pl7.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | grep -qF "ключ active есть только у kind: tunnel"; then ok; else
        bad "active у interface — отказ «только у kind: tunnel»" "$out"; fi
    # kind: block — «Блок»: цепочки forward_block/output_block по метке соединения (TCP — RST,
    # остальное — ICMP запрет), без устройства и таблиц; доменный канал — режим 2 в таблице резолвера.
    printf 'bad.example\n' > "$tmp/blk.lst"
    printf '203.0.113.0/24\n' > "$tmp/blk4.lst"
    printf 'version: 2\noutputs:\n  blk: { kind: block }\nlists:\n  bd: { domains_file: %s/blk.lst }\n  bp: { prefixes_file: %s/blk4.lst }\nrules:\n  - { name: bd, to: [bd], out: blk, resolve: realip }\n  - { name: bp, to: [bp], out: blk }\n' "$tmp" "$tmp" > "$tmp/bk.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec bk.yaml --state-dir "$tmp/state" 2>&1)"
    if [ $? = 0 ] && echo "$out" | grep -q 'chain forward_block' && echo "$out" | grep -q 'chain output_block' &&
       echo "$out" | grep -q 'meta l4proto tcp counter reject with tcp reset' &&
       echo "$out" | grep -q 'reject with icmpx admin-prohibited'; then ok; else
        bad "kind: block — цепочки отказа по метке соединения" "$(echo "$out" | grep -n 'block\|reject' | head -n 8)"; fi
    if ! echo "$out" | grep -q 'ip rule.*blk\|table.*blk_'; then ok; else bad "kind: block — без таблиц маршрутизации"; fi
    tab="$(cd "$tmp" && "$XKA" dnsd-table --spec bk.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$tab" | grep -q '|blk|2|'; then ok; else bad "kind: block — доменный канал с режимом 2 (пустой адрес)" "$tab"; fi
    # Страж меток пропускает петлю: собственный сокет роутера с меткой туннельного выхода (замер члена
    # группы, over) перенаправляется к слушателю модуля и уходит в lo — прежде страж его отбрасывал.
    printf 'version: 2\noutputs:\n  t1: { kind: tunnel, protocol: vless, subscription: sub/t1 }\n  g: { kind: group, pick: latency, members: [t1] }\nlists:\n  bp: { prefixes_file: %s/blk4.lst }\nrules:\n  - { name: bp, to: [bp], out: g }\n' "$tmp" > "$tmp/lo.yaml"
    out="$(cd "$tmp" && "$XKA" apply --dry-run --spec lo.yaml --state-dir "$tmp/state" 2>&1)"
    if echo "$out" | sed -n '/chain postrouting_guard/,/^    }/p' | grep -q 'oifname "lo" return'; then ok; else
        bad "страж меток пропускает lo при перенаправлении TCP к модулю" "$(echo "$out" | sed -n '/chain postrouting_guard/,/^    }/p' | head -n 8)"; fi
    # spec convert --json: та же спека JSON-объектом; YAML → JSON → YAML — тот же текст, JSON — неподвижная точка,
    # спека читается и со стандартного ввода (--spec -).
    (cd "$tmp" && "$XKA" spec convert --spec pl8.yaml > j1.yaml && "$XKA" spec convert --json --spec j1.yaml > j.json &&
        "$XKA" spec convert --spec - < j.json > j2.yaml && "$XKA" spec convert --json --spec - < j.json > j2.json) 2>/dev/null
    if cmp -s "$tmp/j1.yaml" "$tmp/j2.yaml" && cmp -s "$tmp/j.json" "$tmp/j2.json" && grep -q '^{"version":2,' "$tmp/j.json" &&
       grep -q '"tolerance":0' "$tmp/j.json"; then ok; else bad "spec convert --json — круг YAML → JSON → YAML" "$(cat "$tmp/j.json" 2>&1 | head -c 300)"; fi
else
    bad "не собран $XK (make build/steer-xk)"
fi

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0 }
lists:
  a: { prefixes_file: TMP/a.lst }
rules:
  - { name: a, to: [a], out: vpn }
EOF
accepted "простая спека"
json="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>/dev/null)"
printf '{"version": 2, "outputs": {"vpn": {"kind": "interface", "device": "wg0"}}, "lists": {"a": {"prefixes_file": "%s/a.lst"}}, "rules": [{"name": "a", "to": ["a"], "out": "vpn"}]}\n' "$tmp" > "$tmp/s.json"
if [ "$("$BIN" apply --dry-run --spec "$tmp/s.json" $S 2>/dev/null)" = "$json" ] && [ -n "$json" ]; then ok; else bad "JSON с version: 2 — тот же ruleset, что YAML"; fi

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0, colour: red }
EOF
refused "неизвестный ключ выхода — с местом" "неизвестный ключ «colour»" 3:40

y <<'EOF'
version: 2
lan: { devices: [br-lan] }
listz: {}
EOF
refused "неизвестный раздел — с местом" "неизвестный ключ «listz» в спеке" 3:1

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0, strategy: /etc/x.opts }
EOF
refused "чужой ключ вида" "ключ strategy есть только у kind: recheck" 3:40

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { name: a, to: [nolist], out: vpn }
EOF
refused "ссылка на несуществующий список" "списка «nolist» нет в lists" 5:21

y <<'EOF'
version: 2
lists:
  a: { prefixes_file: TMP/a.lst }
rules:
  - { name: a, to: a, out: nowhere }
EOF
refused "ссылка на несуществующий выход" "выхода «nowhere» нет в outputs" 5:28

y <<'EOF'
version: 2
lists:
  a: { prefixes_file: TMP/a.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { to: a, for: [ghost], out: vpn }
EOF
refused "ссылка на несуществующего клиента" "клиента «ghost» нет в clients" 7:20

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  g1:  { kind: group, members: [wg0, g2] }
  g2:  { kind: group, members: [g1] }
EOF
refused "круг в группах" "группы замыкаются в круг (g1 → g2 → g1)" 4

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  res: { kind: group, members: [wg0, wg9] }
EOF
refused "член группы, которого нет" "выхода «wg9» нет в outputs" 4:38

y <<'EOF'
version: 2
outputs:
  a: { kind: awg, over: b }
  b: { kind: awg, over: a }
EOF
refused "круг в over" "over замыкается в круг" 3

y <<'EOF'
version: 2
outputs:
  a: { kind: awg, over: nope }
EOF
refused "over на несуществующий выход" "over: выхода «nope» нет в outputs" 3:25

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  eu:  { kind: group, pick: manual, members: [wg0, wg1], default: wg1 }
EOF
accepted "pick: manual с default"

# Шаг 3 из 1.9: вложенность, balance с весами, urltest — принимаются; balance в ruleset — переход
# в цепочку группы, карта numgen и метка соединения.
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  in:  { kind: group, members: [wg0, wg1] }
  out: { kind: group, members: [in, wg1] }
  bal: { kind: group, pick: balance, members: [in, wg1], weights: [3, 1] }
  lat: { kind: group, pick: latency, members: [wg0, out], url: "http://1.1.1.1:8080/generate_204", idle_timeout: 0 }
rules:
  - { name: b, to: all, out: bal }
EOF
accepted "группа в группе, balance с весами, url и idle_timeout"
out="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if echo "$out" | grep -q 'counter goto bal_[0-9]* comment "steer:bal_all"' &&
   echo "$out" | grep -q 'numgen random mod 120 vmap @balmap_' &&
   echo "$out" | grep -q 'ct mark set mark comment "steer-mark:in"' &&
   [ "$(echo "$out" | grep -o 'goto mark_[0-9]*' | sort -u | wc -l)" -ge 3 ]; then ok; else
    bad "balance: goto в цепочку группы, карта numgen, метки членов" "$(echo "$out" | head -n 20)"; fi

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  bal: { kind: group, pick: balance, members: [wg0, wg1] }
  res: { kind: group, pick: order, members: [bal, wg1] }
EOF
refused "balance членом order — отказ" "группа pick: balance, а членом группы pick: order" 6

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  bal: { kind: group, pick: balance, members: [wg0, wg1], weights: [1] }
EOF
refused "weights не по числу членов" "весов 1, а членов 2" 5

# by: site и site_client — слот по хешу адресов вместо numgen (balance.c); convert печатает by, и
# напечатанное — неподвижная точка; by не у balance и неверное значение — отказ с местом.
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  st:  { kind: group, pick: balance, by: site, members: [wg0, wg1] }
  sc:  { kind: group, pick: balance, by: site_client, members: [wg0, wg1], weights: [1, 2] }
rules:
  - { name: s, to: all, out: st }
  - { name: c, to: all, out: sc }
EOF
accepted "balance by: site и by: site_client"
out="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if echo "$out" | grep -q 'meta nfproto ipv4 jhash ip daddr mod 120 seed 0x[0-9a-f]* vmap @balmap_[0-9]* comment "steer-balance:st"' &&
   echo "$out" | grep -q 'meta nfproto ipv6 jhash ip6 daddr mod 120 seed 0x[0-9a-f]* vmap @balmap_[0-9]* comment "steer-balance:st"' &&
   echo "$out" | grep -q 'meta nfproto ipv4 jhash ip saddr . ip daddr mod 120 seed 0x[0-9a-f]* vmap @balmap_[0-9]* comment "steer-balance:sc"' &&
   echo "$out" | grep -q 'meta nfproto ipv6 jhash ip6 saddr . ip6 daddr mod 120 seed 0x[0-9a-f]* vmap @balmap_[0-9]* comment "steer-balance:sc"' &&
   ! echo "$out" | grep -q 'numgen'; then ok; else
    bad "by: site/site_client — jhash по обоим семействам, без numgen" "$(echo "$out" | grep -E 'jhash|numgen' | head -n 8)"; fi
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/by1.yaml" 2>&1
"$BIN" spec convert --spec "$tmp/by1.yaml" > "$tmp/by2.yaml" 2>&1
if grep -q 'pick: balance, members: \[wg0, wg1\], by: site }' "$tmp/by1.yaml" &&
   grep -q 'weights: \[1, 2\], by: site_client }' "$tmp/by1.yaml" && cmp -s "$tmp/by1.yaml" "$tmp/by2.yaml"; then ok; else
    bad "convert печатает by (неподвижная точка)" "$(grep -n balance "$tmp/by1.yaml")"; fi

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  o:   { kind: group, pick: order, members: [wg0, wg1], by: site }
EOF
refused "by не у balance — отказ" "by — как раздавать соединения, он есть только у pick: balance" 5

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  b:   { kind: group, pick: balance, members: [wg0, wg1], by: dst }
EOF
refused "by неверный — отказ" "«dst» — нужен connection, site или site_client" 5

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  m: { kind: group, pick: manual, members: [wg0, wg1], url: "http://x/generate_204" }
EOF
refused "url не у latency" "url — замер задержки, он есть только у pick: latency" 5

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  l: { kind: group, pick: latency, members: [wg0, wg1], url: "ftp://x/" }
EOF
refused "url не http/https" "outputs.l.url:" 5

y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  l: { kind: group, pick: latency, members: [wg0, wg1], url: "https://www.gstatic.com/generate_204" }
EOF
refused "https в сборке без TLS — отказ с понятным текстом" "https:// в этой сборке нет (сборка без TLS)" 5

y <<'EOF'
version: 2
dns:
  mode: fakeip
  cache: 2048
EOF
accepted "dns.cache (с 1.11)"

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0 }
dns:
  bootstrap: [1.1.1.1]
  upstream: doh
  upstreams:
    doh: { url: https://dns.google/dns-query, out: vpn }
    dot: { url: "tls://1.1.1.1" }
EOF
accepted "dns.upstreams, bootstrap и общий upstream (с 1.11)"

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0 }
dns:
  upstreams:
    doh: { url: https://dns.google/dns-query, out: vpn }
EOF
refused "имя сервера DoH без ips и bootstrap — отказ" "нечем разрешить" 6

y <<'EOF'
version: 2
dns:
  upstreams:
    doq: { url: "quic://1.1.1.1" }
EOF
accepted "DoQ (quic://) — принят (с 1.11)"

y <<'EOF'
version: 2
dns:
  upstreams:
    doq: { url: "quic://dns.test" }
EOF
refused "имя сервера DoQ без ips и bootstrap — отказ" "нечем разрешить" 4

y <<'EOF'
version: 2
dns:
  upstreams:
    doq: { url: "doq://dns.test", ips: [192.0.2.1] }
EOF
refused "doq:// — не схема" "нужен адрес вида" 4

y <<'EOF'
version: 2
dns:
  upstreams:
    h3: { url: "h3://dns.google/dns-query", ips: [8.8.8.8] }
    h3p: { url: "h3://1.1.1.1:8443/q" }
EOF
accepted "DoH3 (h3://) — принят"

y <<'EOF'
version: 2
dns:
  upstreams:
    h3: { url: "h3://dns.test" }
EOF
refused "имя сервера DoH3 без ips и bootstrap — отказ" "нечем разрешить" 4

y <<'EOF'
version: 2
dns:
  upstreams:
    q: { url: "quic://dns.test/x", ips: [192.0.2.1] }
EOF
refused "путь у quic:// — отказ, и подсказка называет h3://" "только у https:// и h3://" 4

# Адреса IPv6 клиентов и lan законны с 1.9 (docs/architecture.md, «4б»): правило получает
# v6-двойник, convert печатает адреса как есть.
y <<'EOF'
version: 2
lan: { addr: [192.168.1.0/24, "fd00:1::/64"] }
clients:
  v6: { addr: [192.168.1.5, "fd00::5"] }
lists:
  a: { prefixes_file: TMP/a.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { for: v6, to: a, out: vpn }
EOF
accepted "адреса IPv6 в clients и lan — приняты"
out6="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if echo "$out6" | grep -q 'ip saddr { 192.168.1.5 } ip daddr @vpn_ip' &&
   echo "$out6" | grep -q 'ip6 saddr fd00:1::/64 udp dport 53'; then ok
else bad "адреса IPv6 — правило IPv4 без них, заворот DNS по подсети IPv6 lan" "$(echo "$out6" | head -n 30)"; fi
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c6.yaml" 2>&1
if grep -q 'addr: \[192.168.1.5, fd00::5\]' "$tmp/c6.yaml" && grep -q 'fd00:1::/64' "$tmp/c6.yaml"; then ok
else bad "convert печатает адреса IPv6 клиентов и lan (в addr, не в mac)" "$(head -n 20 "$tmp/c6.yaml")"; fi
"$BIN" spec convert --spec "$tmp/c6.yaml" > "$tmp/c6b.yaml" 2>&1
if cmp -s "$tmp/c6.yaml" "$tmp/c6b.yaml"; then ok
else bad "convert с адресами IPv6 — неподвижная точка" "$(head -n 20 "$tmp/c6b.yaml")"; fi
y <<'EOF'
version: 2
clients:
  v6: { addr: ["fd00::/129"] }
EOF
refused "адрес IPv6 с негодной длиной — отказ" "не адрес IPv4 или IPv6" 3:16

y <<'EOF'
version: 2
lists:
  w: { domains: [corp.example] }
EOF
refused "встроенные домены — ещё не поддерживается" "встроенные domains" 3:17

y <<'EOF'
version: 2
outputs:
  vpn: { kind: interface, device: wg0 }
  bad: { kind: group, members: [vpn] }
EOF
accepted "группа из одного члена"

y <<'EOF'
version: 2
outputs:
  nl: { kind: vless, subscription: /tmp/x }
EOF
refused "kind: vless — подсказка про tunnel" "kind: tunnel, protocol: vless" 3:15

y <<'EOF'
version: 3
EOF
refused "version 3" "version 3 не поддерживается" 1:10

y <<'EOF'
lan: { devices: [br-lan] }
EOF
refused "YAML без version" "нет version: 2" 1:1

printf '{"schema": 1, "version": 2}\n' > "$tmp/s.yaml"
refused "и version, и schema" "и version, и schema"

y <<'EOF'
version: 2
clients:
  kids: { mac: [aa:bb:cc:dd:ee:01] }
  tv:   { mac: [aa:bb:cc:dd:ee:02] }
lists:
  a: { prefixes_file: TMP/a.lst }
  d: { domains_file: TMP/d.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { name: a, for: [kids, tv], to: [a, d], out: vpn, resolve: realip }
EOF
accepted "несколько клиентов одного вида и списков без сужения — сводятся"
got="$("$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>/dev/null | grep -c 'ether saddr { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 }')"
[ "$got" -ge 1 ] && ok || bad "сведённый клиент — оба MAC в одном правиле" "$got"

y <<'EOF'
version: 2
clients:
  kids: { mac: [aa:bb:cc:dd:ee:01] }
  tv:   { addr: [192.168.1.50] }
lists:
  a: { prefixes_file: TMP/a.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { name: a, for: [kids, tv], to: a, out: vpn }
EOF
refused "клиенты разных видов в одном for — ещё не поддерживается" "клиенты разных видов" 10:21

y <<'EOF'
version: 2
lists:
  a: { prefixes_file: TMP/a.lst, ports: [443, 400-500] }
EOF
refused "пересечение портов" "диапазоны 443-443 и 400-500 пересекаются" 3

# Телефон: приложения по UID и весь телефон; на роутере — отказ.
y <<'EOF'
version: 2
clients:
  tg:  { uid: [10123, 10200-10210] }
  me:  { self: true }
lists:
  a: { prefixes_file: TMP/a.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { name: tg, for: tg, to: a, out: vpn }
  - { name: me, for: me, to: all, out: vpn }
EOF
if out="$("$ANDROID_BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)" &&
   echo "$out" | grep -qF 'meta skuid'; then ok; else bad "телефон: uid и self" "$(echo "$out" | head -n 3)"; fi
refused "uid на роутере" "clients.tg.uid: приложения (uid) — только на телефоне" 3:15

# Относительный путь — от каталога файла спеки, а не от рабочего каталога.
mkdir -p "$tmp/rel/lists"
printf '198.51.100.0/24\n' > "$tmp/rel/lists/r.lst"
cat > "$tmp/rel/s.yaml" <<'EOF'
version: 2
lists:
  r: { prefixes_file: lists/r.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
rules:
  - { to: r, out: vpn }
EOF
"$BIN" apply --dry-run --spec "$tmp/rel/s.yaml" $S 2>&1 | grep -qF '198.51.100.0/24' && ok ||
    bad "относительный путь списка — от каталога спеки"

# Файл спеки по умолчанию ({etc} платформы на стенде не подменить) — справка его называет.
"$BIN" help apply 2>&1 | grep -qF 'spec.yaml' && ok || bad "справка --spec называет spec.yaml"

# convert печатает v2, который разбирается обратно (v2 → v2 — неподвижная точка).
y <<'EOF'
version: 2
clients:
  tv: { addr: [192.168.1.50] }
lists:
  a: { prefixes_file: TMP/a.lst, proto: udp, ports: [50000-65535] }
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  res: { kind: group, pick: latency, members: [wg0, wg1], tolerance: 80, on_fail: direct }
rules:
  - { name: "голос", for: tv, to: a, out: res, scope: device }
EOF
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>&1 && "$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>&1
if cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml" && grep -q 'tolerance: 80' "$tmp/c1.yaml"; then ok; else bad "convert v2 → v2 — неподвижная точка" "$(head -n 20 "$tmp/c1.yaml")"; fi

# tolerance: 0 — настоящий ноль («выигрыш любой величины значим»), а не «не задан»: convert печатает его у
# группы, где он написан, и не придумывает допуск группе без него; напечатанное читается обратно.
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  wg1: { kind: interface, device: wg1 }
  strict: { kind: group, pick: latency, members: [wg0, wg1], tolerance: 0 }
  plain: { kind: group, pick: latency, members: [wg0, wg1] }
rules:
  - { to: all, out: strict }
EOF
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c3.yaml" 2>&1 && "$BIN" spec convert --spec "$tmp/c3.yaml" > "$tmp/c4.yaml" 2>&1
if cmp -s "$tmp/c3.yaml" "$tmp/c4.yaml" && grep 'strict:' "$tmp/c3.yaml" | grep -q 'tolerance: 0' &&
   ! grep 'plain:' "$tmp/c3.yaml" | grep -q tolerance; then ok; else
    bad "convert: tolerance: 0 печатается, у группы без допуска — нет" "$(head -n 20 "$tmp/c3.yaml")"; fi

# Ключ ipv6 у выхода (шаг 8 выпуска 1.10): режимы, prefix и отказы с местом.
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: routed, prefix: "2001:db8:1::/56" }
  wg1: { kind: interface, device: wg1, ipv6: nat }
  wg2: { kind: interface, device: wg2, ipv6: off }
lists:
  a: { prefixes_file: TMP/a.lst }
rules:
  - { to: a, out: wg0 }
EOF
accepted "ipv6: routed с prefix, nat и off"
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>&1 && "$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>&1
if cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml" && grep -q 'ipv6: routed, prefix: 2001:db8:1::/56 }' "$tmp/c1.yaml" &&
   grep -q 'ipv6: nat' "$tmp/c1.yaml" && grep -q 'ipv6: "off"' "$tmp/c1.yaml"; then ok; else
    bad "convert печатает ключ ipv6 и prefix (неподвижная точка)" "$(grep -n ipv6 "$tmp/c1.yaml")"; fi
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: bridged }
EOF
refused "ipv6: неизвестный режим — с местом" "outputs.wg0.ipv6: «bridged» — нужен routed, nat или off" 3:46
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: nat, prefix: "2001:db8:1::/56" }
EOF
refused "prefix без ipv6: routed" "prefix — префикс хоста, он есть только у ipv6: routed" 3:59
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: routed, prefix: "2001:db8:1::1/56" }
EOF
refused "prefix с битами хоста" "у префикса ненулевые биты хоста: сеть этой длины — 2001:db8:1::/56" 3:62
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: routed, prefix: "2001:db8:1::/80" }
EOF
refused "prefix длиннее /64" "длина префикса от 1 до 64" 3:62
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0, ipv6: routed }
  wg1: { kind: interface, device: wg1, ipv6: routed }
EOF
refused "два донора IPv6" "outputs.wg1.ipv6: routed уже у выхода wg0 — донор IPv6 в спеке один" 4:46
y <<'EOF'
version: 2
outputs:
  tg: { kind: tgws, domain: example.com, ipv6: off }
EOF
refused "ipv6 у вида без IPv6" "kind: tgws IPv6 не несёт" 3:42
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  g: { kind: group, pick: order, members: [wg0], ipv6: routed }
EOF
refused "ipv6: routed у группы" "outputs.g.ipv6: routed — свойство туннеля на том конце, у группы его нет" 4:56
y <<'EOF'
version: 2
outputs:
  wg0: { kind: interface, device: wg0 }
  g: { kind: group, pick: order, members: [wg0], ipv6: off }
lists:
  a: { prefixes_file: TMP/a.lst }
rules:
  - { to: a, out: g }
EOF
accepted "ipv6: off у группы"

# ---- R-050: «РФ напрямую, всё остальное в туннель» — порядок правил, отдельного ключа нет ------
# Правило выше сильнее: список РФ в direct встаёт первым и заканчивает разбор пакета без метки,
# `to: all` ниже получает остальное.
printf '203.0.113.0/24\n' > "$tmp/ru.lst"
y <<'EOF'
version: 2
lan: { devices: [br-lan], addr: [192.168.1.0/24] }
lists:
  ru: { prefixes_file: TMP/ru.lst }
outputs:
  direct: { kind: direct }
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: ru-direct, to: [ru], out: direct }
  - { name: rest, to: all, out: wg0 }
EOF
accepted "инверсный режим: РФ напрямую, остальное в туннель"
out="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
l1="$(echo "$out" | grep -n 'ip daddr @direct_ip counter return comment "steer:direct_ip"' | head -n 1 | cut -d: -f1)"
l2="$(echo "$out" | grep -n 'meta mark set .* comment "steer:wg0_all"' | head -n 1 | cut -d: -f1)"
if [ -n "$l1" ] && [ -n "$l2" ] && [ "$l1" -lt "$l2" ]; then ok; else
    bad "инверсный режим — direct для РФ раньше метки to: all" "$(echo "$out" | grep -n 'steer:' | head -n 6)"; fi

# ---- quic: block — UDP/443 к назначениям правила отвергается до разметки той же группы ----------
printf 'example.org\n' > "$tmp/qd.dom"
y <<'EOF'
version: 2
lan: { devices: [br-lan], addr: [192.168.1.0/24] }
lists:
  ru: { prefixes_file: TMP/ru.lst }
  dm: { domains_file: TMP/qd.dom }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: ru, to: [ru], out: wg0, quic: block }
  - { name: dm, to: [dm], out: wg0 }
  - { name: rest, to: all, out: wg0, quic: block }
EOF
accepted "quic: block у правил со списком адресов и «весь трафик»"
out="$(STEER_NFT_INGRESS=all "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
q1="$(echo "$out" | grep -n 'steer-quic:wg0_ip_c0_p1"' | head -n 1 | cut -d: -f1)"
m1="$(echo "$out" | grep -n 'comment "steer:wg0_ip_c0_p1"' | head -n 1 | cut -d: -f1)"
if [ -n "$q1" ] && [ -n "$m1" ] && [ "$q1" -lt "$m1" ] &&
   echo "$out" | grep -q 'ip daddr @wg0_ip_c0_p1 meta l4proto udp th dport 443 counter reject with icmpx admin-prohibited'; then ok; else
    bad "quic: block — отказ UDP/443 по набору правила раньше его метки" "$(echo "$out" | grep -n 'quic\|wg0_ip' | head -n 6)"; fi
if echo "$out" | grep -q 'ip daddr != { 10.0.0.0/8.*th dport 443 counter reject.*steer-quic:wg0_all_c0_p1' &&
   echo "$out" | grep -q 'ip6 daddr != { ::1, fe80::/10, fc00::/7, ff00::/8 }.*th dport 443 counter reject.*steer-quic:wg0_all_c0_p1'; then ok; else
    bad "quic: block у «весь трафик» — свои сети не затронуты, оба семейства" "$(echo "$out" | grep 'quic:wg0_all' | head -n 4)"; fi
# Правило dm без quic — своя группа и свой набор: QUIC к его доменам не трогается.
if ! echo "$out" | grep -q 'steer-quic:wg0_dom'; then ok; else bad "quic: block не заходит в соседнее правило без ключа" "$(echo "$out" | grep 'steer-quic' | head -n 6)"; fi
# reject на ingress невозможен — разметка на ingress при таком правиле не ставится.
if ! echo "$out" | grep -q 'hook ingress'; then ok; else bad "quic: block — без разметки на ingress"; fi
# Спека без ключа — без правил отказа.
sed 's/, quic: block//' "$tmp/s.yaml" > "$tmp/s0.yaml"
out0="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s0.yaml" $S 2>&1)"
if ! echo "$out0" | grep -q 'steer-quic'; then ok; else bad "без quic: block правил steer-quic нет"; fi
# Домен: резолвер кладёт адреса в тот же набор, что и правило отказа.
y <<'EOF'
version: 2
lists:
  dm: { domains_file: TMP/qd.dom }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: dm, to: [dm], out: wg0, quic: block }
EOF
out="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
tab="$("$BIN" dnsd-table --spec "$tmp/s.yaml" $S 2>&1)"
sn="$(echo "$tab" | grep -o 'wg0_dom_c0_p[0-9]*' | head -n 1)"
if [ -n "$sn" ] && echo "$out" | grep -q "ip daddr @$sn meta l4proto udp th dport 443 counter reject"; then ok; else
    bad "quic: block у доменов — набор резолвера и набор правила отказа один" "таблица: $tab"; fi
# convert — неподвижная точка, ключ печатается, оригинальный список не размножается.
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>/dev/null
"$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>/dev/null
if grep -q 'quic: block' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml" && [ "$(grep -c '^  dm' "$tmp/c1.yaml")" = 1 ]; then ok; else
    bad "quic: block — spec convert неподвижен и без копий списка" "$(cat "$tmp/c1.yaml")"; fi
y <<'EOF'
version: 2
lists:
  dm: { domains_file: TMP/qd.dom }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: dm, to: [dm], out: wg0, quic: off }
EOF
refused "quic: неизвестное значение" "«off» — нужен block"
y <<'EOF'
version: 2
lists:
  t: { domains_file: TMP/qd.dom, proto: tcp }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: t, to: [t], out: wg0, quic: block }
EOF
refused "quic: block у списка только tcp" "список только tcp — QUIC это UDP"
y <<'EOF'
version: 2
lists:
  t: { domains_file: TMP/qd.dom, proto: udp, ports: [80, 8000-9000] }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: t, to: [t], out: wg0, quic: block }
EOF
refused "quic: block у списка без порта 443" "порты списка не содержат 443"
y <<'EOF'
version: 2
lists:
  s: { srs: TMP/x.srs }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: s, to: [s], out: wg0, quic: block }
EOF
refused "quic: block у списка srs — ещё не поддерживается" "ещё не поддерживается"


# ---- family / on_family_unavailable — политика семейства IP правила (R-154) ----------------------
printf 'example.com\n' > "$tmp/fd.dom"
printf '203.0.113.0/24\n2001:db8:5::/48\n' > "$tmp/fp.lst"
y <<'EOF'
version: 2
lan: { devices: [br-lan] }
lists:
  web: { domains_file: TMP/fd.dom }
  nets: { prefixes_file: TMP/fp.lst }
outputs:
  wg0: { kind: interface, device: wg0 }
  off: { kind: interface, device: wg1, ipv6: off }
rules:
  - { name: r4, to: [web], out: wg0, family: 4 }
  - { name: r6, to: [nets], out: wg0, family: 6 }
  - { name: rf, to: [web], out: off, family: 6 }
  - { name: rb, to: [web], out: off, family: 6, on_family_unavailable: block }
  - { name: ra, to: all, out: wg0, family: 4 }
EOF
accepted "family и on_family_unavailable — принимаются"
out="$(STEER_NFT_INGRESS=all "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
tab="$("$BIN" dnsd-table --spec "$tmp/s.yaml" $S 2>&1)"
# Хвост имени набора: v — только IPv4, w — только IPv6 с запасом, k — без запаса; наборы разные.
if echo "$out" | grep -q 'set wg0_domv {' && echo "$out" | grep -q 'set wg0_ipw {' &&
   echo "$out" | grep -q 'set off_domw {' && echo "$out" | grep -q 'set off_domk {'; then ok; else bad "политика семейства — наборы с хвостом v/w/k" "$(echo "$out" | grep 'set ')"; fi
# family: 4 — правила IPv6 у набора нет; family: 6 — правила IPv4 нет, только поиск в наборе IPv6.
if ! echo "$out" | grep -q 'ip6 daddr @wg0_domv6' && echo "$out" | grep -q 'ip6 daddr @wg0_ipw6.*steer:wg0_ipw"' &&
   ! echo "$out" | grep -q 'ip daddr @wg0_ipw '; then ok; else
    bad "family: 4 без IPv6-правила, family: 6 без IPv4-правила" "$(echo "$out" | grep 'steer:wg0')"; fi
# «весь трафик» с family: 4 — правило только для IPv4 и отказ IPv6 клиентов (не утечка), без ingress.
if echo "$out" | grep -q 'meta nfproto ipv4 meta mark set .*steer:wg0_allv"' &&
   echo "$out" | grep -q 'meta nfproto ipv6 ip6 daddr != .*reject with icmpx type admin-prohibited comment "steer-v6fam:wg0_allv"'; then ok; else
    bad "to: all, family: 4 — IPv4 в выход, IPv6 отвергнут" "$(echo "$out" | grep 'allv')"; fi
if ! echo "$out" | grep -q 'hook ingress'; then ok; else bad "отказ IPv6 по политике — без разметки на ingress"; fi
# Резолвер: семейства канала — 4 / 4 (запас) / блок (режим 2, семейство 6).
if echo "$tab" | grep -q '^wg0_domv|wg0|0|4|r4|' && echo "$tab" | grep -q '^off_domw|off|0|4|rf|' &&
   echo "$tab" | grep -q '^off_domk|off|2|6|rb|'; then ok; else bad "таблица резолвера: family, fallback, block" "$tab"; fi
# convert неподвижен и печатает оба ключа.
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>/dev/null
"$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>/dev/null
if grep -q 'family: 4' "$tmp/c1.yaml" && grep -q 'family: 6, on_family_unavailable: block' "$tmp/c1.yaml" &&
   ! grep -q 'family: both' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
    bad "family — spec convert неподвижен, умолчание не печатается" "$(grep family "$tmp/c1.yaml")"; fi
# Спека без ключей — ни хвостов, ни отказа steer-v6fam.
sed -e 's/, family: [46]//' -e 's/, on_family_unavailable: block//' "$tmp/s.yaml" > "$tmp/s0.yaml"
out0="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s0.yaml" $S 2>&1)"
if ! echo "$out0" | grep -q 'steer-v6fam'; then ok; else bad "без family правил steer-v6fam нет"; fi
y <<'EOF'
version: 2
lists:
  d: { domains_file: TMP/fd.dom }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: d, to: [d], out: wg0, family: 5 }
EOF
refused "family: 5 — отказ" "нужен 4, 6 или both"
sed -i 's/family: 5/on_family_unavailable: maybe/' "$tmp/s.yaml"
refused "on_family_unavailable: maybe — отказ" "нужен block или fallback"
sed -i 's/on_family_unavailable: maybe/family: 4, on_family_unavailable: block/' "$tmp/s.yaml"
refused "block без family: 6 — отказ" "действует только при family: 6"
y <<'EOF'
version: 2
lists:
  s: { srs: TMP/x.srs }
outputs:
  wg0: { kind: interface, device: wg0 }
rules:
  - { name: s, to: [s], out: wg0, family: 6 }
EOF
refused "family: 6 у списка srs — ещё не поддерживается" "ещё не поддерживается"

# ---- dns.mesh_clients (I-273): заворот DNS клиентов mesh-VPN — только по просьбе ----------------
printf 'a.example\n' > "$tmp/mesh.dom"
y <<'EOF'
version: 2
lists:
  m: { domains_file: TMP/mesh.dom }
outputs:
  wg0: { kind: interface, device: wg0 }
dns:
  mesh_clients: true
rules:
  - { name: m, to: [m], out: wg0 }
EOF
accepted "dns.mesh_clients: true — принимается"
out="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if echo "$out" | grep -q 'iifname { "tailscale\*", "zt\*" } udp dport 53 counter redirect to :5300' &&
   echo "$out" | grep -q 'iifname { "tailscale\*", "zt\*" } tcp dport 53 counter redirect to :5300'; then ok; else
    bad "mesh_clients: true — заворот UDP и TCP :53 с tailscale*/zt*" "$(echo "$out" | grep -A8 'chain prerouting_dns')"; fi
"$BIN" spec convert --spec "$tmp/s.yaml" > "$tmp/c1.yaml" 2>/dev/null
"$BIN" spec convert --spec "$tmp/c1.yaml" > "$tmp/c2.yaml" 2>/dev/null
if grep -q 'mesh_clients: true' "$tmp/c1.yaml" && cmp -s "$tmp/c1.yaml" "$tmp/c2.yaml"; then ok; else
    bad "mesh_clients — spec convert печатает поле и неподвижен" "$(grep -n mesh "$tmp/c1.yaml")"; fi
sed -i 's/mesh_clients: true/mesh_clients: false/' "$tmp/s.yaml"
out="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if ! echo "$out" | grep -q 'tailscale\*" } udp dport 53'; then ok; else bad "mesh_clients: false — завората нет"; fi
sed -i '/mesh_clients/d;/^dns:/d' "$tmp/s.yaml"
out="$(STEER_NFT_INGRESS=0 "$BIN" apply --dry-run --spec "$tmp/s.yaml" $S 2>&1)"
if ! echo "$out" | grep -q 'tailscale\*" } udp dport 53'; then ok; else bad "без mesh_clients завората нет (умолчание)"; fi
y <<'EOF'
version: 2
dns:
  mesh_clients: maybe
EOF
refused "dns.mesh_clients: maybe — отказ" "mesh_clients"


echo "v2match: разбор v2 — $pass проверок прошли"
if [ "$fail" -gt 0 ]; then echo "v2match: ПРОВАЛЕНО $fail"; exit 1; fi
exit 0
