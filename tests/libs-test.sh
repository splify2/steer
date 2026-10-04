#!/bin/sh
# Разделяемая раскладка роутера на хосте (шаг 4 выпуска 1.10, build/build-libs.sh): собирается то же,
# что кладёт в пакеты build.sh, — libsteer-wolfssl.so, libsteer.so, steerd и четыре модуля, —
# только хостовым компилятором, и проверяется как устроенное целое:
#
#   • списки экспорта (build/libsteer.map, build/wolfssl/libsteer-wolfssl.map) сходятся с кодом, а
#     в .dynsym библиотек лежит ровно то, что в списках, — никаких yaml_*, wolfSSL_* и прочего;
#   • SONAME по версии движка, у модулей единственный NEEDED из наших — libsteer.so.<версия>, у
#     libsteer — libsteer-wolfssl.so.<версия wolfSSL>; в модуле нет ни failover.c, ни модели;
#   • команды модулей через steerd: без модуля — отказ со словами «нужен пакет steer-vless» и
#     контрактной подстрокой steer-extended, с модулем — steerd запускает его и отвечает ровно
#     тем же (вывод и код выхода), что сам модуль;
#   • hello: первое сообщение модуля в линию событий — версия его сборки;
#   • ABI между библиотеками: libsteer при загрузке сверяет отпечаток libsteer-wolfssl.so, и
#     библиотека другой сборки — отказ со строкой, а не порча памяти;
#   • снимок генератора динамическим steerd (139 снимков) — ядро в раскладке пакета ведёт себя
#     так же, как статическое.
#
# wolfSSL — те же исходники, что у tests/ext-test.sh (STEER_WOLFSSL или $BUILD/wolfssl-host/src);
# нет их — громкий пропуск, как там. Зовёт этот стенд tests/ext-test.sh в конце и `make libs-test`.
set -u
BUILD=${BUILD:-build}
CC=${CC:-cc}
WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
if [ ! -f "$WSRC/wolfssl/wolfcrypt/settings.h" ]; then
    echo "libs-test: исходников wolfSSL нет ($WSRC) — ПРОПУСК (это не падение)."
    exit 0
fi
# ngtcp2 с патчем — тем же деревом, что у ext-test (STEER_NGTCP2 или $BUILD/ngtcp2-host/src); не
# нашлось — пробуем скачать, как ext-test, и без него libsteer не собрать: тот же громкий пропуск.
NSRC="${STEER_NGTCP2:-$BUILD/ngtcp2-host/src}"
if [ ! -f "$NSRC/lib/ngtcp2_brutal.c" ] && [ -z "${STEER_NGTCP2:-}" ]; then
    sh build/ngtcp2/fetch.sh "$NSRC" >/dev/null 2>&1
fi
if [ ! -f "$NSRC/lib/ngtcp2_brutal.c" ]; then
    echo "libs-test: исходников ngtcp2 нет ($NSRC) — ПРОПУСК (это не падение)."
    exit 0
fi
VER="$(cat VERSION)"
WVER="$(sh build/wolfssl/fetch.sh version)"
L="$BUILD/libs-host"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

echo "libs-test: собираю раскладку в $L ..."
mkdir -p "$BUILD"
rm -rf "$L"
# В образе сборщика компилятор — zig: у его драйвера свои ограничения на флаги компоновщика
# (ZIG=1 в build/build-libs.sh).
case "$CC" in zig*) ZIG=1; AR="zig ar"; export ZIG AR ;; esac
if ! CC="$CC" LIBS="-lpthread -ldl -lm" WOLFSSL_DIR="$WSRC" NGTCP2_DIR="$NSRC" JOBS="$(nproc 2>/dev/null || echo 4)" \
        sh build/build-libs.sh "$L" "$VER" "libs-test" > "$L.log" 2>&1; then
    echo "libs-test: сборка не удалась:"; grep -m10 -i "error\|undefined" "$L.log"
    exit 1
fi
LD_LIBRARY_PATH="$L"; export LD_LIBRARY_PATH
SO="$L/libsteer.so.$VER"; WSO="$L/libsteer-wolfssl.so.$WVER"

# ---- списки экспорта и таблица символов -----------------------------------------------------
if command -v nm >/dev/null 2>&1; then
    STEER_WOLFSSL="$WSRC" STEER_NGTCP2="$NSRC" BUILD="$BUILD" CC="$CC" sh build/libs-exports.sh check > "$L.exp" 2>&1
    check "списки экспорта сходятся с кодом" "0" "$?"
    want="$(sed -n 's/^ *\([A-Za-z_0-9]*\);$/\1/p' build/libsteer.map | sort)"
    # nm -D печатает версию символа (имя@@LIBSTEER_1) — её отрезаем.
    have="$(nm -D --defined-only "$SO" | awk '$2 ~ /^[TDBRVW]$/ {sub(/@.*/, "", $3); print $3}' | sort)"
    check "в .dynsym libsteer — ровно список build/libsteer.map" "$want" "$have"
    check "  и в нём нет ни libyaml, ни wolfSSL" "0" \
        "$(printf '%s\n' "$have" | grep -c '^yaml_\|^wc_\|^wolfSSL_')"
    wwant="$(sed -n 's/^ *\([A-Za-z_0-9]*\);$/\1/p' build/wolfssl/libsteer-wolfssl.map | sort)"
    whave="$(nm -D --defined-only "$WSO" | awk '$2 ~ /^[TDBRVW]$/ {sub(/@.*/, "", $3); print $3}' | sort)"
    check "в .dynsym libsteer-wolfssl — ровно список её карты" "$wwant" "$whave"
    for m in steer-vless steer-xsteer steer-obfs steer-tgws steer-hysteria2; do
        check "$m: в модуле нет failover.c (маршрут ставит демон)" "0" \
            "$(nm "$L/$m" 2>/dev/null | grep -c ' bind_device$\| table_bind$')"
        check "$m: в модуле нет разбора спеки (модель — в libsteer)" "0" \
            "$(nm "$L/$m" 2>/dev/null | grep -c ' load_spec$\| v2_parse')"
    done
else
    echo "libs-test: nm нет — таблицы символов не проверены (ПРОПУСК этих проверок)"
fi
if command -v readelf >/dev/null 2>&1; then
    check "SONAME libsteer — по версии движка" "libsteer.so.$VER" \
        "$(readelf -d "$SO" | sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
    check "SONAME libsteer-wolfssl — по версии wolfSSL" "libsteer-wolfssl.so.$WVER" \
        "$(readelf -d "$WSO" | sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
    check "libsteer зависит от libsteer-wolfssl" "libsteer-wolfssl.so.$WVER" \
        "$(readelf -d "$SO" | sed -n 's/.*Shared library: \[\(libsteer[^]]*\)\]/\1/p')"
    for m in steer-vless steer-xsteer steer-obfs steer-tgws steer-hysteria2 steerd; do
        check "$m: из нашего только libsteer.so.$VER" "libsteer.so.$VER" \
            "$(readelf -d "$L/$m" | sed -n 's/.*Shared library: \[\(libsteer[^]]*\)\]/\1/p')"
    done
fi

# ---- команды модулей через steerd ----------------------------------------------------------
empty="$L/nomods"
mkdir -p "$empty"
out="$(STEER_MODULE_DIR="$empty" "$L/steerd" vless '' 2>&1)"; rc=$?
check "без модуля: steerd vless — код 2" "2" "$rc"
check "  отказ называет пакет модуля" "1" "$(printf '%s' "$out" | grep -c 'steer-vless')"
check "  и контрактную подстроку steer-extended (splify2)" "1" "$(printf '%s' "$out" | grep -c 'steer-extended')"
for c in "vless-nodes v" "sub-fetch http://x --out /dev/null" "tls-probe x" "xsteer x" "xsteer-key" \
         "tgws x" "tgws-probe" "obfs x"; do
    o="$(STEER_MODULE_DIR="$empty" "$L/steerd" $c 2>&1)"; r=$?
    check "без модуля: steerd $c — код 2 и «нужен пакет»" "2 1" \
        "$r $(printf '%s' "$o" | grep -c 'нужен пакет steer-')"
done
# steer-hysteria2 — отдельный пакет, не часть steer-extended: отказ называет его одного, и прежней
# отсылки к мета-пакету в нём нет; вид выхода без модуля отвечает так же (kind.c).
out="$(STEER_MODULE_DIR="$empty" "$L/steerd" hysteria2 x 2>&1)"; rc=$?
check "без модуля: steerd hysteria2 — код 2 и «нужен пакет steer-hysteria2»" "2 1 0" \
    "$rc $(printf '%s' "$out" | grep -c 'нужен пакет steer-hysteria2') $(printf '%s' "$out" | grep -c 'steer-extended')"
mkdir -p "$L/hy2spec"
printf 'hysteria2://p@h.example:443/?sni=h.example#n\n' > "$L/hy2spec/sub.txt"
cat > "$L/hy2spec/spec.yaml" <<SPEC
version: 2
outputs:
  hy: { kind: tunnel, protocol: hysteria2, subscription: $L/hy2spec/sub.txt }
SPEC
out="$(STEER_MODULE_DIR="$empty" "$L/steerd" apply --dry-run --spec "$L/hy2spec/spec.yaml" --state-dir "$L/hy2spec/st" 2>&1)"
check "спека с protocol: hysteria2 без модуля: отказ «требует пакет steer-hysteria2»" "1" \
    "$(printf '%s' "$out" | grep -c 'kind hysteria2 требует пакет steer-hysteria2')"
cp "$L/steer-hysteria2" "$empty/steer-hysteria2"
out="$(STEER_MODULE_DIR="$empty" "$L/steerd" apply --dry-run --spec "$L/hy2spec/spec.yaml" --state-dir "$L/hy2spec/st" 2>&1)"
check "  с модулем та же спека принимается" "0" "$(printf '%s' "$out" | grep -c 'требует пакет')"
rm -f "$empty/steer-hysteria2"
# Спека с группой замера по https:// читается модулем: свойство «https:// доступен» — системы, и
# steerd, который меряет, его принимает; модуль разбор не отвергает (раньше слабая ссылка на
# steer_urltls_present в бинарнике модуля была нулевой, и каждый модуль падал кодом 2).
mkdir -p "$L/httpsspec"
printf 'vless://11111111-2222-3333-4444-555555555555@vless.test:443?security=tls&sni=vless.test#n\n' \
    > "$L/httpsspec/sub.txt"
cat > "$L/httpsspec/spec.yaml" <<SPEC
version: 2
outputs:
  vl: { kind: tunnel, protocol: vless, subscription: sub.txt }
  lat: { kind: group, pick: latency, members: [vl], url: "https://vless.test:18447/generate_204" }
SPEC
out="$("$L/steer-vless" vless-nodes vl --spec "$L/httpsspec/spec.yaml" --state-dir "$L/httpsspec/st" 2>&1)"; rc=$?
check "модуль читает спеку с https-группой: не отказ про https, не код 2" "0 0" \
    "$(printf '%s' "$out" | grep -c 'https:// в этой сборке нет') $([ "$rc" = 2 ] && echo 1 || echo 0)"
out="$("$L/steerd" apply --dry-run --spec "$L/httpsspec/spec.yaml" --state-dir "$L/httpsspec/st" 2>&1)"
check "  и steerd такую же спеку принимает (замер ведёт он)" "0" \
    "$(printf '%s' "$out" | grep -c 'https:// в этой сборке нет')"
# ---- --insecure у перечня и проверки узлов по файлу; поля узла для бейджей ------------------------
# Узел TLS с allowInsecure пригоден только при insecure: у выхода — его ключ, у файла — `--insecure`.
# Номера узлов по файлу с флагом обязаны совпасть с номерами выхода с insecure: true (иначе интерфейс
# выбирает в редакторе один узел, а поднимается другой), без флага — с номерами выхода без него.
names() { grep -o '"index":[0-9]*,"name":"[^"]*"' | sed 's/.*"name":"\([^"]*\)"/\1/' | tr '\n' ' '; }
node_of() { # ИМЯ — объект узла с этим именем
    grep -o '{"index":[0-9]*,"name":"'"$1"'"[^}]*}'
}
mkdir -p "$L/insec"
# Путь к файлу — абсолютный: команды отличают файл подписки от имени выхода по ведущей «/».
IN="$(cd "$L/insec" && pwd)"
U=11111111-2222-3333-4444-555555555555
cat > "$IN/vl.txt" <<SUB
vless://$U@a.test:443?security=tls&sni=a.test&fp=chrome#A
vless://$U@b.test:443?security=tls&sni=b.test&allowInsecure=1#B
vless://$U@c.test:443?security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=0123&sni=c.test&fp=firefox#C
SUB
VM="$(printf '{"v":"2","ps":"V","add":"v.test","port":"443","id":"%s","aid":"0","scy":"chacha20-poly1305","net":"tcp","tls":"tls","sni":"v.test"}' "$U" | base64 | tr -d '\n')"
cat > "$IN/px.txt" <<SUB
trojan://p@t1.test:443?security=tls&sni=t1.test&fp=chrome#T1
trojan://p@t2.test:443?security=tls&sni=t2.test&allowInsecure=1#T2
ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@s.test:8388#S
vmess://$VM
SUB
printf 'hysteria2://p@h.test:443/?sni=h.test&insecure=1#H\n' > "$IN/hy.txt"
cat > "$L/insec/spec.yaml" <<SPEC
version: 2
outputs:
  vl:  { kind: tunnel, protocol: vless, subscription: vl.txt, insecure: true }
  vl0: { kind: tunnel, protocol: vless, subscription: vl.txt }
  tj:  { kind: tunnel, protocol: trojan, subscription: px.txt, insecure: true }
SPEC
SI="--spec $L/insec/spec.yaml --state-dir $L/insec/st"
f_plain="$("$L/steer-vless" vless-nodes "$IN/vl.txt" 2>/dev/null)"
f_ins="$("$L/steer-vless" vless-nodes "$IN/vl.txt" --insecure 2>/dev/null)"
o_ins="$("$L/steer-vless" vless-nodes vl $SI 2>/dev/null)"
o_plain="$("$L/steer-vless" vless-nodes vl0 $SI 2>/dev/null)"
check "vless-nodes /файл: узел с allowInsecure пропущен (как у выхода без insecure)" "A C |A C " \
    "$(printf '%s' "$f_plain" | names)|$(printf '%s' "$o_plain" | names)"
check "vless-nodes /файл --insecure: номера как у выхода с insecure: true" "A B C |A B C " \
    "$(printf '%s' "$f_ins" | names)|$(printf '%s' "$o_ins" | names)"
check "  узел B помечен insecure, без fp" '{"index":1,"name":"B","host":"b.test","port":443,"type":"tcp","security":"tls","vision":false,"insecure":true}' \
    "$(printf '%s' "$f_ins" | node_of B)"
check "  у A и C — fp, без insecure" '"fp":"chrome"}|"fp":"firefox"}' \
    "$(printf '%s' "$f_ins" | node_of A | grep -o '"fp".*')|$(printf '%s' "$f_ins" | node_of C | grep -o '"fp".*')"
o="$("$L/steer-vless" vless-probe "$IN/vl.txt" --node 9 --insecure 2>/dev/null)"
check "vless-probe /файл --insecure: узлов столько же, сколько в перечне с флагом" "1" \
    "$(printf '%s' "$o" | grep -c 'всего 3')"
o="$("$L/steer-vless" vless-probe "$IN/vl.txt" --node 9 2>/dev/null)"
check "  и без флага — как без него" "1" "$(printf '%s' "$o" | grep -c 'всего 2')"
o="$("$L/steer-vless" vless-nodes vl --insecure $SI 2>&1)"; rc=$?
check "vless-nodes выход --insecure: отказ кодом 2 со словами" "2 1" \
    "$rc $(printf '%s' "$o" | grep -c 'только с файлом подписки')"

f_plain="$("$L/steer-proxy" proxy-nodes "$IN/px.txt" 2>/dev/null)"
f_ins="$("$L/steer-proxy" proxy-nodes "$IN/px.txt" --insecure 2>/dev/null)"
o_ins="$("$L/steer-proxy" proxy-nodes tj $SI 2>/dev/null)"
check "proxy-nodes /файл: trojan с allowInsecure пропущен" "T1 S V " "$(printf '%s' "$f_plain" | names)"
check "proxy-nodes /файл --insecure: все четыре; trojan в том же порядке, что у выхода" "T1 T2 S V |T1 T2 " \
    "$(printf '%s' "$f_ins" | names)|$(printf '%s' "$o_ins" | names)"
check "  T1: fp, без insecure" '"fp":"chrome"}' "$(printf '%s' "$f_ins" | node_of T1 | grep -o '"fp".*')"
check "  T2: insecure" '"insecure":true}' "$(printf '%s' "$f_ins" | node_of T2 | grep -o '"insecure".*')"
check "  S: method" '"transport":"tcp","method":"2022-blake3-aes-128-gcm"}' \
    "$(printf '%s' "$f_ins" | node_of S | grep -o '"transport".*')"
check "  V: cipher" '"transport":"tcp","cipher":"chacha20-poly1305"}' \
    "$(printf '%s' "$f_ins" | node_of V | grep -o '"transport".*')"
o="$("$L/steer-proxy" proxy-probe "$IN/px.txt" --node 9 --insecure 2>/dev/null)"
check "proxy-probe /файл --insecure: узлов столько же, сколько в перечне с флагом" "1" \
    "$(printf '%s' "$o" | grep -c 'всего 4')"

f_plain="$("$L/steer-hysteria2" hysteria2-nodes "$IN/hy.txt" 2>/dev/null)"
f_ins="$("$L/steer-hysteria2" hysteria2-nodes "$IN/hy.txt" --insecure 2>/dev/null)"
check "hysteria2-nodes /файл --insecure: принят и ничего не меняет (insecure=1 — параметр узла)" \
    "$f_plain" "$f_ins"
check "  узел с insecure=1 в перечне и помечен" "1" "$(printf '%s' "$f_ins" | grep -c '"name":"H".*"insecure":true')"

# ---- exclude и exclude_name: отбор кандидатов без сдвига номеров -----------------------------------
# Страна узла — флаг-эмодзи в имени (пара regional indicator), как у интерфейса splify2. Узлы на
# 192.0.2.x (TEST-NET-1): проба честно не дождётся ответа за секунду, но по списку results видно, каких
# кандидатов она брала.
RU="$(printf '\360\237\207\267\360\237\207\272')"; NL="$(printf '\360\237\207\263\360\237\207\261')"
DE="$(printf '\360\237\207\251\360\237\207\252')"
mkdir -p "$L/excl"
EX="$(cd "$L/excl" && pwd)"
cat > "$EX/vl.txt" <<SUB
vless://$U@192.0.2.1:443?security=tls&sni=a.test#$RU Москва
vless://$U@192.0.2.2:443?security=tls&sni=b.test#$NL Мобильный
vless://$U@192.0.2.3:443?security=tls&sni=c.test#$DE Франкфурт
SUB
# У hysteria2 пробел — разделитель ссылок подписки (hy2sub.c), поэтому пробел в имени — %20.
printf 'hysteria2://p@192.0.2.4:443/?sni=h.test#%s%%20hy\nhysteria2://p@192.0.2.5:443/?sni=h.test#%s%%20hy\n' "$RU" "$DE" > "$EX/hy.txt"
printf 'trojan://p@192.0.2.6:443?security=tls&sni=t.test#%s t\ntrojan://p@192.0.2.7:443?security=tls&sni=t.test#%s t\n' "$RU" "$DE" > "$EX/px.txt"
cat > "$EX/spec.yaml" <<SPEC
version: 2
outputs:
  vl:  { kind: tunnel, protocol: vless, subscription: vl.txt, exclude: RU, exclude_name: мобил }
  all: { kind: tunnel, protocol: vless, subscription: vl.txt, exclude: [RU, NL, DE] }
  pin: { kind: tunnel, protocol: vless, subscription: vl.txt, nodes: [0, 2], exclude: RU }
  hy:  { kind: tunnel, protocol: hysteria2, subscription: hy.txt, exclude: RU }
  tj:  { kind: tunnel, protocol: trojan, subscription: px.txt, exclude: RU }
SPEC
SE="--spec $EX/spec.yaml --state-dir $EX/st"
f="$("$L/steer-vless" vless-nodes "$EX/vl.txt" 2>/dev/null)"
o="$("$L/steer-vless" vless-nodes vl $SE 2>/dev/null)"
check "vless-nodes /файл: у узла cc по флагу, без excluded" "RU NL DE |0" \
    "$(printf '%s' "$f" | grep -o '"cc":"[A-Z]*"' | sed 's/"cc":"\(..\)"/\1/' | tr '\n' ' ')|$(printf '%s' "$f" | grep -c excluded)"
check "vless-nodes выход с exclude: номера те же, что по файлу" "$(printf '%s' "$f" | names)" "$(printf '%s' "$o" | names)"
check "  исключённые — RU по стране и «Мобильный» по куску имени" \
    '{"index":0,"name":"'"$RU"' Москва","host":"192.0.2.1","port":443,"type":"tcp","security":"tls","vision":false,"cc":"RU","excluded":true}|"cc":"NL","excluded":true}|"cc":"DE"}' \
    "$(printf '%s' "$o" | node_of "$RU Москва")|$(printf '%s' "$o" | node_of "$NL Мобильный" | grep -o '"cc".*')|$(printf '%s' "$o" | node_of "$DE Франкфурт" | grep -o '"cc".*')"
p="$("$L/steer-vless" vless-probe vl --timeout 1 $SE 2>/dev/null)"
check "vless-probe выход с exclude: перебор только по неисключённым (номер 2)" "2" \
    "$(printf '%s' "$p" | grep -o '"index":[0-9]*' | sed 's/.*://' | tr '\n' ' ' | sed 's/ $//')"
p="$("$L/steer-vless" vless-probe pin --timeout 1 $SE 2>/dev/null)"
check "  вместе с nodes — пересечение: из [0, 2] остаётся 2" "2" \
    "$(printf '%s' "$p" | grep -o '"index":[0-9]*' | sed 's/.*://' | tr '\n' ' ' | sed 's/ $//')"
p="$("$L/steer-vless" vless-probe all --timeout 1 $SE 2>/dev/null)"; rc=$?
check "  все исключены — отказ со своей причиной, а не перебор исключённых" "1 1" \
    "$rc $(printf '%s' "$p" | grep -c 'все выбранные узлы исключены')"
p="$("$L/steer-vless" vless-probe vl --node 0 --timeout 1 $SE 2>/dev/null)"
check "  узел, названный --node, проверяется и исключённым" "0" \
    "$(printf '%s' "$p" | grep -o '"index":[0-9]*' | sed 's/.*://')"
o="$("$L/steer-hysteria2" hysteria2-nodes hy $SE 2>/dev/null)"
check "hysteria2-nodes выход с exclude: RU помечен, DE нет" '"cc":"RU","excluded":true}|"cc":"DE"}' \
    "$(printf '%s' "$o" | node_of "$RU hy" | grep -o '"cc".*')|$(printf '%s' "$o" | node_of "$DE hy" | grep -o '"cc".*')"
p="$("$L/steer-hysteria2" hysteria2-probe hy --timeout 1 $SE 2>/dev/null)"
check "hysteria2-probe выход с exclude: перебор только по DE (номер 1)" "1" \
    "$(printf '%s' "$p" | grep -o '"index":[0-9]*' | sed 's/.*://' | tr '\n' ' ' | sed 's/ $//')"
o="$("$L/steer-proxy" proxy-nodes tj $SE 2>/dev/null)"
check "proxy-nodes выход с exclude: RU помечен, DE нет" '"cc":"RU","excluded":true}|"cc":"DE"}' \
    "$(printf '%s' "$o" | node_of "$RU t" | grep -o '"cc".*')|$(printf '%s' "$o" | node_of "$DE t" | grep -o '"cc".*')"
p="$("$L/steer-proxy" proxy-probe tj --timeout 1 $SE 2>/dev/null)"
check "proxy-probe выход с exclude: перебор только по DE (номер 1)" "1" \
    "$(printf '%s' "$p" | grep -o '"index":[0-9]*' | sed 's/.*://' | tr '\n' ' ' | sed 's/ $//')"

# С модулем: steerd передаёт командную строку модулю, ответ тот же байт в байт.
cp "$L/steer-vless" "$empty/steer-vless"
a="$(STEER_MODULE_DIR="$empty" "$L/steerd" vless-nodes nosuch --spec /nonexistent 2>&1; echo "rc=$?")"
b="$("$L/steer-vless" vless-nodes nosuch --spec /nonexistent 2>&1; echo "rc=$?")"
check "с модулем: steerd vless-nodes отвечает как сам модуль (вывод и код)" "$b" "$a"
check "  и это не отказ «нужен пакет»" "0" "$(printf '%s' "$a" | grep -c 'нужен пакет')"

# ---- hello ------------------------------------------------------------------------------------
h="$(STEER_EVENT_FD=3 "$L/steer-vless" vless x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "первое сообщение модуля — hello с версией его сборки" \
    "{\"ev\":\"hello\",\"ver\":\"$VER\",\"mod\":\"vless\"}" "$h"
h="$(STEER_EVENT_FD=3 "$L/steer-obfs" obfs x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "  и у steer-obfs" "{\"ev\":\"hello\",\"ver\":\"$VER\",\"mod\":\"obfs\"}" "$h"
h="$(STEER_EVENT_FD=3 "$L/steer-hysteria2" hysteria2 x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "  и у steer-hysteria2" "{\"ev\":\"hello\",\"ver\":\"$VER\",\"mod\":\"hysteria2\"}" "$h"
out="$("$L/steer-obfs" vless x 2>&1)"
check "модуль чужой команды не берёт" "steer-obfs: команда vless — не этого модуля" "$out"

# ---- ABI между библиотеками ---------------------------------------------------------------------
# Подложная libsteer-wolfssl.so с чужим отпечатком: то же имя (SONAME) и те же символы (иначе
# загрузчик отказал бы раньше, не дойдя до сверки), но steer_wolfssl_abi другой — так выглядела бы
# библиотека иной сборки (иные опции — иные размеры структур). Собирается из того же архива wolfSSL.
bad="$L/badabi"
mkdir -p "$bad"
cp "$L"/libsteer.so.* "$bad/"
cat > "$bad/abi.c" <<'EOF'
__attribute__((visibility("default")))
const unsigned long steer_wolfssl_abi[13] = { 0x05009004, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
EOF
WLIB="$(ls "$L"/wolfssl-pic/*/libwolfssl.a | head -1)"
$CC -shared -fPIC -o "$bad/libsteer-wolfssl.so.$WVER" "$bad/abi.c" \
    -Wl,--whole-archive "$WLIB" -Wl,--no-whole-archive -Wl,-soname,"libsteer-wolfssl.so.$WVER" \
    -Wl,--version-script=build/wolfssl/libsteer-wolfssl.map -Wl,--gc-sections \
    -lpthread -lm > "$bad/build.log" 2>&1
o="$(LD_LIBRARY_PATH="$bad" "$L/steer-vless" vless x --spec /nonexistent 2>&1)"; r=$?
check "libsteer-wolfssl другой сборки: процесс не стартует, код 3" "3" "$r"
check "  и строка называет причину и лечение" "1" \
    "$(printf '%s' "$o" | grep -c 'другой сборки.*обновите пакеты libsteer и libsteer-wolfssl вместе')"
# Настоящая библиотека — проходит (модуль отвечает своим отказом про спеку, а не про библиотеку).
o="$("$L/steer-vless" vless x --spec /nonexistent 2>&1)"
check "настоящая libsteer-wolfssl: сверка молчит" "0" "$(printf '%s' "$o" | grep -c 'другой сборки')"

# ---- QUIC в раскладке пакета (шаг 7) ---------------------------------------------------------------
# Клиент замера (tests/qcbench.c — он же «потребитель», чьи символы дали qc_* в списке экспорта)
# линкуется с настоящей libsteer.so и ходит через настоящую libsteer-wolfssl.so, то есть на ту
# wolfSSL, что поедет в пакет — без сервера TLS, с QUIC и AES-ECB. Сервер — build/qcserver из
# ext-test (собран на статической wolfSSL стенда, с сервером TLS): две разные сборки wolfSSL по
# разные стороны провода — как в жизни.
if [ -x "$BUILD/qcserver" ]; then
    $CC -O2 -w -Isrc/proto/quic -Itests -o "$L/qcbench" tests/qcbench.c "$SO" -Wl,-rpath,"$L" -lpthread
    check "стенд-потребитель QUIC слинковался с libsteer.so" "0" "$?"
    for mode in "cubic" "brutal 6250000"; do
        "$BUILD/qcserver" --port 0 --idle 15 > "$L/qcsrv.out" 2>/dev/null &
        spid=$!
        n=0
        while ! grep -q '^listening' "$L/qcsrv.out" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
        port="$(sed -n 's/^listening //p' "$L/qcsrv.out")"
        o="$("$L/qcbench" 127.0.0.1 "${port:-1}" 1 $mode 2>&1)"
        check "QUIC через libsteer.so и libsteer-wolfssl.so ($mode): рукопожатие и передача, сервер ответил" "1" \
            "$(printf '%s' "$o" | grep -c 'replied=1')"
        kill "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
    done
else
    echo "libs-test: нет $BUILD/qcserver (его собирает make ext-test) — QUIC через раскладку пакета пропущен"
fi

# ---- снимок генератора динамическим steerd ---------------------------------------------------------
# Клиент, steerd и библиотеки — в отдельном каталоге БЕЗ модулей (клиент берёт движок рядом с
# собой, а модули ищутся рядом с движком): это пакет ядра без модулей, то есть та же база, что у
# статического build/steerd, и снимок обязан совпасть до байта. Переменную STEER_MODULE_DIR для
# этого не ставим — снимок записывает в заголовок все STEER_*, и она разошлась бы с эталоном.
if [ -x "$BUILD/steer" ] && [ -x "$BUILD/steer-android" ] && [ -x "$BUILD/tgwssim" ]; then
    core="$L/core"
    mkdir -p "$core"
    cp "$L/steerd" "$L"/libsteer.so.* "$L"/libsteer-wolfssl.so.* "$core/"
    cp "$BUILD/steer" "$core/steer"
    # env -u: STEER_WOLFSSL (путь к исходникам библиотеки) — тоже STEER_*, и снимок записал бы его.
    o="$(env -u STEER_WOLFSSL -u STEER_NGTCP2 LD_LIBRARY_PATH="$core" STEER="$core/steer" sh tests/snapshot.sh 2>&1 | tail -1)"
    check "снимок генератора динамическим steerd: совпал" "1" "$(printf '%s' "$o" | grep -c 'снимков совпали')"
else
    echo "libs-test: нет build/steer, steer-android или tgwssim — снимок динамическим steerd пропущен (make)"
fi

# ---- hysteria2 против настоящего сервера (apernet/hysteria) ----------------------------------------
# Сетевые пространства, TUN и docker-образ tobyxdd/hysteria:v2 (или HY2_SERVER): нет чего-то из этого —
# стенд сам говорит «ПРОПУСК» и выходит с нулём, это не падение.
o="$(LIBS="$L" sh tests/run-hy2.sh 2>&1 | tail -1)"
case "$o" in
    *ПРОПУСК*) echo "libs-test: $o" ;;
    *) check "hysteria2 против настоящего сервера: стенд tests/run-hy2.sh" "0" "$(printf '%s' "$o" | grep -c 'провалено [1-9]')"
       check "  и он дошёл до итога" "1" "$(printf '%s' "$o" | grep -c 'проверок пройдено')" ;;
esac
# Долгие соединения через вложенную группу с туннелями hysteria2 (демон раскладки, мост, fake-IP,
# IPv6; клиент управляющего сокета — build/steer): то же условие пропуска.
o="$(LIBS="$L" sh tests/nestlong.sh 2>&1 | tail -1)"
case "$o" in
    *пропуск*) echo "libs-test: $o" ;;
    *) check "долгие соединения через вложенную группу: стенд tests/nestlong.sh" "1" \
           "$(printf '%s' "$o" | grep -c '^nestlong: [0-9]* ok, 0 fail$')" ;;
esac

# Модуль туннеля переживает закрытие соединений узлом на скорости (SIGPIPE выключен у модульных команд,
# cli/modcmd.c): демон раскладки, два выхода vless (TLS и без шифрования), поддельные узлы, закрывающие
# соединения рано, клиент в своём пространстве. Нужны root, сетевые пространства и python3 с ssl — нет их,
# и стенд сам говорит «пропуск».
full="$(LIBS="$L" sh tests/sigpipe.sh 2>&1)"
o="$(printf '%s\n' "$full" | tail -n 1)"
case "$o" in
    *пропуск*) echo "libs-test: $o" ;;
    *) check "модуль переживает закрытие соединений узлом на скорости: стенд tests/sigpipe.sh" "1" \
           "$(printf '%s' "$o" | grep -c '^sigpipe: [0-9]* ok, 0 fail$')"
       printf '%s\n' "$o" | grep -q ', 0 fail$' || printf '%s\n' "$full" | sed 's/^/    sigpipe: /' ;;
esac

# Окно приёма стека TUN с настоящим клиентом ядра: масштаб окна согласован (wscale в ss клиента), выгрузка
# при задержке в LAN не упирается в 64 КБ на круг, STEER_TUN_RCVWND=0 возвращает прежнее окно, клиент без
# масштаба работает. Нужны root, сетевые пространства, tc с netem и ss — нет их, и стенд сам говорит «пропуск».
full="$(LIBS="$L" sh tests/rcvwnd.sh 2>&1)"
o="$(printf '%s\n' "$full" | tail -n 1)"
case "$o" in
    *пропуск*) echo "libs-test: $o" ;;
    *) check "окно приёма клиента: масштаб согласован, выгрузка не упирается в 64 КБ: стенд tests/rcvwnd.sh" "1" \
           "$(printf '%s' "$o" | grep -c '^rcvwnd: [0-9]* ok, 0 fail$')"
       printf '%s\n' "$o" | grep -q ', 0 fail$' || printf '%s\n' "$full" | sed 's/^/    rcvwnd: /' ;;
esac

# Замер группы latency по HTTPS (urltls.c) — раньше его не доставал ни один стенд: демон раскладки, два
# члена-интерфейса, сервер TLS 1.3 со своим CA; хранилище корней без CA — причина неудачи в журнале и в
# status, с CA — замер есть и группа на быстром. Нужны root, сетевые пространства, tc с netem, openssl и
# python3 с ssl — нет их, и стенд сам говорит «пропуск».
full="$(LIBS="$L" sh tests/urlhttps.sh 2>&1)"
o="$(printf '%s\n' "$full" | tail -n 1)"
case "$o" in
    *пропуск*) echo "libs-test: $o" ;;
    *) check "замер группы по HTTPS: стенд tests/urlhttps.sh" "1" \
           "$(printf '%s' "$o" | grep -c '^urlhttps: [0-9]* ok, 0 fail$')"
       printf '%s\n' "$o" | grep -q ', 0 fail$' || printf '%s\n' "$full" | sed 's/^/    urlhttps: /' ;;
esac

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
