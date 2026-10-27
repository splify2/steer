#!/bin/sh
# Менеджер плагинов (`steer plugin …`, src/pluginmgr; plugin-sdk: s2p.md, index.md) на настоящих архивах,
# индексах и ключах, собранных инструментом s2p из plugin-sdk, и настоящей подписи Ed25519 (wolfSSL).
#
# Репозиторий раздаёт локальный python http.server; каталоги менеджера — во временном месте
# (STEER_PLUGIN_DIR, _ETC, _KEYS, _SEED, _RUN, _TMP, _KEEPD), архитектура — STEER_PLUGIN_ARCH, место на
# разделе — STEER_PLUGIN_FREE (подмена statvfs), системные пакеты — STEER_PLUGIN_PKG (заглушка apk/opkg).
#
# Что проверяется: установка с зависимостью; отказ по месту числами; подмена архива на зеркале; чужой
# ключ (индекс, архив, сторонний репозиторий); несовместимая версия и выбор совместимой; обновление и
# откат по scripts/postinst (bad_versions); удаление (зависимые, выходы спеки, --force, --purge); ensure
# из семени без сети; задания; busy; установка из файла (--unsigned); репозитории (add/list/del);
# системные пакеты и пути ядра; keep.d; с демоном (root и unshare) — команды plugin-* сокета, событие
# plugin подписчику и plugin-reload.
#
#   sh tests/pluginmgrmatch.sh [steerd с менеджером]
# Без аргумента — собирает его сам (профиль extended + PLUGMGR_SRC + wolfSSL из $BUILD/wolfssl-host, как
# tests/ext-test.sh). Нет wolfSSL, s2p или python3 — громкий пропуск.
set -u
BUILD=${BUILD:-build}
CC=${CC:-cc}
command -v python3 >/dev/null 2>&1 || { echo "pluginmgrmatch: python3 нет — ПРОПУСК"; exit 0; }
S2P="${S2P:-}"
if [ -z "$S2P" ]; then
    for c in "$(command -v s2p 2>/dev/null)" ../plugin-sdk/bin/s2p ../../plugin-sdk/bin/s2p \
             /home/yo1nk/splicicd/plugin-sdk/bin/s2p; do
        [ -n "$c" ] && [ -x "$c" ] && { S2P="$c"; break; }
    done
fi
[ -n "$S2P" ] && [ -x "$S2P" ] || { echo "pluginmgrmatch: инструмента s2p нет (S2P=… или plugin-sdk/bin/s2p) — ПРОПУСК"; exit 0; }
S2P="$(cd "$(dirname "$S2P")" && pwd)/$(basename "$S2P")"

BIN="${1:-${PMSTEERD:-}}"
if [ -z "$BIN" ]; then
    CCTAG=$(printf '%s' "$CC" | tr -c 'a-zA-Z0-9' '_')
    WLIB="$BUILD/wolfssl-host/libwolfssl-$CCTAG.a"
    [ -f "$WLIB" ] || { echo "pluginmgrmatch: нет $WLIB (make ext-test собирает его) — ПРОПУСК"; exit 0; }
    . build/sources.sh
    INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done) $(profile_var THIRD_DEFS)"
    WCF=$(cat "$WLIB.cflags")
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC $WCF -c src/lib/scrypto.c -o "$BUILD/wolfssl-host/scrypto-pm-$CCTAG.o" || exit 1
    SRC="$(for f in $(profile_src extended) $(profile_var PLUGMGR_SRC); do
        [ "$f" = "$(profile_var CRYPTO_SRC)" ] || printf '%s ' "$f"; done)"
    echo "pluginmgrmatch: собираю steerd с менеджером плагинов..."
    # shellcheck disable=SC2086
    $CC -O1 -g -w $INC -DSTEER_VERSION='"2.1.0"' -o "$BUILD/steerd-pm" $SRC "$BUILD/wolfssl-host/scrypto-pm-$CCTAG.o" \
        "$WLIB" -lpthread || exit 1
    BIN="$BUILD/steerd-pm"
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "pluginmgrmatch: нет $BIN"; exit 2; }

if [ "${PM_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    PM_INNER=1 S2P="$S2P" exec unshare -n sh "$0" "$BIN"
fi
[ "${PM_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

T="$(mktemp -d /tmp/pluginmgrmatch.XXXXXX)"
HP="" D="" SUBP=""
trap 'kill $HP $D $SUBP 2>/dev/null; rm -rf "$T"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
has() {   # описание, подстрока, текст
    case "$3" in *"$2"*) pass=$((pass + 1)) ;; *)
        fail=$((fail + 1)); printf 'FAIL %s\n  нет подстроки: %s\n  текст: %s\n' "$1" "$2" "$3" ;; esac
}
jq_() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

cd "$T" || exit 1
"$S2P" keygen -o idx >/dev/null && "$S2P" keygen -o proto >/dev/null && "$S2P" keygen -o plg >/dev/null &&
    "$S2P" keygen -o evil >/dev/null && "$S2P" keygen -o third >/dev/null || { echo "s2p keygen не работает"; exit 1; }
mkdir -p keys/index keys/protocols keys/plugins etc/repos.d root run tmp seed repo src dist
cp idx.pub keys/index/ && cp proto.pub keys/protocols/ && cp plg.pub keys/plugins/

# Плагин: mk ИМЯ ВЕРСИЯ 'доп. поля JSON' [postinst-код]
mk() {
    d="src/$1-$2"
    rm -rf "$d"; mkdir -p "$d/bin"
    printf '{"schema":1,"id":"%s","version":"%s","name":"%s","compat":{"steer-api":"^1.0"},"arch":"all"%s}\n' \
        "$1" "$2" "$1" "$3" > "$d/plugin.json"
    printf '#!/bin/sh\necho %s %s\n' "$1" "$2" > "$d/bin/$1"
    chmod 755 "$d/bin/$1"
    if [ -n "${4:-}" ]; then
        mkdir -p "$d/scripts"
        printf '#!/bin/sh\n[ "$1" = --check ] && exit 0\necho "postinst $STEER_PLUGIN_ID $1" >> %s/postinst.log\nexit %s\n' "$T" "$4" > "$d/scripts/postinst"
        chmod 755 "$d/scripts/postinst"
    fi
}
build() {   # КАТАЛОГ КЛЮЧ
    "$S2P" build "$1" --key "$2" -o dist >/dev/null 2>&1 || { echo "s2p build $1 не прошёл"; exit 1; }
}
index() {   # индекс репозитория splify2 из dist, подпись ключом index
    "$S2P" index dist -o repo --repo splify2 --pub proto.pub --pub plg.pub --key "${1:-idx.sec}" \
        --mirror https://mirror.invalid/ --meta meta.json ${2:-} >/dev/null 2>idx.err || { cat idx.err; exit 1; }
}
cat > meta.json <<'E'
{"plugins":{"net1":{"key_role":"protocols","default":true},"foo":{"key_role":"protocols","default":true},
"bar":{"key_role":"plugins"},"big":{"key_role":"protocols"},"neu":{"key_role":"protocols"},"evil":{"key_role":"protocols"},
"pk":{"key_role":"plugins"},"kern":{"key_role":"plugins"},"tg":{"key_role":"protocols"}}}
E
mk net1 1.2.0 ''
mk foo 1.0.0 ',"requires":{"plugins":{"net1":"^1.2"}},"steer":{"commands":[{"name":"foo-hello","prog":"bin/foo"}],"kinds":[{"name":"tunnel:foo","helper":{"prog":"bin/foo"}}]},"scripts":{"postinst":"scripts/postinst"},"keep":["/etc/foo"],"permissions":["fs:/etc/foo"]' 0
mk neu 1.0.0 ''
mk neu 2.0.0 ''
sed -i 's/"steer-api":"\^1.0"/"steer-api":"^9.0"/' src/neu-2.0.0/plugin.json
mk bar 1.0.0 ',"steer":{"commands":[{"name":"bar-x","prog":"bin/bar"}]}'
mk big 1.0.0 ''
head -c 300000 /dev/urandom > src/big-1.0.0/bin/blob
mk evil 1.0.0 ''
mk pk 1.0.0 ',"requires":{"system":["kmod-test|kmod-alt"]},"permissions":["system-packages"]'
mk kern 1.0.0 ',"requires":{"kernel":["/nonexistent/steer-test-path"]}'
# tg: полный вариант большой, облегчённый (variant: lite) маленький — одна версия, один id.
mk tg 1.0.0 ''
head -c 400000 /dev/urandom > src/tg-1.0.0/bin/blob
mk tglite 1.0.0 ',"variant":"lite"'
sed -i 's/"id":"tglite"/"id":"tg"/; s/"name":"tglite"/"name":"tg"/' src/tglite-1.0.0/plugin.json
mv src/tglite-1.0.0/bin/tglite src/tglite-1.0.0/bin/tg
for p in net1-1.2.0 foo-1.0.0 neu-1.0.0 neu-2.0.0 big-1.0.0 tg-1.0.0 tglite-1.0.0; do build "src/$p" proto.sec; done
build src/bar-1.0.0 plg.sec
build src/pk-1.0.0 plg.sec
build src/kern-1.0.0 plg.sec
# evil: архив протокола подписан ключом plugins (а индекс говорит key_role protocols).
build src/evil-1.0.0 plg.sec
"$S2P" index dist -o repo --repo splify2 --pub proto.pub --pub plg.pub --key idx.sec --mirror https://mirror.invalid/ \
    --meta meta.json >/dev/null 2>idx.err || { cat idx.err; exit 1; }

python3 - "$T/repo" > port.txt 2>http.log <<'PY' &
import http.server, socketserver, sys, os, functools
# Каталог — путём, а не chdir: стенд подменяет repo целиком (rm -rf, mv), и cwd сервера осиротел бы.
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k): super().__init__(*a, directory=sys.argv[1], **k)
    def log_message(self, *a): pass
class S(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
srv = S(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
HP=$!
i=0; while [ ! -s port.txt ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
PORT=$(cat port.txt)
printf '{"id":"splify2","url":"http://127.0.0.1:%s/","official":true,"priority":0,"keys":[]}\n' "$PORT" > etc/repos.d/splify2.json

export STEER_PLUGIN_DIR="$T/root" STEER_PLUGIN_ETC="$T/etc" STEER_PLUGIN_KEYS="$T/keys" STEER_PLUGIN_SEED="$T/seed"
export STEER_PLUGIN_RUN="$T/run" STEER_PLUGIN_TMP="$T/tmp" STEER_PLUGIN_KEEPD="$T/keepd" STEER_PLUGIN_ARCH=x86_64
export STEER_SOCKET="$T/none.sock" STEER_PLUGIN_SPEC="$T/spec.yaml" STEER_PLUGIN_HOST_API="" STEER_PLUGIN_SPLIFY2="" STEER_PLUGIN_PANEL_DIR="$T/nopanel"
export STEER_PLUGIN_AUTO=0
P() { "$BIN" plugin "$@"; }

# ---- версия ядра для оси compat ----
check "steer version --json: core, api, abi" "2.1.0 1.2 1.0" \
    "$("$BIN" version --json | jq_ 'd["core"]+" "+d["api"]+" "+d["abi"]')"

# ---- каталог ----
o="$(P search --json)"
check "search: каталог из индекса" "bar big evil foo kern net1 neu pk tg" "$(printf '%s\n' "$o" | jq_ '" ".join(sorted(p["id"] for p in d["plugins"]))')"
check "  neu: показана совместимая 1.0.0, самая новая 2.0.0" "1.0.0 2.0.0" \
    "$(printf '%s\n' "$o" | jq_ '[p["version"]+" "+p["latest"] for p in d["plugins"] if p["id"]=="neu"][0]')"
check "  repo list: официальный" "splify2 True" "$(P repo list --json | jq_ 'd["repos"][0]["name"]+" "+str(d["repos"][0]["official"])')"
check "  кэш индекса с ETag" "yes" "$([ -s run/splify2/index.json ] && [ -s run/splify2/index.json.sig ] && echo yes)"

# ---- установка с зависимостью ----
o="$(P install foo --json 2>err.txt)"; rc=$?
check "install foo: код 0" "0" "$rc"
check "  net1 раньше foo" "net1,foo" "$(printf '%s\n' "$o" | jq_ '",".join(x["id"] for x in d["installed"])')"
check "  файлы на месте" "yes" "$([ -x root/foo/bin/foo ] && [ -f root/net1/plugin.json ] && [ -f root/foo/MANIFEST.sig ] && echo yes)"
check "  .stage и .prev пусты" "" "$(ls root/.stage root/.prev 2>/dev/null | grep -v ':$' | tr -d '\n')"
check "  postinst с пустой прежней версией" "postinst foo " "$(cat postinst.log)"
o="$(P list --json)"
check "list: состояние, репозиторий, доверие" "enabled splify2 official" \
    "$(printf '%s\n' "$o" | jq_ '[p["state"]+" "+p["repo"]+" "+p["trust"] for p in d["plugins"] if p["id"]=="foo"][0]')"
check "  поля манифеста: kinds, compat, used_by" "['tunnel:foo'] ^1.0 ['foo']" \
    "$(printf '%s\n' "$o" | jq_ 'str([p for p in d["plugins"] if p["id"]=="foo"][0]["kinds"])+" "+[p for p in d["plugins"] if p["id"]=="foo"][0]["compat"]["steer-api"]+" "+str([p for p in d["plugins"] if p["id"]=="net1"][0]["used_by"])')"
check "  state.json: from network" "network" "$(jq_ 'd["plugins"]["foo"]["from"]' < etc/state.json)"
has "keep.d: каталоги плагинов и keep" "/etc/foo" "$(cat keepd)"
has "  и корень плагинов" "$T/root/" "$(cat keepd)"
check "status foo: файлы сходятся с MANIFEST" "True" "$(P status foo --json | jq_ 'd["plugins"][0]["files_ok"]')"
echo x >> root/foo/bin/foo
check "  испорченный файл виден" "False" "$(P status foo --json | jq_ 'd["plugins"][0]["files_ok"]')"
P install foo 1.0.0 --json >/dev/null 2>&1   # та же версия — нечего делать, файл остаётся испорченным
cp src/foo-1.0.0/bin/foo root/foo/bin/foo

# ---- несовместимая версия ----
o="$(P install neu --json 2>/dev/null)"
check "install neu: взята совместимая 1.0.0 (2.0.0 требует steer-api ^9)" "1.0.0" "$(printf '%s\n' "$o" | jq_ 'd["version"]')"
o="$(P install neu 2.0.0 --json 2>/dev/null)"; rc=$?
check "install neu 2.0.0: отказ" "1" "$rc"
has "  причина с числами" "требует steer-api ^9.0, у ядра 1.2" "$o"

# ---- место ----
o="$(STEER_PLUGIN_FREE=1000 P install big --json 2>/dev/null)"; rc=$?
check "нет места: отказ" "1" "$rc"
has "  называет нужное и свободное" "нужно 294 КБ, свободно 1 КБ" "$o"
check "  ничего не поставлено" "no" "$([ -d root/big ] && echo yes || echo no)"
o="$(STEER_PLUGIN_FREE=100000000:10 P install big --json 2>/dev/null)"
has "  во /tmp тоже считается" "нет места во временном каталоге" "$o"

# ---- облегчённый вариант, когда на полный нет места ----
o="$(STEER_PLUGIN_FREE=200000 P install tg --json 2>/dev/null)"; rc=$?
check "на полный tg нет места, облегчённый помещается: поставлен lite" "0 lite" "$rc $(jq_ 'd["plugins"]["tg"].get("variant","full")' < etc/state.json)"
has "  причина в state.json с числами" "облегчённый вариант: на полный нет места" "$(jq_ 'd["plugins"]["tg"]["why"]' < etc/state.json)"
P remove tg --json >/dev/null 2>&1

# ---- подмена архива на зеркале ----
cp repo/bar/1.0.0/bar-1.0.0-all.s2p bar.orig
printf 'X' | dd of=repo/bar/1.0.0/bar-1.0.0-all.s2p bs=1 seek=100 conv=notrunc 2>/dev/null
o="$(P install bar --json 2>/dev/null)"; rc=$?
check "подменённый архив: отказ" "1" "$rc"
has "  по сумме из подписанного индекса" "не совпал с подписанным индексом" "$o"
cp bar.orig repo/bar/1.0.0/bar-1.0.0-all.s2p

# ---- чужой ключ ----
o="$(P install evil --json 2>/dev/null)"; rc=$?
check "архив протокола подписан ключом plugins: отказ" "1" "$rc"
has "  называет номер ключа" "подписан ключом $(sed -n 2p plg.pub | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read())[2:10].hex())')" "$o"
# Индекс, подписанный чужим ключом (зеркало подменило и индекс, и подпись).
cp -r repo repo.good
"$S2P" index dist -o repo --repo splify2 --pub proto.pub --pub plg.pub --key evil.sec --mirror https://mirror.invalid/ \
    --meta meta.json --replace >/dev/null 2>&1
rm -rf run/splify2
o="$(P search --json 2>/dev/null)"
has "индекс чужим ключом не принят" "такого ключа у ядра нет" "$o"
rm -rf repo && mv repo.good repo

# ---- откат индекса ----
cp etc/repos.d/splify2.json repo.bak
python3 - etc/repos.d/splify2.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["last_generated"] = "2099-01-01T00:00:00Z"; json.dump(d, open(sys.argv[1], "w"))
PY
rm -rf run/splify2
o="$(P search --json 2>/dev/null)"
has "индекс старее виденного отвергнут" "старее уже виденного" "$o"
cp repo.bak etc/repos.d/splify2.json

# ---- обновление и откат ----
mk foo 1.1.0 ',"requires":{"plugins":{"net1":"^1.2"}},"steer":{"commands":[{"name":"foo-hello","prog":"bin/foo"}],"kinds":[{"name":"tunnel:foo","helper":{"prog":"bin/foo"}}]},"scripts":{"postinst":"scripts/postinst"},"keep":["/etc/foo"],"permissions":["fs:/etc/foo"]' 3
build src/foo-1.1.0 proto.sec
index
P search --json >/dev/null 2>&1   # list берёт только кэш индекса; search освежает его
check "list: доступно обновление 1.1.0" "1.1.0" "$(P list --json | jq_ '[p["update"] for p in d["plugins"] if p["id"]=="foo"][0]')"
: > postinst.log
o="$(P update foo --json 2>err.txt)"; rc=$?
check "update foo до 1.1.0 с упавшим postinst: отказ" "1" "$rc"
has "  причина — проверка здоровья и возврат" "возвращена прежняя версия" "$o"
check "  стоит прежняя 1.0.0" "foo 1.0.0" "$(root/foo/bin/foo)"
check "  state.json: 1.0.0, 1.1.0 в bad_versions" "1.0.0 True" \
    "$(jq_ 'd["plugins"]["foo"]["version"]+" "+str("1.1.0" in d["plugins"]["foo"]["bad_versions"])' < etc/state.json)"
check "  .prev убран" "no" "$([ -d root/.prev/foo ] && echo yes || echo no)"
o="$(P update foo --json 2>/dev/null)"
check "повторное обновление 1.1.0 не берёт" "[]" "$(printf '%s\n' "$o" | jq_ 'str(d["updated"])')"
mk foo 1.2.0 ',"requires":{"plugins":{"net1":"^1.2"}},"steer":{"commands":[{"name":"foo-hello","prog":"bin/foo"}],"kinds":[{"name":"tunnel:foo","helper":{"prog":"bin/foo"}}]},"scripts":{"postinst":"scripts/postinst"},"keep":["/etc/foo"],"permissions":["fs:/etc/foo"]' 0
build src/foo-1.2.0 proto.sec
index
: > postinst.log
o="$(P update --json 2>/dev/null)"; rc=$?
check "update (все): foo 1.0.0 → 1.2.0" "0 foo 1.2.0 1.0.0" "$rc $(printf '%s\n' "$o" | jq_ '" ".join(x["id"]+" "+x["version"]+" "+x["old"] for x in d["updated"])')"
check "  postinst получил прежнюю версию" "postinst foo 1.0.0" "$(cat postinst.log)"
check "  на месте 1.2.0" "foo 1.2.0" "$(root/foo/bin/foo)"
o="$(P install foo 1.1.0 --json 2>/dev/null)"; rc=$?
check "явная версия из bad_versions ставится только явно (и откатывается снова)" "1" "$rc"

# ---- фоновое обновление: окно, отзыв по безопасности ----
mk foo 1.3.0 ',"requires":{"plugins":{"net1":"^1.2"}},"steer":{"commands":[{"name":"foo-hello","prog":"bin/foo"}],"kinds":[{"name":"tunnel:foo","helper":{"prog":"bin/foo"}}]},"scripts":{"postinst":"scripts/postinst"},"keep":["/etc/foo"],"permissions":["fs:/etc/foo"]' 0
build src/foo-1.3.0 proto.sec
index
WIN="$(python3 -c 'import time; t=time.localtime(time.time()+7200); u=time.localtime(time.time()+10800); print("%02d:%02d-%02d:%02d" % (t.tm_hour, t.tm_min, u.tm_hour, u.tm_min))')"
python3 - etc/state.json "$WIN" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["auto_window"] = sys.argv[2]; json.dump(d, open(sys.argv[1], "w"))
PY
o="$(P update --auto --json 2>/dev/null)"
check "update --auto вне окна: ждёт окна" "[] 1" "$(printf '%s\n' "$o" | jq_ 'str(d["updated"])+" "+str(d["waiting"])')"
check "  срок следующего прохода — к началу окна" "yes" "$(python3 - etc/state.json "$WIN" <<'PY'
import json, sys, time, calendar
d = json.load(open(sys.argv[1])); nx = calendar.timegm(time.strptime(d["auto"]["next"], "%Y-%m-%dT%H:%M:%SZ"))
print("yes" if 7000 < nx - time.time() < 7200 + 700 else "no %s" % (nx - time.time()))
PY
)"
check "  last_check записан" "yes" "$(jq_ '"yes" if d["auto"]["last_check"] else "no"' < etc/state.json)"
o="$(P update --auto --if-stale --json 2>/dev/null)"
has "--if-stale: проверка была только что — пропуск" "skipped" "$o"
"$S2P" index dist -o repo --repo splify2 --pub proto.pub --pub plg.pub --key idx.sec --mirror https://mirror.invalid/ \
    --meta meta.json --yank foo@1.2.0 --why "уязвимость" --security >/dev/null 2>&1
P search --json >/dev/null 2>&1
check "list: стоящая отозвана по безопасности" "уязвимость True" \
    "$(P list --json | jq_ '[str(p.get("yanked"))+" "+str(p.get("update_security")) for p in d["plugins"] if p["id"]=="foo"][0]')"
o="$(P update --auto --json 2>/dev/null)"
check "update --auto: отозванная по безопасности меняется сразу, вне окна" "foo 1.3.0" \
    "$(printf '%s\n' "$o" | jq_ '" ".join(x["id"]+" "+x["version"] for x in d["updated"])')"

# ---- autoupdate, enable, disable ----
P autoupdate foo off --json >/dev/null
check "autoupdate off" "False" "$(jq_ 'd["plugins"]["foo"]["auto_update"]' < etc/state.json)"
P autoupdate foo on --json >/dev/null
P disable foo --json >/dev/null
check "disable" "disabled" "$(jq_ 'd["plugins"]["foo"]["state"]' < etc/state.json)"
P enable foo --json >/dev/null
check "enable" "enabled" "$(jq_ 'd["plugins"]["foo"]["state"]' < etc/state.json)"

# ---- удаление ----
o="$(P remove net1 --json 2>/dev/null)"; rc=$?
check "remove net1, нужный foo: отказ" "1" "$rc"
has "  называет зависимого" "нужен плагинам foo" "$o"
printf 'outputs:\n  nl: { kind: tunnel, protocol: foo, subscription: sub/nl }\n  de: { kind: tunnel, protocol: foo }\n' > spec.yaml
mkdir -p etc/conf/foo && echo 1 > etc/conf/foo/x
o="$(P remove foo --json 2>/dev/null)"; rc=$?
check "remove foo, чей вид в спеке: отказ" "1" "$rc"
has "  называет выходы" "выходы nl, de — вида tunnel:foo" "$o"
o="$(P remove foo --force --json 2>/dev/null)"; rc=$?
check "remove --force" "0" "$rc"
check "  каталог и запись убраны, настройки остались" "no no yes" \
    "$([ -d root/foo ] && echo yes || echo no) $(python3 -c 'import json;print("yes" if "foo" in json.load(open("etc/state.json"))["plugins"] else "no")') $([ -f etc/conf/foo/x ] && echo yes || echo no)"
mkdir -p etc/conf/net1 && echo 1 > etc/conf/net1/x
P remove net1 --purge --json >/dev/null 2>&1
check "remove --purge убирает и настройки" "no no" "$([ -d root/net1 ] && echo yes || echo no) $([ -d etc/conf/net1 ] && echo yes || echo no)"
rm -f spec.yaml

# ---- системные пакеты и пути ядра ----
cat > pkg.sh <<E
#!/bin/sh
case "\$1" in
installed) grep -qx "\$2" "$T/pkgs" 2>/dev/null ;;
add) [ "\$2" = kmod-test ] && echo "\$2" >> "$T/pkgs" && echo "add \$2" >> "$T/pkg.log" ;;
esac
E
chmod 755 pkg.sh
o="$(STEER_PLUGIN_PKG="$T/pkg.sh" P install pk --json 2>/dev/null)"; rc=$?
check "requires.system: пакет поставлен менеджером" "0 add kmod-test" "$rc $(cat pkg.log 2>/dev/null)"
check "  записан в system_ours и system плагина" "kmod-test kmod-test" \
    "$(jq_ '" ".join(d["system_ours"])+" "+" ".join(d["plugins"]["pk"]["system"])' < etc/state.json)"
o="$(P install kern --json 2>/dev/null)"; rc=$?
check "requires.kernel: пути нет — отказ" "1" "$rc"
has "  называет путь" "нет /nonexistent/steer-test-path" "$o"

# ---- busy ----
python3 - "$T/root/.lock" > lock.ready <<'PY' &
import fcntl, sys, time
f = open(sys.argv[1], "a"); fcntl.flock(f, fcntl.LOCK_EX); print("ok", flush=True); time.sleep(5)
PY
LP=$!
i=0; while [ ! -s lock.ready ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
o="$(P install bar --json 2>/dev/null)"; rc=$?
check "занятый менеджер: busy" "1" "$rc"
has "  слово busy в начале" '"error":"busy:' "$o"
check "  чтение работает и под чужой блокировкой" "0" "$(P list --json >/dev/null 2>&1; echo $?)"
kill $LP 2>/dev/null; wait $LP 2>/dev/null

# ---- задания ----
o="$(P install bar --job --json)"
J="$(printf '%s\n' "$o" | jq_ 'd["job"]')"
check "install --job: номер задания сразу" "yes" "$([ -n "$J" ] && echo yes)"
i=0; st=running
while [ "$st" = running ] && [ $i -lt 100 ]; do
    st="$(P job "$J" --json | jq_ 'd["state"]')"; sleep 0.1; i=$((i + 1))
done
check "  задание: done" "done" "$st"
check "  итог — ответ менеджера" "bar" "$(P job "$J" --json | jq_ 'd["result"]["id"]')"
check "  нет такого задания" "1" "$(P job 1-1 --json >/dev/null 2>&1; echo $?)"

# ---- установка из файла ----
P remove bar --json >/dev/null 2>&1
"$S2P" build src/bar-1.0.0 --unsigned -o udist >/dev/null 2>&1
o="$(P install --file udist/bar-1.0.0-all.s2p --json 2>/dev/null)"; rc=$?
check "файл без подписи без --unsigned: отказ" "1" "$rc"
has "  причина" "не подписан" "$o"
o="$(P install --file udist/bar-1.0.0-all.s2p --unsigned --json 2>/dev/null)"; rc=$?
check "  с --unsigned — ставится, помечен" "0 unsigned False" \
    "$rc $(P list --json | jq_ '[p["trust"]+" "+str(p["auto_update"]) for p in d["plugins"] if p["id"]=="bar"][0]')"
P remove bar --json >/dev/null 2>&1
o="$(P install --file dist/bar-1.0.0-all.s2p --json 2>/dev/null)"; rc=$?
check "подписанный файл ставится" "0" "$rc"
"$S2P" build src/bar-1.0.0 --key evil.sec -o edist >/dev/null
P remove bar --json >/dev/null 2>&1
o="$(P install --file edist/bar-1.0.0-all.s2p --json 2>/dev/null)"; rc=$?
check "файл чужим ключом: отказ" "1" "$rc"
has "  причина" "такого ключа у ядра нет" "$o"

# ---- сторонний репозиторий ----
mkdir -p repo3 dist3
mk qux 1.0.0 ''
"$S2P" build src/qux-1.0.0 --key third.sec -o dist3 >/dev/null
"$S2P" index dist3 -o repo3 --repo third --pub third.pub --key third.sec --mirror https://x.invalid/ >/dev/null 2>&1
cp -r repo3 repo/third
KID="$(sed -n 2p third.pub | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read())[2:10].hex())')"
EID="$(sed -n 2p evil.pub | python3 -c 'import sys,base64;print(base64.b64decode(sys.stdin.read())[2:10].hex())')"
o="$(P repo add "http://127.0.0.1:$PORT/third/" "$EID" --json < evil.pub 2>/dev/null)"; rc=$?
check "repo add с ключом не того издателя: отказ" "1" "$rc"
has "  индекс подписан другим ключом" "такого ключа у ядра нет" "$o"
o="$(P repo add "http://127.0.0.1:$PORT/third/" "$EID" --json < third.pub 2>/dev/null)"; rc=$?
check "repo add: номер ключа не совпал" "1" "$rc"
o="$(P repo add "http://127.0.0.1:$PORT/third/" "$KID" --json < third.pub 2>/dev/null)"; rc=$?
check "repo add: подключён под именем из индекса" "0 third $KID" "$rc $(printf '%s\n' "$o" | jq_ 'd["name"]+" "+d["key_id"]')"
check "  repo list: не официальный" "third False" \
    "$(P repo list --json | jq_ '[r["name"]+" "+str(r["official"]) for r in d["repos"] if r["name"]=="third"][0]')"
o="$(P install qux --json 2>/dev/null)"; rc=$?
check "  плагин стороннего репозитория ставится" "0 third-party" \
    "$rc $(P list --json | jq_ '[p["trust"] for p in d["plugins"] if p["id"]=="qux"][0]')"
o="$(P repo del splify2 --json 2>/dev/null)"; rc=$?
check "официальный не отключается" "1" "$rc"
P repo del third --json >/dev/null
check "repo del: файл и ключи убраны" "no no" \
    "$([ -f etc/repos.d/third.json ] && echo yes || echo no) $([ -d etc/keys/third ] && echo yes || echo no)"

# ---- ensure из семени без сети ----
P remove qux --json >/dev/null 2>&1; P remove pk --json >/dev/null 2>&1; P remove neu --json >/dev/null 2>&1
rm -rf root/foo root/net1
python3 - etc/state.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["plugins"] = {}; json.dump(d, open(sys.argv[1], "w"))
PY
cp repo/index.json repo/index.json.sig seed/
cp repo/net1/1.2.0/net1-1.2.0-all.s2p repo/foo/1.3.0/foo-1.3.0-all.s2p seed/
rm -rf run/splify2
printf '{"id":"splify2","url":"http://127.0.0.1:1/","official":true,"priority":0,"keys":[]}\n' > etc/repos.d/splify2.json
o="$(P ensure foo --json 2>err.txt)"; rc=$?
check "ensure без сети: из семени" "0 net1:seed,foo:seed" "$rc $(printf '%s\n' "$o" | jq_ '",".join(x["id"]+":"+x["from"] for x in d["installed"])')"
check "  стоит версия семени" "foo 1.3.0" "$(root/foo/bin/foo)"
o="$(P ensure foo net1 --json 2>/dev/null)"
check "ensure уже стоящих — ничего не ставит" "[] ['foo', 'net1']" "$(printf '%s\n' "$o" | jq_ 'str(d["installed"])+" "+str(d["present"])')"
# migrate (переход 2.0.x → 2.1, migration-2.1.md, 3.3): плагины — по видам выходов спеки и по прежним пакетам модулей
# (migrate.json), из семени без сети; `steer-tgws` пакетом остаётся и плагином не ставится; готовый переход
# получает имя migrate.done.json.
P remove foo --force --json >/dev/null 2>&1; P remove net1 --force --json >/dev/null 2>&1
printf 'version: 2\noutputs:\n  d: { kind: direct }\n  f: { kind: tunnel, protocol: foo, subscription: /x }\n' > mspec.yaml
o="$(STEER_SPEC="$T/mspec.yaml" P migrate --json 2>err.txt)"; rc=$?
check "migrate по спеке: плагин вида tunnel:foo и его net1 — из семени" "0 net1:seed,foo:seed" \
    "$rc $(printf '%s\n' "$o" | jq_ '",".join(x["id"]+":"+x["from"] for x in d["installed"])')"
P remove foo --force --json >/dev/null 2>&1; P remove net1 --force --json >/dev/null 2>&1
printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > mspec0.yaml
printf '{"packages":["steer-foo","steer-tgws"]}\n' > etc/migrate.json
o="$(STEER_SPEC="$T/mspec0.yaml" P migrate --json 2>err.txt)"; rc=$?
check "migrate по прежним пакетам: steer-foo → плагин foo, steer-tgws пропущен" "0 net1:seed,foo:seed" \
    "$rc $(printf '%s\n' "$o" | jq_ '",".join(x["id"]+":"+x["from"] for x in d["installed"])')"
check "  готовый переход: migrate.done.json есть, migrate.json нет" "yes no" \
    "$([ -f etc/migrate.done.json ] && echo yes || echo no) $([ -f etc/migrate.json ] && echo yes || echo no)"
o="$(STEER_SPEC="$T/mspec.yaml" P migrate --json 2>/dev/null)"
check "повторный migrate ничего не ставит" "[] ['foo', 'net1']" "$(printf '%s\n' "$o" | jq_ 'str(d["installed"])+" "+str(d["present"])')"
# migrate обновляет стоящие плагины из семени: версия семени выше стоящей — ставится (net1 1.2.0 → 1.3.0), та же —
# нет; плагин из чужого репозитория не трогается.
mk net1 1.3.0 ''
build src/net1-1.3.0 proto.sec
index
cp repo/index.json repo/index.json.sig seed/
cp repo/net1/1.3.0/net1-1.3.0-all.s2p seed/
python3 - etc/state.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["plugins"]["net1"]["repo"] = "third"; json.dump(d, open(sys.argv[1], "w"))
PY
o="$(STEER_SPEC="$T/mspec.yaml" P migrate --json 2>/dev/null)"
check "migrate: плагин из чужого репозитория не обновляется" "[] 1.2.0" \
    "$(printf '%s\n' "$o" | jq_ 'str(d["installed"])+" "+json.load(open("etc/state.json"))["plugins"]["net1"]["version"]')"
python3 - etc/state.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["plugins"]["net1"]["repo"] = "splify2"; json.dump(d, open(sys.argv[1], "w"))
PY
o="$(STEER_SPEC="$T/mspec.yaml" P migrate --json 2>/dev/null)"; rc=$?
check "migrate: версия семени выше стоящей — обновление из семени" "0 net1 1.3.0 1.2.0 seed" \
    "$rc $(printf '%s\n' "$o" | jq_ '" ".join(x["id"]+" "+x["version"]+" "+x["old"]+" "+x["from"] for x in d["installed"])')"
check "  на месте 1.3.0" "1.3.0" "$(jq_ 'd["version"]' < root/net1/plugin.json)"
o="$(STEER_SPEC="$T/mspec.yaml" P migrate --json 2>/dev/null)"
check "migrate: версия та же — ничего не обновляет" "[]" "$(printf '%s\n' "$o" | jq_ 'str(d["installed"])')"
# Пометка «ядро не перечитало плагины» (прежнее поведение метило версию и при ошибке, бывшей до установки) снимается при
# переходе на новое ядро; прочие пометки остаются.
python3 - etc/state.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["plugins"]["foo"]["bad_versions"] = {"9.9.9": "ядро не перечитало плагины: spec.yaml:3: outputs.w: нужен reload", "9.9.8": "postinst вернул 3"}
json.dump(d, open(sys.argv[1], "w"))
PY
STEER_SPEC="$T/mspec.yaml" P migrate --json >/dev/null 2>&1
check "migrate: пометка с ошибкой перечитывания снята, чужая осталась" "['9.9.8']" \
    "$(jq_ 'str(sorted(d["plugins"]["foo"].get("bad_versions", {})))' < etc/state.json)"
rm -f etc/migrate.done.json
printf 'X' | dd of=seed/foo-1.3.0-all.s2p bs=1 seek=200 conv=notrunc 2>/dev/null
P remove foo --force --json >/dev/null 2>&1
o="$(P ensure foo --json 2>/dev/null)"; rc=$?
check "испорченное семя: отказ" "1" "$rc"
has "  причина" "испорчен" "$o"
printf '{"id":"splify2","url":"http://127.0.0.1:%s/","official":true,"priority":0,"keys":[]}\n' "$PORT" > etc/repos.d/splify2.json

# ---- с демоном: plugin-* сокета, событие plugin, plugin-reload ----
if [ "${PM_INNER:-}" = 1 ]; then
    mkdir -p st
    printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > dspec.yaml
    export STEER_SOCKET="$T/s.sock"
    # Срок автообновления уже прошёл: демон зовёт `plugin update --auto` через секунду после старта.
    python3 - etc/state.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["auto"] = {"next": "2000-01-01T00:00:00Z"}; json.dump(d, open(sys.argv[1], "w"))
PY
    # Демон читает плагины по своим переменным (реестр ядра): те же каталоги, что у менеджера.
    export STEER_PLUGINS_ROOT="$T/root" STEER_PLUGINS_ETC="$T/etc"
    STEER_PLUGIN_AUTO=1 "$BIN" daemon --socket "$T/s.sock" --spec "$T/dspec.yaml" --state-dir "$T/st" 2>d.err &
    D=$!
    i=0; while [ ! -S s.sock ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    python3 - "$T/s.sock" > events.txt <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"subscribe\n")
s.settimeout(30); buf = b""; end = time.time() + 30
while time.time() < end:
    try:
        d = s.recv(4096)
    except Exception:
        break
    if not d: break
    buf += d
    sys.stdout.write(d.decode()); sys.stdout.flush()
    if b'"state":"removed"' in buf: break
PY
    SUBP=$!
    sleep 0.5
    o="$("$BIN" ctl --socket "$T/s.sock" plugin-install foo)"
    check "ctl plugin-install foo: код 0" "0" "$(printf '%s\n' "$o" | jq_ 'd["code"]')"
    has "  stdout — ответ менеджера" '\"id\":\"foo\"' "$o"
    o="$("$BIN" ctl --socket "$T/s.sock" plugin-list)"
    check "ctl plugin-list" "foo,net1" "$(printf '%s\n' "$o" | jq_ '",".join(sorted(p["id"] for p in json.loads(d["stdout"])["plugins"]))' 2>/dev/null || echo "$o")"
    o="$("$BIN" ctl --socket "$T/s.sock" plugin-remove foo force)"
    check "ctl plugin-remove foo force" "0" "$(printf '%s\n' "$o" | jq_ 'd["code"]')"
    o="$("$BIN" ctl --socket "$T/s.sock" plugin-install '../x' 2>&1)"
    has "ctl: имя плагина проверяется до запуска" "bad-request" "$o"
    wait $SUBP 2>/dev/null
    has "событие plugin подписчику: enabled" '"ev":"plugin","id":"foo","state":"enabled","version":"1.3.0"' "$(cat events.txt)"
    has "  и removed" '"ev":"plugin","id":"foo","state":"removed"' "$(cat events.txt)"
    has "plugin-reload дошёл до демона: reload спеки" '"ev":"applied","by":"reload"' "$(cat events.txt)"
    i=0; while [ "$(jq_ 'd.get("auto",{}).get("last_check") or ""' < etc/state.json)" = "" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    check "таймер демона: фоновое обновление прошло по сроку из state.json" "yes" \
        "$([ -n "$(jq_ 'd.get("auto",{}).get("last_check") or ""' < etc/state.json)" ] && echo yes)"
    # ---- здоровье: откат только если установка УХУДШИЛА состояние; группа — одна проверка и откат целиком ----
    FOOK=',"requires":{"plugins":{"net1":"^1.2"}},"steer":{"commands":[{"name":"foo-hello","prog":"bin/foo"}],"kinds":[{"name":"tunnel:foo","helper":{"prog":"bin/foo"}}]}'
    "$BIN" ctl --socket "$T/s.sock" plugin-install foo >/dev/null 2>&1
    # (а) спека негодна ещё до установки (вид warp без плагина): установка не делает хуже — плагин остаётся.
    printf 'version: 2\noutputs:\n  a: { kind: warp }\n' > dspec.yaml
    "$BIN" ctl --socket "$T/s.sock" plugin-reload >/dev/null 2>&1
    mk foo 1.5.1 "$FOOK"
    "$S2P" build src/foo-1.5.1 --unsigned -o udist >/dev/null 2>&1
    o="$(P install --file udist/foo-1.5.1-all.s2p --unsigned --json 2>/dev/null)"; rc=$?
    check "здоровье: ошибка перечитывания была и до установки — плагин остаётся" "0 1.5.1" "$rc $(jq_ 'd["plugins"]["foo"]["version"]' < etc/state.json)"
    # Установка УХУДШИЛА: спека была здорова, postinst её испортил — откат.
    printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > dspec.yaml
    "$BIN" ctl --socket "$T/s.sock" plugin-reload >/dev/null 2>&1
    mk foo 1.5.2 "$FOOK"
    mkdir -p src/foo-1.5.2/scripts
    printf '#!/bin/sh\n[ "$1" = --check ] && exit 0\nprintf "outputs: [" > %s/dspec.yaml\nexit 0\n' "$T" > src/foo-1.5.2/scripts/postinst
    chmod 755 src/foo-1.5.2/scripts/postinst
    sed -i 's/"arch":"all"/"arch":"all","scripts":{"postinst":"scripts\/postinst"}/' src/foo-1.5.2/plugin.json
    "$S2P" build src/foo-1.5.2 --unsigned -o udist >/dev/null 2>&1
    o="$(P install --file udist/foo-1.5.2-all.s2p --unsigned --json 2>/dev/null)"; rc=$?
    check "здоровье: установка ухудшила (перечитывание теперь не удаётся) — откат" "1 1.5.1" "$rc $(jq_ 'd["plugins"]["foo"]["version"]' < etc/state.json)"
    printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > dspec.yaml
    P enable foo --json >/dev/null 2>&1
    # Плагин с хуком expand, которого требует спека: установка перечитывает плагины и заново готовит спеку
    # (а не требует reload), проверка здоровья проходит, выход разворачивается.
    mk xpw 1.0.0 ',"permissions":["spec.transform"],"steer":{"kinds":[{"name":"xpw","caps":["mark"],"resources":{"ports":1},"expand":{"prog":"bin/expand","argv":["{out}"]}}]}'
    printf '#!/bin/sh\ncat >/dev/null\nn="$1"\nprintf %s "{\\"self\\":{\\"kind\\":\\"group\\",\\"pick\\":\\"order\\",\\"members\\":[\\"$n.1\\"],\\"on_fail\\":\\"drop\\"},\\"outputs\\":{\\"$n.1\\":{\\"kind\\":\\"interface\\",\\"device\\":\\"lo\\"}},\\"helper\\":true}"\n' "'%s\\n'" > src/xpw-1.0.0/bin/expand
    printf '#!/bin/sh\nexit 0\n' > src/xpw-1.0.0/bin/xpwh
    chmod 755 src/xpw-1.0.0/bin/expand src/xpw-1.0.0/bin/xpwh
    "$S2P" build src/xpw-1.0.0 --unsigned -o udist >/dev/null 2>&1
    # Старая версия того же плагина — без хука expand (так стоял warpbox до 2.1.0).
    mk xpw 0.9.0 ',"steer":{"kinds":[{"name":"xpw","caps":["mark"]}]}'
    "$S2P" build src/xpw-0.9.0 --unsigned -o udist >/dev/null 2>&1
    P install --file udist/xpw-0.9.0-all.s2p --unsigned --json >/dev/null 2>&1
    printf 'version: 2\noutputs:\n  w1: { kind: xpw }\n' > dspec.yaml
    "$BIN" ctl --socket "$T/s.sock" plugin-reload >/dev/null 2>&1
    o="$(P install --file udist/xpw-1.0.0-all.s2p --unsigned --json 2>err.txt)"; rc=$?
    check "плагин с expand, которого требует спека: установка проходит" "0" "$rc"
    o="$("$BIN" ctl --socket "$T/s.sock" status)"
    check "  выход развёрнут: подготовленная спека, группа с членом" "group lo" \
        "$(printf '%s\n' "$o" | jq_ 'json.loads(d["stdout"])["outputs"]["w1"]["kind"]+" "+json.loads(d["stdout"])["outputs"]["w1"]["device"]')"
    P remove xpw --force --json >/dev/null 2>&1
    printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > dspec.yaml
    "$BIN" ctl --socket "$T/s.sock" plugin-reload >/dev/null 2>&1
    # Обновление из семени группой (migrate): новая версия net1 и foo встают вместе, проверка здоровья одна на группу;
    # не прошла — откатываются обе.
    P remove foo --force --json >/dev/null 2>&1
    P ensure foo --json >/dev/null 2>&1
    check "  до группы: net1 1.3.0, foo 1.3.0 из семени" "1.3.0 1.3.0" "$(jq_ 'd["plugins"]["net1"]["version"]+" "+d["plugins"]["foo"]["version"]' < etc/state.json)"
    mk net1 1.4.0 ''
    build src/net1-1.4.0 proto.sec
    mk foo 1.6.0 "$FOOK"
    mkdir -p src/foo-1.6.0/scripts
    printf '#!/bin/sh\n[ "$1" = --check ] && exit 0\nprintf "outputs: [" > %s/dspec.yaml\nexit 0\n' "$T" > src/foo-1.6.0/scripts/postinst
    chmod 755 src/foo-1.6.0/scripts/postinst
    sed -i 's/"arch":"all"/"arch":"all","scripts":{"postinst":"scripts\/postinst"}/' src/foo-1.6.0/plugin.json
    build src/foo-1.6.0 proto.sec
    index
    cp repo/index.json repo/index.json.sig seed/
    cp repo/net1/1.4.0/net1-1.4.0-all.s2p repo/foo/1.6.0/foo-1.6.0-all.s2p seed/
    o="$(P migrate --json 2>err.txt)"; rc=$?
    check "группа: foo 1.6.0 портит спеку — откатываются и foo, и net1" "1 1.3.0 1.3.0" \
        "$rc $(jq_ 'd["plugins"]["net1"]["version"]+" "+d["plugins"]["foo"]["version"]' < etc/state.json)"
    has "  проверка здоровья одна, на группу" "проверка здоровья группы" "$(cat err.txt)"
    printf 'version: 2\noutputs:\n  d: { kind: direct }\n' > dspec.yaml
    "$BIN" ctl --socket "$T/s.sock" plugin-reload >/dev/null 2>&1
    # Версии, не прошедшие проверку, помечены (bad_versions) и не берутся снова: здоровая группа — новыми версиями.
    mk net1 1.4.1 ''
    build src/net1-1.4.1 proto.sec
    mk foo 1.7.0 "$FOOK"
    build src/foo-1.7.0 proto.sec
    index
    cp repo/index.json repo/index.json.sig seed/
    cp repo/net1/1.4.1/net1-1.4.1-all.s2p repo/foo/1.7.0/foo-1.7.0-all.s2p seed/
    o="$(P migrate --json 2>err.txt)"; rc=$?
    check "группа: здоровая — net1 и foo обновлены" "0 1.4.1 1.7.0" \
        "$rc $(jq_ 'd["plugins"]["net1"]["version"]+" "+d["plugins"]["foo"]["version"]' < etc/state.json)"
    check "  проверка здоровья одна на группу, не по плагину" "1 0" \
        "$(grep -c 'проверка здоровья группы' err.txt) $(grep -c 'проверка здоровья foo\|проверка здоровья net1' err.txt)"
    kill $D 2>/dev/null; wait $D 2>/dev/null; D=""
else
    echo "pluginmgrmatch: блок с демоном ПРОПУЩЕН — нужен root и unshare (сеть демона и reload)"
fi

printf '\npluginmgrmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
