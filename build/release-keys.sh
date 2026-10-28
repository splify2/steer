#!/bin/sh
# Ключи подписи выпуска из секретов: закрытые — в файлы для s2p, открытые — раскладкой /usr/share/steer/keys/<роль>/.
#
#     S2P_KEY_INDEX=… S2P_KEY_PROTOCOLS=… [S2P_KEY_PLUGINS=…] sh build/release-keys.sh КАТАЛОГ
#
# Значение секрета — содержимое файла .sec в формате usign без пароля (`s2p keygen -o имя` или `usign -G -N`).
# Пишется:
#   КАТАЛОГ/sec/<роль>.sec, КАТАЛОГ/sec/<роль>.pub   — для s2p build/index (--key; --pub ищется рядом с ключом)
#   КАТАЛОГ/pub/<роль>/<номер>.pub                    — в пакет steer-core (STEER_KEYS_DIR=КАТАЛОГ/pub, build.sh)
# Открытый ключ выводится из закрытого (в закрытом ключе usign лежат номер и ключ Ed25519 целиком): ключ в пакете
# не может разойтись с ключом, которым подписан выпуск.
#
# Роли index и protocols обязательны: без них выпуск ядра не выходит (без индекса и семени, подписанных
# официальным ключом, роутер не поставит ни одного протокола). Тестового ключа здесь нет намеренно.
# plugins — по желанию: ядро подписывает им только при наличии, но кладёт открытый ключ в пакет, чтобы
# роутер принимал архивы splify2-core-plugins и splify2-extended-plugins.
set -eu
DIR="${1:?нужен каталог для ключей}"
umask 077
mkdir -p "$DIR/sec" "$DIR/pub"
miss=""
for role in index protocols plugins; do
    case "$role" in
        index) val="${S2P_KEY_INDEX:-}" ;;
        protocols) val="${S2P_KEY_PROTOCOLS:-}" ;;
        plugins) val="${S2P_KEY_PLUGINS:-}" ;;
    esac
    if [ -z "$val" ]; then
        [ "$role" = plugins ] || miss="$miss S2P_KEY_$(echo "$role" | tr a-z A-Z)"
        continue
    fi
    printf '%s\n' "$val" > "$DIR/sec/$role.sec"
    num="$(python3 - "$DIR/sec/$role.sec" "$DIR/sec/$role.pub" "$role" <<'PY'
import base64, sys
sec, pub, role = sys.argv[1:4]
lines = [l for l in open(sec).read().splitlines() if l.strip()]
if len(lines) != 2 or not lines[0].startswith("untrusted comment:"):
    sys.exit(f"{role}: секрет не похож на закрытый ключ usign (две строки: «untrusted comment: …» и base64)")
raw = base64.b64decode(lines[1])
if len(raw) != 104 or raw[:4] != b"EdBK":
    sys.exit(f"{role}: не закрытый ключ Ed25519 usign (нужно 104 байта «EdBK…», а их {len(raw)})")
if any(raw[4:8]):
    sys.exit(f"{role}: закрытый ключ зашифрован паролем — s2p читает ключи без пароля")
num = raw[32:40]
# Закрытый ключ Ed25519 в usign — 64 байта: семя и открытый ключ; открытый — последние 32.
body = base64.b64encode(b"Ed" + num + raw[72:104]).decode()
open(pub, "w").write(f"untrusted comment: splify2 {role} key {num.hex()}\n{body}\n")
print(num.hex())
PY
)"
    mkdir -p "$DIR/pub/$role"
    umask 022
    cp "$DIR/sec/$role.pub" "$DIR/pub/$role/$num.pub"
    chmod 0644 "$DIR/pub/$role/$num.pub"
    umask 077
    echo "ключ $role: $num"
done
if [ -n "$miss" ]; then
    echo "нет секретов:$miss — выпуск подписывается только ключами splify2 (Settings → Secrets and variables → Actions;" \
         "значение — файл .sec от \`s2p keygen -o имя\`), тестового ключа в выпуске нет" >&2
    exit 1
fi
