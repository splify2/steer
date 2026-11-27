# Приёмка `install --file`: net1 + VLESS

Linux x86_64/glibc, `cc`, `git`, `ldconfig`, `unshare`, `setpriv`, Python 3. Внешняя
оболочка должна уметь создать mount/net/PID namespaces; внутри — UID 65534, только `lo`,
частные `/etc`, `/var`, `/run`, `/tmp`. `steerd` не берётся из PATH. Gate проверяет три
разрешённых загрузчиком `.so` ядра; локальный ctl в опытах с health — наблюдатель протокола.

| Вход | Что нужно |
| --- | --- |
| `A` | Каталог `build-libs` core `70d11ebb6ab7b618508e1bbb593a3d28a9cf4d08` (ELF net1 1.5.0 / ABI 1.4 и VLESS 2.1.4). |
| `B` | Каталог `build-libs` core `515a4633fd3031ab40666df40094b06fbe19d4f4` (net1 1.6.0 / ABI 1.5 и другой VLESS 2.1.4). |
| `SDK`, `S2P` | Checkout `plugin-sdk` с объектом `fa2b823d928f6bdd3f1b4a533a0b2cb874b4f4dd`; исполняемый `s2p` с `keygen`, `lint`, `sign`. |
| `WOLFSSL_DIR`, `NGTCP2_DIR` | Деревья исходников для штатного `build/build-libs.sh`. |

Идентичность каждого исходного ELF проверяется по полному SHA-256 в `pluginmgr-net1-group.py`.
Это локальные host-фикстуры: примеры SDK без системных пакетов, TUN и UI, общий host
`steer-crypto`, одноразовые ключи. Упаковка не меняет ELF. До повторного чтения все `.s2p`
удаляются. Для наблюдения загрузки используются `LD_DEBUG` у manager и `LD_AUDIT` у
отдельной пробы. Отрицательный контроль fingerprint включается только в своём опыте.

Из корня проверяемого core (выходной каталог вне рабочего дерева):

```sh
R=$(mktemp -d /tmp/opencode/net1-accept.XXXXXX)
export WOLFSSL_DIR NGTCP2_DIR
JOBS=4 LIBS='-lpthread -ldl -lm' sh build/build-libs.sh "$R/libs" \
  "$(cat VERSION)" "$(git rev-parse --short HEAD)" >"$R/build.log" 2>&1
BUILD="$R/exports" STEER_WOLFSSL="$WOLFSSL_DIR" STEER_NGTCP2="$NGTCP2_DIR" \
  STEER_EXPORT_JOBS=4 sh build/libs-exports.sh check >"$R/exports.log" 2>&1
sh tests/pluginmgr-net1-group.sh "$A" "$B" "$SDK" "$S2P" "$R/libs" >"$R/net1.jsonl"
sh tests/pluginmgr-file-group.sh "$R/libs/steerd" "$R/libs" >"$R/file-group.log"
sh tests/pluginmgr-file-group.sh "$R/libs/steerd" "$B" >"$R/file-stock-so.log"
```

Код 0 требует всех результатов:

- Чистое обновление в обе стороны даёт целевые деревья и успешные пробу/`hello`.
  На штатном отказе зависимости или fingerprint возвращаются прежние деревья, а в реестре
  меняется только `bad_versions` уже опубликованного участника.
- `SIGKILL` после первого `state.json` даёт на диске B/A или A/B; первая смесь проходит
  отдельную пробу, во второй загрузчик возвращает 127. **Следующее** чтение обязано
  восстановить точные прежние деревья, реестр и `keep.d` в обоих случаях.
- То же — при разрезе после второго `state.json`, и после повторного `SIGKILL` между двумя
  обратными rename. После `finished`, включая середину GC, чтение сохраняет принятую пару.
  Убитая команда не отвечает успехом. Каждый результат проверяется отдельными `list`, `status`,
  повторным `status`; локальный конфиг и неизвестное поле старого реестра участвуют в проверке.
- Если часть отложенного дерева утрачена, прежнее состояние **не выводится из версий**
  и не берётся из архивов: три отказа `plugin.install_degraded`, свидетельства на месте.
- Та же сборка `.so` из постороннего каталога или код 0 без ABI-квитанции не годятся для принятия. Пустая подпись
  участника не допускается даже при `--unsigned`. Потеря `status` до/после публикации
  и ранее поднятый, но не вернувшийся выход не превращаются в успех.
