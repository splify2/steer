# PVS-Studio: прогон и базовая линия

`steer.suppress.json` — разобранные ложные срабатывания PVS-Studio 8.01 на коде steer
(2026-10-10, main 0bbb6ee): каждое предупреждение первого прогона получило вердикт, настоящие
исправлены (V522, V575, V597, V1032, V1071, V519, V547, V576). Файл гасит только разобранное —
новое предупреждение в изменённой строке покажется. Не погашены семь V597 в
`src/proto/xsteer/xshake.c` (защищённый путь): правка ждёт решения владельца.

Прогон на машине разработки (нужна лицензия PVS-Studio, `pvs-studio-analyzer credentials`):

```sh
export STEER_WOLFSSL=<исходники wolfSSL, как для make ext-test>
pvs-studio-analyzer trace -o /tmp/steer.trace -- make -B all ext-syntax libs-test
pvs-studio-analyzer analyze -f /tmp/steer.trace -o /tmp/steer.pvs -j8 \
    -s build/pvs/steer.suppress.json -e src/third_party -e /usr -e "$STEER_WOLFSSL"
plog-converter -t fullhtml -a 'GA:1,2,3;64:1,2,3;OP:1,2,3' -o /tmp/steer-pvs /tmp/steer.pvs
```

Трасса снимается и при упавшем стенде `libs-test` под strace — важна компиляция, а не итог.
Обновить базовую линию после разбора новых ложных: `pvs-studio-analyzer suppress -o
build/pvs/steer.suppress.json /tmp/steer.pvs` (только если всё, что в логе, разобрано).
