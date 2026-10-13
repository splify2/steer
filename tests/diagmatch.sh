#!/bin/sh
# Диагностика (`steer diag`) на фикстурах: без роутера, в своих пространствах имён.
#
# Почему стенд шелловый, а не на C. diag — подкоманда, которая почти целиком состоит из вопросов
# к системе: таблица и наборы nf_tables, маршрут IPv6, живые процессы. Проверять её по функциям
# нечего, зато поставить ядру нужное состояние и посмотреть на JSON — ровно то, что делает
# человек, когда читает вывод diag на роутере.
#
# Раньше состояние подставлялось подменой nft, pgrep и ip в PATH. Теперь diag этих команд не
# запускает вовсе (ядро — по netlink, процессы — обходом /proc), поэтому стенд живёт в своём
# сетевом пространстве (набор правил и маршруты заводят настоящие nft и ip) и в своём
# пространстве PID со своим /proc (резолвер «запущен» ровно тогда, когда его запустил стенд).
# Нужны root, unshare и nft; без них стенд пропускается.
#
# Бинарник отдельный (build/diagsim): спека с `kind: vless` отвергается парсером базовой
# сборки, а именно VLESS-выход интересен диагностике — см. tests/vless-stub.c.
set -u
DIAG="${DIAG:-./build/diagsim}"
[ -x "$DIAG" ] || { echo "not built: $DIAG (make test)"; exit 2; }
if [ "${DIAGMATCH_INNER:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ] && command -v nft >/dev/null 2>&1 &&
       unshare -n -p -f -m --mount-proc true 2>/dev/null; then
        DIAGMATCH_INNER=1 exec unshare -n -p -f -m --mount-proc sh "$0" "$@"
    fi
    echo "diagmatch: нет root, nft или своих пространств имён — пропущен"
    exit 0
fi
ip link set lo up
# Свой sysfs: diag смотрит устройства по /sys/class/net, а sysfs показывает сеть того
# пространства, в котором его смонтировали. Без перемонтирования стенд читал устройства ХОСТА —
# на машине с настоящим wg0 «выход в wg0» был у стенда живым, на машине без него — пропавшим.
mount -t sysfs sysfs /sys 2>/dev/null || echo "diagmatch: свой sysfs не смонтирован — устройства читаются с хоста"

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# ---- окружение: таблица движка в ядре своего пространства --------------------
# Таблица на месте, встречная цепочка тоже: так проверки 1-2 дают ok и не шумят в выводе, а
# интересующие нас проверки остаются единственными находками. Наборы каналов пусты. Резолвер не
# запущен и IPv6 наружу нет: обе проверки при этом молчат либо ругаются предсказуемо.
{ nft add table inet steer &&
  nft add set inet steer vpn_ip '{ type ipv4_addr; flags interval; }' &&
  nft add chain inet steer prerouting_mark &&
  nft add chain inet steer postrouting_down; } || { echo "diagmatch: nft не прошёл"; exit 1; }

# spec NAME KIND — конфигурация с одним адресным каналом в выход указанного вида.
#
# Локальная переменная называется outdef, а НЕ out. Раньше здесь было `out`, то есть то же
# имя, в котором ниже лежит отчёт diag: вызов `spec vless vless` затирал отчёт интерфейсного
# выхода куском JSON, и две проверки после него сравнивали пустоту с пустотой, а «у vless
# проверок больше» превращалось в «4 больше 0» — истинное при любом поведении движка.
spec() {
    if [ "$2" = "vless" ]; then
        outdef='vpn: { kind: tunnel, protocol: vless, subscription: /etc/steer/sub.json, on_fail: drop }'
    else
        outdef='vpn: { kind: interface, device: wg0, on_fail: drop }'
    fi
    # Локальное устройство здесь `lo`, а не `br-lan`, и это не описка. diag проверяет
    # перечисленные устройства по /sys/class/net, и `br-lan` в окружении стенда не
    # существует — то есть КАЖДАЯ фикстура несла бы лишний warn, а две проверки ниже стоят
    # ровно на том, что счётчик warn остаётся нулём. `lo` есть везде, включая контейнер
    # сборки. Сама проверка «устройства нет» стоит отдельным блоком в конце файла.
    cat > "$tmp/$1.yaml" <<EOF
version: 2
lan: { devices: [lo], addr: [192.168.1.0/24] }
lists:
  cloudflare: { prefixes_file: $tmp/cf.lst }
outputs:
  $outdef
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: vpn }
EOF
}
echo '104.16.0.0/13' > "$tmp/cf.lst"

# verdict ID < вывод diag — приговор проверки с данным id, пусто если проверки нет.
verdict() { sed -n "s/.*{\"id\":\"$1\",\"verdict\":\"\([a-z]*\)\".*/\1/p" | head -1; }
# count — сколько всего проверок в отчёте.
count() { tr ',' '\n' | grep -c '"id":'; }

# ---- отчёт вообще собирается ------------------------------------------------
spec iface interface
out="$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null)"
check "отчёт начинается со schema" "1" "$(printf '%s' "$out" | sed -n 's/.*"schema":\([0-9]*\).*/\1/p')"
check "таблица найдена" "ok" "$(printf '%s' "$out" | verdict table)"
check "встречная цепочка найдена" "ok" "$(printf '%s' "$out" | verdict down_chain)"

# ---- UDP через VLESS: заметки БОЛЬШЕ НЕТ (I-026 снят) ------------------------
# Прежде здесь проверялось, что движок говорит «выход VLESS несёт только TCP». Туннель
# теперь несёт UDP командой VLESS 2 (QUIC, WireGuard, игры), и заметка убрана: сообщение о
# снятом ограничении хуже молчания — по нему уходят настраивать обход, которого не нужно.
#
# Проверка осталась, но с обратным ожиданием: пусто. Так поломка «заметку вернули вместе с
# копипастой» будет видна сразу.
spec vless vless
outv="$($DIAG diag --spec "$tmp/vless.yaml" 2>/dev/null)"
check "выход vless: про UDP молчим (UDP поддержан)" "" "$(printf '%s' "$outv" | verdict udp)"
check "выход interface: про UDP молчим" "" "$(printf '%s' "$out" | verdict udp)"

# ---- публичный резолвер внутри списка канала (I-030) ------------------------
# Категории издателя собираются по ASN целиком, поэтому 8.8.8.0/24 (Google Public DNS)
# лежит внутри «YouTube» и «Google», а 1.1.1.0/24 — внутри «Cloudflare». Уйдя в туннель
# VLESS, запросы к такому резолверу теперь ПРОХОДЯТ — но у UDP поток к узлу свой на каждую
# пару адрес-порт, а DNS берёт новый порт на каждый запрос: имя разрешается ценой отдельного
# рукопожатия с узлом. Поэтому заметка осталась, а приговор стал мягче.
echo '1.1.1.0/24' >> "$tmp/cf.lst"
outr="$($DIAG diag --spec "$tmp/vless.yaml" 2>/dev/null)"
check "резолвер в списке: сказано" "note" "$(printf '%s' "$outr" | verdict resolver)"
check "назван сам адрес" "1" \
      "$(printf '%s' "$outr" | grep -c '1\.1\.1\.0/24' || true)"
# Приговор note, а не warn: имена разрешаются, поломки нет — а warn на постоянном условии
# красит исправный роутер в жёлтый навсегда (та же причина, что у doh).
check "note не идёт в счётчик warn" "0" "$(printf '%s' "$outr" | sed -n 's/.*"warn":\([0-9]*\).*/\1/p')"

# Выход-устройство несёт UDP ядром, своих потоков к узлу там нет — говорить не о чем.
outri="$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null)"
check "выход interface: про резолвер молчим" "" "$(printf '%s' "$outri" | verdict resolver)"

# С доменными правилами есть перенаправление DNS, и цену платят только клиенты вне
# from_default. Приговор тот же note, но текст другой — проверяем, что он про перенаправление.
echo 'example.com' > "$tmp/dom.lst"
sed 's#prefixes_file: '"$tmp"'/cf.lst }#prefixes_file: '"$tmp"'/cf.lst, domains_file: '"$tmp"'/dom.lst }#' \
    "$tmp/vless.yaml" > "$tmp/vless-dom.yaml"
outrd="$($DIAG diag --spec "$tmp/vless-dom.yaml" 2>/dev/null)"
check "есть редирект DNS: он и назван" "1" \
      "$(printf '%s' "$outrd" | grep -c 'from_default прикрывает' || true)"

# Список без резолверов — молчим: иначе метка станет постоянной.
grep -v '^1\.1\.1\.0/24$' "$tmp/cf.lst" > "$tmp/cf-clean.lst"
sed "s#$tmp/cf.lst#$tmp/cf-clean.lst#" "$tmp/vless.yaml" > "$tmp/vless-clean.yaml"
outrc="$($DIAG diag --spec "$tmp/vless-clean.yaml" 2>/dev/null)"
check "список без резолверов: молчим" "" "$(printf '%s' "$outrc" | verdict resolver)"

# ---- отчёт остаётся разбираемым --------------------------------------------
# Здесь стояло «проверок с vless больше, чем без него». Лишней у vless была ровно заметка
# про UDP, и когда её убрали (I-026, см. выше), утверждение стало неверным — но заметить
# это было нельзя: переменная с отчётом интерфейсного выхода затиралась вызовом spec(), и
# сравнение вырождалось в «4 больше 0», истинное всегда.
#
# Проверяется то, что осталось правдой: отчёт разбираем для обоих видов выхода, и состав
# проверок у них ОДИНАКОВ — то есть vless больше не порождает заметок про самого себя.
check "отчёт с vless разбираем" "1" \
      "$([ "$(printf '%s' "$outv" | count)" -gt 0 ] && echo 1 || echo 0)"
# Единственное, что у vless своё, — заметка ipv6_output (1.9): IPv6 его правил отбрасывается, а не
# идёт напрямую. Это свойство вида, а не заметка про самого себя, и она совет (note), а не warn.
check "vless не добавляет своих заметок (кроме ipv6_output)" \
      "$(printf '%s' "$out" | count)" "$(($(printf '%s' "$outv" | count) - 1))"
check "  ipv6_output у vless — совет, а не предупреждение" "note" \
      "$(printf '%s' "$outv" | verdict ipv6_output)"
check "  у интерфейса (IPv6 есть) её нет" "" "$(printf '%s' "$out" | verdict ipv6_output)"

# ---- подъём выхода vless: перебор узлов больше не выглядит отказом (I-100) ----
# Устройство туннеля vless появляется только ПОСЛЕ выбора узла, а при `node: -1` выбор — это
# перебор подписки с таймаутом восемь секунд на узел. Пока перебор идёт, устройства нет, и
# раньше diag говорил «устройства нет, туннель не поднят» — то есть в точности то же, что при
# настоящем отказе. На трёх десятках нерабочих узлов исправная настройка минутами выглядела
# сломанной, а настоящий отказ — медленной проверкой.
#
# Клиент теперь пишет ход перебора файлом в state_dir, а diag его читает. Проверяются все
# ветви, включая обе защиты от устаревания: без них новый канал состояния сам стал бы
# источником лжи — «проверяю узлы» навсегда после убитого процесса.
mkdir -p "$tmp/state"
probe() { printf '%s\n' "$1" > "$tmp/state/probe-vpn"; }
dg() { $DIAG diag --spec "$tmp/vless.yaml" --state-dir "$tmp/state" 2>/dev/null; }
# what у проверки с данным id — им и отличаются три случая одного «устройства нет».
what() { sed -n 's/.*{"id":"output","verdict":"[a-z]*","what":"\([^"]*\)".*/\1/p' | head -1; }

rm -f "$tmp/state/probe-vpn"
check "файла состояния нет — приговор прежний" "fail" "$(dg | verdict output)"

probe "probing 3 26 $$ $(date +%s)"
check "идёт перебор: это совет, а не находка" "note" "$(dg | verdict output)"
check "названы номер узла и сколько их всего" "1" \
      "$(dg | what | grep -c 'проверяю узлы, 3 из 26')"
# Совет не идёт в счётчик warn: иначе на исправном роутере всё время подъёма горела бы
# жёлтая метка, а она учит не смотреть на проверки вовсе.
check "перебор не считается предупреждением" "0" \
      "$(dg | sed -n 's/.*"warn":\([0-9]*\).*/\1/p')"

# Первая защита от устаревания: «проверяю» верно, только пока жив написавший процесс.
probe "probing 3 26 999999 $(date +%s)"
check "перебор от мёртвого процесса читается как «не знаем»" "fail" "$(dg | verdict output)"
check "и приговор возвращается к прежнему тексту" "1" \
      "$(dg | what | grep -c 'устройства vpn нет')"

probe "failed 0 26 999999 $(date +%s)"
check "ни один узел не ответил — отказ, а не «устройства нет»" "fail" "$(dg | verdict output)"
check "названо, сколько узлов проверено" "1" \
      "$(dg | what | grep -c 'ни один узел подписки не ответил (проверено 26)')"

probe "failed 0 0 999999 $(date +%s)"
check "узлов в подписке нет — сказано именно это" "1" \
      "$(dg | what | grep -c 'в подписке нет пригодных узлов')"

# Вторая защита: приговор переживает смерть процесса намеренно (procd поднимает клиента
# заново каждые пять секунд), но живёт, пока свеж. Старше двух минут — никто больше не
# пробует, и говорить за него нельзя.
probe "failed 0 26 999999 $(( $(date +%s) - 200 ))"
check "устаревший приговор не выдаётся за свежий" "1" \
      "$(dg | what | grep -c 'устройства vpn нет')"

# Мусор в файле — тоже «не знаем»: разбор обязан отличать «нечего сказать» от «сломано».
probe "какая-то ерунда"
check "неразбираемый файл читается как «не знаем»" "1" \
      "$(dg | what | grep -c 'устройства vpn нет')"

# ---- то же поле в status: интерфейс не должен гадать -------------------------
probe "probing 7 26 $$ $(date +%s)"
st() { $DIAG status --spec "$tmp/vless.yaml" --state-dir "$tmp/state" 2>/dev/null; }
check "status несёт ход перебора" "1" \
      "$(st | grep -c '"probe":{"state":"probing","node":7,"total":26}')"
probe "failed 0 26 999999 $(date +%s)"
check "status несёт и отказ" "1" \
      "$(st | grep -c '"probe":{"state":"failed","total":26}')"
rm -f "$tmp/state/probe-vpn"
check "нечего сказать — поля нет вовсе" "0" "$(st | grep -c '"probe"')"

# ---- выбранные узлы подписки в status ----------------------------------------
#
# Поле обязано печататься ВСЕГДА у kind=vless, в том числе пустым, и это здесь главное.
# Незнакомый ключ спеки движок пропускает молча (js_skip), поэтому интерфейс, записавший
# `nodes` в движок, который их не понимает, получил бы применённую спеку и трафик через узел,
# которого не выбирал. Наличие поля в status — единственный способ отличить такой движок, не
# применяя спеку; ровно тем же приёмом отличается движок с lan_devices.
check "status: выбор узлов есть и пустым" "1" \
      "$(st | grep -c '"nodes":\[\]')"
sed 's/on_fail: drop }/on_fail: drop, nodes: [6, 7, 12] }/' \
    "$tmp/vless.yaml" > "$tmp/vless-nodes.yaml"
check "status: выбранные узлы в порядке предпочтения" "1" \
      "$($DIAG status --spec "$tmp/vless-nodes.yaml" 2>/dev/null | grep -c '"nodes":\[6,7,12\]')"
# У выхода без подписки поля нет вовсе: кандидаты kind=interface — устройства, и пустой
# `nodes` рядом с ними читался бы как «узлы есть, но не выбраны».
#
# Ищется `"nodes":` с двоеточием, а не одно имя: верхним уровнем status печатает перечень
# умений, и слово `nodes` стоит там ВСЕГДА как имя умения (см. tests/statusmatch.sh). Поиск
# по одному имени с появлением перечня стал бы вечнозелёным и перестал бы стеречь то, ради
# чего заведён.
check "status: у выхода-интерфейса поля нет" "0" \
      "$($DIAG status --spec "$tmp/iface.yaml" 2>/dev/null | grep -c '"nodes":')"

# ---- локальные устройства: перечислено одно, а на роутере его нет (splify2#16) -----
#
# Правило по `iifname` грузится и на отсутствующее устройство — так и задумано, иначе
# перезагрузка роутера оставляла бы человека без правил, пока не поднимется tailscale0. Но
# «правило есть, устройства нет» означает «правило не сработает ни разу», и у человека,
# опечатавшегося в имени, картина ровно та же, что у исправной настройки. Отвечает на это
# diag, и вот чем именно.
cat > "$tmp/lan.yaml" <<EOF
version: 2
lan: { devices: [lo, нетакого0] }
lists:
  cloudflare: { prefixes_file: $tmp/cf.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: vpn }
EOF
# Имя с кириллицей до /sys/class/net не доходит: состав имени проверяется при загрузке
# спеки, потому что оно уходит и в текст правил, и в командные строки.
check "негодное имя устройства — отказ загрузки" "2" \
      "$($DIAG diag --spec "$tmp/lan.yaml" >/dev/null 2>&1; echo $?)"

sed -i 's/нетакого0/zt7bcxxxxx/' "$tmp/lan.yaml"
outl="$($DIAG diag --spec "$tmp/lan.yaml" 2>/dev/null)"
# Приговор общий по проверке: первым идёт `lo`, он есть, поэтому ok; отсутствующее
# устройство ищем по тексту, а не по первому приговору.
check "существующее устройство — ok" "1" \
      "$(printf '%s' "$outl" | grep -c '{"id":"lan_device","verdict":"ok","what":"трафик забирается с lo"')"
check "отсутствующее — warn, и названо по имени" "1" \
      "$(printf '%s' "$outl" | grep -c '{"id":"lan_device","verdict":"warn","what":"zt7bcxxxxx перечислен')"
# Предупреждение, а не поломка: остальные перечисленные устройства при этом работают, и
# красить весь роутер в красный из-за выключенного Tailscale нельзя.
check "отсутствие устройства — не поломка" "0" \
      "$(printf '%s' "$outl" | grep -c '{"id":"lan_device","verdict":"fail"')"
# И то же поле в status: интерфейсу нужно знать, с чего забирается трафик, не читая спеку.
check "status перечисляет локальные устройства" "1" \
      "$($DIAG status --spec "$tmp/lan.yaml" 2>/dev/null | grep -c '"lan_devices":\["lo","zt7bcxxxxx"\]')"

# ---- br_netfilter: кадры внутри моста идут через ip-хуки netfilter -----------
#
# Модуль br_netfilter вместе с `net.bridge.bridge-nf-call-iptables=1` заставляет кадры,
# ходящие ВНУТРИ моста (клиент↔клиент по LAN), проходить через ip-хуки netfilter. Значит наше
# перенаправление порта 53 начинает касаться и запросов, которые из роутера не выходят вовсе:
# правило `... udp dport 53 redirect to :5300` условия на ПОЛУЧАТЕЛЯ не имеет, и запрос
# клиента к DNS-серверу на той же LAN (Pi-hole, второй роутер, AdGuard на NAS) заворачивается
# к нам. Выглядит это как «мой Pi-hole перестал получать запросы» при исправной настройке
# steer, и объяснить это без приговора нечем.
#
# Приговор warn, а не note: в отличие от совета про DoH, это не свойство мира, а
# переключаемая настройка ЭТОЙ системы с наблюдаемым следствием. Модуль при этом НЕ
# выключается: он чужой, у него бывают причины (docker, libvirt), и наше дело сказать.
#
# Путь к sysctl берётся из STEER_BRIDGE_NF, иначе стенду нечего проверять: загрузить модуль в
# контейнере сборки нельзя, а приговор обязан стеречься так же, как остальные.
cat > "$tmp/nobr.yaml" <<EOF
version: 2
lan: { devices: [lo], addr: [192.168.1.0/24] }
lists:
  cloudflare: { prefixes_file: $tmp/cf-clean.lst }
outputs:
  vpn: { kind: interface, device: wg0 }
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: vpn }
EOF
dgb() { STEER_BRIDGE_NF="$1" $DIAG diag --spec "$tmp/nobr.yaml" 2>/dev/null; }

# Модуль не загружен — файла нет вовсе. Это хорошее состояние, и сказать о нём надо: «нечего
# не сказано» человек читает как «не проверяли».
check "модуля нет: ok" "ok" "$(dgb "$tmp/нетфайла" | verdict bridge_nf)"
# Модуль загружен, но выключен — то же самое хорошее состояние.
printf '0\n' > "$tmp/brnf"
check "модуль есть, выключен: ok" "ok" "$(dgb "$tmp/brnf" | verdict bridge_nf)"
# Включён — предупреждение.
printf '1\n' > "$tmp/brnf"
check "включён: предупреждение" "warn" "$(dgb "$tmp/brnf" | verdict bridge_nf)"
check "включён: сказано про DNS внутри LAN" "1" \
      "$(dgb "$tmp/brnf" | grep -c 'bridge-nf-call-iptables')"
# Приговор обязан идти в счётчик warn: это находка, а не совет.
check "включён: считается предупреждением" "1" \
      "$(dgb "$tmp/brnf" | sed -n 's/.*"warn":\([0-9]*\).*/\1/p')"
# И не поломка: маршрутизация работает, объяснять надо чужую жалобу, а не свою.
check "включён: не поломка" "0" \
      "$(dgb "$tmp/brnf" | grep -c '{"id":"bridge_nf","verdict":"fail"')"
# Мусор в файле читается как «не знаем» и молчит: приговор наугад хуже молчания.
printf 'ерунда\n' > "$tmp/brnf"
check "мусор в файле: молчим" "" "$(dgb "$tmp/brnf" | verdict bridge_nf)"

# ---- masquerade в пуле: приговор по ВЛАДЕЛЬЦУ устройства ----------------------
#
# Пул разнородных туннелей — это выход kind=interface, в devices которого названо устройство,
# созданное выходом kind=vless или kind=xsteer. Приговор «нужен ли masquerade» брался по виду
# выхода, который устройство НАЗВАЛ, поэтому на исправно собранном пуле висело вечное «нет
# masquerade»: жёлтая метка, от которой перестают смотреть на проверки вовсе. Той же болезнью
# болел device_healthy_for, там она стоила дороже (пул уходил в blackhole).
#
# Фикстура требует УСТРОЙСТВА, которое существует: до fw_check диагностика не доходит, пока
# устройства нет в /sys/class/net. Поэтому и туннель, и пул смотрят в `lo`, а фаервол
# подменён так, чтобы устройство было в зоне и masquerade у него НЕ БЫЛО, — иначе проверка
# уходила бы в ветку «NAT есть» и не значила бы ничего. Блок последний в файле: подменённый
# набор правил здесь другой, и восстанавливать его больше некому.
nft add table inet fw4
nft add chain inet fw4 forward_lan
nft add rule inet fw4 forward_lan oifname '"lo"' accept
cat > "$tmp/pool.yaml" <<EOF
version: 2
lan: { devices: [zt7bcxxxxx], addr: [192.168.1.0/24] }
lists:
  cloudflare: { prefixes_file: $tmp/cf.lst }
outputs:
  loc: { kind: tunnel, protocol: vless, subscription: /etc/steer/sub.json, device: lo }
  pool: { kind: interface, device: lo, on_fail: drop }
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: pool }
EOF
outp="$($DIAG diag --spec "$tmp/pool.yaml" 2>/dev/null)"
check "пул: устройство туннеля в зоне" "1" \
      "$(printf '%s' "$outp" | grep -c '"what":"выход pool: устройство lo в зоне"')"
check "пул: masquerade не требуется" "0" \
      "$(printf '%s' "$outp" | grep -c 'у lo нет masquerade')"
# Приговор владельца при этом остаётся его собственным: у выхода vless он был верен и раньше.
check "владелец устройства: masquerade не требуется" "1" \
      "$(printf '%s' "$outp" | grep -c '"what":"выход loc: устройство lo в зоне"')"

# ---- группа судится по члену, который НЕСЁТ ТРАФИК, а не по первому в списке ----
#
# Группа из двух членов, основной на роутере отсутствует: трафик идёт через второго. Приговор
# первому члену — «выход pool: устройства nodev0 нет», fail — рисовал бы поломку на работающем
# выходе, а вместе с ней и вечное «нет masquerade», если владелец спрашивается про не то
# устройство. Выбор группы v2 считается по присутствию членов (outputs_adopt_active_st), запись
# `active` лишь подсказка: с «pool lo» и без записи результат один.
mkdir -p "$tmp/state"
cat > "$tmp/pool2.yaml" <<EOF
version: 2
lan: { devices: [zt7bcxxxxx], addr: [192.168.1.0/24] }
lists:
  cloudflare: { prefixes_file: $tmp/cf.lst }
outputs:
  loc: { kind: tunnel, protocol: vless, subscription: /etc/steer/sub.json, device: lo }
  pool: { kind: group, pick: order, members: [pool.nodev0, pool.lo], on_fail: drop }
  pool.nodev0: { kind: interface, device: nodev0 }
  pool.lo: { kind: interface, device: lo }
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: pool }
EOF
printf 'pool lo\n' > "$tmp/state/active"
outp2="$($DIAG diag --spec "$tmp/pool2.yaml" --state-dir "$tmp/state" 2>/dev/null)"
st2="$($DIAG status --spec "$tmp/pool2.yaml" --state-dir "$tmp/state" 2>/dev/null)"
check "группа: status — несёт трафик второй член, устройство lo, выход поднят" "1" \
      "$(printf '%s' "$st2" | grep -c '"pool":{"kind":"group","device":"lo","up":true,.*"selected":"pool.lo","alive":\["pool.lo"\]')"
check "группа: masquerade не требуется и здесь" "0" \
      "$(printf '%s' "$outp2" | grep -c 'нет masquerade')"
# diag судит членов по одному: отсутствующий nodev0 — приговор ему самому, а не группе.
check "группа: приговор отсутствующему члену — его собственный" "1" \
      "$(printf '%s' "$outp2" | grep -c '"what":"выход pool.nodev0: устройства nodev0 нет"')"
check "группа: про саму группу «нет устройства» не сказано" "0" \
      "$(printf '%s' "$outp2" | grep -c '"what":"выход pool: устройства')"

# Записи сторожа нет вовсе (он ещё не проходил): берётся первый СУЩЕСТВУЮЩИЙ член — то же
# самое устройство, к которому привяжет таблицу apply.
rm -f "$tmp/state/active"
check "группа без записи сторожа: первый существующий член" "1" \
      "$($DIAG status --spec "$tmp/pool2.yaml" --state-dir "$tmp/state" 2>/dev/null | grep -c '"pool":{"kind":"group","device":"lo","up":true,')"

# ---- выход в отказе ---------------------------------------------------------------
#
# Живых членов нет — группа в отказе, ставится on_fail. У прежнего пула отказ ставила запись «-»
# в active; у группы v2 он выводится из присутствия и приговоров членов, записи не нужно. Член на
# отсутствующем устройстве не живой, и status не рисует группу живой, пока трафик её стоит:
# интерфейс иначе показывал бы работающим выход, чей трафик остановлен.
cat > "$tmp/pool3.yaml" <<EOF
version: 2
lan: { devices: [zt7bcxxxxx], addr: [192.168.1.0/24] }
lists:
  cloudflare: { prefixes_file: $tmp/cf.lst }
outputs:
  loc: { kind: tunnel, protocol: vless, subscription: /etc/steer/sub.json, device: lo }
  pool: { kind: group, pick: order, members: [pool.nodev0, pool.nodev1], on_fail: drop }
  pool.nodev0: { kind: interface, device: nodev0 }
  pool.nodev1: { kind: interface, device: nodev1 }
  direct: { kind: direct }
rules:
  - { name: cloudflare, to: cloudflare, out: pool }
EOF
stf="$($DIAG status --spec "$tmp/pool3.yaml" --state-dir "$tmp/state" 2>/dev/null)"
check "отказ: status — up false и failed true у группы, выбранного члена нет" "1" \
      "$(printf '%s' "$stf" | grep -c '"pool":{"kind":"group","device":"nodev0","up":false,"failed":true,.*"selected":null,"alive":\[\]')"
check "отказ: у соседнего выхода failed нет" "0" \
      "$(printf '%s' "$stf" | grep -c '"loc":{[^}]*"failed"')"
check "отказ: умение названо" "1" "$(printf '%s' "$stf" | grep -o '"features":\[[^]]*\]' | grep -c '"failed"')"
check "без отказа: failed нет" "0" \
      "$($DIAG status --spec "$tmp/pool2.yaml" --state-dir "$tmp/state" 2>/dev/null | grep -c '"failed":true')"

# ---- число адресов в наборе — у ядра, столько же, сколько у nft ---------------------
nft add element inet steer vpn_ip '{ 104.16.0.0/13, 1.1.1.0/24, 9.9.9.9 }'
want="$(nft list set inet steer vpn_ip | tr ',' '\n' | grep -c '[0-9]\.[0-9]')"
check "набор: адресов в ядре — столько, сколько элементов печатает nft" "1" \
      "$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null | grep -c "\"verdict\":\"ok\",\"what\":\"канал vpn_ip: адресов в ядре $want\"")"

# ---- резолвер жив — по /proc своего пространства PID -----------------------------
check "резолвера нет — fail" "fail" "$($DIAG diag --spec "$tmp/vless-dom.yaml" 2>/dev/null | verdict dnsd)"
mkdir -p "$tmp/fake"
printf '#!/bin/sh\nsleep 30\n' > "$tmp/fake/steer"
chmod +x "$tmp/fake/steer"
"$tmp/fake/steer" dnsd &
FPID=$!
sleep 0.2
check "процесс «…/steer dnsd» есть — ok" "ok" "$($DIAG diag --spec "$tmp/vless-dom.yaml" 2>/dev/null | verdict dnsd)"
kill "$FPID" 2>/dev/null
wait "$FPID" 2>/dev/null

# ---- IPv6 наружу — маршрут по умолчанию в таблице main -------------------------
check "маршрута IPv6 нет — проверки нет" "" "$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null | verdict ipv6)"
if ip link add d6 type dummy 2>/dev/null && ip link set d6 up && ip -6 route add default dev d6 2>/dev/null; then
    # С 1.9 правила разбирают IPv6 сами (выход с IPv6 ведёт его своей таблицей, on_fail=drop
    # действует на оба семейства) — прежний fail «каналы IPv6 не разбирают» снят.
    check "маршрут IPv6 есть — ok, правила его разбирают" "ok" \
          "$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null | verdict ipv6)"
    ip link del d6
else
    echo "diagmatch: dummy-устройства или IPv6 нет — проверка IPv6 пропущена"
fi

# ---- группа из обёрток: устройство проверяется ОДИН раз ----------------------------------
#
# splify2 пишет пул v2 группой, члены которой — именованные выходы-обёртки «<пул>.<устройство>»
# вида interface, а устройство такой обёртки часто создаёт другой выход (туннель части пула).
# Диагностика проверяла каждое устройство дважды — у туннеля и у обёртки, — а группу ещё и
# третий раз по её нынешнему устройству: на роутере владельца шесть строк на три устройства,
# «выход wg0-1: … вне зоны» и тут же «выход wg0.wg0-1: … вне зоны». Обёртка, чьё устройство
# есть у выхода вне группы, и группа, чьё нынешнее устройство — у её же именованного члена,
# отдельной строки не получают.
if ip link add gd1 type dummy 2>/dev/null && ip link add gd2 type dummy 2>/dev/null &&
   ip link set gd1 up && ip link set gd2 up; then
    cat > "$tmp/grp.json" <<GRP
{
  "version": 2,
  "outputs": {
    "direct": { "kind": "direct" },
    "t1":     { "kind": "interface", "device": "gd1" },
    "g":      { "kind": "group", "pick": "order", "members": ["g.gd1", "g.gd2"], "on_fail": "drop" },
    "g.gd1":  { "kind": "interface", "device": "gd1" },
    "g.gd2":  { "kind": "interface", "device": "gd2" }
  },
  "lists": { "cf": { "prefixes_file": ["$tmp/cf.lst"] } },
  "rules": [ { "name": "cf", "to": ["cf"], "out": "g" } ]
}
GRP
    outg="$($DIAG diag --spec "$tmp/grp.json" 2>/dev/null)"
    check "группа: устройство туннеля — строкой его выхода" "1" \
          "$(printf '%s' "$outg" | grep -c '"what":"выход t1: ')"
    check "группа: обёртка того же устройства строки не получает" "0" \
          "$(printf '%s' "$outg" | grep -c '"what":"выход g.gd1: ')"
    check "группа: сама группа по устройству члена строки не получает" "0" \
          "$(printf '%s' "$outg" | grep -c '"what":"выход g: ')"
    check "группа: член со своим устройством проверяется" "1" \
          "$(printf '%s' "$outg" | grep -c '"what":"выход g.gd2: ')"
    ip link del gd1; ip link del gd2
else
    echo "diagmatch: dummy-устройств нет — проверка группы из обёрток пропущена"
fi

# ---- устройство есть, но выключено (down) --------------------------------------------------
#
# status отдаёт такому выходу `up: false` без `failed` (сторож мог ещё не успеть или выход не в
# группе), а diag видел только «есть ли /sys/class/net/<имя>» и шёл дальше к зоне и NAT: на
# выключенном wg0 отчёт молчал о главном. Теперь — отказ «устройство выключено».
if ip link add wg0 type dummy 2>/dev/null; then
    outd="$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null)"
    check "устройство down: отказ" "fail" "$(printf '%s' "$outd" | verdict output)"
    check "устройство down: так и названо" "1" \
          "$(printf '%s' "$outd" | grep -c '"what":"выход vpn: устройство wg0 выключено')"
    ip link set wg0 up
    outu="$($DIAG diag --spec "$tmp/iface.yaml" 2>/dev/null)"
    check "устройство поднято: про «выключено» молчим" "0" \
          "$(printf '%s' "$outu" | grep -c 'выключено')"
    ip link del wg0
else
    echo "diagmatch: dummy-устройств нет — проверка выключенного устройства пропущена"
fi

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
