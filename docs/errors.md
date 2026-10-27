# Коды отказов ядра steer

Отказы ядра, которые читает программа (панель, мост, скрипт), несут рядом с текстом **машинную часть**:

| Поле | Что |
|---|---|
| `error` | текст отказа по-русски — для журнала и командной строки; не менялся и остаётся как есть |
| `code` | стабильное машинное слово вида `раздел.слово` (`spec.unknown_kind`, `plugin.needs_plugin`): по нему каркас показывает текст на языке человека |
| `args` | объект JSON со строковыми подстановками текста: `{"1":"outputs.a","2":"bogus"}` |

Код стабилен: слово не переименовывается и не меняет смысла; новая причина — новый код. Нет `code` — у отказа слова пока нет,
каркас показывает `error` как есть. Подстановки названы по тексту отказа: в спеке — по порядку («1», «2», …), у менеджера плагинов и
у `xsteer-link` — по смыслу (`id`, `version`, `why`).

## Где какие поля

| Откуда | Как приходит |
|---|---|
| `steer plugin … --json`, `plugin-*` сокета | `{"ok":false,"error":…,"code":…,"args":{…}}` в stdout (у `plugin-*` — внутри поля `stdout` ответа сокета, см. [ctl.md](ctl.md)); у `plugin update` с несколькими отказами — первый (`error`, `code`, `args`) и все словами (`errors`) |
| `steer plugin job` | `code` и `args` — те, что менеджер записал в итог задания; нет итога — `plugin.job_failed` |
| Отказ сервера сокета | `{"v":1,"error":"busy","message":"…","code":"ctl.busy","args":{}}`: `error` — прежний вид отказа, `code` — слово |
| Подкоманда, исполненная демоном (`check`, `apply`, `reload`, `helper`, …) | поле `code` здесь занято — это код возврата подкоманды, поэтому машинное слово лежит в **`ecode`**, подстановки — в `args`; пара есть, когда подкоманда отказала с кодом. Строка JSON отказа убрана из `stderr` ответа |
| Любая подкоманда в командной строке | при переменной окружения `STEER_ERR_JSON=1` после текста отказа (`steer: …` в stderr) идёт ещё одна строка — объект `{"ok":false,"error":…,"code":…,"args":{…}}`; без переменной вывод прежний |

## Подстановки места

Отказы спеки несут место в тексте и в подстановках:

| Подстановка | Что |
|---|---|
| `at` | `файл:строка:столбец` узла спеки (без строки — одно имя файла); в тексте `error` это приставка |
| `line`, `col` | строка и столбец числами строкой (если место известно) |
| `in` | путь, в котором нашли отказ (`outputs.proxy`), у отказов ключей вида плагина |
| `path` | путь ключа внутри выхода (`nodes[1]`) у отказов схемы вида |

Каркас строит текст так: `{in}: {path}: ` (что есть) и перевод кода с подстановками; место (`at`, `line`, `col`) показывает отдельно. Подстановки с английскими или
пользовательскими значениями (`why`, имена, пути) каркас не переводит: они вставляются как есть.

## Что ещё без кода

Тексты без слова остаются прежними (`error` без `code`): спека формата v1 (JSON `schema: 1`), подготовка спеки хуками плагинов
(`plugprep`), построение набора правил (`compile`), события (`spec-error` в потоке событий — только `message`), причины
остановки помощников (`last_down`), отказы разбора командной строки и подкоманд протоколов (`vless-nodes`, `proxy-probe`, `dns-probe`
и другие, кроме `xsteer-link`), причины внутри `why` (тексты из чужих библиотек и сообщения плагинов).

## Список кодов

### Спека: разбор и проверка (`spec.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `spec.address_too_long` | `1` | {1}: адрес слишком длинный |
| `spec.awg_conf_path` | `1` | outputs.{1}: conf должен быть абсолютным путём без кавычек |
| `spec.awg_one_device` | `1` | outputs.{1}: у kind awg одно устройство — его заводит ядро steer; пул собирается выходом kind=interface |
| `spec.bad_address` | `1`, `2` | {1}: «{2}» — не адрес IPv4 или IPv6, не подсеть и не диапазон |
| `spec.bad_country` | `1`, `2` | {1}: «{2}» — код страны: две заглавные латинские буквы (ISO 3166-1), например RU |
| `spec.bad_mac` | `1`, `2` | {1}: «{2}» — не MAC-адрес (шесть пар шестнадцатеричных цифр через двоеточие) |
| `spec.bad_name` | `1`, `2` | {1}: имя «{2}» — только буквы, цифры, _ - и точка |
| `spec.bad_uid` | `1`, `2` | {1}: «{2}» — не UID приложения (нужно N или N-M) |
| `spec.balance_members` | `1`, `2`, `3`, `4` | outputs.{1}: у группы pick: balance членов не больше {2} (в карте ядра {3} слотов, у каждого члена нужен хотя бы один), а их {4} |
| `spec.balance_nested` | `1`, `2`, `3` | outputs.{1}: {2} — группа pick: balance, а членом группы pick: {3} она быть не может: у такой группы трафик идёт в одно устройство, а у balance устройство на каждое соединение своё |
| `spec.both_formats` | — | в спеке и version, и schema — это два формата (version: 2 — спека v2, schema — v1); оставьте одно |
| `spec.by_bad` | `1`, `2` | {1}: «{2}» — нужен connection, site или site_client |
| `spec.by_balance_only` | `1` | {1}: by — как раздавать соединения, он есть только у pick: balance |
| `spec.cache_ttl` | `1`, `2` | dns.cache_ttl: min ({1}) больше max ({2}) |
| `spec.client_addr_and_mac` | `1` | {1}: и addr, и mac в одном клиенте — nft не умеет «или» внутри правила; заведите два клиента |
| `spec.client_empty` | `1` | {1}: пустой клиент — нужен addr, mac, uid или self |
| `spec.client_lan_reserved` | — | clients: имя lan занято — так называются клиенты по умолчанию (раздел lan) |
| `spec.client_phone_and_lan` | `1` | {1}: сам телефон (uid, self) и клиенты раздачи (addr, mac) — разные пути пакета; заведите два клиента |
| `spec.client_twice` | `1` | clients: клиент {1} описан дважды |
| `spec.country_both` | `1`, `2` | {1}: {2} — и в only, и в exclude |
| `spec.country_pick_only` | `1`, `2` | {1}: {2} — выбор члена по стране, он есть только у pick: latency и order |
| `spec.country_twice` | `1`, `2` | {1}: {2} указан дважды |
| `spec.default_manual_only` | `1` | outputs.{1}.default: default есть только у pick: manual |
| `spec.default_not_member` | `1`, `2` | outputs.{1}.default: «{2}» — не член группы |
| `spec.device_bad_name` | `1`, `2` | {1}: «{2}» — имя устройства негодного состава |
| `spec.device_is_lan` | `1`, `2` | выход {1} ведёт в {2} — это локальная сеть, трафик закольцуется |
| `spec.device_name_long` | `1` | outputs.{1}: имя устройства длиннее 15 символов |
| `spec.device_name_tunnel` | `1` | outputs.{1}: имя устройства выдаёт туннель (tun, wg, awg, ppp, vpn…) — уберите device, и ядро steer выберет имя само |
| `spec.device_twice` | `1`, `2` | выход {1}: устройство {2} указано дважды |
| `spec.dns_host_unresolvable` | `1`, `2` | {1}: имя «{2}» нечем разрешить — задайте ips (адреса сервера) или bootstrap |
| `spec.dns_host_unresolvable_ips` | `1`, `2` | {1}: имя «{2}» нечем разрешить — задайте ips или bootstrap |
| `spec.dns_mode_bad` | `1` | dns.mode: «{1}» — нужен fakeip или realip |
| `spec.dns_mode_bad_at` | `1`, `2` | {1}: «{2}» — нужен fakeip или realip |
| `spec.dns_output_no_device` | `1`, `2`, `3` | {1}: выход «{2}» (kind={3}) без своего устройства — запрос к DNS нельзя направить через него; нужен interface, awg, tunnel или xsteer, либо direct |
| `spec.empty_string` | `1` | {1}: пустая строка |
| `spec.family_bad` | `1`, `2` | {1}: «{2}» — нужен 4, 6 или both |
| `spec.family_unavailable_bad` | `1`, `2` | {1}: «{2}» — нужен block или fallback |
| `spec.family_unavailable_v6` | `1` | правило {1}: on_family_unavailable: block действует только при family: 6 — IPv4 у выхода есть всегда, а при both без IPv6 правило остаётся по IPv4 |
| `spec.group_cycle` | `1` | группы замыкаются в круг ({1}) — выбор члена не кончился бы никогда |
| `spec.group_mode_bad` | `1`, `2` | {1}: «{2}» — нужен race (все сразу) или failover (по очереди) |
| `spec.group_needs_members` | `1` | {1}: у группы нужен members |
| `spec.group_no_device` | `1` | {1}: у группы нет своего устройства — оно у членов (members) |
| `spec.group_no_members` | `1` | {1}: у группы нет членов |
| `spec.group_no_members_name` | `1` | outputs.{1}: у группы нет членов |
| `spec.group_only_key` | `1`, `2` | {1}: {2} есть только у kind: group |
| `spec.int_range` | `1`, `2`, `3` | {1} — от {2} до {3} |
| `spec.interface_needs_device` | `1` | outputs.{1}: kind interface needs a device |
| `spec.ipv6_bad` | `1`, `2` | {1}: «{2}» — нужен routed, nat или off |
| `spec.ipv6_donor_twice` | `1`, `2` | outputs.{1}.ipv6: routed уже у выхода {2} — донор IPv6 в спеке один: адрес из префикса одного хоста другой хост не пропустит |
| `spec.ipv6_group` | `1`, `2` | {1}: {2} — свойство туннеля на том конце, у группы его нет: задайте его у члена |
| `spec.ipv6_not_carried` | `1`, `2` | {1}: kind: {2} IPv6 не несёт — его правила IPv6 и так отвергаются, ключ ipv6 ему не нужен |
| `spec.ipv6_rejected` | `1`, `2` | {1}: {2} |
| `spec.ipv6_tunnel_only` | `1`, `2`, `3` | {1}: {2} — только у выхода с туннелем (kind: interface, awg); у kind: {3} есть только off |
| `spec.key_owner_only` | `1`, `2`, `3` | {1}: ключ {2} есть только у {3} |
| `spec.key_rejected` | `1`, `2` | {1}: {2} |
| `spec.kind_absent` | `1`, `2` | {1}: {2} |
| `spec.kind_lan_only` | `1`, `2`, `3` | правило {1}: выход kind={2} работает только для клиентов раздачи — {3} |
| `spec.kind_no_device` | `1`, `2` | {1}: у kind: {2} нет устройства — трафик никуда не уводится |
| `spec.kind_plugin_only` | `1`, `2` | {1}: kind {2} заводит только плагин — в подготовленной спеке и с owner |
| `spec.kind_zapret_removed` | `1` | {1}: kind zapret убран из ядра steer: обход DPI — отдельный модуль recheck, без обхода выход заменяет kind: direct |
| `spec.lan_addr_and_devices` | — | lan: клиенты описаны дважды — и addr, и несколько devices. Уберите addr — устройства опишут клиентов точнее |
| `spec.lan_device_name` | `1` | lan.devices: «{1}» — имя устройства негодного состава |
| `spec.lan_device_twice` | `1` | lan.devices: устройство {1} указано дважды |
| `spec.lan_devices_empty` | — | lan.devices: пустой список — некому адресовать правила |
| `spec.latency_only` | `1`, `2` | {1}: {2} — замер задержки, он есть только у pick: latency |
| `spec.list_address_in_domains` | `1`, `2` | {1}: «{2}» — адрес, а не домен; ему место в prefixes |
| `spec.list_all_alone` | `1` | {1}: all — весь трафик; источники рядом с ним ничего не значат |
| `spec.list_all_reserved` | — | lists: имя all занято — to: all значит весь трафик |
| `spec.list_bad_ports` | `1`, `2` | {1}: «{2}» — нужно 443 или 50000-65535, числа от 1 до 65535, начало не больше конца |
| `spec.list_bad_prefix` | `1`, `2` | {1}: «{2}» — не адрес, не подсеть и не диапазон |
| `spec.list_bad_proto` | `1`, `2` | {1}: «{2}» — нужен tcp, udp или both |
| `spec.list_item` | `1`, `2` | {1}: элемент — непустая строка, а не {2} |
| `spec.list_no_source` | `1` | {1}: у списка нет источника — нужен srs, prefixes_file, domains_file или all: true |
| `spec.list_override_port` | `1` | {1}: подмена порта — только у списка имён (domains_file) без prefixes_file, srs и all |
| `spec.list_ports_many` | `1`, `2`, `3` | {1}: диапазонов портов {2}, а не больше {3} — каждый диапазон размножает все адреса списка в составном наборе nftables (адрес . протокол . порт), и память роутера кончилась бы раньше |
| `spec.list_ports_overlap` | `1`, `2`, `3`, `4`, `5` | {1}: диапазоны {2}-{3} и {4}-{5} пересекаются — сложите их в один |
| `spec.list_twice` | `1` | lists: список {1} описан дважды |
| `spec.mark_slots` | `1`, `2`, `3`, `4`, `5` | выходов с меткой {1}, а поле метки даёт мест не больше {2}: у метки {3} бит (биты {4}-{5}), значения, которые чужая перезапись соседних битов 16-23 могла бы превратить в метку другого выхода, не раздаются. Выходы без метки (direct) в счёт не идут |
| `spec.member_missing` | `1`, `2` | outputs.{1}.members: выхода «{2}» нет в outputs |
| `spec.member_no_device` | `1`, `2`, `3` | outputs.{1}.members: {2} — kind: {3}, у него нет устройства, выбирать группе нечего |
| `spec.member_no_device_name` | `1` | outputs.{1}: член группы без устройства |
| `spec.member_self` | `1` | outputs.{1}.members: группа не может быть членом самой себя |
| `spec.member_twice` | `1`, `2` | outputs.{1}.members: {2} указан дважды |
| `spec.need_ip` | `1`, `2` | {1}: «{2}» — нужен адрес IPv4 или IPv6 |
| `spec.no_kind` | `1` | {1}: нет kind |
| `spec.no_memory` | — | Недостаточно памяти для спеки |
| `spec.no_on_fail` | `1`, `2` | {1}: у kind: {2} нет on_fail — он не может отказать |
| `spec.no_plugin` | `1` | {1}: нет plugin |
| `spec.no_spec_dir` | `1`, `2` | {1}: каталог файла спеки не определить — относительный путь «{2}» не разрешить, задайте абсолютный |
| `spec.no_tls_build` | `1` | {1}: https:// в этой сборке нет (сборка без TLS) — нужен пакет steer-core или адрес http:// |
| `spec.no_url` | `1` | {1}: нет url |
| `spec.no_version` | — | нет version: 2 |
| `spec.no_version_yaml` | — | нет version: 2 — спека YAML — это спека v2 (docs/spec-v2.md); спека v1 — JSON-объект со schema |
| `spec.not_prepared` | `1` | {1}: спека не подготовлена — нужен reload |
| `spec.obfs_listen_form` | `1` | outputs.{1}: obfs.listen должен быть вида адрес:порт |
| `spec.obfs_listen_name` | `1` | outputs.{1}: obfs.listen должен быть адресом, а не именем |
| `spec.obfs_mode` | `1` | outputs.{1}: неизвестный obfs.mode (сейчас есть только wg-over-tcp) |
| `spec.obfs_no_listen` | `1` | outputs.{1}: obfs нужен listen — тот же адрес и порт, что в Endpoint пира WireGuard |
| `spec.obfs_no_server` | `1` | outputs.{1}: obfs нужен server вида адрес:порт |
| `spec.obfs_server_form` | `1` | outputs.{1}: obfs.server должен быть вида адрес:порт |
| `spec.obfs_server_name` | `1` | outputs.{1}: obfs.server должен быть адресом, а не именем |
| `spec.on_fail_bad` | `1`, `2` | {1}: «{2}» — нужен drop или direct |
| `spec.on_fail_bad_zapret` | `1`, `2` | {1}: «{2}» — нужен drop, direct или zapret |
| `spec.on_fail_phone` | `1` | {1}: zapret на телефоне нет — нужен drop или direct |
| `spec.output_missing_direct` | `1`, `2` | {1}: выхода «{2}» нет в outputs (или слово direct — напрямую) |
| `spec.output_twice` | `1` | outputs: выход {1} описан дважды |
| `spec.over_cycle` | `1`, `2`, `3` | выход {1}: {2} замыкается в круг ({3}) — туннели заворачивались бы друг в друга, и не встал бы ни один |
| `spec.over_depth` | `1`, `2`, `3`, `4` | выход {1}: цепочка {2} длиннее {3} переходов ({4}) |
| `spec.over_incapable` | `1`, `2`, `3` | выход {1}: {2} есть только у выходов со своим соединением с сервером — туннели со своим сокетом, awg и interface с obfs; у kind={3} соединение открывает не ядро steer, и пустить его через другой выход нечем |
| `spec.over_missing` | `1`, `2` | outputs.{1}.over: выхода «{2}» нет в outputs |
| `spec.over_name` | `1`, `2` | {1}: «{2}» — имя другого выхода |
| `spec.over_pool_cycle` | `1`, `2` | выход {1}: {2} замыкается в круг через устройства пула — туннель однажды пошёл бы внутрь себя |
| `spec.over_pool_device` | `1`, `2`, `3`, `4` | выход {1}: {2} ведёт в {3}, а среди его устройств {4} — устройство самого выхода, туннель пошёл бы внутрь себя |
| `spec.over_self` | `1`, `2` | выход {1}: {2} указывает на него самого — туннель не может идти внутри себя |
| `spec.over_target_missing` | `1`, `2`, `3` | выход {1}: {2} «{3}» — такого выхода в спеке нет |
| `spec.over_target_no_device` | `1`, `2`, `3`, `4` | выход {1}: {2} «{3}» — это kind={4}, у него нет устройства, в которое можно пустить туннель (нужен выход с устройством: interface, awg или туннель) |
| `spec.owner_plugin_only` | `1` | {1}: owner пишет только плагин — в спеке человека его нет |
| `spec.path_too_long` | `1`, `2` | {1}: путь с каталогом спеки длиннее {2} байт |
| `spec.phone_only_apps` | `1` | {1}: приложения — только на телефоне |
| `spec.phone_only_self` | `1` | {1}: трафик самого устройства — только на телефоне |
| `spec.phone_only_uid` | `1` | {1}: приложения (uid) — только на телефоне |
| `spec.pick_bad` | `1`, `2` | {1}: «{2}» — нужен order, latency, manual или balance |
| `spec.prefix_routed_only` | `1` | {1}: prefix — префикс хоста, он есть только у ipv6: routed |
| `spec.protocol_tunnel_only` | `1` | {1}: protocol есть только у kind: tunnel |
| `spec.quic_bad` | `1`, `2` | {1}: «{2}» — нужен block (отвергать UDP/443) или allow |
| `spec.quic_no_443` | `1` | правило {1}: quic: block, а порты списка не содержат 443 |
| `spec.quic_phone` | `1` | правило {1}: quic: block действует на трафик клиентов раздачи, а не самого телефона (uid, self) |
| `spec.quic_tcp_list` | `1` | правило {1}: quic: block, а список только tcp — QUIC это UDP |
| `spec.resources_not_allocated` | `1` | {1}: ресурсы выхода не выданы (alloc.json) — нужен reload |
| `spec.rule_all_alone` | `1` | правило {1}: all — весь трафик; другие списки рядом с ним ничего не значат |
| `spec.rule_client_missing` | `1`, `2` | правило {1}: клиента «{2}» нет в clients |
| `spec.rule_client_twice` | `1`, `2` | правило {1}: клиент {2} указан дважды |
| `spec.rule_lan_alone` | `1` | правило {1}: lan — клиенты по умолчанию; с другими клиентами в одном for не сочетается |
| `spec.rule_list_missing` | `1`, `2` | правило {1}: списка «{2}» нет в lists |
| `spec.rule_list_twice` | `1`, `2` | правило {1}: список {2} указан дважды |
| `spec.rule_name_chars` | `1` | имя правила «{1}»: нельзя кавычку, обратную косую и управляющие символы |
| `spec.rule_no_out` | `1` | правило {1}: нет out — куда вести трафик |
| `spec.rule_no_to` | `1` | правило {1}: нет to — списки из lists или all (весь трафик) |
| `spec.rule_output_missing` | `1`, `2` | правило {1}: выхода «{2}» нет в outputs |
| `spec.rule_to_empty` | `1` | правило {1}: to пустой — списки из lists или all |
| `spec.rule_upstream_missing` | `1`, `2` | правило {1}: апстрима «{2}» нет в dns.upstreams |
| `spec.rules_shape` | `1` | rules — список правил «- { to: …, out: … }», а не {1} |
| `spec.scope_bad` | `1`, `2` | {1}: «{2}» — нужен device или global |
| `spec.scope_device_no_clients` | `1` | правило {1} объявлено правилом на устройство (scope: device), но в for нет клиентов — назовите клиента с адресом или MAC |
| `spec.scope_device_subnet` | `1`, `2` | правило {1}: правило на устройство принимает только одиночных хозяев, а у клиента {2} подсеть или диапазон — приоритет достался бы не одному устройству, а всем в нём |
| `spec.self_and_uid` | `1` | {1}: self уже включает все приложения — уберите uid |
| `spec.servers_empty` | `1` | {1}: пустой список — нужен хотя бы один сервер |
| `spec.split_needs_tls` | `1` | {1}: делить ClientHello можно только у DoT (tls://) и DoH (https://); у этого сервера нет TLS поверх TCP |
| `spec.too_long` | `1`, `2` | {1}: длиннее {2} байт |
| `spec.too_long_79` | `1` | {1}: длиннее 79 байт |
| `spec.tunnel_kind_v2` | `1`, `2` | {1}: в спеке v2 туннель пишется kind: tunnel, protocol: {2} |
| `spec.tunnel_needs_protocol` | `1`, `2` | {1}: kind: tunnel нужен protocol (протоколы: {2}) |
| `spec.uid_root` | `1` | {1}: uid 0 — это root, то есть само ядро steer и системные демоны; их трафик правилом не маршрутизируется |
| `spec.unknown_key` | `1`, `2`, `3` | неизвестный ключ «{1}» в {2} (есть: {3}) |
| `spec.unknown_kind` | `1`, `2`, `3` | {1}: неизвестный kind «{2}» (есть direct, block, interface, tunnel, awg, group{3}) |
| `spec.unknown_protocol` | `1`, `2`, `3` | {1}: протокол «{2}» не знаю (протоколы: {3}) |
| `spec.unsup_app_names` | `1` | ещё не поддерживается в этой версии ядра steer: {1} — имена пакетов приложений; пока пишите uid |
| `spec.unsup_balance_phone` | `1` | ещё не поддерживается в этой версии ядра steer: правило {1}: pick: balance для трафика самого телефона (uid, self) |
| `spec.unsup_family6_srs` | `1` | ещё не поддерживается в этой версии ядра steer: правило {1}: family: 6 со списком srs — пока со списками prefixes_file и domains_file или с to: all |
| `spec.unsup_inline_list` | `1` | ещё не поддерживается в этой версии ядра steer: встроенные {1} у списка — пока только файлами: prefixes_file, domains_file, srs |
| `spec.unsup_mixed_clients` | `1` | ещё не поддерживается в этой версии ядра steer: правило {1}: клиенты разных видов (адреса, MAC, телефон) в одном for — разнесите их по правилам |
| `spec.unsup_mixed_lists` | `1` | ещё не поддерживается в этой версии ядра steer: правило {1}: списки с разными proto/ports или с all в одном to — разнесите их по правилам |
| `spec.unsup_quic_srs` | `1` | ещё не поддерживается в этой версии ядра steer: правило {1}: quic: block со списком srs — пока со списками prefixes_file и domains_file или с to: all |
| `spec.upstream_group_nested` | `1`, `2` | {1}: «{2}» — группа; группа в группе не поддерживается — перечислите её серверы |
| `spec.upstream_missing` | `1`, `2` | {1}: сервера «{2}» нет в dns.upstreams |
| `spec.upstream_name_twice` | `1` | dns.upstreams: имя «{1}» повторяется |
| `spec.upstream_self` | `1` | {1}: группа не может входить сама в себя |
| `spec.upstream_twice` | `1`, `2` | {1}: сервер «{2}» указан дважды |
| `spec.url_and_servers` | `1` | {1}: url и servers вместе — это либо сервер (url), либо группа серверов (servers) |
| `spec.url_rejected` | `1`, `2`, `3` | {1}: «{2}» — {3} |
| `spec.v1_in_yaml` | — | спека v1 пишется JSON-объектом ({"schema": 1, …}); спека YAML — это v2, и начинается она с version: 2 |
| `spec.version_unsupported` | `1` | version {1} не поддерживается (эта сборка понимает 2) |
| `spec.want_bool` | `1` | {1} — true или false |
| `spec.want_int` | `1` | {1} — целое число без кавычек |
| `spec.want_list` | `1` | {1} — список [a, b] или одно значение, а не отображение |
| `spec.want_map` | `1`, `2` | {1} — отображение «ключ: значение», а не {2} |
| `spec.want_string` | `1`, `2` | {1} — строка, а не {2} |
| `spec.weights_balance_only` | `1` | {1}: weights — доли соединений, они есть только у pick: balance |
| `spec.weights_count` | `1`, `2`, `3` | outputs.{1}.weights: весов {2}, а членов {3} — по весу на каждого члена, по порядку members |

### Спека: ключи вида плагина по его схеме (`schema.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `schema.above_max` | `1`, `2` | {1} — больше допустимого {2} |
| `schema.abs_path` | `1` | «{1}» — нужен абсолютный путь файла |
| `schema.bad_pattern` | `1` | pattern «{1}» схемы не разобран |
| `schema.below_min` | `1`, `2` | {1} — меньше допустимого {2} |
| `schema.kind_has_no_keys` | `1`, `2` | неизвестный ключ «{1}» — у вида {2} ключей нет |
| `schema.list_dup` | `1` | «{1}» уже есть в списке |
| `schema.list_max` | `1`, `2` | в списке {1} элементов, а можно не больше {2} |
| `schema.list_min` | `1`, `2` | в списке {1} элементов, а нужно не меньше {2} |
| `schema.list_min_one` | `1` | в списке 1 элемент, а нужно не меньше {1} |
| `schema.list_simple` | — | для списка без схемы нужны простые значения |
| `schema.need_const` | `1`, `2` | «{1}» — нужно «{2}» |
| `schema.need_one_of` | `1`, `2` | «{1}» — нужно одно из: {2} |
| `schema.need_what` | `1`, `2` | «{1}» — нужно: {2} |
| `schema.needs_key` | `1`, `2`, `3` | {1}: {2} — без ключа {3} он не разобран |
| `schema.object_needed` | — | схема вида: нужен объект |
| `schema.one_or_list_array` | — | x-one-or-list — у массива (type: array) |
| `schema.one_or_list_bool` | — | x-one-or-list — true или false |
| `schema.pattern_mismatch` | `1`, `2` | «{1}» не подходит под {2} |
| `schema.ref_missing` | `1`, `2` | «{1}» — в разделе {2} такой записи нет |
| `schema.ref_missing_also` | `1`, `2`, `3` | «{1}» — в разделе {2} такой записи нет (и это не {3}) |
| `schema.required_key` | `1` | нет обязательного ключа {1} |
| `schema.simple_value` | — | для ключа без схемы нужно простое значение |
| `schema.too_long` | `1` | длиннее {1} знаков |
| `schema.too_short` | `1` | короче {1} знаков |
| `schema.unknown_key` | `1` | неизвестный ключ «{1}» |
| `schema.unknown_key_list` | `1`, `2` | неизвестный ключ «{1}» (есть: {2}) |
| `schema.unsupported_word` | `1` | в схеме вида ключевое слово «{1}» не поддерживается |
| `schema.value_not_list` | — | здесь нужно значение, а не список |
| `schema.value_not_map` | — | здесь нужно значение, а не отображение |
| `schema.when_set_list` | — | x-when-set — список ключей-соседей |
| `schema.word_list` | `1`, `2` | {1}: у «{2}» нужен список строк |
| `schema.word_map` | `1` | {1} в схеме вида — отображение «значение: [ключи]» |
| `schema.xpath_string` | — | x-path — у строки |
| `schema.xpath_word` | `1` | x-path — etc, conf или abs, а не «{1}» |
| `schema.xref_also` | — | x-ref.also — список слов |
| `schema.xref_form` | — | x-ref — {section: outputs, lists, clients или dns.upstreams} |
| `schema.xref_key` | `1` | в x-ref ключа «{1}» нет (есть: section, also) |

### Спека: чтение текста YAML (`yaml.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `yaml.alias` | `1` | алиас *{1}: якоря и алиасы в спеке не поддерживаются — повторяющееся задаётся именем и ссылкой на него |
| `yaml.anchor` | `1` | якорь &{1}: якоря и алиасы в спеке не поддерживаются — повторяющееся задаётся именем и ссылкой на него |
| `yaml.duplicate_key` | `1`, `2` | ключ «{1}» повторяется (первый раз — строка {2}) |
| `yaml.empty` | — | документ пуст |
| `yaml.key_not_string` | — | ключ отображения — не строка (составные ключи не поддерживаются) |
| `yaml.nul_byte` | — | в строке нулевой байт — такое значение обрезалось бы молча |
| `yaml.reader` | `problem` | текст не читается как UTF-8/UTF-16: {problem} |
| `yaml.second_document` | — | второй документ в потоке: ожидался один документ |
| `yaml.syntax` | `problem` | ошибка YAML: {problem} |
| `yaml.tab` | `problem` | ошибка YAML: {problem}; табуляция: отступ в YAML — только пробелы |
| `yaml.too_big` | `1` | документ больше {1} байт |
| `yaml.too_deep` | `1` | вложенность глубже {1} уровней |
| `yaml.too_many_nodes` | `1` | в документе больше {1} узлов |

### Менеджер плагинов (`plugin.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `plugin.archive_download` | `why` | {why} |
| `plugin.archive_file_missing` | `id`, `path` | в архиве {id} нет файла {path} из MANIFEST — подмена |
| `plugin.archive_incomplete` | `id` | архив {id}: нет plugin.json, MANIFEST и MANIFEST.sig |
| `plugin.archive_name` | `got`, `want` | архив назван {got}, а ждали {want} — подмена |
| `plugin.archive_unsigned` | `id` | архив {id} не подписан |
| `plugin.bad_name` | — | недопустимое имя плагина |
| `plugin.bad_version` | — | недопустимая версия |
| `plugin.busy` | — | busy: менеджер плагинов занят другим запросом — повторите позже |
| `plugin.compat_bad_range` | `axis`, `range` | диапазон {axis} «{range}» не разобрался |
| `plugin.compat_core_op` | `range` | ось steer-core принимает только «>=», а не «{range}» |
| `plugin.compat_needs_core` | `axis`, `range`, `have` | требует {axis} {range}, у ядра {have} |
| `plugin.compat_needs_panel` | `axis`, `range`, `have` | требует {axis} {range}, у панели {have} |
| `plugin.compat_no_range` | `axis` | ось {axis} без диапазона |
| `plugin.compat_unknown_axis_core` | `axis` | неизвестная ось совместимости {axis} — обновите ядро |
| `plugin.compat_unknown_axis_panel` | `axis` | неизвестная ось совместимости {axis} — обновите панель splify2 |
| `plugin.core_impl_kind` | `id`, `kind` | {id}: вида {kind} ядро не знает — impl: core для него нельзя |
| `plugin.core_impl_official` | `id` | {id}: impl: core принимается только из официального репозитория |
| `plugin.dependency_cycle` | `chain` | цикл зависимостей: {chain} |
| `plugin.dependency_failed` | `id`, `version`, `why` | {id} {version}: {why} |
| `plugin.dir_mode` | `path`, `mode` | каталог {path}: режим {mode}, а нужен 0755 |
| `plugin.entry_mode_file` | `path`, `mode` | запись {path}: режим {mode}, а нужен 0644 |
| `plugin.entry_not_file` | `path` | запись {path}: не файл и не каталог |
| `plugin.entry_order` | `id`, `index`, `want`, `path` | архив {id}: запись {index} должна быть {want}, а это {path} |
| `plugin.entry_special` | `path` | запись {path}: setuid, setgid или sticky |
| `plugin.entry_twice` | `id`, `path` | архив {id}: запись {path} повторена |
| `plugin.extra_dir` | `id`, `path` | в архиве {id} лишний каталог {path} |
| `plugin.extra_file` | `id`, `path` | в архиве {id} лишний файл {path}, которого нет в MANIFEST — подмена |
| `plugin.file_mismatch` | `path`, `id` | файл {path} архива {id} не совпадает с MANIFEST — подмена |
| `plugin.file_mode` | `path`, `mode` | файл {path}: режим {mode}, а нужен 0644 или 0755 |
| `plugin.file_mode_mismatch` | `path`, `mode`, `want` | файл {path}: режим {mode}, а в MANIFEST {want} |
| `plugin.file_unreadable` | `path`, `why` | {path} не читается: {why} |
| `plugin.files_missing` | `id` | файлов плагина {id} нет — поставьте его заново |
| `plugin.group_health_failed` | `why` | группа плагинов не прошла проверку здоровья: {why} — возвращены прежние версии |
| `plugin.health_failed` | `id`, `version`, `why` | {id} {version} не прошёл проверку здоровья: {why} |
| `plugin.health_failed_restored` | `id`, `version`, `why` | {id} {version} не прошёл проверку здоровья: {why} — возвращена прежняя версия |
| `plugin.incompatible` | `id`, `version` | {id} {version} несовместим |
| `plugin.index_archive_mismatch` | `id`, `version`, `field` | индекс и архив {id} {version} не совпадают ({field}) |
| `plugin.index_download` | `name`, `why` | индекс репозитория {name} не скачался: {why} |
| `plugin.index_expired` | `name`, `expires` | индекс репозитория {name} просрочен ({expires}) — зеркало отдаёт старый индекс |
| `plugin.index_failed` | `name`, `why` | индекс репозитория {name} не получен: {why} |
| `plugin.index_foreign` | `name`, `id` | индекс репозитория {name} назван «{id}» — это чужой индекс |
| `plugin.index_missing` | `name`, `why` | индекса репозитория {name} нет: {why} |
| `plugin.index_new_format` | `name` | индекс репозитория {name} нового формата — обновите ядро |
| `plugin.index_new_format_url` | — | индекс нового формата — обновите ядро |
| `plugin.index_no_name` | — | индекс не называет репозиторий (repo.id) |
| `plugin.index_rollback` | `name`, `generated`, `seen` | индекс репозитория {name} старее уже виденного ({generated} < {seen}) — откат индекса отвергнут |
| `plugin.index_sig_download` | `url`, `why` | подпись индекса {url} не скачалась: {why} |
| `plugin.index_url_download` | `url`, `why` | индекс {url} не скачался: {why} |
| `plugin.job_failed` | — | args |
| `plugin.job_not_found` | — | такого задания нет |
| `plugin.job_start_failed` | — | не завести задание |
| `plugin.json_empty` | `name` | {name}: пустой документ |
| `plugin.json_id_mismatch` | `id`, `header` | plugin.json ({id}) не совпадает с MANIFEST ({header}) — подмена |
| `plugin.json_index_mismatch` | `id`, `version` | plugin.json ({id} {version}) не совпадает с MANIFEST и индексом — подмена |
| `plugin.json_invalid` | `why` | {why} |
| `plugin.json_manifest_mismatch` | `id` | plugin.json {id} не совпадает с MANIFEST — подмена |
| `plugin.json_unparsable` | `why` | plugin.json не разбирается: {why} |
| `plugin.keep_path` | `id`, `path` | {id}: путь keep «{path}» не абсолютный |
| `plugin.keep_perm` | `id`, `path` | {id}: путь keep {path} без права fs: |
| `plugin.key_mismatch` | `keyid`, `hex` | номер ключа {keyid} не совпадает с ключом ({hex}) |
| `plugin.key_number_form` | — | номер ключа — 16 знаков hex |
| `plugin.key_revoked` | — | этот ключ отозван |
| `plugin.key_unreadable` | — | ключ не распознан |
| `plugin.key_write_failed` | — | не записать ключ |
| `plugin.link_busy` | `id`, `path` | {id} не встаёт: {path} уже есть, и поставил его не менеджер плагинов |
| `plugin.link_core_path` | `id`, `path` | {id}: ссылка {path} — путь ядра steer, плагину его не дать |
| `plugin.link_create` | `path`, `why` | не поставить ссылку {path}: {why} |
| `plugin.link_exists` | `path` | {path} уже есть, и поставил его не менеджер плагинов |
| `plugin.link_mode` | `id`, `path`, `mode` | {id}: ссылка {path} — неизвестный mode «{mode}» |
| `plugin.link_owned_by_package` | `id`, `path`, `pkg` | {id} не встаёт: {path} принадлежит пакету {pkg} |
| `plugin.link_path` | `id`, `path` | {id}: путь ссылки «{path}» не абсолютный путь файла |
| `plugin.link_perm` | `id`, `path` | {id}: ссылка {path} без права fs: |
| `plugin.link_taken` | `path`, `other`, `repo` | путь {path} уже занят плагином {other} из {repo} |
| `plugin.link_target_missing` | `id`, `path`, `target` | {id}: цели ссылки {path} ({target}) нет в плагине |
| `plugin.link_target_outside` | `id`, `path` | {id}: цель ссылки {path} вне каталога плагина |
| `plugin.link_write` | `path`, `why` | не записать {path}: {why} |
| `plugin.manifest_file_twice` | `id`, `path` | MANIFEST {id}: файл {path} назван дважды |
| `plugin.manifest_header` | `id` | MANIFEST {id}: заголовок не «s2p 1 <id> <версия> <арх>» |
| `plugin.manifest_line` | `id`, `line` | MANIFEST {id}: строка не разбирается: {line} |
| `plugin.manifest_new_schema` | `id` | манифест {id} нового формата (schema) — обновите ядро |
| `plugin.manifest_unreadable` | `id` | MANIFEST {id} не читается |
| `plugin.name_taken_command` | `name`, `owner`, `repo` | подкоманда {name} уже есть у {owner} из {repo} |
| `plugin.name_taken_command_file` | `name`, `owner` | подкоманда {name} уже есть у {owner} из файла |
| `plugin.name_taken_kind` | `name`, `owner`, `repo` | вид {name} уже есть у {owner} из {repo} |
| `plugin.name_taken_kind_file` | `name`, `owner` | вид {name} уже есть у {owner} из файла |
| `plugin.name_taken_service` | `name`, `owner`, `repo` | служба {name} уже есть у {owner} из {repo} |
| `plugin.name_taken_service_file` | `name`, `owner` | служба {name} уже есть у {owner} из файла |
| `plugin.needed_by_outputs` | `id`, `outputs` | плагин {id} нужен выходам: {outputs}; снять всё равно — с --force |
| `plugin.needed_by_plugins` | `id`, `users` | плагин {id} нужен плагинам {users}; снять всё равно — с --force |
| `plugin.needs_package_after` | `id`, `pkg`, `tx` | {id} не встаёт: нужен пакет {pkg} — поставьте его после установки {tx} |
| `plugin.needs_plugin` | `id`, `dep`, `range` | {id} требует плагин {dep} {range} — поставьте его |
| `plugin.net_and_seed` | `net`, `seed` | {net}; из семени: {seed} |
| `plugin.no_archive_url` | `id`, `version` | у архива {id} {version} в индексе нет адреса |
| `plugin.no_autoupdate_unsigned` | — | у плагина без подписи автообновления нет |
| `plugin.no_id_version` | — | в plugin.json нет id или version |
| `plugin.no_memory` | — | Нет памяти |
| `plugin.no_seed` | — | семени нет |
| `plugin.no_seed_at` | `path` | семени нет ({path}) |
| `plugin.no_space_root` | `path`, `need`, `free` | нет места на разделе плагинов ({path}): нужно {need}, свободно {free} |
| `plugin.no_space_tmp` | `path`, `need`, `free` | нет места во временном каталоге ({path}): нужно {need}, свободно {free} |
| `plugin.no_suitable_version` | `id` | нет годной версии {id} |
| `plugin.no_version_in_range` | `id`, `range` | нет версии {id} в диапазоне {range} |
| `plugin.no_versions` | `id` | у плагина {id} нет версий |
| `plugin.not_in_any_available_repo` | `id`, `why` | плагина {id} нет ни в одном доступном репозитории ({why}) |
| `plugin.not_in_any_repo` | `id` | плагина {id} нет ни в одном репозитории |
| `plugin.not_in_repo` | `id`, `name` | плагина {id} нет в репозитории {name} |
| `plugin.not_installed` | `id` | плагин {id} не установлен |
| `plugin.on_off` | — | нужно on или off |
| `plugin.output_not_up` | `name`, `seconds` | выход {name} не поднялся за {seconds} с |
| `plugin.package_failed` | `name`, `sep`, `last` | пакет {name} не поставился{sep}{last} |
| `plugin.perm_nft` | `id` | {id}: файлы nft без права nft |
| `plugin.perm_so` | `id` | {id}: steer.so без права so |
| `plugin.perm_system` | `id` | {id}: requires.system без права system-packages |
| `plugin.perm_transform` | `id` | {id}: хуки pre_apply/expand без права spec.transform |
| `plugin.place_failed` | `id`, `why` | не поставить {id} на место: {why} |
| `plugin.prev_move_failed` | `id`, `why` | не убрать прежнюю версию {id} в .prev: {why} |
| `plugin.reload_bad_reply` | — | демон ответил не по форме на plugin-reload |
| `plugin.reload_failed` | `why` | ядро не перечитало плагины: {why} |
| `plugin.remove_failed` | `path`, `why` | не удалить {path}: {why} |
| `plugin.repo_bad_name` | — | недопустимое имя репозитория |
| `plugin.repo_disabled` | `repo`, `id` | репозиторий {repo}, из которого поставлен {id}, отключён |
| `plugin.repo_exists` | `name`, `url` | репозиторий {name} уже подключён с адресом {url} |
| `plugin.repo_not_found` | `name` | репозитория {name} нет |
| `plugin.repo_official_keep` | — | официальный репозиторий не отключается |
| `plugin.repo_official_name` | `name` | репозиторий {name} — официальный, сторонний под этим именем не подключается |
| `plugin.repo_unreadable` | `path`, `why` | репозиторий {path} не читается: {why} |
| `plugin.repo_url_chars` | — | в адресе репозитория недопустимые знаки |
| `plugin.repo_url_scheme` | — | адрес репозитория — https://… |
| `plugin.script_check_refused` | `name`, `id`, `rc`, `sep`, `last` | scripts/{name} плагина {id} отказал в проверке (код {rc}){sep}{last} |
| `plugin.script_failed` | `name`, `id`, `rc`, `sep`, `last` | scripts/{name} плагина {id} не прошёл (код {rc}){sep}{last} |
| `plugin.script_path` | `id`, `name` | у {id} путь scripts.{name} вне каталога плагина |
| `plugin.seed_archive_broken` | `id`, `version`, `why` | архива {id} {version} в семени нет или он испорчен: {why} |
| `plugin.seed_archive_missing` | `id`, `version` | архива {id} {version} в семени нет |
| `plugin.seed_no_index` | — | в семени нет индекса: нечего ставить |
| `plugin.seed_other_repo` | — | семя — индекс другого репозитория |
| `plugin.signature_mismatch` | `what` | подпись {what} не сходится — файл подменён или испорчен |
| `plugin.signature_unreadable` | `what` | подпись {what} не разбирается |
| `plugin.signed_revoked_key` | `what`, `keys` | {what} подписан отозванным ключом {keys} |
| `plugin.signed_unknown_key` | `what`, `keys` | {what} подписан ключом {keys}, такого ключа у ядра нет |
| `plugin.stage_move_failed` | — | не переложить распаковку |
| `plugin.standalone_official` | `id` | {id}: standalone разрешён только официальному репозиторию |
| `plugin.subcommand_core` | `name` | подкоманда {name} — команда ядра, плагину её не дать |
| `plugin.system_missing` | `id`, `alt` | {id} не встаёт: нет {alt} |
| `plugin.system_missing_pkg` | `id`, `alt`, `package` | {id} не встаёт: нет {alt} (нужен пакет {package}) |
| `plugin.unpack_failed` | `id`, `why` | архив {id} не распаковался: {why} |
| `plugin.unsigned` | `what` | {what} не подписан |
| `plugin.version_conflict` | `id`, `range`, `have` | нужен {id} {range}, а план уже берёт {have} |
| `plugin.version_conflict_installed` | `id`, `version`, `other` | {id} {version} не ставится рядом с установленным {other} |
| `plugin.version_no_build` | `id`, `version`, `arch`, `variant` | у {id} {version} нет сборки под {arch}{variant} |
| `plugin.version_not_in_repo` | `id`, `version`, `name` | версии {id} {version} нет в репозитории {name} |
| `plugin.version_unhealthy` | `id`, `version`, `why` | {id} {version} уже не прошла проверку здоровья: {why} |
| `plugin.version_yanked` | `id`, `version`, `why` | {id} {version} отозвана: {why} |
| `plugin.write_failed` | `path` | не записать {path} |
| `plugin.wrong_arch` | `id`, `got`, `want` | архив {id} собран под {got}, а нужен {want} |
| `plugin.wrong_variant` | `id`, `got`, `want` | вариант архива {id} ({got}) не тот, что в индексе ({want}) |

### Управляющий сокет (`ctl.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `ctl.bad_body_length` | — | длина тела — десятичное число байт |
| `ctl.bad_plugin_name` | — | недопустимое имя плагина в теле |
| `ctl.bad_request` | — | Запрос составлен неверно |
| `ctl.body_plugin_event` | — | тело — объект JSON с id и state |
| `ctl.body_plugin_ids` | — | тело — id плагинов через пробел |
| `ctl.body_timeout` | — | тело не пришло целиком за 5 секунд |
| `ctl.body_tmp_failed` | — | не удалось записать временный файл тела |
| `ctl.busy` | — | сервер занят другими запросами — повторите позже |
| `ctl.cannot_start` | — | не удалось начать обработку запроса |
| `ctl.denied` | — | этому процессу управлять ядром steer нельзя |
| `ctl.empty_word` | — | пустое слово: слова разделяются одним пробелом |
| `ctl.file_in_use` | — | файл упомянут в сохранённой спеке — сначала примените спеку без него |
| `ctl.file_remove_failed` | — | не удалось удалить файл |
| `ctl.file_write_failed` | — | не удалось записать файл (нет места?) |
| `ctl.in_use` | — | Файл используется |
| `ctl.internal` | — | Внутренняя ошибка ядра steer |
| `ctl.line_too_long` | — | строка запроса длиннее 512 байт |
| `ctl.lists_dir_failed` | — | не удалось создать каталог списков |
| `ctl.lists_dir_not_dir` | — | каталог списков — не каталог |
| `ctl.lists_path_long` | — | слишком длинный путь каталога списков |
| `ctl.lists_tmp_failed` | — | не удалось создать временный файл в каталоге списков |
| `ctl.lists_total_big` | — | файлы списков заняли бы больше 128 МиБ — уберите ненужные (rm-file) |
| `ctl.need_body_length` | — | нужна длина тела последним словом |
| `ctl.no_memory` | — | Нет памяти |
| `ctl.plan_unreadable` | — | план применения не разобран |
| `ctl.request_timeout` | — | запрос не пришёл целиком за 5 секунд |
| `ctl.saved_spec_unreadable` | — | не удалось прочитать сохранённую спеку |
| `ctl.spawn_failed` | — | не удалось запустить ядро |
| `ctl.spec_replace_failed` | — | не удалось заменить спеку |
| `ctl.spec_tmp_failed` | — | не удалось записать временный файл спеки |
| `ctl.spec_unreadable` | — | не удалось прочитать спеку |
| `ctl.timeout` | — | Команда не уложилась в свой срок и остановлена |
| `ctl.too_large` | — | Запрос слишком велик |
| `ctl.too_many_words` | — | слишком много слов в запросе |
| `ctl.unknown_command` | — | такой команды нет |
| `ctl.wait_failed` | — | не удалось дождаться ядра |
| `ctl.wrong_word_count` | — | не то число слов у команды |

### `steer xsteer-link` (`xslink.*`)

| Код | Подстановки | Текст (русский, как в журнале) |
|---|---|---|
| `xslink.hub_config` | — | это конфигурация хаба — ссылка описывает доступ ОДНОГО пира, а у хаба список пиров. Ссылку выдают из конфигурации пира. |
| `xslink.need_arg` | — | нужен файл, ссылка xs:// или «-» (позиционным аргументом или --config) |
| `xslink.rejected` | `why` | {why} |
| `xslink.render_failed` | `why` | {why} |
