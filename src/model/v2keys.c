/* Таблицы ключей спеки v2 (v2keys.h). Порядок записей внутри раздела — порядок показа в схеме.
 *
 * Подсказки — по docs/spec-v2.md. Примеры (ex) годятся стенду tests/specschemamatch.sh как значения
 * ключей, и ссылочные из них называют записи его основы: выходы wg0 и wg1 (kind: interface), список
 * work, клиент kids, апстрим dns1. Умолчания (def) — те, что ставит разбор; где умолчание выводится
 * из другого (устройство из имени выхода, путь conf из имени), его нет, а сказано в подсказке. */
#include <stdio.h>
#include <string.h>

#include "v2keys.h"
#include "spec.h"
#include "kind.h"

/* Записи таблицы — позиционные до примера, дальше именованные поля: хвост нулевой по построению. */
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

#define CC_PAT "^[A-Z][A-Z]$"
#define NAME_HINT "Имя — буквы, цифры, «_», «-», «.», до 31 байта."

static const struct v2key T[] = {
    /* ---- корень ------------------------------------------------------------------------- */
    { V2S_TOP, "version", VT_INT, VF_REQUIRED, "Версия формата спеки: сейчас 2.", NULL, "2", "2" },
    { V2S_TOP, "lan", VT_OBJ, 0, "Клиенты по умолчанию: правило без for относится к ним.", NULL, "{}",
      .sub = V2S_LAN },
    { V2S_TOP, "clients", VT_MAP, 0, "Именованные группы клиентов: по адресам, MAC или приложениям.", NULL, "{}",
      .sub = V2S_CLIENT, .reserved = "lan" },
    { V2S_TOP, "lists", VT_MAP, 0, "Назначения: именованные списки адресов, доменов и наборов sing-box.", NULL, "{}",
      .sub = V2S_LIST, .reserved = "all" },
    { V2S_TOP, "outputs", VT_MAP, 0, "Выходы: куда вести трафик — устройство, туннель, группа, блок.", NULL, "{}",
      .sub = V2S_OUT },
    { V2S_TOP, "dns", VT_OBJ, 0, "Резолвер ядра: режим, кэш, серверы DNS.", NULL, "{}", .sub = V2S_DNS },
    { V2S_TOP, "rules", VT_SEQ, 0, "Правила сверху вниз: выше — сильнее.", NULL, "[]", .sub = V2S_RULE },

    /* ---- lan ---------------------------------------------------------------------------- */
    { V2S_LAN, "devices", VT_STRS, 0, "Устройства, с которых ядро забирает трафик клиентов.", "[\"br-lan\"]",
      "[\"br-lan\"]", .min_items = 1 },
    { V2S_LAN, "addr", VT_STRS, 0, "Адреса, подсети или диапазоны клиентов по умолчанию, IPv4 и IPv6. "
      "Вместе с несколькими устройствами не пишется.", NULL, "[\"192.168.1.0/24\"]" },

    /* ---- clients ------------------------------------------------------------------------ */
    { V2S_CLIENT, "addr", VT_STRS, 0, "Адреса, подсети или диапазоны клиента, IPv4 и IPv6. "
      "Вместе с mac в одном клиенте не пишется.", NULL, "[\"192.168.1.50\"]" },
    { V2S_CLIENT, "mac", VT_STRS, 0, "MAC-адреса клиента.", NULL, "[\"aa:bb:cc:dd:ee:01\"]",
      .pat = "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$" },
    { V2S_CLIENT, "uid", VT_STRS, VF_PHONE | VF_ITEM_NUM, "Приложения телефона: UID вида 10123 или диапазон 10000-10099.",
      NULL, "[10123]" },
    { V2S_CLIENT, "self", VT_BOOL, VF_PHONE, "Трафик всех приложений самого устройства.", NULL, "true" },
    { V2S_CLIENT, "app", VT_STRS, VF_PHONE | VF_NOT_YET, "Имена пакетов приложений; пока вместо них — uid.", NULL,
      "[\"org.example.app\"]" },
    { V2S_CLIENT, "owner", VT_OBJ, VF_INTERNAL },

    /* ---- lists -------------------------------------------------------------------------- */
    { V2S_LIST, "srs", VT_STRS, VF_PATH, "Наборы sing-box (.srs): имена, подсети и сужение в одном файле.", NULL,
      "[\"lists/work.srs\"]" },
    { V2S_LIST, "prefixes_file", VT_STRS, VF_PATH, "Файлы адресов и подсетей, IPv4 и IPv6.", NULL,
      "[\"lists/work.lst\"]" },
    { V2S_LIST, "domains_file", VT_STRS, VF_PATH, "Файлы доменов.", NULL, "[\"lists/work.dom\"]" },
    { V2S_LIST, "domains", VT_STRS, VF_NOT_YET, "Встроенные домены; пока вместо них — domains_file.", NULL,
      "[\"corp.example\"]" },
    { V2S_LIST, "prefixes", VT_STRS, VF_NOT_YET, "Встроенные адреса и подсети; пока вместо них — prefixes_file.",
      NULL, "[\"10.20.0.0/16\"]" },
    { V2S_LIST, "proto", VT_STR, 0, "Протокол, к которому относится список: без сужения, если both.", "\"both\"",
      "\"udp\"", "tcp|udp|both" },
    { V2S_LIST, "ports", VT_STRS, VF_ITEM_NUM, "Порты 443 и диапазоны 50000-65535; диапазоны не пересекаются.", NULL,
      "[\"50000-65535\"]", .max_items = L4_PORTS_MAX },
    { V2S_LIST, "all", VT_BOOL, 0, "Весь трафик (с сужением proto и ports); источники рядом не пишутся.", "false",
      "true" },
    { V2S_LIST, "override_port", VT_INT, 0, "Подмена порта назначения для имён списка; только у списка доменов "
      "(domains_file без prefixes_file, srs и all) и в режиме fakeip.", NULL, "8443", .range = 1, .lo = 1, .hi = 65535 },
    { V2S_LIST, "owner", VT_OBJ, VF_INTERNAL },

    /* ---- outputs: общие ключи ----------------------------------------------------------- */
    { V2S_OUT, "kind", VT_STR, VF_REQUIRED, "Вид выхода.", NULL, NULL, .who = W_ALL },
    { V2S_OUT, "protocol", VT_STR, VF_REQUIRED, "Протокол туннеля.", NULL, NULL, .who = W_PROTOCOL,
      .owner = "kind: tunnel" },
    { V2S_OUT, "on_fail", VT_STR, 0, "Что делать, когда выход не работает: drop — отказ, direct — напрямую, "
      "zapret — обход DPI (не на телефоне).", "\"drop\"", "\"drop\"", "drop|direct|zapret", .who = W_FAIL },
    { V2S_OUT, "over", VT_STR, 0, "Выход-подложка: через него идёт трафик самого туннеля; без ключа — напрямую.",
      NULL, "\"wg0\"", .ref = "outputs", .who = W_OVER },
    { V2S_OUT, "device", VT_STR, 0, "Устройство выхода; без ключа выводится из имени выхода (у interface обязательно).",
      NULL, "\"ext0\"", .who = W_DEVICE },
    { V2S_OUT, "ipv6", VT_STR, 0, "IPv6 от хоста на том конце туннеля: routed и nat — у interface и awg, off — "
      "и у туннеля, и у группы.", NULL, "\"off\"", "routed|nat|off", .who = W_IPV6 },
    { V2S_OUT, "prefix", VT_STR, 0, "Префикс хоста при ipv6: routed, например 2001:db8:1::/56; без ключа "
      "выводится из адресов LAN.", NULL, "\"2001:db8:1::/56\"", .when = "ipv6=routed", .who = W_PREFIX },
    { V2S_OUT, "owner", VT_OBJ, VF_INTERNAL, .who = W_INTERNAL },

    /* ---- outputs: kind: group ----------------------------------------------------------- */
    { V2S_OUT, "pick", VT_STR, 0, "Как выбирается член: order — первый живой, latency — самый быстрый с допуском, "
      "manual — выбор человека, balance — соединения раздаются по живым.", "\"order\"", "\"order\"",
      "order|latency|manual|balance", .who = W_GROUP, .owner = "kind: group" },
    { V2S_OUT, "members", VT_STRS, VF_REQUIRED, "Члены группы по предпочтению: выходы с устройством, в том числе "
      "другие группы.", NULL, "[\"wg0\", \"wg1\"]", .min_items = 1, .ref = "outputs", .who = W_GROUP,
      .owner = "kind: group" },
    { V2S_OUT, "default", VT_STR, 0, "Член до первой команды select.", NULL, "\"wg0\"", .ref = "outputs",
      .when = "pick=manual", .who = W_GROUP, .owner = "kind: group" },
    { V2S_OUT, "tolerance", VT_INT, 0, "Допуск смены члена, мс: 0 — строго самый быстрый. Без ключа — умолчание сторожа (50).",
      NULL, "50", .range = 1, .lo = 0, .hi = GROUP_TOL_MAX_MS, .when = "pick=latency", .who = W_GROUP,
      .owner = "kind: group" },
    { V2S_OUT, "interval", VT_INT, 0, "Интервал замера, секунды. Без ключа — умолчание сторожа (180).", NULL, "180",
      .range = 1, .lo = GROUP_INT_MIN_S, .hi = GROUP_INT_MAX_S, .when = "pick=latency", .who = W_GROUP,
      .owner = "kind: group" },
    { V2S_OUT, "url", VT_STR, 0, "Адрес проверки http:// или https://; без ключа http://cp.cloudflare.com/generate_204.",
      NULL, "\"http://cp.cloudflare.com/generate_204\"", .when = "pick=latency", .who = W_GROUP,
      .owner = "kind: group" },
    { V2S_OUT, "idle_timeout", VT_INT, 0, "Сколько секунд без трафика замер не делается; 0 — мерить всегда "
      "(телефон — 1800, роутер — 0).", NULL, "0", .range = 1, .lo = 0, .hi = GROUP_IDLE_MAX_S,
      .when = "pick=latency", .who = W_GROUP, .owner = "kind: group" },
    { V2S_OUT, "weights", VT_INTS, 0, "Вес каждого члена по порядку members: доля новых соединений; без ключа — "
      "по 1.", NULL, "[2, 1]", .range = 1, .lo = 1, .hi = GROUP_WEIGHT_MAX, .when = "pick=balance",
      .who = W_GROUP, .owner = "kind: group" },
    { V2S_OUT, "by", VT_STR, 0, "Чем раздаются соединения: connection — случайно, site — один сайт на одном члене, "
      "site_client — сайт каждого устройства на одном члене.", "\"connection\"", "\"site\"",
      "connection|site|site_client", .when = "pick=balance", .who = W_GROUP, .owner = "kind: group" },
    { V2S_OUT, "exclude", VT_STRS, VF_NOMSG, "Страны (ISO 3166-1), члены которых не берутся; член без известной "
      "страны берётся.", NULL, "[\"RU\"]", .pat = CC_PAT, .when = "pick=latency|order", .who = W_GROUP,
      .owner = "kind: group" },
    { V2S_OUT, "only", VT_STRS, VF_NOMSG, "Страны (ISO 3166-1), чьи члены только и берутся.", NULL, "[\"NL\"]",
      .pat = CC_PAT, .when = "pick=latency|order", .who = W_GROUP, .owner = "kind: group" },

    /* ---- outputs: ключи видов (KK_*) ---------------------------------------------------- */
    { V2S_OUT, "obfs", VT_OBJ, 0, "WireGuard поверх поддельного TCP.", NULL, "{\"server\": \"192.0.2.1:443\", \"listen\": \"127.0.0.1:51821\"}",
      .sub = V2S_OBFS, .who = W_KK, .kk = KK_OBFS, .owner = "kind: interface" },
    { V2S_OUT, "conf", VT_STR, VF_PATH, "Файл настройки в стиле wg; без ключа {etc}/<вид>/<имя>.conf.", NULL,
      "\"xsteer/x.conf\"", .who = W_KK, .kk = KK_CONF, .owner = "kind: xsteer и kind: awg" },
    { V2S_OUT, "subscription", VT_STR, VF_PATH | VF_REQUIRED, "Файл подписки с узлами.", NULL, "\"sub/nl.txt\"",
      .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel" },
    { V2S_OUT, "nodes", VT_INTS, 0, "Номера пригодных узлов подписки по предпочтению; пусто — первый рабочий.",
      NULL, "[3, 5]", .range = 1, .lo = 0, .hi = 65535, .who = W_KK, .kk = KK_NODES, .owner = "kind: tunnel" },
    { V2S_OUT, "transport", VT_STRS, 0, "Транспорты узлов подписки, которыми ходить (фильтр узлов); без ключа — любые.",
      NULL, "[\"ws\"]", "tcp|grpc|xhttp|ws|httpupgrade", .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel",
      .protos = "vless" },
    { V2S_OUT, "insecure", VT_BOOL, 0, "Не проверять сертификат узлов TLS этого выхода.", "false", "true",
      .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel", .protos = "vless,trojan,vmess,http" },
    { V2S_OUT, "exclude", VT_STRS, 0, "Страны (ISO 3166-1), узлы которых не брать.", NULL, "[\"RU\"]", .pat = CC_PAT,
      .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel" },
    { V2S_OUT, "exclude_name", VT_STRS, 0, "Куски имени узла (без учёта регистра): узел с любым из них не берётся.",
      NULL, "[\"LTE\"]", .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel" },
    { V2S_OUT, "only", VT_STRS, 0, "Страны (ISO 3166-1), узлы которых только и берутся.", NULL, "[\"NL\"]", .pat = CC_PAT,
      .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel" },
    { V2S_OUT, "active", VT_INT, VF_POOL, "Сколько узлов работают сразу; кандидатов меньше — активны все.", "1", "2",
      .range = 1, .lo = 1, .hi = 65536, .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel", .protos = "vless,trojan,shadowsocks,socks,http,vmess" },
    { V2S_OUT, "active", VT_INT, VF_POOL, "У hysteria2 узел один: несколько сразу не бывает.", "1", "1",
      .range = 1, .lo = 1, .hi = 1, .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel", .protos = "hysteria2" },
    { V2S_OUT, "by", VT_STR, VF_POOL, "Как соединения делятся между активными узлами (при active больше 1): "
      "connection, site, site_client.", "\"connection\"", "\"site\"", "connection|site|site_client",
      .needs = "*:active", .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel", .protos = "vless,trojan,shadowsocks,socks,http,vmess" },
    { V2S_OUT, "interval", VT_INT, VF_POOL, "Период проверки узла, секунды (60; при pick: latency — 180).", NULL, "60",
      .range = 1, .lo = GROUP_INT_MIN_S, .hi = GROUP_INT_MAX_S, .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel" },
    { V2S_OUT, "silence", VT_INT, VF_POOL, "Порог молчания узла на живом соединении, секунды: 0 — порога нет, "
      "иначе от 5 (20; у hysteria2 — 30).", NULL, "20", .range = 1, .lo = 0, .hi = 32767, .who = W_KK, .kk = KK_SUB,
      .owner = "kind: tunnel" },
    { V2S_OUT, "pick", VT_STR, VF_POOL, "Какие узлы активны: order — первые живые по порядку, latency — самые быстрые "
      "по замеру.", "\"order\"", "\"order\"", "order|latency", .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel",
      .protos = "vless,trojan,shadowsocks,socks,http,vmess" },
    { V2S_OUT, "pick", VT_STR, VF_POOL, "У hysteria2 узел один: замера кандидатов нет, узлы по порядку.", "\"order\"",
      "\"order\"", "order", .who = W_KK, .kk = KK_SUB, .owner = "kind: tunnel", .protos = "hysteria2" },
    { V2S_OUT, "tolerance", VT_INT, VF_POOL, "Допуск смены узла по замеру, мс; 0 — на любой более быстрый.", "50", "50",
      .range = 1, .lo = 0, .hi = GROUP_TOL_MAX_MS, .when = "pick=latency", .who = W_KK, .kk = KK_SUB,
      .owner = "kind: tunnel", .protos = "vless,trojan,shadowsocks,socks,http,vmess" },
    { V2S_OUT, "stream", VT_BOOL, 0, "Транспорт xsteer — потоковый, а не поддельный TCP.", "false", "true",
      .who = W_KK, .kk = KK_STREAM, .owner = "kind: xsteer" },
    { V2S_OUT, "stream_port", VT_INT, 0, "Порт потокового транспорта xsteer.", NULL, "443",
      .range = 1, .lo = 1, .hi = 65535, .when = "stream=true", .who = W_KK, .kk = KK_STREAM, .owner = "kind: xsteer" },
    { V2S_OUT, "strategy", VT_STR, VF_PATH, "Файл стратегии обхода DPI.", NULL, "\"recheck/strategy.json\"",
      .who = W_KK, .kk = KK_OPTS, .owner = "kind: recheck" },
    { V2S_OUT, "domain", VT_STR, VF_REQUIRED, "Имя за Cloudflare, у которого kwsN.<domain> ведёт на веб-точку Telegram.",
      NULL, "\"tg.example\"", .who = W_KK, .kk = KK_DOMAIN, .owner = "kind: tgws" },

    /* ---- obfs --------------------------------------------------------------------------- */
    { V2S_OBFS, "mode", VT_STR, 0, "Режим: WireGuard поверх поддельного TCP.", "\"wg-over-tcp\"", "\"wg-over-tcp\"",
      "wg-over-tcp" },
    { V2S_OBFS, "server", VT_STR, VF_REQUIRED, "Сервер обфускации: адрес:порт литералом.", NULL, "\"192.0.2.1:443\"" },
    { V2S_OBFS, "listen", VT_STR, VF_REQUIRED, "Локальный адрес:порт обфускатора литералом: тот же, что в Endpoint пира WireGuard.", NULL, "\"127.0.0.1:51821\"" },

    /* ---- kind: warp (разворачивает ядро) ------------------------------------------------ */
    { V2S_WARP, "kind", VT_STR, VF_REQUIRED, "Вид выхода.", NULL, "\"warp\"", "warp" },
    { V2S_WARP, "transport", VT_STR, 0, "Транспорт туннелей: awg или MASQUE.", "\"awg\"", "\"awg\"", "awg|masque" },
    { V2S_WARP, "count", VT_INT, 0, "Сколько туннелей держать: запасные для мгновенного переключения.", "1", "2",
      .range = 1, .lo = 1, .hi = 255 },
    { V2S_WARP, "pick", VT_STR, 0, "Как выбирается туннель: latency — самый быстрый, order — по порядку.",
      "\"latency\"", "\"latency\"", "latency|order" },
    { V2S_WARP, "tolerance", VT_INT, 0, "Допуск смены туннеля, мс.", NULL, "50", .range = 1, .lo = 0,
      .hi = GROUP_TOL_MAX_MS, .when = "pick=latency" },
    { V2S_WARP, "interval", VT_INT, 0, "Интервал замера, секунды.", "600", "600", .range = 1, .lo = GROUP_INT_MIN_S,
      .hi = GROUP_INT_MAX_S, .when = "pick=latency" },
    { V2S_WARP, "url", VT_STR, 0, "Адрес проверки http:// или https://.", NULL, "\"http://cp.cloudflare.com/generate_204\"",
      .when = "pick=latency" },
    { V2S_WARP, "idle_timeout", VT_INT, 0, "Сколько секунд без трафика замер не делается; 0 — мерить всегда.", NULL, "0",
      .range = 1, .lo = 0, .hi = GROUP_IDLE_MAX_S, .when = "pick=latency" },
    { V2S_WARP, "countries", VT_STRS, 0, "Страны (ISO 3166-1) точек входа.", NULL, "[\"NL\"]", .pat = CC_PAT },
    { V2S_WARP, "exclude_countries", VT_STRS, 0, "Страны (ISO 3166-1), точки которых не брать.", NULL, "[\"RU\"]",
      .pat = CC_PAT },
    { V2S_WARP, "on_fail", VT_STR, 0, "Что делать, когда выход не работает.", "\"drop\"", "\"drop\"",
      "drop|direct|zapret" },
    { V2S_WARP, "over", VT_STR, 0, "Выход-подложка для туннелей WARP.", NULL, "\"wg0\"", .ref = "outputs" },
    { V2S_WARP, "ipv6", VT_STR, 0, "IPv6 через WARP: nat — с подменой, off — без IPv6.", "\"nat\"", "\"nat\"", "nat|off" },

    /* ---- dns ---------------------------------------------------------------------------- */
    { V2S_DNS, "mode", VT_STR, 0, "Режим доменных правил без своего resolve: поддельные адреса или настоящие.",
      "\"fakeip\"", "\"realip\"", "fakeip|realip" },
    { V2S_DNS, "cache", VT_INT, 0, "Записей в кэше ответов; 0 — кэша нет.", "0", "1000", .range = 1, .lo = 0, .hi = 100000 },
    { V2S_DNS, "cache_ttl", VT_OBJ, 0, "Пределы жизни записи кэша, секунды.", NULL, "{}", .sub = V2S_CACHE_TTL },
    { V2S_DNS, "upstream", VT_STR, 0, "Общий сервер для имён под правилами, у которых своего нет.", NULL, "\"dns1\"",
      .ref = "dns.upstreams" },
    { V2S_DNS, "upstreams", VT_MAP, 0, "Серверы DNS и группы серверов.", NULL, "{}", .sub = V2S_DNS_UP },
    { V2S_DNS, "other", VT_STR, 0, "Сервер для имён вне правил; без ключа — прежний путь наверх.", NULL, "\"dns1\"",
      .ref = "dns.upstreams" },
    { V2S_DNS, "bootstrap", VT_STRS, 0, "Адреса серверов обычного DNS, которыми разрешается имя сервера DoT, DoH, DoQ.",
      NULL, "[\"1.1.1.1\"]" },
    { V2S_DNS, "traceroute_hops", VT_BOOL, 0, "Трассировка через поддельные адреса видит настоящие узлы.", "false", "true" },
    { V2S_DNS, "mesh_clients", VT_BOOL, 0, "Запросы DNS клиентов mesh-VPN (tailscale, zerotier) заворачиваются "
      "на резолвер ядра.", "false", "true" },

    { V2S_CACHE_TTL, "min", VT_INT, 0, "Ответ живёт не меньше, секунд.", "10", "10", .range = 1, .lo = 0, .hi = 86400 },
    { V2S_CACHE_TTL, "max", VT_INT, 0, "Ответ живёт не дольше, секунд.", "3600", "3600", .range = 1, .lo = 1, .hi = 604800 },
    { V2S_CACHE_TTL, "negative", VT_INT, 0, "Срок отрицательного ответа (NXDOMAIN, пустой), секунд.", "30", "30",
      .range = 1, .lo = 0, .hi = 86400 },

    /* ---- dns: сервер и группа серверов -------------------------------------------------- */
    { V2S_DNS_UP, "url", VT_STR, VF_REQUIRED, "Адрес сервера: https://, tls://, quic://, h3://, udp://, tcp://.",
      NULL, "\"tls://dns.example\"" },
    { V2S_DNS_UP, "out", VT_STR, 0, "Выход, через который уходит запрос; без ключа или direct — напрямую.", NULL,
      "\"wg0\"", .ref = "outputs", .also = "direct" },
    { V2S_DNS_UP, "ips", VT_STRS, 0, "Адреса сервера: имя тогда не разрешается вовсе.", NULL, "[\"1.1.1.1\"]" },
    { V2S_DNS_UP, "bootstrap", VT_STRS, 0, "Серверы, которые разрешают имя сервера; без ключа — общие из dns.bootstrap.",
      NULL, "[\"1.1.1.1\"]" },
    { V2S_DNS_UP, "fragment", VT_BOOL, 0, "Делить ClientHello на две записи TLS; только у tls:// и https://.",
      "false", "true" },
    { V2S_DNS_GRP, "servers", VT_STRS, VF_REQUIRED, "Серверы группы по порядку: имена из dns.upstreams.", NULL,
      "[\"dns1\"]", .min_items = 1, .ref = "dns.upstreams" },
    { V2S_DNS_GRP, "mode", VT_STR, 0, "failover — по очереди, race — всем сразу, берётся первый годный ответ.",
      "\"failover\"", "\"race\"", "failover|race" },

    /* ---- rules -------------------------------------------------------------------------- */
    { V2S_RULE, "name", VT_STR, 0, "Подпись правила в status и журнале; без ключа — rule-<номер>.", NULL, "\"kids\"",
      .pat = "^[^\"\\\\]+$" },
    { V2S_RULE, "for", VT_STRS, 0, "Клиенты из clients; lan — клиенты по умолчанию.", "[\"lan\"]", "[\"kids\"]",
      .ref = "clients", .also = "lan" },
    { V2S_RULE, "to", VT_STRS, VF_REQUIRED, "Списки из lists; all — весь трафик.", NULL, "[\"work\"]", .min_items = 1,
      .ref = "lists", .also = "all" },
    { V2S_RULE, "out", VT_STR, VF_REQUIRED, "Выход или группа, куда вести трафик.", NULL, "\"wg0\"", .ref = "outputs" },
    { V2S_RULE, "resolve", VT_STR, 0, "Как отвечать на имена правила; без ключа — dns.mode.", NULL, "\"realip\"",
      "fakeip|realip" },
    { V2S_RULE, "dns", VT_STR_OBJ, 0, "Сервер DNS правила: имя из dns.upstreams или сервер, описанный здесь же.", NULL,
      "\"dns1\"", .ref = "dns.upstreams", .sub = V2S_DNS_UP },
    { V2S_RULE, "enabled", VT_BOOL, 0, "false — правило лежит в спеке, но не действует.", "true", "false" },
    { V2S_RULE, "scope", VT_STR, 0, "device — правило на одно устройство, старше глобальных; global — обычное.",
      "\"global\"", "\"global\"", "device|global", .needs = "device:for" },
    { V2S_RULE, "quic", VT_STR, 0, "block — UDP/443 к назначениям правила отвергается; allow — не трогать.", "\"allow\"",
      "\"block\"", "block|allow" },
    { V2S_RULE, "family", VT_STR, 0, "Семейство IP правила: 4, 6 или both.", "\"both\"", "\"both\"", "4|6|both" },
    { V2S_RULE, "on_family_unavailable", VT_STR, 0, "Что делать, когда выход не несёт IPv6: fallback — остаться по IPv4, "
      "block — отказать.", "\"fallback\"", "\"fallback\"", "fallback|block", .when = "family=6" },
    { V2S_RULE, "owner", VT_OBJ, VF_INTERNAL },
};
#define T_N (sizeof(T) / sizeof(T[0]))

const struct v2key *v2keys_all(size_t *n) {
    *n = T_N;
    return T;
}

const struct v2key *v2key_find(enum v2_scope sc, const char *key) {
    for (size_t i = 0; i < T_N; i++)
        if (T[i].scope == sc && !strcmp(T[i].key, key)) return &T[i];
    return NULL;
}

const struct v2key *v2key_out_find(const char *key, enum v2_who who) {
    for (size_t i = 0; i < T_N; i++)
        if (T[i].scope == V2S_OUT && T[i].who == who && !strcmp(T[i].key, key)) return &T[i];
    return NULL;
}

const char *v2key_name_at(enum v2_scope sc, size_t i) {
    for (size_t j = 0; j < T_N; j++)
        if (T[j].scope == sc && !(T[j].flags & VF_INTERNAL) && i-- == 0) return T[j].key;
    return NULL;
}

int v2key_known(enum v2_scope sc, const char *key) {
    return v2key_find(sc, key) != NULL;
}

void v2keys_list(enum v2_scope sc, char *buf, size_t n) {
    size_t l = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < T_N && l < n; i++) {
        if (T[i].scope != sc || (T[i].flags & VF_INTERNAL)) continue;
        l += (size_t)snprintf(buf + l, n - l, "%s%s", l ? ", " : "", T[i].key);
    }
}

int v2key_applies(const struct v2key *k, const struct kind_ops *kd, int group) {
    unsigned caps = kd->caps;
    switch (k->who) {
    case W_ALL: return 1;
    case W_PROTOCOL: return !group && (kd->keys & KK_SUB) != 0;
    case W_FAIL: return group || (caps & (KC_DEVICE | KC_MARK)) != 0;
    case W_IPV6: return group || (caps & KC_IPV6) != 0;
    case W_PREFIX: return !group && (caps & KC_IPV6) && (caps & KC_DEVICE) && !(caps & KC_TCP_REDIR);
    /* interface несёт подложку только с obfs (kind_ops.caps_of): ключ ему принадлежит, а смысл
     * имеет при obfs. */
    case W_OVER: return !group && ((caps & KC_OVER) || kd->caps_of);
    case W_DEVICE: return !group && (caps & KC_DEVICE) != 0;
    case W_GROUP: return group;
    case W_KK: return !group && (kd->keys & k->kk) != 0;
    case W_INTERNAL: return 0;
    }
    return 0;
}

int v2key_proto_ok(const struct v2key *k, const char *proto) {
    if (!k->protos || !proto) return 1;
    size_t pl = strlen(proto);
    for (const char *p = k->protos; *p; ) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == pl && !strncmp(p, proto, l)) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

int v2key_range(enum v2_scope sc, const char *key, long *lo, long *hi) {
    const struct v2key *k = v2key_find(sc, key);
    if (!k || !k->range) return 0;
    *lo = k->lo;
    *hi = k->hi;
    return 1;
}

void v2keys_out_list(const struct kind_ops *kd, int group, int tunnel, const char *proto, char *buf, size_t n) {
    size_t l = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < T_N && l < n; i++) {
        const struct v2key *k = &T[i];
        if (k->scope != V2S_OUT || k->who == W_INTERNAL) continue;
        if (k->who == W_PROTOCOL ? !tunnel : !v2key_applies(k, kd, group)) continue;
        if (!v2key_proto_ok(k, proto)) continue;
        /* Одно имя у нескольких записей (pick у группы и у туннеля) — один раз. */
        int dup = 0;
        for (size_t j = 0; j < i; j++)
            if (T[j].scope == V2S_OUT && !strcmp(T[j].key, k->key) && T[j].who != W_INTERNAL &&
                (T[j].who == W_PROTOCOL ? tunnel : v2key_applies(&T[j], kd, group)) &&
                v2key_proto_ok(&T[j], proto)) dup = 1;
        if (dup) continue;
        l += (size_t)snprintf(buf + l, n - l, "%s%s", l ? ", " : "", k->key);
    }
}
