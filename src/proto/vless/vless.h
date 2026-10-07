/* Клиент VLESS/Reality для steer-extended.
 *
 * Отдельный пакет по той же логике, по которой в OpenWrt есть dnsmasq и dnsmasq-full:
 * базовому движку VLESS не нужен, а весит он вместе с TLS-стеком заметно больше самого
 * движка. Кто хочет — ставит extended, у кого туннели wireguard — не платит за это.
 *
 * Почему свой клиент, а не xray/sing-box: те бинарники — это клиент И сервер И два
 * десятка протоколов, 27–38 МБ. На роутере с 6.9 МБ overlay они не помещаются вовсе, а
 * нужен из них один клиентский путь.
 */
#ifndef STEER_VLESS_H
#define STEER_VLESS_H
#include <stdint.h>
#include <stddef.h>

/* Узел подписки. Строки, а не разобранные структуры: всё это едет в конфиг как есть, и
 * лишнее преобразование туда-обратно только добавило бы место для расхождения. */
struct vless_node {
    char name[128];        /* человеческое имя из #фрагмента, уже раскодированное */
    char host[128];
    uint16_t port;
    char uuid[64];
    char type[16];         /* tcp | grpc | xhttp | ws | httpupgrade */
    char security[16];     /* none | tls | reality */
    char sni[128];         /* маскировочный домен — он же SNI в ClientHello */
    char fp[16];           /* отпечаток браузера: chrome, firefox, qq… */
    char pbk[64];          /* публичный ключ сервера, base64url */
    char sid[32];          /* short id, hex */
    char flow[32];         /* xtls-rprx-vision или пусто */
    /* xhttp, ws, httpupgrade. У ws и httpupgrade — как в ссылке, вместе с `?ed=N`: ранние данные
     * вырезаются из пути при запросе, ровно как у Xray (src/proto/transport/trpath.h). */
    char path[128];
    char service[64];      /* grpc serviceName */
    char mode[16];         /* grpc: multi/gun; xhttp: auto/packet-up… */
    /* ws и httpupgrade: заголовок Host — параметр `host` ссылки, `host` в wsSettings или
     * httpupgradeSettings конфига Xray. Пусто — sni, затем адрес узла (правило Xray). */
    char http_host[128];
    /* ws и httpupgrade: свои заголовки запроса — `headers` конфига Xray, строками «Имя: значение\n».
     * У ссылки vless:// такого поля нет вовсе (формат Xray его не знает), поэтому заголовки бывают
     * только у подписки в виде конфига. Проверены при разборе: имя — знаки токена HTTP, в значении
     * нет перевода строки (иначе один заголовок узла становился бы двумя строками запроса). */
    char headers[192];
    /* Заголовок из конфига не влез в headers или негоден — узел непригоден (skip_reason), а не
     * уходит с молча выброшенным заголовком. */
    uint8_t headers_bad;

    /* Длина набивки xhttp, в знаках: сколько сервер согласен принять в x_padding.
     *
     * ЭТО НЕ УКРАШЕНИЕ, А УСЛОВИЕ. Сервер xhttp ПРОВЕРЯЕТ длину и на несовпадение отвечает
     * 400 — то есть узел с чужой набивкой выглядит неисправным, притом что исправно всё.
     * Снято на живой подписке: продавец объявил «50-150», мы слали 150…660, и все четыре
     * его узла xhttp отвечали отказом.
     *
     * Ноль в pad_to означает «не объявлено» — тогда берётся умолчание Xray, 100…1000
     * (GetNormalizedXPaddingBytes). */
    uint16_t pad_from, pad_to;
    /* xhttp packet-up: сколько самое большее несёт тело POST (scMaxEachPostBytes у Xray: число или
     * диапазон, клиент выбирает одно значение на соединение). Больше сервер отвечает 413.
     * post_to == 0 — не объявлено: умолчание Xray 1000000, больше любого нашего куска. */
    uint32_t post_from, post_to;
    /* Постквантовые поля Xray-core. Длинные (ключ ML-DSA-65 — 2603 знака base64url, реле VLESS
     * encryption с ключом ML-KEM-768 — около 1600), поэтому строки лежат не в узле, а в общей
     * таблице sub.c (sub_intern): одинаковые значения — один экземпляр, память не освобождается и не
     * растёт от повторных разборов. NULL — поля нет. Указатель переживает узел и его копии. */
    const char *pqv;         /* reality: mldsa65Verify / pqv */
    const char *encryption;  /* vless: encryption=mlkem768x25519plus.… (none не хранится) */
    /* Настройки, которых клиент не умеет и которые сервер ТРЕБУЕТ (иначе соединение не откроется): узел
     * объявляется непригодным сразу, с названной причиной, а не тратит попытки сторожа. tcp_http —
     * заголовок HTTP-маскировки tcp (headerType=http); xh_extra — обфускация запросов xhttp
     * (xPaddingObfsMode, размещения sessionID/seq/данных, downloadSettings). */
    uint8_t tcp_http, xh_extra;
    /* Клиентская проверка сертификата узла security=tls (Xray-core: pinnedPeerCertSha256 / `pcs`,
     * verifyPeerCertByName / `vcn`; sing-box: certificate_public_key_sha256). Строки из общей таблицы
     * sub_intern, NULL — поля нет. pcs и pks — SHA-256 в hex строчными, через запятую: pcs от всего
     * сертификата (DER), pks от его SubjectPublicKeyInfo; vcn — имена через запятую. */
    const char *pcs, *pks, *vcn;
    /* security=tls: ECHConfigList в base64 (Encrypted Client Hello), интернирован; NULL — без ECH. */
    const char *ech;
    /* allowInsecure=1 (skip-cert-verify, insecure) в подписке. Подписка сама проверку сертификата НЕ
     * выключает: узел пригоден, только если у выхода явно стоит `insecure` (sub.c, node_usable). */
    uint8_t allow_insecure;
    /* Ключ `insecure` выхода на момент разбора (node_usable): клиент не проверяет сертификат этого
     * узла. Живёт в узле, а не читается из глобала при подключении, чтобы клиент (client.c) не зависел
     * от разбора подписки: стенды собирают их порознь. */
    uint8_t insecure;
    char skip_reason[96];  /* почему узел непригоден — чтобы это можно было показать */
};

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n);

/* 0 — узел пригоден, 1 — пропущен (причина в skip_reason), -1 — не vless-ссылка. */
int vless_parse_url(const char *url, struct vless_node *n);

/* Причины непригодности, сгруппированные по тексту причины.
 *
 * Группировка здесь, а не в интерфейсе: подписка, целиком собранная из узлов с
 * неподдержанным security, даёт 26 одинаковых строк, и гонять их по ubus ради того,
 * чтобы свернуть на экране, незачем. Отдельного кода причины нет намеренно — текст уже
 * содержит и класс («транспорт X не поддержан»), и само значение, а код был бы вторым
 * способом сказать то же самое, который со временем разойдётся с первым. */
#define VLESS_SKIP_REASONS 8

struct vless_skip {
    /* та же строка, что легла бы в vless_node.skip_reason, и того же размера: при 64 байтах против 96
     * у узла причина в skipped_reasons обрезалась («…включите insecure у выхода явн»). */
    char reason[96];
    char example[144];     /* имя ПЕРВОГО узла с этой причиной, иначе host:port.
                            * Длиннее name[128] намеренно: во второй форме сюда влезает
                            * host целиком плюс ":65535", а обрезанный хост в объяснении
                            * хуже, чем его отсутствие. */
    size_t count;
};

/* Итог разбора подписки: сколько узлов пригодно — возвращаемое значение, всё остальное
 * здесь, с объяснением. До запуска 45 отсюда наружу шли только два числа, и человек с
 * подпиской из одних tls-узлов видел «пригодно 0, пропущено 26» без причины, хотя
 * причина у движка была в руках (splicicd#16, вариант А). */
struct vless_sub_stats {
    size_t skipped;                              /* непригодных ссылок vless:// */
    size_t foreign;                              /* ссылок чужих протоколов */
    size_t reasons_n;                            /* сколько РАЗНЫХ причин собрано */
    size_t reasons_dropped;                      /* узлов, чья причина не влезла */
    struct vless_skip reasons[VLESS_SKIP_REASONS];
};

/* Ключ `insecure` выхода: подписке разрешено нести узлы с allowInsecure, а клиент не проверяет
 * сертификат узлов security=tls. Ставится процессом выхода ДО разбора подписки; по умолчанию — 0.
 * Глобальная настройка, а не поле узла, потому что процесс клиента обслуживает ровно один выход,
 * а решение «пригоден ли узел» принимает разбор, которому выхода не передают. */
void vless_set_insecure(int on);
int vless_insecure(void);

/* st допускает NULL: подъёму туннеля счётчики не нужны. */
/* Привести прочитанный файл подписки к тексту для vless_parse_sub: конфиг Xray и список
 * ссылок отдаются как есть, base64 раскодируется в dec. Подробности — в sub.c. */
const char *vless_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n);

size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st);

/* Файл подписки → массив узлов в куче (free вызывающему), *cnt — сколько пригодных. NULL — файл
 * не открылся или больше 64 МиБ. Ни число узлов, ни размер подписки константой не ограничены. */
struct vless_node *vless_load_sub(const char *path, size_t *cnt, struct vless_sub_stats *st);

#endif
