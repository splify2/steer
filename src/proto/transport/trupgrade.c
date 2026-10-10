/* Запрос Upgrade по HTTP/1.1 — общий у ws и httpupgrade — и транспорт httpupgrade.
 *
 * Верхний ярус транспорта (transport.h), шаг 5 выпуска 1.10. Оба транспорта начинаются одним и тем
 * же: GET с `Connection: Upgrade` и `Upgrade: websocket`, ответ 101 — и расходятся после него. У
 * ws дальше кадры (trws.c), у httpupgrade — поток как есть: это «апгрейд без WebSocket», который
 * Xray и sing-box завели ради посредников (CDN), пропускающих только запросы, похожие на
 * WebSocket, — без затрат на кадры и маску.
 *
 * ЧТО ШЛЁМ — ТО ЖЕ, ЧТО XRAY, ДО БАЙТА. Так сделано ради того, чтобы не выделяться: запрос
 * Upgrade идёт первым байтом после TLS (а у security=none — открытым текстом), и посредник,
 * отличающий клиентов по составу и порядку заголовков, видит его целиком. Повторён клиент Xray
 * (transport/internet/websocket/dialer.go, httpupgrade/dialer.go), а не sing-box: у Xray облик
 * Chrome (common/utils/browser.go, applyMasqueradedHeaders с вариантом "ws"), у sing-box —
 * «Go-http-client/1.1», то есть заведомо не браузер. Сверено перехватом Xray 26.3.27 (клиент в
 * docker, сервер — слушающий сокет):
 *
 *   GET /p/q?x=1 HTTP/1.1                         ← ws; у httpupgrade `?` уезжает как %3F
 *   Host: cdn.example.com                         ← host, иначе sni, иначе адрес узла
 *   User-Agent: Mozilla/5.0 (Windows NT 10.0; …) Chrome/151.0.0.0 Safari/537.36
 *   Accept: * / *                                 ← без пробелов (в комментарии C иначе нельзя)
 *   Accept-Language: en-US,en;q=0.9
 *   Cache-Control: no-cache
 *   Connection: Upgrade
 *   DNT: 1
 *   Pragma: no-cache
 *   Sec-CH-UA: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"
 *   Sec-CH-UA-Mobile: ?0
 *   Sec-CH-UA-Platform: "Windows"
 *   Sec-Fetch-Dest: empty
 *   Sec-Fetch-Mode: websocket
 *   Sec-Fetch-Site: same-origin
 *   Sec-WebSocket-Key: U9ViAcDvC6DKctF7OLzaBA==   ← только ws
 *   Sec-WebSocket-Version: 13                     ← только ws
 *   Upgrade: websocket
 *
 * Порядок — не выбор Xray, а net/http Go: http.Request.Write печатает Host, потом User-Agent,
 * потом ВСЕ остальные заголовки по алфавиту ключа (байтово: заглавные раньше строчных), каждый
 * своим регистром. Регистр ключей тоже от Go: заголовки, которые Xray кладёт прямым присваиванием
 * (`Sec-CH-UA`, `DNT`, у gorilla — `Sec-WebSocket-Key`), остаются как написаны; поставленные через
 * Set и Add — приводятся к каноническому виду (`Sec-Fetch-Mode`); свои заголовки узла у ws тоже
 * приводятся (header.Add), у httpupgrade — нет (AddHeader в dialer.go кладёт ключ как есть, ради
 * тех, кто хочет «WebSocket» с большой S). Ниже это повторено моделью «словарь с точными ключами
 * и печатью по алфавиту», а не списком строк: тогда совпадают и случаи, где свой заголовок узла
 * перекрывает облик браузера, и случаи, где нет.
 *
 * Версия Chrome — наша зашитая (UA_CHROME в h2.h), а не 151 из перехвата: у Xray она считается от
 * даты со сдвигом от процессора, то есть у двух клиентов Xray тоже разная. Строка sec-ch-ua — та,
 * что Xray собрал бы для нашей версии (h2.h).
 *
 * Где Xray и sing-box расходятся — делаем как Xray (решение владельца 2026-09-29: эталон байтов на
 * проводе для VLESS и его транспортов — Xray-core). В том числе:
 *   - прочие облики по слову в своём User-Agent узла (firefox, safari, edge, curl, golang) —
 *     try_default_ws ниже;
 *   - РАННИЕ ДАННЫЕ (`?ed=N`, Ed у Xray, trpath.h). У ws — delayDialConn: запрос откладывается до
 *     первой записи, и она, если не длиннее Ed, уезжает в Sec-WebSocket-Protocol (base64url без
 *     выравнивания, tr_h1_send), иначе — кадрами после 101 (trws.c). У httpupgrade — ConnRF: запрос
 *     уходит при открытии, но ответа не ждём, данные идут следом, ответ разбирает первое чтение
 *     (hu_read_wait). sing-box делает иначе (режет первую запись по Ed и шлёт хвост отдельно) — ему
 *     не следуем. Что у ws цикл туннеля не может, как Xray, ждать ответа внутри записи, закрыто
 *     очередью: записи до 101 копятся и уходят сразу за ним, то есть на проводе тот же порядок —
 *     запрос, ответ, кадры (слать кадры раньше 101 нельзя: gorilla на стороне сервера рвёт такое
 *     соединение, «client sent data before handshake is complete»). Цена одна: у отложенного
 *     ответа нет своего срока (у Xray — HandshakeTimeout 8 с); молчащий сервер снимает простой
 *     соединения в стеке туннеля.
 *
 * ALPN — только http/1.1, как у Xray (tls.WithNextProto("http/1.1") и WebsocketHandshakeContext у
 * uTLS: он переписывает расширение ALPN отпечатка на один http/1.1). С парой «h2, http/1.1»
 * сервер за TLS вправе выбрать h2, и тогда наш запрос HTTP/1.1 для него мусор — ровно это уже
 * снято на мосту tgws (alpn_http11 в reality.h). Сам Chrome для веб-сокета поступает так же:
 * отдельное соединение с ALPN http/1.1. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/random.h>

#include "transport.h"
#include "trpath.h"

/* ---- мелочи: случайность, base64, SHA-1 ------------------------------------------------ */

/* Случайные байты у ядра. У слоя scrypto своего генератора нет: случайность в проекте берётся у
 * getrandom напрямую (reality.c, trxhttp.c, vision.c), и у ключа запроса и маски кадров нет
 * причины идти другим путём. Отказ — отказ соединения, а не нули: предсказуемая маска — ровно то,
 * против чего RFC 6455 (10.3) её и вводит. */
int tr_h1_random(unsigned char *out, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static size_t b64_std(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = i + 1 < n ? T[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? T[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

/* SHA-1 (FIPS 180-4) — только для Sec-WebSocket-Accept.
 *
 * Своя, а не из слоя scrypto, и это не небрежность. Accept — не защита: он лишь доказывает, что
 * ответил сервер, понявший запрос WebSocket, а не кеш или посредник, вернувший чужой ответ 101
 * (RFC 6455, 1.3). Заводить ради него SHA-1 в слое примитивов значило бы тащить в криптографию
 * движка устаревший хэш, которым ничего нельзя подписывать, — и ещё терять проверку в `make
 * test`, где библиотеки нет. Сорок строк за одну проверку на соединение — дешевле. */
struct sha1 { uint32_t h[5]; unsigned char b[64]; size_t bn; uint64_t len; };

static uint32_t rol(uint32_t x, int k) { return (x << k) | (x >> (32 - k)); }

static void sha1_block(struct sha1 *s, const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

static void sha1_update(struct sha1 *s, const void *d, size_t n) {
    const unsigned char *p = d;
    s->len += n;
    while (n) {
        size_t take = 64 - s->bn;
        if (take > n) take = n;
        memcpy(s->b + s->bn, p, take);
        s->bn += take; p += take; n -= take;
        if (s->bn == 64) { sha1_block(s, s->b); s->bn = 0; }
    }
}

static void sha1(const void *d, size_t n, unsigned char out[20]) {
    struct sha1 s = { { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }, { 0 }, 0, 0 };
    sha1_update(&s, d, n);
    uint64_t bits = s.len * 8;
    unsigned char pad = 0x80;
    sha1_update(&s, &pad, 1);
    unsigned char z = 0;
    while (s.bn != 56) sha1_update(&s, &z, 1);
    unsigned char l[8];
    for (int i = 0; i < 8; i++) l[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha1_update(&s, l, 8);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (unsigned char)(s.h[i] >> 24); out[4 * i + 1] = (unsigned char)(s.h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(s.h[i] >> 8); out[4 * i + 3] = (unsigned char)s.h[i];
    }
}

void tr_ws_accept(const char *key, char out[29]) {
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char h[20];
    sha1(buf, n > 0 && (size_t)n < sizeof(buf) ? (size_t)n : 0, h);
    b64_std(h, sizeof(h), out);
}

/* ---- заголовки запроса: словарь net/http ------------------------------------------------ */

#define HM_MAX 40
struct hent { char k[48]; const char *v; size_t vn; };
struct hmap { struct hent e[HM_MAX]; size_t n; int over; };

/* textproto.CanonicalMIMEHeaderKey: первая буква и буквы после `-` заглавные, прочие строчные;
 * ключ с незаконным для имени заголовка знаком возвращается как есть. */
static int token_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL && c != '\0';
}

static void canon(const char *k, size_t kn, char *out, size_t cap) {
    size_t n = kn < cap - 1 ? kn : cap - 1;
    int ok = 1;
    for (size_t i = 0; i < n; i++) if (!token_char((unsigned char)k[i])) ok = 0;
    int up = 1;
    for (size_t i = 0; i < n; i++) {
        char c = k[i];
        if (ok) {
            if (up && c >= 'a' && c <= 'z') c = (char)(c - 32);
            else if (!up && c >= 'A' && c <= 'Z') c = (char)(c + 32);
            up = c == '-';
        }
        out[i] = c;
    }
    out[n] = '\0';
}

static void hm_add(struct hmap *m, const char *k, const char *v, size_t vn) {
    if (m->n >= HM_MAX) { m->over = 1; return; }
    snprintf(m->e[m->n].k, sizeof(m->e[m->n].k), "%s", k);
    m->e[m->n].v = v;
    m->e[m->n].vn = vn;
    m->n++;
}

static void hm_del(struct hmap *m, const char *k) {
    size_t o = 0;
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->e[i].k, k) != 0) m->e[o++] = m->e[i];
    m->n = o;
}

/* Присваивание по ТОЧНОМУ ключу: и header.Set (ключ уже канонический), и header["Sec-CH-UA"]. */
static void hm_set(struct hmap *m, const char *k, const char *v) {
    hm_del(m, k);
    hm_add(m, k, v, strlen(v));
}

static const struct hent *hm_get(const struct hmap *m, const char *k) {
    for (size_t i = 0; i < m->n; i++)
        if (!strcmp(m->e[i].k, k)) return &m->e[i];
    return NULL;
}

static void hm_set_empty(struct hmap *m, const char *k, const char *v) {
    const struct hent *e = hm_get(m, k);
    if (!e || !e->vn) hm_set(m, k, v);
}

/* Прочие облики Xray (common/utils/browser.go) — для узла, чей User-Agent в headers задан словом
 * firefox, safari, edge, curl или golang: Xray понимает это слово как «представляйся этим
 * клиентом». Версии у Xray считаются от даты со сдвигом от процессора (FirefoxVersion,
 * SafariVersion, CurlVersion); здесь они зашиты тем же правилом, что UA_CHROME в h2.h, —
 * значением формулы на сентябрь 2026 при срединном сдвиге. Edge у Xray — ChromeUA и сразу, без
 * пробела, «Edg/…»: так в browser.go, так и здесь. sec-ch-ua у Edge собран правилом
 * getGreasedChUa для версии 149 (перестановка {2,1,0}, та же поддельная марка, что у Chrome). */
#define UA_FIREFOX \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"
#define UA_SAFARI \
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) " \
    "Version/26.6 Safari/605.1.15"
#define UA_EDGE UA_CHROME "Edg/" UA_CHROME_MAJOR ".0.0.0"
#define UA_CH_EDGE \
    "\"Microsoft Edge\";v=\"" UA_CHROME_MAJOR "\", \"Chromium\";v=\"" UA_CHROME_MAJOR \
    "\", \"Not)A;Brand\";v=\"24\""
#define UA_CURL "curl/8.20.0"

enum browser { BR_CHROME, BR_EDGE, BR_FIREFOX, BR_SAFARI, BR_CURL, BR_GOLANG };

/* applyMasqueradedHeaders(header, browser, "ws") — построчно. */
static void masq_ws(struct hmap *m, enum browser b) {
    switch (b) {
    case BR_CHROME:
    case BR_EDGE:
        hm_set(m, "Sec-CH-UA", b == BR_EDGE ? UA_CH_EDGE : UA_CH_CHROME);
        hm_set(m, "Sec-CH-UA-Mobile", "?0");
        hm_set(m, "Sec-CH-UA-Platform", "\"Windows\"");
        hm_set(m, "DNT", "1");
        hm_set(m, "User-Agent", b == BR_EDGE ? UA_EDGE : UA_CHROME);
        hm_set(m, "Accept-Language", "en-US,en;q=0.9");
        break;
    case BR_FIREFOX:
        hm_set(m, "User-Agent", UA_FIREFOX);
        hm_set(m, "DNT", "1");
        hm_set(m, "Accept-Language", "en-US,en;q=0.5");
        break;
    case BR_SAFARI:
        hm_set(m, "User-Agent", UA_SAFARI);
        hm_set(m, "Accept-Language", "en-US,en;q=0.9");
        break;
    case BR_GOLANG:
        /* «Показать умолчание net/http»: User-Agent снимается, дальше http.Request.Write сам
         * поставит Go-http-client/1.1; заголовков варианта нет (return в browser.go). */
        hm_del(m, "User-Agent");
        return;
    case BR_CURL:
        hm_set(m, "User-Agent", UA_CURL);
        return;
    }
    hm_set(m, "Sec-Fetch-Mode", "websocket");
    /* «Safari is NOT web-compliant here!» — у Safari Sec-Fetch-Dest другой (browser.go). */
    hm_set(m, "Sec-Fetch-Dest", b == BR_SAFARI ? "websocket" : "empty");
    hm_set(m, "Sec-Fetch-Site", "same-origin");
    hm_set_empty(m, "Cache-Control", "no-cache");
    hm_set_empty(m, "Pragma", "no-cache");
    hm_set_empty(m, "Accept", "*/*");
}

/* TryDefaultHeadersWith(header, "ws"): своего User-Agent нет — облик Chrome; есть и это одно из
 * слов Xray — облик этого клиента; иначе — ничего, User-Agent уходит как написан. */
static void try_default_ws(struct hmap *m) {
    const struct hent *ua = hm_get(m, "User-Agent");
    if (!ua) { masq_ws(m, BR_CHROME); return; }
    static const struct { const char *w; enum browser b; } W[] = {
        { "chrome", BR_CHROME }, { "firefox", BR_FIREFOX }, { "safari", BR_SAFARI },
        { "edge", BR_EDGE }, { "curl", BR_CURL }, { "golang", BR_GOLANG },
    };
    for (size_t i = 0; i < sizeof(W) / sizeof(*W); i++)
        if (ua->vn == strlen(W[i].w) && !strncmp(ua->v, W[i].w, ua->vn)) { masq_ws(m, W[i].b); return; }
}

struct wb { char *p; size_t n, cap; int over; };

static void w_s(struct wb *b, const char *s, size_t n) {
    if (b->n + n >= b->cap) { b->over = 1; return; }
    memcpy(b->p + b->n, s, n);
    b->n += n;
}
static void w_z(struct wb *b, const char *s) { w_s(b, s, strlen(s)); }

/* textproto.TrimString: пробелы и табуляции по краям. */
static void trim(const char **v, size_t *vn) {
    while (*vn && (**v == ' ' || **v == '\t')) { (*v)++; (*vn)--; }
    while (*vn && ((*v)[*vn - 1] == ' ' || (*v)[*vn - 1] == '\t')) (*vn)--;
}

/* Имя хоста для Host: host, иначе sni, иначе адрес узла (у Xray — wsSettings.Host,
 * tConfig.ServerName, dest.Address). Адрес IPv6 — в скобках, как его печатает Xray. */
static const char *host_of(const struct tr_node *n, char *buf, size_t cap) {
    if (n->http_host && n->http_host[0]) return n->http_host;
    if (n->sni && n->sni[0]) return n->sni;
    if (strchr(n->host, ':')) { snprintf(buf, cap, "[%s]", n->host); return buf; }
    return n->host;
}

size_t tr_h1_request(const struct tr_node *n, int ws, const char *key, const char *proto,
                     char *out, size_t cap) {
    char target[1024];
    if (tr_upgrade_target(n->path ? n->path : "", ws, target, sizeof(target), NULL) != 0) return 0;

    struct hmap m;
    m.n = 0;
    m.over = 0;
    char hostbuf[160];
    const char *host = host_of(n, hostbuf, sizeof(hostbuf));

    /* Свои заголовки узла. Host в них у ws Xray переносит в host (Build, с предупреждением
     * «устарело»), а у httpupgrade отвергает — это решает разбор подписки (sub.c); сюда Host
     * не доходит. */
    const char *h = n->headers ? n->headers : "";
    while (*h) {
        const char *eol = strchr(h, '\n');
        size_t ln = eol ? (size_t)(eol - h) : strlen(h);
        const char *colon = memchr(h, ':', ln);
        if (colon) {
            char key_raw[48], key_c[48];
            size_t kn = (size_t)(colon - h);
            snprintf(key_raw, sizeof(key_raw), "%.*s", (int)kn, h);
            const char *v = colon + 1;
            size_t vn = ln - kn - 1;
            trim(&v, &vn);
            if (ws) { canon(h, kn, key_c, sizeof(key_c)); hm_add(&m, key_c, v, vn); }
            else hm_add(&m, key_raw, v, vn);
        }
        h += ln + (eol ? 1 : 0);
    }

    try_default_ws(&m);

    if (ws) {
        /* Ранние данные: Xray — header.Set("Sec-WebSocket-Protocol", …), то есть канонический
         * ключ Sec-Websocket-Protocol (перекрывает свой такой же у узла), а gorilla перекладывает
         * его под ключ Sec-WebSocket-Protocol. Своё значение узла без ранних данных — так же
         * переложенным ключом. */
        const struct hent *sp = hm_get(&m, "Sec-Websocket-Protocol");
        if (proto) {
            hm_del(&m, "Sec-Websocket-Protocol");
            hm_set(&m, "Sec-WebSocket-Protocol", proto);
        } else if (sp) {
            struct hent e = *sp;
            hm_del(&m, "Sec-Websocket-Protocol");
            hm_add(&m, "Sec-WebSocket-Protocol", e.v, e.vn);
        }
        /* gorilla/websocket (client.go, DialContext): четыре своих заголовка точными ключами. */
        hm_set(&m, "Upgrade", "websocket");
        hm_set(&m, "Connection", "Upgrade");
        hm_set(&m, "Sec-WebSocket-Key", key ? key : "");
        hm_set(&m, "Sec-WebSocket-Version", "13");
    } else {
        /* httpupgrade/dialer.go: req.Header.Set — ключи канонические. */
        hm_set(&m, "Connection", "Upgrade");
        hm_set(&m, "Upgrade", "websocket");
    }
    if (m.over) return 0;

    /* http.Request.Write: строка запроса, Host, User-Agent (своего нет — умолчание Go), затем
     * остальные по алфавиту ключа; одинаковые ключи — в порядке добавления. */
    struct wb b = { out, 0, cap, 0 };
    w_z(&b, "GET ");
    w_z(&b, target);
    w_z(&b, " HTTP/1.1\r\nHost: ");
    w_z(&b, host);
    w_z(&b, "\r\n");
    const struct hent *ua = hm_get(&m, "User-Agent");
    const char *uav = ua ? ua->v : "Go-http-client/1.1";
    size_t uan = ua ? ua->vn : strlen(uav);
    if (uan) { w_z(&b, "User-Agent: "); w_s(&b, uav, uan); w_z(&b, "\r\n"); }

    size_t ord[HM_MAX], no = 0;
    for (size_t i = 0; i < m.n; i++) {
        const char *k = m.e[i].k;
        if (!strcmp(k, "Host") || !strcmp(k, "User-Agent") || !strcmp(k, "Content-Length") ||
            !strcmp(k, "Transfer-Encoding") || !strcmp(k, "Trailer"))
            continue;
        size_t j = no++;
        while (j > 0 && strcmp(m.e[ord[j - 1]].k, k) > 0) { ord[j] = ord[j - 1]; j--; }
        ord[j] = i;
    }
    for (size_t j = 0; j < no; j++) {
        const struct hent *e = &m.e[ord[j]];
        const char *v = e->v;
        size_t vn = e->vn;
        trim(&v, &vn);
        w_z(&b, e->k);
        w_z(&b, ": ");
        w_s(&b, v, vn);
        w_z(&b, "\r\n");
    }
    w_z(&b, "\r\n");
    if (b.over) return 0;
    out[b.n] = '\0';
    return b.n;
}

/* ---- ответ ------------------------------------------------------------------------------- */

/* Предел заголовков ответа. Ответ 101 — сотня байт; 16 КБ хватает любому посреднику, а без
 * предела сервер, льющий бесконечную строку, держал бы установщика до срока соединения. */
#define H1_RESP_MAX 16384

#define SEEN_UP   1u
#define SEEN_CONN 2u
#define SEEN_ACC  4u

static int eqfold(const char *a, size_t an, const char *b) {
    size_t bn = strlen(b);
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return 1;
}

/* Есть ли слово в списке через запятую (tokenListContainsValue у gorilla). */
static int token_in(const char *v, size_t vn, const char *want) {
    size_t i = 0;
    while (i <= vn) {
        const char *s = v + i;
        const char *c = memchr(s, ',', vn - i);
        size_t sl = c ? (size_t)(c - s) : vn - i;
        const char *t = s;
        size_t tn = sl;
        trim(&t, &tn);
        if (eqfold(t, tn, want)) return 1;
        i += sl + 1;
    }
    return 0;
}

/* Строка статуса по правилам http.ReadResponse: «HTTP/x.y КОД причина», код — ровно три цифры. */
static int status_of(const char *l, size_t n) {
    if (n < 12 || strncmp(l, "HTTP/", 5) != 0) return -1;
    if (l[5] < '0' || l[5] > '9' || l[6] != '.' || l[7] < '0' || l[7] > '9' || l[8] != ' ') return -1;
    if (l[9] < '0' || l[9] > '9' || l[10] < '0' || l[10] > '9' || l[11] < '0' || l[11] > '9') return -1;
    if (n > 12 && l[12] != ' ') return -1;
    return (l[9] - '0') * 100 + (l[10] - '0') * 10 + (l[11] - '0');
}

static void resp_line(struct h1_resp *r, int ws, const char *accept) {
    const char *l = r->line;
    size_t n = r->line_n;
    if (n && l[n - 1] == '\r') n--;
    if (!r->status) {
        int st = status_of(l, n);
        if (st < 0) { r->bad = 1; return; }
        r->status = st;
        return;
    }
    if (!n) { r->done = 1; return; }
    if (l[0] == ' ' || l[0] == '\t') return;      /* продолжение прежней строки — не наше */
    const char *colon = memchr(l, ':', n);
    if (!colon) return;
    size_t kn = (size_t)(colon - l);
    const char *v = colon + 1;
    size_t vn = n - kn - 1;
    trim(&v, &vn);
    if (eqfold(l, kn, "Upgrade")) {
        /* gorilla (ws) ищет слово во ВСЕХ строках Upgrade; Xray и sing-box (httpupgrade)
         * сравнивают первое значение целиком. */
        if (ws) { if (token_in(v, vn, "websocket")) r->up_ok = 1; }
        else if (!(r->seen & SEEN_UP)) r->up_ok = (uint8_t)eqfold(v, vn, "websocket");
        r->seen |= SEEN_UP;
    } else if (eqfold(l, kn, "Connection")) {
        if (ws) { if (token_in(v, vn, "upgrade")) r->conn_ok = 1; }
        else if (!(r->seen & SEEN_CONN)) r->conn_ok = (uint8_t)eqfold(v, vn, "upgrade");
        r->seen |= SEEN_CONN;
    } else if (ws && eqfold(l, kn, "Sec-WebSocket-Accept") && !(r->seen & SEEN_ACC)) {
        r->acc_ok = (uint8_t)(accept && vn == strlen(accept) && !memcmp(v, accept, vn));
        r->seen |= SEEN_ACC;
    }
}

void tr_h1_resp_feed(struct h1_resp *r, int ws, const char *accept,
                     const unsigned char *in, size_t n, size_t *used) {
    size_t i = 0;
    while (i < n && !r->done && !r->bad) {
        unsigned char c = in[i++];
        if (++r->total > H1_RESP_MAX) { r->bad = 1; break; }
        if (c == '\n') {
            resp_line(r, ws, accept);
            r->line_n = 0;
            continue;
        }
        /* Строка длиннее буфера обрезается, а не отвергается: нужные нам заголовки короткие,
         * а длинная строка посредника (Set-Cookie, CSP) законна и нам не нужна. Обрезанная
         * строка с нужным именем даст несовпадение значения — то есть честный отказ. */
        if (r->line_n < sizeof(r->line)) r->line[r->line_n++] = (char)c;
    }
    *used = i;
}

int tr_h1_resp_verdict(const struct h1_resp *r, int ws) {
    if (r->bad || !r->done) return TR_EUPTOOBIG;
    if (r->status != 101) return TR_EUPSTATUS;
    if (!r->up_ok || !r->conn_ok) return TR_ENOUPGRADE;
    if (ws && !r->acc_ok) return TR_EWSACCEPT;
    return 0;
}

/* Код ответа последнего отказа TR_EUPSTATUS — для текста (transport_strerror). На поток: отказы
 * у установщиков параллельные. */
static __thread int g_last_status;
int tr_h1_last_status(void) { return g_last_status; }

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* base64.RawURLEncoding — ранние данные у Xray («RawURLEncoding is support by both V2Ray/V2Fly
 * and XRay», websocket/dialer.go): алфавит URL и без выравнивания `=`. */
static size_t b64_url(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        if (i + 1 < n) out[o++] = T[(v >> 6) & 63];
        if (i + 2 < n) out[o++] = T[v & 63];
    }
    out[o] = '\0';
    return o;
}

int tr_h1_send(struct transport *t, int ws, const unsigned char *ed, size_t ed_n) {
    struct h1_state *s = &t->h1;
    char key[32] = "";
    if (ws) {
        unsigned char r[16];
        if (tr_h1_random(r, sizeof(r)) != 0) return TR_EIO;
        b64_std(r, sizeof(r), key);
        tr_ws_accept(key, s->accept);
    }
    /* В куче, а не __thread: с ранними данными запрос несёт до всей первой записи в base64 —
     * десятки килобайт, которые держать на каждый поток незачем. */
    size_t bn = ed ? (ed_n + 2) / 3 * 4 + 1 : 0;
    size_t cap = 4096 + bn;
    char *req = malloc(cap + bn);
    if (!req) return TR_EIO;
    char *proto = NULL;
    if (ed) { proto = req + cap; b64_url(ed, ed_n, proto); }
    size_t rn = tr_h1_request(&s->node, ws, ws ? key : NULL, proto, req, cap);
    int rc = rn ? tr_link_write(&t->link, (const unsigned char *)req, rn) : TR_EUPTOOBIG;
    free(req);
    return rc;
}

int tr_h1_lazy(struct transport *t, int ws, const unsigned char *in, size_t n, size_t *used) {
    struct h1_state *s = &t->h1;
    *used = 0;
    if (!s->resp) return TR_EIO;
    tr_h1_resp_feed(s->resp, ws, ws ? s->accept : NULL, in, n, used);
    if (s->resp->bad) return TR_EUPTOOBIG;
    if (!s->resp->done) return 0;
    int rc = tr_h1_resp_verdict(s->resp, ws);
    if (rc == TR_EUPSTATUS) g_last_status = s->resp->status;
    free(s->resp);
    s->resp = NULL;
    if (rc) return rc;
    s->phase = H1_OPEN;
    s->upgraded = 1;
    return 1;
}

/* Ответ 101 синхронно — путь без ранних данных. */
static int h1_wait(struct transport *t, int ws, int timeout_s) {
    int rc;
    const char *accept = t->h1.accept;
    /* Ответ ждём здесь, синхронно: открытие идёт в потоке установщика, со сроком соединения. */
    struct h1_resp r;
    memset(&r, 0, sizeof(r));
    int64_t deadline = mono_ms() + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    static __thread unsigned char raw[4096];
    for (;;) {
        const unsigned char *in = NULL;
        size_t got = 0;
        if (!t->link.plain && tls13_has_record(&t->link.tls)) {
            rc = tls13_read_ref(&t->link.tls, &in, &got);
            if (rc) return rc;
        } else {
            int64_t left = deadline - mono_ms();
            if (left <= 0) return TR_EUPTIMEOUT;
            struct pollfd p = { .fd = t->link.fd, .events = POLLIN, .revents = 0 };
            int pr = poll(&p, 1, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) return pr == 0 ? TR_EUPTIMEOUT : TR_EIO;
            if (t->link.plain) {
                ssize_t k = read(t->link.fd, raw, sizeof(raw));
                if (k == 0) return TR_ECLOSED;
                if (k < 0) {
                    if (errno == EINTR) continue;
                    return errno == EAGAIN || errno == EWOULDBLOCK ? TR_EUPTIMEOUT : TR_EIO;
                }
                in = raw;
                got = (size_t)k;
            } else {
                rc = tls13_read_ref(&t->link.tls, &in, &got);
                if (rc) return rc;
            }
        }
        if (!got) continue;
        size_t used = 0;
        tr_h1_resp_feed(&r, ws, ws ? accept : NULL, in, got, &used);
        if (r.bad) return TR_EUPTOOBIG;
        if (!r.done) continue;
        rc = tr_h1_resp_verdict(&r, ws);
        if (rc == TR_EUPSTATUS) g_last_status = r.status;
        if (rc) return rc;
        /* То, что приехало за ответом тем же куском, — уже поток: сохранить (см. h1_state). */
        if (used < got) {
            t->h1.stash = malloc(got - used);
            if (!t->h1.stash) return TR_EIO;
            memcpy(t->h1.stash, in + used, got - used);
            t->h1.stash_n = (uint32_t)(got - used);
            t->h1.stash_off = 0;
        }
        t->h1.upgraded = 1;
        return 0;
    }
}

/* Открытие по Ed — как у Xray:
 *   ws, Ed > 0          delayDialConn: ничего не шлём до первой записи (trws.c, H1_DEFER). У Xray
 *                       отложен даже сам TCP; у нас TCP и TLS открыты заранее — байты на проводе
 *                       те же, раньше лишь время;
 *   httpupgrade, Ed > 0 запрос сразу, а ответ читает первое чтение (ConnRF у Xray, H1_WAIT): данные
 *                       клиента идут вслед за запросом, не дожидаясь 101;
 *   Ed == 0             запрос и ответ синхронно. */
int tr_h1_upgrade(struct transport *t, const struct tr_node *n, int ws, int timeout_s) {
    struct h1_state *s = &t->h1;
    s->node = *n;
    char target[1024];
    if (tr_upgrade_target_ed(n->path ? n->path : "", ws, target, sizeof(target), NULL, &s->ed) != 0)
        return TR_EUPTOOBIG;
    if (ws && s->ed) { s->phase = H1_DEFER; return 0; }
    int rc = tr_h1_send(t, ws, NULL, 0);
    if (rc) return rc;
    /* httpupgrade с Ed > 0 не ждёт ответа — но только поверх TLS или REALITY. Без TLS (security=
     * none) ответ ждём, как при Ed == 0: сервер httpupgrade у Xray читает запрос через bufio и
     * дальше отдаёт голое соединение (hub.go), поэтому данные, приехавшие с запросом ОДНИМ
     * сегментом TCP, у него пропадают — снято на Xray 26.3.27: наш запрос и первая запись,
     * ушедшие подряд, давали «invalid request version» на каждом соединении. Клиент Xray на этом
     * не спотыкается лишь потому, что его первая запись уходит позже, уже отдельным сегментом.
     * Поверх TLS сервер читает запись TLS целиком и не больше, и потери нет. Байты на проводе в
     * обоих случаях те же, что у Xray, — различается только момент, когда уходит первая запись. */
    if (s->ed && !t->link.plain) {
        s->resp = calloc(1, sizeof(*s->resp));
        if (!s->resp) return TR_EIO;
        s->phase = H1_WAIT;
        return 0;
    }
    return h1_wait(t, ws, timeout_s);
}

void tr_h1_free(struct transport *t) {
    free(t->h1.stash);
    t->h1.stash = NULL;
    t->h1.stash_n = t->h1.stash_off = 0;
    free(t->h1.resp);
    t->h1.resp = NULL;
    free(t->h1.q);
    t->h1.q = NULL;
    t->h1.q_n = t->h1.q_cap = 0;
}

/* ---- транспорт httpupgrade ----------------------------------------------------------------- */

static int hu_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    return tr_h1_upgrade(t, n, 0, timeout_s);
}

/* Как ConnRF.Write у Xray — поток как есть, и в H1_WAIT тоже: ответа 101 запись не ждёт. */
static int hu_write(struct transport *t, const unsigned char *d, size_t n) {
    return tr_link_write(&t->link, d, n);
}

/* Отложенный ответ 101 (Ed > 0): первое чтение сперва дочитывает ответ, а то, что за ним, — уже
 * поток (ConnRF.Read у Xray отдаёт буферизованное за ответом тем же вызовом). */
static int hu_read_wait(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    const unsigned char *in = d;
    size_t n = 0;
    if (t->link.plain) {
        int rc = tr_sock_read(t->link.fd, d, cap, &n);
        if (rc) return rc;
    } else {
        int rc = tls13_read_ref(&t->link.tls, &in, &n);
        if (rc) return rc;
    }
    if (!n) return 0;
    size_t used = 0;
    int rc = tr_h1_lazy(t, 0, in, n, &used);
    if (rc <= 0) return rc;
    size_t rest = n - used;
    if (rest > cap) return H2_ETOOBIG;
    memmove(d, in + used, rest);
    *got = rest;
    return 0;
}

/* Сначала — остаток, приехавший вместе с ответом 101: это начало потока, и отдать его позже
 * следующего чтения сокета значило бы переставить байты. */
static int hu_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    struct h1_state *s = &t->h1;
    if (s->phase == H1_WAIT) return hu_read_wait(t, d, cap, got);
    if (s->stash) {
        size_t left = s->stash_n - s->stash_off;
        size_t take = left < cap ? left : cap;
        memcpy(d, s->stash + s->stash_off, take);
        s->stash_off += (uint32_t)take;
        *got = take;
        if (s->stash_off >= s->stash_n) tr_h1_free(t);
        return 0;
    }
    return tr_link_read(&t->link, d, cap, got);
}

static int hu_pending(const struct transport *t) { return t->h1.stash != NULL; }

static int hu_busy(const struct transport *t) { return t->h1.phase == H1_WAIT; }

static void hu_close(struct transport *t) { tr_h1_free(t); }

/* zc = 1: после ответа 101 данные лежат в записях TLS как есть, как у tcp, и чтение без копии
 * годится — пока остатка нет и ответ разобран (transport_read_zc спрашивает pending и busy). */
const struct transport_ops tr_httpupgrade = {
    .name = "httpupgrade", .alpn = "http/1.1", .zc = 1,
    .open = hu_open, .write = hu_write, .read = hu_read,
    .moved = NULL, .close = hu_close, .pending = hu_pending, .busy = hu_busy,
};
