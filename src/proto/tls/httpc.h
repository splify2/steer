/* HTTP/1.1-клиент libsteer: GET, HEAD и запросы с телом (POST, PUT, PATCH, DELETE) по http:// и https://,
 * переадресации, потоковое тело ответа, сроки, If-None-Match/ETag (подробности — в httpc.c). Один клиент
 * на всё: подписки (subfetch.c), пакеты плагинов, каталоги, API WARP (wbhttps.c — тонкая обёртка).
 * Формата того, что качают, он не знает. */
#ifndef STEER_HTTPC_H
#define STEER_HTTPC_H
#include <stddef.h>
#include <stdint.h>

struct http_req {
    const char *url;            /* http://… или https://… (userinfo в ссылке — отказ) */
    const char *method;         /* "GET" (NULL), "HEAD", "POST", "PUT", "PATCH" или "DELETE" */
    const void *body;           /* тело запроса (Content-Length ставится само; тип — в headers); NULL — нет */
    size_t body_n;
    const char *headers;        /* добавочные «Имя: значение\r\n…» или NULL; User-Agent и Accept отсюда
                                 * заменяют свои. Уходят и на переадресованные адреса — Cookie и
                                 * Authorization туда класть не надо */
    const char *etag;           /* значение If-None-Match («"abc"» с кавычками) или NULL */
    const char *addr;           /* соединиться с этим адресом (имя или IP) вместо разрешения хоста ссылки; Host, SNI
                                 * и проверка сертификата остаются по ссылке. Только для хоста первой ссылки,
                                 * не для переадресаций на другие хосты */
    int any_status;             /* отдавать тело и при статусе не 2xx (4xx/5xx: API присылает в нём причину) */

    /* Куда тело. Оба нуля — тело отбрасывается (HEAD, проверка статуса). Тело отдаётся только при
     * статусе 2xx (с any_status — при любом, кроме 204 и 304); у 3xx без Location оно не читается. */
    const char *dest_path;      /* файл: создаётся с нуля (O_TRUNC), при отказе удаляется */
    int (*body_cb)(void *arg, const void *data, size_t n);   /* порция тела; ненулевой ответ — прервать (HTTPC_ESINK) */
    void *cb_arg;

    /* Сроки, мс; 0 — умолчание. Общего предела на скачивание нет нарочно: пакет в сотни мегабайт на
     * медленном канале законен, пока данные идут. Хочется общий срок — total_ms. */
    int connect_ms;             /* соединение и рукопожатие TLS на каждый адрес; умолчание 10000 */
    int idle_ms;                /* молчание сервера между порциями; умолчание 30000 */
    int total_ms;               /* на весь вызов, со всеми переадресациями; 0 — без предела */
    int max_redirects;          /* 0 — 10; отрицательное — не следовать (3xx отдаётся как ответ). 301/302/303 у метода с
                                 * телом превращают запрос в GET без тела, 307/308 повторяют его как есть */

    /* Путь сокета (как wb_route у warpbox): метка выхода steer или устройство; оба нуля — обычный маршрут. */
    uint32_t mark;
    const char *dev;
    const char *roots;          /* хранилище корней для https; NULL — как у остальных (tls_cert_roots) */
};

struct http_resp {
    int status;                 /* конечный статус; 304 — не изменилось (not_modified) */
    int not_modified;
    char *headers;              /* заголовки конечного ответа: строка статуса и поля, без '\r'; http_resp_free */
    size_t headers_n;
    char *url;                  /* адрес конечного ответа после переадресаций */
    char *etag;                 /* значение ETag конечного ответа или NULL */
    unsigned long long body_n;  /* байт тела, отданных приёмнику */
    int redirects;              /* сколько переадресаций пройдено */
};

#define HTTPC_EURL      (-1)    /* ссылка не разобралась или схема не http/https */
#define HTTPC_ERESOLVE  (-2)    /* имя не разрешилось */
#define HTTPC_ECONNECT  (-3)    /* соединиться не удалось */
#define HTTPC_ETLS      (-4)    /* рукопожатие TLS или сертификат */
#define HTTPC_ETIMEOUT  (-5)    /* вышел один из сроков */
#define HTTPC_EPROTO    (-6)    /* ответ не похож на HTTP или разбор тела (chunked) сломался */
#define HTTPC_ETRUNC    (-7)    /* тело оборвано: меньше Content-Length или нет завершающего куска */
#define HTTPC_EREDIR    (-8)    /* переадресаций больше предела, либо https -> http */
#define HTTPC_ESINK     (-9)    /* приёмник тела отказал: запись файла или body_cb */
#define HTTPC_ENOMEM    (-10)
#define HTTPC_EHDR      (-11)   /* заголовки ответа длиннее HTTPC_HDR_MAX */
#define HTTPC_EIO       (-12)   /* обрыв чтения или записи сокета */

/* Единственный предел клиента, и у него настоящая причина: заголовки копятся в памяти, пока не
 * придёт пустая строка, а сервер, который её не присылает, иначе съел бы память. Тело пределом не
 * ограничено — оно уходит приёмнику потоком. */
#define HTTPC_HDR_MAX (1u << 20)

/* 0 — ответ получен (любой статус, в том числе 404 и 304; смотри r->status); отрицательное — код
 * выше, why (если не NULL) — одной строкой. r заполняется и при отказе (то, что успело). */
int http_get(const struct http_req *q, struct http_resp *r, char *why, size_t wn);
void http_resp_free(struct http_resp *r);

/* Значение поля в r->headers (без регистра имени, пробелы по краям срезаны): указатель внутрь
 * заголовков и длина в *n; NULL — поля нет. Поле повторено — первое. */
const char *http_resp_header(const struct http_resp *r, const char *name, size_t *n);

#endif
