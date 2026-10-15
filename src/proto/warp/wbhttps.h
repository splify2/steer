/* HTTPS-запрос модуля steer-warpbox (подробности — в wbhttps.c). */
#ifndef STEER_WBHTTPS_H
#define STEER_WBHTTPS_H

#include <stddef.h>
#include <stdint.h>

#define WB_RESP_MAX (1 << 20)

struct wb_req {
    const char *host;           /* имя: SNI, Host и проверка сертификата */
    const char *addr;           /* куда соединяться (NULL — разрешить host) */
    unsigned port;              /* 0 — 443 */
    const char *method;         /* GET, POST, PATCH */
    const char *path;
    const char *headers;        /* дополнительные «Имя: значение\r\n…» или NULL */
    const char *body;           /* JSON или NULL */
    size_t body_n;
    int timeout_ms;             /* на весь запрос; 0 — 20 с */
};

/* Путь сокета: метка (выход steer) или устройство; оба нуля — обычный маршрут. */
struct wb_route {
    uint32_t mark;
    const char *dev;
};

struct wb_resp {
    int status;
    char *body;                 /* с завершающим нулём; освобождать wb_resp_free */
    size_t body_n;
};

/* 0 — ответ получен (любой статус, out заполнен); -1 — нет, почему — в why. */
int wb_https(const struct wb_req *q, const struct wb_route *rt, struct wb_resp *out, char *why, size_t wn);
void wb_resp_free(struct wb_resp *r);

#endif
