/* HTTPS-клиент ядра для .so-плагинов (host->http, src/daemon/plugso.c): тонкий вход в http_get без
 * struct http_req в заголовке демона. Демон — слой src/daemon, клиент HTTP — слой TLS, которого нет в базовых
 * сборках: демон зовёт этот вход слабой ссылкой (как urltls_start у замера групп) и без него отвечает отказом. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "httpc.h"

/* method GET по умолчанию; headers — «Имя: значение\r\n…» или NULL; mark — метка сокета (0 — обычный
 * маршрут); timeout_ms — срок соединения, молчания и всего вызова. Тело ответа — порциями в sink (ненулевой
 * ответ прерывает). Любой статус HTTP, кроме обрыва, отдаётся как ответ (*status); 0 — ответ получен,
 * отрицательное — код httpc.h, why — одной строкой. */
int plugso_http_get(const char *method, const char *url, const char *headers, const void *body, size_t body_n,
                    uint32_t mark, uint32_t timeout_ms, int (*sink)(void *, const void *, size_t), void *arg,
                    int *status, char *why, size_t wn) {
    struct http_req q;
    struct http_resp r;
    memset(&q, 0, sizeof q);
    memset(&r, 0, sizeof r);
    q.url = url;
    q.method = method;
    q.body = body;
    q.body_n = body_n;
    q.headers = headers;
    q.any_status = 1;
    q.body_cb = sink;
    q.cb_arg = arg;
    q.idle_ms = q.connect_ms = q.total_ms = (int)timeout_ms;
    q.mark = mark;
    int rc = http_get(&q, &r, why, wn);
    *status = rc == 0 ? r.status : -1;
    http_resp_free(&r);
    return rc;
}
