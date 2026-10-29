/* HTTPS-запрос модуля steer-warpbox: регистрация в API Cloudflare и проверки через туннель.
 *
 * ТОНКАЯ ОБЁРТКА НАД ОБЩИМ КЛИЕНТОМ (src/proto/tls/httpc.c; в src/lib он не лежит: файлы src/lib входят в
 * каждый профиль, а ему нужен TLS). Здесь жил свой клиент — соединение, ClientHello, рукопожатие, запрос, разбор ответа, — и ровно он стал основой общего: подписки, пакеты плагинов и
 * каталоги ходят тем же кодом (PLUGINS.md, решение О-16). Осталось то, что у WARP своё: ответ целиком в
 * память с пределом WB_RESP_MAX (JSON API), тип тела application/json, тело и при статусе не 2xx (причина
 * отказа лежит в нём), без переадресаций (API отвечает сам), срок на весь запрос.
 *
 * Блокирующий, со сроком на всё: модуль — свой процесс, и ждать ему некого (у демона так нельзя —
 * поэтому там рабочий поток). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httpc.h"
#include "wbhttps.h"

struct acc {
    char *b;
    size_t n, cap;
    int over;
};

static int collect(void *arg, const void *d, size_t n) {
    struct acc *a = arg;
    if (a->n + n > WB_RESP_MAX) { a->over = 1; return 1; }
    if (a->n + n + 1 > a->cap) {
        size_t nc = (a->n + n + 1) * 2;
        char *nb = realloc(a->b, nc);
        if (!nb) return 1;
        a->b = nb;
        a->cap = nc;
    }
    memcpy(a->b + a->n, d, n);
    a->n += n;
    return 0;
}

int wb_https(const struct wb_req *q, const struct wb_route *rt, struct wb_resp *out, char *why, size_t wn) {
    out->status = 0;
    out->body = NULL;
    out->body_n = 0;
    if (why && wn) why[0] = '\0';
    char url[1100];
    unsigned port = q->port ? q->port : 443u;
    int ul = port == 443 ? snprintf(url, sizeof url, "https://%s%s", q->host, q->path)
                         : snprintf(url, sizeof url, "https://%s:%u%s", q->host, port, q->path);
    if (ul <= 0 || (size_t)ul >= sizeof url) { if (why && wn) snprintf(why, wn, "ссылка не уместилась"); return -1; }
    size_t hl = q->headers ? strlen(q->headers) : 0;
    char *hdrs = malloc(hl + 64);
    if (!hdrs) { if (why && wn) snprintf(why, wn, "нет памяти"); return -1; }
    snprintf(hdrs, hl + 64, "%s%s", q->headers ? q->headers : "", q->body ? "Content-Type: application/json\r\n" : "");

    struct acc a = {0};
    struct http_req hq = {
        .url = url, .method = q->method, .headers = hdrs, .body = q->body, .body_n = q->body_n,
        .addr = q->addr && q->addr[0] ? q->addr : NULL, .any_status = 1,
        .body_cb = collect, .cb_arg = &a,
        .max_redirects = -1,
        .total_ms = q->timeout_ms > 0 ? q->timeout_ms : 20000,
        .mark = rt ? rt->mark : 0, .dev = rt ? rt->dev : NULL,
    };
    struct http_resp r;
    char w2[300];
    int rc = http_get(&hq, &r, w2, sizeof w2);
    free(hdrs);
    if (rc != 0) {
        if (why && wn) {
            if (a.over) snprintf(why, wn, "ответ длиннее %d байт", WB_RESP_MAX);
            else snprintf(why, wn, "%s", w2);
        }
        http_resp_free(&r);
        free(a.b);
        return -1;
    }
    if (!a.b) a.b = calloc(1, 1);
    if (!a.b) { http_resp_free(&r); if (why && wn) snprintf(why, wn, "нет памяти"); return -1; }
    a.b[a.n] = '\0';
    out->status = r.status;
    out->body = a.b;
    out->body_n = a.n;
    http_resp_free(&r);
    return 0;
}

void wb_resp_free(struct wb_resp *r) {
    free(r->body);
    r->body = NULL;
    r->body_n = 0;
}
