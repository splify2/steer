/* Тонкая обвязка над http_get для tests/httpsmatch.sh: настоящий TLS libsteer против python-сервера.
 *   httpsget <ссылка> <корни.pem> <файл-тела> [etag]
 * Печатает «rc=<код> status=<статус> body=<байт> redirects=<n> etag=<…> why=<…>». */
#include <stdio.h>
#include <stdlib.h>
#include "httpc.h"

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    struct http_req q = { .url = argv[1], .roots = argv[2], .dest_path = argv[3], .etag = argc > 4 ? argv[4] : NULL,
                          .total_ms = 30000 };
    struct http_resp r;
    char why[300];
    int rc = http_get(&q, &r, why, sizeof why);
    printf("rc=%d status=%d body=%llu redirects=%d etag=%s why=%s\n", rc, r.status, r.body_n, r.redirects,
           r.etag ? r.etag : "-", why);
    http_resp_free(&r);
    return 0;
}
