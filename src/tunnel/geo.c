/* Фактическая страна выхода туннеля (D-S2.5, R-124).
 *
 * ЗАЧЕМ. Страна узла в подписке — обещание имени: флаг-эмодзи ставит продавец. Выход сам знает лучше:
 * после подъёма туннеля и после каждой смены узла клиент спрашивает https://1.1.1.1/cdn-cgi/trace
 * через устройство туннеля — ответ Cloudflare называет страну, которую видят сайты (`loc=`). Её
 * кладут в файл состояния рядом с заявленной (pool.c, hy2main.c), и расхождение видно человеку.
 *
 * ТОЛЬКО ПО СОБЫТИЮ. Проверка — один запрос на подъём и на смену узла, не опрос: каждый запрос — это
 * ещё и трафик через узел, а страна узла между сменами не меняется.
 *
 * ЦЕЛИ. Первая — 1.1.1.1 по адресу, без DNS (имя «one.one.one.one» только для SNI и сертификата, как
 * у модуля WARP). Запасная — www.cloudflare.com: адрес разрешается обычным путём, поэтому она
 * последняя — в ответ на имя может прийти fake-IP, и тогда проверка честно скажет «нет».
 * HTTPS — wbhttps.c (TLS 1.3 libsteer, тот же клиент, что у проверок WARP). */
#include <stdio.h>
#include <string.h>

#include "geo.h"
#include "wbhttps.h"

/* Значение поля «ключ=значение» ответа trace. */
static int trace_field(const char *body, const char *key, char *dst, size_t n) {
    size_t kl = strlen(key);
    for (const char *l = body; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL)
        if (!strncmp(l, key, kl) && l[kl] == '=') {
            snprintf(dst, n, "%.*s", (int)strcspn(l + kl + 1, "\r\n"), l + kl + 1);
            return 0;
        }
    return -1;
}

int geo_trace(const char *dev, char cc[3], char *why, size_t wn) {
    static const struct { const char *host, *addr; } T[] = {
        { "one.one.one.one", "1.1.1.1" },
        { "www.cloudflare.com", NULL },
    };
    const struct wb_route rt = { .dev = dev };
    why[0] = '\0';
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
        struct wb_req q = { .host = T[i].host, .addr = T[i].addr, .method = "GET",
                            .path = "/cdn-cgi/trace", .timeout_ms = 8000 };
        struct wb_resp r;
        char w[160];
        if (wb_https(&q, &rt, &r, w, sizeof(w)) != 0) {
            snprintf(why, wn, "%s: %s", T[i].host, w);
            continue;
        }
        char loc[16] = "";
        int ok = r.status == 200 && r.body && trace_field(r.body, "loc", loc, sizeof(loc)) == 0 &&
                 loc[0] >= 'A' && loc[0] <= 'Z' && loc[1] >= 'A' && loc[1] <= 'Z' && !loc[2];
        if (!ok) snprintf(why, wn, "%s: ответ %d без страны", T[i].host, r.status);
        wb_resp_free(&r);
        if (ok) {
            cc[0] = loc[0];
            cc[1] = loc[1];
            cc[2] = '\0';
            return 0;
        }
    }
    return -1;
}
