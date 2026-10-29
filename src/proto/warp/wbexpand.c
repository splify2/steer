/* Разворот выхода `kind: warp` (wbexpand.h): хук expand вида warp плагина warpbox. */
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "jsonw.h"
#include "pkjson.h"
#include "wbexpand.h"

/* ---- разворот (хук expand вида warp, steer-api.md, 3.3) ---------------------------------------
 *
 * Вход — stdin: {"output":{"name","kind","keys","common"},"spec":{"etc"}}; ключи уже проверены схемой
 * вида (plugins/warpbox/kinds/warp.schema.json). Ответ — stdout:
 *   self    — группа с именем выхода: pick (latency по умолчанию), members «<имя>.<n>», ключи замера
 *             (tolerance, interval — 600 с по умолчанию у latency, url, idle_timeout) и on_fail выхода;
 *   outputs — члены: awg с файлом {etc}/warp/<имя>-<n>.conf или plugin-device (transport: masque),
 *             у каждого ipv6 (nat по умолчанию: адрес IPv6 у регистрации WARP один) и over выхода;
 *   helper  — true: помощник вида ведёт группу.
 * Детерминированно: тот же вход — тот же ответ (ядро кэширует ответ по входу). Отказ — код 2 и строка.
 *
 * Интервал замера по умолчанию — 600 с (апстрим Zapret Manager): туннели WARP меняются редко, и мерить
 * чаще незачем. Допуск — обычное умолчание группы. Один туннель по умолчанию (решение владельца
 * 2026-10-12: «самый быстрый, не держа кучу интерфейсов»); count больше 1 — запасные туннели для
 * мгновенного переключения и разные колонии сразу. */
#define WARP_INT_DEFAULT_S 600

static void put_kv(FILE *f, int *first, const char *k) {
    if (!*first) fputc(',', f);
    *first = 0;
    jsonw_str(f, k);
    fputc(':', f);
}

/* Значение узла JSON как есть (число — записью, строка — в кавычках). */
static void put_val(FILE *f, const struct pkj *v) {
    if (!v) { fputs("null", f); return; }
    switch (v->t) {
    case PKJ_NULL: fputs("null", f); break;
    case PKJ_BOOL: fputs(v->b ? "true" : "false", f); break;
    case PKJ_NUM: fputs(v->s, f); break;
    case PKJ_STR: jsonw_str(f, v->s); break;
    case PKJ_ARR:
        fputc('[', f);
        for (size_t i = 0; i < v->n; i++) { if (i) fputc(',', f); put_val(f, v->v[i]); }
        fputc(']', f);
        break;
    case PKJ_OBJ:
        fputc('{', f);
        for (size_t i = 0; i < v->n; i++) { if (i) fputc(',', f); jsonw_str(f, v->k[i]); fputc(':', f); put_val(f, v->v[i]); }
        fputc('}', f);
        break;
    }
}

int warp_expand(const struct pkj *d, FILE *f) {
    const struct pkj *out = pkj_get(d, "output"), *k = pkj_get(out, "keys"), *cm = pkj_get(out, "common");
    const char *name = pkj_str(pkj_get(out, "name"));
    const char *etc = pkj_str(pkj_path(d, "spec.etc"));
    if (!name || !etc) { fprintf(stderr, "во входе нет output.name или spec.etc\n"); return 2; }
    /* Члены «<имя>.<n>» — имя выхода в сокете не длиннее 31 знака. */
    if (strlen(name) > 27) { fprintf(stderr, "имя для kind: warp — не длиннее 27 знаков (у туннелей «%s.<n>»)\n", name); return 2; }
    const char *tr = pkj_str(pkj_get(k, "transport"));
    int mq = tr && !strcmp(tr, "masque");
    long count = 1;
    pkj_long(pkj_get(k, "count"), &count);
    if (count < 1) { fprintf(stderr, "count — от 1\n"); return 2; }
    /* Страны: и в countries, и в exclude_countries — спор с самим собой. */
    const struct pkj *cc = pkj_get(k, "countries"), *xcc = pkj_get(k, "exclude_countries");
    for (size_t i = 0; i < pkj_len(cc); i++)
        for (size_t j = 0; j < pkj_len(xcc); j++)
            if (!strcasecmp(pkj_str(pkj_at(cc, i)), pkj_str(pkj_at(xcc, j)))) {
                fprintf(stderr, "%s — и в countries, и в exclude_countries\n", pkj_str(pkj_at(cc, i)));
                return 2;
            }
    const char *pick = pkj_str(pkj_get(k, "pick"));
    if (!pick) pick = "latency";
    int lat = !strcmp(pick, "latency");
    if (!lat) {
        static const char *const LAT[] = { "tolerance", "interval", "url", "idle_timeout", NULL };
        for (size_t i = 0; LAT[i]; i++)
            if (pkj_get(k, LAT[i])) { fprintf(stderr, "%s — замер задержки, он есть только у pick: latency\n", LAT[i]); return 2; }
    }
    /* IPv6 членов: у регистрации WARP один адрес /128, и IPv6 клиентов через туннель идёт только с
     * подменой — nat по умолчанию; off — без IPv6. */
    const struct pkj *v6 = pkj_get(cm, "ipv6");
    if (v6 && (!pkj_str(v6) || (strcmp(pkj_str(v6), "nat") && strcmp(pkj_str(v6), "off")))) {
        fprintf(stderr, "ipv6: «%s» — у kind: warp nat или off (адрес IPv6 у WARP один)\n", pkj_str(v6) ? pkj_str(v6) : "?");
        return 2;
    }
    if (pkj_get(cm, "device")) { fprintf(stderr, "device — у kind: warp устройства у туннелей, их имена выбирает ядро steer\n"); return 2; }
    const struct pkj *over = pkj_get(cm, "over"), *onf = pkj_get(cm, "on_fail");
    int first = 1;
    fputs("{\"self\":{", f);
    put_kv(f, &first, "kind"); jsonw_str(f, "group");
    put_kv(f, &first, "pick"); jsonw_str(f, pick);
    static const char *const COPY[] = { "tolerance", "interval", "url", "idle_timeout", NULL };
    for (size_t i = 0; COPY[i]; i++)
        if (pkj_get(k, COPY[i])) { put_kv(f, &first, COPY[i]); put_val(f, pkj_get(k, COPY[i])); }
    if (lat && !pkj_get(k, "interval")) { put_kv(f, &first, "interval"); fprintf(f, "%d", WARP_INT_DEFAULT_S); }
    if (onf) { put_kv(f, &first, "on_fail"); put_val(f, onf); }
    put_kv(f, &first, "members");
    fputc('[', f);
    for (long n = 1; n <= count; n++) {
        char mn[64];
        snprintf(mn, sizeof mn, "%s.%ld", name, n);
        if (n > 1) fputc(',', f);
        jsonw_str(f, mn);
    }
    fputs("]},\"outputs\":{", f);
    for (long n = 1; n <= count; n++) {
        char mn[64], conf[4200];
        snprintf(mn, sizeof mn, "%s.%ld", name, n);
        if (n > 1) fputc(',', f);
        jsonw_str(f, mn);
        fputs(":{", f);
        first = 1;
        put_kv(f, &first, "kind"); jsonw_str(f, mq ? "plugin-device" : "awg");
        if (!mq) {
            snprintf(conf, sizeof conf, "%s/warp/%s-%ld.conf", etc, name, n);
            put_kv(f, &first, "conf"); jsonw_str(f, conf);
        }
        put_kv(f, &first, "ipv6");
        if (v6) put_val(f, v6);
        else jsonw_str(f, "nat");
        if (over) { put_kv(f, &first, "over"); put_val(f, over); }
        fputc('}', f);
    }
    fputs("},\"helper\":true}\n", f);
    return 0;
}

int cmd_warp_expand(void) {
    char err[300];
    struct pkj *d = pkj_load("-", err, sizeof err);
    if (!d) { fprintf(stderr, "вход не разобран: %s\n", err); return 2; }
    int rc = warp_expand(d, stdout);
    pkj_free(d);
    return rc;
}
