/* Регистрация устройства WARP (steer-warpbox; WARPBOX.md в хабе, раздел «Модуль», п. 1).
 *
 * КАК. Ключ X25519 — здесь, на роутере (xc_x25519_keypair): закрытый ключ никуда не уходит. POST
 * `/<версия>/reg` с открытым ключом даёт id, token, ключ пира и адреса туннеля, но устройство
 * приходит выключенным (warp_enabled=false): рукопожатие идёт, а данные Cloudflare молча
 * отбрасывает — так ломается регистрация без второго шага (разбор brb). Второй шаг — PATCH
 * `/<версия>/reg/<id>` с Bearer token и {"warp_enabled":true}; проверено 2026-10-12 с машины
 * разработки: 200 и warp_enabled=true, после чего туннель несёт данные.
 *
 * КУДА. Сначала прямой API (несколько версий пути — Cloudflare отключает старые), затем реле
 * (решение владельца: прямой API, реле запасом). Хост, не давший даже соединения, в этом проходе
 * больше не пробуется. Последний запас — готовая регистрация santa-atmo.ru: там ключ создаёт чужой
 * сервер, поэтому только когда ни прямой путь, ни реле не прошли.
 *
 * ЛИШНИХ РЕГИСТРАЦИЙ НЕ ПЛОДИТЬ: удалить устройство нельзя, оно остаётся у Cloudflare навсегда.
 * Регистрация кэшируется файлом (wb_reg_save) и делается заново только по решению сторожа
 * (смена ключей после повторных неудач). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "reality.h"
#include "wbhttps.h"
#include "wbjson.h"
#include "wbreg.h"

#define CF_UA  "okhttp/3.12.1"
#define CF_VER "a-6.11-2223"

static const struct { const char *host, *path; } REG_HOSTS[] = {
    { "api.cloudflareclient.com", "/v0a4005/reg" },
    { "api.cloudflareclient.com", "/v0i1909051800/reg" },
    { "api.cloudflareclient.com", "/v0a2158/reg" },
    { "api.cloudflareclient.com", "/v0a1922/reg" },
    { "edge-client-api.vercel.app", "/v0a4005/reg" },
};

static void b64(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (i + 1 < n ? (unsigned)in[i + 1] << 8 : 0) |
                     (i + 2 < n ? in[i + 2] : 0);
        out[o++] = T[v >> 18 & 63];
        out[o++] = T[v >> 12 & 63];
        out[o++] = i + 1 < n ? T[v >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? T[v & 63] : '=';
    }
    out[o] = '\0';
}

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

/* Поля ответа регистрации: у прямого API — внутри result, у реле — бывает и без него. */
static int reg_fields(const char *doc, struct wb_reg *r) {
    char pfx[16] = "result.";
    char tmp[16];
    if (wb_json_get(doc, "result.id", tmp, sizeof(tmp)) != 0) pfx[0] = '\0';
    char path[96];
#define F(field, dst) (snprintf(path, sizeof(path), "%s" field, pfx), wb_json_get(doc, path, dst, sizeof(dst)))
    if (F("id", r->id) || F("token", r->token) || F("config.peers.0.public_key", r->peer_pub) ||
        F("config.interface.addresses.v4", r->v4))
        return -1;
    F("config.interface.addresses.v6", r->v6);
    F("config.client_id", r->client_id);
#undef F
    return 0;
}

static int enable(const char *host, const char *path, struct wb_reg *r, char *why, size_t wn) {
    char p[160], hdr[400];
    snprintf(p, sizeof(p), "%s/%s", path, r->id);
    snprintf(hdr, sizeof(hdr), "User-Agent: " CF_UA "\r\nCF-Client-Version: " CF_VER "\r\n"
             "Authorization: Bearer %s\r\n", r->token);
    static const char body[] = "{\"warp_enabled\":true}";
    struct wb_req q = { .host = host, .method = "PATCH", .path = p, .headers = hdr, .body = body,
                        .body_n = sizeof(body) - 1, .timeout_ms = 25000 };
    struct wb_resp res;
    if (wb_https(&q, NULL, &res, why, wn) != 0) return -1;
    char en[8] = "";
    int ok = res.status / 100 == 2 &&
             (wb_json_get(res.body, "result.warp_enabled", en, sizeof(en)) == 0 ||
              wb_json_get(res.body, "warp_enabled", en, sizeof(en)) == 0) && !strcmp(en, "true");
    if (!ok) snprintf(why, wn, "%s: включение устройства — ответ %d, warp_enabled=%s", host, res.status, en[0] ? en : "?");
    wb_resp_free(&res);
    return ok ? 0 : -1;
}

/* Готовая регистрация santa-atmo.ru: ключ создал чужой сервер — только последним запасом. */
static int reg_ready(struct wb_reg *r, char *why, size_t wn) {
    struct wb_req q = { .host = "santa-atmo.ru", .method = "GET", .path = "/warp/warp.php", .timeout_ms = 30000 };
    struct wb_resp res;
    if (wb_https(&q, NULL, &res, why, wn) != 0) return -1;
    char en[8] = "";
    int ok = res.status == 200 && wb_json_get(res.body, "result.key", r->priv, sizeof(r->priv)) == 0 &&
             wb_json_get(res.body, "result.config.peers.0.public_key", r->peer_pub, sizeof(r->peer_pub)) == 0 &&
             wb_json_get(res.body, "result.config.interface.addresses.v4", r->v4, sizeof(r->v4)) == 0 &&
             wb_json_get(res.body, "result.warp_enabled", en, sizeof(en)) == 0 && !strcmp(en, "true");
    if (ok) {
        wb_json_get(res.body, "result.config.interface.addresses.v6", r->v6, sizeof(r->v6));
        snprintf(r->api, sizeof(r->api), "santa-atmo.ru");
        r->id[0] = r->token[0] = '\0';
    } else {
        snprintf(why, wn, "santa-atmo.ru: ответ %d без готовой включённой регистрации", res.status);
        wipe(r->priv, sizeof(r->priv));
    }
    wb_resp_free(&res);
    return ok ? 0 : -1;
}

int wb_register(struct wb_reg *r, char *why, size_t wn) {
    memset(r, 0, sizeof(*r));
    unsigned char priv[32], pub[32];
    if (xc_x25519_keypair(priv, pub) != 0) { snprintf(why, wn, "ключ X25519 не создался"); return -1; }
    b64(priv, 32, r->priv);
    b64(pub, 32, r->pub);
    wipe(priv, sizeof(priv));
    char tos[40];
    time_t now = time(NULL);
    strftime(tos, sizeof(tos), "%Y-%m-%dT%H:%M:%S.000Z", gmtime(&now));
    char body[400];
    int bn = snprintf(body, sizeof(body),
                      "{\"key\":\"%s\",\"install_id\":\"\",\"fcm_token\":\"\",\"tos\":\"%s\","
                      "\"model\":\"PC\",\"type\":\"Android\",\"locale\":\"en_US\"}", r->pub, tos);
    char dead[sizeof(REG_HOSTS) / sizeof(REG_HOSTS[0])] = { 0 };
    char last[256] = "";
    for (size_t i = 0; i < sizeof(REG_HOSTS) / sizeof(REG_HOSTS[0]); i++) {
        if (dead[i]) continue;
        struct wb_req q = { .host = REG_HOSTS[i].host, .method = "POST", .path = REG_HOSTS[i].path,
                            .headers = "User-Agent: " CF_UA "\r\nCF-Client-Version: " CF_VER "\r\n",
                            .body = body, .body_n = (size_t)bn, .timeout_ms = 25000 };
        struct wb_resp res;
        if (wb_https(&q, NULL, &res, last, sizeof(last)) != 0) {
            fprintf(stderr, "steer-warpbox: регистрация %s%s: %s\n", REG_HOSTS[i].host, REG_HOSTS[i].path, last);
            /* Хост не ответил вовсе — остальные пути того же хоста в этом проходе не пробуем. */
            for (size_t k = i; k < sizeof(REG_HOSTS) / sizeof(REG_HOSTS[0]); k++)
                if (!strcmp(REG_HOSTS[k].host, REG_HOSTS[i].host)) dead[k] = 1;
            continue;
        }
        int ok = res.status / 100 == 2 && reg_fields(res.body, r) == 0;
        if (!ok) {
            snprintf(last, sizeof(last), "%s%s: ответ %d", REG_HOSTS[i].host, REG_HOSTS[i].path, res.status);
            fprintf(stderr, "steer-warpbox: регистрация %s\n", last);
        }
        wb_resp_free(&res);
        if (!ok) continue;
        if (enable(REG_HOSTS[i].host, REG_HOSTS[i].path, r, last, sizeof(last)) != 0) {
            fprintf(stderr, "steer-warpbox: регистрация %s\n", last);
            continue;
        }
        snprintf(r->api, sizeof(r->api), "%s%s", REG_HOSTS[i].host, REG_HOSTS[i].path);
        return 0;
    }
    char priv_keep[sizeof(r->priv)];
    memcpy(priv_keep, r->priv, sizeof(priv_keep));
    if (reg_ready(r, why, wn) == 0) { wipe(priv_keep, sizeof(priv_keep)); return 0; }
    wipe(priv_keep, sizeof(priv_keep));
    if (last[0]) snprintf(why, wn, "%s", last);
    wipe(r->priv, sizeof(r->priv));
    return -1;
}

/* ---- кэш регистрации: «ключ=значение» по строке, права 0600, запись заменой ---------------- */

static const struct { const char *k; size_t off, n; } FIELDS[] = {
#define FL(name) { #name, offsetof(struct wb_reg, name), sizeof(((struct wb_reg *)0)->name) }
    FL(id), FL(token), FL(priv), FL(pub), FL(peer_pub), FL(v4), FL(v6), FL(client_id), FL(api),
#undef FL
};

int wb_reg_save(const char *path, const struct wb_reg *r) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }
    for (size_t i = 0; i < sizeof(FIELDS) / sizeof(FIELDS[0]); i++)
        fprintf(f, "%s=%s\n", FIELDS[i].k, (const char *)r + FIELDS[i].off);
    int bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    bad |= fclose(f) != 0;
    if (bad || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int wb_reg_load(const char *path, struct wb_reg *r) {
    memset(r, 0, sizeof(*r));
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        for (size_t i = 0; i < sizeof(FIELDS) / sizeof(FIELDS[0]); i++)
            if (!strcmp(line, FIELDS[i].k))
                snprintf((char *)r + FIELDS[i].off, FIELDS[i].n, "%s", eq + 1);
    }
    wipe(line, sizeof(line));
    fclose(f);
    return r->priv[0] && r->peer_pub[0] && r->v4[0] ? 0 : -1;
}

void wb_reg_wipe(struct wb_reg *r) { wipe(r, sizeof(*r)); }
