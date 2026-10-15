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
#include "wbx509.h"
#include "scrypto.h"

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

int wb_b64_decode(const char *in, unsigned char *out, size_t cap) {
    size_t o = 0;
    unsigned v = 0;
    int bits = 0;
    for (const char *p = in; *p && *p != '='; p++) {
        int c = *p;
        int d = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26
              : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' || c == '-' ? 62 : c == '/' || c == '_' ? 63 : -1;
        if (d < 0) return -1;
        v = (v << 6) | (unsigned)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o == cap) return -1;
            out[o++] = (unsigned char)(v >> bits);
        }
    }
    return (int)o;
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
    FL(mq_priv), FL(mq_peer), FL(mq_ep4), FL(mq_ep6),
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

/* ---- MASQUE: ключ P-256 у регистрации (WARPBOX.md в хабе, «Протокол») ---------------------------
 *
 * PATCH /<версия>/reg/<id> с Bearer token и {"key": <SPKI DER base64>, "key_type": "secp256r1",
 * "tunnel_type": "masque"} — версия API и заголовки клиента Android, с которыми это работает у usque
 * (v0a4471, «a-6.35-4471», «WARP for Android»). Ответ — та же учётная запись: ключ сервера (PEM) для
 * сверки в рукопожатии, точка входа (адрес с портом 0 — порт не значим), адреса туннеля. */
#define MQ_PATH "/v0a4471/reg/"
#define MQ_UA   "WARP for Android"
#define MQ_VER  "a-6.35-4471"

/* PEM → base64 тела одной строкой: между «-----BEGIN …-----» и «-----END», только знаки base64.
 * Переводы строк в ответе бывают и настоящими, и буквальными «\\n» (так их оставляет разбор JSON). */
static int pem_body(const char *pem, char *out, size_t n) {
    const char *b = strstr(pem, "-----BEGIN");
    if (!b || !(b = strstr(b + 10, "-----"))) return -1;
    b += 5;
    const char *e = strstr(b, "-----END");
    if (!e) return -1;
    size_t o = 0;
    for (const char *p = b; p < e; p++) {
        if (*p == '\\' && p + 1 < e) { p++; continue; }        /* \n, \r */
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
            *p == '+' || *p == '/' || *p == '=') {
            if (o + 1 >= n) return -1;
            out[o++] = *p;
        }
    }
    out[o] = '\0';
    return o ? 0 : -1;
}

/* «адрес:порт» / «[адрес]:порт» → адрес. */
static void ep_host(const char *ep, char *out, size_t n) {
    if (ep[0] == '[') {
        size_t l = strcspn(ep + 1, "]");
        snprintf(out, n, "%.*s", (int)l, ep + 1);
        return;
    }
    const char *c = strrchr(ep, ':');
    snprintf(out, n, "%.*s", c ? (int)(c - ep) : (int)strlen(ep), ep);
}

/* Вернуть устройству ключ WireGuard (смена transport с masque на awg): включение MASQUE заменило у
 * Cloudflare ключ устройства на P-256, и прежний файл туннеля awg больше не принимается (стенд QEMU
 * 2026-10-12: после смены транспорта туда и обратно туннели awg молчали). PATCH тем же путём, что
 * включение MASQUE, с открытой половиной ключа X25519 регистрации. */
int wb_enroll_wireguard(struct wb_reg *r, char *why, size_t wn) {
    if (!r->id[0] || !r->token[0] || !r->pub[0]) {
        snprintf(why, wn, "у регистрации нет id, token или ключа — ключ WireGuard не вернуть");
        return -1;
    }
    char body[256], path[160], hdr[400];
    int bn = snprintf(body, sizeof(body), "{\"key\":\"%s\",\"key_type\":\"curve25519\",\"tunnel_type\":\"wireguard\"}",
                      r->pub);
    snprintf(path, sizeof(path), MQ_PATH "%s", r->id);
    snprintf(hdr, sizeof(hdr), "User-Agent: " MQ_UA "\r\nCF-Client-Version: " MQ_VER "\r\n"
             "Authorization: Bearer %s\r\n", r->token);
    struct wb_req q = { .host = "api.cloudflareclient.com", .method = "PATCH", .path = path, .headers = hdr,
                        .body = body, .body_n = (size_t)bn, .timeout_ms = 25000 };
    struct wb_resp res;
    if (wb_https(&q, NULL, &res, why, wn) != 0) return -1;
    int ok = res.status / 100 == 2;
    if (!ok) snprintf(why, wn, "возврат ключа WireGuard — ответ %d", res.status);
    wb_resp_free(&res);
    if (!ok) return -1;
    wipe(r->mq_priv, sizeof(r->mq_priv));
    r->mq_peer[0] = r->mq_ep4[0] = r->mq_ep6[0] = '\0';
    return 0;
}

int wb_reg_has_masque(const struct wb_reg *r) {
    return r->mq_priv[0] && r->mq_peer[0] && (r->mq_ep4[0] || r->mq_ep6[0]) && r->v4[0];
}

int wb_enroll_masque(struct wb_reg *r, char *why, size_t wn) {
    if (!r->id[0] || !r->token[0]) {
        snprintf(why, wn, "у регистрации нет id и token (готовая чужая) — MASQUE не включить");
        return -1;
    }
    unsigned char priv[32], pub[65], spki[WB_SPKI_P256];
    if (sc_p256_keygen(priv, pub) != 0) { snprintf(why, wn, "ключ P-256 не создался"); return -1; }
    wb_p256_spki(pub, spki);
    char spki_b64[160], body[320], path[160], hdr[400];
    b64(spki, sizeof(spki), spki_b64);
    int bn = snprintf(body, sizeof(body), "{\"key\":\"%s\",\"key_type\":\"secp256r1\",\"tunnel_type\":\"masque\"}",
                      spki_b64);
    snprintf(path, sizeof(path), MQ_PATH "%s", r->id);
    snprintf(hdr, sizeof(hdr), "User-Agent: " MQ_UA "\r\nCF-Client-Version: " MQ_VER "\r\n"
             "Authorization: Bearer %s\r\n", r->token);
    struct wb_req q = { .host = "api.cloudflareclient.com", .method = "PATCH", .path = path, .headers = hdr,
                        .body = body, .body_n = (size_t)bn, .timeout_ms = 25000 };
    struct wb_resp res;
    int rc = -1;
    if (wb_https(&q, NULL, &res, why, wn) != 0) goto out;
    if (res.status / 100 != 2) {
        char code[16] = "";
        wb_json_get(res.body, "errors.0.code", code, sizeof(code));
        snprintf(why, wn, "включение MASQUE — ответ %d%s%s", res.status, code[0] ? ", код " : "", code);
        wb_resp_free(&res);
        goto out;
    }
    char pfx[16] = "";
    char tmp[16];
    if (wb_json_get(res.body, "result.id", tmp, sizeof(tmp)) == 0) snprintf(pfx, sizeof(pfx), "result.");
    char p2[96], pem[512], ep[96];
    snprintf(p2, sizeof(p2), "%sconfig.peers.0.public_key", pfx);
    int ok = wb_json_get(res.body, p2, pem, sizeof(pem)) == 0 && pem_body(pem, r->mq_peer, sizeof(r->mq_peer)) == 0;
    snprintf(p2, sizeof(p2), "%sconfig.peers.0.endpoint.v4", pfx);
    r->mq_ep4[0] = r->mq_ep6[0] = '\0';
    if (wb_json_get(res.body, p2, ep, sizeof(ep)) == 0) ep_host(ep, r->mq_ep4, sizeof(r->mq_ep4));
    snprintf(p2, sizeof(p2), "%sconfig.peers.0.endpoint.v6", pfx);
    if (wb_json_get(res.body, p2, ep, sizeof(ep)) == 0) ep_host(ep, r->mq_ep6, sizeof(r->mq_ep6));
    snprintf(p2, sizeof(p2), "%sconfig.interface.addresses.v4", pfx);
    wb_json_get(res.body, p2, r->v4, sizeof(r->v4));
    snprintf(p2, sizeof(p2), "%sconfig.interface.addresses.v6", pfx);
    wb_json_get(res.body, p2, r->v6, sizeof(r->v6));
    wb_resp_free(&res);
    if (!ok || (!r->mq_ep4[0] && !r->mq_ep6[0])) {
        snprintf(why, wn, "включение MASQUE: в ответе нет ключа сервера или точки входа");
        r->mq_peer[0] = '\0';
        goto out;
    }
    b64(priv, 32, r->mq_priv);
    rc = 0;
out:
    wipe(priv, sizeof(priv));
    return rc;
}
