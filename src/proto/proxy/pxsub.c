/* Узлы steer-proxy: ссылки trojan://, ss://, socks*://, http(s)://, vmess:// и подписка из них
 * (proxy.h). Ни сети, ни криптографии — ключи ss и vmess выводит дайлер при подключении (pxwire.c),
 * здесь только форма. Общие поля транспорта и безопасности — через sublink.h, как у vless.
 *
 * Эталоны форматов: trojan-gfw/trojan (ссылка trojan://), Shadowsocks SIP002 (ss://), v2rayN
 * (vmess:// — base64 от JSON), стандартные socks://, http:// с userinfo. Чужие ссылки и узлы
 * считаются (foreign) и не мешают: подписка бывает общая. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "proxy.h"
#include "pxwire.h"

const char *px_proto_name(enum px_proto p) {
    switch (p) {
    case PX_TROJAN: return "trojan";
    case PX_SS:     return "shadowsocks";
    case PX_SOCKS:  return "socks";
    case PX_HTTP:   return "http";
    case PX_VMESS:  return "vmess";
    }
    return "";
}

enum px_proto px_proto_by_name(const char *s) {
    if (!strcmp(s, "trojan")) return PX_TROJAN;
    if (!strcmp(s, "shadowsocks") || !strcmp(s, "ss")) return PX_SS;
    if (!strcmp(s, "socks")) return PX_SOCKS;
    if (!strcmp(s, "http")) return PX_HTTP;
    if (!strcmp(s, "vmess")) return PX_VMESS;
    return 0;
}

/* ---- мелочи ---------------------------------------------------------------------------------- */

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Разобрать host[:port] (host — имя, IPv4 или [IPv6]) в узел; порт обязателен и в 1..65535. 0 —
 * ок, -1 — нет. */
static int set_hostport(struct vless_node *n, const char *s, size_t len) {
    char buf[256];
    if (len >= sizeof(buf)) return -1;
    memcpy(buf, s, len);
    buf[len] = '\0';
    char *colon;
    if (buf[0] == '[') {
        char *rb = strchr(buf, ']');
        if (!rb || rb[1] != ':') return -1;
        *rb = '\0';
        sl_set_field(n->host, sizeof(n->host), buf + 1, strlen(buf + 1));
        colon = rb + 1;
    } else {
        colon = strrchr(buf, ':');
        if (!colon) return -1;
        *colon = '\0';
        sl_set_field(n->host, sizeof(n->host), buf, strlen(buf));
    }
    n->port = sl_port_of(colon + 1);
    return (n->host[0] && n->port) ? 0 : -1;
}

/* Разобрать параметры запроса (?a=b&c=d) ссылки: поля транспорта/безопасности (sl_link_param) плюс
 * свой обработчик own. Возвращает указатель на '#' или конец. */
static const char *parse_query(struct px_node *n, const char *q, const char *end,
                               int (*own)(struct px_node *, const char *, size_t, const char *, size_t)) {
    const char *hash = memchr(q, '#', (size_t)(end - q));
    const char *qe = hash ? hash : end;
    const char *k = q;
    while (k < qe) {
        const char *amp = memchr(k, '&', (size_t)(qe - k));
        const char *stop = amp ? amp : qe;
        const char *eq = memchr(k, '=', (size_t)(stop - k));
        if (eq) {
            size_t klen = (size_t)(eq - k), vlen = (size_t)(stop - eq - 1);
            const char *v = eq + 1;
            if (!own || !own(n, k, klen, v, vlen))
                sl_link_param(&n->vn, k, klen, v, vlen);
        }
        if (!amp) break;
        k = amp + 1;
    }
    return hash;
}

/* userinfo (до '@') процентно-раскодированным в dst. secret — начало userinfo, secret_n — длина. */
static void set_secret(char *dst, size_t cap, const char *s, size_t n) {
    char tmp[PX_PASS_MAX * 3];
    if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    sl_pct_decode(tmp);
    sl_set_field(dst, cap, tmp, strlen(tmp));
}

/* ---- trojan ---------------------------------------------------------------------------------- */

static int trojan_parse(const char *url, struct px_node *n) {
    /* Та же форма, что vless://: секрет@хост:порт?параметры#имя, те же поля транспорта. Пароль —
     * весь userinfo (в поле vn.uuid кладёт sl_link_parse; копируем в pass процентно-раскодированным). */
    const char *secret = NULL;
    size_t secret_n = 0;
    int rc = sl_link_parse(url, "trojan://", &n->vn, NULL, &secret, &secret_n);
    if (rc) return rc;
    n->proto = PX_TROJAN;
    set_secret(n->pass, sizeof(n->pass), secret, secret_n);
    sl_set_field(n->name, sizeof(n->name), n->vn.name, strlen(n->vn.name));
    if (sl_link_usable_pre(&n->vn)) { goto skip; }
    if (!n->pass[0]) { snprintf(n->vn.skip_reason, sizeof(n->vn.skip_reason), "trojan без пароля"); goto skip; }
    /* trojan не бывает голым (security=none): это TLS или Reality с паролем вместо UUID. */
    if (!strcmp(n->vn.security, "none")) {
        snprintf(n->vn.skip_reason, sizeof(n->vn.skip_reason), "trojan без TLS не бывает");
        goto skip;
    }
    if (sl_link_usable_post(&n->vn)) goto skip;
    return 0;
skip:
    snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", n->vn.skip_reason);
    return 1;
}

/* ---- shadowsocks (SIP002) -------------------------------------------------------------------- */

static enum ss_method ss_method_by_name(const char *m) {
    if (!strcasecmp(m, "aes-128-gcm")) return SS_AES128_GCM;
    if (!strcasecmp(m, "aes-256-gcm")) return SS_AES256_GCM;
    if (!strcasecmp(m, "chacha20-ietf-poly1305") || !strcasecmp(m, "chacha20-poly1305")) return SS_CHACHA20_POLY1305;
    if (!strcasecmp(m, "2022-blake3-aes-128-gcm")) return SS_2022_AES128;
    if (!strcasecmp(m, "2022-blake3-aes-256-gcm")) return SS_2022_AES256;
    if (!strcasecmp(m, "2022-blake3-chacha20-poly1305")) return SS_2022_CHACHA20;
    if (!strcasecmp(m, "none") || !strcasecmp(m, "plain")) return SS_NONE;
    return (enum ss_method)-1;
}

/* Имя метода для вывода (proxy-nodes, поле method): каноническое, как в ss:// и sing-box, — у
 * «chacha20-poly1305» это «chacha20-ietf-poly1305», у «plain» — «none». */
const char *px_ss_method_name(enum ss_method m) {
    switch (m) {
    case SS_NONE:              return "none";
    case SS_AES128_GCM:        return "aes-128-gcm";
    case SS_AES256_GCM:        return "aes-256-gcm";
    case SS_CHACHA20_POLY1305: return "chacha20-ietf-poly1305";
    case SS_2022_AES128:       return "2022-blake3-aes-128-gcm";
    case SS_2022_AES256:       return "2022-blake3-aes-256-gcm";
    case SS_2022_CHACHA20:     return "2022-blake3-chacha20-poly1305";
    }
    return "";
}

static size_t ss_keylen(enum ss_method m) {
    switch (m) {
    case SS_AES128_GCM: case SS_2022_AES128: return 16;
    case SS_AES256_GCM: case SS_CHACHA20_POLY1305:
    case SS_2022_AES256: case SS_2022_CHACHA20: return 32;
    default: return 0;
    }
}

/* PSK одного уровня base64 → ключ ss_key_n байт. 0 — ок, -1 — не та длина. */
static int ss_psk_decode(const char *b64, size_t blen, unsigned char *out, size_t key_n) {
    char raw[64];
    size_t rn = b64_decode(b64, blen, raw, sizeof(raw));
    if (rn != key_n) return -1;
    memcpy(out, raw, rn);
    return 0;
}

static int ss_parse(const char *url, struct px_node *n) {
    n->proto = PX_SS;
    const char *p = url + 5;             /* после ss:// */
    const char *hash = strchr(p, '#');
    const char *end = hash ? hash : p + strlen(p);
    const char *q = memchr(p, '?', (size_t)(end - p));
    const char *body_end = q ? q : end;
    const char *at = memchr(p, '@', (size_t)(body_end - p));

    char method[64] = "", pass[PX_PASS_MAX] = "";
    const char *hp;                      /* host:port */
    if (at) {
        /* SIP002: userinfo@host:port. userinfo — base64url(method:pass) или method:pass
         * процентно. */
        size_t ulen = (size_t)(at - p);
        char ui[PX_PASS_MAX * 2];
        if (ulen >= sizeof(ui)) return -1;
        memcpy(ui, p, ulen);
        ui[ulen] = '\0';
        if (!memchr(ui, ':', ulen)) {
            /* чистый base64 от "method:pass" */
            char dec[PX_PASS_MAX * 2];
            size_t dn = b64_decode(ui, ulen, dec, sizeof(dec));
            dec[dn < sizeof(dec) ? dn : sizeof(dec) - 1] = '\0';
            memcpy(ui, dec, strlen(dec) + 1);
        } else {
            sl_pct_decode(ui);
        }
        char *colon = strchr(ui, ':');
        if (!colon) return -1;
        *colon = '\0';
        snprintf(method, sizeof(method), "%s", ui);
        snprintf(pass, sizeof(pass), "%s", colon + 1);
        hp = at + 1;
    } else {
        /* Старая форма: ss://base64(method:pass@host:port). */
        char dec[PX_PASS_MAX * 3];
        size_t dn = b64_decode(p, (size_t)(body_end - p), dec, sizeof(dec));
        dec[dn < sizeof(dec) ? dn : sizeof(dec) - 1] = '\0';
        char *a2 = strrchr(dec, '@');    /* «@» бывает в пароле, в хосте — нет */
        char *colon = strchr(dec, ':');
        if (!a2 || !colon || colon > a2) return -1;
        *colon = '\0';
        *a2 = '\0';
        snprintf(method, sizeof(method), "%s", dec);
        snprintf(pass, sizeof(pass), "%s", colon + 1);
        if (set_hostport(&n->vn, a2 + 1, strlen(a2 + 1)) != 0) return -1;
        hp = NULL;
    }
    if (hp && set_hostport(&n->vn, hp, (size_t)(body_end - hp)) != 0) return -1;
    if (hash) sl_set_name(n->vn.name, sizeof(n->vn.name), hash + 1);
    sl_set_field(n->name, sizeof(n->name), n->vn.name, strlen(n->vn.name));
    /* shadowsocks без TLS: голый tcp (шифрует сам дайлер). */
    snprintf(n->vn.type, sizeof(n->vn.type), "tcp");
    snprintf(n->vn.security, sizeof(n->vn.security), "none");

    n->ss_method = ss_method_by_name(method);
    if ((int)n->ss_method < 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "метод %.40s не поддержан", method);
        return 1;
    }
    /* plugin — не поддержан: обфускаторы ss (v2ray-plugin, obfs) — отдельная связка, которой у нас
     * нет, и молчаливое игнорирование увело бы на сервер, ждущий плагин. */
    if (q) {
        for (const char *s = q; s + 7 <= end; s++)
            if (!strncmp(s, "plugin=", 7) && s[7] != '&' && s[7] != '\0') {
                snprintf(n->skip_reason, sizeof(n->skip_reason), "plugin= не поддержан");
                return 1;
            }
    }
    size_t kl = ss_keylen(n->ss_method);
    n->ss_key_n = kl;
    if (n->ss_method >= SS_2022_AES128) {
        /* 2022: пароль — base64 PSK, либо iPSK:uPSK (многопользовательский, реле на один уровень). */
        char *colon = strchr(pass, ':');
        if (colon) {
            *colon = '\0';
            if (ss_psk_decode(pass, strlen(pass), n->ss_ipsk, kl) != 0 ||
                ss_psk_decode(colon + 1, strlen(colon + 1), n->ss_key, kl) != 0) {
                snprintf(n->skip_reason, sizeof(n->skip_reason), "2022 PSK не той длины");
                return 1;
            }
            n->ss_ipsk_n = kl;
            if (strchr(colon + 1, ':')) {
                snprintf(n->skip_reason, sizeof(n->skip_reason), "2022: реле глубже одного не поддержано");
                return 1;
            }
        } else if (ss_psk_decode(pass, strlen(pass), n->ss_key, kl) != 0) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "2022 PSK не той длины (нужно base64 %zu байт)", kl);
            return 1;
        }
    } else if (n->ss_method != SS_NONE) {
        snprintf(n->pass, sizeof(n->pass), "%s", pass);   /* ключ выведет дайлер (pxwire) */
        if (!pass[0]) { snprintf(n->skip_reason, sizeof(n->skip_reason), "shadowsocks без пароля"); return 1; }
    }
    if (sl_host_leads_nowhere(n->vn.host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->vn.host);
        return 1;
    }
    return 0;
}

/* ---- socks ----------------------------------------------------------------------------------- */

static int socks_parse(const char *url, struct px_node *n, int ver) {
    n->proto = PX_SOCKS;
    n->socks_ver = (uint8_t)ver;
    const char *p = strstr(url, "://");
    if (!p) return -1;
    p += 3;
    const char *hash = strchr(p, '#');
    const char *end = hash ? hash : p + strlen(p);
    const char *q = memchr(p, '?', (size_t)(end - p));
    const char *body_end = q ? q : end;
    const char *at = memchr(p, '@', (size_t)(body_end - p));
    if (at) {
        char ui[PX_PASS_MAX * 2];
        size_t ul = (size_t)(at - p);
        if (ul >= sizeof(ui)) return -1;
        memcpy(ui, p, ul); ui[ul] = '\0';
        sl_pct_decode(ui);
        char *colon = strchr(ui, ':');
        if (colon) { *colon = '\0'; snprintf(n->pass, sizeof(n->pass), "%s", colon + 1); }
        snprintf(n->user, sizeof(n->user), "%s", ui);
        p = at + 1;
    }
    if (set_hostport(&n->vn, p, (size_t)(body_end - p)) != 0) return -1;
    if (hash) sl_set_name(n->vn.name, sizeof(n->vn.name), hash + 1);
    sl_set_field(n->name, sizeof(n->name), n->vn.name, strlen(n->vn.name));
    snprintf(n->vn.type, sizeof(n->vn.type), "tcp");
    snprintf(n->vn.security, sizeof(n->vn.security), "none");
    if (ver == 5 && n->user[0] && !n->pass[0]) {
        /* socks5 с именем без пароля — законно (user/pass auth с пустым паролем бывает), но
         * socks4 пароля не знает вовсе. */
    }
    if (ver != 5 && n->user[0] && n->pass[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "socks4 не знает пароля");
        return 1;
    }
    if (sl_host_leads_nowhere(n->vn.host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->vn.host);
        return 1;
    }
    return 0;
}

/* ---- http CONNECT ---------------------------------------------------------------------------- */

static int http_parse(const char *url, struct px_node *n, int tls) {
    n->proto = PX_HTTP;
    const char *p = strstr(url, "://");
    if (!p) return -1;
    p += 3;
    const char *hash = strchr(p, '#');
    const char *end = hash ? hash : p + strlen(p);
    const char *slash = memchr(p, '/', (size_t)(end - p));
    const char *q = memchr(p, '?', (size_t)((slash ? slash : end) - p));
    const char *body_end = q ? q : slash ? slash : end;
    const char *at = memchr(p, '@', (size_t)(body_end - p));
    if (at) {
        char ui[PX_PASS_MAX * 2];
        size_t ul = (size_t)(at - p);
        if (ul >= sizeof(ui)) return -1;
        memcpy(ui, p, ul); ui[ul] = '\0';
        sl_pct_decode(ui);
        char *colon = strchr(ui, ':');
        if (colon) { *colon = '\0'; snprintf(n->pass, sizeof(n->pass), "%s", colon + 1); }
        snprintf(n->user, sizeof(n->user), "%s", ui);
        p = at + 1;
    }
    if (set_hostport(&n->vn, p, (size_t)(body_end - p)) != 0) return -1;
    /* Параметры (?sni=, ?type=, ?security=…) — для https поверх ws/grpc и проверки сертификата. */
    if (q) parse_query(n, q + 1, hash ? hash : end, NULL);
    if (hash) sl_set_name(n->vn.name, sizeof(n->vn.name), hash + 1);
    sl_set_field(n->name, sizeof(n->name), n->vn.name, strlen(n->vn.name));
    snprintf(n->vn.type, sizeof(n->vn.type), "%s", n->vn.type[0] ? n->vn.type : "tcp");
    snprintf(n->vn.security, sizeof(n->vn.security), tls ? "tls" : "none");
    if (tls && !n->vn.sni[0] && sl_host_is_name(n->vn.host))
        sl_set_field(n->vn.sni, sizeof(n->vn.sni), n->vn.host, strlen(n->vn.host));
    if (sl_host_leads_nowhere(n->vn.host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->vn.host);
        return 1;
    }
    /* https — обе половины общей годности, как у trojan и vmess. Прежде здесь была одна вторая, и
     * allowInsecure подписки (первая половина, sl_link_usable_pre) у https не решал ничего: узел
     * оставался в перечне при любом insecure выхода, а его номер не зависел от ключа, от которого
     * у trojan и vmess зависит. Теперь он, как у них, пригоден только при insecure (ключ выхода либо
     * `--insecure` по файлу), а иначе пропущен с причиной. Адрес без sni отбраковывает вторая
     * половина («tls по адресу без sni: нечем сверить»). */
    if (tls) {
        if (sl_link_usable_pre(&n->vn) || sl_link_usable_post(&n->vn)) {
            snprintf(n->skip_reason, sizeof n->skip_reason, "%s", n->vn.skip_reason);
            return 1;
        }
    }
    return 0;
}

/* ---- vmess (v2rayN base64 JSON) -------------------------------------------------------------- */

/* Плоский JSON-объект: значение ключа key в строку out (строки и числа). 1 — нашли. */
static int vj_get(const char *json, const char *key, char *out, size_t cap) {
    char pat[48];
    int kl = snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pat))) {
        const char *c = p + kl;
        while (*c == ' ' || *c == '\t') c++;
        if (*c != ':') { p += kl; continue; }
        c++;
        while (*c == ' ' || *c == '\t') c++;
        size_t o = 0;
        if (*c == '"') {
            c++;
            /* Экранирование раскрывается (sl_unescape): v2rayN на Windows пишет ps как \uXXXX с
             * суррогатной парой для эмодзи. Знак, которому не хватило места, не пишется. */
            while (*c && *c != '"') {
                char e[4] = { *c, 0, 0, 0 };
                size_t el = 1;
                if (*c == '\\' && c[1]) c += sl_unescape(c + 1, 0, e, &el);
                c++;
                if (o + el >= cap) break;
                memcpy(out + o, e, el);
                o += el;
            }
        } else {
            while (*c && *c != ',' && *c != '}' && *c != ' ' && o + 1 < cap) out[o++] = *c++;
        }
        out[o] = '\0';
        return 1;
    }
    out[0] = '\0';
    return 0;
}

/* Шифр тела vmess для вывода (proxy-nodes, поле cipher): как в scy ссылки. none и zero узлом не
 * бывают — такой узел непригоден (vmess_parse). */
const char *px_vmess_sec_name(enum vmess_sec v) {
    switch (v) {
    case VMESS_AUTO:              return "auto";
    case VMESS_AES128_GCM:        return "aes-128-gcm";
    case VMESS_CHACHA20_POLY1305: return "chacha20-poly1305";
    case VMESS_NONE:              return "none";
    case VMESS_ZERO:              return "zero";
    }
    return "";
}

static int vmess_parse(const char *url, struct px_node *n) {
    n->proto = PX_VMESS;
    const char *b = url + 8;             /* после vmess:// */
    char json[4096];
    size_t jn = b64_decode(b, strlen(b), json, sizeof(json));
    json[jn < sizeof(json) ? jn : sizeof(json) - 1] = '\0';
    if (json[0] != '{') return -1;
    char v[256];
    vj_get(json, "add", n->vn.host, sizeof(n->vn.host));
    if (vj_get(json, "port", v, sizeof(v))) n->vn.port = sl_port_of(v);
    vj_get(json, "id", v, sizeof(v));
    if (sl_uuid_parse(v, n->vmess_id) != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vmess id не UUID");
        return 1;
    }
    n->vmess_aid = vj_get(json, "aid", v, sizeof(v)) ? atoi(v) : 0;
    char scy[32] = "auto";
    vj_get(json, "scy", scy, sizeof(scy));
    if (!strcasecmp(scy, "auto") || !scy[0]) n->vmess_sec = VMESS_AUTO;
    else if (!strcasecmp(scy, "aes-128-gcm")) n->vmess_sec = VMESS_AES128_GCM;
    else if (!strcasecmp(scy, "chacha20-poly1305")) n->vmess_sec = VMESS_CHACHA20_POLY1305;
    else if (!strcasecmp(scy, "none") || !strcasecmp(scy, "zero")) {
        /* none и zero (тело без AEAD) не поддержаны: podkop/коннектор их не выдаёт, а без шифра тела
         * у vmess нет и проверки — отдельный путь без выигрыша (docs/proxy.md). */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vmess scy=%.20s не поддержан (нужен aes-128-gcm или chacha20-poly1305)", scy);
        return 1;
    }
    else { snprintf(n->skip_reason, sizeof(n->skip_reason), "vmess scy=%.20s не поддержан", scy); return 1; }
    /* Транспорт: net → type; у ws/httpupgrade host→Host, path; grpc serviceName=path. */
    char net[16] = "tcp";
    vj_get(json, "net", net, sizeof(net));
    if (!strcmp(net, "h2")) snprintf(n->vn.type, sizeof(n->vn.type), "xhttp");   /* h2 ≈ xhttp stream */
    else snprintf(n->vn.type, sizeof(n->vn.type), "%s", net);
    /* type у v2rayN — вид маскировки tcp: «http» — HTTP-заголовок, которого клиент не шлёт
     * (как headerType=http у vless; sl_link_usable_pre называет причину). */
    char htype[16] = "";
    vj_get(json, "type", htype, sizeof(htype));
    if (!strcmp(htype, "http")) n->vn.tcp_http = 1;
    vj_get(json, "path", n->vn.path, sizeof(n->vn.path));
    vj_get(json, "host", n->vn.http_host, sizeof(n->vn.http_host));
    if (!strcmp(net, "grpc")) sl_set_field(n->vn.service, sizeof(n->vn.service), n->vn.path, strlen(n->vn.path));
    char tls[16] = "";
    vj_get(json, "tls", tls, sizeof(tls));
    snprintf(n->vn.security, sizeof(n->vn.security), !strcasecmp(tls, "tls") ? "tls" : "none");
    vj_get(json, "sni", n->vn.sni, sizeof(n->vn.sni));
    vj_get(json, "fp", n->vn.fp, sizeof(n->vn.fp));
    vj_get(json, "ps", n->vn.name, sizeof(n->vn.name));
    sl_set_field(n->name, sizeof(n->name), n->vn.name, strlen(n->vn.name));
    if (!n->vn.port) { snprintf(n->skip_reason, sizeof(n->skip_reason), "vmess без порта"); return 1; }
    if (n->vmess_aid != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vmess alterId=%d: только 0 (AEAD)", n->vmess_aid);
        return 1;
    }
    if (!strcmp(n->vn.security, "tls") && !n->vn.sni[0] && sl_host_is_name(n->vn.host))
        sl_set_field(n->vn.sni, sizeof(n->vn.sni), n->vn.host, strlen(n->vn.host));
    if (!strcmp(n->vn.security, "tls")) { n->vn.insecure = vless_insecure(); }
    if (sl_host_leads_nowhere(n->vn.host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->vn.host);
        return 1;
    }
    if (sl_link_usable_pre(&n->vn) || sl_link_usable_post(&n->vn)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", n->vn.skip_reason);
        return 1;
    }
    return 0;
}

/* ---- одна ссылка ---------------------------------------------------------------------------- */

int px_parse_url(const char *url, struct px_node *n, enum px_proto want) {
    memset(n, 0, sizeof(*n));
    int rc = -1;
    if (!strncmp(url, "trojan://", 9)) rc = trojan_parse(url, n);
    else if (!strncmp(url, "ss://", 5)) rc = ss_parse(url, n);
    else if (!strncmp(url, "socks5://", 9) || !strncmp(url, "socks://", 8)) rc = socks_parse(url, n, 5);
    else if (!strncmp(url, "socks4a://", 10)) rc = socks_parse(url, n, 4);   /* 4a — те же 4 с именем */
    else if (!strncmp(url, "socks4://", 9)) rc = socks_parse(url, n, 4);
    else if (!strncmp(url, "https://", 8)) rc = http_parse(url, n, 1);
    else if (!strncmp(url, "http://", 7)) rc = http_parse(url, n, 0);
    else if (!strncmp(url, "vmess://", 8)) rc = vmess_parse(url, n);
    else return -1;
    if (rc < 0) return -1;
    if (want && n->proto != want) return -1;
    /* Своей причины нет — берём причину общей половины. Копировать skip_reason в самого себя
     * (snprintf с тем же буфером источником) нельзя: это неопределённое поведение, и glibc
     * на -O2 оставлял пустую строку — все причины пропуска терялись. */
    if (rc > 0 && !n->skip_reason[0])
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", n->vn.skip_reason);
    return rc;
}

/* ---- причины пропуска ----------------------------------------------------------------------- */

void px_skip_note(struct px_sub_stats *st, const struct px_node *n, const char *reason) {
    if (!st) return;
    st->skipped++;
    for (size_t i = 0; i < st->reasons_n; i++)
        if (!strcmp(st->reasons[i].reason, reason)) { st->reasons[i].count++; return; }
    if (st->reasons_n >= PX_SKIP_REASONS) { st->reasons_dropped++; return; }
    struct px_skip *s = &st->reasons[st->reasons_n++];
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
    if (n && n->name[0]) snprintf(s->example, sizeof(s->example), "%s", n->name);
    else if (n && n->vn.host[0]) snprintf(s->example, sizeof(s->example), "%s:%u", n->vn.host, n->vn.port);
    s->count = 1;
}

/* ---- подписка -------------------------------------------------------------------------------- */

size_t px_parse_sub(const char *text, struct px_node *out, size_t max, enum px_proto want,
                    struct px_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    /* Подписка коннектора — список share-ссылок (по одной на файл), по строкам или в base64.
     * Конфиг sing-box целиком коннектор не кладёт: он сам переводит его в спеку и ссылки. */
    while (*p) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '\n' && *e != '\r') e++;
        /* Строка — в куче своей длины: буфер постоянного размера был пределом длины ссылки, а
         * строка длиннее него читалась из неинициализированного буфера. */
        char *line = strndup(p, (size_t)(e - p));
        if (!line) break;
        struct px_node node;
        int rc = px_parse_url(line, &node, want);
        if (rc == 0 && n < max) out[n++] = node;
        else if (rc == 0) px_skip_note(st, &node, "узлов больше, чем помещается");
        else if (rc > 0) px_skip_note(st, &node, node.skip_reason);
        else if (strstr(line, "://") && st) st->foreign++;
        free(line);
        p = e;
    }
    return n;
}

const char *px_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    const char *p = raw;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return raw;
    if (strstr(raw, "://")) return raw;
    b64_decode(raw, raw_n, dec, dec_n);
    return dec;
}

#define PX_SUB_FILE_MAX ((size_t)64 << 20)
struct px_node *px_load_sub(const char *path, enum px_proto want, size_t *cnt,
                            struct px_sub_stats *st) {
    *cnt = 0;
    if (st) memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 0 || (size_t)fl > PX_SUB_FILE_MAX) { fclose(f); return NULL; }
    size_t sz = (size_t)fl;
    char *raw = malloc(sz + 1), *dec = malloc(sz + 16);
    if (!raw || !dec) { fclose(f); free(raw); free(dec); return NULL; }
    size_t rn = fread(raw, 1, sz, f);
    fclose(f);
    raw[rn] = '\0';
    dec[0] = '\0';
    const char *text = px_sub_text(raw, rn, dec, sz + 16);
    size_t hint = 1;
    for (const char *q = text; (q = strstr(q, "://")); q += 3) hint++;
    for (const char *q = text; (q = strstr(q, "\"type\"")); q += 6) hint++;
    struct px_node *nodes = calloc(hint, sizeof(*nodes));
    if (nodes) *cnt = px_parse_sub(text, nodes, hint, want, st);
    free(raw);
    free(dec);
    return nodes;
}
