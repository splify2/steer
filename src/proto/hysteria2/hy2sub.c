/* Узлы hysteria2: ссылки hysteria2:// и конфиг Xray-core (docs/hysteria2.md, «Формат узла»).
 *
 * ЭТАЛОНЫ. Ссылка — «URI Scheme» документации apernet/hysteria: hysteria2://[auth@]хост[:порт[,порты]]
 * /?sni=&insecure=&pinSHA256=&obfs=salamander&obfs-password=. Ключи up, down, mport и hop-interval
 * в документации эталона нет: их пишут панели и клиенты подписок (v2rayN, NekoBox, Hiddify), и мы
 * читаем их так же — иначе узел с прыжками по портам приходил бы без прыжков и без единой жалобы.
 * Конфиг — Xray-core: outbound protocol «hysteria» (infra/conf/hysteria.go, transport_method.go,
 * transport_finalmask.go, transport_security.go): settings.address/port, streamSettings.
 * hysteriaSettings.auth, tlsSettings.serverName и pinnedPeerCertSha256, finalmask.udp с масками
 * salamander (password) и udphop (remotePorts, interval), finalmask.quicParams.brutalUp/brutalDown.
 * allowInsecure в Xray снят (его конфиг с ним не собирается), поэтому «не проверять сертификат»
 * читаем только у ссылки; у конфига это отпечаток или проверка цепочки.
 *
 * ЧТО ДЕЛАЕМ С ЧУЖИМ. Ссылки других протоколов считаются («foreign») и не мешают: подписка
 * бывает общая, с VLESS и hysteria2 в одном списке. Узел hysteria2, которого мы не потянем
 * (obfs не Salamander, отпечаток негодный), не выбрасывается молча, а идёт в причины пропуска —
 * по тому же приёму, что у подписки VLESS. */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "hy2.h"

/* ---- мелочи ---------------------------------------------------------------------------------- */

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void pct_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && hexv(r[1]) >= 0 && hexv(r[2]) >= 0) {
            *w++ = (char)(hexv(r[1]) * 16 + hexv(r[2]));
            r += 2;
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

/* Отрезать хвост до границы знака UTF-8: строка, обрезанная посреди знака, ломает JSON статуса. */
static void utf8_trim(char *s) {
    size_t n = strlen(s), i = n;
    while (i > 0 && ((unsigned char)s[i - 1] & 0xc0) == 0x80) i--;
    if (i > 0) {
        unsigned char lead = (unsigned char)s[i - 1];
        size_t need = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 1;
        if (n - (i - 1) < need) s[i - 1] = '\0';        /* знак оборван — отрезать целиком */
    }
}

static void set_str(char *dst, size_t cap, const char *src, size_t len) {
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
    utf8_trim(dst);
}

uint64_t hy2_parse_bandwidth(const char *s) {
    while (*s == ' ') s++;
    char *end;
    double v = strtod(s, &end);
    if (end == s || v <= 0) return 0;
    while (*end == ' ') end++;
    double mul = 1000000.0;             /* без единицы — Мбит/с (так пишут ссылки) */
    if (*end) {
        if (!strncasecmp(end, "bps", 3) || !strcasecmp(end, "b")) mul = 1.0;
        else if (!strncasecmp(end, "kbps", 4) || !strcasecmp(end, "k") || !strcasecmp(end, "kb")) mul = 1e3;
        else if (!strncasecmp(end, "mbps", 4) || !strcasecmp(end, "m") || !strcasecmp(end, "mb")) mul = 1e6;
        else if (!strncasecmp(end, "gbps", 4) || !strcasecmp(end, "g") || !strcasecmp(end, "gb")) mul = 1e9;
        else return 0;
    }
    double bps = v * mul / 8.0;
    if (bps > 4e9) bps = 4e9;           /* потолок обёртки QUIC — 2^31 байт/с */
    return (uint64_t)bps;
}

int hy2_parse_ports(const char *s, uint16_t *first, uint16_t *hop, unsigned *hop_n) {
    *hop_n = 0;
    *first = 0;
    unsigned parts = 0, ranges = 0;
    const char *p = s;
    while (*p) {
        char *e;
        long a = strtol(p, &e, 10);
        if (e == p || a < 1 || a > 65535) return -1;
        long b = a;
        if (*e == '-') {
            const char *q = e + 1;
            b = strtol(q, &e, 10);
            if (e == q || b < a || b > 65535) return -1;
        }
        if (*e && *e != ',') return -1;
        if (!parts) *first = (uint16_t)a;
        parts++;
        /* Диапазонов в списке портов — не больше HY2_HOP_RANGES (8): они лежат в самой записи
         * узла и в настройках соединения QUIC (QC_HOP_RANGES), а порт прыжка выбирается по
         * случайному числу из всех. У панелей и эталона — один-два диапазона. -2 — «слишком
         * много», вызывающий называет число. */
        if (ranges >= HY2_HOP_RANGES) return -2;
        hop[2 * ranges] = (uint16_t)a;
        hop[2 * ranges + 1] = (uint16_t)b;
        ranges++;
        p = *e == ',' ? e + 1 : e;
    }
    if (!parts) return -1;
    /* Один порт без диапазона — не прыжки. */
    *hop_n = (parts == 1 && hop[0] == hop[1]) ? 0 : ranges;
    return 0;
}

static int parse_pin(const char *s, uint8_t out[32]) {
    size_t k = 0;
    for (; *s; s++) {
        if (*s == ':') continue;
        int hi = hexv(s[0]), lo = s[1] ? hexv(s[1]) : -1;
        if (hi < 0 || lo < 0 || k >= 32) return -1;
        out[k++] = (uint8_t)(hi * 16 + lo);
        s++;
    }
    return k == 32 ? 0 : -1;
}

static int truthy(const char *v) {
    return !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes");
}

static void finish_name(struct hy2_node *n) {
    if (!n->name[0]) snprintf(n->name, sizeof n->name, "%.100s:%u", n->host, n->port);
    /* SNI по умолчанию — хост, если это имя, а не адрес: сертификат на IP-адрес выпускают редко, и
     * SNI с адресом не разрешён стандартом. */
    if (!n->sni[0] && n->host[0] && !strchr(n->host, ':') && strspn(n->host, "0123456789.") != strlen(n->host))
        snprintf(n->sni, sizeof n->sni, "%s", n->host);
}

/* Итоговая проверка узла: 0 — годен, 1 — негоден (skip_reason). */
static int node_check(struct hy2_node *n) {
    if (!n->host[0] || !n->port) { snprintf(n->skip_reason, sizeof n->skip_reason, "нет адреса или порта"); return 1; }
    if (n->obfs && !n->obfs_pass[0]) {
        snprintf(n->skip_reason, sizeof n->skip_reason, "salamander без пароля");
        return 1;
    }
    /* Эталон (extras/obfs, ErrPSKTooShort) не принимает пароль короче четырёх байт: сервер с таким
     * не запустится, и узел с ним — ошибка панели, а не рабочий узел. */
    if (n->obfs && strlen(n->obfs_pass) < 4) {
        snprintf(n->skip_reason, sizeof n->skip_reason, "пароль salamander короче 4 знаков");
        return 1;
    }
    return 0;
}

/* ---- ссылка ---------------------------------------------------------------------------------- */

static int parse_url_buf(char *buf, struct hy2_node *n);

/* Длина ссылки не ограничена: рабочая копия (её режут разбором на части) — на стеке, если
 * короткая, иначе в куче по длине. Поля узла свои и режутся по ширине. */
int hy2_parse_url(const char *url, struct hy2_node *n) {
    static const char *const schemes[] = { "hysteria2://", "hy2://" };
    size_t sl = 0;
    for (size_t i = 0; i < 2; i++)
        if (!strncasecmp(url, schemes[i], strlen(schemes[i]))) sl = strlen(schemes[i]);
    if (!sl) return -1;
    memset(n, 0, sizeof *n);
    n->hop_s = 30;

    char sbuf[1536];
    size_t ul = strcspn(url + sl, " \t\r\n");
    char *buf = ul < sizeof sbuf ? sbuf : malloc(ul + 1);
    if (!buf) { snprintf(n->skip_reason, sizeof n->skip_reason, "нет памяти под ссылку"); return 1; }
    memcpy(buf, url + sl, ul);
    buf[ul] = '\0';
    int rc = parse_url_buf(buf, n);
    if (buf != sbuf) free(buf);
    return rc;
}

static int parse_url_buf(char *buf, struct hy2_node *n) {
    char *frag = strchr(buf, '#');
    if (frag) { *frag++ = '\0'; pct_decode(frag); set_str(n->name, sizeof n->name, frag, strlen(frag)); }
    char *query = strchr(buf, '?');
    if (query) *query++ = '\0';
    char *slash = strchr(buf, '/');
    if (slash) *slash = '\0';

    char *host = buf;
    char *at = strrchr(buf, '@');
    if (at) {
        *at = '\0';
        host = at + 1;
        pct_decode(buf);
        set_str(n->auth, sizeof n->auth, buf, strlen(buf));
    }
    const char *ports = NULL;
    if (host[0] == '[') {
        char *rb = strchr(host, ']');
        if (!rb) { snprintf(n->skip_reason, sizeof n->skip_reason, "адрес в скобках не закрыт"); return 1; }
        *rb = '\0';
        set_str(n->host, sizeof n->host, host + 1, strlen(host + 1));
        if (rb[1] == ':') ports = rb + 2;
    } else {
        char *colon = strchr(host, ':');
        if (colon) { *colon = '\0'; ports = colon + 1; }
        pct_decode(host);
        set_str(n->host, sizeof n->host, host, strlen(host));
    }
    if (ports && *ports) {
        int prc = hy2_parse_ports(ports, &n->port, n->hop, &n->hop_n);
        if (prc != 0) {
            snprintf(n->skip_reason, sizeof n->skip_reason, prc == -2 ?
                     "порты: диапазонов больше %d" : "порт не разбирается", HY2_HOP_RANGES);
            return 1;
        }
    } else {
        n->port = 443;                  /* умолчание эталона */
    }

    char obfs[32] = "";
    for (char *kv = query; kv && *kv; ) {
        char *amp = strchr(kv, '&');
        if (amp) *amp = '\0';
        char *eq = strchr(kv, '=');
        const char *k = kv, *v = "";
        if (eq) { *eq = '\0'; v = eq + 1; }
        char val[512];
        set_str(val, sizeof val, v, strlen(v));
        pct_decode(val);
        if (!strcasecmp(k, "sni")) set_str(n->sni, sizeof n->sni, val, strlen(val));
        else if (!strcasecmp(k, "insecure")) n->insecure = truthy(val);
        else if (!strcasecmp(k, "pinSHA256")) {
            if (val[0]) {
                if (parse_pin(val, n->pin) != 0) {
                    snprintf(n->skip_reason, sizeof n->skip_reason, "pinSHA256 не разбирается");
                    return 1;
                }
                n->has_pin = 1;
            }
        } else if (!strcasecmp(k, "obfs")) set_str(obfs, sizeof obfs, val, strlen(val));
        else if (!strcasecmp(k, "obfs-password") || !strcasecmp(k, "obfs_password"))
            set_str(n->obfs_pass, sizeof n->obfs_pass, val, strlen(val));
        else if (!strcasecmp(k, "up")) n->up_bps = hy2_parse_bandwidth(val);
        else if (!strcasecmp(k, "down")) n->down_bps = hy2_parse_bandwidth(val);
        else if (!strcasecmp(k, "mport")) {
            uint16_t first;
            int prc = hy2_parse_ports(val, &first, n->hop, &n->hop_n);
            if (prc != 0) {
                snprintf(n->skip_reason, sizeof n->skip_reason, prc == -2 ?
                         "mport: диапазонов больше %d" : "mport не разбирается", HY2_HOP_RANGES);
                return 1;
            }
        } else if (!strcasecmp(k, "hop-interval") || !strcasecmp(k, "hop_interval") ||
                   !strcasecmp(k, "hopInterval")) {
            long s = strtol(val, NULL, 10);
            if (s >= 5 && s <= 3600) n->hop_s = (unsigned)s;
        }
        kv = amp ? amp + 1 : NULL;
    }
    if (obfs[0]) {
        if (!strcasecmp(obfs, "salamander")) n->obfs = 1;
        else if (!strcasecmp(obfs, "gecko")) n->obfs = 2;         /* размеры в ссылке не задаются: умолчания */
        else {
            snprintf(n->skip_reason, sizeof n->skip_reason, "obfs %.20s не поддержан", obfs);
            return 1;
        }
    }
    finish_name(n);
    return node_check(n);
}

/* ---- JSON конфига Xray-core ------------------------------------------------------------------ */

/* Разбор без дерева: лексер в духе jsmn — плоский массив токенов, у контейнеров размер (число
 * элементов). Конфиг подписки — сотни узлов и десятки тысяч токенов, но нужна из него
 * малая часть, и дерево с указателями стоило бы больше, чем сам разбор. */
enum { J_OBJ = 1, J_ARR, J_STR, J_PRIM };
struct jt { uint8_t type; int start, end, size; };
struct js {
    const char *s;
    struct jt *t;
    int n, cap;
};

static int jt_new(struct js *j, int type, int start) {
    if (j->n == j->cap) {
        if (j->cap >= (1 << 17)) return -1;
        int nc = j->cap ? j->cap * 2 : 1024;
        struct jt *nt = realloc(j->t, (size_t)nc * sizeof *nt);
        if (!nt) return -1;
        j->t = nt;
        j->cap = nc;
    }
    j->t[j->n] = (struct jt){ type, start, -1, 0 };
    return j->n++;
}

/* Разобрать одно значение с позиции *p; возвращает индекс токена или -1. */
static int j_value(struct js *j, const char **p, const char *e, int depth) {
    while (*p < e && isspace((unsigned char)**p)) (*p)++;
    if (*p >= e || depth > 24) return -1;
    char c = **p;
    if (c == '{' || c == '[') {
        int me = jt_new(j, c == '{' ? J_OBJ : J_ARR, (int)(*p - j->s));
        if (me < 0) return -1;
        (*p)++;
        for (;;) {
            while (*p < e && isspace((unsigned char)**p)) (*p)++;
            if (*p >= e) return -1;
            if (**p == (c == '{' ? '}' : ']')) { (*p)++; break; }
            if (j->t[me].size && **p == ',') { (*p)++; continue; }
            if (c == '{') {
                if (**p != '"' || j_value(j, p, e, depth + 1) < 0) return -1;
                while (*p < e && isspace((unsigned char)**p)) (*p)++;
                if (*p >= e || **p != ':') return -1;
                (*p)++;
            }
            if (j_value(j, p, e, depth + 1) < 0) return -1;
            j->t[me].size++;
        }
        j->t[me].end = (int)(*p - j->s);
        return me;
    }
    if (c == '"') {
        int me = jt_new(j, J_STR, (int)(*p - j->s) + 1);
        if (me < 0) return -1;
        (*p)++;
        while (*p < e && **p != '"') { if (**p == '\\') (*p)++; (*p)++; }
        if (*p >= e) return -1;
        j->t[me].end = (int)(*p - j->s);
        (*p)++;
        return me;
    }
    int me = jt_new(j, J_PRIM, (int)(*p - j->s));
    if (me < 0) return -1;
    while (*p < e && !strchr(",]} \t\r\n", **p)) (*p)++;
    j->t[me].end = (int)(*p - j->s);
    return me;
}

/* Индекс токена, следующего за поддеревом i. */
static int j_next(const struct js *j, int i) {
    int k = i + 1;
    if (j->t[i].type == J_OBJ)
        for (int c = 0; c < j->t[i].size; c++) k = j_next(j, k + 1);     /* ключ + значение */
    else if (j->t[i].type == J_ARR)
        for (int c = 0; c < j->t[i].size; c++) k = j_next(j, k);
    return k;
}

static int j_get(const struct js *j, int obj, const char *key) {
    if (obj < 0 || j->t[obj].type != J_OBJ) return -1;
    int k = obj + 1;
    for (int c = 0; c < j->t[obj].size; c++) {
        size_t kl = (size_t)(j->t[k].end - j->t[k].start);
        if (kl == strlen(key) && !strncmp(j->s + j->t[k].start, key, kl)) return k + 1;
        k = j_next(j, k + 1);
    }
    return -1;
}

/* Строка или примитив → текст (escape-последовательности JSON раскрываются в объёме, нужном
 * ссылкам и паролям: \" \\ \/ \n \t \uXXXX). */
static int j_str(const struct js *j, int i, char *out, size_t cap) {
    if (i < 0 || (j->t[i].type != J_STR && j->t[i].type != J_PRIM)) return -1;
    size_t o = 0;
    for (int p = j->t[i].start; p < j->t[i].end && o + 4 < cap; p++) {
        char c = j->s[p];
        if (c == '\\' && j->t[i].type == J_STR && p + 1 < j->t[i].end) {
            c = j->s[++p];
            if (c == 'n') c = '\n';
            else if (c == 't') c = '\t';
            else if (c == 'u' && p + 4 < j->t[i].end) {
                unsigned u = 0;
                for (int q = 1; q <= 4; q++) u = u * 16 + (unsigned)(hexv(j->s[p + q]) < 0 ? 0 : hexv(j->s[p + q]));
                p += 4;
                /* Суррогатная пара \ud83d\udcf1 — один знак вне BMP (эмодзи), а не два трёхбайтовых. */
                if (u >= 0xd800 && u <= 0xdbff && p + 6 < j->t[i].end && j->s[p + 1] == '\\' && j->s[p + 2] == 'u') {
                    unsigned lo = 0;
                    for (int q = 3; q <= 6; q++) lo = lo * 16 + (unsigned)(hexv(j->s[p + q]) < 0 ? 0 : hexv(j->s[p + q]));
                    if (lo >= 0xdc00 && lo <= 0xdfff) {
                        unsigned cp = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
                        p += 6;
                        out[o++] = (char)(0xf0 | (cp >> 18)); out[o++] = (char)(0x80 | ((cp >> 12) & 63));
                        out[o++] = (char)(0x80 | ((cp >> 6) & 63)); out[o++] = (char)(0x80 | (cp & 63));
                        continue;
                    }
                }
                if (u >= 0xd800 && u <= 0xdfff) u = 0xfffd;      /* одинокий суррогат */
                if (u < 0x80) out[o++] = (char)u;
                else if (u < 0x800) { out[o++] = (char)(0xc0 | (u >> 6)); out[o++] = (char)(0x80 | (u & 63)); }
                else { out[o++] = (char)(0xe0 | (u >> 12)); out[o++] = (char)(0x80 | ((u >> 6) & 63)); out[o++] = (char)(0x80 | (u & 63)); }
                continue;
            }
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return 0;
}

static int j_get_str(const struct js *j, int obj, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    return j_str(j, j_get(j, obj, key), out, cap);
}

/* outbound Xray → узел. 0 — годен, 1 — негоден, -1 — не hysteria. */
static int xray_outbound(const struct js *j, int ob, struct hy2_node *n) {
    char tmp[256];
    if (j_get_str(j, ob, "protocol", tmp, sizeof tmp) != 0 || strcasecmp(tmp, "hysteria")) return -1;
    memset(n, 0, sizeof *n);
    n->hop_s = 30;
    int st = j_get(j, ob, "settings");
    j_get_str(j, st, "address", n->host, sizeof n->host);
    j_get_str(j, st, "port", tmp, sizeof tmp);
    n->port = (uint16_t)atoi(tmp);
    j_get_str(j, st, "version", tmp, sizeof tmp);
    if (tmp[0] && atoi(tmp) != 2) { snprintf(n->skip_reason, sizeof n->skip_reason, "hysteria версии %.4s не поддержан", tmp); return 1; }
    j_get_str(j, ob, "tag", n->name, sizeof n->name);
    utf8_trim(n->name);

    int ss = j_get(j, ob, "streamSettings");
    int hs = j_get(j, ss, "hysteriaSettings");
    j_get_str(j, hs, "auth", n->auth, sizeof n->auth);
    int tls = j_get(j, ss, "tlsSettings");
    j_get_str(j, tls, "serverName", n->sni, sizeof n->sni);
    char pins[400];
    if (j_get_str(j, tls, "pinnedPeerCertSha256", pins, sizeof pins) == 0 && pins[0]) {
        /* Список через запятую; сверяется отпечаток листа — берём первый (подмена цепочки из
         * нескольких отпечатков в эталоне нужна ротации сертификатов, у нас это узел на выбор). */
        char *c = strchr(pins, ',');
        if (c) *c = '\0';
        if (parse_pin(pins, n->pin) != 0) { snprintf(n->skip_reason, sizeof n->skip_reason, "pinnedPeerCertSha256 не разбирается"); return 1; }
        n->has_pin = 1;
    }
    int fm = j_get(j, ss, "finalmask");
    int udp = j_get(j, fm, "udp");
    if (udp >= 0 && j->t[udp].type == J_ARR) {
        int k = udp + 1;
        for (int c = 0; c < j->t[udp].size; c++, k = j_next(j, k)) {
            char type[32];
            j_get_str(j, k, "type", type, sizeof type);
            int set = j_get(j, k, "settings");
            if (!strcasecmp(type, "salamander")) {
                n->obfs = 1;
                j_get_str(j, set, "password", n->obfs_pass, sizeof n->obfs_pass);
                /* packetSize у маски salamander в Xray-core — это Gecko (transport_finalmask.go:
                 * To > 0 даёт GeckoConfig): та же Salamander плюс нарезка пакетов рукопожатия. */
                char rng[48];
                if (j_get_str(j, set, "packetSize", rng, sizeof rng) == 0 && rng[0]) {
                    unsigned a = 0, b = 0;
                    int m = sscanf(rng, "%u-%u", &a, &b);
                    if (m == 1) b = a;
                    if (m < 1 || b == 0) { n->obfs = 1; }             /* To = 0 — обычный salamander */
                    else if (a == 0 || b > 2048 || a > b) {
                        snprintf(n->skip_reason, sizeof n->skip_reason, "packetSize gecko негоден");
                        return 1;
                    } else {
                        n->obfs = 2;
                        n->gecko_min = (uint16_t)a;
                        n->gecko_max = (uint16_t)b;
                    }
                }
            } else if (!strcasecmp(type, "udphop")) {
                char pl[128];
                j_get_str(j, set, "remotePorts", pl, sizeof pl);
                uint16_t first;
                int prc = pl[0] ? hy2_parse_ports(pl, &first, n->hop, &n->hop_n) : 0;
                if (prc != 0) {
                    snprintf(n->skip_reason, sizeof n->skip_reason, prc == -2 ?
                             "remotePorts: диапазонов больше %d" : "remotePorts не разбирается",
                             HY2_HOP_RANGES);
                    return 1;
                }
                j_get_str(j, set, "interval", pl, sizeof pl);
                long s = strtol(pl, NULL, 10);
                if (s >= 5 && s <= 3600) n->hop_s = (unsigned)s;
            } else {
                snprintf(n->skip_reason, sizeof n->skip_reason, "маска %.20s не поддержана", type);
                return 1;
            }
        }
    }
    int qp = j_get(j, fm, "quicParams");
    if (qp >= 0) {
        char bw[64];
        if (j_get_str(j, qp, "brutalUp", bw, sizeof bw) == 0) n->up_bps = hy2_parse_bandwidth(bw);
        if (j_get_str(j, qp, "brutalDown", bw, sizeof bw) == 0) n->down_bps = hy2_parse_bandwidth(bw);
    }
    finish_name(n);
    return node_check(n);
}

/* ---- подписка -------------------------------------------------------------------------------- */

static void skip_note(struct hy2_sub_stats *st, const struct hy2_node *n) {
    st->skipped++;
    const char *ex = n->name[0] ? n->name : n->host;
    for (size_t i = 0; i < st->reasons_n; i++)
        if (!strcmp(st->reasons[i].reason, n->skip_reason)) { st->reasons[i].count++; return; }
    if (st->reasons_n < HY2_SKIP_REASONS) {
        struct hy2_skip *r = &st->reasons[st->reasons_n++];
        snprintf(r->reason, sizeof r->reason, "%s", n->skip_reason);
        snprintf(r->example, sizeof r->example, "%.140s", ex);
        r->count = 1;
    } else {
        st->reasons_dropped++;
    }
}

static void take(struct hy2_node *out, size_t max, size_t *cnt, struct hy2_node *n, int rc,
                 struct hy2_sub_stats *st) {
    if (rc == 0) { if (*cnt < max) out[(*cnt)++] = *n; }
    else if (rc == 1) skip_note(st, n);
}

static void parse_xray_doc(const char *text, struct hy2_node *out, size_t max, size_t *cnt,
                           struct hy2_sub_stats *st) {
    struct js j = { text, NULL, 0, 0 };
    const char *p = text, *e = text + strlen(text);
    if (j_value(&j, &p, e, 0) < 0) { free(j.t); return; }
    /* Корень — объект конфига (outbounds внутри), массив конфигов или массив outbound. Обходим
     * оба уровня. */
    for (int i = 0; i < j.n; i++) {
        if (j.t[i].type != J_OBJ) continue;
        struct hy2_node nd;
        int rc = xray_outbound(&j, i, &nd);
        if (rc < 0) continue;
        take(out, max, cnt, &nd, rc, st);
    }
    free(j.t);
}

size_t hy2_parse_sub(const char *text, struct hy2_node *out, size_t max, struct hy2_sub_stats *st) {
    memset(st, 0, sizeof *st);
    size_t cnt = 0;
    const char *s = text;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '{' || *s == '[') {
        parse_xray_doc(s, out, max, &cnt, st);
        return cnt;
    }
    /* Список ссылок: разделители — перевод строки и пробел. */
    while (*s) {
        while (*s && isspace((unsigned char)*s)) s++;
        const char *e = s + strcspn(s, " \t\r\n");
        if (e > s) {
            /* Короткая ссылка — в стековый буфер, длинная — в кучу по длине: предела длины ссылки
             * нет (поля узла режет по ширине hy2_parse_url). */
            char sbuf[1600];
            size_t l = (size_t)(e - s);
            char *line = l < sizeof sbuf ? sbuf : malloc(l + 1);
            if (line) {
                memcpy(line, s, l);
                line[l] = '\0';
                struct hy2_node nd;
                int rc = hy2_parse_url(line, &nd);
                if (rc < 0) { if (strstr(line, "://")) st->foreign++; }
                else take(out, max, &cnt, &nd, rc, st);
                if (line != sbuf) free(line);
            } else if (strstr(s, "://") && strstr(s, "://") < e) {
                st->foreign++;
            }
        }
        s = e;
    }
    return cnt;
}

/* base64 (обычный и URL-безопасный алфавиты, с набивкой и без). */
static size_t b64(const char *in, size_t n, char *out, size_t cap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v;
        char c = in[i];
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=' || isspace((unsigned char)c)) continue;
        else return 0;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 >= cap) return 0;
            out[o++] = (char)((acc >> bits) & 0xff);
        }
    }
    out[o] = '\0';
    return o;
}

const char *hy2_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    (void)raw_n;
    if (strstr(raw, "://")) return raw;
    const char *s = raw;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '{' || *s == '[') return raw;
    size_t o = b64(raw, strlen(raw), dec, dec_n);
    if (o && (strstr(dec, "://") || dec[0] == '{' || dec[0] == '[')) return dec;
    return raw;
}

/* Подписка из файла целиком: буферы и массив узлов — в куче по размеру файла и числу узлов в нём
 * (как vless_load_sub). Мест под узлы — по числу «://» и объектов Xray («"protocol"») в тексте:
 * верхняя граница числа узлов. Потолок файла — 64 МиБ: защита от файла-не-подписки под этим
 * именем, а не размер подписки (тысяча узлов — сотни килобайт). NULL — файл не открылся, слишком
 * велик или нет памяти; иначе массив (free), *cnt — пригодных узлов. */
#define HY2_SUB_FILE_MAX ((size_t)64 << 20)
struct hy2_node *hy2_load_sub(const char *path, size_t *cnt, struct hy2_sub_stats *st) {
    *cnt = 0;
    if (st) memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 0 || (size_t)fl > HY2_SUB_FILE_MAX) { fclose(f); return NULL; }
    size_t sz = (size_t)fl;
    char *raw = malloc(sz + 1), *dec = malloc(sz + 16);
    if (!raw || !dec) { fclose(f); free(raw); free(dec); return NULL; }
    size_t n = fread(raw, 1, sz, f);
    fclose(f);
    raw[n] = '\0';
    dec[0] = '\0';
    const char *text = hy2_sub_text(raw, n, dec, sz + 16);
    size_t hint = 1;
    for (const char *q = text; (q = strstr(q, "://")); q += 3) hint++;
    for (const char *q = text; (q = strstr(q, "\"protocol\"")); q += 10) hint++;
    struct hy2_node *nodes = calloc(hint, sizeof(*nodes));
    struct hy2_sub_stats tmp;
    if (nodes) *cnt = hy2_parse_sub(text, nodes, hint, st ? st : &tmp);
    free(raw);
    free(dec);
    return nodes;
}
