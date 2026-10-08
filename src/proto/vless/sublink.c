/* Ссылка узла в форме Xray: строки ссылки, поля транспорта и безопасности, их годность. Зачем
 * отдельно от sub.c и почему в libsteer — в sublink.h.
 *
 * Код перенесён из sub.c без изменений в поведении: те же правила, те же тексты причин, тот же
 * порядок проверок (node_usable в sub.c зовёт обе половины годности в прежнем порядке). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "vless.h"
#include "sublink.h"
/* Ради tr_upgrade_target: путь ws и httpupgrade, на котором Xray споткнулся бы, отбраковывается
 * здесь тем же правилом, по которому транспорт собирает запрос (src/proto/transport/trpath.c —
 * чистые строки, без сети и библиотек). */
#include "trpath.h"
/* Ради vencp_b64url_len: длина ключа pqv — та же арифметика base64url, что у VLESS encryption. Только
 * строки, без криптографии. */
#include "vencp.h"

/* base64: только декодирование и только то, что встречается в подписках — с переводами
 * строк внутри и, возможно, без выравнивающих '='. URL-safe алфавит тоже принимается:
 * часть панелей отдаёт именно его. */
static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n) {
    size_t o = 0;
    /* Накопитель БЕЗ знака и с маской: читаются из него только младшие bits+8 разрядов
     * (bits после уменьшения не больше 7), а старшие копились без нужды — на длинной
     * подписке int переполнялся, то есть разбор недоверенного текста упирался в
     * неопределённое поведение. UBSan на стенде подписки это и показывал:
     * «left shift of 496703836 by 6 places cannot be represented in type int». */
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        /* '=' закрывает блок: недобранные биты — его остаток, а не начало следующего.
         * Без сброса склеенные блоки с выравниванием внутри («QQ==QQ==») сдвигали всё
         * дальнейшее на остаток и давали мусор (I-326). */
        if (in[i] == '=') { acc = 0; bits = 0; continue; }
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;                  /* переводы строк, мусор */
        acc = ((acc << 6) | (unsigned)v) & 0x3FFFu;   /* хватает 14 разрядов: 7 + 6 + 1 */
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 < out_n) out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    if (o < out_n) out[o] = '\0';
    return o;
}

/* Процентное декодирование на месте: имена узлов приходят как %F0%9F%8C%8D... и без
 * этого в интерфейсе выглядят мусором. */
/* Адрес, по которому собеседника не бывает в принципе.
 *
 * Только такие: не указан (0.0.0.0, ::), петля (127.0.0.0/8, ::1) и широковещательный.
 * Частные сети сюда НЕ входят — узел в 10.0.0.0/8 это законная настройка внутри своей сети
 * или поверх второго туннеля, и отбрасывать его значило бы решить за человека.
 *
 * Имя не разрешается: подписка приходит из интернета, и разрешение имён на этапе разбора
 * означало бы поход в сеть внутри парсера чужого текста. Строка сравнивается как строка —
 * заглушки панелей пишут адрес цифрами, а не именем.
 */
int sl_host_leads_nowhere(const char *h) {
    if (!h || !h[0]) return 1;
    if (!strcmp(h, "0.0.0.0") || !strcmp(h, "::") || !strcmp(h, "[::]")) return 1;
    if (!strcmp(h, "::1") || !strcmp(h, "[::1]")) return 1;
    if (!strcmp(h, "255.255.255.255")) return 1;
    /* 127.0.0.0/8 целиком: заглушки встречаются и как 127.0.0.1, и как 127.0.0.53. */
    if (!strncmp(h, "127.", 4)) {
        const char *p = h + 4;
        while (*p) { if ((*p < '0' || *p > '9') && *p != '.') return 0; p++; }
        return 1;
    }
    return 0;
}

/* Имя это или адрес. Нужно security=tls: сертификат выдают на имя, и узел, объявленный
 * одним адресом без sni, проверять не против чего.
 *
 * Разбирается СТРОКОЙ, без inet_pton, и по той же причине, что и выше: этот файл разбирает
 * чужой текст из интернета и не ходит в сеть и не тянет сетевые заголовки. Правило простое и
 * достаточное: двоеточие бывает только у IPv6 (в скобках или без), а строка из одних цифр и
 * точек — это IPv4. Всё остальное — имя. Ошибиться здесь можно лишь в сторону «принять имя
 * за имя», а дальше сертификат всё равно проверяется по-настоящему. */
int sl_host_is_name(const char *h) {
    if (!h || !h[0]) return 0;
    if (strchr(h, ':') || h[0] == '[') return 0;
    for (const char *p = h; *p; p++)
        if ((*p < '0' || *p > '9') && *p != '.') return 1;
    return 0;
}

static int pct_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

void sl_pct_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            /* Только шестнадцатеричные цифры: прежняя арифметика считала «@» и «`» девяткой
             * (0x40|32 = 0x60 → 9), и «%@@» в имени узла давал байт 0x99 — битый UTF-8. */
            int hi = pct_hex(r[1]), lo = pct_hex(r[2]);
            if (hi >= 0 && lo >= 0) {
                *w++ = (char)((hi << 4) | lo);
                r += 2;
                continue;
            }
        }
        *w++ = *r;
    }
    *w = '\0';
}

void sl_set_field(char *dst, size_t n, const char *src, size_t len) {
    if (len >= n) len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Поле ссылки в процентной форме: раскодировать, ПОТОМ обрезать по полю. Наоборот (как было у
 * path) путь в 60 знаков, записанный процентами целиком (`%2Fstatic%2Fv1…` — так его кодируют
 * многие панели), обрезался до раскодирования на трети и уезжал на сервер чужим путём: у xhttp и
 * ws это 404 при исправном узле. */
void sl_set_pct(char *dst, size_t n, const char *src, size_t len) {
    char tmp[512];
    sl_set_field(tmp, sizeof(tmp), src, len);
    sl_pct_decode(tmp);
    sl_set_field(dst, n, tmp, strlen(tmp));
}

/* Снять с конца строки неполную последовательность UTF-8. Нужно там, где строку обрезал
 * буфер: обрезка идёт по байту, а буква вне ASCII занимает от двух байт, и граница
 * приходится на её середину. Одинокий ведущий байт — не «испорченная буква», а байт,
 * который ни один потребитель истолковать не может: JSON статуса печатает его как есть,
 * и разбирать этот JSON приходится уже интерфейсу. Терять последнюю букву честнее. */
void sl_utf8_trim_tail(char *s) {
    size_t n = strlen(s);
    if (!n) return;
    unsigned char last = (unsigned char)s[n - 1];
    if (last < 0x80) return;                       /* ASCII — рвать нечего */
    if ((last & 0xC0) != 0x80) { s[n - 1] = '\0'; return; }  /* ведущий байт без продолжения */

    /* Байт продолжения последним: отступить к ведущему и сверить длину. */
    size_t at = n - 1, cont = 1;
    while (at && ((unsigned char)s[at - 1] & 0xC0) == 0x80) { at--; cont++; }
    if (!at) { s[0] = '\0'; return; }              /* одни продолжения — мусор целиком */
    unsigned char lead = (unsigned char)s[at - 1];
    /* Перед продолжениями ASCII: ведущего байта нет, и снимаются только продолжения. Иначе
     * «ab\x80» теряло бы и «b» — букву, которая ни при чём (I-326). */
    if (lead < 0x80) { s[at] = '\0'; return; }
    size_t need = (lead & 0xE0) == 0xC0 ? 1 :
                  (lead & 0xF0) == 0xE0 ? 2 :
                  (lead & 0xF8) == 0xF0 ? 3 : 0;
    if (need && cont == need) return;              /* последовательность целая */
    s[at - 1] = '\0';
}

static size_t utf8_put(unsigned cp, char out[4]) {
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) { out[0] = (char)(0xC0 | cp >> 6); out[1] = (char)(0x80 | (cp & 63)); return 2; }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | cp >> 12); out[1] = (char)(0x80 | (cp >> 6 & 63)); out[2] = (char)(0x80 | (cp & 63));
        return 3;
    }
    out[0] = (char)(0xF0 | cp >> 18); out[1] = (char)(0x80 | (cp >> 12 & 63));
    out[2] = (char)(0x80 | (cp >> 6 & 63)); out[3] = (char)(0x80 | (cp & 63));
    return 4;
}

/* Ровно n шестнадцатеричных цифр (строка оканчивается нулём, за него не читаем): -1, если их меньше. */
static long hex_run(const char *p, int n) {
    long v = 0;
    for (int i = 0; i < n; i++) {
        int h = pct_hex((unsigned char)p[i]);
        if (h < 0) return -1;
        v = v * 16 + h;
    }
    return v;
}

size_t sl_unescape(const char *p, int yaml, char out[4], size_t *olen) {
    char c = *p;
    *olen = 1;
    out[0] = c;
    switch (c) {
    case 'n': out[0] = '\n'; return 1;
    case 't': out[0] = '\t'; return 1;
    case 'r': out[0] = '\r'; return 1;
    case 'b': out[0] = '\b'; return 1;
    case 'f': out[0] = '\f'; return 1;
    case 'u': {
        long u = hex_run(p + 1, 4);
        if (u < 0) break;
        size_t used = 5;
        if (u >= 0xD800 && u <= 0xDBFF) {
            long lo = (p[5] == '\\' && p[6] == 'u') ? hex_run(p + 7, 4) : -1;
            if (lo >= 0xDC00 && lo <= 0xDFFF) { u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00); used = 11; }
            else u = 0xFFFD;
        } else if (u >= 0xDC00 && u <= 0xDFFF) u = 0xFFFD;
        *olen = utf8_put((unsigned)u, out);
        return used;
    }
    case 'U': case 'x': {
        if (!yaml) break;
        int nd = c == 'U' ? 8 : 2;
        long u = hex_run(p + 1, nd);
        if (u < 0 || u > 0x10FFFF || (u >= 0xD800 && u <= 0xDFFF)) break;
        *olen = utf8_put((unsigned)u, out);
        return (size_t)nd + 1;
    }
    default: break;
    }
    return 1;
}

/* Имя узла: единственное поле, куда подписка кладёт что угодно, включая UTF-8, и потому
 * единственное, где обрезка по байту буфера видна снаружи. Порядок важен: сначала снять
 * оборванную процентную форму (её оставила та же обрезка, декодировать её нечем), потом
 * раскодировать, потом снять оборванную последовательность UTF-8 — она могла появиться и
 * из процентной формы, и из сырых байт во фрагменте ссылки. */
void sl_set_name(char *dst, size_t n, const char *src) {
    size_t len = strlen(src);
    int cut = len >= n;
    sl_set_field(dst, n, src, len);
    if (cut) {
        size_t l = strlen(dst);
        if (l >= 1 && dst[l - 1] == '%') dst[l - 1] = '\0';
        else if (l >= 2 && dst[l - 2] == '%') dst[l - 2] = '\0';
    }
    sl_pct_decode(dst);
    sl_utf8_trim_tail(dst);
}

/* Длина набивки xhttp из значения `xPaddingBytes`.
 *
 * Значение бывает двух видов, и оба законны у Xray: одно число («512») или диапазон
 * («50-150»). Разбирается вручную, без sscanf: строка приходит из интернета, а sscanf на
 * мусоре ведёт себя тем интереснее, чем мусор изобретательнее.
 *
 * Ничего не понято — поля не трогаются, и дальше работает умолчание. Молчание здесь верно:
 * набивка, которую мы не сумели прочитать, не повод объявлять узел негодным — умолчание
 * Xray подойдёт большинству серверов. */
static int sl_range(const char *v, unsigned long max, unsigned long *from, unsigned long *to) {
    unsigned long a = 0, b = 0;
    const char *p = v;
    while (*p == ' ' || *p == '"') p++;
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (unsigned)(*p - '0'); p++; if (a > max) return -1; }
    if (*p == '-') {
        p++;
        if (*p < '0' || *p > '9') return -1;
        while (*p >= '0' && *p <= '9') { b = b * 10 + (unsigned)(*p - '0'); p++; if (b > max) return -1; }
    } else {
        b = a;
    }
    if (b < a) return -1;
    *from = a;
    *to = b;
    return 0;
}

void sl_pad_range(struct vless_node *n, const char *v) {
    unsigned long a, b;
    if (sl_range(v, 65535, &a, &b) != 0) return;
    n->pad_from = (uint16_t)a;
    n->pad_to = (uint16_t)b;
}

/* xhttp `scMaxEachPostBytes` в тех же формах. 0 — предел, который Xray не принял бы (его клиент
 * по нему не режет): остаётся умолчание. */
void sl_post_range(struct vless_node *n, const char *v) {
    unsigned long a, b;
    if (sl_range(v, 100000000, &a, &b) != 0 || a == 0) return;
    n->post_from = (uint32_t)a;
    n->post_to = (uint32_t)b;
}

/* `extra` ссылки — это кусок настроек транспорта в JSON, и нас в нём занимает ровно одно
 * поле. Полного разбора здесь нет намеренно: остальное (xmux, сроки переиспользования
 * соединений) относится к мультиплексору, которого у нас нет, и разбирать его значило бы
 * читать чужие настройки, чтобы их выбросить.
 *
 * Поиск по имени поля, а не разбор объекта: `extra` приезжает уже раскодированным из
 * процентной формы, вложенность в нём одна, и вытащить одно число дешевле, чем заводить
 * второй разбор JSON рядом с тем, что уже есть в этом файле. */
/* Настройки xhttp, меняющие запросы на проводе в форму, которой клиент не делает (имена Xray
 * 26.3): идентификатор сессии или seq не в пути, данные выгрузки в заголовках или куках,
 * tokenish-набивка, обфусцированная набивка, отдельный сервер скачивания. Узел с одной из них не
 * откроется, потому что сервер ждёт другого запроса, так что отсев сразу, с названной причиной,
 * ничего не теряет.
 *
 * По ЗНАЧЕНИЮ, а не по наличию: панели записывают умолчания явно ("path", "auto", "repeat-x"), а
 * это ровно то, что шлёт клиент. uplinkHTTPMethod и xPaddingPlacement здесь нет: сервер не
 * проверяет метод, а место набивки важно только при xPaddingObfsMode. */
int sl_xh_setting_bad(const char *key, const char *val) {
    if (!val || !val[0] || !strcmp(val, "null")) return 0;
    if (!strcmp(key, "downloadSettings")) return 1;
    if (!strcmp(key, "sessionPlacement") || !strcmp(key, "sessionIDPlacement") ||
        !strcmp(key, "seqPlacement"))
        return strcmp(val, "path") != 0;
    if (!strcmp(key, "uplinkDataPlacement")) return strcmp(val, "auto") && strcmp(val, "body");
    if (!strcmp(key, "xPaddingMethod")) return strcmp(val, "repeat-x") != 0;
    if (!strcmp(key, "xPaddingObfsMode")) return !strcmp(val, "true");
    return 0;
}

static int xh_extra_bad(const char *json) {
    static const char *const keys[] = { "downloadSettings", "sessionPlacement", "sessionIDPlacement",
                                        "seqPlacement", "uplinkDataPlacement", "xPaddingMethod",
                                        "xPaddingObfsMode" };
    for (size_t i = 0; i < sizeof keys / sizeof *keys; i++) {
        char q[32];
        snprintf(q, sizeof q, "\"%s\"", keys[i]);
        const char *k = strstr(json, q);
        if (!k || !(k = strchr(k + strlen(q), ':'))) continue;
        k++;
        while (*k == ' ') k++;
        /* Значение: содержимое строки или голое слово (true, null, скобка объекта). */
        char v[32];
        size_t l = 0;
        if (*k == '"') {
            k++;
            while (k[l] && k[l] != '"' && l < sizeof v - 1) l++;
        } else {
            while (k[l] && k[l] != ',' && k[l] != '}' && k[l] != ' ' && l < sizeof v - 1) l++;
            if (*k == '{') l = 1;
        }
        memcpy(v, k, l);
        v[l] = 0;
        if (sl_xh_setting_bad(keys[i], v)) return 1;
    }
    return 0;
}

void sl_parse_extra(struct vless_node *n, const char *extra) {
    if (xh_extra_bad(extra)) n->xh_extra = 1;
    const char *k = strstr(extra, "\"xPaddingBytes\"");
    if (k && (k = strchr(k + 15, ':'))) sl_pad_range(n, k + 1);
    k = strstr(extra, "\"scMaxEachPostBytes\"");
    if (k && (k = strchr(k + 20, ':'))) sl_post_range(n, k + 1);
}


/* ---- длинные значения узла: encryption и pqv ---------------------------------------------------
 *
 * Значения длинные (ключ ML-DSA-65 в base64url — 2603 знака, реле VLESS encryption с ключом ML-KEM-768 —
 * около 1600), а узлов в массиве сотни: по полю в узле это сотни килобайт статической памяти под то,
 * что бывает у единиц. Поэтому узел держит УКАЗАТЕЛЬ на строку из общей таблицы, где одинаковые
 * значения хранятся один раз. Строки не освобождаются: указатель обязан пережить и узел, и его копии
 * (узлы копируются по значению между массивами разбора и стеком туннеля), а повторные разборы той же
 * подписки находят уже занесённое и памяти не прибавляют. Таблица ограничена — переполнение узла не
 * теряет, а объявляет непригодным с названной причиной (без неё хостильная подписка со случайными
 * ключами росла бы в памяти роутера на каждом обновлении). */
#define SUB_INTERN_MAX 256
static const char *g_intern[SUB_INTERN_MAX];
static volatile int g_intern_lock;
/* Метки непригодных значений: разбор не удался, причина уже названа в node_usable. */
const char SL_BAD_PQV[] = "!pqv";
const char SL_FULL[] = "!full";

const char *sl_intern(const char *v, size_t n) {
    while (__atomic_test_and_set(&g_intern_lock, __ATOMIC_ACQUIRE)) { }
    const char *r = SL_FULL;
    for (int i = 0; i < SUB_INTERN_MAX; i++) {
        if (!g_intern[i]) {
            char *c = malloc(n + 1);
            if (c) { memcpy(c, v, n); c[n] = '\0'; g_intern[i] = c; r = c; }
            break;
        }
        if (strlen(g_intern[i]) == n && !memcmp(g_intern[i], v, n)) { r = g_intern[i]; break; }
    }
    __atomic_clear(&g_intern_lock, __ATOMIC_RELEASE);
    return r;
}

/* pqv / mldsa65Verify: открытый ключ ML-DSA-65, base64url, ровно 1952 байта. */
void sl_set_pqv(struct vless_node *n, const char *v) {
    n->pqv = NULL;
    if (!v[0]) return;
    if (vencp_b64url_len(v, strlen(v)) != 1952) { n->pqv = SL_BAD_PQV; return; }
    n->pqv = sl_intern(v, strlen(v));
}

/* ---- проверка сертификата узла: pcs, pks, vcn, allowInsecure ------------------------------------
 *
 * Xray-core (transport/internet/tls/config.go, infra/conf/transport_security.go) знает два способа
 * не полагаться на хранилище корней: pinnedPeerCertSha256 (`pcs` в ссылке) — SHA-256 сертификата в
 * hex, через запятую, двоеточия OpenSSL допустимы; verifyPeerCertByName (`vcn`) — имена, против
 * которых проверяется цепочка ВМЕСТО SNI. allowInsecure Xray снял совсем (конфиг с ним не
 * собирается), а в ссылках и чужих подписках он живёт по-прежнему. sing-box держит отпечаток иначе —
 * SHA-256 от SubjectPublicKeyInfo в base64 (`certificate_public_key_sha256`); он хранится отдельно
 * (pks), потому что считается от другого куска сертификата и смешивать два вида отпечатков нельзя.
 *
 * Отпечаток приводится к одному виду (64 знака hex строчными) ЗДЕСЬ, при разборе: испорченный
 * отпечаток — непригодный узел с названной причиной, а не проверка, которая на каждом соединении
 * молча ничего не сравнивает. */
const char SL_BAD_PIN[] = "!pin";

static const char *pin_slot(const struct vless_node *n, int spki) { return spki ? n->pks : n->pcs; }

void sl_add_pins(struct vless_node *n, const char *v, int spki) {
    const char *cur = pin_slot(n, spki);
    if (cur == SL_BAD_PIN || cur == SL_FULL) return;
    char buf[1100];
    size_t bl = 0;
    if (cur) bl = (size_t)snprintf(buf, sizeof buf, "%s", cur);
    const char *p = v;
    int bad = 0;
    while (*p && !bad) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        unsigned char raw[32] = { 0 };
        if (tn) {
            if (spki) {
                char d[48];
                bad = tn < 43 || tn > 44 || b64_decode(p, tn, d, sizeof d) != 32;
                if (!bad) memcpy(raw, d, 32);
            } else {
                /* Двоеточия — привычная запись OpenSSL (`AB:CD:…`), Xray их отбрасывает. */
                size_t k = 0;
                for (size_t i = 0; i < tn && !bad; i++) {
                    int c = (unsigned char)p[i], h;
                    if (c == ':') continue;
                    h = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
                    if (h < 0 || k >= 64) { bad = 1; break; }
                    if (k & 1) raw[k / 2] = (unsigned char)(raw[k / 2] << 4 | h);
                    else raw[k / 2] = (unsigned char)h;
                    k++;
                }
                if (!bad && k != 64) bad = 1;
            }
            if (!bad) {
                if (bl + 66 >= sizeof buf) bad = 1;
                else {
                    if (bl) buf[bl++] = ',';
                    for (int i = 0; i < 32; i++) bl += (size_t)snprintf(buf + bl, 3, "%02x", raw[i]);
                }
            }
        }
        if (!e) break;
        p = e + 1;
    }
    const char *r = bad ? SL_BAD_PIN : bl ? sl_intern(buf, bl) : NULL;
    if (spki) n->pks = r; else n->pcs = r;
}

/* verifyPeerCertByName: имена через запятую, пробелы вокруг отбрасываются, пустые пропускаются
 * (так читает и Xray). */
void sl_set_vcn(struct vless_node *n, const char *v) {
    char buf[300];
    size_t bl = 0;
    n->vcn = NULL;
    const char *p = v;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        if (tn) {
            if (bl + tn + 2 >= sizeof buf) { n->vcn = SL_BAD_PIN; return; }
            if (bl) buf[bl++] = ',';
            memcpy(buf + bl, p, tn);
            bl += tn;
        }
        if (!e) break;
        p = e + 1;
    }
    if (bl) n->vcn = sl_intern(buf, bl);
}

/* ECH: ECHConfigList узла (Xray echConfigList, `ech=` ссылки, ech-opts.config Clash, ech.config sing-box) в
 * base64. Здесь — только форма: список начинается длиной и в нём есть запись версии 0xfe0d; какую запись
 * можно использовать, решает ech_pick при подключении (ech.c не линкуется в стенд подписки, а причина
 * отказа там названа отдельно). Значение в виде «домен+https://сервер DNS» (Xray умеет спросить запись из
 * DNS) не поддержано: узел пропускается с причиной, а не уходит без ECH — молчаливая отправка имени
 * открытым текстом была бы тем самым, от чего ECH защищает. */
const char SL_BAD_ECH[] = "!ech";
const char SL_ECH_DNS[] = "!ech-dns";
void sl_set_ech(struct vless_node *n, const char *v) {
    char raw[1100];
    n->ech = NULL;
    if (!v[0]) return;
    if (strstr(v, "://")) { n->ech = SL_ECH_DNS; return; }
    size_t bl = b64_decode(v, strlen(v), raw, sizeof raw);
    int ok = bl >= 8 && bl < sizeof raw && (size_t)(((unsigned char)raw[0] << 8) | (unsigned char)raw[1]) + 2 == bl;
    if (ok) {
        ok = 0;
        for (size_t p = 2; p + 4 <= bl;) {
            size_t l = ((unsigned char)raw[p + 2] << 8) | (unsigned char)raw[p + 3];
            if (p + 4 + l > bl) { ok = 0; break; }
            if ((((unsigned char)raw[p] << 8) | (unsigned char)raw[p + 1]) == 0xfe0d) ok = 1;
            p += 4 + l;
        }
    }
    n->ech = ok ? sl_intern(v, strlen(v)) : SL_BAD_ECH;
}

/* allowInsecure / insecure / skip-cert-verify: 1, true, yes — «включено». Всё остальное, в том числе
 * пустое, — выключено: включать отказ проверки сертификата догадкой нельзя, выключать можно. */
int sl_truthy(const char *v) {
    return !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes");
}

/* Ключ `insecure` выхода (см. vless.h). */
static volatile int g_insecure;
void vless_set_insecure(int on) { g_insecure = on ? 1 : 0; }
int vless_insecure(void) { return g_insecure; }

/* Значение параметра ссылки в куче-буфере: длинные значения (pqv, encryption) не помещаются в
 * узел, а стек рабочих потоков мал. Процентная форма раскрывается. Возвращает NULL при нехватке памяти. */
char *sl_param_dup(const char *v, size_t vlen) {
    char *c = malloc(vlen + 1);
    if (!c) return NULL;
    memcpy(c, v, vlen);
    c[vlen] = '\0';
    sl_pct_decode(c);
    return c;
}

/* Порт из строки цифр: 1..65535, иначе 0. Одно место на ссылку и на конфиг Xray. */
int sl_uuid_parse(const char *s, unsigned char out[16]) {
    int hi = -1;
    size_t k = 0;
    for (; *s && k < 16; s++) {
        if (*s == '-') continue;
        int c = (unsigned char)*s, v;
        v = c >= '0' && c <= '9' ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1;
        if (v < 0) return -1;
        if (hi < 0) hi = v;
        else { out[k++] = (unsigned char)(hi << 4 | v); hi = -1; }
    }
    /* Ровно 16 байт и без висячего полубайта; хвоста (лишних знаков) быть не должно. */
    while (*s == '-') s++;
    return (k == 16 && hi < 0 && !*s) ? 0 : -1;
}

uint16_t sl_port_of(const char *s) {
    if (!*s) return 0;
    unsigned long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > 65535) return 0;
    }
    return (uint16_t)v;
}


/* Узел ws или httpupgrade: то, на чём Xray споткнулся бы сам, — заранее и с причиной. 1 —
 * непригоден (причина в skip_reason).
 *
 *   - Vision поверх них не бывает (отказ — в sl_link_usable_post, общий для всех транспортов,
 *     кроме tcp): у нас прямое копирование Vision прочитало бы сокет мимо кадров;
 *   - путь, который Xray не разобрал бы однозначно или у ws не открыл бы вовсе (trpath.h) — одно
 *     правило с транспортом, чтобы «пригоден» здесь значило «откроется» там;
 *   - host — имя для заголовка Host: без пробелов и управляющих знаков, иначе строка запроса
 *     рвётся посередине;
 *   - заголовки из конфига, которые не влезли или негодны (headers_bad, см. xray_headers). */
static int upg_node_bad(struct vless_node *n, int ws) {
    char tgt[1024];
    const char *why = "";
    if (tr_upgrade_target(n->path, ws, tgt, sizeof(tgt), &why) != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", why);
        return 1;
    }
    for (const char *p = n->http_host; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "негодный host у %s", n->type);
            return 1;
        }
    }
    if (n->headers_bad) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "негодные headers у %s", n->type);
        return 1;
    }
    return 0;
}


/* Поле транспорта или безопасности ссылки (sublink.h). Ключи и их разбор — прежние, из цикла
 * параметров vless:// в sub.c; VLESS-своё (flow, encryption) разбирает own вызывающего. */
int sl_link_param(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen) {
    if (klen == 4 && !strncmp(k, "type", 4)) {
        sl_set_field(n->type, sizeof(n->type), v, vlen);
        /* Те же вторые имена, что у конфига Xray (sub.c): raw — каноническое имя tcp с Xray 24.9.30,
         * websocket — ws. Без этого ссылка с type=raw отсеивалась «транспорт raw не поддержан». */
        if (!strcmp(n->type, "raw")) snprintf(n->type, sizeof(n->type), "tcp");
        else if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof(n->type), "ws");
    }
    else if (klen == 8 && !strncmp(k, "security", 8)) sl_set_field(n->security, sizeof(n->security), v, vlen);
    else if (klen == 3 && !strncmp(k, "sni", 3)) sl_set_field(n->sni, sizeof(n->sni), v, vlen);
    else if (klen == 2 && !strncmp(k, "fp", 2)) sl_set_field(n->fp, sizeof(n->fp), v, vlen);
    else if (klen == 3 && !strncmp(k, "pbk", 3)) sl_set_field(n->pbk, sizeof(n->pbk), v, vlen);
    else if (klen == 3 && !strncmp(k, "sid", 3)) sl_set_field(n->sid, sizeof(n->sid), v, vlen);
    else if (klen == 10 && !strncmp(k, "headerType", 10)) { if (vlen == 4 && !strncmp(v, "http", 4)) n->tcp_http = 1; }
    /* pqv — постквантовая часть Xray-core (паритет 26.9): проверка подписи ML-DSA-65 сертификата
     * Reality. Значение длинное — см. sl_intern. */
    else if (klen == 3 && !strncmp(k, "pqv", 3)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { sl_set_pqv(n, d); free(d); } else n->pqv = SL_BAD_PQV;
    }
    /* pcs / vcn — pinnedPeerCertSha256 и verifyPeerCertByName Xray-core; allowInsecure (и
     * insecure, как пишут панели) подписка нести вправе, но выключить проверку сама не может —
     * см. sl_link_usable_pre. */
    else if ((klen == 3 && !strncmp(k, "pcs", 3)) || (klen == 3 && !strncmp(k, "vcn", 3))) {
        char *d = sl_param_dup(v, vlen);
        if (d) {
            if (k[0] == 'p') sl_add_pins(n, d, 0); else sl_set_vcn(n, d);
            free(d);
        } else if (k[0] == 'p') n->pcs = SL_BAD_PIN; else n->vcn = SL_BAD_PIN;
    }
    else if (klen == 3 && !strncmp(k, "ech", 3)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { sl_set_ech(n, d); free(d); } else n->ech = SL_BAD_ECH;
    }
    else if ((klen == 13 && !strncmp(k, "allowInsecure", 13)) || (klen == 8 && !strncmp(k, "insecure", 8))) {
        char *d = sl_param_dup(v, vlen);
        if (d) { if (sl_truthy(d)) n->allow_insecure = 1; free(d); }
    }
    else if (klen == 4 && !strncmp(k, "path", 4)) sl_set_pct(n->path, sizeof(n->path), v, vlen);
    else if (klen == 11 && !strncmp(k, "serviceName", 11)) { sl_set_field(n->service, sizeof(n->service), v, vlen); sl_pct_decode(n->service); }
    else if (klen == 4 && !strncmp(k, "mode", 4)) sl_set_field(n->mode, sizeof(n->mode), v, vlen);
    /* host — заголовок Host у ws и httpupgrade. У xhttp в ссылке он тоже бывает, но xhttp его не
     * читает: :authority там — sni, как было. */
    else if (klen == 4 && !strncmp(k, "host", 4)) sl_set_pct(n->http_host, sizeof(n->http_host), v, vlen);
    /* extra — настройки транспорта в JSON. Читается ради длины набивки: сервер её ПРОВЕРЯЕТ и на
     * чужую отвечает 400 (см. sl_pad_range). Буфер под ПРОЦЕНТНУЮ форму: она втрое длиннее текста,
     * и 256 байт обрезали JSON до раскодирования — xPaddingBytes дальше ~85 знаков пропадал молча. */
    else if (klen == 5 && !strncmp(k, "extra", 5)) {
        char ex[2048];
        sl_set_field(ex, sizeof(ex), v, vlen);
        sl_pct_decode(ex);
        sl_parse_extra(n, ex);
    }
    else return 0;
    return 1;
}

/* схема://секрет@хост:порт?параметры#имя (sublink.h). Тело — прежний разбор vless:// из sub.c;
 * отличаются только схема, параметры протокола (own) и то, что годность проверяет вызывающий. */
int sl_link_parse(const char *url, const char *scheme, struct vless_node *n, sl_own_fn own,
                  const char **secret, size_t *secret_n) {
    memset(n, 0, sizeof(*n));
    size_t scl = strlen(scheme);
    if (strncmp(url, scheme, scl) != 0) return -1;
    const char *p = url + scl;

    const char *at = strchr(p, '@');
    if (!at) return -1;
    sl_set_field(n->uuid, sizeof(n->uuid), p, (size_t)(at - p));
    if (secret) *secret = p;
    if (secret_n) *secret_n = (size_t)(at - p);

    p = at + 1;
    /* Границы: хост и порт лежат ДО '?' и '#', параметры — до '#'. Иначе имя узла «Fast?type=ws»
     * без параметров читалось как параметры, а «host?type=tcp#name:1» — как хост с портом 1. */
    const char *hash = strchr(p, '#');
    const char *hp_end = hash ? hash : p + strlen(p);
    const char *qmark = memchr(p, '?', (size_t)(hp_end - p));
    const char *colon = memchr(p, ':', (size_t)((qmark ? qmark : hp_end) - p));
    if (!colon) return -1;
    sl_set_field(n->host, sizeof(n->host), p, (size_t)(colon - p));
    {
        /* Порт — только цифры до конца хоста и в диапазоне 1..65535: atoi давал 4464 на
         * «:70000», 65535 на «:-1» и 443 на «:443abc», и узел шёл не туда. */
        char pnum[8];
        const char *pe = colon + 1;
        size_t pl = 0;
        while (pe < (qmark ? qmark : hp_end) && *pe >= '0' && *pe <= '9' && pl + 1 < sizeof(pnum))
            pnum[pl++] = *pe++;
        pnum[pl] = '\0';
        if (!pl || pe != (qmark ? qmark : hp_end)) return -1;
        n->port = sl_port_of(pnum);
    }
    if (!n->port) return -1;

    /* Имя узла: за '#', и оно единственное, что может содержать что угодно. */
    if (hash) {
        sl_set_name(n->name, sizeof(n->name), hash + 1);
    }

    /* Параметры. Значения по умолчанию — те, что подразумевает VLESS, когда поле
     * опущено: type=tcp и security=none встречаются именно так. */
    snprintf(n->type, sizeof(n->type), "tcp");
    if (qmark) {
        const char *end = hash && hash > qmark ? hash : qmark + strlen(qmark);
        const char *k = qmark + 1;
        while (k < end) {
            const char *amp = memchr(k, '&', (size_t)(end - k));
            const char *stop = amp ? amp : end;
            const char *eq = memchr(k, '=', (size_t)(stop - k));
            if (eq) {
                size_t klen = (size_t)(eq - k), vlen = (size_t)(stop - eq - 1);
                const char *v = eq + 1;
                if (!own || !own(n, k, klen, v, vlen)) sl_link_param(n, k, klen, v, vlen);
            }
            if (!amp) break;
            k = amp + 1;
        }
    }

    /* Годность — у вызывающего: между половинами sl_link_usable_pre и _post протокол проверяет
     * своё. */
    return 0;
}

/* Первая половина годности транспорта и безопасности (sublink.h). Тело — прежний node_usable из
 * sub.c без VLESS-своего: flow, encryption и UUID проверяет sub.c между pre и post, и порядок
 * причин у VLESS от этого не меняется. Поля, которых в ссылке не было, к этому моменту уже
 * заполнены умолчаниями: делает это первая строка. */
int sl_link_usable_pre(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* Постквантовые поля. Метки ставит разбор (set_encryption в sub.c, sl_set_pqv): значение не по правилу Xray или
     * таблица длинных значений полна. Причины короткие — skip_reason всего 64 байта. */
    if (n->pqv == SL_BAD_PQV) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "pqv: не ключ ML-DSA-65");
        return 1;
    }
    if (n->tcp_http && !strcmp(n->type, "tcp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "tcp headerType=http не поддержан");
        return 1;
    }
    if (n->xh_extra && !strcmp(n->type, "xhttp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "xhttp: обфускация не поддержана");
        return 1;
    }
    if (n->encryption == SL_FULL || n->pqv == SL_FULL || n->pcs == SL_FULL || n->pks == SL_FULL ||
        n->vcn == SL_FULL) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "слишком много разных ключей");
        return 1;
    }
    /* Проверка сертификата касается только security=tls: у reality подлинность доказывает сам
     * протокол, а pcs/vcn/allowInsecure, попавшие в такую ссылку, ничего не значат. Испорченный
     * отпечаток у tls — непригодный узел, а не проверка, которая молча ничего не сверяет. */
    if (!strcmp(n->security, "tls")) {
        if (n->ech == SL_BAD_ECH) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "ech: не ECHConfigList в base64");
            return 1;
        }
        if (n->ech == SL_ECH_DNS) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "ech: запрос записи из DNS не поддержан");
            return 1;
        }
        if (n->ech == SL_FULL) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "слишком много разных ключей");
            return 1;
        }
        if (n->pcs == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "pcs: не SHA-256 в hex");
            return 1;
        }
        if (n->pks == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "certificate_public_key_sha256: не SHA-256");
            return 1;
        }
        if (n->vcn == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "vcn: слишком длинный список имён");
            return 1;
        }
        /* Решение безопасности: подписка не выключает проверку сертификата сама. Узел с allowInsecure
         * пригоден, только если человек явно поставил `insecure` у выхода. */
        if (n->allow_insecure && !g_insecure) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "allowInsecure: включите insecure у выхода явно");
            return 1;
        }
        n->insecure = g_insecure ? 1 : 0;
    }

    return 0;
}

/* Вторая половина (sublink.h): то, что у VLESS проверяется после идентификатора. */
int sl_link_usable_post(struct vless_node *n) {
    if (strcmp(n->security, "reality") != 0 && strcmp(n->security, "none") != 0 &&
        strcmp(n->security, "tls") != 0) {
        /* Остаётся непригодным xtls: это уже не «TLS с проверкой цепочки», а свой обмен,
         * которого у нас нет. tls поддержан — см. certverify.c и ветку в client.c. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "security=%s не поддержан",
                 n->security);
        return 1;
    }

    /* У обычного TLS имя обязательно, и отбраковывается оно ЗДЕСЬ, а не при подключении.
     *
     * Проверять сертификат не против чего: sni — это то, что мы просим у сервера, и он же
     * то, что должно найтись в сертификате. Узел без sni проверяется против адреса, и если
     * адрес — это IP, сертификат на него почти наверняка не выдан. Сказать об этом заранее
     * честнее, чем потратить попытку сторожа и вернуть «сервер не доказал подлинность»:
     * причина-то не в сервере. (У reality пустой sni, наоборот, законен — см. ниже.) */
    if (strcmp(n->security, "tls") == 0 && !n->sni[0] && !sl_host_is_name(n->host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "tls по адресу без sni: нечем сверить");
        return 1;
    }
    /* Ключ сервера обязателен: без него Reality нечем проверить, и узел не поднимется.
     *
     * А ВОТ ИМЯ (sni) — НЕТ, и раньше его отсутствие тоже отбраковывало узел. Reality
     * сверяет присланное имя со своим списком `serverNames`, и пустая строка в этом списке
     * законна: тогда сервер ждёт ClientHello БЕЗ расширения server_name, а клиенты Xray его
     * и не шлют. Снято на живой подписке владельца: панель во всех форматах разом — ссылка
     * vless://, вариант для Happ, YAML для Clash — отдаёт узел без `sni`, то есть это выбор
     * владельца сервера, а не потеря по дороге. Мы такой узел объявляли непригодным, и
     * подписка из одного узла выглядела пустой. ClientHello без имени собирает reality.c. */
    if (!strcmp(n->security, "reality") && !n->pbk[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "reality без pbk");
        return 1;
    }
    const int upg_ws = !strcmp(n->type, "ws"), upg = upg_ws || !strcmp(n->type, "httpupgrade");
    if (strcmp(n->type, "tcp") != 0 && strcmp(n->type, "grpc") != 0 &&
        strcmp(n->type, "xhttp") != 0 && !upg) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "транспорт %s не поддержан", n->type);
        return 1;
    }
    /* Vision (flow xtls-rprx-vision, а при чтении и xtls-rprx-vision-udp443 — sub.c приводит его к
     * обычному) бывает только поверх голого TCP: Xray требует, чтобы под ним лежала связь TLS или
     * REALITY напрямую, и на ws, httpupgrade, grpc и xhttp отвечает «XTLS only supports TLS and
     * REALITY directly for now», после чего выход перезапускается без конца. Отказ — здесь, до
     * кандидатов, и один на все форматы подписки: ссылка, конфиг Xray, sing-box, Clash. */
    if (n->flow[0] && strcmp(n->type, "tcp") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vision поверх %s не бывает", n->type);
        return 1;
    }
    if (upg && upg_node_bad(n, upg_ws)) return 1;

    /* Узел, который никуда не ведёт. Отдельная причина, а не «не подключился»: панели,
     * привязывающие подписку к устройствам, отвечают клиенту без идентификатора не отказом,
     * а ЗАГЛУШКОЙ — законными ссылками vless:// на `0.0.0.0:1`, где сообщение человеку
     * спрятано в ИМЯ узла («📱 Неправильный клиент», «🔌 Лимит устройств достигнут»).
     *
     * Разбор такую ссылку принимает целиком, и правильно: по форме она безупречна. Но
     * пригодной она быть не может — по этому адресу не существует собеседника, и connect
     * либо уйдёт в свой же роутер (0.0.0.0 ядро трактует как локальный), либо в чужую сеть.
     * Раньше такой узел попадал в кандидаты, тратил попытки сторожа и давал ровно тот вид
     * отказа, которого в этом коде нет больше нигде: «узлов два, туннель не работает,
     * сказать нечего».
     *
     * Названная причина при этом ДОНОСИТ сообщение панели: skip_reason уезжает в интерфейс
     * вместе с примером, а примером служит имя узла — то есть человек читает «узел ведёт в
     * 0.0.0.0 — например „Неправильный клиент“» и понимает, что дело в панели, а не в
     * роутере.
     *
     * Проверяются только адреса, у которых собеседника не бывает В ПРИНЦИПЕ: не указан
     * (0.0.0.0, ::), локальная петля (127.0.0.0/8, ::1) и широковещательный. Частные сети
     * НЕ проверяются: узел в 10.0.0.0/8 — законная и рабочая настройка внутри своей сети или
     * поверх второго туннеля. */
    if (sl_host_leads_nowhere(n->host)) {
        /* Длина держится в пределах skip_reason (64 байта, а буква кириллицы это два):
         * обрезка причины по границе буфера разрубила бы букву посередине, и в JSON уехала
         * бы недобитая последовательность — ровно то, чем ломался вывод стенда в I-029. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->host);
        return 1;
    }

    /* Режим xhttp, которого мы не умеем, называется ЗДЕСЬ, а не выясняется при
     * подключении: непригодный узел не должен попадать в кандидаты и тратить попытки.
     *
     * Поддержаны все три ходовых:
     *
     *   stream-one — один запрос POST, тело запроса наверх, тело ответа вниз. Дешевле
     *     всех, и его же выбирает сам Xray при reality с mode=auto, поэтому «auto» ведёт
     *     сюда же;
     *   stream-up  — GET за загрузкой и длинный POST под выгрузку;
     *   packet-up  — GET за загрузкой и череда коротких POST по куску в каждом.
     *
     * Остаётся неподдержанным «stream-down» и всё незнакомое: у первого нет выгрузки
     * вовсе, он половина связки с отдельным download-сервером, которой у нас нет. */
    if (!strcmp(n->type, "xhttp") && n->mode[0] &&
        strcmp(n->mode, "auto") != 0 && strcmp(n->mode, "stream-one") != 0 &&
        strcmp(n->mode, "stream-up") != 0 && strcmp(n->mode, "packet-up") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "xhttp mode=%s не поддержан", n->mode);
        return 1;
    }
    return 0;
}

/* Отнести непригодный узел к его причине. Единственное место, где растёт skipped:
 * счётчик и объяснение обязаны сходиться, а два независимых инкремента — это ровно тот
 * случай, когда «пропущено 26» и «причин на 24 узла» уезжают друг от друга молча. */
void sl_skip_note(struct vless_sub_stats *st, const struct vless_node *n, const char *reason) {
    if (!st) return;
    st->skipped++;
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (!strcmp(st->reasons[i].reason, reason)) { st->reasons[i].count++; return; }
    }
    if (st->reasons_n >= VLESS_SKIP_REASONS) { st->reasons_dropped++; return; }
    struct vless_skip *s = &st->reasons[st->reasons_n++];
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
    /* Пример — чтобы причину можно было привязать к узлу в подписке. Имя есть не
     * всегда: во ссылке без '#' его нет вовсе, а у неразобранной ссылки может не быть
     * и host — тогда пример остаётся пустым, и это честнее выдуманного «узел 3». */
    if (n && n->name[0]) snprintf(s->example, sizeof(s->example), "%s", n->name);
    else if (n && n->host[0]) snprintf(s->example, sizeof(s->example), "%s:%u",
                                      n->host, n->port);
    s->count = 1;
}

