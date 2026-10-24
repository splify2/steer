/* Кэш ответов резолвера для имён под правилами (dns.cache, docs/spec-v2.md).
 *
 * ЗАЧЕМ. Имя под правилом при каждом новом запросе идёт наверх, а наверху теперь может быть
 * сервер за туннелем (DoH через выход) — круг в сотни миллисекунд. Клиентские кэши TTL уважают,
 * но их много (каждое устройство, каждое приложение свой), и десять устройств за час спросят одно
 * и то же имя десять раз. Кэш роутера снимает повторы, не меняя ответа: клиент получает то же
 * самое, что дал бы сервер, только раньше.
 *
 * ЧТО ЛОЖИТСЯ. Только настоящий ответ апстрима: NOERROR и NXDOMAIN, целиком (не TC), с одним
 * вопросом. Подмена fake-IP происходит ПОСЛЕ кэша, в upstream_answer, — ответ из кэша идёт тем же
 * путём, что ответ по сети, и сначала ставит подмену в ядро, потом отвечает клиенту. Кэш не даёт
 * «ответа из пула сразу»: он даёт настоящий адрес быстрее, а подмена по-прежнему строгая.
 *
 * СРОК. Срок записи — наименьший TTL записей ответа, зажатый между dns.cache_ttl.min и .max;
 * у отрицательного ответа (NXDOMAIN или пустой) — dns.cache_ttl.negative. Зажатые TTL
 * ПЕРЕПИСЫВАЮТСЯ в самом ответе, и при выдаче из кэша уменьшаются на возраст записи. Это нужно для
 * real-ip: адрес из ответа резолвер кладёт в набор правила на срок TTL из ответа, а клиенту
 * говорит тот же TTL, — они кончаются одновременно. Отдай кэш ответ со старым TTL, набор
 * продержал бы чужой адрес дольше, чем правило его разрешает, а клиент считал бы его
 * действительным ещё столько же. С уменьшением на возраст такого расхождения нет по построению.
 * Из-за него же ключ — не только имя и тип, но и номер апстрима: один и тот же вопрос у двух
 * серверов (например, у разных стран) — два разных ответа.
 *
 * ПАМЯТЬ. Записей не больше dns.cache. Таблица — корзины по четыре места; при переполнении
 * корзины вытесняется запись с ближайшим концом срока. Каждая запись — два malloc (заголовок с
 * именем и сам ответ), ответ до DC_MAXWIRE (4096) байт — всё, что проходит датаграммным путём; больше не кладётся.
 * Не потоко-безопасен: цикл резолвера однопоточный. */

#include "dnsd_int.h"
#include "dup.h"

#define DC_WAYS 4
/* Ответ из кэша выдаётся тем же путём, что ответ апстрима по датаграмме, а он — не длиннее MAX_PKT
 * (proxy.c): больше в кэш класть нечего, оно не вышло бы обратно. Прежние 1232 резали ответы EDNS
 * побольше (DNSKEY, длинные TXT, много A) без причины. */
#define DC_MAXWIRE 4096

struct dent {
    uint32_t h;
    uint16_t up, qtype, qclass;
    uint16_t len;
    uint8_t nlen;
    long exp, stored;
    uint8_t *data;
    char name[];
};

static struct dent **g_tab;
static size_t g_nb;                     /* корзин */
static struct dcache_cfg g_cfg;
static unsigned long g_hits, g_miss, g_puts, g_evict;
static size_t g_n;

int dcache_on(void) { return g_tab != NULL; }

static void ent_free(struct dent *e) {
    if (!e) return;
    free(e->data);
    free(e);
}

void dcache_flush(void) {
    if (!g_tab) return;
    for (size_t i = 0; i < g_nb * DC_WAYS; i++) { ent_free(g_tab[i]); g_tab[i] = NULL; }
    g_n = 0;
}

void dcache_config(const struct dcache_cfg *c) {
    dcache_flush();
    free(g_tab);
    g_tab = NULL;
    g_nb = 0;
    g_cfg = *c;
    if (c->entries <= 0) return;
    g_nb = ((size_t)c->entries + DC_WAYS - 1) / DC_WAYS;
    g_tab = calloc(g_nb * DC_WAYS, sizeof(*g_tab));
    if (!g_tab) g_nb = 0;
}

/* Имя в проводе (без сжатия, как в секции вопроса) -> строка строчными буквами через точки;
 * возвращает смещение за именем или -1. */
static long qname_lower(const uint8_t *p, size_t n, size_t off, char *out, size_t cap, size_t *len) {
    size_t o = 0;
    for (;;) {
        if (off >= n) return -1;
        uint8_t l = p[off++];
        if (!l) break;
        if (l & 0xC0) return -1;
        if (off + l > n || o + l + 2 > cap) return -1;
        if (o) out[o++] = '.';
        for (uint8_t i = 0; i < l; i++) out[o++] = (char)tolower(p[off + i]);
        off += l;
    }
    out[o] = '\0';
    *len = o;
    return (long)off;
}

/* Смещение за именем в ответе (допускает сжатие); -1 — испорчено. */
static long skip_name(const uint8_t *p, size_t n, size_t off) {
    for (;;) {
        if (off >= n) return -1;
        uint8_t l = p[off];
        if (!l) return (long)off + 1;
        if ((l & 0xC0) == 0xC0) return off + 2 <= n ? (long)off + 2 : -1;
        if (l & 0xC0) return -1;
        off += 1u + l;
    }
}

static uint32_t key_hash(unsigned up, const char *name, size_t nl, unsigned qt, unsigned qc) {
    uint32_t h = 2166136261u ^ up;
    for (size_t i = 0; i < nl; i++) h = (h ^ (uint8_t)name[i]) * 16777619u;
    h = (h ^ qt) * 16777619u;
    return (h ^ qc) * 16777619u;
}

/* Обход записей ответа. Для каждой (кроме OPT) зовёт fn(ttl_ptr, section, ctx). */
typedef void (*rr_fn)(uint8_t *ttl, int section, void *ctx);
static int rr_walk(uint8_t *p, size_t n, rr_fn fn, void *ctx) {
    if (n < 12) return -1;
    unsigned qd = (p[4] << 8) | p[5];
    unsigned cnt[3] = { (unsigned)((p[6] << 8) | p[7]), (unsigned)((p[8] << 8) | p[9]),
                        (unsigned)((p[10] << 8) | p[11]) };
    size_t off = 12;
    for (unsigned i = 0; i < qd; i++) {
        long o = skip_name(p, n, off);
        if (o < 0 || (size_t)o + 4 > n) return -1;
        off = (size_t)o + 4;
    }
    for (int s = 0; s < 3; s++)
        for (unsigned i = 0; i < cnt[s]; i++) {
            long o = skip_name(p, n, off);
            if (o < 0 || (size_t)o + 10 > n) return -1;
            unsigned type = (p[o] << 8) | p[o + 1];
            unsigned rdl = (p[o + 8] << 8) | p[o + 9];
            if ((size_t)o + 10 + rdl > n) return -1;
            if (type != 41) fn(p + o + 4, s, ctx);
            off = (size_t)o + 10 + rdl;
        }
    return 0;
}

static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

struct scan { uint32_t min; int any; };
static void scan_min(uint8_t *ttl, int section, void *ctx) {
    struct scan *s = ctx;
    if (section == 2) return;                /* дополнительная секция срока не задаёт */
    uint32_t t = get32(ttl);
    if (!s->any || t < s->min) s->min = t;
    s->any = 1;
}

struct clampctx { uint32_t lo, hi, cap; };
static void clamp_ttl(uint8_t *ttl, int section, void *ctx) {
    (void)section;
    struct clampctx *c = ctx;
    uint32_t t = get32(ttl);
    if (t < c->lo) t = c->lo;
    if (t > c->hi) t = c->hi;
    if (c->cap && t > c->cap) t = c->cap;
    put32(ttl, t);
}

struct agectx { uint32_t age, rem; };
static void age_ttl(uint8_t *ttl, int section, void *ctx) {
    (void)section;
    struct agectx *a = ctx;
    uint32_t t = get32(ttl);
    t = t > a->age ? t - a->age : 1;
    if (t > a->rem) t = a->rem;
    if (t < 1) t = 1;
    put32(ttl, t);
}

int dcache_put(unsigned up, const uint8_t *ans, size_t n, long now_s) {
    if (!g_tab || n < 12 || n > DC_MAXWIRE) return 0;
    if (!(ans[2] & 0x80) || (ans[2] & 0x02)) return 0;             /* не ответ или усечён */
    unsigned rcode = ans[3] & 0x0F;
    if (rcode != 0 && rcode != 3) return 0;                        /* SERVFAIL и прочее не кэшируем */
    if (((ans[4] << 8) | ans[5]) != 1) return 0;
    char name[256];
    size_t nl = 0;
    long qo = qname_lower(ans, n, 12, name, sizeof(name), &nl);
    if (qo < 0 || (size_t)qo + 4 > n) return 0;
    unsigned qt = (ans[qo] << 8) | ans[qo + 1], qc = (ans[qo + 2] << 8) | ans[qo + 3];
    int neg = rcode == 3 || (((ans[6] << 8) | ans[7]) == 0);
    /* Черновик для правки сроков — общий и растущий, а не 64 КиБ на стеке ради редкого большого ответа. */
    static uint8_t *scratch;
    static size_t scratch_cap;
    if (n > scratch_cap) {
        uint8_t *ns = realloc(scratch, n < 2048 ? 2048 : n);
        if (!ns) return 0;
        scratch = ns;
        scratch_cap = n < 2048 ? 2048 : n;
    }
    uint8_t *tmp = scratch;
    memcpy(tmp, ans, n);
    uint32_t ttl;
    if (neg) {
        ttl = (uint32_t)g_cfg.ttl_neg;
    } else {
        struct scan sc = { 0, 0 };
        if (rr_walk(tmp, n, scan_min, &sc) != 0 || !sc.any) return 0;
        ttl = sc.min;
        if (ttl < (uint32_t)g_cfg.ttl_min) ttl = (uint32_t)g_cfg.ttl_min;
        if (ttl > (uint32_t)g_cfg.ttl_max) ttl = (uint32_t)g_cfg.ttl_max;
    }
    if (!ttl) return 0;
    struct clampctx cc = { (uint32_t)g_cfg.ttl_min, (uint32_t)g_cfg.ttl_max, neg ? ttl : 0 };
    if (neg) cc.lo = 0;
    if (rr_walk(tmp, n, clamp_ttl, &cc) != 0) return 0;

    uint32_t h = key_hash(up, name, nl, qt, qc);
    struct dent **b = &g_tab[(h % g_nb) * DC_WAYS];
    struct dent **slot = NULL;
    for (int i = 0; i < DC_WAYS; i++) {
        if (b[i] && b[i]->h == h && b[i]->up == up && b[i]->qtype == qt && b[i]->qclass == qc &&
            b[i]->nlen == nl && !memcmp(b[i]->name, name, nl)) { slot = &b[i]; break; }
    }
    if (!slot)
        for (int i = 0; i < DC_WAYS; i++)
            if (!b[i] || b[i]->exp <= now_s) { slot = &b[i]; break; }
    if (!slot) {
        slot = &b[0];
        for (int i = 1; i < DC_WAYS; i++) if (b[i]->exp < (*slot)->exp) slot = &b[i];
        g_evict++;
    }
    if (*slot) { ent_free(*slot); g_n--; *slot = NULL; }
    struct dent *e = malloc(sizeof(*e) + nl + 1);
    uint8_t *d = e ? malloc(n) : NULL;
    if (!e || !d) { free(e); free(d); return 0; }
    e->h = h; e->up = (uint16_t)up; e->qtype = (uint16_t)qt; e->qclass = (uint16_t)qc;
    e->len = (uint16_t)n; e->nlen = (uint8_t)nl;
    e->exp = now_s + (long)ttl; e->stored = now_s;
    memcpy(e->name, name, nl + 1);
    memcpy(d, tmp, n);
    e->data = d;
    *slot = e;
    g_n++;
    g_puts++;
    return 1;
}

size_t dcache_get(unsigned up, const uint8_t *q, size_t qn, uint8_t *out, size_t cap, long now_s) {
    if (!g_tab || qn < 17) return 0;
    if (((q[4] << 8) | q[5]) != 1 || (q[2] & 0x80)) return 0;
    char name[256];
    size_t nl = 0;
    long qo = qname_lower(q, qn, 12, name, sizeof(name), &nl);
    if (qo < 0 || (size_t)qo + 4 > qn) return 0;
    unsigned qt = (q[qo] << 8) | q[qo + 1], qc = (q[qo + 2] << 8) | q[qo + 3];
    uint32_t h = key_hash(up, name, nl, qt, qc);
    struct dent **b = &g_tab[(h % g_nb) * DC_WAYS];
    for (int i = 0; i < DC_WAYS; i++) {
        struct dent *e = b[i];
        if (!e || e->h != h || e->up != up || e->qtype != qt || e->qclass != qc || e->nlen != nl ||
            memcmp(e->name, name, nl))
            continue;
        if (e->exp <= now_s) { ent_free(e); b[i] = NULL; g_n--; break; }
        long eo = skip_name(e->data, e->len, 12);
        if (e->len > cap || eo != qo) break;      /* имя той же длины — вопрос совпал по построению */
        memcpy(out, e->data, e->len);
        /* Номер и вопрос — как у спрашивающего (регистр имени у клиентов с DNS-0x20 свой). */
        out[0] = q[0]; out[1] = q[1];
        memcpy(out + 12, q + 12, (size_t)qo + 4 - 12);
        struct agectx a = { (uint32_t)(now_s - e->stored), (uint32_t)(e->exp - now_s) };
        rr_walk(out, e->len, age_ttl, &a);
        g_hits++;
        return e->len;
    }
    g_miss++;
    return 0;
}

void dcache_render(FILE *f) {
    fprintf(f, "{\"entries\":%zu,\"max\":%zu,\"hits\":%lu,\"misses\":%lu,\"stored\":%lu,"
               "\"evicted\":%lu}", g_n, g_nb * DC_WAYS, g_hits, g_miss, g_puts, g_evict);
}
