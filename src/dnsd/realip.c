#include "dnsd_int.h"

/* ---- real-ip: память выданных элементов со сроком -------------------------------------------
 *
 * ЗАЧЕМ. Канал в режиме realip кладёт в свой набор (и в парный «<набор>6») НАСТОЯЩИЕ адреса из
 * ответа DNS — элементом со сроком, равным TTL записи (proxy.c, ветка real-IP). apply, меняющий
 * набор правил, заменяет таблицу nftables целиком (src/daemon/apply.c, «ЗАМЕНА ТАБЛИЦЫ»), и
 * наборы каналов приходят в ней пустыми. Постоянные элементы fake-IP резолвер возвращает сразу
 * (fakeip_rehydrate, df46f82), а элементы real-ip возвращались только со следующим ответом DNS
 * на это имя: клиент с адресом в кэше до конца TTL шёл напрямую, мимо выхода канала. Проверка
 * 1.9 на QEMU-роутере.
 *
 * ЧТО ХРАНИТСЯ. По записи на (имя, семейство, адрес): имя нижним регистром — по нему после новой
 * таблицы заново выводятся каналы (как у fake-IP: набор каналов и его имена могли смениться, и
 * помнить номер канала бессмысленно) и сужение составного набора (dch_add, dch_boxes); адрес;
 * монотонный срок. Проход после таблицы ставит каждый живой элемент в каждый совпавший канал
 * real-ip с ОСТАВШИМСЯ сроком — ровно столько, сколько клиент ещё держит ответ в кэше. Элемент,
 * уцелевший в ядре, от повторной вставки не страдает.
 *
 * ГДЕ. Только в памяти, не на диске: срок — минуты, запись на флеш ради них — дороже пользы, а
 * перезапуск резолвера (stop службы) снимает таблицу nftables вместе с наборами всё равно.
 * Демон, упав, резолвер не уносит (adopt.c), поэтому память переживает и его перезапуск.
 *
 * ПРЕДЕЛА ПО ЧИСЛУ ЗАПИСЕЙ НЕТ. Запись живёт ровно срок ответа (set_ttl_clamp), потом уходит при
 * проходе очистки — тот делается, когда записей вдвое больше, чем осталось после прошлого
 * (и при каждой пересборке таблицы), так что стоимость размазана, а память — это адреса,
 * которые клиенты ещё держат. Прежде 2048 записей с тихим вытеснением самых ранних оставляли
 * клиентов с адресом в кэше без набора на сервере с сотнями клиентов. Поиск повтора — по
 * открытому хэшу (индекс пересобирается при очистке и росте), а не линейным проходом. */

struct realip_ent {
    char *domain;
    uint32_t hash;
    uint8_t v6;
    uint8_t addr[16];           /* IPv4 — первые 4 байта, порядок сети */
    time_t expires;             /* CLOCK_MONOTONIC, секунды */
};

static struct realip_ent *g_ri;
static size_t g_ri_n, g_ri_cap;
static uint32_t *g_ri_ix;               /* открытый хэш: номер записи + 1, 0 — пусто */
static size_t g_ri_ixn;                 /* размер индекса — степень двойки, не меньше 2·g_ri_cap */
static size_t g_ri_purge_at = 64;       /* при скольких записях чистить в следующий раз */

static time_t ri_mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec;
}

static void ri_drop(size_t i) {
    free(g_ri[i].domain);
    g_ri[i] = g_ri[--g_ri_n];
}

static int ri_same(const struct realip_ent *e, uint32_t h, int v6, const uint8_t *addr,
                   size_t alen, const char *qname) {
    return e->hash == h && e->v6 == v6 && !memcmp(e->addr, addr, alen) && !strcmp(e->domain, qname);
}

/* Индекс заново по всем записям (после сдвигов ri_drop и при росте). Нет памяти — индекса нет,
 * и ri_note ищет линейно, как раньше: медленнее, но верно. */
static void ri_reindex(void) {
    free(g_ri_ix);
    g_ri_ix = NULL;
    g_ri_ixn = 0;
    size_t n = 64;
    while (n < g_ri_cap * 2) n <<= 1;
    g_ri_ix = calloc(n, sizeof(*g_ri_ix));
    if (!g_ri_ix) return;
    g_ri_ixn = n;
    for (size_t i = 0; i < g_ri_n; i++) {
        size_t k = g_ri[i].hash & (n - 1);
        while (g_ri_ix[k]) k = (k + 1) & (n - 1);
        g_ri_ix[k] = (uint32_t)(i + 1);
    }
}

static void ri_purge(time_t now) {
    for (size_t i = 0; i < g_ri_n;)
        if (g_ri[i].expires <= now) ri_drop(i);
        else i++;
    ri_reindex();
    g_ri_purge_at = g_ri_n * 2 < 64 ? 64 : g_ri_n * 2;
}

/* Запомнить элемент (qname — уже нижним регистром, proxy.c). ttl — тот, с которым элемент лёг
 * в набор (set_ttl_clamp). Повторный ответ продлевает срок — клиент получил тот же адрес заново. */
static void ri_note(const char *qname, int v6, const uint8_t *addr, uint32_t ttl) {
    size_t alen = v6 ? 16 : 4;
    uint32_t h = sidx_hash(qname);
    time_t now = ri_mono();
    time_t exp = now + (time_t)ttl;
    if (g_ri_ixn) {
        for (size_t k = h & (g_ri_ixn - 1); g_ri_ix[k]; k = (k + 1) & (g_ri_ixn - 1)) {
            struct realip_ent *e = &g_ri[g_ri_ix[k] - 1];
            if (ri_same(e, h, v6, addr, alen, qname)) {
                if (exp > e->expires) e->expires = exp;
                return;
            }
        }
    } else {
        for (size_t i = 0; i < g_ri_n; i++) {
            struct realip_ent *e = &g_ri[i];
            if (ri_same(e, h, v6, addr, alen, qname)) {
                if (exp > e->expires) e->expires = exp;
                return;
            }
        }
    }
    if (g_ri_n >= g_ri_purge_at) ri_purge(now);
    if (g_ri_n == g_ri_cap) {
        size_t c = g_ri_cap ? g_ri_cap * 2 : 64;
        struct realip_ent *q = realloc(g_ri, c * sizeof(*q));
        if (!q) return;
        g_ri = q;
        g_ri_cap = c;
        ri_reindex();
    }
    char *d = strdup(qname);
    if (!d) return;
    struct realip_ent *e = &g_ri[g_ri_n++];
    memset(e, 0, sizeof(*e));
    e->domain = d;
    e->hash = h;
    e->v6 = (uint8_t)(v6 != 0);
    memcpy(e->addr, addr, alen);
    e->expires = exp;
    if (g_ri_ixn) {
        size_t k = h & (g_ri_ixn - 1);
        while (g_ri_ix[k]) k = (k + 1) & (g_ri_ixn - 1);
        g_ri_ix[k] = (uint32_t)g_ri_n;
    }
}

void realip_note(const char *qname, uint32_t addr_host, uint32_t ttl) {
    uint32_t n = htonl(addr_host);
    ri_note(qname, 0, (const uint8_t *)&n, ttl);
}

void realip_note6(const char *qname, const uint8_t addr[16], uint32_t ttl) {
    ri_note(qname, 1, addr, ttl);
}

/* Вернуть в наборы каналов real-ip все живые элементы — с оставшимся сроком. Каналы выводятся
 * заново тем же правилом, что у ответа (proxy.c): IPv4 — во все совпавшие каналы real-ip с
 * половиной IPv4; IPv6 — только если у ВСЕХ совпавших каналов есть половина IPv6 (иначе на AAAA
 * имени теперь отвечают пустым ответом, и адресу в наборе делать нечего). Имя, больше не
 * входящее ни в один канал real-ip, из памяти уходит. Возвращает число вставок. */
/* Сколько элементов помнится сейчас (для проверки). */
size_t realip_count(void) { return g_ri_n; }

size_t realip_reassert(void) {
    time_t now = ri_mono();
    ri_purge(now);
    size_t put = 0;
    for (size_t i = 0; i < g_ri_n;) {
        struct realip_ent *e = &g_ri[i];
        chm_t all = dch_match_mask(e->domain);
        chm_t m = 0;
        for (size_t c = 0; c < g_dch_n; c++) {
            if (!chm_has(all, c) || !g_dch[c].realip) continue;
            if (!(g_dch[c].fam & (e->v6 ? DCH_V6 : DCH_V4))) continue;
            m = chm_or(m, chm_one(c));
        }
        if (e->v6 && !dch_all_v6(all)) m = 0;
        if (!m) { ri_drop(i); continue; }
        uint32_t left = (uint32_t)(e->expires - now);
        if (left < 1) left = 1;
        for (size_t c = 0; c < g_dch_n; c++) {
            if (!chm_has(m, c)) continue;
            if (e->v6) {
                dch_add6(c, e->domain, e->addr, left);
            } else {
                uint32_t a;
                memcpy(&a, e->addr, 4);
                dch_add(c, e->domain, ntohl(a), left);
            }
            put++;
        }
        i++;
    }
    ri_reindex();
    return put;
}
