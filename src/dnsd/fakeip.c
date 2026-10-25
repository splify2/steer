#include "dnsd_int.h"
#include "nftnl.h"
#include "srs.h"
#include "ctnl.h"
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <pthread.h>

/* ---------------------------------------------------------------------- */
/* fake-IP pool: one stable, exclusive synthetic IPv4 per matched domain    */
/* ---------------------------------------------------------------------- */
/* Real CDN-fronted IPs (Cloudflare etc.) are shared across many unrelated
 * customer domains from a dynamic anycast pool — there is no fixed 1:1
 * domain->IP mapping, so tagging the real resolved IP into a set (as
 * nft_add_element above does) is collision-prone: two configured domains
 * can end up sharing one real IP, and then whichever one's set entry is
 * freshest decides routing for BOTH. Handing the client a synthetic IP that
 * THIS daemon allocates and owns 1:1 per domain makes that collision
 * structurally impossible, and — since the decision is made from the DNS
 * question name, always visible in plaintext — sidesteps ECH entirely (no
 * TLS/SNI parsing needed at all). Pool: 198.18.0.0/15, the RFC 2544
 * benchmarking range, the same convention already used by Clash/sing-box/
 * mihomo for this exact purpose; effectively never a real destination. */
/* FAKEIP_POOL_BASE/SIZE — в dnsd_int.h. */

/* ПУЛ fake-IP v6 (docs/architecture.md, «4б»): fdfe:dcba:9876::/96, и адрес — это поддельный IPv4
 * той же записи в младших 32 битах (fakeip6_of, spec.h): у youtube.com с 198.18.0.5 поддельный
 * IPv6 — fdfe:dcba:9876::c612:5.
 *
 * ПОЧЕМУ ТАКОЙ ПРЕФИКС. Уникальный локальный адрес (fc00::/7, RFC 4193) в интернете не
 * маршрутизируется, то есть настоящим назначением не бывает никогда — то же свойство, ради
 * которого у IPv4 взят 198.18.0.0/15. Сам префикс — тот же, что у mihomo (fake-ip-range6), по той
 * же причине, по которой пул IPv4 совпадает с Clash и sing-box: это соглашение, и с настоящей
 * сетью оно не столкнётся — локальный префикс роутера (ula_prefix OpenWrt) выбирается случайно из
 * 2^40 вариантов. Половина fd00::/8, а не fc00::/8, как у sing-box: fc00::/8 зарезервирована под
 * централизованную раздачу, и что с ней сделает завтрашний стек, не знает никто.
 *
 * ПОЧЕМУ ПАРА К IPv4, А НЕ СВОЯ ВЫДАЧА. Запись домена одна, и адресов у неё два: выдавать их
 * отдельно — значит держать второй счётчик, вторую верхнюю отметку, второе поле «пул исчерпан» и
 * следить, чтобы у домена не оказалось IPv6 от одной записи и IPv4 от другой. Пара выводится из
 * адреса IPv4, поэтому хранить её не надо вовсе (в файле состояния — только настоящий IPv6), по
 * ней explain сразу называет домен, а адреса сети и последнего у неё нет по той же причине, что у
 * IPv4 (выдача начинается с 1 и не доходит до последнего). /96 — место под все 2^32 адресов, хотя
 * заняты из них только 2^17 пула IPv4. */
const char *g_fakeip6_map = "fakeip6";

struct fakeip_table g_fakeip;
const char *g_fakeip_state_path;

/* Индекс домен -> номер записи. Тот же приём, что у правил, и по той же причине: без него
 * каждый ответ стоил трёх переборов таблицы со сравнением строк, а загрузка состояния была
 * квадратичной — файл на 5000 записей означал 12,5 миллиона сравнений при старте. */
struct sindex g_fakeip_idx;

static const char *fakeip_key(const void *owner, uint32_t idx) {
    return ((const struct fakeip_table *)owner)->entries[idx].domain;
}

/* Номер записи домена или -1. Единственное место поиска: три прежних копии этого перебора
 * (найти, прочитать реальный адрес, записать его) разошлись бы при первом же изменении. */
long fakeip_find(const char *domain) {
    uint32_t hit = sindex_get(&g_fakeip_idx, &g_fakeip, fakeip_key, domain);
    return hit ? (long)((hit & SIDX_IDX_MASK) - 1) : -1;
}

static uint32_t fakeip_index_to_addr(size_t idx) { return FAKEIP_POOL_BASE + (uint32_t)idx; }

/* Next pool index to hand out — a HIGH-WATER MARK, not the entry count.
 *
 * Deriving the index from t->n only works while the file is a dense 0..n-1
 * prefix, and it is not: the --fakeip CLI appends an entry it just looked up, so
 * a duplicate line is normal, and a skipped (malformed) line leaves a hole. With
 * a count-based index, `a -> .3` alone in the file makes the fourth new domain
 * allocate .3 as well — two domains on ONE fake IP, whose DNAT entry then points
 * at whichever was inserted last, i.e. one of them silently reaches the other's
 * site.
 *
 * Starts at 1, not 0: index 0 is 198.18.0.0 — the network address of the pool, which some
 * stacks and tools treat as unusable (found on Cuttlefish, Android 16). The last index is
 * skipped for the same reason (see the exhaustion check in fakeip_lookup_or_alloc). An old
 * state file that already maps a domain to .0 is loaded as is — no migration. */
size_t g_fakeip_next = 1;

static int fakeip_table_add(struct fakeip_table *t, const char *domain, uint32_t addr) {
    if (t->n == t->cap) {
        size_t newcap = t->cap ? t->cap * 2 : 64;
        struct fakeip_entry *ne = realloc(t->entries, newcap * sizeof(*ne));
        if (!ne) return -1;
        t->entries = ne;
        t->cap = newcap;
    }
    t->entries[t->n].domain = strdup(domain);
    if (!t->entries[t->n].domain) return -1;
    t->entries[t->n].addr = addr;
    t->entries[t->n].last_used = time(NULL);
    t->entries[t->n].real_host = 0;
    t->entries[t->n].real_saved = 0;
    t->entries[t->n].has_real6_saved = 0;
    t->entries[t->n].sets = 0;            /* unknown until the resolver routes it */
    t->entries[t->n].route_asserted = 0;
    t->entries[t->n].refreshed = 0;
    memset(t->entries[t->n].real6, 0, 16);
    t->entries[t->n].has_real6 = 0;
    t->entries[t->n].sets6 = 0;
    t->entries[t->n].route6_asserted = 0;
    t->entries[t->n].refreshed6 = 0;
    t->n++;
    if (t == &g_fakeip &&
        sindex_put(&g_fakeip_idx, t, fakeip_key, t->entries[t->n - 1].domain,
                   (uint32_t)(t->n - 1), 0) != 0) {
        /* Индекс не вырос — запись всё равно добавлена, но найти её будет нечем. Честнее
         * откатить, чем оставить домен, который существует и не находится: иначе он получит
         * второй адрес при следующем запросе, а DNAT будет показывать на один из них. */
        free(t->entries[t->n - 1].domain);
        t->n--;
        return -1;
    }
    if (addr >= FAKEIP_POOL_BASE && addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE) {
        size_t idx = (size_t)(addr - FAKEIP_POOL_BASE);
        if (idx + 1 > g_fakeip_next) g_fakeip_next = idx + 1;
    }
    return 0;
}

/* 0 iff DOMAIN already has an allocation. */
static int fakeip_table_has(const struct fakeip_table *t, const char *domain) {
    (void)t;
    return fakeip_find(domain) >= 0 ? 0 : -1;
}

/* State file format: one entry per line.
 *   domain\tfake_ip            (legacy / --fakeip CLI output)
 *   domain\tfake_ip\treal_ip   (extended: real backend, for post-restart rehydrate)
 *   domain\tfake_ip\treal_ip\treal_ip6
 *   domain\tfake_ip\t-\treal_ip6
 *                              (1.9, fake-IP v6: настоящий IPv6 под элементом карты fakeip6;
 *                               «-» — настоящий IPv4 не известен. Поддельный IPv6 не пишется —
 *                               он выводится из fake_ip, см. шапку файла)
 * Missing file -> empty table, not an error (first run). A malformed line is
 * skipped, not fatal — the domain simply gets re-allocated (a fresh index) on
 * the next match. The legacy 2-field form is parsed identically to before, so
 * an existing state file upgrades transparently. Испорченное четвёртое поле строку не
 * отвергает: пропадает только настоящий IPv6, и первый AAAA спросит его заново. */
void fakeip_state_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[MAX_HOSTNAME + 128];          /* имя, два адреса IPv4, IPv6 и табуляции */
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *tab1 = strchr(line, '\t');
        if (!tab1) continue;
        *tab1 = '\0';
        /* Terminate the fake-IP field BEFORE parsing it. inet_aton() rejects a
         * string with anything after the address, so reading the 3-field form
         * without cutting at the second tab fed it "198.18.0.0\t104.20.39.144"
         * and skipped the line — and since the daemon REWRITES the file in the
         * 3-field form as soon as a domain's real backend is known, that made
         * every restart lose the whole table. Consequences, in order of how much
         * they hurt: fake IPs are handed out again from the start of the pool, so
         * an address a client still has cached now DNATs to a DIFFERENT site's
         * backend; the rehydrate pass below never had anything to rehydrate; and
         * the first query per domain after a restart relays the real answer. */
        char *fake_s = tab1 + 1;
        char *tab2 = strchr(fake_s, '\t');
        if (tab2) *tab2 = '\0';
        struct in_addr a;
        if (inet_aton(fake_s, &a) == 0) continue;
        /* Адрес вне пула — брак строки, а не запись: одна такая строка (203.0.113.5) ставила
         * верхнюю отметку пула за его край, и каждый новый домен получал «пул исчерпан»
         * навсегда, а сам чужой адрес выдавался клиентам как поддельный. */
        if (ntohl(a.s_addr) < FAKEIP_POOL_BASE ||
            ntohl(a.s_addr) >= FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE) continue;
        /* Keep the FIRST allocation for a domain: a duplicate line is expected
         * (the --fakeip CLI appends what it looked up), and adding it twice would
         * both bloat the table and, before the high-water mark above, corrupt the
         * next index. */
        if (fakeip_table_has(&g_fakeip, line) == 0) continue;
        if (fakeip_table_add(&g_fakeip, line, ntohl(a.s_addr)) != 0) continue;

        if (tab2) { /* optional third field: last-seen real backend */
            char *real_s = tab2 + 1;
            char *tab3 = strchr(real_s, '\t');
            if (tab3) *tab3 = '\0';
            struct in_addr r;
            /* И «в ядре» (real_host — до rehydrate, который подтвердит его или обнулит), и «знаем»
             * (real_saved — до следующего ответа; неудачная запись в ядро его не трогает, см.
             * struct fakeip_entry). */
            if (inet_aton(real_s, &r) != 0)
                g_fakeip.entries[g_fakeip.n - 1].real_host =
                    g_fakeip.entries[g_fakeip.n - 1].real_saved = ntohl(r.s_addr);
            uint8_t r6[16];
            if (tab3 && inet_pton(AF_INET6, tab3 + 1, r6) == 1) {
                memcpy(g_fakeip.entries[g_fakeip.n - 1].real6, r6, 16);
                g_fakeip.entries[g_fakeip.n - 1].has_real6 = 1;
                g_fakeip.entries[g_fakeip.n - 1].has_real6_saved = 1;
            }
        }
    }
    fclose(f);
}

static int fakeip_writer_active(void);

static void fakeip_state_append(const char *path, const char *domain, uint32_t addr) {
    /* Поток записи (ниже) держит снимок, снятый ДО этого имени, и его rename затёр бы дописанную строку:
     * имя пропало бы из файла, а флаг «грязно» уже снят. Строка не дописывается — таблица грязная, и ближайшая
     * перезапись (по сроку, по просьбе загрузчика, при выходе) унесёт имя в файл вместе со всеми. */
    if (fakeip_writer_active()) { g_fakeip_dirty = 1; return; }
    FILE *f = fopen(path, "a");
    if (!f) return;
    struct in_addr a; a.s_addr = htonl(addr);
    char ipstr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr)))
        fprintf(f, "%s\t%s\n", domain, ipstr);
    fclose(f);
}

/* Rewrites the whole state file from g_fakeip in the extended 3-field format.
 * Called after we learn a fresh real_ip for an already-allocated domain, so
 * the next restart can rehydrate the DNAT map without re-resolving. Best-effort
 * (atomic via rename); a failure just means a later restart re-resolves. */
/* Содержимое файла состояния из g_fakeip — в памяти, без ввода-вывода (строки — формат выше). NULL — нет
 * памяти. Вызывающий освобождает. */
static char *fakeip_state_serialize(size_t *len) {
    char *buf = NULL;
    FILE *f = open_memstream(&buf, len);
    if (!f) return NULL;
    for (size_t i = 0; i < g_fakeip.n; i++) {
        const struct fakeip_entry *en = &g_fakeip.entries[i];
        struct in_addr fa; fa.s_addr = htonl(en->addr);
        char fstr[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &fa, fstr, sizeof(fstr))) continue;
        /* Пишется то, что ЗНАЕМ, а не только то, что стоит в ядре (struct fakeip_entry,
         * real_saved): отказ ядра — не повод забыть адрес, по которому следующая замена набора
         * правил засеет карту. */
        char rstr[INET_ADDRSTRLEN] = "";
        uint32_t real = en->real_host ? en->real_host : en->real_saved;
        if (real) {
            struct in_addr ra; ra.s_addr = htonl(real);
            if (!inet_ntop(AF_INET, &ra, rstr, sizeof(rstr))) rstr[0] = '\0';
        }
        char r6str[INET6_ADDRSTRLEN] = "";
        if ((en->has_real6 || en->has_real6_saved) &&
            !inet_ntop(AF_INET6, en->real6, r6str, sizeof(r6str)))
            r6str[0] = '\0';
        /* Строка без IPv6 — прежней формы до байта: файл, который пишет движок без IPv6 в
         * доменных правилах, не меняется. */
        if (r6str[0])
            fprintf(f, "%s\t%s\t%s\t%s\n", en->domain, fstr, rstr[0] ? rstr : "-", r6str);
        else if (rstr[0])
            fprintf(f, "%s\t%s\t%s\n", en->domain, fstr, rstr);
        else
            fprintf(f, "%s\t%s\n", en->domain, fstr);
    }
    if (fclose(f) != 0) { free(buf); return NULL; }
    return buf;
}

/* Записать содержимое в файл состояния атомарно: временный файл, fsync, rename. Может стоять на носителе
 * сотни миллисекунд (флеш), поэтому из цикла резолвера её не зовут — только синхронные места (fakeip_state_flush)
 * и поток записи (ниже). */
static void fakeip_state_store(const char *path, const char *buf, size_t len) {
    /* Буфер — по длине ПУТИ, а не имени хоста: путь состояния задаёт снаружи
     * (--state-file/--state-dir), и обрезка «%s.tmp» на произвольном месте давала
     * чужое имя — от несуществующего до самого файла состояния или существующего
     * каталога. Обрезка проверяется явно: писать некуда лучше, чем писать не туда. */
    char tmp[PATH_MAX];
    int need = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (need < 0 || (size_t)need >= sizeof(tmp)) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    if (len && fwrite(buf, 1, len, f) != len) { fclose(f); unlink(tmp); return; }
    /* Данные должны лечь на носитель ДО rename: иначе отключение питания между
     * rename и фактической записью оставляет пустой state-файл — ровно ту
     * потерю всей таблицы, от которой защищается разбор в fakeip_state_load. */
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return;
    }
    fclose(f);
    if (rename(tmp, path) != 0)
        unlink(tmp);
}

/* ПОТОК ЗАПИСИ (I-534). Перезапись с fsync в цикле резолвера останавливала все вопросы клиентов на время записи
 * на носитель — на флеше это десятки и сотни миллисекунд раз в FAKEIP_ANSWER_TTL. Теперь цикл только
 * сериализует таблицу в память (процессор, без ввода-вывода) и передаёт буфер потоку, который пишет, делает fsync и
 * rename. Передаётся последний снимок: пока поток занят, следующий просто заменяет ожидающий. Места, где файл
 * должен лежать на носителе СЕЙЧАС (засев по просьбе загрузчика, выход резолвера), ждут поток
 * (fakeip_state_wait) и пишут сами. */
static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    char *buf;                  /* ожидающий снимок */
    size_t len;
    char *path;                 /* копия пути: g_fakeip_state_path меняется только при старте, но поток живёт дольше */
    int busy;                   /* поток пишет сейчас */
    int started;
} g_fw = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };

static void *fakeip_writer(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_fw.mu);
    for (;;) {
        while (!g_fw.buf) pthread_cond_wait(&g_fw.cv, &g_fw.mu);
        char *buf = g_fw.buf;
        size_t len = g_fw.len;
        char *path = g_fw.path;
        g_fw.buf = NULL;
        g_fw.path = NULL;
        g_fw.busy = 1;
        pthread_mutex_unlock(&g_fw.mu);
        fakeip_state_store(path, buf, len);
        free(buf);
        free(path);
        pthread_mutex_lock(&g_fw.mu);
        g_fw.busy = 0;
        pthread_cond_broadcast(&g_fw.cv);
    }
    return NULL;
}

/* Занят ли поток записи или ждёт ли его снимок. */
static int fakeip_writer_active(void) {
    pthread_mutex_lock(&g_fw.mu);
    int a = g_fw.buf != NULL || g_fw.busy;
    pthread_mutex_unlock(&g_fw.mu);
    return a;
}

/* Дождаться, пока поток записи отдаст то, что принял и что ждёт. */
void fakeip_state_wait(void) {
    pthread_mutex_lock(&g_fw.mu);
    while (g_fw.buf || g_fw.busy) pthread_cond_wait(&g_fw.cv, &g_fw.mu);
    pthread_mutex_unlock(&g_fw.mu);
}

/* Перезапись файла в фоне: цикл не ждёт носителя. 0 — снимок передан, -1 — не вышло (нет памяти или потока:
 * вызывающий оставит таблицу грязной и повторит). */
int fakeip_state_rewrite_async(void) {
    if (!g_fakeip_state_path) return 0;
    size_t len;
    char *buf = fakeip_state_serialize(&len);
    if (!buf) return -1;
    char *path = strdup(g_fakeip_state_path);
    if (!path) { free(buf); return -1; }
    pthread_mutex_lock(&g_fw.mu);
    if (!g_fw.started) {
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        pthread_t t;
        int er = pthread_create(&t, &a, fakeip_writer, NULL);
        pthread_attr_destroy(&a);
        if (er != 0) { pthread_mutex_unlock(&g_fw.mu); free(buf); free(path); return -1; }
        g_fw.started = 1;
    }
    free(g_fw.buf);
    free(g_fw.path);
    g_fw.buf = buf;
    g_fw.len = len;
    g_fw.path = path;
    pthread_cond_broadcast(&g_fw.cv);
    pthread_mutex_unlock(&g_fw.mu);
    return 0;
}

void fakeip_state_rewrite(void) {
    if (!g_fakeip_state_path) return;
    fakeip_state_wait();                      /* не наперегонки с потоком записи: тот же временный файл */
    size_t len;
    char *buf = fakeip_state_serialize(&len);
    if (!buf) return;
    fakeip_state_store(g_fakeip_state_path, buf, len);
    free(buf);
}

/* ФАЙЛ НЕ ОТСТАЁТ ОТ ПАМЯТИ ТАМ, ГДЕ ИЗ НЕГО ЧИТАЮТ (проверка на QEMU 98b7964, 2026-09-28).
 * Перезапись по сроку — не чаще раза в FAKEIP_STATE_DEBOUNCE_S (цикл в proxy.c; была минута
 * «ради флеша» — отставание файла стоило связи, I-541). Но из файла читают двое, и обоим отставание
 * стоило связи: засев карты и наборов при замене набора
 * правил (fpseed.c) — новое имя без подмены, старый адрес вместо нового; и новый резолвер после
 * `steer restart` — SIGTERM прежнего выход из цикла ничего не дописывал, и имена последних секунд
 * терялись вовсе, пока их не спросят заново. Поэтому файл пишется ещё в два мига, и оба — редкие
 * события, а не трафик: по просьбе загрузчика прямо перед засевом («flush», adopt.c) и при выходе
 * резолвера (proxy.c, после цикла). Ничего не менялось — ничего и не пишется. */
void fakeip_state_flush(void) {
    /* Флаг чист, но снимок может быть ещё у потока записи (fakeip_state_flush_async снял его при передаче):
     * файл нужен на носителе к возврату — загрузчик прочтёт его сразу, а резолвер сейчас выйдет. */
    fakeip_state_wait();
    if (!g_fakeip_dirty) return;
    fakeip_state_rewrite();
    g_fakeip_dirty = 0;
    g_fakeip_last_rewrite = time(NULL);
}

/* Возврат адресов — ниже, после работы с наборами каналов (ей нужны dch_del и карта). */
static uint32_t *g_free;                 /* свободные адреса пула в порядке выдачи */
static size_t g_free_n, g_free_i;
static void fakeip_reclaim_try(time_t now);
/* То же по сроку в цикле (proxy.c): запись идёт в фоне, цикл не ждёт носителя (I-534). Не вышло передать —
 * таблица остаётся грязной, и срок придёт снова. */
void fakeip_state_flush_async(void) {
    if (!g_fakeip_dirty) return;
    if (fakeip_state_rewrite_async() != 0) return;
    g_fakeip_dirty = 0;
    g_fakeip_last_rewrite = time(NULL);
}

/* Looks up domain's existing fake IP, or allocates the next free one and
 * persists it. Returns 0 and fills *out_addr (host order) on success; -1 if
 * the pool is exhausted (caller falls back to relaying the real answer
 * unchanged — fail open, never block DNS over an exhausted pool). */
int fakeip_lookup_or_alloc(const char *domain_in, uint32_t *out_addr) {
    /* Ключ таблицы — строчные буквы, и приводит к ним сама таблица, а не каждый вызывающий:
     * демон приводил, команда `--fakeip` нет, и X.TEST получала второй адрес рядом с x.test. */
    char domain[MAX_HOSTNAME];
    snprintf(domain, sizeof(domain), "%s", domain_in);
    str_lower(domain);
    long at = fakeip_find(domain);
    time_t now = time(NULL);
    if (at >= 0) {
        g_fakeip.entries[at].last_used = now;
        *out_addr = g_fakeip.entries[at].addr;
        return 0;
    }
    uint32_t addr;
    int from_free = 0;
    if (g_fakeip_next < FAKEIP_POOL_SIZE - 1) {    /* последний — широковещательный пула */
        addr = fakeip_index_to_addr(g_fakeip_next);
    } else {
        /* Выдача дошла до края пула: возвращаем адреса простоявших имён. Свободные берутся по
         * кругу от места последней выдачи, а не сразу заново: клиент с кэшем DNS успевает
         * отпустить прежний адрес. */
        if (g_free_i >= g_free_n) fakeip_reclaim_try(now);
        if (g_free_i >= g_free_n) {
            /* Пул кончился по-настоящему: домен уйдёт клиенту реальным адресом, то есть МИМО
             * канала, в который его положил человек. Молчать об этом нельзя — снаружи это
             * «правило перестало работать», и связать это с пулом нечем. */
            static time_t said_pool;
            if (warn_due(&said_pool, now))
                fprintf(stderr, "steer dnsd: пул fake-IP исчерпан (%u адресов, занято %zu: все "
                                "спрошены в последние %d с или держат соединения): новые "
                                "домены идут мимо каналов\n",
                        (unsigned)FAKEIP_POOL_SIZE, g_fakeip.n, g_fakeip_idle);
            return -1;
        }
        addr = g_free[g_free_i];
        from_free = 1;
    }
    if (fakeip_table_add(&g_fakeip, domain, addr) != 0) return -1;
    if (from_free) g_free_i++;
    if (g_fakeip_state_path) fakeip_state_append(g_fakeip_state_path, domain, addr);
    *out_addr = addr;
    return 0;
}

int g_fakeip_dirty = 0;
time_t g_fakeip_last_rewrite = 0;

/* Records the last-seen real backend for an allocated domain. Called after a
 * successful DNAT-map insert so the mapping can survive a restart via the
 * rehydrate pass (run_proxy's startup). Triggers a one-shot state rewrite so
 * the extended 3-field form persists. */
/* The real backend we last installed for this domain, or 0 if we never did. */
uint32_t fakeip_entry_get_real(const char *domain) {
    long at = fakeip_find(domain);
    return at >= 0 ? g_fakeip.entries[at].real_host : 0;
}

uint32_t fakeip_entry_known_real(const char *domain) {
    long at = fakeip_find(domain);
    if (at < 0) return 0;
    const struct fakeip_entry *e = &g_fakeip.entries[at];
    return e->real_host ? e->real_host : e->real_saved;
}

/* Подмена встала (ack ядра): и «в ядре», и «знаем». Файл перезаписывается, только когда меняется
 * то, что в нём лежит (fakeip_state_rewrite пишет «знаем»): подтверждение сохранённого адреса
 * после отказа ядра — не новость для файла. */
void fakeip_entry_set_real(const char *domain, uint32_t real_host) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    struct fakeip_entry *e = &g_fakeip.entries[at];
    uint32_t was = e->real_host ? e->real_host : e->real_saved;
    e->real_host = e->real_saved = real_host;
    if (was != real_host) g_fakeip_dirty = 1;
}

/* Половина IPv6: то же для карты fakeip6 — только после ack ядра (как real_host). */
const uint8_t *fakeip_entry_get_real6(const char *domain) {
    long at = fakeip_find(domain);
    return at >= 0 && g_fakeip.entries[at].has_real6 ? g_fakeip.entries[at].real6 : NULL;
}

const uint8_t *fakeip_entry_known_real6(const char *domain) {
    long at = fakeip_find(domain);
    if (at < 0) return NULL;
    const struct fakeip_entry *e = &g_fakeip.entries[at];
    return e->has_real6 || e->has_real6_saved ? e->real6 : NULL;
}

void fakeip_entry_set_real6(const char *domain, const uint8_t real6[16]) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    struct fakeip_entry *e = &g_fakeip.entries[at];
    int same = (e->has_real6 || e->has_real6_saved) && !memcmp(e->real6, real6, 16);
    memcpy(e->real6, real6, 16);
    e->has_real6 = e->has_real6_saved = 1;
    if (!same) g_fakeip_dirty = 1;
}

/* Ensures DOMAIN's fake IP is a PERMANENT member of channel NEW_SET_IDX's nft set
 * (g_dch[new_set_idx].set), moving it from its previous channel set if the domain
 * has been re-classified. Defined after g_dch (below): it needs the channel table.
 *
 * Why this is NOT a timeout element (and why it has to live here, beside the real
 * backend bookkeeping): a fake IP is a STABLE, exclusive allocation — it never
 * moves in the pool, and the DNAT map holds it forever. The channel set is the
 * routing decision (`ip daddr @set -> meta mark set`), and it used to inherit the
 * real answer's TTL. That TTL (often 30-60s for a CDN) is far shorter than the
 * long-lived TCP/QUIC sessions clients open against the resolved domain. When the
 * element expired, the mark rule stopped matching, the packet fell through to the
 * default route — the WAN — and the session to the VPN-hosted site broke for a
 * second. Reproduced on the router: conntrack showed claude.ai flows with
 * mark=0 leaving via the WAN address while the tunnel itself stayed perfectly
 * healthy. A permanent element makes the route match the lifetime of the
 * allocation, which is what a routing decision should do.
 *
 * Channel reassignment: if the ruleset is edited so a domain now matches a
 * different channel, the fake IP must move to that channel's set — leaving it in
 * the old one would keep steering it the old way. Best-effort on the delete: a
 * missing element is exactly the post-restart state and is harmless. */
const char *g_fakeip_map = "fakeip";

/* ---- адрес имени в наборе канала -------------------------------------------------------------
 *
 * Обычный набор — адрес. Составной (канал со смешанным сужением, src/model/srsplan.c) — адрес
 * . протокол . порты: имя попадает туда с сужением тех правил канала, с которыми совпало, а
 * если совпало с несколькими — их объединением, разложенным на непересекающиеся ящики (ядро не
 * принимает в составной набор пересекающиеся элементы). */
static struct nftlk_box *dch_boxes(size_t i, const char *domain, size_t *n) {
    static const struct l4match none;
    const struct dchan *d = &g_dch[i];
    /* Частей у канала сколько есть — совпавших не больше, чем частей, плюс «без сужения». */
    const struct l4match **ms = malloc((d->parts_n + 1) * sizeof(*ms));
    *n = 0;
    if (!ms) return NULL;
    size_t k = 0;
    if (ruleset_match(&d->rules, domain)) ms[k++] = &none;
    for (size_t p = 0; p < d->parts_n; p++)
        if (ruleset_match(&d->parts[p].rules, domain) &&
            !(d->parts[p].has_excl && ruleset_match(&d->parts[p].excl, domain)))
            ms[k++] = &d->parts[p].l4;
    /* Правила сменились с тех пор, как адрес туда лёг (удаление после перечитывания): прежнего
     * сужения уже не узнать — берётся полный ящик, лучшее, что можно сделать. */
    if (!k) ms[k++] = &none;
    size_t nb;
    struct l4box *b = l4_union_alloc(ms, k, &nb);
    free(ms);
    if (!b) return NULL;
    struct nftlk_box *out = malloc((nb ? nb : 1) * sizeof(*out));
    if (!out) { free(b); return NULL; }
    for (size_t j = 0; j < nb; j++) {
        out[j].plo = b[j].plo;
        out[j].phi = b[j].phi;
        out[j].lo = b[j].lo;
        out[j].hi = b[j].hi;
    }
    free(b);
    *n = nb;
    return out;
}

int dch_add(size_t i, const char *domain, uint32_t addr_host, uint32_t ttl) {
    if (!g_dch[i].composite) return nft_add_element(g_dch[i].set, addr_host, ttl);
    size_t n;
    struct nftlk_box *b = dch_boxes(i, domain, &n);
    if (!b) return -1;
    int rc = 0;
    for (size_t j = 0; j < n; j++)
        if (nft_concat_element(1, g_dch[i].set, addr_host, &b[j], ttl) != 0) rc = -1;
    free(b);
    return rc;
}

/* Пул fake-IP как отрезок ключей в порядке сети — для nft_elem_carve: вырезать адрес можно только
 * из отрезка, целиком лежащего в пуле (засев), а не из префикса адресного списка. Первый и
 * последний адреса пула не выдаются (fakeip_lookup_or_alloc), и в засев они не попадают. */
static void pool_bounds4(uint8_t lo[4], uint8_t hi[4]) {
    uint32_t a = htonl(FAKEIP_POOL_BASE + 1), b = htonl(FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE - 2);
    memcpy(lo, &a, 4);
    memcpy(hi, &b, 4);
}

static void pool_bounds6(uint8_t lo[16], uint8_t hi[16]) {
    fakeip6_of(FAKEIP_POOL_BASE + 1, lo);
    fakeip6_of(FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE - 2, hi);
}

/* Снятие из обычного набора канала: точным ключом, а на ENOENT — вырезая адрес из слитого отрезка.
 * Засев набора правил кладёт соседние поддельные адреса одного канала, и auto-merge при загрузке
 * сливает их в отрезок (print.c, src/dnsd/fpseed.c); точного элемента [F, F+1) тогда в ядре нет,
 * и без вырезания имя, ушедшее из канала, оставалось бы в его наборе до следующей замены таблицы
 * (nft_elem_carve, nftnl.c). ENOENT и после этого — адреса в наборе нет вовсе: перезапуск, или он
 * туда и не лёг, — желаемое состояние. Составной набор засев не сливает (seed_edge4 в print.c), и
 * там точного ключа хватает. */
void dch_del(size_t i, const char *domain, uint32_t addr_host) {
    if (!g_dch[i].composite) {
        uint32_t k_net = htonl(addr_host);
        int drc = nftlk_elem_msg(NFT_MSG_DELSETELEM, g_nft_table, g_dch[i].set,
                                 &k_net, 1, NULL, 0);
        if (drc == -ENOENT) {
            uint8_t lo[4], hi[4];
            pool_bounds4(lo, hi);
            drc = nft_elem_carve(g_dch[i].set, (const uint8_t *)&k_net, 4, lo, hi);
        }
        if (drc != 0 && drc != -ENOENT && dbg())
            fprintf(stderr, "nftlk: channel-move delete from %s rc=%d\n", g_dch[i].set, drc);
        return;
    }
    size_t n;
    struct nftlk_box *b = dch_boxes(i, domain, &n);
    for (size_t j = 0; j < n; j++) nft_concat_element(0, g_dch[i].set, addr_host, &b[j], 0);
    free(b);
}

/* Адрес IPv6 — в парный набор «<set>6» (компилятор заводит его доменной группе с dom6, тем же
 * именем, что group_set6_name). Сужение составного набора — то же, что у IPv4 (dch_boxes). */
static void dch_set6_name(size_t i, char *dst, size_t n) {
    snprintf(dst, n, "%.62s6", g_dch[i].set);
}

int dch_add6(size_t i, const char *domain, const uint8_t addr[16], uint32_t ttl) {
    char s6[80];
    dch_set6_name(i, s6, sizeof(s6));
    if (!g_dch[i].composite) return nft_add_element6(s6, addr, ttl);
    size_t n;
    struct nftlk_box *b = dch_boxes(i, domain, &n);
    if (!b) return -1;
    int rc = 0;
    for (size_t j = 0; j < n; j++)
        if (nft_concat_element6(1, s6, addr, &b[j], ttl) != 0) rc = -1;
    free(b);
    return rc;
}

void dch_del6(size_t i, const char *domain, const uint8_t addr[16]) {
    char s6[80];
    dch_set6_name(i, s6, sizeof(s6));
    if (!g_dch[i].composite) {
        int drc = nftlk_elem_msg6(NFT_MSG_DELSETELEM, g_nft_table, s6, addr, 1, NULL, 0);
        if (drc == -ENOENT) {
            uint8_t lo[16], hi[16];
            pool_bounds6(lo, hi);
            drc = nft_elem_carve(s6, addr, 16, lo, hi);
        }
        if (drc != 0 && drc != -ENOENT && dbg())
            fprintf(stderr, "nftlk: channel-move delete from %s rc=%d\n", s6, drc);
        return;
    }
    size_t n;
    struct nftlk_box *b = dch_boxes(i, domain, &n);
    for (size_t j = 0; j < n; j++) nft_concat_element6(0, s6, addr, &b[j], 0);
    free(b);
}

/* ---- возврат адресов пула ----------------------------------------------------------------------
 *
 * ЗАЧЕМ. Пул — 131070 адресов, и раньше они только выдавались: имя получало адрес навсегда, и на
 * устройстве, которое живёт месяцами и ходит на десятки тысяч разных имён (сервер, компьютер),
 * пул кончался, а новые имена шли мимо каналов до перезапуска. Теперь у записи есть время
 * последнего вопроса (last_used), и когда выдача доходит до края пула, имена, которых не
 * спрашивали дольше g_fakeip_idle секунд, отдают адрес.
 *
 * КОГДА ЗАПИСЬ ВОЗВРАЩАЕТ АДРЕС. Только если её не спрашивали g_fakeip_idle секунд (клиент с
 * кэшем DNS приходит за адресом заново раньше: поддельный ответ живёт FAKEIP_ANSWER_TTL) И к
 * адресу нет живых соединений в conntrack: сеанс, открытый часы назад, держит адрес, пока идёт
 * (пересдать его другому имени значило бы увести сеанс на чужой сайт). Не удалось спросить
 * conntrack — решает один срок простоя, а не «никогда»: иначе пул без conntrack кончался бы
 * по-прежнему.
 *
 * ЧТО СНИМАЕТСЯ. Адрес — из наборов каналов (v4 и v6), элементы карт fakeip и fakeip6, запись —
 * из таблицы, индекса и файла состояния (перезаписывается сразу: иначе в файле у одного адреса
 * два имени до следующей перезаписи). Размер пула не из спеки: диапазон 198.18.0.0/15 зашит в
 * правила (метка, nat), в разбор спеки и в пару fdfe:dcba:9876::/96, и менять его значит менять
 * все три места; число адресов называет сообщение об исчерпании. */
int g_fakeip_idle = FAKEIP_IDLE_DEFAULT;

/* Живые адреса по conntrack: записи с исходным назначением в пуле (подмена переписывает только
 * кортеж ответа, так что поддельный адрес стоит в исходном кортеже — как у ct_origdst и
 * ctnl_evict_mark_keep). */
static int fakeip_live_rec(const uint8_t *a, const uint8_t *end, uint8_t family, void *ctx) {
    uint8_t *bits = ctx;
    const struct nlattr *orig = ct_attr(a, end, CTA_TUPLE_ORIG);
    const struct nlattr *tip = ct_attr_in(orig, CTA_TUPLE_IP);
    int v6 = family == AF_INET6;
    const struct nlattr *da = ct_attr_in(tip, v6 ? CTA_IP_V6_DST : CTA_IP_V4_DST);
    size_t alen = v6 ? 16 : 4;
    if (!da || da->nla_len < NLA_HDRLEN + alen) return 0;
    uint32_t h;
    if (v6) {
        h = fakeip6_to4((const uint8_t *)da + NLA_HDRLEN);
        if (!h) return 0;
    } else {
        uint32_t n;
        memcpy(&n, (const uint8_t *)da + NLA_HDRLEN, 4);
        h = ntohl(n);
    }
    if (h < FAKEIP_POOL_BASE || h >= FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE) return 0;
    uint32_t i = h - FAKEIP_POOL_BASE;
    bits[i >> 3] |= (uint8_t)(1u << (i & 7));
    return 0;
}

static int fakeip_live_ct(uint8_t *bits) {
    int dfd = ctnl_socket();
    uint8_t *buf = malloc(CTNL_RCVBUF);
    if (dfd < 0 || !buf) {
        if (dfd >= 0) close(dfd);
        free(buf);
        return -1;
    }
    uint32_t seq = (uint32_t)time(NULL);
    int rc = 0;
    static const uint8_t fam[] = { AF_INET, AF_INET6 };
    for (size_t i = 0; i < sizeof(fam) && rc == 0; i++)
        rc = ctnl_dump(dfd, fam[i], 0, 0, 0, &seq, buf, fakeip_live_rec, bits);
    close(dfd);
    free(buf);
    return rc == 0 ? 0 : -1;
}

int (*g_fakeip_live)(uint8_t *bits) = fakeip_live_ct;

/* Снять всё, что ядро держит под записью: адрес в наборах каналов и подмену в картах. ENOENT —
 * желаемое состояние. */
static void fakeip_entry_unroute(const struct fakeip_entry *e) {
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(e->sets, i)) dch_del(i, e->domain, e->addr);
    uint8_t f6[16];
    fakeip6_of(e->addr, f6);
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(e->sets6, i)) dch_del6(i, e->domain, f6);
    if (e->real_host || e->real_saved) {
        uint32_t k = htonl(e->addr);
        nftlk_elem_msg(NFT_MSG_DELSETELEM, g_nft_table, g_fakeip_map, &k, 0, NULL, 0);
    }
    if (e->has_real6 || e->has_real6_saved)
        nftlk_elem_msg6(NFT_MSG_DELSETELEM, g_nft_table, g_fakeip6_map, f6, 0, NULL, 0);
}

void fakeip_pool_reset(void) {
    free(g_free);
    g_free = NULL;
    g_free_n = g_free_i = 0;
}

size_t fakeip_reclaim(time_t now) {
    size_t bytes = FAKEIP_POOL_SIZE / 8;
    uint8_t *live = calloc(1, bytes), *used = calloc(1, bytes);
    if (!live || !used) {
        free(live);
        free(used);
        return 0;
    }
    int known = g_fakeip_live && g_fakeip_live(live) == 0;
    static time_t said_ct;
    if (!known && warn_due(&said_ct, now))
        fprintf(stderr, "steer dnsd: conntrack недоступен — адреса пула fake-IP возвращаются "
                        "только по сроку простоя (%d с)\n", g_fakeip_idle);
    size_t w = 0;
    for (size_t r = 0; r < g_fakeip.n; r++) {
        struct fakeip_entry *e = &g_fakeip.entries[r];
        uint32_t i = e->addr - FAKEIP_POOL_BASE;
        int in_pool = e->addr >= FAKEIP_POOL_BASE && e->addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE;
        if (in_pool && now - e->last_used >= g_fakeip_idle &&
            !(known && (live[i >> 3] & (1u << (i & 7))))) {
            fakeip_entry_unroute(e);
            free(e->domain);
            continue;
        }
        if (in_pool) used[i >> 3] |= (uint8_t)(1u << (i & 7));
        if (w != r) g_fakeip.entries[w] = *e;
        w++;
    }
    size_t freed = g_fakeip.n - w;
    if (freed) {
        g_fakeip.n = w;
        /* Номера записей сдвинулись — индекс строится заново (один проход; случай редкий: пул
         * кончается раз в много часов). */
        sindex_free(&g_fakeip_idx);
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        for (size_t k = 0; k < g_fakeip.n; k++)
            if (sindex_put(&g_fakeip_idx, &g_fakeip, fakeip_key, g_fakeip.entries[k].domain,
                           (uint32_t)k, 0) != 0)
                fprintf(stderr, "steer dnsd: индекс fake-IP не пересобран (нет памяти)\n");
        fakeip_state_rewrite();
        g_fakeip_dirty = 0;
        g_fakeip_last_rewrite = now;
    }
    /* Свободные адреса — все, что не заняты (и дыры от прежних запусков: файл состояния уплотнял
     * пул не сам), по кругу от последней выдачи. Первый и последний адрес пула не выдаются. */
    uint32_t start = g_free_i ? g_free[g_free_i - 1] - FAKEIP_POOL_BASE + 1 : 1;
    if (start >= FAKEIP_POOL_SIZE - 1) start = 1;
    size_t cnt = 0;
    for (uint32_t i = 1; i < FAKEIP_POOL_SIZE - 1; i++)
        if (!(used[i >> 3] & (1u << (i & 7)))) cnt++;
    uint32_t *nf = cnt ? malloc(cnt * sizeof(*nf)) : NULL;
    fakeip_pool_reset();
    if (nf) {
        size_t k = 0;
        for (uint32_t j = 0; j < FAKEIP_POOL_SIZE - 2; j++) {
            uint32_t i = 1 + (start - 1 + j) % (FAKEIP_POOL_SIZE - 2);
            if (!(used[i >> 3] & (1u << (i & 7)))) nf[k++] = FAKEIP_POOL_BASE + i;
        }
        g_free = nf;
        g_free_n = k;
    }
    free(live);
    free(used);
    return freed;
}

/* С дросселем: пул полон занятыми — каждое новое имя заново обходило бы таблицу и дампило бы
 * conntrack; раз в 10 с достаточно (срок простоя — минуты). */
static void fakeip_reclaim_try(time_t now) {
    static time_t last;
    if (last && now - last < WARN_EVERY_SEC) return;
    last = now;
    fakeip_reclaim(now);
    if (g_free_i < g_free_n) last = 0;      /* вернулось — следующий край пула без ожидания */
}

void fakeip_route_set(const char *domain, chm_t want) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    want = chm_upto(want, g_dch_n);
    if (!want) return;

    chm_t old = g_fakeip.entries[at].sets;
    if (old == want) {
        /* Те же наборы: постоянные элементы уже стоят (или пережили прошлый запуск).
         * Переутверждаем идемпотентно — ядро, потерявшее их (fw4 reload смывает
         * наборы), получает их обратно, не дожидаясь повторного разрешения имени.
         *
         * Но не чаще TTL ответа: без дросселя КАЖДЫЙ повторный запрос платил
         * блокирующей nf_tables-транзакцией за ответ EEXIST — и второй раз тем
         * же, когда фоновый ответ upstream доходил до этой же строки. После
         * fw4 reload элемент вернётся с первым запросом по истечении TTL —
         * раньше клиент со старым кешем и не придёт. */
        time_t now = time(NULL);
        if (now - g_fakeip.entries[at].route_asserted < FAKEIP_ANSWER_TTL)
            return;
        g_fakeip.entries[at].route_asserted = now;
        for (size_t i = 0; i < g_dch_n; i++)
            if (chm_has(want, i))
                dch_add(i, domain, g_fakeip.entries[at].addr, 0);
        return;
    }

    /* Убираем из наборов, которым имя больше не принадлежит: правило выключили,
     * удалили или переписали его списки. ENOENT законен — удалять нечего
     * (перезапуск, или элемент туда и не лёг). */
    for (size_t i = 0; i < g_dch_n; i++) {
        if (!chm_has(old, i) || chm_has(want, i)) continue;
        dch_del(i, domain, g_fakeip.entries[at].addr);
    }

    /* И кладём во все, где его ещё нет, постоянным элементом. EEXIST — уже
     * желаемое состояние. */
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(want, i) && !chm_has(old, i))
            dch_add(i, domain, g_fakeip.entries[at].addr, 0);
    g_fakeip.entries[at].sets = want;
    g_fakeip.entries[at].route_asserted = time(NULL);
}

/* То же для поддельного IPv6 — постоянный элемент в «<канал>6» каждого канала из want, с тем же
 * дросселем переутверждения и тем же переездом между каналами. want — только каналы с DCH_V6:
 * у остальных набора IPv6 нет (и AAAA им адресом не отвечают — dch_all_v6). */
void fakeip_route_set6(const char *domain, chm_t want) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    want = chm_upto(want, g_dch_n);
    for (size_t i = 0; i < g_dch_n; i++)
        if (!(g_dch[i].fam & DCH_V6) && chm_has(want, i)) want = chm_andn(want, chm_one(i));
    if (!want) return;
    struct fakeip_entry *e = &g_fakeip.entries[at];
    uint8_t f6[16];
    fakeip6_of(e->addr, f6);
    chm_t old = e->sets6;
    time_t now = time(NULL);
    if (old == want) {
        if (now - e->route6_asserted < FAKEIP_ANSWER_TTL) return;
        e->route6_asserted = now;
        for (size_t i = 0; i < g_dch_n; i++)
            if (chm_has(want, i)) dch_add6(i, domain, f6, 0);
        return;
    }
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(old, i) && !chm_has(want, i)) dch_del6(i, domain, f6);
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(want, i) && !chm_has(old, i)) dch_add6(i, domain, f6, 0);
    e->sets6 = want;
    e->route6_asserted = now;
}

/* Постоянные элементы имени — в каждый канал want заново, без дросселя fakeip_route_set и
 * независимо от того, что память считает уже стоящим; из каналов прежнего sets, которых нет в
 * want, — снять. EEXIST у dch_add — желаемое состояние. Нужен проходу ниже: после замены набора
 * правил (apply пересоздаёт таблицу целиком, наборы каналов — пустыми) sets записи совпадает с
 * want, и fakeip_route_set молчал бы до конца дросселя, а клиент с поддельным адресом в кэше всё
 * это время шёл бы мимо выхода: пакет к поддельному адресу набор не метит, а карта dnat, которую
 * apply засевает из файла состояния, разворачивает его в настоящий адрес — напрямую. */
/* Элемент уже стоит в наборе канала — засев набора правил положил его текстом (fpseed.c), и
 * добавлять его заново значило бы транзакцию nftables впустую: на роутере их было по нескольку
 * на имя, по десятку-другому миллисекунд каждая, и сотня имён держала резолвер (и DNS) секунд
 * десять после каждой новой таблицы. У составного набора ключ — адрес с протоколом и портами,
 * и одного GET мало: туда — как прежде, добавлением. */
static int dch_present(size_t i, uint32_t addr_host) {
    if (g_dch[i].composite) return 0;
    uint32_t k = htonl(addr_host);
    return nft_set_has(g_dch[i].set, &k, 4);
}

static int dch_present6(size_t i, const uint8_t addr[16]) {
    if (g_dch[i].composite) return 0;
    char s6[80];
    dch_set6_name(i, s6, sizeof(s6));
    return nft_set_has(s6, addr, 16);
}

/* Наборы каналов, которых в ядре нет (добавление ответило ENOENT), — на время одного прохода
 * восстановления: стучаться в них за каждой следующей записью — по транзакции впустую. */
static chm_t g_dch_missing, g_dch_missing6;

static void route_reassert(struct fakeip_entry *e, chm_t want) {
    want = chm_upto(want, g_dch_n);
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(e->sets, i) && !chm_has(want, i)) dch_del(i, e->domain, e->addr);
    for (size_t i = 0; i < g_dch_n; i++) {
        if (!chm_has(want, i) || chm_has(g_dch_missing, i) || dch_present(i, e->addr)) continue;
        nft_last_add_rc = 0;
        dch_add(i, e->domain, e->addr, 0);
        if (nft_last_add_rc == -ENOENT) g_dch_missing = chm_or(g_dch_missing, chm_one(i));
    }
    e->sets = want;
    e->route_asserted = time(NULL);
}

static void route_reassert6(struct fakeip_entry *e, chm_t want) {
    want = chm_upto(want, g_dch_n);
    for (size_t i = 0; i < g_dch_n; i++)
        if (!(g_dch[i].fam & DCH_V6) && chm_has(want, i)) want = chm_andn(want, chm_one(i));
    uint8_t f6[16];
    fakeip6_of(e->addr, f6);
    for (size_t i = 0; i < g_dch_n; i++)
        if (chm_has(e->sets6, i) && !chm_has(want, i)) dch_del6(i, e->domain, f6);
    for (size_t i = 0; i < g_dch_n; i++) {
        if (!chm_has(want, i) || chm_has(g_dch_missing6, i) || dch_present6(i, f6)) continue;
        nft_last_add_rc = 0;
        dch_add6(i, e->domain, f6, 0);
        if (nft_last_add_rc == -ENOENT) g_dch_missing6 = chm_or(g_dch_missing6, chm_one(i));
    }
    e->sets6 = want;
    e->route6_asserted = time(NULL);
}

/* Восстановить DNAT-карту и наборы каналов после (пере)запуска — и после каждой новой таблицы
 * каналов или перечитывания списков (proxy.c, reassert_routes): набор правил мог быть заменён
 * вместе с наборами каналов. Возвращает число
 * восстановленных отображений fake→real, в *routed_out — число вновь утверждённых маршрутов.
 *
 * ГЛАВНОЕ ЗДЕСЬ — real_host остаётся у записи ТОЛЬКО если ядро подтвердило отображение.
 * Быстрый путь handle_client_query отвечает клиенту поддельным адресом без похода наверх,
 * когда real_host ненулевой, и считает это безопасным потому, что «real_host запоминается
 * только после ack ядра либо восстановлен rehydrate». Загрузка файла состояния писала третье
 * поле в real_host безусловно, а неудача восстановления его не обнуляла — и при пустой
 * таблице ядра (netlink не открылся, таблица снесена) клиент получал fake-IP в чёрную дыру,
 * пока свежие домены честно шли наверх. Теперь несостоявшееся отображение обнуляет поле, и
 * такой домен идёт долгим путём — как обещает шапка файла про fail-open.
 *
 * НО НАСТОЯЩИЙ АДРЕС ОТ ЭТОГО НЕ ЗАБЫВАЕТСЯ (проверка на QEMU 04664a5). Обнулялся он раньше
 * вместе с real_host — и резолвер, поднятый до набора правил (steer restart: таблицы ещё нет,
 * ENOENT), забывал настоящие адреса всех имён; первая же
 * перезапись файла (новое имя, новый ответ) писала их без адреса, и следующая замена набора
 * правил засевала карту без них: клиент с поддельным адресом в кэше DNS упирался в «без подмены —
 * никуда» (17 из 38 запросов на стенде QEMU). Теперь отказ ядра гасит только «стоит в ядре»
 * (real_host, has_real6), а «знаем» (real_saved, has_real6_saved) остаётся: файл пишет его, а
 * подмену ставит этот же проход, как только таблица появится, — его зовут и после каждой новой
 * таблицы (reassert после загрузки набора правил демоном, SIGHUP без демона). Ставится именно
 * «знаем».
 *
 * ПО ЯДРУ, А НЕ ПО EEXIST (проверка на QEMU 98b7964). В ядре после
 * замены набора лежит засев из файла, и прежде здесь считалось, что это то же значение: простой
 * add, EEXIST — «желаемое состояние». Файл же отставал от памяти до минуты (перезапись раз в
 * FAKEIP_ANSWER_TTL): dnsmasq отдал n1 = .10, карта и память — .10, в файле ещё .11; замена набора
 * засеяла .11, add ответил EEXIST, память осталась при .10, а повторный вопрос n1 шёл быстрым
 * путём по real_host и ничего не менял — клиенты n1 ходили на .11 до перезапуска резолвера. Теперь
 * загрузчик перед засевом просит резолвер записать файл (просьба «flush», adopt.c), и засев с
 * памятью совпадает, но окно между записью и nft -f остаётся, а резолвер может и не ответить
 * вовремя. Поэтому подмена ставится по тому, что стоит в ядре (nft_map_ensure_element: спросить
 * элемент, другое значение — заменить одной транзакцией), и real_host после этого прохода значит
 * ровно то, что обещает быстрому пути: в карте ядра стоит этот адрес. Исправленные — в
 * g_fakeip_fixed (строка журнала у reassert_routes). */
/* ПОРЯДОК В ЗАПИСИ — СНАЧАЛА НАБОРЫ КАНАЛОВ, ПОТОМ КАРТА. Подмена без метки — это утечка: пакет
 * клиента с поддельным адресом в кэше разворачивается картой в настоящий адрес и, не найдя себя в
 * наборе канала, уходит по таблице main в WAN (перепроверка на QEMU, 2026-09-28). Метка без
 * подмены — нет: помеченный пакет к поддельному адресу подмены не находит и дальше правила за
 * dnat не идёт (generate.c, fakeip_nomap_drop). Поэтому
 * между двумя транзакциями одной записи наборы уже стоят, а карта — ещё нет, а не наоборот. После
 * замены набора правил оба уже засеяны текстом (src/dnsd/fpseed.c), и здесь всё уже стоит; порядок
 * решает там, где засева не было: первый запуск резолвера, старый набор правил, засев не
 * собрался. Не встала карта IPv6 — элементы IPv6 снимаются обратно (адресом AAAA на такое имя
 * больше не отвечают, как и прежде). */
size_t g_fakeip_fixed;

size_t fakeip_rehydrate(int nk_open, size_t *routed_out) {
    size_t restored = 0, routed = 0;
    g_fakeip_fixed = 0;
    /* ТАБЛИЦЫ НЕТ — В ЯДРО НЕ ХОДИТЬ. Резолвер, поднятый вместе с движком (steer restart, запуск
     * коннектора), стартует раньше, чем демон загрузил набор правил: таблицы ещё нет, и каждая
     * запись давала по нескольку отказов ENOENT. На роутере это было почти десять секунд (сотня
     * имён), и всё это время резолвер не слушал ни DNS, ни свой управляющий сокет, а загрузчик
     * набора правил ждал его засева по таймауту. ENOENT при добавлении в карту fake-IP значит
     * «карты нет», а карта есть всегда, когда есть таблица с доменными каналами, — и остальные
     * записи идут как без netlink: «знаем» остаётся, «стоит в ядре» — нет. Вернёт их этот же
     * проход, когда демон загрузит таблицу (reassert после загрузки). Отдельный набор канала,
     * которого нет (а таблица есть), таблицу отсутствующей не делает: он пропускается сам
     * (g_dch_missing). */
    int absent = 0;
    g_dch_missing = g_dch_missing6 = 0;
    for (size_t i = 0; i < g_fakeip.n; i++) {
        struct fakeip_entry *e = &g_fakeip.entries[i];
        chm_t all = 0, m = 0;
        if (nk_open == 0 && !absent) {
            /* Re-derive the channels for the stored domain and re-assert the permanent route
             * elements — БЕЗ дросселя и во все каналы, а не только в новые (route_reassert ниже):
             * этот проход зовут и после замены набора правил, когда наборы в ядре пересозданы
             * пустыми, а память резолвера помнит элементы «уже стоящими». */
            all = dch_match_mask(e->domain);
            m = dch_fakeip_only(all);
            if (m || e->sets) route_reassert(e, m);
            if (m) routed++;
        }
        int kern = nk_open == 0 && !absent;
        if (!kern && absent) { e->sets = 0; e->sets6 = 0; }
        uint32_t want = e->real_host ? e->real_host : e->real_saved;
        if (want) {
            /* Что стоит в ядре, память не знает (засев из файла, карта, пережившая резолвер) —
             * спрашивается само ядро (см. выше, «ПО ЯДРУ»). Отказ гасит только «стоит в ядре»;
             * real_saved остаётся. */
            int mrc = kern ? nft_map_ensure_element(g_fakeip_map, e->addr, want) : -1;
            /* Добавление в карту отвечает ENOENT, только если карты нет. */
            if (kern && mrc == -ENOENT) absent = 1;
            if (mrc >= 0) {
                e->real_host = e->real_saved = want;
                restored++;
                if (mrc > 0) g_fakeip_fixed++;
            } else {
                e->real_saved = want;
                e->real_host = 0;
            }
        }
        if (e->has_real6) e->has_real6_saved = 1;
        if (!kern) {
            e->has_real6 = 0;
            continue;
        }
        /* Половина IPv6 — тем же порядком. Поддельный IPv6 ложится в наборы, только если он у имени
         * был выдан (есть настоящий IPv6) и все совпавшие каналы по-прежнему несут IPv6; иначе
         * прежние элементы IPv6 снимаются — на AAAA такого имени адресом больше не отвечают.
         * Настоящий IPv6 остаётся у записи, только если ядро приняло элемент карты fakeip6; иначе
         * быстрый путь AAAA закрыт до нового ответа, и элементы IPv6 снимаются тоже. */
        chm_t m6 = e->has_real6_saved && m && dch_all_v6(all) ? m : 0;
        if (m6 || e->sets6) route_reassert6(e, m6);
        if (e->has_real6_saved) {
            uint8_t f6[16];
            fakeip6_of(e->addr, f6);
            int mrc = nft_map_ensure_element6(g_fakeip6_map, f6, e->real6);
            if (mrc < 0) {
                e->has_real6 = 0;             /* «знаем» (has_real6_saved) остаётся */
                if (e->sets6) route_reassert6(e, 0);
            } else {
                e->has_real6 = 1;
                if (mrc > 0) g_fakeip_fixed++;
            }
        }
    }
    if (routed_out) *routed_out = routed;
    return restored;
}
