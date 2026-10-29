#include "dnsd_int.h"
#include "fpseed.h"
#include "ir.h"

/* ---- засев наборов каналов fake-IP в тексте набора правил -------------------------------------
 *
 * ЧТО БЫЛО. Перепроверка на QEMU-роутере (2026-09-28): клиент
 * гоняет `dig s19.test` и curl по полученному поддельному адресу каждые 0,2 с, и ровно в момент
 * «ставлю набор правил заново» ответ приходит с адреса WAN — один запрос после reload_config, два
 * после kill -9 демона, три-четыре при загрузке и start. Выход выбран, on_fail=drop, а пакет ушёл
 * напрямую. Замена таблицы — одна транзакция nft -f (apply.c, «ЗАМЕНА ТАБЛИЦЫ»), и карта подмены
 * fakeip приходит в ней засеянной из fakeip.state (print.c, emit_fakeip_elements), а набор канала,
 * по которому пакет к поддельному адресу получает метку выхода, — пустым: его наполняет резолвер,
 * когда к нему придёт таблица от демона (reassert_routes → route_reassert). В этом промежутке DNAT
 * уже стоит, а метки нет: пакет разворачивается в настоящий адрес и уходит по таблице main.
 *
 * ЧТО ЗДЕСЬ. Решение о маршруте каждого поддельного адреса принимается тем же кодом, что у
 * резолвера после таблицы (fakeip_rehydrate): каналы — из спеки (dch_build — та же таблица, что
 * демон шлёт резолверу, tabfmt_build), правила каналов — из их списков и наборов .srs
 * (dch_rules_load), записи — из того же файла состояния (fakeip_state_load, тем же разбором:
 * «первая раздача побеждает», адрес вне пула — брак строки), каналы имени — dch_match_mask и
 * dch_fakeip_only, половина IPv6 — только у имени с настоящим IPv6 и только если все совпавшие
 * каналы несут IPv6 (dch_all_v6). Печатник вписывает результат в наборы каналов в том же тексте,
 * что и карту, — значит подмена и метка появляются в ядре одной транзакцией, и промежутка «DNAT
 * есть, метки нет» после замены таблицы нет вовсе. Резолвер, получив таблицу, ставит те же
 * элементы ещё раз и получает EEXIST — желаемое состояние.
 *
 * ФАЙЛ, А НЕ ПАМЯТЬ РЕЗОЛВЕРА — И ПОЭТОМУ СВЕЖИЙ (проверка на QEMU 98b7964). Засев читает
 * файл: загрузчик — другой процесс, и файл — единственное, что у него есть от резолвера (а
 * резолвера может и не быть: init, подкоманда). Резолвер же переписывает файл не
 * чаще раза в минуту, и засев отставал: новое имя без подмены, сменившийся адрес — прежним.
 * Поэтому загрузчик прямо перед засевом просит живой резолвер записать файл (seed_begin в
 * src/daemon/apply.c, просьба «flush» в adopt.c), а резолвер после таблицы сверяет засеянную карту
 * со своей памятью по ядру (fakeip_rehydrate, nft_map_ensure_element). Снимок памяти по сокету
 * вместо файла дал бы второй разбор и второй формат того же самого; файл уже есть, и разбор у него
 * общий с запуском резолвера (fakeip_state_load).
 *
 * Засев в отпечаток плана не входит (g_print_state_seed = 0 у apply-plan): элементы, которые он
 * ставит, в незаменённой таблице уже положил резолвер при раздаче, и заменять таблицу ради них
 * незачем — довод у print_elements в print.c (коммит c5d0c53). Засев печатается только при
 * загрузке: apply-commit --ruleset, подкоманда `steer apply`, её --dry-run.
 *
 * ПОЧЕМУ ЗДЕСЬ, А НЕ В КОМПИЛЯТОРЕ. Каналы имени — это правила резолвера (списки имён, выбор клауз
 * наборов .srs, исключения, составные части); компилятор их не читает вовсе — «имена берёт
 * резолвер». Повторить сопоставление у компилятора значило бы завести вторую его копию, а две
 * копии одного решения расходятся молча (ровно это было с именами наборов до общей
 * group_set_name). Поэтому засев собирает код резолвера, а печатник получает только готовые
 * элементы по имени набора (g_print_seed, ir.h).
 *
 * ПАМЯТЬ И ВРЕМЯ. Правила всех каналов — как у резолвера при запуске (списки имён целиком, до
 * сколько в них строк), плюс записи файла состояния. Только в процессе загрузки (ребёнок
 * демона apply-commit или подкоманда), только когда в спеке есть канал fake-IP и файл состояния
 * не пуст, и освобождается сразу после печати (fpseed_free). Правила каналов real-ip тоже
 * читаются: без них dch_all_v6 не знает, есть ли среди совпавших канал без IPv6. */

/* Элемент на время сборки: адрес и сужения (номер первого в пуле и число). Пул растёт realloc'ом,
 * поэтому указатели ставятся только в конце, при переводе в struct ir_seed. */
struct fps_b {
    unsigned char a[16];
    size_t off, n;
};

struct fps_vec {
    struct fps_b *b;
    size_t n, cap;
    struct ir_seed *out;          /* готовый засев — после fps_finish */
    size_t out_n;
};

static struct fps_vec (*g_fps)[2];              /* [канал][0 — IPv4, 1 — IPv6]; по числу каналов */
static size_t g_fps_n;
static const struct l4match **g_l4;
static size_t g_l4_n, g_l4_cap;
static int g_rules_loaded;

/* Канал без сужения — полный ящик: протоколы 0-255, порты 0-65535 (так же у dch_boxes). */
static const struct l4match g_none;

static int l4_push(const struct l4match *m) {
    if (g_l4_n == g_l4_cap) {
        size_t c = g_l4_cap ? g_l4_cap * 2 : 64;
        const struct l4match **p = realloc(g_l4, c * sizeof(*p));
        if (!p) return -1;
        g_l4 = p;
        g_l4_cap = c;
    }
    g_l4[g_l4_n++] = m;
    return 0;
}

static int fps_push(struct fps_vec *v, const unsigned char *a, size_t alen, size_t off, size_t n) {
    if (v->n == v->cap) {
        size_t c = v->cap ? v->cap * 2 : 64;
        struct fps_b *p = realloc(v->b, c * sizeof(*p));
        if (!p) return -1;
        v->b = p;
        v->cap = c;
    }
    struct fps_b *e = &v->b[v->n++];
    memset(e, 0, sizeof(*e));
    memcpy(e->a, a, alen);
    e->off = off;
    e->n = n;
    return 0;
}

/* Сужения, с которыми имя ложится в составной набор канала: те же, что берёт dch_boxes
 * (fakeip.c) — основные правила канала без сужения и каждая совпавшая часть без исключения. Не
 * совпало ничего (правила сменились) — полный ящик, как там же. */
static int l4_of(const struct dchan *d, const char *domain, size_t *off, size_t *n) {
    *off = g_l4_n;
    if (ruleset_match(&d->rules, domain) && l4_push(&g_none) != 0) return -1;
    for (size_t p = 0; p < d->parts_n; p++)
        if (ruleset_match(&d->parts[p].rules, domain) &&
            !(d->parts[p].has_excl && ruleset_match(&d->parts[p].excl, domain)) &&
            l4_push(&d->parts[p].l4) != 0)
            return -1;
    if (g_l4_n == *off && l4_push(&g_none) != 0) return -1;
    *n = g_l4_n - *off;
    return 0;
}

static int fps_cmp(const void *x, const void *y) {
    return memcmp(((const struct fps_b *)x)->a, ((const struct fps_b *)y)->a, 16);
}

/* Сортировка по адресу и снятие повторов: nft отвергает набор с двойным элементом
 * ЦЕЛИКОМ (`nft -f` атомарен), а повтор поддельного адреса в файле законен только у
 * одного имени (fakeip_state_load берёт первую строку имени), у двух разных имён — это брак файла,
 * и первая раздача побеждает, как у карты (emit_fakeip_elements). Порядок по адресу нужен и
 * печатнику: составной набор ищет в засеве границы бинарным поиском. */
static int fps_finish(struct fps_vec *v) {
    if (!v->n) return 0;
    qsort(v->b, v->n, sizeof(v->b[0]), fps_cmp);
    v->out = calloc(v->n, sizeof(*v->out));
    if (!v->out) return -1;
    size_t k = 0;
    for (size_t i = 0; i < v->n; i++) {
        if (k && !memcmp(v->out[k - 1].a, v->b[i].a, 16)) continue;
        memcpy(v->out[k].a, v->b[i].a, 16);
        v->out[k].l4 = v->b[i].n ? g_l4 + v->b[i].off : NULL;
        v->out[k].l4_n = v->b[i].n;
        k++;
    }
    v->out_n = k;
    free(v->b);
    v->b = NULL;
    v->n = v->cap = 0;
    return 0;
}

static void fakeip_table_drop(void) {
    for (size_t i = 0; i < g_fakeip.n; i++) free(g_fakeip.entries[i].domain);
    free(g_fakeip.entries);
    memset(&g_fakeip, 0, sizeof(g_fakeip));
    sindex_free(&g_fakeip_idx);
    memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
    g_fakeip_next = 1;
    fakeip_pool_reset();
}

void fpseed_free(void) {
    for (size_t i = 0; i < g_fps_n; i++)
        for (int f = 0; f < 2; f++) {
            free(g_fps[i][f].b);
            free(g_fps[i][f].out);
        }
    free(g_fps);
    g_fps = NULL;
    g_fps_n = 0;
    free(g_l4);
    g_l4 = NULL;
    g_l4_n = g_l4_cap = 0;
    if (g_rules_loaded) {
        for (size_t i = 0; i < g_dch_n; i++) {
            ruleset_free(&g_dch[i].rules);
            dch_parts_free(g_dch[i].parts, g_dch[i].parts_n);
            g_dch[i].parts = NULL;
            g_dch[i].parts_n = 0;
            free(g_dch[i].rules_path);              /* массив путей; сами строки — взаймы у спеки */
            g_dch[i].rules_path = NULL;
            g_dch[i].rules_n = g_dch[i].rules_cap = 0;
        }
        g_dch_n = 0;
        g_rules_loaded = 0;
    }
    fakeip_table_drop();
}

int fpseed_build(const struct spec *sp, const char *path) {
    fpseed_free();
    fakeip_state_load(path);
    if (!g_fakeip.n) return 0;
    dch_build(sp);
    g_rules_loaded = 1;
    /* Правила — как при запуске резолвера (reload_rules в proxy.c без «оставить прежние»: прежних
     * здесь нет). Непрочитанный источник не отказ: у резолвера его тоже не будет, и засев обязан
     * совпасть с тем, что резолвер поставит, а не с тем, что было бы при целых списках. */
    for (size_t i = 0; i < g_dch_n; i++) {
        struct ruleset rs;
        struct dpart *parts;
        size_t parts_n;
        int composite;
        dch_rules_load(&g_dch[i], &rs, &parts, &parts_n, &composite);
        g_dch[i].rules = rs;
        g_dch[i].parts = parts;
        g_dch[i].parts_n = parts_n;
        g_dch[i].composite = composite;
    }
    size_t nch = g_dch_n;
    if (nch) {
        g_fps = calloc(nch, sizeof(*g_fps));
        if (!g_fps) goto oom;
        g_fps_n = nch;
    }
    for (size_t k = 0; k < g_fakeip.n; k++) {
        const struct fakeip_entry *e = &g_fakeip.entries[k];
        /* Каналы — ровно как у fakeip_rehydrate: все совпавшие каналы fake-IP (не первый: имя,
         * названное в двух правилах, обязано лечь в оба набора — порядок цепочки решает, кто
         * заберёт пакет), половина IPv6 — у имени с настоящим IPv6 и только если все совпавшие
         * каналы несут IPv6. */
        chm_t all = dch_match_mask(e->domain);
        chm_t m = dch_fakeip_only(all);
        if (!m) continue;
        chm_t m6 = e->has_real6 && dch_all_v6(all) ? m : 0;
        unsigned char a4[16], a6[16];
        uint32_t n4 = htonl(e->addr);
        memcpy(a4, &n4, 4);
        fakeip6_of(e->addr, a6);
        for (size_t c = 0; c < nch; c++) {
            if (!chm_has(m, c)) continue;
            size_t off = 0, n = 0;
            if (g_dch[c].composite && l4_of(&g_dch[c], e->domain, &off, &n) != 0) goto oom;
            if (fps_push(&g_fps[c][0], a4, 4, off, n) != 0) goto oom;
            if (chm_has(m6, c) && (g_dch[c].fam & DCH_V6) &&
                fps_push(&g_fps[c][1], a6, 16, off, n) != 0)
                goto oom;
        }
    }
    for (size_t c = 0; c < nch; c++)
        for (int f = 0; f < 2; f++)
            if (fps_finish(&g_fps[c][f]) != 0) goto oom;
    return 0;
oom:
    fpseed_free();
    return -1;
}

size_t fpseed_els(const char *set, int fam, const struct ir_seed **out) {
    size_t sl = strlen(set);
    for (size_t c = 0; c < g_dch_n && c < g_fps_n; c++) {
        if (g_dch[c].realip) continue;
        const char *d = g_dch[c].set;
        size_t dl = strlen(d);
        /* Имя парного набора IPv6 — «<набор>6», как у dch_set6_name (fakeip.c) и group_set6_name
         * у компилятора. */
        int hit = fam == 6 ? sl == dl + 1 && !strncmp(set, d, dl) && set[dl] == '6'
                           : !strcmp(set, d);
        if (!hit) continue;
        const struct fps_vec *v = &g_fps[c][fam == 6];
        *out = v->out;
        return v->out_n;
    }
    return 0;
}
