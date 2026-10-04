/* Группы выходов в сторожe (docs/architecture.md, «4в») и команда select.
 *
 * Проход сторожа — автомат failover.c; решения выбора — функции группы (src/kinds/group.c). Здесь
 * то, что между ними: порядок обхода с вложенностью, память групп между проходами (записи
 * хранилища fostate.h), простой группы для idle_timeout, сверка карты balance с ядром и команда
 * select. Отдельным файлом, чтобы автомат прохода менялся точечно.
 *
 * ЧЛЕНЫ v2 — ВЫХОДЫ СО СВОИМ ПРИГОВОРОМ. У группы спеки v2 члены именованные: у каждого своя
 * метка, таблица и свой проход в том же обходе (раньше группы — fog_order). Поэтому группа своих
 * устройств не пробует и не оживляет: жив ли член — это приговор его собственного прохода (тот же
 * via, та же проба, то же оживление), а лист члена — устройство, которое его проход выбрал (у
 * вложенной группы — её текущий лист). Пул v1 (безымянные члены) идёт прежним путём: пробы
 * устройств самим пулом, и его поведение не меняется ни в чём, кроме меры задержки.
 *
 * ЗАПИСИ ХРАНИЛИЩА (тексты, как файлы каталога состояния; у демона — в памяти, с копией на диск):
 *   select  — `группа член` по строке: выбор человека у pick: manual. Переживает перезапуск и
 *             перезагрузку: файл select рядом со спекой (steer_keep_dir, platform.h; каталог
 *             состояния роутера — tmpfs), пишется только при изменении, атомарно и с fsync;
 *   groups  — `группа член|- живые,через,запятую|-`: итог прохода для status и для следующего
 *             прохода (кто был выбран — у вложенных групп устройство листа неоднозначно);
 *   latency — прежняя запись замеров; у именованного члена ключ — его имя, у безымянного —
 *             устройство (fog_lat_key).
 *
 * СВЕРКА КАРТЫ balance — по факту в ядре (nfv_map_read), а не по памяти, тем же доводом, что
 * сверка маршрутизации в failover.c: apply пересоздаёт таблицу с картой «все живы», и сторож,
 * помнящий «член X мёртв, карту уже переписал», не заметил бы, что X снова получает соединения.
 * Чтение карты — один дамп netlink на группу за проход; запись — только при расхождении. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "spec.h"
#include "fostate.h"
#include "fogroup.h"
#include "folat.h"
#include "nftvmap.h"
#include "nftdump.h"
#include "failover_int.h"

#define LOG_W "steer[warn] failover: "

/* ---- порядок обхода ---------------------------------------------------------------------- */

size_t fog_order(const struct spec *sp, size_t *ord) {
    /* Рабочие массивы — по числу выходов (раньше на стеке под 16). Без памяти — порядок спеки. */
    unsigned char *placed = calloc(sp->out_n ? sp->out_n : 1, 1);
    size_t *add = malloc((sp->out_n ? sp->out_n : 1) * sizeof(*add));
    size_t n = 0;
    if (!placed || !add) {
        free(placed);
        free(add);
        for (size_t i = 0; i < sp->out_n; i++) ord[n++] = i;
        return n;
    }
    for (int progress = 1; progress && n < sp->out_n; ) {
        progress = 0;
        /* Круг: все, чьи зависимости уже в порядке. Кладутся после круга, а не сразу, — так внутри
         * круга остаётся порядок спеки, и выходы одной глубины over идут как прежде. */
        size_t an = 0;
        for (size_t i = 0; i < sp->out_n; i++) {
            if (placed[i]) continue;
            const struct output *o = &sp->out[i];
            int ready = 1;
            const struct output *t = out_over(sp, o);
            if (t && !placed[t - sp->out]) ready = 0;
            const struct group_cfg *g = out_group(o);
            for (size_t k = 0; ready && g && k < g->members_n; k++)
                if (g->members[k] < sp->out_n && !placed[g->members[k]]) ready = 0;
            if (ready) add[an++] = i;
        }
        for (size_t k = 0; k < an; k++) {
            placed[add[k]] = 1;
            ord[n++] = add[k];
            progress = 1;
        }
    }
    /* Не бывает (круги отвергает разбор), но стенд может собрать спеку руками: остаток — как есть. */
    for (size_t i = 0; i < sp->out_n; i++)
        if (!placed[i]) ord[n++] = i;
    free(placed);
    free(add);
    return n;
}

/* ---- записи ------------------------------------------------------------------------------- */

/* Прочитать запись целиком. Строка malloc'ом ("" — записи нет); NULL — нет памяти. */
static char *rec_read(struct fo_store *st, const char *name) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *out = open_memstream(&buf, &bn);
    if (!out) return NULL;
    FILE *f = st->ops->open_r(st, name);
    if (f) {
        char chunk[1024];
        size_t k;
        while ((k = fread(chunk, 1, sizeof(chunk), f)) > 0) fwrite(chunk, 1, k, out);
        fclose(f);
    }
    if (fclose(out) != 0) { free(buf); return NULL; }
    return buf;
}

/* Значение (остаток строки после первого слова) строки с первым словом key. 1 — нашлась. */
static int rec_get(const char *text, const char *key, char *val, size_t n) {
    size_t kl = strlen(key);
    for (const char *ln = text; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        if (len > kl && !strncmp(ln, key, kl) && ln[kl] == ' ') {
            size_t vl = len - kl - 1;
            if (vl >= n) vl = n - 1;
            memcpy(val, ln + kl + 1, vl);
            val[vl] = '\0';
            return 1;
        }
        ln = end ? end + 1 : NULL;
    }
    return 0;
}

/* Заменить (или дописать) строку key в записи name; line NULL — снять строку. Пишет только при
 * изменении текста. */
static void rec_set(struct fo_store *st, const char *name, const char *key, const char *line) {
    char *old = rec_read(st, name);
    if (!old) return;
    char *buf = NULL;
    size_t bn = 0;
    FILE *out = open_memstream(&buf, &bn);
    if (!out) { free(old); return; }
    size_t kl = strlen(key);
    int done = 0;
    for (const char *ln = old; *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        int mine = len >= kl && !strncmp(ln, key, kl) && (len == kl || ln[kl] == ' ');
        if (mine) {
            if (line && !done) fprintf(out, "%s\n", line);
            done = 1;
        } else if (len) {
            fwrite(ln, 1, len, out);
            fputc('\n', out);
        }
        if (!end) break;
        ln = end + 1;
    }
    if (line && !done) fprintf(out, "%s\n", line);
    if (fclose(out) == 0 && (bn != strlen(old) || memcmp(buf, old, bn) != 0))
        st->ops->put(st, name, buf, bn);
    free(buf);
    free(old);
}

static int member_idx(const struct spec *sp, const struct group_cfg *g, const char *name) {
    for (size_t k = 0; k < g->members_n; k++)
        if (!strcmp(spec_out(sp, g->members[k])->name, name)) return (int)k;
    return -1;
}

int fog_manual_pick(const struct spec *sp, struct fo_store *st, const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (!g || !g->members_n) return -1;
    char *text = rec_read(st, "select");
    char val[64];
    int k = -1;
    if (text && rec_get(text, go->name, val, sizeof(val))) k = member_idx(sp, g, val);
    free(text);
    if (k >= 0) return k;
    return g->def >= 0 && (size_t)g->def < g->members_n ? g->def : 0;
}

const char *fog_lat_key(const struct output *m) {
    return m->name[0] ? m->name : m->device;
}

/* ОДНО РЕШЕНИЕ НА ПРОХОД И НА СТАРТ.
 *
 * До этой функции выбор члена группы v2 принимали в двух местах, и по-разному. Проход (fo_step в
 * failover.c) выбирал по правилам pick: у manual — член из `select`, у balance — первый живой. А
 * подхват outputs_adopt_active_st, по которому apply привязывает таблицу группы и status о ней
 * рассказывает, знал одно правило на всех: запись `active` сторожа, а нет её — первый
 * существующий кандидат. Каталог состояния на роутере — tmpfs, и после перезагрузки записи нет:
 * группа manual с выбором `man wg1` (файл select рядом со спекой перезагрузку пережил) несколько
 * секунд до первого прохода вела трафик через wg0 — первого члена, а не выбранного; status в это
 * окно говорил `"selected":null,"select":"wg1"`, и первый DNS-запрос клиента ушёл через wg0.
 * Выбранный член лежит — таблица получала первого живого, а не on_fail, который обещан для
 * manual (docs/spec-v2.md). Найдено проверкой долгов на QEMU-роутере с настоящим procd.
 *
 * Правило теперь одно, и оно — правило прохода, только без проб: жив ли член, решил приговор его
 * собственного прохода (у подхвата — последний записанный приговор и наличие устройства), а
 * группа своих устройств и так не пробует (шапка файла, «ЧЛЕНЫ v2»). Поэтому у manual и balance
 * решение прохода и есть эта функция целиком — он её и зовёт. У order и latency проходу есть что
 * добавить: гистерезис возврата (серия проходов подряд) и свежий замер. Подхвату ни того, ни
 * другого делать нельзя — status зовёт его на каждый запрос, и он обязан только читать, — поэтому
 * здесь живой текущий держится (таблица и так на нём, а уйти с него — дело прохода), а без
 * текущего берётся то, что взял бы проход по уже известному: у latency — лучший по последнему
 * замеру (тот же group_latency_pick с тем же допуском), без замеров — первый живой, как у прохода,
 * когда не измерился никто (S_LAT_C → S_HYST). После перезагрузки замеров нет (они в том же
 * tmpfs), и latency до первого замера идёт по порядку — это сказано в docs/ctl.md. */
int fog_pick_known(const struct spec *sp, struct fo_store *st, const struct output *go,
                   const unsigned char *alive, int cur) {
    const struct group_cfg *g = out_group(go);
    if (!g || !g->members_n) return -1;
    size_t n = g->members_n;
    int first = -1;
    for (size_t k = 0; k < n && first < 0; k++)
        if (alive[k]) first = (int)k;
    if (g->pick == PICK_MANUAL) {
        /* Не работает выбранный — отказ группы с её on_fail: переключиться на другого значило бы
         * решить за человека. */
        int k = fog_manual_pick(sp, st, go);
        return k >= 0 && alive[k] ? k : -1;
    }
    if (g->pick == PICK_BALANCE) return first;
    if (cur >= 0 && (size_t)cur < n && alive[cur]) return cur;
    if (g->pick == PICK_LATENCY && first >= 0) {
        int best = -1;
        int *ms = malloc(n * sizeof(int));
        if (!ms) return first;
        for (size_t k = 0; k < n; k++) {
            struct folat_rec rc;
            ms[k] = -1;
            if (alive[k] && folat_rec_get(st, go->name, fog_lat_key(spec_out(sp, g->members[k])), &rc))
                ms[k] = rc.ms;
        }
        int p = group_latency_pick(ms, n, group_tolerance_ms(g), &best);
        free(ms);
        if (p >= 0) return p;
    }
    return first;
}

/* ---- состояние «замера нет» (журнал) -------------------------------------------------------- */

struct lat_note {
    char name[32];
    int none;
};
static struct lat_note *g_latn;
static size_t g_latn_n, g_latn_cap;

int fog_lat_note(const char *group, int none) {
    for (size_t i = 0; i < g_latn_n; i++)
        if (!strcmp(g_latn[i].name, group)) {
            int changed = g_latn[i].none != none;
            g_latn[i].none = none;
            return changed;
        }
    if (g_latn_n == g_latn_cap) {
        size_t nc = g_latn_cap ? g_latn_cap * 2 : 8;
        struct lat_note *nn = realloc(g_latn, nc * sizeof(*nn));
        if (!nn) return none;
        g_latn = nn;
        g_latn_cap = nc;
    }
    snprintf(g_latn[g_latn_n].name, sizeof(g_latn[g_latn_n].name), "%s", group);
    g_latn[g_latn_n++].none = none;
    return none;
}

/* ---- простой группы (idle_timeout) --------------------------------------------------------- */

int fog_idle_limit(const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (g && g->idle_timeout_s >= 0) return g->idle_timeout_s;
    /* Умолчание — по платформе: на телефоне сторож в фоне обязан не тратить батарею на замеры
     * группы, через которую ничего не идёт (решение владельца: «на телефоне проверка идёт, только
     * пока через группу идёт трафик»); полчаса — как idle_timeout у urltest sing-box. На роутере
     * питание от сети, и замер по интервалу, как было у prefer_latency. */
    return plat()->netifd ? 0 : 1800;
}

struct idle_rec {
    char name[32];
    unsigned long long pkts;
    long changed;       /* CLOCK_MONOTONIC, с: когда счётчик последний раз рос */
    int limit;          /* с каким пределом спрашивали в последний раз (fog_idle_now) */
    int seen;
};
/* Записи простоя групп растут по числу групп (раньше — 16 мест, и 17-я группа считалась
 * «трафик есть» навсегда). */
static struct idle_rec *g_idle;
static size_t g_idle_n, g_idle_cap;

static long mono_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

int fog_idle(const struct spec *sp, const struct output *go, int limit, fo_traffic_fn fn, void *arg) {
    if (limit <= 0 || !fn) return 0;
    unsigned long long pk = 0;
    if (fn(arg, sp, go, &pk) != 0) return 0;
    struct idle_rec *r = NULL;
    for (size_t i = 0; i < g_idle_n && !r; i++)
        if (g_idle[i].seen && !strcmp(g_idle[i].name, go->name)) r = &g_idle[i];
    long now = mono_s();
    if (!r) {
        if (g_idle_n == g_idle_cap) {
            size_t nc = g_idle_cap ? g_idle_cap * 2 : 16;
            struct idle_rec *ni = realloc(g_idle, nc * sizeof(*ni));
            if (!ni) return 0;
            g_idle = ni;
            g_idle_cap = nc;
        }
        r = &g_idle[g_idle_n++];
        memset(r, 0, sizeof(*r));
        snprintf(r->name, sizeof(r->name), "%s", go->name);
        r->seen = 1;
        r->limit = limit;
        r->pkts = pk;
        /* Первая встреча: отсчёт взят, трафика ещё не видели — замера нет, пока он не пойдёт. */
        r->changed = now - limit - 1;
        return 1;
    }
    r->limit = limit;
    if (pk != r->pkts) {
        r->pkts = pk;
        r->changed = now;
    }
    return now - r->changed > limit;
}

int fog_idle_now(const char *group) {
    for (size_t i = 0; i < g_idle_n; i++)
        if (g_idle[i].seen && !strcmp(g_idle[i].name, group))
            return g_idle[i].limit > 0 && mono_s() - g_idle[i].changed > g_idle[i].limit;
    return 0;
}

/* ---- balance: карта в ядре --------------------------------------------------------------- */

int fog_balance_sync(const struct spec *sp, const struct output *go, const unsigned char *alive) {
    static int told;
    const struct group_cfg *g = out_group(go);
    if (!g || g->pick != PICK_BALANCE) return 0;
    char map[32];
    group_bal_map(go, map, sizeof(map));
    static char have[GROUP_BAL_SLOTS][NFV_CHAIN_MAX], want[GROUP_BAL_SLOTS][NFV_CHAIN_MAX];
    memset(have, 0, sizeof(have));
    memset(want, 0, sizeof(want));
    if (nfv_map_read(NFD_INET, nft_table(), map, have, GROUP_BAL_SLOTS) < 0) {
        /* Карты нет: набор правил не применён или группа не ведёт ни одного правила (карту
         * компилятор ставит только тем, в кого идут каналы). Второе — не беда, первое сторож
         * всё равно увидит по маршрутизации. */
        if (!told && errno != ENOENT) {
            told = 1;
            fprintf(stderr, LOG_W "%s: карту %s не прочитать (%s) — раздачу не сверяю\n", go->name,
                    map, strerror(errno));
        }
        return -1;
    }
    unsigned char owner[GROUP_BAL_SLOTS];
    group_balance_slots(g, alive, owner);
    for (unsigned s = 0; s < GROUP_BAL_SLOTS; s++)
        if (owner[s] != 0xff) group_bal_target(spec_out(sp, g->members[owner[s]]), want[s], NFV_CHAIN_MAX);
    if (!memcmp(have, want, sizeof(have))) return 0;
    if (nfv_map_write(NFD_INET, nft_table(), map, (const char (*)[NFV_CHAIN_MAX])want,
                      (const char (*)[NFV_CHAIN_MAX])have, GROUP_BAL_SLOTS) != 0) {
        fprintf(stderr, LOG_W "%s: карту %s не переписать (%s)\n", go->name, map, strerror(errno));
        return -1;
    }
    return 1;
}

/* Карта после загрузки набора правил. Компилятор ставит карту balance со всеми членами (набор
 * правил от живости членов не зависит — иначе его отпечаток менялся бы с каждым упавшим туннелем, и
 * apply-сверка перезагружала бы набор без смены спеки). До этой сверки упавший член получал новые
 * соединения до первого прохода сторожа после apply — при старте несколько секунд, а после apply,
 * менявшего только набор правил (списки), до периода сторожа: такой apply внеочередного прохода не
 * зовёт. Сверяется тем же fog_balance_sync, что у прохода, по той же маске, что подхват выдал
 * status (group_cfg.alive), — то есть карта сразу та, что поставил бы проход. */
void fog_balance_adopt(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct group_cfg *g = out_group(&sp->out[i]);
        if (g && g->pick == PICK_BALANCE && group_named(g))
            fog_balance_sync(sp, &sp->out[i], g->alive);
    }
}

/* ---- запись groups ------------------------------------------------------------------------- */

/* Имена живых членов через запятую — строка в куче (NULL — нет памяти). Длина по числу членов:
 * раньше буфер был на 16 имён, и запись groups у группы побольше обрывалась на середине имени. */
static char *alive_csv(const struct spec *sp, const struct group_cfg *g, const unsigned char *alive) {
    size_t cap = g->members_n * 33 + 1, l = 0;
    char *dst = malloc(cap);
    if (!dst) return NULL;
    dst[0] = '\0';
    for (size_t k = 0; k < g->members_n; k++)
        if (alive && alive[k])
            l += (size_t)snprintf(dst + l, cap - l, "%s%s", l ? "," : "", spec_out(sp, g->members[k])->name);
    return dst;
}

void fog_groups_save(struct fo_store *st, const struct spec *sp, const int *cur,
                     unsigned char *const *alive) {
    /* Строка группы: имя ≤ 31, выбранный ≤ 31, живые ≤ 33 на члена — буфер по сумме. */
    size_t wcap = 1;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct group_cfg *g = out_group(&sp->out[i]);
        if (group_named(g)) wcap += 96 + g->members_n * 33;
    }
    char *want = malloc(wcap);
    if (!want) return;
    size_t wn = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct group_cfg *g = out_group(&sp->out[i]);
        if (!group_named(g)) continue;
        char *al = alive_csv(sp, g, alive[i]);
        if (!al) { free(want); return; }
        int w = snprintf(want + wn, wcap - wn, "%s %s %s\n", sp->out[i].name,
                         cur[i] >= 0 && (size_t)cur[i] < g->members_n ? spec_out(sp, g->members[cur[i]])->name
                                                                     : "-",
                         al[0] ? al : "-");
        free(al);
        if (w < 0 || (size_t)w >= wcap - wn) break;
        wn += (size_t)w;
    }
    char *have = rec_read(st, "groups");
    if (have && strlen(have) == wn && !memcmp(have, want, wn)) { free(have); free(want); return; }
    free(have);
    st->ops->put(st, "groups", want, wn);
    free(want);
}

/* Значение записи key из text — строка в куче ровно нужной длины (NULL — записи нет или нет
 * памяти). Буфер под значение не «700 байт»: у группы на десятки членов строка живых длиннее. */
static char *rec_dup(const char *text, const char *key) {
    if (!text) return NULL;
    char *val = malloc(strlen(text) + 1);
    if (!val) return NULL;
    if (!rec_get(text, key, val, strlen(text) + 1)) { free(val); return NULL; }
    return val;
}

/* Разрезать значение записи groups «<выбранный> <живые через запятую>» на два слова на месте.
 * 1 — оба есть. */
static int groups_split(char *val, char **cur, char **al) {
    char *sp1 = val + strcspn(val, " \t");
    if (!*sp1) return 0;
    *sp1++ = '\0';
    sp1 += strspn(sp1, " \t");
    if (!*sp1) return 0;
    *al = sp1;
    sp1[strcspn(sp1, " \t\r\n")] = '\0';
    *cur = val;
    return 1;
}

int fog_groups_cur(struct fo_store *st, const struct spec *sp, const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (!g) return -1;
    char *text = rec_read(st, "groups");
    char *val = rec_dup(text, go->name);
    int k = -1;
    if (val) {
        val[strcspn(val, " \t\r\n")] = '\0';        /* первое слово — выбранный член */
        if (val[0]) k = member_idx(sp, g, val);
    }
    free(val);
    free(text);
    return k;
}

int fog_groups_alive(struct fo_store *st, const struct spec *sp, const struct output *go,
                     unsigned char *alive) {
    const struct group_cfg *g = out_group(go);
    if (!g) return 0;
    memset(alive, 0, g->members_n);
    char *text = rec_read(st, "groups");
    char *val = rec_dup(text, go->name), *cur, *al;
    int found = 0;
    if (val && groups_split(val, &cur, &al)) {
        found = 1;
        for (char *tok = strtok(al, ","); tok; tok = strtok(NULL, ",")) {
            int k = member_idx(sp, g, tok);
            if (k >= 0) alive[k] = 1;
        }
    }
    free(val);
    free(text);
    return found;
}

void fog_adopt(struct spec *sp, struct fo_store *st) {
    char *groups = rec_read(st, "groups"), *sel = rec_read(st, "select");
    char *lat = rec_read(st, "latency");
    for (size_t i = 0; i < sp->out_n; i++) {
        struct group_cfg *g = (struct group_cfg *)out_group(&sp->out[i]);
        if (!g) continue;
        g->cur = -1;
        if (g->alive) memset(g->alive, 0, g->members_n);
        g->sel = -1;
        char *gv = rec_dup(groups, sp->out[i].name), *gcur, *gal;
        if (gv && g->alive && groups_split(gv, &gcur, &gal)) {
            g->cur = member_idx(sp, g, gcur);
            for (char *tok = strtok(gal, ","); tok; tok = strtok(NULL, ",")) {
                int k = member_idx(sp, g, tok);
                if (k >= 0) g->alive[k] = 1;
            }
        }
        free(gv);
        if (g->pick == PICK_MANUAL) {
            char *sv = rec_dup(sel, sp->out[i].name);
            if (sv) {
                sv[strcspn(sv, " \t\r\n")] = '\0';
                g->sel = member_idx(sp, g, sv);
            }
            free(sv);
            if (g->sel < 0) g->sel = g->def >= 0 ? g->def : 0;
        }
        /* Замеры: запись latency (формат — folat.h). */
        for (size_t k = 0; k < g->members_n; k++) {
            g->lat_ms[k] = -1;
            g->lat4_ms[k] = g->lat6_ms[k] = -2;
        }
        for (size_t k = 0; lat && k < g->members_n; k++) {
            struct folat_rec rc;
            if (!folat_rec_get(st, sp->out[i].name, fog_lat_key(spec_out(sp, g->members[k])), &rc))
                continue;
            g->lat_ms[k] = rc.ms;
            g->lat4_ms[k] = rc.ms4;
            g->lat6_ms[k] = rc.ms6;
        }
    }
    free(groups);
    free(sel);
    free(lat);
}

/* ---- select ------------------------------------------------------------------------------- */

/* Запись active: устройство выхода и серия. "" — записи нет. */
static void active_of(struct fo_store *st, const char *out, char *dev, size_t n, int *streak) {
    dev[0] = '\0';
    if (streak) *streak = 0;
    char *text = rec_read(st, "active");
    char val[96];
    if (text && rec_get(text, out, val, sizeof(val))) {
        char d[32] = "";
        int sk = 0;
        if (sscanf(val, "%31s %d", d, &sk) >= 1) {
            snprintf(dev, n, "%s", d);
            if (streak) *streak = sk;
        }
    }
    free(text);
}

static int dev_up(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", dev);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char s[16] = "";
    int up = fgets(s, sizeof(s), f) && strncmp(s, "down", 4) != 0;
    fclose(f);
    return up;
}

int fog_select(struct spec *sp, struct fo_store *st, const char *gname, const char *mname,
               int route, fo_event_fn ev, void *arg, FILE *out) {
    struct output *go = NULL;
    for (size_t i = 0; i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, gname)) go = &sp->out[i];
    if (!go || !out_group(go)) {
        fprintf(stderr, "steer: select: группы «%s» в спеке нет\n", gname);
        return 2;
    }
    const struct group_cfg *g = out_group(go);
    if (g->pick != PICK_MANUAL || !group_named(g)) {
        fprintf(stderr, "steer: select: у группы %s pick: %s — выбирает сторож, а не команда; "
                        "select — для pick: manual\n", gname, group_pick_name(g->pick));
        return 2;
    }
    int k = member_idx(sp, g, mname);
    if (k < 0) {
        fprintf(stderr, "steer: select: %s — не член группы %s\n", mname, gname);
        return 2;
    }
    /* ЧТО НЕСЁТ ТАБЛИЦА ГРУППЫ СЕЙЧАС — по подхвату, а не по записи active сторожа, и до того, как
     * новый выбор ляжет в запись select: подхват решает по прежнему выбору ровно то, к чему apply
     * привязал таблицу (outputs_adopt_active_st, fog_pick_known). Запись сторожа отстаёт от ядра
     * до первого прохода: после старта с файлом select, сменённым при остановленном демоне, apply
     * ведёт группу на член из файла, а запись всё ещё называет прежний. Сравнивая с записью,
     * команда приняла бы «выбран тот же, что в записи» за «ничего не меняется» и не переписала бы
     * таблицу, которая на самом деле ведёт на другой член. Спеку команде дают свежей копией
     * (ctl.c, mem_select; cmd_select), так что устройства здесь переписывать можно. */
    outputs_adopt_active_st(sp, st);
    char was[32];
    snprintf(was, sizeof(was), "%s", go->failed ? "-" : go->device);
    char line[80];
    snprintf(line, sizeof(line), "%s %s", gname, mname);
    rec_set(st, "select", gname, line);
    if (!route) {
        fprintf(out, "steer: группа %s — выбран %s; ядро выключено, выбор применится при "
                     "включении\n", gname, mname);
        return 0;
    }

    /* Лист члена и жив ли он — по памяти сторожа: приговор последнего прохода члена (запись
     * active: «-» — отказ). Записи нет (сторож ещё не проходил) — по наличию устройства. */
    const struct output *m = spec_out(sp, g->members[k]);
    char mdev[32];
    active_of(st, m->name, mdev, sizeof(mdev), NULL);
    int alive = strcmp(mdev, "-") != 0;
    if (!mdev[0]) {
        snprintf(mdev, sizeof(mdev), "%s", m->device);
        alive = dev_up(mdev);
    }
    char gline[96];
    if (alive) {
        int moved = strcmp(was, mdev) != 0;
        if (moved) bind_device(go, mdev);
        snprintf(gline, sizeof(gline), "%s %s 0", go->name, mdev);
        rec_set(st, "active", go->name, gline);
        /* Событие — только если маршрут группы действительно сменился (повтор того же выбора —
         * не новость). */
        if (ev && moved) {
            struct fo_event e = { .kind = FO_EV_SWITCHED, .out = go->name,
                                  .from = was[0] && strcmp(was, "-") ? was : NULL, .to = mdev,
                                  .why = "select", .on_fail = NULL, .member = m->name, .by = "select" };
            ev(arg, &e);
        }
        fprintf(out, "steer: группа %s — выбран %s (%s)\n", gname, mname, mdev);
    } else {
        /* manual — выбор человека: молча отдать трафик другому члену значило бы решить за него.
         * Группа получает свой on_fail, пока выбранный член не поднимется (сторож вернёт трафик
         * на него сам, как только его проход скажет «жив»). */
        int moved = strcmp(was, "-") != 0;
        if (moved) fo_fail_apply(go);
        snprintf(gline, sizeof(gline), "%s - 0", go->name);
        rec_set(st, "active", go->name, gline);
        const char *of = go->on_fail == FAIL_DROP ? "drop" : go->on_fail == FAIL_ZAPRET ? "zapret"
                                                                                       : "direct";
        if (ev && moved) {
            struct fo_event e = { .kind = FO_EV_FAILED, .out = go->name,
                                  .from = was[0] && strcmp(was, "-") ? was : NULL, .to = NULL,
                                  .why = "down", .on_fail = of, .member = m->name, .by = "select" };
            ev(arg, &e);
        }
        fprintf(out, "steer: группа %s — выбран %s, но он не работает: трафик группы по on_fail=%s, "
                     "пока %s не поднимется\n", gname, mname, of, mname);
    }
    /* Запись groups — выбранный член сразу, чтобы status не ждал прохода. */
    char *text = rec_read(st, "groups");
    char val[700], cur[64] = "-", al[640] = "-";
    if (text && rec_get(text, go->name, val, sizeof(val))) sscanf(val, "%63s %639s", cur, al);
    free(text);
    snprintf(gline, sizeof(gline), "%s %s ", go->name, alive ? mname : "-");
    char full[800];
    snprintf(full, sizeof(full), "%s%s", gline, al);
    rec_set(st, "groups", go->name, full);
    return 0;
}

int cmd_select(const char *spec, const char *group, const char *member) {
    static struct spec cfg;
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    return fog_select(&cfg, &fo_store_files, group, member, 1, NULL, NULL, stdout);
}
