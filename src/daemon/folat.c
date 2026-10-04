/* Замер групп pick: latency (urltest) своими таймерами цикла демона (docs/architecture.md, «4в»).
 *
 * ЗАЧЕМ СВОИ ТАЙМЕРЫ. Прежде замер шёл внутри прохода сторожа: проход видел, что запись замеров
 * старше `interval` группы, и мерил всех членов. Проход идёт раз в период (60 с), поэтому
 * `interval: 10` на деле значил 60, а смена быстрого члена ждала ближайшего прохода. Теперь у
 * каждой группы latency в демоне свой таймер на её интервал: замер идёт, когда пришёл его срок, а
 * не когда сторож проходит, и проход сторожа зовётся внеочередным ТОЛЬКО если замер меняет выбор —
 * лучший член другой, и выигрыш больше допуска (тот же гистерезис, что у прохода:
 * group_latency_pick и group_latency_keep в src/kinds/group.c). Замер, который выбор не меняет,
 * только обновляет запись: проход ради него не нужен.
 *
 * Проход в демоне сам не меряет по сроку (fo_pass_lat_extern в failover.c): только если у живого
 * члена замера нет вовсе — первый проход после старта или член только что ожил. Так первый выбор
 * делается по замеру сразу, без лишнего переключения «по порядку, потом на быстрого», и замер не
 * идёт дважды — проходом и таймером. `steer failover` (один проход на процесс) меряет по-прежнему
 * в проходе: расписания у него нет.
 *
 * idle_timeout — как у прохода (fog_idle, счётчики правил каналов по netlink): без трафика через
 * группу таймер тикает, но запросов не шлёт. Выключенный движок — ни одного таймера (folat_stop):
 * требование батареи телефона то же, что у сторожа.
 *
 * СПЕКА НЕ ХРАНИТСЯ. apply посреди замера заменяет спеку демона (и освобождает прежнюю), поэтому
 * замер держит только имя группы и ключи членов, а спеку берёт у демона на каждом шаге; группа
 * сменила состав или ушла — замер выбрасывается.
 *
 * ПО IPv4 И IPv6. Выбор члена один на оба семейства, и прежде замер шёл только по IPv4: путь IPv4
 * есть у каждого члена, IPv6 — не у всех. Но группа, у которой IPv6 несёт каждый живой член
 * (KC_IPV6: у правила группы есть двойник IPv6, и клиенты ходят через неё по обоим семействам),
 * меряется по обоим — запросом из сокета AF_INET6 с меткой члена к адресу из AAAA (urltest.c).
 * Выбор — по ХУДШЕМУ из двух у каждого члена (group_latency_score): член, быстрый по IPv4, но
 * медленный или глухой по IPv6, половине соединений клиента хуже того, кто ровен по обоим, а
 * выбор «по лучшему» или «по IPv4» отдал бы группу именно ему. Если по IPv6 не ответил никто
 * (у адреса проверки нет AAAA, туннели не выпускают IPv6 наружу) — выбор по IPv4: мерить нечем, и
 * наказывать за это всех членов незачем. Пул v1 (безымянные члены без своей метки) меряется, как
 * прежде, только по IPv4: привязка сокета к устройству ведёт IPv6 по main, а не по таблице члена.
 * status показывает обе задержки (latency4, latency6) рядом с той, по которой выбирают. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include "spec.h"
#include "loop.h"
#include "fostate.h"
#include "fogroup.h"
#include "folat.h"
#include "urltest.h"
#include "grpurl.h"
#include "failover_int.h"

static long mono_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

/* ---- запись latency ---------------------------------------------------------------------- */

/* Разобрать строку записи. 1 — строка годна. */
static int rec_line(const char *ln, char *o, char *k, struct folat_rec *r) {
    int ms4 = -2, ms6 = -2;
    int got = sscanf(ln, "%31s %31s %d %ld %d %d", o, k, &r->ms, &r->at, &ms4, &ms6);
    if (got < 4) return 0;
    r->ms4 = got >= 6 ? ms4 : -2;
    r->ms6 = got >= 6 ? ms6 : -2;
    return 1;
}

int folat_rec_get(struct fo_store *st, const char *out, const char *key, struct folat_rec *r) {
    FILE *f = st->ops->open_r(st, "latency");
    if (!f) return 0;
    char ln[160], o[32], k[32];
    struct folat_rec x;
    int found = 0;
    while (fgets(ln, sizeof(ln), f))
        if (rec_line(ln, o, k, &x) && !strcmp(o, out) && !strcmp(k, key)) { *r = x; found = 1; }
    fclose(f);
    return found;
}

void folat_rec_put(struct fo_store *st, const char *out, const struct output *const *m,
                   const struct folat_rec *r, size_t n, int keep_failed) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *f = open_memstream(&buf, &bn);
    if (!f) return;
    FILE *old = st->ops->open_r(st, "latency");
    if (old) {
        char ln[160], o[32], k[32];
        struct folat_rec x;
        while (fgets(ln, sizeof(ln), old)) {
            if (!rec_line(ln, o, k, &x) || !strcmp(o, out)) continue;
            fputs(ln, f);
            if (!strchr(ln, '\n')) fputc('\n', f);
        }
        fclose(old);
    }
    /* Ключ члена — устройство у безымянного члена пула v1 (как было) и имя у именованного члена
     * группы v2: у вложенной группы устройство листа меняется, а член — нет (fog_lat_key). */
    for (size_t k = 0; k < n; k++) {
        if (r[k].ms == -2 || (r[k].ms < 0 && !keep_failed)) continue;
        fprintf(f, "%s %s %d %ld", out, fog_lat_key(m[k]), r[k].ms < 0 ? -1 : r[k].ms, r[k].at);
        if (r[k].ms4 != -2 || r[k].ms6 != -2) fprintf(f, " %d %d", r[k].ms4, r[k].ms6);
        fputc('\n', f);
    }
    if (fclose(f) == 0) st->ops->put(st, "latency", buf, bn);
    free(buf);
}

/* ---- замер члена ----------------------------------------------------------------------------- */

int folat_want_v6(const struct spec *sp, const struct output *go, const unsigned char *alive) {
    const struct group_cfg *g = out_group(go);
    if (!g || !group_named(g) || !alive) return 0;
    int any = 0;
    for (size_t k = 0; k < g->members_n; k++)
        if (alive[k]) {
            any = 1;
            if (!out_route6(spec_out(sp, g->members[k]))) return 0;
        }
    return any;
}

void folat_score(const int *ms4, const int *ms6, size_t n, int v6, int *score) {
    if (v6) {
        group_latency_score(ms4, ms6, n, score);
        return;
    }
    for (size_t k = 0; k < n; k++) score[k] = ms4[k] >= 0 ? ms4[k] : -1;
}

struct folat_m {
    struct urltest *u4, *u6;
    int ms4, ms6, left;
    folat_m_cb cb;
    void *arg;
    /* Чей это замер и по какому адресу — для строки журнала о неудаче (fm_note): к моменту обратного
     * вызова спека могла смениться, поэтому копии, а не указатели в неё. */
    char grp[32], key[32], url[192];
};

/* ЖУРНАЛ НЕУДАЧ ЗАМЕРА. Замер, не давший ответа, превращает «самый быстрый» в «первый живой», и без
 * причины в журнале человек видит только то, что группа «не работает»: пустой `latency` в status
 * говорит, ЧТО мерить не вышло, но не почему (имя не разрешилось, порт закрыт, ответ 503,
 * сертификат не принят, часы без NTP). Строка — на (группу, члена): пока причина та же, не чаще раза
 * в FOLAT_NOTE_S, а после удачного замера следующая неудача скажет снова. Только IPv4: по IPv6
 * у большинства туннелей ответа нет, и это не новость. */
#define FOLAT_NOTE_S 600
#define LOG_WL "steer[warn] latency: "
struct fl_note {
    char grp[32], key[32], why[192];
    long at;                          /* CLOCK_MONOTONIC, с; 0 — говорить, как только случится */
};
static struct fl_note *g_notes;
static size_t g_notes_n, g_notes_cap;

static void fm_note(const struct folat_m *fm, int fam, int ms) {
    if (fam != 4) return;
    struct fl_note *n = NULL;
    for (size_t i = 0; i < g_notes_n && !n; i++)
        if (!strcmp(g_notes[i].grp, fm->grp) && !strcmp(g_notes[i].key, fm->key)) n = &g_notes[i];
    if (ms >= 0) {                    /* удалось — следующая неудача заговорит сразу */
        if (n) n->at = 0;
        return;
    }
    const char *why = urltest_why();
    if (!why[0]) return;
    long now = loop_now_ms() / 1000 + 1;
    if (n && n->at && now - n->at < FOLAT_NOTE_S && !strcmp(n->why, why)) return;
    if (!n) {
        if (g_notes_n == g_notes_cap) {
            size_t nc = g_notes_cap ? g_notes_cap * 2 : 16;
            struct fl_note *nn = realloc(g_notes, nc * sizeof(*nn));
            if (!nn) return;
            g_notes = nn;
            g_notes_cap = nc;
        }
        n = &g_notes[g_notes_n++];
        memset(n, 0, sizeof(*n));
        snprintf(n->grp, sizeof(n->grp), "%s", fm->grp);
        snprintf(n->key, sizeof(n->key), "%s", fm->key);
    }
    snprintf(n->why, sizeof(n->why), "%s", why);
    n->at = now;
    fprintf(stderr, LOG_WL "группа %s, член %s: замер %s не удался — %s\n", fm->grp, fm->key,
            fm->url, why);
}

static void fm_done(struct folat_m *fm) {
    if (--fm->left > 0) return;
    folat_m_cb cb = fm->cb;
    void *arg = fm->arg;
    int a = fm->ms4, b = fm->ms6;
    free(fm);
    cb(arg, a, b);
}

static void fm_cb4(void *arg, int ms) {
    struct folat_m *fm = arg;
    fm->u4 = NULL;
    fm->ms4 = ms;
    fm_note(fm, 4, ms);
    fm_done(fm);
}

static void fm_cb6(void *arg, int ms) {
    struct folat_m *fm = arg;
    fm->u6 = NULL;
    fm->ms6 = ms;
    fm_done(fm);
}

struct folat_m *folat_member(struct loop *l, const struct spec *sp, const struct output *go,
                             const struct output *m, const char *dev, struct fo_hsrc *hs, int v6,
                             folat_m_cb cb, void *arg, int *ms4, int *ms6) {
    *ms4 = -1;
    *ms6 = v6 ? -1 : -2;
    if (g_latency_probe) { *ms4 = g_latency_probe(sp, go, dev); *ms6 = -2; return NULL; }
    if (!device_present(dev)) return NULL;
    const struct group_cfg *g = out_group(go);
    uint32_t mark = m && spec_out_idx(sp, m) != (size_t)-1 ? m->mark : 0;
    const struct output *o = out_for_device(sp, m && mark ? m : go, dev);
    const struct kind_ops *k = kind_of(o);
    /* Своя мера у вида (xsteer не меряется: его путь — хаб, а не выход в интернет). */
    if (k->latency) { *ms4 = k->latency(sp, o, dev); *ms6 = -2; return NULL; }
    /* И туннель xsteer, поднятый netifd, — по тому же доводу, что у вида xsteer: мерить его нечем,
     * а число из пробы наружу означало бы не задержку туннеля, а наличие интернета у хаба. */
    if (hs && hs->ops->xsdev(hs, dev, NULL, NULL)) { *ms6 = -2; return NULL; }
    if (!mark) {                        /* безымянный член пула v1 — только IPv4 (шапка) */
        v6 = 0;
        *ms6 = -2;
    }
    const char *url = g && g->url[0] ? g->url : GROUP_URL_DEFAULT;
    struct folat_m *fm = calloc(1, sizeof(*fm));
    if (!fm) return NULL;
    fm->cb = cb;
    fm->arg = arg;
    fm->ms4 = -1;
    fm->ms6 = v6 ? -1 : -2;
    snprintf(fm->grp, sizeof(fm->grp), "%s", go->name);
    snprintf(fm->key, sizeof(fm->key), "%s", m ? fog_lat_key(m) : dev);
    snprintf(fm->url, sizeof(fm->url), "%s", url);
    int r;
    fm->u4 = urltest_start(l, url, AF_INET, mark, mark ? NULL : dev, FOLAT_TIMEOUT_MS, fm_cb4, fm, &r);
    if (fm->u4) fm->left++;
    else {
        fm->ms4 = r;
        fm_note(fm, 4, r);            /* итог сразу: причина — у urltest_why, пока не начат другой замер */
    }
    if (v6) {
        fm->u6 = urltest_start(l, url, AF_INET6, mark, NULL, FOLAT_TIMEOUT_MS, fm_cb6, fm, &r);
        if (fm->u6) fm->left++;
        else fm->ms6 = r;
    }
    if (!fm->left) {
        *ms4 = fm->ms4;
        *ms6 = fm->ms6;
        free(fm);
        return NULL;
    }
    return fm;
}

void folat_member_cancel(struct folat_m *fm) {
    if (!fm) return;
    urltest_cancel(fm->u4);
    urltest_cancel(fm->u6);
    free(fm);
}

/* ---- расписание ------------------------------------------------------------------------------ */

struct fl_grp {
    int used;
    char name[32];
    struct folat *f;
    struct loop_timer *tm;
    /* Подряд неудавшихся кругов замера (у живого члена нет ответа проверочного узла) и когда
     * таймер сработает (loop_now_ms): по первому — повтор раньше срока (fl_delay_ms), по второму
     * folat_sync не отодвигает повтор, который и так ближе. */
    int fails;
    long due;
    /* Идущий замер: ключи членов на момент начала (сверка в конце), кого мерить, итоги. */
    int running;
    size_t n, k;
    /* По числу членов на момент начала замера (fl_alloc): раньше — массивы на 16. */
    char (*key)[32];
    unsigned char *todo;              /* по байту на члена: мерить ли */
    int v6;
    int *ms4, *ms6;
    struct folat_m *fm;
};

/* Группы расписания — по указателю на каждую: таймер держит адрес своей группы, и он не должен
 * переезжать, когда массив растёт. */
struct folat {
    struct folat_conf c;
    struct fl_grp **g;
    size_t g_n, g_cap;
    unsigned long rounds;
};

/* Массивы замера на n членов. 0 — есть; -1 — нет памяти. */
static int fl_alloc(struct fl_grp *g, size_t n) {
    free(g->key); free(g->todo); free(g->ms4); free(g->ms6);
    g->key = NULL; g->todo = NULL; g->ms4 = g->ms6 = NULL;
    if (!n) return 0;
    g->key = calloc(n, sizeof(*g->key));
    g->todo = calloc(n, 1);
    g->ms4 = calloc(n, sizeof(int));
    g->ms6 = calloc(n, sizeof(int));
    return g->key && g->todo && g->ms4 && g->ms6 ? 0 : -1;
}

/* Кандидаты группы go — массив в куче (free вызывающему); *n — сколько. NULL при n == 0 и без
 * памяти (тогда *n == 0). */
static const struct output **fl_cands(const struct spec *sp, const struct output *go, size_t *n) {
    size_t c = out_members_n(sp, go);
    *n = 0;
    if (!c) return NULL;
    const struct output **v = malloc(c * sizeof(*v));
    if (!v) return NULL;
    for (size_t k = 0; k < c; k++) v[k] = out_member(sp, go, k);
    *n = c;
    return v;
}

/* Группа по имени в спеке прямо сейчас — только latency с двумя членами и больше. */
static const struct output *fl_group(const struct spec *sp, const char *name) {
    if (!sp) return NULL;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        const struct group_cfg *g = out_group(o);
        if (strcmp(o->name, name) || !g || g->pick != PICK_LATENCY || g->members_n < 2) continue;
        return o;
    }
    return NULL;
}

static long fl_interval_ms(const struct output *go) {
    return (long)group_interval_s(out_group(go)) * 1000L;
}

/* Через сколько мс следующий круг: после удачного — interval, после неудавшегося — повтор раньше
 * (FOLAT_RETRY_S, дальше вдвое реже на каждый неудавшийся круг подряд), но не позже самого
 * interval: короче срок не станет у того, у кого он и так короткий. */
static long fl_delay_ms(const struct fl_grp *g, const struct output *go) {
    long iv = go ? fl_interval_ms(go) : FOLAT_INTERVAL_S * 1000L;
    if (g->fails <= 0) return iv;
    long r = FOLAT_RETRY_S * 1000L;
    for (int i = 1; i < g->fails && r < iv; i++) r *= 2;
    return r < iv ? r : iv;
}

static void fl_rearm_ms(struct fl_grp *g, long ms) {
    g->due = loop_now_ms() + ms;
    loop_timer_set(g->tm, ms);
}

static void fl_rearm(struct fl_grp *g, const struct output *go) {
    fl_rearm_ms(g, fl_delay_ms(g, go));
}

static void fl_abort(struct fl_grp *g) {
    folat_member_cancel(g->fm);
    g->fm = NULL;
    g->running = 0;
}

/* Члены группы go сейчас те же, что в начале замера? */
static int fl_same(const struct fl_grp *g, const struct output *const *cand, size_t n) {
    if (n != g->n) return 0;
    for (size_t k = 0; k < n; k++)
        if (strcmp(fog_lat_key(cand[k]), g->key[k])) return 0;
    return 1;
}

static void fl_finish(struct fl_grp *g) {
    struct folat *f = g->f;
    g->running = 0;
    f->rounds++;
    const struct spec *sp = f->c.spec(f->c.arg);
    const struct output *go = fl_group(sp, g->name);
    size_t cn = 0;
    const struct output **cand = go ? fl_cands(sp, go, &cn) : NULL;
    if (!go || !cand || !fl_same(g, cand, cn)) { free(cand); fl_rearm(g, go); return; }
    const struct group_cfg *gc = out_group(go);
    int *score = malloc(g->n * sizeof(int));
    struct folat_rec *rec = malloc(g->n * sizeof(*rec));
    if (!score || !rec) { free(score); free(rec); free(cand); fl_rearm(g, go); return; }
    folat_score(g->ms4, g->ms6, g->n, g->v6, score);
    long now = mono_s();
    /* Неудавшийся круг — у живого члена не ответил проверочный узел по IPv4 (у xsteer мерить нечем
     * вовсе, и такой круг повторяется с нарастающим сроком до самого interval — как обычный). У
     * пула v1 кандидаты мерятся все, живы они или нет, и мёртвый запас не повод повторять круг. */
    int bad = 0;
    for (size_t k = 0; group_named(gc) && k < g->n; k++)
        if (g->todo[k] && g->ms4[k] < 0) bad++;
    g->fails = bad ? (g->fails < 30 ? g->fails + 1 : g->fails) : 0;
    for (size_t k = 0; k < g->n; k++) {
        int mine = g->todo[k];
        rec[k].ms = mine ? score[k] : -2;
        rec[k].ms4 = mine && g->v6 ? g->ms4[k] : -2;
        rec[k].ms6 = mine && g->v6 ? g->ms6[k] : -2;
        rec[k].at = now;
        if (!mine) score[k] = -1;
    }
    folat_rec_put(f->c.st, g->name, cand, rec, g->n, 1);

    /* Сменил бы проход выбор? Тот же гистерезис, что у прохода (S_LAT_C в failover.c): лучший с
     * допуском, а с живого текущего — только при выигрыше больше допуска. */
    int cur = -1;
    char dev[32];
    active_get_st(f->c.st, go->name, dev, sizeof(dev));
    if (dev[0] && strcmp(dev, "-") != 0) {
        if (group_named(gc)) {
            cur = fog_groups_cur(f->c.st, sp, go);
        } else {
            for (size_t k = 0; k < g->n && cur < 0; k++)
                if (!strcmp(cand[k]->device, dev)) cur = (int)k;
        }
    }
    int tol = group_tolerance_ms(gc);
    int best = -1;
    int pick = group_latency_pick(score, g->n, tol, &best);
    if (cur >= 0 && pick >= 0 && pick != cur &&
        !(score[cur] >= 0 && group_latency_keep(score, cur, pick, tol)) && f->c.kick)
        f->c.kick(f->c.arg, g->name);
    free(score);
    free(rec);
    free(cand);
    fl_rearm(g, go);
}

static void fl_next(struct fl_grp *g);

static void fl_member_cb(void *arg, int ms4, int ms6) {
    struct fl_grp *g = arg;
    g->fm = NULL;
    g->ms4[g->k] = ms4;
    g->ms6[g->k] = ms6;
    g->k++;
    fl_next(g);
}

static void fl_next(struct fl_grp *g) {
    struct folat *f = g->f;
    while (g->k < g->n) {
        size_t k = g->k;
        if (!g->todo[k]) {
            g->ms4[k] = -1;
            g->ms6[k] = g->v6 ? -1 : -2;
            g->k++;
            continue;
        }
        const struct spec *sp = f->c.spec(f->c.arg);
        const struct output *go = fl_group(sp, g->name);
        size_t cn = 0;
        const struct output **cand = go ? fl_cands(sp, go, &cn) : NULL;
        if (!go || !cand || !fl_same(g, cand, cn)) {
            free(cand);
            g->running = 0;
            fl_rearm(g, go);
            return;
        }
        const struct output *m = cand[k];
        free(cand);                       /* m — указатель в спеку, не в этот массив */
        /* Устройство именованного члена — то, что выбрал его проход (запись active; у вложенной
         * группы — её лист); безымянного — его собственное. */
        char dev[32] = "";
        if (group_named(out_group(go))) active_get_st(f->c.st, m->name, dev, sizeof(dev));
        if (!strcmp(dev, "-")) {
            g->ms4[k] = -1;
            g->ms6[k] = g->v6 ? -1 : -2;
            g->k++;
            continue;
        }
        if (!dev[0]) snprintf(dev, sizeof(dev), "%s", m->device);
        int a4, a6;
        g->fm = folat_member(f->c.l, sp, go, m, dev, f->c.hs ? f->c.hs(f->c.arg) : NULL, g->v6,
                             fl_member_cb, g, &a4, &a6);
        if (g->fm) return;
        g->ms4[k] = a4;
        g->ms6[k] = a6;
        g->k++;
    }
    fl_finish(g);
}

static void fl_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct fl_grp *g = arg;
    struct folat *f = g->f;
    if (g->running) return;
    const struct spec *sp = f->c.spec(f->c.arg);
    const struct output *go = fl_group(sp, g->name);
    if (!go) return;                          /* ушла — folat_sync снимет слот */
    /* Без трафика через группу замеров нет (idle_timeout) — таймер идёт дальше. */
    if (fog_idle(sp, go, fog_idle_limit(go), f->c.traffic, f->c.arg)) { fl_rearm_ms(g, fl_interval_ms(go)); return; }
    size_t cn = 0;
    const struct output **cand = fl_cands(sp, go, &cn);
    if (!cand || fl_alloc(g, cn) != 0) { free(cand); fl_rearm(g, go); return; }
    g->n = cn;
    if (group_named(out_group(go))) {
        /* Живые — по последнему проходу; сторож группу ещё не проходил — мерить некого. */
        int any = 0;
        if (!fog_groups_alive(f->c.st, sp, go, g->todo)) { free(cand); fl_rearm(g, go); return; }
        for (size_t k = 0; k < cn; k++) any |= g->todo[k];
        if (!any) { free(cand); fl_rearm(g, go); return; }
    } else {
        memset(g->todo, 1, cn);
    }
    for (size_t k = 0; k < g->n; k++) snprintf(g->key[k], sizeof(g->key[k]), "%s", fog_lat_key(cand[k]));
    g->v6 = folat_want_v6(sp, go, g->todo);
    g->k = 0;
    g->running = 1;
    free(cand);
    fl_next(g);
}

struct folat *folat_new(const struct folat_conf *c) {
    struct folat *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->c = *c;
    return f;
}

static void fl_free(struct fl_grp *g) {
    fl_abort(g);
    loop_timer_free(g->tm);
    free(g->key); free(g->todo); free(g->ms4); free(g->ms6);
    memset(g, 0, sizeof(*g));
}

/* Место в списке групп под ещё одну; слот освобождённой группы (used == 0) берётся снова. */
static struct fl_grp *fl_slot(struct folat *f) {
    for (size_t s = 0; s < f->g_n; s++)
        if (!f->g[s]->used) return f->g[s];
    if (f->g_n == f->g_cap) {
        size_t nc = f->g_cap ? f->g_cap * 2 : 8;
        struct fl_grp **ng = realloc(f->g, nc * sizeof(*ng));
        if (!ng) return NULL;
        f->g = ng;
        f->g_cap = nc;
    }
    struct fl_grp *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    f->g[f->g_n++] = g;
    return g;
}

/* У живого члена группы (по записи groups последнего прохода) нет удачного замера: записи нет или
 * в ней «не ответил». Только у группы v2: у пула v1 живость членов в записи не хранится, и мёртвый
 * кандидат давал бы «нет замера» всегда. И только у группы, что мерится всегда: с паузой замера без
 * трафика (idle_timeout, умолчание телефона) замера нет не из-за неудачи, а потому что трафика нет, и
 * будить ради повтора незачем. */
static int fl_unmeasured(struct folat *f, const struct spec *sp, const struct output *go) {
    size_t n = out_members_n(sp, go);
    if (!n || !group_named(out_group(go)) || fog_idle_limit(go) > 0) return 0;
    unsigned char *al = calloc(n, 1);
    if (!al) return 0;
    int bad = 0;
    if (fog_groups_alive(f->c.st, sp, go, al))
        for (size_t k = 0; k < n && !bad; k++) {
            struct folat_rec rc;
            if (al[k] && (!folat_rec_get(f->c.st, go->name, fog_lat_key(out_member(sp, go, k)), &rc) ||
                          rc.ms < 0))
                bad = 1;
        }
    free(al);
    return bad;
}

void folat_sync(struct folat *f) {
    if (!f) return;
    const struct spec *sp = f->c.spec(f->c.arg);
    unsigned char *seen = calloc(f->g_n + 1, 1);       /* по слотам, что были до этого вызова */
    size_t was_n = f->g_n;
    if (!seen) return;
    for (size_t i = 0; sp && i < sp->out_n; i++) {
        const struct output *go = &sp->out[i];
        if (fl_group(sp, go->name) != go) continue;
        struct fl_grp *g = NULL;
        size_t gi = 0;
        for (size_t s = 0; s < f->g_n && !g; s++)
            if (f->g[s]->used && !strcmp(f->g[s]->name, go->name)) { g = f->g[s]; gi = s; }
        if (!g) {
            struct fl_grp *slot = fl_slot(f);
            if (!slot) continue;
            slot->tm = loop_timer_new(f->c.l, fl_timer, slot);
            if (!slot->tm) continue;
            slot->used = 1;
            slot->f = f;
            snprintf(slot->name, sizeof(slot->name), "%s", go->name);
            /* Первый замер — проходом (у членов замера ещё нет), дальше — таймером. */
            fl_rearm(slot, go);
            g = slot;
            for (size_t s = 0; s < f->g_n; s++) if (f->g[s] == slot) gi = s;
        } else if (!g->running && !loop_timer_armed(g->tm)) {
            fl_rearm(g, go);
        }
        /* Замер проходом (первый после старта, член ожил) мог не удаться у живого члена — и тогда
         * повтор раньше срока: до него группа шла бы «по порядку». Уже идущий повтор (fails) и
         * срок, что и так ближе, не трогаются. */
        if (!g->running && !g->fails && fl_unmeasured(f, sp, go)) {
            g->fails = 1;
            long ms = fl_delay_ms(g, go);
            if (g->due > loop_now_ms() + ms) fl_rearm_ms(g, ms);
        }
        if (gi < was_n) seen[gi] = 1;
    }
    for (size_t s = 0; s < was_n; s++)
        if (f->g[s]->used && !seen[s]) fl_free(f->g[s]);
    free(seen);
}

void folat_stop(struct folat *f) {
    if (!f) return;
    for (size_t s = 0; s < f->g_n; s++) {
        if (f->g[s]->used) fl_free(f->g[s]);
        free(f->g[s]);
    }
    free(f->g);
    f->g = NULL;
    f->g_n = f->g_cap = 0;
}

unsigned long folat_rounds(const struct folat *f) {
    return f ? f->rounds : 0;
}
