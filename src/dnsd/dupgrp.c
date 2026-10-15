/* ГРУППА СЕРВЕРОВ DNS: несколько апстримов как один (`{ servers: [...], mode: race | failover }` в
 * dns.upstreams, docs/spec-v2.md). Устройство апстримов — шапка dup.h.
 *
 * ЗАЧЕМ. Один сервер DoH бывает недоступен часами (блокировка, перегрузка, сбой у провайдера), и
 * с одним сервером у правила имена под ним получают SERVFAIL, пока сервер не вернётся. Группа
 * держит несколько серверов: либо спрашивает всех сразу и берёт первый годный ответ (race),
 * либо по очереди — следующий, когда предыдущий отказал или молчит (failover).
 *
 * ГРУППА ДЛЯ РЕЗОЛВЕРА — ОДИН АПСТРИМ. Она занимает своё место в настройке (dup_cfg с grp, свой
 * struct dup без сокетов), и proxy.c спрашивает её тем же dup_ask: обратный вызов ровно один — с
 * первым годным ответом (dup_ans_good: не SERVFAIL и не REFUSED; NXDOMAIN годен) или отказом, если
 * годного не дал никто. Члены — обычные апстримы той же настройки, со своими соединениями,
 * путями и паузами после неудачи соединения; группа только решает, кого и когда спросить.
 *
 * RACE. Вопрос уходит всем членам без паузы сразу, в порядке спеки. Первый годный ответ уходит
 * клиенту, остальные ответы приходят и выбрасываются (каждому члену их вопрос — свой, dup отвечает на
 * каждый ровно один раз). Отказ — когда отказали все. Член, отказавший прежде, на паузе (как у
 * failover) и не спрашивается, пока она идёт.
 *
 * ВЫЖИВАНИЕ. Все члены на паузе — вопрос уходит ОДНОМУ, наименее плохому (grp_ask): без обхода и без
 * веера. Годный ответ снимает паузу, только если вопрос ушёл позже последнего отказа (dpause_ok_at).
 *
 * FAILOVER. Порядок опроса — порядок спеки, но член на паузе (struct dpause, dup.h: отказал — не
 * ответил за срок, нет соединения, SERVFAIL или REFUSED) уходит в конец, за всех без паузы, и
 * паузы между собой — по сроку окончания. Вопрос уходит первому; отказал — сразу следующему; не
 * ответил за GRP_STEP_MS — вопрос уходит и следующему, а первый ещё может успеть (годный ответ от
 * любого из спрошенных — ответ группы). Медленный, но отвечающий член паузу не получает: пауза — за
 * отказ, а не за медлительность. Пауза кончилась — член снова первый в своём порядке, и следующий
 * вопрос проверяет его по-настоящему; ответил годно — пауза снята, отказал — она вдвое длиннее.
 *
 * ЦИКЛ. Следующий член спрашивается не из обратного вызова отказавшего, а из grp_tick (каждый виток
 * цикла, dup_tick): обратный вызов приходит изнутри разбора соединения апстрима, и новый вопрос к
 * другому члену оттуда мог бы цепочкой обратных вызовов дойти до того же соединения. Отложенный на
 * один виток вопрос стоит микросекунды; dup_wait_ms тогда велит циклу не спать.
 *
 * ПАМЯТЬ. Вопрос группы (struct greq) — в куче, со своими местами членов; он живёт, пока не отвечен
 * вызывающему И пока не вернулись все принятые вопросы членов: их обратные вызовы держат адрес
 * места. Группа перенастроена или убрана (поколение struct dup сменилось) — вопрос дожидается
 * спрошенных, новых не задаёт и паузы не трогает. Чисел членов и вопросов константой нет. */

#include "dnsd_int.h"
#include "dupint.h"

/* Сколько ждать ответа члена failover, прежде чем спросить и следующего. Рукопожатие TLS к DoH
 * через туннель бывает и дольше, но тогда второй вопрос — лишь страховка: ответит тот, кто
 * быстрее. */
#define GRP_STEP_MS 1500
#define PAUSE_FIRST_MS 5000L
#define PAUSE_MAX_MS 300000L

long dup_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static long pause_first(void) {
    static long v;
    if (!v) {
        const char *e = getenv("STEER_DNSD_PAUSE_MS");
        long x = e ? atol(e) : 0;
        v = x >= 100 ? x : PAUSE_FIRST_MS;
    }
    return v;
}

void dpause_ok(struct dpause *p) {
    p->ok++;
    p->step_ms = 0;
    p->until_ms = 0;
}

void dpause_ok_at(struct dpause *p, long sent_ms) {
    if (sent_ms < p->fail_ms) {         /* вопрос старше последнего отказа: в счёт, но паузу не трогает */
        p->ok++;
        return;
    }
    dpause_ok(p);
}

void dpause_fail(struct dpause *p, long now) {
    p->fail++;
    p->fail_ms = now;
    p->step_ms = p->step_ms ? p->step_ms * 2 : pause_first();
    if (p->step_ms > PAUSE_MAX_MS) p->step_ms = PAUSE_MAX_MS;
    p->until_ms = now + p->step_ms;
}

int dpause_on(const struct dpause *p, long now) { return p->until_ms > now; }

int dup_ans_good(const uint8_t *ans, size_t n) {
    if (!ans || n < 12) return 0;
    int rc = ans[3] & 0x0f;
    return rc != 2 && rc != 5;
}

/* ---- вопрос группы ---------------------------------------------------------------------------- */

struct greq;
struct gsub {
    struct greq *r;
    size_t pos;                 /* номер члена в группе (в cfg.gm) */
    int st;                     /* 0 — не спрошен, 1 — ждём, 2 — вернулся */
    long sent_ms;               /* когда вопрос ушёл члену (для dpause_ok_at) */
};
struct greq {
    struct greq *link;          /* список живых вопросов (g_greqs) */
    struct dup *g;
    unsigned g_gen;
    dup_done_fn cb;
    void *ctx;
    int done;                   /* вызывающему уже ответили */
    int busy;                   /* идёт greq_step: обратные вызовы членов не освобождают вопрос */
    int want;                   /* failover: спросить следующего (отказ или срок) */
    int outstanding;            /* принятых вопросов членов, чей ответ ещё не вернулся */
    size_t n, next;             /* членов; сколько из order уже спрошено */
    long step_at;               /* failover: когда спросить следующего, если ответа нет (0 — не ждём) */
    size_t *order;              /* порядок опроса: номера членов */
    uint8_t q[DUP_QMAX];
    uint16_t qn;
    struct gsub sub[];
};

static struct greq *g_greqs;

static int greq_alive(const struct greq *r) { return r->g->live && r->g->gen == r->g_gen; }

static void greq_unlink_free(struct greq *r) {
    for (struct greq **pp = &g_greqs; *pp; pp = &(*pp)->link)
        if (*pp == r) { *pp = r->link; break; }
    free(r->order);
    free(r);
}

/* Ответить вызывающему отказом, если спрашивать больше некого и ждать нечего. Освободить вопрос,
 * если ответ отдан и все члены вернулись. Зовётся вне greq_step. */
static void greq_settle(struct greq *r) {
    if (!r->done && r->outstanding == 0 && (r->next >= r->n || !greq_alive(r))) {
        r->done = 1;
        if (greq_alive(r)) r->g->q_fail++;
        r->cb(r->ctx, NULL, 0, r->q, r->qn);
    }
    if (r->done && r->outstanding == 0) greq_unlink_free(r);
}

/* Итог члена: отказ — пауза (dpause), годный ответ её снимает, но только если вопрос ушёл позже
 * последнего отказа. Одинаково у failover и race: по паузам группа решает, кого спрашивать (grp_ask). */
static void member_note(struct dup *g, size_t pos, int good, long sent_ms) {
    struct dpause *p = &g->gp[pos];
    if (good) dpause_ok_at(p, sent_ms);
    else dpause_fail(p, dup_now_ms());
}

static void member_done(void *ctx, const uint8_t *ans, size_t n, const uint8_t *q, size_t qn) {
    (void)q; (void)qn;
    struct gsub *s = ctx;
    struct greq *r = s->r;
    s->st = 2;
    r->outstanding--;
    int good = dup_ans_good(ans, n);
    if (greq_alive(r) && s->pos < r->g->cfg.gm_n) member_note(r->g, s->pos, good, s->sent_ms);
    if (!r->done && good) {
        r->done = 1;
        if (greq_alive(r)) { r->g->q_ok++; r->g->ok_ms = dup_now_ms(); }
        r->cb(r->ctx, ans, n, r->q, r->qn);
    } else if (!r->done && greq_alive(r) && r->g->cfg.grp == DNSG_FAILOVER) {
        r->want++;                              /* следующего — на следующем витке (grp_tick) */
    }
    if (!r->busy) greq_settle(r);
}

/* Спросить тех, кого пора: race — всех ещё не спрошенных, failover — следующего по порядку, если
 * некого ждать или пришёл отказ/срок. Члена, не принявшего вопрос сразу (пауза соединения, нет
 * метки выхода, нет TLS), failover пропускает к следующему тут же. */
static void greq_step(struct greq *r) {
    r->busy = 1;
    while (!r->done && greq_alive(r) && r->next < r->n) {
        int race = r->g->cfg.grp == DNSG_RACE;
        if (!race && !(r->want > 0 || r->outstanding == 0)) break;
        if (r->want > 0) r->want--;
        size_t pos = r->order[r->next++];
        struct gsub *s = &r->sub[pos];
        unsigned idx = r->g->cfg.gm[pos];
        s->st = 1;
        s->sent_ms = dup_now_ms();
        r->outstanding++;
        if (idx >= g_dups_n || !g_dups[idx] || g_dups[idx] == r->g || g_dups[idx]->cfg.grp ||
            dup_ask(idx, r->q, r->qn, member_done, s) != 0) {
            r->outstanding--;
            s->st = 2;
            member_note(r->g, pos, 0, s->sent_ms);
            if (!race) r->want++;
            continue;
        }
        if (!race) r->step_at = dup_now_ms() + GRP_STEP_MS;
    }
    /* Спрашивать больше некого: ни отказ, ни срок нового вопроса не дадут — и будить цикл незачем. */
    if (r->next >= r->n) { r->want = 0; r->step_at = 0; }
    r->busy = 0;
}

int grp_ask(struct dup *g, const uint8_t *q, size_t n, dup_done_fn cb, void *ctx) {
    size_t m = g->cfg.gm_n;
    if (!m || !g->gp || n < 12 || n > DUP_QMAX) return -1;
    struct greq *r = calloc(1, sizeof(*r) + m * sizeof(r->sub[0]));
    size_t *ord = malloc(m * sizeof(*ord));
    if (!r || !ord) { free(r); free(ord); return -1; }
    r->g = g;
    r->g_gen = g->gen;
    r->cb = cb;
    r->ctx = ctx;
    r->n = m;
    r->order = ord;
    memcpy(r->q, q, n);
    r->qn = (uint16_t)n;
    for (size_t i = 0; i < m; i++) { r->sub[i].r = r; r->sub[i].pos = i; }
    /* Порядок и состав. Без паузы — по спеке. Все на паузе (выживание): ОДНА попытка через наименее
     * плохого — с самым коротким нынешним сроком паузы (меньше подряд отказов), при равных — чья пауза
     * кончается раньше; не обход всех и не веер. Отказавший уходит на паузу вдвое длиннее, и со
     * следующим вопросом наименее плохим становится другой. Часть на паузе: race спрашивает только
     * тех, кто без паузы (известно плохих не дёргает), failover ставит их следом, по сроку окончания
     * паузы, — запасной ход, если отказали все без паузы. */
    long now = dup_now_ms();
    size_t k = 0;
    for (size_t i = 0; i < m; i++)
        if (!dpause_on(&g->gp[i], now)) ord[k++] = i;
    if (!k) {
        size_t best = 0;
        for (size_t i = 1; i < m; i++) {
            const struct dpause *a = &g->gp[i], *b = &g->gp[best];
            if (a->step_ms < b->step_ms || (a->step_ms == b->step_ms && a->until_ms < b->until_ms)) best = i;
        }
        ord[k++] = best;
    } else if (g->cfg.grp != DNSG_RACE) {
        size_t first_paused = k;
        for (size_t i = 0; i < m; i++)
            if (dpause_on(&g->gp[i], now)) {
                size_t j = k++;
                while (j > first_paused && g->gp[ord[j - 1]].until_ms > g->gp[i].until_ms) {
                    ord[j] = ord[j - 1];
                    j--;
                }
                ord[j] = i;
            }
    }
    r->n = k;
    r->link = g_greqs;
    g_greqs = r;
    g->q_sent++;
    greq_step(r);
    greq_settle(r);
    return 0;
}

/* Виток цикла: failover — спросить следующего тем, у кого отказ или срок ответа вышел. */
void grp_tick(long now) {
    for (struct greq *r = g_greqs, *nx; r; r = nx) {
        nx = r->link;
        if (r->done) continue;
        if (r->g->cfg.grp == DNSG_FAILOVER && r->step_at && now >= r->step_at && r->outstanding > 0 &&
            r->next < r->n) {
            r->step_at = 0;
            r->want++;
        }
        /* Группа перенастроена — новых вопросов нет, вопрос ждёт ответов спрошенных (member_done). */
        if (r->want > 0 && greq_alive(r)) {
            greq_step(r);
            nx = r->link;               /* settle может освободить r: следующий взят до этого */
            greq_settle(r);
        }
    }
}

long grp_deadline(void) {
    long best = -1;
    for (const struct greq *r = g_greqs; r; r = r->link) {
        /* Спрашивать больше некого или группа перенастроена: ждём только ответов, сроки — у dup. */
        if (r->done || r->next >= r->n || !greq_alive(r)) continue;
        long t = r->want > 0 ? 0 : r->step_at ? r->step_at : -1;
        if (t >= 0 && (best < 0 || t < best)) best = t;
    }
    return best;
}

int grp_busy(void) { return g_greqs != NULL; }

/* Состояние группы для dns-log: ready — хоть один член без паузы и в порядке (ready/idle/
 * connecting), down — все на паузе или не могут работать. Члены — с паузой и счётчиками; active —
 * кого failover спросит первым сейчас. */
void grp_render(FILE *f, const struct dup *g) {
    long now = dup_now_ms();
    int alive = 0;
    long active = -1;
    for (size_t i = 0; i < g->cfg.gm_n; i++) {
        unsigned idx = g->cfg.gm[i];
        if (idx >= g_dups_n || !g_dups[idx] || !g->gp) continue;
        const char *st = dup_state(g_dups[idx]);
        int ok = !dpause_on(&g->gp[i], now) && (!strcmp(st, "ready") || !strcmp(st, "idle") ||
                                                 !strcmp(st, "connecting"));
        alive += ok;
        if (ok && active < 0) active = (long)i;
    }
    const char *state = alive ? (g->q_ok ? "ready" : "idle") : (g->q_sent ? "down" : "idle");
    fprintf(f, "\"proto\":\"group\",\"mode\":\"%s\",\"via\":null,\"state\":\"%s\",\"sent\":%lu,"
               "\"ok\":%lu,\"failed\":%lu,\"last_ok_ago\":",
            g->cfg.grp == DNSG_RACE ? "race" : "failover", state, g->q_sent, g->q_ok, g->q_fail);
    if (g->ok_ms) fprintf(f, "%ld", (now - g->ok_ms) / 1000); else fputs("null", f);
    fputs(",\"active\":", f);
    if (g->cfg.grp == DNSG_FAILOVER && active >= 0)
        fprintf(f, "\"%s\"", g_dups[g->cfg.gm[active]]->cfg.u.name);
    else fputs("null", f);
    fputs(",\"servers\":[", f);
    int shown = 0;
    for (size_t i = 0; i < g->cfg.gm_n; i++) {
        unsigned idx = g->cfg.gm[i];
        if (idx >= g_dups_n || !g_dups[idx] || !g->gp) continue;
        const struct dpause *p = &g->gp[i];
        long left = dpause_on(p, now) ? (p->until_ms - now + 999) / 1000 : 0;
        fprintf(f, "%s{\"name\":\"%s\",\"pause\":%ld,\"ok\":%lu,\"failed\":%lu}", shown++ ? "," : "",
                g_dups[idx]->cfg.u.name, left, p->ok, p->fail);
    }
    fputc(']', f);
}
