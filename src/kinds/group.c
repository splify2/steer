/* kind=group — ГРУППА ВЫХОДОВ (docs/architecture.md, «4в»).
 *
 * Группа — выход, у которого вместо своего устройства члены: другие выходы. Своя метка, своя
 * таблица и свой on_fail у неё есть, как у любого выхода с устройством, — правило ведёт трафик в
 * группу, а сторож привязывает таблицу группы к устройству выбранного члена. КАК выбрать, говорит
 * pick (group_cfg в spec.h):
 *   order   — первый живой член по порядку. Это прежний пул `devices` у выхода v1: перевод
 *             (model/v1.c) делает из каждого устройства безымянный член-интерфейс, а имя группы
 *             — прежнее имя выхода, поэтому status, реестр меток и имена наборов не меняются;
 *   latency — самый быстрый с допуском (прежний `prefer: latency`); задержка — urltest,
 *             HTTP(S)-запрос к url через члена (src/daemon/urltest.c);
 *   manual  — член, выбранный человеком командой `select` (default — до первой команды);
 *   balance — ядро раскидывает НОВЫЕ соединения по живым членам: правило группы переходит в
 *             свою цепочку, та по карте `numgen random mod GROUP_BAL_SLOTS` ставит метку члена и
 *             сохраняет её в метке соединения (compile/generate.c, build_balance); упавший член
 *             сторож вынимает из карты по netlink (src/daemon/fogroup.c).
 * Спека v1 рождает только order и latency из безымянных членов; v2 — все четыре из именованных.
 *
 * ВЛОЖЕННОСТЬ. Член группы — любой выход с устройством, в том числе другая группа. order, latency
 * и manual разворачивают выбор до ЛИСТА: таблица группы ведёт в устройство, которое сейчас несёт
 * трафик выбранного члена (у вложенной группы — её текущий лист; сторож проходит вложенную
 * раньше внешней). У balance вложенная группа — ОДИН член со своим весом: её метка ведёт в её
 * таблицу, а таблица — в её текущий лист, то есть её собственный выбор (order, manual) внутри
 * доли balance сохраняется; вложенная balance — переход в её цепочку, и доля внешней делится
 * внутренней по её весам. Группа balance членом order/latency/manual быть не может: у таких
 * групп одна таблица — одно устройство, а у balance устройство на каждое соединение своё.
 *
 * ЧТО ЗДЕСЬ, А ЧТО У СТОРОЖА. Сторож (src/daemon/failover.c) — автомат на цикле событий: он
 * пробует устройства, ждёт ответов и оживляет. Решения о выборе — чистые функции над ответами
 * проб — здесь: первый живой, выбор по замеру с допуском, гистерезис возврата. Их зовёт сторож в
 * тех же местах и в том же порядке, в каких прежде принимал их сам, поэтому число проб и их
 * порядок прежние (это проверяет стенд failovermatch).
 *
 * КАК ГРУППА ОТВЕЧАЕТ НА ВОПРОСЫ О ВИДЕ. Свойства группы — пересечение свойств её членов
 * (group_seal): у пула интерфейсов это ровно свойства интерфейса без obfs, то есть устройство,
 * метка, метка соединения, мимо общего обхода — всё, по чему компилятор, apply и сторож вели
 * прежний пул. Своих проб, оживления, помощника и правил у группы нет (функции NULL): проба и
 * оживление принадлежат устройству и его владельцу (out_for_device), а у безымянного члена
 * владельца нет — и тогда отвечает группа тем же общим путём, каким отвечал выход-пул вида
 * interface (ICMP, ifdown/ifup). */
#include <stdio.h>
#include <string.h>

#include "spec.h"

/* Спека v2 знает группу по имени; спека v1 — нет (kind_by_name её не находит, см. kind.h). */
const struct kind_ops *kind_by_name_v2(const char *name) {
    if (!strcmp(name, kind_group.name)) return &kind_group;
    return kind_by_name(name);
}

const struct group_cfg *out_group(const struct output *o) {
    return kind_of(o) == &kind_group ? &o->grp : NULL;
}

const struct kind_ops *out_kind_shown(const struct output *o) {
    const struct group_cfg *g = out_group(o);
    return g && g->shown ? g->shown : kind_of(o);
}

const char *out_kind_name(const struct output *o) {
    return out_kind_shown(o)->name;
}

size_t out_members_n(const struct spec *sp, const struct output *o) {
    (void)sp;
    const struct group_cfg *g = out_group(o);
    if (g) return g->members_n;
    return out_has_device(o) ? 1 : 0;
}

const struct output *out_member(const struct spec *sp, const struct output *o, size_t i) {
    const struct group_cfg *g = out_group(o);
    return g ? spec_out(sp, g->members[i]) : o;
}

void group_cfg_init(struct group_cfg *g) {
    memset(g, 0, sizeof(*g));
    g->def = -1;
    g->lat_tolerance_ms = -1;
    g->idle_timeout_s = -1;
    g->cur = -1;
    g->sel = -1;
}

int group_members_alloc(struct spec *sp, struct group_cfg *g, size_t n) {
    g->members_n = 0;
    g->members = NULL;
    g->weight = g->alive = NULL;
    g->lat_ms = g->lat4_ms = g->lat6_ms = NULL;
    if (!n) return 0;
    g->members = (unsigned *)spec_alloc(sp, n * sizeof(*g->members));
    g->weight = (unsigned char *)spec_alloc(sp, n);
    g->alive = (unsigned char *)spec_alloc(sp, n);
    g->lat_ms = (int *)spec_alloc(sp, n * sizeof(int));
    g->lat4_ms = (int *)spec_alloc(sp, n * sizeof(int));
    g->lat6_ms = (int *)spec_alloc(sp, n * sizeof(int));
    if (!g->members || !g->weight || !g->alive || !g->lat_ms || !g->lat4_ms || !g->lat6_ms) return -1;
    for (size_t i = 0; i < n; i++) {
        g->lat_ms[i] = -1;
        g->lat4_ms[i] = g->lat6_ms[i] = -2;
    }
    return 0;
}

int group_named(const struct group_cfg *g) {
    return g && g->members_n && spec_is_named(g->members[0]);
}

int group_seal(struct spec *sp, struct output *go, struct err *e) {
    struct group_cfg *g = &go->grp;
    if (!g->members_n) return err_set(e, "outputs.%s: у группы нет членов", go->name);
    /* Единственный предел числа членов, и он — свойство карты balance (kind.h, GROUP_BAL_SLOTS):
     * у члена без слота доли нет. Остальные pick пределов по числу членов не имеют. */
    if (g->pick == PICK_BALANCE && g->members_n > GROUP_BAL_SLOTS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "outputs.%.31s: у группы pick: balance членов не больше %d "
                 "(в карте ядра %d слотов, у каждого члена нужен хотя бы один), а их %zu",
                 go->name, GROUP_BAL_SLOTS, GROUP_BAL_SLOTS, g->members_n);
        return err_set(e, "%s", msg);
    }
    unsigned caps = ~0u;
    for (size_t i = 0; i < g->members_n; i++) {
        const struct output *m = spec_out(sp, g->members[i]);
        /* Вложенная группа замыкается раньше внешней (разбор v2 идёт по вложенности), и её
         * свойства уже посчитаны. balance внутри группы с одной таблицей — отказ: выбрать ей
         * одно устройство нечем (см. шапку, «ВЛОЖЕННОСТЬ»). */
        const struct group_cfg *mg = out_group(m);
        if (mg && mg->pick == PICK_BALANCE && g->pick != PICK_BALANCE) {
            char msg[400];
            snprintf(msg, sizeof(msg), "outputs.%s: %s — группа pick: balance, а членом группы pick: %s "
                     "она быть не может: у такой группы трафик идёт в одно устройство, а у balance "
                     "устройство на каждое соединение своё", go->name, m->name,
                     group_pick_name(g->pick));
            return err_set(e, "%s", msg);
        }
        if (!out_has_device(m))
            return err_set(e, "outputs.%s: член группы без устройства", go->name);
        caps &= out_caps(m);
    }
    /* Своего сокета наверх и своего процесса у группы нет: KC_OVER и KC_ENGINE_OWNED — свойства
     * членов, не группы. У пула интерфейсов без obfs их и не было. */
    g->caps = caps & ~(unsigned)(KC_OVER | KC_ENGINE_OWNED);
    return 0;
}

int group_of_devices(struct spec *sp, struct output *o, const char (*devs)[32], size_t n,
                     struct err *e) {
    if (spec_grow((void **)&sp->anon, &sp->anon_cap, sp->anon_n + n, sizeof(*sp->anon)) != 0)
        return err_set(e, "%s", "недостаточно памяти для спеки");
    /* Члены — того же вида, каким был выход: пул `devices` у interface — это интерфейсы. Своих
     * настроек вида (obfs) у безымянного члена нет: их нёс выход, а не его устройства. */
    const struct kind_ops *k = kind_of(o);
    struct output g = {0};
    memcpy(g.name, o->name, sizeof(g.name));
    memcpy(g.device, o->device, sizeof(g.device));
    memcpy(g.over, o->over, sizeof(g.over));
    g.on_fail = o->on_fail;
    g.mark = o->mark;
    g.table = o->table;
    g.kind = &kind_group;
    group_cfg_init(&g.grp);
    g.grp.shown = k;
    if (group_members_alloc(sp, &g.grp, n) != 0) return err_set(e, "%s", "недостаточно памяти для спеки");
    for (size_t i = 0; i < n; i++) {
        size_t idx = SPEC_ANON_BASE + sp->anon_n++;
        struct output *m = spec_out(sp, idx);
        memset(m, 0, sizeof(*m));
        m->kind = k;
        snprintf(m->device, sizeof(m->device), "%s", devs[i]);
        m->on_fail = o->on_fail;
        g.grp.members[g.grp.members_n++] = (unsigned)idx;
    }
    /* Активное устройство до первого прохода сторожа — первое по предпочтению, если выход не
     * назвал своё (так делал разбор interface: device выводится из devices[0]). */
    if (!g.device[0] && n) snprintf(g.device, sizeof(g.device), "%s", devs[0]);
    *o = g;
    return group_seal(sp, o, e);
}

int group_tolerance_ms(const struct group_cfg *g) {
    return g && g->lat_tolerance_ms >= 0 ? g->lat_tolerance_ms : GROUP_TOL_DEFAULT_MS;
}

int group_interval_s(const struct group_cfg *g) {
    return g && g->lat_interval_s > 0 ? g->lat_interval_s : GROUP_INT_DEFAULT_S;
}

int group_latency_pick(const int *ms, size_t n, int tol, int *best) {
    int b = -1;
    for (size_t k = 0; k < n; k++)
        if (ms[k] >= 0 && (b < 0 || ms[k] < b)) b = ms[k];
    *best = b;
    if (b < 0) return -1;
    for (size_t k = 0; k < n; k++)
        if (ms[k] >= 0 && ms[k] - b <= tol) return (int)k;
    return -1;
}

int group_latency_keep(const int *ms, int cur, int pick, int tol) {
    return ms[cur] - ms[pick] <= tol;
}

int group_latency_why(const int *ms, const unsigned char *alive, size_t n, int cur, int tol,
                      int *fastest) {
    int f = -1;
    for (size_t k = 0; k < n; k++)
        if (alive[k] && ms[k] >= 0 && (f < 0 || ms[k] < ms[f])) f = (int)k;
    if (fastest) *fastest = f;
    if (cur < 0 || (size_t)cur >= n) return GW_NONE;
    if (f < 0) return GW_NOMEASURE;
    if (!alive[cur] || ms[cur] < 0) return GW_UNMEASURED;
    if (ms[cur] == ms[f]) return GW_FASTEST;
    return ms[cur] - ms[f] <= tol ? GW_TOLERANCE : GW_PENDING;
}

const char *group_why_name(int why) {
    switch (why) {
    case GW_NOMEASURE:  return "no_measure";
    case GW_UNMEASURED: return "unmeasured";
    case GW_FASTEST:    return "fastest";
    case GW_TOLERANCE:  return "in_tolerance";
    case GW_PENDING:    return "pending";
    case GW_IDLE:       return "idle";
    default:            return NULL;
    }
}

void group_latency_score(const int *ms4, const int *ms6, size_t n, int *score) {
    int any6 = 0;
    for (size_t k = 0; k < n; k++)
        if (ms6[k] >= 0) any6 = 1;
    for (size_t k = 0; k < n; k++) {
        if (!any6) score[k] = ms4[k] >= 0 ? ms4[k] : -1;
        else if (ms4[k] < 0 || ms6[k] < 0) score[k] = -1;
        else score[k] = ms4[k] > ms6[k] ? ms4[k] : ms6[k];
    }
}

int group_hysteresis(int cur, int first, int cur_alive, int streak, int hyst, int *new_streak) {
    *new_streak = 0;
    if (cur > first && cur_alive) {
        int s = streak + 1;
        if (hyst > 0 && s < hyst) { *new_streak = s; return cur; }
    }
    return first;
}

const char *group_pick_name(int p) {
    static const char *const N[] = { "order", "latency", "manual", "balance" };
    return p >= 0 && (size_t)p < sizeof(N) / sizeof(N[0]) ? N[p] : "order";
}

const char *group_by_name(int b) {
    static const char *const N[] = { "connection", "site", "site_client" };
    return b >= 0 && (size_t)b < sizeof(N) / sizeof(N[0]) ? N[b] : "connection";
}

/* РАЗДАЧА СЛОТОВ balance. Правило ядра — `numgen random mod GROUP_BAL_SLOTS vmap @карта` (у by: site
 * и site_client — `jhash … mod GROUP_BAL_SLOTS`): число слотов постоянное, а меняются только
 * элементы карты. Иначе уход члена менял бы `mod N` в самом правиле, то есть правило, а не элемент,
 * — а переписывать правило сторож не должен (ни процесса nft, ни перезагрузки набора на отказ
 * туннеля). 120 делится на 1..6, 8, 10, 12, 15: у частых случаев (2-6 равных членов) доли точные,
 * у семи — 17 и 18 слотов, перекос долей ~6%.
 *
 * Доля — по весам живых членов методом наибольшего остатка. Слоты при всех живых раздаются подряд,
 * по порядку членов, — это ОСНОВНАЯ раскладка. Когда кто-то лёг, живые сохраняют свои слоты
 * основной раскладки (сколько их влезает в новую долю), а добирают долю слотами ушедших. Для
 * случайного numgen это всё равно, а у хеша (by: site) слот — это сайты: перекладка подряд по живым
 * сдвигала бы границы, и сайты живых членов переезжали бы на соседа от чужого отказа. Вернулся член
 * — карта снова основная, и его сайты — снова на нём. Чистая функция: её зовут компилятор (карта
 * при apply — все члены живы) и сторож (карта по живым), а сверяет стенд. */
static void bal_split(const unsigned *w, size_t n, unsigned *cnt, unsigned *rem) {
    unsigned total = 0, used = 0;
    for (size_t k = 0; k < n; k++) total += w[k];
    memset(cnt, 0, n * sizeof(*cnt));
    if (!total) return;
    for (size_t k = 0; k < n; k++) {
        cnt[k] = GROUP_BAL_SLOTS * w[k] / total;
        rem[k] = GROUP_BAL_SLOTS * w[k] % total;
        used += cnt[k];
    }
    /* Остаток слотов — тем, у кого больше дробная часть; при равенстве — первому по порядку. */
    while (used < GROUP_BAL_SLOTS) {
        size_t best = n;
        for (size_t k = 0; k < n; k++)
            if (w[k] && (best == n || rem[k] > rem[best])) best = k;
        cnt[best]++;
        rem[best] = 0;
        used++;
    }
}

void group_balance_slots(const struct group_cfg *g, const unsigned char *alive,
                         unsigned char owner[GROUP_BAL_SLOTS]) {
    size_t n = g->members_n;
    memset(owner, 0xff, GROUP_BAL_SLOTS);
    /* Рабочие массивы — по числу членов, одним куском (w, cnt, rem, keep). Членов больше слотов у
     * balance не бывает (group_seal), но функция чистая и от этого не зависит. */
    unsigned *buf = n ? (unsigned *)calloc(4 * n, sizeof(unsigned)) : NULL;
    if (!buf) return;
    unsigned *w = buf, *cnt = buf + n, *rem = buf + 2 * n, *keep = buf + 3 * n;
    /* Основная раскладка: все живы. */
    for (size_t k = 0; k < n; k++) w[k] = g->weight[k] ? g->weight[k] : 1u;
    bal_split(w, n, cnt, rem);
    size_t s = 0;
    for (size_t k = 0; k < n; k++)
        for (unsigned c = 0; c < cnt[k] && s < GROUP_BAL_SLOTS; c++) owner[s++] = (unsigned char)k;
    if (!alive) { free(buf); return; }
    /* Доли живых; слоты основной раскладки остаются у хозяина, пока его доля не набрана. */
    for (size_t k = 0; k < n; k++)
        if (!alive[k]) w[k] = 0;
    bal_split(w, n, cnt, rem);
    for (s = 0; s < GROUP_BAL_SLOTS; s++) {
        unsigned k = owner[s];
        if (k < n && w[k] && keep[k] < cnt[k]) keep[k]++;
        else owner[s] = 0xff;
    }
    /* Свободные слоты (ушедших и лишние) — недобравшим, по порядку членов. */
    size_t k = 0;
    for (s = 0; s < GROUP_BAL_SLOTS; s++) {
        if (owner[s] != 0xff) continue;
        while (k < n && keep[k] >= cnt[k]) k++;
        if (k == n) break;
        owner[s] = (unsigned char)k;
        keep[k]++;
    }
    free(buf);
}

/* Имена объектов balance в таблице движка — по номеру таблицы выхода из реестра, а не по имени:
 * имя выхода бывает до 31 байта, и с приставкой оно не влезло бы в предел имени цепочки старых
 * ядер (32 с нулём, ядро 4.9 телефона). Номер таблицы у выхода свой и живёт в реестре. */
void group_bal_chain(const struct output *o, char *dst, size_t n) {
    snprintf(dst, n, "bal_%d", o->table);
}
void group_bal_map(const struct output *o, char *dst, size_t n) {
    snprintf(dst, n, "balmap_%d", o->table);
}
void group_mark_chain(const struct output *o, char *dst, size_t n) {
    snprintf(dst, n, "mark_%d", o->table);
}
void group_bal_target(const struct output *m, char *dst, size_t n) {
    const struct group_cfg *g = out_group(m);
    if (g && g->pick == PICK_BALANCE) group_bal_chain(m, dst, n);
    else group_mark_chain(m, dst, n);
}

static unsigned group_caps_of(const struct output *o) {
    return o->grp.caps;
}

const struct kind_ops kind_group = {
    .name = "group",
    .caps_of = group_caps_of,
    .novia = "группа",
};
