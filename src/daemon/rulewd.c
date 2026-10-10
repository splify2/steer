/* Страж правил выходов: чужое удаление наших ip rule демон замечает сам и возвращает правила.
 *
 * ЗАЧЕМ. netd на телефоне при каждом своём (пере)запуске стирает все правила маршрутизации,
 * кроме приоритета 0 (RouteController::Init → flushRules), и перестраивает свои цепочки iptables —
 * вместе с ними пропадают правила fwmark наших выходов (приоритет 9000) и masquerade. До этого
 * их возвращал только очередной проход сторожа («маршрутизация разъехалась») — через минуту, а
 * masquerade — через десять; всё это время помеченный трафик уходил напрямую, мимо туннеля. На
 * роутере то же делает netifd при каждом своём старте (`/etc/init.d/network restart`: снимает все
 * правила и ставит свои local, main, default — проверка на QEMU 04664a5) и чужой `ip rule
 * flush` (скрипт, другой пакет маршрутизации). Поэтому механизм один на обе платформы и живёт в
 * демоне-движке (`--watch`).
 *
 * СОБЫТИЯ. Отдельный сокет rtnetlink на группы RTNLGRP_IPV4_RULE и RTNLGRP_IPV6_RULE (с 1.9 у
 * выходов с KC_IPV6 есть и правила IPv6 — docs/architecture.md, «4б», — и проверка ниже сверяет
 * оба семейства). Фильтр BPF на сокете пропускает из ядра только RTM_DELRULE: netd добавляет и
 * снимает свои правила на каждой смене сети, и будить демон ради чужих добавлений незачем. Из
 * удалений повод — только наше правило: метка в поле меток движка с нашей маской
 * (STEER_MARK_MASK) или, где приоритет свой (телефон, rule_pref), правило с меткой на этом
 * приоритете. Правило пробы сторожа (from-правило без метки) поводом не бывает. Третий повод —
 * снятый запасной запрет в таблице IPv6 выхода (группа RTNLGRP_IPV6_ROUTE, фильтр пропускает из
 * снятых маршрутов только запреты; ниже, «ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo»).
 *
 * СРАЗУ, А НЕ ЧЕРЕЗ СЕКУНДУ (проверка на QEMU 04664a5). Прежде проверка шла через секунду
 * тишины после последнего события пачки (не позже двух после первого), а чинил ребёнок
 * `apply-commit --rule`: после `network restart` правило возвращалось через 2-2,5 с, и в этом окне
 * клиент открывал соединения мимо туннеля. Теперь:
 *   - проверка — через RULEWD_FAST_MS после последнего события (не позже RULEWD_FAST_MAX_MS после
 *     первого). Сто миллисекунд — не тишина, а пачка: flush снимает правила по одному, и события
 *     одного flush приходят за единицы миллисекунд; собрать их в одну проверку всё ещё стоит, а
 *     ждать секунду — нет. Тот же запас покрывает и своё «снять правило, потом таблицу» у
 *     подкоманды мимо очереди демона (`steer apply` без сокета, cleanup прежних меток): это два
 *     запуска ip подряд, и к проверке таблица уже пуста — правило не возвращается туда, где его
 *     сняли нарочно (см. «СВОИ УДАЛЕНИЯ»);
 *   - возвращает сам демон, в своём процессе, одним сообщением rtnetlink на правило
 *     (rtnl_rule_fwmark) — без ребёнка и без ip. Приоритет — тот, что был у снятого правила (его
 *     несёт событие RTM_DELRULE): на роутере наше правило ставится без pref, и ядро выбирает
 *     «перед первым ненулевым» по тому, что стоит в этот миг, — посреди чужого flush это мог бы
 *     оказаться 0. На телефоне приоритет свой (STEER_RULE_PREF) всегда. Проверка после записи —
 *     тем же rulewd_missing: не встало (нет прав, ядро отказало) — прежняя починка ребёнком в
 *     очереди изменяющих команд;
 *   - masquerade на телефоне (iptables — это процессы, и в цикле демона их не запускают)
 *     возвращает внеочередной проход сторожа, который звучит после починки всегда: проход после
 *     события считается «событийным», и masquerade он сверяет сразу (watch_masq_due).
 * Окно сторожа теперь — десятки-сотни миллисекунд, и его закрывает набор правил: помеченный пакет,
 * уходящий не в устройство своего выхода, отбрасывается (postrouting_guard, compile/generate.c),
 * так что и эти миллисекунды — «не работает», а не «мимо».
 *
 * ШТОРМ. Кто снимает правила без остановки (скрипт в цикле, два пакета маршрутизации дерутся за
 * `ip rule`), тому незачем отвечать мгновенно на каждое снятие: это была бы драка на скорости
 * цикла. Больше RULEWD_STORM_N возвратов за RULEWD_STORM_WIN_MS — страж переходит на прежний
 * порядок: проверка через секунду тишины после последнего события пачки и не позже двух секунд
 * после первого (правило возвращается за три секунды даже тогда, когда кто-то снимает правила без
 * остановки), — и говорит об этом в журнал один раз на окно. Одиночное снятие (netifd снимает наши
 * правила один раз на свой старт — одна строка «возвращены» в журнале QEMU на `network restart`)
 * шторма не делает.
 *
 * СВОИ УДАЛЕНИЯ — НЕ ПОВОД. Демон и сам снимает правила: apply-сверка — правило убранного выхода
 * (--drop) и лишние копии (rule_ensure), сторож — правило выхода в отказе с on_fail=direct, `steer
 * down` — все. Флаг «идёт своя операция» здесь не годится один: событие своего удаления приходит
 * асинхронно, а проход сторожа и init с `steer down` — не команды очереди. Поэтому решает не
 * событие, а сверка с ожидаемым набором, и событие только зовёт её:
 *   правило выхода ОБЯЗАНО стоять, если таблица выхода чем-то занята — маршрутом на устройство,
 *   запретом или запасным запретом (STEER_BACKSTOP_METRIC). Все наши собственные снятия правила
 *   сбрасывают и таблицу (apply --drop, отказ direct у сторожа, `steer down`), а лишние копии
 *   снимаются, только когда верная стоит. Чужое снятие таблицу не трогает — netd правил своих
 *   таблиц не касается, `ip rule flush` маршрутов не снимает. «Правила нет, а таблица занята» —
 *   значит, правило сняли не мы.
 *
 * IPv6 — ПО ТАБЛИЦЕ IPv4 (проверка на QEMU 98b7964, 2026-09-28).
 * Прежде у правила IPv6 признак был тот же, но по таблице IPv6: «правила нет, а таблица IPv6
 * занята». На `/etc/init.d/network restart` он не сработал ни разу из восьми: netifd кладёт lo, и
 * ядро вместе с ним снимает запасной запрет во всех таблицах IPv6 выходов (запрет в IPv6 висит на
 * lo, см. ниже), а падение wg снимает `default dev wgX`. Таблицы IPv6 стояли пустыми с +1,4 по
 * +6,5 с, netifd снимал правила на +4 с — и страж принимал «правила нет, таблица пуста» за своё
 * снятие. Правила IPv6 возвращал reload (сверка по новому br-lan, «правила fwmark IPv6 нет —
 * привязываю заново») за +1,2…+2,9 с, по одному выходу на ~0,4 с, и цепочка ingress_mark ждала
 * его: 2,6–3,7 с вместо ~300 мс. Пустую таблицу IPv6 делает не только движок, но и ядро, поэтому
 * судить по ней о «снято нами» нельзя. Судит таблица IPv4: каждое наше снятие правила IPv6 снимает
 * и маршрутизацию IPv4 выхода вместе с таблицей (отказ direct у сторожа и apply_routing_one,
 * `--drop` убранного выхода, `steer down`), а запрет IPv4 от lo не зависит. Правило IPv6 обязано
 * стоять, если стоит правило IPv4 или занята таблица IPv4 (или всё ещё занята таблица IPv6 —
 * прежний признак остаётся частным случаем). Своя «отметка о снятии» в памяти демона была бы
 * вторым источником правды, который врёт, как только снимает не демон: подкоманда `steer apply`
 * без сокета, init с `steer down`.
 *
 * ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo. В IPv6 запрет (blackhole, unreachable, prohibit) у ядра — маршрут
 * на петлю: `ip -6 route add blackhole default table N` без устройства ядро принимает, но вешает на
 * lo само (ip6_route_info_create: у запрета устройство — loopback), и `ip link set lo down`
 * снимает его вместе с остальными маршрутами lo (проверено в netns на 6.8: и с метрикой, и без).
 * Запрета «без устройства» в IPv6 нет, другого вида маршрута-запрета тоже; запрет правилом
 * (`ip -6 rule … blackhole`) от lo не зависит, но снимается тем же flush, что и наше правило, и
 * меняет раскладку правил на обеих платформах (приоритеты, сверка сторожа, снимки) — ради окна,
 * которое страж закрывает и так. Поэтому запрет остаётся на lo, а снятым его возвращает страж:
 * событие RTM_DELROUTE запрета с метрикой STEER_BACKSTOP_METRIC — та же проверка через 100 мс, и
 * запрет — одним сообщением rtnetlink (rtnl_route6_backstop, вид prohibit — как у table_bind6). Ставится он и при лежащем lo (ядро
 * принимает, и подъём lo его не трогает — проверено там же). Запрет обязан лежать у выхода, чья
 * таблица IPv4 занята: table_bind6 кладёт его при любой привязке, а снимают его только вместе со
 * всей маршрутизацией выхода (те же снятия, что выше). Маршрут `default dev wgX` страж не
 * возвращает — какое устройство ведёт трафик, решает проход сторожа; до него IPv6 выхода стоит на
 * запрете, а помеченный пакет не туда отбрасывает postrouting_guard.
 *
 * Отказ сторожа (apply_failed: снять правило, сбросить таблицу) идёт в цикле демона одним
 * синхронным куском — событие своего снятия страж читает уже после сброса таблицы. `steer down`
 * снимает таблицы nftables раньше правил — проверка видит «таблицы движка нет» и молчит.
 * Сверка — два дампа rtnetlink в процессе (rtnl_rules_text, rtnl_routes_text) и разбор тем же
 * route_facts_of, которым сверяет маршрутизацию сторож, — без единого процесса. Пока идёт своя
 * команда, которая сама снимает правила (посреди apply-commit с --drop или --route правило бывает
 * уже снято, а таблица ещё не сброшена), проверка не трогает только выходы, которых команда держит
 * (rulewd_conf.held), а остальные возвращает сразу: раньше она ждала конца всей команды, и на
 * `network restart` команда с --route (привязка ~0,4 с на выход) держала правила снятыми
 * 0,5–1,65 с (проверка на QEMU). Проверка по выходам, которых держат, и по командам, которых ждут
 * целиком (busy), не теряется: пока команда идёт, она повторяется каждые RULEWD_BUSY_MS
 * (rulewd_defer) и сразу после неё (rulewd_kick). План и применение одного набора правил проверку
 * не держат: прежде ждала любая изменяющая команда, и на `network
 * restart` сверка по новому мосту, державшая очередь, успевала сама перепривязать выходы ребёнком
 * по одному — ~0,4 с на выход, и цепочка ingress_mark ждала их (проверка на QEMU 4192267, доводы
 * — у srv_rules_busy в ctl.c). Перед решением сверки проверка идёт сразу (rulewd_settle). Таблицы движка в ядре нет — движок снят целиком (`steer
 * down`), и возвращать правила, которые никуда не ведут, незачем.
 *
 * ЗАПАСНАЯ ПОЧИНКА — сервер сокета (ctl.c, починка в очереди изменяющих команд): ребёнок
 * `apply-commit --rule <выходы> --masq-ensure` — правило тем же rule_ensure, что у apply, masquerade
 * тем же iptables_masq_ensure, что у сторожа. Таблица не перепривязывается ни там, ни здесь: она
 * цела (это условие починки), а в ней может стоять запрет сторожа при on_fail=drop, который
 * перепривязка к устройству сняла бы до следующего прохода. После любой починки — внеочередной
 * проход сторожа, который сверяет остальное, и событие repaired подписчикам.
 *
 * БАТАРЕЯ. Сокет открыт, только пока движок включён: выключенному стражу нечего стеречь (правила
 * снял init), и событие чужих правил не будит демон. Таймер — только на время пачки. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/filter.h>

#include "platform.h"
#include "spec.h"
#include "loop.h"
#include "state.h"
#include "rtnl.h"
#include "recon.h"
#include "failover_int.h"
#include "rulewd.h"

/* Обычный порядок: пачка событий — одна проверка через RULEWD_FAST_MS после последнего события,
 * не позже RULEWD_FAST_MAX_MS после первого (см. шапку, «СРАЗУ, А НЕ ЧЕРЕЗ СЕКУНДУ»). */
#define RULEWD_FAST_MS      100
#define RULEWD_FAST_MAX_MS  300
/* Опрос при занятости — как часто. */
#define RULEWD_BUSY_MS      50
/* Шторм: тишина после последнего события пачки и предел от первого — прежние числа. */
#define RULEWD_QUIET_MS 1000
#define RULEWD_MAX_MS   2000
/* Шторм — больше RULEWD_STORM_N возвратов за RULEWD_STORM_WIN_MS. */
#define RULEWD_STORM_N      3
#define RULEWD_STORM_WIN_MS 60000L
/* Приоритеты снятых правил (выход — метка и семейство) запоминаются растущим массивом. */

struct rulewd {
    struct steerd *d;
    struct loop *l;
    struct rulewd_conf cf;
    int on;
    int nl;
    struct loop_timer *tm;
    int pending;                  /* было наше удаление — нужна проверка */
    long first;                   /* когда пришло первое событие пачки, мс монотонных */
    /* Когда страж возвращал правила сам, по кругу (0 — не было): по ним узнаётся шторм. */
    long back_at[RULEWD_STORM_N + 1];
    int back_i;
    long storm_said;              /* когда последний раз сказали о шторме в журнал */
    /* Приоритеты снятых правил: с каким вернуть (см. шапку). */
    struct { int fam; uint32_t mark; uint32_t prio; } *pref;
    size_t pref_n, pref_cap;
};

/* ---- проверка ------------------------------------------------------------------------------ */

/* Чего не хватает у выхода (биты): правила IPv4, правила IPv6, запасного запрета в таблице IPv6. */
enum { MISS_R4 = 1, MISS_R6 = 2, MISS_BS6 = 4 };

/* Чего у выхода не хватает — по признакам из шапки («СВОИ УДАЛЕНИЯ», «IPv6 — ПО ТАБЛИЦЕ IPv4»,
 * «ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo»). rules и rules6 — дампы правил, уже прочитанные (rules6 пуст —
 * ядро без IPv6, и половина IPv6 не сверяется). -1 — ядро не спросить. */
static int out_missing(const char *rules, const char *rules6, const struct output *o) {
    static char routes[8192], routes6[8192];
    if (rtnl_routes_text(o->table, routes, sizeof(routes)) != 0) return -1;
    struct route_facts f = route_facts_of(rules, routes, o->mark, o->table);
    if (!f.known) return -1;
    /* Таблица IPv4 занята — маршрут на устройство, запрет или запасной запрет. Пуста — правило
     * снято вместе с ней, и это наше решение (см. шапку). */
    int busy4 = !(f.table == TBL_EMPTY && !f.backstop);
    int miss = !f.rule && busy4 ? MISS_R4 : 0;
    /* С 1.9 у выхода с маршрутом IPv6 так же сверяется и его половина IPv6. */
    if (!out_route6(o) || !rules6[0]) return miss;
    if (rtnl_routes_text6(o->table, routes6, sizeof(routes6)) != 0) return miss;
    struct route_facts f6 = route_facts_of(rules6, routes6, o->mark, o->table);
    if (!f6.known) return miss;
    int busy6 = !(f6.table == TBL_EMPTY && !f6.backstop);
    /* Правило IPv6 обязано стоять, если выход ведёт трафик по IPv4 (правило IPv4 стоит или его
     * таблица занята) — пустая таблица IPv6 здесь не довод: её опустошает и ядро. */
    if (!f6.rule && (f.rule || busy4 || busy6)) miss |= MISS_R6;
    /* Запасной запрет IPv6 лежит у каждого привязанного выхода; нет его только там, где снята
     * вся маршрутизация выхода вместе с таблицей IPv4. */
    if (busy4 && !f6.backstop) miss |= MISS_BS6;
    return miss;
}

static void list_add(char *list, size_t n, size_t *k, int cnt, const char *name) {
    int w = snprintf(list + *k, n > *k ? n - *k : 0, "%s%s", cnt ? "," : "", name);
    if (w > 0 && *k + (size_t)w < n) *k += (size_t)w;
}

/* Дампы правил обоих семейств для out_missing. -1 — правил IPv4 не прочитать; правил IPv6 нет
 * (ядро без IPv6) — rules6 пуст. */
static int rules_read(char **rules, char **rules6) {
    *rules = rtnl_rules_dup(0);         /* дамп растёт по числу правил: их не 16 КиБ */
    if (!*rules || !(*rules)[0]) { free(*rules); *rules = NULL; *rules6 = NULL; return -1; }
    *rules6 = rtnl_rules_dup(1);
    if (!*rules6) *rules6 = strdup("");
    if (!*rules6) { free(*rules); *rules = NULL; return -1; }
    return 0;
}

/* Держит ли выход идущая команда демона (rulewd_conf.held): его правила проверка не трогает. */
static int out_held(const struct rulewd *r, const struct output *o) {
    return r && r->cf.held && r->cf.held(r->cf.arg, o);
}

/* rulewd_missing с учётом held: выходы, чьи правила держит идущая команда, не считаются, а
 * *heldmiss (если он есть) отмечает, что среди них есть и такие, у которых чего-то не хватает, —
 * их проверять после конца команды (rulewd_defer). r == NULL — held не спрашивается. */
static int missing_x(const struct rulewd *r, const struct spec *sp, char *list, size_t n,
                     int *heldmiss) {
    char *rules, *rules6;
    if (n) list[0] = '\0';
    if (heldmiss) *heldmiss = 0;
    if (!sp) return 0;
    if (rules_read(&rules, &rules6) != 0) return -1;
    int cnt = 0;
    size_t k = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o) || !o->mark || !o->table) continue;
        int m = out_missing(rules, rules6, o);
        if (m < 0) { free(rules); free(rules6); return -1; }
        if (!m) continue;
        if (out_held(r, o)) {
            if (heldmiss) *heldmiss = 1;
            continue;
        }
        list_add(list, n, &k, cnt, o->name);
        cnt++;
    }
    free(rules);
    free(rules6);
    return cnt;
}

int rulewd_missing(const struct spec *sp, char *list, size_t n) {
    return missing_x(NULL, sp, list, n, NULL);
}

/* Приоритет, с которым вернуть правило семейства fam с меткой mark: свой у платформы, иначе тот,
 * что был у снятого (0 — не знаем, ядро выберет само). */
static uint32_t pref_of(const struct rulewd *r, int fam, uint32_t mark) {
    if (STEER_RULE_PREF) return (uint32_t)STEER_RULE_PREF;
    for (size_t i = 0; i < r->pref_n; i++)
        if (r->pref[i].fam == fam && r->pref[i].mark == mark) return r->pref[i].prio;
    return 0;
}

static void pref_note(struct rulewd *r, int fam, uint32_t mark, uint32_t prio) {
    if (!prio) return;
    size_t i = 0;
    while (i < r->pref_n && !(r->pref[i].fam == fam && r->pref[i].mark == mark)) i++;
    if (i == r->pref_n) {
        if (r->pref_n == r->pref_cap) {
            size_t nc = r->pref_cap ? r->pref_cap * 2 : 32;
            void *np = realloc(r->pref, nc * sizeof(*r->pref));
            if (!np) return;
            r->pref = np;
            r->pref_cap = nc;
        }
        r->pref_n++;
    }
    r->pref[i].fam = fam;
    r->pref[i].mark = mark;
    r->pref[i].prio = prio;
}

/* Вернуть снятое сами, в процессе (см. шапку). Имена выходов, у которых что-то ставилось, — в all;
 * из них те, чьи правила ставились, — в rl, чей запасной запрет IPv6 — в bs (по n байт каждый).
 * Возврат — сколько выходов тронуто, -1 — ядро не спросить или не приняло. */
static int rulewd_restore(struct rulewd *r, const struct spec *sp, char *all, char *rl, char *bs,
                          size_t n) {
    char *rules, *rules6;
    if (n) all[0] = rl[0] = bs[0] = '\0';
    if (rules_read(&rules, &rules6) != 0) return -1;
    int cnt = 0, rcnt = 0, bcnt = 0, bad = 0;
    size_t k = 0, rk = 0, bk = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o) || !o->mark || !o->table) continue;
        int m = out_missing(rules, rules6, o);
        if (m < 0) { free(rules); free(rules6); return -1; }
        if (!m || out_held(r, o)) continue;
        if ((m & MISS_R4) && rtnl_rule_fwmark(4, o->mark, STEER_MARK_MASK, o->table,
                                              (int)pref_of(r, 4, o->mark)) != 0) bad = 1;
        /* Запрет — раньше правила IPv6: вернувшееся правило должно найти в таблице запрет, а не
         * пустоту (тот же порядок, что у привязки: маршрут первым, правило вторым). */
        if ((m & MISS_BS6) && rtnl_route6_backstop(o->table, STEER_BACKSTOP_METRIC) != 0) bad = 1;
        if ((m & MISS_R6) && rtnl_rule_fwmark(6, o->mark, STEER_MARK_MASK, o->table,
                                              (int)pref_of(r, 6, o->mark)) != 0) bad = 1;
        list_add(all, n, &k, cnt++, o->name);
        if (m & (MISS_R4 | MISS_R6)) list_add(rl, n, &rk, rcnt++, o->name);
        if (m & MISS_BS6) list_add(bs, n, &bk, bcnt++, o->name);
    }
    free(rules);
    free(rules6);
    return bad ? -1 : cnt;
}

/* Шторм ли сейчас: больше RULEWD_STORM_N возвратов за окно (см. шапку, «ШТОРМ»). back_at — круг
 * из RULEWD_STORM_N + 1 мест: самое старое место — back_at[back_i]. */
static int rulewd_storm(const struct rulewd *r, long now) {
    long oldest = r->back_at[r->back_i];
    return oldest && now - oldest < RULEWD_STORM_WIN_MS;
}

/* Проверку — повторить через RULEWD_BUSY_MS: идёт команда, которая держит правила выхода, или
 * своя операция целиком (rulewd_conf.busy, held). Одного rulewd_kick из конца операции мало: он
 * зовётся, только когда очередь изменяющих команд опустела, а за одной командой обычно стоит
 * следующая (сверка по проходу сторожа, потом сверка по новому мосту), и проверка, отложенная до
 * «тишины», ждала бы их всех. Опрос раз в 50 мс идёт только пока команда работает и есть что
 * проверять — два дампа rtnetlink, без единого процесса. */
static void rulewd_defer(struct rulewd *r) {
    r->pending = 1;
    loop_timer_set(r->tm, RULEWD_BUSY_MS);
}

static void rulewd_check(struct rulewd *r) {
    struct steerd *d = r->d;
    r->pending = 0;
    if (!r->on || !d->have) return;
    /* Таблицы движка нет — движок снят целиком (`steer down`): правила вести некуда. Спросить не
     * вышло (-1) — проверяем как обычно. */
    uint64_t h;
    if (recon_table_handle(nft_table(), &h) == 1) return;
    char list[512];
    int hm = 0;
    int cnt = missing_x(r, d->sp, list, sizeof(list), &hm);
    /* Чего-то не хватает у выхода, которого держит идущая команда, — вернуться к нему, когда она
     * кончится (rulewd_defer): событие снятия не повторится. */
    if (hm) rulewd_defer(r);
    if (cnt <= 0) return;
    if (!r->cf.restored) { r->cf.repair(r->cf.arg); return; }
    char rl[512], bs[512];
    int rc = rulewd_restore(r, d->sp, list, rl, bs, sizeof(list));
    /* В счёт шторма — возвраты правил (и неудачные попытки), но не одного запрета IPv6: его
     * снимает ядро вместе с lo, а не тот, кто дерётся за `ip rule`, и на `network restart` он
     * приходит вторым возвратом рядом с правилами — два перезапуска сети за минуту иначе уже
     * были бы «штормом». */
    if (rl[0] || rc < 0) {
        r->back_at[r->back_i] = loop_now_ms();
        r->back_i = (r->back_i + 1) % (RULEWD_STORM_N + 1);
    }
    char left[512];
    if (rc > 0 && missing_x(r, d->sp, left, sizeof(left), NULL) == 0) {
        r->cf.restored(r->cf.arg, list, rl, bs);
        return;
    }
    /* Сами не смогли — прежняя починка ребёнком (правило и masquerade тем же кодом, что apply). */
    r->cf.repair(r->cf.arg);
}

static void rulewd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct rulewd *r = arg;
    if (!r->pending) return;
    /* Своя операция идёт — проверка после неё: опрос (rulewd_defer) и rulewd_kick из конца
     * операции. Событие, пришедшее в занятости, не теряется. */
    if (r->cf.busy && r->cf.busy(r->cf.arg)) { rulewd_defer(r); return; }
    rulewd_check(r);
}

/* ---- события ------------------------------------------------------------------------------- */

/* Наше ли снятое правило (см. шапку, «СОБЫТИЯ»). Своё — семейство, метка и приоритет правила в
 * *fam, *mark, *prio (приоритет 0 — событие его не несло). */
static int rule_is_ours(const struct nlmsghdr *h, int *fam, uint32_t *markp, uint32_t *priop) {
    const struct fib_rule_hdr *fr = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*fr));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return 0;
    uint32_t mark = 0, mask = 0xffffffffu, prio = 0;
    int have_mark = 0;
    const char *p = (const char *)fr + hl, *e = (const char *)h + h->nlmsg_len;
    while (p + sizeof(struct rtattr) <= e) {
        const struct rtattr *a = (const struct rtattr *)p;
        if (a->rta_len < sizeof(*a) || p + a->rta_len > e) break;
        if (RTA_PAYLOAD(a) >= 4) {
            uint32_t v;
            memcpy(&v, RTA_DATA(a), 4);
            if (a->rta_type == FRA_FWMARK) { mark = v; have_mark = 1; }
            else if (a->rta_type == FRA_FWMASK) mask = v;
            else if (a->rta_type == FRA_PRIORITY) prio = v;
        }
        p += RTA_ALIGN(a->rta_len);
    }
    if (!have_mark || !(mark & STEER_MARK_MASK)) return 0;
    *fam = fr->family == AF_INET6 ? 6 : 4;
    *markp = mark;
    *priop = prio;
    if (mask == STEER_MARK_MASK && !(mark & ~STEER_MARK_MASK)) return 1;
    return STEER_RULE_PREF && prio == (uint32_t)STEER_RULE_PREF;
}

/* Снят ли запасной запрет IPv6 (см. шапку, «ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo»): маршрут IPv6
 * `prohibit default` (или `blackhole default` прежней версии — его заменяет первая же привязка) с
 * метрикой STEER_BACKSTOP_METRIC. Чья это таблица, событие не решает — это
 * сверка по спеке (out_missing): так чужой запрет с той же метрикой стоит лишь одной проверки. */
static int route_is_backstop6(const struct nlmsghdr *h) {
    const struct rtmsg *rt = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*rt));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return 0;
    if (rt->rtm_family != AF_INET6 || rt->rtm_dst_len ||
        (rt->rtm_type != RTN_PROHIBIT && rt->rtm_type != RTN_BLACKHOLE))
        return 0;
    const char *p = (const char *)rt + hl, *e = (const char *)h + h->nlmsg_len;
    while (p + sizeof(struct rtattr) <= e) {
        const struct rtattr *a = (const struct rtattr *)p;
        if (a->rta_len < sizeof(*a) || p + a->rta_len > e) break;
        if (a->rta_type == RTA_PRIORITY && RTA_PAYLOAD(a) >= 4) {
            uint32_t v;
            memcpy(&v, RTA_DATA(a), 4);
            return v == (uint32_t)STEER_BACKSTOP_METRIC;
        }
        p += RTA_ALIGN(a->rta_len);
    }
    return 0;
}

static void rulewd_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct rulewd *r = arg;
    _Alignas(struct nlmsghdr) char buf[8192];
    int ours = 0;
    for (;;) {
        ssize_t m = recv(fd, buf, sizeof(buf), 0);
        if (m < 0 && errno == EINTR) continue;
        /* Переполнение: события потеряны — среди них могли быть и наши. */
        if (m < 0 && errno == ENOBUFS) { ours = 1; continue; }
        if (m <= 0) break;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)m);
             h = NLMSG_NEXT(h, m)) {
            int fam = 4;
            uint32_t mark = 0, prio = 0;
            if (h->nlmsg_type == RTM_DELRULE && rule_is_ours(h, &fam, &mark, &prio)) {
                ours = 1;
                pref_note(r, fam, mark, prio);
            } else if (h->nlmsg_type == RTM_DELROUTE && route_is_backstop6(h)) {
                ours = 1;
            }
        }
    }
    if (!ours || !r->on) return;
    long now = loop_now_ms();
    int storm = rulewd_storm(r, now);
    if (storm && (!r->storm_said || now - r->storm_said >= RULEWD_STORM_WIN_MS)) {
        r->storm_said = now;
        fprintf(stderr, "steer[warn] rules: правила выходов снимают снаружи снова и снова (больше "
                        "%d раз за %ld с) — возвращаю их через секунду после пачки, а не сразу\n",
                RULEWD_STORM_N, RULEWD_STORM_WIN_MS / 1000);
    }
    long quiet = storm ? RULEWD_QUIET_MS : RULEWD_FAST_MS;
    long most = storm ? RULEWD_MAX_MS : RULEWD_FAST_MAX_MS;
    if (!r->pending) { r->pending = 1; r->first = now; }
    long left = r->first + most - now;
    loop_timer_set(r->tm, left < quiet ? (left > 0 ? left : 0) : quiet);
}

/* Сокет на группы правил IPv4 и IPv6 и маршрутов IPv6 с фильтром «только RTM_DELRULE и снятый
 * запрет IPv6». -1 — не открылся. */
static int rulewd_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    /* Фильтр ядру: сообщение уведомления — одно на пакет, тип — u16 по смещению 4
     * (nlmsghdr.nlmsg_type, порядок байт хоста: BPF_H в сокетном фильтре читает сетевой, поэтому
     * сравнение — с обоими видами). Снятый маршрут пропускается, только если это запрет: байт
     * rtm_type — по смещению 16 + 7 (заголовок nlmsghdr и седьмое поле struct rtmsg), байт от
     * порядка не зависит. Так маршруты, которые netd и netifd снимают на каждой смене сети,
     * демон не будят вовсе; из запретов разбор ниже оставит только наш (route_is_backstop6). Не
     * встал фильтр — живём без него: разбор тот же. */
    uint16_t t = RTM_DELRULE;
    uint16_t sw = (uint16_t)((t >> 8) | (t << 8));
    uint16_t tr = RTM_DELROUTE;
    uint16_t swr = (uint16_t)((tr >> 8) | (tr << 8));
    struct sock_filter code[] = {
        /* 0 */ BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4),
        /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t, 7, 0),       /* → 9 принять */
        /* 2 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sw, 6, 0),      /* → 9 */
        /* 3 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, tr, 1, 0),      /* → 5 */
        /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, swr, 0, 3),     /* → 5, иначе → 8 */
        /* 5 */ BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 16 + 7),
        /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTN_PROHIBIT, 2, 0),  /* → 9 */
        /* 7 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTN_BLACKHOLE, 1, 0), /* → 9 */
        /* 8 */ BPF_STMT(BPF_RET | BPF_K, 0),
        /* 9 */ BPF_STMT(BPF_RET | BPF_K, 0xffff),
    };
    struct sock_fprog prog = { (unsigned short)(sizeof(code) / sizeof(code[0])), code };
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = (1u << (RTNLGRP_IPV4_RULE - 1)) | (1u << (RTNLGRP_IPV6_RULE - 1)) |
                  (1u << (RTNLGRP_IPV6_ROUTE - 1));
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

/* ---- заведение ---------------------------------------------------------------------------- */

struct rulewd *rulewd_start(struct steerd *d, const struct rulewd_conf *c, int on) {
    struct rulewd *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->d = d;
    r->l = d->loop;
    r->cf = *c;
    r->nl = -1;
    r->tm = loop_timer_new(r->l, rulewd_timer, r);
    if (!r->tm) { free(r); return NULL; }
    rulewd_enable(r, on);
    return r;
}

void rulewd_enable(struct rulewd *r, int on) {
    if (!r || r->on == !!on) return;
    r->on = !!on;
    if (on) {
        r->nl = rulewd_open();
        if (r->nl >= 0 && loop_fd_add(r->l, r->nl, EPOLLIN, rulewd_nl, r) != 0) {
            close(r->nl);
            r->nl = -1;
        }
        if (r->nl < 0)
            fprintf(stderr, "steer[warn] rules: события правил недоступны — снятые правила "
                            "вернёт только проход сторожа\n");
        return;
    }
    r->pending = 0;
    loop_timer_stop(r->tm);
    if (r->nl >= 0) {
        loop_fd_del(r->l, r->nl);
        close(r->nl);
        r->nl = -1;
    }
}

void rulewd_kick(struct rulewd *r) {
    if (!r || !r->pending || !r->on) return;
    loop_timer_set(r->tm, 0);
}

/* Проверка сейчас, в обход пачки и без события (шапка, «СРАЗУ, А НЕ ЧЕРЕЗ СЕКУНДУ»; зовёт
 * commit_start в ctl.c перед решением сверки). Без события — потому что событие снятия может ещё
 * лежать в сокете, не прочитанное циклом: netifd снял правило за миг до решения. Проверка —
 * два дампа rtnetlink, и когда всё на месте, она ничего не пишет и никого не будит. Шторм здесь
 * не спрашивается: решение сверки идёт раз на команду, а не на каждое снятие. */
void rulewd_settle(struct rulewd *r) {
    if (!r || !r->on) return;
    loop_timer_stop(r->tm);
    rulewd_check(r);
}
