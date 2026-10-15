/* pick: balance — раздача НОВЫХ соединений по живым членам группы в ядре (docs/architecture.md,
 * «4в», группы; устройство группы — src/kinds/group.c).
 *
 * ЧТО СТОИТ В ЯДРЕ. Правило канала, ведущего в группу balance, не ставит метку само, а переходит
 * (goto) в цепочку группы `bal_<таблица>`:
 *
 *   chain bal_305 {
 *     ct mark and МАСКА == 0x00100000 goto mark_301     ← соединение уже на члене: туда же
 *     ct mark and МАСКА == 0x00200000 goto mark_302
 *     numgen random mod 120 vmap @balmap_305           ← новое соединение: слот → член (by: site — jhash)
 *     goto mark_305                                     ← живых нет: метка самой группы
 *   }
 *   chain mark_301 { meta mark set mark and ~МАСКА or 0x00100000 ...; ct mark set mark }
 *
 * Метка члена — его собственная (реестр): пакет уходит по правилу fwmark члена в ЕГО таблицу, а
 * таблицу члена сторож держит на его устройстве, как у любого выхода. Метка соединения запоминает
 * член, и следующие пакеты соединения идут первым правилом цепочки на тот же член, что бы ни
 * случилось с картой: уход или возврат другого члена установленное соединение не перекидывает.
 * Метка соединения при этом нужна всегда — у каждого члена с устройством она и так есть
 * (out_needs_ctmark), здесь она ещё и память выбора.
 *
 * ПОЧЕМУ numgen random, А НЕ jhash ПО КОРТЕЖУ. Постоянство соединения держит метка соединения, а не
 * хеш: хеш по кортежу дал бы то же самое только первому пакету и не пережил бы смены карты
 * (вернувшийся член забрал бы себе чужие слоты вместе с их установленными соединениями). Случайный
 * номер равномерен при любом составе трафика (у jhash по адресу клиента один клиент со всеми его
 * соединениями ложился бы на один член), и ему не нужны порты — у ICMP и GRE их нет.
 *
 * by: site и site_client — ДРУГОЙ ВОПРОС: не «соединение на одном члене», а «сайт на одном члене»
 * (у Clash — consistent-hashing и sticky-sessions). Его хеш и решает: вместо numgen —
 *
 *     meta nfproto ipv4 jhash ip daddr mod 120 seed 0x<таблица> vmap @balmap_<таблица>
 *     meta nfproto ipv6 jhash ip6 daddr mod 120 seed 0x<таблица> vmap @balmap_<таблица>
 *
 * (site_client — `ip saddr . ip daddr`). Карта, метка соединения и сторож — те же: установленное
 * соединение держит метка, новое соединение сайта — его слот. Сайт — адрес назначения в момент
 * разметки, то есть до dnat fake-IP: при fake-IP это имя (у имени свой поддельный адрес), без
 * него — адрес. Чтобы уход члена не тасовал сайты остальных, слоты живых при уходе не двигаются:
 * group_balance_slots раздаёт живым только слоты ушедших (src/kinds/group.c).
 *
 * ПОЧЕМУ КАРТА СЛОТОВ, А НЕ `mod <живых>`. Уход члена меняет только элементы карты: сторож
 * переписывает их одной транзакцией по netlink (src/lib/nftvmap.c, src/daemon/fogroup.c), без
 * процесса nft и без перезагрузки набора правил. `mod N` сидит в самом правиле, и уход члена
 * менял бы правило. Раздачу слотов по весам считает group_balance_slots (одна функция на
 * компилятор и сторожа); здесь карта — все члены живы: apply ставит набор целиком, а первый же
 * проход сторожа сверяет карту с живыми членами по факту в ядре.
 *
 * ВЛОЖЕННЫЕ. Член — группа order/latency/manual: одна метка, её таблица ведёт в её текущий лист.
 * Член — группа balance: слот ведёт в её цепочку `bal_…`, а соединения, уже живущие на её
 * членах, узнаются по их меткам ещё в цепочке внешней (правила восстановления — по всем листам
 * вниз по вложенности).
 *
 * ЗАКРЕПЛЕНИЕ (order и latency с именованными членами, group_carded). Та же цепочка, а в карте один
 * слот (`numgen inc mod 1`) — текущий выбор сторожа. Новое соединение получает его метку, а
 * метка соединения держит его там и дальше: когда сторож меняет член (по задержке, возврат на
 * предпочтительный), он переписывает только карту, и установленные соединения доживают на прежнем
 * члене, пока тот жив. Умер член — его соединения снимает его же проход (выход-член с on_fail, как
 * любой выход), и следующий их пакет уходит по карте на текущий. Раньше таблица группы перекидывалась
 * на новое устройство, а записи conntrack группы снимались — и смена члена по задержке рвала все
 * соединения группы (у WARP — каждые несколько минут, без всякого отказа).
 *
 * У группы без живых членов карта пуста (так её оставляет сторож), numgen ничего не находит, и
 * пакет получает метку самой группы: её таблицу сторож держит по on_fail группы — запрет или
 * «напрямую». То есть отказ balance выглядит ровно как отказ любого выхода. */
#include <stdio.h>
#include <string.h>

#include "spec.h"
#include "groups.h"
#include "ir.h"
#include "balance.h"

/* Группа с картой: balance и закрепляющие order/latency (group_carded, kinds/group.c). */
static int is_balance(const struct output *o) {
    return group_carded(o);
}

/* Цепочка метки выхода o — один раз на дерево. */
static void mark_chain(struct nft_table *t, const struct output *o) {
    char name[32];
    group_mark_chain(o, name, sizeof(name));
    if (ir_chain_find(t, name)) return;
    struct nft_rule *r = ir_rule(ir_chain_add(t, ir_strdup(t->rs, name)));
    unsigned mark = out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark;
    ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK, mark);
    ir_x(r, "ct mark set mark");
    ir_comment(r, "steer-mark:%s", o->name);
}

/* Правила восстановления: соединение уже на листе x — сразу в его цепочку метки. Листья вложенных
 * balance — тоже (соединение, раз попавшее на член внутренней группы, остаётся там). */
static void restore_rules(struct nft_table *t, struct nft_chain *c, const struct spec *sp,
                          const struct output *g, int depth) {
    const struct group_cfg *gc = out_group(g);
    for (size_t k = 0; gc && k < gc->members_n && (size_t)depth <= sp->out_n; k++) {
        const struct output *m = spec_out(sp, gc->members[k]);
        if (is_balance(m)) {
            restore_rules(t, c, sp, m, depth + 1);
            continue;
        }
        char name[32], cond[64];
        group_mark_chain(m, name, sizeof(name));
        /* Лист, достижимый двумя путями (напрямую и через вложенную), — одно правило. */
        snprintf(cond, sizeof(cond), "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, m->mark);
        int dup = 0;
        for (const struct nft_rule *q = c->rules; q && !dup; q = q->next)
            if (ir_rule_has(q, cond)) dup = 1;
        if (dup) continue;
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, m->mark);
        ir_x(r, "goto %s", name);
        mark_chain(t, m);
    }
}

static void build_one(struct nft_table *t, const struct spec *sp, const struct output *g, int depth) {
    char chain[32], map[32], fall[32];
    group_bal_chain(g, chain, sizeof(chain));
    if (ir_chain_find(t, chain) || (size_t)depth > sp->out_n) return;
    group_bal_map(g, map, sizeof(map));
    group_mark_chain(g, fall, sizeof(fall));
    const struct group_cfg *gc = out_group(g);

    /* Карта: все члены живы. У закрепляющей order/latency — все слоты первому члену (его выбрал бы
     * проход, когда живы все); текущий по факту ставит сверка после загрузки (fog_balance_adopt). */
    struct nft_set *m = ir_map_add(t, ir_strdup(t->rs, map), "mark", "verdict");
    ir_gap(m);
    unsigned char owner[GROUP_BAL_SLOTS];
    unsigned slots = gc->pick == PICK_BALANCE ? GROUP_BAL_SLOTS : 1;
    if (gc->pick == PICK_BALANCE) group_balance_slots(gc, NULL, owner);   /* NULL — все члены живы */
    else owner[0] = 0;
    for (unsigned s = 0; s < slots; s++) {
        if (owner[s] == 0xff) continue;
        char tgt[32];
        group_bal_target(spec_out(sp, gc->members[owner[s]]), tgt, sizeof(tgt));
        ir_set_value(m, ir_printf(t->rs, "%u : goto %s", s, tgt));
    }

    struct nft_chain *c = ir_chain_add(t, ir_strdup(t->rs, chain));
    /* IPv6. Группа несёт IPv6, только если его несут все члены (свойства группы — пересечение,
     * KC_IPV6): тогда IPv6 раздаётся той же картой и держится той же меткой соединения, а метка
     * члена ведёт в его таблицу IPv6 (ip -6 rule члена). Иначе IPv6 группы — в метку самой группы
     * первым правилом, и цепочка forward_v6 отвергает его (выход без IPv6, generate.c): отказ
     * заметный и сразу, а не «часть соединений v6 работает, часть уходит в отказ» по случайному
     * слоту. */
    if (!out_has_cap(g, KC_IPV6)) {
        struct nft_rule *r6 = ir_rule(c);
        ir_family(r6, 6);
        ir_x(r6, "goto %s", fall);
        ir_comment(r6, "steer-balance-v6:%s", g->name);
    }
    restore_rules(t, c, sp, g, 0);
    struct nft_rule *r;
    if (gc->pick != PICK_BALANCE) {
        /* Закрепляющая order/latency: один слот — текущий член. */
        r = ir_rule(c);
        ir_x(r, "numgen inc mod 1 vmap @%s", map);
        ir_comment(r, "steer-pin:%s", g->name);
    } else if (gc->by == BY_CONNECTION) {
        r = ir_rule(c);
        ir_x(r, "numgen random mod %d vmap @%s", GROUP_BAL_SLOTS, map);
        ir_comment(r, "steer-balance:%s", g->name);
    }
    /* by: site, site_client — слот по хешу адресов, по правилу на семейство (адрес IPv4 и IPv6 —
     * разные поля заголовка). Семя — номер таблицы группы: постоянное (тот же сайт попадает в тот
     * же слот и после apply, и после перезагрузки — без семени ядро берёт случайное на каждое
     * правило), и у каждой группы своё — иначе вложенная balance с тем же хешем получала бы
     * только «свои» слоты внешней и отдавала бы их одному члену. */
    for (int fam = 4; gc->by != BY_CONNECTION && fam <= 6; fam += 2) {
        if (fam == 6 && !out_has_cap(g, KC_IPV6)) break;
        const char *ip = fam == 4 ? "ip" : "ip6";
        r = ir_rule(c);
        ir_family(r, fam);
        if (gc->by == BY_SITE_CLIENT)
            ir_x(r, "jhash %s saddr . %s daddr mod %d seed 0x%x vmap @%s", ip, ip, GROUP_BAL_SLOTS,
                 (unsigned)g->table, map);
        else
            ir_x(r, "jhash %s daddr mod %d seed 0x%x vmap @%s", ip, GROUP_BAL_SLOTS, (unsigned)g->table, map);
        ir_comment(r, "steer-balance:%s", g->name);
    }
    r = ir_rule(c);
    ir_x(r, "goto %s", fall);
    mark_chain(t, g);
    /* Вложенные balance — свои цепочки и карты. */
    for (size_t k = 0; k < gc->members_n; k++) {
        const struct output *mm = spec_out(sp, gc->members[k]);
        if (is_balance(mm)) build_one(t, sp, mm, depth + 1);
    }
}

int nft_emit_balance(struct nft_table *t, const struct spec *sp, const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct output *o = out_by_name(sp, gr->g[i].out);
        if (o && is_balance(o)) build_one(t, sp, o, 0);
    }
    return t->rs->oom ? -1 : 0;
}

int out_balanced(const struct output *o) {
    return is_balance(o);
}
