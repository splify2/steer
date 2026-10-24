/* ---- генератор: спека и группы каналов → дерево набора правил -----------------------------
 *
 * С 1.7 генератор строит дерево (ir.h), а не печатает текст: печатает print.c, раскладку
 * старого ядра делает legacy.c преобразованием этого же дерева, и здесь про неё не знают
 * ничего — всё, что ниже, это набор правил современного ядра.
 *
 * Части, которые зависят от вида выхода, — kind_ops.emit модулей видов (zapret_emit в
 * kinds/zapret.c, tgws_emit в kinds/tgws.c, docs/architecture.md, «Вид выхода»): их зовёт
 * kind_emit_all (kind.c) двумя проходами по видам в порядке реестра, поэтому здесь про них не
 * знают ничего, кроме самого вызова в nft_build. Части, которые есть только на телефоне
 * (разметка на выходе, счёт скачанного на входе, заворот DNS приложений, «кто» по владельцу
 * сокета), — nft_emit_output_mark, nft_emit_output_dns и local_who; их заберёт platform_ops. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "spec.h"
#include "generate.h"
#include "srs.h"
#include "nftdump.h"
#include "nftcompat.h"
#include "balance.h"

/* Строковый буфер для выражений-перечней («ip saddr { a, b }», «th dport { … }»). Растёт по
 * надобности: раньше это было 4 КБ «с запасом на 32 адреса», и клиент с сотней адресов терял хвост
 * перечня МОЛЧА — правило применялось, а часть устройств оно не касалось. Освобождается
 * sb_emit (вместе с выдачей выражения в правило) или sb_free. */
struct sbuf { char *s; size_t n, cap; int oom; };

static void sb_add(struct sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_add(struct sbuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char probe[1];
    va_list cp;
    va_copy(cp, ap);
    int k = vsnprintf(probe, sizeof(probe), fmt, cp);
    va_end(cp);
    if (k < 0) { va_end(ap); return; }
    if (b->n + (size_t)k + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + (size_t)k + 1) nc *= 2;
        char *p = realloc(b->s, nc);
        if (!p) { b->oom = 1; va_end(ap); return; }   /* sb_emit скажет об этом правилам: rs->oom */
        b->s = p;
        b->cap = nc;
    }
    vsnprintf(b->s + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)k;
}
static const char *sb_str(const struct sbuf *b) { return b->s ? b->s : ""; }
static void sb_free(struct sbuf *b) { free(b->s); b->s = NULL; b->n = b->cap = 0; b->oom = 0; }
/* Выражение — в правило, буфер — обратно. Без памяти на выражение оно НЕ уходит в правило урезанным:
 * правило без условия сработало бы на весь трафик вместо перечня. Вместо этого rs->oom — общий отказ
 * сборки (ir.h, «отказ памяти»), и применение спеки не состоится (I-543). */
static void sb_emit(struct nft_rule *r, struct sbuf *b) {
    if (b->oom) {
        if (r && r->chain && r->chain->o.table && r->chain->o.table->rs) r->chain->o.table->rs->oom = 1;
    } else
        ir_x(r, "%s", sb_str(b));
    sb_free(b);
}

/* Единственные оставшиеся в этом файле пользователи — построители цепочек output для каналов
 * на само устройство ниже (plat()->local_channels): kind_ops.emit видов zapret/tgws берёт
 * таблицу так же, но своим вызовом ir_table_find в src/kinds. */
static struct nft_table *inet_table(struct nft_rs *rs) {
    return ir_table_find(rs, NFT_FAM_INET, NULL);
}

/* «Кто» одной или двумя проверками.
 *
 * Адреса и MAC-и уходят РАЗНЫМИ выражениями, объединёнными по И... нет — по ИЛИ быть не может:
 * nft не умеет «или» внутри правила. Поэтому смешивать их в одном правиле нельзя, и это
 * проверяется при загрузке спеки: правило либо про адреса, либо про MAC-и. Молча взять только
 * половину значило бы, что часть устройств правило не касается, и понять это было бы нечем. */
/* Семейство записи «кому»: адрес IPv6 — с двоеточием (MAC отсюда не спрашивают: у клиента
 * либо все записи MAC, либо ни одной — это проверяет разбор). */
static int from_fam(const char *s) {
    return strchr(s, ':') ? 6 : 4;
}

/* Сколько в «кому» группы записей семейства fam. */
static size_t who_count(const struct group *g, int fam) {
    size_t n = 0;
    for (size_t i = 0; i < g->from_n; i++) if (from_fam(g->from[i]) == fam) n++;
    return n;
}

/* «Кто» узнаётся не адресом, а устройством или MAC — одним выражением на оба семейства. */
static int who_any_family(const struct group *g) {
    return !g->from_n || is_mac(g->from[0]);
}

/* С 1.9 в «кому» бывают адреса обоих семейств (docs/architecture.md, «4б»): у правила IPv4 в
 * перечне только записи IPv4 (`ip saddr`), у его v6-двойника — только IPv6 (`ip6 saddr`, x_who6).
 * У клиента из одних IPv4 перечень тот же, что до 1.9, до байта. MAC — одно выражение на оба. */
static void x_who(struct nft_rule *r, const struct group *g, int reverse) {
    if (!g->from_n) return;
    int mac = is_mac(g->from[0]);
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s %s { ", mac ? "ether" : "ip", reverse ? "daddr" : "saddr");
    size_t k = 0;
    for (size_t i = 0; i < g->from_n; i++) {
        if (!mac && from_fam(g->from[i]) != 4) continue;
        sb_add(&b, "%s%s", k++ ? ", " : "", g->from[i]);
    }
    sb_add(&b, " }");
    sb_emit(r, &b);
}

static void x_who6(struct nft_rule *r, const struct group *g, int reverse) {
    struct sbuf b = { .n = 0 };
    sb_add(&b, "ip6 %s { ", reverse ? "daddr" : "saddr");
    size_t k = 0;
    for (size_t i = 0; i < g->from_n; i++) {
        if (from_fam(g->from[i]) != 6) continue;
        sb_add(&b, "%s%s", k++ ? ", " : "", g->from[i]);
    }
    sb_add(&b, " }");
    sb_emit(r, &b);
}

/* «Кто» по устройству: клиенты, которых мы узнаём по интерфейсу, а не по адресу.
 *
 * ИМЕНЕМ (`iifname`), А НЕ НОМЕРОМ (`iif`). Разница не косметическая: `iif` ядро разрешает
 * в индекс в момент ЗАГРУЗКИ правила и на отсутствующем устройстве отказывает всей
 * транзакции. А tailscale0 и zt* появляются позже сети и пропадают при перезапуске своего
 * демона — то есть на `iif` перезагрузка роутера оставляла бы человека вообще без правил.
 * `iifname` сверяется по имени в момент прохода пакета: правило спокойно грузится на
 * отсутствующее устройство и начинает работать само, когда оно поднимется.
 *
 * Один элемент печатается без фигурных скобок: так вывод `--dry-run` у обычной
 * конфигурации остаётся тем же текстом, что и раньше, и nft печатает его так же. */
static void x_ifs(struct nft_rule *r, const struct spec *sp, int reverse) {
    const char *kw = reverse ? "oifname" : "iifname";
    if (sp->lan_dev_n == 1) { ir_x(r, "%s \"%s\"", kw, sp->lan_dev[0]); return; }
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s { ", kw);
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        sb_add(&b, "%s\"%s\"", i ? ", " : "", sp->lan_dev[i]);
    sb_add(&b, " }");
    sb_emit(r, &b);
}

/* «Кто» у правила группы. Способ ровно один, и это принципиально: адреса ИЛИ устройства, а
 * не то и другое сразу.
 *
 * ПОЧЕМУ НЕ ОБА. Соблазн был — добавлять правило по устройствам вдобавок к адресному, чтобы
 * перечень интерфейсов действовал всегда. Но `from_default` пишут в спеке, чтобы клиентов
 * ОГРАНИЧИТЬ: гостевая подсеть на том же мосту нарочно остаётся за пределами списка. Второе
 * правило по `iifname "br-lan"` молча забрало бы и её — то есть добавление интерфейса меняло
 * бы смысл давно написанной строки. Поэтому явный `from_default` значит ровно то, что
 * написано, а противоречие «клиенты описаны и подсетями, и несколькими устройствами»
 * отвергается при загрузке спеки (см. load_spec), а не разрешается движком на свой вкус. */
static void x_from(struct nft_rule *r, const struct spec *sp, const struct group *g) {
    if (g->from_n) x_who(r, g, 0); else x_ifs(r, sp, 0);
}

/* То же «кто», но на встречном пути: там наш клиент — это ПОЛУЧАТЕЛЬ. */
static void x_to(struct nft_rule *r, const struct spec *sp, const struct group *g) {
    if (g->from_n) x_who(r, g, 1); else x_ifs(r, sp, 1);
}

/* ---- IPv6 правил (docs/architecture.md, «4б») ---------------------------------------------
 *
 * Правило группы в таблице inet смотрит в набор ipv4_addr, и пакет IPv6 его не касается. С 1.9
 * у группы есть v6-двойник: то же «кто», то же сужение, поиск в парном наборе «<имя>6» (или
 * «весь трафик»), та же метка — и тот же комментарий, поэтому счётчик канала остаётся одним
 * числом (counters_load складывает правила с одним именем, как у половин набора старого ядра).
 *
 * «Кто» у двойника:
 *   устройства (iifname) и MAC (ether saddr) — одно выражение на оба семейства. У группы «весь
 *   трафик» с таким «кто» двойника нет вовсе: правило IPv4 и так ловит оба семейства, и так было
 *   и до 1.9 — только маршрута IPv6 у выхода не было, и трафик уходил напрямую;
 *   адреса — записи IPv6 из «кому» (`ip6 saddr`). У клиентов по умолчанию, заданных одними
 *   подсетями IPv4 (from_default), — по устройствам, как у заворота DNS: стабильного префикса
 *   IPv6 у локальной сети нет (его раздаёт провайдер и меняет), и записать его в from_default
 *   нельзя. У своего клиента правила из одних адресов IPv4 двойника нет: его IPv6 правило не
 *   узнаёт, и diag об этом говорит (для такого клиента нужен MAC или адрес IPv6). */
static int who_is_lan(const struct spec *sp, const struct group *g) {
    if (g->from_n != sp->lan.from_n) return 0;
    for (size_t i = 0; i < g->from_n; i++)
        if (strcmp(g->from[i], sp->lan.from[i]) != 0) return 0;
    return 1;
}

/* Можно ли выразить «кто» для IPv6. */
static int who6_ok(const struct spec *sp, const struct group *g) {
    return who_any_family(g) || who_count(g, 6) || who_is_lan(sp, g);
}

/* Есть ли у группы правило IPv4: «кто» из одних адресов IPv6 его не даёт. */
static int who4_ok(const struct group *g) {
    if (!(g->fam & 1)) return 0;               /* family: 6 — IPv4 не наше дело (R-154) */
    return who_any_family(g) || who_count(g, 4);
}

/* Правило IPv4 группы ловит и IPv6: «кто» без адресов и назначение без набора («весь трафик»). */
static int group_v4_agn(const struct group *g) {
    /* С политикой семейства правило IPv4 семейство называет само (ir_family в build_mark_rule4), и
     * двойник у группы свой — «оба семейства одним правилом» остаётся только у группы без неё. */
    return !g->famreq && who_any_family(g) && !group_has_set(g) && !g->xsrc_n;
}

/* IPv6 клиентов группы «весь трафик» с политикой семейства, оставившей её без половины IPv6, —
 * отвергается правилом в prerouting_mark: иначе при family: 4 (или запасном IPv4) он шёл бы
 * напрямую мимо выхода, а правило «весь трафик» именно это и обещает не делать. Выходу без метки
 * (direct) нечего охранять — его трафик и так идёт обычным путём. */
static int group_v6_guard(const struct spec *sp, const struct group *g, const struct output *o) {
    return g->famreq && g->all && !g->xsrc_n && !(g->fam & 2) && out_needs_mark(o) &&
           who6_ok(sp, g);
}

/* Нужен ли группе v6-двойник: есть набор IPv6 или это «весь трафик» (не доп. группа с «ip saddr»
 * из набора — ограничение по клиенту у неё только IPv4), и правило IPv4 IPv6 не ловит. */
static int group_needs6(const struct spec *sp, const struct group *g) {
    if (!(g->fam & 2)) return 0;               /* family: 4 или IPv6 недоступен с запасом (R-154) */
    if (group_v4_agn(g)) return 0;
    if (!group_has_set6(g) && !(g->all && !g->xsrc_n)) return 0;
    return who6_ok(sp, g);
}

/* «Кто» двойника. need_fam — у правила нет выражения, которое само сужает до IPv6 (поиска в
 * наборе IPv6), и «кто» по устройству поймал бы и IPv4: тогда `meta nfproto ipv6`. */
static void x_from6(struct nft_rule *r, const struct spec *sp, const struct group *g, int reverse,
                    int need_fam) {
    if (who_any_family(g) || !who_count(g, 6)) {
        if (g->from_n && is_mac(g->from[0])) x_who(r, g, reverse);
        else x_ifs(r, sp, reverse);
        if (need_fam) ir_family(r, 6);
        return;
    }
    x_who6(r, g, reverse);
}

/* Выход несёт IPv6: у него свой маршрут IPv6 (KC_IPV6) или метки нет вовсе (direct — трафик идёт
 * обычным путём, как у IPv4). */
static int out_v6_ok(const struct output *o) {
    return !out_needs_mark(o) || out_has_cap(o, KC_IPV6);
}

/* «Чем и куда именно»: сужение канала по протоколу и портам назначения (схема 2).
 *
 * ПОЧЕМУ `meta l4proto` ПЛЮС `th dport`, А НЕ `tcp dport`/`udp dport`. Две причины, и
 * первая решающая.
 *
 * Первая: nft не умеет «или» внутри правила. Слово `tcp dport` само тянет за собой
 * зависимость «протокол tcp», поэтому «и TCP, и UDP на этих портах» им не записать — пришлось
 * бы ставить ДВА правила на один канал. А правило у канала одно не для красоты: на нём висит
 * счётчик (второе правило разделило бы объёмы канала на две половины, и ни одна не была бы
 * ответом на «сколько ушло»), и на нём же держится «первое совпадение выигрывает» — порядок,
 * который человек читает прямо по спеке. `meta l4proto { tcp, udp }` — это МНОЖЕСТВО, а не
 * «или», и оно укладывается в то же одно правило.
 *
 * Вторая: одна форма и для одного протокола, и для двух. Ветка «а если протокол один,
 * печатаем по-другому» — это второй путь, по которому пойдёт ровно половина каналов, и
 * расходиться этим двум путям негде, кроме опыта на живом роутере.
 *
 * И ЭТО НЕ КОМПРОМИСС: разницы с «правильной» формой нет никакой. Проверено загрузкой в
 * ядро (nftables 1.0.9): `meta l4proto udp th dport { … }` ядро печатает обратно как
 * `udp dport { … }`, а `meta l4proto tcp th dport 1-1024` — как `tcp dport 1-1024`. То
 * есть специальная форма и есть наша, просто записанная короче, — а множество из двух
 * протоколов ядро оставляет как написано, потому что короче его не записать.
 *
 * ЗАЧЕМ ПРОТОКОЛ ОБЯЗАТЕЛЕН ПЕРЕД ПОРТОМ. `th` — это смещение в транспортном заголовке, и
 * никакой проверки протокола в нём нет. У icmp, esp, gre по этому смещению лежат чужие байты,
 * и `th dport 50000-65535` совпал бы на них — то есть канал забирал бы пакеты, у которых
 * портов не бывает вовсе. Поэтому при заданных портах протокол пинится ВСЕГДА, и когда
 * человек его не назвал — множеством `{ tcp, udp }`, которое здесь работает носителем для
 * чтения порта, а не сужением по протоколу.
 *
 * СЕМЕЙСТВА АДРЕСОВ. Таблица `inet` несёт и IPv4, и IPv6; `meta l4proto` и `th` смотрят на
 * транспортный уровень и одинаково верны для обоих — в отличие от `ip saddr`, которому нужен
 * близнец `ip6 saddr` (см. x_ifs и правило DNS). Пометки семейства здесь поэтому нет.
 *
 * ПОРЯДОК В ПРАВИЛЕ: сужение стоит ПЕРЕД поиском по набору адресов. Сравнение одного байта
 * протокола дешевле поиска в наборе на 19 тысяч префиксов, и для канала «только UDP» оно
 * отбрасывает весь TCP роутера до поиска, а не после. На пакет это один и тот же путь, но
 * пакетов, которым канал не подходит, всегда больше.
 *
 * reverse — встречный путь: там наш клиент получатель, а порт сервера ИСХОДЯЩИЙ. */
static void x_l4(struct nft_rule *r, const struct l4match *m, int reverse) {
    if (l4match_plain(m)) return;       /* признак quic трафик не сужает */
    if (m->proto == CH_PROTO_TCP)      ir_x(r, "meta l4proto tcp");
    else if (m->proto == CH_PROTO_UDP) ir_x(r, "meta l4proto udp");
    else                               ir_x(r, "meta l4proto { tcp, udp }");
    if (!m->ports_n) return;
    /* Один диапазон печатается без фигурных скобок — ровно как одно устройство в x_ifs, и
     * по той же причине: так это печатает сам nft, и вывод `--dry-run` совпадает с тем, что
     * человек потом увидит в `nft list`. */
    int one = m->ports_n == 1;
    struct sbuf b = { .n = 0 };
    sb_add(&b, "th %s %s", reverse ? "sport" : "dport", one ? "" : "{ ");
    for (size_t i = 0; i < m->ports_n; i++) {
        if (i) sb_add(&b, ", ");
        if (m->ports[i].lo == m->ports[i].hi) sb_add(&b, "%u", m->ports[i].lo);
        else sb_add(&b, "%u-%u", m->ports[i].lo, m->ports[i].hi);
    }
    if (!one) sb_add(&b, " }");
    sb_emit(r, &b);
}

/* Сужение словами, для explain. Отдельно от x_l4, потому что там формат nftables, а
 * здесь фраза человеку; печатать в ответ человеку синтаксис ядра значило бы объяснять
 * настройку языком, которого он не выбирал.
 *
 * Дописывается КУСКАМИ С ПРОВЕРКОЙ МЕСТА, а не сложением возвратов snprintf, и это не
 * педантизм: snprintf возвращает длину, которая ПОЛУЧИЛАСЬ БЫ, а не записанную. Сложение
 * таких возвратов уводит смещение за буфер, и следующий `n - k` уходит в подпол size_t,
 * превращая ограничение длины в «сколько угодно». Шестнадцать диапазонов по «50000-65535» —
 * это 217 байт, то есть предел L4_PORTS_MAX переполняет любой разумный буфер, и случай не
 * гипотетический. Не влезло — обрываем на границе куска: обрезанный перечень портов в
 * ПОЯСНЕНИИ безобиден, порванная память — нет. */
void l4_describe(const struct l4match *m, char *dst, size_t n) {
    if (!n) return;
    size_t k = 0;
    dst[0] = '\0';
    char piece[32];
    snprintf(piece, sizeof(piece), "%s",
             m->proto == CH_PROTO_TCP ? "tcp" :
             m->proto == CH_PROTO_UDP ? "udp" : "tcp и udp");
    for (size_t i = 0; i <= m->ports_n; i++) {
        if (i) {
            if (m->ports[i - 1].lo == m->ports[i - 1].hi)
                snprintf(piece, sizeof(piece), "%s%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo);
            else
                snprintf(piece, sizeof(piece), "%s%u-%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo, m->ports[i - 1].hi);
        }
        size_t len = strlen(piece);
        if (k + len + 1 > n) return;
        memcpy(dst + k, piece, len);
        k += len;
        dst[k] = '\0';
    }
}

/* ---- перенос счётчиков через apply ------------------------------------------
 *
 * `apply` заменяет таблицу новой одной транзакцией, а счётчики живут в правилах —
 * значит каждый apply обнулял их. Само по себе это выглядело безобидно, но обновление списков
 * из splify2 вызывает apply по расписанию, раз в сутки в пять утра. То есть объёмы в
 * интерфейсе всегда были «с пяти утра», нигде об этом не сказано, и вопрос «сколько ушло за
 * сутки» ответа не имел. Замер: 4 090 141 байт до apply, 0 после.
 *
 * Поэтому перед генерацией читаем то, что накопилось, и вписываем в новые правила: nft
 * принимает `counter packets N bytes M` на входе — ровно в том виде, в каком сам печатает.
 *
 * Переносим ПО ИМЕНИ КАНАЛА, а не по номеру правила: правила перетасовываются при любой
 * правке спеки, и перенос по позиции приписал бы чужой трафик. Канал, которого в новой спеке
 * нет, свой счётчик теряет — это и правильно, его больше не существует.
 */
/* Счётчики растут по числу каналов в ядре (раньше — массивы на 64: у 65-го канала счётчик при
 * каждом apply обнулялся МОЛЧА, и «объём канала» врал). */
struct ctr { char name[32]; unsigned long pkts, bytes; };
static struct ctr *g_ctr_up, *g_ctr_down;
static size_t g_ctr_up_n, g_ctr_down_n, g_ctr_up_cap, g_ctr_down_cap;

/* Чтение счётчиков — ОДНО на apply и status. Раздельные разошлись бы в понимании одного и того
 * же, а расхождение здесь означало бы, что перенесённое и показанное — разные числа.
 *
 * Спрашивается ядро по netlink (src/lib/nftdump.c), а не `nft -a list chain`: status интерфейс
 * опрашивает раз в несколько секунд, и запуск `sh -c nft …` на каждый вызов был половиной его
 * цены в процессах (docs/architecture.md, «4а», «Сокет и протокол»). Имя канала — в комментарии
 * правила (userdata, как его пишет nft), число — в выражении counter того же правила. */
static void ctr_take(void *arg, const char *comment, int has_counter,
                     uint64_t packets, uint64_t bytes) {
    (void)arg;
    /* Встречный вид проверяется первым: «steer:» — начало и «steer-down:». */
    int down = 0;
    const char *c;
    if (!strncmp(comment, "steer-down:", 11)) { c = comment + 11; down = 1; }
    else if (!strncmp(comment, "steer:", 6)) c = comment + 6;
    else return;
    unsigned long p = has_counter ? (unsigned long)packets : 0;
    unsigned long b = has_counter ? (unsigned long)bytes : 0;
    struct ctr **arrp = down ? &g_ctr_down : &g_ctr_up;
    struct ctr *arr = *arrp;
    size_t *n = down ? &g_ctr_down_n : &g_ctr_up_n;
    size_t *cap = down ? &g_ctr_down_cap : &g_ctr_up_cap;
    /* Одно имя — одно число. С 1.9 у правила группы бывает v6-двойник под тем же именем
     * (docs/architecture.md, «4б»), а в старой раскладке у доменной группы с префиксами правил
     * два (по одному на половину набора, см. legacy.c): объём канала — их сумма. */
    size_t k = 0;
    while (k < *n && strcmp(arr[k].name, c) != 0) k++;
    if (k < *n) {
        arr[k].pkts += p;
        arr[k].bytes += b;
        return;
    }
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 32;
        struct ctr *na = realloc(arr, nc * sizeof(*na));
        if (!na) return;                /* нет памяти — счётчик этого канала не переносится */
        *arrp = arr = na;
        *cap = nc;
    }
    {
        snprintf(arr[*n].name, sizeof(arr[*n].name), "%s", c);
        arr[*n].pkts = p;
        arr[*n].bytes = b;
        (*n)++;
    }
}

void counters_load(void) {
    g_ctr_up_n = g_ctr_down_n = 0;
    /* Все цепочки одним дампом: счётчики, снятые в разные моменты, дали бы «отдано больше,
     * чем скачано» на глазах у человека.
     *
     * Таблица — своя у каждой сборки (nft_table): у мини-сборки моста это inet stgws, и с
     * жёстким «inet steer» её счётчики через apply не переносились.
     *
     * Каналы на сам телефон считаются в своих цепочках: отданное — в output_mark (правило
     * разметки на хуке output), скачанное — в input_down (см. nft_emit_output_mark). Без них
     * status не отдавал для таких каналов ни одного байта, и экран приложения показывал пустой
     * «трафик по правилам» при живом туннеле. На роутере этих цепочек нет, и ядро просто
     * отвечает, что их нет.
     *
     * ingress_mark — разметка на хуке ingress (ниже, «разметка на ingress»): там считает правило
     * канала, когда пакет пришёл с устройства раздачи, а prerouting_mark — когда пакет разобран
     * заново там (устройство без хука, чужая перезапись метки). Одно имя — одна сумма (ctr_take),
     * так что объём канала — оба вместе. */
    static const char *const chains[] = {
        "ingress_mark", "prerouting_mark", "postrouting_down", "output_mark", "input_down",
    };
    nfd_chain_rules(NFD_INET, nft_table(), chains, sizeof(chains) / sizeof(chains[0]),
                    ctr_take, NULL);
}

/* Найти прежнее значение. -1 — канала в ядре не было (первый apply или новый канал). */
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b) {
    const struct ctr *arr = down ? g_ctr_down : g_ctr_up;
    size_t n = down ? g_ctr_down_n : g_ctr_up_n;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(arr[i].name, name)) { *p = arr[i].pkts; *b = arr[i].bytes; return 0; }
    return -1;
}

/* `counter` с прежним значением, если оно есть (нули печатник пишет коротким `counter`). */
static void x_counter_carried(struct nft_rule *r, const char *name, int down) {
    unsigned long p = 0, b = 0;
    if (counter_find(name, down, &p, &b) != 0) p = b = 0;
    ir_counter(r, p, b);
}

/* Разметка пакета выходом: НАШИ биты, а не всё слово — см. у prerouting_mark. */
static void x_mark(struct nft_rule *r, const struct output *o, unsigned mark) {
    if (!out_needs_mark(o)) return;
    ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK, mark);
    if (out_needs_ctmark(o)) ir_x(r, "ct mark set mark");
}

/* То же на хуке ingress: только метка пакета. Записи conntrack на ingress ещё нет (её заводит
 * conntrack на prerouting, приоритет -200), и `ct mark set` там ядро не выполнит; метку
 * соединения ставит prerouting_mark по готовой метке пакета (цепочка ingress_ct). */
static void x_mark_ingress(struct nft_rule *r, const struct output *o, unsigned mark) {
    if (!out_needs_mark(o)) return;
    ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK, mark);
}

/* ---- наборы групп ----------------------------------------------------------------------- */

/* Подсети наборов sing-box группы — источниками элементов (печатник читает их потоком). */
/* fam — семейство набора: 4 — обычный, 6 — парный «<имя>6» (подсети v6 тех же клауз). */
static void set_add_srs(struct nft_table *t, struct nft_set *s, const struct group *g, int excl,
                        int fam) {
    for (size_t k = 0; k < g->srs_n; k++) {
        const struct srs_psel *ps = g->srs[k];
        size_t n = 0;
        for (size_t c = 0; c < ps->ncl; c++)
            if (ps->sel[c >> 3] & (1u << (c & 7))) {
                const struct srs_clause *cl = srs_clause(ps->set, c);
                if (cl->kind == SRS_C_CIDR)
                    n += fam == 6 ? (excl ? 0 : cl->n_v6) : excl ? cl->n_xv4 : cl->n_v4;
            }
        if (!n) continue;
        struct ir_srs *src = ir_mem(t->rs, sizeof(*src));
        if (!src) return;
        src->set = ps->set;
        src->sel = ps->sel;
        src->excl = excl;
        ir_set_srs(s, ps->path, src);
    }
}

/* Элементы составного набора: адресные списки со сужением канала и подсети наборов со своим
 * сужением у каждой клаузы. Раскладку в непересекающиеся элементы делает печатник. */
static void set_add_mixed(struct nft_table *t, struct nft_set *s, const struct group *g, int fam) {
    size_t addrs = fam == 6 ? g->addrs6 : g->addrs;
    size_t srs_addrs = fam == 6 ? g->srs_addrs6 : g->srs_addrs;
    size_t n = (addrs ? g->files_n : 0) + (srs_addrs ? g->srs_n : 0);
    if (!n) return;
    struct ir_mixed_src *v = ir_mem(t->rs, n * sizeof(*v));
    struct ir_mixed *m = ir_mem(t->rs, sizeof(*m));
    if (!v || !m) return;
    size_t k = 0;
    if (addrs)
        for (size_t f = 0; f < g->files_n; f++) {
            v[k].path = g->files[f];
            v[k].l4 = g->files_l4[f];
            k++;
        }
    if (srs_addrs)
        for (size_t f = 0; f < g->srs_n; f++) {
            v[k].path = g->srs[f]->path;
            v[k].set = g->srs[f]->set;
            v[k].sel = g->srs[f]->sel;
            v[k].eff = g->srs[f]->eff;
            k++;
        }
    m->n = k;
    m->v = v;
    ir_set_mixed(s, m);
}

static void build_group_sets(struct nft_table *t, const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        /* `any`-группе набор не нужен; опустевшей — нужен, иначе её правило потеряет
         * `ip daddr` и станет безусловным (см. поле `emptied`). */
        if (!group_has_set(g)) continue;
        /* Составной набор: адрес . протокол . порты — у списка канала смешанное сужение, и у
         * каждого элемента оно своё (src/model/srsplan.c). Флаги те же, что у обычного; без
         * auto-merge: ядро сливает в составном ключе только точные повторы, а пересечений в нём
         * нет по построению (раскладку делает печатник). */
        char n6[80];
        group_set6_name(g, n6, sizeof(n6));
        if (g->composite) {
            struct nft_set *s = ir_set_add(t, g->name, "ipv4_addr . inet_proto . inet_service");
            if (!s) return;
            s->flags = NFT_SET_INTERVAL | (g->domains ? NFT_SET_TIMEOUT : 0);
            set_add_mixed(t, s, g, 4);
            /* Парный составной набор IPv6: те же списки и наборы, их строки и подсети IPv6. */
            if (group_has_set6(g)) {
                struct nft_set *s6 = ir_set_add(t, n6, "ipv6_addr . inet_proto . inet_service");
                if (!s6) return;
                s6->flags = NFT_SET_INTERVAL | (g->dom6 ? NFT_SET_TIMEOUT : 0);
                set_add_mixed(t, s6, g, 6);
            }
            continue;
        }
        struct nft_set *s = ir_set_add(t, g->name, "ipv4_addr");
        if (!s) return;
        /* Доменный набор — timeout из-за резолвера: он кладёт адреса с TTL ответа, и адрес,
         * который CDN перестал отдавать, истекает сам, а не копится вечно.
         *
         * Адресные списки в ТОЙ ЖЕ группе печатаются элементами без timeout, то есть
         * остаются навсегда. Что набор держит и те, и другие — проверено на живом nft, а
         * не выведено: элемент без своего timeout в наборе с этим флагом постоянный. Это
         * и позволяет одному правилу быть про сервис, а не про вид списка.
         *
         * auto-merge because several lists in one group WILL overlap — an address
         * list and a service list cover the same hosting — and folding duplicates
         * in the kernel is cheaper than rewriting the text. */
        s->flags = NFT_SET_INTERVAL | (g->domains ? NFT_SET_TIMEOUT : 0);
        s->auto_merge = 1;
        /* Пустой набор объявляется БЕЗ строки elements: `elements = {  }` nft не примет,
         * а объявление без элементов — обычное дело (так же начинают жизнь доменные
         * наборы, которые наполняет резолвер). Списки в набор — ССЫЛКАМИ: элементы читает
         * печатник потоком (ir.h, «Память»). */
        if (g->files_n && g->addrs)
            for (size_t k = 0; k < g->files_n; k++) ir_set_file(s, g->files[k]);
        if (g->srs_addrs) set_add_srs(t, s, g, 0, 4);
        /* Исключения-подсети доп. группы («x.com, но не эти адреса»): свой набор рядом, и
         * правило проверяет его ПЕРЕД поиском в основном (x_dest). */
        if (g->xcidr) {
            char xn[80];
            snprintf(xn, sizeof(xn), "%s_x", g->name);
            struct nft_set *x = ir_set_add(t, xn, "ipv4_addr");
            if (!x) return;
            x->flags = NFT_SET_INTERVAL;
            x->auto_merge = 1;
            set_add_srs(t, x, g, 1, 4);
        }
        /* Парный набор IPv6 (docs/architecture.md, «4б»): строки IPv6 тех же файлов и подсети
         * IPv6 тех же наборов .srs. У доменной группы с половиной IPv6 (dom6) его наполняет и
         * резолвер — поддельными адресами IPv6 (навсегда) и настоящими из ответов AAAA (со
         * сроком ответа), поэтому флаг timeout, как у набора IPv4 доменной группы. На старом
         * ядре такой набор делится надвое тем же шагом, что набор IPv4 (legacy.c). Без dom6
         * элементы в нём только постоянные, и флага нет. */
        if (group_has_set6(g)) {
            struct nft_set *s6 = ir_set_add(t, n6, "ipv6_addr");
            if (!s6) return;
            s6->flags = NFT_SET_INTERVAL | (g->dom6 ? NFT_SET_TIMEOUT : 0);
            s6->auto_merge = 1;
            if (g->addrs6)
                for (size_t k = 0; k < g->files_n; k++) ir_set_file(s6, g->files[k]);
            if (g->srs_addrs6) set_add_srs(t, s6, g, 0, 6);
        }
    }
}

/* Назначение v6-двойника: сужение и поиск в парном наборе (или «весь трафик» — без поиска). */
static void x_dest6(struct nft_rule *r, const struct group *g, int reverse) {
    char n6[80];
    group_set6_name(g, n6, sizeof(n6));
    if (g->composite) {
        if (group_has_set6(g))
            ir_setref(r, reverse ? "ip6 saddr . meta l4proto . th sport"
                                 : "ip6 daddr . meta l4proto . th dport", n6);
        return;
    }
    x_l4(r, g->l4, reverse);
    if (group_has_set6(g)) ir_setref(r, reverse ? "ip6 saddr" : "ip6 daddr", n6);
}

/* Назначение у правила группы: сужение и поиск в наборе, а у групп каналов с наборами sing-box
 * ещё и их условия. reverse — встречный путь (там наш клиент — получатель, сервер — источник).
 * lookup — ставить ли поиск в наборе (у разных цепочек своё условие, см. вызовы).
 *
 * Составной набор ищется одним выражением: адрес, протокол и порт сразу (`ip daddr . meta
 * l4proto . th dport`), и отдельного x_l4 у такого правила нет — сужение лежит в элементах.
 * У пакета без портов (ICMP, GRE) `th dport` читает два байта его заголовка, а элемент без
 * сужения покрывает протоколы 0-255 и порты 0-65535, поэтому такой пакет ловится тем же
 * правилом, что и раньше обычным набором. */
static void x_dest(struct nft_rule *r, const struct group *g, int reverse, int lookup) {
    if (g->xsrc_n) {
        /* Ограничение по клиенту из набора (source_ip_cidr) — второе «ip saddr» рядом с «кому»
         * канала: два сравнения в одном правиле — это пересечение. */
        struct sbuf b = { .n = 0 };
        sb_add(&b, "ip %s { ", reverse ? "daddr" : "saddr");
        for (size_t i = 0; i < g->xsrc_n; i++) {
            uint32_t a = g->xsrc[i].net;
            sb_add(&b, "%s%u.%u.%u.%u/%d", i ? ", " : "", a >> 24, (a >> 16) & 255,
                   (a >> 8) & 255, a & 255, g->xsrc[i].plen);
        }
        sb_add(&b, " }");
        sb_emit(r, &b);
    }
    if (g->composite) {
        if (lookup)
            ir_setref(r, reverse ? "ip saddr . meta l4proto . th sport"
                                 : "ip daddr . meta l4proto . th dport", g->name);
        return;
    }
    x_l4(r, g->l4, reverse);
    if (g->xcidr) ir_x(r, "ip %s != @%s_x", reverse ? "saddr" : "daddr", g->name);
    if (lookup) ir_setref(r, reverse ? "ip saddr" : "ip daddr", g->name);
}

/* ---- разметка: prerouting_mark ------------------------------------------------------------
 *
 * mangle + 1: the mark must exist before the routing decision, and staying one
 * step after mangle leaves room for anything that legitimately wants to run first.
 *
 * Где стоят правила каналов — mh (ниже, «разметка на ingress»): только здесь (MH_PREROUTING,
 * прежний набор до байта), на ingress (MH_INGRESS) или здесь же запасными к ingress
 * (MH_FALLBACK). */
enum mark_hook { MH_PREROUTING, MH_INGRESS, MH_FALLBACK };

/* Счётчик правила канала. Запасное правило prerouting рядом с ingress начинает с нуля: прежний
 * объём канала переносится один раз — в правило ingress, которое и считает его трафик, — иначе
 * каждый apply удваивал бы сумму (counters_load складывает правила с одним именем). */
static void x_counter_mh(struct nft_rule *r, const char *name, enum mark_hook mh) {
    if (mh == MH_FALLBACK) ir_counter(r, 0, 0);
    else x_counter_carried(r, name, 0);
}

static void build_mark_rule4(struct nft_chain *c, const struct spec *sp, const struct group *g,
                             const struct output *o, enum mark_hook mh);

/* ---- IPv6 ОТ ХОСТА: донор (ipv6: routed), шаг 8 выпуска 1.10 ------------------------------
 *
 * Устройство режимов — у enum out_ipv6 в spec.h. Здесь — три куска набора правил донора, и все
 * они стоят только в спеке с донором (spec_v6_donor), поэтому спека без ключа ipv6 даёт прежний
 * текст до байта.
 *
 * НАБОР v6donor (V6DONOR_SET) — префикс хоста: `prefix:` спеки или выведенный из адресов раздачи
 * (v6donor_derive, failover.c). Набор, а не адрес в тексте правил: выведенный префикс меняется без
 * смены спеки (netifd выдал LAN адрес позже, чем встал движок; человек сменил ip6prefix), и сторож
 * переписывает элементы набора сам (v6donor_sync), не заменяя набор правил. Элементы в тексте —
 * то, что известно при apply, чтобы с загрузки до первого прохода набор не стоял пустым.
 *
 * ВСЁ НЕСОВПАВШЕЕ ИЗ ПРЕФИКСА — В ДОНОРА: последнее правило разметки (v6donor_catchall). Правила
 * каналов стоят выше и решают первыми: правило в донора — его метка, правило в другой выход — метка
 * того выхода, и такой IPv6 отвергает forward_v6 (IPv6 у выхода рядом с донором снят,
 * spec_v6_resolve), правило direct — без метки, и его отвергает запрет источника ниже. Назначения
 * внутри своей сети в донора не уводятся: сам префикс (другие куски LAN), ULA, link-local и
 * multicast — их маршрут в main, а метка увела бы их в таблицу донора, то есть в туннель.
 *
 * ИСТОЧНИК ИЗ ПРЕФИКСА — ТОЛЬКО В ДОНОРА (v6donor_guard, цепочка forward_v6): пересылаемый пакет с
 * адресом из префикса, который уходит не в устройство донора и не в устройство раздачи, —
 * отвергается сразу (ICMPv6 admin-prohibited, клиент переходит на IPv4). Это fail-closed на все
 * случаи сразу: правило канала direct, упавший донор с on_fail=direct (правило fwmark снято, пакет
 * пошёл по main — в WAN), снятое netifd правило ip rule, чужой маршрут. Ответа на такой пакет всё
 * равно не было бы: другой сервер отбросит чужой источник по AllowedIPs, провайдер — по BCP38. По
 * имени устройства, как postrouting_guard, и в forward: там reject разрешён, и туда не попадает
 * трафик к самому роутеру. Там же — ULA-источник в донора (клиент идёт к поддельному адресу
 * fake-IP fdfe:… со своего ULA: так выбирает источник RFC 6724), если префикс хоста не сам ULA:
 * хост маршрутизует только префикс, и такой пакет он отбросит молча — отказ сразу лучше таймаута.
 *
 * Трафик самого роутера (хук output) сюда не входит: наружу роутер ходит со своих адресов WAN и
 * туннелей (выбор источника по устройству выхода), а не с адреса раздачи. */
static void v6donor_catchall(struct nft_chain *c, const struct spec *sp, enum mark_hook mh) {
    const struct output *d = spec_v6_donor(sp);
    if (!d || !d->mark) return;
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 6);
    ir_setref(r, "ip6 saddr", V6DONOR_SET);
    ir_setref(r, "ip6 daddr !=", V6DONOR_SET);
    ir_x(r, "ip6 daddr != { fc00::/7, fe80::/10, ff00::/8 }");
    unsigned mk = out_skips_zapret(d) ? (d->mark | ZAPRET_SKIP_MARK) : d->mark;
    if (mh == MH_INGRESS) x_mark_ingress(r, d, mk);
    else x_mark(r, d, mk);
    ir_counter(r, 0, 0);
    ir_x(r, "return");
    ir_comment(r, "steer-v6donor:%s", d->name);
}

/* QUIC ВЫКЛЮЧЕН у правила (`quic: block`, l4.quic_block группы): UDP/443 к назначениям группы
 * отвергается ДО правила разметки той же группы — первое совпавшее решает, и правило выше (иное
 * назначение, иной выход) QUIC своих адресов не теряет. Отказ — тот же ICMP «запрещено», что у
 * kind=block: браузер узнаёт о нём сразу и уходит на TCP, а не ждёт срока.
 *
 * Отвергает цепочка prerouting_mark: на ingress (netdev) reject недоступен, поэтому ingress_devs
 * при таком правиле разметку на ingress не ставит. «Весь трафик» — это интернет, как у
 * output_mark: своя сеть (принтер, NAS с HTTP/3) не затрагивается. Адреса домена здесь уже
 * поддельные (fake-IP): dnat к настоящему стоит позже разметки, и набор группы их и содержит. */
static void quic_reject(struct nft_chain *c, const struct spec *sp, const struct group *g) {
    static const char *const LOCAL4 = "ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, "
        "172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }";
    static const char *const LOCAL6 = "ip6 daddr != { ::1, fe80::/10, fc00::/7, ff00::/8 }";
    if (who4_ok(g)) {
        struct nft_rule *r = ir_rule(c);
        x_from(r, sp, g);
        if (g->all) { ir_family(r, 4); ir_x(r, "%s", LOCAL4); }
        x_dest(r, g, 0, group_has_set(g));
        ir_x(r, "meta l4proto udp");
        ir_x(r, "th dport 443");
        ir_counter(r, 0, 0);
        ir_x(r, "reject with icmpx admin-prohibited");
        ir_comment(r, "steer-quic:%s", g->name);
    }
    if (g->all ? who6_ok(sp, g) : group_needs6(sp, g)) {
        struct nft_rule *r = ir_rule(c);
        ir_rule_fam(r, 6);
        x_from6(r, sp, g, 0, !group_has_set6(g));
        if (g->all) ir_x(r, "%s", LOCAL6);
        x_dest6(r, g, 0);
        ir_x(r, "meta l4proto udp");
        ir_x(r, "th dport 443");
        ir_counter(r, 0, 0);
        ir_x(r, "reject with icmpx admin-prohibited");
        ir_comment(r, "steer-quic:%s", g->name);
    }
}

static int build_mark_rules(struct nft_chain *c, const struct spec *sp, const struct groups *gr,
                            enum mark_hook mh, struct err *e) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        struct output *o = out_by_name(sp, g->out);
        if (!o) return err_set(e, "channel group %s points at a missing output", g->name);
        /* Каналы на сам телефон — на хуке output, см. nft_emit_output_mark. */
        if (group_is_local(g)) continue;
        if (g->l4 && g->l4->quic_block && mh != MH_INGRESS) quic_reject(c, sp, g);
        /* ПРАВИЛО У ГРУППЫ ОДНО (в старой раскладке у доменной группы с префиксами их
         * становится два — см. legacy.c, шаг 1), и с 1.9 у него бывает v6-двойник ниже.
         * Клиент из одних адресов IPv6 правила IPv4 не даёт вовсе. */
        int carried = 0;
        if (who4_ok(g)) {
            carried = 1;
            build_mark_rule4(c, sp, g, o, mh);
        }
        /* Политика семейства: IPv6 «весь трафик» без половины IPv6 — отказ, не утечка. */
        if (mh != MH_INGRESS && group_v6_guard(sp, g, o)) {
            struct nft_rule *rg = ir_rule(c);
            ir_rule_fam(rg, 6);
            x_from6(rg, sp, g, 0, 1);
            x_l4(rg, g->l4, 0);
            ir_x(rg, "ip6 daddr != { ::1, fe80::/10, fc00::/7, ff00::/8 }");
            ir_counter(rg, 0, 0);
            ir_x(rg, "reject with icmpx type admin-prohibited");
            ir_comment(rg, "steer-v6fam:%s", g->name);
        }
        if (group_needs6(sp, g)) {
            struct nft_rule *r6 = ir_rule(c);
            ir_rule_fam(r6, 6);
            x_from6(r6, sp, g, 0, !group_has_set6(g));
            x_dest6(r6, g, 0);
            /* balance: двойник переходит в ту же цепочку группы — карта и метка соединения
             * семейству безразличны (IPv6 группы без IPv6 там же уходит в отказ, balance.c). На
             * ingress — метка самой группы, как у правила IPv4 (build_mark_rule4). */
            char bc[32] = "";
            unsigned mk = out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark;
            if (out_balanced(o) && mh == MH_INGRESS)
                ir_markset(r6, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK,
                           o->mark);
            else if (out_balanced(o)) group_bal_chain(o, bc, sizeof(bc));
            else if (mh == MH_INGRESS) x_mark_ingress(r6, o, mk);
            else x_mark(r6, o, mk);
            if (carried) ir_counter(r6, 0, 0);
            else x_counter_mh(r6, g->name, mh);
            if (bc[0]) ir_x(r6, "goto %s", bc);
            else ir_x(r6, "return");
            ir_comment(r6, "steer:%s", g->name);
        }
    }
    v6donor_catchall(c, sp, mh);
    return 0;
}

/* Правило IPv4 группы в prerouting_mark — прежнее, до байта (снимок tests/golden/ruleset); на
 * ingress — без метки соединения, а у группы balance — с меткой самой группы вместо перехода. */
static void build_mark_rule4(struct nft_chain *c, const struct spec *sp, const struct group *g,
                             const struct output *o, enum mark_hook mh) {
    {
        struct nft_rule *r = ir_rule(c);
        x_from(r, sp, g);
        if (g->famreq && !group_has_set(g) && who_any_family(g)) ir_family(r, 4);
        x_dest(r, g, 0, group_has_set(g));
        /* НАШИ биты, а не всё слово: `mark and ~маска or метка`. Перезапись стирала метку
         * mwan3/pbr/sqm молча, а их перезапись — нашу, и тогда помеченный пакет уходил по
         * таблице main, минуя запрет on_fail=drop (I-135). Диапазон объявлен в spec.h и в
         * контракте. Ядро при выводе канонизирует выражение (оно само выставляет в маске
         * бит, который следующий `or` всё равно поднимает) — на поведение это не влияет,
         * проверено на живом роутере. */
        /* Метка ПАКЕТА решает маршрут, метка СОЕДИНЕНИЯ позволяет с этим соединением
         * потом что-то сделать. Без второй запись conntrack про выход не знает ничего
         * (mark=0 в дампе), и «сними соединения этого выхода» выразить нечем — а это
         * единственный способ пересмотреть маршрут уже установленного соединения.
         *
         * Понадобилось это из-за выгрузки потоков: замер на роутере показал, что при
         * flow_offloading=1 наша цепочка видит 2-7 пакетов соединения вместо
         * одиннадцати тысяч, то есть после установления маршрут больше не
         * пересматривается — и запрет on_fail=drop до такого соединения не доходит
         * (R-096). Тот же приём и по той же причине использует mwan3. */
        /* Ко всем выходам, КРОМЕ kind=direct, к нашей метке добавляется чужой бит —
         * тот, которым системный zapret узнаёт «этот пакет не мой» (ZAPRET_SKIP_MARK,
         * см. spec.h; кому именно и почему — out_skips_zapret там же).
         *
         * У kind=zapret без него трафик разбирали бы двое: сначала общий обход своей
         * стратегией, потом наш экземпляр своей, — и вышло бы не то, что выбрал
         * человек, ни в одном из двух смыслов. У туннельных выходов причина другая и
         * не менее веская: обход стал бы рассинхронизировать ВНЕШНИЕ пакеты туннеля,
         * до полезной нагрузки не добираясь вовсе.
         *
         * Ставится ЗДЕСЬ, в prerouting, потому что цепочки zapret висят на
         * postrouting: позже было бы поздно. */
        /* Метка СОЕДИНЕНИЯ ставится не всем: она живёт в conntrack и переживает
         * снятие правил, поэтому у выходов, которым она не нужна, её нет вовсе — см.
         * out_needs_ctmark в spec.h и что из-за неё случалось после удаления tgws. */
        /* Группа pick: balance метку не ставит здесь: правило переходит в её цепочку, и метку
         * члена выбирает карта (compile/balance.c). goto, а не jump: конец цепочки группы — это
         * конец и этой цепочки, как `return` ниже, — первое совпавшее правило решает. */
        /* На ingress записи conntrack ещё нет, и карта раздачи с её памятью соединения (`ct
         * mark and … goto mark_…`) там не работает. Поэтому правило канала ставит метку САМОЙ
         * группы, а prerouting_mark по ней переходит в цепочку группы (ingress_trust ниже):
         * дальше всё как без ingress — восстановление по метке соединения, карта, отказ. */
        if (out_balanced(o) && mh == MH_INGRESS) {
            ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK, o->mark);
            x_counter_mh(r, g->name, mh);
            ir_x(r, "return");
            ir_comment(r, "steer:%s", g->name);
            return;
        }
        if (out_balanced(o)) {
            char bc[32];
            group_bal_chain(o, bc, sizeof(bc));
            x_counter_mh(r, g->name, mh);
            ir_x(r, "goto %s", bc);
            ir_comment(r, "steer:%s", g->name);
            return;
        }
        unsigned mk = out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark;
        if (mh == MH_INGRESS) x_mark_ingress(r, o, mk);
        else x_mark(r, o, mk);
        /* `return` and not `accept`: it ends OUR chain, letting the rest of the
         * firewall proceed, while making the first matching group the winner. */
        x_counter_mh(r, g->name, mh);
        ir_x(r, "return");
        ir_comment(r, "steer:%s", g->name);
    }
}

/* ---- разметка на ingress ------------------------------------------------------------------
 *
 * РЕШЕНИЕ ВЛАДЕЛЬЦА (опрос 2026-09-28): «inet ingress — делаем сразу», по правилу раздела 2
 * docs/architecture.md — «чем ближе к L2, тем лучше, когда это даёт пользу». Классификация
 * пакета по наборам каналов — самая дорогая работа движка на пакет (поиск в наборах на десятки
 * тысяч префиксов), и она переезжает на хук ingress устройств раздачи: пакет получает метку
 * выхода ещё до conntrack, до чужих цепочек prerouting и до решения маршрутизации.
 *
 * ЧТО НЕ ПЕРЕЕЗЖАЕТ И ПОЧЕМУ. На ingress нет записи conntrack — её заводит conntrack на
 * prerouting (-200). Значит там нельзя ни поставить метку соединения (`ct mark set mark`: на неё
 * опираются снятие соединений выхода сторожем, очередь kind=zapret и счёт телефона), ни
 * прочитать её (память выбора группы balance, balance.c). Эти две вещи остаются в
 * prerouting_mark, и делает их там правило ingress_trust ниже по готовой метке пакета. Заворот
 * DNS, dnat fake-IP и перехват моста — цепочки nat, на ingress их нет вовсе; они на месте.
 *
 * УСТРОЙСТВО.
 *   ingress_mark (hook ingress, устройства раздачи, приоритет filter + 10): первым правилом
 *     пакет с пустым полем получает значение «разобран, выхода нет» (STEER_INGRESS_SEEN,
 *     marks.h), дальше — правила каналов в том же порядке и с тем же «кто» и «куда», что в
 *     prerouting, с меткой пакета без метки соединения. Совпавший канал ставит метку выхода
 *     (у balance — метку группы); direct и «ничего не совпало» оставляют «разобран».
 *   prerouting_mark первым правилом узнаёт пакет, пришедший с устройства ingress, по значению
 *     поля — картой вердиктов (ingress_trust): «разобран» — снять значение и выйти (цепочка
 *     ingress_seen), метка выхода с меткой соединения — `ct mark set mark` (ingress_ct), без неё
 *     — выйти, метка группы balance — в цепочку группы. Одно сравнение имени устройства и один
 *     поиск в хеше из десятка значений вместо поиска по наборам.
 *   Остальные правила prerouting_mark — те же правила каналов, что и без ingress, до байта
 *     (кроме переноса счётчика — x_counter_mh). Они запасные, и доходит до них пакет, который
 *     ingress не разбирал: пришедший с устройства, на котором хука нет (ниже, «устройство»), с
 *     другого устройства (клиент, заданный адресом, за туннелем, которого нет в lan_devices) и
 *     пакет, чью метку между ingress и нами переписал чужой (pbr, Tailscale: `and 0xff00ffff`
 *     обнуляет метки выходов 1-15 — почему ни одна из них не становится другой нашей меткой, у
 *     STEER_INGRESS_SEEN). Незнакомое значение поля — не наше, и пакет разбирается заново, как
 *     до ingress. Поэтому хуже прежнего не становится ни в одном из этих случаев: в худшем
 *     классификация стоит в prerouting, как стояла.
 *
 * ПРИОРИТЕТ filter + 10 — ПОСЛЕ flowtable. Выгрузка потоков fw4 (flow_offloading) висит на том
 *   же хуке ingress с приоритетом filter (0) и забирает пакеты выгруженного соединения себе
 *   (NF_STOLEN). До нас такой пакет не доходит, как не доходил и до prerouting: цепочка разметки
 *   по-прежнему видит единицы пакетов соединения, а не тысячи (замер у conntrack_evict в
 *   daemon/failover.c). Встань мы раньше flowtable, каждый выгруженный пакет проходил бы поиск по
 *   наборам впустую — это ровно та обработка, от которой выгрузка и избавляет.
 *
 * УСТРОЙСТВО, КОТОРОГО НЕТ. Цепочку ingress ядро принимает только на существующие устройства:
 *   одно несуществующее в списке — и отвергнута вся транзакция (проверено на 6.8, «No such file
 *   or directory»), то есть apply снял бы и наборы, и заворот DNS. Поэтому в цепочку идут
 *   только те устройства раздачи, что есть сейчас (if_nametoindex); остальных ведёт prerouting,
 *   как раньше. Исчезнувшее потом устройство ядро из цепочки вынимает (снова созданное — не
 *   возвращает), а с последним снимает всю цепочку. Для трафика это не поломка — prerouting
 *   видит пустое поле и разбирает пакет сам, — а отпечаток таблицы в ядре (nfd_table_fp, хук
 *   входит в него целиком) расходится с применённым, и следующий apply или reload (apply-сверка,
 *   daemon/recon.c) ставит набор заново уже на новое устройство (стенд ingressns). SIGHUP от
 *   hotplug (files/etc/hotplug.d) набор не ставит: он перечитывает спеку и зовёт проход сторожа.
 *   Демон со сторожем ставит его сам и сразу: новое устройство раздачи он узнаёт по событию
 *   rtnetlink (daemon/watchd.c, «УСТРОЙСТВА РАЗДАЧИ»; проверка на QEMU 04664a5 — после `network
 *   restart` цепочка возвращалась только сверкой на проходе, через 3,6-8,6 с). До того теряется
 *   только выигрыш ingress, а не маршрутизация.
 *
 * МОСТ. Цепочка висит на самом мосту (br-lan), а не на его портах: пакет с порта в стек
 *   маршрутизации мост отдаёт вверх через свой приёмник (br_pass_frame_up), и ingress моста его
 *   видит — с тем же ether saddr клиента (стенд ingressns). Пакеты между портами моста в стек
 *   не поднимаются и нас не касаются, как и раньше.
 *
 * ФРАГМЕНТЫ. На ingress пакеты ещё не собраны (сборка — defrag на prerouting, -400), и у
 *   фрагмента без начала портов нет: правило канала с сужением по портам его не узнаёт. Это
 *   безвредно: собранный пакет наследует метаданные первого фрагмента (inet_frag_reasm_prepare:
 *   skb_morph от головы очереди), а первый фрагмент порты несёт и разобран верно. Без сборки
 *   (conntrack выключен) фрагменты шли по отдельности и без ingress — prerouting тоже видел их
 *   без портов.
 *
 * ГДЕ INGRESS НЕ СТАВИТСЯ (ingress_devs): старое ядро и ядро без inet ingress (NFTC_INGRESS,
 *   проба nft_ingress_ok), платформа, где устройства раздачи появляются по требованию
 *   (lan_devs_persist — телефон), поле метки без места под «разобран» (мини-сборка tgws), спека
 *   без правил для раздачи, и ни одного существующего устройства раздачи. Каналы на сам телефон (from self, uid) —
 *   хук output, их это не касается вовсе.
 *
 * ЦЕНА. Выигрыша в работе на пакет нет: поиск по наборам тот же, только раньше, а к нему
 *   добавляется второй хук (ingress) и правило ingress_trust в prerouting. Замер в сетевых
 *   пространствах (стенд ingressns, INGRESSNS_BENCH=1, UDP по 64 байта, девять кругов, медианы):
 *   91,8 тыс. пакетов/с с ingress против 93,4 тыс. только в prerouting и 134,7 тыс. без движка
 *   (серия из семи кругов — 94,1, 98,9 и 139,9) — пересылка пакета на 2-5 % дороже, разбросы
 *   перекрываются; TCP на veth с GRO — в пределах разброса.
 *   Устройство — docs/architecture.md, раздел 2, «Набор правил», «Разметка на ingress». */
static size_t ingress_devs(const struct spec *sp, const struct groups *gr, const char **devs) {
    if (!(g_nftc & NFTC_INGRESS) || (g_nftc & NFTC_LEGACY)) return 0;
    if (!plat()->lan_devs_persist || !steer_ingress_seen_ok()) return 0;
    int any = 0;
    for (size_t i = 0; i < gr->n && !any; i++) any = !group_is_local(&gr->g[i]);
    if (!any) return 0;
    /* Правило с выключенным QUIC отвергает пакет в prerouting_mark, а на ingress reject нет, и
     * раньше отказа пакет уже получил бы метку выхода (разметка на ingress решает первой). */
    for (size_t i = 0; i < gr->n; i++)
        if (gr->g[i].l4 && gr->g[i].l4->quic_block) return 0;
    /* То же у отказа IPv6 «весь трафик» по политике семейства (group_v6_guard). */
    for (size_t i = 0; i < gr->n; i++) {
        const struct output *go = out_by_name(sp, gr->g[i].out);
        if (go && !group_is_local(&gr->g[i]) && group_v6_guard(sp, &gr->g[i], go)) return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        if (nft_ingress_all_devs() || if_nametoindex(sp->lan_dev[i]))
            devs[n++] = sp->lan_dev[i];
    return n;
}

/* «device "a"» или «devices = { "a", "b" }» — как пишет nft. */
static void devs_text(struct sbuf *b, const char *const *devs, size_t n) {
    if (n == 1) { sb_add(b, "device \"%s\"", devs[0]); return; }
    sb_add(b, "devices = { ");
    for (size_t i = 0; i < n; i++) sb_add(b, "%s\"%s\"", i ? ", " : "", devs[i]);
    sb_add(b, " }");
}

/* Первое правило prerouting_mark рядом с ingress: пакет с устройства ingress — по значению поля
 * метки. Ключи — ровно те значения, что ставят правила ingress_mark; прочие (пустое поле — хука
 * на устройстве нет; чужая перезапись) карта не узнаёт, и пакет идёт к запасным правилам. */
static void ingress_trust(struct nft_table *t, struct nft_chain *pm, const struct spec *sp,
                          const struct groups *gr, const char *const *devs, size_t nd) {
    struct sbuf b = { .n = 0 };
    sb_add(&b, "meta mark and 0x%08x vmap { 0x%08x : goto ingress_seen", STEER_MARK_MASK,
           STEER_INGRESS_SEEN);
    /* Различных меток — не больше, чем выходов в спеке (плюс донор IPv6, который тоже выход). */
    uint32_t *keys = malloc((sp->out_n + 1) * sizeof(*keys));
    if (!keys) { sb_free(&b); return; }
    size_t nk = 0;
    int ct = 0;
    /* Последним — донор IPv6: его метку ставит и правило «всё несовпавшее из префикса»
     * (v6donor_catchall), даже если ни одно правило в донора не ведёт. */
    for (size_t i = 0; i <= gr->n; i++) {
        const struct output *o;
        if (i == gr->n) {
            o = spec_v6_donor(sp);
        } else {
            const struct group *g = &gr->g[i];
            if (group_is_local(g)) continue;
            o = out_by_name(sp, g->out);
        }
        if (!o || (!out_balanced(o) && !out_needs_mark(o))) continue;
        size_t k = 0;
        while (k < nk && keys[k] != o->mark) k++;
        if (k < nk || nk >= sp->out_n + 1) continue;
        keys[nk++] = o->mark;
        char bc[32];
        if (out_balanced(o)) {
            group_bal_chain(o, bc, sizeof(bc));
            sb_add(&b, ", 0x%08x : goto %s", o->mark, bc);
        } else if (out_needs_ctmark(o)) {
            sb_add(&b, ", 0x%08x : goto ingress_ct", o->mark);
            ct = 1;
        } else {
            sb_add(&b, ", 0x%08x : return", o->mark);
        }
    }
    sb_add(&b, " }");
    free(keys);
    struct nft_rule *r = ir_rule(pm);
    struct sbuf d = { .n = 0 };
    if (nd == 1) sb_add(&d, "iifname \"%s\"", devs[0]);
    else {
        sb_add(&d, "iifname { ");
        for (size_t i = 0; i < nd; i++) sb_add(&d, "%s\"%s\"", i ? ", " : "", devs[i]);
        sb_add(&d, " }");
    }
    sb_emit(r, &d);
    sb_emit(r, &b);
    ir_comment(r, "steer-ingress");
    /* «Разобран, выхода нет» — снять значение: дальше пакет идёт с тем же пустым полем, что без
     * ingress (его видят чужие правила postrouting, сторож, очередь zapret). */
    ir_markset(ir_rule(ir_chain_add(t, "ingress_seen")), "meta mark set mark and 0x%08x",
               ~STEER_MARK_MASK);
    if (ct) ir_x(ir_rule(ir_chain_add(t, "ingress_ct")), "ct mark set mark");
}

/* Разметка каналов раздачи: prerouting_mark, а где можно — ingress_mark перед ним. */
static int build_mark(struct nft_table *t, const struct spec *sp, const struct groups *gr,
                      struct err *e) {
    /* Устройства ingress — не больше устройств спеки, массив по их числу (раньше 32 на стеке). */
    const char **devs = malloc((sp->lan_dev_n ? sp->lan_dev_n : 1) * sizeof(*devs));
    if (!devs) return err_set(e, "%s", "недостаточно памяти для разметки ingress");
    size_t nd = ingress_devs(sp, gr, devs);
    int rc = 0;
    if (nd) {
        struct nft_chain *ic = ir_base_chain_add(t, "ingress_mark", "filter", "ingress",
                                                 "filter", 10);
        struct sbuf d = { .n = 0 };
        devs_text(&d, devs, nd);
        ir_chain_devices(ic, sb_str(&d));
        sb_free(&d);
        struct nft_rule *r = ir_rule(ic);
        ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_MARK_MASK);
        ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK,
                   STEER_INGRESS_SEEN);
        ir_comment(r, "steer-ingress");
        if (build_mark_rules(ic, sp, gr, MH_INGRESS, e) != 0) { rc = -1; goto out; }
    }
    struct nft_chain *pm = ir_base_chain_add(t, "prerouting_mark", "filter", "prerouting",
                                             "mangle", 1);
    if (!nd) { rc = build_mark_rules(pm, sp, gr, MH_PREROUTING, e); goto out; }
    /* Правило ingress_trust — первым в prerouting_mark, запасные правила каналов — за ним.
     * Цепочки ingress_seen и ingress_ct ingress_trust заводит сразу, и в тексте они встают прямо
     * за prerouting_mark (порядок объектов дерева — порядок печати, а правила принадлежат своей
     * цепочке, где бы ни стояли объекты после неё). */
    ingress_trust(t, pm, sp, gr, devs, nd);
    rc = build_mark_rules(pm, sp, gr, MH_FALLBACK, e);
out:
    free(devs);
    return rc;
}

/* ВЫХОД УПАЛ И ПУЩЕН НАПРЯМУЮ — бит «не для zapret» снимается. Правило разметки выше
 * ставит его безусловно, а при on_fail=direct/zapret упавший выход отдаёт трафик
 * таблице main, то есть открытому пути; там пакет обязан быть обычным трафиком роутера
 * и для общего обхода тоже. Какие выходы сейчас в таком состоянии, знает сторож: он
 * держит их метки в наборе. Зачем именно так — у out_failopen_capable в spec.h.
 *
 * mangle + 2 — сразу после разметки (mangle + 1), то есть задолго до цепочек zapret на
 * postrouting. Счётчик — чтобы по дампу было видно, что правило действительно брало
 * пакеты, а не только стояло.
 *
 * НАБОР — ШИРЕ ЦЕПОЧКИ. С проверки на QEMU 04664a5 его читает и postrouting_guard ниже, которой
 * отметка нужна на любой платформе (out_releasable в spec.h): набор есть, когда в спеке есть
 * выход с устройством и on_fail не drop, а цепочка снятия бита — только там, где этот бит вообще
 * ставится (out_failopen_capable; на телефоне zapret нет, и цепочки нет). Где выход такой один и
 * бит есть — текст прежний до байта. */
static int has_releasable(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (sp->out[i].mark && out_releasable(&sp->out[i])) return 1;
    return 0;
}

const unsigned *g_failopen_seed;
size_t g_failopen_seed_n;

static void build_failopen(struct nft_table *t, const struct spec *sp) {
    int failopen = 0;
    for (size_t i = 0; i < sp->out_n; i++)
        if (out_failopen_capable(&sp->out[i])) failopen = 1;
    if (!failopen && !has_releasable(sp)) return;
    struct nft_set *fs = ir_set_add(t, FAILOPEN_SET, "mark");
    ir_gap(fs);
    for (size_t i = 0; i < g_failopen_seed_n; i++)
        ir_set_value(fs, ir_printf(t->rs, "0x%08x", g_failopen_seed[i]));
    if (!failopen) return;
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_failopen", "filter",
                                                   "prerouting", "mangle", 2));
    char m[40];
    snprintf(m, sizeof(m), "meta mark and 0x%08x", STEER_MARK_MASK);
    ir_setref(r, m, FAILOPEN_SET);
    ir_markset(r, "meta mark set mark and 0x%08x", ~ZAPRET_SKIP_MARK);
    ir_counter(r, 0, 0);
    ir_comment(r, "steer-failopen");
}

/* ВОЗВРАТ РЕШЕНИЯ ПОСЛЕ ЧУЖОЙ ПЕРЕЗАПИСИ (STEER_MARK_RESTORE=1 в окружении apply).
 *
 * Нужен экземпляру steer-box-connector — sing-box для podkop и forkop. Их цепочки ставят метку
 * пакету ЦЕЛИКОМ (`meta mark set 0x04000000`) на тех же хуках и приоритетах, что наша разметка:
 * forkop — `mangle + 1`, как prerouting_mark (порядок цепочек одного приоритета не определён), и
 * ещё на dstnat, уже по настоящему адресу после подмены fake-IP. Снято на стенде: первый пакет
 * соединения (SYN) терял наше поле и уходил напрямую, а следующие (forkop пропускает их по
 * `ct status dnat`) — в туннель; соединение разрывалось надвое, сервер отвечал сбросом.
 *
 * Решение уже записано в метку соединения (prerouting_mark: `ct mark set mark`), поэтому
 * последним перед выбором маршрута (dstnat + 10 — после nat и после чужих dstnat) пакет, у
 * которого наше поле пусто, а у соединения нет, получает поле и бит пропуска zapret обратно.
 * Пакет с непустым полем не трогается: у failopen бит zapret снят нарочно. Без переменной
 * цепочки нет, и набор правил прежний до байта. */
static void build_mark_restore(struct nft_table *t) {
    const char *e = getenv("STEER_MARK_RESTORE");
    if (!e || strcmp(e, "1")) return;
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_restore", "filter",
                                                   "prerouting", "dstnat", 10));
    /* Только прямое направление: ответ, который стек туннеля отдаёт клиенту из своего
     * устройства, несёт ту же метку соединения, и вернуть ему поле значило бы увести его по
     * таблице выхода обратно в туннель — петля (снято на стенде: миллионы пакетов в sbx0). */
    ir_x(r, "ct direction original");
    ir_x(r, "meta mark and 0x%08x == 0", STEER_MARK_MASK);
    ir_x(r, "ct mark and 0x%08x != 0", STEER_MARK_MASK);
    ir_markset(r, "meta mark set ct mark and 0x%08x", STEER_MARK_MASK | ZAPRET_SKIP_MARK);
    ir_counter(r, 0, 0);
    ir_comment(r, "steer-restore");
}

/* Встречный путь — только чтобы его было ЧЕМ ПОСЧИТАТЬ. Метку здесь не ставим и
 * решений не принимаем: маршрут ответным пакетам не нужен, их ведёт conntrack.
 *
 * Зачем вообще. Счётчик в prerouting_mark стоит на правиле, ставящем метку, а метка
 * ставится по пути «из локальной сети наружу»: скачанное под `ip saddr <сеть>` не
 * подпадает и в него не попадает никогда. На живом роутере это выглядело как 4,3 МБ при
 * скачанных 223 МБ — человек видел одни подтверждения и не мог понять, куда ушёл
 * трафик. Объём по устройству выхода отвечал на «сколько всего», но не «сколько по
 * этому каналу».
 *
 * ПОЧЕМУ POSTROUTING, а не prerouting. Тут я ошибся и был поправлен опытом
 * (build/natorder.sh), поэтому вывод записан числами. Для доменного канала в наборе
 * лежат fake-IP, и у ответного пакета адрес источника обязан быть переведён обратно в
 * fake-IP, чтобы совпасть с набором. Этот обратный перевод — манипуляция ИСТОЧНИКОМ, а
 * она делается в postrouting: в prerouting в saddr стоит настоящий адрес сервера, каким
 * бы приоритет ни был. Опыт: мегабайт через fake-IP дал в prerouting (и на месте метки,
 * и после dstnat) ровно нуль, а в postrouting — 42 пакета и 1 050 973 байта.
 *
 * Адресному каналу postrouting тоже годится: там адрес источника настоящий с обеих
 * сторон и переводить его нечего — тот же мегабайт, те же 42 пакета. Поэтому одна
 * цепочка покрывает оба вида, и разделять их не нужно.
 *
 * Правило `counter` без вердикта: цепочка ничего не решает, policy accept, и на пути
 * скачивания это один поиск по набору на пакет. */
static void build_postrouting_down(struct nft_table *t, const struct spec *sp,
                                   const struct groups *gr) {
    struct nft_chain *c = ir_base_chain_add(t, "postrouting_down", "filter", "postrouting",
                                            "srcnat", 10);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        /* Скачанное каналом на сам телефон этой цепочкой не считается: получатель у него —
         * сокет телефона, и пакет идёт через input, а не через postrouting. */
        if (group_is_local(g)) continue;
        int carried = 0;
        if (who4_ok(g)) {
            carried = 1;
            struct nft_rule *r = ir_rule(c);
            x_to(r, sp, g);
            /* Зеркало сужения: без него счётчик скачанного считал бы и тот трафик, который
             * правило разметки не берёт, — то есть врал бы ровно на ту величину, ради которой
             * порты и заведены. Тот же довод, что у x_to рядом. */
            x_dest(r, g, 1, g->files_n || g->srs_n || g->domains);
            x_counter_carried(r, g->name, 1);
            ir_comment(r, "steer-down:%s", g->name);
        }
        /* Скачанное по IPv6 — зеркало v6-двойника разметки, под тем же именем. */
        if (group_needs6(sp, g)) {
            struct nft_rule *r = ir_rule(c);
            ir_rule_fam(r, 6);
            x_from6(r, sp, g, 1, !group_has_set6(g));
            x_dest6(r, g, 1);
            if (carried) ir_counter(r, 0, 0);
            else x_counter_carried(r, g->name, 1);
            ir_comment(r, "steer-down:%s", g->name);
        }
    }
}

/* ---- IPv6 правила, ведущего в выход без IPv6: отказ, а не прямой путь ------------------------
 *
 * У выходов vless, xsteer и tgws (и у группы, где такой выход — член) маршрута IPv6 нет
 * (KC_IPV6 не стоит): туннель не несёт IPv6 или это ещё не проверено. Пакет IPv6 правила,
 * ведущего в такой выход, метится как обычно (двойником или правилом «весь трафик», которое ловит
 * оба семейства), но правила маршрутизации IPv6 для метки нет — и без этой цепочки он ушёл бы по
 * таблице main, то есть напрямую, мимо туннеля. Для правила, заведённого ради туннеля, это утечка;
 * поэтому отказ — то же «лучше не работает заметно, чем работает не туда», что у on_fail=drop.
 *
 * ПОЧЕМУ В forward, А НЕ В prerouting_mark. reject в prerouting ядро не принимает (только input,
 * forward, output), а drop там задел бы и трафик к самому роутеру: правило «весь трафик» ловит
 * и DNS клиента к адресу IPv6 роутера, и соседские сообщения ICMPv6 — без них IPv6 в локальной
 * сети кончился бы целиком. forward видит ровно то, что ушло бы наружу. reject, а не drop: клиент
 * с двумя стеками получает отказ сразу и переходит на IPv4 (так выбирает адрес любой клиент),
 * а не ждёт таймаута соединения. Цепочка — только в спеке, где такой трафик вообще бывает. */
/* Запрет источника из префикса мимо донора и ULA-источника в донора — доводы у v6donor_catchall.
 * Устройства, куда адресу из префикса уходить можно: донор и устройства раздачи (соседний кусок
 * сети между двумя устройствами раздачи — тоже своя сеть; назначение в самом префиксе пропускается
 * и так). */
static void v6donor_guard(struct nft_chain *c, const struct spec *sp, const struct output *d) {
    struct sbuf b = { .n = 0 };
    sb_add(&b, "oifname != { \"%s\"", d->device);
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        if (strcmp(sp->lan_dev[i], d->device)) sb_add(&b, ", \"%s\"", sp->lan_dev[i]);
    sb_add(&b, " }");
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 6);
    ir_setref(r, "ip6 saddr", V6DONOR_SET);
    ir_setref(r, "ip6 daddr !=", V6DONOR_SET);
    sb_emit(r, &b);
    ir_counter(r, 0, 0);
    ir_x(r, "reject with icmpx type admin-prohibited");
    ir_comment(r, "steer-v6src:%s", d->name);
    r = ir_rule(c);
    ir_rule_fam(r, 6);
    ir_x(r, "oifname \"%s\"", d->device);
    ir_x(r, "ip6 saddr fc00::/7");
    ir_setref(r, "ip6 saddr !=", V6DONOR_SET);
    ir_counter(r, 0, 0);
    ir_x(r, "reject with icmpx type admin-prohibited");
    ir_comment(r, "steer-v6ula:%s", d->name);
}

static void build_forward_v6(struct nft_table *t, const struct spec *sp, const struct groups *gr) {
    /* Различных меток не больше, чем выходов спеки. */
    uint32_t *marks = malloc((sp->out_n ? sp->out_n : 1) * sizeof(*marks));
    const char **names = malloc((sp->out_n ? sp->out_n : 1) * sizeof(*names));
    size_t n = 0;
    if (!marks || !names) { free(marks); free(names); return; }
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (group_is_local(g)) continue;
        const struct output *o = out_by_name(sp, g->out);
        if (!o || out_v6_ok(o)) continue;
        if (!group_v4_agn(g) && !group_needs6(sp, g)) continue;
        size_t k = 0;
        while (k < n && marks[k] != o->mark) k++;
        if (k == n && n < sp->out_n) {
            marks[n] = o->mark;
            names[n] = o->name;
            n++;
        }
    }
    const struct output *d = spec_v6_donor(sp);
    if (d && !d->device[0]) d = NULL;
    if (!n && !d) { free(marks); free(names); return; }
    struct nft_chain *c = ir_base_chain_add(t, "forward_v6", "filter", "forward", "mangle", 0);
    for (size_t k = 0; k < n; k++) {
        struct nft_rule *r = ir_rule(c);
        ir_family(r, 6);
        ir_x(r, "meta mark and 0x%08x == 0x%08x", STEER_MARK_MASK, marks[k]);
        ir_counter(r, 0, 0);
        ir_x(r, "reject with icmpx type admin-prohibited");
        ir_comment(r, "steer-v6drop:%s", names[k]);
    }
    free(marks);
    free(names);
    if (d) v6donor_guard(c, sp, d);
}

/* ---- ПОМЕЧЕННЫЙ ПАКЕТ НЕ ТУДА — НИКУДА: postrouting_guard ------------------------------------
 *
 * ЧТО СЛУЧИЛОСЬ (проверка на QEMU 04664a5, OpenWrt 25.12.5).
 * `/etc/init.d/network restart`: netifd при старте снимает ВСЕ правила ip rule и ставит свои
 * (local, main, default), и вместе с ними пропадает наше `fwmark <метка>/<маска> lookup <таблица>`.
 * Разметка при этом цела — prerouting_mark метит, dnat fake-IP подменяет адрес, — а правила нет:
 * помеченный пакет идёт по таблице main, masquerade — и он в WAN с адресом WAN, мимо выхода и мимо
 * on_fail=drop. Страж правил (daemon/rulewd.c) возвращал правило через 2-2,5 с, и в 5 прогонах из
 * 6 клиент успевал открыть в этом окне 2-4 соединения мимо туннеля. Правило ip rule живёт вне
 * нашей таблицы и принадлежит всем, кто трогает маршрутизацию, — его снимут ещё не раз (netifd,
 * netd, чужой `ip rule flush`), и никакой скоростью стража окно не закрыть до нуля.
 *
 * ПОЭТОМУ — ПРОВЕРКА ПО ФАКТУ, ГДЕ ПАКЕТ УЖЕ ЗНАЕТ, КУДА ИДЁТ. Пакет с меткой выхода с
 * устройством обязан уйти в одно из устройств этого выхода. Решение маршрутизации уже принято
 * (postrouting), oifname известен — и если это не устройство выхода, значит правило fwmark снято,
 * таблица выхода пуста (устройство пересоздано, TUN помощника пропал) или маршрут переписал кто-то
 * чужой; во всех трёх случаях пакет идёт не туда, куда его вели, и отбрасывается. Это та же
 * страховка fail-closed, что `steer-fakeip-nomap` для подмены: не «успеть вернуть», а «пока не
 * вернули — никуда». TCP клиента повторит SYN через секунду и найдёт правило на месте.
 *
 * КАКИЕ МЕТКИ. Только выходов с устройством и своей таблицей (out_has_device, метка и таблица):
 *   - direct метки нет вовсе; kind=zapret и tgws метку имеют, но таблицы у них нет, и их трафик
 *     законно идёт обычным маршрутом (zapret — в очередь на postrouting, tgws — в мост на самом
 *     роутере, через input, сюда не доходит);
 *   - «пущен напрямую» (набор FAILOPEN_SET: сторож при on_fail=direct/zapret снял правило нарочно)
 *     — законно идёт по main: первым проверяется набор (out_releasable в spec.h — почему набор
 *     теперь есть и на телефоне);
 *   - «разобран на ingress» (STEER_INGRESS_SEEN) метки выхода не несёт и снимается ещё в
 *     prerouting_mark; метка «сам движок» у телефона (STEER_SELF_MARK) — не метка выхода. Ни одно
 *     правило ниже с ними не совпадёт;
 *   - пустое поле — первым правилом, одним сравнением: так идёт почти весь трафик.
 *
 * КАКИЕ УСТРОЙСТВА. Все листья выхода по спеке: у выхода — его устройство (у vless и xsteer — их
 * TUN, у awg — его интерфейс), у группы — устройства всех членов вглубь (out_members). Не «то, что
 * сейчас выбрал сторож»: группа переключается между членами без замены набора правил, и правило,
 * знающее только активного члена, отбросило бы трафик нового. Члены группы известны при apply, их
 * смена — это смена спеки и новый набор. Устройство — ИМЕНЕМ (oifname), как «кто» по устройству
 * (x_ifs): пересозданный wg0 или TUN с тем же именем узнаётся сам, а пока его нет, пакет и так идёт
 * не туда — и отбрасывается, это и есть fail-closed. Балансирующая группа: пакет несёт метку члена
 * (цепочка mark_…) — правило члена; метку самой группы (живых нет) — правило группы.
 *
 * ПОЧЕМУ НЕ «oif НЕ WAN». Устройства WAN движок не знает и знать не должен: их бывает несколько
 * (mwan3, pppoe поверх eth, мобильный модем), на телефоне это любая сеть netd, и выход kind=
 * interface сам может быть «второй WAN». Перечень устройств выхода движок знает точно — из спеки.
 * Карта «метка → набор устройств», которую правил бы сторож элементами, не нужна по той же причине:
 * перечень статичен между заменами набора, а менять его на каждом переключении — лишняя транзакция
 * и лишнее окно.
 *
 * ГДЕ И ПОЧЕМУ ТАМ. postrouting, приоритет filter: видит и пересылаемое (раздача), и порождённое
 * самим устройством (каналы на телефон — output_mark; сокет туннеля `over` несёт метку цели), до
 * masquerade (srcnat) и до очереди zapret (srcnat + 2). Отброшенный здесь пакет ещё не
 * подтверждён conntrack (подтверждение — на последнем приоритете postrouting), так что записи с
 * подменой и masquerade не остаётся, и повтор SYN разбирается заново. Выгруженные потоки
 * (flowtable) postrouting не проходят вовсе — у них маршрут уже запомнен, и снятие правила их не
 * уводит. Оба семейства одним правилом: у выхода без IPv6 правила IPv6 для метки нет, и такой пакет
 * (сокет туннеля поверх выхода без IPv6) раньше уходил в WAN — теперь отбрасывается, как обещает
 * «лучше не работает заметно, чем работает не туда». Пересылаемый IPv6 такого выхода отвергает ещё
 * forward_v6 выше, раньше и с ответом клиенту.
 *
 * Старая раскладка (legacy.c) цепочку не трогает: filter на postrouting в inet есть и на 4.9, и в
 * ней нет ни nat, ни notrack. Счётчик на правиле — чтобы diag и человек видели, что пакеты
 * отбрасывались. */
struct guard_list { const char **v; size_t n, cap; int oom; };

static void guard_devs(const struct spec *sp, const struct output *o, struct guard_list *d,
                       size_t depth) {
    if (depth > sp->out_n) return;      /* группы без кругов вкладываются не глубже, чем их всего */
    if (out_group(o)) {
        size_t mn = out_members_n(sp, o);
        for (size_t k = 0; k < mn; k++) guard_devs(sp, out_member(sp, o, k), d, depth + 1);
        return;
    }
    if (!o->device[0]) return;
    for (size_t k = 0; k < d->n; k++) if (!strcmp(d->v[k], o->device)) return;
    if (d->n == d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 16;
        const char **nv = realloc(d->v, nc * sizeof(*nv));
        if (!nv) { d->oom = 1; return; }
        d->v = nv;
        d->cap = nc;
    }
    d->v[d->n++] = o->device;
}

/* Чьи метки вообще бывают на пакетах: выход правила, члены группы balance вглубь (их метку ставит
 * цепочка mark_…, compile/balance.c) и цель подложки `over` (её метку несёт сокет туннеля, marks.h,
 * out_underlay_mark). Правило guard — только им: у выхода, чью метку никто не ставит, правило ничего
 * не ловило бы, а у спеки v2, переведённой из v1, лишние правила членов пула (у v1 они безымянны и
 * без меток) разошлись бы с набором правил v1 (стенд v2match). Замер группы latency через члена
 * (urltest, SO_MARK члена) сюда не входит по той же причине: у v1 он идёт SO_BINDTODEVICE. */
static void guard_use(const struct spec *sp, const struct output *o, unsigned char *used,
                      size_t depth) {
    if (!o || depth > sp->out_n) return;
    size_t i = spec_out_idx(sp, o);
    if (i == (size_t)-1 || used[i]) return;
    used[i] = 1;
    if (!out_balanced(o)) return;
    size_t mn = out_members_n(sp, o);
    for (size_t k = 0; k < mn; k++) guard_use(sp, out_member(sp, o, k), used, depth + 1);
}

static int has_tcp_redir(const struct spec *sp);

static void build_guard(struct nft_table *t, const struct spec *sp, const struct groups *gr) {
    unsigned char *used = calloc(sp->out_n ? sp->out_n : 1, 1);
    if (!used) return;
    struct guard_list dl = {0};
    for (size_t i = 0; i < gr->n; i++) guard_use(sp, out_by_name(sp, gr->g[i].out), used, 0);
    for (size_t i = 0; i < sp->out_n; i++)
        if (sp->out[i].over[0]) guard_use(sp, out_over(sp, &sp->out[i]), used, 0);
    /* Метку донора IPv6 ставит и правило «всё несовпавшее из префикса» (v6donor_catchall). */
    guard_use(sp, spec_v6_donor(sp), used, 0);
    /* Метку выхода несёт и сокет апстрима DNS «через выход» (dns.upstreams.<имя>.out, src/dnsd/dup.h),
     * если на него ссылается правило или он общий: запрос к серверу обязан уйти в устройство этого
     * выхода, а снятое правило ip rule или лёгший выход не должны выпускать его в WAN. Неиспользуемый
     * апстрим метки не получает и правила не заводит. Используемый — и член группы серверов, и
     * сервер для имён вне правил (`dns.other`): spec_dns_up_used. */
    for (size_t u = 0; u < sp->dns.up_n; u++) {
        if (sp->dns.up[u].out < 0 || (size_t)sp->dns.up[u].out >= sp->out_n) continue;
        if (spec_dns_up_used(sp, u)) guard_use(sp, &sp->out[sp->dns.up[u].out], used, 0);
    }
    struct nft_chain *c = NULL;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!used[i] || !out_has_device(o) || !o->mark || !o->table) continue;
        dl.n = 0;
        guard_devs(sp, o, &dl, 0);
        const char *const *devs = dl.v;
        size_t nd = dl.n;
        if (!nd) continue;
        if (!c) {
            c = ir_base_chain_add(t, "postrouting_guard", "filter", "postrouting", "filter", 0);
            struct nft_rule *r = ir_rule(c);
            ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_MARK_MASK);
            ir_x(r, "return");
            /* Петля — не утечка. Собственный сокет роутера с меткой туннельного выхода (замер члена
             * группы — urltest, туннель поверх туннеля — over) перенаправляется к слушателю модуля
             * (R-152, build_tcp_redir) и уходит в lo; страж отбрасывал его как «не в устройство
             * выхода», и замер членов-туннелей не проходил никогда («срок вышел: соединение не
             * установилось», стенд QEMU 2026-10-13). */
            if (has_tcp_redir(sp)) {
                r = ir_rule(c);
                ir_x(r, "oifname \"lo\"");
                ir_x(r, "return");
            }
            if (has_releasable(sp)) {
                char m[40];
                snprintf(m, sizeof(m), "meta mark and 0x%08x", STEER_MARK_MASK);
                r = ir_rule(c);
                ir_setref(r, m, FAILOPEN_SET);
                ir_x(r, "return");
            }
        }
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "meta mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        struct sbuf b = { .n = 0 };
        if (nd == 1) sb_add(&b, "oifname != \"%s\"", devs[0]);
        else {
            sb_add(&b, "oifname != { ");
            for (size_t k = 0; k < nd; k++) sb_add(&b, "%s\"%s\"", k ? ", " : "", devs[k]);
            sb_add(&b, " }");
        }
        sb_emit(r, &b);
        ir_counter(r, 0, 0);
        ir_x(r, "drop");
        ir_comment(r, "steer-guard:%s", o->name);
    }
    free(dl.v);
    free(used);
}

/* ПЕРЕНАПРАВЛЕНИЕ DNS СТОИТ ВСЕГДА, а не только при доменных каналах (кроме профиля без
 * резолвера — мини-сборки tgws, src/profile/tgws.c).
 *
 * Раньше оно появлялось и исчезало вместе с has_domains(), и это была переменная,
 * от которой зависели три вещи в разных местах: сам резолвер (needs-dnsd в
 * init-скрипте), это правило и ключ force_dns у https-dns-proxy в splify2. Две
 * последние обязаны меняться вместе — два перенаправления порта 53 в одной точке
 * nat prerouting выигрывает то, которое зарегистрировалось раньше, а проигравший
 * молчит: домены перестают маршрутизироваться, сайты при этом открываются.
 *
 * Пока «нужен ли резолвер» выводилось из спеки, синхронизировать их успевал метод
 * apply управляющего слоя. С гибридными списками (домен и подсеть в одном файле)
 * доменность стала бы зависеть от СОДЕРЖИМОГО файла — то есть могла бы перевернуться
 * ночным обновлением списков, которое зовёт `steer apply` напрямую, минуя метод и
 * его синхронизацию. Решение владельца: резолвер держим всегда, и тогда переворачивать
 * нечего — force_dns навсегда 0, а гонки не существует.
 *
 * Цена названа вслух: у роутера без единого доменного канала DNS всё равно идёт через
 * наш резолвер. Взамен уходит целый класс отказов «доменность изменилась, а что-то не
 * пересинхронизировалось».
 *
 * Форм у правила две, и выбирает между ними то же, что выбирает «кто» у каналов.
 * Заданы подсети — забираем IPv4 по адресу, а IPv6 по устройству, потому что
 * стабильного `ip6 saddr` у локального префикса нет. Подсетей нет — забираем по
 * устройству ОБА семейства одним правилом.
 *
 * TCP/53 рядом с UDP/53. Резолвер слушает TCP на том же порту (dnsd/proxy.c, «DNS по TCP»), а без
 * заворота доменный канал слеп ко всему, что спрошено по TCP: к переспросу после усечённого
 * ответа (TC=1) и к клиентам, которые ходят по TCP сразу. Имя, спрошенное так, не получает
 * fakeip и не попадает в набор, и соединение уходит по настоящему адресу мимо выхода.
 * Замерено на живом роутере с steer 1.5.8: Windows-клиент за несколько минут задал 22
 * вопроса по TCP к IPv6-адресу роутера — все мимо резолвера, прямо в dnsmasq.
 *
 * The resolver only sees what is steered to it. IPv6 as well as IPv4: the router
 * advertises itself as an IPv6 resolver by default and clients prefer that server, so an
 * IPv4-only redirect catches almost nothing — measured on a real client, 15 of its DNS
 * packets went over IPv6 against 20 over IPv4.
 *
 * НО НЕ В МИНИ-СБОРКЕ, И ЭТО НЕ ЭКОНОМИЯ, А ИСПРАВЛЕНИЕ ОТКАЗА.
 *
 * Микропакет tgws поднимает ровно мост (см. его init-скрипт: procd получает только
 * экземпляры `tgws`), резолвера в нём не поднимает никто и спека у него адресная —
 * канал по prefixes_files, ни одного имени. А правило ставилось всё равно, потому что
 * решение «резолвер держим всегда» принималось для полного движка, где init поднимает
 * dnsd безусловно.
 *
 * Получалось так: пакет встаёт, подбор домена заканчивается через минуту, apply
 * ставит таблицу — и весь DNS локальной сети заворачивается на порт 5300, где никто
 * не слушает. У сети пропадает разрешение имён целиком, а Telegram продолжает
 * работать, потому что его клиент ходит к дата-центрам по вшитым адресам и DNS не
 * спрашивает. Снаружи это выглядит как «поставил прокси, через минуту помер
 * интернет, помогло только удаление и ребут» — ребут помогает потому, что правила
 * nft не сохраняются между загрузками. Ровно это сообщение и пришло от человека, и
 * воспроизведено в openwrt/rootfs:x86-64-24.10.6.
 *
 * Инвариант поэтому привязан к сборке, а не к спеке и не к настройке: правило
 * существует там и только там, где существует поднимающий резолвер. Настройкой этот
 * выбор делать нельзя — разошедшиеся правило и процесс это ровно тот отказ, который
 * здесь и починен. */
static void build_dns_redirect(struct nft_table *t, const struct spec *sp) {
    /* dstnat - 2: раньше перенаправления TCP в модули (build_tcp_redir) — запрос к 53-му порту
     * забирает резолвер, даже если метка клиента ведёт в выход. */
    struct nft_chain *c = ir_base_chain_add(t, "prerouting_dns", "nat", "prerouting",
                                            "dstnat", -2);
    static const char *const protos[2] = { "udp", "tcp" };
    /* Подсети IPv6 в from_default (с 1.9 это законно): тогда и IPv6 забирается по адресу, а не по
     * устройству — ровно как IPv4. Без них — прежние две формы, до байта. */
    int lan6 = 0;
    for (size_t i = 0; i < sp->lan.from_n; i++) if (strchr(sp->lan.from[i], ':')) lan6 = 1;
    for (int k = 0; k < 2; k++) {
        for (size_t i = 0; i < sp->lan.from_n; i++) {
            int v6 = strchr(sp->lan.from[i], ':') != NULL;
            struct nft_rule *r = ir_rule(c);
            ir_rule_fam(r, v6 ? 6 : 4);
            ir_x(r, "%s saddr %s", v6 ? "ip6" : "ip", sp->lan.from[i]);
            ir_x(r, "%s dport 53", protos[k]);
            ir_counter(r, 0, 0);
            ir_x(r, "redirect to :%d", DNS_PORT);
        }
        if (lan6) continue;
        struct nft_rule *r = ir_rule(c);
        if (sp->lan.from_n) ir_family(r, 6);
        x_ifs(r, sp, 0);
        ir_x(r, "%s dport 53", protos[k]);
        ir_counter(r, 0, 0);
        ir_x(r, "redirect to :%d", DNS_PORT);
    }
}

/* Карта подмены fake→real и её правило dnat. Элементы карты — из файла состояния резолвера,
 * читает печатник (почему она засевается — у emit_fakeip_elements в print.c).
 *
 * Счётчик здесь обязателен, и это не единообразие с соседями. Правило
 * отвечает на единственный вопрос, который встаёт, когда «домены не
 * работают»: доехал ли поддельный адрес до роутера вообще. Без счётчика
 * «клиент не прислал» и «прислал, а мы не развернули» различаются только
 * tcpdump'ом на роутере, а первое — обычное дело у клиента из mesh-VPN
 * (Tailscale, ZeroTier): 198.18.0.0/15 уходит в туннель, только если роутер
 * объявил этот диапазон маршрутом, и по умолчанию он его не объявляет. Из
 * локальной сети вопрос не встаёт вовсе — там роутер и есть шлюз. */
static void fakeip_nomap_drop(struct nft_chain *c, int v6, const char *comment);

/* ПОДМЕНА ПОРТА (`override_port` списка, как route-options override_port у sing-box): поддельный
 * адрес из набора группы — на настоящий адрес с портом из списка. Стоит в цепочке nat ПЕРЕД
 * общим dnat по карте: ядро берёт первое совпавшее dnat, и общее правило подменило бы адрес с
 * прежним портом. Набор у такой группы свой (подмена входит в сужение, groups.c), поэтому соседние
 * имена того же выхода порт не теряют.
 *
 * Зачем это было нужно сразу: проверка FakeIP в браузере у podkop и forkop — запрос к
 * https://fakeip.podkop.fyi/check, и их sing-box подменяет у этого имени порт на 8443; сервер на
 * 8443 отвечает fakeip: true. Без подмены запрос шёл на 443, и проверка показывала, что FakeIP
 * не работает, хотя он работал. */
static void port_override_rules(struct nft_chain *c, const struct groups *gr, const char *comment) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!g->domains || g->realip || !g->l4 || !g->l4->override_port || !group_has_set(g)) continue;
        struct nft_rule *r = ir_rule(c);
        ir_rule_fam(r, 4);
        ir_x(r, "ip daddr @%s", g->name);
        x_l4(r, g->l4, 0);
        ir_counter(r, 0, 0);
        ir_x(r, "dnat ip to ip daddr map @fakeip : %u", g->l4->override_port);
        ir_comment(r, "%s:%s", comment, g->name);
        if (g->dom6 && group_has_set6(g)) {
            char n6[80];
            group_set6_name(g, n6, sizeof(n6));
            r = ir_rule(c);
            ir_rule_fam(r, 6);
            ir_x(r, "ip6 daddr @%s", n6);
            x_l4(r, g->l4, 0);
            ir_counter(r, 0, 0);
            ir_x(r, "dnat ip6 to ip6 daddr map @fakeip6 : %u", g->l4->override_port);
            ir_comment(r, "%s:%s", comment, g->name);
        }
    }
}

/* ПОДДЕЛЬНЫЙ АДРЕС НЕ ВЫХОДИТ В УСТРОЙСТВА КЛИЕНТОВ И В MESH-VPN (I-558).
 *
 * Пул fake-IP — адреса, которых настоящими не бывает, и дороги из него наружу нет нигде, кроме
 * подмены в ядре steer (fakeip_nomap_drop держит первый пакет, но не остальные и не свой трафик
 * роутера). Tailscale же ставит свои маршруты в таблицу 52 по правилу 5270 и при узле выхода или
 * объявленной кем-то подсети 198.18.0.0/15 уводит пакет к пулу в tailscale0; пир возвращает его
 * роутеру, и пакет идёт по кругу. Снято у пользователя: очередь установщиков стека туннеля
 * (CONNQ) забита соединениями к поддельным адресам, лишние SYN получают RST, сайты не открываются.
 *
 * Поэтому пакет к пулу, которому остаётся выйти в устройство клиентов спеки или в сеть mesh-VPN
 * (имена tailscale*, zt* — их демоны создают устройство позже сети, поэтому по имени, как iifname
 * у x_ifs), отбрасывается. Клиентов Tailscale это не задевает: их пакеты ПРИХОДЯТ с tailscale0, а
 * ответ роутера идёт на адрес клиента, не на пул. Подмена fake→real делается в prerouting, до
 * postrouting, поэтому законный пакет несёт здесь уже настоящий адрес. Счётчик — чтобы петлю было
 * видно (diag и человек). */
static void build_fakeip_guard(struct nft_table *t, const struct spec *sp, int v6) {
    struct nft_chain *c = ir_base_chain_add(t, "postrouting_fakeguard", "filter", "postrouting",
                                            "filter", 0);
    for (int fam = 4; fam <= (v6 ? 6 : 4); fam += 2) {
        struct nft_rule *r = ir_rule(c);
        ir_rule_fam(r, fam);
        ir_x(r, "%s", fam == 4 ? "ip daddr 198.18.0.0/15" : "ip6 daddr " FAKEIP6_NET);
        struct sbuf b = { .n = 0 };
        sb_add(&b, "oifname { \"tailscale*\", \"zt*\"");
        for (size_t i = 0; i < sp->lan_dev_n; i++) sb_add(&b, ", \"%s\"", sp->lan_dev[i]);
        sb_add(&b, " }");
        sb_emit(r, &b);
        ir_counter(r, 0, 0);
        ir_x(r, "drop");
        ir_comment(r, "steer-fakeip-guard");
    }
}

static void build_fakeip(struct nft_table *t, const struct groups *gr, int v6) {
    struct nft_set *m = ir_map_add(t, "fakeip", "ipv4_addr", "ipv4_addr");
    ir_gap(m);
    char path[512];
    int have_path = snprintf(path, sizeof(path), "%s/fakeip.state", steer_state_dir()) <
                    (int)sizeof(path);
    if (have_path) ir_set_fakeip_state(m, path);
    /* Карта fake-IP v6 (docs/architecture.md, «4б»): поддельный IPv6 из пула FAKEIP6_NET →
     * настоящий адрес из ответа AAAA. Засевается из того же файла состояния (четвёртое поле —
     * см. fakeip.c). Только когда есть доменная группа fake-IP с половиной IPv6: иначе резолвер
     * поддельных IPv6 не выдаёт, и спека без IPv6 даёт прежний набор правил до байта. */
    if (v6) {
        struct nft_set *m6 = ir_map_add(t, "fakeip6", "ipv6_addr", "ipv6_addr");
        if (m6 && have_path) ir_set_fakeip_state(m6, path);
    }
    struct nft_chain *c = ir_base_chain_add(t, "prerouting_dnat", "nat", "prerouting", "dstnat", 0);
    port_override_rules(c, gr, "steer-port");
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 4);
    ir_x(r, "ip daddr 198.18.0.0/15");
    ir_counter(r, 0, 0);
    ir_dnat(r, "ip daddr", "fakeip");
    if (v6) {
        r = ir_rule(c);
        ir_rule_fam(r, 6);
        ir_x(r, "ip6 daddr " FAKEIP6_NET);
        ir_counter(r, 0, 0);
        ir_dnat(r, "ip6 daddr", "fakeip6");
    }
    fakeip_nomap_drop(c, v6, "steer-fakeip-nomap");
}

/* ПОДДЕЛЬНЫЙ АДРЕС БЕЗ ПОДМЕНЫ — НИКУДА. Правило за dnat в той же цепочке nat: dnat по карте, не
 * нашедший в ней адреса, не срабатывает (поиск в карте не совпал — правило не совпало), и пакет
 * идёт дальше — сюда.
 *
 * ЗАЧЕМ. Пул 198.18.0.0/15 (и fdfe:dcba:9876::/96) настоящим назначением не бывает (RFC 2544,
 * ULA): пакет к нему без подмены никуда не доедет, но по пути уйдёт — по таблице main в WAN (без
 * метки) или в туннель выхода (с меткой), унося наружу адрес, которого там никто не знает. А
 * бывает такой пакет ровно в промежутках, которые и закрывались перепроверкой на QEMU
 * (2026-09-28): подмены для адреса ещё нет — засев карты не собрался (apply.c, seed_begin), адрес
 * выдан резолвером в миг замены таблицы и в новом тексте его нет, запись файла состояния без
 * настоящего адреса, — и резолвер вернёт подмену вместе с меткой, когда к нему дойдёт таблица.
 * До того соединение ждёт (повтор SYN через секунду находит уже и подмену, и метку), а не уходит
 * мимо выхода. Это и есть страховка fail-closed для fake-IP: подмена в ядре появляется только
 * вместе с решением о маршруте (засев карты и наборов — одним текстом, fpseed.c; резолвер ставит
 * подмену и сразу набор), а всё, что подмены не нашло, отсюда не выходит.
 *
 * ПОЧЕМУ НЕ ПО МЕТКЕ. Проверка «адрес назначения был поддельным, а метки канала нет — не пускать в
 * WAN» отрезала бы законные пути: канал fake-IP в выход без метки (direct), клиент вне «кто»
 * канала (правило на телевизор, а поддельный адрес получил и ноутбук — резолвер отвечает по имени,
 * не по клиенту), трафик вне сужения составного канала (канал — udp 50000-65535, а TCP 443 к тому
 * же имени идёт напрямую), приложение телефона вне канала (nft_emit_output_dns). Все они — «подмена
 * есть, метки нет» по замыслу, и напрямую они уходят законно. Отличить от них утечку по метке
 * нельзя; утечку закрывает то, что подмена не появляется раньше решения о маршруте.
 *
 * ПОЧЕМУ ЗДЕСЬ. Цепочка nat видит только первый пакет соединения — правило ничего не стоит
 * остальному трафику, — и стоит там же, где решается подмена, поэтому не зависит от того, где и
 * когда ставится метка (цепочка разметки, хук ingress): метку оно не читает вовсе. В старой
 * раскладке оно уезжает вместе с dnat в таблицы ip и ip6 (legacy.c, шаг 4) — ссылок на наборы
 * inet у него нет. Счётчик — чтобы diag и человек видели, что такие пакеты были. */
static void fakeip_nomap_drop(struct nft_chain *c, int v6, const char *comment) {
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 4);
    ir_x(r, "ip daddr 198.18.0.0/15");
    ir_counter(r, 0, 0);
    ir_x(r, "drop");
    ir_comment(r, "%s", comment);
    if (!v6) return;
    r = ir_rule(c);
    ir_rule_fam(r, 6);
    ir_x(r, "ip6 daddr " FAKEIP6_NET);
    ir_counter(r, 0, 0);
    ir_x(r, "drop");
    ir_comment(r, "%s", comment);
}

/* Make traceroute show the REAL intermediate routers while the destination
 * stays the fake address.
 *
 * ONLY WORKS WHEN THE OUTPUT DOES NOT MASQUERADE — measured: with NAT on, 13
 * errors hit this rule, 0 reached the accept for untracked traffic, and every
 * hop after the first became an asterisk. With NAT the error is addressed to
 * the ROUTER, so only conntrack knows which client it belongs to; untracking
 * removes exactly that knowledge. Tracking is the delivery mechanism and being
 * tracked is what rewrites the source — one does not come without the other.
 *
 * Scope is just time-exceeded (type 11): dest-unreachable must stay tracked or
 * path-MTU discovery breaks, which trades a cosmetic win for broken transfers. */
static void build_traceroute_raw(struct nft_table *t) {
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_raw", "filter", "prerouting",
                                                   "raw", 0));
    ir_x(r, "meta l4proto icmp");
    ir_x(r, "icmp type time-exceeded");
    ir_counter(r, 0, 0);
    ir_notrack(r);
    ir_comment(r, "steer:traceroute-hops");
}

/* ---- DNS приложений телефона — к резолверу движка -------------------------------------
 *
 * Доменный канал на сам телефон видит только те имена, что спросили через наш резолвер. DNS
 * приложений делает DnsResolver (netd) — сокетом, который он приписывает UID приложения, — к
 * серверам текущей сети; правило ниже заворачивает эти запросы к нам, а резолвер переспрашивает
 * тот же сервер (dnsd --upstream-origdst: адрес берётся из conntrack).
 *
 * ВСЕ приложения, а не только приложения каналов. У DnsResolver общий кэш на сеть: заверни мы
 * только своих, настоящий адрес, полученный чужим приложением первым, достался бы из кэша и
 * своему — мимо набора канала, то есть мимо туннеля. Кроме root: это сам резолвер (его запрос
 * наверх иначе завернулся бы по кругу) и прочие демоны.
 *
 * И перевод поддельных адресов для соединений самого телефона — тот же, что prerouting_dnat
 * делает для раздачи: поддельный адрес из кэша DnsResolver получает любое приложение, и у
 * приложения вне канала соединение должно уйти напрямую к настоящему адресу, а не в никуда.
 *
 * И UDP, и TCP: по TCP приходят переспросы после усечённого ответа (TC=1) и запросы приложений,
 * которые ходят по TCP сразу, — без заворота имя, спрошенное так, прошло бы мимо канала, и
 * соединение ушло бы по настоящему адресу. Резолвер слушает TCP на том же порту и переспрашивает
 * тот же сервер тоже по TCP (см. «DNS по TCP» в dnsd/proxy.c).
 *
 * ОБА СЕМЕЙСТВА. Запрос по IPv6 (сервер сети из RDNSS, в том числе link-local) заворачивается
 * так же: резолвер ищет исходное назначение и в AF_INET6 и переспрашивает тот же IPv6-сервер
 * (см. g_origdst в dnsd/proxy.c). В современной раскладке это одно правило в inet, в старой — по
 * цепочке nat output в ip и ip6 (legacy.c разносит его по семействам); на старом ядре без nat в
 * ip6 (NFTC_IP6NAT) IPv6-половины нет — там такого правила не поставить, и apply об этом говорит. */

/* Само правило заворота — одно на всех раскладках и семействах (по правилу на протокол).
 *
 * Всех, кроме собственного запроса резолвера наверх (STEER_SELF_MARK) и собственного трафика
 * туннелей (без via — тот же STEER_SELF_MARK, с via — STEER_TUNNEL_BIT, см. ниже): DnsResolver
 * шлёт запросы приложений от root, поэтому по UID отличить нельзя. Метка «сам движок» у переспроса по TCP та же, что по UDP
 * (tcpu_open в dnsd/proxy.c).
 *
 * `ct mark set mark` — чтобы резолвер узнал метку сети исходного запроса: на 4.9 принятому сокету
 * метку датаграммы не узнать (SO_RCVMARK — с 5.19), а запись conntrack резолвер и так читает
 * целиком (подробно — у g_up_mark в dnsd/proxy.c). У TCP это та же запись conntrack, что ищет резолвер
 * по соединению, и цепочка nat видит её первый пакет (SYN) — метку сокета приложения. Копируется
 * метка ЦЕЛИКОМ, и это не расходится с тем, как метку соединения пишет сам движок: разметка
 * каналов (output_mark, раньше по приоритету) тоже делает `ct mark set mark` целиком
 * (out_needs_ctmark верно для всякого выхода канала телефона: tgws там спека отвергает), то есть к
 * этому правилу пакет приходит с той же меткой, что уже лежит в ct mark, и перезапись ничего не
 * меняет. У запроса, который канал не пометил, ct mark получает fwmark netd — поле движка там
 * нулевое, и читателям ct mark движка (сравнения `ct mark and МАСКА == метка`) это ничего не
 * значит. Смешать метку пакета со старой ct mark (`ct mark and … or mark`) на 4.9 нельзя вовсе:
 * там нет bitwise двух регистров. Цепочка nat видит только первый пакет соединения — ровно тот
 * момент, когда метку и надо запомнить. */
/* Туннели через via — тоже мимо заворота. Сокет наверх такого туннеля несёт метку ЦЕЛИ, а не
 * «сам движок», и у сервера на 53-м порту (UDP или TCP — их и выбирают, чтобы пройти там, где
 * режут остальное) заворот забрал бы соединение туннеля к нашему резолверу: туннель не встал бы
 * вовсе. Пропуск — по биту STEER_TUNNEL_BIT, который такой сокет несёт рядом с меткой цели (почему
 * бит, а не UID помощника, — у определения в spec.h). Условие пишется только в спеке с via: у
 * остальных текст правил остаётся прежним побайтно, а бита там не ставит никто. */
static void local_dns_redirect(struct nft_chain *c, const struct spec *sp) {
    static const char *const protos[2] = { "udp", "tcp" };
    static const char *const names[2] = { "steer-dns-local", "steer-dns-local-tcp" };
    for (int k = 0; k < 2; k++) {
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "meta mark and 0x%08x != 0x%08x", STEER_MARK_MASK, STEER_SELF_MARK);
        if (has_via(sp)) ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_TUNNEL_BIT);
        ir_x(r, "%s dport 53", protos[k]);
        ir_x(r, "ct mark set mark");
        ir_counter(r, 0, 0);
        ir_x(r, "redirect to :%d", DNS_PORT);
        ir_comment(r, "%s", names[k]);
    }
}

/* Заворот DNS приложений и перевод поддельных адресов для соединений самого телефона —
 * цепочка nat на хуке output. */
void nft_emit_output_dns(struct nft_rs *rs, const struct spec *sp, const struct groups *gr) {
    struct nft_chain *c = ir_base_chain_add(inet_table(rs), "output_dns", "nat", "output",
                                            "dstnat", 0);
    if (plat()->local_dns) local_dns_redirect(c, sp);
    if (!has_fakeip(gr)) return;
    port_override_rules(c, gr, "steer-port-local");
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 4);
    ir_x(r, "ip daddr 198.18.0.0/15");
    ir_counter(r, 0, 0);
    ir_dnat(r, "ip daddr", "fakeip");
    ir_comment(r, "steer-fakeip-local");
    /* Поддельные IPv6 — тем же правилом по карте fakeip6 (только когда она есть; на старом ядре
     * без nat в ip6 её нет — dom6_ok). */
    int v6 = has_fakeip6(gr);
    if (v6) {
        r = ir_rule(c);
        ir_rule_fam(r, 6);
        ir_x(r, "ip6 daddr " FAKEIP6_NET);
        ir_counter(r, 0, 0);
        ir_dnat(r, "ip6 daddr", "fakeip6");
        ir_comment(r, "steer-fakeip-local");
    }
    /* Поддельный адрес без подмены — и у приложений телефона никуда (fakeip_nomap_drop). */
    fakeip_nomap_drop(c, v6, "steer-fakeip-local-nomap");
}

/* «Кто» у группы на сам телефон: владелец сокета. "self" — все приложения (UID от
 * STEER_APP_UID_MIN; почему не демоны — у from_is_local); "uid:N[-M]" — перечисленные. У
 * пакета без сокета (RST и ICMP, которые ядро шлёт само) владельца нет, и skuid не совпадает
 * ни с чем — такие пакеты идут обычным путём.
 *
 * `ct direction original` — только соединения, которые приложение ОТКРЫЛО само. Ответы на
 * входящие (беспроводной adb, сервер в приложении) обязаны уйти тем же путём, каким пришёл
 * запрос, а не в туннель.
 *
 * `meta mark and <поле движка> == 0` — пакет, у которого поле метки движка уже заполнено, не
 * наш клиент, а собственный трафик туннеля, и перемечать его нельзя. Найдено на телефоне:
 * WireGuard (и AmneziaWG) в ядре шифрует пакет приложения на месте и отправляет внешний UDP
 * с тем же skb->sk — от сокета отвязывает (skb_orphan) только пока ждёт рукопожатия. Хук
 * OUTPUT видит у внешнего пакета uid приложения, группа «весь трафик» метила его меткой
 * выхода, и он уходил в тот же туннель: петля, сотни мегабайт исходящих за секунды при почти
 * нулевом входящем и ни одного рабочего соединения. Внешний пакет туннель метит сам
 * (WGDEVICE_A_FWMARK) — STEER_SELF_MARK, а при via меткой цели, — то есть поле движка у него
 * всегда не пустое; у пакета приложения до нашего правила в слове метки только биты netd
 * (0-19), поле движка пустое. Так же пропускается и переспрос резолвера (STEER_SELF_MARK). */
static int local_who(struct nft_rule *r, const struct group *g, struct err *e) {
    ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_MARK_MASK);
    if (!strcmp(g->from[0], "self")) {
        ir_x(r, "meta skuid >= %u", STEER_APP_UID_MIN);
        ir_x(r, "ct direction original");
        return 0;
    }
    int one = g->from_n == 1 && !strchr(g->from[0], '-');
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s", one ? "meta skuid " : "meta skuid { ");
    for (size_t i = 0; i < g->from_n; i++) {
        unsigned lo, hi;
        if (from_uid_range(g->from[i], &lo, &hi) != 0)
            return err_set(e, "группа %s: негодный UID", g->name);   /* спека это уже отвергла */
        if (lo == hi) sb_add(&b, "%s%u", i ? ", " : "", lo);
        else sb_add(&b, "%s%u-%u", i ? ", " : "", lo, hi);
    }
    if (!one) sb_add(&b, " }");
    sb_emit(r, &b);
    ir_x(r, "ct direction original");
    return 0;
}

/* ---- каналы на сам телефон: разметка на выходе ------------------------------------
 *
 * Тот же приём, что prerouting_mark для раздачи, но на хуке output: «первое совпадение
 * решает», одно правило на группу, метка — наши биты с маской, метка соединения — как там.
 *
 * Тип цепочки — route, прямо в inet, где и наборы: смена метки в ней сама заставляет ядро
 * искать маршрут заново. В старой раскладке route в inet нет — там её переделывает legacy.c
 * (шаг 2: filter и бит перемаршрутизации).
 *
 * IPv6 (docs/architecture.md, «4б»). У группы — v6-двойник: с набором IPv6 «<имя>6» или, у «весь
 * трафик», интернет IPv6 мимо своей сети. Выход с IPv6 ведёт его своей таблицей IPv6. Выходу без
 * IPv6 двойник отвечает отказом — приложения переходят на IPv4 (так устроен выбор адреса у
 * любого клиента с двумя стеками), и ничего не утекает напрямую. */
int nft_emit_output_mark(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
                         struct err *e) {
    struct nft_table *t = inet_table(rs);
    struct nft_chain *c = ir_base_chain_add(t, "output_mark", "route", "output", "mangle", 1);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(sp, g->out);
        if (!o) return err_set(e, "channel group %s points at a missing output", g->name);
        if (g->all && out_needs_mark(o) && (!out_v6_ok(o) || (g->famreq && !(g->fam & 2)))) {
            /* С тем же сужением по протоколу и портам, что и канал: канал «UDP 50000-65535»
             * не вправе отнимать у приложения весь IPv6. Своя сеть (петля, link-local, ULA,
             * мультикаст) — не наружу и не мимо туннеля, её не трогаем. */
            struct nft_rule *r = ir_rule(c);
            if (local_who(r, g, e) != 0) return -1;
            ir_family(r, 6);
            x_l4(r, g->l4, 0);
            ir_x(r, "oifname != \"lo\"");
            ir_x(r, "ip6 daddr != { fe80::/10, fc00::/7, ff00::/8 }");
            ir_counter(r, 0, 0);
            ir_x(r, "reject");
            ir_comment(r, "steer-v6:%s", g->name);
        }
        struct nft_rule *r;
        if (g->fam & 1) {
            r = ir_rule(c);
            if (local_who(r, g, e) != 0) return -1;
            /* «Весь трафик» — это интернет, а не своя сеть: принтер, NAS и Chromecast в Wi-Fi
             * через туннель не видны. Только IPv4 — IPv6 такой группы отвергнут правилом выше
             * (выход без IPv6) или уведён двойником ниже. */
            if (g->all) {
                ir_family(r, 4);
                ir_x(r, "ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
                        "192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }");
            } else {
                ir_rule_fam(r, 4);          /* поиск в наборе IPv4 — только IPv4 */
            }
            x_dest(r, g, 0, group_has_set(g));
            x_mark(r, o, o->mark);
            x_counter_carried(r, g->name, 0);
            ir_x(r, "return");
            ir_comment(r, "steer:%s", g->name);
        }
        /* v6-двойник (docs/architecture.md, «4б»). «Весь трафик» в выход с IPv6 (или direct) —
         * интернет IPv6 мимо своей сети, как у IPv4 выше; с набором IPv6 — поиск в нём. Выход без
         * IPv6: у «весь трафик» отказ стоит выше, у набора — отказ здесь же, тем же текстом. */
        int all6 = g->all && out_v6_ok(o) && (g->fam & 2);
        if (!all6 && !group_has_set6(g)) continue;
        r = ir_rule(c);
        if (local_who(r, g, e) != 0) return -1;
        if (all6) {
            ir_family(r, 6);
            x_l4(r, g->l4, 0);
            ir_x(r, "oifname != \"lo\"");
            ir_x(r, "ip6 daddr != { ::1, fe80::/10, fc00::/7, ff00::/8 }");
        } else {
            ir_rule_fam(r, 6);
            x_dest6(r, g, 0);
        }
        if (!out_v6_ok(o)) {
            ir_counter(r, 0, 0);
            ir_x(r, "reject");
            ir_comment(r, "steer-v6:%s", g->name);
            continue;
        }
        x_mark(r, o, o->mark);
        ir_counter(r, 0, 0);
        ir_x(r, "return");
        ir_comment(r, "steer:%s", g->name);
    }

    /* Скачанное каналами на сам телефон. Ответ приходит сокету телефона и идёт через input, а
     * не через postrouting — postrouting_down его не видит (см. там). Узнаётся по метке
     * соединения: правило разметки выше пишет в ct mark метку выхода, и у ответных пакетов
     * того же соединения она та же. Канал со списком дополнительно сужается адресом
     * источника ответа — это адрес сервера из его набора, — чтобы два канала на один выход
     * не считали трафик друг друга; у канала «весь трафик» набора нет, и два таких канала на
     * одном выходе покажут одно и то же скачанное. Цепочка ничего не решает: policy accept,
     * правила без вердикта. */
    c = ir_base_chain_add(t, "input_down", "filter", "input", "filter", 10);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(sp, g->out);
        if (!o || !out_needs_mark(o) || !out_needs_ctmark(o)) continue;
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "ct direction reply");
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        x_dest(r, g, 1, group_has_set(g));
        x_counter_carried(r, g->name, 1);
        ir_comment(r, "steer-down:%s", g->name);
        /* Скачанное по IPv6 из парного набора — тем же именем (у «весь трафик» набора нет, и
         * правило выше и так считает оба семейства). */
        if (!group_has_set6(g) || !out_v6_ok(o)) continue;
        r = ir_rule(c);
        ir_rule_fam(r, 6);
        ir_x(r, "ct direction reply");
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        x_dest6(r, g, 1);
        ir_counter(r, 0, 0);
        ir_comment(r, "steer-down:%s", g->name);
    }
    return 0;
}

void v6_notes(const struct spec *sp, const struct groups *gr, v6_note_fn fn, void *ctx) {
    char what[160], why[200];
    /* Выход без IPv6, в который ведёт хоть одно включённое правило. */
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (out_v6_ok(o)) continue;
        int used = 0;
        for (size_t k = 0; k < gr->n && !used; k++) used = !strcmp(gr->g[k].out, o->name);
        if (!used) continue;
        /* IPv6 снят спекой, а не видом (spec_v6_resolve): сказать, чем именно. */
        const struct output *d = spec_v6_donor(sp);
        if (o->v6_denied && out_ipv6_mode(o) == OUT_V6_OFF)
            snprintf(what, sizeof(what), "выход %.40s: IPv6 выключен (ipv6: off)", o->name);
        else if (o->v6_denied && d)
            snprintf(what, sizeof(what), "выход %.40s: IPv6 идёт только через %.40s (ipv6: routed)",
                     o->name, d->name);
        else
            snprintf(what, sizeof(what), "выход %.40s: IPv6 не поддерживается", o->name);
        snprintf(why, sizeof(why), "IPv6 правил этого выхода отбрасывается, а не идёт напрямую; "
                 "сайты откроются по IPv4");
        fn(ctx, "ipv6_output", "note", what, why);
    }
    /* ipv6: routed и nat там, где раздачей IPv6 владеет не netifd (телефон): ключ разобран, но
     * действует как его отсутствие (out_ipv6_mode) — сказать об этом, а не молчать. */
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if ((o->ipv6 != OUT_V6_ROUTED && o->ipv6 != OUT_V6_NAT) || out_ipv6_mode(o) == o->ipv6)
            continue;
        snprintf(what, sizeof(what), "выход %.40s: ipv6: %s здесь не действует", o->name,
                 o->ipv6 == OUT_V6_ROUTED ? "routed" : "nat");
        snprintf(why, sizeof(why), "раздачей IPv6 на телефоне владеет Android — IPv6 выхода идёт "
                 "как без ключа ipv6");
        fn(ctx, "ipv6_host", "note", what, why);
    }
    /* Свой клиент правила из одних адресов IPv4: его IPv6 правилом не узнаётся. */
    for (size_t k = 0; k < gr->n; k++) {
        const struct group *g = &gr->g[k];
        if (group_is_local(g) || who6_ok(sp, g)) continue;
        snprintf(what, sizeof(what), "канал %.48s: IPv6 клиентов не маршрутизируется",
                 g->members_n ? g->members[0] : g->name);
        snprintf(why, sizeof(why), "клиенты заданы адресами IPv4 — добавьте их адрес IPv6 или MAC");
        fn(ctx, "ipv6_clients", "warn", what, why);
    }
}

/* Набор v6donor — префикс хоста у донора IPv6 (доводы — у v6donor_catchall). Объявлен всегда, когда
 * донор есть, даже без известного префикса: правила ссылаются на него, а элементы кладёт сторож,
 * как только префикс узнаётся (v6donor_sync). Пустой набор ничего не забирает и ничего не
 * запрещает — IPv6 правил в донора идёт по меткам, как без префикса. */
static void build_v6donor_set(struct nft_table *t, const struct spec *sp) {
    const struct output *d = spec_v6_donor(sp);
    if (!d || !d->mark) return;
    struct nft_set *s = ir_set_add(t, V6DONOR_SET, "ipv6_addr");
    if (!s) return;
    s->flags = NFT_SET_INTERVAL;
    if (d->v6pfx.len) {
        char p[64];
        v6pfx_str(&d->v6pfx, p, sizeof(p));
        ir_set_value(s, ir_strdup(t->rs, p));
    }
}

/* NAT66 выхода `ipv6: nat` (spec.h, enum out_ipv6). ЯВНОЕ ИСКЛЮЧЕНИЕ из «steer не трогает
 * файрвол» (шапка src/daemon/fwcheck.c; docs/contract-v1.md, §7): masquerade IPv6 на устройство
 * выхода ставит сам движок, в своей таблице и только по этому ключу — решение владельца (шаг 8
 * выпуска 1.10). Довод: у пира один адрес IPv6, клиенты LAN на ULA, и без подмены IPv6 в туннель
 * не пойдёт вовсе, а masq6 зоны fw4 — это «подменять всё IPv6 зоны», то есть настройка чужого
 * пакета, которую человек заводил бы ради одного туннеля. Своё правило — ровно на устройство
 * выхода, снимается вместе с нашей таблицей, и fw4 оно не трогает. Если masq6 у зоны тоже
 * включён — вреда нет: подмену соединения выбирает первая цепочка nat, вторая его уже не меняет.
 *
 * По устройству, а не по метке: в устройство выхода IPv6 клиентов уводит только наша метка, а
 * свой трафик роутер шлёт с адреса этого же устройства — masquerade ему ничего не меняет. Цепочка
 * nat в inet; старая раскладка (legacy.c) переносит правило в ip6 по его семейству. */
static void build_nat6(struct nft_table *t, const struct spec *sp) {
    struct nft_chain *c = NULL;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (out_ipv6_mode(o) != OUT_V6_NAT || !o->device[0] || !out_route6(o)) continue;
        if (!c) c = ir_base_chain_add(t, "postrouting_nat6", "nat", "postrouting", "srcnat", 0);
        struct nft_rule *r = ir_rule(c);
        ir_rule_fam(r, 6);
        ir_x(r, "oifname \"%s\"", o->device);
        ir_family(r, 6);
        ir_counter(r, 0, 0);
        ir_x(r, "masquerade");
        ir_comment(r, "steer-nat6:%s", o->name);
    }
}

/* Подмена IPv4 на устройствах выходов — в СВОЕЙ таблице, как IPv6 у `ipv6: nat` (build_nat6).
 *
 * РЕШЕНИЕ ВЛАДЕЛЬЦА (2026-10-12): все устройства выходов steer лежат в одной зоне fw4 `steer_zone`
 * БЕЗ masq (её ведёт splify2), а подмену адреса ставит ядро — тем видам, которым она нужна: туннель
 * с устройством, который адреса клиентов не завершает сам (interface, awg, члены kind: warp — у WARP
 * туннель принимает пакеты только с адреса регистрации). Сами себе подмена — vless, hysteria2, прокси
 * (завершают соединения у себя) и xsteer (подмена ему вредна: хаб узнаёт пира по адресу) —
 * KC_SELF_NAT, им правила нет. Прежде masquerade ставила зона steer_iface, и смысл был тот же; две зоны
 * splify2 (с подменой и без) сведены в одну.
 *
 * Зоны fw4 ядро по-прежнему не трогает, и ЗОНА устройству нужна: политика forward зоны в fw4
 * действует только внутри зоны, а транзит в устройство вне всех зон уходит в handle_reject (стенд
 * QEMU 2026-10-12). Подмена дважды (своя зона человека с masq и это правило) не страшна: адрес
 * соединению назначает первая сработавшая цепочка nat.
 *
 * Устройства — выходов спеки и безымянных членов пула v1 (`devices`), каждое один раз. */
static void nat4_dev(struct nft_table *t, struct nft_chain **c, const struct output *o,
                     const char **seen, size_t *seen_n) {
    if (!out_nat4_by_steer(o)) return;
    for (size_t k = 0; k < *seen_n; k++)
        if (!strcmp(seen[k], o->device)) return;
    seen[(*seen_n)++] = o->device;
    if (!*c) *c = ir_base_chain_add(t, "postrouting_nat4", "nat", "postrouting", "srcnat", 0);
    struct nft_rule *r = ir_rule(*c);
    ir_rule_fam(r, 4);
    ir_x(r, "oifname \"%s\"", o->device);
    ir_family(r, 4);
    ir_counter(r, 0, 0);
    ir_x(r, "masquerade");
    ir_comment(r, "steer-nat4:%s", o->name[0] ? o->name : o->device);
}

static void build_nat4(struct nft_table *t, const struct spec *sp) {
    struct nft_chain *c = NULL;
    size_t cap = sp->out_n + sp->anon_n + 1, seen_n = 0;
    const char **seen = calloc(cap, sizeof(*seen));
    if (!seen) { t->rs->oom = 1; return; }
    for (size_t i = 0; i < sp->out_n; i++) nat4_dev(t, &c, &sp->out[i], seen, &seen_n);
    for (size_t i = 0; i < sp->anon_n; i++) nat4_dev(t, &c, &sp->anon[i], seen, &seen_n);
    free(seen);
}

/* ---- TCP клиентов — к слушателю модуля (R-152) ----------------------------------------------
 *
 * У выхода с KC_TCP_REDIR (vless, hysteria2, прокси) TCP клиентов завершает ядро Linux: первый
 * пакет соединения перенаправляется по метке выхода на порт слушателя модуля (out_tcp_port), а
 * модуль гонит поток узлу. Прежде такой TCP шёл пакетами в TUN, и модуль разбирал его своим
 * стеком: два прохода пакета через границу ядра и свой TCP поверх. Замер на одном стенде —
 * перенаправление 21-27 Гбит/с при 0,22-0,27 с CPU на ГиБ против 10-12 Гбит/с и 0,59-0,85 у
 * обхода через TUN (решение владельца 2026-10-11, R-152 в хабе). UDP по-прежнему идёт в TUN.
 *
 * КАРТА, А НЕ ПРАВИЛО НА ВЫХОД. Куда вести метку, решает не спека, а сторож: метка группы ведёт
 * в порт того члена, на котором группа сейчас (таблица выхода привязана к его устройству), а у
 * выхода без живого модуля элемента нет вовсе — тогда правило не совпадает, и соединение идёт
 * по маршруту выхода, то есть туда, куда решает on_fail (запрет, напрямую). Элементы ведёт демон
 * вместе с привязкой таблицы (tcp_redir_sync в failover.c); набор правил приходит с пустой картой
 * и заполняется после загрузки.
 *
 * ПРИОРИТЕТ dstnat - 1 — РАНЬШЕ подмены fake-IP. Трансляция назначения у соединения одна: первая
 * цепочка nat, назначившая её, решает за остальные (nf_nat_inet_fn), поэтому перенаправление
 * после dnat по карте fakeip не сработало бы никогда. Поддельный адрес модуль разворачивает сам —
 * по тому же файлу состояния резолвера, что засевает карту (fakeip.state), — и подделку без
 * подмены сбрасывает, как сбросило бы правило steer-fakeip-nomap. Заворот DNS стоит ещё раньше,
 * на dstnat - 2 (build_dns_redirect): запрос к 53-му порту забирает резолвер, а не выход.
 *
 * Хук output — для соединений самого роутера с меткой выхода: сокет туннеля поверх другого
 * выхода (over) несёт метку цели и попадает к её слушателю так же, как трафик клиента. На
 * платформе с заворотом DNS приложений (output_dns на dstnat) запрос к 53-му порту в выход не
 * уводится — его забирает тот заворот, как и прежде.
 *
 * Старая раскладка (Linux 4.9, legacy.c) складывает nat в таблицы ip и ip6, а карту демон ведёт
 * в inet: там перенаправления нет, и TCP идёт через TUN, как до R-152. */
static int has_tcp_redir(const struct spec *sp) {
    if (g_nftc & NFTC_LEGACY) return 0;
    for (size_t i = 0; i < sp->out_n; i++)
        if (sp->out[i].mark && out_has_cap(&sp->out[i], KC_TCP_REDIR)) return 1;
    return 0;
}

static void build_tcp_redir(struct nft_table *t, const struct spec *sp) {
    if (!has_tcp_redir(sp)) return;
    ir_gap(ir_map_add(t, TCP_REDIR_MAP, "mark", "inet_service"));
    static const char *const hooks[2] = { "prerouting", "output" };
    static const char *const names[2] = { "prerouting_tcp_redir", "output_tcp_redir" };
    char m[40];
    snprintf(m, sizeof(m), "meta mark and 0x%08x", STEER_MARK_MASK);
    for (int k = 0; k < 2; k++) {
        struct nft_chain *c = ir_base_chain_add(t, names[k], "nat", hooks[k], "dstnat", -1);
        if (!k) ir_gap(c);
        struct nft_rule *r = ir_rule(c);
        /* Только IPv4: стек модуля и ключ его потока — IPv4 (tun.h, flow_key). */
        ir_x(r, "ip protocol tcp");
        /* Метка — в карте: счётчик правила считает перенаправленные соединения, а не весь TCP. */
        ir_setref(r, m, TCP_REDIR_MAP);
        /* Адрес самого роутера (его WAN, адрес в другой своей сети) остаётся ему: в маршруте
         * выхода такой пакет и прежде доставлялся локально — таблица local стоит раньше правил
         * меток. */
        ir_x(r, "fib daddr type != local");
        if (k == 1 && plat()->local_dns) ir_x(r, "tcp dport != 53");
        ir_counter(r, 0, 0);
        ir_x(r, "redirect to :meta mark and 0x%08x map @%s", STEER_MARK_MASK, TCP_REDIR_MAP);
        ir_comment(r, "steer-tcp-redir");
    }
}

/* Дерево набора правил современной раскладки. Порядок объектов — порядок печати, и он
 * прежний до байта (снимок tests/golden/ruleset). */
int nft_build(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
              struct err *e) {
    /* Подмена порта делается по карте fake-IP (port_override_rules): у канала realip поддельных
     * адресов нет, и подмена молча не случилась бы. */
    for (size_t i = 0; i < gr->n; i++)
        if (gr->g[i].domains && gr->g[i].realip && gr->g[i].l4 && gr->g[i].l4->override_port)
            return err_set(e, "группа %s: override_port у списка — только с dns.mode fakeip, а у "
                           "канала realip", gr->g[i].name);
    struct nft_table *t = ir_table_add(rs, NFT_FAM_INET, nft_table());
    build_group_sets(t, gr);
    build_v6donor_set(t, sp);
    if (build_mark(t, sp, gr, e) != 0) return -1;
    /* Группы balance: цепочки, карты и цепочки меток (compile/balance.c). Без таких групп — ничего,
     * и текст прежний до байта. */
    if (nft_emit_balance(t, sp, gr) != 0) return err_set(e, "out of memory building the ruleset", NULL);
    if (plat()->local_channels && has_local(gr) && nft_emit_output_mark(rs, sp, gr, e) != 0)
        return -1;
    build_failopen(t, sp);
    build_mark_restore(t);
    build_postrouting_down(t, sp, gr);
    build_forward_v6(t, sp, gr);
    build_guard(t, sp, gr);
    build_nat6(t, sp);
    build_nat4(t, sp);
    /* Построители видов (kind_ops.emit): по видам, в порядке реестра, поэтому все цепочки
     * zapret в тексте стоят раньше цепочки моста, в каком бы порядке выходы ни шли в спеке
     * (kind.c: kind_emit_all). */
    kind_emit_all(rs, sp);
    if (!prof()->no_resolver) build_dns_redirect(t, sp);
    build_tcp_redir(t, sp);
    /* Остальное по-прежнему по факту доменных каналов: карта fakeip и цепочка dstnat
     * стоят per-packet, и держать их пустыми на роутере без доменов незачем. Это гейт
     * по СТОИМОСТИ, а не по смыслу, и переворачиваться он может свободно — ни один
     * чужой ключ от него не зависит. */
    if (has_domains(gr)) {
        if (has_fakeip(gr)) {
            build_fakeip(t, gr, has_fakeip6(gr));
            build_fakeip_guard(t, sp, has_fakeip6(gr));
        }
        if (plat()->local_channels && has_local_domains(gr)) nft_emit_output_dns(rs, sp, gr);
        if (sp->traceroute_hops) build_traceroute_raw(t);
    }
    if (rs->oom) return err_set(e, "out of memory building the ruleset", NULL);
    return 0;
}

/* Текст набора правил этого запуска: дерево, раскладка ядра (g_nftc) и печать. На отказе в f
 * не пишется ничего — дерево строится целиком до печати. */
int generate(const struct spec *sp, const struct groups *gr, FILE *f, struct err *e) {
    struct nft_rs rs;
    nft_rs_init(&rs);
    int rc = nft_build(&rs, sp, gr, e);
    if (rc == 0) rc = legacy_rewrite(&rs, sp, g_nftc, e);
    if (rc == 0) nft_print(&rs, f);
    nft_rs_free(&rs);
    return rc;
}
