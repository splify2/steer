#ifndef STEER_GROUPS_H
#define STEER_GROUPS_H

/* Группы каналов: слияние правил, которые ведут в один и тот же выход и совпадают на всём,
 * что важно ядру (см. комментарий у struct group ниже, в src/compile/groups.c). Отдельный
 * заголовок — потому что поля struct group читают и generate.c (компиляция в текст правил),
 * и apply.c/status.c/diag.c/explain.c (объём, число списков, объяснение совпадения). */

#include <stddef.h>
#include "spec.h"
#include "srsplan.h"

/* ---- coalescing: one interface, at most two sets ---------------------------
 *
 * Channels are how a configuration is WRITTEN — a list, who it applies to, where it
 * goes. They are not how it has to be EXECUTED. Emitting one set and one rule per
 * channel means a box with a dozen enabled lists walks a dozen rules for every
 * packet and holds a dozen sets, when all of them lead to the same tunnel.
 *
 * So channels that agree on everything that matters to the kernel — the output, the
 * kind of list, the clients, and (for domains) the resolver mode — are merged into
 * one set and one rule. With one tunnel and every list enabled that is 2 sets and 2
 * rules instead of a dozen each: addresses and domains, because those two reach a
 * set by different routes and cannot share one.
 *
 * Expressiveness is not lost, only deduplicated: a channel that differs in `from` or
 * mode still gets its own group, so "only the TV, only this list" remains sayable.
 */
struct group {
    char name[64];              /* <output>_ip | <output>_dom, and the set name */
    const char *out;
    int domains;                /* addresses otherwise */
    /* Группа «весь трафик»: набора у неё нет, правило безусловное. Признак входит в ключ
     * слияния — см. build_groups, почему такую группу нельзя объединять со списочной. */
    int all;
    int realip;
    const char (*from)[64];
    size_t from_n;
    /* Сужение по протоколу и портам — УКАЗАТЕЛЬ на сужение первого канала группы, ровно как
     * `from` указывает на его список клиентов. Каналы группы по этому признаку совпадают
     * (он входит в ключ слияния), а спека разобранной живёт до конца процесса, так что
     * копировать 68 байт в каждую группу незачем. NULL быть не может: у канала без сужения
     * структура просто пустая, и l4match_empty отвечает про неё то же самое. */
    const struct l4match *l4;
    /* ТОЛЬКО адресные файлы: их элементы уходят в набор при компиляции. Доменные читает
     * резолвер сам, из спеки, поэтому здесь их держать незачем — а держали, и из-за этого
     * группа не могла быть смешанной. */
    /* Адресные списки группы. Вектор, а не массив на MAX_RULES*MAX_FILES: с пределом в
     * шестьдесят четыре файла на правило такой массив стоил бы 32 КБ на группу и два
     * мегабайта на все — при том, что обычная группа держит один-два файла. */
    const char **files;
    size_t files_n, files_cap;
    /* Сколько доменных списков в группе. Нужно только чтобы сказать это человеку в status:
     * набор у них общий, а вот «сколько списков» он спрашивает про правило. */
    size_t dfiles_n;
    /* Все адресные списки группы оказались непрочитанными — набор и правило остаются, но
     * набор пуст.
     *
     * Почему не выбросить группу совсем: правило без `ip daddr @набор` это «весь трафик
     * этих клиентов в туннель», то есть пропавший список молча превратил бы узкий канал в
     * полный туннель. Почему не оставить как было (die на первом непрочитанном файле):
     * тогда не появляется НИ ОДНОГО правила, и напрямую идёт весь роутер, включая каналы,
     * чьи списки на месте (I-136). Пустой набор — единственный вариант, при котором
     * пропавший список уносит ровно свои адреса и ничего больше. */
    int emptied;
    /* Сколько АДРЕСНЫХ строк во всех файлах группы — считает check_address_lists. Ноль при
     * непустом files_n бывает законно (файл из одних имён, см. там же), и тогда набор
     * объявляется без строки elements: `elements = {  }` nft не принимает и отвергает весь
     * набор правил — то есть один такой список снимал бы маршрутизацию целиком. */
    size_t addrs;
    /* Сколько строк IPv6 в тех же файлах — они идут в парный набор «<имя>6» (ipv6_addr), а
     * правило получает v6-двойника (docs/architecture.md, «4б»). Считает тот же
     * check_address_lists; ноль — набора IPv6 у группы нет вовсе. */
    size_t addrs6;
    /* Доменная группа с половиной IPv6: резолвер кладёт в «<имя>6» поддельные адреса IPv6 или
     * настоящие из ответов AAAA (dom6_ok, spec.h). Ставит build_groups по раскладке g_nftc — её
     * вызывающий задаёт до build_groups. Набору тогда нужен флаг timeout (адреса real-ip — со
     * сроком ответа). */
    int dom6;
    /* Политика семейства IP (R-154; struct spec_rule). famreq/famblk — как записаны у правил группы
     * (входят в ключ слияния и в хвост имени набора: правила с разной политикой — разные наборы).
     * fam — какие половины остаются по итогу (rule_fam_eff: биты 1 — IPv4, 2 — IPv6; считает
     * build_groups по выходу и клиентам группы), blocked — IPv6 нужен, а его нет, и запаса нет:
     * правило не ведёт ничего. У группы без политики fam — 3, и всё, как до неё. */
    int famreq, famblk;
    int fam, blocked;
    /* Which channels fed it — reported so a counter still has names behind it. */
    const char **members;       /* куча, растёт по числу каналов группы (member_add) */
    size_t members_n, members_cap;

    /* ---- наборы sing-box (srs_files, раскладка — src/model/srsplan.c) ---------------------
     *
     * srs — клаузы наборов, попавшие в группу (указатели в раскладку, которую держит struct
     * groups): их подсети v4 компилятор кладёт в набор сам, потоком, имена берёт резолвер.
     * srs_addrs — сколько подсетей v4 из них (как addrs у списков). */
    const struct srs_psel **srs;
    size_t srs_n, srs_cap;
    size_t srs_addrs;
    size_t srs_addrs6;          /* подсетей v6 из наборов (не у доп. группы — см. srsplan.c) */
    /* Составной набор (ipv4_addr . inet_proto . inet_service): у списка канала смешанное
     * сужение, и у каждого элемента оно своё — правило одно, без x_l4. files_l4 — сужение, с
     * которым идут адреса каждого файла files (параллельно files). */
    int composite;
    const struct l4match **files_l4;
    /* Доп. группа канала — клаузы набора с условиями, которых у канала нет: номер в имени
     * (0 — обычная группа), второе «ip saddr» (source_ip_cidr), исключения-подсети — набор
     * «<имя>_x». */
    unsigned extra;
    const struct srs_pfx4 *xsrc;
    size_t xsrc_n;
    int xcidr;
};

/* Есть ли в группе подсети v4 из наборов sing-box (без подсчёта — по разметке клауз). */
static inline int group_srs_v4(const struct group *g) {
    for (size_t i = 0; i < g->srs_n; i++) if (g->srs[i]->has_v4) return 1;
    return 0;
}

/* Есть ли у группы набор адресов (правило с поиском в нём), а не «весь трафик». */
static inline int group_has_set(const struct group *g) {
    return g->files_n || g->srs_n || g->domains || g->emptied;
}

/* Есть ли у группы парный набор IPv6 «<имя>6» — по СОДЕРЖИМОМУ списков: строки IPv6 в файлах
 * и подсети IPv6 из наборов .srs. Считает check_address_lists, поэтому ответ верен только после
 * него (apply, план демона); status, diag и explain его не зовут, и для них ответ — «нет».
 * Набора без элементов не заводится: пустой поиск на каждом пакете IPv6 ничего бы не дал. У
 * доменной группы с dom6 набор есть всегда — его наполняет резолвер (fake-IP v6, real-ip v6). */
static inline int group_has_set6(const struct group *g) {
    return !g->extra && (g->fam & 2) && (g->addrs6 || g->srs_addrs6 || g->dom6);
}

/* Имя парного набора IPv6: имя группы и «6». Имена групп рассчитаны на 31 символ старых ядер
 * (group_set_name), и одна цифра в них укладывается: самое длинное имя с ней — 28 символов.
 * С именем набора IPv4 двойник совпасть не должен («_c1»+«6» и «_c16»): group_set_name сама
 * разводит такое имя хвостом «x» у старшего набора (twin_clash, src/model/parse.c). */
static inline void group_set6_name(const struct group *g, char *dst, size_t n) {
    snprintf(dst, n, "%.62s6", g->name);
}


/* Группы одного разбора спеки — результат build_groups. До 1.7 они лежали в глобале
 * g_grp/g_grp_n, и любой, кто читал группы (генератор, status, diag, explain), читал то, что
 * оставил последний build_groups в процессе, — долг пересборки ядра. Теперь
 * это значение: точка входа держит свой экземпляр (static) и передаёт его параметром, как
 * struct spec. Массивы групп и раскладок растут по надобности (было g[64] и plans[64], то есть
 * около 45 КБ bss на любом роутере и «too many channels» на 65-й группе) и, как векторы files,
 * отдаются groups_free; build_groups сам отдаёт прежние, поэтому экземпляр до первого вызова
 * обязан быть нулевым (static или `= {0}`). Указатель на элемент g живёт до следующего
 * group_new: кто добавляет группу, держит индекс. */
struct groups {
    struct group *g;
    size_t n, cap;
    /* Раскладки каналов с наборами sing-box: группы указывают в них (l4, srs), поэтому они
     * живут столько же, сколько группы, и отдаются groups_free. Группы указывают внутрь
     * pl->p / pl->p[].sel — отдельных куч, не в сам массив plans, поэтому его рост им не вредит. */
    struct srs_plan *plans;
    size_t plans_n, plans_cap;
};

/* build_groups/check_address_lists возвращают код ошибки, а не завершают процесс — правило 5,
 * docs/architecture.md, раздел 2. 0 — успех; -1 — отказ, текст в e->msg. Читают спеку sp — правило 6. */
int build_groups(const struct spec *sp, struct groups *gr, struct err *e);
void groups_free(struct groups *gr);
/* Отдать и сами массивы групп и раскладок (groups_free оставляет их на повторный разбор). */
void groups_release(struct groups *gr);
int has_domains(const struct groups *gr);
/* Есть ли в спеке выход tgws — вопрос к виду (kind.h: tgws_present),
 * не к группам; здесь не живут (общий код кроме src/kinds вид не сравнивает). */
int has_fakeip(const struct groups *gr);
/* Есть ли группа fake-IP с половиной IPv6 — тогда нужны карта fakeip6 и её dnat. */
int has_fakeip6(const struct groups *gr);
int is_mac(const char *s);
int group_is_local(const struct group *g);
int check_address_lists(struct groups *gr, struct err *e);

int has_local(const struct groups *gr);
int has_local_domains(const struct groups *gr);
int has_via(const struct spec *sp);

#endif
