#ifndef STEER_IR_H
#define STEER_IR_H

/* ---- промежуточное дерево набора правил nftables -------------------------------------
 *
 * ЗАЧЕМ. Всё, что хочет знать о наборе правил что-то кроме текста, — стенды, модули видов и
 * платформ — иначе должно было бы либо вклиниваться в печать ветками, либо разбирать текст
 * обратно. Дерево разводит эти две заботы: генератор (generate.c) и модули видов строят ЧТО
 * стоит в ядре, а печатник (print.c) один на всех и знает только синтаксис nft.
 *
 * СТРУКТУРА. Набор правил (struct nft_rs) — список таблиц в порядке печати (у движка одна —
 * inet); таблица (семейство, имя) — упорядоченный список объектов: наборов/карт (struct nft_set) и цепочек
 * (struct nft_chain) вперемешку, потому что в тексте они и идут вперемешку (набор failopen
 * стоит между цепочками, карта fakeip — рядом со своей цепочкой dnat), а снимок генератора
 * обязан совпадать до байта. Цепочка — базовая (type/hook/priority/policy) или обычная
 * (type == NULL), с правилами в порядке проверки.
 *
 * УРОВЕНЬ ДЕТАЛИЗАЦИИ ПРАВИЛА — последовательность выражений-токенов, каждое со своим
 * видом (enum nft_xk). Почти все выражения — NFT_X_RAW, то есть готовый текст nft
 * («meta l4proto tcp», «ip saddr { 192.168.1.0/24 }»): глубокая типизация каждого
 * сравнения ничего бы сейчас не дала, а стоила бы второго словаря nft внутри движка. Свой
 * вид получают только те выражения, которые кто-то ищет или переделывает, не разбирая текст:
 *
 *   NFT_X_SETREF   поиск в наборе — стенды спрашивают «правило смотрит в @X»;
 *   NFT_X_COUNTER  место счётчика в правиле (оно не всегда в конце: «counter redirect…»),
 *                  сами значения — в полях pkts/bytes правила: перенос счётчиков через apply
 *                  кладёт их туда;
 *   NFT_X_MARKSET  запись метки пакета — стенды спрашивают «правило ставит метку»;
 *   NFT_X_FAMILY   «meta nfproto ipvN»;
 *   NFT_X_DNAT     dnat по карте — «dnat ip to» или «dnat ip6 to» по семейству правила;
 *   NFT_X_NOTRACK  «notrack».
 *
 * comment — отдельным полем: по нему стенды и перенос счётчиков находят правило
 * («steer:<группа>», «steer-down:<группа>»), и печатается он всегда последним. fam — для
 * какого семейства правило (0 — для обоих, 4, 6): по нему dnat выбирает «ip» или «ip6».
 *
 * ПАМЯТЬ. Всё дерево — в арене (цепочка кусков), освобождение одно: nft_rs_free. Элементы
 * наборов в дерево НЕ загружаются: списки бывают на сотни тысяч префиксов, а роутер — на
 * 64 МБ. Набор держит ИСТОЧНИКИ элементов (struct nft_elsrc): путь к адресному списку,
 * путь к файлу состояния fakeip или встроенное значение, — и печатник читает файлы потоком,
 * строка за строкой, как прежде emit_elements. Пиковая память печати та же, что у прямой.
 *
 * ОТКАЗ ПАМЯТИ. Строители не проверяют каждый вызов: при нехватке арены rs->oom ставится в
 * 1, дальнейшие вызовы на NULL-объектах ничего не делают, и тот, кто строил, один раз
 * спрашивает rs->oom и возвращает отказ (правило 5, docs/architecture.md, раздел 2). */

#include <stddef.h>
#include <stdio.h>

enum nft_family { NFT_FAM_INET };

enum nft_xk {
    NFT_X_RAW,       /* text — готовый текст nft */
    NFT_X_FAMILY,    /* «meta nfproto ipv<fam>» */
    NFT_X_SETREF,    /* «<text> @<arg>» — поиск в наборе arg */
    NFT_X_MARKSET,   /* text — запись метки пакета («meta mark set …») */
    NFT_X_COUNTER,   /* «counter» или «counter packets N bytes M» (значения — в правиле) */
    NFT_X_DNAT,      /* «dnat ip[6] to <text> map @<arg>» */
    NFT_X_NOTRACK,   /* «notrack» */
};

struct nft_expr {
    enum nft_xk k;
    int fam;                    /* NFT_X_FAMILY: 4 или 6 */
    const char *text;
    const char *arg;
    struct nft_expr *next;
};

struct nft_chain;
struct nft_table;
struct nft_rs;

struct nft_rule {
    struct nft_expr *x, **x_tail;
    int fam;                    /* 0 — оба семейства, 4, 6 */
    unsigned long pkts, bytes;  /* значения NFT_X_COUNTER; нули печатаются коротким «counter» */
    const char *comment;        /* NULL — без комментария */
    struct nft_chain *chain;
    struct nft_rule *next;
};

enum nft_objk { NFT_OBJ_SET, NFT_OBJ_CHAIN };

/* Общая голова набора и цепочки — первый член обеих структур. */
struct nft_obj {
    enum nft_objk k;
    const char *name;
    int gap;                    /* пустая строка перед объектом — ради совпадения текста */
    struct nft_table *table;
    struct nft_obj *next;
};

#define NFT_SET_INTERVAL 1u
#define NFT_SET_TIMEOUT  2u
/* Набор, который пополняет сам пакетный путь (`update @набор { … }`): флаг dynamic, а с ним — свой
 * срок элементов (timeout) и потолок (size) набора; ядро без size ставит такому набору 65535. */
#define NFT_SET_DYNAMIC  4u

enum nft_elk {
    NFT_EL_VALUE,               /* s — один элемент как есть */
    NFT_EL_ADDR_FILE,           /* s — путь к списку: адресные строки, прочее пропускается */
    NFT_EL_FAKEIP_STATE,        /* s — путь к fakeip.state резолвера: пары «поддельный : настоящий» */
    NFT_EL_SRS,                 /* s — путь к набору .srs, p — struct ir_srs: его подсети v4 */
    NFT_EL_MIXED,               /* p — struct ir_mixed: элементы составного набора (адрес . протокол
                                 * . порты) из списков и наборов со своим сужением у каждого */
};

/* Источники элементов из наборов sing-box (src/model/srs.h). Дерево держит только указатели:
 * набор читает печатник, потоком, как адресный список. Сами типы дереву не нужны — объявлены
 * по имени, чтобы ir.c по-прежнему ничего не знал о модели. */
struct srs_set;
struct l4match;
struct ir_srs {
    const struct srs_set *set;
    const unsigned char *sel;   /* бит на клаузу набора; NULL — все */
    int excl;                   /* 1 — подсети ИСКЛЮЧЕНИЙ клауз, а не назначения */
};
struct ir_mixed_src {
    const char *path;           /* адресный список или набор .srs */
    const struct l4match *l4;   /* список: сужение, с которым идут все его адреса */
    const struct srs_set *set;  /* набор: NULL — это адресный список */
    const unsigned char *sel;
    const struct l4match *eff;  /* набор: сужение каждой клаузы, по номеру */
};
struct ir_mixed {
    size_t n;
    const struct ir_mixed_src *v;
};

struct nft_elsrc {
    enum nft_elk k;
    const char *s;
    const void *p;
    struct nft_elsrc *next;
};

struct nft_set {
    struct nft_obj o;
    const char *key;            /* «ipv4_addr», «mark» */
    const char *data;           /* не NULL — это карта (map), тип значения */
    unsigned flags;             /* NFT_SET_* */
    int auto_merge;
    unsigned long size;         /* 0 — строки size нет */
    const char *timeout;        /* срок элементов набора («10m»); NULL — строки timeout нет */
    struct nft_elsrc *els, **els_tail;
};

struct nft_chain {
    struct nft_obj o;
    const char *type;           /* NULL — обычная цепочка, без хука */
    const char *hook;
    const char *prio_name;      /* «mangle», «dstnat»…; NULL — приоритет числом prio_off */
    int prio_off;
    /* Устройства хука ingress — готовым текстом («device "br-lan"», «devices = { "a", "b" }»);
     * NULL — хук без устройств (все, кроме ingress). */
    const char *devices;
    const char *policy;
    struct nft_rule *rules, **rules_tail;
};

struct nft_table {
    enum nft_family fam;
    const char *name;
    struct nft_obj *objs, **objs_tail;
    struct nft_rs *rs;
    struct nft_table *next;
};

struct ir_chunk;
struct nft_rs {
    struct nft_table *tables, **tables_tail;
    struct ir_chunk *arena;
    int oom;
};

/* ---- жизнь дерева ---- */
void nft_rs_init(struct nft_rs *rs);
void nft_rs_free(struct nft_rs *rs);
const char *ir_strdup(struct nft_rs *rs, const char *s);
const char *ir_printf(struct nft_rs *rs, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ---- построение ---- */
struct nft_table *ir_table_add(struct nft_rs *rs, enum nft_family fam, const char *name);
struct nft_set *ir_set_add(struct nft_table *t, const char *name, const char *key);
struct nft_set *ir_map_add(struct nft_table *t, const char *name, const char *key, const char *data);
void ir_set_value(struct nft_set *s, const char *v);
void ir_set_file(struct nft_set *s, const char *path);
void ir_set_fakeip_state(struct nft_set *s, const char *path);
/* Подсети набора .srs (NFT_EL_SRS) и элементы составного набора (NFT_EL_MIXED). Указатели
 * живут дольше дерева (разбор набора и группы каналов) — дерево их не копирует. */
void ir_set_srs(struct nft_set *s, const char *path, const struct ir_srs *src);
void ir_set_mixed(struct nft_set *s, const struct ir_mixed *m);
/* Память арены дерева — для того, что живёт вместе с ним (источники элементов). */
void *ir_mem(struct nft_rs *rs, size_t n);
struct nft_chain *ir_chain_add(struct nft_table *t, const char *name);
struct nft_chain *ir_base_chain_add(struct nft_table *t, const char *name, const char *type,
                                    const char *hook, const char *prio_name, int prio_off);
/* Устройства хука базовой цепочки (ingress) — текст копируется в арену. */
void ir_chain_devices(struct nft_chain *c, const char *text);
/* Пустая строка перед набором или цепочкой (obj — struct nft_set* или struct nft_chain*). */
void ir_gap(void *obj);

struct nft_rule *ir_rule(struct nft_chain *c);
void ir_x(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_family(struct nft_rule *r, int fam);
void ir_setref(struct nft_rule *r, const char *match, const char *set);
void ir_markset(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_counter(struct nft_rule *r, unsigned long pkts, unsigned long bytes);
void ir_dnat(struct nft_rule *r, const char *key, const char *map);
void ir_notrack(struct nft_rule *r);
void ir_comment(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_rule_fam(struct nft_rule *r, int fam);

/* ---- поиск ---- */
/* name == NULL — первая таблица этого семейства. */
struct nft_table *ir_table_find(const struct nft_rs *rs, enum nft_family fam, const char *name);
struct nft_chain *ir_chain_find(const struct nft_table *t, const char *name);
/* Есть ли в правиле выражение, чей текст содержит needle. */
int ir_rule_has(const struct nft_rule *r, const char *needle);
/* Приоритет словами, как пишет nft («mangle + 1»). */
void ir_prio_str(const struct nft_chain *c, char *dst, size_t n);

static inline struct nft_set *ir_obj_set(struct nft_obj *o) {
    return o && o->k == NFT_OBJ_SET ? (struct nft_set *)o : NULL;
}
static inline struct nft_chain *ir_obj_chain(struct nft_obj *o) {
    return o && o->k == NFT_OBJ_CHAIN ? (struct nft_chain *)o : NULL;
}

/* ---- печать (print.c) ---- */
/* Текст nft всего дерева в f. Элементы наборов читаются из файлов потоком. */
void nft_print(const struct nft_rs *rs, FILE *f);
/* 1 (по умолчанию) — элементы из файла состояния резолвера (NFT_EL_FAKEIP_STATE и засев наборов
 * каналов ниже) печатаются; 0 — пропускаются, будто файла нет. 0 ставит отпечаток плана
 * apply-сверки (apply-plan в src/daemon/apply.c) — зачем, у print_elements в print.c, — и apply,
 * когда засев наборов не собрался: карта подмены без решения о маршруте — это утечка. */
extern int g_print_state_seed;

/* ЗАСЕВ НАБОРОВ КАНАЛОВ fake-IP — поддельные адреса, которые резолвер положил бы в набор канала
 * после таблицы, печатаются в той же транзакции, что и карта подмены (доводы — у print_elements в
 * print.c и в шапке src/dnsd/fpseed.c). Какой адрес в какой набор, решает код резолвера
 * (fpseed_els); печатник спрашивает его по имени набора и семейству, только у набора со сроками
 * (доменного) и только при g_print_state_seed. NULL — засева нет: так у стендов, которые зовут
 * печать сами, — и у них текст прежний.
 *
 * a — адрес в порядке сети (IPv4 — первые 4 байта); l4 — у составного набора сужения совпавших
 * частей канала (их объединение печатник раскладывает на ящики, как dch_boxes у резолвера), у
 * обычного NULL. Массив отсортирован по адресу, повторов нет, живёт до конца печати. */
struct ir_seed {
    unsigned char a[16];
    const struct l4match *const *l4;
    size_t l4_n;
};
extern size_t (*g_print_seed)(const char *set, int fam, const struct ir_seed **out);

/* Засев набора «пущен напрямую» (failopen): метки выходов, которые на загрузке уже без маршрута
 * по умолчанию (apply.c, failopen_seed_begin). Элементы идут текстом той же транзакции, что и
 * таблица, — окна, в котором трафик такого выхода отбрасывается postrouting_guard, нет. NULL/0 —
 * засева нет (--dry-run, стенды): текст прежний. */
extern const unsigned *g_failopen_seed;
extern size_t g_failopen_seed_n;

#endif
