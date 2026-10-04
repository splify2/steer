/* ВИД ВЫХОДА — МОДУЛЬ (docs/architecture.md, раздел 2, правило 1).
 *
 * Всё, что знает о виде, лежит в src/kinds/<вид>.c и отдаётся остальному движку одной таблицей
 * struct kind_ops. Общий код спрашивает вид — его свойства (caps) и его функции, — а не
 * сравнивает, какой он. Сравнение `kind == …` в общем коде означало бы, что новый вид требует
 * найти все такие места, а забытое место — это выход, который настроен и молча не работает
 * (ровно этот класс поломки описан у предикатов out_* в spec.h). Стенд tests/buildmatch.sh
 * ловит такие сравнения вне src/kinds.
 *
 * Любая функция таблицы может быть NULL — «виду здесь сказать нечего», — и общий код это
 * проверяет явно, а не зовёт пустышки.
 *
 * РЕЕСТР собирается из того, что вошло в сборку (kind.c): запись вида, файла которого в профиле
 * нет (build/sources.mk), отвечает одной строкой отказа — `absent`. Так «kind vless требует пакет
 * steer-extended» говорится из одного места, а не из #ifdef в разборе. */
#ifndef STEER_KIND_H
#define STEER_KIND_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct output;
struct spec;
struct err;
struct out_keys;
struct out_obfs;
struct vless_cfg;
struct hy2_cfg;
struct xsteer_cfg;
struct tgws_cfg;
struct group_cfg;
/* Дерево ruleset (src/lib/ir.h). Объявлено ради поля emit ниже: заголовок дерева подключают
 * сами виды, которые его строят (zapret.c, tgws.c). */
struct nft_rs;

/* Свойства вида — то, о чём спрашивает общий код. Были предикатами со списком видов внутри
 * (out_has_device и соседи в spec.h); предикаты остались тонкими обёртками над этими битами,
 * а смысл каждого бита записан у своего предиката. */
enum kind_cap {
    KC_DEVICE       = 1 << 0,   /* своё устройство и таблица маршрутизации (out_has_device) */
    KC_MARK         = 1 << 1,   /* своя метка пакета (out_needs_mark) */
    KC_CTMARK       = 1 << 2,   /* метка соединения (out_needs_ctmark) */
    KC_ENGINE_OWNED = 1 << 3,   /* устройство заводит наш процесс, а не netifd (out_engine_managed) */
    KC_SELF_NAT     = 1 << 4,   /* masquerade не нужен (out_self_natting) */
    KC_OVER         = 1 << 5,   /* свой сокет наверх — подложка `over` (v1: `via`) имеет смысл (out_over_capable) */
    KC_SKIP_ZAPRET  = 1 << 6,   /* общий обход DPI трафик не трогает (out_skips_zapret) */
    /* Здоровье устройства — рукопожатием TCP через него, а не ICMP: туннель завершает TCP у
     * себя, и пинг наружу через его устройство не проходит никогда (failover.c). */
    KC_TCP_PROBE    = 1 << 7,
    /* UDP идёт к узлу своим потоком на каждую пару адрес-порт, то есть у каждого DNS-запроса
     * своё рукопожатие (заметка «resolver» в diag.c). */
    KC_FLOW_UDP     = 1 << 8,
    /* Выход несёт IPv6: трафик v6 можно отдавать в него так же, как v4 (docs/architecture.md,
     * «4б»). У вида с устройством это правило `ip -6 rule` и таблица IPv6 (out_route6 в spec.h),
     * у zapret — та же очередь nfqws. Поставлен тем видам, у которых v6 есть по устройству
     * выхода: интерфейс и awg — устройства ядра с обоими семействами, zapret трафик никуда не
     * уводит, а только разбирает. VLESS — после проверки v6 в стеке src/tunnel, xsteer и tgws —
     * по их протоколам; direct маршрута не меняет вовсе. IPv6 правил, ведущих в выход без бита,
     * отвергается (цепочка forward_v6, generate.c), а не уходит напрямую. */
    KC_IPV6         = 1 << 9,
};

/* Ключи спеки, которые принадлежат виду. Разбирает их parse.c — для всех видов, в том числе не
 * вошедших в сборку: иначе базовая сборка перестала бы отвечать прежними отказами на ключ
 * расширенного вида у чужого выхода («stream есть только у kind=xsteer»). Бит говорит, чей ключ:
 * у выхода другого вида такой ключ — отказ. `conf` и `sub_file` у чужого вида в v1 и прежде молча
 * ничего не делали, и отказ на них сломал бы работавшие спеки: их биты (KK_CONF, KK_SUB) читает
 * только разбор v2. */
enum kind_key {
    KK_OBFS   = 1 << 0,
    KK_STREAM = 1 << 1,
    KK_OPTS   = 1 << 2,
    KK_DOMAIN = 1 << 3,
    KK_NODES  = 1 << 4,
    /* `devices` спеки v1 — пул кандидатов. Принимает его только interface: пул устройств — это
     * группа (kind: group), и собирает её перевод v1 (model/v1.c) из безымянных интерфейсов. */
    KK_DEVICES = 1 << 5,
    /* `conf` (xsteer, awg) и подписка (vless: `sub_file` в v1, `subscription` в v2). Спека v1 по
     * этим битам НЕ отказывает — у чужого вида ключи и прежде молча ничего не делали (см. выше);
     * по ним отказывает разбор v2, где неизвестный или чужой ключ — всегда отказ. */
    KK_CONF   = 1 << 6,
    KK_SUB    = 1 << 7,
};

/* Помощник выхода — процесс, который поднимает супервизор (daemon/helpers.c: `steer supervise` и
 * демон с --supervise). cmd — подкоманда движка («vless», «xsteer», «obfs», «tgws») или имя
 * помощника-программы («nfqws»), sig — подпись того, что помощник читает из спеки при
 * старте: супервизор кладёт в неё начальное значение FNV, вид подмешивает свои поля
 * (kind_sig_mix), общий код — цель `via`. */
struct kind_helper {
    char cmd[16];               /* «hysteria2» — девять знаков */
    unsigned long long sig;
    /* Помощник — не подкоманда движка, а своя программа рядом с ним (zapret: обработчик
     * steer-nfqws, init.d/steer). prog — имя файла в каталоге движка, arg — её аргументы
     * (пустой — конец). prog пуст — `<движок> <cmd> <выход> --spec …`, как у остальных. */
    char prog[16];
    char arg[2][256];
    /* Переменная окружения помощнику («ИМЯ=значение»; пусто — нет) — то, что init.d ставит
     * procd_set_param env (STEER_TUN_STATS у vless). В подпись не входит: это отладка. */
    char env[32];
    /* Помощнику нужны метки реестра (номер очереди zapret выводится из метки): супервизор,
     * который иначе реестр не трогает (supervise.c), назначает их перед подсчётом состава. */
    int marks;
};

/* Имя, которое починка вида разрешила бы getaddrinfo (Endpoint у awg). Разрешение имени
 * блокирует — DNS может отвечать секунды или не отвечать вовсе, — а сторож в демоне работает на
 * цикле событий и ждать синхронно не вправе. Поэтому вид НАЗЫВАЕТ имена заранее (revive_names),
 * сторож разрешает их рабочим потоком (src/daemon/gaiw.c) и отдаёт ответы в revive. Верхняя
 * половина — вопрос вида, нижняя — ответ сторожа. */
struct kind_name {
    char host[256];
    uint16_t port;
    int v4only;                     /* только IPv4 (туннель через via — см. awg_via_check) */
    int v6only;                     /* только IPv6 (замер urltest по IPv6, src/daemon/urltest.c) */
    int rc;                         /* 0 — разрешилось; иначе код getaddrinfo */
    struct sockaddr_storage addr;
    socklen_t addr_len;
};
#define KIND_NAMES_MAX 8

/* Куда вид отдаёт свои проверки diag: id, приговор (ok/note/warn/fail), что смотрели, что делать. */
typedef void kind_diag_fn(const char *id, const char *verdict, const char *what, const char *why);

struct kind_ops {
    const char *name;           /* как пишется в спеке */
    unsigned caps;              /* enum kind_cap */
    unsigned keys;              /* enum kind_key */
    /* Не NULL — вида в этой сборке нет, и разбор отвечает ровно этой строкой (после
     * «outputs.<имя>: »). У такой записи остальные поля пусты. */
    const char *absent;

    /* Свойства, которые зависят не только от вида, но и от настройки выхода (interface с obfs
     * умеет via). Складываются с caps. */
    unsigned (*caps_of)(const struct output *);

    /* ---- тексты, которые общий код печатает о виде ---- */
    /* Как назвать вид в отказе «via есть только у…», если выход этого вида via не умеет;
     * NULL — просто name. */
    const char *novia;
    /* Почему masquerade не нужен (у вида с KC_SELF_NAT) — причины у видов РАЗНЫЕ, см.
     * out_self_natting в spec.h. */
    const char *selfnat_why;
    /* Не NULL — выход работает только для клиентов раздачи, а для трафика самого устройства его
     * нет; строка — почему. */
    const char *lan_only;

    /* ---- спека ---- */
    /* Свои ключи и умолчания: k — что спека написала в ключах видов, выход уже с общими полями.
     * 0 — годится; -1 — отказ, текст в e.
     *
     * ОДИН РАЗБОР НА ОБА ФОРМАТА. struct out_keys — не JSON и не YAML, а значения ключей: их
     * заполняет читатель формата (model/v1.c из JSON, model/v2.c из дерева YAML), а вид
     * проверяет и толкует одинаково для обоих. Где форматы называют ключ по-разному
     * (`opts_file`/`strategy`, `sub_file`/`subscription`), вид берёт имя для отказа у out_key. */
    int (*parse)(struct output *o, const struct out_keys *k, struct err *e);
    /* Обратное parse: что выход написал бы в ключах видов (`steer spec convert`). Умолчания,
     * которые parse выводит сам (путь conf из имени выхода, имя устройства), не пишутся — тогда
     * k->device_derived = 1 про устройство. NULL — своих ключей у вида нет. */
    void (*keys_of)(const struct output *o, struct out_keys *k);
    /* Проверка после разбора и общих проверок выхода (владельцы ключей) — то, что зависит от
     * общих полей (on_fail). sp — спека с выходами, разобранными до этого. */
    int (*check)(const struct spec *sp, const struct output *o, struct err *e);

    /* ---- правила ---- */
    /* Свои правила nft: дописывает в дерево (lib/ir.h) то, что нужно ОДНОМУ выходу этого
     * вида. Цепочки, общие для всех выходов вида (например, zapret_queue — своя очередь на
     * каждый выход, но цепочка одна), заводит первый вызов на пустом дереве — тот же приём,
     * что у build_group_sets и соседей. NULL — виду в дереве сказать нечего (direct, group и
     * виды с устройством: их правила пишет общий код по caps, а не per-kind emit).
     *
     * Порядок вызовов — kind_emit_all (kind.c): по ВИДАМ, в порядке реестра (kind_at), а
     * внутри вида — по выходам в порядке спеки. Так текст ruleset не зависит от того, в каком
     * порядке человек перечислил выходы разных видов: все правила одного вида ложатся в дерево
     * подряд, одним блоком, как было при отдельных построителях nft_emit_zapret/nft_emit_tgws
     * (docs/architecture.md, «Вид выхода»). Тот же приём и с тем же доводом уже применяется в
     * kind_ops.diag (daemon/diag.c). */
    void (*emit)(struct nft_rs *rs, const struct spec *sp, const struct output *o);

    /* ---- сторож (failover.c) ---- */
    /* Мера здоровья устройства, владелец которого — выход этого вида. NULL — общая проба
     * (ICMP или TCP по KC_TCP_PROBE). 1 — живо, 0 — нет. */
    int (*health)(const struct spec *sp, const struct output *o, const char *dev);
    /* Починка молчащего устройства. NULL — общий путь (ждать свой процесс, ifdown/ifup).
     * names — ответы на revive_names (n штук); NULL — вид разрешает имена сам, синхронно (так
     * зовут стенды). Сама починка обязана не ждать: всё, что в ней было ожиданием, — это
     * разрешение имён, и оно вынесено в revive_names. */
    int (*revive)(const struct spec *sp, const struct output *o, const char *dev,
                  const struct kind_name *names, size_t n);
    /* Имена, которые revive разрешит (не больше max, в dst). NULL или 0 — имён нет. */
    size_t (*revive_names)(const struct spec *sp, const struct output *o, struct kind_name *dst,
                           size_t max);
    /* Замер задержки. NULL — общий замер соединением TCP; мс или -1. */
    int (*latency)(const struct spec *sp, const struct output *o, const char *dev);

    /* ---- наблюдаемость ---- */
    /* Свои поля в объекте выхода `steer status`: фрагмент JSON, начинающийся с запятой. */
    void (*status)(FILE *out, const struct spec *sp, const struct output *o);
    /* Свои проверки `steer diag`. */
    void (*diag)(kind_diag_fn *put, const struct spec *sp, const struct output *o);

    /* ---- помощник ---- */
    /* 0 — выходу нужен помощник, h заполнен; -1 — не нужен. */
    int (*helper)(const struct spec *sp, const struct output *o, struct kind_helper *h);
};

/* ---- реестр (kind.c) ---- */
/* Запись вида по имени из спеки, в том числе вида вне сборки (у неё absent); NULL — такого вида
 * нет вовсе. */
const struct kind_ops *kind_by_name(const char *name);
/* То же для спеки v2: реестр и группа (kind: group — её в реестре нет, см. ниже). */
const struct kind_ops *kind_by_name_v2(const char *name);
/* Все виды по порядку реестра: direct, interface, vless, xsteer, zapret, tgws, awg. */
size_t kind_count(void);
const struct kind_ops *kind_at(size_t i);
/* Шаг FNV-1a подписи помощника (с границей поля: «ab»+«c» не равно «a»+«bc»). */
void kind_sig_mix(unsigned long long *h, const void *p, size_t n);
#define KIND_SIG_INIT 14695981039346656037ULL

/* Дописать в дерево rs правила всех видов, у которых есть emit: по видам в порядке реестра,
 * внутри вида — по выходам в порядке спеки (см. kind_ops.emit выше). Одна точка входа вместо
 * ручного прохода по видам в generate.c — новый вид с emit не требует правки компилятора. */
void kind_emit_all(struct nft_rs *rs, const struct spec *sp);

/* Записи видов. Определены в src/kinds/<вид>.c; реестр ссылается на них слабо (kind.c), поэтому
 * вид, файла которого нет в сборке, у реестра есть — записью отказа.
 *
 * group в реестр НЕ входит. Реестр — это виды из профиля: по нему ищет вид разбор спеки v1, по
 * его порядку ложатся правила видов (kind_emit_all) и проверки diag. Группа — часть модели v2:
 * спека v1 её не знает (`"kind": "group"` в v1 обязан остаться неизвестным видом, иначе спека,
 * принятая с ним, значила бы то, чего v1 не обещал), своих правил и проверок у неё нет, а
 * собирает её перевод v1 (model/v1.c) напрямую. Разбор v2 находит её через kind_by_name_v2. */
extern const struct kind_ops kind_direct, kind_interface, kind_vless, kind_xsteer, kind_zapret,
                             kind_tgws, kind_awg, kind_group, kind_hysteria2,
                             kind_trojan, kind_shadowsocks, kind_socks, kind_http, kind_vmess;

/* Вид обнулённого выхода (kind == NULL; так их собирают стенды) — direct, как у нулевого
 * значения прежнего перечня видов. Читает его kind_of в spec.h. */
#define KIND_ZERO (&kind_direct)

/* ПРЕЖНИЕ ИМЕНА ВИДОВ — только для стендов (tests/specmatch.c, tests/failovermatch.c), которым
 * нужно собрать выход конкретного вида, не читая спеку: `g_spec.out[0].kind = OUT_XSTEER`.
 * Общий код вида не сравнивает — он спрашивает kind_of(o)->caps или конкретную функцию вида
 * (zapret_present, out_tgws и соседи ниже). Вне src/kinds и стендов эти имена ловит
 * tests/buildmatch.sh. */
#define OUT_DIRECT    (&kind_direct)
#define OUT_INTERFACE (&kind_interface)
#define OUT_VLESS     (&kind_vless)
#define OUT_XSTEER    (&kind_xsteer)
#define OUT_ZAPRET    (&kind_zapret)
#define OUT_TGWS      (&kind_tgws)
#define OUT_AWG       (&kind_awg)
#define OUT_GROUP     (&kind_group)

/* ---- вопросы к отдельным видам ------------------------------------------------------------
 *
 * Помощнику вида (клиенту vless, xsteer, мосту tgws) нужна настройка своего выхода, и спросить
 * её он должен у вида: «это мой выход?» — NULL, если выход другого вида. */

/* Вид, которым выход виден снаружи: в status, в `steer outputs --kind`, в подписях сверки и в
 * отказах разбора. У группы из перевода v1 — вид прежнего выхода (interface), см.
 * group_cfg.shown в spec.h; у остальных — свой. */
const struct kind_ops *out_kind_shown(const struct output *o);
const char *out_kind_name(const struct output *o);

/* ---- группа (src/kinds/group.c) ---- */
/* Настройка группы или NULL, если выход не группа. */
const struct group_cfg *out_group(const struct output *o);
/* КАНДИДАТЫ ВЫХОДА — из чего сторож выбирает устройство: у группы — её члены по порядку, у
 * выхода с устройством — он сам, единственным кандидатом, у остальных — никого. Одна функция на
 * всех, кому нужен «пул» (сторож, status, apply, сверка), — чтобы группа и одиночный выход не
 * расходились в ответе на один и тот же вопрос. Сколько их — out_members_n (число не ограничено
 * константой: пул любой длины), i-й — out_member (i < out_members_n). Раньше членов копировали
 * в массив вызывающего на предельное число; теперь читают по одному, ничего не выделяя. */
size_t out_members_n(const struct spec *sp, const struct output *o);
const struct output *out_member(const struct spec *sp, const struct output *o, size_t i);
/* Сделать выход o группой pick: order из безымянных выходов-членов, по одному на устройство devs
 * (того же вида, каким был o), — так перевод v1 превращает пул `devices` в группу (model/v1.c), и
 * так же собирают пул стенды. Имя, активное устройство, over, on_fail, метка и таблица остаются
 * у группы: снаружи это прежний выход. Члены ложатся в безымянную часть sp->out (struct spec).
 * 0 — готово; -1 — отказ в e. */
int group_of_devices(struct spec *sp, struct output *o, const char (*devs)[32], size_t n,
                     struct err *e);
/* Замкнуть группу, когда её члены известны: свойства группы — пересечение свойств членов
 * (group_cfg.caps). Вложенная группа замыкается раньше внешней. 0 — годится; -1 — отказ (членов
 * нет, член не годится, balance членом группы с одной таблицей), текст в e. */
int group_seal(struct spec *sp, struct output *g, struct err *e);
/* Настройка группы до разбора: умолчания (def, idle_timeout_s, состояние cur/sel/lat_ms — «нет»). */
void group_cfg_init(struct group_cfg *g);
/* Члены — именованные выходы спеки (v2), а не безымянные члены пула v1: у каждого своя метка,
 * своя таблица и свой приговор сторожа в том же проходе (src/daemon/failover.c). */
int group_named(const struct group_cfg *g);
/* Имя pick (enum group_pick в spec.h), как пишется в спеке. */
const char *group_pick_name(int p);
/* Имя `by` группы balance (enum group_by в spec.h), как пишется в спеке. */
const char *group_by_name(int b);
/* Завести группе массивы на n членов в арене спеки: members, weight, alive, lat_ms, lat4_ms,
 * lat6_ms (замеры «не мерили», weight 0, никто не жив). n == 0 не выделяет ничего. 0 — есть;
 * -1 — нехватка памяти. Число членов константой не ограничено. */
int group_members_alloc(struct spec *sp, struct group_cfg *g, size_t n);
/* balance: карта ядра — GROUP_BAL_SLOTS слотов `numgen random mod N` (by: site — `jhash … mod N`);
 * owner[s] — номер члена слота s (0..members_n-1) по весам живых членов alive (байт на члена,
 * 1 — жив; NULL — все живы), 0xff — живых нет. Слоты живых при уходе члена остаются на месте.
 * Почему слоты, а не `mod <живых>`, — у определения.
 *
 * ЭТО НАСТОЯЩИЙ ПРЕДЕЛ balance, и он свойство карты, а не выбор кода: у члена без слота доли нет,
 * поэтому членов у группы pick: balance не больше слотов (group_seal отказывает с цифрой), а
 * номер члена в owner — байт (0xff занят под «живых нет»). Остальные pick пределов по числу
 * членов не имеют. */
#define GROUP_BAL_SLOTS 120
void group_balance_slots(const struct group_cfg *g, const unsigned char *alive,
                         unsigned char owner[GROUP_BAL_SLOTS]);
/* Имена объектов balance в таблице движка (compile/balance.c строит, сторож переписывает карту):
 * цепочка группы `bal_<таблица>`, её карта `balmap_<таблица>` (`type mark : verdict`, ключ — слот
 * numgen) и цепочка метки выхода `mark_<таблица>` (член или сама группа — запасной путь). */
void group_bal_chain(const struct output *o, char *dst, size_t n);
void group_bal_map(const struct output *o, char *dst, size_t n);
void group_mark_chain(const struct output *o, char *dst, size_t n);
/* Куда ведёт слот карты, отданный члену m: вложенная balance — в её цепочку (её доля делится
 * дальше по её весам), остальные — в цепочку метки члена. */
void group_bal_target(const struct output *m, char *dst, size_t n);
/* Вес члена balance — 1..GROUP_WEIGHT_MAX (`weights` спеки v2). */
#define GROUP_WEIGHT_MAX 100
/* Сколько секунд без трафика через группу urltest не делается — предел `idle_timeout`. */
#define GROUP_IDLE_MAX_S 86400
/* ВЫБОР ПО ЗАМЕРУ (pick: latency): ms — задержки членов по порядку (-1 — не измерено). Лучший —
 * наименьшая задержка; из тех, кто хуже лучшего не больше чем на tol, берётся самый
 * предпочтительный (первый по порядку): порядок человека решает при равенстве. Возврат — номер
 * выбранного или -1, если не измерен никто; *best — лучшая задержка. */
int group_latency_pick(const int *ms, size_t n, int tol, int *best);
/* Уходить ли с живого текущего cur на выбранный замером pick: только если выигрыш больше
 * допуска. 1 — остаться на cur. */
int group_latency_keep(const int *ms, int cur, int pick, int tol);
/* ЗАДЕРЖКА, ПО КОТОРОЙ ВЫБИРАЮТ, у группы, меренной по обоим семействам (все живые члены несут
 * IPv6): ms4, ms6 — замеры по IPv4 и IPv6 (-1 — не измерилось, -2 — не мерили). Если по IPv6 не
 * измерился никто (адрес проверки без AAAA, у туннелей нет IPv6 наружу) — выбор по IPv4: мерить
 * IPv6 нечем, и наказывать за это членов незачем. Иначе у члена — ХУДШЕЕ из двух, а не
 * измерившийся по одному из них выбыл (-1): трафик группы идёт по обоим семействам, и член,
 * быстрый по IPv4, но медленный или глухой по IPv6, клиентам с IPv6 хуже того, кто ровен по
 * обоим. Пишет n чисел в score. */
void group_latency_score(const int *ms4, const int *ms6, size_t n, int *score);
/* ГИСТЕРЕЗИС ВОЗВРАТА (pick: order): трафик на менее предпочтительном cur, более
 * предпочтительное first ожило. Живое текущее держится, пока верхнее не подтвердит здоровье hyst
 * тиков подряд. streak — сколько тиков подряд оно уже было здорово до этого прохода, cur_alive —
 * жив ли текущий. Возврат — номер выбранного; *new_streak — серия, которую запомнить. */
int group_hysteresis(int cur, int first, int cur_alive, int streak, int hyst, int *new_streak);
/* Пределы настройки замера (pick: latency). Ноль допуска законен — «переключаться на любое
 * улучшение». Интервал у демона — свой таймер группы (src/daemon/folat.c), а не проход сторожа,
 * поэтому он может быть и короче периода; пять секунд — не чаще, чем идёт сам замер (срок
 * запроса — пять секунд). Спека v1 держит прежний предел 30 своим текстом отказа (model/v1.c):
 * её формат заморожен. */
#define GROUP_TOL_MAX_MS  60000
#define GROUP_INT_MIN_S   5
#define GROUP_INT_MAX_S   86400
/* Умолчания, когда человек допуск и интервал не задал, — числа sing-box (interval 3m, tolerance
 * 50). Одно место на всех, кто их читает: сторож (failover.c), таймеры замера (folat.c), подхват
 * (fogroup.c) и status. */
#define GROUP_TOL_DEFAULT_MS 50
#define GROUP_INT_DEFAULT_S  180
/* Допуск и интервал группы latency с учётом умолчаний. Допуск 0, заданный человеком, остаётся
 * нулём (lat_tolerance_ms: -1 — не задан), а не превращается в умолчание: ноль — это «выигрыш
 * любой величины значим», и настройка «самый быстрый строго» без него недостижима. */
int group_tolerance_ms(const struct group_cfg *g);
int group_interval_s(const struct group_cfg *g);

/* ПОЧЕМУ ГРУППА latency СЕЙЧАС НА ЭТОМ ЧЛЕНЕ — для status (docs/contract-v1.md, поле `why`).
 * ms — задержки, по которым выбирает сторож (-1 — не измерено), alive — живые члены (байт на
 * члена; замер члена, которого нет в живых, не в счёт), cur — выбранный член (-1 — группа в отказе
 * или сторож не проходил), tol — допуск. *fastest — самый быстрый из живых измеренных (-1 — таких
 * нет; NULL — не нужен). Возврат — GW_*: по порядку проверок —
 *   GW_NONE      — группа никого не выбрала;
 *   GW_NOMEASURE — ни у одного живого члена нет замера: группа идёт по порядку (первый живой), и
 *                  «самый быстрый» здесь ничего не решает — причина в том, что мерить не вышло;
 *   GW_UNMEASURED — выбранный жив, но не измерен, тогда как другие измерены;
 *   GW_FASTEST   — выбран самый быстрый (или равный ему);
 *   GW_TOLERANCE — выбран не самый быстрый, но не хуже него больше чем на допуск: порядок и
 *                  текущий член решают при равенстве (docs/spec-v2.md, «Как выбирает каждый pick»);
 *   GW_PENDING   — выбран не самый быстрый и хуже него больше допуска: переход — на ближайшем
 *                  проходе сторожа (или член только что оказался хуже);
 *   GW_IDLE      — замера нет, потому что он на паузе без трафика (idle_timeout); сама функция его не
 *                  возвращает — про простой знает status (fog_idle_now) и подменяет GW_NOMEASURE.
 * Чистая функция: её зовёт status и сверяет стенд. */
enum group_why { GW_NONE = 0, GW_NOMEASURE, GW_UNMEASURED, GW_FASTEST, GW_TOLERANCE, GW_PENDING,
                GW_IDLE };
int group_latency_why(const int *ms, const unsigned char *alive, size_t n, int cur, int tol,
                      int *fastest);
/* Имя причины, как оно печатается в status: no_measure, unmeasured, fastest, in_tolerance, pending,
 * idle; NULL у GW_NONE — группа никого не выбрала, и поля `why` нет. */
const char *group_why_name(int why);

/* interface: обфускация транспорта или NULL, если её нет (или выход не interface). */
const struct out_obfs *iface_obfs(const struct output *o);

/* vless */
const struct vless_cfg *out_vless(const struct output *o);
/* Развернуть выбор узлов выхода в порядок перебора при подписке из `usable` пригодных узлов.
 * Пишет в dst номера кандидатов по предпочтению и возвращает, сколько написал.
 *
 * Живёт рядом с разбором выхода, а не в клиенте vless: это ЗНАЧЕНИЕ поля `nodes`, а не деталь
 * подъёма туннеля, и проверить его стендом надо там, где стенд не требует ни криптобиблиотеки, ни
 * сети. Клиент и `vless-probe` зовут одну и ту же функцию — иначе диагностика показывала бы
 * перебор, отличный от настоящего.
 *
 * Номер вне подписки ПРОПУСКАЕТСЯ, а не роняет выход: подписка обновляется, узлов в ней
 * становится меньше, и устаревший номер не повод выключить локации, которые на месте.
 * Возврат 0 при непустом `nodes` означает, что не осталось ни одного, — вот это уже отказ,
 * потому что перебирать вместо выбранного что попало значит увести трафик в локацию,
 * которую человек не выбирал. */
size_t out_node_list(const struct output *o, size_t usable, int *dst, size_t max);
/* hysteria2: настройка выхода, порядок перебора узлов и «назван ли узел» — те же вопросы, что у
 * vless выше, с тем же смыслом (kinds/hysteria2.c). */
const struct hy2_cfg *out_hysteria2(const struct output *o);
size_t out_hy2_node_list(const struct output *o, size_t usable, int *dst, size_t max);
int out_hy2_node_named(const struct output *o);
/* Протоколы прокси (trojan, shadowsocks, socks, http, vmess): те же вопросы, с тем же смыслом
 * (kinds/proxy.c). out_proxy — настройка любого из пяти видов, иначе NULL. */
const struct proxy_cfg *out_proxy(const struct output *o);
size_t out_proxy_node_list(const struct output *o, size_t usable, int *dst, size_t max);
int out_proxy_node_named(const struct output *o);
/* Назван ли узел ЧЕЛОВЕКОМ — то есть выбирать не из чего и перебор не нужен.
 *
 * Отдельным вопросом, а не длиной списка кандидатов, потому что это разные вещи. Кандидат
 * остаётся один и тогда, когда его никто не называл: в подписке единственный узел, или из
 * трёх выбранных в ней уцелел один. Клиент решал по длине — и на подписке из одного узла
 * переставал его проверять вовсе: туннель поднимался на молчащем узле, а вместо «ни один
 * узел подписки не отвечает» человек снова видел «устройства нет» (I-100, ради снятия
 * которого перебор и стал виден).
 *
 * Пропускать проверку можно ровно в одном случае — номер написан в спеке: там человек уже
 * решил, и сообщать ему «выбран единственный выбранный» нечего. */
int out_node_named(const struct output *o);

/* xsteer */
const struct xsteer_cfg *out_xsteer(const struct output *o);

/* zapret */
/* Жив ли обработчик очереди nfqueue с этим номером — то есть работает ли выход kind=zapret. */
int nfqws_on_queue(int queue);
/* Работает ли системный обход (любой nfqws) — нужен on_fail=zapret у выходов с устройством. */
int zapret_running(void);
/* `steer zapret-instances`: что поднимать init-скрипту. Код — как у команды. */
int zapret_instances(const struct spec *sp);
/* Есть ли в спеке хоть один выход kind=zapret — общему коду (apply.c) это нужно знать про
 * ядро: без notrack порождённые обработчиком пакеты остаются на учёте conntrack, а без
 * kmod-nft-queue правило очереди не встанет вовсе. Раньше жила в compile/groups.c как
 * has_zapret и сравнивала kind напрямую; здесь то же самое — вопрос вида, а не общего кода. */
int zapret_present(const struct spec *sp);

/* tgws */
const struct tgws_cfg *out_tgws(const struct output *o);
/* `steer tgws-instances`: что поднимать init-скрипту. Код — как у команды. */
int tgws_instances(const struct spec *sp);
/* Есть ли в спеке хоть один выход kind=tgws — нужно раскладке старого ядра (legacy.c): в ней
 * заводится своя таблица `ip`, только когда моста есть куда перехватывать. Тот же довод и та
 * же замена, что у zapret_present. */
int tgws_present(const struct spec *sp);

#endif
