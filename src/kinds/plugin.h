/* ПЛАГИНЫ В ЯДРЕ: реестр видов, подкоманд и хуков из манифестов (docs плагинов: spec-fields.md,
 * steer-api.md, manifest.md).
 *
 * Плагин — каталог /usr/lib/steer/plugins/<id>/ с plugin.json. Ядро читает манифесты при старте и по
 * plugin_reload и строит из них реестр: вид выхода (схема ключей, свойства caps, помощник, шаблоны
 * nft, хуки check и expand), подкоманды `steer`, хуки pre_apply. Всё это — данные, а не код ядра: у
 * вида плагина нет своего kind_*.c, его struct kind_ops собирает реестр (plugin_kind.ops) и общий
 * код спрашивает его так же, как вид ядра.
 *
 * ВИДОВ ПРОТОКОЛОВ В ЯДРЕ НЕТ. tunnel:vless, xsteer, warp и соседи приходят только из манифестов. Вид,
 * которого нет, — «недоступный» (kind_unavail): его выход живёт по on_fail, остальное работает
 * (steer-api.md, 3.5); apply и check отказывают с причиной «нужен плагин X» (X — из индекса семени).
 * Виды ядра (interface, awg…) плагин может дополнить: допуск (impl: core) и помощник по ключу вида
 * (helper.when — обфускатор у interface с obfs).
 *
 * Реестр один на процесс и неизменяем между plugin_reload: записи видов живут в куче, указатели из
 * выходов спеки (plugin_out.pk) остаются годными, пока не вызван plugin_reload — его зовут при
 * старте, по SIGHUP и по команде plugin-reload, когда спеки старого состава уже нет. */
#ifndef STEER_PLUGIN_H
#define STEER_PLUGIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "cli.h"
#include "kind.h"

/* Версия steer-api этого ядра (steer-api.md): плагин `^1.x` исполняется, если x не больше минора.
 * Число одно — CLI_STEER_API (cli/cli.h). */
#define STEER_API_VERSION CLI_STEER_API

struct err;
struct spec;
struct output;
struct ynode;
struct ydoc;

/* Программа плагина: помощник, хук, подкоманда, служба. prog — полный путь
 * (<каталог плагина>/<prog манифеста>); argv — слова манифеста без argv[0], подстановки ({out},
 * {conf}…) раскрываются при запуске; env — «ИМЯ=значение». Всё в куче, любой длины. */
struct plugin_prog {
    char *prog;
    char **argv;  size_t argc;
    char **env;   size_t envc;
    int timeout_s;              /* 0 — умолчание места (хуки check/expand 10 с, pre_apply 30 с) */
};

struct plugin;
struct pnft;                    /* разобранный файл nft плагина (plugin.c) */

/* Подкоманда из манифеста: `steer <name> <слова человека…>` исполняет prog с argv. */
struct plugin_cmd {
    char *name;
    const struct plugin *owner;
    struct plugin_prog run;
    char *help, *usage;
    int ctl;                    /* есть строка `ctl` в манифесте: доступна и через сокет */
    int ctl_timeout_s;
    /* conf (manifest.md, commands[]): первое слово — имя выхода вида этого плагина (не путь с «/»);
     * ядро кладёт его файл настройки {conf} и передаёт программе `--conf <файл>`, а --spec и
     * --state-dir человека забирает себе (steer-api.md, 1.4, 4.3). */
    int conf;
    /* ctl.args — слова запроса сокета по порядку: вид (name, int, target, file, word) и флаг, которым
     * слово уходит программе (NULL — позиционное); у int — пределы. ctl.optional — сколько последних
     * слов можно опустить. ctl.body — тело запроса файлом: путь — последним словом программе. */
    struct plugin_ctl_arg { char *kind; char *flag; long lo, hi; } *ctl_args;
    size_t ctl_args_n;
    int ctl_optional;
    long ctl_body_max;          /* 0 — тела нет */
    int ctl_lock;               /* изменяющая: в очереди с apply */
};

/* Служба из манифеста (steer.services[], manifest.md): один помощник на роутер, а не на выход. Поднимается
 * тем же супервизором, что помощники выходов, пока плагин включён. */
struct plugin_svc {
    char *name;
    const struct plugin *owner;
    struct plugin_prog run;     /* prog, argv (умолчание — [<name>]), env, timeout_s — срок hello */
};

struct plugin_kind {
    const struct plugin *owner;
    char *name;                 /* как в манифесте: «warp», «xsteer», «tunnel:vless» */
    const char *proto;          /* у «tunnel:<протокол>» — часть после двоеточия, иначе NULL */
    int impl_core;              /* impl: core — код вида остаётся в ядре, плагин даёт допуск */
    unsigned caps;              /* enum kind_cap из имён манифеста */
    struct ydoc *schema_doc;    /* схема ключей (kinds/<вид>.schema.json); NULL — ключей нет */
    const struct ynode *schema;
    char *schema_path;          /* файл схемы — для отказов */
    struct plugin_prog helper;  /* prog NULL — помощника нет */
    char *helper_cmd;           /* имя помощника в журнале и status */
    int helper_argv_set;        /* argv задан манифестом; иначе умолчание [cmd, {out}, --conf, {conf}] */
    struct plugin_prog check;   /* prog NULL — хука нет */
    struct plugin_prog expand;
    char **nft;  size_t nft_n;  /* шаблоны nft на выход: полные пути файлов */
    struct pnft **nftp;         /* их разбор, по одному на файл */
    unsigned res_ports, res_queues;     /* kinds[].resources: сколько на каждый выход */
    char *lan_only, *novia, *selfnat_why;
    char *desc;                 /* kinds[].description, иначе description плагина; NULL — нет */
    int health_events;          /* health: events — здоровье и задержку судит помощник (up/down), а не проба */
    int paths;                  /* paths: true — помощник отставляет пути (событие health): status выхода несёт
                                 * paths_down всегда, пустым массивом — когда отставленных нет (steer-api 1.4) */
    char *helper_when;          /* helper.when — помощник только у выходов с этим ключом (вид ядра impl: core) */
    char **watch;  size_t watch_n;  /* ключи x-watch: содержимое их файлов — в подпись перезапуска */
    struct kind_ops ops;        /* запись вида: её и возвращает реестр видов (kind_by_name) */
};

/* Плагин из реестра. */
/* ПЛАГИНЫ, ВКОМПИЛИРОВАННЫЕ В СТАТИЧЕСКУЮ СБОРКУ (телефон; plugin-sdk, open.md, О-13). Каталога плагинов
 * там нет, а протоколы нужны: манифест и файлы официального плагина (plugins/<id>/) лежат в бинарнике
 * строками (src/plugkit/pkembed.c — его пишет build/pkembed.sh, сверяет tests/buildmatch.sh), программа —
 * сам бинарник (PK_PROGRAM, src/plugkit). Реестр читает их, как каталог «@builtin/<id>»; плагин того же
 * id в настоящем каталоге плагинов главнее. files[0] — plugin.json; @VERSION@ — версия ядра. */
#define PLUGIN_BUILTIN_DIR "@builtin"
struct plugin_embed_file { const char *path, *text; };
struct plugin_embed { const char *id; const struct plugin_embed_file *files; };
extern const struct plugin_embed steer_plugin_embed[] __attribute__((weak));

struct plugin {
    char *id, *version, *dir;
    int builtin;                /* вкомпилирован (PLUGIN_BUILTIN_DIR): программа — этот бинарник */
    char *name;
    char *desc;                 /* description манифеста */
    int enabled;                /* включён и совместим: его виды и команды зарегистрированы */
    char *why;                  /* почему не включён (для status и отказов); NULL — включён */
    struct plugin_cmd *cmd;  size_t cmd_n;
    struct plugin_kind **kind;  size_t kind_n;   /* в порядке манифеста */
    struct plugin_svc *svc;  size_t svc_n;       /* steer.services[], в порядке манифеста */
    struct plugin_prog pre_apply;       /* prog NULL — хука нет */
    int has_hooks;              /* есть check, expand, pre_apply или ресурсы видов: от них зависит подготовка спеки */
    int settings_restart;       /* steer.settings: "restart" — settings.json плагина в подписи его помощников и служб (1.4) */
    unsigned res_ports, res_queues, res_marks;   /* resources манифеста: сколько на весь плагин */
    char **kind_names;  size_t kind_names_n;    /* имена видов манифеста — и у выключенного плагина: для отказа «плагин X отключён» */
    char **requires;  size_t requires_n;    /* requires.plugins: id плагинов, раньше которых идут хуки */
    char **nft;  size_t nft_n;  /* steer.nft[]: файлы плагина с наборами и цепочками слотов */
    struct pnft **nftp;
    char *manifest;             /* байты plugin.json — в ключ подготовки */
    size_t manifest_len;
};

/* ---- реестр ---- */

/* Каталог плагинов: STEER_PLUGINS_ROOT (стенды), иначе /usr/lib/steer/plugins. */
const char *plugin_root(void);
/* Каталог данных менеджера (state.json, conf/, cache/): STEER_PLUGIN_ETC, иначе <etc платформы>/plugins. */
const char *plugin_etc(char *buf, size_t n);
/* Прочитать манифесты заново и перестроить реестр. root NULL — plugin_root(). 0 — готово (в том
 * числе без единого плагина); -1 — нет памяти. Манифест, который не читается, не роняет реестр:
 * плагин записывается выключенным с причиной (plugin_at(i)->why). */
int plugin_reload(const char *root);
/* Реестр читается лениво при первом вопросе (plugin_reload(NULL)). */
size_t plugin_n(void);
const struct plugin *plugin_at(size_t i);
const struct plugin *plugin_find(const char *id);

/* Вид плагина по имени манифеста («tunnel:vless»); NULL — нет такого у включённого плагина. */
const struct plugin_kind *plugin_kind_find(const char *name);
/* Вид по имени записи реестра видов (name у kind_ops: «vless», «tunnel:vless», «warp»). */
const struct plugin_kind *plugin_kind_of_ops(const struct kind_ops *k);
/* Почему вида нет: «нужен плагин vless», «плагин vless отключён: …». NULL — вид неизвестен совсем
 * (не называется ни одним плагином, включённым или нет, ни семенем). *id — id плагина, если
 * известен. Текст — в buf. */
const char *plugin_kind_why(const char *name, char *buf, size_t n, const char **id);

/* Виды плагинов в порядке реестра — после видов ядра (kind.c: kind_count, kind_at). */
size_t plugin_kinds_n(void);
const struct kind_ops *plugin_kind_ops_at(size_t i);

/* Подкоманда плагина по имени; NULL — такой нет у включённого плагина. */
const struct plugin_cmd *plugin_cmd_find(const char *name);
/* Исполнить подкоманду плагина вместо этого процесса: argv — слова человека. Возвращает только
 * при отказе запуска (код 2, причина на stderr). */
int plugin_cmd_exec(const struct plugin_cmd *c, int argc, char **argv);

/* ---- ключи вида по схеме ---- */

/* Проверить ключи выхода keys (отображение YAML, только ключи вида — общие уже вынуты) по схеме вида
 * и собрать keys_json: JSON-объект с умолчаниями схемы и абсолютными путями x-path. etc — каталог
 * спеки (x-path: etc), conf — каталог настроек плагина (x-path: conf). 0 — годится, *json — в куче
 * вызывающего (free); -1 — отказ, текст в e (без места: его добавляет вызывающий по узлу *at). */
int plugin_keys_check(const struct plugin_kind *pk, const struct ynode *keys, const char *etc,
                      const char *conf, char **json, const struct ynode **at, struct err *e);

/* Проверка x-ref: есть ли в разделе спеки (outputs, lists, clients, dns.upstreams) запись с таким
 * именем. Спрашивает plugin_keys_refs, когда спека разобрана целиком. */
typedef int (*plugin_ref_fn)(void *ctx, const char *section, const char *name);

/* Ссылки x-ref в ключах вида (сырой узел keys, как в plugin_keys_check): имя обязано быть записью
 * раздела или словом also. 0 — годится; -1 — отказ, текст в e («путь: «имя» — …», без места), *at —
 * узел значения. */
int plugin_keys_refs(const struct plugin_kind *pk, const struct ynode *keys, plugin_ref_fn has, void *ctx,
                     const struct ynode **at, struct err *e);

/* ---- nft: слоты и шаблоны (steer-api.md, раздел 5) ---- */

struct nft_rs;
/* Дописать в дерево rs наборы, цепочки слотов и правила видов всех включённых плагинов: файлы
 * steer.nft[] и шаблоны kinds[].nft на каждый выход вида. Порядок — по id плагина, затем по порядку
 * манифеста, поэтому текст набора правил не зависит от порядка установки. Слот занят — ядро заводит
 * базовую цепочку plugin_<слот> и пишет в неё `jump plugin_<id>_<слот>`. 0 — готово; -1 — отказ,
 * причина с именем плагина и строкой файла в e. */
int plugin_emit_all(struct nft_rs *rs, const struct spec *sp, struct err *e);
/* `steer nft-map`: карта ядра для плагинов — таблица, базовые цепочки с хуком и приоритетом числом,
 * поле метки, слоты. json — JSON, иначе текст для человека. */
void plugin_nft_map(FILE *out, int json);

/* Вид, чей помощник ведёт выход: вид самого выхода или — у развёрнутой группы — вид плагина с
 * разворотом и помощником. NULL — помощника у выхода нет. */
const struct plugin_kind *plugin_helper_kind(const struct output *o);
/* Содержимое файла настройки выхода {conf} (steer-api.md, 1.4) — JSON в куче. */
char *plugin_conf_json(const struct spec *sp, const struct output *o, const struct plugin_kind *pk);
/* Записать {conf} выхода атомарно (0600) в <state>/plugin/<id>/<выход>.json до запуска помощника.
 * 0 / -1 (причина — errno). */
int plugin_conf_write(const struct spec *sp, const struct output *o);
/* Перечитать реестр плагинов, если каталог плагинов или state.json изменились с прошлого чтения
 * (1 — перечитан). Зовёт загрузка спеки в демоне, чтобы смена плагинов подхватывалась на reload. */
int plugin_refresh(void);

/* Файл состояния выхода плагина (steer-api.md, 2.2): <state>/plugin/<id>/<выход>.status.json —
 * выхода вида плагина или развёрнутого выхода с помощником (owner). Текст в куче (free); NULL — файла
 * нет, он не объект JSON или называет мёртвый процесс (поле pid). */
char *plugin_out_state(const struct output *o);
/* status развёрнутого выхода с помощником (owner — он сам): поле plugin, как у вида плагина. */
void plugin_owner_status(FILE *out, const struct output *o);

/* Помощник выхода от вида плагина pk: программа плагина с раскрытым argv, {conf} и подпись. 0 / -1. */
int plugin_kind_helper(const struct plugin_kind *pk, const struct spec *sp, const struct output *o,
                       struct kind_helper *h);
/* Помощник, которого плагин даёт виду ЯДРА (kinds[] с impl: core и helper.when, manifest.md): запись
 * включённого плагина для вида kind и ключа key; NULL — такого плагина нет. */
const struct plugin_kind *plugin_core_ext(const char *kind, const char *key);

/* Службы включённых плагинов в порядке реестра (по id плагина, затем по порядку манифеста). */
size_t plugin_svc_n(void);
const struct plugin_svc *plugin_svc_at(size_t i);
/* Помощник службы: программа плагина с раскрытым argv и подпись перезапуска (версия плагина, argv с
 * выданными ресурсами, env). cmd помощника — имя службы. 0 / -1 (причина — в stderr). */
int plugin_svc_helper(const struct plugin_svc *sv, const struct spec *sp, struct kind_helper *h);

/* Помощник развёрнутого выхода (хук expand вернул helper: true): kind_ops.helper группы зовёт его. */
int plugin_owner_helper(const struct spec *sp, const struct output *o, struct kind_helper *h);

/* Окружение программы плагина (steer-api.md, 1.2) — в процесс, который сейчас запустит exec: хуки
 * (plugprep.c), помощники, подкоманды. p — env из манифеста программы или NULL. */
void plugin_env_set(const struct plugin *pl, const struct plugin_prog *p);
/* Подстановки {out}, {plugin_dir}… в слове argv хука; NULL — отказ с причиной в why. */
char *plugin_subst(const struct plugin *pl, const char *out_name, const char *s, char *why, size_t wn);
/* Узел YAML/JSON → текст JSON по записи значения (тип — как читает YAML 1.2: число, true/false, null,
 * иначе строка). */
struct sbuf;
void plugin_node_json(struct sbuf *b, const struct ynode *n);

/* Ресурсы плагина целиком (resources манифеста): порты, очереди NFQUEUE, биты метки — выданные при
 * подготовке. bits — номера битов вне поля метки steer. 0 — выданы; -1 — нет записи. */
struct plugin_res { uint32_t *ports; size_t ports_n; uint32_t *queues; size_t queues_n; uint32_t *bits; size_t bits_n; };
int plugin_res_get(const struct plugin *pl, struct plugin_res *r);
void plugin_res_free(struct plugin_res *r);

/* Ресурсы выхода вида плагина — порты и очереди, выданные при подготовке (alloc.json в каталоге
 * данных менеджера). 0 — выданы; -1 — нет записи (спека не подготовлена). Массивы в арене sp. */
int plugin_alloc_lookup(struct spec *sp, const struct plugin_kind *pk, const char *out,
                        uint32_t **ports, size_t *pn, uint32_t **queues, size_t *qn);
/* То же, но с выдачей: ресурсов у выхода ещё нет — выдать (alloc.json) и вернуть. Нужна разбору спеки v1:
 * её подготовка не идёт (plugprep.c готовит только v2), а вид плагина с ресурсами без номеров не работает.
 * 0 / -1 (причина в e). */
int plugin_alloc_out(struct spec *sp, const struct plugin_kind *pk, const char *out,
                     uint32_t **ports, size_t *pn, uint32_t **queues, size_t *qn, struct err *e);

/* Отчёт последней подготовки спеки path (JSON: что изменили хуки pre_apply и expand, предупреждения)
 * в кучу; -1 — отчёта нет. Ответ apply кладёт его в поле plugins. */
int spec_prepare_report(const char *path, char **json);

/* Ключи выхода как есть, без схемы — JSON-объект (недоступный вид: ключи проверить нечем, но
 * печать спеки не должна их терять). 0 / -1 (нет памяти). */
int plugin_keys_raw(const struct ynode *keys, char **json);

/* ---- вид unavail и plugin-device ---- */
extern const struct kind_ops kind_unavail;
extern const struct kind_ops kind_plugin_device;

/* Сделать выход o недоступным: вид unavail, failed. why — причина (копируется в арену sp),
 * plugin — id плагина или NULL, shown — прежнее имя вида для status. 0 / -1 (нет памяти). */
int out_make_unavail(struct spec *sp, struct output *o, const char *why, const char *plugin,
                     const char *shown);

/* ---- шаг подготовки спеки (plugprep.c) ---- */

/* Исполнить хуки check, expand, pre_apply и записать подготовленную спеку (spec.prepared.json) и
 * ключ. Без хуков в реестре — ничего не пишет и возвращает 0: подготовленной спеки нет, читается
 * спека человека. Отказ — причина с именем плагина в e. Вызывают apply-plan, check, reload, старт
 * демона. warnings — предупреждения хуков (printf в stderr, если не NULL, не нужно). */
int spec_prepare(const char *path, struct err *e);
/* Подготовленная спека для load_spec: если ключ совпал — её текст (malloc) и 1; 0 — не подготовлена
 * (нет файла, ключ не совпал, подготовка не нужна); -1 — нет памяти. human — байты спеки человека. */
int spec_prepared_text(const char *path, const char *human, size_t human_n, char **text, size_t *n,
                       char key[65]);

#endif
