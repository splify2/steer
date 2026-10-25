/* ПЛАГИНЫ В ЯДРЕ: реестр видов, подкоманд и хуков из манифестов (docs плагинов: spec-fields.md,
 * steer-api.md, manifest.md).
 *
 * Плагин — каталог /usr/lib/steer/plugins/<id>/ с plugin.json. Ядро читает манифесты при старте и по
 * plugin_reload и строит из них реестр: вид выхода (схема ключей, свойства caps, помощник, шаблоны
 * nft, хуки check и expand), подкоманды `steer`, хуки pre_apply. Всё это — данные, а не код ядра: у
 * вида плагина нет своего kind_*.c, его struct kind_ops собирает реестр (plugin_kind.ops) и общий
 * код спрашивает его так же, как вид ядра.
 *
 * ВИД ПЛАГИНА И ВИД ЯДРА СОСУЩЕСТВУЮТ. Пока протоколы не вынесены из дерева steer, у `tunnel:vless`
 * есть встроенная запись (kinds/vless.c): если плагин того же имени стоит и включён, вид берётся у
 * плагина, иначе — встроенный. Вид, которого нет ни там, ни там, — «недоступный» (kind_unavail):
 * его выход живёт по on_fail, остальное работает (steer-api.md, 3.5).
 *
 * Реестр один на процесс и неизменяем между plugin_reload: записи видов живут в куче, указатели из
 * выходов спеки (plugin_out.pk) остаются годными, пока не вызван plugin_reload — его зовут при
 * старте, по SIGHUP и по команде plugin-reload, когда спеки старого состава уже нет. */
#ifndef STEER_PLUGIN_H
#define STEER_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#include "kind.h"

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

/* Подкоманда из манифеста: `steer <name> <слова человека…>` исполняет prog с argv. */
struct plugin_cmd {
    char *name;
    const struct plugin *owner;
    struct plugin_prog run;
    char *help, *usage;
    int ctl;                    /* есть строка `ctl` в манифесте: доступна и через сокет */
    int ctl_timeout_s;
};

struct plugin_kind {
    const struct plugin *owner;
    char *name;                 /* как в манифесте: «warp», «xsteer», «tunnel:vless» */
    const char *proto;          /* у «tunnel:<протокол>» — часть после двоеточия, иначе NULL */
    int impl_core;              /* impl: core — код вида остаётся в ядре, плагин даёт допуск */
    unsigned caps;              /* enum kind_cap из имён манифеста */
    struct ydoc *schema_doc;    /* схема ключей (kinds/<вид>.schema.json); NULL — ключей нет */
    const struct ynode *schema;
    struct plugin_prog helper;  /* prog NULL — помощника нет */
    char *helper_cmd;           /* имя помощника в журнале и status */
    int helper_argv_set;        /* argv задан манифестом; иначе умолчание [cmd, {out}, --conf, {conf}] */
    struct plugin_prog check;   /* prog NULL — хука нет */
    struct plugin_prog expand;
    char **nft;  size_t nft_n;  /* шаблоны nft на выход: полные пути файлов */
    unsigned res_ports, res_queues;     /* kinds[].resources: сколько на каждый выход */
    char *lan_only, *novia, *selfnat_why;
    struct kind_ops ops;        /* запись вида: её и возвращает реестр видов (kind_by_name) */
    struct plugin_kind *next;
};

/* Плагин из реестра. */
struct plugin {
    char *id, *version, *dir;
    char *name;
    int enabled;                /* включён и совместим: его виды и команды зарегистрированы */
    char *why;                  /* почему не включён (для status и отказов); NULL — включён */
    struct plugin_cmd *cmd;  size_t cmd_n;
    struct plugin_prog pre_apply;       /* prog NULL — хука нет */
    int has_hooks;              /* есть check, expand или pre_apply: от них зависит подготовка спеки */
    char *manifest;             /* байты plugin.json — в ключ подготовки */
    size_t manifest_len;
};

/* ---- реестр ---- */

/* Каталог плагинов: STEER_PLUGIN_DIR (стенды), иначе /usr/lib/steer/plugins. */
const char *plugin_root(void);
/* Каталог данных менеджера (state.json, conf/, cache/): STEER_PLUGIN_ETC, иначе <etc платформы>/plugins. */
const char *plugin_etc(char *buf, size_t n);
/* Каталог плагинной раскладки есть на этой машине. Нет — ядро ведёт себя как до плагинов: виды без
 * модуля отказывают всей спеке, как прежде (kind.c, absent). */
int plugin_layout_present(void);
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
