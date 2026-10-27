/* PLUGKIT — сторона плагина в API ядра steer (plugin-sdk/docs/steer-api.md): то, чем программа
 * официального протокола-плагина говорит с ядром, и ничего сверх.
 *
 *   • точка входа программы: свои подкоманды, свой разбор флагов, hello с версией API (2.1), флаг
 *     --platform; модель спеки ядра и её разбор команд (cli.c) программе не нужны;
 *   • файл настройки выхода {conf} (1.4): помощник выхода и подкоманды выхода (`<id>-nodes <выход>`)
 *     получают его от ядра флагом --conf и знают о своём выходе только то, что в нём: ключи вида
 *     (ядро уже проверило их схемой из манифеста), устройство, метку, таблицу, метку сокетов, порт
 *     слушателя, свои каталоги, таблицу fake-IP. Спеку человека программа не читает;
 *   • файл состояния выхода <plugin_state>/<выход>.status.json и событие state (2.2): status и diag
 *     ядра берут их оттуда.
 *
 * Чего здесь нет нарочно: struct output и struct spec модели ядра, реестр меток, виды. Всё, что ядро
 * вычисляет по всей спеке, приходит готовым в {conf}. */
#ifndef STEER_PLUGKIT_H
#define STEER_PLUGKIT_H

#include <stddef.h>
#include <stdint.h>

#include "pkjson.h"
#include "stack.h"

/* Версия steer-api, которой говорят программы этого дерева (hello, compat манифестов). */
#define PK_API "1.1"

/* Выход глазами программы плагина — файл {conf}. */
struct pk_out {
    struct tun_out tun;         /* имя, устройство, таблица, метка, порт слушателя */
    char kind[64];              /* «tunnel:vless», «xsteer», «warp»… */
    uint32_t mark_mask;
    uint32_t sock_mark;         /* метка своих сокетов к узлам (SO_MARK) */
    int sock_mark_required;     /* отказ SO_MARK при подложке — отказ, а не «напрямую» */
    int ipv6;                   /* выход несёт IPv6 */
    char over[32];              /* подложка; пусто — напрямую */
    char *conf_path;            /* сам файл {conf} */
    char *etc;                  /* paths.etc */
    char *state;                /* paths.state — каталог состояния ядра */
    char *plugin_state;         /* paths.plugin_state — свой каталог состояния (tmpfs) */
    char *plugin_conf;          /* paths.conf — свой каталог настроек */
    char *plugin_dir;           /* paths.plugin */
    char *fakeip;               /* paths.fakeip; NULL — ядро не дало */
    char *platform;
    char *status_path;          /* <plugin_state>/<выход>.status.json */
    struct pkj *doc;            /* весь {conf} */
    const struct pkj *keys;     /* output.keys — ключи вида по схеме */
    const struct pkj *output;   /* output целиком (members развёрнутого выхода и прочее) */
};

/* Прочитать {conf}. 0 — готово; -1 — отказ, причина в err. */
int pk_conf_load(const char *path, struct pk_out *o, char *err, size_t errn);
/* То, что {conf} говорит процессу: платформа, каталог состояния (свой каталог плагина), файл
 * состояния пула, таблица fake-IP стека. */
void pk_conf_apply(const struct pk_out *o);
/* {conf} процесса (флаг --conf); NULL — запущен без него. */
const struct pk_out *pk_out(void);

/* Метка своих сокетов к узлам: из {conf}; без него (проба файла подписки) — «мимо каналов»
 * платформы (self_mark: на роутере 0). */
uint32_t pk_sock_mark(const struct pk_out *o);

/* ---- ключи вида ---- */
const char *pk_key_str(const struct pk_out *o, const char *key);
int pk_key_bool(const struct pk_out *o, const char *key, int def);
long pk_key_long(const struct pk_out *o, const char *key, long def);
/* Число или список чисел (x-one-or-list) → массив в куче (*out, *n); ключа нет — n 0. 0 / -1. */
int pk_key_ints(const struct pk_out *o, const char *key, int **out, size_t *n);
/* Строка или список строк → массив указателей в куче на строки {conf} (живут, пока жив o). */
int pk_key_strs(const struct pk_out *o, const char *key, const char ***out, size_t *n);

/* ---- файл состояния и события ---- */
/* Переписать файл состояния выхода атомарно (rename) и сказать ядру событием state. json — объект
 * целиком. 0 / -1. Без {conf} — ничего (0). */
int pk_status_write(const struct pk_out *o, const char *json);

/* ---- точка входа ---- */

/* Разобранная командная строка подкоманды. */
struct pk_args {
    const char *cmd;
    const char **pos;           /* позиционные слова (куча) */
    int npos;
    const struct pk_out *out;   /* --conf; NULL — без него */
    /* флаги: имя без «--» → значение («» у флага без значения) */
    const char **fk, **fv;
    int nf;
};
/* Значение флага («node» для --node); NULL — не задан. */
const char *pk_opt(const struct pk_args *a, const char *name);
int pk_has(const struct pk_args *a, const char *name);
/* Целое значение флага в [lo, hi]; не задан — def; не число или вне границ — отказ (exit 2). */
long pk_opt_long(const struct pk_args *a, const char *name, long def, long lo, long hi);

/* Подкоманда программы. flags — флаги через пробел, у флага со значением «:» в конце
 * («node: timeout: insecure»); --conf, --state-dir и --platform понимает каждая. */
struct pk_cmd {
    const char *name;
    const char *args;           /* «<выход>», «<выход|/файл>» — для справки */
    int npos_min, npos_max;
    const char *flags;
    const char *help;
    int conf;                   /* 1 — без --conf отказ (помощник выхода) */
    int (*run)(const struct pk_args *a);
};

/* Точка входа программы плагина id: argv[1] — подкоманда из cmds. Код возврата — её. */
int pk_main(int argc, char **argv, const char *id, const char *version, const struct pk_cmd *cmds, size_t n);

/* ПРОГРАММА ПЛАГИНА — таблица подкоманд под id. Объявляется в src/modules/main_<id>.c одной строкой
 * PK_PROGRAM("<id>", CMDS) и ложится в раздел steer_pk объекта. main ей даёт src/plugkit/pkmain.c
 * (программа плагина: одна запись в разделе), а статический бинарник ядра (телефон), куда вкомпилированы
 * несколько протоколов, находит запись по имени, под которым его запустили (pk_prog_find): в каталоге
 * плагина bin/<id> — ссылка на него. Имён протоколов ядро при этом не знает — только раздел. */
struct pk_prog {
    const char *id;
    const char *version;
    const struct pk_cmd *cmds;
    size_t n;
};
#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif
#define PK_PROGRAM(ID, CMDS)                                                                   \
    __attribute__((used, section("steer_pk"), aligned(sizeof(void *))))                       \
    static const struct pk_prog pk_prog_entry = { ID, STEER_VERSION, CMDS, sizeof(CMDS) / sizeof((CMDS)[0]) }
/* Программа плагина id, вкомпилированная в этот бинарник; NULL — нет. id NULL — первая. */
const struct pk_prog *pk_prog_find(const char *id);
/* Запустить программу p: как pk_main. */
int pk_prog_run(const struct pk_prog *p, int argc, char **argv);

/* Отказ программы (steer-api.md, 1.5): строка в stderr, код 2. */
__attribute__((noreturn, format(printf, 1, 2))) void pk_fail(const char *fmt, ...);

#endif
