/* .SO-ПЛАГИНЫ В ПРОЦЕССЕ steerd (steer-abi v1): загрузчик, таблица функций ядра, журнал виновного.
 *
 * Контракт — plugabi.h (копия include/steer/plugin.h из plugin-sdk), описание — docs/plugin-abi.md.
 * Загрузчик живёт внутри steerd (plugso.c), а не отдельной библиотекой libsteer-plugin.so.1: таблице
 * host_v1 нужны цикл демона, спека, подписчики и сторож — то есть внутренности steerd, и
 * библиотеке пришлось бы получать их второй таблицей от того же steerd. Плагину разницы нет: он не
 * связан ни с чем, его нужды — таблица в init.
 *
 * ЧТО ДЕЛАЕТ ЗАГРУЗЧИК
 *   - перед dlopen читает ELF плагина и отказывает, если он связан с libsteer* (DT_NEEDED);
 *   - dlopen(RTLD_NOW | RTLD_LOCAL), один символ steer_plugin_v1_entry, сверка major, minor и
 *     отпечатка сборки, id и версии;
 *   - init(host, &host_v1) на цикле демона; виды, хуки, события и команды плагина доступны через
 *     plugso_* ниже — реестр видов (kinds/plugin.c) оборачивает их в kind_ops;
 *   - каждый вход в плагин — под сторожем: id и время входа пишутся в переменную, обработчик
 *     SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGABRT и сторожевой поток (5 с) по ней называют виновного в
 *     <state>/plugin/so.crash. Три падения плагина за 10 минут — .so больше не грузится, пока человек
 *     не включит его (plugso_enable), и это видно в status (plugins_so).
 *
 * СТАТИЧЕСКИЕ СБОРКИ (телефон, расширенный пакет, стенды): dlopen в них нет, plugso_load отказывает
 * сообщением, а не падает в заглушке libc.
 *
 * ПОТОКИ. Всё, что описано здесь, зовётся на цикле демона. Исключение — plugso_enter/leave, они
 * безопасны из любого потока: плагин, свои потоки которого зовут ядро, этим нарушает ABI. */
#ifndef STEER_PLUGSO_H
#define STEER_PLUGSO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "plugabi.h"

struct steerd;
struct output;
struct spec;
struct plugso;

enum plugso_state {
    PLUGSO_LOADED = 1,      /* init вернул 0, виды и хуки годны */
    PLUGSO_FAILED = 2,      /* не загрузился: why — причина (ABI, init, ELF, нет файла…) */
    PLUGSO_OFF    = 3,      /* отключён по падениям: не грузится до plugso_enable */
};

/* Окно подсчёта падений и их число, с которого плагин отключается. */
#define PLUGSO_CRASH_WINDOW_S 600
#define PLUGSO_CRASH_LIMIT    3
/* Вызов плагина дольше этого — зависание: сторож пишет запись и роняет процесс. */
#define PLUGSO_CALL_LIMIT_MS  5000

/* ---- загрузка ---- */

/* Эта сборка умеет dlopen: 0 — да; иначе -1 и причина в why (статическая сборка). */
int plugso_supported(char *why, size_t n);

/* Загрузить .so плагина id: dir — каталог плагина, so — путь файла внутри него (как `so.path`
 * манифеста: относительный, без «..»), version — как в манифесте (NULL — не сверять). Запись остаётся
 * в реестре и при отказе (plugso_find, status). Повторный вызов для записи не LOADED повторяет
 * попытку (после plugso_enable); для LOADED возвращает её же. 0 — загружен, *out — запись (если не
 * NULL); -1 — отказ, причина в why (и в записи); *out при отказе тоже заполнен, если запись есть. */
int plugso_load(const char *id, const char *version, const char *dir, const char *so,
                struct plugso **out, char *why, size_t n);

/* Включить плагин, отключённый по падениям: снять отметку, сбросить счётчик, повторить загрузку,
 * если запись уже известна. Зовёт менеджер при `enable` и при обновлении плагина. Процесс может быть
 * любым: отметка — файл в <state>/plugin. 0 — сделано (загрузка в том же процессе могла и не
 * удаться — смотри plugso_state); -1 — нет каталога состояния. */
int plugso_enable(const char *id);

/* fini всех загруженных плагинов — при остановке steerd (библиотеки musl не выгружает). */
void plugso_fini_all(void);

/* ---- реестр ---- */
size_t plugso_n(void);
struct plugso *plugso_at(size_t i);
struct plugso *plugso_find(const char *id);
const char *plugso_id(const struct plugso *p);
const char *plugso_version(const struct plugso *p);
const char *plugso_why(const struct plugso *p);              /* NULL — нечего сказать */
enum plugso_state plugso_state(const struct plugso *p);
const struct steer_plugin_v1 *plugso_desc(const struct plugso *p);   /* только у LOADED */
const struct steer_kind_v1 *plugso_kind_find(const struct plugso *p, const char *name);
/* Падений плагина в окне PLUGSO_CRASH_WINDOW_S (по so.crash на момент загрузки и позже). */
int plugso_crashes(const struct plugso *p);

/* ---- вызовы плагина под сторожем ----
 *
 * Все вызываются только для LOADED. Указатели spec/out — спека и выход ядра (struct spec,
 * struct output), плагин видит их непрозрачными. Если у плагина нет нужной функции, возвращается
 * значение «нет»: check 0, health -1, revive -1, apply_all/down_all 0, status NULL, expand -1. */
int plugso_call_check(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                      const struct output *o, char *why, size_t n);
/* Приёмник правил, которые плагин даёт host->nft_rule во время emit: slot — слот, rule — текст. 0 —
 * принято, -1 — отказ. */
typedef int plugso_nft_sink(void *arg, const char *plugin_id, const char *slot, const char *rule);
void plugso_call_emit(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                      const struct output *o, plugso_nft_sink *sink, void *arg);
int plugso_call_health(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                       const struct output *o, const char *dev);
int plugso_call_revive(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                       const struct output *o, const char *dev);
int plugso_call_apply_all(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                          char *why, size_t n);
int plugso_call_down_all(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp);
/* JSON-объект в памяти malloc (free) или NULL. */
char *plugso_call_status(struct plugso *p, const struct steer_kind_v1 *k, const struct spec *sp,
                         const struct output *o);
int plugso_call_expand(struct plugso *p, const struct steer_kind_v1 *k, const char *out_json,
                       char **frag_json, char *why, size_t n);
int plugso_call_pre_apply(struct plugso *p, const char *spec_json, char **out_json, char *why, size_t n);
int plugso_call_ctl(struct plugso *p, const char *cmd, const char *const *argv, size_t argc,
                    const char *body, size_t body_len, char **resp_json);

/* Любая другая функция плагина — под сторожем вручную: fn — статическая строка для журнала. */
struct plugso_guard { struct plugso *p; const char *fn; long t; };
void plugso_enter(struct plugso_guard *saved, struct plugso *p, const char *fn);
void plugso_leave(const struct plugso_guard *saved);

/* ---- шов с моделью ----
 *
 * Три вопроса host_v1 зависят от настройки выхода, которую хранит модель (ключи вида, файл {conf},
 * владелец-плагин), и ресурсы — от менеджера плагинов (alloc.json). Загрузчик их не знает: кто знает,
 * ставит функции сюда (реестр видов, kinds/plugin.c). Не поставлены — NULL («нет»). Возвращаемые
 * строки живут до конца вызова плагина. */
struct plugso_model_ops {
    const char *(*out_keys_json)(const struct output *o);
    const char *(*out_conf_json)(const struct output *o);
    const char *(*out_owner)(const struct output *o);          /* "<plugin>/<выход>" или NULL */
    int (*resource)(const char *plugin, const char *kind, unsigned i, uint32_t *out);
};
void plugso_set_model(const struct plugso_model_ops *m);

/* ---- демон ---- */

/* Подключить загрузчик к демону d (цикл, спека, подписчики, сторож, супервизор) и загрузить плагины,
 * перечисленные в <state>/plugin/so.load: строка на плагин — «id версия каталог путь-к-.so» через
 * табуляцию (пишет менеджер; пока реестр видов не читает манифесты сам, это единственный источник).
 * Плагины с on_event подписываются на события сокета. Зовёт ctl_serve_main при старте. */
void plugso_boot(struct steerd *d);
/* Загрузчик подключается к демону без чтения so.load (стенд, реестр видов). */
void plugso_attach(struct steerd *d);

/* status: `,"plugins_so":[…]` — по записи на плагин, если реестр не пуст; иначе ничего. */
void plugso_status_print(FILE *out);
/* status выхода: `,"plugin":{…}` — то, что плагин дал host->set_status для этого выхода. */
void plugso_status_out(FILE *out, const char *out_name);

#endif
