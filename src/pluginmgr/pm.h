/* Менеджер плагинов ядра steer: `steer plugin …` и команды сокета `plugin-*` (plugin-sdk: s2p.md,
 * index.md, manifest.md, steer-api.md 4.2).
 *
 * ХОЗЯИН ПЛАГИНОВ — ЯДРО (решение В1). Менеджер ставит, обновляет, снимает, включает и выключает
 * плагины в /usr/lib/steer/plugins/<id>, ведёт /etc/steer/plugins/state.json, репозитории
 * (repos.d) и ключи. Реестр видов, подкоманд и служб из манифестов строит ядро само (kinds/plugin.c);
 * менеджер после каждого изменения зовёт демон командой `plugin-reload` и шлёт событие `plugin`.
 *
 * СЛОИ ВНУТРИ:
 *   pmutil.c   пути (с подменами для стендов), файлы, JSON (чтение — ynode, запись — struct jw),
 *              время, место на разделах, блокировка;
 *   pmver.c    semver и диапазоны в синтаксисе npm (оси compat, requires.plugins);
 *   pmstate.c  state.json, repos.d, ключи по ролям и отзыв;
 *   pmindex.c  индекс репозитория: загрузка с ETag, подпись, срок, отбор совместимой версии;
 *   pminst.c   план, место, скачивание, проверка архива, системные пакеты, .stage/.prev, проверка
 *              здоровья, откат, снятие, keep.d;
 *   pmmain.c   команда `steer plugin …`, задания, автообновление, семя.
 *
 * Пределов на число плагинов, версий, репозиториев, ключей нет: всё в куче (решение 5). */
#ifndef STEER_PM_H
#define STEER_PM_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include "ynode.h"
#include "sigverify.h"

/* Версии осей, которые даёт это ядро (manifest.md, «compat»). */
#include "cli.h"
#define PM_STEER_API CLI_STEER_API
#define PM_STEER_ABI CLI_STEER_ABI

/* ---- ошибка ---- */
/* Отказ менеджера: текст (русский, для журнала и командной строки) и машинная часть — code (стабильное слово,
 * docs/errors.md) и args (объект JSON со строковыми подстановками). У pm_errf кода нет. */
struct pm_err { char msg[4096]; char code[64]; char args[1024]; };
int pm_errf(struct pm_err *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* Отказ с кодом: kv — пары «имя, значение» (PMA("id", id, …) или NULL), по порядку подстановок fmt. */
#define PMA(...) ((const char *const[]){ __VA_ARGS__, NULL })
int pm_errc(struct pm_err *e, const char *code, const char *const *kv, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
/* Перенести отказ целиком (текст, код, подстановки) из src в dst. */
int pm_errcopy(struct pm_err *dst, const struct pm_err *src);
/* Добавить подстановку к отказу. */
void pm_err_arg(struct pm_err *e, const char *name, const char *val);
/* Число и восьмеричный режим строкой для подстановок (буферы по кругу, живут до восьми вызовов). */
const char *pm_itoa(long long v);
const char *pm_oct(unsigned v);
/* Отказ как объект JSON одной строкой с ok:false, error, code, args. */
void pm_err_json(const struct pm_err *e, char *buf, size_t cap);

/* ---- пути (pmutil.c). Подмены — переменные окружения STEER_PLUGIN_* (стенды). ---- */
const char *pm_root(void);      /* /usr/lib/steer/plugins            STEER_PLUGIN_DIR */
const char *pm_etc(void);       /* /etc/steer/plugins                STEER_PLUGIN_ETC */
const char *pm_keys(void);      /* /usr/share/steer/keys             STEER_PLUGIN_KEYS */
const char *pm_seed(void);      /* /usr/share/steer/seed             STEER_PLUGIN_SEED */
const char *pm_run(void);       /* /var/run/steer/plugins            STEER_PLUGIN_RUN */
const char *pm_tmp(void);       /* /tmp/steer-plugins                STEER_PLUGIN_TMP */
const char *pm_keepd(void);     /* /lib/upgrade/keep.d/steer-plugins STEER_PLUGIN_KEEPD */
const char *pm_sysroot(void);   /* ""  — корень путей steer.links     STEER_PLUGIN_SYSROOT */
/* Путь «a/b» в куче (die при нехватке памяти — это точка входа команды). */
char *pm_path(const char *a, const char *b);
char *pm_strdup(const char *s);
char *pm_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void *pm_alloc(size_t n);
void *pm_realloc(void *p, size_t n);

/* ---- файлы ---- */
char *pm_read(const char *path, size_t *n);                  /* NULL — нет файла; в конце '\0' */
int pm_write_atomic(const char *path, const void *d, size_t n, unsigned mode);
int pm_mkdirs(const char *path);
int pm_rmrf(const char *path);
int pm_exists(const char *path);
int pm_is_dir(const char *path);
unsigned long long pm_du(const char *path);                  /* сумма размеров файлов */
/* Свободно на разделе пути, байт. Подмена STEER_PLUGIN_FREE=«корень[:tmp]» — для стенда. */
unsigned long long pm_free(const char *path, int is_tmp);
/* «1,8 МБ», «12 КБ». */
void pm_human(unsigned long long b, char *out, size_t n);
/* Блокировка менеджера (flock на <root>/.lock). 0 — взята; -1 — занята (busy). */
int pm_lock(void);
void pm_unlock(void);

/* ---- время ---- */
time_t pm_parse_time(const char *s);                         /* RFC 3339 UTC; -1 — не время */
void pm_time_str(time_t t, char *out, size_t n);             /* 2026-11-02T10:00:00Z */

/* ---- JSON: чтение ---- */
struct ydoc *pm_json_load(const char *path, struct pm_err *e);   /* NULL: e->msg пуст — файла нет */
struct ydoc *pm_json_parse(const char *buf, size_t n, const char *name, struct pm_err *e);
const char *yn_str(const struct ynode *map, const char *key);   /* скаляр не null, иначе NULL */
int yn_bool(const struct ynode *map, const char *key, int dflt);
long yn_long(const struct ynode *map, const char *key, long dflt);
int yn_is_str(const struct ynode *n);
/* Деревья равны (у отображений порядок ключей не важен, у скаляров — значение). */
int yn_equal(const struct ynode *a, const struct ynode *b);

/* ---- JSON: запись ---- */
struct jw { FILE *f; int comma; };
void jw_init(struct jw *w, FILE *f);
void jw_obj(struct jw *w);
void jw_end(struct jw *w);          /* закрыть объект */
void jw_arr(struct jw *w);
void jw_aend(struct jw *w);         /* закрыть массив */
void jw_key(struct jw *w, const char *k);
void jw_str(struct jw *w, const char *s);   /* NULL — null */
void jw_int(struct jw *w, long long v);
void jw_bool(struct jw *w, int v);
void jw_null(struct jw *w);
void jw_raw(struct jw *w, const char *json);   /* готовое значение JSON как есть */
void jw_node(struct jw *w, const struct ynode *n);   /* NULL — null */
void jw_kstr(struct jw *w, const char *k, const char *s);
void jw_kint(struct jw *w, const char *k, long long v);
void jw_kbool(struct jw *w, const char *k, int v);
void jw_knode(struct jw *w, const char *k, const struct ynode *n);

/* ---- semver (pmver.c) ---- */
int pm_ver_cmp(const char *a, const char *b);               /* как strcmp; неразбираемое — меньше */
int pm_ver_ok(const char *v);                               /* похоже на semver */
/* Версия v в диапазоне r (npm: = ^ ~ >= > <= < пробел «и», || «или», * x). -1 — диапазон не
 * разобрался. */
int pm_range_match(const char *r, const char *v);
long pm_ver_major(const char *v);

/* ---- состояние (pmstate.c) ---- */
struct pm_bad { char *ver, *why; };
struct pm_inst {
    char *id, *repo, *version, *arch, *variant;
    char *state;                 /* installed, enabled, disabled, failed, pending */
    char *why;
    int auto_update;
    char *pinned;
    struct pm_bad *bad; size_t nbad;
    char **system; size_t nsystem;
    char *installed_at, *from;
    int unsigned_;
    int disabled_by_human;
};
struct pm_state {
    struct pm_inst *v; size_t n;
    size_t cap;                  /* место в v: растёт вдвое */
    size_t *hx, hcap;            /* хеш id -> индекс+1 в v (0 — пусто), hcap — степень двойки */
    char **system_ours; size_t nsys;
    char *auto_window;           /* «03:00-05:00» */
    char *last_check, *next_check;
    long retry_s;                /* пауза повтора плагинов pending, с */
};
int pm_state_load(struct pm_state *s, struct pm_err *e);
int pm_state_save(const struct pm_state *s, struct pm_err *e);
void pm_state_free(struct pm_state *s);
struct pm_inst *pm_state_find(struct pm_state *s, const char *id);
struct pm_inst *pm_state_add(struct pm_state *s, const char *id);
void pm_state_del(struct pm_state *s, const char *id);
const char *pm_bad_why(const struct pm_inst *p, const char *ver);
void pm_bad_set(struct pm_inst *p, const char *ver, const char *why);
size_t pm_bad_clear_reload(struct pm_state *s);
void pm_sys_ours_add(struct pm_state *s, const char *pkg);
void pm_inst_set(char **field, const char *v);

struct pm_repo {
    char *name, *url, *file;
    char **mirrors; size_t nmirrors;
    int official, auto_update, seed;
    long priority;
    char **keys; size_t nkeys;
    char *last_generated;
    /* индекс (pmindex.c) */
    struct ydoc *idx;
    const struct ynode *iroot;
    char *idx_err;
    int idx_fresh;               /* загружен из сети в этом запуске */
    struct pm_err *idx_miss;     /* без сети индекс уже не нашёлся в этом запуске — причина */
};
struct pm_repos { struct pm_repo *v; size_t n; };
int pm_repos_load(struct pm_repos *r, struct pm_err *e);
void pm_repos_free(struct pm_repos *r);
struct pm_repo *pm_repo_find(struct pm_repos *r, const char *name);
int pm_repo_save(const struct pm_repo *p, struct pm_err *e);
/* Семя как репозиторий (официальный, база — каталог семени). NULL — семени нет. */
struct pm_repo *pm_seed_repo(void);

/* Доверенные ключи: role — «index», «protocols», «plugins» (официальные) или NULL и repo —
 * ключи стороннего репозитория. Отозванные (keys/revoked) не входят. */
struct pm_keyset { struct sigv_key *k; size_t n; char **revoked; size_t nrev; };
void pm_keys_role(struct pm_keyset *ks, const char *role);
void pm_keys_repo(struct pm_keyset *ks, const struct pm_repo *r);
void pm_keys_all(struct pm_keyset *ks);       /* все доверенные ролей архивов и сторонние — для --file */
void pm_keys_free(struct pm_keyset *ks);
int pm_key_revoked(const char *hex);
/* Проверка подписи (одного или нескольких блоков) над msg. 0 — годится; иначе текст в e:
 * what — что подписано («индекс репозитория x», «MANIFEST vless»). */
int pm_sig_check(const struct pm_keyset *ks, const char *sig, size_t sig_n, const void *msg,
                 size_t msg_n, const char *what, struct pm_err *e);

/* ---- цель отбора ---- */
struct pm_target { char *core, *api, *abi, *host, *splify2, *arch; };
void pm_target_load(struct pm_target *t);

/* ---- индекс и отбор (pmindex.c) ---- */
/* Загрузить индекс репозитория: refresh — из сети (с ETag), иначе кэш; не вышло — кэш; у
 * официального — ещё индекс семени. 0 — индекс есть (r->iroot). */
int pm_index_get(struct pm_repo *r, int refresh, struct pm_err *e);
const struct ynode *pm_index_plugin(const struct pm_repo *r, const char *id);

struct pm_cand {
    struct pm_repo *repo;
    const char *id, *version;
    const struct ynode *plug, *ver, *asset;
    char variant[16];            /* full, lite */
    char asset_key[96];
};
/* Отбор версии (index.md, «Отбор»): range — диапазон (NULL — любой), exact — точная версия (NULL —
 * самая новая годная); below — только версии ниже этой (перебор при неразрешённых зависимостях).
 * 0 — найдена (*c); -1 — причина в e (от самой новой версии). */
struct pm_ctx;
int pm_select(struct pm_ctx *x, struct pm_repo *r, const char *id, const char *range,
              const char *exact, const char *variant, const char *below, struct pm_cand *c,
              struct pm_err *e);
/* Причина несовместимости версии ver (NULL — совместима). */
void pm_compat_err(struct pm_err *e, const char *id, const char *ver, const char *cw);
const char *pm_compat_why(const struct pm_target *t, const struct ynode *compat, char *buf,
                          size_t n);

/* ---- общий контекст команды ---- */
struct pm_ctx {
    struct pm_state st;
    struct pm_repos repos;
    struct pm_target tg;
    int json;
    const char *by;              /* human, auto, migrate */
    int quiet;
    int no_daemon;               /* не звать демон (без сокета) */
    int allow_bad;               /* отбор берёт и версии из bad_versions (явная версия) */
    int defer;                   /* группа: проверка здоровья откладывается до конца группы (pm_opts.group) */
    void *undo;                  /* записи отката группы (pminst.c) */
    size_t nundo;
    struct pm_err before_err;    /* ошибка plugin-reload до установки (before_bad) */
    int before_bad;
    const char *pkg_tx;          /* --pkg ИМЯ: менеджер зовёт скрипт этого системного пакета изнутри
                                    транзакции apk/opkg — пакет считается стоящим, база заперта */
    struct pm_mslot *mc;         /* кэш манифестов команд только чтения (pm_mcache_on): хеш по id */
    size_t mcap, mn;
    int mcache;
};
void pm_progress(struct pm_ctx *x, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* ---- установка (pminst.c) ---- */
struct pm_req { const char *id, *version; };
struct pm_opts {
    int seed_only;               /* только из семени */
    int allow_seed;              /* сеть не вышла — семя */
    int allow_bad;               /* явная версия из bad_versions */
    const char *file;            /* установка из файла */
    int unsigned_ok;             /* --unsigned */
    int update;                  /* обновление: только из своего репозитория */
    int auto_;                   /* фоновое */
    int group;                   /* весь план одной группой: одна проверка здоровья, откат всей группы */
};
struct pm_done { char *id, *version, *from, *old; int updated; };
struct pm_result { struct pm_done *v; size_t n; char **failed; size_t nfailed; };
int pm_install(struct pm_ctx *x, const struct pm_req *req, size_t nreq, const struct pm_opts *o,
               struct pm_result *res, struct pm_err *e);
int pm_remove(struct pm_ctx *x, const char *id, int force, int purge, struct pm_err *e);
int pm_set_enabled(struct pm_ctx *x, const char *id, int on, struct pm_err *e);
void pm_result_free(struct pm_result *r);
int pm_keepd_write(struct pm_ctx *x);
/* steer.links (steer-api 1.3): пути в системе, которые менеджер ведёт, пока плагин стоит. Восстановить
 * недостающие у стоящего плагина (ensure). 0 — на месте; -1 — путь занят чужим, причина в e. */
int pm_links_repair(struct pm_ctx *x, const char *id, struct pm_err *e);
int pm_file_sha256(const char *path, unsigned char out[32], unsigned long long *size);
/* Скачать url в память (pmindex.c). 0 — ответ 2xx; why — причина отказа. */
int pm_http_mem(const char *url, char **body, size_t *n, char *why, size_t wn);
/* Манифест стоящего плагина (NULL — не читается). */
struct ydoc *pm_manifest(const char *id);
/* Манифест для чтения: при включённом кэше (команды без записи — list, status) каждый plugin.json
 * разбирается один раз за процесс и *own остаётся NULL; без кэша *own — документ, его освобождает
 * вызывающий. NULL — манифест не читается. */
struct pm_mslot { char *id; struct ydoc *d; };
const struct ynode *pm_manifest_ro(struct pm_ctx *x, const char *id, struct ydoc **own);
void pm_mcache_on(struct pm_ctx *x);
void pm_mcache_free(struct pm_ctx *x);

/* Демон: перечитать плагины и спеку (plugin-reload). 0 — прошло или демона нет; -1 — отказ, текст в e. */
int pm_daemon_reload(struct pm_ctx *x, struct pm_err *e);
void pm_event(struct pm_ctx *x, const char *id, const char *state, const char *version,
              const char *from, const char *why);

/* Главная: `steer plugin <действие> …`. */
int pm_main(int argc, char **argv);

#endif
