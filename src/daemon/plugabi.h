/* ЭТО КОПИЯ include/steer/plugin.h ИЗ plugin-sdk (контракт .so-плагинов, steer-abi v1); правится только
 * там, а здесь меняется только имя охранного макроса (в дереве steer свой заголовок plugin.h — kinds/plugin.h,
 * имена заголовков в src уникальны). tests/abimatch.sh сверяет копию с оригиналом.
 *
 * steer-abi v1: .so плагина в процессе steerd. Описание и правила — docs/steer-abi.md.
 *
 * Плагин НЕ связывается с libsteer.so.<версия> и не берёт её символов: всё, что ему даёт ядро, — таблица
 * struct steer_host_v1, которую ядро передаёт в init. Экспорт плагина — ровно один символ,
 * steer_plugin_v1_entry; остальное скрыто (-fvisibility=hidden, файл версий с local: *).
 *
 * Стабильность: в пределах STEER_ABI_MAJOR структуры только растут в конец, о наличии поля говорит
 * size. Указатель на функцию, которой у этой стороны нет (size меньше), читать нельзя: проверяйте
 * STEER_HAS(p, поле). */
#ifndef STEER_PLUGABI_H
#define STEER_PLUGABI_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STEER_ABI_MAJOR 1
#define STEER_ABI_MINOR 0

/* Есть ли поле f в структуре *p версии, которую прислала другая сторона. */
#define STEER_HAS(p, f) \
    ((p) && (p)->size >= offsetof(__typeof__(*(p)), f) + sizeof((p)->f))

/* Отпечаток сборки: то, что меняет раскладку структур, кроме версии ABI. Несовпадение — .so не
 * грузится (как NGX_MODULE_SIGNATURE у nginx). */
#define STEER_ABI_FP_PTR64   (1u << 0)   /* sizeof(void *) == 8 */
#define STEER_ABI_FP_TIME64  (1u << 1)   /* sizeof(time_t) == 8 (musl ≥ 1.2 — всегда) */
#define STEER_ABI_FP_LE      (1u << 2)   /* little-endian */
#define STEER_ABI_FINGERPRINT                                                    \
    ((sizeof(void *) == 8 ? STEER_ABI_FP_PTR64 : 0u) |                          \
     (sizeof(time_t) == 8 ? STEER_ABI_FP_TIME64 : 0u) |                      \
     (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ? STEER_ABI_FP_LE : 0u))

/* Непрозрачные: устройство их знает только ядро. */
struct steer_host;   /* ядро для этого плагина: передаётся в каждый вызов */
struct steer_out;    /* выход спеки, живёт до конца вызова */
struct steer_spec;   /* спека в памяти, живёт до конца вызова */

/* Уровни журнала. */
enum steer_log { STEER_LOG_ERR = 3, STEER_LOG_WARN = 4, STEER_LOG_INFO = 6, STEER_LOG_DEBUG = 7 };

/* События дескриптора — как у epoll. */
#define STEER_FD_IN  0x001u
#define STEER_FD_OUT 0x004u
#define STEER_FD_ERR 0x008u
#define STEER_FD_HUP 0x010u

typedef void steer_fd_cb(void *arg, int fd, uint32_t events);
typedef void steer_timer_cb(void *arg);
/* Ответ разрешения имени: rc 0 — есть адреса (addrs — массив sockaddr_storage, n штук); иначе
 * код getaddrinfo. */
typedef void steer_resolve_cb(void *arg, int rc, const void *addrs, size_t n);
/* Ответ HTTPS: status — код HTTP или -1 (сеть, TLS; why — причина); body — тело (не строка). */
typedef void steer_http_cb(void *arg, int status, const char *body, size_t len, const char *why);

struct steer_http_req {
    uint32_t size;
    const char *method;          /* "GET", "POST" */
    const char *url;             /* только https:// */
    const char *const *headers;  /* "Имя: значение", NULL в конце; может быть NULL */
    const char *body;
    size_t body_len;
    uint32_t timeout_ms;         /* 0 — 30 с */
    const char *via_out;         /* через какой выход (метка сокета); NULL — напрямую */
};

/* ---- ядро → плагин ------------------------------------------------------------------------ */
struct steer_host_v1 {
    uint32_t size;
    uint16_t abi_major, abi_minor;
    const char *core_version;    /* "2.1.0" */
    const char *api_version;     /* steer-api ядра, "1.0" */

    /* журнал: строка уходит с приставкой steer[<id>] */
    void (*log)(struct steer_host *, int level, const char *fmt, ...)
        __attribute__((format(printf, 3, 4)));
    void (*vlog)(struct steer_host *, int level, const char *fmt, va_list ap);

    /* память, которую ядро освобождает само (ответы out_json, status и т. п.) */
    void *(*alloc)(size_t n);
    void (*free)(void *p);

    /* ---- спека: только чтение, указатели живут до конца вызова ---- */
    const struct steer_out *(*out_by_name)(struct steer_host *, const struct steer_spec *, const char *name);
    size_t (*out_count)(struct steer_host *, const struct steer_spec *);
    const struct steer_out *(*out_at)(struct steer_host *, const struct steer_spec *, size_t i);
    const char *(*out_name)(const struct steer_out *);
    const char *(*out_kind)(const struct steer_out *);           /* "awg", "tunnel:vless" */
    const char *(*out_keys_json)(const struct steer_out *);      /* ключи вида, JSON-объект */
    const char *(*out_conf_json)(const struct steer_out *);      /* то же, что файл {conf} (steer-api.md, 1.4) */
    const char *(*out_device)(const struct steer_out *);
    uint32_t (*out_mark)(const struct steer_out *);
    int (*out_table)(const struct steer_out *);
    const char *(*out_owner)(const struct steer_out *);          /* "<plugin>/<выход>" или NULL */

    /* ---- цикл событий демона: свои дескрипторы и таймеры, без своих потоков на цикле ---- */
    int (*watch_fd)(struct steer_host *, int fd, uint32_t events, steer_fd_cb *, void *arg);
    void (*unwatch_fd)(struct steer_host *, int fd);
    int (*timer)(struct steer_host *, uint32_t ms, steer_timer_cb *, void *arg);   /* id ≥ 0 */
    void (*timer_cancel)(struct steer_host *, int id);

    /* ---- сеть ---- */
    /* SO_MARK сокету, чтобы его трафик шёл подложкой выхода out (или мимо каналов, out == NULL). */
    int (*sock_mark)(struct steer_host *, int fd, const struct steer_out *out);
    /* Разрешение имени рабочим потоком ядра (gaiw); ответ — на цикле демона. */
    int (*resolve)(struct steer_host *, const char *host, uint16_t port, int family,
                   steer_resolve_cb *, void *arg);
    /* HTTPS-клиент ядра (TLS 1.3, корни ядра); ответ — на цикле демона. */
    int (*http)(struct steer_host *, const struct steer_http_req *, steer_http_cb *, void *arg);

    /* ---- nft: правило текстом в цепочку слота plugin_<id>_<слот>; зовётся только из emit ---- */
    int (*nft_rule)(struct steer_host *, const char *slot, const char *rule);

    /* ---- события сокета (ev без "v" и "ev": ядро допишет) ---- */
    int (*emit)(struct steer_host *, const char *ev, const char *fields_json);

    /* ---- ресурсы (steer-api.md, 6): kind — "mark", "queue", "port", "table"; i — номер ---- */
    int (*resource)(struct steer_host *, const char *kind, unsigned i, uint32_t *out);

    /* ---- состояние выхода для status (outputs.<имя>.plugin) ---- */
    int (*set_status)(struct steer_host *, const struct steer_out *, const char *json);

    /* ---- просьбы к сторожу ---- */
    void (*wake_watch)(struct steer_host *);                       /* внеочередной проход */
    int (*member_verdict)(struct steer_host *, const struct steer_out *, int ok);   /* -1/0/1 */

    /* ---- каталоги ---- */
    const char *plugin_dir, *conf_dir, *state_dir;
};

/* ---- плагин → ядро: вид выхода ---------------------------------------------------------- */
/* Биты caps — те же имена, что в манифесте (kinds[].caps). */
#define STEER_CAP_DEVICE       (1u << 0)
#define STEER_CAP_MARK         (1u << 1)
#define STEER_CAP_CTMARK       (1u << 2)
#define STEER_CAP_ENGINE_OWNED (1u << 3)
#define STEER_CAP_SELF_NAT     (1u << 4)
#define STEER_CAP_OVER         (1u << 5)
#define STEER_CAP_TCP_PROBE    (1u << 7)
#define STEER_CAP_FLOW_UDP     (1u << 8)
#define STEER_CAP_IPV6         (1u << 9)
#define STEER_CAP_TCP_REDIR    (1u << 10)

struct steer_kind_v1 {
    uint32_t size;
    const char *name;            /* как kinds[].name манифеста */
    uint32_t caps;
    /* Проверка выхода после схемы ключей: 0 — годится; -1 — отказ, текст в why. Зовётся в шаге
     * подготовки спеки (ребёнок apply-plan), не на цикле демона. */
    int (*check)(struct steer_host *, const struct steer_spec *, const struct steer_out *,
                 char *why, size_t n);
    /* Правила вида: host->nft_rule(...) на каждый нужный слот. */
    void (*emit)(struct steer_host *, const struct steer_spec *, const struct steer_out *);
    /* Здоровье устройства: 1 — живо, 0 — нет, -1 — общая проба ядра. Не блокирует. */
    int (*health)(struct steer_host *, const struct steer_spec *, const struct steer_out *, const char *dev);
    /* Починка молчащего устройства; не блокирует (имена — host->resolve заранее). */
    int (*revive)(struct steer_host *, const struct steer_spec *, const struct steer_out *, const char *dev);
    /* Поднять, перенастроить, снять устройства всех выходов вида после apply (как awg_apply_all). */
    int (*apply_all)(struct steer_host *, const struct steer_spec *, char *why, size_t n);
    int (*down_all)(struct steer_host *, const struct steer_spec *);
    /* Поля выхода в status: JSON-объект в памяти host->alloc; NULL — нечего. */
    char *(*status)(struct steer_host *, const struct steer_spec *, const struct steer_out *);
    /* Разворот (steer-api.md, 3.3): ответ — JSON того же вида, что stdout хука expand. */
    int (*expand)(struct steer_host *, const char *out_json, char **frag_json, char *why, size_t n);
};

/* ---- плагин → ядро: регистрация -------------------------------------------------------- */
struct steer_plugin_v1 {
    uint32_t size;
    uint16_t abi_major, abi_minor;   /* с какими собран: STEER_ABI_MAJOR, STEER_ABI_MINOR */
    uint32_t fingerprint;            /* STEER_ABI_FINGERPRINT */
    const char *id, *version;        /* совпадают с манифестом */

    /* После dlopen, на цикле демона. 0 — готов; иначе плагин failed с причиной why. */
    int (*init)(struct steer_host *, const struct steer_host_v1 *, char *why, size_t n);
    /* Только при остановке steerd: musl библиотеки не выгружает. */
    void (*fini)(struct steer_host *);
    const struct steer_kind_v1 *const *kinds;   /* NULL в конце; может быть NULL */
    /* Хук pre-apply (steer-api.md, 3.4): out_json — в памяти host->alloc. */
    int (*pre_apply)(struct steer_host *, const char *spec_json, char **out_json, char *why, size_t n);
    /* Событие сокета строкой JSON (как у subscribe). */
    void (*on_event)(struct steer_host *, const char *ev_json);
    /* Свои команды сокета (commands[].ctl с prog "so"): ответ — JSON в host->alloc, код как у подкоманды. */
    int (*ctl)(struct steer_host *, const char *cmd, const char *const *argv, size_t argc,
               const char *body, size_t body_len, char **resp_json);
};

/* Единственный экспорт .so плагина. host_major/host_minor — ABI ядра; вернуть NULL — «не могу». */
typedef const struct steer_plugin_v1 *steer_plugin_v1_entry_fn(uint16_t host_major, uint16_t host_minor);
#define STEER_PLUGIN_ENTRY "steer_plugin_v1_entry"

#ifdef __cplusplus
}
#endif
#endif
