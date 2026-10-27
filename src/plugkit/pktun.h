/* Ключи туннеля по подписке у программ протоколов (vless, hysteria2, протоколы прокси): общие ключи
 * схем их видов — subscription, nodes, transport, insecure, exclude, exclude_name, only и ключи пула
 * active, by, interval, silence, pick, tolerance (plugins/<id>/kinds/<вид>.schema.json).
 *
 * Типы и границы ключей проверила схема ядра; сочетания ключей, которых схема не выражает (by без
 * active больше 1, active больше выбранных узлов, tolerance без pick: latency, страна и в only, и в
 * exclude, silence от 1 до 4), проверяет pk_tun_check — её зовут хук check вида (при подготовке
 * спеки) и помощник при старте. */
#ifndef STEER_PKTUN_H
#define STEER_PKTUN_H

#include <stddef.h>

#include "nodesel.h"
#include "plugkit.h"

/* Пул узлов: ноль — ключа нет, действует умолчание пула (src/tunnel/pool.c); silence_s -1 —
 * порог выключен явно (`silence: 0`). */
struct pk_pool {
    int active, by, interval_s, silence_s, pick, tolerance_ms, tol_set, by_set;
};

struct pk_tun {
    const char *sub_file;       /* subscription — путь (x-path), строка {conf} */
    int *nodes;                 /* выбранные номера узлов по порядку предпочтения; куча */
    size_t nodes_n;
    unsigned transports;        /* биты TT_* (только у vless) */
    int insecure;
    struct node_exclude excl;   /* массивы в куче */
    struct pk_pool pool;
};

/* Транспорты узла — имена как в ссылке узла (type=) и биты для pk_tun.transports. */
enum { TT_TCP = 1u << 0, TT_GRPC = 1u << 1, TT_XHTTP = 1u << 2, TT_WS = 1u << 3,
       TT_HTTPUPGRADE = 1u << 4, TT_COUNT = 5 };
unsigned pk_transport_bit(const char *name);

/* Ключи туннеля из {conf}. 0 — готово; -1 — отказ, причина в err (без имени выхода). */
int pk_tun_load(const struct pk_out *o, struct pk_tun *t, char *err, size_t errn);
/* Сочетания ключей (см. шапку). 0 — годится; -1 — причина в err. */
int pk_tun_check(const struct pk_tun *t, char *err, size_t errn);

/* Порядок перебора узлов подписки: выбранные номера (в пределах usable) или все по порядку. */
size_t pk_node_list(const struct pk_tun *t, size_t usable, int *dst, size_t max);
/* Узел назван человеком (ровно один номер): перебора нет. */
int pk_node_named(const struct pk_tun *t);

/* Хук check вида туннеля (steer-api.md, 3.2): stdin — {"output":{"keys":…}}, отказ — код 2 и строка
 * в stderr. extra — свои проверки протокола поверх общих (NULL — нет). */
int pk_tun_check_hook(int (*extra)(const struct pk_tun *t, const struct pk_out *o, char *err, size_t errn));

/* Строка diag в файл состояния (steer-api.md, 2.3): {"id","verdict","what","why"} через запятую. */
void pk_diag_json(char **buf, const char *id, const char *verdict, const char *what, const char *why);

#endif
