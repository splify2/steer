/* Пул узлов выхода: N активных узлов подписки сразу, раздача новых соединений между ними и слежка
 * за каждым. Подробности — в pool.c. */
#ifndef STEER_POOL_H
#define STEER_POOL_H
#include <stddef.h>
#include "dialer.h"
#include "stack.h"

/* Как раздаются новые соединения — ключ `by` выхода, enum group_by (spec.h), те же значения и имена,
 * что у `by` группы balance (group_by_name):
 *   BY_CONNECTION  — каждое новое соединение на случайный живой узел (поровну);
 *   BY_SITE        — по адресу назначения: сайт на одном узле;
 *   BY_SITE_CLIENT — по паре «клиент, адрес назначения»: сайт одного клиента на одном узле. */

/* Что пул спрашивает у протокола. ops — дайлер протокола, у которого ctx — узел подписки. */
struct pool_proto {
    const struct dialer_ops *ops;
    /* Проверка узла — та же мера, по которой он выбран при подъёме (у VLESS — vless_probe):
     * 0 — жив, иначе why — причина для человека. */
    int (*probe)(const void *node, int timeout_s, char *why, size_t why_n);
    const char *(*name)(const void *node);
    /* Приставка файла состояния: <каталог состояния>/<tag>-<выход> (status, diag). */
    const char *tag;
    /* Поля протокола в файл состояния — готовым куском JSON (`"protocol":"trojan"`); NULL — нет. */
    const char *extra;
};

/* Умолчания ключей выхода (docs/spec-v2.md): период проверки узла и порог молчания, секунды. */
#define POOL_INTERVAL_S 60
#define POOL_SILENCE_S  20
/* pick: latency — период замера всех кандидатов (умолчание `interval` при этом выборе), как у url-test
 * sing-box, и допуск по умолчанию, мс — как у группы latency. */
#define POOL_LAT_INTERVAL_S 180
#define POOL_LAT_TOLERANCE_MS 50
enum pool_pick { POOL_PICK_ORDER = 0, POOL_PICK_LATENCY = 1 };

struct pool_cfg {
    const struct pool_proto *proto;
    /* Узлы подписки: узел i — nodes + i * stride; живут до конца процесса. */
    const void *nodes;
    size_t stride;
    /* Кандидаты в порядке предпочтения (индексы узлов, out_node_list и фильтры модуля) — живут до
     * конца процесса. */
    const int *sel;
    size_t sel_n;
    int first;          /* узел, выбранный при подъёме (индекс) */
    int checked;        /* first проверен при подъёме (перебор), а не назван человеком */
    int active;         /* сколько узлов держать активными (ключ `active`, 1 — прежнее поведение) */
    int by;             /* enum group_by */
    int interval_s;     /* период проверки каждого узла */
    int silence_s;      /* порог молчания узла на живом соединении (struct dialer), 0 — нет */
    int pick;           /* enum pool_pick: по порядку предпочтения или самые быстрые */
    int tolerance_ms;   /* pick: latency — допуск смены узла, мс; < 0 — умолчание */
    const char *out;    /* имя выхода: файл состояния */
};

/* Поднять туннель выхода o на пуле узлов: стек с дайлером пула (stack_run), слежка за узлами, когда
 * устройство поднято, и ready модуля после неё (может быть NULL). Код выхода процесса — как у
 * stack_run. */
int pool_run(struct output *o, const struct pool_cfg *pc, stack_ready_fn ready, void *arg);

#endif
