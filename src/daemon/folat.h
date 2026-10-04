/* Замер групп pick: latency (urltest) — запись замеров, замер одного члена по IPv4 и IPv6 и
 * расписание замеров своими таймерами цикла демона. Устройство и доводы — в шапке folat.c. */
#ifndef STEER_FOLAT_H
#define STEER_FOLAT_H

#include <stddef.h>

#include "spec.h"
#include "fostate.h"

struct loop;

/* Срок одного запроса проверки — на весь замер члена, с DNS. */
#define FOLAT_TIMEOUT_MS 5000
/* Умолчания группы без tolerance и interval — числа sing-box (interval 3m, tolerance 50); значения
 * — у группы (kind.h), здесь прежние имена. Допуск и интервал группы с умолчаниями —
 * group_tolerance_ms и group_interval_s. */
#define FOLAT_TOLERANCE_MS GROUP_TOL_DEFAULT_MS
#define FOLAT_INTERVAL_S   GROUP_INT_DEFAULT_S
/* Первый повтор замера, когда у живого члена он не удался (DNS ещё не поднялся, туннель только
 * встал, часы без NTP у HTTPS): не ждать целого interval, а повторить через столько секунд, дальше
 * вдвое реже, но не дольше самого interval. Без этого неудавшийся замер держал группу «по порядку» до
 * следующего срока — у interval в час это час. */
#define FOLAT_RETRY_S      15

/* ---- запись latency ------------------------------------------------------------------------
 *
 * Строка на член: `группа ключ мс отметка`, у группы, меренной по обоим семействам, ещё
 * ` мс4 мс6`. мс — задержка, по которой выбирает сторож (-1 — не измерилась); отметка —
 * CLOCK_MONOTONIC в секундах; ключ — fog_lat_key (имя именованного члена, устройство
 * безымянного). */
struct folat_rec {
    int ms;
    int ms4, ms6;       /* -2 — по семействам не мерили */
    long at;
};
/* Замер члена key группы out. 1 — есть, *r заполнен. */
int folat_rec_get(struct fo_store *st, const char *out, const char *key, struct folat_rec *r);
/* Замеры n членов m группы out — вместо прежних строк группы, остальные группы на месте.
 * keep_failed = 0 — член без замера (ms < 0) строки не получает (прежняя запись `steer failover`,
 * байт в байт); 1 — получает строку с -1: демон так помнит, что член мерили и он не ответил, и
 * проход не меряет его заново до срока расписания. */
void folat_rec_put(struct fo_store *st, const char *out, const struct output *const *m,
                   const struct folat_rec *r, size_t n, int keep_failed);

/* ---- замер члена ---------------------------------------------------------------------------- */

/* Мерить ли группу go ещё и по IPv6: группа v2 (именованные члены — у каждого своя метка и своё
 * правило IPv6), и каждый живой член (alive — маска) несёт IPv6 (KC_IPV6). */
int folat_want_v6(const struct spec *sp, const struct output *go, const unsigned char *alive);

struct folat_m;
/* Итог замера члена: ms4, ms6 — мс (-1 — не измерилось; ms6 = -2 — по IPv6 не мерили). */
typedef void (*folat_m_cb)(void *arg, int ms4, int ms6);
/* Замер члена m группы go через его устройство dev (m — выход спеки sp: у именованного — его
 * метка, у безымянного члена пула v1 — привязка к dev). v6 — ещё и по IPv6, одновременно с IPv4.
 * hs — источник здоровья помощников (туннель xsteer, поднятый netifd, не меряется). NULL — итог
 * сразу в *ms4 и *ms6, обратного вызова не будет; иначе cb позовётся один раз, если не отменено. */
struct folat_m *folat_member(struct loop *l, const struct spec *sp, const struct output *go,
                             const struct output *m, const char *dev, struct fo_hsrc *hs, int v6,
                             folat_m_cb cb, void *arg, int *ms4, int *ms6);
void folat_member_cancel(struct folat_m *fm);

/* Задержки по записям в выбор: ms4/ms6 — замеры, score — по чему выбирать (group_latency_score). */
void folat_score(const int *ms4, const int *ms6, size_t n, int v6, int *score);

/* ---- расписание (демон) ----------------------------------------------------------------------- */

struct folat;
struct folat_conf {
    struct loop *l;
    struct fo_store *st;                              /* память сторожа */
    /* Спека в памяти демона прямо сейчас (NULL — нет): берётся на каждый шаг, а не хранится, —
     * apply посреди замера заменяет её. */
    const struct spec *(*spec)(void *arg);
    struct fo_hsrc *(*hs)(void *arg);                 /* источник здоровья помощников */
    fo_traffic_fn traffic;                            /* трафик через группу (idle_timeout) */
    /* Замер показал, что выбор группы сменился бы: внеочередной проход сторожа. */
    void (*kick)(void *arg, const char *group);
    void *arg;
};
struct folat *folat_new(const struct folat_conf *c);
/* Сверить таймеры с группами спеки: новой группе latency — таймер на её интервал, ушедшей —
 * снять (с идущим замером). Звать после каждого прохода и при включении. */
void folat_sync(struct folat *f);
/* Сторож уснул (движок выключен): все таймеры и замеры сняты. folat_sync заводит их заново. */
void folat_stop(struct folat *f);
/* Сколько замеров групп сделано с начала (стенд и журнал). */
unsigned long folat_rounds(const struct folat *f);

#endif
