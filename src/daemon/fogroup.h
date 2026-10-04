/* Группы в сторожe и команда select — устройство и доводы в шапке fogroup.c. */
#ifndef STEER_FOGROUP_H
#define STEER_FOGROUP_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "spec.h"
#include "fostate.h"

/* Порядок обхода прохода: цель `over` и члены именованной группы — раньше того, кто от них
 * зависит; внутри круга — порядок спеки. Для спеки без таких групп это ровно прежний порядок по
 * глубине over. Пишет номера в ord (не больше sp->out_n; место выделяет вызывающий), возвращает, сколько. */
size_t fog_order(const struct spec *sp, size_t *ord);

/* Выбор человека у группы pick: manual: номер члена по записи `select` (член всё ещё в группе),
 * иначе default, иначе первый. */
int fog_manual_pick(const struct spec *sp, struct fo_store *st, const struct output *g);

/* ВЫБОР ЧЛЕНА ГРУППЫ v2 ПО УЖЕ ИЗВЕСТНЫМ ПРИГОВОРАМ ЧЛЕНОВ — без проб и без замеров. alive —
 * маска живых членов (бит на член по порядку members), cur — член, который несёт трафик сейчас
 * (-1 — никто: записи нет или группа в отказе). Возврат — номер выбранного члена или -1: живого,
 * которого можно взять, нет, и группа применяет свой on_fail. Правила — те же, что у прохода:
 *   manual  — выбор человека (fog_manual_pick), если он жив; иначе -1, а не другой член;
 *   balance — первый живой (таблица группы; соединения раздаёт карта по alive);
 *   order   — живой текущий держится (возврат на верхний — дело гистерезиса прохода), иначе
 *             первый живой;
 *   latency — живой текущий держится; иначе лучший по последнему замеру среди живых (с допуском,
 *             group_latency_pick), а без замеров — первый живой.
 * Зовут её проход (manual и balance: там это всё решение) и подхват outputs_adopt_active_st
 * (apply и status до первого прохода) — одно решение на оба пути; доводы — у определения. */
int fog_pick_known(const struct spec *sp, struct fo_store *st, const struct output *g,
                   const unsigned char *alive, int cur);

/* balance: привести карты всех групп pick: balance в ядре к живым членам по состоянию подхвата
 * (group_cfg.alive, outputs_adopt_active_st). Зовёт apply после загрузки набора правил: тот
 * ставит карту «все члены живы». */
void fog_balance_adopt(const struct spec *sp);

/* Сколько секунд без трафика через группу замер urltest не делается: idle_timeout спеки, а без
 * него — умолчание платформы (телефон — 1800, роутер — 0, то есть мерить всегда). */
int fog_idle_limit(const struct output *g);
/* Нет ли трафика через группу дольше limit секунд — по счётчику пакетов её правил (fn; NULL —
 * узнать нечем, и тогда трафик «есть»). Первая встреча группы берёт отсчёт и считает её
 * незанятой: без трафика замеров нет. 1 — простаивает. */
int fog_idle(const struct spec *sp, const struct output *g, int limit, fo_traffic_fn fn, void *arg);
/* Простаивает ли группа group по последнему наблюдению процесса (без чтения счётчиков — для status):
 * 1 — трафика не видели дольше предела, замер на паузе. 0 — нет, пределом не спрашивали или группы
 * сторож ещё не встречал. */
int fog_idle_now(const char *group);

/* balance: привести карту группы в ядре к живым членам alive (байт на члена: 1 — жив). По факту в ядре, а
 * не по памяти: apply ставит карту со всеми членами, и сверка обязана это заметить. 1 — карта
 * переписана; 0 — уже такая; -1 — карты нет или ядро отказало (сказано в журнале один раз). */
int fog_balance_sync(const struct spec *sp, const struct output *g, const unsigned char *alive);

/* Запись `groups` прохода: по группе — выбранный член (или «-») и живые члены. Пишется только
 * при изменении текста (тот же довод про флеш, что у active_save). cur[i] — номер члена группы
 * sp->out[i] (-1 — нет), alive[i] — байты по числу членов группы (1 — жив; NULL — никого). */
void fog_groups_save(struct fo_store *st, const struct spec *sp, const int *cur,
                     unsigned char *const *alive);
/* Номер члена по записи `groups` (-1 — записи нет или член больше не в группе). */
int fog_groups_cur(struct fo_store *st, const struct spec *sp, const struct output *g);
/* Живые члены по записи `groups`: байты 0/1 в alive (по числу членов группы; место даёт
 * вызывающий). 0 — записи нет: сторож группу ещё не проходил. */
int fog_groups_alive(struct fo_store *st, const struct spec *sp, const struct output *g,
                     unsigned char *alive);

/* Состояние групп для status (cur, alive, sel, lat_ms у struct group_cfg) — из записей `groups`,
 * `select` и `latency` хранилища st. */
void fog_adopt(struct spec *sp, struct fo_store *st);

/* Группа latency: замер дал ответ хотя бы у одного живого члена (none = 0) или не дал ни у одного
 * (none = 1) — и сменилось ли это с прошлого вопроса процесса о группе: 1 — сменилось (строку в
 * журнал пишут на смене, а не на каждом проходе). Первый вопрос о группе с замерами — не смена
 * (молчим), без замеров — смена (сказать надо: группа идёт по порядку). */
int fog_lat_note(const char *group, int none);

/* Ключ замера члена в записи `latency`: имя именованного члена, устройство безымянного (v1). */
const char *fog_lat_key(const struct output *m);

/* КОМАНДА select: группа gname (pick: manual) — член mname. Выбор кладётся в запись `select`
 * (переживает перезапуск и перезагрузку: файл рядом со спекой), таблица группы тут же переписывается на
 * лист члена — как сторож при переключении, — а упавший член даёт группе её on_fail, а не
 * другого члена. ev — событие switched (by: select) или failed. route = 0 — только запомнить
 * выбор (движок выключен: маршрутизацию трогать нельзя, выбор применит следующий проход после
 * включения). Текст для человека — в out, отказы — в stderr. Код: 0 — выбор принят; 2 — отказ
 * (нет такой группы, не manual, не член). */
int fog_select(struct spec *sp, struct fo_store *st, const char *gname, const char *mname,
               int route, fo_event_fn ev, void *arg, FILE *out);

/* `steerd select ГРУППА ЧЛЕН` без демона: спека с диска, память сторожа — файлы. */
int cmd_select(const char *spec, const char *group, const char *member);

#endif
