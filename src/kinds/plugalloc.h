/* Выдача ресурсов плагинам: alloc.json (plugalloc.c). Порты, очереди NFQUEUE и биты метки выдаёт ядро по
 * resources манифеста и kinds[].resources; номера постоянны между перезагрузками и обновлениями
 * плагина (steer-api.md, раздел 6). Заголовок — для шага подготовки (model/plugprep.c), который
 * выдаёт; читают выданное сам реестр плагинов (подстановки {mark}, {queue0}…) и разбор спеки. */
#ifndef STEER_PLUGALLOC_H
#define STEER_PLUGALLOC_H

#include <stddef.h>
#include <stdint.h>

struct err;
struct plugin;

struct pal_ent { char *owner; uint32_t *ports; size_t pn; uint32_t *queues; size_t qn; uint32_t *bits; size_t bn; };
struct pal { struct pal_ent *e; size_t n; };


void pal_free(struct pal *a);
/* Прочитать alloc.json (нет файла — пусто). 0 / -1 (нет памяти). */
int pal_load(struct pal *a);
/* Записать alloc.json атомарно. 0 / -1. */
int pal_save(const struct pal *a);
/* Выдать выходу owner («плагин/выход») n портов и m очередей: сколько уже есть — остаётся. 0 — готово;
 * -1 — отказ с числами в e. */
int pal_ensure(struct pal *a, const char *owner, size_t n, size_t m, int *changed, struct err *e);
/* То же для плагина целиком (resources манифеста), плюс биты метки. */
int pal_ensure_plugin(struct pal *a, const struct plugin *pl, int *changed, struct err *e);

#endif
