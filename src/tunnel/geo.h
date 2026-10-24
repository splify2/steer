/* Фактическая страна выхода туннеля — одна проверка через его устройство (подробности — в geo.c). */
#ifndef STEER_GEO_H
#define STEER_GEO_H

#include <stddef.h>

/* Спросить trace Cloudflare через устройство dev: cc — две заглавные буквы страны (loc=). 0 — страна
 * получена; -1 — нет, why — почему. Блокирует до 8 с на цель, зовут из своего потока. */
int geo_trace(const char *dev, char cc[3], char *why, size_t wn);

#endif
