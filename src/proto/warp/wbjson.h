/* Значение по пути в ответе JSON (подробности — в wbjson.c). */
#ifndef STEER_WBJSON_H
#define STEER_WBJSON_H

#include <stddef.h>

/* Путь — ключи через точку, число — номер в массиве: "result.config.peers.0.public_key".
 * Строка кладётся раскодированной, true/false/null/число — как в тексте. 0 — найдено и уместилось. */
int wb_json_get(const char *doc, const char *path, char *out, size_t n);

#endif
