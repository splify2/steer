/* Значение по пути в ответе JSON (подробности — в wbjson.c). */
#ifndef STEER_WBJSON_H
#define STEER_WBJSON_H

#include <stddef.h>

/* Путь — ключи через точку, число — номер в массиве: "result.config.peers.0.public_key".
 * Строка кладётся раскодированной, true/false/null/число — как в тексте. 0 — найдено и уместилось. */
int wb_json_get(const char *doc, const char *path, char *out, size_t n);

/* Разобрать ответ HTTP/1.x целиком (в buf, n байт): статус, смещение и длина тела; chunked сжимается на
 * месте. 0 — разобрано; -1 — не HTTP; -2 — ответ оборван (тела меньше Content-Length, у chunked нет
 * завершающего куска). Без Content-Length и chunked тело — всё до конца: закрытие соединения вызывающий
 * отличает от обрыва сам. */
int wb_http_split(char *buf, size_t n, int *status, size_t *body_off, size_t *body_n);

#endif
