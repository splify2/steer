/* HTTPS для замера задержки группы (src/daemon/urltest.c) — только в полном пакете: TLS 1.3 из
 * src/proto/tls, рабочим потоком. Устройство и доводы — в шапке urltls.c. */
#ifndef STEER_URLTLS_H
#define STEER_URLTLS_H

#include <stdint.h>
#include <netinet/in.h>

struct loop;
struct urltls;

/* Запрос GET path к host (SNI и проверка сертификата) по адресу dst (IPv4 или IPv6 — по его
 * семейству) — через сокет с SO_MARK mark (mark != 0) или привязанный к dev (dev != NULL). cb
 * позовётся один раз из цикла l: ms >= 0 — пришёл ответ 204 или 200, время до первого байта
 * ответа от начала соединения; -1 — нет, и why — почему, одной строкой (сертификат не принят,
 * срок вышел, ответ 503 вместо 204/200…); у удавшегося замера why пустая и живёт только на время
 * вызова. NULL — поток не завёлся, обратного вызова не будет (итог — «не измерилось»). */
struct urltls *urltls_start(struct loop *l, const struct sockaddr_storage *dst, const char *host,
                            const char *path, uint32_t mark, const char *dev, int timeout_ms,
                            void (*cb)(void *arg, int ms, const char *why), void *arg);
/* Отменить: cb не позовётся, поток уйдёт сам, дойдя до конца. */
void urltls_cancel(struct urltls *t);

/* Признак для слабой ссылки из ядра (urltest_https_ok, src/kinds/grpurl.c): HTTPS в сборке есть. */
extern const int steer_urltls_present;

#endif
