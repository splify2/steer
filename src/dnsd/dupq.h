#ifndef STEER_DNSD_DUPQ_H
#define STEER_DNSD_DUPQ_H

/* ШОВ МЕЖДУ РЕЗОЛВЕРОМ И ОБЁРТКОЙ QUIC (DoQ).
 *
 * ЗАЧЕМ ШОВ. Резолвер (src/dnsd) входит в каждую сборку движка, а обёртка QUIC (src/proto/quic, с
 * ngtcp2 и wolfSSL за ней) — только в libsteer.so: статическая базовая сборка, микропакет tgws и
 * телефон её не содержат. Включи dup.c заголовок quic.h напрямую — сборочные списки (проверка
 * замыкания по #include, tests/buildmatch.sh) потребовали бы quic.c в каждом профиле, то есть
 * тянули бы ngtcp2 туда, где QUIC не нужен. Поэтому dup.c видит только этот заголовок, а
 * функции dupq_* лежат в src/proto/quic/qcdoq.c — файле стороны QUIC — и подключаются слабыми
 * ссылками, как TLS у DoT/DoH: без них DoQ-апстрим отказывает с причиной в `dns-log`, а сборка
 * не падает. Файл называется не dupq.c нарочно: замыкание ищет .c рядом с включённым
 * заголовком по имени, и одноимённый файл снова стал бы «обязательным» в каждом профиле.
 *
 * Имена и смысл — те же, что у qc_* (src/proto/quic/quic.h); здесь только то, что нужно клиенту DoQ:
 * один сервер, один SNI, метка пути, ALPN (`doq`, по умолчанию, или `h3`) и корни как у DoT зашиты внутри. Возврат
 * функций — 0 или отрицательное число; DUPQ_EAGAIN — «сейчас нельзя» (новых потоков пока нет). */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct dupq;                                /* соединение (под ним struct qc) */

#define DUPQ_EAGAIN (-6)                    /* то же число, что QC_EAGAIN */

/* Причины закрытия (on_closed) — числа QC_CLOSE_* обёртки: 0 закрыли мы, 1 закрыл сервер, 2 простой,
 * 3 рукопожатие, 4 ошибка. Резолверу они нужны только для журнала. */
struct dupq_ops {
    void (*on_handshake)(void *user);
    void (*on_stream_data)(void *user, int64_t sid, const uint8_t *d, size_t n, int fin);
    void (*on_stream_close)(void *user, int64_t sid, uint64_t app_err);
    void (*on_closed)(void *user, int reason, const char *why);
    /* Сервер не принял 0-RTT: вопросы, ушедшие раньше рукопожатия, потеряны — повторить на новых потоках. */
    void (*on_early_rejected)(void *user);
};

struct dupq_cfg {
    const char *host;                       /* адрес сервера текстом */
    uint16_t port;
    const char *sni;                        /* имя апстрима: SNI и проверка сертификата */
    const char *alpn;                       /* NULL — "doq"; DoH по HTTP/3 — "h3" */
    uint32_t sock_mark;                     /* метка пути выхода; 0 — не метить */
    unsigned handshake_ms, idle_ms;
    /* Вопрос можно отправить до конца рукопожатия (0-RTT), если для этого сервера есть билет прошлой
     * сессии. Вопрос DNS идемпотентен, повтор на пути ничего не портит (RFC 9250, раздел 5.5). */
    int early_data;
};

/* Приготовить контекст TLS (корни разбираются один раз на процесс). Блокирует — зовётся из потока
 * установки (dupdial.c). roots — файл корней, NULL — умолчание обёртки. 1 — готов, 0 — нет (нет
 * файла корней: соединяться без проверки не будем). */
int dupq_prepare(const char *roots);
/* Готов ли уже контекст (без блокировки). */
int dupq_ready(void);

int dupq_open(const struct dupq_cfg *cfg, const struct dupq_ops *ops, void *user, struct dupq **out);
void dupq_close(struct dupq *q, uint64_t app_err);
void dupq_free(struct dupq *q);
int dupq_fd(const struct dupq *q);
int dupq_timeout_ms(struct dupq *q);
int dupq_on_readable(struct dupq *q);
int dupq_on_timer(struct dupq *q);
/* Рукопожатие идёт, но по билету потоки уже можно открывать и слать в них (0-RTT). */
int dupq_early_ready(const struct dupq *q);
int dupq_stream_open(struct dupq *q, int64_t *sid);
/* Однонаправленный поток клиента (поток управления HTTP/3). Только после рукопожатия. */
int dupq_stream_open_uni(struct dupq *q, int64_t *sid);
ssize_t dupq_stream_send(struct dupq *q, int64_t sid, const uint8_t *d, size_t n, int fin);
int dupq_stream_reset(struct dupq *q, int64_t sid, uint64_t app_err);

#endif
