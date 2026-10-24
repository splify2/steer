/* Очередь исходящих байт сокета в живом режиме записи (I-534).
 *
 * Запись связи с узлом в цикле стека не ждёт сокета: что он не принял сразу, лежит в очереди и дослается по событию
 * записи (EPOLLOUT), а порядок байт при этом сохраняется. Прежде send блокировал поток цикла до срока сокета
 * (SO_SNDTIMEO), и медленный узел останавливал все соединения потока.
 *
 * Только заголовок, и функции static inline — сознательно: очередью пользуются tls13.c, transport.c и дайлеры
 * (socks), а они собираются в разных бинарниках и стендах; общий .c потребовал бы добавлять его в каждый список
 * исходников и подменять в каждом стенде, а здесь зависимостей нет вовсе. */
#ifndef STEER_OUTQ_H
#define STEER_OUTQ_H
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* p — буфер из кучи, [off, n) — ещё не отправленное, cap — его размер. Нулевая структура — пустая очередь. */
struct outq {
    unsigned char *p;
    size_t n, off, cap;
};

static inline size_t outq_pending(const struct outq *q) { return q->n - q->off; }

static inline void outq_free(struct outq *q) {
    free(q->p);
    memset(q, 0, sizeof(*q));
}

static inline int outq_add(struct outq *q, const unsigned char *d, size_t n) {
    if (!n) return 0;
    if (q->off == q->n) q->off = q->n = 0;                  /* пусто — писать с начала */
    if (q->n + n > q->cap) {
        if (q->off) {                                       /* сперва уплотнить: отправленное не держим */
            memmove(q->p, q->p + q->off, q->n - q->off);
            q->n -= q->off;
            q->off = 0;
        }
        if (q->n + n > q->cap) {
            size_t nc = q->cap ? q->cap : 4096;
            while (nc < q->n + n) nc *= 2;
            unsigned char *np = realloc(q->p, nc);
            if (!np) return -1;
            q->p = np;
            q->cap = nc;
        }
    }
    memcpy(q->p + q->n, d, n);
    q->n += n;
    return 0;
}

/* Отправить d: сперва в сокет без ожидания, остаток — в очередь. 0 — принято целиком (часть могла остаться в
 * очереди), -1 — сокет отказал насовсем или нет памяти. Очередь не пуста — новые байты идут в её хвост: порядок
 * важнее скорости. */
static inline int outq_send(int fd, struct outq *q, const unsigned char *d, size_t n) {
    size_t sent = 0;
    if (q->off == q->n) {
        while (sent < n) {
            ssize_t w = send(fd, d + sent, n - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR) continue;
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (w <= 0) return -1;
            sent += (size_t)w;
        }
    }
    return outq_add(q, d + sent, n - sent);
}

/* Дослать очередь без ожидания: 0 — пусто, 1 — сокет снова занят, -1 — сокет отказал. Опустевшая очередь отдаёт
 * буфер системе: держать его на каждом соединении незачем, а затор случается редко. */
static inline int outq_flush(int fd, struct outq *q) {
    while (q->off < q->n) {
        ssize_t w = send(fd, q->p + q->off, q->n - q->off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        if (w <= 0) return -1;
        q->off += (size_t)w;
    }
    outq_free(q);
    return 0;
}

#endif
