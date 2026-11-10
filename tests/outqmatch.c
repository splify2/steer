/* Очередь исходящих байт живой связи (outq_send, outq_flush; I-534).
 *
 * Запись связи в цикле стека не ждёт сокета: что он не принял сразу, лежит в очереди и дослается по событию
 * записи, а порядок байт при этом не нарушается. Стенд — пара сокетов AF_UNIX/STREAM с маленьким буфером:
 * отправка мегабайта должна вернуться сразу с остатком в очереди, после слива на другом конце те же
 * байты в том же порядке, включая записанное, пока очередь ещё не опустела (оно идёт в хвост, а не в сокет
 * в обход очереди). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "unit.h"
#include "../src/lib/outq.h"

static long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
    int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    struct outq q;
    memset(&q, 0, sizeof q);

    /* Малое — прямо в сокет, очередь не заводится. */
    unsigned char hello[16];
    memset(hello, 7, sizeof hello);
    check("outq: малая запись принята", 0, outq_send(sv[0], &q, hello, sizeof hello));
    check("outq: в очереди ничего, буфер не заведён", 1, outq_pending(&q) == 0 && q.p == NULL);
    unsigned char got[16];
    check("outq: байты дошли", 16, read(sv[1], got, sizeof got));

    /* Крупная запись (три OUTQ_HIWAT — столько законная очередь не набирает, но и до потолка OUTQ_MAX далеко) при
     * буфере в 4 КБ: вызов не ждёт, остаток в очереди. */
    enum { BIG = 3 * OUTQ_HIWAT };
    unsigned char *big = malloc(BIG);
    for (size_t i = 0; i < BIG; i++) big[i] = (unsigned char)(i * 31 + (i >> 8));
    long t0 = ms_now();
    int rc = outq_send(sv[0], &q, big, BIG);
    long dt = ms_now() - t0;
    check("outq: крупная запись принята без ожидания (< 100 мс)", 1, rc == 0 && dt < 100);
    check("outq: почти всё в очереди", 1, outq_pending(&q) > BIG - 200000);

    /* Пока очередь не пуста, новая запись идёт в хвост. */
    static const unsigned char tail[] = "хвост-за-очередью";
    check("outq: запись при непустой очереди принята", 0, outq_send(sv[0], &q, tail, sizeof tail));

    /* Слив: читаем с другого конца и досылаем. Порядок байт — как записано. */
    size_t want = BIG + sizeof tail, off = 0;
    unsigned char *rx = malloc(want);
    int busy_seen = 0, flush_rc = 1;
    for (int round = 0; round < 200000 && off < want; round++) {
        ssize_t r = recv(sv[1], rx + off, want - off, MSG_DONTWAIT);
        if (r > 0) off += (size_t)r;
        if (outq_pending(&q)) {
            flush_rc = outq_flush(sv[0], &q);
            if (flush_rc == 1) busy_seen = 1;
        }
    }
    check("outq: слив — дошло всё записанное", 1, off == want);
    check("outq: сокет по ходу был занят (flush вернул 1), очередь опустела (0)", 1, busy_seen && flush_rc == 0);
    check("outq: после слива буфер возвращён", 1, q.p == NULL && outq_pending(&q) == 0);
    check("outq: байты крупной записи в том же порядке", 1, off == want && !memcmp(rx, big, BIG));
    check("outq: хвост — после крупной записи", 1, off == want && !memcmp(rx + BIG, tail, sizeof tail));

    /* Собеседник ушёл: запись — отказ, а не сигнал и не ожидание. */
    close(sv[1]);
    int er = 0;
    for (int i = 0; i < 4 && !er; i++) er = outq_send(sv[0], &q, hello, sizeof hello);
    check("outq: закрытый собеседник — отказ записи", -1, er);
    outq_free(&q);
    close(sv[0]);

    /* Потолок (аудит 2.1.0, F9): узел, заказывающий ответы и не читающий их, раздувал очередь без предела
     * (16 МБ PING — 16 МБ в очереди). До OUTQ_MAX очередь принимает, сверх — отказ, и очередь не тронута. */
    struct outq cq;
    memset(&cq, 0, sizeof cq);
    unsigned char *blk = calloc(1, OUTQ_MAX);
    check("outq: до потолка OUTQ_MAX очередь принимает", 0, outq_add(&cq, blk, OUTQ_MAX));
    check("outq: байт сверх потолка — отказ", -1, outq_add(&cq, blk, 1));
    check("outq: отказ очередь не тронул", 1, outq_pending(&cq) == OUTQ_MAX);
    outq_free(&cq);
    free(blk);
    free(big);
    free(rx);
    return unit_done("outqmatch");
}
