/* Чтение потока TLS (tls13_read, tls13_read_ref) не ждёт и не спрашивает poll перед чтением.
 *
 * Сокет узла блокирующий и со сроком (trdial.c, SO_RCVTIMEO), и голый read на пустом ждал бы до его
 * конца — восьми секунд на весь цикл туннеля. Прежде поэтому перед каждым чтением стоял poll(…, 0):
 * второй системный вызов на каждое чтение, 66–115 вызовов poll на МБ у gRPC и Vision (замер R-148).
 * Теперь чтение само не ждёт (recv с MSG_DONTWAIT). Стенд считает вызовы poll подменой символа и
 * проверяет оба исхода, которые прежде давал poll: на пустом сокете — «пока нечего» сразу, а не
 * через срок сокета; на закрытом — конец потока, а не вечное «пока нечего».
 *
 * Записи стенд подаёт ChangeCipherSpec (тип 0x14): в 1.3 она пропускается без расшифровки, так что
 * ключи не нужны и шифр не вызывается — неразрешённые ссылки tls13.c на криптографию стенду не мешают
 * (--unresolved-symbols=ignore-all в Makefile). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "unit.h"
#include "../src/proto/tls/tls13.h"

static int g_poll_calls;

int poll(struct pollfd *fds, nfds_t n, int timeout) {
    static int (*real)(struct pollfd *, nfds_t, int);
    g_poll_calls++;
    if (!real) real = (int (*)(struct pollfd *, nfds_t, int))dlsym(RTLD_NEXT, "poll");
    return real(fds, n, timeout);
}

static long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static struct tls13 g_t;   /* статический: буфер записи — шестнадцать с лишним килобайт */

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
    /* Как у сокета узла: блокирующий и со сроком. Срок — две секунды: дождись чтение его, стенд увидит. */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    g_t.fd = sv[0];
    g_t.ready = 1;

    unsigned char out[64];
    size_t got = 99;
    long t0 = ms_now();
    g_poll_calls = 0;
    int rc = tls13_read(&g_t, out, sizeof(out), &got);
    check("пустой сокет: код «пока нечего» (0)", 0, rc);
    check("пустой сокет: ноль байт", 0, (long)got);
    check("пустой сокет: не ждёт срока сокета (< 200 мс)", 1, ms_now() - t0 < 200);
    check("пустой сокет: ни одного poll", 0, g_poll_calls);

    /* Половина заголовка записи: записи целиком нет — тоже «пока нечего», и тоже без ожидания. */
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    if (write(sv[1], ccs, 3) != 3) return 1;
    t0 = ms_now();
    const unsigned char *body = NULL;
    size_t bn = 99;
    rc = tls13_read_ref(&g_t, &body, &bn);
    check("неполная запись: код 0, без данных", 0, rc + (long)bn);
    check("неполная запись: не ждёт дособирания", 1, ms_now() - t0 < 200);

    /* Дописали — служебная запись разобрана (пропущена), данных нет, а дальше снова пусто. */
    if (write(sv[1], ccs + 3, 3) != 3) return 1;
    g_poll_calls = 0;
    for (int i = 0; i < 10; i++) rc |= tls13_read(&g_t, out, sizeof(out), &got);
    check("служебная запись и девять пустых чтений: код 0", 0, rc);
    check("десять чтений подряд — ни одного poll", 0, g_poll_calls);
    check("служебная запись разобрана целиком", 1, g_t.rbuf_off == g_t.rbuf_n);

    /* Узел закрыл: конец потока, а не «пока нечего» навсегда. */
    close(sv[1]);
    rc = tls13_read(&g_t, out, sizeof(out), &got);
    check("закрытый сокет: конец потока (TLS13_ECLOSED)", TLS13_ECLOSED, rc);

    close(sv[0]);
    return unit_done("tls13readmatch");
}
