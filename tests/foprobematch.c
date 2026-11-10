/* Проба ICMP сторожа (src/daemon/foprobe.c) одним вызовом — для стенда tests/foprobe.sh.
 *
 *   foprobematch УСТРОЙСТВО АДРЕС-ИСТОЧНИКА ЦЕЛЬ СРОК-МС ЗАПРОСОВ
 *
 * Печатает `ok <мс>` или `fail <мс>` (мс — сколько длилась проба по CLOCK_MONOTONIC) и выходит с
 * 0 или 1. Сеть, потери и задержки ответов готовит стенд; здесь — только цикл событий и та же
 * foprobe_icmp, что зовёт проход (hp_icmp_next в failover.c). */
#include <stdio.h>
#include <stdlib.h>

#include "loop.h"
#include "foprobe.h"

static int g_ok = -1;
static long g_t0;

static void done(void *arg, int ok, int ms) {
    (void)ms;
    g_ok = ok;
    loop_stop(arg, 0);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s dev src host timeout_ms tries\n", argv[0]);
        return 2;
    }
    struct loop *l = loop_new();
    if (!l) { perror("loop_new"); return 2; }
    int ok = 0;
    g_t0 = loop_now_ms();
    struct foprobe *p = foprobe_icmp(l, argv[1], argv[2], argv[3], atoi(argv[4]), atoi(argv[5]),
                                     done, l, &ok);
    if (p) loop_run(l);
    else g_ok = ok;
    printf("%s %ld\n", g_ok == 1 ? "ok" : "fail", loop_now_ms() - g_t0);
    loop_free(l);
    return g_ok == 1 ? 0 : 1;
}
