/* Выбор записей conntrack для снятия по наборам (src/daemon/conns.c, rr_keep): запись остаётся,
 * если её назначение лежит в одном из интервалов наборов. Интервалы разных наборов перекрываются.
 * Стенд линкуется с conns.c (заголовок rrkeep.h) и проверяет: верность на перекрытиях и срок —
 * 200 тысяч интервалов, 5 тысяч назначений вне всех (раньше каждое просматривало все интервалы
 * назад, O(n) на запись conntrack, и при больших списках сторож стоял секунды). */
#include "rrkeep.h"
#include "spec.h"
#include "kind.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Остальное conns.c тянет за собой, а rr_keep этого не касается: заглушки вместо ядра, модели и видов. */
const struct kind_ops kind_direct;
struct output *out_by_name(const struct spec *sp, const char *n) { (void)sp; (void)n; return NULL; }
const struct group_cfg *out_group(const struct output *o) { (void)o; return NULL; }
void conntrack_evict(unsigned mark) { (void)mark; }

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) fails++;
}

static void put4(struct rr_iv *v, uint32_t lo, uint32_t hi) {
    memset(v, 0, sizeof *v);
    lo = htonl(lo); hi = htonl(hi);
    memcpy(v->lo, &lo, 4);
    memcpy(v->hi, &hi, 4);
}

static int keep4(struct rr_ivs *iv, uint32_t a) {
    uint32_t n = htonl(a);
    return rr_keep(AF_INET, (const uint8_t *)&n, iv);
}

/* Как rr_evict_filtered готовит интервалы: сортировка по началу, затем rr_iv_ready. */
static void ready(struct rr_ivs *iv) {
    qsort(iv->v4, iv->n4, sizeof(*iv->v4), rr_iv_cmp);
    rr_iv_ready(iv->v4, iv->n4);
}

int main(void) {
    /* Перекрытия: длинный [10,1000] накрывает короткие после себя; [2000,2010] отдельно. */
    struct rr_iv a[4];
    put4(&a[0], 2000, 2010);
    put4(&a[1], 10, 1000);
    put4(&a[2], 20, 30);
    put4(&a[3], 500, 600);
    struct rr_ivs iv = { .v4 = a, .n4 = 4, .c4 = 4 };
    ready(&iv);
    check(keep4(&iv, 5) == 0, "перед всеми интервалами — не оставлять");
    check(keep4(&iv, 10) == 1 && keep4(&iv, 1000) == 1, "границы длинного интервала — оставить");
    check(keep4(&iv, 700) == 1, "под длинным интервалом, вне вложенных — оставить (вложенные короче)");
    check(keep4(&iv, 1001) == 0 && keep4(&iv, 1999) == 0, "между интервалами — не оставлять");
    check(keep4(&iv, 2005) == 1 && keep4(&iv, 2011) == 0, "последний интервал");

    enum { N = 200000, M = 5000 };
    struct rr_iv *big = malloc((size_t)N * sizeof *big);
    for (uint32_t i = 0; i < N; i++) put4(&big[i], 1000 + i * 4, 1000 + i * 4 + 1);
    struct rr_ivs bg = { .v4 = big, .n4 = N, .c4 = N };
    ready(&bg);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int kept = 0;
    for (uint32_t i = 0; i < M; i++) kept += keep4(&bg, 5000000u + i);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("  %d назначений вне 200000 интервалов: %.1f мс\n", M, ms);
    check(kept == 0 && keep4(&bg, 1000) == 1 && keep4(&bg, 1002) == 0, "большой набор: верность");
    check(ms < 200.0, "большой набор: 5000 назначений вне интервалов быстрее 200 мс");
    free(big);
    printf("rrkeepmatch: %s\n", fails ? "есть провалы" : "всё ok");
    return fails != 0;
}
