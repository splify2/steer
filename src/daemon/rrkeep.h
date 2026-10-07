#ifndef STEER_RRKEEP_H
#define STEER_RRKEEP_H

#include <stddef.h>
#include <stdint.h>

/* Интервалы назначений из наборов ядра, отсортированные по началу; конец включительно
 * (src/daemon/conns.c, снятие записей conntrack по наборам). Вынесено, чтобы стенд rrkeepmatch
 * линковался с conns.c, а не включал его. */
struct rr_iv { uint8_t lo[16], hi[16], pm[16]; };   /* pm — наибольший hi среди интервалов до этого включительно */
struct rr_ivs {
    struct rr_iv *v4, *v6;
    size_t n4, n6, c4, c6;
    int bad;
};

int rr_iv_cmp(const void *a, const void *b);           /* порядок qsort по началу */
void rr_iv_ready(struct rr_iv *v, size_t n);           /* после сортировки: префиксные максимумы pm */
int rr_keep(uint8_t family, const uint8_t *dst, void *ctx);   /* 1 — назначение в одном из интервалов */

#endif
