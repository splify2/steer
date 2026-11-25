/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_EXPERIMENTAL_STREAM_OPEN_DEADLINE_H
#define STEER_EXPERIMENTAL_STREAM_OPEN_DEADLINE_H
#include "loop.h"
#include <limits.h>
#include <stdint.h>
#include <time.h>

static inline uint64_t steer_draft_stream_now_ns(void)
{
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
/* A timer wakes the owner; absolute checks govern progress and publication. */
static inline void steer_draft_stream_arm_deadline(struct loop_timer *timer,uint64_t deadline,uint64_t now)
{
    uint64_t remaining=deadline>now?deadline-now:0;
    uint64_t ms=remaining/UINT64_C(1000000)+(remaining%UINT64_C(1000000)!=0);
    loop_timer_set(timer,ms>(uint64_t)LONG_MAX?LONG_MAX:(long)ms);
}
#endif
