/* Internal monotonic millisecond arithmetic; never store absolute time in long.
 * OpenWrt ILP32 long milliseconds overflow after approximately 24.9 days. */
#ifndef STEER_MONOTIME_H
#define STEER_MONOTIME_H
#include <stdint.h>
#include <time.h>
static inline int64_t steer_mono_ms_from_timespec(const struct timespec *t) {
    if(t->tv_sec<0)return 0;
    if((uint64_t)t->tv_sec>(uint64_t)INT64_MAX/1000)return INT64_MAX;
    int64_t seconds=(int64_t)t->tv_sec*1000;
    int64_t fraction=t->tv_nsec/1000000;
    return seconds>INT64_MAX-fraction?INT64_MAX:seconds+fraction;
}
static inline int64_t steer_mono_ms(void) {
    struct timespec t={0,0};
    if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
    return steer_mono_ms_from_timespec(&t);
}
static inline int64_t steer_mono_after(int64_t now,long delay) {
    if(delay<=0)return now;
    return now>INT64_MAX-delay?INT64_MAX:now+delay;
}
#endif
