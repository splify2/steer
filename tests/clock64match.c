#define _GNU_SOURCE
#include "loop.h"
#include "helpers.h"
#include "monotime.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/timerfd.h>

/* Link --wrap injects time without including implementation .c files or
 * changing the system clock. Timerfd is armed for a real immediate wake while
 * the captured absolute deadline and monotonic reading cross ILP32 LONG_MAX. */
static int64_t injected;
static int fired,arms;
static int check_storage=1;
static int64_t expected_due;
static int starts;
static int start_helper(struct helper *h, void *arg) {
    assert(arg == &starts);
    starts++;
    h->pid = 42;
    return 0;
}
int __real_timerfd_settime(int,int,const struct itimerspec *,struct itimerspec *);
int __wrap_clock_gettime(clockid_t clock,struct timespec *t) {
    assert(clock==CLOCK_MONOTONIC);
    t->tv_sec=(time_t)(injected/1000);t->tv_nsec=(long)(injected%1000)*1000000;
    return 0;
}
int __wrap_timerfd_settime(int fd,int flags,const struct itimerspec *given,struct itimerspec *old) {
    if(flags&TFD_TIMER_ABSTIME){
        int64_t due=steer_mono_ms_from_timespec(&given->it_value);
        assert(due==expected_due);arms++;
        injected=due;
        struct itimerspec actual={{0,0},{0,1}};
        return __real_timerfd_settime(fd,0,&actual,old);
    }
    return __real_timerfd_settime(fd,flags,given,old);
}
static void done(struct loop *l,struct loop_timer *t,void *arg) {
    (void)t;(void)arg;assert(loop_now_ms()==expected_due);fired++;loop_stop(l,0);
}
static void boundary(int64_t start,long delay) {
    injected=start;expected_due=start+delay;
    assert(loop_now_ms()==start&&helpers_now_ms()==start);
    struct helper h={0};h.started_ms=start;h.next_ms=start+delay;
    if(check_storage)assert(h.started_ms==start&&h.next_ms==expected_due);
    struct helper fresh = {0};
    struct helper_set set = { .h = &fresh, .n = 1, .cap = 1 };
    int before = starts;
    assert(helpers_due(&set, start_helper, &starts) == -1);
    assert(starts == before + 1 && fresh.pid == 42);
    fresh.pid = 0;
    fresh.next_ms = expected_due;
    assert(helpers_due(&set, start_helper, &starts) == delay);
    assert(starts == before + 1);
    struct loop *l=loop_new();assert(l);
    struct loop_timer *t=loop_timer_new(l,done,NULL);assert(t);
    loop_timer_set(t,delay);assert(!loop_run(l));loop_timer_free(t);loop_free(l);
}
int main(int argc,char **argv) {
    (void)argv;if(argc>1)check_storage=0;
    boundary(INT32_MAX-10ll,100);
    boundary(INT32_MAX+1000ll,50);
    boundary(UINT32_MAX+1000ll,50);
    assert(fired==3&&arms==3);
    assert(steer_mono_after(INT64_MAX-10,20)==INT64_MAX);
    printf("monotonic64: long=%zu conversion/storage/timer boundaries PASS\n",sizeof(long));
    return 0;
}
