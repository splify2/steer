/* SPDX-License-Identifier: GPL-3.0-only
 * Deterministic completed-result window: loop dispatch deliberately withheld. */
#define _GNU_SOURCE
#include "prototype_prepare.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static const char document[]="{\"prototype\":\"steer-linux-v1\",\"listeners\":[],\"routing\":{\"default\":\"block\",\"rules\":[]}}";
struct fixture { struct loop *loop;struct loop_timer *finish;struct steer_prototype_prepare *worker;uint64_t deadline;int expected,callbacks; };
static void done(void *user,struct steer_prototype_prepared_input *result) {
    struct fixture *f=user;assert(result->error==f->expected&&result->serial==77&&result->control_index==2);
    assert(result->config&&result->config->generation==1);f->callbacks++;
    steer_prototype_prepare_stop(f->worker);
    assert(steer_prototype_prepare_destroy(f->worker)==-1);
    loop_timer_set(f->finish,0);
}
static void finish(struct loop *loop,struct loop_timer *timer,void *user) {
    struct fixture *f=user;(void)timer;assert((uint64_t)loop_now_ms()<f->deadline);
    if(steer_prototype_prepare_destroy(f->worker)) { loop_timer_set(f->finish,1);return; }
    f->worker=NULL;loop_stop(loop,0);
}
static void run(int mode) {
    struct fixture f={0};struct timespec pause={0,1000000};
    f.expected=mode==1||mode==3?499:mode==2?408:0;f.deadline=(uint64_t)loop_now_ms()+3000;
    f.loop=loop_new();assert(f.loop);f.finish=loop_timer_new(f.loop,finish,&f);assert(f.finish);
    assert(!steer_prototype_prepare_create(f.loop,done,&f,NULL,&f.worker));
    uint64_t deadline=(uint64_t)loop_now_ms()+(mode==2?100:2000);char *copy=strdup(document);assert(copy);
    assert(!steer_prototype_prepare_submit(f.worker,copy,strlen(copy),1,0,2,77,1,deadline));
    memset(copy,0,strlen(copy));free(copy);
    while(!steer_prototype_prepare_result_pending(f.worker)) { assert((uint64_t)loop_now_ms()<deadline);nanosleep(&pause,NULL); }
    assert(steer_prototype_prepare_submit(f.worker,document,strlen(document),1,0,2,78,1,deadline)==503);
    if(mode==1)steer_prototype_prepare_cancel(f.worker,2,77);
    if(mode==2)while((uint64_t)loop_now_ms()<=deadline)nanosleep(&pause,NULL);
    if(mode==3)steer_prototype_prepare_stop(f.worker);
    if(mode==4)steer_prototype_prepare_cancel(f.worker,2,76);
    assert(!loop_run(f.loop)&&f.callbacks==1&&!f.worker);
    loop_timer_free(f.finish);loop_free(f.loop);
}
int main(void) {
    for(int mode=0;mode<5;mode++)run(mode);
    puts("prepare worker: copied input, completed-result cancel/deadline/stop, stale token and callback/join barrier PASS");return 0;
}
