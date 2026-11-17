#define _GNU_SOURCE
#include "binding_lease.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
struct fixture {
    struct loop *loop;struct loop_timer *cleanup;
    struct steer_draft_binding_lease *lease;
    pthread_mutex_t mutex;pthread_cond_t condition;
    int paused,proceed,retire_seen,finalized,count;
    pthread_t threads[4];
    _Atomic unsigned iterations;
};
static void before_ready(void *arg) {
    struct fixture *f=arg;pthread_mutex_lock(&f->mutex);
    f->paused=1;pthread_cond_broadcast(&f->condition);
    while(!f->proceed)pthread_cond_wait(&f->condition,&f->mutex);
    pthread_mutex_unlock(&f->mutex);
}
static void stale_retire_seen(void *arg) {
    struct fixture *f=arg;f->retire_seen++;
    assert(!f->finalized&&!steer_draft_binding_references(f->lease));
    assert(steer_draft_binding_lease_destroy(f->lease).code==STEER_PV1_POLICY_DENIED);
    pthread_mutex_lock(&f->mutex);assert(f->paused);f->proceed=1;
    pthread_cond_broadcast(&f->condition);pthread_mutex_unlock(&f->mutex);
}
static void cleanup(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)timer;struct fixture *f=arg;
    for(int i=0;i<f->count;i++)assert(!pthread_join(f->threads[i],NULL));
    assert(f->finalized==1&&!steer_draft_binding_references(f->lease));
    assert(!steer_draft_binding_lease_destroy(f->lease).code);f->lease=NULL;
    loop_stop(loop,0);
}
static void finalized(void *arg,const struct steer_draft_binding_identity *identity) {
    struct fixture *f=arg;assert(identity->generation==7&&identity->instance_token==99);
    assert(identity->provider_id.len==6&&!memcmp(identity->provider_id.data,"native",6));
    assert(steer_draft_binding_lease_destroy(f->lease).code==STEER_PV1_POLICY_DENIED);
    f->finalized++;loop_timer_set(f->cleanup,0);
}
static void initialize(struct fixture *f,uint32_t maximum) {
    memset(f,0,sizeof(*f));atomic_init(&f->iterations,0);
    assert(!pthread_mutex_init(&f->mutex,NULL));assert(!pthread_cond_init(&f->condition,NULL));
    f->loop=loop_new();assert(f->loop);f->cleanup=loop_timer_new(f->loop,cleanup,f);assert(f->cleanup);
    uint8_t name[]="native";
    struct steer_draft_binding_identity identity={sizeof(identity),STEER_PV1_DRAFT_LAYOUT,7,99,{name,6},0,STEER_PV1_FLOW_STREAM};
    assert(!steer_draft_binding_lease_create(f->loop,&identity,maximum,finalized,f,&f->lease).code);
    memset(name,'x',6);
    assert(steer_draft_binding_unpin(f->lease).code==STEER_PV1_POLICY_DENIED); /* owner belongs to retire */
    assert(steer_draft_binding_admit(f->lease,8,STEER_PV1_FLOW_STREAM).code==STEER_PV1_POLICY_DENIED);
    assert(steer_draft_binding_admit(f->lease,7,STEER_PV1_FLOW_DATAGRAM).code==STEER_PV1_UNSUPPORTED);
}
static void finish(struct fixture *f) {
    loop_timer_free(f->cleanup);loop_free(f->loop);
    pthread_cond_destroy(&f->condition);pthread_mutex_destroy(&f->mutex);
}
static void *last_unpin(void *arg) {
    struct fixture *f=arg;assert(!steer_draft_binding_unpin(f->lease).code);return NULL;
}
static void paused_publication(void) {
    struct fixture f;initialize(&f,2);
    assert(!steer_draft_binding_admit(f.lease,7,STEER_PV1_FLOW_STREAM).code);
    assert(steer_draft_binding_pin(f.lease,7,STEER_PV1_FLOW_STREAM).code==STEER_PV1_RESOURCE_EXHAUSTED);
    steer_draft_binding_test_hooks(f.lease,before_ready,stale_retire_seen,&f);
    assert(!steer_draft_binding_retire(f.lease).code);assert(!steer_draft_binding_retire(f.lease).code);
    f.count=1;assert(!pthread_create(&f.threads[0],NULL,last_unpin,&f));
    pthread_mutex_lock(&f.mutex);while(!f.paused)pthread_cond_wait(&f.condition,&f.mutex);pthread_mutex_unlock(&f.mutex);
    assert(!steer_draft_binding_references(f.lease));
    assert(steer_draft_binding_admit(f.lease,7,STEER_PV1_FLOW_STREAM).code==STEER_PV1_POLICY_DENIED);
    assert(!loop_run(f.loop));assert(f.retire_seen==1);finish(&f);
    puts("lease: paused zero-ref producer + stale RETIRE cannot finalize before READY PASS");
}
static void *racing(void *arg) {
    struct fixture *f=arg;
    for(unsigned i=0;i<5000;i++){
        atomic_fetch_add_explicit(&f->iterations,1,memory_order_relaxed);
        struct steer_pv1_error e=steer_draft_binding_admit(f->lease,7,STEER_PV1_FLOW_STREAM);
        if(e.code){assert(e.code==STEER_PV1_POLICY_DENIED);break;}
        assert(!steer_draft_binding_pin(f->lease,7,STEER_PV1_FLOW_STREAM).code);
        assert(!steer_draft_binding_unpin(f->lease).code);assert(!steer_draft_binding_unpin(f->lease).code);
    }
    /* Parent ref keeps derived operations legal through retirement. */
    assert(!steer_draft_binding_pin(f->lease,7,STEER_PV1_FLOW_STREAM).code);
    assert(!steer_draft_binding_unpin(f->lease).code);
    assert(!steer_draft_binding_unpin(f->lease).code);return NULL;
}
static void retire_race(void) {
    struct fixture f;initialize(&f,32);f.count=4;
    for(int i=0;i<f.count;i++){
        assert(!steer_draft_binding_admit(f.lease,7,STEER_PV1_FLOW_STREAM).code);
        assert(!pthread_create(&f.threads[i],NULL,racing,&f));
    }
    while(atomic_load_explicit(&f.iterations,memory_order_relaxed)<64)sched_yield();
    assert(!steer_draft_binding_retire(f.lease).code);
    assert(steer_draft_binding_admit(f.lease,7,STEER_PV1_FLOW_STREAM).code==STEER_PV1_POLICY_DENIED);
    assert(!loop_run(f.loop));finish(&f);
    puts("lease: four worker admit/retire/derived-pin race, exact generation, bounded refs PASS");
}
int main(void) {alarm(10);paused_publication();retire_race();alarm(0);return 0;}
