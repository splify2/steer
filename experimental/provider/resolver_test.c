#define _GNU_SOURCE
#include "resolver.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
struct fixture {
    struct loop*loop;
    struct loop_timer*timer;
    struct steer_draft_resolver*resolver;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int entered,released,other;
    unsigned calls,phase;
}
;
static void blocked(void*arg,const char*name,uint16_t port,struct steer_draft_resolve_result*out){
    struct fixture*f=arg;
    (void)name;
    (void)port;
    pthread_mutex_lock(&f->lock);
    f->entered=1;
    pthread_cond_signal(&f->changed);
    while(!f->released)pthread_cond_wait(&f->changed,&f->lock);
    pthread_mutex_unlock(&f->lock);
    memset(out,0,sizeof(*out));
    out->code=STEER_PV1_IO;
}
static void unexpected(void*arg,const struct steer_draft_resolve_result*out){
    struct fixture*f=arg;
    (void)out;
    f->calls++;
    assert(0);
}
static void other(struct loop*l,int fd,uint32_t ev,void*arg){
    struct fixture*f=arg;
    uint64_t n;
    (void)l;
    (void)ev;
    assert(read(fd,&n,sizeof(n))==(ssize_t)sizeof(n));
    f->other=1;
}
static void tick(struct loop*l,struct loop_timer*t,void*arg){
    struct fixture*f=arg;
    (void)t;
    if(!f->phase++){
        assert(f->other&&!f->calls);
        assert(steer_draft_resolver_jobs(f->resolver)==1);
        assert(steer_draft_resolver_destroy(f->resolver).code==STEER_PV1_POLICY_DENIED);
        pthread_mutex_lock(&f->lock);
        f->released=1;
        pthread_cond_signal(&f->changed);
        pthread_mutex_unlock(&f->lock);
    }
    if(steer_draft_resolver_jobs(f->resolver)){
        assert(f->phase<1000);
        loop_timer_set(f->timer,1);
        return;
    }
    assert(!f->calls);
    assert(!steer_draft_resolver_destroy(f->resolver).code);
    loop_stop(l,0);
}
static void timeout(struct loop*l,struct loop_timer*t,void*arg){
    (void)t;
    (void)arg;
    loop_stop(l,99);
}
static void real_done(void*arg,const struct steer_draft_resolve_result*out){
    struct fixture*f=arg;
    uint32_t i;
    assert(!out->code&&out->count);
    for(i=0;i<out->count;i++)assert(out->addresses[i].ss_family==AF_INET||out->addresses[i].ss_family==AF_INET6);
    f->calls++;
    loop_stop(f->loop,0);
}
int main(void){
    struct fixture f={
        0
    }
    ;
    struct steer_draft_resolve_job*a,*b,*c;
    struct steer_pv1_span name={
        (const uint8_t*)"localhost",9
    }
    ;
    uint64_t one=1;
    int fd;
    struct loop_timer*guard;
    f.loop=loop_new();
    assert(f.loop);
    assert(!pthread_mutex_init(&f.lock,NULL));
    assert(!pthread_cond_init(&f.changed,NULL));
    assert(!steer_draft_resolver_create(f.loop,1,2,blocked,&f,&f.resolver).code);
    assert(!steer_draft_resolver_submit(f.resolver,name,80,unexpected,&f,&a).code);
    pthread_mutex_lock(&f.lock);
    while(!f.entered)pthread_cond_wait(&f.changed,&f.lock);
    pthread_mutex_unlock(&f.lock);
    assert(!steer_draft_resolver_submit(f.resolver,name,80,unexpected,&f,&b).code);
    assert(steer_draft_resolver_submit(f.resolver,name,80,unexpected,&f,&c).code==STEER_PV1_RESOURCE_EXHAUSTED&&!c);
    steer_draft_resolver_cancel(a);
    steer_draft_resolver_cancel(b);
    assert(steer_draft_resolver_jobs(f.resolver)==1);
    fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    assert(fd>=0);
    assert(!loop_fd_add(f.loop,fd,EPOLLIN,other,&f));
    assert(write(fd,&one,sizeof(one))==(ssize_t)sizeof(one));
    f.timer=loop_timer_new(f.loop,tick,&f);
    guard=loop_timer_new(f.loop,timeout,NULL);
    assert(f.timer&&guard);
    loop_timer_set(f.timer,5);
    loop_timer_set(guard,2000);
    assert(!loop_run(f.loop));
    loop_fd_del(f.loop,fd);
    close(fd);
    loop_timer_free(f.timer);
    loop_timer_free(guard);
    loop_free(f.loop);
    pthread_cond_destroy(&f.changed);
    pthread_mutex_destroy(&f.lock);
    memset(&f,0,sizeof(f));
    f.loop=loop_new();
    assert(f.loop);
    assert(!steer_draft_resolver_create(f.loop,2,2,NULL,NULL,&f.resolver).code);
    assert(!steer_draft_resolver_retain(f.resolver).code);
    assert(steer_draft_resolver_destroy(f.resolver).code==STEER_PV1_POLICY_DENIED);
    steer_draft_resolver_release(f.resolver);
    assert(!steer_draft_resolver_submit(f.resolver,name,80,real_done,&f,&a).code);
    guard=loop_timer_new(f.loop,timeout,NULL);
    assert(guard);
    loop_timer_set(guard,2000);
    assert(!loop_run(f.loop)&&f.calls==1);
    assert(!steer_draft_resolver_destroy(f.resolver).code);
    loop_timer_free(guard);
    loop_free(f.loop);
    puts("resolver tests passed");
    return 0;
}
