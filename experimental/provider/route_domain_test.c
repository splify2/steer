#define _GNU_SOURCE
#include "route_dial.h"
#include "resolver.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
struct test {
    struct loop*loop;
    struct loop_timer*work;
    struct steer_draft_resolver*resolver;
    struct steer_draft_routes*routes;
    struct steer_draft_stream_runtime*streams;
    struct steer_pv1_host*host;
    struct steer_pv1_stream*stream;
    struct steer_pv1_async_start operation;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned kind,calls,phase,block;
    int entered,released,listener;
    uint32_t code;
}
;
static uint64_t now(void){
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;
}
static void backend(void*arg,const char*host,uint16_t port,struct steer_draft_resolve_result*out){
    struct test*t=arg;
    uint32_t i;
    assert(!strcmp(host,"localhost"));
    pthread_mutex_lock(&t->lock);
    t->entered=1;
    pthread_cond_signal(&t->changed);
    while((t->kind==1||t->kind==2)&&!t->released)pthread_cond_wait(&t->changed,&t->lock);
    pthread_mutex_unlock(&t->lock);
    memset(out,0,sizeof(*out));
    out->count=2;
    for(i=0;i<2;i++){
        struct sockaddr_in*a=(struct sockaddr_in*)&out->addresses[i];
        a->sin_family=AF_INET;
        a->sin_port=htons(port);
        a->sin_addr.s_addr=htonl(i?0x7f000001:0x7f000002);
    }
}
static struct steer_pv1_error policy(void*arg,const struct steer_draft_accepted*f,uint32_t*a){
    struct steer_pv1_error e={
        0,0
    }
    ;
    struct test*t=arg;
    assert(f->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&f->destination.address.len==9&&!memcmp(f->destination.address.data,"localhost",9));
    *a=t->block?STEER_DRAFT_ROUTE_BLOCK:STEER_DRAFT_ROUTE_DIRECT;
    return e;
}
static void done(void*arg,struct steer_pv1_error e,uint32_t failure,struct steer_pv1_stream*s,const struct steer_pv1_endpoint*b){
    struct test*t=arg;
    (void)failure;
    t->calls++;
    assert(t->calls==1);
    t->code=e.code;
    t->stream=s;
    if(!e.code)assert(s&&b&&b->port);
    else assert(!s&&!b);
    loop_timer_set(t->work,0);
}
static void work(struct loop*l,struct loop_timer*timer,void*arg){
    struct test*t=arg;
    (void)timer;
    if(!t->phase++){
        assert(t->code==(t->kind==1?STEER_PV1_CANCELLED:t->kind==2?STEER_PV1_TIMEOUT:STEER_PV1_OK));
        t->operation.operation.api->release(t->operation.operation.handle);
        if(t->stream){
            steer_draft_stream_api()->close(t->stream);
            assert(!steer_draft_stream_api()->release(t->stream).code);
        }
        assert(!steer_draft_routes_destroy(t->routes).code);
        if(t->kind==1||t->kind==2){
            assert(steer_draft_resolver_destroy(t->resolver).code==STEER_PV1_POLICY_DENIED);
            pthread_mutex_lock(&t->lock);
            t->released=1;
            pthread_cond_signal(&t->changed);
            pthread_mutex_unlock(&t->lock);
        }
    }
    if(steer_draft_resolver_jobs(t->resolver)){
        assert(t->phase<1000);
        loop_timer_set(t->work,1);
        return;
    }
    assert(!steer_draft_resolver_destroy(t->resolver).code);
    assert(!steer_draft_stream_runtime_destroy(t->streams).code);
    assert(!steer_draft_buffers_destroy(t->host).code);
    loop_stop(l,0);
}
static void guard(struct loop*l,struct loop_timer*t,void*arg){
    (void)t;
    (void)arg;
    loop_stop(l,99);
}
static void run(unsigned kind){
    struct test t={
        0
    }
    ;
    struct sockaddr_in address={
        0
    }
    ;
    socklen_t len=sizeof(address);
    struct steer_draft_buffer_limits limits={
        4096,2,1
    }
    ;
    struct steer_draft_accepted flow={
        0
    }
    ;
    uint8_t ip[4]={
        127,0,0,1
    }
    ;
    struct loop_timer*timeout;
    t.kind=kind;
    t.loop=loop_new();
    assert(t.loop);
    assert(!pthread_mutex_init(&t.lock,NULL)&&!pthread_cond_init(&t.changed,NULL));
    assert(!steer_draft_buffers_create(&limits,NULL,&t.host).code);
    assert(!steer_draft_stream_runtime_create(t.loop,t.host,2,4,32,&t.streams).code);
    assert(!steer_draft_resolver_create(t.loop,1,2,kind==3?NULL:backend,&t,&t.resolver).code);
    assert(!steer_draft_routes_create(t.loop,t.streams,1,4,policy,&t,&t.routes).code);
    assert(!steer_draft_routes_use_resolver(t.routes,t.resolver).code);
    t.listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    assert(t.listener>=0);
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(!bind(t.listener,(struct sockaddr*)&address,len)&&!listen(t.listener,2)&&!getsockname(t.listener,(struct sockaddr*)&address,&len));
    flow.generation=1;
    flow.inbound_id.data=(const uint8_t*)"test";
    flow.inbound_id.len=4;
    flow.flow_class=STEER_PV1_FLOW_STREAM;
    flow.source.size=sizeof(flow.source);
    flow.source.version=1;
    flow.source.tag=STEER_PV1_ENDPOINT_IPV4;
    flow.source.address.data=ip;
    flow.source.address.len=4;
    flow.source.port=1234;
    flow.destination=flow.source;
    flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;
    flow.destination.address.data=(const uint8_t*)"localhost";
    flow.destination.address.len=9;
    flow.destination.port=ntohs(address.sin_port);
    t.work=loop_timer_new(t.loop,work,&t);
    timeout=loop_timer_new(t.loop,guard,NULL);
    assert(t.work&&timeout);
    loop_timer_set(timeout,3000);
    {
        struct steer_pv1_async_start rejected;
        t.block=1;
        rejected=steer_draft_route_dial(t.routes,&flow,now()+2000000000u,done,&t);
        assert(rejected.disposition==STEER_PV1_REJECTED&&rejected.error.code==STEER_PV1_POLICY_DENIED&&!steer_draft_resolver_jobs(t.resolver));
        t.block=0;
    }
    t.operation=steer_draft_route_dial(t.routes,&flow,now()+(kind==2?30000000u:2000000000u),done,&t);
    assert(t.operation.disposition==STEER_PV1_PENDING&&!t.calls);
    if(kind==1||kind==2){
        pthread_mutex_lock(&t.lock);
        while(!t.entered)pthread_cond_wait(&t.changed,&t.lock);
        pthread_mutex_unlock(&t.lock);
    }
    if(kind==1)t.operation.operation.api->cancel(t.operation.operation.handle);
    assert(!loop_run(t.loop)&&t.calls==1);
    close(t.listener);
    loop_timer_free(t.work);
    loop_timer_free(timeout);
    loop_free(t.loop);
    pthread_cond_destroy(&t.changed);
    pthread_mutex_destroy(&t.lock);
}
int main(void){
    run(0);
    run(1);
    run(2);
    run(3);
    puts("route domain tests passed");
    return 0;
}
