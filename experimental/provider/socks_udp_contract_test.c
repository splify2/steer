/* SPDX-License-Identifier: GPL-3.0-only */
#include "socks_udp_backend.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct test {
    struct loop *loop;
    struct loop_timer *work,*watch;
    struct steer_pv1_host *host;
    struct steer_socks_udp_backend *backend;
    struct steer_pv1_datagram_ref ref;
    struct steer_pv1_async_start op;
    struct steer_pv1_buffer *buf;
    int phase,drained;
    uint32_t code,bytes;
    uint64_t cpu;
};
static uint64_t clock_ns(clockid_t id) {
    struct timespec t;assert(!clock_gettime(id,&t));
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
}
static uint64_t deadline(void){return clock_ns(CLOCK_MONOTONIC)+3000000000ull;}
static void pending(struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING);}
static void opened(void *p,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
                   const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct test *t=p;assert(!e.code&&ref.handle&&!bound&&peer);t->ref=ref;loop_timer_set(t->work,0);
}
static void completed(void *p,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n) {
    struct test *t=p;assert(b==t->buf);t->code=e.code;t->bytes=n;loop_timer_set(t->work,0);
}
static void drained(void *p){struct test *t=p;t->drained=1;loop_timer_set(t->work,0);}
static void work(struct loop *loop,struct loop_timer *timer,void *p) {
    struct test *t=p;const struct steer_pv1_datagram_api *api=t->ref.api;
    struct steer_pv1_mut_span view;(void)timer;
    if(t->phase!=2&&t->phase<6)t->op.operation.api->release(t->op.operation.handle);
    switch(t->phase++) {
    case 0:
        assert(api->message_limit(t->ref.handle)==65000);
        assert(!steer_draft_buffers_api()->writable(t->host,t->buf,&view).code);
        view.data[0]=1;
        t->op=api->send(t->ref.handle,t->buf,0,1,deadline(),completed,t);pending(t->op);break;
    case 1:
        assert(!t->code&&t->bytes==1);
        /* Independent server signals only after all three replies were sent. */
        {char ready;assert(read(STDIN_FILENO,&ready,1)==1&&ready=='R');}
        t->cpu=clock_ns(CLOCK_PROCESS_CPUTIME_ID);loop_timer_set(t->work,400);break;
    case 2:
        assert(clock_ns(CLOCK_PROCESS_CPUTIME_ID)-t->cpu<150000000ull);
        t->op=api->receive(t->ref.handle,t->buf,0,65520,deadline(),completed,t);pending(t->op);break;
    case 3:
        assert(!t->code&&t->bytes==65000);
        assert(!steer_draft_buffers_api()->writable(t->host,t->buf,&view).code);
        assert(view.data[0]==0x41&&view.data[64999]==0x41);
        t->op=api->receive(t->ref.handle,t->buf,0,65520,deadline(),completed,t);pending(t->op);break;
    case 4:
        assert(t->code==STEER_PV1_RESOURCE_EXHAUSTED&&!t->bytes);
        t->op=api->receive(t->ref.handle,t->buf,0,65520,deadline(),completed,t);pending(t->op);break;
    case 5:
        assert(!t->code&&t->bytes==1);
        assert(!steer_draft_buffers_api()->writable(t->host,t->buf,&view).code&&view.data[0]==0x43);
        api->close(t->ref.handle);assert(!api->release(t->ref.handle).code);
        steer_socks_udp_backend_retire(t->backend);break;
    case 6:
        assert(t->drained);
        {uint32_t ops;uint64_t bytes;steer_socks_udp_backend_usage(t->backend,&ops,&bytes);assert(!ops&&!bytes);}
        loop_stop(loop,0);break;
    default:assert(0);
    }
}
static void watch(struct loop *l,struct loop_timer *t,void *p){(void)l;(void)t;(void)p;abort();}
int main(int argc,char **argv) {
    assert(argc==3);struct test t={0};t.loop=loop_new();assert(t.loop);
    struct steer_draft_buffer_limits lim={131072,4,4};
    assert(!steer_draft_buffers_create(&lim,NULL,&t.host).code);
    assert(!steer_draft_buffers_api()->allocate(t.host,65520,&t.buf).code);
    struct sockaddr_in up={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons((uint16_t)atoi(argv[1]))};
    assert(!steer_socks_udp_backend_create(t.loop,t.host,&up,7,1,8,131072,8,1000,drained,&t,&t.backend).code);
    t.work=loop_timer_new(t.loop,work,&t);t.watch=loop_timer_new(t.loop,watch,&t);assert(t.work&&t.watch);loop_timer_set(t.watch,8000);
    uint8_t ip[]={127,0,0,1};
    struct steer_pv1_endpoint ep={sizeof ep,STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},(uint16_t)atoi(argv[2]),0};
    struct steer_pv1_flow_metadata flow={.size=sizeof flow,.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={(const uint8_t *)"test",4},.source=ep,.destination=ep,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    const struct steer_draft_datagram_binding *b=steer_socks_udp_backend_binding(t.backend);
    t.op=b->api->open(b->context,&flow,deadline(),opened,&t);pending(t.op);
    assert(!loop_run(t.loop));assert(!steer_socks_udp_backend_destroy(t.backend).code);
    steer_draft_buffers_api()->release(t.host,t.buf);assert(!steer_draft_buffers_destroy(t.host).code);
    loop_timer_free(t.work);loop_timer_free(t.watch);loop_free(t.loop);
    puts("PASS delayed receive, idle CPU, limit, oversize consumption and next packet");return 0;
}
