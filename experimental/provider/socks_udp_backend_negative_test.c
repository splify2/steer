/* SPDX-License-Identifier: GPL-3.0-only */
#include "socks_udp_backend.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct state { struct loop *loop;struct loop_timer *work,*watch;
    struct steer_socks_udp_backend *backend;struct steer_pv1_async_start op;int result,done; };
static uint64_t now(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static void done(void *p,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
                 const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct state *s=p;assert(e.code && !ref.handle && !bound && !peer);s->result=e.code;loop_timer_set(s->work,0);
}
static void drained(void *p){struct state *s=p;s->done=1;loop_timer_set(s->work,0);}
static void work(struct loop *loop,struct loop_timer *t,void *p){
    struct state *s=p;(void)t;
    if(s->result){s->op.operation.api->release(s->op.operation.handle);s->result=0;steer_socks_udp_backend_retire(s->backend);}
    if(s->done){uint32_t n;uint64_t bytes;steer_socks_udp_backend_usage(s->backend,&n,&bytes);assert(!n&&!bytes);loop_stop(loop,0);}
}
static void watch(struct loop *loop,struct loop_timer *t,void *p){(void)loop;(void)t;(void)p;abort();}
int main(int argc,char **argv){
    assert(argc==2);struct state s={0};s.loop=loop_new();assert(s.loop);
    struct steer_pv1_host *host;struct steer_draft_buffer_limits limits={1024,2,2};
    assert(!steer_draft_buffers_create(&limits,NULL,&host).code);
    struct sockaddr_in up={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons((uint16_t)atoi(argv[1]))};
    assert(!steer_socks_udp_backend_create(s.loop,host,&up,7,1,8,1024,8,1000,drained,&s,&s.backend).code);
    s.work=loop_timer_new(s.loop,work,&s);s.watch=loop_timer_new(s.loop,watch,&s);assert(s.work&&s.watch);loop_timer_set(s.watch,5000);
    uint8_t ip[]={127,0,0,1};
    struct steer_pv1_endpoint ep={sizeof ep,STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},12345,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof flow,.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={(const uint8_t *)"test",4},.source=ep,.destination=ep,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    const struct steer_draft_datagram_binding *b=steer_socks_udp_backend_binding(s.backend);
    s.op=b->api->open(b->context,&flow,now()+2000000000ull,done,&s);assert(s.op.disposition==STEER_PV1_PENDING);
    assert(!loop_run(s.loop));assert(!steer_socks_udp_backend_destroy(s.backend).code);
    assert(!steer_draft_buffers_destroy(host).code);loop_timer_free(s.work);loop_timer_free(s.watch);loop_free(s.loop);
    puts("PASS upstream failure is not direct; zero-budget drain");return 0;
}
