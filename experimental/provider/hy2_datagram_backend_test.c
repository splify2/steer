/* SPDX-License-Identifier: GPL-3.0-only */
#include "hy2_datagram_backend.h"
#include "hy2_tcp_client.h"
#include "buffers.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct fixture {
    struct loop *loop;
    struct loop_timer *work,*watchdog;
    struct steer_pv1_host *host;
    struct steer_hy2_datagram_backend *backend;
    struct steer_pv1_datagram_ref ref;
    struct steer_pv1_async_start op;
    struct steer_pv1_buffer *buffer,*other;
    uint64_t until;
    uint32_t code,bytes;
    int phase,calls,drained;
};
static uint64_t now(void) {
    struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
}
static void pending(struct steer_pv1_async_start a) { assert(a.disposition==STEER_PV1_PENDING); }
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;
    assert(!e.code&&ref.handle&&ref.api&&!bound&&peer);
    assert(now()<f->until);
    f->ref=ref;loop_timer_set(f->work,0);
}
static void completed(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n) {
    struct fixture *f=arg;
    assert(b==f->buffer);
    f->code=e.code;f->bytes=n;f->calls++;
    if (e.code==STEER_PV1_TIMEOUT) {
        uint64_t observed=now();
        assert(observed>=f->until);
        printf("receive deadline_ns=%llu callback_ns=%llu\n",
               (unsigned long long)f->until,(unsigned long long)observed);
    }
    assert(f->ref.api->release(f->ref.handle).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0);
}
static void drained(void *arg) {
    struct fixture *f=arg;
    assert(f->phase==6);f->drained=1;loop_timer_set(f->work,0);
}
static void work(struct loop *l,struct loop_timer *t,void *arg) {
    (void)t;struct fixture *f=arg;
    const struct steer_pv1_datagram_api *api=f->ref.api;
    struct steer_pv1_mut_span view;
    if (f->phase<6) f->op.operation.api->release(f->op.operation.handle);
    switch (f->phase++) {
    case 0:
        assert(api->message_limit(f->ref.handle)==1000);
        assert(api->receive(f->ref.handle,f->buffer,0,1,now()-1,completed,f).disposition==STEER_PV1_REJECTED);
        f->op=api->send(f->ref.handle,f->buffer,0,0,now()+2000000000ull,completed,f);
        pending(f->op);assert(!f->calls);break;
    case 1:
        assert(!f->code&&!f->bytes);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);
        for (unsigned i=0;i<1000;i++) view.data[i]=(uint8_t)(i*17u);
        f->op=api->send(f->ref.handle,f->buffer,0,1000,now()+2000000000ull,completed,f);
        pending(f->op);break;
    case 2:
        assert(!f->code&&f->bytes==1000);
        f->op=api->receive(f->ref.handle,f->buffer,0,1000,now()+2000000000ull,completed,f);
        pending(f->op);break;
    case 3:
        assert(!f->code&&f->bytes==1000);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);
        for (unsigned i=0;i<1000;i++) assert(view.data[i]==(uint8_t)(i*17u));
        f->until=now()+50000000ull;
        f->op=api->receive(f->ref.handle,f->buffer,0,1000,f->until,completed,f);
        pending(f->op);break;
    case 4:
        assert(f->code==STEER_PV1_TIMEOUT&&!f->bytes);
        f->op=api->receive(f->ref.handle,f->buffer,0,1000,now()+2000000000ull,completed,f);
        pending(f->op);
        assert(api->receive(f->ref.handle,f->other,0,1,now()+1000000000ull,completed,f).disposition==STEER_PV1_REJECTED);
        f->op.operation.api->cancel(f->op.operation.handle);
        steer_hy2_datagram_backend_retire(f->backend);
        assert(!f->drained);
        api->close(f->ref.handle);
        assert(api->release(f->ref.handle).code==STEER_PV1_POLICY_DENIED);
        break;
    case 5:
        assert(f->code==STEER_PV1_CANCELLED&&!f->bytes&&!f->drained);
        assert(!api->release(f->ref.handle).code);
        break;
    case 6:
        assert(f->drained);
        loop_stop(l,0);break;
    default: assert(0);
    }
}
static void watchdog(struct loop *l,struct loop_timer *t,void *arg) {
    (void)l;(void)t;(void)arg;assert(!"watchdog");
}
int main(int argc,char **argv) {
    assert(argc==4);
    struct fixture f={0};f.loop=loop_new();assert(f.loop);
    struct steer_draft_buffer_limits limits={65536,4,4};
    assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,1000,&f.buffer).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,1,&f.other).code);
    struct steer_hy2_profile *profile=NULL;
    assert(!steer_hy2_profile_prepare(7,"127.0.0.1",(uint16_t)atoi(argv[1]),
        "localhost",argv[2],getenv("STEER_LAB_HY2_TOKEN"),&profile));
    assert(!steer_hy2_datagram_backend_create(f.loop,f.host,profile,7,1,16,65536,32,
                                              3000,drained,&f,&f.backend).code);
    f.work=loop_timer_new(f.loop,work,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);
    assert(f.work&&f.watchdog);loop_timer_set(f.watchdog,10000);
    uint8_t ip[]={127,0,0,1};
    struct steer_pv1_endpoint ep={sizeof ep,STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof flow,.version=STEER_PV1_DRAFT_LAYOUT,
        .generation=7,.inbound_id={(const uint8_t *)"test",4},.source=ep,.destination=ep,
        .flow_class=STEER_PV1_FLOW_DATAGRAM};
    flow.destination.port=(uint16_t)atoi(argv[3]);
    const struct steer_draft_datagram_binding *binding=steer_hy2_datagram_binding(f.backend);
    f.until=now()+3000000000ull;
    f.op=binding->api->open(binding->context,&flow,f.until,opened,&f);pending(f.op);
    assert(!f.ref.handle);memset(ip,0,sizeof ip);
    assert(!loop_run(f.loop));
    assert(!steer_hy2_datagram_backend_destroy(f.backend).code);
    steer_draft_buffers_api()->release(f.host,f.buffer);
    steer_draft_buffers_api()->release(f.host,f.other);
    assert(!steer_draft_buffers_destroy(f.host).code);
    loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
    puts("PASS SDK backend echo, receive deadline, cancel, release and drain");
    return 0;
}
