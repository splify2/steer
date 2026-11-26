#define _GNU_SOURCE
#include "datagram_routes.h"
#include "datagram.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct fixture;
struct watch {struct fixture *fixture;struct steer_draft_binding_lease *lease;int finalized;};
struct backend {struct steer_draft_datagram_runtime *native;struct fixture *fixture;unsigned calls,releases;int refuse,failure;};
struct origin {struct steer_pv1_datagram_ref inner;struct backend *backend;};
struct open_job {struct origin *origin;steer_pv1_datagram_open_done done;void *userdata;};
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct loop_timer *error_timer;struct steer_draft_operations *errors;
    struct steer_pv1_host *host;struct steer_draft_datagram_runtime *native;
    struct steer_draft_datagram_router *router;
    struct steer_pv1_datagram_association_ref association;
    struct steer_pv1_datagram_ref refs[2];struct steer_pv1_operation_ref operation;
    struct backend backends[2];struct watch watches[7];
    struct steer_pv1_endpoint endpoint;struct steer_pv1_flow_metadata flow;
    struct steer_pv1_buffer *buffer;struct sockaddr_in locals[2];
    uint8_t ip[4];unsigned selected,slot,phase,drained;int peer;uint32_t bytes,code;
};
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+1000000000ull;}
static uint32_t limit(struct steer_pv1_datagram *p){struct origin *o=(void *)p;return o->inner.api->message_limit(o->inner.handle)?8:0;}
static struct steer_pv1_async_start send_message(struct steer_pv1_datagram *p,struct steer_pv1_buffer *b,
    uint32_t at,uint32_t n,uint64_t until,steer_pv1_datagram_done done,void *u){
    struct origin *o=(void *)p;return o->inner.api->send(o->inner.handle,b,at,n,until,done,u);
}
static struct steer_pv1_async_start receive_message(struct steer_pv1_datagram *p,struct steer_pv1_buffer *b,
    uint32_t at,uint32_t n,uint64_t until,steer_pv1_datagram_done done,void *u){
    struct origin *o=(void *)p;return o->inner.api->receive(o->inner.handle,b,at,n,until,done,u);
}
static void close_origin(struct steer_pv1_datagram *p){struct origin *o=(void *)p;o->inner.api->close(o->inner.handle);}
static struct steer_pv1_error release_origin(struct steer_pv1_datagram *p){
    struct origin *o=(void *)p;o->backend->releases++;
    if(o->backend->refuse)return (struct steer_pv1_error){STEER_PV1_IO,0};
    struct steer_pv1_error e=o->inner.api->release(o->inner.handle);if(!e.code)free(o);return e;
}
static const struct steer_pv1_datagram_api origin_api={sizeof(origin_api),STEER_PV1_DRAFT_LAYOUT,
    limit,send_message,receive_message,close_origin,release_origin};
static void origin_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct open_job *job=arg;
    if(e.code){free(job->origin);job->done(job->userdata,e,ref,bound,peer);}
    else{job->origin->inner=ref;job->done(job->userdata,e,(struct steer_pv1_datagram_ref){(void *)job->origin,&origin_api},bound,peer);}
    free(job);
}
static void error_deliver(void *arg,struct steer_pv1_error e){
    struct open_job *job=arg;job->done(job->userdata,e,(struct steer_pv1_datagram_ref){NULL,NULL},NULL,NULL);free(job);
}
static void error_dispatch(struct loop *l,struct loop_timer *t,void *arg){
    (void)l;(void)t;struct fixture *f=arg;(void)steer_draft_operations_dispatch(f->errors,32,NULL);
}
static struct steer_pv1_async_start backend_open(void *arg,const struct steer_pv1_flow_metadata *flow,
    uint64_t until,steer_pv1_datagram_open_done done,void *u){
    struct backend *b=arg;b->calls++;
    if(b->failure==1)return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{STEER_PV1_IO,0},{NULL,NULL}};
    struct open_job *job=calloc(1,sizeof(*job));assert(job);
    if(b->failure==2){
        job->done=done;job->userdata=u;
        struct steer_pv1_async_start a=steer_draft_operation_start(b->fixture->errors,error_deliver,job);
        assert(a.disposition==STEER_PV1_PENDING);
        assert(!steer_draft_operation_resolve(a.operation.handle,(struct steer_pv1_error){STEER_PV1_IO,0}).code);
        loop_timer_set(b->fixture->error_timer,0);return a;
    }
    job->origin=calloc(1,sizeof(*job->origin));assert(job->origin);job->origin->backend=b;job->done=done;job->userdata=u;
    struct steer_pv1_async_start a=steer_draft_datagram_backend_api()->open(b->native,flow,until,origin_opened,job);
    if(a.disposition!=STEER_PV1_PENDING){free(job->origin);free(job);}return a;
}
static const struct steer_pv1_datagram_backend_api backend_api={sizeof(backend_api),STEER_PV1_DRAFT_LAYOUT,backend_open};
static struct steer_pv1_error select_binding(void *arg,const struct steer_pv1_flow_metadata *flow,uint32_t *index){
    struct fixture *f=arg;assert(flow->generation==7);
    if(flow->destination.port==1)return (struct steer_pv1_error){STEER_PV1_IO,0};
    *index=flow->destination.port==2?UINT32_MAX:flow->destination.port==3?999:f->selected;
    return (struct steer_pv1_error){0,0};
}
static void finalized(void *arg,const struct steer_draft_binding_identity *id){
    struct watch *w=arg;(void)id;assert(!w->finalized);w->finalized=1;loop_timer_set(w->fixture->work,0);
}
static void make_lease(struct fixture *f,unsigned n,uint64_t generation,uint32_t flow){
    struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,generation,n==6?101:n+100,
        {(const uint8_t *)(n==2?"backend-b":"backend-a"),9},n==5?0:STEER_DRAFT_DATAGRAM_BINDING_PREPARED,flow};
    f->watches[n].fixture=f;
    assert(!steer_draft_binding_lease_create(f->loop,&id,128,finalized,&f->watches[n],&f->watches[n].lease).code);
}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct fixture *f=arg;assert(!e.code&&ref.handle&&bound&&peer);f->refs[f->slot]=ref;
    assert(steer_draft_binding_references(f->watches[f->slot+1].lease)==3);
    f->locals[f->slot]=(struct sockaddr_in){.sin_family=AF_INET,.sin_port=htons(bound->port)};
    memcpy(&f->locals[f->slot].sin_addr,bound->address.data,4);loop_timer_set(f->work,0);
}
static void completed(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t n){
    struct fixture *f=arg;assert(buffer==f->buffer);f->code=e.code;f->bytes=n;loop_timer_set(f->work,0);
}
static void open_error(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct fixture *f=arg;assert(e.code==STEER_PV1_IO&&!ref.handle&&!ref.api&&!bound&&!peer);
    assert(!f->backends[1].calls);loop_timer_set(f->work,0);
}
static void remember(struct fixture *f,struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING);f->operation=a.operation;}
static void release_operation(struct fixture *f){if(f->operation.handle){f->operation.api->release(f->operation.handle);f->operation=(struct steer_pv1_operation_ref){NULL,NULL};}}
static void watchdog(struct loop *l,struct loop_timer *t,void *u){(void)l;(void)t;(void)u;assert(!"registry watchdog");}
static void drained(void *arg,struct steer_draft_datagram_router *r){
    struct fixture *f=arg;uint32_t a,t,o;uint64_t bytes;
    assert(r==f->router&&!f->drained++);
    steer_draft_datagram_router_usage(r,&a,&t,&o,&bytes);assert(!a&&!t&&!o&&!bytes);
    assert(steer_draft_datagram_router_destroy(r).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0); /* host owner collects only after notification returns */
}
static void server_reply(struct fixture *f,unsigned slot,const char *request,const char *reply){
    struct pollfd p={.fd=f->peer,.events=POLLIN};assert(poll(&p,1,1000)==1);
    char bytes[32];struct sockaddr_in from;socklen_t n=sizeof(from);
    ssize_t got=recvfrom(f->peer,bytes,sizeof(bytes),MSG_DONTWAIT,(struct sockaddr *)&from,&n);
    assert(got==(ssize_t)strlen(request)&&!memcmp(bytes,request,(size_t)got));
    assert(from.sin_port==f->locals[slot].sin_port);
    assert(sendto(f->peer,reply,strlen(reply),0,(struct sockaddr *)&from,n)==(ssize_t)strlen(reply));
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
    (void)timer;struct fixture *f=arg;struct steer_pv1_mut_span span;uint32_t targets;
    if(f->phase<6||f->phase>=100)release_operation(f);
    switch(f->phase){
    case 100:case 101:
        steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);
        if(targets){loop_timer_set(f->work,0);break;}
        assert(steer_draft_binding_references(f->watches[0].lease)==3);
        assert(steer_draft_binding_references(f->watches[1].lease)==2);
        if(f->phase==100){
            f->backends[0].failure=2;f->phase=101;
            remember(f,f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),open_error,f));
        }else{
            assert(f->backends[0].calls==2);f->backends[0].failure=0;f->phase=0;
            remember(f,f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),opened,f));
        }break;
    case 0:
        f->selected=f->slot=1;f->phase=1;
        remember(f,f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),opened,f));break;
    case 1:
        assert(f->backends[0].calls==3&&f->backends[1].calls==1);
        assert(f->locals[0].sin_port!=f->locals[1].sin_port);
        assert(!steer_draft_binding_retire(f->watches[1].lease).code);f->selected=0;
        assert(f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),opened,f).error.code==STEER_PV1_POLICY_DENIED);
        f->selected=1;
        assert(f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),opened,f).error.code==STEER_PV1_RESOURCE_EXHAUSTED);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&span).code);memcpy(span.data,"ping0",5);
        assert(f->refs[0].api->send(f->refs[0].handle,f->buffer,0,9,deadline(),completed,f).disposition==STEER_PV1_REJECTED);
        f->phase=2;remember(f,f->refs[0].api->send(f->refs[0].handle,f->buffer,0,5,deadline(),completed,f));break;
    case 2:
        assert(!f->code&&f->bytes==5);server_reply(f,0,"ping0","old0");f->phase=3;
        remember(f,f->refs[0].api->receive(f->refs[0].handle,f->buffer,0,16,deadline(),completed,f));break;
    case 3:
        assert(!f->code&&f->bytes==4);assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&span).code);
        assert(!memcmp(span.data,"old0",4));
        for(unsigned i=0;i<3;i++)assert(!steer_draft_binding_retire(f->watches[i].lease).code);
        steer_draft_datagram_router_quiesce(f->router);
        assert(f->association.api->open_target(f->association.handle,&f->endpoint,deadline(),opened,f).error.code==STEER_PV1_POLICY_DENIED);
        memcpy(span.data,"ping1",5);f->phase=4;
        remember(f,f->refs[1].api->send(f->refs[1].handle,f->buffer,0,5,deadline(),completed,f));break;
    case 4:
        assert(!f->code&&f->bytes==5);server_reply(f,1,"ping1","old1");f->phase=5;
        remember(f,f->refs[1].api->receive(f->refs[1].handle,f->buffer,0,16,deadline(),completed,f));break;
    case 5:
        assert(!f->code&&f->bytes==4);assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&span).code);
        assert(!memcmp(span.data,"old1",4));f->backends[0].refuse=1;
        for(unsigned i=0;i<2;i++){f->refs[i].api->close(f->refs[i].handle);assert(!f->refs[i].api->release(f->refs[i].handle).code);}
        f->association.api->close(f->association.handle);assert(!f->association.api->release(f->association.handle).code);
        for(unsigned i=3;i<7;i++)assert(!steer_draft_binding_retire(f->watches[i].lease).code);
        f->phase=6;loop_timer_set(f->work,0);break;
    case 6:
        if(!f->backends[0].releases||!f->backends[1].releases){loop_timer_set(f->work,0);break;}
        steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);assert(targets==1);
        assert(!f->watches[0].finalized&&!f->watches[1].finalized&&!f->watches[2].finalized);
        assert(!f->drained);
        assert(steer_draft_binding_references(f->watches[1].lease)>0);
        assert(steer_draft_datagram_router_destroy(f->router).code==STEER_PV1_POLICY_DENIED);
        f->backends[0].refuse=0;assert(steer_draft_datagram_router_retry_cleanup(f->router)==1);
        f->phase=7;loop_timer_set(f->work,0);break;
    case 7:
        steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);
        if(!f->drained)return; /* no retry timer: actual owner drain notification wakes us */
        assert(!targets&&f->drained==1);
        assert(f->backends[0].releases==2&&f->backends[1].releases==1);
        assert(!steer_draft_datagram_router_destroy(f->router).code);f->router=NULL;
        assert(!steer_draft_datagram_runtime_destroy(f->native).code);f->native=NULL;
        f->phase=8;loop_timer_set(f->work,0);break;
    case 8:
        for(unsigned i=0;i<7;i++)if(!f->watches[i].finalized)return;
        for(unsigned i=0;i<7;i++)assert(!steer_draft_binding_lease_destroy(f->watches[i].lease).code);
        loop_stop(loop,0);break;
    default:assert(0);
    }
}
static void expect_rejected(struct fixture *f,struct steer_draft_binding_lease *configuration,
    const struct steer_draft_datagram_binding *bindings,uint32_t count,uint32_t code){
    struct steer_draft_datagram_route_limits limits={1,2,2,8,128,1000000000ull};
    struct steer_draft_datagram_router *r=NULL;
    assert(steer_draft_datagram_router_create_registry(f->loop,f->host,configuration,bindings,count,
        &limits,select_binding,f,&r).code==code&&!r);
    for(unsigned i=0;i<7;i++)assert(steer_draft_binding_references(f->watches[i].lease)==1);
}
static void *run_fixture(void *unused){
    (void)unused;struct fixture f={0};f.loop=loop_new();assert(f.loop);
    f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);assert(f.work&&f.watchdog);
    f.error_timer=loop_timer_new(f.loop,error_dispatch,&f);assert(f.error_timer);
    assert(!steer_draft_operations_create(8,NULL,&f.errors).code);
    loop_timer_set(f.watchdog,5000);
    struct steer_draft_buffer_limits buffer_limits={4096,8,8};assert(!steer_draft_buffers_create(&buffer_limits,NULL,&f.host).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,32,&f.buffer).code);
    assert(!steer_draft_datagram_runtime_create(f.loop,f.host,8,16,4096,&f.native).code);
    for(unsigned i=0;i<7;i++)make_lease(&f,i,i==3?8:7,i==4?STEER_PV1_FLOW_STREAM:STEER_PV1_FLOW_DATAGRAM);
    struct steer_draft_datagram_binding bindings[2];
    for(unsigned i=0;i<2;i++){
        f.backends[i].native=f.native;
        f.backends[i].fixture=&f;
        bindings[i]=(struct steer_draft_datagram_binding){f.loop,f.watches[i+1].lease,&backend_api,&f.backends[i]};
    }
    struct steer_draft_datagram_binding duplicate[2]={bindings[0],bindings[1]};
    duplicate[1].lease=f.watches[6].lease; /* distinct lease, same identity tuple */
    expect_rejected(&f,f.watches[0].lease,duplicate,2,STEER_PV1_INVALID);
    expect_rejected(&f,f.watches[3].lease,bindings,2,STEER_PV1_POLICY_DENIED);
    struct steer_draft_datagram_binding bad=bindings[0];bad.lease=f.watches[4].lease;
    expect_rejected(&f,f.watches[0].lease,&bad,1,STEER_PV1_POLICY_DENIED);
    bad.lease=f.watches[5].lease;expect_rejected(&f,f.watches[0].lease,&bad,1,STEER_PV1_UNSUPPORTED);
    bad=bindings[0];bad.owner=NULL;expect_rejected(&f,f.watches[0].lease,&bad,1,STEER_PV1_INVALID);
    expect_rejected(&f,f.watches[0].lease,bindings,STEER_DRAFT_DATAGRAM_BINDINGS_MAX+1,STEER_PV1_INVALID);
    struct steer_draft_datagram_route_limits limits={1,2,2,8,128,1000000000ull};
    assert(!steer_draft_datagram_router_create_registry(f.loop,f.host,f.watches[0].lease,bindings,2,
        &limits,select_binding,&f,&f.router).code);
    assert(!steer_draft_datagram_router_on_drained(f.router,drained,&f).code);
    assert(steer_draft_datagram_router_on_drained(f.router,drained,&f).code==STEER_PV1_POLICY_DENIED);
    memset(bindings,0,sizeof(bindings)); /* copied registry is independent */
    f.peer=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(f.peer>=0);
    struct sockaddr_in server={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(f.peer,(struct sockaddr *)&server,sizeof(server)));socklen_t length=sizeof(server);
    assert(!getsockname(f.peer,(struct sockaddr *)&server,&length));memcpy(f.ip,(uint8_t[]){127,0,0,1},4);
    f.endpoint=(struct steer_pv1_endpoint){sizeof(f.endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{f.ip,4},ntohs(server.sin_port),0};
    f.flow=(struct steer_pv1_flow_metadata){.size=sizeof(f.flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={(const uint8_t *)"hy2",3},.principal_id={(const uint8_t *)"verified",8},
        .source=f.endpoint,.destination=f.endpoint,.flow_class=STEER_PV1_FLOW_DATAGRAM};f.flow.source.port=5555;
    const struct steer_pv1_datagram_route_api *api=steer_draft_datagram_router_api();
    assert(!api->create(f.router,&f.flow,&f.association).code);
    struct steer_pv1_endpoint denied=f.endpoint;denied.tag=STEER_PV1_ENDPOINT_DOMAIN;
    denied.address=(struct steer_pv1_span){(const uint8_t *)"localhost",9};
    assert(f.association.api->open_target(f.association.handle,&denied,deadline(),opened,&f).error.code==STEER_PV1_UNSUPPORTED);
    denied.port=1;assert(f.association.api->open_target(f.association.handle,&denied,deadline(),opened,&f).error.code==STEER_PV1_IO);
    denied.port=2;assert(f.association.api->open_target(f.association.handle,&denied,deadline(),opened,&f).error.code==STEER_PV1_POLICY_DENIED);
    denied.port=3;assert(f.association.api->open_target(f.association.handle,&denied,deadline(),opened,&f).error.code==STEER_PV1_INVALID);
    assert(!f.backends[0].calls&&!f.backends[1].calls);
    f.phase=100;f.backends[0].failure=1;
    remember(&f,api->open_target(f.association.handle,&f.endpoint,deadline(),open_error,&f));assert(!loop_run(f.loop));
    close(f.peer);steer_draft_buffers_api()->release(f.host,f.buffer);assert(!steer_draft_buffers_destroy(f.host).code);
    assert(!steer_draft_operations_destroy(f.errors).code);
    loop_timer_free(f.error_timer);loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);return NULL;
}
struct empty_fixture {struct loop *loop;struct loop_timer *work;struct steer_pv1_host *host;
    struct steer_draft_binding_lease *lease;struct steer_draft_datagram_router *router;unsigned notified,finalized,pumped;
    struct steer_pv1_datagram_association_ref association;};
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
static void empty_pumped(void *arg){
    struct empty_fixture *f=arg;if(f->pumped)return;
    assert(!f->notified&&f->association.handle);f->pumped=1;loop_timer_set(f->work,0);
}
#endif
static void empty_drained(void *arg,struct steer_draft_datagram_router *r){
    struct empty_fixture *f=arg;assert(r==f->router&&!f->notified++);
    assert(steer_draft_datagram_router_destroy(r).code==STEER_PV1_POLICY_DENIED);loop_timer_set(f->work,0);
}
static void empty_finalized(void *arg,const struct steer_draft_binding_identity *id){
    (void)id;struct empty_fixture *f=arg;assert(!f->router&&!f->finalized++);loop_timer_set(f->work,0);
}
static void empty_work(struct loop *l,struct loop_timer *t,void *arg){
    (void)t;struct empty_fixture *f=arg;
    if(f->association.handle){
        assert(f->pumped&&!f->notified);f->association.api->close(f->association.handle);
        assert(!f->association.api->release(f->association.handle).code);f->association.handle=NULL;
        assert(!f->notified);return; /* only the new final-collection event wakes the router */
    }
    assert(f->notified==1);
    if(f->router){assert(!steer_draft_datagram_router_destroy(f->router).code);f->router=NULL;return;}
    assert(f->finalized==1);assert(!steer_draft_binding_lease_destroy(f->lease).code);
    assert(!steer_draft_buffers_destroy(f->host).code);loop_stop(l,0);
}
static void empty_test(void){
    struct empty_fixture f={0};f.loop=loop_new();assert(f.loop);f.work=loop_timer_new(f.loop,empty_work,&f);assert(f.work);
    struct loop_timer *guard=loop_timer_new(f.loop,watchdog,NULL);assert(guard);loop_timer_set(guard,3000);
    struct steer_draft_buffer_limits buffers={64,1,1};assert(!steer_draft_buffers_create(&buffers,NULL,&f.host).code);
    struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,7,1,{(const uint8_t *)"empty",5},0,STEER_PV1_FLOW_DATAGRAM};
    assert(!steer_draft_binding_lease_create(f.loop,&id,8,empty_finalized,&f,&f.lease).code);
    struct steer_draft_datagram_route_limits limits={1,1,1,1,0,1000000};
    assert(!steer_draft_datagram_router_create_registry(f.loop,f.host,f.lease,NULL,0,&limits,select_binding,NULL,&f.router).code);
    assert(!steer_draft_datagram_router_on_drained(f.router,empty_drained,&f).code);
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
    steer_draft_datagram_router_test_after_pump(f.router,empty_pumped,&f);
    uint8_t ip[4]={127,0,0,1};
    struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={(const uint8_t *)"empty",5},.source=endpoint,.destination=endpoint,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    assert(!steer_draft_datagram_router_api()->create(f.router,&flow,&f.association).code);
#endif
    assert(!steer_draft_binding_retire(f.lease).code);steer_draft_datagram_router_quiesce(f.router);
    assert(!f.notified&&steer_draft_datagram_router_destroy(f.router).code==STEER_PV1_POLICY_DENIED);
    assert(!loop_run(f.loop));loop_timer_free(f.work);loop_timer_free(guard);loop_free(f.loop);
}
int main(void){
    empty_test();run_fixture(NULL);pthread_t workers[4];
    for(unsigned i=0;i<4;i++)assert(!pthread_create(&workers[i],NULL,run_fixture,NULL));
    for(unsigned i=0;i<4;i++)assert(!pthread_join(workers[i],NULL));
    puts("datagram registry: 1/4 owners, selected reject/deferred error, two providers/same destination, policy-before-DNS, provider/config retire drain, quarantine pins PASS");return 0;
}
