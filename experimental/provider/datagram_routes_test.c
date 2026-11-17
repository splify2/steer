#define _GNU_SOURCE
#include "datagram_routes.h"
#include "datagram.h"
#include "buffers.h"
#include "resolver.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct steer_pv1_host *host;struct steer_draft_datagram_runtime *native;
    struct steer_draft_datagram_router *router;struct steer_draft_binding_lease *lease;
    struct steer_pv1_datagram_association_ref associations[2];
    struct steer_pv1_datagram_ref ref;struct steer_pv1_async_start operation;
    struct steer_pv1_buffer *buffer;
    struct steer_pv1_flow_metadata flow;struct steer_pv1_endpoint destination;
    struct sockaddr_in server,local[2],received_from;
    uint8_t ip[4],source[4],inbound[5],principal[8];
    unsigned phase,backend_calls,evaluations,slot,finalized;uint32_t code,bytes;
    uint16_t expected_port;int peer;
    unsigned fault_mode,fault_callbacks;
    unsigned release_attempts,recovered;
    struct steer_pv1_datagram_ref private_origin;
    steer_pv1_datagram_open_done private_done;void *private_arg;
    struct steer_draft_resolver *resolver;
    pthread_mutex_t mutex;pthread_cond_t condition;int resolving,unblock;
};
static uint64_t deadline(uint64_t ms) {struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+ms*1000000ull;}
static struct steer_pv1_error evaluate(void *arg,const struct steer_pv1_flow_metadata *flow,uint32_t *action) {
    struct fixture *f=arg;f->evaluations++;
    assert(flow->generation==7&&flow->flow_class==STEER_PV1_FLOW_DATAGRAM);
    assert(flow->inbound_id.len==5&&!memcmp(flow->inbound_id.data,"socks",5));
    assert(flow->principal_id.len==8&&!memcmp(flow->principal_id.data,"verified",8));
    *action=(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&(f->fault_mode!=4||flow->destination.port==53))||flow->destination.port==1?
        STEER_DRAFT_DATAGRAM_ROUTE_BLOCK:flow->destination.port==2?STEER_DRAFT_DATAGRAM_ROUTE_DETOUR:STEER_DRAFT_DATAGRAM_ROUTE_DIRECT;
    return (struct steer_pv1_error){0,0};
}
static void warm_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;assert(!e.code&&ref.handle&&bound&&peer);
    f->ref=ref;loop_timer_set(f->work,0);
}
static uint32_t private_limit(struct steer_pv1_datagram *p) {
    struct fixture *f=(void *)p;return f->private_origin.api->message_limit(f->private_origin.handle);
}
static struct steer_pv1_async_start private_send(struct steer_pv1_datagram *p,struct steer_pv1_buffer *b,
    uint32_t o,uint32_t n,uint64_t d,steer_pv1_datagram_done cb,void *u) {
    struct fixture *f=(void *)p;return f->private_origin.api->send(f->private_origin.handle,b,o,n,d,cb,u);
}
static struct steer_pv1_async_start private_receive(struct steer_pv1_datagram *p,struct steer_pv1_buffer *b,
    uint32_t o,uint32_t n,uint64_t d,steer_pv1_datagram_done cb,void *u) {
    struct fixture *f=(void *)p;return f->private_origin.api->receive(f->private_origin.handle,b,o,n,d,cb,u);
}
static void private_close(struct steer_pv1_datagram *p) {
    struct fixture *f=(void *)p;f->private_origin.api->close(f->private_origin.handle);
}
static struct steer_pv1_error private_release(struct steer_pv1_datagram *p) {
    struct fixture *f=(void *)p;f->release_attempts++;
    if(!f->recovered)return (struct steer_pv1_error){STEER_PV1_IO,0};
    struct steer_pv1_error e=f->private_origin.api->release(f->private_origin.handle);
    if(!e.code)f->private_origin=(struct steer_pv1_datagram_ref){NULL,NULL};
    return e;
}
static const struct steer_pv1_datagram_api private_api={sizeof(private_api),STEER_PV1_DRAFT_LAYOUT,
    private_limit,private_send,private_receive,private_close,private_release};
static void private_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;assert(!e.code);f->private_origin=ref;
    f->private_done(f->private_arg,e,(struct steer_pv1_datagram_ref){(void *)f,&private_api},bound,peer);
}
static struct steer_pv1_async_start counted_open(void *arg,const struct steer_pv1_flow_metadata *flow,uint64_t until,
    steer_pv1_datagram_open_done done,void *userdata) {
    struct fixture *f=arg;f->backend_calls++;
    if(f->fault_mode==3){
        f->private_done=done;f->private_arg=userdata;
        return steer_draft_datagram_backend_api()->open(f->native,flow,until,private_opened,f);
    }
    return steer_draft_datagram_backend_api()->open(f->native,flow,until,done,userdata);
}
static const struct steer_pv1_datagram_backend_api backend={sizeof(backend),STEER_PV1_DRAFT_LAYOUT,counted_open};
static void completed(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes) {
    struct fixture *f=arg;assert(buffer==f->buffer);f->code=e.code;f->bytes=bytes;
    f->operation.operation.api->release(f->operation.operation.handle); /* early release denied */
    assert(steer_draft_datagram_router_destroy(f->router).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0);
}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;assert(!e.code&&ref.handle&&bound&&peer&&peer->port==f->expected_port);
    f->ref=ref;f->local[f->slot]=(struct sockaddr_in){.sin_family=AF_INET,.sin_port=htons(bound->port)};
    memcpy(&f->local[f->slot].sin_addr,bound->address.data,4);
    f->operation.operation.api->release(f->operation.operation.handle);
    assert(f->associations[f->slot].api->release(f->associations[f->slot].handle).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0);
}
static void request_open(struct fixture *f,unsigned slot,uint16_t port) {
    f->slot=slot;f->expected_port=port;f->destination.port=port;
    f->operation=f->associations[slot].api->open_target(f->associations[slot].handle,&f->destination,deadline(1000),opened,f);
    assert(f->operation.disposition==STEER_PV1_PENDING);
}
static void release_operation(struct fixture *f) {
    if(f->operation.operation.handle){f->operation.operation.api->release(f->operation.operation.handle);f->operation.operation=(struct steer_pv1_operation_ref){NULL,NULL};}
}
static void close_ref(struct fixture *f) {
    f->ref.api->close(f->ref.handle);assert(!f->ref.api->release(f->ref.handle).code);
    f->ref=(struct steer_pv1_datagram_ref){NULL,NULL};
}
static void receive_peer(struct fixture *f,const char *wanted) {
    struct pollfd p={.fd=f->peer,.events=POLLIN};assert(poll(&p,1,1000)==1);
    char bytes[32];socklen_t n=sizeof(f->received_from);
    ssize_t got=recvfrom(f->peer,bytes,sizeof(bytes),MSG_DONTWAIT,(struct sockaddr *)&f->received_from,&n);
    assert(got==(ssize_t)strlen(wanted)&&!memcmp(bytes,wanted,(size_t)got));
}
static void finalized(void *arg,const struct steer_draft_binding_identity *identity) {
    struct fixture *f=arg;assert(identity->generation==7&&!f->router&&!f->native);f->finalized++;
    loop_timer_set(f->work,0);
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)timer;struct fixture *f=arg;unsigned phase=f->phase++;
    uint32_t associations,targets,operations;uint64_t bytes;struct steer_pv1_mut_span view;
    if(phase!=0&&phase!=1)release_operation(f);
    switch(phase){
    case 0:
        assert(f->backend_calls==1);close_ref(f); /* keep open operation unreleased */
        loop_timer_set(f->work,80);break;
    case 1:
        steer_draft_datagram_router_usage(f->router,&associations,&targets,&operations,&bytes);
        assert(targets==1&&operations==1&&!bytes);release_operation(f);
        loop_timer_set(f->work,80);break;
    case 2:{
        steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);assert(!targets);
        int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(fd>=0);
        assert(!bind(fd,(struct sockaddr *)&f->local[0],sizeof(f->local[0])));close(fd);
        request_open(f,0,ntohs(f->server.sin_port));break;
    }
    case 3:{
        assert(f->backend_calls==2);assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);
        memset(view.data,33,65);
        struct steer_pv1_async_start too_big=f->ref.api->send(f->ref.handle,f->buffer,0,65,deadline(1000),completed,f);
        assert(too_big.disposition==STEER_PV1_REJECTED&&too_big.error.code==STEER_PV1_RESOURCE_EXHAUSTED);
        memcpy(view.data,"old",3);
        f->operation=f->ref.api->send(f->ref.handle,f->buffer,0,3,deadline(1000),completed,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);break;
    }
    case 4:
        assert(!f->code&&f->bytes==3);receive_peer(f,"old");
        assert(f->received_from.sin_port==f->local[0].sin_port);close_ref(f);
        request_open(f,1,ntohs(f->server.sin_port));break;
    case 5:
        assert(f->backend_calls==3&&f->local[0].sin_port!=f->local[1].sin_port);
        assert(sendto(f->peer,"stale",5,0,(struct sockaddr *)&f->local[0],sizeof(f->local[0]))==5);
        f->operation=f->ref.api->receive(f->ref.handle,f->buffer,0,16,deadline(5),completed,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);break;
    case 6:
        assert(f->code==STEER_PV1_TIMEOUT&&!f->bytes);close_ref(f);
        request_open(f,0,ntohs(f->server.sin_port));break;
    case 7:
        assert(f->backend_calls==3);
        f->operation=f->ref.api->receive(f->ref.handle,f->buffer,0,16,deadline(1000),completed,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);break;
    case 8:
        assert(!f->code&&f->bytes==5);assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);
        assert(!memcmp(view.data,"stale",5));close_ref(f);
        request_open(f,0,(uint16_t)(ntohs(f->server.sin_port)+1));break;
    case 9:
        assert(f->backend_calls==4);close_ref(f);request_open(f,0,ntohs(f->server.sin_port));break;
    case 10:{
        assert(f->backend_calls==5);
        struct steer_pv1_endpoint other=f->destination;other.port++;
        struct steer_pv1_async_start a=f->associations[0].api->open_target(f->associations[0].handle,&other,deadline(1000),opened,f);
        assert(a.disposition==STEER_PV1_REJECTED&&a.error.code==STEER_PV1_RESOURCE_EXHAUSTED);
        assert(!steer_draft_binding_retire(f->lease).code&&!f->finalized);
        a=f->associations[0].api->open_target(f->associations[0].handle,&other,deadline(1000),opened,f);
        assert(a.disposition==STEER_PV1_REJECTED&&a.error.code==STEER_PV1_POLICY_DENIED&&f->backend_calls==5);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);memcpy(view.data,"drain",5);
        f->operation=f->ref.api->send(f->ref.handle,f->buffer,0,5,deadline(1000),completed,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);break;
    }
    case 11:
        assert(!f->code&&f->bytes==5);receive_peer(f,"drain");
        assert(sendto(f->peer,"reply",5,0,(struct sockaddr *)&f->received_from,sizeof(f->received_from))==5);
        f->operation=f->ref.api->receive(f->ref.handle,f->buffer,0,16,deadline(1000),completed,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);break;
    case 12:
        assert(!f->code&&f->bytes==5);close_ref(f);
        for(unsigned i=0;i<2;i++)f->associations[i].api->close(f->associations[i].handle);
        for(unsigned i=0;i<2;i++){
            assert(!f->associations[i].api->release(f->associations[i].handle).code);
            f->associations[i].handle=NULL;
        }
        assert(steer_draft_datagram_router_destroy(f->router).code==STEER_PV1_POLICY_DENIED);
        loop_timer_set(f->work,0);break;
    case 13:
        steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);
        if(targets){f->phase--;loop_timer_set(f->work,1);break;}
        assert(!steer_draft_datagram_runtime_destroy(f->native).code);f->native=NULL;
        assert(!steer_draft_datagram_router_destroy(f->router).code);f->router=NULL;break;
    case 14:
        assert(f->finalized==1);assert(!steer_draft_binding_lease_destroy(f->lease).code);loop_stop(loop,0);break;
    default:assert(0);
    }
}
static void watchdog(struct loop *l,struct loop_timer *t,void *arg) {(void)l;(void)t;(void)arg;assert(!"router watchdog");}
static void stuck_resolver(void *arg,const char *host,uint16_t port,struct steer_draft_resolve_result *result) {
    struct fixture *f=arg;assert(!strcmp(host,"localhost")&&port);
    pthread_mutex_lock(&f->mutex);f->resolving=1;pthread_cond_signal(&f->condition);
    while(!f->unblock)pthread_cond_wait(&f->condition,&f->mutex);
    pthread_mutex_unlock(&f->mutex);
    memset(result,0,sizeof(*result));result->code=STEER_PV1_IO;
}
static void fault_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref ref,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;
    assert(!f->fault_callbacks++);
    if(f->fault_mode==3){
        assert(!e.code&&ref.handle&&bound&&peer);f->ref=ref;
        loop_timer_set(f->work,0);return;
    }
    assert(e.code==(f->fault_mode==1?STEER_PV1_TIMEOUT:STEER_PV1_CANCELLED));
    assert(!ref.handle&&!ref.api&&!bound&&!peer);
    loop_timer_set(f->work,0);
}
static void fault_step(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)timer;struct fixture *f=arg;uint32_t targets;
    if(!f->router){
        if(f->resolver){
            if(steer_draft_resolver_jobs(f->resolver)){loop_timer_set(f->work,1);return;}
            assert(!steer_draft_resolver_destroy(f->resolver).code);f->resolver=NULL;
        }
        assert(f->finalized==1);assert(!steer_draft_binding_lease_destroy(f->lease).code);
        loop_stop(loop,0);return;
    }
    if(f->fault_mode==1&&!f->phase){
        release_operation(f);close_ref(f);f->phase=1;
        uint64_t until=deadline(20);
        f->operation=f->associations[0].api->open_target(f->associations[0].handle,&f->destination,until,fault_opened,f);
        assert(f->operation.disposition==STEER_PV1_PENDING);
        /* Cached success has queued its callback without a deadline timer.
         * Hold this test-only callback past its deadline before dispatch. */
        struct timespec wait={(time_t)(until/1000000000ull),(long)(until%1000000000ull)};
        assert(!clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&wait,NULL));
        return;
    }
    if(f->fault_mode==3&&f->phase==1){
        if(!f->release_attempts){loop_timer_set(f->work,0);return;}
        assert(f->release_attempts==1&&f->private_origin.handle);
        assert(steer_draft_datagram_router_destroy(f->router).code==STEER_PV1_POLICY_DENIED);
        assert(steer_draft_datagram_runtime_destroy(f->native).code==STEER_PV1_POLICY_DENIED);
        f->recovered=1;assert(steer_draft_datagram_router_retry_cleanup(f->router)==1);
        f->phase=2;loop_timer_set(f->work,0);return;
    }
    if(f->phase<2){
        f->phase=f->fault_mode==3?1:2;
        release_operation(f);
        if(f->fault_mode==3)close_ref(f);
        for(unsigned i=0;i<2;i++){
            f->associations[i].api->close(f->associations[i].handle);
            assert(!f->associations[i].api->release(f->associations[i].handle).code);
        }
        assert(!steer_draft_binding_retire(f->lease).code);
        if(f->fault_mode==3){loop_timer_set(f->work,0);return;}
    }
    steer_draft_datagram_router_usage(f->router,NULL,&targets,NULL,NULL);
    if(targets){loop_timer_set(f->work,0);return;}
    assert(!steer_draft_datagram_runtime_destroy(f->native).code);f->native=NULL;
    if(f->resolver){
        assert(steer_draft_resolver_destroy(f->resolver).code==STEER_PV1_POLICY_DENIED);
        pthread_mutex_lock(&f->mutex);f->unblock=1;pthread_cond_signal(&f->condition);pthread_mutex_unlock(&f->mutex);
    }
    assert(!steer_draft_datagram_router_destroy(f->router).code);f->router=NULL;
}
int main(int argc,char **argv) {
    struct fixture f={0};f.loop=loop_new();assert(f.loop);
    if(argc>1)f.fault_mode=!strcmp(argv[1],"deadline")?1:!strcmp(argv[1],"release")?3:!strcmp(argv[1],"resolver")?4:2;
    struct steer_draft_buffer_limits buffer_limits={1048576,8,8};assert(!steer_draft_buffers_create(&buffer_limits,NULL,&f.host).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,128,&f.buffer).code);
    assert(!steer_draft_datagram_runtime_create(f.loop,f.host,8,32,1048576,&f.native).code);
    if(f.fault_mode==4){
        assert(!pthread_mutex_init(&f.mutex,NULL));assert(!pthread_cond_init(&f.condition,NULL));
        assert(!steer_draft_resolver_create(f.loop,1,1,stuck_resolver,&f,&f.resolver).code);
        assert(!steer_draft_datagram_use_resolver(f.native,f.resolver).code);
    }
    struct steer_draft_binding_identity identity={sizeof(identity),STEER_PV1_DRAFT_LAYOUT,7,99,{(const uint8_t *)"native",6},0,STEER_PV1_FLOW_DATAGRAM};
    assert(!steer_draft_binding_lease_create(f.loop,&identity,32,finalized,&f,&f.lease).code);
    struct steer_draft_datagram_route_limits limits={2,2,1,1,64,50000000};
    assert(!steer_draft_datagram_router_create(f.loop,f.host,f.lease,&backend,&f,&limits,evaluate,&f,&f.router).code);
    f.peer=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(f.peer>=0);
    f.server=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(f.peer,(struct sockaddr *)&f.server,sizeof(f.server)));socklen_t n=sizeof(f.server);
    assert(!getsockname(f.peer,(struct sockaddr *)&f.server,&n));
    memcpy(f.ip,(uint8_t[]){127,0,0,1},4);memcpy(f.source,f.ip,4);memcpy(f.inbound,"socks",5);memcpy(f.principal,"verified",8);
    f.destination=(struct steer_pv1_endpoint){sizeof(f.destination),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{f.ip,4},ntohs(f.server.sin_port),0};
    f.flow=(struct steer_pv1_flow_metadata){.size=sizeof(f.flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={f.inbound,5},.principal_id={f.principal,8},.source=f.destination,.destination=f.destination,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    f.flow.source.address.data=f.source;f.flow.source.port=5555;
    const struct steer_pv1_datagram_route_api *api=steer_draft_datagram_router_api();
    for(unsigned i=0;i<2;i++)assert(!api->create(f.router,&f.flow,&f.associations[i]).code);
    struct steer_pv1_datagram_association_ref rejected;
    assert(api->create(f.router,&f.flow,&rejected).code==STEER_PV1_RESOURCE_EXHAUSTED);
    f.flow.generation=8;assert(api->create(f.router,&f.flow,&rejected).code==STEER_PV1_POLICY_DENIED);f.flow.generation=7;
    memset(f.inbound,'x',5);memset(f.principal,'y',8);memset(f.source,0,4);
    struct steer_pv1_endpoint blocked=f.destination;blocked.port=1;
    assert(api->open_target(f.associations[0].handle,&blocked,deadline(1000),opened,&f).error.code==STEER_PV1_POLICY_DENIED);
    blocked.port=2;assert(api->open_target(f.associations[0].handle,&blocked,deadline(1000),opened,&f).error.code==STEER_PV1_UNSUPPORTED);
    blocked.tag=STEER_PV1_ENDPOINT_DOMAIN;blocked.port=53;blocked.address=(struct steer_pv1_span){(const uint8_t *)"blocked.invalid",15};
    assert(api->open_target(f.associations[0].handle,&blocked,deadline(1000),opened,&f).error.code==STEER_PV1_POLICY_DENIED&&!f.backend_calls);
    f.work=loop_timer_new(f.loop,f.fault_mode?fault_step:step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);assert(f.work&&f.watchdog);loop_timer_set(f.watchdog,3000);
    if(f.fault_mode){
        if(f.fault_mode==4){
            f.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;
            f.destination.address=(struct steer_pv1_span){(const uint8_t *)"localhost",9};
        }
        f.operation=api->open_target(f.associations[0].handle,&f.destination,deadline(1000),f.fault_mode==1?warm_opened:fault_opened,&f);
        assert(f.operation.disposition==STEER_PV1_PENDING);
        if(f.fault_mode==2)f.operation.operation.api->cancel(f.operation.operation.handle);
        if(f.fault_mode==4){
            struct timespec until;assert(!clock_gettime(CLOCK_REALTIME,&until));until.tv_sec+=2;
            pthread_mutex_lock(&f.mutex);
            while(!f.resolving)assert(!pthread_cond_timedwait(&f.condition,&f.mutex,&until));
            pthread_mutex_unlock(&f.mutex);
            f.operation.operation.api->cancel(f.operation.operation.handle);
        }
    }else request_open(&f,0,ntohs(f.server.sin_port));
    assert(!f.ref.handle);assert(!loop_run(f.loop));
    if(f.fault_mode)assert(f.fault_callbacks==1);
    if(f.fault_mode==3)assert(f.release_attempts==2&&!f.private_origin.handle);
    if(f.fault_mode==4){assert(!pthread_cond_destroy(&f.condition));assert(!pthread_mutex_destroy(&f.mutex));}
    close(f.peer);steer_draft_buffers_api()->release(f.host,f.buffer);assert(!steer_draft_buffers_destroy(f.host).code);
    loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
    printf("datagram router: %s PASS\n",f.fault_mode==1?"cached deadline publication":
        f.fault_mode==2?"cancel queued native success":f.fault_mode==3?"release quarantine and explicit recovery":
        f.fault_mode==4?"cancel running resolver and shutdown barrier":"generation/policy/isolated cache/idle/budget/old IO drain");
    return 0;
}
