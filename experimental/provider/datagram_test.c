#define _GNU_SOURCE
#include "datagram.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct steer_pv1_host *host;struct steer_draft_datagram_runtime *runtime;
    struct steer_pv1_datagram_ref datagram;struct steer_pv1_async_start operation;
    struct steer_pv1_buffer *buffer,*other;
    struct sockaddr_in server,local;
    unsigned phase,calls;uint32_t code,bytes;int peer;
};
static uint64_t deadline(uint64_t ms) {
    struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+ms*1000000ull;
}
static void hold_until(uint64_t until){
    struct timespec t={(time_t)(until/1000000000ull),(long)(until%1000000000ull)};
    assert(!clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL));
}
static void pending(struct steer_pv1_async_start a) {assert(a.disposition==STEER_PV1_PENDING);}
static ssize_t peer_receive(int fd,void *data,size_t n) {
    struct pollfd p={.fd=fd,.events=POLLIN};assert(poll(&p,1,1000)==1);
    return recv(fd,data,n,MSG_DONTWAIT);
}
static void completed(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t bytes) {
    struct fixture *f=arg;struct steer_pv1_mut_span view;
    assert(b==f->buffer);f->calls++;f->code=e.code;f->bytes=bytes;
    assert(!steer_draft_buffers_api()->writable(f->host,b,&view).code);
    f->operation.operation.api->release(f->operation.operation.handle); /* rejected inside callback */
    assert(f->datagram.api->release(f->datagram.handle).code==STEER_PV1_POLICY_DENIED);
    assert(steer_draft_datagram_runtime_destroy(f->runtime).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0);
}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref d,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct fixture *f=arg;assert(!e.code&&d.handle&&d.api&&bound&&peer);
    assert(bound->tag==STEER_PV1_ENDPOINT_IPV4&&bound->port&&peer->port==ntohs(f->server.sin_port));
    f->datagram=d;f->local.sin_family=AF_INET;f->local.sin_port=htons(bound->port);
    memcpy(&f->local.sin_addr,bound->address.data,4);
    assert(!connect(f->peer,(struct sockaddr *)&f->local,sizeof(f->local)));
    loop_timer_set(f->work,0);
}
static void late_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref d,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct fixture *f=arg;assert(e.code==STEER_PV1_TIMEOUT&&!d.handle&&!d.api&&!bound&&!peer);
    assert(steer_draft_datagram_runtime_destroy(f->runtime).code==STEER_PV1_POLICY_DENIED);
    loop_timer_set(f->work,0);
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)timer;struct fixture *f=arg;struct steer_pv1_mut_span view;
    const struct steer_pv1_datagram_api *api=f->datagram.api;
    f->operation.operation.api->release(f->operation.operation.handle);
    if(f->phase==UINT_MAX){
        uint8_t ip[4]={127,0,0,1};
        struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1,0};
        struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=9,
            .inbound_id={(const uint8_t *)"udp-test",8},.source=endpoint,.destination=endpoint,.flow_class=STEER_PV1_FLOW_DATAGRAM};
        flow.destination.port=ntohs(f->server.sin_port);f->phase=0;
        f->operation=steer_draft_datagram_backend_api()->open(f->runtime,&flow,deadline(1000),opened,f);pending(f->operation);return;
    }
    switch(f->phase++){
    case 0:{
        assert(api->message_limit(f->datagram.handle)==65507);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code);
        memcpy(view.data+4,"send",4);
        uint64_t until=deadline(20);
        f->operation=api->send(f->datagram.handle,f->buffer,4,4,until,completed,f);pending(f->operation);
        struct steer_pv1_async_start second=api->send(f->datagram.handle,f->other,0,1,deadline(1000),completed,f);
        assert(second.disposition==STEER_PV1_REJECTED&&second.error.code==STEER_PV1_POLICY_DENIED&&!f->calls);
        char bytes[16];assert(peer_receive(f->peer,bytes,sizeof(bytes))==4&&!memcmp(bytes,"send",4));
        hold_until(until); /* Known side effect remains success at late dispatch. */
        assert(send(f->peer,"",0,0)==0);break;
    }
    case 1:
        assert(!f->code&&f->bytes==4);
        f->operation=api->receive(f->datagram.handle,f->buffer,0,64,deadline(1000),completed,f);pending(f->operation);break;
    case 2:
        assert(!f->code&&!f->bytes);
        f->operation=api->send(f->datagram.handle,f->buffer,0,0,deadline(1000),completed,f);pending(f->operation);
        {char bytes[1];assert(peer_receive(f->peer,bytes,sizeof(bytes))==0);}break;
    case 3:{
        assert(!f->code&&!f->bytes);
        char large[128];memset(large,77,sizeof(large));assert(send(f->peer,large,sizeof(large),0)==sizeof(large));
        f->operation=api->receive(f->datagram.handle,f->buffer,0,8,deadline(1000),completed,f);pending(f->operation);break;
    }
    case 4:{
        assert(f->code==STEER_PV1_RESOURCE_EXHAUSTED&&!f->bytes);
        int attacker=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(attacker>=0);
        assert(sendto(attacker,"spoof",5,0,(struct sockaddr *)&f->local,sizeof(f->local))==5);close(attacker);
        assert(send(f->peer,"after",5,0)==5);
        f->operation=api->receive(f->datagram.handle,f->buffer,3,16,deadline(1000),completed,f);pending(f->operation);break;
    }
    case 5:
        assert(!f->code&&f->bytes==5);
        assert(!steer_draft_buffers_api()->writable(f->host,f->buffer,&view).code&&!memcmp(view.data+3,"after",5));
        f->operation=api->receive(f->datagram.handle,f->buffer,0,8,deadline(5),completed,f);pending(f->operation);break;
    case 6:{
        assert(f->code==STEER_PV1_TIMEOUT&&!f->bytes);
        unsigned before=f->calls;
        f->operation=api->receive(f->datagram.handle,f->buffer,0,8,deadline(1000),completed,f);pending(f->operation);
        f->operation.operation.api->cancel(f->operation.operation.handle);
        api->close(f->datagram.handle);api->close(f->datagram.handle);assert(f->calls==before);
        int reused=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(reused>=0);
        assert(!bind(reused,(struct sockaddr *)&f->local,sizeof(f->local)));close(reused);break;
    }
    case 7:
        assert(f->code==STEER_PV1_CANCELLED&&!f->bytes&&f->calls==7);
        assert(!api->release(f->datagram.handle).code);
        assert(!steer_draft_datagram_runtime_destroy(f->runtime).code);
        loop_stop(loop,0);break;
    default:assert(0);
    }
}
static void timed_out(struct loop *loop,struct loop_timer *timer,void *arg) {(void)loop;(void)timer;(void)arg;assert(!"test watchdog");}
int main(void) {
    struct fixture f={0};f.loop=loop_new();assert(f.loop);
    struct steer_draft_buffer_limits limits={1048576,8,8};
    assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
    assert(!steer_draft_datagram_runtime_create(f.loop,f.host,4,16,1048576,&f.runtime).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,64,&f.buffer).code);
    assert(!steer_draft_buffers_api()->allocate(f.host,64,&f.other).code);
    f.peer=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(f.peer>=0);
    f.server=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(f.peer,(struct sockaddr *)&f.server,sizeof(f.server)));
    socklen_t n=sizeof(f.server);assert(!getsockname(f.peer,(struct sockaddr *)&f.server,&n));
    uint8_t ip[4]={127,0,0,1};
    struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=9,
        .inbound_id={(const uint8_t *)"udp-test",8},.source=endpoint,.destination=endpoint,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    flow.destination.port=ntohs(f.server.sin_port);
    f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,timed_out,&f);assert(f.work&&f.watchdog);
    loop_timer_set(f.watchdog,2000);
    uint64_t until=deadline(20);f.phase=UINT_MAX;
    f.operation=steer_draft_datagram_backend_api()->open(f.runtime,&flow,until,late_opened,&f);pending(f.operation);
    assert(!f.datagram.handle);memset(ip,0,sizeof(ip)); /* no borrowed input survives start */
    hold_until(until);
    assert(!loop_run(f.loop));
    close(f.peer);steer_draft_buffers_api()->release(f.host,f.buffer);steer_draft_buffers_api()->release(f.host,f.other);
    assert(!steer_draft_buffers_destroy(f.host).code);loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
    puts("datagram: atomic/zero/truncation/spoof/open publication deadline/late sent success/timeout/cancel/ownership PASS");return 0;
}
