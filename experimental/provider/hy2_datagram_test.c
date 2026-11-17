#define _GNU_SOURCE
#include "hy2_datagram.h"
#include "prototype_resources.h"
#include "datagram_routes.h"
#include "datagram.h"
#include "hy2wire.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct steer_pv1_host *buffers;struct steer_draft_datagram_runtime *native;
    struct steer_draft_datagram_router *routers[3];struct steer_draft_binding_lease *leases[3];
    struct steer_draft_hy2_datagram *adapter,*quota_peers[2];struct steer_draft_hy2_datagram_budget budget;struct hy2_rasm *reassembly;
    unsigned generation,acquired,released,phase,replies,received,finalized;
    int peers[2];uint16_t ports[2];char addresses[2][64];uint8_t wanted[65507];size_t wanted_length;
};
static struct steer_pv1_error evaluate(void *user,const struct steer_pv1_flow_metadata *flow,uint32_t *action){
    struct fixture *f=user;assert(flow->principal_id.len==5&&!memcmp(flow->principal_id.data,"alice",5));
    assert(flow->source.tag==STEER_PV1_ENDPOINT_IPV4&&flow->source.port==12345);
    *action=flow->generation==2&&flow->destination.port==f->ports[1]?STEER_DRAFT_DATAGRAM_ROUTE_BLOCK:STEER_DRAFT_DATAGRAM_ROUTE_DIRECT;
    return (struct steer_pv1_error){0,0};
}
static struct steer_pv1_error acquire(void *user,struct steer_pv1_span inbound,struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_hy2_datagram_binding *out){
    struct fixture *f=user;assert(inbound.len==3&&!memcmp(inbound.data,"hy2",3)&&principal.len==5&&epoch==7);
    f->acquired++;*out=(struct steer_draft_hy2_datagram_binding){steer_draft_datagram_router_api(),f->routers[f->generation-1],f,f->generation};
    return (struct steer_pv1_error){0,0};
}
static void release(void *user,struct steer_draft_hy2_datagram_binding *binding){struct fixture *f=user;assert(binding->lease==f);f->released++;memset(binding,0,sizeof *binding);}
static size_t limit(void *user){struct fixture *f=user;return f->wanted_length>3000?1500:100;}
static void wake(void *user){struct fixture *f=user;loop_timer_set(f->work,0);}
static int outgoing(void *user,const uint8_t *data,size_t length){
    struct fixture *f=user;struct hy2_udp_msg message;assert(!hy2_udp_parse(data,length,&message));
    assert(message.sid==42);uint8_t *assembled=NULL;size_t total;
    if(message.nfrag>1){assembled=hy2_rasm_feed(&f->reassembly,&message,(uint64_t)loop_now_ms(),0,&total);if(!assembled)return 0;message.data=assembled;message.n=total;}
    assert(message.n==f->wanted_length&&!memcmp(message.data,f->wanted,message.n));free(assembled);f->replies++;wake(f);return 0;
}
static void incoming(struct fixture *f,unsigned peer,uint32_t session,int fragmented){
    uint8_t data[4096];size_t n;
    if(fragmented){
        size_t count=(f->wanted_length+999)/1000;
        for(size_t i=0,offset=0;i<count;i++){
            size_t part=f->wanted_length-offset;if(part>1000)part=1000;
            n=hy2_udp_header(data,sizeof data,session,17,(uint8_t)i,(uint8_t)count,f->addresses[peer]);memcpy(data+n,f->wanted+offset,part);
            steer_draft_hy2_datagram_input(f->adapter,data,n+part);offset+=part;
        }
    }else{
        n=hy2_udp_header(data,sizeof data,session,0,0,1,f->addresses[peer]);memcpy(data+n,f->wanted,f->wanted_length);
        steer_draft_hy2_datagram_input(f->adapter,data,n+f->wanted_length);
    }
}
static void echo(struct loop *loop,int fd,uint32_t events,void *user){
    struct fixture *f=user;struct sockaddr_storage address;socklen_t size=sizeof address;uint8_t data[65535];(void)loop;(void)events;
    ssize_t n=recvfrom(fd,data,sizeof data,0,(struct sockaddr *)&address,&size);assert(n>=0);f->received++;
    assert(sendto(fd,data,(size_t)n,0,(struct sockaddr *)&address,size)==n);
}
static void finalizer(void *user,const struct steer_draft_binding_identity *identity){struct fixture *f=user;assert(identity->generation);f->finalized++;wake(f);}
static void watchdog(struct loop *loop,struct loop_timer *timer,void *user){(void)loop;(void)timer;struct fixture *f=user;struct steer_draft_hy2_datagram_usage u;steer_draft_hy2_datagram_usage(f->adapter,&u);fprintf(stderr,"phase=%u replies=%u received=%u targets=%u operations=%u drops=%llu queued=%llu\n",f->phase,f->replies,f->received,u.targets,u.operations,(unsigned long long)u.dropped_packets,(unsigned long long)u.queued_bytes);assert(!"HY2 datagram bounded deadline");}
static void step(struct loop *loop,struct loop_timer *timer,void *user){
    struct fixture *f=user;struct steer_draft_hy2_datagram_usage usage;(void)timer;
    if(f->adapter){steer_draft_hy2_datagram_poll(f->adapter);steer_draft_hy2_datagram_usage(f->adapter,&usage);}
    switch(f->phase){
    case 100:{
        unsigned pending=0;
        for(unsigned i=0;i<2;i++)if(f->quota_peers[i]){
            steer_draft_hy2_datagram_poll(f->quota_peers[i]);
            struct steer_draft_hy2_datagram_usage q;steer_draft_hy2_datagram_usage(f->quota_peers[i],&q);
            if(!q.operations&&!q.targets)assert(q.completed_after_cancel>=1);
            if(!steer_draft_hy2_datagram_destroy(f->quota_peers[i]))f->quota_peers[i]=NULL;else pending++;
        }
        if(!pending){assert(!f->budget.upload_bytes&&!f->budget.receives&&!f->budget.packets&&f->acquired==f->released);f->acquired=f->released=0;f->generation=1;f->phase=0;}
    }break;
    case 0: f->phase=1;incoming(f,0,42,1);break;
    case 1: if(f->replies==1){f->wanted_length=3000;f->generation=2;f->phase=2;incoming(f,0,42,0);}break;
    case 2: if(f->replies==2){assert(f->acquired==1);f->phase=3;incoming(f,1,42,0);loop_timer_set(f->work,20);}break;
    case 3: assert(f->received==2&&f->acquired==2);f->generation=3;f->phase=4;incoming(f,1,42,0);break;
    case 4: if(f->replies==3){assert(f->acquired==3);f->wanted_length=0;f->phase=5;incoming(f,0,42,0);}break;
    case 5: if(f->replies==4){steer_draft_hy2_datagram_retire(f->adapter);f->phase=6;incoming(f,0,42,0);incoming(f,0,99,0);}break;
    case 6: if(f->replies==5){assert(f->received==5);steer_draft_hy2_datagram_stop(f->adapter);assert(steer_draft_hy2_datagram_destroy(f->adapter)==-1);f->phase=7;}break;
    case 7:
        if(!usage.sessions&&!usage.operations){
            assert(!usage.targets&&!usage.contexts&&!usage.packets&&!usage.queued_bytes&&!usage.quarantined&&f->acquired==f->released);
            assert(usage.max_fragment_burst==32);
            assert(!steer_draft_hy2_datagram_destroy(f->adapter));f->adapter=NULL;
            assert(!f->budget.upload_bytes&&!f->budget.receives&&!f->budget.packets);
            for(unsigned i=0;i<3;i++)steer_draft_datagram_router_close(f->routers[i]);
            f->phase=8;
        }break;
    case 8:{
        unsigned live=0;
        for(unsigned i=0;i<3;i++)if(f->routers[i]){
            if(!steer_draft_datagram_router_destroy(f->routers[i]).code){f->routers[i]=NULL;assert(!steer_draft_binding_retire(f->leases[i]).code);}else live++;
        }
        if(!live&&f->finalized==3){for(unsigned i=0;i<3;i++)assert(!steer_draft_binding_lease_destroy(f->leases[i]).code);assert(!steer_draft_datagram_runtime_destroy(f->native).code);loop_stop(loop,0);return;}
    }break;
    }
    loop_timer_set(f->work,5);
}
static void quota(struct fixture *f,const struct steer_draft_hy2_datagram_config *config,
    const struct steer_draft_hy2_datagram_services *services){
    struct steer_draft_hy2_datagram *peers[2];
    for(unsigned i=0;i<2;i++)assert(!steer_draft_hy2_datagram_create(config,services,&peers[i]));
    uint8_t wire[50300];memset(wire,0xa5,sizeof wire);
    for(unsigned i=0;i<6;i++){
        size_t header=hy2_udp_header(wire,sizeof wire,100+i,17,0,2,f->addresses[0]);
        steer_draft_hy2_datagram_input(peers[i%2],wire,header+50000);
    }
    struct steer_draft_hy2_datagram_usage first,second;
    steer_draft_hy2_datagram_usage(peers[0],&first);steer_draft_hy2_datagram_usage(peers[1],&second);
    assert(first.queued_bytes&&second.queued_bytes&&first.queued_bytes+second.queued_bytes==f->budget.upload_bytes);
    assert(f->budget.upload_bytes<=262144&&first.dropped_packets+second.dropped_packets==1);
    assert(!f->budget.receives&&!f->budget.packets&&!f->acquired);
    for(unsigned i=0;i<2;i++){
        steer_draft_hy2_datagram_stop(peers[i]);steer_draft_hy2_datagram_poll(peers[i]);
        assert(!steer_draft_hy2_datagram_destroy(peers[i]));
    }
    assert(!f->budget.upload_bytes&&!f->budget.receives&&!f->budget.packets);
}
static void tcp_reserve(void){
    struct steer_pv1_host *host;struct steer_pv1_buffer *buffers[136];
    struct steer_draft_buffer_limits limits=steer_draft_prototype_buffer_limits(32,16384,1);
    assert(!steer_draft_buffers_create(&limits,NULL,&host).code);
    const struct steer_pv1_buffer_api *api=steer_draft_buffers_api();
    for(unsigned i=0;i<8;i++)assert(!api->allocate(host,65507,&buffers[i]).code);
    for(unsigned i=8;i<72;i++)assert(!api->allocate(host,4096,&buffers[i]).code);
    for(unsigned i=72;i<136;i++)assert(!api->allocate(host,16384,&buffers[i]).code);
    struct steer_pv1_buffer *extra=NULL;assert(api->allocate(host,1,&extra).code==STEER_PV1_RESOURCE_EXHAUSTED&&!extra);
    for(unsigned i=0;i<136;i++)api->release(host,buffers[i]);
    assert(!steer_draft_buffers_destroy(host).code);
}
static void packet_quota(struct fixture *f,const struct steer_draft_hy2_datagram_config *config,
    const struct steer_draft_hy2_datagram_services *services){
    for(unsigned i=0;i<2;i++)assert(!steer_draft_hy2_datagram_create(config,services,&f->quota_peers[i]));
    uint8_t wire[5000];memset(wire,0,sizeof wire);size_t header=hy2_udp_header(wire,sizeof wire,42,0,0,1,f->addresses[0]);
    for(unsigned i=0;i<64;i++)steer_draft_hy2_datagram_input(f->quota_peers[0],wire,header+4000);
    f->generation=2;steer_draft_hy2_datagram_input(f->quota_peers[1],wire,header+4000);
    struct steer_draft_hy2_datagram_usage first,second;steer_draft_hy2_datagram_usage(f->quota_peers[0],&first);steer_draft_hy2_datagram_usage(f->quota_peers[1],&second);
    assert(f->budget.packets==64&&f->budget.upload_bytes==256000&&first.packets==64&&second.dropped_packets==1);
    assert(f->budget.receives==2&&f->acquired==2); /* distinct peers/generations */
    for(unsigned i=0;i<2;i++)steer_draft_hy2_datagram_stop(f->quota_peers[i]);
    f->phase=100;
}
int main(void){
    tcp_reserve();
    struct fixture f={.generation=1,.wanted_length=65507};uint8_t ip[]={127,0,0,1};
    for(unsigned i=0;i<sizeof f.wanted;i++)f.wanted[i]=(uint8_t)i;
    f.loop=loop_new();assert(f.loop);f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);
    const struct steer_draft_buffer_limits limits={8*1024*1024,128,2};assert(!steer_draft_buffers_create(&limits,NULL,&f.buffers).code);
    assert(!steer_draft_datagram_runtime_create(f.loop,f.buffers,16,128,4*1024*1024,&f.native).code);
    for(unsigned i=0;i<2;i++){
        f.peers[i]=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(f.peers[i]>=0);
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};assert(!bind(f.peers[i],(struct sockaddr *)&address,sizeof address));
        socklen_t size=sizeof address;assert(!getsockname(f.peers[i],(struct sockaddr *)&address,&size));f.ports[i]=ntohs(address.sin_port);
        snprintf(f.addresses[i],sizeof f.addresses[i],"127.0.0.1:%u",f.ports[i]);assert(!loop_fd_add(f.loop,f.peers[i],EPOLLIN,echo,&f));
    }
    for(unsigned i=0;i<3;i++){
        struct steer_draft_binding_identity id={.size=sizeof id,.version=STEER_PV1_DRAFT_LAYOUT,.generation=i+1,.instance_token=5,.provider_id={(const uint8_t *)"native",6},.flow_class=STEER_PV1_FLOW_DATAGRAM};
        assert(!steer_draft_binding_lease_create(f.loop,&id,128,finalizer,&f,&f.leases[i]).code);
        struct steer_draft_datagram_route_limits route_limits={8,8,4,64,1048576,50000000};
        assert(!steer_draft_datagram_router_create(f.loop,f.buffers,f.leases[i],steer_draft_datagram_backend_api(),f.native,&route_limits,evaluate,&f,&f.routers[i]).code);
    }
    steer_draft_hy2_datagram_budget_init(&f.budget);
    struct steer_draft_hy2_datagram_services services={f.loop,f.buffers,&f.budget,&f,acquire,release};
    struct steer_draft_hy2_datagram_config config={.inbound={(const uint8_t *)"hy2",3},.principal={(const uint8_t *)"alice",5},
        .source={sizeof(config.source),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},12345,0},.admission_epoch=7,
        .transport=&f,.message_limit=limit,.send=outgoing,.wake=wake};
    assert(!steer_draft_hy2_datagram_create(&config,&services,&f.adapter));quota(&f,&config,&services);packet_quota(&f,&config,&services);loop_timer_set(f.work,0);loop_timer_set(f.watchdog,3000);assert(!loop_run(f.loop));
    for(unsigned i=0;i<2;i++){loop_fd_del(f.loop,f.peers[i]);close(f.peers[i]);}
    hy2_rasm_free(&f.reassembly);assert(!steer_draft_buffers_destroy(f.buffers).code);loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
    puts("HY2 datagram adapter: native echo/fragment/zero/policy/reload/retire/cancel lease drain PASS");return 0;
}
