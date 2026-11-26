/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "socks_datagram.h"
#include "datagram_routes.h"
#include "datagram.h"
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
    struct loop *loop;struct loop_timer *timer,*watchdog;
    struct steer_pv1_host *buffers;struct steer_draft_datagram_runtime *native;
    struct steer_draft_binding_lease *lease;struct steer_draft_datagram_router *router;
    struct steer_draft_hy2_datagram_budget budget;struct steer_socks_datagram *adapter;
    struct steer_draft_hy2_datagram_services services;
    struct steer_socks_datagram_config config;
    struct sockaddr_in relay;int client,echo[2],control_client,control_server;uint16_t port[2];
    unsigned phase,received[2],checks,acquired,released,finalized,generation;
    int64_t started;
};
static void wake(void *p){struct fixture *f=p;loop_timer_set(f->timer,0);}
static struct steer_pv1_error evaluate(void *p,const struct steer_pv1_flow_metadata *flow,uint32_t *action) {
    struct fixture *f=p;assert(flow->generation==7 && flow->flow_class==STEER_PV1_FLOW_DATAGRAM);
    *action=flow->destination.port==f->port[1]?STEER_DRAFT_DATAGRAM_ROUTE_BLOCK:STEER_DRAFT_DATAGRAM_ROUTE_DIRECT;
    return (struct steer_pv1_error){0,0};
}
static int authorize(void *p,const struct s5_address *a){struct fixture *f=p;f->checks++;return !a->port;}
static struct steer_pv1_error acquire(void *p,struct steer_pv1_span in,struct steer_pv1_span principal,
    uint64_t epoch,struct steer_draft_hy2_datagram_binding *out) {
    struct fixture *f=p;(void)in;(void)principal;assert(epoch==9);f->acquired++;
    *out=(struct steer_draft_hy2_datagram_binding){steer_draft_datagram_router_api(),f->router,f,f->generation};
    return (struct steer_pv1_error){0,0};
}
static void release(void *p,struct steer_draft_hy2_datagram_binding *b) {
    struct fixture *f=p;assert(b->lease==f);f->released++;memset(b,0,sizeof *b);
}
static void finalizer(void *p,const struct steer_draft_binding_identity *id){
    struct fixture *f=p;assert(id->generation==7);f->finalized++;wake(f);
}
static void echo(struct loop *loop,int fd,uint32_t events,void *p){
    struct fixture *f=p;struct sockaddr_in from;socklen_t n=sizeof from;uint8_t buf[4096];(void)loop;(void)events;
    ssize_t len=recvfrom(fd,buf,sizeof buf,0,(void *)&from,&n);assert(len>=0);
    f->received[fd==f->echo[1]]++;
    assert(sendto(fd,buf,(size_t)len,0,(void *)&from,n)==len);
}
static void control_eof(struct loop *loop,int fd,uint32_t events,void *p){
    struct fixture *f=p;char b;(void)events;
    if(recv(fd,&b,1,0)==0){
        loop_fd_del(loop,fd);close(fd);f->control_server=-1;
        steer_socks_datagram_stop(f->adapter);wake(f);
    }
}
static void send_packet(struct fixture *f,unsigned target,uint8_t frag,const char *data){
    struct s5_address a={.type=1,.length=4,.bytes={127,0,0,1},.port=f->port[target]};
    uint8_t buf[128];size_t n;
    assert(s5_udp_encode(buf,sizeof buf,&a,(const uint8_t *)data,strlen(data),&n)==S5_UDP_OK);
    buf[2]=frag;assert(sendto(f->client,buf,n,0,(void *)&f->relay,sizeof f->relay)==(ssize_t)n);
}
static int receive(struct fixture *f,const char *wanted){
    uint8_t buf[128];ssize_t n=recv(f->client,buf,sizeof buf,MSG_DONTWAIT);
    if(n<0)return 0;
    struct s5_address a;const uint8_t *payload;size_t size;
    assert(s5_udp_parse(buf,(size_t)n,&a,&payload,&size)==S5_UDP_OK);
    assert(a.port==f->port[0] && size==strlen(wanted) && !memcmp(payload,wanted,size));return 1;
}
static void timeout(struct loop *l,struct loop_timer *t,void *p){
    (void)l;(void)t;struct fixture *f=p;fprintf(stderr,"socks adapter timeout phase=%u\n",f->phase);abort();
}
static void step(struct loop *loop,struct loop_timer *timer,void *p){
    struct fixture *f=p;(void)timer;
    switch(f->phase){
    case 0:{
        int foreign=socket(AF_INET,SOCK_DGRAM,0);assert(foreign>=0);
        struct sockaddr_in wrong={.sin_family=AF_INET,.sin_addr.s_addr=htonl(0x7f000002)};
        assert(!bind(foreign,(void *)&wrong,sizeof wrong));
        uint8_t packet[32];size_t n;
        struct s5_address a={.type=1,.length=4,.bytes={127,0,0,1},.port=f->port[0]};
        assert(s5_udp_encode(packet,sizeof packet,&a,(const uint8_t *)"bad",3,&n)==S5_UDP_OK);
        assert(sendto(foreign,packet,n,0,(void *)&f->relay,sizeof f->relay)==(ssize_t)n);
        close(foreign);
        foreign=socket(AF_INET,SOCK_DGRAM,0);assert(foreign>=0);
        wrong.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        assert(!bind(foreign,(void *)&wrong,sizeof wrong));
        assert(sendto(foreign,packet,n,0,(void *)&f->relay,sizeof f->relay)==(ssize_t)n);
        close(foreign);
        a.type=3;a.length=9;memcpy(a.bytes,"127.0.0.1",9);
        assert(s5_udp_encode(packet,sizeof packet,&a,(const uint8_t *)"bad",3,&n)==S5_UDP_OK);
        assert(sendto(f->client,packet,n,0,(void *)&f->relay,sizeof f->relay)==(ssize_t)n);
        send_packet(f,0,0,"first");f->phase=1;break;
    }
    case 1:if(receive(f,"first")){f->generation=8;send_packet(f,1,0,"wrong-generation");f->phase=10;}break;
    case 10:
        if(f->released){assert(f->acquired==2 && f->released==1 && !f->received[1]);
            f->generation=7;send_packet(f,1,0,"blocked");send_packet(f,0,1,"fragment");f->phase=2;}break;
    case 2:
        if(f->checks>=3){assert(f->received[1]==0);send_packet(f,0,0,"again");f->phase=3;}break;
    case 3:
        if(receive(f,"again")){assert(f->received[0]==2 && f->received[1]==0 && f->checks==4);
            close(f->control_client);f->control_client=-1;f->phase=4;}break;
    case 4:
        if(f->control_server<0 && !steer_socks_datagram_destroy(f->adapter)){
            struct s5_address bound;f->adapter=NULL;assert(f->acquired==f->released);
            send_packet(f,0,0,"closed");
            f->config.idle_ms=50;
            assert(!steer_socks_datagram_open(&f->config,&f->services,&f->adapter,&bound));
            f->relay.sin_port=htons(bound.port);memcpy(&f->relay.sin_addr,bound.bytes,4);
            f->started=loop_now_ms();f->phase=40;
        }break;
    case 40:
        if(loop_now_ms()-f->started>=100){
            assert(!steer_socks_datagram_destroy(f->adapter));f->adapter=NULL;
            assert(f->received[0]==2 && f->received[1]==0);
            send_packet(f,0,0,"expired");
            steer_draft_datagram_router_close(f->router);f->phase=5;
        }break;
    case 5:
        if(!steer_draft_datagram_router_destroy(f->router).code){f->router=NULL;
            assert(!steer_draft_binding_retire(f->lease).code);f->phase=6;}break;
    case 6:
        if(f->finalized){assert(!steer_draft_binding_lease_destroy(f->lease).code);
            assert(!steer_draft_datagram_runtime_destroy(f->native).code);
            for(unsigned i=0;i<2;i++){loop_fd_del(loop,f->echo[i]);close(f->echo[i]);}
            close(f->client);loop_stop(loop,0);return;}break;
    }
    loop_timer_set(f->timer,5);
}
int main(void){
    struct fixture f={0};f.generation=7;f.loop=loop_new();assert(f.loop);
    struct steer_draft_buffer_limits bl={1048576,64,64};
    assert(!steer_draft_buffers_create(&bl,NULL,&f.buffers).code);
    assert(!steer_draft_datagram_runtime_create(f.loop,f.buffers,16,64,1048576,&f.native).code);
    struct steer_draft_binding_identity id={sizeof id,STEER_PV1_DRAFT_LAYOUT,7,99,
        {(const uint8_t *)"native",6},0,STEER_PV1_FLOW_DATAGRAM};
    assert(!steer_draft_binding_lease_create(f.loop,&id,64,finalizer,&f,&f.lease).code);
    struct steer_draft_datagram_route_limits limits={8,8,8,64,1048576,60000000000ULL};
    assert(!steer_draft_datagram_router_create(f.loop,f.buffers,f.lease,
        steer_draft_datagram_backend_api(),f.native,&limits,evaluate,&f,&f.router).code);
    for(unsigned i=0;i<2;i++){
        struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        socklen_t n=sizeof a;f.echo[i]=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);assert(f.echo[i]>=0);
        assert(!bind(f.echo[i],(void *)&a,sizeof a)&&!getsockname(f.echo[i],(void *)&a,&n));
        f.port[i]=ntohs(a.sin_port);assert(!loop_fd_add(f.loop,f.echo[i],EPOLLIN,echo,&f));
    }
    f.client=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);assert(f.client>=0);
    struct sockaddr_in client={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t n=sizeof client;assert(!bind(f.client,(void *)&client,sizeof client)&&!getsockname(f.client,(void *)&client,&n));
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in tcp={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    n=sizeof tcp;assert(!bind(listener,(void *)&tcp,sizeof tcp)&&!listen(listener,1)&&!getsockname(listener,(void *)&tcp,&n));
    f.control_client=socket(AF_INET,SOCK_STREAM,0);assert(f.control_client>=0);
    assert(!connect(f.control_client,(void *)&tcp,sizeof tcp));
    f.control_server=accept(listener,NULL,NULL);close(listener);assert(f.control_server>=0);
    assert(!loop_fd_add(f.loop,f.control_server,EPOLLIN|EPOLLRDHUP,control_eof,&f));
    struct sockaddr_in control_peer;n=sizeof control_peer;
    assert(!getpeername(f.control_server,(void *)&control_peer,&n));
    f.timer=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,timeout,&f);assert(f.timer&&f.watchdog);
    steer_draft_hy2_datagram_budget_init(&f.budget);
    f.services=(struct steer_draft_hy2_datagram_services){f.loop,f.buffers,&f.budget,&f,acquire,release};
    f.config=(struct steer_socks_datagram_config){.inbound={(const uint8_t *)"socks",5},
        .principal={(const uint8_t *)"alice",5},.tcp_peer=control_peer,
        .requested_peer={.type=1,.length=4,.bytes={127,0,0,1},.port=ntohs(client.sin_port)},
        .generation=7,.admission_epoch=9,.idle_ms=10000,.user=&f,.authorize=authorize,.wake=wake};
    struct s5_address bound;assert(!steer_socks_datagram_open(&f.config,&f.services,&f.adapter,&bound));
    f.relay=(struct sockaddr_in){.sin_family=AF_INET,.sin_port=htons(bound.port)};
    memcpy(&f.relay.sin_addr,bound.bytes,4);
    loop_timer_set(f.timer,0);loop_timer_set(f.watchdog,5000);assert(!loop_run(f.loop));
    loop_timer_free(f.timer);loop_timer_free(f.watchdog);
    assert(!steer_draft_buffers_destroy(f.buffers).code);loop_free(f.loop);
    puts("SOCKS UDP adapter: real router direct/block/direct and close PASS");return 0;
}
