/* SPDX-License-Identifier: GPL-3.0-only
 * SOCKS framing and loopback socket around the bounded SDK datagram dispatcher.
 * The HY2 framing is internal only; it is never exposed on the SOCKS socket. */
#define _GNU_SOURCE
#include "socks_datagram.h"
#include "hy2_address.h"
#include "hy2wire.h"
#include "loop.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define SOCKS_UDP_MAX 65000u
struct steer_socks_datagram {
    struct steer_socks_datagram_config cfg;
    struct steer_draft_hy2_datagram_services outer, inner;
    struct steer_draft_hy2_datagram *route;
    struct sockaddr_in peer;
    struct loop_timer *idle;
    int fd, stopped;
};
static struct steer_pv1_error acquire(void *user,struct steer_pv1_span in,
    struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_hy2_datagram_binding *out)
{
    struct steer_socks_datagram *s=user;
    struct steer_pv1_error e=s->outer.acquire(s->outer.context,in,principal,epoch,out);
    if(!e.code && out->generation!=s->cfg.generation) {
        s->outer.release(s->outer.context,out);
        return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};
    }
    return e;
}
static void release(void *user,struct steer_draft_hy2_datagram_binding *binding)
{
    struct steer_socks_datagram *s=user;
    s->outer.release(s->outer.context,binding);
}
static void wake(void *user) {
    struct steer_socks_datagram *s=user;
    s->cfg.wake(s->cfg.user);
}
static size_t limit(void *user) { (void)user;return 65535; }
static int address_text(const struct s5_address *a,char *out,size_t cap)
{
    char host[256];int n;
    if(!a->port)return -1;
    if(a->type==1 && a->length==4) {
        if(!inet_ntop(AF_INET,a->bytes,host,sizeof host))return -1;
    } else if(a->type==4 && a->length==16) {
        if(!inet_ntop(AF_INET6,a->bytes,host,sizeof host))return -1;
    } else if(a->type==3 && a->length && !memchr(a->bytes,0,a->length) &&
              !memchr(a->bytes,':',a->length)) {
        uint8_t numeric[4];
        memcpy(host,a->bytes,a->length);host[a->length]=0;
        /* The internal address parser infers numeric types. Never let it turn
         * a domain request into a different policy target. */
        if(host[0]=='[' || inet_pton(AF_INET,host,numeric)==1)return -1;
    } else return -1;
    n=snprintf(out,cap,a->type==4?"[%s]:%u":"%s:%u",host,(unsigned)a->port);
    return n>0 && (size_t)n<cap ? 0 : -1;
}
static int outgoing(void *user,const uint8_t *data,size_t n)
{
    struct steer_socks_datagram *s=user;struct hy2_udp_msg m;
    struct steer_pv1_endpoint ep;struct s5_address a={0};
    uint8_t ip[16],wire[65507];char host[2049];size_t written;
    if(s->stopped||!s->peer.sin_port||hy2_udp_parse(data,n,&m)||m.sid!=1||
       m.nfrag!=1||m.n>SOCKS_UDP_MAX||
       steer_draft_hy2_address((const uint8_t *)m.addr,strlen(m.addr),host,ip,&ep))return -1;
    if(ep.tag==STEER_PV1_ENDPOINT_IPV4) a.type=1;
    else if(ep.tag==STEER_PV1_ENDPOINT_IPV6) a.type=4;
    else if(ep.tag==STEER_PV1_ENDPOINT_DOMAIN) a.type=3;
    else return -1;
    if(!ep.address.len||ep.address.len>sizeof a.bytes)return -1;
    a.length=(uint8_t)ep.address.len;a.port=ep.port;memcpy(a.bytes,ep.address.data,a.length);
    if(s5_udp_encode(wire,sizeof wire,&a,m.data,m.n,&written)!=S5_UDP_OK)return -1;
    return sendto(s->fd,wire,written,MSG_DONTWAIT,(void *)&s->peer,sizeof s->peer)==(ssize_t)written?0:-1;
}
void steer_socks_datagram_stop(struct steer_socks_datagram *s)
{
    if(!s||s->stopped)return;
    s->stopped=1;loop_timer_stop(s->idle);
    if(s->fd>=0){loop_fd_del(s->outer.loop,s->fd);close(s->fd);s->fd=-1;}
    steer_draft_hy2_datagram_stop(s->route);
}
static void idle(struct loop *loop,struct loop_timer *timer,void *user)
{
    struct steer_socks_datagram *s=user;(void)loop;(void)timer;
    steer_socks_datagram_stop(s);wake(s);
}
static void readable(struct loop *loop,int fd,uint32_t events,void *user)
{
    struct steer_socks_datagram *s=user;(void)loop;
    if(events&(EPOLLERR|EPOLLHUP)){steer_socks_datagram_stop(s);wake(s);return;}
    for(unsigned i=0;i<32;i++){
        uint8_t packet[65535],wire[65535];struct sockaddr_in from;socklen_t alen=sizeof from;
        struct s5_address a;const uint8_t *payload;size_t size,head;char target[264];
        ssize_t n=recvfrom(fd,packet,sizeof packet,MSG_DONTWAIT,(void *)&from,&alen);
        if(n<0)break;
        if(alen!=sizeof from || from.sin_family!=AF_INET ||
           from.sin_addr.s_addr!=s->cfg.tcp_peer.sin_addr.s_addr ||
           (s->peer.sin_port && s->peer.sin_port!=from.sin_port) ||
           s5_udp_parse(packet,(size_t)n,&a,&payload,&size)!=S5_UDP_OK ||
           size>SOCKS_UDP_MAX || address_text(&a,target,sizeof target) ||
           s->cfg.authorize(s->cfg.user,&a))continue;
        head=hy2_udp_header(wire,sizeof wire,1,0,0,1,target);
        if(!head||size>sizeof wire-head)continue;
        if(!s->peer.sin_port)s->peer=from;
        if(size)memcpy(wire+head,payload,size);
        loop_timer_set(s->idle,(long)s->cfg.idle_ms);
        steer_draft_hy2_datagram_input(s->route,wire,head+size);
    }
}
int steer_socks_datagram_open(const struct steer_socks_datagram_config *cfg,
    const struct steer_draft_hy2_datagram_services *svc,struct steer_socks_datagram **out,
    struct s5_address *bound)
{
    struct steer_socks_datagram *s;struct sockaddr_in local={0};socklen_t len=sizeof local;
    struct steer_draft_hy2_datagram_config dc={0};uint8_t source[4];
    if(out)*out=NULL;
    if(!out||!bound||!cfg||!svc||!svc->loop||!svc->acquire||!svc->release||
       !cfg->authorize||!cfg->wake||!cfg->generation||!cfg->idle_ms||cfg->idle_ms>600000||
       cfg->tcp_peer.sin_family!=AF_INET || ntohl(cfg->tcp_peer.sin_addr.s_addr)!=INADDR_LOOPBACK ||
       cfg->requested_peer.type!=1 || cfg->requested_peer.length!=4)return -1;
    if(memcmp(cfg->requested_peer.bytes,"\0\0\0\0",4) &&
       memcmp(cfg->requested_peer.bytes,&cfg->tcp_peer.sin_addr,4))return -1;
    s=calloc(1,sizeof *s);if(!s)return -1;
    s->fd=-1;s->cfg=*cfg;s->outer=*svc;s->inner=*svc;s->inner.context=s;
    s->inner.acquire=acquire;s->inner.release=release;
    s->peer.sin_family=AF_INET;s->peer.sin_addr=cfg->tcp_peer.sin_addr;
    s->peer.sin_port=htons(cfg->requested_peer.port);
    s->fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(s->fd<0||bind(s->fd,(void *)&local,sizeof local)||getsockname(s->fd,(void *)&local,&len))goto fail;
    memcpy(source,&cfg->tcp_peer.sin_addr,4);
    dc.inbound=cfg->inbound;dc.principal=cfg->principal;dc.admission_epoch=cfg->admission_epoch;
    dc.source=(struct steer_pv1_endpoint){sizeof dc.source,STEER_PV1_DRAFT_LAYOUT,
        STEER_PV1_ENDPOINT_IPV4,{source,4},ntohs(cfg->tcp_peer.sin_port),0};
    dc.max_sessions=1;dc.max_targets=8;dc.max_contexts=1;dc.max_packets=64;
    dc.max_queued_bytes=1048576;dc.idle_ms=cfg->idle_ms;dc.operation_ms=5000;
    dc.transport=s;dc.message_limit=limit;dc.send=outgoing;dc.wake=wake;
    if(steer_draft_hy2_datagram_create(&dc,&s->inner,&s->route))goto fail;
    s->idle=loop_timer_new(svc->loop,idle,s);
    if(!s->idle||loop_fd_add(svc->loop,s->fd,EPOLLIN,readable,s))goto fail;
    loop_timer_set(s->idle,(long)cfg->idle_ms);
    memset(bound,0,sizeof *bound);bound->type=1;bound->length=4;bound->port=ntohs(local.sin_port);
    memcpy(bound->bytes,&local.sin_addr,4);*out=s;return 0;
fail:
    if(s->route){steer_draft_hy2_datagram_stop(s->route);steer_draft_hy2_datagram_poll(s->route);(void)steer_draft_hy2_datagram_destroy(s->route);}
    if(s->idle)loop_timer_free(s->idle);
    if(s->fd>=0)close(s->fd);
    free(s);return -1;
}
int steer_socks_datagram_destroy(struct steer_socks_datagram *s)
{
    if(!s)return 0;
    if(!s->stopped||steer_draft_hy2_datagram_destroy(s->route))return -1;
    loop_timer_free(s->idle);free(s);return 0;
}
