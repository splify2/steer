/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "socks_udp_transport.h"
#include "socks5/codec.h"
#include "socks5/outbound.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum phase { CONNECT, GREETING, METHOD, ASSOCIATE, RESPONSE, READY, FAILED };
struct steer_socks_udp_transport {
    int tcp,udp;
    enum phase phase;
    struct sockaddr_in target;
    struct s5_out_reply reply;
    uint8_t tx[10],rx[2];
    size_t used, sent;
};
static int again(void){return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR;}
int steer_socks_udp_transport_open(const struct sockaddr_in *up,const struct sockaddr_in *dst,
                                    struct steer_socks_udp_transport **out)
{
    if(out)*out=NULL;
    if(!out||!up||!dst||up->sin_family!=AF_INET||dst->sin_family!=AF_INET||
       ntohl(up->sin_addr.s_addr)!=INADDR_LOOPBACK||!up->sin_port||!dst->sin_port)return -1;
    struct steer_socks_udp_transport *s=calloc(1,sizeof *s);if(!s)return -1;
    s->tcp=s->udp=-1;s->target=*dst;
    struct sockaddr_in local={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    s->udp=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    s->tcp=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(s->udp<0||s->tcp<0||bind(s->udp,(void *)&local,sizeof local))goto fail;
    socklen_t len=sizeof local;
    if(getsockname(s->udp,(void *)&local,&len))goto fail;
    int r=connect(s->tcp,(const void *)up,sizeof *up);
    if(r && errno!=EINPROGRESS)goto fail;
    s->phase=CONNECT;
    s->tx[0]=5;s->tx[1]=3;s->tx[2]=0;s->tx[3]=1;
    memcpy(s->tx+4,&local.sin_addr,4);memcpy(s->tx+8,&local.sin_port,2);
    *out=s;return 0;
fail: steer_socks_udp_transport_destroy(s);return -1;
}
int steer_socks_udp_transport_tcp_fd(const struct steer_socks_udp_transport *s){return s?s->tcp:-1;}
int steer_socks_udp_transport_udp_fd(const struct steer_socks_udp_transport *s){return s?s->udp:-1;}
enum steer_socks_udp_state steer_socks_udp_transport_state(const struct steer_socks_udp_transport *s){
    return !s||s->phase==FAILED?SOCKS_UDP_FAILED:s->phase==READY?SOCKS_UDP_READY:SOCKS_UDP_CONNECTING;
}
int steer_socks_udp_transport_wants_write(const struct steer_socks_udp_transport *s){
    return s&&(s->phase==CONNECT||s->phase==GREETING||s->phase==ASSOCIATE);
}
void steer_socks_udp_transport_drive(struct steer_socks_udp_transport *s)
{
    if(!s||s->phase==FAILED)return;
    for(unsigned step=0;step<16;step++){
        ssize_t n;
        if(s->phase==CONNECT){
            int e=0;socklen_t len=sizeof e;
            if(getsockopt(s->tcp,SOL_SOCKET,SO_ERROR,&e,&len)||e){s->phase=FAILED;return;}
            s->phase=GREETING;s->sent=0;
        } else if(s->phase==GREETING || s->phase==ASSOCIATE){
            static const uint8_t greeting[]={5,1,0};
            const uint8_t *p=s->phase==GREETING?greeting:s->tx;
            size_t len=s->phase==GREETING?sizeof greeting:sizeof s->tx;
            n=send(s->tcp,p+s->sent,len-s->sent,MSG_DONTWAIT|MSG_NOSIGNAL);
            if(n<0){if(again())return;s->phase=FAILED;return;}
            if(!n){s->phase=FAILED;return;}s->sent+=(size_t)n;
            if(s->sent==len){s->phase=s->phase==GREETING?METHOD:RESPONSE;s->used=0;s->sent=0;}
        } else if(s->phase==METHOD){
            n=recv(s->tcp,s->rx+s->used,2-s->used,MSG_DONTWAIT);
            if(n<0){if(again())return;s->phase=FAILED;return;}
            if(!n){s->phase=FAILED;return;}s->used+=(size_t)n;
            if(s->used==2){if(!s5_out_method_ok(S5_NOAUTH,s->rx,2)){s->phase=FAILED;return;}
                s->phase=ASSOCIATE;s5_out_reply_init(&s->reply);}
        } else if(s->phase==RESPONSE){
            uint8_t byte;size_t used;
            n=recv(s->tcp,&byte,1,MSG_DONTWAIT);
            if(n<0){if(again())return;s->phase=FAILED;return;}
            if(!n){s->phase=FAILED;return;}
            enum s5_out_event ev=s5_out_reply_feed(&s->reply,&byte,1,&used);
            if(ev==S5_OUT_MORE)continue;
            if(ev!=S5_OUT_CONNECTED||s->reply.frame[3]!=1){s->phase=FAILED;return;}
            struct sockaddr_in relay={.sin_family=AF_INET};
            memcpy(&relay.sin_addr,s->reply.frame+4,4);memcpy(&relay.sin_port,s->reply.frame+8,2);
            if(ntohl(relay.sin_addr.s_addr)!=INADDR_LOOPBACK||!relay.sin_port||
               connect(s->udp,(void *)&relay,sizeof relay)){s->phase=FAILED;return;}
            s->phase=READY;return;
        } else {
            uint8_t byte;n=recv(s->tcp,&byte,1,MSG_DONTWAIT);
            if(n<0 && again())return;
            s->phase=FAILED;return; /* EOF, error, or unexpected control bytes */
        }
    }
}
int steer_socks_udp_transport_send(struct steer_socks_udp_transport *s,const uint8_t *data,size_t n)
{
    uint8_t wire[65507];size_t len;
    if(!s||s->phase!=READY||(!data&&n)||n>STEER_SOCKS_UDP_MESSAGE_LIMIT)return -1;
    struct s5_address a={.type=1,.length=4,.port=ntohs(s->target.sin_port)};
    memcpy(a.bytes,&s->target.sin_addr,4);
    if(s5_udp_encode(wire,sizeof wire,&a,data,n,&len)!=S5_UDP_OK)return -1;
    ssize_t r=send(s->udp,wire,len,MSG_DONTWAIT|MSG_NOSIGNAL);
    if(r<0&&again())return -2;
    return r==(ssize_t)len?0:-1;
}
int steer_socks_udp_transport_receive(struct steer_socks_udp_transport *s,uint8_t *out,size_t cap,size_t *size)
{
    uint8_t wire[65535];const uint8_t *data;size_t n;struct s5_address a;
    if(!s||s->phase!=READY||!out||!cap||!size)return -1;
    for(unsigned i=0;i<32;i++){
        ssize_t r=recv(s->udp,wire,sizeof wire,MSG_DONTWAIT);
        if(r<0)return again()?-2:-1;
        if(s5_udp_parse(wire,(size_t)r,&a,&data,&n)!=S5_UDP_OK||a.type!=1||
           memcmp(a.bytes,&s->target.sin_addr,4)||a.port!=ntohs(s->target.sin_port))continue;
        if(n>STEER_SOCKS_UDP_MESSAGE_LIMIT||n>cap)return -3;
        if(n)memcpy(out,data,n);
        *size=n;return 0;
    }
    return -2;
}
void steer_socks_udp_transport_destroy(struct steer_socks_udp_transport *s){
    if(!s)return;
    if(s->tcp>=0)close(s->tcp);
    if(s->udp>=0)close(s->udp);
    free(s);
}
