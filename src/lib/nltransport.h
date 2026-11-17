/* Internal bounded Linux netlink exchange. No mutable global state or ABI. */
#ifndef STEER_NLTRANSPORT_H
#define STEER_NLTRANSPORT_H
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/netlink.h>
static inline void steer_nl_wipe(void *p,size_t n){volatile unsigned char *b=p;while(n--)*b++=0;}
static inline uint32_t steer_nl_next_sequence(uint32_t *counter){uint32_t n=__atomic_add_fetch(counter,1,__ATOMIC_RELAXED);return n?n:__atomic_add_fetch(counter,1,__ATOMIC_RELAXED);}
static inline uint64_t steer_nl_now_ns(void){
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static inline int steer_nl_wait(int fd,short events,uint64_t deadline){
    for(;;){
        uint64_t now=steer_nl_now_ns();if(!now)return EIO;if(now>=deadline)return ETIMEDOUT;
        uint64_t left=(deadline-now)/1000000ULL+((deadline-now)%1000000ULL!=0);
        struct pollfd p={.fd=fd,.events=events};int ready=poll(&p,1,left>INT_MAX?INT_MAX:(int)left);
        if(ready>0){now=steer_nl_now_ns();if(!now)return EIO;if(now>=deadline)return ETIMEDOUT;return p.revents&POLLNVAL?EBADF:0;}
        if(!ready)return ETIMEDOUT;
        if(errno!=EINTR)return errno;
    }
}

typedef void (*steer_nl_reply_fn)(const struct nlmsghdr *h, void *ctx);

static inline int steer_nl_exchange_until(int fd,void *msg,size_t len,steer_nl_reply_fn cb,void *ctx,uint64_t deadline){
    if(!msg||len<sizeof(struct nlmsghdr)||((struct nlmsghdr *)msg)->nlmsg_len!=len)return EINVAL;
    struct nlmsghdr *req=msg;int dump=(req->nlmsg_flags&NLM_F_DUMP)==NLM_F_DUMP;
    uint64_t now=steer_nl_now_ns();if(!now)return EIO;if(now>=deadline)return ETIMEDOUT;
    /* One bounded scratch allocation per exchange, BEFORE sending mutation.
     * Heap preserves small worker stacks. Replies may contain private keys. */
    uint8_t *rbuf=malloc(65536);if(!rbuf)return ENOMEM;
    struct sockaddr_nl to={.nl_family=AF_NETLINK};int rc=EIO,done=0,interrupted=0;
    for(;;){
        now=steer_nl_now_ns();if(!now){rc=EIO;goto out;}if(now>=deadline){rc=ETIMEDOUT;goto out;}
        ssize_t sent=sendto(fd,msg,len,MSG_DONTWAIT,(struct sockaddr *)&to,sizeof to);
        if(sent==(ssize_t)len)break;
        if(sent>=0){rc=EIO;goto out;}
        if(errno==EINTR)continue;
        if(errno!=EAGAIN&&errno!=EWOULDBLOCK){rc=errno;goto out;}
        rc=steer_nl_wait(fd,POLLOUT,deadline);if(rc)goto out;
    }
    while(!done){
        rc=steer_nl_wait(fd,POLLIN,deadline);if(rc)break;
        struct sockaddr_nl from={0};struct iovec io={rbuf,65536};
        struct msghdr response={.msg_name=&from,.msg_namelen=sizeof from,.msg_iov=&io,.msg_iovlen=1};
        ssize_t n=recvmsg(fd,&response,MSG_DONTWAIT);
        if(n<0){if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)continue;rc=errno;break;}
        if(response.msg_flags&MSG_TRUNC){rc=EMSGSIZE;break;}
        if(!n){rc=EIO;break;}
        now=steer_nl_now_ns();if(!now){rc=EIO;break;}if(now>=deadline){rc=ETIMEDOUT;break;}
        if(response.msg_namelen<sizeof from||from.nl_family!=AF_NETLINK||from.nl_pid!=0)continue;
        for(struct nlmsghdr *h=(void *)rbuf;NLMSG_OK(h,(size_t)n);h=NLMSG_NEXT(h,n)){
            now=steer_nl_now_ns();if(!now){rc=EIO;done=1;break;}if(now>=deadline){rc=ETIMEDOUT;done=1;break;}
            if(h->nlmsg_seq!=req->nlmsg_seq)continue;
            if(h->nlmsg_flags&NLM_F_DUMP_INTR)interrupted=1;
            if(h->nlmsg_type==NLMSG_NOOP)continue;
            if(h->nlmsg_type==NLMSG_OVERRUN){rc=ENOBUFS;done=1;break;}
            if(h->nlmsg_type==NLMSG_ERROR){
                if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))){rc=EPROTO;done=1;break;}
                const struct nlmsgerr *e=NLMSG_DATA(h);
                rc=e->error>0||e->error==INT_MIN?EPROTO:e->error?-e->error:0;
                if(!rc&&dump){
                    /* A successful ACK acknowledges the request, not the end
                     * of a multipart dump. Only DONE proves completion. An
                     * already interrupted dump may fail fast, never succeed. */
                    if(interrupted){rc=EINTR;done=1;break;}
                    continue;
                }
                done=1;break;
            }
            if(h->nlmsg_type==NLMSG_DONE){
                size_t payload=h->nlmsg_len-NLMSG_HDRLEN;rc=0;
                if(payload){
                    if(payload<sizeof(int))rc=EPROTO;
                    else{int value;memcpy(&value,NLMSG_DATA(h),sizeof value);rc=value>0||value==INT_MIN?EPROTO:value?-value:0;}
                }
                if(!rc&&dump&&interrupted)rc=EINTR;
                done=1;break;
            }
            if(cb)cb(h,ctx);
            if(!dump&&!(req->nlmsg_flags&NLM_F_ACK)){rc=0;done=1;break;}
        }
        if(!done&&n){rc=EPROTO;break;}
    }
out:
    steer_nl_wipe(rbuf,65536);free(rbuf);
    if(!rc){now=steer_nl_now_ns();if(!now)rc=EIO;else if(now>=deadline)rc=ETIMEDOUT;}
    return rc;
}

#endif
