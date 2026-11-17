#define _GNU_SOURCE
#include "datagram.h"
#include "buffers.h"
#include "operations.h"
#include "flow_metadata.h"
#include "resolver.h"
#include "loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
#define MESSAGE_LIMIT 65507u
#define COMPLETION_BATCH 32u
struct datagram_io;
struct steer_draft_datagram_runtime {
    struct loop *loop;
    struct steer_pv1_host *host;
    struct steer_draft_operations *operations;
    struct steer_draft_resolver *resolver;
    uint64_t bytes,max_bytes;
    uint32_t associations,max_associations,live;
    int wake,dispatching;
};
struct steer_pv1_datagram {
    struct steer_draft_datagram_runtime *runtime;
    struct datagram_io *send,*receive;
    uint32_t live;
    int fd,watching;
};
struct datagram_io {
    struct steer_pv1_datagram *datagram;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_buffer *buffer;
    struct loop_timer *timer;
    uint64_t deadline;
    uint8_t *data;
    uint32_t length,bytes;
    steer_pv1_datagram_done done;
    void *userdata;
    int writing,detached,completed;
};
static struct steer_pv1_error error(uint32_t code) {struct steer_pv1_error e={code,0};return e;}
static uint64_t now_ns(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
}
static void notify(struct steer_draft_datagram_runtime *r) {
    uint64_t one=1;ssize_t n;
    do{n=write(r->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);
}
static void deadline_arm(struct loop_timer *timer,uint64_t deadline) {
    uint64_t now=now_ns(),delta=deadline>now?deadline-now:0;
    uint64_t ms=delta/1000000ull+(delta%1000000ull!=0);
    if(ms>(uint64_t)LONG_MAX/2)ms=(uint64_t)LONG_MAX/2;
    loop_timer_set(timer,(long)ms);
}
static void io_ready(struct loop *,int,uint32_t,void *);
static int arm(struct steer_pv1_datagram *d) {
    uint32_t events=0;
    if(d->receive&&!d->receive->detached)events|=EPOLLIN;
    if(d->send&&!d->send->detached)events|=EPOLLOUT;
    if(!events||d->fd<0){
        if(d->watching)loop_fd_del(d->runtime->loop,d->fd);
        d->watching=0;return 0;
    }
    if(d->watching)return loop_fd_mod(d->runtime->loop,d->fd,events);
    if(loop_fd_add(d->runtime->loop,d->fd,events,io_ready,d))return -1;
    d->watching=1;return 0;
}
static void io_finish(struct datagram_io *io,uint32_t code,uint32_t bytes) {
    if(io->detached)return;
    io->detached=1;io->bytes=bytes;
    loop_timer_free(io->timer);io->timer=NULL;
    io->datagram->runtime->bytes-=io->length;
    (void)arm(io->datagram);
    (void)steer_draft_operation_resolve(io->inner.handle,error(code));
    notify(io->datagram->runtime);
}
static void io_attempt(struct datagram_io *io) {
    if(!io||io->detached)return;
    if(now_ns()>=io->deadline){io_finish(io,STEER_PV1_TIMEOUT,0);return;}
    ssize_t n;
    if(io->writing){
        n=send(io->datagram->fd,io->data,io->length,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(n>=0){io_finish(io,(uint32_t)n==io->length?STEER_PV1_OK:STEER_PV1_IO,
                          (uint32_t)n==io->length?(uint32_t)n:0);return;}
    }else{
        struct iovec iov={.iov_base=io->data,.iov_len=io->length};
        struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
        n=recvmsg(io->datagram->fd,&message,MSG_DONTWAIT|MSG_TRUNC);
        if(n>=0){
            if((message.msg_flags&MSG_TRUNC)||(uint64_t)n>io->length)
                io_finish(io,STEER_PV1_RESOURCE_EXHAUSTED,0);
            else io_finish(io,STEER_PV1_OK,(uint32_t)n);
            return;
        }
    }
    if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)return;
    io_finish(io,STEER_PV1_IO,0);
}
static void io_ready(struct loop *l,int fd,uint32_t events,void *arg) {
    (void)l;(void)fd;struct steer_pv1_datagram *d=arg;
    if(events&(EPOLLIN|EPOLLERR|EPOLLHUP))io_attempt(d->receive);
    if(events&(EPOLLOUT|EPOLLERR|EPOLLHUP))io_attempt(d->send);
}
static void io_timeout(struct loop *l,struct loop_timer *t,void *arg) {
    (void)l;(void)t;struct datagram_io *io=arg;
    if(now_ns()<io->deadline)deadline_arm(io->timer,io->deadline);
    else io_finish(io,STEER_PV1_TIMEOUT,0);
}
static void io_deliver(void *arg,struct steer_pv1_error e) {
    struct datagram_io *io=arg;
    if(io->writing)io->datagram->send=NULL;else io->datagram->receive=NULL;
    struct steer_pv1_buffer *buffer=io->buffer;io->buffer=NULL;
    io->done(io->userdata,e,buffer,io->bytes);io->completed=1;
}
static void STEER_PV1_CALL io_cancel(struct steer_pv1_operation *op) {
    io_finish((struct datagram_io *)op,STEER_PV1_CANCELLED,0);
}
static void STEER_PV1_CALL io_release(struct steer_pv1_operation *op) {
    struct datagram_io *io=(void *)op;if(!io->completed)return;
    io->inner.api->release(io->inner.handle);
    io->datagram->live--;io->datagram->runtime->live--;free(io);
}
static const struct steer_pv1_operation_api io_operation_api={
    sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,io_cancel,io_release
};
static struct steer_pv1_async_start io_start(struct steer_pv1_datagram *d,
    struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,uint64_t deadline,
    steer_pv1_datagram_done done,void *userdata,int writing) {
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_INVALID,0},{NULL,NULL}};
    if(!d||!buffer||!done||(!writing&&!length)||length>MESSAGE_LIMIT||deadline<=now_ns())return a;
    if(d->fd<0||(writing?d->send:d->receive)){a.error=error(STEER_PV1_POLICY_DENIED);return a;}
    struct steer_pv1_mut_span view;
    a.error=steer_draft_buffers_api()->writable(d->runtime->host,buffer,&view);
    if(a.error.code)return a;
    a.error=error(STEER_PV1_INVALID);
    if(offset>view.len||length>view.len-offset)return a;
    a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);
    if(length>d->runtime->max_bytes-d->runtime->bytes)return a;
    struct datagram_io *io=calloc(1,sizeof(*io));if(!io)return a;
    io->datagram=d;io->buffer=buffer;io->data=length?view.data+offset:view.data;
    io->length=length;io->deadline=deadline;io->done=done;io->userdata=userdata;io->writing=writing;
    a=steer_draft_operation_start(d->runtime->operations,io_deliver,io);
    if(a.disposition!=STEER_PV1_PENDING){free(io);return a;}
    io->inner=a.operation;
    a.operation.handle=(void *)io;a.operation.api=&io_operation_api;
    d->live++;d->runtime->live++;d->runtime->bytes+=length;
    if(writing)d->send=io;else d->receive=io;
    io_attempt(io);
    if(!io->detached){
        io->timer=loop_timer_new(d->runtime->loop,io_timeout,io);
        if(!io->timer)io_finish(io,STEER_PV1_RESOURCE_EXHAUSTED,0);
        else{deadline_arm(io->timer,deadline);if(arm(d))io_finish(io,STEER_PV1_IO,0);}
    }
    return a;
}
static struct steer_pv1_async_start STEER_PV1_CALL send_datagram(struct steer_pv1_datagram *d,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t deadline,steer_pv1_datagram_done done,void *u) {
    return io_start(d,b,o,n,deadline,done,u,1);
}
static struct steer_pv1_async_start STEER_PV1_CALL receive_datagram(struct steer_pv1_datagram *d,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t deadline,steer_pv1_datagram_done done,void *u) {
    return io_start(d,b,o,n,deadline,done,u,0);
}
static uint32_t STEER_PV1_CALL message_limit(struct steer_pv1_datagram *d) {return d&&d->fd>=0?MESSAGE_LIMIT:0;}
static void STEER_PV1_CALL close_datagram(struct steer_pv1_datagram *d) {
    if(!d||d->fd<0)return;
    if(d->watching)loop_fd_del(d->runtime->loop,d->fd);
    d->watching=0;close(d->fd);d->fd=-1;
    if(d->receive)io_finish(d->receive,STEER_PV1_CANCELLED,0);
    if(d->send)io_finish(d->send,STEER_PV1_CANCELLED,0);
}
static struct steer_pv1_error STEER_PV1_CALL release_datagram(struct steer_pv1_datagram *d) {
    if(!d)return error(STEER_PV1_INVALID);
    if(d->fd>=0||d->live)return error(STEER_PV1_POLICY_DENIED);
    d->runtime->associations--;free(d);return error(STEER_PV1_OK);
}
static const struct steer_pv1_datagram_api datagram_api={
    sizeof(datagram_api),STEER_PV1_DRAFT_LAYOUT,message_limit,send_datagram,receive_datagram,
    close_datagram,release_datagram
};
static void pump(struct loop *l,int fd,uint32_t events,void *arg) {
    (void)l;(void)events;struct steer_draft_datagram_runtime *r=arg;uint64_t count;ssize_t n;
    do{n=read(fd,&count,sizeof(count));}while(n<0&&errno==EINTR);
    r->dispatching=1;
    (void)steer_draft_operations_dispatch(r->operations,COMPLETION_BATCH,NULL);
    r->dispatching=0;
    uint32_t queued;steer_draft_operations_usage(r->operations,NULL,&queued);
    if(queued)notify(r);
}
struct steer_pv1_error steer_draft_datagram_runtime_create(struct loop *loop,
    struct steer_pv1_host *host,uint32_t associations,uint32_t operations,uint64_t bytes,
    struct steer_draft_datagram_runtime **out) {
    if(out)*out=NULL;
    if(!loop||!host||!out)return error(STEER_PV1_INVALID);
    struct steer_draft_datagram_runtime *r=calloc(1,sizeof(*r));if(!r)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_error e=steer_draft_operations_create(operations,NULL,&r->operations);
    if(e.code){free(r);return e;}
    r->loop=loop;r->host=host;r->max_associations=associations;r->max_bytes=bytes;
    r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(r->wake<0||loop_fd_add(loop,r->wake,EPOLLIN,pump,r)){
        if(r->wake>=0)close(r->wake);
        (void)steer_draft_operations_destroy(r->operations);free(r);return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=r;return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_datagram_runtime_destroy(struct steer_draft_datagram_runtime *r) {
    if(!r)return error(STEER_PV1_INVALID);
    if(r->associations||r->live||r->dispatching)return error(STEER_PV1_POLICY_DENIED);
    loop_fd_del(r->loop,r->wake);close(r->wake);
    (void)steer_draft_operations_destroy(r->operations);
    if(r->resolver)steer_draft_resolver_release(r->resolver);
    free(r);return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_datagram_use_resolver(struct steer_draft_datagram_runtime *r,
    struct steer_draft_resolver *resolver) {
    if(!r)return error(STEER_PV1_INVALID);
    if(r->live||r->associations||r->resolver)return error(STEER_PV1_POLICY_DENIED);
    if(!resolver)return error(STEER_PV1_OK);
    struct steer_pv1_error e=steer_draft_resolver_retain(resolver);
    if(!e.code)r->resolver=resolver;
    return e;
}
int steer_draft_datagram_has_resolver(const struct steer_draft_datagram_runtime *r){return r&&r->resolver;}
struct steer_pv1_error steer_draft_datagram_adopt(struct steer_draft_datagram_runtime *r,int fd,
    struct steer_pv1_datagram_ref *out) {
    if(out)*out=(struct steer_pv1_datagram_ref){NULL,NULL};
    int type,protocol; socklen_t n=sizeof(type);
    struct sockaddr_storage peer; socklen_t length=sizeof(peer);
    if(!r||!out||fd<0||getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)||type!=SOCK_DGRAM||
       getsockopt(fd,SOL_SOCKET,SO_PROTOCOL,&protocol,&n)||protocol!=IPPROTO_UDP||
       getpeername(fd,(struct sockaddr *)&peer,&length))return error(STEER_PV1_INVALID);
    if(peer.ss_family!=AF_INET&&peer.ss_family!=AF_INET6)return error(STEER_PV1_UNSUPPORTED);
    if(peer.ss_family==AF_INET6&&((struct sockaddr_in6 *)&peer)->sin6_scope_id)return error(STEER_PV1_UNSUPPORTED);
    if(r->associations>=r->max_associations)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_datagram *d=calloc(1,sizeof(*d));if(!d)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    int flags=fcntl(fd,F_GETFL);
    if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0||(flags=fcntl(fd,F_GETFD))<0||
       fcntl(fd,F_SETFD,flags|FD_CLOEXEC)<0){free(d);return error(STEER_PV1_IO);}
    d->runtime=r;d->fd=fd;r->associations++;out->handle=d;out->api=&datagram_api;
    return error(STEER_PV1_OK);
}
struct datagram_open {
    struct steer_draft_datagram_runtime *runtime;
    struct steer_draft_flow_owned flow;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_datagram_ref result;
    struct steer_pv1_endpoint bound,peer;
    uint8_t bound_bytes[16],peer_bytes[16];
    struct steer_draft_resolve_job *resolve;
    struct loop_timer *timer;
    uint64_t deadline;
    steer_pv1_datagram_open_done done;
    void *userdata;
    int terminal,completed;
};
static void open_finish(struct datagram_open *op,uint32_t code) {
    if(op->terminal)return;
    op->terminal=1;
    if(op->resolve)steer_draft_resolver_cancel(op->resolve);
    op->resolve=NULL;loop_timer_free(op->timer);op->timer=NULL;
    if(code&&op->result.handle){
        op->result.api->close(op->result.handle);(void)op->result.api->release(op->result.handle);
        op->result=(struct steer_pv1_datagram_ref){NULL,NULL};
    }
    (void)steer_draft_operation_resolve(op->inner.handle,error(code));notify(op->runtime);
}
static void open_deliver(void *arg,struct steer_pv1_error e) {
    struct datagram_open *op=arg;
    if(!e.code&&now_ns()>=op->deadline){
        e=error(STEER_PV1_TIMEOUT);
        if(op->result.handle){op->result.api->close(op->result.handle);(void)op->result.api->release(op->result.handle);}
        op->result=(struct steer_pv1_datagram_ref){NULL,NULL};
    }
    struct steer_pv1_datagram_ref result=op->result;
    op->result=(struct steer_pv1_datagram_ref){NULL,NULL};
    op->done(op->userdata,e,result,e.code?NULL:&op->bound,e.code?NULL:&op->peer);
    op->completed=1;
}
static void STEER_PV1_CALL open_cancel(struct steer_pv1_operation *opaque) {open_finish((void *)opaque,STEER_PV1_CANCELLED);}
static void STEER_PV1_CALL open_release(struct steer_pv1_operation *opaque) {
    struct datagram_open *op=(void *)opaque;if(!op->completed)return;
    op->inner.api->release(op->inner.handle);op->runtime->live--;free(op);
}
static const struct steer_pv1_operation_api open_operation_api={
    sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,open_cancel,open_release
};
static void open_timeout(struct loop *l,struct loop_timer *t,void *arg) {
    (void)l;(void)t;struct datagram_open *op=arg;
    if(now_ns()<op->deadline)deadline_arm(op->timer,op->deadline);else open_finish(op,STEER_PV1_TIMEOUT);
}
static int endpoint_from_socket(int fd,int peer,struct steer_pv1_endpoint *out,uint8_t storage[16]) {
    struct sockaddr_storage sa;socklen_t n=sizeof(sa);
    if(peer?getpeername(fd,(struct sockaddr *)&sa,&n):getsockname(fd,(struct sockaddr *)&sa,&n))return -1;
    *out=(struct steer_pv1_endpoint){.size=sizeof(*out),.version=STEER_PV1_DRAFT_LAYOUT};
    out->address.data=storage;
    if(sa.ss_family==AF_INET){
        struct sockaddr_in *a=(void *)&sa;out->tag=STEER_PV1_ENDPOINT_IPV4;
        out->address.len=4;out->port=ntohs(a->sin_port);memcpy(storage,&a->sin_addr,4);
    }else if(sa.ss_family==AF_INET6){
        struct sockaddr_in6 *a=(void *)&sa;if(a->sin6_scope_id)return -1;
        out->tag=STEER_PV1_ENDPOINT_IPV6;out->address.len=16;out->port=ntohs(a->sin6_port);memcpy(storage,&a->sin6_addr,16);
    }else return -1;
    return 0;
}
static uint32_t open_address(struct datagram_open *op,const struct sockaddr_storage *address) {
    if(now_ns()>=op->deadline)return STEER_PV1_TIMEOUT;
    struct sockaddr_storage sa=*address;socklen_t n;
    uint16_t port=op->flow.value.destination.port;
    if(sa.ss_family==AF_INET){((struct sockaddr_in *)&sa)->sin_port=htons(port);n=sizeof(struct sockaddr_in);}
    else if(sa.ss_family==AF_INET6){
        struct sockaddr_in6 *a=(void *)&sa;
        if(a->sin6_scope_id||IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr))return STEER_PV1_UNSUPPORTED;
        a->sin6_port=htons(port);n=sizeof(*a);
    }else return STEER_PV1_INVALID;
    int fd=socket(sa.ss_family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_UDP);
    if(fd<0)return STEER_PV1_IO;
    if(connect(fd,(struct sockaddr *)&sa,n)||endpoint_from_socket(fd,0,&op->bound,op->bound_bytes)||
       endpoint_from_socket(fd,1,&op->peer,op->peer_bytes)){close(fd);return STEER_PV1_IO;}
    struct steer_pv1_error e=steer_draft_datagram_adopt(op->runtime,fd,&op->result);
    if(e.code)close(fd);
    return e.code;
}
static void open_resolved(void *arg,const struct steer_draft_resolve_result *result) {
    struct datagram_open *op=arg;op->resolve=NULL;
    if(result->code){open_finish(op,result->code<=STEER_PV1_INTERNAL?result->code:STEER_PV1_INTERNAL);return;}
    if(!result->count||result->count>STEER_DRAFT_RESOLVE_ADDRESSES){open_finish(op,STEER_PV1_IO);return;}
    uint32_t code=STEER_PV1_IO;
    /* Only try alternatives when local socket setup fails. UDP connect proves
     * no remote reachability; never replay application datagrams on another IP. */
    for(uint32_t i=0;i<result->count;i++){
        code=open_address(op,&result->addresses[i]);
        if(!code||code==STEER_PV1_TIMEOUT)break;
    }
    open_finish(op,code);
}
static struct steer_pv1_async_start STEER_PV1_CALL backend_open(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_datagram_open_done done,void *userdata) {
    struct steer_draft_datagram_runtime *r=context;
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_INVALID,0},{NULL,NULL}};
    if(!r||!done||deadline<=now_ns())return a;
    a.error=steer_draft_flow_validate(flow,STEER_PV1_FLOW_DATAGRAM);if(a.error.code)return a;
    if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&!r->resolver){a.error=error(STEER_PV1_UNSUPPORTED);return a;}
    struct datagram_open *op=calloc(1,sizeof(*op));
    if(!op){a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);return a;}
    a.error=steer_draft_flow_copy(&op->flow,flow,STEER_PV1_FLOW_DATAGRAM);
    if(a.error.code){free(op);return a;}
    op->runtime=r;op->deadline=deadline;op->done=done;op->userdata=userdata;
    a=steer_draft_operation_start(r->operations,open_deliver,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);return a;}
    op->inner=a.operation;a.operation.handle=(void *)op;a.operation.api=&open_operation_api;r->live++;
    if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN){
        struct steer_pv1_error e=steer_draft_resolver_submit(r->resolver,op->flow.value.destination.address,
            flow->destination.port,open_resolved,op,&op->resolve);
        if(e.code)open_finish(op,e.code);
    }else{
        struct sockaddr_storage sa={0};
        if(flow->destination.tag==STEER_PV1_ENDPOINT_IPV4){
            struct sockaddr_in *address=(void *)&sa;address->sin_family=AF_INET;
            memcpy(&address->sin_addr,flow->destination.address.data,4);
        }else{
            struct sockaddr_in6 *address=(void *)&sa;address->sin6_family=AF_INET6;
            memcpy(&address->sin6_addr,flow->destination.address.data,16);
        }
        open_finish(op,open_address(op,&sa));
    }
    if(!op->terminal){
        op->timer=loop_timer_new(r->loop,open_timeout,op);
        if(!op->timer)open_finish(op,STEER_PV1_RESOURCE_EXHAUSTED);else deadline_arm(op->timer,deadline);
    }
    return a;
}
static const struct steer_pv1_datagram_backend_api backend_api={
    sizeof(backend_api),STEER_PV1_DRAFT_LAYOUT,backend_open
};
const struct steer_pv1_datagram_backend_api *steer_draft_datagram_backend_api(void) {return &backend_api;}
