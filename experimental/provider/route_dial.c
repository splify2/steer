#define _GNU_SOURCE
#include "route_dial.h"
#include "operations.h"
#include "resolver.h"
#include "loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
struct steer_draft_routes {
    struct loop *loop;
    struct steer_draft_stream_runtime *streams;
    struct steer_draft_operations *operations;
    steer_draft_route_evaluate evaluate;
    void *context;
    struct steer_draft_resolver *resolver;
    uint64_t generation;
    uint32_t live;
    int wake, dispatching;
};
struct route_operation {
    struct steer_draft_routes *routes;
    struct steer_pv1_operation_ref inner;
    struct loop_timer *deadline;
    steer_draft_route_done done;
    void *userdata;
    struct steer_pv1_stream *stream;
    struct steer_pv1_endpoint bound;
    uint8_t bound_bytes[16];
    uint64_t deadline_ns;
    uint32_t failure;
    struct steer_draft_resolve_job *resolve_job;
    struct steer_draft_resolve_result resolved;
    uint32_t address_index;
    uint16_t destination_port;
    int fd, watching, terminal, completed;
};
static struct steer_pv1_error error(uint32_t code) {
    struct steer_pv1_error e={code,0}; return e;
}
static uint64_t now_ns(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static void notify(struct steer_draft_routes *r) {
    uint64_t one=1; ssize_t n;
    do { n=write(r->wake,&one,sizeof(one)); } while(n<0 && errno==EINTR);
}
static void finish(struct route_operation *op,uint32_t code) {
    if(op->terminal) return;
    op->terminal=1;
    if(op->resolve_job) steer_draft_resolver_cancel(op->resolve_job);
    op->resolve_job=NULL;
    if(op->watching) loop_fd_del(op->routes->loop,op->fd);
    op->watching=0;
    if(op->fd>=0) close(op->fd);
    op->fd=-1;
    loop_timer_free(op->deadline); op->deadline=NULL;
    (void)steer_draft_operation_resolve(op->inner.handle,error(code));
    notify(op->routes);
}
static void cancelled(struct steer_pv1_operation *opaque) {
    finish((struct route_operation *)opaque,STEER_PV1_CANCELLED);
}
static void released(struct steer_pv1_operation *opaque) {
    struct route_operation *op=(struct route_operation *)opaque;
    if(!op->completed) return;
    op->inner.api->release(op->inner.handle); op->routes->live--; free(op);
}
static const struct steer_pv1_operation_api operation_api={
    sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,cancelled,released
};
static void delivered(void *arg,struct steer_pv1_error e) {
    struct route_operation *op=arg;
    struct steer_pv1_stream *s=op->stream;
    op->stream=NULL;
    op->done(op->userdata,e,op->failure,s,e.code?NULL:&op->bound);
    op->completed=1;
}
static void pump(struct loop *l,int fd,uint32_t events,void *arg) {
    struct steer_draft_routes *r=arg; uint64_t n; ssize_t got;
    (void)l;(void)events;
    do { got=read(fd,&n,sizeof(n)); } while(got<0 && errno==EINTR);
    r->dispatching=1;
    (void)steer_draft_operations_dispatch(r->operations,UINT32_MAX,NULL);
    r->dispatching=0;
}
static void timed_out(struct loop *l,struct loop_timer *t,void *arg) {
    (void)l;(void)t; finish(arg,STEER_PV1_TIMEOUT);
}
static void dial_address(struct route_operation *);
static void connected(struct route_operation *op,int code) {
    struct sockaddr_storage sa; socklen_t n=sizeof(sa);
    if(now_ns()>=op->deadline_ns) { finish(op,STEER_PV1_TIMEOUT); return; }
    if(code || getsockname(op->fd,(struct sockaddr *)&sa,&n)) {
        if(!code) code=errno;
        op->failure=code==ECONNREFUSED?STEER_DRAFT_DIAL_REFUSED:
            code==ENETUNREACH?STEER_DRAFT_DIAL_NETWORK_UNREACHABLE:
            code==EHOSTUNREACH?STEER_DRAFT_DIAL_HOST_UNREACHABLE:STEER_DRAFT_DIAL_OTHER;
        if(op->address_index<op->resolved.count) {
            if(op->watching) loop_fd_del(op->routes->loop,op->fd);
            op->watching=0; close(op->fd); op->fd=-1;
            dial_address(op); return;
        }
        finish(op,STEER_PV1_IO); return;
    }
    if(op->watching) loop_fd_del(op->routes->loop,op->fd);
    op->watching=0;
    if(steer_draft_stream_adopt(op->routes->streams,op->fd,&op->stream).code) {
        finish(op,STEER_PV1_RESOURCE_EXHAUSTED); return;
    }
    op->fd=-1;
    op->failure=STEER_DRAFT_DIAL_NONE;
    op->bound.size=sizeof(op->bound); op->bound.version=STEER_PV1_DRAFT_LAYOUT;
    op->bound.address.data=op->bound_bytes;
    if(sa.ss_family==AF_INET) {
        struct sockaddr_in *a=(struct sockaddr_in *)&sa;
        op->bound.tag=STEER_PV1_ENDPOINT_IPV4; op->bound.address.len=4;
        memcpy(op->bound_bytes,&a->sin_addr,4); op->bound.port=ntohs(a->sin_port);
    } else {
        struct sockaddr_in6 *a=(struct sockaddr_in6 *)&sa;
        op->bound.tag=STEER_PV1_ENDPOINT_IPV6; op->bound.address.len=16;
        memcpy(op->bound_bytes,&a->sin6_addr,16); op->bound.port=ntohs(a->sin6_port);
    }
    finish(op,STEER_PV1_OK);
}
static void ready(struct loop *l,int fd,uint32_t events,void *arg) {
    int code=0; socklen_t n=sizeof(code); (void)l;(void)events;
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&code,&n)) code=errno;
    connected(arg,code);
}
static void dial_address(struct route_operation *op) {
    struct sockaddr_storage *address;
    socklen_t length;
    int result;
    if(now_ns()>=op->deadline_ns) { finish(op,STEER_PV1_TIMEOUT);return; }
    if(op->address_index>=op->resolved.count) { finish(op,STEER_PV1_IO);return; }
    address=&op->resolved.addresses[op->address_index++];
    length=address->ss_family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
    op->fd=socket(address->ss_family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(op->fd<0) { finish(op,STEER_PV1_IO);return; }
    result=connect(op->fd,(struct sockaddr *)address,length);
    if(!result) connected(op,0);
    else if(errno!=EINPROGRESS) connected(op,errno);
    else if(loop_fd_add(op->routes->loop,op->fd,EPOLLOUT,ready,op)) finish(op,STEER_PV1_IO);
    else op->watching=1;
}
static void resolved(void *arg,const struct steer_draft_resolve_result *result) {
    struct route_operation *op=arg;
    uint32_t i;
    op->resolve_job=NULL;
    if(result->code) { op->failure=STEER_DRAFT_DIAL_HOST_UNREACHABLE;finish(op,result->code);return; }
    for(i=0;i<result->count;i++) {
        const struct sockaddr_storage *a=&result->addresses[i];
        if(a->ss_family!=AF_INET&&a->ss_family!=AF_INET6) { finish(op,STEER_PV1_INVALID);return; }
        if(a->ss_family==AF_INET6&&((const struct sockaddr_in6 *)a)->sin6_scope_id) { finish(op,STEER_PV1_UNSUPPORTED);return; }
    }
    op->resolved=*result;
    for(i=0;i<op->resolved.count;i++) {
        struct sockaddr_storage *a=&op->resolved.addresses[i];
        if(a->ss_family==AF_INET) ((struct sockaddr_in *)a)->sin_port=htons(op->destination_port);
        else ((struct sockaddr_in6 *)a)->sin6_port=htons(op->destination_port);
    }
    dial_address(op);
}
static int endpoint_valid(const struct steer_pv1_endpoint *e,int domain) {
    uint32_t i;
    if(e->size<sizeof(*e) || e->version!=STEER_PV1_DRAFT_LAYOUT || e->reserved ||
       !e->address.data || !e->port) return 0;
    if(e->tag==STEER_PV1_ENDPOINT_IPV4) return e->address.len==4;
    if(e->tag==STEER_PV1_ENDPOINT_IPV6) return e->address.len==16;
    if(!domain || e->tag!=STEER_PV1_ENDPOINT_DOMAIN || !e->address.len || e->address.len>254) return 0;
    for(i=0;i<e->address.len;i++) if(!e->address.data[i]) return 0;
    return 1;
}
static int identifier(struct steer_pv1_span s,int empty) {
    uint32_t i;
    if(!s.len) return empty;
    if(!s.data || s.len>64) return 0;
    for(i=0;i<s.len;i++) {
        uint8_t c=s.data[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.')) return 0;
    }
    return 1;
}
struct steer_pv1_error steer_draft_routes_create(struct loop *l,
    struct steer_draft_stream_runtime *streams,uint64_t generation,uint32_t max,
    steer_draft_route_evaluate evaluate,void *context,struct steer_draft_routes **out) {
    struct steer_draft_routes *r; struct steer_pv1_error e;
    if(out) *out=NULL;
    if(!l || !streams || !generation || !evaluate || !out) return error(STEER_PV1_INVALID);
    r=calloc(1,sizeof(*r)); if(!r) return error(STEER_PV1_RESOURCE_EXHAUSTED);
    e=steer_draft_operations_create(max,NULL,&r->operations);
    if(e.code) { free(r); return e; }
    r->loop=l; r->streams=streams; r->evaluate=evaluate; r->context=context;
    r->generation=generation;
    r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(r->wake<0 || loop_fd_add(l,r->wake,EPOLLIN,pump,r)) {
        if(r->wake>=0) close(r->wake);
        (void)steer_draft_operations_destroy(r->operations); free(r);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=r; return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_routes_destroy(struct steer_draft_routes *r) {
    if(!r) return error(STEER_PV1_INVALID);
    if(r->live || r->dispatching) return error(STEER_PV1_POLICY_DENIED);
    loop_fd_del(r->loop,r->wake); close(r->wake);
    if(r->resolver) steer_draft_resolver_release(r->resolver);
    (void)steer_draft_operations_destroy(r->operations); free(r); return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_routes_use_resolver(struct steer_draft_routes *r,
    struct steer_draft_resolver *resolver) {
    struct steer_pv1_error e;
    if(!r||!resolver) return error(STEER_PV1_INVALID);
    if(r->live||r->resolver) return error(STEER_PV1_POLICY_DENIED);
    e=steer_draft_resolver_retain(resolver);
    if(!e.code) r->resolver=resolver;
    return e;
}
struct steer_pv1_async_start steer_draft_route_dial(struct steer_draft_routes *r,
    const struct steer_draft_accepted *flow,uint64_t deadline_ns,
    steer_draft_route_done done,void *userdata) {
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_INVALID,0},{NULL,NULL}};
    struct route_operation *op; struct sockaddr_storage *address;
    uint64_t now=now_ns(),ms; uint32_t action=UINT32_MAX;
    if(!r || !flow || !done || !flow->generation || !identifier(flow->inbound_id,0) ||
       !identifier(flow->principal_id,1) || !endpoint_valid(&flow->source,0) ||
       !endpoint_valid(&flow->destination,1) || deadline_ns<=now) return a;
    a.error=error(STEER_PV1_UNSUPPORTED);
    if(flow->principal || flow->flow_class!=STEER_PV1_FLOW_STREAM) return a;
    a.error=error(STEER_PV1_POLICY_DENIED);
    if(flow->generation!=r->generation) return a;
    a.error=r->evaluate(r->context,flow,&action);
    if(a.error.code>STEER_PV1_INTERNAL || a.error.transient>1 ||
       (!a.error.code && a.error.transient)) { a.error=error(STEER_PV1_INVALID); return a; }
    if(a.error.code) return a;
    a.error=error(action==STEER_DRAFT_ROUTE_BLOCK?STEER_PV1_POLICY_DENIED:STEER_PV1_UNSUPPORTED);
    if(action!=STEER_DRAFT_ROUTE_DIRECT ||
        (flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&!r->resolver)) return a;
    now=now_ns();
    if(deadline_ns<=now) { a.error=error(STEER_PV1_TIMEOUT); return a; }
    ms=(deadline_ns-now)/UINT64_C(1000000)+1;
    if(ms>INT32_MAX) { a.error=error(STEER_PV1_INVALID); return a; }
    a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);
    op=calloc(1,sizeof(*op)); if(!op) return a;
    op->routes=r; op->done=done; op->userdata=userdata; op->fd=-1;
    op->deadline_ns=deadline_ns;
    op->destination_port=flow->destination.port;
    a=steer_draft_operation_start(r->operations,delivered,op);
    if(a.disposition!=STEER_PV1_PENDING) { free(op); return a; }
    op->inner=a.operation; a.operation.handle=(struct steer_pv1_operation *)op;
    a.operation.api=&operation_api; r->live++;
    op->deadline=loop_timer_new(r->loop,timed_out,op);
    if(!op->deadline) { finish(op,STEER_PV1_RESOURCE_EXHAUSTED); return a; }
    loop_timer_set(op->deadline,(long)ms);
    if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN) {
        struct steer_pv1_error e=steer_draft_resolver_submit(r->resolver,
            flow->destination.address,flow->destination.port,resolved,op,&op->resolve_job);
        if(e.code) finish(op,e.code);
        return a;
    }
    address=&op->resolved.addresses[0];op->resolved.count=1;
    if(flow->destination.tag==STEER_PV1_ENDPOINT_IPV4) {
        struct sockaddr_in *s=(struct sockaddr_in *)address;
        s->sin_family=AF_INET;
        memcpy(&s->sin_addr,flow->destination.address.data,4); s->sin_port=htons(flow->destination.port);
    } else {
        struct sockaddr_in6 *s=(struct sockaddr_in6 *)address;
        s->sin6_family=AF_INET6;
        memcpy(&s->sin6_addr,flow->destination.address.data,16); s->sin6_port=htons(flow->destination.port);
    }
    dial_address(op);
    return a;
}
