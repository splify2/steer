/* SPDX-License-Identifier: GPL-3.0-only */
#include "socks_udp_backend.h"
#include "socks_udp_transport.h"
#include "buffers.h"
#include "operations.h"
#include "flow_metadata.h"
#include "stream_open_deadline.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#define NS_MS UINT64_C(1000000)
#define LIMIT STEER_SOCKS_UDP_MESSAGE_LIMIT
struct association;
struct operation;
struct steer_socks_udp_backend {
    struct steer_draft_datagram_binding binding;
    struct steer_pv1_host *buffers;
    struct sockaddr_in upstream;
    struct steer_draft_operations *operations;
    struct loop_timer *dispatch;
    struct association *head;
    uint64_t max_bytes, bytes, retire_deadline;
    unsigned drain_ms;
    int finalized;
    void (*drained)(void *);
    void *user;
};
enum kind { OPEN, SEND, RECEIVE };
struct association {
    struct steer_socks_udp_backend *backend;
    struct association *next, *prev;
    struct steer_socks_udp_transport *udp;
    struct loop_timer *timer;
    struct operation *opening, *send, *receive;
    struct steer_pv1_endpoint peer;
    uint8_t peer_address[16];
    uint64_t open_deadline;
    uint32_t refs, failure;
    int watching, udp_watching, closed;
};
struct operation {
    struct steer_socks_udp_backend *backend;
    struct association *association;
    enum kind kind;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_buffer *buffer;
    uint8_t *data;
    uint64_t deadline;
    uint32_t length, bytes;
    int detached, completed;
    union { steer_pv1_datagram_open_done open; steer_pv1_datagram_done io; } done;
    void *user;
};
static const struct steer_pv1_datagram_api datagram_api;
static struct steer_pv1_error error(uint32_t code) { return (struct steer_pv1_error){code,0}; }
static struct steer_pv1_async_start rejected(uint32_t code) {
    return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{code,0},{NULL,NULL}};
}
static void arm(struct association *s) {
    if (!s->udp) return;
    uint64_t now=steer_draft_stream_now_ns();
    uint64_t due=0;
    uint64_t ds[]={s->opening?s->open_deadline:0,
        s->send&&!s->send->detached?s->send->deadline:0,
        s->receive&&!s->receive->detached?s->receive->deadline:0,
        s->backend->retire_deadline};
    for (size_t i=0;i<sizeof ds/sizeof ds[0];i++)
        if (ds[i] && (!due || ds[i]<due)) due=ds[i];
    if (due) steer_draft_stream_arm_deadline(s->timer,due,now);
    else loop_timer_stop(s->timer);
}
static void detach(struct association *s) {
    if (!s->udp) return;
    if (s->watching) loop_fd_del(s->backend->binding.owner,steer_socks_udp_transport_tcp_fd(s->udp));
    if (s->udp_watching) loop_fd_del(s->backend->binding.owner,steer_socks_udp_transport_udp_fd(s->udp));
    s->watching=0;
    s->udp_watching=0;
    loop_timer_stop(s->timer);
    steer_socks_udp_transport_destroy(s->udp);
    s->udp=NULL;
}
static void dispose(struct association *s) {
    struct steer_socks_udp_backend *b=s->backend;
    detach(s);
    loop_timer_free(s->timer);
    if (s->prev) s->prev->next=s->next; else b->head=s->next;
    if (s->next) s->next->prev=s->prev;
    free(s);
    (void)steer_draft_binding_unpin(b->binding.lease);
}
static void resolve(struct operation *o,uint32_t code,uint32_t bytes) {
    if (!o || o->detached) return;
    o->detached=1;o->bytes=bytes;
    o->backend->bytes-=o->length;
    (void)steer_draft_operation_resolve(o->inner.handle,error(code));
    loop_timer_set(o->backend->dispatch,0);
}
static void finish_open(struct association *s,uint32_t code) {
    struct operation *o=s->opening;
    s->opening=NULL;
    if (code) { o->association=NULL;dispose(s); }
    resolve(o,code,0);
}
static void broken(struct association *s,uint32_t code) {
    if (s->opening) { finish_open(s,code);return; }
    if (!s->failure) s->failure=code;
    detach(s);
    resolve(s->send,code,0);
    resolve(s->receive,code,0);
}
static void deliver(void *arg,struct steer_pv1_error e) {
    struct operation *o=arg;
    struct association *s=o->association;
    if (o->kind==OPEN) {
        struct steer_pv1_datagram_ref ref={NULL,NULL};
        const struct steer_pv1_endpoint *peer=NULL;
        if (!e.code) {
            uint64_t now=steer_draft_stream_now_ns();
            if (s->failure || now>=s->open_deadline ||
                (o->backend->retire_deadline && now>=o->backend->retire_deadline)) {
                e=error(s->failure?s->failure:STEER_PV1_TIMEOUT);
                dispose(s);
            } else {
                ref.handle=(struct steer_pv1_datagram *)s;ref.api=&datagram_api;peer=&s->peer;
            }
        }
        o->association=NULL;
        o->done.open(o->user,e,ref,NULL,peer);
    } else {
        if (o->kind==SEND) s->send=NULL; else s->receive=NULL;
        o->done.io(o->user,e,o->buffer,o->bytes);
    }
    o->completed=1;
}
static void dispatch(struct loop *loop,struct loop_timer *timer,void *arg) {
    struct steer_socks_udp_backend *b=arg;
    uint32_t queued;
    (void)loop;
    (void)steer_draft_operations_dispatch(b->operations,32,NULL);
    steer_draft_operations_usage(b->operations,NULL,&queued);
    if (queued) loop_timer_set(timer,0);
}
static void progress(struct association *,int);
static void STEER_PV1_CALL cancel(struct steer_pv1_operation *handle) {
    struct operation *o=(void *)handle;
    if (o->detached) return;
    if (o->kind==OPEN) finish_open(o->association,STEER_PV1_CANCELLED);
    else { resolve(o,STEER_PV1_CANCELLED,0);progress(o->association,0); }
}
static void STEER_PV1_CALL release_op(struct steer_pv1_operation *handle) {
    struct operation *o=(void *)handle;
    if (!o->completed) return;
    o->inner.api->release(o->inner.handle);
    if (o->association) o->association->refs--;
    else (void)steer_draft_binding_unpin(o->backend->binding.lease);
    free(o);
}
static const struct steer_pv1_operation_api operation_api={
    sizeof operation_api,STEER_PV1_DRAFT_LAYOUT,cancel,release_op
};
static struct steer_pv1_async_start start(struct operation *o) {
    struct steer_pv1_async_start a=steer_draft_operation_start(o->backend->operations,deliver,o);
    if (a.disposition==STEER_PV1_PENDING) {
        o->inner=a.operation;a.operation.handle=(void *)o;a.operation.api=&operation_api;
        o->backend->bytes+=o->length;
    }
    return a;
}
static void fd_ready(struct loop *,int,uint32_t,void *);
static void progress(struct association *s,int readable) {
    if (!s->udp) return;
    struct steer_socks_udp_backend *b=s->backend;
    uint64_t now=steer_draft_stream_now_ns();
    if ((s->opening && now>=s->open_deadline) ||
        (b->retire_deadline && now>=b->retire_deadline)) {
        broken(s,STEER_PV1_TIMEOUT);return;
    }
    (void)readable;
    steer_socks_udp_transport_drive(s->udp);
    enum steer_socks_udp_state state=steer_socks_udp_transport_state(s->udp);
    if (state==SOCKS_UDP_FAILED) { broken(s,STEER_PV1_IO);return; }
    if (state==SOCKS_UDP_CONNECTING &&
        loop_fd_mod(b->binding.owner,steer_socks_udp_transport_tcp_fd(s->udp),
                    EPOLLIN|EPOLLRDHUP|(steer_socks_udp_transport_wants_write(s->udp)?EPOLLOUT:0))) {
        broken(s,STEER_PV1_IO);return;
    }
    if (state==SOCKS_UDP_READY && s->opening) {
        if(loop_fd_mod(b->binding.owner,steer_socks_udp_transport_tcp_fd(s->udp),EPOLLIN|EPOLLRDHUP)) {
            broken(s,STEER_PV1_IO);return;
        }
    }
    if (s->opening && state==SOCKS_UDP_READY) finish_open(s,STEER_PV1_OK);
    struct operation *o=s->receive;
    if (o && !o->detached) {
        size_t bytes=0;
        if (now>=o->deadline) resolve(o,STEER_PV1_TIMEOUT,0);
        else {
            int r=steer_socks_udp_transport_receive(s->udp,o->data,o->length,&bytes);
            if(r==0)resolve(o,STEER_PV1_OK,(uint32_t)bytes);
            else if(r==-3)resolve(o,STEER_PV1_RESOURCE_EXHAUSTED,0);
            else if(r!=-2)resolve(o,STEER_PV1_IO,0);
        }
    }
    o=s->send;
    if (o && !o->detached) {
        if (now>=o->deadline) resolve(o,STEER_PV1_TIMEOUT,0);
        else {
            int r=steer_socks_udp_transport_send(s->udp,o->data,o->length);
            if (!r) resolve(o,STEER_PV1_OK,o->length);
            else if (r!=-2) resolve(o,STEER_PV1_IO,0);
        }
    }
    uint32_t events=(s->receive&&!s->receive->detached?EPOLLIN:0)|
                    (s->send&&!s->send->detached?EPOLLOUT:0);
    int fd=steer_socks_udp_transport_udp_fd(s->udp);
    if (!events && s->udp_watching) {
        loop_fd_del(b->binding.owner,fd);s->udp_watching=0;
    } else if (events) {
        int rc=s->udp_watching?loop_fd_mod(b->binding.owner,fd,events):
                               loop_fd_add(b->binding.owner,fd,events,fd_ready,s);
        if(rc){broken(s,STEER_PV1_IO);return;}
        s->udp_watching=1;
    }
    arm(s);
}
static void fd_ready(struct loop *l,int fd,uint32_t events,void *arg) {
    struct association *s=arg;
    (void)l;
    if(s->udp && fd==steer_socks_udp_transport_udp_fd(s->udp) &&
       (events&(EPOLLERR|EPOLLHUP))) { broken(s,STEER_PV1_IO);return; }
    progress(s,1);
}
static void timer_ready(struct loop *l,struct loop_timer *t,void *arg) {
    (void)l;(void)t;progress(arg,0);
}
static struct steer_pv1_async_start submit(struct association *s,enum kind kind,
    struct steer_pv1_buffer *buf,uint32_t off,uint32_t n,uint64_t deadline,
    steer_pv1_datagram_done done,void *user) {
    if (!s || !buf || !done || (kind==RECEIVE&&!n)) return rejected(STEER_PV1_INVALID);
    if (deadline<=steer_draft_stream_now_ns()) return rejected(STEER_PV1_TIMEOUT);
    if (s->closed || s->failure) return rejected(s->failure?s->failure:STEER_PV1_POLICY_DENIED);
    struct operation **slot=kind==SEND?&s->send:&s->receive;
    if (*slot) return rejected(STEER_PV1_POLICY_DENIED);
    if (kind==SEND && n>LIMIT)
        return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_socks_udp_backend *b=s->backend;
    struct steer_pv1_mut_span view={NULL,0};
    struct steer_pv1_error e=steer_draft_buffers_api()->writable(b->buffers,buf,&view);
    if (e.code) return rejected(e.code);
    if (off>view.len || n>view.len-off) return rejected(STEER_PV1_INVALID);
    if (n>b->max_bytes-b->bytes) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct operation *o=calloc(1,sizeof *o);
    if (!o) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    o->backend=b;o->association=s;o->kind=kind;o->buffer=buf;o->data=n?view.data+off:view.data;
    o->length=n;o->deadline=deadline;o->done.io=done;o->user=user;
    struct steer_pv1_async_start a=start(o);
    if (a.disposition!=STEER_PV1_PENDING) { free(o);return a; }
    *slot=o;s->refs++;
    progress(s,0);
    return a;
}
static uint32_t STEER_PV1_CALL message_limit(struct steer_pv1_datagram *h) {
    struct association *s=(void *)h;
    return s && !s->closed && !s->failure && s->udp?
        LIMIT:0;
}
static struct steer_pv1_async_start STEER_PV1_CALL send_message(struct steer_pv1_datagram *h,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t d,steer_pv1_datagram_done f,void *u) {
    return submit((void *)h,SEND,b,o,n,d,f,u);
}
static struct steer_pv1_async_start STEER_PV1_CALL receive_message(struct steer_pv1_datagram *h,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t d,steer_pv1_datagram_done f,void *u) {
    return submit((void *)h,RECEIVE,b,o,n,d,f,u);
}
static void STEER_PV1_CALL close_message(struct steer_pv1_datagram *h) {
    struct association *s=(void *)h;
    if (s && !s->closed) { s->closed=1;broken(s,STEER_PV1_CANCELLED); }
}
static struct steer_pv1_error STEER_PV1_CALL release_message(struct steer_pv1_datagram *h) {
    struct association *s=(void *)h;
    if (!s) return error(STEER_PV1_INVALID);
    if (!s->closed || s->refs) return error(STEER_PV1_POLICY_DENIED);
    dispose(s);return error(STEER_PV1_OK);
}
static const struct steer_pv1_datagram_api datagram_api={
    sizeof datagram_api,STEER_PV1_DRAFT_LAYOUT,message_limit,send_message,receive_message,
    close_message,release_message
};
static struct steer_pv1_async_start STEER_PV1_CALL open_datagram(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,
    steer_pv1_datagram_open_done done,void *user) {
    struct steer_socks_udp_backend *b=context;
    struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_DATAGRAM);
    if (!b || e.code || !done) return rejected(e.code?e.code:STEER_PV1_INVALID);
    uint64_t now=steer_draft_stream_now_ns();
    if (now>=deadline) return rejected(STEER_PV1_TIMEOUT);
    const struct steer_pv1_endpoint *dst=&flow->destination;
    if (dst->tag!=STEER_PV1_ENDPOINT_IPV4)
        return rejected(STEER_PV1_UNSUPPORTED);
    struct sockaddr_in target={.sin_family=AF_INET,.sin_port=htons(dst->port)};
    memcpy(&target.sin_addr,dst->address.data,4);
    e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_DATAGRAM);
    if (e.code) return rejected(e.code);
    e=steer_draft_binding_pin(b->binding.lease,flow->generation,STEER_PV1_FLOW_DATAGRAM);
    if (e.code) { (void)steer_draft_binding_unpin(b->binding.lease);return rejected(e.code); }
    struct operation *o=calloc(1,sizeof *o);
    struct association *s=calloc(1,sizeof *s);
    struct steer_pv1_async_start a=rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    if (!o || !s) goto fail;
    s->timer=loop_timer_new(b->binding.owner,timer_ready,s);
    if (!s->timer) goto fail;
    o->backend=b;o->association=s;o->kind=OPEN;o->done.open=done;o->user=user;
    a=start(o);
    if (a.disposition!=STEER_PV1_PENDING) goto fail;
    s->backend=b;s->open_deadline=deadline;s->opening=o;
    s->peer=*dst;
    memcpy(s->peer_address,dst->address.data,dst->address.len);
    s->peer.address.data=s->peer_address;
    s->next=b->head;if (b->head) b->head->prev=s;b->head=s;
    if (steer_socks_udp_transport_open(&b->upstream,&target,&s->udp)) {
        finish_open(s,STEER_PV1_IO);return a;
    }
    if (loop_fd_add(b->binding.owner,steer_socks_udp_transport_tcp_fd(s->udp),EPOLLIN|EPOLLOUT|EPOLLRDHUP,fd_ready,s)) {
        finish_open(s,STEER_PV1_IO);return a;
    }
    s->watching=1;arm(s);return a;
fail:
    if (s) loop_timer_free(s->timer);
    free(s);free(o);
    (void)steer_draft_binding_unpin(b->binding.lease);
    (void)steer_draft_binding_unpin(b->binding.lease);
    return a;
}
static const struct steer_pv1_datagram_backend_api backend_api={
    sizeof backend_api,STEER_PV1_DRAFT_LAYOUT,open_datagram
};
static void finalized(void *arg,const struct steer_draft_binding_identity *identity) {
    struct steer_socks_udp_backend *b=arg;
    (void)identity;b->finalized=1;
    if (b->drained) b->drained(b->user);
}
struct steer_pv1_error steer_socks_udp_backend_create(struct loop *loop,
    struct steer_pv1_host *buffers,const struct sockaddr_in *upstream,uint64_t generation,
    uint64_t token,uint32_t max_operations,uint64_t max_bytes,uint32_t max_references,
    unsigned drain_ms,void (*drained)(void *),void *user,struct steer_socks_udp_backend **out) {
    if (out) *out=NULL;
    if (!loop||!buffers||!upstream||upstream->sin_family!=AF_INET||
        ntohl(upstream->sin_addr.s_addr)!=INADDR_LOOPBACK||!upstream->sin_port||
        !generation||!token||!out||!drain_ms)
        return error(STEER_PV1_INVALID);
    struct steer_socks_udp_backend *b=calloc(1,sizeof *b);
    if (!b) return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_error e=steer_draft_operations_create(max_operations,NULL,&b->operations);
    if (e.code) goto fail;
    b->dispatch=loop_timer_new(loop,dispatch,b);
    if (!b->dispatch) { e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail; }
    static const uint8_t provider[]="steer.socks5.udp";
    struct steer_draft_binding_identity identity={sizeof identity,STEER_PV1_DRAFT_LAYOUT,
        generation,token,{provider,sizeof provider-1},STEER_DRAFT_DATAGRAM_BINDING_PREPARED,
        STEER_PV1_FLOW_DATAGRAM};
    e=steer_draft_binding_lease_create(loop,&identity,max_references,finalized,b,&b->binding.lease);
    if (e.code) goto fail;
    b->binding.owner=loop;b->binding.context=b;b->binding.api=&backend_api;
    b->buffers=buffers;b->upstream=*upstream;b->max_bytes=max_bytes;b->drain_ms=drain_ms;
    b->drained=drained;b->user=user;*out=b;
    return error(STEER_PV1_OK);
fail:
    loop_timer_free(b->dispatch);
    if (b->operations) (void)steer_draft_operations_destroy(b->operations);
    free(b);return e;
}
const struct steer_draft_datagram_binding *steer_socks_udp_backend_binding(
    const struct steer_socks_udp_backend *b) { return b?&b->binding:NULL; }
void steer_socks_udp_backend_retire(struct steer_socks_udp_backend *b) {
    if (!b || b->retire_deadline) return;
    (void)steer_draft_binding_retire(b->binding.lease);
    b->retire_deadline=steer_draft_stream_now_ns()+(uint64_t)b->drain_ms*NS_MS;
    for (struct association *s=b->head;s;s=s->next) arm(s);
}
struct steer_pv1_error steer_socks_udp_backend_destroy(struct steer_socks_udp_backend *b) {
    if (!b||!b->finalized||b->head) return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);
    if (e.code) return e;
    loop_timer_free(b->dispatch);
    (void)steer_draft_operations_destroy(b->operations);
    free(b);return error(STEER_PV1_OK);
}
void steer_socks_udp_backend_usage(const struct steer_socks_udp_backend *b,uint32_t *ops,uint64_t *bytes) {
    uint32_t live=0;
    if(b)steer_draft_operations_usage(b->operations,&live,NULL);
    if(ops)*ops=live;
    if(bytes)*bytes=b?b->bytes:0;
}
