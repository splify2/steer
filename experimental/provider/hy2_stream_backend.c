/* SPDX-License-Identifier: GPL-3.0-only */
#include "hy2_stream_backend.h"
#include "hy2_tcp_client.h"
#include "buffers.h"
#include "operations.h"
#include "stream_open_deadline.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#define NS_PER_MS UINT64_C(1000000)

struct operation;
struct hy2_stream;
struct steer_hy2_stream_backend {
    struct steer_draft_stream_binding binding;
    struct steer_pv1_host *buffers;
    struct steer_hy2_profile *profile;
    struct steer_draft_operations *operations;
    struct loop_timer *dispatch;
    struct hy2_stream *head;
    uint64_t bytes, max_bytes, retire_deadline;
    unsigned drain_ms;
    int finalized;
    void (*retired)(void *);
    void *userdata;
};
struct hy2_stream {
    struct steer_hy2_stream_backend *backend;
    struct hy2_stream *next, *prev;
    struct steer_hy2_tcp *tcp;
    struct loop_timer *timer;
    struct operation *opening, *read, *write; /* write slot includes finish */
    uint64_t deadline;
    uint32_t refs, failure;
    int watching, closed, finishing;
};
enum operation_kind { OPEN, READ, WRITE, FINISH };
struct operation {
    struct steer_hy2_stream_backend *backend;
    struct hy2_stream *stream;
    enum operation_kind kind;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_buffer *buffer;
    uint8_t *data;
    uint32_t length, transferred;
    int detached, completed;
    union {
        steer_pv1_stream_open_done open;
        steer_pv1_backend_io_done io;
        steer_pv1_backend_finish_done finish;
    } done;
    void *user;
};

static const struct steer_pv1_backend_stream_api stream_api;
static struct steer_pv1_error error(uint32_t c) { return (struct steer_pv1_error){c,0}; }
static struct steer_pv1_async_start rejected(uint32_t c) {
    return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{c,0},{NULL,NULL}};
}
static uint64_t ceil_ms(uint64_t ns) { return ns/NS_PER_MS+(ns%NS_PER_MS!=0); }

static void arm(struct hy2_stream *s) {
    if(!s->tcp) return;
    struct steer_hy2_stream_backend *b=s->backend;
    uint64_t now=steer_draft_stream_now_ns();
    int timeout=steer_hy2_tcp_timeout(s->tcp,now/NS_PER_MS);
    uint64_t due=timeout>=0?now+(uint64_t)timeout*NS_PER_MS:0;
    if(s->opening&&(!due||s->deadline<due)) due=s->deadline;
    if(b->retire_deadline&&(!due||b->retire_deadline<due)) due=b->retire_deadline;
    if(due) steer_draft_stream_arm_deadline(s->timer,due,now);
    else loop_timer_stop(s->timer);
}
static void unwatch(struct hy2_stream *s) {
    if(s->watching) {
        loop_fd_del(s->backend->binding.owner,steer_hy2_tcp_fd(s->tcp));
        s->watching=0;
    }
}
static void detach_tcp(struct hy2_stream *s) {
    unwatch(s);
    loop_timer_free(s->timer);
    s->timer=NULL;
    steer_hy2_tcp_destroy(s->tcp);
    s->tcp=NULL;
}
static void dispose_stream(struct hy2_stream *s) {
    struct steer_hy2_stream_backend *b=s->backend;
    detach_tcp(s);
    if(s->prev) s->prev->next=s->next; else b->head=s->next;
    if(s->next) s->next->prev=s->prev;
    free(s);
    (void)steer_draft_binding_unpin(b->binding.lease);
}
static void resolve(struct operation *op,uint32_t status,uint32_t n) {
    if(!op||op->detached) return;
    op->detached=1;
    op->transferred=n;
    op->backend->bytes-=op->length;
    (void)steer_draft_operation_resolve(op->inner.handle,error(status));
    loop_timer_set(op->backend->dispatch,0);
}
static void finish_open(struct hy2_stream *s,uint32_t status) {
    struct operation *op=s->opening;
    s->opening=NULL;
    if(status) { op->stream=NULL;dispose_stream(s); }
    resolve(op,status,0);
}
static void broken(struct hy2_stream *s,uint32_t status) {
    if(s->opening) { finish_open(s,status);return; }
    if(!s->failure) s->failure=status;
    detach_tcp(s);
    resolve(s->read,status,0);
    resolve(s->write,status,0);
}
static void deliver(void *arg,struct steer_pv1_error e) {
    struct operation *op=arg;
    struct hy2_stream *s=op->stream;
    if(op->kind==OPEN) {
        struct steer_pv1_stream_ref stream={NULL,NULL};
        if(!e.code) {
            uint64_t now=steer_draft_stream_now_ns(),retire=op->backend->retire_deadline;
            if(s->failure||now>=s->deadline||(retire&&now>=retire)) {
                e=error(s->failure?s->failure:STEER_PV1_TIMEOUT);
                dispose_stream(s);
            } else {
                stream.handle=(struct steer_pv1_backend_stream *)s;
                stream.api=&stream_api;
            }
        }
        op->stream=NULL;
        op->done.open(op->user,e,stream,NULL,NULL,NULL);
    } else if(op->kind==FINISH) {
        s->write=NULL;
        op->done.finish(op->user,e);
    } else {
        if(op->kind==READ) s->read=NULL; else s->write=NULL;
        op->done.io(op->user,e,op->buffer,op->transferred);
    }
    op->completed=1;
}
static void dispatch(struct loop *loop,struct loop_timer *timer,void *arg) {
    struct steer_hy2_stream_backend *b=arg;
    uint32_t queued;
    (void)loop;
    (void)steer_draft_operations_dispatch(b->operations,32,NULL);
    steer_draft_operations_usage(b->operations,NULL,&queued);
    if(queued) loop_timer_set(timer,0);
}
static void STEER_PV1_CALL cancel(struct steer_pv1_operation *handle) {
    struct operation *op=(struct operation *)handle;
    if(op->detached) return;
    if(op->kind==OPEN) finish_open(op->stream,STEER_PV1_CANCELLED);
    else if(op->kind==FINISH) broken(op->stream,STEER_PV1_CANCELLED);
    else resolve(op,STEER_PV1_CANCELLED,0);
}
static void STEER_PV1_CALL release_op(struct steer_pv1_operation *handle) {
    struct operation *op=(struct operation *)handle;
    if(!op->completed) return;
    struct steer_draft_binding_lease *lease=op->backend->binding.lease;
    op->inner.api->release(op->inner.handle);
    if(op->stream) op->stream->refs--;
    else (void)steer_draft_binding_unpin(lease); /* open owns its own admission pin */
    free(op);
}
static const struct steer_pv1_operation_api operation_api={
    sizeof operation_api,STEER_PV1_DRAFT_LAYOUT,cancel,release_op
};
static struct steer_pv1_async_start start(struct operation *op) {
    struct steer_hy2_stream_backend *b=op->backend;
    struct steer_pv1_async_start a=steer_draft_operation_start(b->operations,deliver,op);
    if(a.disposition==STEER_PV1_PENDING) {
        op->inner=a.operation;
        a.operation.handle=(struct steer_pv1_operation *)op;
        a.operation.api=&operation_api;
        b->bytes+=op->length;
    }
    return a;
}

static void progress(struct hy2_stream *s,int readable) {
    struct steer_hy2_stream_backend *b=s->backend;
    uint64_t now=steer_draft_stream_now_ns();
    if(!s->tcp) return;
    if((s->opening&&now>=s->deadline)||(b->retire_deadline&&now>=b->retire_deadline)) {
        broken(s,STEER_PV1_TIMEOUT);return;
    }
    steer_hy2_tcp_drive(s->tcp,now/NS_PER_MS,readable);
    enum steer_hy2_state state=steer_hy2_tcp_state(s->tcp);
    if(state>STEER_HY2_FINISHED) {
        broken(s,state==STEER_HY2_TIMEOUT?STEER_PV1_TIMEOUT:STEER_PV1_IO);
        return;
    }
    if(s->opening&&state==STEER_HY2_READY) {
        if(steer_draft_stream_now_ns()>=s->deadline) { finish_open(s,STEER_PV1_TIMEOUT);return; }
        finish_open(s,STEER_PV1_OK);
    }
    if(state==STEER_HY2_FINISHED) unwatch(s);
    struct operation *o=s->read;
    if(o&&!o->detached) {
        ssize_t n=steer_hy2_tcp_read(s->tcp,o->data,o->length);
        if(n==-1) { broken(s,STEER_PV1_IO);return; }
        if(n>=0) resolve(o,STEER_PV1_OK,(uint32_t)n);
    }
    o=s->write;
    if(o&&!o->detached) {
        if(o->kind==FINISH) {
            if(steer_hy2_tcp_shutdown_write(s->tcp)) { broken(s,STEER_PV1_IO);return; }
            resolve(o,STEER_PV1_OK,0);
        } else if(steer_hy2_tcp_room(s->tcp)) {
            ssize_t n=steer_hy2_tcp_write(s->tcp,o->data,o->length);
            if(n<0) { broken(s,STEER_PV1_IO);return; }
            if(n>0) resolve(o,STEER_PV1_OK,(uint32_t)n);
        }
    }
    /* Credit flush may surface a transport error synchronously. */
    if(steer_hy2_tcp_state(s->tcp)>STEER_HY2_FINISHED) { broken(s,STEER_PV1_IO);return; }
    arm(s);
}
static void udp_ready(struct loop *loop,int fd,uint32_t events,void *arg) {
    (void)loop;(void)fd;(void)events;
    progress(arg,1);
}
static void timer_ready(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)loop;(void)timer;
    progress(arg,0);
}
static struct steer_pv1_async_start submit(struct hy2_stream *s,enum operation_kind kind,
    struct steer_pv1_buffer *buf,uint32_t offset,uint32_t length,steer_pv1_backend_io_done io,
    steer_pv1_backend_finish_done finish,void *user) {
    if(s->closed) return rejected(STEER_PV1_POLICY_DENIED);
    if(s->failure) return rejected(s->failure);
    struct operation **slot=kind==READ?&s->read:&s->write;
    if(*slot||(kind!=READ&&s->finishing)) return rejected(STEER_PV1_POLICY_DENIED);
    struct steer_hy2_stream_backend *b=s->backend;
    struct steer_pv1_mut_span view={NULL,0};
    if(kind!=FINISH) {
        if(!buf||!io||!length) return rejected(STEER_PV1_INVALID);
        struct steer_pv1_error e=steer_draft_buffers_api()->writable(b->buffers,buf,&view);
        if(e.code) return rejected(e.code);
        if(offset>view.len||length>view.len-offset) return rejected(STEER_PV1_INVALID);
        if(length>b->max_bytes-b->bytes) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    } else if(!finish) return rejected(STEER_PV1_INVALID);
    struct operation *op=calloc(1,sizeof *op);
    if(!op) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->backend=b;op->stream=s;op->kind=kind;op->buffer=buf;op->length=length;op->user=user;
    if(kind==FINISH) op->done.finish=finish;
    else { op->done.io=io;op->data=view.data+offset; }
    struct steer_pv1_async_start a=start(op);
    if(a.disposition!=STEER_PV1_PENDING) { free(op);return a; }
    *slot=op;s->refs++;
    if(kind==FINISH) s->finishing=1;
    progress(s,0);
    return a;
}
static uint64_t STEER_PV1_CALL capabilities(const struct steer_pv1_backend_stream *handle) {
    (void)handle;
    return STEER_PV1_STREAM_CAP_HALF_CLOSE;
}
static struct steer_pv1_async_start STEER_PV1_CALL read_stream(struct steer_pv1_backend_stream *handle,
    struct steer_pv1_buffer *buf,uint32_t off,uint32_t n,steer_pv1_backend_io_done done,void *user) {
    return submit((struct hy2_stream *)handle,READ,buf,off,n,done,NULL,user);
}
static struct steer_pv1_async_start STEER_PV1_CALL write_stream(struct steer_pv1_backend_stream *handle,
    struct steer_pv1_buffer *buf,uint32_t off,uint32_t n,steer_pv1_backend_io_done done,void *user) {
    return submit((struct hy2_stream *)handle,WRITE,buf,off,n,done,NULL,user);
}
static struct steer_pv1_async_start STEER_PV1_CALL finish_write(struct steer_pv1_backend_stream *handle,
    steer_pv1_backend_finish_done done,void *user) {
    return submit((struct hy2_stream *)handle,FINISH,NULL,0,0,NULL,done,user);
}
static void STEER_PV1_CALL close_stream(struct steer_pv1_backend_stream *handle) {
    struct hy2_stream *s=(struct hy2_stream *)handle;
    if(!s->closed) { s->closed=1;broken(s,STEER_PV1_CANCELLED); }
}
static struct steer_pv1_error STEER_PV1_CALL release_stream(struct steer_pv1_backend_stream *handle) {
    struct hy2_stream *s=(struct hy2_stream *)handle;
    if(!s->closed||s->refs) return error(STEER_PV1_POLICY_DENIED);
    dispose_stream(s);
    return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api stream_api={
    sizeof stream_api,STEER_PV1_STREAM_BACKEND_LAYOUT,
    capabilities,read_stream,write_stream,finish_write,close_stream,release_stream
};

static struct steer_pv1_async_start STEER_PV1_CALL open_stream(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *user) {
    struct steer_hy2_stream_backend *b=context;
    struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM);
    if(e.code||!done) return rejected(e.code?e.code:STEER_PV1_INVALID);
    uint64_t now=steer_draft_stream_now_ns();
    if(now>=deadline) return rejected(STEER_PV1_TIMEOUT);
    const struct steer_pv1_endpoint *dst=&flow->destination;
    char target[255];
    if(dst->tag==STEER_PV1_ENDPOINT_DOMAIN) {
        memcpy(target,dst->address.data,dst->address.len);target[dst->address.len]=0;
    } else if(!inet_ntop(dst->tag==STEER_PV1_ENDPOINT_IPV4?AF_INET:AF_INET6,
               dst->address.data,target,sizeof target)) return rejected(STEER_PV1_INVALID);
    e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);
    if(e.code) return rejected(e.code);
    e=steer_draft_binding_pin(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);
    if(e.code) { (void)steer_draft_binding_unpin(b->binding.lease);return rejected(e.code); }
    struct operation *op=calloc(1,sizeof *op);
    struct hy2_stream *s=calloc(1,sizeof *s);
    struct steer_pv1_async_start a=rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    if(!op||!s) goto fail;
    s->timer=loop_timer_new(b->binding.owner,timer_ready,s);
    if(!s->timer) goto fail;
    op->backend=b;op->stream=s;op->kind=OPEN;op->done.open=done;op->user=user;
    a=start(op);
    if(a.disposition!=STEER_PV1_PENDING) goto fail;
    s->backend=b;s->deadline=deadline;s->opening=op;
    s->next=b->head;
    if(b->head) b->head->prev=s;
    b->head=s;
    if(steer_hy2_tcp_open(b->profile,flow->generation,target,dst->port,now/NS_PER_MS,
                         ceil_ms(deadline),&s->tcp)) {
        finish_open(s,STEER_PV1_IO);return a;
    }
    if(loop_fd_add(b->binding.owner,steer_hy2_tcp_fd(s->tcp),EPOLLIN,udp_ready,s)) {
        finish_open(s,STEER_PV1_IO);return a;
    }
    s->watching=1;
    arm(s);
    return a;
fail:
    if(s) loop_timer_free(s->timer);
    free(s);free(op);
    (void)steer_draft_binding_unpin(b->binding.lease);
    (void)steer_draft_binding_unpin(b->binding.lease);
    return a;
}
static const struct steer_pv1_stream_backend_api backend_api={
    sizeof backend_api,STEER_PV1_STREAM_BACKEND_LAYOUT,open_stream
};
static void finalized(void *arg,const struct steer_draft_binding_identity *identity) {
    struct steer_hy2_stream_backend *b=arg;
    (void)identity;
    b->finalized=1;
    if(b->retired) b->retired(b->userdata);
}
struct steer_pv1_error steer_hy2_stream_backend_create(struct loop *loop,
    struct steer_pv1_host *buffers,struct steer_hy2_profile *profile,uint64_t generation,
    uint64_t token,uint32_t max_operations,uint64_t max_bytes,uint32_t max_references,
    unsigned drain_ms,void (*retired)(void *),void *user,struct steer_hy2_stream_backend **out) {
    if(out) *out=NULL;
    if(!loop||!buffers||!profile||!generation||!token||!out||!drain_ms) return error(STEER_PV1_INVALID);
    struct steer_hy2_stream_backend *b=calloc(1,sizeof *b);
    if(!b) return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_error e=steer_draft_operations_create(max_operations,NULL,&b->operations);
    if(e.code) goto fail;
    b->dispatch=loop_timer_new(loop,dispatch,b);
    if(!b->dispatch) { e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail; }
    static const uint8_t provider[]="steer.hysteria2.tcp";
    struct steer_draft_binding_identity identity={sizeof identity,STEER_PV1_DRAFT_LAYOUT,generation,token,
        {provider,sizeof provider-1},STEER_DRAFT_STREAM_BINDING_PREPARED|
        STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN,STEER_PV1_FLOW_STREAM};
    e=steer_draft_binding_lease_create(loop,&identity,max_references,finalized,b,&b->binding.lease);
    if(e.code) goto fail;
    b->binding.api=&backend_api;b->binding.context=b;b->binding.owner=loop;
    b->buffers=buffers;b->profile=profile;b->max_bytes=max_bytes;
    b->drain_ms=drain_ms;b->retired=retired;b->userdata=user;
    *out=b;
    return error(STEER_PV1_OK);
fail:
    loop_timer_free(b->dispatch);
    if(b->operations) (void)steer_draft_operations_destroy(b->operations);
    free(b);
    return e;
}
const struct steer_draft_stream_binding *steer_hy2_stream_binding(const struct steer_hy2_stream_backend *b) {
    return b?&b->binding:NULL;
}
void steer_hy2_stream_backend_retire(struct steer_hy2_stream_backend *b) {
    if(!b||b->retire_deadline) return;
    steer_hy2_profile_retire(b->profile);
    (void)steer_draft_binding_retire(b->binding.lease);
    b->retire_deadline=steer_draft_stream_now_ns()+(uint64_t)b->drain_ms*NS_PER_MS;
    for(struct hy2_stream *s=b->head;s;s=s->next) arm(s);
}
struct steer_pv1_error steer_hy2_stream_backend_destroy(struct steer_hy2_stream_backend *b) {
    if(!b||!b->finalized||b->head) return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);
    if(e.code) return e;
    loop_timer_free(b->dispatch);
    (void)steer_draft_operations_destroy(b->operations);
    (void)steer_hy2_profile_destroy(b->profile);
    free(b);
    return error(STEER_PV1_OK);
}
