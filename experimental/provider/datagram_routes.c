#define _GNU_SOURCE
#include "datagram_routes.h"
#include "buffers.h"
#include "flow_metadata.h"
#include "operations.h"
#include "loop.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
#define DISPATCH_BUDGET 32u
struct target;
struct routed_datagram;
struct route_open;
struct route_io;
struct steer_draft_datagram_router {
    struct loop *loop;struct steer_pv1_host *host;
    struct steer_draft_binding_lease *lease;
    const struct steer_pv1_datagram_backend_api *backend;void *backend_context;
    struct steer_draft_datagram_binding *bindings;uint32_t binding_count;
    steer_draft_datagram_route_select select;
    struct steer_draft_operations *operations;
    struct steer_draft_datagram_route_limits limits;
    steer_draft_datagram_evaluate evaluate;void *policy;
    struct steer_pv1_datagram_association *associations;
    struct target *targets,*work_head,*work_tail,*recovery_cursor;
    struct loop_timer *idle;
    uint64_t generation,bytes;
    uint32_t association_count,target_count,live,queued;
    int wake,dispatching,quiescing,lease_pinned;
    steer_draft_datagram_drained drained;void *drained_user;int drain_notified;
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
    void (*after_pump)(void *);void *after_pump_user;
#endif
};
struct steer_pv1_datagram_association {
    struct steer_draft_datagram_router *router;
    struct steer_pv1_datagram_association *next;
    struct steer_draft_flow_owned identity;
    struct target *targets;
    struct routed_datagram *handles;
    uint32_t target_count,handle_count,live;
    int closing,quiescing,released;
};
struct target {
    struct steer_pv1_datagram_association *association;
    struct target *next,*assoc_next,*work_next;
    struct steer_draft_flow_owned flow;
    struct steer_pv1_datagram_ref origin;
    struct steer_pv1_operation_ref opening;
    struct route_open *opener;
    struct steer_pv1_endpoint bound,peer;
    uint8_t bound_bytes[254],peer_bytes[254];
    struct steer_pv1_error opened_error;
    uint64_t last_use;
    uint32_t users;
    uint32_t binding_index;
    int queued,opened,has_bound,retiring,origin_closed,quarantined,release_refused;
};
struct routed_datagram {
    struct target *target;struct routed_datagram *next;
    struct route_io *send,*receive;
    uint32_t live;int closed;
};
struct route_open {
    struct target *target;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_datagram_ref result;
    struct loop_timer *timer;
    uint64_t deadline;
    steer_pv1_datagram_open_done done;void *userdata;
    uint32_t cancel_code;
    struct steer_draft_binding_lease *selected_lease;
    int terminal,completed;
};
struct route_io {
    struct routed_datagram *handle;
    struct steer_pv1_operation_ref origin;
    struct steer_pv1_buffer *buffer;
    uint32_t length;int writing,completed;
    steer_pv1_datagram_done done;void *userdata;
};
static const struct steer_pv1_datagram_route_api route_api;
static struct steer_pv1_error error(uint32_t c) {struct steer_pv1_error e={c,0};return e;}
static uint64_t now_ns(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static void notify(struct steer_draft_datagram_router *r) {uint64_t one=1;ssize_t n;do{n=write(r->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);}
static void timer_at(struct loop_timer *t,uint64_t deadline) {
    uint64_t now=now_ns(),delta=deadline>now?deadline-now:0;
    uint64_t ms=delta/1000000ull+(delta%1000000ull!=0);if(ms>(uint64_t)LONG_MAX/2)ms=(uint64_t)LONG_MAX/2;
    loop_timer_set(t,(long)ms);
}
static int operation_valid(struct steer_pv1_operation_ref ref) {
    return ref.handle&&ref.api&&ref.api->size>=sizeof(*ref.api)&&ref.api->version==STEER_PV1_DRAFT_LAYOUT&&ref.api->cancel&&ref.api->release;
}
static int datagram_valid(struct steer_pv1_datagram_ref ref) {
    return ref.handle&&ref.api&&ref.api->size>=sizeof(*ref.api)&&ref.api->version==STEER_PV1_DRAFT_LAYOUT&&
        ref.api->message_limit&&ref.api->send&&ref.api->receive&&ref.api->close&&ref.api->release;
}
static void schedule(struct target *target) {
    if(target->queued)return;
    struct steer_draft_datagram_router *r=target->association->router;
    target->queued=1;target->work_next=NULL;
    if(r->work_tail)r->work_tail->work_next=target;else r->work_head=target;
    r->work_tail=target;r->queued++;notify(r);
}
static void idle_arm(struct steer_draft_datagram_router *);
static void association_collect(struct steer_pv1_datagram_association *a) {
    if(!a->released||a->target_count)return;
    struct steer_draft_datagram_router *r=a->router;
    struct steer_pv1_datagram_association **p=&r->associations;
    while(*p&&*p!=a)p=&(*p)->next;
    if(*p)*p=a->next;
    r->association_count--;
    /* Private cleanup owns this pin after public release has consumed a. */
    (void)steer_draft_binding_unpin(r->lease);free(a);
    if(r->quiescing)notify(r);
}
static void target_close(struct target *t) {
    t->retiring=1;
    if(t->opening.handle&&operation_valid(t->opening))t->opening.api->cancel(t->opening.handle);
    if(t->origin.handle&&!t->origin_closed&&datagram_valid(t->origin)){
        t->origin_closed=1;t->origin.api->close(t->origin.handle);
    }
    schedule(t);
}
static int target_free(struct target *t) {
    if(t->users||t->opening.handle||t->queued)return 0;
    struct steer_pv1_datagram_association *a=t->association;
    struct steer_draft_datagram_router *r=a->router;
    if(t->origin.handle){
        if(!datagram_valid(t->origin)){t->quarantined=1;return 0;}
        if(!t->origin_closed){t->origin_closed=1;t->origin.api->close(t->origin.handle);}
        if(t->origin.api->release(t->origin.handle).code){t->quarantined=1;t->release_refused=1;return 0;}
    }
    struct target **p=&r->targets;while(*p&&*p!=t)p=&(*p)->next;if(*p)*p=t->next;
    p=&a->targets;while(*p&&*p!=t)p=&(*p)->assoc_next;if(*p)*p=t->assoc_next;
    if(r->recovery_cursor==t)r->recovery_cursor=t->next;
    r->target_count--;a->target_count--;free(t);association_collect(a);return 1;
}
static void idle_expired(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)loop;(void)timer;struct steer_draft_datagram_router *r=arg;uint64_t now=now_ns();
    for(struct target *t=r->targets;t;t=t->next)
        if(!t->users&&!t->opening.handle&&!t->retiring&&now>=t->last_use&&now-t->last_use>=r->limits.idle_ns)target_close(t);
    idle_arm(r);
}
static void idle_arm(struct steer_draft_datagram_router *r) {
    uint64_t first=UINT64_MAX;int any=0;
    for(struct target *t=r->targets;t;t=t->next)if(!t->users&&!t->opening.handle&&!t->retiring){
        uint64_t due=t->last_use>UINT64_MAX-r->limits.idle_ns?UINT64_MAX:t->last_use+r->limits.idle_ns;
        if(!any||due<first){first=due;any=1;}
    }
    if(any)timer_at(r->idle,first);else loop_timer_stop(r->idle);
}
static uint32_t STEER_PV1_CALL routed_limit(struct steer_pv1_datagram *opaque) {
    struct routed_datagram *h=(void *)opaque;
    if(!h||h->closed||!datagram_valid(h->target->origin))return 0;
    uint32_t limit=h->target->origin.api->message_limit(h->target->origin.handle);
    return limit>65507?65507:limit;
}
static void forwarded(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes) {
    struct route_io *io=arg;struct routed_datagram *h=io->handle;
    struct steer_draft_datagram_router *r=h->target->association->router;
    if(io->writing)h->send=NULL;else h->receive=NULL;
    r->bytes-=io->length;h->target->last_use=now_ns();
    if(e.code>STEER_PV1_INTERNAL||e.transient>1||(!e.code&&e.transient)||
       (e.code&&bytes)||(!e.code&&(io->writing?bytes!=io->length:bytes>io->length))){e=error(STEER_PV1_PROTOCOL);bytes=0;}
    io->done(io->userdata,e,buffer,bytes);io->completed=1;
}
static void STEER_PV1_CALL forwarded_cancel(struct steer_pv1_operation *opaque) {
    struct route_io *io=(void *)opaque;
    if(operation_valid(io->origin))io->origin.api->cancel(io->origin.handle);
}
static void STEER_PV1_CALL forwarded_release(struct steer_pv1_operation *opaque) {
    struct route_io *io=(void *)opaque;
    if(!io->completed)return;
    if(!operation_valid(io->origin)){io->handle->target->quarantined=1;return;}
    io->origin.api->release(io->origin.handle);
    io->handle->live--;io->handle->target->association->live--;
    io->handle->target->association->router->live--;free(io);
}
static const struct steer_pv1_operation_api forwarded_operation_api={
    sizeof(forwarded_operation_api),STEER_PV1_DRAFT_LAYOUT,forwarded_cancel,forwarded_release
};
static struct steer_pv1_async_start forward_io(struct steer_pv1_datagram *opaque,
    struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,uint64_t deadline,
    steer_pv1_datagram_done done,void *userdata,int writing) {
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_INVALID,0},{NULL,NULL}};
    struct routed_datagram *h=(void *)opaque;
    if(!h||!buffer||!done||(!writing&&!length)||deadline<=now_ns())return a;
    uint32_t limit=routed_limit(opaque);
    if(!limit||h->closed||(writing?h->send:h->receive)){a.error=error(STEER_PV1_POLICY_DENIED);return a;}
    /* message_limit bounds datagram payload, not the caller's receive buffer. */
    if(writing&&length>limit)return a;
    struct steer_pv1_datagram_association *association=h->target->association;
    struct steer_draft_datagram_router *r=association->router;
    struct steer_pv1_mut_span view;
    a.error=steer_draft_buffers_api()->writable(r->host,buffer,&view);if(a.error.code)return a;
    a.error=error(STEER_PV1_INVALID);if(offset>view.len||length>view.len-offset)return a;
    a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);
    if(r->live>=r->limits.max_operations||length>r->limits.max_queued_bytes-r->bytes)return a;
    struct route_io *io=calloc(1,sizeof(*io));if(!io)return a;
    io->handle=h;io->buffer=buffer;io->length=length;io->writing=writing;io->done=done;io->userdata=userdata;
    r->live++;association->live++;h->live++;r->bytes+=length;
    if(writing)h->send=io;else h->receive=io;
    struct steer_pv1_datagram_ref origin=h->target->origin;
    a=writing?origin.api->send(origin.handle,buffer,offset,length,deadline,forwarded,io):
              origin.api->receive(origin.handle,buffer,offset,length,deadline,forwarded,io);
    if(a.disposition!=STEER_PV1_PENDING){
        if(writing)h->send=NULL;else h->receive=NULL;
        r->live--;association->live--;h->live--;r->bytes-=length;free(io);
        a.disposition=STEER_PV1_REJECTED;a.operation=(struct steer_pv1_operation_ref){NULL,NULL};
        if(!a.error.code||a.error.code>STEER_PV1_INTERNAL)a.error=error(STEER_PV1_PROTOCOL);
        return a;
    }
    io->origin=a.operation;
    a.operation.handle=(void *)io;a.operation.api=&forwarded_operation_api;
    return a;
}
static struct steer_pv1_async_start STEER_PV1_CALL routed_send(struct steer_pv1_datagram *d,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t deadline,steer_pv1_datagram_done done,void *u) {
    return forward_io(d,b,o,n,deadline,done,u,1);
}
static struct steer_pv1_async_start STEER_PV1_CALL routed_receive(struct steer_pv1_datagram *d,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,uint64_t deadline,steer_pv1_datagram_done done,void *u) {
    return forward_io(d,b,o,n,deadline,done,u,0);
}
static void STEER_PV1_CALL routed_close(struct steer_pv1_datagram *opaque) {
    struct routed_datagram *h=(void *)opaque;if(!h||h->closed)return;
    h->closed=1;
    if(h->send)forwarded_cancel((void *)h->send);
    if(h->receive)forwarded_cancel((void *)h->receive);
}
static struct steer_pv1_error STEER_PV1_CALL routed_release(struct steer_pv1_datagram *opaque) {
    struct routed_datagram *h=(void *)opaque;if(!h)return error(STEER_PV1_INVALID);
    if(!h->closed||h->live)return error(STEER_PV1_POLICY_DENIED);
    struct target *target=h->target;struct steer_pv1_datagram_association *association=target->association;
    struct routed_datagram **p=&association->handles;while(*p&&*p!=h)p=&(*p)->next;if(*p)*p=h->next;
    association->handle_count--;target->users--;target->last_use=now_ns();free(h);
    if(target->retiring)schedule(target);else idle_arm(association->router);
    return error(STEER_PV1_OK);
}
static const struct steer_pv1_datagram_api routed_api={
    sizeof(routed_api),STEER_PV1_DRAFT_LAYOUT,routed_limit,routed_send,routed_receive,routed_close,routed_release
};
static int make_handle(struct route_open *op) {
    struct routed_datagram *h=calloc(1,sizeof(*h));if(!h)return -1;
    struct target *target=op->target;struct steer_pv1_datagram_association *a=target->association;
    h->target=target;h->next=a->handles;a->handles=h;a->handle_count++;target->users++;
    op->result=(struct steer_pv1_datagram_ref){(void *)h,&routed_api};return 0;
}
static void open_finish(struct route_open *op,struct steer_pv1_error e) {
    if(op->terminal)return;
    op->terminal=1;loop_timer_free(op->timer);op->timer=NULL;
    (void)steer_draft_operation_resolve(op->inner.handle,e);notify(op->target->association->router);
}
static void open_deliver(void *arg,struct steer_pv1_error e) {
    struct route_open *op=arg;struct target *t=op->target;
    /* Publication, rather than timer dispatch order, is the success boundary. */
    if(!e.code&&now_ns()>=op->deadline){
        e=error(STEER_PV1_TIMEOUT);
        if(op->result.handle){
            routed_close(op->result.handle);
            (void)routed_release(op->result.handle);
            op->result=(struct steer_pv1_datagram_ref){NULL,NULL};
        }
        target_close(t);
    }
    struct steer_pv1_datagram_ref result=op->result;op->result=(struct steer_pv1_datagram_ref){NULL,NULL};
    op->done(op->userdata,e,result,e.code||!t->has_bound?NULL:&t->bound,e.code?NULL:&t->peer);
    op->completed=1;
}
static void STEER_PV1_CALL open_cancel(struct steer_pv1_operation *opaque) {
    struct route_open *op=(void *)opaque;if(op->terminal)return;
    if(!op->cancel_code)op->cancel_code=STEER_PV1_CANCELLED;
    if(operation_valid(op->target->opening))op->target->opening.api->cancel(op->target->opening.handle);
}
static void STEER_PV1_CALL open_release(struct steer_pv1_operation *opaque) {
    struct route_open *op=(void *)opaque;if(!op->completed)return;
    struct target *t=op->target;struct steer_pv1_datagram_association *a=t->association;
    op->inner.api->release(op->inner.handle);
    if(t->opener==op)t->opener=NULL;
    a->live--;a->router->live--;t->users--;
    /* This open's admission pin remains through callback AND operation release. */
    if(op->selected_lease)(void)steer_draft_binding_unpin(op->selected_lease);
    (void)steer_draft_binding_unpin(a->router->lease);free(op);
    if(t->retiring)schedule(t);else idle_arm(a->router);
    if(a->router->quiescing)notify(a->router);
}
static const struct steer_pv1_operation_api open_operation_api={
    sizeof(open_operation_api),STEER_PV1_DRAFT_LAYOUT,open_cancel,open_release
};
static void open_timeout(struct loop *loop,struct loop_timer *timer,void *arg) {
    (void)loop;(void)timer;struct route_open *op=arg;
    if(now_ns()<op->deadline){timer_at(op->timer,op->deadline);return;}
    if(!op->cancel_code)op->cancel_code=STEER_PV1_TIMEOUT;
    if(operation_valid(op->target->opening))op->target->opening.api->cancel(op->target->opening.handle);
}
static int endpoint_copy(struct target *t,const struct steer_pv1_endpoint *input,
    struct steer_pv1_endpoint *out,uint8_t storage[254]) {
    if(!input)return -1;
    struct steer_pv1_flow_metadata flow=t->flow.value;flow.destination=*input;
    if(steer_draft_flow_validate(&flow,STEER_PV1_FLOW_DATAGRAM).code)return -1;
    *out=*input;out->size=sizeof(*out);memcpy(storage,input->address.data,input->address.len);out->address.data=storage;
    return 0;
}
static void backend_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref result,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer) {
    struct target *t=arg;t->origin=result;t->opened=1;t->has_bound=bound!=NULL;
    if(e.code>STEER_PV1_INTERNAL||e.transient>1||(!e.code&&e.transient))e=error(STEER_PV1_PROTOCOL);
    if(!e.code&&(!datagram_valid(result)||endpoint_copy(t,peer,&t->peer,t->peer_bytes)||
       (bound&&endpoint_copy(t,bound,&t->bound,t->bound_bytes))))e=error(STEER_PV1_PROTOCOL);
    if(e.code&&result.handle)t->retiring=1;
    t->opened_error=e;schedule(t);
}
static void process(struct target *t) {
    if(t->opened){
        t->opened=0;
        if(operation_valid(t->opening)){
            t->opening.api->release(t->opening.handle);t->opening=(struct steer_pv1_operation_ref){NULL,NULL};
        }else t->quarantined=1;
        struct route_open *op=t->opener;
        if(op&&!op->terminal){
            struct steer_pv1_error e=t->opened_error;
            if(op->cancel_code)e=error(op->cancel_code);
            else if(now_ns()>=op->deadline)e=error(STEER_PV1_TIMEOUT);
            else if(t->association->closing)e=error(STEER_PV1_CANCELLED);
            else if(!e.code&&(!datagram_valid(t->origin)||!t->origin.api->message_limit(t->origin.handle)))e=error(STEER_PV1_IO);
            if(!e.code&&make_handle(op))e=error(STEER_PV1_RESOURCE_EXHAUSTED);
            if(e.code){
                t->retiring=1;
                if(t->origin.handle&&datagram_valid(t->origin)&&!t->origin_closed){t->origin_closed=1;t->origin.api->close(t->origin.handle);}
            }
            open_finish(op,e);
        }else t->retiring=1;
    }
    if(t->retiring&&!t->users&&!t->opening.handle&&!t->quarantined)(void)target_free(t);
}
static void pump(struct loop *loop,int fd,uint32_t events,void *arg) {
    (void)loop;(void)events;struct steer_draft_datagram_router *r=arg;uint64_t tokens;ssize_t n;
    do{n=read(fd,&tokens,sizeof(tokens));}while(n<0&&errno==EINTR);
    r->dispatching=1;
    uint32_t count=r->queued;if(count>DISPATCH_BUDGET)count=DISPATCH_BUDGET;
    for(uint32_t i=0;i<count;i++){
        struct target *t=r->work_head;if(!t)break;
        r->work_head=t->work_next;if(!r->work_head)r->work_tail=NULL;
        r->queued--;t->queued=0;t->work_next=NULL;process(t);
    }
    (void)steer_draft_operations_dispatch(r->operations,DISPATCH_BUDGET,NULL);
    if(r->quiescing&&r->drained&&!r->drain_notified&&!r->association_count&&!r->target_count&&!r->live&&!r->queued){
        r->drain_notified=1;r->drained(r->drained_user,r);
    }
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
    if(r->after_pump)r->after_pump(r->after_pump_user);
#endif
    r->dispatching=0;idle_arm(r);
    uint32_t queued;steer_draft_operations_usage(r->operations,NULL,&queued);
    if(r->queued||queued)notify(r);
}
static int same_endpoint(const struct steer_pv1_endpoint *a,const struct steer_pv1_endpoint *b) {
    return a->tag==b->tag&&a->port==b->port&&a->address.len==b->address.len&&
        !memcmp(a->address.data,b->address.data,a->address.len);
}
static int evict_one(struct steer_draft_datagram_router *r,struct steer_pv1_datagram_association *only) {
    struct target *old=NULL;
    for(struct target *t=r->targets;t;t=t->next)
        if((!only||t->association==only)&&!t->users&&!t->opening.handle&&!t->queued&&!t->quarantined&&
           (!old||t->last_use<old->last_use))old=t;
    if(!old)return 0;
    old->retiring=1;return target_free(old);
}
static struct steer_pv1_async_start STEER_PV1_CALL open_target(struct steer_pv1_datagram_association *association,
    const struct steer_pv1_endpoint *destination,uint64_t deadline,steer_pv1_datagram_open_done done,void *userdata) {
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_INVALID,0},{NULL,NULL}};
    if(!association||!destination||!done||deadline<=now_ns())return a;
    struct steer_draft_datagram_router *r=association->router;
    if(association->closing||association->quiescing||r->quiescing){a.error=error(STEER_PV1_POLICY_DENIED);return a;}
    struct steer_pv1_flow_metadata flow=association->identity.value;flow.destination=*destination;
    a.error=steer_draft_flow_validate(&flow,STEER_PV1_FLOW_DATAGRAM);if(a.error.code)return a;
    uint32_t index=STEER_DRAFT_DATAGRAM_ROUTE_BLOCK_INDEX;
    if(r->select)a.error=r->select(r->policy,&flow,&index);
    else{
        uint32_t action=STEER_DRAFT_DATAGRAM_ROUTE_BLOCK;
        a.error=r->evaluate(r->policy,&flow,&action);
        if(!a.error.code&&action==STEER_DRAFT_DATAGRAM_ROUTE_DIRECT)index=0;
        else if(!a.error.code&&action!=STEER_DRAFT_DATAGRAM_ROUTE_BLOCK)a.error=error(STEER_PV1_UNSUPPORTED);
    }
    if(a.error.code>STEER_PV1_INTERNAL||a.error.transient>1||(!a.error.code&&a.error.transient))a.error=error(STEER_PV1_INVALID);
    if(a.error.code)return a;
    if(index==STEER_DRAFT_DATAGRAM_ROUTE_BLOCK_INDEX){a.error=error(STEER_PV1_POLICY_DENIED);return a;}
    if(r->select&&index>=r->binding_count){a.error=error(STEER_PV1_INVALID);return a;}
    struct steer_draft_binding_lease *selected=r->select?r->bindings[index].lease:NULL;
    if(selected&&destination->tag==STEER_PV1_ENDPOINT_DOMAIN&&
       !(steer_draft_binding_identity(selected)->prepared_capabilities&STEER_DRAFT_DATAGRAM_BINDING_TARGET_DOMAIN)){
        a.error=error(STEER_PV1_UNSUPPORTED);return a;
    }
    a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);
    if(r->live>=r->limits.max_operations)return a;
    /* Linearize admission BEFORE touching cache/budget victims. Retirement
     * cannot cause a rejected new target to mutate an old generation's cache. */
    a.error=steer_draft_binding_admit(r->lease,r->generation,STEER_PV1_FLOW_DATAGRAM);
    if(a.error.code)return a;
    if(selected){
        a.error=steer_draft_binding_admit(selected,r->generation,STEER_PV1_FLOW_DATAGRAM);
        if(a.error.code){(void)steer_draft_binding_unpin(r->lease);return a;}
    }
    a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct target *target=association->targets;
    while(target&&(target->binding_index!=index||!same_endpoint(&target->flow.value.destination,destination)))target=target->assoc_next;
    if(target&&(target->users||target->opening.handle||target->queued||target->quarantined))goto reject_pin;
    if(target&&(!datagram_valid(target->origin)||!target->origin.api->message_limit(target->origin.handle))){
        target->retiring=1;if(!target_free(target))goto reject_pin;target=NULL;
    }
    int fresh=target==NULL;
    if(fresh){
        if(association->target_count>=r->limits.max_targets_per_association&&!evict_one(r,association))goto reject_pin;
        if(r->target_count>=r->limits.max_targets&&!evict_one(r,NULL))goto reject_pin;
        target=calloc(1,sizeof(*target));if(!target)goto reject_pin;
        target->association=association;target->binding_index=index;target->last_use=now_ns();
        a.error=steer_draft_flow_copy(&target->flow,&flow,STEER_PV1_FLOW_DATAGRAM);
        if(a.error.code){free(target);goto reject_pin;}
    }
    struct route_open *op=calloc(1,sizeof(*op));
    if(!op){if(fresh)free(target);a.error=error(STEER_PV1_RESOURCE_EXHAUSTED);goto reject_pin;}
    op->target=target;op->deadline=deadline;op->done=done;op->userdata=userdata;
    op->selected_lease=selected;
    a=steer_draft_operation_start(r->operations,open_deliver,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);if(fresh)free(target);goto reject_pin;}
    op->inner=a.operation;a.operation.handle=(void *)op;a.operation.api=&open_operation_api;
    r->live++;association->live++;target->users++;target->opener=op;
    if(fresh){
        target->next=r->targets;r->targets=target;target->assoc_next=association->targets;association->targets=target;
        r->target_count++;association->target_count++;
        const struct steer_pv1_datagram_backend_api *api=r->select?r->bindings[index].api:r->backend;
        void *context=r->select?r->bindings[index].context:r->backend_context;
        struct steer_pv1_async_start backend=api->open(context,&target->flow.value,deadline,backend_opened,target);
        if(backend.disposition!=STEER_PV1_PENDING){
            struct steer_pv1_error e=backend.error;
            if(!e.code||e.code>STEER_PV1_INTERNAL||e.transient>1)e=error(STEER_PV1_PROTOCOL);
            target->retiring=1;open_finish(op,e);schedule(target);
        }else{
            target->opening=backend.operation;
            if(!operation_valid(backend.operation)){target->quarantined=1;target->retiring=1;open_finish(op,error(STEER_PV1_PROTOCOL));}
            else if(backend.error.code||backend.error.transient){op->cancel_code=STEER_PV1_PROTOCOL;backend.operation.api->cancel(backend.operation.handle);}
        }
    }else{
        target->last_use=now_ns();
        if(make_handle(op))open_finish(op,error(STEER_PV1_RESOURCE_EXHAUSTED));else open_finish(op,error(STEER_PV1_OK));
    }
    if(!op->terminal){
        op->timer=loop_timer_new(r->loop,open_timeout,op);
        if(!op->timer){op->cancel_code=STEER_PV1_RESOURCE_EXHAUSTED;if(operation_valid(target->opening))target->opening.api->cancel(target->opening.handle);}
        else timer_at(op->timer,deadline);
    }
    idle_arm(r);return a;
reject_pin:
    if(selected)(void)steer_draft_binding_unpin(selected);
    (void)steer_draft_binding_unpin(r->lease);return a;
}
static struct steer_pv1_error STEER_PV1_CALL create_association(void *context,
    const struct steer_pv1_flow_metadata *flow,struct steer_pv1_datagram_association_ref *out) {
    if(out)*out=(struct steer_pv1_datagram_association_ref){NULL,NULL};
    struct steer_draft_datagram_router *r=context;
    if(!r||!out)return error(STEER_PV1_INVALID);
    struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_DATAGRAM);if(e.code)return e;
    if(flow->generation!=r->generation||r->quiescing)return error(STEER_PV1_POLICY_DENIED);
    if(r->association_count>=r->limits.max_associations)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    e=steer_draft_binding_admit(r->lease,r->generation,STEER_PV1_FLOW_DATAGRAM);if(e.code)return e;
    struct steer_pv1_datagram_association *a=calloc(1,sizeof(*a));
    if(!a){(void)steer_draft_binding_unpin(r->lease);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
    e=steer_draft_flow_copy(&a->identity,flow,STEER_PV1_FLOW_DATAGRAM);
    if(e.code){(void)steer_draft_binding_unpin(r->lease);free(a);return e;}
    a->router=r;a->next=r->associations;r->associations=a;r->association_count++;
    out->handle=a;out->api=&route_api;return error(STEER_PV1_OK);
}
static void STEER_PV1_CALL quiesce_association(struct steer_pv1_datagram_association *a) {if(a)a->quiescing=1;}
static void STEER_PV1_CALL close_association(struct steer_pv1_datagram_association *a) {
    if(!a)return;
    a->quiescing=a->closing=1;
    for(struct routed_datagram *h=a->handles;h;h=h->next)routed_close((void *)h);
    for(struct target *t=a->targets;t;t=t->assoc_next){
        if(t->opener&&!t->opener->terminal)open_cancel((void *)t->opener);
        target_close(t);
    }
}
static struct steer_pv1_error STEER_PV1_CALL release_association(struct steer_pv1_datagram_association *a) {
    if(!a)return error(STEER_PV1_INVALID);
    if(!a->closing||a->live||a->handle_count)return error(STEER_PV1_POLICY_DENIED);
    a->released=1;association_collect(a);return error(STEER_PV1_OK);
}
static const struct steer_pv1_datagram_route_api route_api={
    sizeof(route_api),STEER_PV1_DRAFT_LAYOUT,create_association,open_target,
    quiesce_association,close_association,release_association
};
const struct steer_pv1_datagram_route_api *steer_draft_datagram_router_api(void) {return &route_api;}
static struct steer_pv1_error router_create_base(struct loop *loop,struct steer_pv1_host *host,
    struct steer_draft_binding_lease *lease,const struct steer_draft_datagram_route_limits *limits,
    struct steer_draft_datagram_router **out) {
    if(out)*out=NULL;
    if(!loop||!host||!lease||!limits||!out||!limits->max_associations||limits->max_associations>1024||
       !limits->max_targets||limits->max_targets>1024||!limits->max_targets_per_association||
       limits->max_targets_per_association>64||limits->max_targets_per_association>limits->max_targets||
       !limits->max_operations||limits->max_operations>4096||!limits->idle_ns)return error(STEER_PV1_INVALID);
    const struct steer_draft_binding_identity *identity=steer_draft_binding_identity(lease);
    if(identity->flow_class!=STEER_PV1_FLOW_DATAGRAM)return error(STEER_PV1_UNSUPPORTED);
    struct steer_pv1_error e=steer_draft_binding_admit(lease,identity->generation,STEER_PV1_FLOW_DATAGRAM);if(e.code)return e;
    struct steer_draft_datagram_router *r=calloc(1,sizeof(*r));
    if(!r){(void)steer_draft_binding_unpin(lease);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
    r->loop=loop;r->host=host;r->lease=lease;r->lease_pinned=1;r->generation=identity->generation;
    r->limits=*limits;
    e=steer_draft_operations_create(limits->max_operations,NULL,&r->operations);
    if(e.code){(void)steer_draft_binding_unpin(lease);free(r);return e;}
    r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(r->wake<0||loop_fd_add(loop,r->wake,EPOLLIN,pump,r)){
        if(r->wake>=0)close(r->wake);
        (void)steer_draft_operations_destroy(r->operations);(void)steer_draft_binding_unpin(lease);free(r);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    r->idle=loop_timer_new(loop,idle_expired,r);
    if(!r->idle){
        loop_fd_del(loop,r->wake);close(r->wake);(void)steer_draft_operations_destroy(r->operations);
        (void)steer_draft_binding_unpin(lease);free(r);return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=r;return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_datagram_router_create(struct loop *loop,struct steer_pv1_host *host,
    struct steer_draft_binding_lease *lease,const struct steer_pv1_datagram_backend_api *backend,void *backend_context,
    const struct steer_draft_datagram_route_limits *limits,steer_draft_datagram_evaluate evaluate,void *policy,
    struct steer_draft_datagram_router **out) {
    if(out)*out=NULL;
    if(!backend||backend->size<sizeof(*backend)||backend->version!=STEER_PV1_DRAFT_LAYOUT||!backend->open||!evaluate)
        return error(STEER_PV1_INVALID);
    struct steer_pv1_error e=router_create_base(loop,host,lease,limits,out);
    if(!e.code){(*out)->backend=backend;(*out)->backend_context=backend_context;(*out)->evaluate=evaluate;(*out)->policy=policy;}
    return e;
}
struct steer_pv1_error steer_draft_datagram_router_create_registry(struct loop *loop,struct steer_pv1_host *host,
    struct steer_draft_binding_lease *lease,const struct steer_draft_datagram_binding *bindings,uint32_t count,
    const struct steer_draft_datagram_route_limits *limits,steer_draft_datagram_route_select select,void *policy,
    struct steer_draft_datagram_router **out) {
    if(out)*out=NULL;
    if(!out||!select||count>STEER_DRAFT_DATAGRAM_BINDINGS_MAX||(count&&!bindings))return error(STEER_PV1_INVALID);
    struct steer_draft_datagram_router *r=NULL;
    struct steer_pv1_error e=router_create_base(loop,host,lease,limits,&r);if(e.code)return e;
    r->select=select;r->policy=policy;
    if(count){r->bindings=calloc(count,sizeof(*r->bindings));if(!r->bindings){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}}
    for(uint32_t i=0;i<count;i++){
        const struct steer_draft_datagram_binding *b=&bindings[i];
        if(!b->lease||b->owner!=loop||!b->api){e=error(STEER_PV1_INVALID);goto fail;}
        const struct steer_draft_binding_identity *id=steer_draft_binding_identity(b->lease);
        if(id->generation!=r->generation||id->flow_class!=STEER_PV1_FLOW_DATAGRAM){e=error(STEER_PV1_POLICY_DENIED);goto fail;}
        if(!(id->prepared_capabilities&STEER_DRAFT_DATAGRAM_BINDING_PREPARED)||b->api->size<sizeof(*b->api)||
           b->api->version!=STEER_PV1_DRAFT_LAYOUT||!b->api->open){e=error(STEER_PV1_UNSUPPORTED);goto fail;}
        for(uint32_t j=0;j<i;j++){
            const struct steer_draft_binding_identity *old=steer_draft_binding_identity(r->bindings[j].lease);
            if(old->instance_token==id->instance_token&&old->provider_id.len==id->provider_id.len&&
               !memcmp(old->provider_id.data,id->provider_id.data,id->provider_id.len)){e=error(STEER_PV1_INVALID);goto fail;}
        }
        e=steer_draft_binding_admit(b->lease,r->generation,STEER_PV1_FLOW_DATAGRAM);if(e.code)goto fail;
        r->bindings[r->binding_count++]=*b;
    }
    *out=r;return error(STEER_PV1_OK);
fail:
    (void)steer_draft_datagram_router_destroy(r);return e;
}
void steer_draft_datagram_router_quiesce(struct steer_draft_datagram_router *r) {
    if(!r)return;
    r->quiescing=1;for(struct steer_pv1_datagram_association *a=r->associations;a;a=a->next)quiesce_association(a);
    notify(r);
}
void steer_draft_datagram_router_close(struct steer_draft_datagram_router *r) {
    if(!r)return;
    r->quiescing=1;for(struct steer_pv1_datagram_association *a=r->associations;a;a=a->next)close_association(a);
    notify(r);
}
struct steer_pv1_error steer_draft_datagram_router_on_drained(struct steer_draft_datagram_router *r,
    steer_draft_datagram_drained callback,void *user){
    if(!r||!callback)return error(STEER_PV1_INVALID);
    if(r->drained||r->quiescing||r->association_count||r->target_count||r->live)return error(STEER_PV1_POLICY_DENIED);
    r->drained=callback;r->drained_user=user;return error(STEER_PV1_OK);
}
uint32_t steer_draft_datagram_router_retry_cleanup(struct steer_draft_datagram_router *r) {
    if(!r)return 0;
    uint32_t examined=0,queued=0,limit=r->target_count;
    if(limit>DISPATCH_BUDGET)limit=DISPATCH_BUDGET;
    struct target *t=r->recovery_cursor?r->recovery_cursor:r->targets;
    while(t&&examined++<limit){
        struct target *next=t->next?t->next:r->targets;
        if(t->release_refused&&t->quarantined&&!t->users&&!t->opening.handle&&!t->queued&&datagram_valid(t->origin)){
            t->release_refused=t->quarantined=0;schedule(t);queued++;
        }
        t=next;
    }
    r->recovery_cursor=t;return queued;
}
struct steer_pv1_error steer_draft_datagram_router_destroy(struct steer_draft_datagram_router *r) {
    if(!r)return error(STEER_PV1_INVALID);
    if(r->association_count||r->target_count||r->live||r->dispatching||r->queued||
       (r->quiescing&&r->drained&&!r->drain_notified))return error(STEER_PV1_POLICY_DENIED);
    while(r->binding_count){
        struct steer_draft_binding_lease *lease=r->bindings[--r->binding_count].lease;
        struct steer_pv1_error e=steer_draft_binding_unpin(lease);if(e.code)return e;
    }
    if(r->lease_pinned){
        r->lease_pinned=0;struct steer_pv1_error e=steer_draft_binding_unpin(r->lease);if(e.code)return e;
    }
    loop_timer_free(r->idle);loop_fd_del(r->loop,r->wake);close(r->wake);
    (void)steer_draft_operations_destroy(r->operations);free(r->bindings);free(r);return error(STEER_PV1_OK);
}
void steer_draft_datagram_router_usage(const struct steer_draft_datagram_router *r,
    uint32_t *associations,uint32_t *targets,uint32_t *operations,uint64_t *bytes) {
    if(associations)*associations=r?r->association_count:0;
    if(targets)*targets=r?r->target_count:0;
    if(operations)*operations=r?r->live:0;
    if(bytes)*bytes=r?r->bytes:0;
}
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
void steer_draft_datagram_router_test_after_pump(struct steer_draft_datagram_router *r,void (*callback)(void *),void *user){
    r->after_pump=callback;r->after_pump_user=user;
}
#endif
