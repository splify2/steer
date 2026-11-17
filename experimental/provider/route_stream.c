#define _POSIX_C_SOURCE 200809L
#include "route_stream.h"
#include "operations.h"
#include "loop.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
#define ROUTE_BATCH 32u
struct stream_open;
struct steer_draft_stream_routes {
 struct loop *loop;uint64_t generation;uint32_t live,streams,max_streams,count,max_operations,quarantined;
 struct stream_open *quarantine;
 struct steer_draft_stream_binding *bindings;
 struct steer_draft_operations *operations;
 steer_draft_stream_route_select select;void *context;struct steer_draft_backend_pin pin;
 int wake,dispatching,quiescing,drain_notified;
 steer_draft_stream_routes_drained drained;void *drained_user;
};
struct guarded_stream {
 struct steer_draft_stream_routes *routes;struct steer_draft_binding_lease *lease;
 struct steer_pv1_stream_ref inner;int closed,write_closing;
};
struct stream_open {
 struct steer_draft_stream_routes *routes;struct steer_draft_binding_lease *lease;
 struct steer_pv1_operation_ref completion,backend;
 struct steer_draft_flow_owned flow;
 steer_pv1_stream_open_done done;void *userdata;
 struct steer_pv1_stream_ref stream;
 struct steer_pv1_endpoint bound,peer;uint8_t bound_bytes[254],peer_bytes[254];
 struct steer_pv1_stream_open_diagnostic diagnostic;
 uint64_t deadline;int has_bound,has_peer,has_diagnostic,terminal,completed;
 struct steer_pv1_stream_ref rejected_stream;
 struct stream_open *quarantine_next;int public_released;
};
static struct steer_pv1_error error(uint32_t c){struct steer_pv1_error e={c,0};return e;}
static struct steer_pv1_async_start rejected(uint32_t c){struct steer_pv1_async_start a={STEER_PV1_REJECTED,{c,0},{NULL,NULL}};return a;}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static void notify(struct steer_draft_stream_routes *r){uint64_t one=1;ssize_t n;do{n=write(r->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);}
static struct guarded_stream *guard(struct steer_pv1_backend_stream *s){return (struct guarded_stream *)s;}
static const struct guarded_stream *cguard(const struct steer_pv1_backend_stream *s){return (const struct guarded_stream *)s;}
static uint64_t STEER_PV1_CALL guard_capabilities(const struct steer_pv1_backend_stream *s){
 const struct guarded_stream *g=cguard(s);uint64_t caps=g->inner.api->capabilities(g->inner.handle);
 if(!g->inner.api->finish_write)caps&=~STEER_PV1_STREAM_CAP_HALF_CLOSE;
 return caps;
}
static struct steer_pv1_async_start STEER_PV1_CALL guard_read(struct steer_pv1_backend_stream *s,
 struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done done,void *userdata){
 struct guarded_stream *g=guard(s);if(g->closed)return rejected(STEER_PV1_POLICY_DENIED);
 return g->inner.api->read(g->inner.handle,b,o,n,done,userdata);
}
static struct steer_pv1_async_start STEER_PV1_CALL guard_write(struct steer_pv1_backend_stream *s,
 struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done done,void *userdata){
 struct guarded_stream *g=guard(s);if(g->closed||g->write_closing)return rejected(STEER_PV1_POLICY_DENIED);
 return g->inner.api->write(g->inner.handle,b,o,n,done,userdata);
}
static struct steer_pv1_async_start STEER_PV1_CALL guard_finish(struct steer_pv1_backend_stream *s,
 steer_pv1_backend_finish_done done,void *userdata){
 struct guarded_stream *g=guard(s);if(g->closed||g->write_closing)return rejected(STEER_PV1_POLICY_DENIED);
 if(!(guard_capabilities(s)&STEER_PV1_STREAM_CAP_HALF_CLOSE))return rejected(STEER_PV1_UNSUPPORTED);
 struct steer_pv1_async_start a=g->inner.api->finish_write(g->inner.handle,done,userdata);
 if(a.disposition==STEER_PV1_PENDING)g->write_closing=1;
 return a;
}
static void STEER_PV1_CALL guard_close(struct steer_pv1_backend_stream *s){
 struct guarded_stream *g=guard(s);if(g->closed)return;g->closed=1;g->inner.api->close(g->inner.handle);
}
static struct steer_pv1_error STEER_PV1_CALL guard_release(struct steer_pv1_backend_stream *s){
 struct guarded_stream *g=guard(s);if(!g->closed)return error(STEER_PV1_POLICY_DENIED);
 /* The host guard still owns the binding pin throughout the foreign release;
  * only host-static code remains on the stack when its final pin is dropped. */
 struct steer_pv1_error e=g->inner.api->release(g->inner.handle);if(e.code)return e;
 struct steer_draft_binding_lease *lease=g->lease;struct steer_draft_stream_routes *r=g->routes;r->streams--;free(g);
 (void)steer_draft_binding_unpin(lease);if(r->quiescing)notify(r);return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api guard_api={
 sizeof(struct steer_pv1_backend_stream_api),STEER_PV1_STREAM_BACKEND_LAYOUT,
 guard_capabilities,guard_read,guard_write,guard_finish,guard_close,guard_release
};
static int stream_valid(struct steer_pv1_stream_ref s){
 return s.handle&&s.api&&s.api->size>=sizeof(*s.api)&&s.api->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&
  s.api->capabilities&&s.api->read&&s.api->write&&s.api->close&&s.api->release;
}
static struct steer_pv1_error discard_stream(struct steer_pv1_stream_ref s){
 if(!s.handle&&!s.api)return error(STEER_PV1_OK);
 if(!stream_valid(s))return error(STEER_PV1_UNSUPPORTED);
 s.api->close(s.handle);return s.api->release(s.handle);
}
static struct steer_pv1_error wrap_guard(struct stream_open *op,struct steer_pv1_stream_ref inner){
 struct steer_draft_stream_routes *r=op->routes;
 if(!stream_valid(inner))return error(STEER_PV1_UNSUPPORTED);
 if(r->streams>=r->max_streams)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 struct steer_pv1_error e=steer_draft_binding_pin(op->lease,r->generation,STEER_PV1_FLOW_STREAM);if(e.code)return e;
 struct guarded_stream *g=calloc(1,sizeof(*g));
 if(!g){(void)steer_draft_binding_unpin(op->lease);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 g->routes=r;g->lease=op->lease;g->inner=inner;r->streams++;
 op->stream.handle=(struct steer_pv1_backend_stream *)g;op->stream.api=&guard_api;return error(STEER_PV1_OK);
}
static int copy_endpoint(struct steer_pv1_endpoint *out,uint8_t *bytes,const struct steer_pv1_endpoint *in){
 if(!in)return 0;
 if(in->size<sizeof(*in)||in->version!=STEER_PV1_DRAFT_LAYOUT||in->reserved||!in->port||!in->address.data)return -1;
 uint32_t n=in->address.len;
 if(!((in->tag==STEER_PV1_ENDPOINT_IPV4&&n==4)||(in->tag==STEER_PV1_ENDPOINT_IPV6&&n==16)||
      (in->tag==STEER_PV1_ENDPOINT_DOMAIN&&n&&n<=254)))return -1;
 *out=*in;out->size=sizeof(*out);memcpy(bytes,in->address.data,n);out->address.data=bytes;return 1;
}
static void backend_done(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,
 const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,
 const struct steer_pv1_stream_open_diagnostic *diagnostic){
 struct stream_open *op=arg;
 if(op->terminal)return; /* Backend contract requires exactly one result. */
 if(e.code>STEER_PV1_INTERNAL||e.transient>1||(!e.code&&e.transient))e=error(STEER_PV1_PROTOCOL);
 if(!e.code && now_ns()>=op->deadline)e=error(STEER_PV1_TIMEOUT);
 if(!e.code){
  op->has_bound=copy_endpoint(&op->bound,op->bound_bytes,bound);
  op->has_peer=copy_endpoint(&op->peer,op->peer_bytes,peer);
  if(op->has_bound<0||op->has_peer<0)e=error(STEER_PV1_PROTOCOL);
 }
 if(diagnostic&&diagnostic->size>=sizeof(*diagnostic)&&diagnostic->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&
    diagnostic->dial_failure<=STEER_PV1_STREAM_DIAL_OTHER){op->diagnostic=*diagnostic;op->diagnostic.size=sizeof(op->diagnostic);op->has_diagnostic=1;}
 if(!e.code){e=wrap_guard(op,stream);if(!e.code){stream.handle=NULL;stream.api=NULL;}}
 struct steer_pv1_error discarded=discard_stream(stream);
 if(discarded.code&&stream.handle){
  op->rejected_stream=stream;op->quarantine_next=op->routes->quarantine;
  op->routes->quarantine=op;op->routes->quarantined++;e=error(STEER_PV1_PROTOCOL);
 }
 if(e.code){op->has_bound=op->has_peer=0;}
 op->terminal=1;(void)steer_draft_operation_resolve(op->completion.handle,e);notify(op->routes);
}
static void delivered(void *arg,struct steer_pv1_error e){
 struct stream_open *op=arg;struct steer_pv1_stream_ref stream=op->stream;
 op->stream.handle=NULL;op->stream.api=NULL;
 op->done(op->userdata,e,stream,op->has_bound?&op->bound:NULL,op->has_peer?&op->peer:NULL,
    op->has_diagnostic?&op->diagnostic:NULL);op->completed=1;
}
static void STEER_PV1_CALL cancel_open(struct steer_pv1_operation *opaque){
 struct stream_open *op=(struct stream_open *)opaque;
 if(!op->terminal && op->backend.handle)op->backend.api->cancel(op->backend.handle);
}
static void STEER_PV1_CALL release_open(struct steer_pv1_operation *opaque){
 struct stream_open *op=(struct stream_open *)opaque;if(!op->completed||op->public_released)return;
 if(op->backend.handle){op->backend.api->release(op->backend.handle);op->backend.handle=NULL;op->backend.api=NULL;}
 op->completion.api->release(op->completion.handle);op->completion.handle=NULL;op->completion.api=NULL;op->public_released=1;
 if(op->rejected_stream.handle)return; /* bounded quarantine owns the remaining ref/pin */
 struct steer_draft_binding_lease *lease=op->lease;struct steer_draft_stream_routes *r=op->routes;r->live--;free(op);
 (void)steer_draft_binding_unpin(lease);if(r->quiescing)notify(r);
}
static const struct steer_pv1_operation_api operation_api={
 sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_open,release_open
};
static void pump(struct loop *loop,int fd,uint32_t events,void *arg){
 struct steer_draft_stream_routes *r=arg;uint64_t counter;ssize_t n;uint32_t queued;(void)loop;(void)events;
 do{n=read(fd,&counter,sizeof(counter));}while(n<0&&errno==EINTR);
 r->dispatching=1;(void)steer_draft_operations_dispatch(r->operations,ROUTE_BATCH,NULL);
 if(r->quiescing&&r->drained&&!r->drain_notified&&!r->live&&!r->streams&&!r->quarantine){
  r->drain_notified=1;r->drained(r->drained_user,r);
 }
 r->dispatching=0;
 steer_draft_operations_usage(r->operations,NULL,&queued);if(queued)notify(r);
}
static int same_identity(const struct steer_draft_binding_identity *a,const struct steer_draft_binding_identity *b){
 return a->instance_token==b->instance_token&&a->provider_id.len==b->provider_id.len&&
  !memcmp(a->provider_id.data,b->provider_id.data,a->provider_id.len);
}
struct steer_pv1_error steer_draft_stream_routes_create(struct loop *loop,uint64_t generation,
 uint32_t max_operations,uint32_t max_streams,const struct steer_draft_stream_binding *bindings,uint32_t count,
 steer_draft_stream_route_select select,void *context,const struct steer_draft_backend_pin *pin,
 struct steer_draft_stream_routes **out){
 if(out)*out=NULL;
 if(!loop||!generation||!max_operations||!max_streams||!select||!out||count>STEER_DRAFT_STREAM_BINDINGS_MAX||
    (count&&!bindings)||(pin&&!pin->release))return error(STEER_PV1_INVALID);
 struct steer_draft_stream_routes *r=calloc(1,sizeof(*r));if(!r)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 r->wake=-1;r->loop=loop;r->generation=generation;r->max_streams=max_streams;r->max_operations=max_operations;r->select=select;r->context=context;
 struct steer_pv1_error e=steer_draft_operations_create(max_operations,NULL,&r->operations);if(e.code){free(r);return e;}
 if(count){r->bindings=calloc(count,sizeof(*r->bindings));if(!r->bindings){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}}
 for(uint32_t i=0;i<count;i++){
  const struct steer_draft_stream_binding *b=&bindings[i];
  if(!b->lease||!b->api||b->owner!=loop){e=error(STEER_PV1_INVALID);goto fail;}
  const struct steer_draft_binding_identity *id=steer_draft_binding_identity(b->lease);
  if(id->generation!=generation||id->flow_class!=STEER_PV1_FLOW_STREAM){e=error(STEER_PV1_POLICY_DENIED);goto fail;}
  if(!(id->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_PREPARED)||b->api->size<sizeof(*b->api)||
     b->api->version!=STEER_PV1_STREAM_BACKEND_LAYOUT||!b->api->open){e=error(STEER_PV1_UNSUPPORTED);goto fail;}
  for(uint32_t j=0;j<i;j++)if(same_identity(id,steer_draft_binding_identity(r->bindings[j].lease))){e=error(STEER_PV1_INVALID);goto fail;}
  e=steer_draft_binding_admit(b->lease,generation,STEER_PV1_FLOW_STREAM);if(e.code)goto fail;
  r->bindings[r->count++]=*b;
 }
 r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
 if(r->wake<0||loop_fd_add(loop,r->wake,EPOLLIN,pump,r)){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
 if(pin)r->pin=*pin;
 *out=r;return error(STEER_PV1_OK);
fail:
 if(r->wake>=0)close(r->wake);
 for(uint32_t i=0;i<r->count;i++)(void)steer_draft_binding_unpin(r->bindings[i].lease);
 free(r->bindings);(void)steer_draft_operations_destroy(r->operations);free(r);return e;
}
struct steer_pv1_error steer_draft_stream_routes_destroy(struct steer_draft_stream_routes *r){
 if(!r)return error(STEER_PV1_INVALID);
 if(r->live||r->streams||r->dispatching||r->quarantine||
    (r->quiescing&&r->drained&&!r->drain_notified))return error(STEER_PV1_POLICY_DENIED);
 struct steer_pv1_error e=steer_draft_operations_destroy(r->operations);if(e.code)return e;
 loop_fd_del(r->loop,r->wake);close(r->wake);
 for(uint32_t i=0;i<r->count;i++)(void)steer_draft_binding_unpin(r->bindings[i].lease);
 struct steer_draft_backend_pin pin=r->pin;free(r->bindings);free(r);if(pin.release)pin.release(pin.context);return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_stream_routes_on_drained(struct steer_draft_stream_routes *r,
 steer_draft_stream_routes_drained callback,void *user){
 if(!r||!callback)return error(STEER_PV1_INVALID);
 if(r->drained||r->quiescing||r->live||r->streams||r->quarantine)return error(STEER_PV1_POLICY_DENIED);
 r->drained=callback;r->drained_user=user;return error(STEER_PV1_OK);
}
void steer_draft_stream_routes_quiesce(struct steer_draft_stream_routes *r){if(r){r->quiescing=1;notify(r);}}
struct steer_pv1_async_start steer_draft_stream_route_open(struct steer_draft_stream_routes *r,
 const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
 if(!r||!done)return rejected(STEER_PV1_INVALID);
 struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
 if(flow->generation!=r->generation||r->quiescing)return rejected(STEER_PV1_POLICY_DENIED);
 if(deadline<=now_ns())return rejected(STEER_PV1_TIMEOUT);
 uint32_t index=STEER_DRAFT_STREAM_ROUTE_BLOCK;e=r->select(r->context,flow,&index);if(e.code)return rejected(e.code);
 if(index==STEER_DRAFT_STREAM_ROUTE_BLOCK)return rejected(STEER_PV1_POLICY_DENIED);
 if(index>=r->count)return rejected(STEER_PV1_UNSUPPORTED);
 if(r->live>=r->max_operations)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
 struct steer_draft_stream_binding *binding=&r->bindings[index];
 const struct steer_draft_binding_identity *identity=steer_draft_binding_identity(binding->lease);
 if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&!(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN))return rejected(STEER_PV1_UNSUPPORTED);
 e=steer_draft_binding_admit(binding->lease,r->generation,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
 struct stream_open *op=calloc(1,sizeof(*op));if(!op){(void)steer_draft_binding_unpin(binding->lease);return rejected(STEER_PV1_RESOURCE_EXHAUSTED);}
 e=steer_draft_flow_copy(&op->flow,flow,STEER_PV1_FLOW_STREAM);
 if(e.code){free(op);(void)steer_draft_binding_unpin(binding->lease);return rejected(e.code);}
 op->routes=r;op->lease=binding->lease;op->deadline=deadline;op->done=done;op->userdata=userdata;
 struct steer_pv1_async_start result=steer_draft_operation_start(r->operations,delivered,op);
 if(result.disposition!=STEER_PV1_PENDING){free(op);(void)steer_draft_binding_unpin(binding->lease);return result;}
 op->completion=result.operation;result.operation.handle=(struct steer_pv1_operation *)op;result.operation.api=&operation_api;r->live++;
 struct steer_pv1_async_start inner=binding->api->open(binding->context,&op->flow.value,deadline,backend_done,op);
 if(inner.disposition==STEER_PV1_PENDING)op->backend=inner.operation;
 else{struct steer_pv1_stream_ref empty={NULL,NULL};e=inner.error;if(!e.code)e=error(STEER_PV1_PROTOCOL);backend_done(op,e,empty,NULL,NULL,NULL);}
 return result;
}
uint32_t steer_draft_stream_routes_quarantined(const struct steer_draft_stream_routes *r){return r?r->quarantined:0;}
struct steer_pv1_error steer_draft_stream_routes_recover(struct steer_draft_stream_routes *r,uint32_t *recovered){
 if(recovered)*recovered=0;
 if(!r)return error(STEER_PV1_INVALID);
 uint32_t count=0,examined=0;struct steer_pv1_error result=error(STEER_PV1_OK);
 struct stream_open **link=&r->quarantine;
 while(*link&&examined++<ROUTE_BATCH){
  struct stream_open *op=*link;
  if(!op->public_released){result=error(STEER_PV1_POLICY_DENIED);link=&op->quarantine_next;continue;}
  struct steer_pv1_error e=discard_stream(op->rejected_stream);
  if(e.code){if(!result.code)result=e;link=&op->quarantine_next;continue;}
  *link=op->quarantine_next;r->quarantined--;r->live--;count++;
  struct steer_draft_binding_lease *lease=op->lease;free(op);(void)steer_draft_binding_unpin(lease);
 }
 if(recovered)*recovered=count;
 if(count&&r->quiescing)notify(r);
 return result;
}
