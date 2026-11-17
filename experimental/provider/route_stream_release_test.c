#define _GNU_SOURCE
#include "route_stream.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct fixture;
struct private_job {struct steer_draft_binding_lease *lease;int active,public_freed;};
struct test_layer {struct steer_pv1_stream_ref inner;struct private_job *job;struct fixture *fixture;int peer,closed,bad;};
struct fake_open {struct fixture *f;struct steer_pv1_operation_ref inner;struct loop_timer *timer;
 steer_pv1_stream_open_done done;void *userdata;int completed;};
struct result {struct fixture *f;struct steer_pv1_async_start op;struct steer_pv1_stream_ref stream;uint32_t code;unsigned calls;};
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_pv1_host *host;
 struct steer_draft_stream_runtime *native;struct steer_draft_backend_runtime *wrapper;
 struct steer_draft_operations *operations;struct steer_draft_binding_lease *lease;
 struct steer_draft_stream_routes *routes;struct steer_draft_stream_binding binding;
 struct steer_pv1_flow_metadata flow;struct private_job jobs[2];struct result result[2];
 unsigned phase,job_count,finalized,release_attempts,drained;int bad_next,inside_job;
};
static struct steer_pv1_error error(uint32_t c){struct steer_pv1_error e={c,0};return e;}
static struct test_layer *layer(struct steer_pv1_backend_stream *s){return (struct test_layer *)s;}
static uint64_t STEER_PV1_CALL layer_caps(const struct steer_pv1_backend_stream *s){const struct test_layer *l=(const struct test_layer *)s;return l->inner.api->capabilities(l->inner.handle);}
static struct steer_pv1_async_start STEER_PV1_CALL layer_read(struct steer_pv1_backend_stream *s,struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done d,void *u){struct test_layer *l=layer(s);return l->inner.api->read(l->inner.handle,b,o,n,d,u);}
static struct steer_pv1_async_start STEER_PV1_CALL layer_write(struct steer_pv1_backend_stream *s,struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done d,void *u){struct test_layer *l=layer(s);return l->inner.api->write(l->inner.handle,b,o,n,d,u);}
static struct steer_pv1_async_start STEER_PV1_CALL layer_finish(struct steer_pv1_backend_stream *s,steer_pv1_backend_finish_done d,void *u){struct test_layer *l=layer(s);return l->inner.api->finish_write(l->inner.handle,d,u);}
static void STEER_PV1_CALL layer_close(struct steer_pv1_backend_stream *s){struct test_layer *l=layer(s);if(l->closed)return;l->closed=1;l->inner.api->close(l->inner.handle);}
static struct steer_pv1_error STEER_PV1_CALL layer_release(struct steer_pv1_backend_stream *s){
 struct test_layer *l=layer(s);l->fixture->release_attempts++;
 if(!l->closed||(l->bad&&l->job->active))return error(STEER_PV1_POLICY_DENIED);
 struct steer_pv1_error e=l->inner.api->release(l->inner.handle);if(e.code)return e;
 struct steer_draft_binding_lease *lease=l->job->lease;l->job->public_freed=1;close(l->peer);free(l);
 assert(!steer_draft_binding_unpin(lease).code);return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api layer_api={sizeof(layer_api),STEER_PV1_STREAM_BACKEND_LAYOUT,
 layer_caps,layer_read,layer_write,layer_finish,layer_close,layer_release};
static void fake_deliver(void *arg,struct steer_pv1_error e){
 struct fake_open *op=arg;struct fixture *f=op->f;struct steer_pv1_stream_ref stream={NULL,NULL};loop_timer_stop(op->timer);
 if(!e.code){
  assert(f->job_count<2);struct private_job *job=&f->jobs[f->job_count++];job->lease=f->lease;job->active=1;
  assert(!steer_draft_binding_pin(f->lease,1,STEER_PV1_FLOW_STREAM).code); /* public handle */
  assert(!steer_draft_binding_pin(f->lease,1,STEER_PV1_FLOW_STREAM).code); /* separate private job */
  struct test_layer *l=calloc(1,sizeof(*l));assert(l);l->job=job;l->fixture=f;l->bad=f->bad_next;
  int pair[2];struct steer_pv1_stream *native;assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));l->peer=pair[1];
  assert(!steer_draft_stream_adopt(f->native,pair[0],&native).code);
  assert(!steer_draft_backend_wrap_native(f->wrapper,native,NULL,&l->inner).code);
  stream.handle=(struct steer_pv1_backend_stream *)l;stream.api=&layer_api;
 }
 op->done(op->userdata,e,stream,NULL,NULL,NULL);op->completed=1;
}
static void fake_ready(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fake_open *op=arg;(void)loop;(void)timer;
 (void)steer_draft_operation_resolve(op->inner.handle,error(STEER_PV1_OK));
 assert(!steer_draft_operations_dispatch(op->f->operations,32,NULL).code);
}
static void STEER_PV1_CALL fake_cancel(struct steer_pv1_operation *opaque){struct fake_open *op=(struct fake_open *)opaque;op->inner.api->cancel(op->inner.handle);if(!op->completed)loop_timer_set(op->timer,0);}
static void STEER_PV1_CALL fake_release(struct steer_pv1_operation *opaque){
 struct fake_open *op=(struct fake_open *)opaque;if(!op->completed)return;
 struct steer_draft_binding_lease *lease=op->f->lease;
 op->inner.api->release(op->inner.handle);loop_timer_free(op->timer);free(op);assert(!steer_draft_binding_unpin(lease).code);
}
static const struct steer_pv1_operation_api fake_operation_api={sizeof(fake_operation_api),STEER_PV1_DRAFT_LAYOUT,fake_cancel,fake_release};
static struct steer_pv1_async_start STEER_PV1_CALL fake_open(void *ctx,const struct steer_pv1_flow_metadata *flow,
 uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
 struct fixture *f=ctx;(void)deadline;assert(!steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM).code);
 assert(!steer_draft_binding_admit(f->lease,flow->generation,flow->flow_class).code);
 struct fake_open *op=calloc(1,sizeof(*op));assert(op);op->f=f;op->done=done;op->userdata=userdata;
 struct steer_pv1_async_start a=steer_draft_operation_start(f->operations,fake_deliver,op);assert(a.disposition==STEER_PV1_PENDING);
 op->inner=a.operation;op->timer=loop_timer_new(f->loop,fake_ready,op);assert(op->timer);loop_timer_set(op->timer,0);
 a.operation.handle=(struct steer_pv1_operation *)op;a.operation.api=&fake_operation_api;return a;
}
static const struct steer_pv1_stream_backend_api fake_api={sizeof(fake_api),STEER_PV1_STREAM_BACKEND_LAYOUT,fake_open};
static struct steer_pv1_error select_binding(void *ctx,const struct steer_pv1_flow_metadata *m,uint32_t *index){(void)ctx;(void)m;*index=0;return error(STEER_PV1_OK);}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+UINT64_C(5000000000);}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref s,
 const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diag){
 struct result *r=arg;(void)diag;assert(++r->calls==1&&!bound&&!peer);r->code=e.code;r->stream=s;
 if(e.code)assert(!s.handle&&!s.api);else assert(s.handle&&s.api);
 r->op.operation.api->release(r->op.operation.handle); /* callback lifetime refusal */
 loop_timer_set(r->f->work,0);
}
static void begin(struct fixture *f,unsigned i){
 struct result *r=&f->result[i];r->f=f;r->op=steer_draft_stream_route_open(f->routes,&f->flow,deadline(),opened,r);
 assert(r->op.disposition==STEER_PV1_PENDING&&!r->calls);
}
static void finish_job(struct fixture *f,unsigned i){
 struct private_job *job=&f->jobs[i];assert(job->active);f->inside_job=1;job->active=0;
 assert(!steer_draft_binding_unpin(job->lease).code);f->inside_job=0;
}
static void finalized(void *arg,const struct steer_draft_binding_identity *id){
 struct fixture *f=arg;(void)id;assert(!f->inside_job);
 for(unsigned i=0;i<2;i++)assert(!f->jobs[i].active&&f->jobs[i].public_freed);
 assert(++f->finalized==1);loop_timer_set(f->work,0);
}
static void drained(void *arg,struct steer_draft_stream_routes *routes){
 struct fixture *f=arg;assert(routes==f->routes&&!f->drained++&&!f->inside_job);
 assert(f->jobs[0].active&&f->jobs[0].public_freed&&!f->jobs[1].active&&f->jobs[1].public_freed);
 assert(!f->finalized&&steer_draft_binding_references(f->lease)==2);
 assert(steer_draft_stream_routes_destroy(routes).code==STEER_PV1_POLICY_DENIED);
 loop_timer_set(f->work,0);
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 switch(f->phase){
 case 0:begin(f,0);f->phase=1;break;
 case 1:
  if(!f->result[0].calls)return;
  assert(!f->result[0].code&&f->jobs[0].active&&!f->jobs[0].public_freed);
  f->result[0].op.operation.api->release(f->result[0].op.operation.handle);
  f->bad_next=1;begin(f,1);f->phase=2;break;
 case 2:{
  if(!f->result[1].calls)return;
  assert(f->result[1].code==STEER_PV1_PROTOCOL&&steer_draft_stream_routes_quarantined(f->routes)==1);
  unsigned before=f->release_attempts;uint32_t recovered=99;
  assert(steer_draft_stream_routes_recover(f->routes,&recovered).code==STEER_PV1_POLICY_DENIED&&!recovered&&f->release_attempts==before);
  f->result[1].op.operation.api->release(f->result[1].op.operation.handle);
  assert(steer_draft_stream_routes_recover(f->routes,&recovered).code==STEER_PV1_POLICY_DENIED&&!recovered);
  assert(f->release_attempts==before+1&&!f->jobs[1].public_freed);
  struct steer_pv1_async_start denied=steer_draft_stream_route_open(f->routes,&f->flow,deadline(),opened,&f->result[1]);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_RESOURCE_EXHAUSTED&&f->job_count==2);
  assert(!steer_draft_binding_retire(f->lease).code&&!f->finalized);
  steer_draft_stream_routes_quiesce(f->routes);
  assert(!f->drained);
  assert(steer_draft_stream_route_open(f->routes,&f->flow,deadline(),opened,&f->result[1]).error.code==STEER_PV1_POLICY_DENIED);
  assert(steer_draft_stream_routes_destroy(f->routes).code==STEER_PV1_POLICY_DENIED);
  finish_job(f,1);
  assert(!steer_draft_stream_routes_recover(f->routes,&recovered).code&&recovered==1&&!steer_draft_stream_routes_quarantined(f->routes));
  assert(f->jobs[1].public_freed);
  struct steer_pv1_stream_ref s=f->result[0].stream;s.api->close(s.handle);
  assert(!s.api->release(s.handle).code&&f->jobs[0].public_freed&&f->jobs[0].active);
  assert(!f->drained);f->phase=3;break;
 }
 case 3:
  if(!f->drained)return;
  assert(!steer_draft_stream_routes_destroy(f->routes).code);f->routes=NULL;
  assert(steer_draft_binding_references(f->lease)==1&&!f->finalized);
  assert(steer_draft_binding_lease_destroy(f->lease).code==STEER_PV1_POLICY_DENIED);
  finish_job(f,0);assert(!f->finalized);f->phase=4;break;
 case 4:
  if(!f->finalized)return;
  assert(!steer_draft_binding_lease_destroy(f->lease).code);
  assert(!steer_draft_operations_destroy(f->operations).code);
  assert(!steer_draft_backend_runtime_destroy(f->wrapper).code&&!steer_draft_stream_runtime_destroy(f->native).code);
  f->phase=5;loop_stop(loop,0);break;
 default:assert(0);
 }
}
static void timeout(struct loop *loop,struct loop_timer *timer,void *arg){(void)loop;(void)timer;(void)arg;assert(!"layered release deadline");}
int main(void){
 struct fixture f={0};struct steer_draft_buffer_limits limits={4096,8,4};f.loop=loop_new();assert(f.loop);
 f.work=loop_timer_new(f.loop,step,&f);struct loop_timer *guard=loop_timer_new(f.loop,timeout,NULL);assert(f.work&&guard);
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,4,16,1024,&f.native).code);
 assert(!steer_draft_backend_runtime_create(f.loop,4,16,1024,&f.wrapper).code);
 assert(!steer_draft_operations_create(4,NULL,&f.operations).code);
 static const uint8_t provider[]="layered.test";
 struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,1,99,{provider,sizeof(provider)-1},STEER_DRAFT_STREAM_BINDING_PREPARED,STEER_PV1_FLOW_STREAM};
 assert(!steer_draft_binding_lease_create(f.loop,&id,64,finalized,&f,&f.lease).code);
 f.binding=(struct steer_draft_stream_binding){f.loop,f.lease,&fake_api,&f};
 assert(!steer_draft_stream_routes_create(f.loop,1,1,1,&f.binding,1,select_binding,NULL,NULL,&f.routes).code);
 assert(!steer_draft_stream_routes_on_drained(f.routes,drained,&f).code);
 static const uint8_t ip[]={127,0,0,1},inbound[]="release-test";
 f.flow.size=sizeof(f.flow);f.flow.version=STEER_PV1_DRAFT_LAYOUT;f.flow.generation=1;f.flow.flow_class=STEER_PV1_FLOW_STREAM;
 f.flow.inbound_id=(struct steer_pv1_span){inbound,sizeof(inbound)-1};
 f.flow.source=(struct steer_pv1_endpoint){sizeof(f.flow.source),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},4242,0};
 f.flow.destination=f.flow.source;f.flow.destination.port=7;
 loop_timer_set(f.work,0);loop_timer_set(guard,5000);assert(!loop_run(f.loop)&&f.phase==5&&f.drained==1);
 loop_timer_free(f.work);loop_timer_free(guard);assert(!steer_draft_buffers_destroy(f.host).code);loop_free(f.loop);
 puts("layered private job survives public release; invalid release retained/quarantined/admission bounded/explicit recovery PASS");return 0;
}
