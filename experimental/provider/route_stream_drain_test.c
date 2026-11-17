#define _POSIX_C_SOURCE 200809L
#include "route_stream.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
struct fixture {
 struct loop *loop;struct loop_timer *work;
 struct steer_draft_stream_routes *routes;struct steer_draft_binding_lease *lease;
 struct steer_pv1_operation_ref open;unsigned calls,notified,finalized,backend_calls,phase;int empty;
};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static struct steer_pv1_error select_binding(void *ctx,const struct steer_pv1_flow_metadata *m,uint32_t *index){(void)ctx;(void)m;*index=0;return error(0);}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+1000000000ull;}
static struct steer_pv1_async_start refuse(void *arg,const struct steer_pv1_flow_metadata *m,uint64_t until,steer_pv1_stream_open_done done,void *user){
 struct fixture *f=arg;(void)m;(void)until;(void)done;(void)user;f->backend_calls++;
 return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{STEER_PV1_IO,0},{NULL,NULL}};
}
static const struct steer_pv1_stream_backend_api backend={sizeof(backend),STEER_PV1_STREAM_BACKEND_LAYOUT,refuse};
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref s,
 const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diagnostic){
 struct fixture *f=arg;(void)diagnostic;assert(!f->calls++&&e.code==STEER_PV1_IO&&!s.handle&&!bound&&!peer);
 assert(!f->notified&&f->backend_calls==1);
 f->open.api->release(f->open.handle); /* callback has not returned: must retain admission */
 assert(steer_draft_stream_routes_destroy(f->routes).code==STEER_PV1_POLICY_DENIED);loop_timer_set(f->work,0);
}
static void drained(void *arg,struct steer_draft_stream_routes *r){
 struct fixture *f=arg;assert(r==f->routes&&!f->notified++);
 assert(f->empty||!f->open.handle);
 assert(steer_draft_stream_routes_destroy(r).code==STEER_PV1_POLICY_DENIED);
 steer_draft_stream_routes_quiesce(r); /* no duplicate notification */
 loop_timer_set(f->work,0);
}
static void finalized(void *arg,const struct steer_draft_binding_identity *id){
 (void)id;struct fixture *f=arg;assert(!f->finalized++);
 if(!f->routes)loop_timer_set(f->work,0);
}
static void work(struct loop *l,struct loop_timer *t,void *arg){
 (void)t;struct fixture *f=arg;
 if(f->phase==0){
  assert(!f->empty&&f->calls==1&&!f->notified&&f->open.handle);
  f->open.api->release(f->open.handle);f->open=(struct steer_pv1_operation_ref){NULL,NULL};f->phase=1;
  assert(!f->notified);return; /* no retry timer; last release must wake owner */
 }
 if(f->phase==1){
  assert(f->notified==1);assert(!steer_draft_stream_routes_destroy(f->routes).code);f->routes=NULL;f->phase=2;
  if(f->finalized)loop_timer_set(f->work,0);
  return;
 }
 assert(f->phase==2&&f->notified==1&&f->finalized==1);
 assert(!steer_draft_binding_lease_destroy(f->lease).code);loop_stop(l,0);
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg){(void)l;(void)t;(void)arg;assert(!"stream drained deadline");}
static void scenario(int empty){
 struct fixture f={0};f.empty=empty;f.phase=empty?1:0;f.loop=loop_new();assert(f.loop);
 f.work=loop_timer_new(f.loop,work,&f);struct loop_timer *guard=loop_timer_new(f.loop,timeout,NULL);assert(f.work&&guard);
 struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,1,99,{(const uint8_t *)"drain-test",10},STEER_DRAFT_STREAM_BINDING_PREPARED,STEER_PV1_FLOW_STREAM};
 assert(!steer_draft_binding_lease_create(f.loop,&id,16,finalized,&f,&f.lease).code);
 struct steer_draft_stream_binding binding={f.loop,f.lease,&backend,&f};
 assert(!steer_draft_stream_routes_create(f.loop,1,4,4,empty?NULL:&binding,empty?0:1,select_binding,NULL,NULL,&f.routes).code);
 assert(!steer_draft_stream_routes_on_drained(f.routes,drained,&f).code);
 assert(steer_draft_stream_routes_on_drained(f.routes,drained,&f).code==STEER_PV1_POLICY_DENIED);
 uint8_t ip[4]={127,0,0,1};
 struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1,0};
 struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=1,
  .inbound_id={(const uint8_t *)"test",4},.source=endpoint,.destination=endpoint,.flow_class=STEER_PV1_FLOW_STREAM};
 if(!empty){struct steer_pv1_async_start a=steer_draft_stream_route_open(f.routes,&flow,deadline(),opened,&f);assert(a.disposition==STEER_PV1_PENDING);f.open=a.operation;}
 assert(!steer_draft_binding_retire(f.lease).code);steer_draft_stream_routes_quiesce(f.routes);
 assert(!f.notified&&steer_draft_stream_routes_destroy(f.routes).code==STEER_PV1_POLICY_DENIED);
 assert(steer_draft_stream_route_open(f.routes,&flow,deadline(),opened,&f).error.code==STEER_PV1_POLICY_DENIED);
 loop_timer_set(guard,3000);assert(!loop_run(f.loop));assert(f.notified==1&&f.calls==(unsigned)!empty);
 loop_timer_free(f.work);loop_timer_free(guard);loop_free(f.loop);
}
static void *owner(void *u){(void)u;scenario(0);scenario(1);return NULL;}
int main(void){owner(NULL);pthread_t threads[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,owner,NULL));
 for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
 puts("stream drained: empty/held exported open/exactonce/next-owner destroy on1+4 owners PASS");return 0;}
