#define _GNU_SOURCE
#include "route_dial.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
struct fixture {
 struct loop *loop; struct loop_timer *work;
 struct steer_draft_stream_runtime *streams; struct steer_draft_routes *routes;
 struct steer_pv1_host *host; struct steer_pv1_stream *stream;
 struct steer_pv1_buffer *buffer;
 struct steer_draft_accepted flow;
 struct steer_pv1_async_start operation;
 uint32_t action, error, failure; unsigned evaluations, completions, phase;
 int listener, peer; uint8_t ip[4];
};
static uint64_t deadline(void) {
 struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t));
 return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec+UINT64_C(2000000000);
}
static struct steer_pv1_error evaluate(void *arg,const struct steer_draft_accepted *flow,uint32_t *action) {
 struct fixture *f=arg; struct steer_pv1_error e={0,0}; f->evaluations++;
 assert(flow->generation==7 && flow->inbound_id.len==5);
 assert(!memcmp(flow->inbound_id.data,"socks",5));
 assert(flow->principal_id.len==8 && !memcmp(flow->principal_id.data,"lab-user",8));
 *action=f->action; return e;
}
static void routed(void *arg,struct steer_pv1_error e,uint32_t failure,struct steer_pv1_stream *s,
 const struct steer_pv1_endpoint *bound) {
 struct fixture *f=arg; f->completions++; f->error=e.code; f->failure=failure; f->stream=s;
 assert(steer_draft_routes_destroy(f->routes).code==STEER_PV1_POLICY_DENIED);
 f->operation.operation.api->release(f->operation.operation.handle); /* too early */
 if(!e.code) { assert(s && bound && bound->port && bound->tag==STEER_PV1_ENDPOINT_IPV4); }
 else assert(!s && !bound);
 loop_timer_set(f->work,0);
}
static void read_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n) {
 struct fixture *f=arg; struct steer_pv1_mut_span span;
 assert(!e.code && n==6 && b==f->buffer);
 assert(!steer_draft_buffers_api()->writable(f->host,b,&span).code);
 assert(!memcmp(span.data,"shared",6)); loop_timer_set(f->work,0);
}
static void work(struct loop *l,struct loop_timer *t,void *arg) {
 struct fixture *f=arg; struct steer_pv1_async_start a;
 (void)t; f->operation.operation.api->release(f->operation.operation.handle);
 switch(f->phase++) {
 case 0:
  assert(!f->error && f->completions==1);
  f->flow.generation=7; f->flow.inbound_id.data=(const uint8_t *)"socks";
  f->flow.destination.address.data=f->ip;
  f->peer=accept(f->listener,NULL,NULL); assert(f->peer>=0);
  assert(send(f->peer,"shared",6,0)==6);
  assert(!steer_draft_buffers_api()->allocate(f->host,16,&f->buffer).code);
  f->operation=steer_draft_stream_api()->read(f->stream,f->buffer,0,16,read_done,f);
  assert(f->operation.disposition==STEER_PV1_PENDING); break;
 case 1:
  steer_draft_stream_api()->close(f->stream);
  assert(!steer_draft_stream_api()->release(f->stream).code); f->stream=NULL;
  close(f->peer); f->peer=-1;
  steer_draft_buffers_api()->release(f->host,f->buffer);
  f->operation=steer_draft_route_dial(f->routes,&f->flow,deadline(),routed,f);
  assert(f->operation.disposition==STEER_PV1_PENDING);
  f->operation.operation.api->cancel(f->operation.operation.handle);
  assert(f->completions==1); break;
 case 2:
  assert(f->error==STEER_PV1_CANCELLED && f->completions==2);
  {
   struct timespec pause={0,20000000};
   f->operation=steer_draft_route_dial(f->routes,&f->flow,
       deadline()-UINT64_C(1990000000),routed,f);
   assert(f->operation.disposition==STEER_PV1_PENDING);
   assert(!nanosleep(&pause,NULL)); /* deadline expires before ready is dispatched */
  }
  break;
 case 3:
  assert(f->error==STEER_PV1_TIMEOUT && f->completions==3);
  close(f->listener); f->listener=-1;
  f->operation=steer_draft_route_dial(f->routes,&f->flow,deadline(),routed,f);
  assert(f->operation.disposition==STEER_PV1_PENDING); break;
 case 4:
  assert(f->error==STEER_PV1_IO && f->failure==STEER_DRAFT_DIAL_REFUSED && f->completions==4);
  f->action=STEER_DRAFT_ROUTE_BLOCK;
  a=steer_draft_route_dial(f->routes,&f->flow,deadline(),routed,f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_POLICY_DENIED);
  f->action=STEER_DRAFT_ROUTE_DIRECT;
  f->flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;
  f->flow.destination.address.data=(const uint8_t *)"example.test"; f->flow.destination.address.len=12;
  a=steer_draft_route_dial(f->routes,&f->flow,deadline(),routed,f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_UNSUPPORTED);
  f->action=99;
  a=steer_draft_route_dial(f->routes,&f->flow,deadline(),routed,f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_UNSUPPORTED);
  assert(f->evaluations==8);
  assert(!steer_draft_routes_destroy(f->routes).code);
  assert(!steer_draft_stream_runtime_destroy(f->streams).code);
  loop_stop(l,0); break;
 default: assert(0);
 }
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg) { (void)t;(void)arg;loop_stop(l,99); }
int main(void) {
 struct fixture f={0}; struct sockaddr_in address={0}; socklen_t n=sizeof(address);
 struct steer_draft_buffer_limits limits={4096,2,1}; struct loop_timer *guard;
 f.loop=loop_new(); assert(f.loop); f.action=STEER_DRAFT_ROUTE_DIRECT;
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,2,2,32,&f.streams).code);
 assert(!steer_draft_routes_create(f.loop,f.streams,7,1,evaluate,&f,&f.routes).code);
 f.listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(f.listener>=0);
 address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 assert(!bind(f.listener,(struct sockaddr *)&address,n) && !listen(f.listener,2));
 assert(!getsockname(f.listener,(struct sockaddr *)&address,&n));
 memcpy(f.ip,&address.sin_addr,4);
 f.flow.generation=7; f.flow.inbound_id.data=(const uint8_t *)"socks"; f.flow.inbound_id.len=5;
 f.flow.principal_id.data=(const uint8_t *)"lab-user"; f.flow.principal_id.len=8;
 f.flow.flow_class=STEER_PV1_FLOW_STREAM;
 f.flow.source.size=sizeof(f.flow.source); f.flow.source.version=STEER_PV1_DRAFT_LAYOUT;
 f.flow.source.tag=STEER_PV1_ENDPOINT_IPV4; f.flow.source.address.data=f.ip;
 f.flow.source.address.len=4; f.flow.source.port=12345;
 f.flow.destination=f.flow.source; f.flow.destination.port=ntohs(address.sin_port);
 f.work=loop_timer_new(f.loop,work,&f); guard=loop_timer_new(f.loop,timeout,NULL); assert(f.work && guard);
 loop_timer_set(guard,3000);
 {
  struct steer_pv1_async_start a;
  f.flow.generation=8;
  a=steer_draft_route_dial(f.routes,&f.flow,deadline(),routed,&f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_POLICY_DENIED && !f.evaluations);
  f.flow.generation=7; f.flow.principal_id.len=65;
  a=steer_draft_route_dial(f.routes,&f.flow,deadline(),routed,&f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_INVALID && !f.evaluations);
  f.flow.principal_id.len=8;
 }
 f.operation=steer_draft_route_dial(f.routes,&f.flow,deadline(),routed,&f);
 assert(f.operation.disposition==STEER_PV1_PENDING && !f.completions);
 {
  struct steer_pv1_async_start a=steer_draft_route_dial(f.routes,&f.flow,deadline(),routed,&f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_RESOURCE_EXHAUSTED);
 }
 /* Async code must not borrow caller flow metadata after start. */
 f.flow.inbound_id.data=(const uint8_t *)"other";
 f.flow.generation=999;
 f.flow.destination.address.data=NULL;
 assert(!loop_run(f.loop) && f.phase==5);
 loop_timer_free(f.work); loop_timer_free(guard);
 assert(!steer_draft_buffers_destroy(f.host).code); loop_free(f.loop);
 puts("route dial tests passed"); return 0;
}
