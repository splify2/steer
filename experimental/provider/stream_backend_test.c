#define _GNU_SOURCE
#include "stream_backend.h"
#include "buffers.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
struct fixture;
struct completion {struct fixture *fixture;struct steer_pv1_async_start start;
 struct steer_pv1_buffer *buffer;uint32_t code,bytes;unsigned calls;};
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_pv1_host *host;
 struct steer_draft_stream_runtime *native;struct steer_draft_backend_runtime *runtime;
 struct steer_pv1_stream_ref stream;struct steer_pv1_buffer *b,*other;
 struct completion c[5];unsigned phase,pins_created,pins_released;int peer;
};
static const struct steer_pv1_buffer_api *ba;
static void pin_release(void *arg){(*(unsigned *)arg)++;}
static void pending(struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING&&a.operation.handle&&a.operation.api&&!a.error.code);}
static void denied(struct steer_pv1_async_start a,uint32_t code){assert(a.disposition==STEER_PV1_REJECTED&&a.error.code==code&&!a.operation.handle&&!a.operation.api);}
static void callback_checks(struct completion *c){
 struct fixture *f=c->fixture;assert(++c->calls==1);
 c->start.operation.api->release(c->start.operation.handle); /* early release must not consume */
 assert(f->stream.api->release(f->stream.handle).code==STEER_PV1_POLICY_DENIED);
 assert(steer_draft_backend_runtime_destroy(f->runtime).code==STEER_PV1_POLICY_DENIED);
 assert(f->pins_released+1==f->pins_created);loop_timer_set(f->work,0);
}
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n){
 struct completion *c=arg;struct steer_pv1_mut_span view;assert(c->buffer==b);
 assert(!ba->writable(c->fixture->host,b,&view).code);c->code=e.code;c->bytes=n;callback_checks(c);
}
static void finish_done(void *arg,struct steer_pv1_error e){struct completion *c=arg;c->code=e.code;callback_checks(c);}
static struct completion *slot(struct fixture *f,unsigned i,struct steer_pv1_buffer *b){
 struct completion *c=&f->c[i];memset(c,0,sizeof(*c));c->fixture=f;c->buffer=b;return c;
}
static void start_read(struct fixture *f,unsigned i,struct steer_pv1_buffer *b,uint32_t n){
 struct completion *c=slot(f,i,b);c->start=f->stream.api->read(f->stream.handle,b,0,n,io_done,c);pending(c->start);assert(!c->calls);
}
static void start_write(struct fixture *f,unsigned i,struct steer_pv1_buffer *b,uint32_t n){
 struct completion *c=slot(f,i,b);c->start=f->stream.api->write(f->stream.handle,b,0,n,io_done,c);pending(c->start);assert(!c->calls);
}
static void start_finish(struct fixture *f,unsigned i){
 struct completion *c=slot(f,i,NULL);c->start=f->stream.api->finish_write(f->stream.handle,finish_done,c);pending(c->start);assert(!c->calls);
}
static void release(struct completion *c){assert(c->calls==1);c->start.operation.api->release(c->start.operation.handle);}
static void wrap(struct fixture *f){
 int pair[2];struct steer_pv1_stream *native;assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));f->peer=pair[1];
 assert(!steer_draft_stream_adopt(f->native,pair[0],&native).code);
 struct steer_draft_backend_pin pin={&f->pins_released,pin_release};
 assert(!steer_draft_backend_wrap_native(f->runtime,native,&pin,&f->stream).code);f->pins_created++;
 assert(f->stream.api->size==sizeof(*f->stream.api)&&f->stream.api->version==STEER_PV1_STREAM_BACKEND_LAYOUT);
 assert(f->stream.api->capabilities(f->stream.handle)==STEER_PV1_STREAM_CAP_HALF_CLOSE);
}
static void fill(struct fixture *f,struct steer_pv1_buffer *b,const char *text){
 struct steer_pv1_mut_span v;assert(!ba->writable(f->host,b,&v).code);assert(strlen(text)<=v.len);memcpy(v.data,text,strlen(text));
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;char text[16];(void)timer;
 switch(f->phase){
 case 0:{
  int extra[2];struct steer_pv1_stream *native;struct steer_pv1_stream_ref failed;unsigned unconsumed=0;
  assert(!socketpair(AF_UNIX,SOCK_STREAM,0,extra));assert(!steer_draft_stream_adopt(f->native,extra[0],&native).code);
  struct steer_draft_backend_pin pin={&unconsumed,pin_release};
  assert(steer_draft_backend_wrap_native(f->runtime,native,&pin,&failed).code==STEER_PV1_RESOURCE_EXHAUSTED);
  assert(!failed.handle&&!failed.api&&!unconsumed);
  steer_draft_stream_api()->close(native);assert(!steer_draft_stream_api()->release(native).code);close(extra[1]);pin.release(pin.context);assert(unconsumed==1);
  denied(f->stream.api->read(f->stream.handle,f->b,15,2,io_done,slot(f,4,f->b)),STEER_PV1_INVALID);
  start_read(f,0,f->b,8);
  denied(f->stream.api->read(f->stream.handle,f->other,0,8,io_done,&f->c[4]),STEER_PV1_POLICY_DENIED);
  fill(f,f->other,"12345678");
  denied(f->stream.api->write(f->stream.handle,f->other,0,9,io_done,&f->c[4]),STEER_PV1_RESOURCE_EXHAUSTED);
  start_write(f,1,f->other,8);f->c[1].start.operation.api->cancel(f->c[1].start.operation.handle);
  denied(f->stream.api->finish_write(f->stream.handle,finish_done,&f->c[4]),STEER_PV1_POLICY_DENIED);
  f->c[0].start.operation.api->cancel(f->c[0].start.operation.handle);f->phase=1;break;
 }
 case 1:
  if(!f->c[0].calls||!f->c[1].calls)return;
  assert(f->c[0].code==STEER_PV1_CANCELLED&&!f->c[0].bytes);
  assert(!f->c[1].code&&f->c[1].bytes==8); /* queued success wins cancellation */
  assert(recv(f->peer,text,8,0)==8&&!memcmp(text,"12345678",8));release(&f->c[0]);
  fill(f,f->b,"two");start_write(f,2,f->b,3);f->phase=2;break;
 case 2:
  if(!f->c[2].calls)return;
  assert(!f->c[2].code&&f->c[2].bytes==3);assert(recv(f->peer,text,3,0)==3&&!memcmp(text,"two",3));
  /* Both completed write operation references deliberately remain unreleased. */
  start_finish(f,3);
  denied(f->stream.api->finish_write(f->stream.handle,finish_done,&f->c[4]),STEER_PV1_POLICY_DENIED);
  denied(f->stream.api->write(f->stream.handle,f->other,0,1,io_done,&f->c[4]),STEER_PV1_POLICY_DENIED);
  start_read(f,0,f->b,8);assert(send(f->peer,"reverse",7,0)==7);assert(!shutdown(f->peer,SHUT_WR));f->phase=3;break;
 case 3:
  if(!f->c[0].calls||!f->c[3].calls)return;
  assert(!f->c[0].code&&f->c[0].bytes==7&&!f->c[3].code);assert(recv(f->peer,text,1,0)==0);
  f->c[3].start.operation.api->cancel(f->c[3].start.operation.handle);assert(f->c[3].calls==1);
  release(&f->c[1]);release(&f->c[2]);release(&f->c[3]);start_read(f,4,f->other,8);f->phase=4;break;
 case 4:
  if(!f->c[4].calls)return;
  assert(!f->c[4].code&&!f->c[4].bytes);f->stream.api->close(f->stream.handle);f->stream.api->close(f->stream.handle);
  assert(f->stream.api->release(f->stream.handle).code==STEER_PV1_POLICY_DENIED&&!f->pins_released);
  release(&f->c[0]);release(&f->c[4]);assert(!f->stream.api->release(f->stream.handle).code&&f->pins_released==1);close(f->peer);
  wrap(f);start_read(f,0,f->b,8);start_finish(f,1);f->c[1].start.operation.api->cancel(f->c[1].start.operation.handle);
  denied(f->stream.api->write(f->stream.handle,f->other,0,1,io_done,&f->c[4]),STEER_PV1_POLICY_DENIED);f->phase=5;break;
 case 5:{
  if(!f->c[0].calls||!f->c[1].calls)return;
  assert(f->c[0].code==STEER_PV1_CANCELLED&&f->c[1].code==STEER_PV1_CANCELLED);
  release(&f->c[0]);release(&f->c[1]);assert(!f->stream.api->release(f->stream.handle).code&&f->pins_released==2);close(f->peer);
  uint32_t streams,ops;uint64_t bytes;steer_draft_backend_usage(f->runtime,&streams,&ops,&bytes);assert(!streams&&!ops&&!bytes);
  assert(!steer_draft_backend_runtime_destroy(f->runtime).code);
  assert(!steer_draft_backend_runtime_create(loop,1,1,16,&f->runtime).code);wrap(f);start_read(f,0,f->b,8);
  denied(f->stream.api->finish_write(f->stream.handle,finish_done,&f->c[4]),STEER_PV1_RESOURCE_EXHAUSTED);
  f->c[0].start.operation.api->cancel(f->c[0].start.operation.handle);f->phase=6;break;
 }
 case 6:
  if(!f->c[0].calls)return;
  assert(f->c[0].code==STEER_PV1_CANCELLED);
  denied(f->stream.api->finish_write(f->stream.handle,finish_done,&f->c[4]),STEER_PV1_RESOURCE_EXHAUSTED);
  release(&f->c[0]);fill(f,f->b,"quota");start_write(f,1,f->b,5);
  denied(f->stream.api->finish_write(f->stream.handle,finish_done,&f->c[4]),STEER_PV1_POLICY_DENIED);f->phase=7;break;
 case 7:
  if(!f->c[1].calls)return;
  assert(!f->c[1].code&&f->c[1].bytes==5);assert(recv(f->peer,text,5,0)==5&&!memcmp(text,"quota",5));
  release(&f->c[1]);start_finish(f,0);f->phase=8;break;
 case 8:{
  if(!f->c[0].calls)return;
  assert(!f->c[0].code&&recv(f->peer,text,1,0)==0);
  f->stream.api->close(f->stream.handle);release(&f->c[0]);assert(!f->stream.api->release(f->stream.handle).code);
  assert(f->pins_released==3);close(f->peer);
  uint32_t streams,ops;uint64_t bytes;steer_draft_backend_usage(f->runtime,&streams,&ops,&bytes);assert(!streams&&!ops&&!bytes);
  f->phase=9;loop_stop(loop,0);break;
 }
 default:assert(0);
 }
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg){(void)l;(void)t;(void)arg;assert(!"backend test deadline");}
static void scenario(void){
 struct fixture f={0};struct steer_draft_buffer_limits limits={4096,8,4};struct loop_timer *guard;
 f.loop=loop_new();assert(f.loop);
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,2,8,1024,&f.native).code);
 assert(!steer_draft_backend_runtime_create(f.loop,1,4,16,&f.runtime).code);
 assert(!ba->allocate(f.host,16,&f.b).code&&!ba->allocate(f.host,16,&f.other).code);wrap(&f);
 f.work=loop_timer_new(f.loop,step,&f);guard=loop_timer_new(f.loop,timeout,NULL);assert(f.work&&guard);
 loop_timer_set(f.work,0);loop_timer_set(guard,5000);assert(!loop_run(f.loop)&&f.phase==9);
 loop_timer_free(f.work);loop_timer_free(guard);
 assert(!steer_draft_backend_runtime_destroy(f.runtime).code&&!steer_draft_stream_runtime_destroy(f.native).code);
 ba->release(f.host,f.b);ba->release(f.host,f.other);assert(!steer_draft_buffers_destroy(f.host).code);loop_free(f.loop);
}
static void *thread_scenario(void *arg){(void)arg;for(unsigned round=0;round<64;round++)scenario();return NULL;}
int main(void){
 ba=steer_draft_buffers_api();scenario();pthread_t owners[4];
 for(unsigned i=0;i<4;i++)assert(!pthread_create(&owners[i],NULL,thread_scenario,NULL));
 for(unsigned i=0;i<4;i++)assert(!pthread_join(owners[i],NULL));
 puts("origin native stream lifecycle/budgets/finish/cancel/pins:1+4 owner shards,257 rounds/771 stream leases PASS");return 0;
}
