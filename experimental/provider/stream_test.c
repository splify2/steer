#define _GNU_SOURCE
#include "stream.h"
#include "buffers.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <unistd.h>
struct fixture {
 struct loop *loop; struct loop_timer *next;
 struct steer_pv1_host *host; struct steer_draft_stream_runtime *runtime;
 struct steer_pv1_stream *stream; struct steer_pv1_buffer *b,*other;
 struct steer_pv1_async_start op;
 unsigned phase,calls; uint32_t code,bytes; int pair[2];
};
static const struct steer_pv1_stream_api *api;
static const struct steer_pv1_buffer_api *ba;
static void done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n) {
 struct fixture *f=arg; struct steer_pv1_mut_span v;
 assert(b==f->b); f->calls++; f->code=e.code; f->bytes=n;
 assert(!ba->writable(f->host,b,&v).code); /* ownership already returned */
 f->op.operation.api->release(f->op.operation.handle); /* early release refused */
 assert(api->release(f->stream).code==STEER_PV1_POLICY_DENIED);
 assert(steer_draft_stream_runtime_destroy(f->runtime).code==STEER_PV1_POLICY_DENIED);
 loop_timer_set(f->next,0);
}
static void pending(struct steer_pv1_async_start op) { assert(op.disposition==STEER_PV1_PENDING); }
static void step(struct loop *l,struct loop_timer *t,void *arg) {
 struct fixture *f=arg; struct steer_pv1_mut_span v; struct steer_pv1_async_start a;
 char response[8]; int size=4096; (void)t;
 if(f->phase) f->op.operation.api->release(f->op.operation.handle);
 switch(f->phase++) {
 case 0:
  a=api->read(f->stream,f->b,31,2,done,f); assert(a.disposition==STEER_PV1_REJECTED);
  assert(!ba->retain(f->host,f->b).code);
  a=api->read(f->stream,f->b,0,1,done,f); assert(a.disposition==STEER_PV1_REJECTED);
  ba->release(f->host,f->b);
  f->op=api->read(f->stream,f->b,4,8,done,f); pending(f->op);
  a=api->read(f->stream,f->other,0,8,done,f); assert(a.disposition==STEER_PV1_REJECTED);
  assert(send(f->pair[1],"hello",5,0)==5); break;
 case 1:
  assert(!f->code && f->bytes==5 && f->calls==1);
  assert(!ba->writable(f->host,f->b,&v).code && !memcmp(v.data+4,"hello",5));
  assert(!shutdown(f->pair[1],SHUT_WR));
  f->op=api->read(f->stream,f->b,0,8,done,f); pending(f->op); break;
 case 2:
  assert(!f->code && !f->bytes);
  assert(!ba->writable(f->host,f->b,&v).code); memcpy(v.data,"response",8);
  f->op=api->write(f->stream,f->b,0,8,done,f); pending(f->op);
  assert(api->shutdown_write(f->stream).code==STEER_PV1_POLICY_DENIED); break;
 case 3:
  assert(!f->code && f->bytes==8);
  assert(recv(f->pair[1],response,8,0)==8 && !memcmp(response,"response",8));
  ba->release(f->host,f->b); assert(!ba->allocate(f->host,1048576,&f->b).code);
  assert(!ba->writable(f->host,f->b,&v).code); memset(v.data,42,v.len);
  assert(!setsockopt(f->pair[0],SOL_SOCKET,SO_SNDBUF,&size,sizeof(size)));
  f->op=api->write(f->stream,f->b,0,1048576,done,f); pending(f->op); break;
 case 4:
  assert(!f->code && f->bytes>0 && f->bytes<1048576);
  f->op=api->write(f->stream,f->b,0,1048576,done,f); pending(f->op);
  a=api->read(f->stream,f->other,0,1,done,f);
  assert(a.disposition==STEER_PV1_REJECTED && a.error.code==STEER_PV1_RESOURCE_EXHAUSTED);
  f->op.operation.api->cancel(f->op.operation.handle); assert(f->calls==4); break;
 case 5:
  assert(f->code==STEER_PV1_CANCELLED && !f->bytes);
  assert(!api->shutdown_write(f->stream).code);
  a=api->write(f->stream,f->b,0,1,done,f); assert(a.disposition==STEER_PV1_REJECTED);
  api->close(f->stream); api->close(f->stream); assert(!api->release(f->stream).code); close(f->pair[1]);
  ba->release(f->host,f->b); assert(!ba->allocate(f->host,8,&f->b).code);
  assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f->pair));
  assert(!steer_draft_stream_adopt(f->runtime,f->pair[0],&f->stream).code);
  f->op=api->read(f->stream,f->b,0,8,done,f); pending(f->op);
  api->close(f->stream); assert(f->calls==5);
  assert(api->release(f->stream).code==STEER_PV1_POLICY_DENIED); break;
 case 6:
  assert(f->code==STEER_PV1_CANCELLED && f->calls==6);
  assert(!api->release(f->stream).code); close(f->pair[1]);
  ba->release(f->host,f->b); ba->release(f->host,f->other);
  assert(!steer_draft_stream_runtime_destroy(f->runtime).code);
  loop_stop(l,0); break;
 default: assert(0);
 }
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg) { (void)t;(void)arg;loop_stop(l,99); }
/* An always-ready one-byte stream completion chain also schedules a host work
 * timer, exactly like SOCKS. Old zero-delay completion timers consumed the
 * entire chain inside timers_fire and starved the unrelated readable eventfd.
 * Cap the chain so the regression fails deterministically rather than hanging. */
struct fairness {
 struct loop *loop; struct loop_timer *work;
 struct steer_pv1_host *host; struct steer_draft_stream_runtime *runtime;
 struct steer_pv1_stream *stream; struct steer_pv1_buffer *buffer;
 struct steer_pv1_async_start operation;
 unsigned completions, observed; int pair[2], notify;
};
static void fair_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n) {
 struct fairness *f=arg; uint64_t one=1;
 assert(!e.code && n==1 && b==f->buffer); f->completions++;
 if(f->completions==100) assert(write(f->notify,&one,sizeof(one))==(ssize_t)sizeof(one));
 loop_timer_set(f->work,0);
}
static void fair_work(struct loop *l,struct loop_timer *t,void *arg) {
 struct fairness *f=arg; (void)t;
 if(f->completions) f->operation.operation.api->release(f->operation.operation.handle);
 if(f->observed || f->completions==10000) {
  api->close(f->stream); assert(!api->release(f->stream).code);
  assert(!steer_draft_stream_runtime_destroy(f->runtime).code); loop_stop(l,0); return;
 }
 assert(send(f->pair[1],"x",1,0)==1);
 f->operation=api->read(f->stream,f->buffer,0,1,fair_done,f); pending(f->operation);
}
static void fair_other(struct loop *l,int fd,uint32_t events,void *arg) {
 struct fairness *f=arg; uint64_t count; (void)l;(void)events;
 assert(read(fd,&count,sizeof(count))==(ssize_t)sizeof(count));
 f->observed=f->completions; assert(f->observed>=100 && f->observed<=102);
}
static void fairness_test(void) {
 struct fairness f={0}; struct steer_draft_buffer_limits limits={4096,1,1};
 struct loop_timer *guard;
 f.loop=loop_new(); assert(f.loop);
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,1,2,1,&f.runtime).code);
 assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f.pair));
 assert(!steer_draft_stream_adopt(f.runtime,f.pair[0],&f.stream).code);
 assert(!ba->allocate(f.host,1,&f.buffer).code);
 f.notify=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC); assert(f.notify>=0);
 assert(!loop_fd_add(f.loop,f.notify,EPOLLIN,fair_other,&f));
 f.work=loop_timer_new(f.loop,fair_work,&f); guard=loop_timer_new(f.loop,timeout,NULL);
 assert(f.work && guard); loop_timer_set(f.work,0); loop_timer_set(guard,3000);
 assert(!loop_run(f.loop)); assert(f.observed && f.completions<=103);
 loop_fd_del(f.loop,f.notify); close(f.notify); close(f.pair[1]);
 loop_timer_free(f.work); loop_timer_free(guard);
 ba->release(f.host,f.buffer); assert(!steer_draft_buffers_destroy(f.host).code); loop_free(f.loop);
}
int main(void) {
 struct fixture f={0}; struct steer_draft_buffer_limits limits={4000000,16,4}; struct loop_timer *guard;
 api=steer_draft_stream_api(); ba=steer_draft_buffers_api(); f.loop=loop_new(); assert(f.loop);
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,1,2,1048576,&f.runtime).code);
 assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f.pair));
 assert(!steer_draft_stream_adopt(f.runtime,f.pair[0],&f.stream).code);
 assert(!ba->allocate(f.host,32,&f.b).code); assert(!ba->allocate(f.host,32,&f.other).code);
 f.next=loop_timer_new(f.loop,step,&f); guard=loop_timer_new(f.loop,timeout,NULL); assert(f.next && guard);
 loop_timer_set(f.next,0); loop_timer_set(guard,3000);
 assert(!loop_run(f.loop)); assert(f.phase==7);
 loop_timer_free(f.next); loop_timer_free(guard); assert(!steer_draft_buffers_destroy(f.host).code);
 loop_free(f.loop); fairness_test(); puts("stream tests passed"); return 0;
}
