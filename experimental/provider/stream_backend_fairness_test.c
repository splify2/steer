#define _GNU_SOURCE
#include "stream_backend.h"
#include "buffers.h"
#include "loop.h"
#include <assert.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#define COUNT 97u
struct bulk;
struct entry {
 struct bulk *bulk;struct steer_pv1_stream_ref stream;struct steer_pv1_stream *native;
 struct steer_pv1_async_start op;struct steer_pv1_buffer *buffer;
 unsigned calls,released;uint32_t code;int peer;
};
struct bulk {
 struct loop *loop;struct steer_pv1_host *host;struct steer_draft_stream_runtime *native;
 struct steer_draft_backend_runtime *runtime;struct entry entries[COUNT];
 unsigned completed,released,observed;int notify,native_only;
};
static void done(struct entry *e,struct steer_pv1_error error){
 struct bulk *b=e->bulk;assert(++e->calls==1);e->code=error.code;b->completed++;
 uint64_t one=1;assert(write(b->notify,&one,sizeof(one))==sizeof(one));
}
static void finish_done(void *arg,struct steer_pv1_error e){done(arg,e);}
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes){
 struct entry *entry=arg;assert(!e.code&&bytes==1&&buffer==entry->buffer);done(entry,e);
}
static void neighbor(struct loop *loop,int fd,uint32_t events,void *arg){
 struct bulk *b=arg;uint64_t counter;(void)events;assert(read(fd,&counter,sizeof(counter))==sizeof(counter));
 if(!b->observed){
  /* Ready in first callback; at most two bounded completion turns precede us. */
  assert(b->completed<=64&&b->completed<COUNT);b->observed=1;
  if(!b->native_only)assert(b->entries[COUNT-1].calls==1&&b->entries[COUNT-1].code==STEER_PV1_CANCELLED);
 }
 for(unsigned i=0;i<COUNT;i++){
  struct entry *e=&b->entries[i];if(!e->calls||e->released)continue;
  e->op.operation.api->release(e->op.operation.handle);
  if(b->native_only){steer_draft_stream_api()->close(e->native);assert(!steer_draft_stream_api()->release(e->native).code);steer_draft_buffers_api()->release(b->host,e->buffer);}
  else{e->stream.api->close(e->stream.handle);assert(!e->stream.api->release(e->stream.handle).code);}
  close(e->peer);e->released=1;b->released++;
 }
 if(b->released==COUNT)loop_stop(loop,0);
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg){(void)l;(void)t;(void)arg;assert(!"batch fairness deadline");}
static void run(int native_only){
 struct bulk b={0};struct steer_draft_buffer_limits limits={262144,COUNT,2};b.native_only=native_only;
 b.loop=loop_new();assert(b.loop);assert(!steer_draft_buffers_create(&limits,NULL,&b.host).code);
 assert(!steer_draft_stream_runtime_create(b.loop,b.host,COUNT,COUNT,1024,&b.native).code);
 if(!native_only)assert(!steer_draft_backend_runtime_create(b.loop,COUNT,COUNT,1024,&b.runtime).code);
 b.notify=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(b.notify>=0);
 assert(!loop_fd_add(b.loop,b.notify,EPOLLIN,neighbor,&b));
 for(unsigned i=0;i<COUNT;i++){
  struct entry *e=&b.entries[i];int pair[2];e->bulk=&b;
  assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));e->peer=pair[1];
  assert(!steer_draft_stream_adopt(b.native,pair[0],&e->native).code);
  if(native_only){
   struct steer_pv1_mut_span view;assert(!steer_draft_buffers_api()->allocate(b.host,1,&e->buffer).code);
   assert(!steer_draft_buffers_api()->writable(b.host,e->buffer,&view).code);view.data[0]=42;
   e->op=steer_draft_stream_api()->write(e->native,e->buffer,0,1,io_done,e);
  }else{
   assert(!steer_draft_backend_wrap_native(b.runtime,e->native,NULL,&e->stream).code);
   e->op=e->stream.api->finish_write(e->stream.handle,finish_done,e);
  }
  assert(e->op.disposition==STEER_PV1_PENDING&&!e->calls);
 }
 if(!native_only)b.entries[COUNT-1].op.operation.api->cancel(b.entries[COUNT-1].op.operation.handle);
 struct loop_timer *guard=loop_timer_new(b.loop,timeout,NULL);assert(guard);loop_timer_set(guard,5000);
 assert(!loop_run(b.loop)&&b.observed&&b.completed==COUNT&&b.released==COUNT);
 loop_timer_free(guard);loop_fd_del(b.loop,b.notify);close(b.notify);
 if(b.runtime)assert(!steer_draft_backend_runtime_destroy(b.runtime).code);
 assert(!steer_draft_stream_runtime_destroy(b.native).code&&!steer_draft_buffers_destroy(b.host).code);loop_free(b.loop);
}
int main(void){run(0);run(1);puts("97 finish tail-cancel/release +97 native completions neighbor fairness PASS");return 0;}
