#define _GNU_SOURCE
#include "route_stream.h"
#include "native_stream_backend.h"
#include "buffers.h"
#include "resolver.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
struct server {int listen,stop;atomic_uint accepted;};
static void *echo_server(void *arg){
 struct server *s=arg;struct pollfd p[2]={{s->listen,POLLIN,0},{s->stop,POLLIN,0}};
 for(;;){
  int ready=poll(p,2,-1);if(ready<0)continue;if(p[1].revents&POLLIN)break;
  if(!(p[0].revents&POLLIN))continue;
  int fd=accept(s->listen,NULL,NULL);if(fd<0)continue;atomic_fetch_add(&s->accepted,1);
  struct timeval tv={5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
  unsigned char body[64];size_t have=0;ssize_t n;
  while(have<sizeof(body)&&(n=recv(fd,body+have,sizeof(body)-have,0))>0)have+=(size_t)n;
  size_t sent=0;while(sent<have){n=send(fd,body+sent,have-sent,MSG_NOSIGNAL);if(n<=0)break;sent+=(size_t)n;}
  shutdown(fd,SHUT_WR);close(fd);
 }
 return NULL;
}
struct fixture;
struct result {struct fixture *f;struct steer_pv1_async_start op;struct steer_pv1_stream_ref stream;
 struct steer_pv1_buffer *buffer;uint32_t code,bytes;unsigned calls,index,reading;};
struct notice {struct fixture *f;unsigned index;};
struct fixture {
 struct loop *loop;struct loop_timer *work;
 struct steer_pv1_host *host;struct steer_draft_stream_runtime *native;
 struct steer_draft_backend_runtime *wrapper;struct steer_draft_resolver *resolver;
 struct steer_draft_native_stream_backend *backend[2];struct notice notice[2];unsigned finalized[2];
 struct steer_draft_stream_routes *old,*current,*blocked;
 struct steer_pv1_flow_metadata meta[2];uint8_t ip[4],inbound[11],domain[9];
 struct result opened[3],writes[2],reads[2],finishes[2];
 struct steer_pv1_buffer *out[2],*in[2];struct server server;unsigned phase,block_calls;
 unsigned received[2],eof[2];
 pthread_mutex_t gate_mutex;pthread_cond_t gate_cond;atomic_int gate_entered;
 int gate_release,worker_notify;
};
static void resolver_backend(void *arg,const char *host,uint16_t port,struct steer_draft_resolve_result *out){
 struct fixture *f=arg;memset(out,0,sizeof(*out));
 if(!strcmp(host,"hold.example")){
  assert(!pthread_mutex_lock(&f->gate_mutex));atomic_store_explicit(&f->gate_entered,1,memory_order_release);
  uint64_t one=1;assert(write(f->worker_notify,&one,sizeof(one))==sizeof(one));
  while(!f->gate_release)assert(!pthread_cond_wait(&f->gate_cond,&f->gate_mutex));
  assert(!pthread_mutex_unlock(&f->gate_mutex));
  struct sockaddr_in *a=(struct sockaddr_in *)&out->addresses[0];a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);a->sin_port=htons(port);out->count=1;
  assert(write(f->worker_notify,&one,sizeof(one))==sizeof(one));return;
 }
 struct addrinfo hints={0},*list=NULL;hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
 if(getaddrinfo(host,NULL,&hints,&list)){out->code=STEER_PV1_IO;return;}
 for(struct addrinfo *a=list;a&&out->count<STEER_DRAFT_RESOLVE_ADDRESSES;a=a->ai_next){
  if((a->ai_family==AF_INET||a->ai_family==AF_INET6)&&a->ai_addrlen<=sizeof(out->addresses[0]))memcpy(&out->addresses[out->count++],a->ai_addr,a->ai_addrlen);
 }
 freeaddrinfo(list);if(!out->count)out->code=STEER_PV1_IO;
}
static void worker_ready(struct loop *loop,int fd,uint32_t events,void *arg){
 (void)loop;(void)events;struct fixture *f=arg;uint64_t count;assert(read(fd,&count,sizeof(count))==sizeof(count));loop_timer_set(f->work,0);
}
static const struct steer_pv1_buffer_api *ba;
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+UINT64_C(5000000000);}
static struct steer_pv1_error select_direct(void *ctx,const struct steer_pv1_flow_metadata *f,uint32_t *index){
 (void)ctx;(void)f;*index=0;struct steer_pv1_error e={0,0};return e;
}
static struct steer_pv1_error select_block(void *ctx,const struct steer_pv1_flow_metadata *f,uint32_t *index){
 struct fixture *fixture=ctx;assert(f->destination.tag==STEER_PV1_ENDPOINT_DOMAIN);fixture->block_calls++;
 *index=STEER_DRAFT_STREAM_ROUTE_BLOCK;struct steer_pv1_error e={0,0};return e;
}
static void retired(void *arg){struct notice *n=arg;assert(++n->f->finalized[n->index]==1);loop_timer_set(n->f->work,0);}
static void pending(struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING&&a.operation.handle&&a.operation.api&&!a.error.code);}
static void denied(struct steer_pv1_async_start a,uint32_t code){assert(a.disposition==STEER_PV1_REJECTED&&a.error.code==code&&!a.operation.handle&&!a.operation.api);}
static void release(struct result *r){assert(r->calls==1);r->op.operation.api->release(r->op.operation.handle);}
static void open_done(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,
 const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diag){
 struct result *r=arg;(void)peer;assert(++r->calls==1);r->code=e.code;r->stream=stream;
 if(e.code)assert(!stream.handle&&!stream.api&&!bound&&!peer);
 else assert(stream.handle&&stream.api&&bound&&bound->tag==STEER_PV1_ENDPOINT_IPV4&&bound->port);
 if(diag)assert(diag->size==sizeof(*diag)&&diag->version==STEER_PV1_STREAM_BACKEND_LAYOUT);
 r->op.operation.api->release(r->op.operation.handle); /* refused inside callback */
 loop_timer_set(r->f->work,0);
}
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t bytes){
 struct result *r=arg;struct steer_pv1_mut_span view;assert(++r->calls==1&&b==r->buffer);
 assert(!ba->writable(r->f->host,b,&view).code);r->code=e.code;r->bytes=bytes;
 if(r->reading&&!e.code){
  const char *expected=r->index?"new":"old";unsigned *have=&r->f->received[r->index];
  assert(bytes<=3-*have&&!memcmp(view.data,expected+*have,bytes));*have+=bytes;
  if(!bytes)r->f->eof[r->index]=1;
 }
 loop_timer_set(r->f->work,0);
}
static void finish_done(void *arg,struct steer_pv1_error e){struct result *r=arg;assert(++r->calls==1);r->code=e.code;loop_timer_set(r->f->work,0);}
static void start_open(struct fixture *f,unsigned i,struct steer_draft_stream_routes *routes,unsigned metadata){
 struct result *r=&f->opened[i];r->f=f;r->op=steer_draft_stream_route_open(routes,&f->meta[metadata],deadline(),open_done,r);
 pending(r->op);assert(!r->calls);
}
static void start_write(struct fixture *f,unsigned i){
 struct result *r=&f->writes[i];r->f=f;r->buffer=f->out[i];struct steer_pv1_mut_span view;
 assert(!ba->writable(f->host,r->buffer,&view).code);memcpy(view.data,i?"new":"old",3);
 struct steer_pv1_stream_ref s=f->opened[i].stream;r->op=s.api->write(s.handle,r->buffer,0,3,io_done,r);pending(r->op);assert(!r->calls);
}
static void start_read(struct fixture *f,unsigned i){
 struct result *r=&f->reads[i];memset(r,0,sizeof(*r));r->f=f;r->buffer=f->in[i];r->reading=1;r->index=i;
 struct steer_pv1_stream_ref s=f->opened[i].stream;r->op=s.api->read(s.handle,r->buffer,0,16,io_done,r);pending(r->op);assert(!r->calls);
}
static void start_finish(struct fixture *f,unsigned i){
 struct result *r=&f->finishes[i];r->f=f;struct steer_pv1_stream_ref s=f->opened[i].stream;
 r->op=s.api->finish_write(s.handle,finish_done,r);pending(r->op);assert(!r->calls);
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 switch(f->phase){
 case 0:{
  struct steer_pv1_flow_metadata domain=f->meta[0];domain.generation=2;
  denied(steer_draft_stream_route_open(f->blocked,&domain,deadline(),open_done,&f->opened[2]),STEER_PV1_POLICY_DENIED);
  assert(f->block_calls==1&&!steer_draft_resolver_jobs(f->resolver)&&!atomic_load(&f->server.accepted));
  denied(steer_draft_stream_route_open(f->current,&f->meta[0],deadline(),open_done,&f->opened[2]),STEER_PV1_POLICY_DENIED);
  denied(steer_draft_stream_route_open(f->current,&f->meta[1],0,open_done,&f->opened[2]),STEER_PV1_TIMEOUT);
  struct steer_pv1_flow_metadata invalid=f->meta[1];invalid.principal=(struct steer_pv1_principal *)f;
  denied(steer_draft_stream_route_open(f->current,&invalid,deadline(),open_done,&f->opened[2]),STEER_PV1_UNSUPPORTED);
  struct steer_draft_stream_binding bindings[2]={*steer_draft_native_stream_binding(f->backend[1]),*steer_draft_native_stream_binding(f->backend[1])};
  uint32_t refs=steer_draft_binding_references(bindings[0].lease);struct steer_draft_stream_routes *failed=NULL;
  assert(steer_draft_stream_routes_create(loop,2,4,4,bindings,2,select_direct,NULL,NULL,&failed).code==STEER_PV1_INVALID&&!failed);
  assert(steer_draft_binding_references(bindings[0].lease)==refs);
  assert(steer_draft_stream_routes_create(loop,99,4,4,bindings,1,select_direct,NULL,NULL,&failed).code==STEER_PV1_POLICY_DENIED&&!failed);
  struct steer_pv1_stream_backend_api short_api={8,STEER_PV1_STREAM_BACKEND_LAYOUT,NULL};bindings[0].api=&short_api;
  assert(steer_draft_stream_routes_create(loop,2,4,4,bindings,1,select_direct,NULL,NULL,&failed).code==STEER_PV1_UNSUPPORTED&&!failed);
  bindings[0]=*steer_draft_native_stream_binding(f->backend[1]);struct loop *foreign=loop_new();assert(foreign);bindings[0].owner=foreign;
  assert(steer_draft_stream_routes_create(loop,2,4,4,bindings,1,select_direct,NULL,NULL,&failed).code==STEER_PV1_INVALID&&!failed);loop_free(foreign);
  start_open(f,0,f->old,0);start_open(f,1,f->current,1);
  assert(!steer_draft_native_stream_backend_retire(f->backend[0]).code&&!f->finalized[0]);
  assert(steer_draft_native_stream_backend_destroy(f->backend[0]).code==STEER_PV1_POLICY_DENIED);
  denied(steer_draft_stream_route_open(f->old,&f->meta[0],deadline(),open_done,&f->opened[2]),STEER_PV1_POLICY_DENIED);
  /* Every borrowed input may be changed after PENDING; submitted opens retain
   * their validated original domain/generation/identity. */
  memset(f->domain,'x',sizeof(f->domain));memset(f->inbound,'z',sizeof(f->inbound));f->meta[0].generation=999;
  f->phase=1;break;
 }
 case 1:
  if(!f->opened[0].calls||!f->opened[1].calls)return;
  assert(!f->opened[0].code&&!f->opened[1].code&&!f->finalized[0]);
  assert(steer_draft_stream_routes_destroy(f->old).code==STEER_PV1_POLICY_DENIED);
  start_write(f,0);start_write(f,1);f->phase=2;break;
 case 2:
  if(!f->writes[0].calls||!f->writes[1].calls)return;
  for(unsigned i=0;i<2;i++){assert(!f->writes[i].code&&f->writes[i].bytes==3);start_finish(f,i);start_read(f,i);}
  f->phase=3;break;
 case 3:{
  for(unsigned i=0;i<2;i++)if(f->reads[i].calls&&!f->eof[i]){assert(!f->reads[i].code);release(&f->reads[i]);start_read(f,i);}
  if(!f->finishes[0].calls||!f->finishes[1].calls||!f->eof[0]||!f->eof[1])return;
  for(unsigned i=0;i<2;i++){
   assert(!f->finishes[i].code&&f->received[i]==3);struct steer_pv1_stream_ref s=f->opened[i].stream;
   s.api->close(s.handle);s.api->close(s.handle);assert(s.api->release(s.handle).code==STEER_PV1_POLICY_DENIED);
   release(&f->writes[i]);release(&f->finishes[i]);release(&f->reads[i]);assert(!s.api->release(s.handle).code);
  }
  assert(steer_draft_stream_routes_destroy(f->old).code==STEER_PV1_POLICY_DENIED); /* open ref still pins */
  release(&f->opened[0]);release(&f->opened[1]);
  static const uint8_t hold[]="hold.example";f->meta[1].destination.tag=STEER_PV1_ENDPOINT_DOMAIN;
  f->meta[1].destination.address=(struct steer_pv1_span){hold,sizeof(hold)-1};start_open(f,2,f->current,1);
  f->phase=4;break;
 }
 case 4:
  if(!atomic_load_explicit(&f->gate_entered,memory_order_acquire))return;
  f->opened[2].op.operation.api->cancel(f->opened[2].op.operation.handle);f->phase=5;break;
 case 5:
  if(!f->opened[2].calls)return;
  assert(f->opened[2].code==STEER_PV1_CANCELLED&&atomic_load(&f->server.accepted)==2);
  release(&f->opened[2]);
  assert(!steer_draft_stream_routes_destroy(f->old).code);f->old=NULL;
  assert(!steer_draft_stream_routes_destroy(f->current).code);f->current=NULL;
  assert(!steer_draft_stream_routes_destroy(f->blocked).code);f->blocked=NULL;
  assert(!steer_draft_native_stream_backend_retire(f->backend[1]).code);
  assert(!steer_draft_native_stream_backend_retire(f->backend[1]).code&&!f->finalized[1]);
  f->phase=6;break;
 case 6:
  if(!f->finalized[0]||!f->finalized[1])return;
  for(unsigned i=0;i<2;i++)assert(!steer_draft_native_stream_backend_destroy(f->backend[i]).code);
  assert(steer_draft_resolver_jobs(f->resolver)==1);
  assert(steer_draft_resolver_destroy(f->resolver).code==STEER_PV1_POLICY_DENIED);
  assert(!pthread_mutex_lock(&f->gate_mutex));f->gate_release=1;assert(!pthread_cond_signal(&f->gate_cond));assert(!pthread_mutex_unlock(&f->gate_mutex));
  f->phase=7;break;
 case 7:
  if(steer_draft_resolver_jobs(f->resolver)){loop_timer_set(f->work,0);return;}
  assert(!steer_draft_resolver_jobs(f->resolver));
  assert(!steer_draft_resolver_destroy(f->resolver).code);
  assert(!steer_draft_backend_runtime_destroy(f->wrapper).code&&!steer_draft_stream_runtime_destroy(f->native).code);
  assert(atomic_load(&f->server.accepted)==2);f->phase=8;loop_stop(loop,0);break;
 default:assert(0);
 }
}
static void timeout(struct loop *l,struct loop_timer *t,void *arg){(void)l;(void)t;(void)arg;assert(!"generic stream route deadline");}
static void scenario(void){
 struct fixture f={0};struct steer_draft_buffer_limits limits={16384,16,4};struct loop_timer *guard;pthread_t peer;
 f.loop=loop_new();assert(f.loop);f.work=loop_timer_new(f.loop,step,&f);guard=loop_timer_new(f.loop,timeout,NULL);assert(f.work&&guard);
 f.server.listen=socket(AF_INET,SOCK_STREAM,0);f.server.stop=eventfd(0,EFD_CLOEXEC);assert(f.server.listen>=0&&f.server.stop>=0);
 struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 assert(!bind(f.server.listen,(struct sockaddr *)&address,sizeof(address))&&!listen(f.server.listen,16));
 socklen_t length=sizeof(address);assert(!getsockname(f.server.listen,(struct sockaddr *)&address,&length));
 assert(!pthread_create(&peer,NULL,echo_server,&f.server));
 assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,8,32,16384,&f.native).code);
 assert(!steer_draft_backend_runtime_create(f.loop,8,32,16384,&f.wrapper).code);
 assert(!pthread_mutex_init(&f.gate_mutex,NULL)&&!pthread_cond_init(&f.gate_cond,NULL));atomic_init(&f.gate_entered,0);
 f.worker_notify=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);assert(f.worker_notify>=0);
 assert(!loop_fd_add(f.loop,f.worker_notify,EPOLLIN,worker_ready,&f));
 assert(!steer_draft_resolver_create(f.loop,2,8,resolver_backend,&f,&f.resolver).code);
 for(unsigned i=0;i<2;i++){
  f.notice[i].f=&f;f.notice[i].index=i;
  assert(!steer_draft_native_stream_backend_create(f.loop,f.native,f.wrapper,f.resolver,i+1,1,8,128,retired,&f.notice[i],&f.backend[i]).code);
  assert(!ba->allocate(f.host,16,&f.out[i]).code&&!ba->allocate(f.host,16,&f.in[i]).code);
 }
 const struct steer_draft_stream_binding *b0=steer_draft_native_stream_binding(f.backend[0]),*b1=steer_draft_native_stream_binding(f.backend[1]);
 assert(!steer_draft_stream_routes_create(f.loop,1,8,4,b0,1,select_direct,NULL,NULL,&f.old).code);
 assert(!steer_draft_stream_routes_create(f.loop,2,8,4,b1,1,select_direct,NULL,NULL,&f.current).code);
 assert(!steer_draft_stream_routes_create(f.loop,2,8,4,b1,1,select_block,&f,NULL,&f.blocked).code);
 f.ip[0]=127;f.ip[3]=1;memcpy(f.inbound,"lab-inbound",sizeof(f.inbound));memcpy(f.domain,"localhost",sizeof(f.domain));
 for(unsigned i=0;i<2;i++){
  struct steer_pv1_flow_metadata *m=&f.meta[i];m->size=sizeof(*m);m->version=STEER_PV1_DRAFT_LAYOUT;m->generation=i+1;
  m->inbound_id.data=f.inbound;m->inbound_id.len=sizeof(f.inbound);m->flow_class=STEER_PV1_FLOW_STREAM;
  m->source=(struct steer_pv1_endpoint){sizeof(m->source),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{f.ip,4},4242,0};
  m->destination=m->source;m->destination.port=ntohs(address.sin_port);
 }
 f.meta[0].destination.tag=STEER_PV1_ENDPOINT_DOMAIN;f.meta[0].destination.address.data=f.domain;f.meta[0].destination.address.len=sizeof(f.domain);
 loop_timer_set(f.work,0);loop_timer_set(guard,10000);assert(!loop_run(f.loop)&&f.phase==8);
 loop_fd_del(f.loop,f.worker_notify);close(f.worker_notify);assert(!pthread_cond_destroy(&f.gate_cond)&&!pthread_mutex_destroy(&f.gate_mutex));
 uint64_t one=1;assert(write(f.server.stop,&one,sizeof(one))==sizeof(one));assert(!pthread_join(peer,NULL));close(f.server.listen);close(f.server.stop);
 loop_timer_free(f.work);loop_timer_free(guard);for(unsigned i=0;i<2;i++){ba->release(f.host,f.out[i]);ba->release(f.host,f.in[i]);}
 assert(!steer_draft_buffers_destroy(f.host).code);loop_free(f.loop);
}
static void *owner_soak(void *arg){(void)arg;for(unsigned round=0;round<8;round++)scenario();return NULL;}
int main(void){
 ba=steer_draft_buffers_api();scenario();pthread_t owners[4];
 for(unsigned i=0;i<4;i++)assert(!pthread_create(&owners[i],NULL,owner_soak,NULL));
 for(unsigned i=0;i<4;i++)assert(!pthread_join(owners[i],NULL));
 puts("generic origin routes:33 generations pairs/99 opens, real TCP FIN echo, blocked DNS, late-worker cancel/drain on4 owners PASS");return 0;
}
