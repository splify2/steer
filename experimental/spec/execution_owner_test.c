#define _GNU_SOURCE
#include "execution_native.h"
#include "../provider/buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_pv1_host *host;
 struct steer_spec_native_services services;struct steer_spec_execution_factory factory;
 struct steer_spec_execution *execution[3];atomic_uint guards;
 struct steer_pv1_flow_metadata flow;uint8_t ip[4];
 struct steer_pv1_stream_ref stream;struct steer_pv1_datagram_ref datagram;
 struct steer_pv1_datagram_association_ref association;
 struct steer_pv1_buffer *buffers[4];struct steer_pv1_async_start ops[4];
 unsigned calls[4],bytes[4],received,udp_checked,phase,drained[3];int tcp,udp;uint16_t tcp_port,udp_port;
};
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static int options(void *a,const struct ynode *n){(void)a;(void)n;return 1;}
struct job {struct fixture *f;unsigned index;int destroy;};
static int reject_validate(void *context,const struct steer_spec_node_view *node){(void)context;(void)node;return 0;}
static struct steer_pv1_error fail_bind(void *context,void *state,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,const struct steer_spec_execution_owner *owner,struct steer_spec_execution_instance *out){
 struct fixture *f=(struct fixture *)((char *)context - offsetof(struct fixture,services));
 struct steer_pv1_error e=f->factory.bind(context,state,node,deps,count,owner,out);assert(!e.code&&out->handle);return (struct steer_pv1_error){STEER_PV1_IO,0};
}
static void *worker(void *arg){
 struct job *j=arg;struct fixture *f=j->f;
 if(j->destroy==1){assert(!steer_spec_execution_destroy_worker(f->execution[j->index]).code);return NULL;}
 const char *source=j->index?"{\"version\":3,\"plugin_remotes\":{},\"plugins\":{},\"inbounds\":{},\"outbounds\":{\"d\":{\"type\":\"direct\",\"flow\":[\"stream\",\"datagram\"]},\"b\":{\"type\":\"block\"}},\"routing\":{\"default\":\"b\",\"rules\":[]}}":
 "{\"version\":3,\"plugin_remotes\":{},\"plugins\":{},\"inbounds\":{},\"outbounds\":{\"d\":{\"type\":\"direct\",\"flow\":[\"stream\",\"datagram\"]},\"b\":{\"type\":\"block\"}},\"routing\":{\"default\":\"b\",\"rules\":["
 "{\"name\":\"blocked\",\"match\":{\"domain_suffix\":[\"blocked.example\"]},\"action\":\"reject\"},"
 "{\"name\":\"domains\",\"match\":{\"domain_suffix\":[\"example\"]},\"outbound\":\"d\"},"
 "{\"name\":\"numeric\",\"match\":{\"flow\":[\"stream\",\"datagram\"],\"cidr\":[\"192.0.2.0/24\",\"127.0.0.0/8\"],\"port\":[\"1024-65534\"],\"protocol\":[\"tcp\",\"udp\"]},\"outbound\":\"d\"},"
 "{\"name\":\"last\",\"match\":{},\"action\":\"reject\"}]}}";
 struct steer_spec_plan *p=steer_spec_compile(source,strlen(source),NULL,0);assert(p);
 struct steer_spec_summary summary=steer_spec_summary(p);if(!summary.syntax_valid||!summary.topology_valid)steer_spec_write_json(p,stderr);assert(summary.syntax_valid&&summary.topology_valid&&summary.requirements<32);
 struct steer_spec_capability inventory[32]={0};
 for(uint32_t i=0;i<summary.requirements;i++){struct steer_spec_requirement_view v;assert(steer_spec_requirement(p,i,&v));inventory[i]=(struct steer_spec_capability){v.name,STEER_SPEC_READY,options,NULL};}
 struct steer_spec_plan *ready=steer_spec_compile(source,strlen(source),inventory,summary.requirements);assert(ready&&steer_spec_summary(ready).runtime_ready);steer_spec_destroy(p);
 struct steer_spec_execution_limits limits={8,32,1024,4,16,{4,4,2,16,4096,1000000000ull}};
 struct steer_draft_cancel cancel;atomic_init(&cancel.requested,0);
 struct steer_spec_execution_factory selected=f->factory;
 if(j->destroy==2){selected.validate=reject_validate;struct steer_spec_execution *none=NULL;assert(steer_spec_execution_prepare(&ready,99,100,&selected,1,&limits,deadline(),&cancel,&none).code==STEER_PV1_UNSUPPORTED&&ready&&!none);steer_spec_destroy(ready);return NULL;}
 if(j->index==2)selected.bind=fail_bind;
 assert(!steer_spec_execution_prepare(&ready,j->index+1,100,&selected,1,&limits,deadline(),&cancel,&f->execution[j->index]).code&&!ready);return NULL;
}
static void run_worker(struct fixture *f,unsigned i,int destroy){struct job j={f,i,destroy};pthread_t t;assert(!pthread_create(&t,NULL,worker,&j));assert(!pthread_join(t,NULL));}
static void pending(struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING&&!a.error.code&&a.operation.handle);}
static void free_op(struct fixture *f,unsigned i){assert(f->calls[i]);f->ops[i].operation.api->release(f->ops[i].operation.handle);memset(&f->ops[i],0,sizeof(f->ops[i]));f->calls[i]=0;}
static void stream_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref r,const struct steer_pv1_endpoint *b,const struct steer_pv1_endpoint *p,const struct steer_pv1_stream_open_diagnostic *d){struct fixture *f=arg;(void)d;if(e.code)fprintf(stderr,"stream open error %u\n",e.code);(void)b;(void)p;assert(!e.code&&r.handle);f->stream=r;f->calls[0]++;wake(f);}
static void udp_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_datagram_ref r,const struct steer_pv1_endpoint *b,const struct steer_pv1_endpoint *p){struct fixture *f=arg;assert(!e.code&&r.handle&&b&&p);f->datagram=r;f->calls[1]++;wake(f);}
struct io_context {struct fixture *f;unsigned index;};
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t n){struct io_context *c=arg;assert(!e.code&&b==c->f->buffers[c->index]);c->f->bytes[c->index]=n;c->f->calls[c->index]++;wake(c->f);}
static void timeout(struct loop *l,struct loop_timer *t,void *arg){(void)l;(void)t;(void)arg;assert(!"executor owner watchdog");}
static void step(struct loop *l,struct loop_timer *t,void *arg){
 struct fixture *f=arg;(void)t;static const char payload[]="generation-owned";
 const struct steer_pv1_buffer_api *ba=steer_draft_buffers_api();
 static _Thread_local struct io_context io[4];for(unsigned i=0;i<4;i++)io[i]=(struct io_context){f,i};
 if(f->phase==0){
  uint32_t progress;assert(!steer_spec_execution_bind_step(f->execution[0],l,f->host,wake,f,&progress).code&&progress==STEER_SPEC_EXECUTION_READY);
  assert(!steer_spec_execution_publish(f->execution[0]).code);
  f->flow.flow_class=STEER_PV1_FLOW_STREAM;f->flow.destination.port=f->tcp_port;
  /* Ordered match: suffix boundary is policy, not a DNS attempt. An allowed
   * domain reaches truthful native no-resolver capability rejection instead. */
  struct steer_pv1_flow_metadata check=f->flow;check.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;
  static const uint8_t blocked[]="sub.blocked.example",boundary[]="badblocked.example";
  check.destination.address=(struct steer_pv1_span){blocked,sizeof(blocked)-1};
  struct steer_pv1_async_start denied=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[0]),&check,deadline(),stream_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_POLICY_DENIED);
  check.destination.address=(struct steer_pv1_span){boundary,sizeof(boundary)-1};
  denied=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[0]),&check,deadline(),stream_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_UNSUPPORTED);
  check=f->flow;static const uint8_t outside[]={198,51,100,1};check.destination.address=(struct steer_pv1_span){outside,4};
  denied=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[0]),&check,deadline(),stream_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_POLICY_DENIED);
  check=f->flow;check.destination.port=1;
  denied=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[0]),&check,deadline(),stream_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_POLICY_DENIED);
  f->ops[0]=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[0]),&f->flow,deadline(),stream_opened,f);pending(f->ops[0]);
  f->flow.flow_class=STEER_PV1_FLOW_DATAGRAM;f->flow.destination.port=f->udp_port;
  const struct steer_pv1_datagram_route_api *api=steer_draft_datagram_router_api();
  assert(!api->create(steer_spec_execution_datagrams(f->execution[0]),&f->flow,&f->association).code);
  f->ops[1]=api->open_target(f->association.handle,&f->flow.destination,deadline(),udp_opened,f);pending(f->ops[1]);f->phase=1;return;
 }
 if(f->phase==1){
  if(!f->calls[0]||!f->calls[1])return;
  free_op(f,0);free_op(f,1);
  /* Failed replacement preparation and partial owner bind cannot publish or
   * disturb the already-open old-generation TCP/UDP refs. */
  run_worker(f,0,2);run_worker(f,2,0);
  uint32_t progress;assert(steer_spec_execution_bind_step(f->execution[2],l,f->host,wake,f,&progress).code==STEER_PV1_IO);
  assert(!steer_spec_execution_streams(f->execution[2])&&!steer_spec_execution_datagrams(f->execution[2]));
  assert(!steer_spec_execution_bind_step(f->execution[1],l,f->host,wake,f,&progress).code&&progress==STEER_SPEC_EXECUTION_READY);
  assert(!steer_spec_execution_publish(f->execution[1]).code);steer_spec_execution_retire(f->execution[0]);
  f->flow.generation=2;f->flow.flow_class=STEER_PV1_FLOW_STREAM;f->flow.destination.port=f->tcp_port;
  struct steer_pv1_async_start denied=steer_draft_stream_route_open(steer_spec_execution_streams(f->execution[1]),&f->flow,deadline(),stream_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_POLICY_DENIED);
  f->flow.flow_class=STEER_PV1_FLOW_DATAGRAM;f->flow.destination.port=f->udp_port;
  struct steer_pv1_datagram_association_ref blocked_association;
  const struct steer_pv1_datagram_route_api *udp_api=steer_draft_datagram_router_api();
  assert(!udp_api->create(steer_spec_execution_datagrams(f->execution[1]),&f->flow,&blocked_association).code);
  denied=udp_api->open_target(blocked_association.handle,&f->flow.destination,deadline(),udp_opened,f);
  assert(denied.disposition==STEER_PV1_REJECTED&&denied.error.code==STEER_PV1_POLICY_DENIED);
  udp_api->close(blocked_association.handle);assert(!udp_api->release(blocked_association.handle).code);
  for(unsigned i=0;i<2;i++){struct steer_pv1_mut_span v;assert(!ba->writable(f->host,f->buffers[i],&v).code);memcpy(v.data,payload,sizeof(payload));}
  f->ops[0]=f->stream.api->write(f->stream.handle,f->buffers[0],0,sizeof(payload),io_done,&io[0]);pending(f->ops[0]);
  f->ops[1]=f->datagram.api->send(f->datagram.handle,f->buffers[1],0,sizeof(payload),deadline(),io_done,&io[1]);pending(f->ops[1]);f->phase=2;return;
 }
 if(f->phase==2){
  if(!f->calls[0]||!f->calls[1])return;
  assert(f->bytes[0]==sizeof(payload)&&f->bytes[1]==sizeof(payload));free_op(f,0);free_op(f,1);
  f->ops[2]=f->stream.api->read(f->stream.handle,f->buffers[2],0,64,io_done,&io[2]);pending(f->ops[2]);
  f->ops[3]=f->datagram.api->receive(f->datagram.handle,f->buffers[3],0,64,deadline(),io_done,&io[3]);pending(f->ops[3]);f->phase=3;return;
 }
 if(f->phase==3){
  if(f->calls[2]){
   struct steer_pv1_mut_span v;assert(f->bytes[2]&&f->bytes[2]<=sizeof(payload)-f->received);
   assert(!ba->writable(f->host,f->buffers[2],&v).code&&!memcmp(v.data,payload+f->received,f->bytes[2]));
   f->received+=f->bytes[2];free_op(f,2);
   if(f->received<sizeof(payload)){f->ops[2]=f->stream.api->read(f->stream.handle,f->buffers[2],0,64,io_done,&io[2]);pending(f->ops[2]);}
  }
  if(f->calls[3]){struct steer_pv1_mut_span v;assert(f->bytes[3]==sizeof(payload)&&!ba->writable(f->host,f->buffers[3],&v).code&&!memcmp(v.data,payload,sizeof(payload)));free_op(f,3);f->udp_checked=1;}
  if(f->received<sizeof(payload)||!f->udp_checked)return;
  f->stream.api->close(f->stream.handle);assert(!f->stream.api->release(f->stream.handle).code);
  f->datagram.api->close(f->datagram.handle);assert(!f->datagram.api->release(f->datagram.handle).code);
  f->association.api->close(f->association.handle);assert(!f->association.api->release(f->association.handle).code);
  steer_spec_execution_retire(f->execution[1]);f->phase=4;
 }
 if(f->phase==4){
  for(unsigned i=0;i<3;i++)if(!f->drained[i]){uint32_t progress;assert(!steer_spec_execution_collect_step(f->execution[i],&progress).code);if(progress==STEER_SPEC_EXECUTION_READY)f->drained[i]=1;}
  if(f->drained[0]&&f->drained[1]&&f->drained[2]){f->phase=5;loop_stop(l,0);}
 }
}
static int bound_socket(int type,uint16_t *port){int fd=socket(AF_INET,type,0);assert(fd>=0);struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};assert(!bind(fd,(void *)&a,sizeof(a)));socklen_t n=sizeof(a);assert(!getsockname(fd,(void *)&a,&n));*port=ntohs(a.sin_port);return fd;}
static void *tcp_peer(void *arg){
 struct fixture *f=arg;int fd=accept(f->tcp,NULL,NULL);assert(fd>=0);char b[17];size_t have=0,sent=0;
 while(have<sizeof(b)){ssize_t n=recv(fd,b+have,sizeof(b)-have,0);assert(n>0);have+=(size_t)n;}
 while(sent<have){ssize_t n=send(fd,b+sent,have-sent,MSG_NOSIGNAL);assert(n>0);sent+=(size_t)n;}
 close(fd);return NULL;
}
static void *udp_peer(void *arg){struct fixture *f=arg;char b[64];struct sockaddr_in a;socklen_t len=sizeof(a);ssize_t n=recvfrom(f->udp,b,sizeof(b),0,(void *)&a,&len);assert(n==17&&sendto(f->udp,b,(size_t)n,0,(void *)&a,len)==n);return NULL;}
static void scenario(void){
 struct fixture f={0};atomic_init(&f.guards,1);f.loop=loop_new();assert(f.loop);f.work=loop_timer_new(f.loop,step,&f);struct loop_timer *guard=loop_timer_new(f.loop,timeout,NULL);assert(f.work&&guard);
 struct steer_draft_buffer_limits limits={16384,16,8};assert(!steer_draft_buffers_create(&limits,NULL,&f.host).code);
 f.services.owner=f.loop;f.services.max_operations=16;f.services.max_references=128;
 assert(!steer_draft_stream_runtime_create(f.loop,f.host,8,32,16384,&f.services.streams).code);
 assert(!steer_draft_backend_runtime_create(f.loop,8,32,16384,&f.services.stream_refs).code);
 assert(!steer_draft_datagram_runtime_create(f.loop,f.host,8,32,16384,&f.services.datagrams).code);
 struct steer_spec_execution_guard module={&f,retain,release};assert(!steer_spec_native_factory(&f.services,&module,&f.factory).code);
 run_worker(&f,0,0);run_worker(&f,1,0);assert(atomic_load(&f.guards)==3);
 f.tcp=bound_socket(SOCK_STREAM,&f.tcp_port);assert(!listen(f.tcp,4));f.udp=bound_socket(SOCK_DGRAM,&f.udp_port);pthread_t tcp,udp;assert(!pthread_create(&tcp,NULL,tcp_peer,&f)&&!pthread_create(&udp,NULL,udp_peer,&f));
 f.ip[0]=127;f.ip[3]=1;f.flow=(struct steer_pv1_flow_metadata){.size=sizeof(f.flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=1,.inbound_id={(const uint8_t *)"actual",6}};
 f.flow.source=(struct steer_pv1_endpoint){sizeof(f.flow.source),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{f.ip,4},4242,0};f.flow.destination=f.flow.source;
 for(unsigned i=0;i<4;i++)assert(!steer_draft_buffers_api()->allocate(f.host,64,&f.buffers[i]).code);
 loop_timer_set(f.work,0);loop_timer_set(guard,10000);assert(!loop_run(f.loop)&&f.phase==5);
 assert(!pthread_join(tcp,NULL)&&!pthread_join(udp,NULL));close(f.tcp);close(f.udp);
 for(unsigned i=0;i<3;i++)run_worker(&f,i,1);
 assert(atomic_load(&f.guards)==1);
 assert(!steer_draft_datagram_runtime_destroy(f.services.datagrams).code);assert(!steer_draft_backend_runtime_destroy(f.services.stream_refs).code);assert(!steer_draft_stream_runtime_destroy(f.services.streams).code);
 for(unsigned i=0;i<4;i++)steer_draft_buffers_api()->release(f.host,f.buffers[i]);
 assert(!steer_draft_buffers_destroy(f.host).code);loop_timer_free(f.work);loop_timer_free(guard);loop_free(f.loop);
}
static void *owner(void *unused){(void)unused;scenario();return NULL;}
int main(void){scenario();pthread_t owners[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&owners[i],NULL,owner,NULL));for(unsigned i=0;i<4;i++)assert(!pthread_join(owners[i],NULL));puts("execution-owner: actual TCP/UDP old-generation drain, failed prepare/partial bind, new block, 1+4 owners PASS");return 0;}
