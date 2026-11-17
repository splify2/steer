#define _POSIX_C_SOURCE 200809L
#include "execution.h"
#include "ynode.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
struct context {
 pthread_t worker;unsigned guards,expected_guards,retains,releases,retain_attempts,validated,prepared,live,discarded;
 int mode,in_callback;char log[32];size_t length;struct steer_draft_cancel cancel;
 pthread_mutex_t mutex;pthread_cond_t condition;int entered;
};
struct prepared {struct context *context;char id;};
static uint64_t now_ns(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static void event(struct context *c,char ch){assert(c->length<sizeof(c->log)-1);c->log[c->length++]=ch;c->log[c->length]=0;}
static struct steer_pv1_error retain(void *arg){struct context *c=arg;assert(pthread_equal(c->worker,pthread_self())&&!c->in_callback);
 c->retain_attempts++;if(c->mode==9&&c->retain_attempts==3)return error(STEER_PV1_IO);
 c->retains++;c->guards++;return error(0);}
static void release(void *arg){struct context *c=arg;assert(pthread_equal(c->worker,pthread_self())&&c->guards&&!c->in_callback&&!c->live);c->guards--;c->releases++;}
static int validate(void *arg,const struct steer_spec_node_view *n){
 struct context *c=arg;assert(c->guards==c->expected_guards&&pthread_equal(c->worker,pthread_self()));c->validated++;
 return !(c->mode==6&&!strcmp(n->id,"x"));
}
static struct steer_pv1_error prepare(void *arg,const struct steer_spec_node_view *n,
 const struct steer_spec_execution_dependency *deps,uint32_t count,uint64_t deadline,
 const struct steer_draft_cancel *cancel,void **out){
 struct context *c=arg;assert(c->guards==c->expected_guards&&pthread_equal(c->worker,pthread_self())&&!c->in_callback);c->in_callback=1;
 assert(!atomic_load(&cancel->requested));
 if(c->mode==17&&!strcmp(n->id,"x")){event(c,'X');*out=NULL;c->in_callback=0;return error(0);}
 struct prepared *p=calloc(1,sizeof(*p));assert(p);p->context=c;p->id=n->id[0];*out=p;c->prepared++;c->live++;
 event(c,(char)(p->id-'a'+'A'));
 if(p->id=='x'){
  unsigned shared=0;const void *secret=NULL;assert(count==4);
  for(uint32_t i=0;i<count;i++){
   assert(deps[i].edge.construction_dependency&&deps[i].prepared&&!deps[i].bound);
   if(deps[i].target.kind==STEER_SPEC_SECRET){if(secret)assert(secret==deps[i].prepared);secret=deps[i].prepared;shared++;}
  }
  assert(shared==2);
  if(c->mode==3){
   struct timespec until;assert(!clock_gettime(CLOCK_REALTIME,&until));until.tv_sec+=5;
   assert(!pthread_mutex_lock(&c->mutex));c->entered=1;assert(!pthread_cond_signal(&c->condition));
   while(!atomic_load_explicit(&c->cancel.requested,memory_order_acquire))assert(!pthread_cond_timedwait(&c->condition,&c->mutex,&until));
   assert(!pthread_mutex_unlock(&c->mutex));
  }
  if(c->mode==4){struct timespec t={(time_t)(deadline/1000000000ull),(long)(deadline%1000000000ull)};assert(!clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL));}
 }
 c->in_callback=0;
 return error((c->mode==1&&p->id=='x')||(c->mode==2&&p->id=='s')?STEER_PV1_IO:0);
}
static void discard(void *arg,void *state){
 struct context *c=arg;struct prepared *p=state;assert(c->guards==c->expected_guards&&!c->in_callback&&pthread_equal(c->worker,pthread_self()));
 assert(p->context==c&&c->live);c->in_callback=1;event(c,p->id);c->live--;c->discarded++;free(p);c->in_callback=0;
}
static struct steer_pv1_error bind_unused(void *a,void *p,const struct steer_spec_node_view *n,
 const struct steer_spec_execution_dependency *d,uint32_t count,const struct steer_spec_execution_owner *owner,struct steer_spec_execution_instance *out){
 (void)a;(void)p;(void)n;(void)d;(void)count;(void)owner;(void)out;assert(!"worker called owner bind");return error(STEER_PV1_INTERNAL);
}
static void retire_unused(void *a,struct steer_spec_execution_instance *out){(void)a;(void)out;assert(!"worker called owner retire");}
static struct steer_pv1_error collect_unused(void *a,struct steer_spec_execution_instance *out){(void)a;(void)out;assert(!"worker called owner collect");return error(STEER_PV1_INTERNAL);}
static int inventory_options(void *arg,const struct ynode *options){(void)arg;return options&&options->kind==YN_MAP;}
static struct steer_spec_plan *ready_source(const char *source){
 struct steer_spec_plan *p=steer_spec_compile(source,strlen(source),NULL,0);assert(p);
 struct steer_spec_summary s=steer_spec_summary(p);assert(s.syntax_valid&&s.topology_valid&&s.requirements<32);
 struct steer_spec_capability inventory[32]={0};
 for(uint32_t i=0;i<s.requirements;i++){
  struct steer_spec_requirement_view v;assert(steer_spec_requirement(p,i,&v));
  inventory[i]=(struct steer_spec_capability){v.name,STEER_SPEC_READY,inventory_options,NULL};
 }
 struct steer_spec_plan *ready=steer_spec_compile(source,strlen(source),inventory,s.requirements);assert(ready&&steer_spec_summary(ready).runtime_ready);
 steer_spec_destroy(p);return ready;
}
static struct steer_spec_plan *plan(int unsupported){
 const char *source="{\"version\":3,\"plugin_remotes\":{\"official\":{\"url\":\"https://example.invalid\",\"trust\":\"root\"}},"
  "\"plugins\":{\"p\":{\"remote\":\"official\",\"package\":\"fixture\",\"version\":\"^1.0.0\"}},\"inbounds\":{},"
  "\"secrets\":{\"s\":{\"source\":\"env\",\"name\":\"EXAMPLE_SECRET\"}},"
  "\"outbounds\":{\"b\":{\"type\":\"direct\",\"flow\":[\"stream\",\"datagram\"]},"
  "\"x\":{\"plugin\":\"opaque:p\",\"flow\":[\"stream\",\"datagram\"],\"transport\":{\"type\":\"udp\"},"
  "\"options\":{\"first\":{\"secret\":\"s\"},\"second\":{\"secret\":\"s\"}},\"detour\":\"b\"}},"
  "\"routing\":{\"default\":\"x\",\"rules\":[]}}";
 char changed[4096];assert(strlen(source)<sizeof(changed));strcpy(changed,source);
 if(unsupported){char *rules=strstr(changed,"\"rules\":[]");assert(rules);strcpy(rules,"\"rules\":[{\"name\":\"network\",\"match\":{\"network_type\":[\"wifi\"]},\"outbound\":\"x\"}]}}");}
 return ready_source(changed);
}
static void *cancel_worker(void *arg){
 struct context *c=arg;struct timespec until;assert(!clock_gettime(CLOCK_REALTIME,&until));until.tv_sec+=5;
 assert(!pthread_mutex_lock(&c->mutex));
 while(!c->entered)assert(!pthread_cond_timedwait(&c->condition,&c->mutex,&until));
 atomic_store_explicit(&c->cancel.requested,1,memory_order_release);assert(!pthread_cond_signal(&c->condition));
 assert(!pthread_mutex_unlock(&c->mutex));return NULL;
}
static void scenario(int mode){
 struct context c={0};c.worker=pthread_self();c.mode=mode;c.expected_guards=4;atomic_init(&c.cancel.requested,mode==7);
 static const char *const plugin_caps[]={"plugin.lock.p"},*const direct_caps[]={"core.outbound.direct"},*const secret_caps[]={"core.secret.env"};
 static const char *const opaque_caps[]={"provider.opaque:p/outbound/stream/udp/none/default",
  "provider.opaque:p/outbound/datagram/udp/none/default","core.transport.udp"};
 struct steer_spec_execution_factory factories[4]={0};
 for(unsigned i=0;i<4;i++){
  factories[i].size=sizeof(factories[i]);factories[i].version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT;
  factories[i].transport="tcp";factories[i].security="none";factories[i].variant="default";
  factories[i].context=&c;factories[i].guard=(struct steer_spec_execution_guard){&c,retain,release};
  factories[i].validate=validate;factories[i].prepare=prepare;factories[i].discard=discard;
  factories[i].bind=bind_unused;factories[i].retire=retire_unused;factories[i].collect=collect_unused;
 }
 factories[0].kind=STEER_SPEC_PLUGIN;factories[0].type="";factories[0].capabilities=plugin_caps;factories[0].capability_count=1;
 factories[1].kind=STEER_SPEC_OUTBOUND;factories[1].type="direct";factories[1].flows=3;factories[1].capabilities=direct_caps;factories[1].capability_count=1;
 factories[1].stream_provider_id="native.stream";factories[1].datagram_provider_id="native.udp";
 factories[2].kind=STEER_SPEC_SECRET;factories[2].type="env";factories[2].capabilities=secret_caps;factories[2].capability_count=1;
 factories[3].kind=STEER_SPEC_OUTBOUND;factories[3].provider="opaque:p";factories[3].flows=3;factories[3].transport="udp";
 factories[3].capabilities=opaque_caps;factories[3].capability_count=3;
 factories[3].stream_provider_id="opaque.stream";factories[3].datagram_provider_id="opaque.udp";
 if(mode==10)factories[3].flows=STEER_SPEC_FLOW_STREAM;
 if(mode==11)factories[3].transport="tcp";
 if(mode==12)factories[3].security="tls";
 if(mode==13)factories[3].variant="other";
 if(mode==14)factories[3].capability_count=2;
 if(mode==15)factories[0].type=NULL;
 struct steer_spec_plan *p=plan(mode==5),*original=p;struct steer_spec_execution *execution=NULL;
 struct steer_spec_execution_limits limits={16,64,4096,8,16,{8,16,4,16,4096,1000000000ull}};
 if(mode==16)limits.datagrams.max_operations=0;
 pthread_t canceller;
 if(mode==3){assert(!pthread_mutex_init(&c.mutex,NULL));assert(!pthread_cond_init(&c.condition,NULL));assert(!pthread_create(&canceller,NULL,cancel_worker,&c));}
 uint64_t deadline=mode==8?now_ns()-1:now_ns()+(mode==4?1000000000ull:5000000000ull);
 struct steer_pv1_error e=steer_spec_execution_prepare(&p,9,100,factories,4,&limits,deadline,&c.cancel,&execution);
 if(mode==3){assert(!pthread_join(canceller,NULL));assert(!pthread_cond_destroy(&c.condition));assert(!pthread_mutex_destroy(&c.mutex));}
 if(!mode){
  assert(!e.code&&!p&&execution);assert(!strcmp(c.log,"PBSX")&&c.live==4&&c.guards==4);
  assert(!steer_spec_execution_destroy_worker(execution).code);assert(!strcmp(c.log,"PBSXxsbp"));
 }else{
  uint32_t code=mode==1||mode==2||mode==9?STEER_PV1_IO:mode==3||mode==7?STEER_PV1_CANCELLED:
   mode==4||mode==8?STEER_PV1_TIMEOUT:mode==15||mode==16?STEER_PV1_INVALID:
   mode==17?STEER_PV1_PROTOCOL:STEER_PV1_UNSUPPORTED;
  assert(e.code==code&&p==original&&!execution);steer_spec_destroy(p);
  if(mode==1||mode==3||mode==4)assert(!strcmp(c.log,"PBSXxsbp"));
  if(mode==2)assert(!strcmp(c.log,"PBSsbp"));
  if(mode>=5&&mode!=17)assert(!c.prepared&&!c.live);
  if(mode==17)assert(!strcmp(c.log,"PBSXsbp")&&c.prepared==3);
 }
 assert(!c.live&&!c.guards&&c.retains==c.releases&&c.prepared==c.discarded&&!c.in_callback);
 if(mode==5)assert(!c.validated);
}
static void requirement_owner_case(int nested){
 const char *prefix="{\"version\":3,\"plugin_remotes\":{\"official\":{\"url\":\"https://example.invalid\",\"trust\":\"root\"}},"
  "\"plugins\":{\"p\":{\"remote\":\"official\",\"package\":\"fixture\",\"version\":\"^1.0.0\"}},\"inbounds\":{},";
 char source[4096];
 snprintf(source,sizeof(source),"%s%s",prefix,nested?
  "\"outbounds\":{\"a\":{\"plugin\":\"first:p\",\"security\":{\"type\":\"tls\",\"verify\":false},\"options\":{}},"
  "\"a.security\":{\"plugin\":\"second:p\",\"security\":{\"type\":\"none\"},\"options\":{}}},\"routing\":{\"default\":\"a\",\"rules\":[]}}":
  "\"outbounds\":{\"a\":{\"plugin\":\"first:p\",\"transport\":{\"type\":\"udp\"},\"options\":{}},"
  "\"a.b\":{\"plugin\":\"second:p\",\"transport\":{\"type\":\"udp\"},\"options\":{}}},\"routing\":{\"default\":\"a.b\",\"rules\":[]}}");
 struct steer_spec_plan *p=ready_source(source),*original=p;
 const char *missing=nested?"core.security.insecure.authorized":"core.transport.udp";
 const char *owner=nested?"a":"a.b";unsigned explicit_owner=0;
 struct steer_spec_summary summary=steer_spec_summary(p);
 for(uint32_t i=0;i<summary.requirements;i++){
  struct steer_spec_requirement_view r;assert(steer_spec_requirement(p,i,&r));
  if(!strcmp(r.name,missing)&&r.owner_node!=UINT32_MAX){
   struct steer_spec_node_view n;assert(steer_spec_node(p,r.owner_node,&n));if(!strcmp(n.id,owner))explicit_owner++;
  }
 }
 assert(explicit_owner==1);
 struct context c={0};c.worker=pthread_self();c.mode=20;c.expected_guards=3;atomic_init(&c.cancel.requested,0);
 static const char *const plugin[]={"plugin.lock.p"};
 static const char *const first_udp[]={"provider.first:p/outbound/stream/udp/none/default","core.transport.udp"};
 static const char *const second_udp[]={"provider.second:p/outbound/stream/udp/none/default"};
 static const char *const first_tls[]={"provider.first:p/outbound/stream/tcp/tls/default","core.security.tls"};
 static const char *const second_none[]={"provider.second:p/outbound/stream/tcp/none/default","core.security.none","core.security.insecure.authorized"};
 struct steer_spec_execution_factory factories[3]={0};
 for(unsigned i=0;i<3;i++){
  factories[i].size=sizeof(factories[i]);factories[i].version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT;
  factories[i].transport=nested||!i?"tcp":"udp";factories[i].security=nested&&i==1?"tls":"none";factories[i].variant="default";
  factories[i].context=&c;factories[i].guard=(struct steer_spec_execution_guard){&c,retain,release};
  factories[i].validate=validate;factories[i].prepare=prepare;factories[i].discard=discard;
  factories[i].bind=bind_unused;factories[i].retire=retire_unused;factories[i].collect=collect_unused;
 }
 factories[0].kind=STEER_SPEC_PLUGIN;factories[0].type="";factories[0].capabilities=plugin;factories[0].capability_count=1;
 for(unsigned i=1;i<3;i++){factories[i].kind=STEER_SPEC_OUTBOUND;factories[i].provider=i==1?"first:p":"second:p";
  factories[i].flows=STEER_SPEC_FLOW_STREAM;factories[i].stream_provider_id=i==1?"first.stream":"second.stream";}
 factories[1].capabilities=nested?first_tls:first_udp;factories[1].capability_count=2;
 factories[2].capabilities=nested?second_none:second_udp;factories[2].capability_count=nested?3:1;
 struct steer_spec_execution_limits limits={16,64,4096,8,16,{8,16,4,16,4096,1000000000ull}};
 struct steer_spec_execution *execution=NULL;
 assert(steer_spec_execution_prepare(&p,9,100,factories,3,&limits,now_ns()+5000000000ull,&c.cancel,&execution).code==STEER_PV1_UNSUPPORTED);
 assert(p==original&&!execution&&!c.prepared&&!c.guards&&c.retains==c.releases);steer_spec_destroy(p);
}
static void *worker(void *arg){(void)arg;for(int mode=0;mode<18;mode++)scenario(mode);requirement_owner_case(0);requirement_owner_case(1);return NULL;}
int main(int argc,char **argv){
 if(argc>1){requirement_owner_case(!strcmp(argv[1],"nested"));puts("exact requirement owner PASS");return 0;}
 pthread_t one;assert(!pthread_create(&one,NULL,worker,NULL));assert(!pthread_join(one,NULL));
 pthread_t several[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&several[i],NULL,worker,NULL));
 for(unsigned i=0;i<4;i++)assert(!pthread_join(several[i],NULL));
 puts("spec prepare: exact factories/shared secret/DAG/reverse worker cleanup/partial failure/cancel/deadline/guards on1+4 workers PASS");return 0;
}
