#define _POSIX_C_SOURCE 200809L
#include "execution_static.h"
#include "ynode.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct fixture {unsigned refs,prepared;};
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;f->refs++;return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(f->refs>1);f->refs--;}
static int options(void *arg,const struct ynode *n){(void)arg;return n&&n->kind==YN_MAP;}
static int direct_validate(void *arg,const struct steer_spec_node_view *node){(void)arg;return node->kind==STEER_SPEC_OUTBOUND&&!strcmp(node->type,"direct");}
static struct steer_pv1_error direct_prepare(void *arg,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,uint64_t deadline,const struct steer_draft_cancel *cancel,void **out){struct fixture *f=arg;(void)node;(void)deps;(void)deadline;(void)cancel;assert(!count);*out=malloc(1);assert(*out);f->prepared++;return (struct steer_pv1_error){0,0};}
static void direct_discard(void *arg,void *state){(void)arg;free(state);}
static struct steer_pv1_error bind_unused(void *arg,void *p,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,const struct steer_spec_execution_owner *owner,struct steer_spec_execution_instance *out){(void)arg;(void)p;(void)node;(void)deps;(void)count;(void)owner;(void)out;assert(!"worker owner bind");return (struct steer_pv1_error){STEER_PV1_INTERNAL,0};}
static void retire_unused(void *arg,struct steer_spec_execution_instance *out){(void)arg;(void)out;assert(!"worker owner retire");}
static struct steer_pv1_error collect_unused(void *arg,struct steer_spec_execution_instance *out){(void)arg;(void)out;assert(!"worker owner collect");return (struct steer_pv1_error){STEER_PV1_INTERNAL,0};}
static struct steer_spec_plan *ready(const char *source){
 struct steer_spec_plan *plan=steer_spec_compile(source,strlen(source),NULL,0);struct steer_spec_summary summary=steer_spec_summary(plan);assert(summary.syntax_valid&&summary.topology_valid&&summary.requirements<16);
 struct steer_spec_capability inventory[16];for(uint32_t i=0;i<summary.requirements;i++){struct steer_spec_requirement_view r;assert(steer_spec_requirement(plan,i,&r));inventory[i]=(struct steer_spec_capability){r.name,STEER_SPEC_READY,options,NULL};}
 struct steer_spec_plan *result=steer_spec_compile(source,strlen(source),inventory,summary.requirements);assert(result&&steer_spec_summary(result).runtime_ready);steer_spec_destroy(plan);return result;
}
static void scenario(void){
 struct fixture f={1,0};struct steer_spec_static_catalogue a={STEER_SPEC_STATIC_LINKED,"test-static-a","provider-a","0.1.0-dev","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","https://fixture.invalid/a","host-a",{&f,retain,release}},b=a;b.origin_id="test-static-b";b.package="provider-b";b.remote_url="https://fixture.invalid/b";b.remote_trust="host-b";
 struct steer_spec_static_module modules[3];struct steer_spec_execution_factory factories[4];
 assert(!steer_spec_static_module_factory(&modules[0],&a,"a",&factories[0]).code);
 assert(!steer_spec_static_module_factory(&modules[1],&a,"a2",&factories[1]).code);
 assert(!steer_spec_static_module_factory(&modules[2],&b,"b",&factories[2]).code);
 static const char *const direct_caps[]={"core.outbound.direct"};factories[3]=(struct steer_spec_execution_factory){.size=sizeof(factories[3]),.version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT,.kind=STEER_SPEC_OUTBOUND,.type="direct",.transport="tcp",.security="none",.variant="default",.stream_provider_id="fixture.direct",.flows=STEER_SPEC_FLOW_STREAM,.capabilities=direct_caps,.capability_count=1,.guard={&f,retain,release},.context=&f,.validate=direct_validate,.prepare=direct_prepare,.discard=direct_discard,.bind=bind_unused,.retire=retire_unused,.collect=collect_unused};
 for(unsigned mode=0;mode<6;mode++){
  char source[4096];const char *url=mode==1?"https://foreign.invalid/a":a.remote_url,*trust=mode==2?"foreign":a.remote_trust,*package=mode==3?a.package:b.package,*version=mode==4?"=9.0.0":"=0.1.0-dev",*alias=mode==5?"unknown":"a";
  int n=snprintf(source,sizeof(source),"{\"version\":3,\"plugin_remotes\":{\"ra\":{\"url\":\"%s\",\"trust\":\"%s\"},\"rb\":{\"url\":\"%s\",\"trust\":\"%s\"}},\"plugins\":{\"%s\":{\"remote\":\"ra\",\"package\":\"provider-a\",\"version\":\"%s\"},\"a2\":{\"remote\":\"ra\",\"package\":\"provider-a\",\"version\":\"=0.1.0-dev\"},\"b\":{\"remote\":\"rb\",\"package\":\"%s\",\"version\":\"=0.1.0-dev\"}},\"inbounds\":{},\"outbounds\":{\"d\":{\"type\":\"direct\",\"flow\":[\"stream\"]}},\"routing\":{\"default\":\"d\",\"rules\":[]}}",url,trust,b.remote_url,b.remote_trust,alias,version,package);assert(n>0&&(size_t)n<sizeof(source));
  /* Deliberately overclaim inventory so executor itself must reject missing or
   * mismatching static identities instead of trusting a fake readiness bit. */
  struct steer_spec_plan *plan=ready(source);struct steer_spec_summary summary=steer_spec_summary(plan);unsigned plugin_views=0;
  for(uint32_t i=0;i<summary.nodes;i++){struct steer_spec_node_view view;assert(steer_spec_node(plan,i,&view));if(view.kind==STEER_SPEC_PLUGIN){assert(view.resolved_remote&&ynode_get(view.resolved_remote,"trust"));plugin_views++;}}assert(plugin_views==3);
  struct steer_spec_execution_limits limits={4,16,1024,4,8,{4,4,2,8,4096,1000000000ull}};struct steer_draft_cancel cancel;atomic_init(&cancel.requested,0);struct steer_spec_execution *execution=NULL;f.prepared=0;
  struct steer_pv1_error result=steer_spec_execution_prepare(&plan,7,100,factories,4,&limits,UINT64_MAX,&cancel,&execution);
  if(!mode){if(result.code)fprintf(stderr,"valid multi-alias prepare error%u\n",result.code);assert(!result.code&&execution&&!plan&&f.prepared==1&&f.refs==5);assert(!steer_spec_execution_destroy_worker(execution).code&&f.refs==1);}
  else{assert(result.code==STEER_PV1_UNSUPPORTED&&!execution&&plan&&!f.prepared&&f.refs==1);steer_spec_destroy(plan);}
 }
 struct steer_spec_static_catalogue invalid=a;invalid.source_sha256="0000000000000000000000000000000000000000000000000000000000000000";assert(steer_spec_static_module_factory(&modules[0],&invalid,"a",&factories[0]).code==STEER_PV1_INVALID);
 assert(!strcmp(a.remote_url,"https://fixture.invalid/a")&&f.refs==1);
}
static void *owner(void *arg){(void)arg;scenario();return NULL;}
int main(void){scenario();pthread_t threads[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,owner,NULL));for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));puts("execution-static: two aliases one package +other package/exact alias/trusted identity/unknown rejection/1+4 owners PASS");return 0;}
