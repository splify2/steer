#define _GNU_SOURCE
#include "execution_prepare_async.h"
#include "../provider/buffers.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
struct fixture;
struct probe_context {struct fixture *f;unsigned index;};
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;
 struct steer_draft_host_job *prepare_job,*probe_jobs[2],*dispose_job;struct steer_spec_execution *execution;
 struct steer_spec_execution_factory factory;struct steer_pv1_host *host;
 pthread_mutex_t mutex;pthread_cond_t condition;unsigned entered,allow;int gate;unsigned mode;struct probe_context probes[2];pthread_t probe_thread[2];
 atomic_uint guards,prepared,discarded;unsigned prepared_done,probe_done,dispose_done,phase,drained;
 pthread_t prepare_thread;
};
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static int validate(void *arg,const struct steer_spec_node_view *node){(void)arg;return node->kind==STEER_SPEC_OUTBOUND&&!strcmp(node->type,"direct");}
static struct steer_pv1_error prepare(void *arg,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,uint64_t until,const struct steer_draft_cancel *cancel,void **out){
 struct fixture *f=arg;(void)node;(void)deps;(void)until;assert(!count&&!atomic_load(&cancel->requested));f->prepare_thread=pthread_self();*out=malloc(1);assert(*out);atomic_fetch_add(&f->prepared,1);return (struct steer_pv1_error){0,0};
}
static void discard(void *arg,void *state){struct fixture *f=arg;assert(state);if(f->mode==2)assert(!pthread_equal(f->prepare_thread,pthread_self()));free(state);atomic_fetch_add(&f->discarded,1);}
static struct steer_pv1_error bind_unused(void *a,void *p,const struct steer_spec_node_view *n,const struct steer_spec_execution_dependency *d,uint32_t count,const struct steer_spec_execution_owner *o,struct steer_spec_execution_instance *out){(void)a;(void)p;(void)n;(void)d;(void)count;(void)o;(void)out;assert(!"cancelled prepared execution bound");return (struct steer_pv1_error){STEER_PV1_INTERNAL,0};}
static void retire_unused(void *arg,struct steer_spec_execution_instance *instance){(void)arg;(void)instance;assert(!"unbound instance retired");}
static struct steer_pv1_error collect_unused(void *arg,struct steer_spec_execution_instance *instance){(void)arg;(void)instance;assert(!"unbound instance collected");return (struct steer_pv1_error){STEER_PV1_INTERNAL,0};}
static struct steer_draft_host_work_result probe(void *arg,const void *input,size_t length,uint64_t until,const struct steer_draft_cancel *cancel){
 struct probe_context *context=arg;struct fixture *f=context->f;unsigned bit=1u<<context->index;(void)input;(void)length;(void)until;(void)cancel;
 if(f->mode==1)assert(pthread_equal(f->prepare_thread,pthread_self())&&atomic_load(&f->prepared)==1);
 pthread_mutex_lock(&f->mutex);f->probe_thread[context->index]=pthread_self();f->entered|=bit;pthread_cond_signal(&f->condition);
 uint64_t one=1;assert(write(f->gate,&one,sizeof(one))==sizeof(one));
 while(!(f->allow&bit))pthread_cond_wait(&f->condition,&f->mutex);
 pthread_mutex_unlock(&f->mutex);return (struct steer_draft_host_work_result){{0,0},NULL,0};
}
static void prepared(void *arg,struct steer_pv1_error e,struct steer_spec_execution *execution){
 struct fixture *f=arg;assert(++f->prepared_done==1&&e.code==(f->mode==1?STEER_PV1_CANCELLED:STEER_PV1_OK)&&execution);f->execution=execution;
 assert(!steer_spec_execution_streams(execution)&&!steer_spec_execution_datagrams(execution));
 assert(steer_spec_execution_publish(execution).code==STEER_PV1_POLICY_DENIED);
 if(f->mode==1){uint32_t progress;assert(steer_spec_execution_bind_step(execution,f->loop,f->host,wake,f,&progress).code==STEER_PV1_POLICY_DENIED);}
 assert(steer_draft_host_job_release(f->prepare_job).code==STEER_PV1_POLICY_DENIED);wake(f);
}
static void probed(void *arg,struct steer_draft_host_work_result result){struct probe_context *context=arg;struct fixture *f=context->f;assert(!result.error.code&&!result.value&&!result.worker_flags);f->probe_done|=1u<<context->index;wake(f);}
static struct steer_draft_host_work_result dispose(void *arg,const void *input,size_t length,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)input;(void)length;(void)until;(void)cancel;assert(!steer_spec_execution_destroy_worker(f->execution).code);f->execution=NULL;return (struct steer_draft_host_work_result){{0,0},NULL,0};}
static void disposed(void *arg,struct steer_draft_host_work_result result){struct fixture *f=arg;assert(!result.error.code&&!result.value);f->dispose_done++;wake(f);}
static void drained(void *arg){struct fixture *f=arg;assert(++f->drained==1&&atomic_load(&f->guards)==1);assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);wake(f);}
static void submit_probe(struct fixture *f,unsigned index){struct steer_draft_host_work_guard guard={f,retain,release};assert(!steer_draft_host_worker_submit(f->worker,"x",1,deadline(),probe,&f->probes[index],&guard,probed,&f->probes[index],&f->probe_jobs[index]).code);}
static void submit_dispose(struct fixture *f){struct steer_draft_host_work_guard guard={f,retain,release};assert(!steer_draft_host_worker_submit(f->worker,"x",1,deadline(),dispose,f,&guard,disposed,f,&f->dispose_job).code);}
static void gate_ready(struct loop *l,int fd,uint32_t events,void *arg){(void)l;(void)events;uint64_t value;assert(read(fd,&value,sizeof(value))==sizeof(value));wake(arg);}
static void step(struct loop *l,struct loop_timer *t,void *arg){
 struct fixture *f=arg;(void)t;
 if(f->mode==2){
  if(f->phase==0){if(!f->prepared_done)return;assert(!steer_draft_host_job_release(f->prepare_job).code);submit_probe(f,0);submit_probe(f,1);f->phase=10;return;}
  if(f->phase==10){pthread_mutex_lock(&f->mutex);if(f->entered!=3){pthread_mutex_unlock(&f->mutex);return;}unsigned blocked=pthread_equal(f->prepare_thread,f->probe_thread[0])?0u:1u;assert(pthread_equal(f->prepare_thread,f->probe_thread[blocked]));f->allow=1u<<(blocked^1u);pthread_cond_broadcast(&f->condition);pthread_mutex_unlock(&f->mutex);f->phase=11;return;}
  if(f->phase==11){if(!f->probe_done)return;unsigned released=f->probe_done==1?0u:1u;assert(!steer_draft_host_job_release(f->probe_jobs[released]).code);submit_dispose(f);f->phase=12;return;}
  if(f->phase==12){if(!f->dispose_done)return;assert(!steer_draft_host_job_release(f->dispose_job).code&&atomic_load(&f->discarded)==1);pthread_mutex_lock(&f->mutex);f->allow=3;pthread_cond_broadcast(&f->condition);pthread_mutex_unlock(&f->mutex);f->phase=13;return;}
  if(f->phase==13){if(f->probe_done!=3)return;unsigned blocked=pthread_equal(f->prepare_thread,f->probe_thread[0])?0u:1u;assert(!steer_draft_host_job_release(f->probe_jobs[blocked]).code);steer_draft_host_worker_stop(f->worker);f->phase=2;return;}
 }else{
  if(!f->phase){if(!f->prepared_done||!f->probe_done)return;assert(!steer_draft_host_job_release(f->prepare_job).code&&!steer_draft_host_job_release(f->probe_jobs[0]).code);submit_dispose(f);f->phase=1;return;}
  if(f->phase==1){if(!f->dispose_done)return;assert(atomic_load(&f->discarded)==1);assert(!steer_draft_host_job_release(f->dispose_job).code);steer_draft_host_worker_stop(f->worker);f->phase=2;return;}
 }
 if(f->phase==2&&f->drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->phase=3;loop_stop(l,0);}
}
static void scenario(unsigned mode){
 struct fixture f={0};f.mode=mode;for(unsigned i=0;i<2;i++)f.probes[i]=(struct probe_context){&f,i};atomic_init(&f.guards,1);atomic_init(&f.prepared,0);atomic_init(&f.discarded,0);assert(!pthread_mutex_init(&f.mutex,NULL)&&!pthread_cond_init(&f.condition,NULL));
 f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);assert(f.loop&&f.work);struct steer_draft_buffer_limits bl={1024,4,4};assert(!steer_draft_buffers_create(&bl,NULL,&f.host).code);
 f.gate=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(f.gate>=0&&!loop_fd_add(f.loop,f.gate,EPOLLIN,gate_ready,&f));
 struct steer_draft_host_worker_limits wl={mode,4,4096,8192};assert(!steer_draft_host_worker_create(f.loop,&wl,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,drained,&f).code);
 static const char *const caps[]={"core.outbound.direct"};f.factory=(struct steer_spec_execution_factory){.size=sizeof(f.factory),.version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT,.kind=STEER_SPEC_OUTBOUND,.type="direct",.transport="tcp",.security="none",.variant="default",.stream_provider_id="fixture",.flows=STEER_SPEC_FLOW_STREAM,.capabilities=caps,.capability_count=1,.guard={&f,retain,release},.context=&f,.validate=validate,.prepare=prepare,.discard=discard,.bind=bind_unused,.retire=retire_unused,.collect=collect_unused};
 const struct steer_spec_capability inventory[]={{"core.outbound.direct",STEER_SPEC_READY,NULL,NULL},{"core.spec-v3.apply",STEER_SPEC_READY,NULL,NULL}};
 struct steer_spec_execution_prepare_input input={.generation=1,.first_instance_token=1,.inventory=inventory,.inventory_count=2,.factories=&f.factory,.factory_count=1,.limits={4,16,1024,4,8,{4,4,2,8,4096,1000000000ull}}};
 const char source[]="{\"version\":3,\"plugin_remotes\":{},\"plugins\":{},\"inbounds\":{},\"outbounds\":{\"d\":{\"type\":\"direct\",\"flow\":[\"stream\"]}},\"routing\":{\"default\":\"d\",\"rules\":[]}}";
 struct steer_draft_host_work_guard guard={&f,retain,release};assert(!steer_spec_execution_submit(f.worker,source,strlen(source),&input,deadline(),&guard,prepared,&f,&f.prepare_job).code);
 if(mode==1){submit_probe(&f,0);pthread_mutex_lock(&f.mutex);while(!f.entered)pthread_cond_wait(&f.condition,&f.mutex);steer_draft_host_job_cancel(f.prepare_job);f.allow=1;pthread_cond_signal(&f.condition);pthread_mutex_unlock(&f.mutex);}
 assert(!loop_run(f.loop)&&f.phase==3);assert(!steer_draft_buffers_destroy(f.host).code);loop_fd_del(f.loop,f.gate);close(f.gate);loop_timer_free(f.work);loop_free(f.loop);assert(!pthread_cond_destroy(&f.condition)&&!pthread_mutex_destroy(&f.mutex));
}

int main(void){alarm(20);scenario(1);scenario(2);puts("execution-async: queued-success latecancel fenced + two-pool-worker prepared-state handoff/discard PASS");return 0;}
