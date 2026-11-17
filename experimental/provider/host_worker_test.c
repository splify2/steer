#define _GNU_SOURCE
#include "host_worker.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
struct fixture;
struct item {struct fixture *f;unsigned index;};
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;
 struct steer_draft_host_job *jobs[2];struct item items[2];
 pthread_mutex_t mutex;pthread_cond_t condition;int entered,allow,fd,mode;
 atomic_uint guards,runs[2];unsigned called[2],phase,drained;int retain_reentry;
};
static uint64_t deadline(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec+5000000000ull;}
static void wake(struct fixture *f){loop_timer_set(f->work,0);}
static struct steer_draft_host_work_result run(void *arg,const void *data,size_t length,uint64_t until,const struct steer_draft_cancel *cancel){
 struct item *item=arg;struct fixture *f=item->f;(void)until;assert(length==4&&!memcmp(data,"copy",4));atomic_fetch_add(&f->runs[item->index],1);
 if(!item->index){pthread_mutex_lock(&f->mutex);f->entered=1;uint64_t one=1;assert(write(f->fd,&one,sizeof(one))==sizeof(one));while(!f->allow)pthread_cond_wait(&f->condition,&f->mutex);pthread_mutex_unlock(&f->mutex);assert(atomic_load(&cancel->requested));}
 return (struct steer_draft_host_work_result){{0,0},item->index?NULL:f,0}; /* f denotes factual CHANGED */
}
static void done(void *,struct steer_draft_host_work_result);
static void release(void *);
static struct steer_pv1_error retain(void *arg){
 struct fixture *f=arg;atomic_fetch_add(&f->guards,1);
 if(f->retain_reentry){
  struct steer_draft_host_job *nested=NULL;struct steer_draft_host_work_guard guard={f,retain,release};
  assert(steer_draft_host_worker_submit(f->worker,"copy",4,deadline(),run,&f->items[1],&guard,done,&f->items[1],&nested).code==STEER_PV1_POLICY_DENIED);
  assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);
  steer_draft_host_worker_stop(f->worker);
 }
 return (struct steer_pv1_error){0,0};
}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);}
static void done(void *arg,struct steer_draft_host_work_result result){
 struct item *item=arg;struct fixture *f=item->f;assert(++f->called[item->index]==1);
 if(!item->index)assert(!result.error.code&&result.value==f);
 else if(f->mode==1)assert(result.error.code==STEER_PV1_CANCELLED&&!result.value&&!atomic_load(&f->runs[1]));
 else assert(!result.error.code&&!result.value&&atomic_load(&f->runs[1])==1);
 assert(steer_draft_host_job_release(f->jobs[item->index]).code==STEER_PV1_POLICY_DENIED);
 assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);wake(f);
}
static void drained(void *arg){struct fixture *f=arg;assert(++f->drained==1&&atomic_load(&f->guards)==1);assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);wake(f);}
static void submit(struct fixture *f,unsigned i){struct steer_draft_host_work_guard guard={f,retain,release};char input[]="copy";assert(!steer_draft_host_worker_submit(f->worker,input,4,deadline(),run,&f->items[i],&guard,done,&f->items[i],&f->jobs[i]).code);memset(input,'X',4);}
static void quota_rejected(struct fixture *f){
 struct steer_draft_host_job *job=NULL;struct steer_draft_host_work_guard guard={f,retain,release};unsigned before=atomic_load(&f->guards);
 assert(steer_draft_host_worker_submit(f->worker,"copy",4,deadline(),run,&f->items[1],&guard,done,&f->items[1],&job).code==STEER_PV1_RESOURCE_EXHAUSTED&&!job);
 assert(atomic_load(&f->guards)==before);
}
static void gate_ready(struct loop *l,int fd,uint32_t events,void *arg){(void)l;(void)events;uint64_t value;assert(read(fd,&value,sizeof(value))==sizeof(value));wake(arg);}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 if(f->phase==0){
  pthread_mutex_lock(&f->mutex);int entered=f->entered;pthread_mutex_unlock(&f->mutex);if(!entered)return;
  if(f->mode==1){submit(f,1);steer_draft_host_job_cancel(f->jobs[1]);quota_rejected(f);}
  if(f->mode==2&&!f->called[1])return; /* healthy second worker finishes while first is stuck */
  steer_draft_host_job_cancel(f->jobs[0]);pthread_mutex_lock(&f->mutex);f->allow=1;pthread_cond_signal(&f->condition);pthread_mutex_unlock(&f->mutex);f->phase=1;
 }
 if(f->phase==1){
  if(!f->called[0]||!f->called[1])return;
  if(f->mode==2)quota_rejected(f); /* both COMPLETE jobs still count */
  assert(!steer_draft_host_job_release(f->jobs[1]).code);steer_draft_host_worker_stop(f->worker);
  assert(!f->drained&&steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);
  f->phase=2;wake(f);return;
 }
 if(f->phase==2){assert(!f->drained);assert(!steer_draft_host_job_release(f->jobs[0]).code);f->phase=3;return;}
 if(f->phase==3&&f->drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->worker=NULL;f->phase=4;loop_stop(loop,0);}
}
static void scenario(int mode){
 struct fixture f={0};f.mode=mode;atomic_init(&f.guards,1);for(unsigned i=0;i<2;i++){atomic_init(&f.runs[i],0);f.items[i]=(struct item){&f,i};}
 assert(!pthread_mutex_init(&f.mutex,NULL)&&!pthread_cond_init(&f.condition,NULL));f.loop=loop_new();assert(f.loop);f.work=loop_timer_new(f.loop,step,&f);assert(f.work);
 f.fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(f.fd>=0&&!loop_fd_add(f.loop,f.fd,EPOLLIN,gate_ready,&f));
 struct steer_draft_host_worker_limits limits={(uint32_t)mode,mode==1?3u:2u,4,8};assert(!steer_draft_host_worker_create(f.loop,&limits,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,drained,&f).code);
 submit(&f,0);if(mode==2)submit(&f,1);assert(!loop_run(f.loop)&&f.phase==4);
 loop_fd_del(f.loop,f.fd);close(f.fd);loop_timer_free(f.work);loop_free(f.loop);assert(!pthread_cond_destroy(&f.condition)&&!pthread_mutex_destroy(&f.mutex));
}
static void empty_step(struct loop *loop,struct loop_timer *t,void *arg){struct fixture *f=arg;(void)t;if(!f->drained)return;assert(!steer_draft_host_worker_destroy(f->worker).code);loop_stop(loop,0);}
static void empty(int reentry){
 struct fixture f={0};atomic_init(&f.guards,1);f.loop=loop_new();f.work=loop_timer_new(f.loop,empty_step,&f);struct steer_draft_host_worker_limits limits={2,2,4,8};assert(!steer_draft_host_worker_create(f.loop,&limits,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,drained,&f).code);
 if(reentry){f.retain_reentry=1;struct steer_draft_host_job *job=NULL;struct steer_draft_host_work_guard guard={&f,retain,release};assert(steer_draft_host_worker_submit(f.worker,"copy",4,deadline(),run,NULL,&guard,done,NULL,&job).code==STEER_PV1_RESOURCE_EXHAUSTED&&!job);assert(atomic_load(&f.guards)==1);}
 else steer_draft_host_worker_stop(f.worker);
 assert(!loop_run(f.loop)&&f.drained==1);loop_timer_free(f.work);loop_free(f.loop);
}
int main(void){alarm(20);empty(0);empty(1);scenario(1);scenario(2);puts("host-worker: empty stop/guard reentry/queued cancel/factual running cancel/two-worker isolation PASS");return 0;}
