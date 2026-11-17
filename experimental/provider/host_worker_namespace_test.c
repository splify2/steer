#define _GNU_SOURCE
#include "host_worker.h"
#include "loop.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
struct fixture;
struct item {struct fixture *fixture;unsigned index;};
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;
 struct steer_draft_host_job *job[3];struct item items[3];unsigned calls[3],phase,threads,drained;
 pthread_mutex_t mutex;pthread_cond_t condition;int allow,event;atomic_uint guards,runs[3];pthread_t ran_on[3];
};
static _Thread_local unsigned namespace_calls;
int __wrap_setns(int fd,int type){(void)type;assert(fcntl(fd,F_GETFD)>=0);if(++namespace_calls==2){errno=EIO;return -1;}return 0;}
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(struct fixture *f){loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static struct steer_draft_host_work_result run(void *arg,const void *input,size_t length,uint64_t until,const struct steer_draft_cancel *cancel){
 struct item *item=arg;struct fixture *f=item->fixture;(void)input;(void)length;(void)until;(void)cancel;
 f->ran_on[item->index]=pthread_self();atomic_fetch_add(&f->runs[item->index],1);
 if(!item->index){pthread_mutex_lock(&f->mutex);uint64_t one=1;assert(write(f->event,&one,sizeof(one))==sizeof(one));while(!f->allow)pthread_cond_wait(&f->condition,&f->mutex);pthread_mutex_unlock(&f->mutex);}
 return (struct steer_draft_host_work_result){{0,0},item->index?NULL:f,0};
}
static void completed(void *arg,struct steer_draft_host_work_result result){
 struct item *item=arg;struct fixture *f=item->fixture;assert(++f->calls[item->index]==1);
 if(!item->index)assert(!result.error.code&&result.value==f&&result.worker_flags==STEER_DRAFT_HOST_QUARANTINE_THREAD);
 else if(f->threads==1)assert(result.error.code==STEER_PV1_RESOURCE_EXHAUSTED&&!result.value&&result.worker_flags==STEER_DRAFT_HOST_NO_HEALTHY_WORKERS&&!atomic_load(&f->runs[1]));
 else assert(!result.error.code&&!result.value&&!result.worker_flags);
 assert(steer_draft_host_job_release(f->job[item->index]).code==STEER_PV1_POLICY_DENIED);wake(f);
}
static void submit(struct fixture *f,unsigned index,int scoped){
 struct steer_draft_host_work_guard guard={f,retain,release};struct steer_pv1_error e;
 if(scoped){int fd=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(fd>=0);e=steer_draft_host_worker_submit_ns(f->worker,fd,"x",1,deadline(),run,&f->items[index],&guard,completed,&f->items[index],&f->job[index]);close(fd);}
 else e=steer_draft_host_worker_submit(f->worker,"x",1,deadline(),run,&f->items[index],&guard,completed,&f->items[index],&f->job[index]);
 assert(!e.code);
}
static void drained(void *arg){struct fixture *f=arg;assert(++f->drained==1&&atomic_load(&f->guards)==1);assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);wake(f);}
static void event(struct loop *l,int fd,uint32_t flags,void *arg){(void)l;(void)flags;uint64_t one;assert(read(fd,&one,sizeof(one))==sizeof(one));struct fixture *f=arg;f->phase=1;if(f->threads==1)submit(f,1,0);wake(f);}
static void step(struct loop *l,struct loop_timer *t,void *arg){
 struct fixture *f=arg;(void)t;
 if(f->phase==1){
  if(f->threads==2&&!f->calls[1])return;
  pthread_mutex_lock(&f->mutex);f->allow=1;pthread_cond_signal(&f->condition);pthread_mutex_unlock(&f->mutex);f->phase=2;
 }
 if(f->phase==2){
  if(!f->calls[0]||!f->calls[1])return;
  if(f->threads==2){submit(f,2,0);f->phase=3;return;}f->phase=3;
 }
 if(f->phase==3){
  if(f->threads==2&&!f->calls[2])return;
  if(f->threads==2){assert(!pthread_equal(f->ran_on[0],f->ran_on[2]));assert(pthread_equal(f->ran_on[1],f->ran_on[2]));}
  for(unsigned i=0;i<(f->threads==2?3u:2u);i++)assert(!steer_draft_host_job_release(f->job[i]).code);
  steer_draft_host_worker_stop(f->worker);f->phase=4;return;
 }
 if(f->phase==4&&f->drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->phase=5;loop_stop(l,0);}
}
static void scenario(unsigned threads){
 struct fixture f={0};f.threads=threads;atomic_init(&f.guards,1);for(unsigned i=0;i<3;i++){f.items[i]=(struct item){&f,i};atomic_init(&f.runs[i],0);}
 assert(!pthread_mutex_init(&f.mutex,NULL)&&!pthread_cond_init(&f.condition,NULL));f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);f.event=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(f.event>=0&&!loop_fd_add(f.loop,f.event,EPOLLIN,event,&f));
 struct steer_draft_host_worker_limits limits={threads,4,8,32};assert(!steer_draft_host_worker_create(f.loop,&limits,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,drained,&f).code);
 submit(&f,0,1);if(threads==2)submit(&f,1,0);assert(!loop_run(f.loop)&&f.phase==5);
 loop_fd_del(f.loop,f.event);close(f.event);loop_timer_free(f.work);loop_free(f.loop);assert(!pthread_cond_destroy(&f.condition)&&!pthread_mutex_destroy(&f.mutex));
}
int main(void){alarm(20);scenario(1);scenario(2);puts("host-worker-namespace: injected restore failure preserves effects/quarantines thread/healthy-only queue/no-health deferred errors PASS");return 0;}
