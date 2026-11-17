#define _GNU_SOURCE
#include "host_worker.h"
#include "loop.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
enum state {QUEUED,RUNNING,DONE,DELIVERING,COMPLETE};
struct steer_draft_host_job {
 struct steer_draft_host_worker *worker;struct steer_draft_host_job *next;
 void *input;int namespace_fd;size_t length;uint64_t deadline;enum state state;
 struct steer_draft_cancel cancel;steer_draft_host_work_run run;void *context;
 struct steer_draft_host_work_guard guard;steer_draft_host_work_done done;void *user;
 struct steer_draft_host_work_result result;
};
struct steer_draft_host_worker {
 struct loop *loop;pthread_mutex_t lock;pthread_cond_t changed;pthread_t threads[4];
 struct steer_draft_host_worker_limits limits;struct steer_draft_host_job *jobs;
 uint32_t live,started,exited,healthy;uint64_t bytes;int wake,stopping,dispatching,notified,foreign_depth;
 void (*drained)(void *);void *drained_user;
};
static struct steer_pv1_error error(uint32_t code){return (struct steer_pv1_error){code,0};}
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static void wipe(void *pointer,size_t n){volatile unsigned char *p=pointer;while(n--)*p++=0;}
static void notify(struct steer_draft_host_worker *w){uint64_t one=1;ssize_t n;do n=write(w->wake,&one,sizeof(one));while(n<0&&errno==EINTR);}
static void free_job(struct steer_draft_host_job *j){if(j->namespace_fd>=0)close(j->namespace_fd);free(j);}
static void *work(void *arg){
 struct steer_draft_host_worker *w=arg;pthread_mutex_lock(&w->lock);
 for(;;){
  struct steer_draft_host_job *j=NULL;
  for(struct steer_draft_host_job *p=w->jobs;p;p=p->next)if(p->state==QUEUED){j=p;break;}
  if(!j){if(w->stopping)break;pthread_cond_wait(&w->changed,&w->lock);continue;}
  j->state=RUNNING;pthread_mutex_unlock(&w->lock);
  struct steer_draft_host_work_result result={error(0),NULL,0};
  if(atomic_load_explicit(&j->cancel.requested,memory_order_acquire))result.error=error(STEER_PV1_CANCELLED);
  else if(now()>=j->deadline)result.error=error(STEER_PV1_TIMEOUT);
  else {
   int baseline=-1,entered=0;
   if(j->namespace_fd>=0){baseline=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);if(baseline<0||setns(j->namespace_fd,CLONE_NEWNET))result.error=error(STEER_PV1_IO);else entered=1;}
   if(!result.error.code)result=j->run(j->context,j->input,j->length,j->deadline,&j->cancel);
   if(entered&&setns(baseline,CLONE_NEWNET))result.worker_flags|=STEER_DRAFT_HOST_QUARANTINE_THREAD;
   if(baseline>=0)close(baseline);
  }
  if(result.worker_flags&~STEER_DRAFT_HOST_QUARANTINE_THREAD){result.error=error(STEER_PV1_PROTOCOL);result.worker_flags=STEER_DRAFT_HOST_QUARANTINE_THREAD;}
  /* Never replace factual effects after run returned. */
  if(result.error.code>STEER_PV1_INTERNAL||result.error.transient>1||(!result.error.code&&result.error.transient))result.error=error(STEER_PV1_PROTOCOL);
  wipe(j->input,j->length);free(j->input);
  pthread_mutex_lock(&w->lock);j->input=NULL;w->bytes-=j->length;j->result=result;j->state=DONE;notify(w);
  if(result.worker_flags&STEER_DRAFT_HOST_QUARANTINE_THREAD){
   if(--w->healthy==0){
    w->stopping=1;
    for(struct steer_draft_host_job *queued=w->jobs;queued;queued=queued->next)if(queued->state==QUEUED){
     wipe(queued->input,queued->length);free(queued->input);queued->input=NULL;w->bytes-=queued->length;
     queued->result=(struct steer_draft_host_work_result){error(STEER_PV1_RESOURCE_EXHAUSTED),NULL,STEER_DRAFT_HOST_NO_HEALTHY_WORKERS};queued->state=DONE;
    }
   }
   break; /* contaminated worker never runs another provider/job */
  }
 }
 w->exited++;notify(w);pthread_mutex_unlock(&w->lock);return NULL;
}
static void ready(struct loop *loop,int fd,uint32_t events,void *arg){
 struct steer_draft_host_worker *w=arg;uint64_t value;(void)loop;(void)events;
 while(read(fd,&value,sizeof(value))<0&&errno==EINTR){}
 struct steer_draft_host_job *batch[32];uint32_t count=0;int more=0;
 pthread_mutex_lock(&w->lock);
 for(struct steer_draft_host_job *j=w->jobs;j;j=j->next)if(j->state==DONE){
  if(count<32){j->state=DELIVERING;batch[count++]=j;}else more=1;
 }
 pthread_mutex_unlock(&w->lock);w->dispatching=1;
 for(uint32_t i=0;i<count;i++){
  struct steer_draft_host_job *j=batch[i];j->done(j->user,j->result);
  pthread_mutex_lock(&w->lock);j->result.value=NULL;j->state=COMPLETE;pthread_mutex_unlock(&w->lock);
 }
 pthread_mutex_lock(&w->lock);int drained=w->stopping&&w->exited==w->started&&!w->live&&w->drained&&!w->notified;
 if(drained)w->notified=1;
 pthread_mutex_unlock(&w->lock);
 if(drained)w->drained(w->drained_user);
 w->dispatching=0;if(more)notify(w);
}
struct steer_pv1_error steer_draft_host_worker_create(struct loop *loop,const struct steer_draft_host_worker_limits *limits,struct steer_draft_host_worker **out){
 if(out)*out=NULL;
 if(!out||!loop||!limits||!limits->threads||limits->threads>4||!limits->max_jobs||limits->max_jobs>1024||!limits->max_input||limits->max_input>65536||limits->max_bytes<limits->max_input)return error(STEER_PV1_INVALID);
 struct steer_draft_host_worker *w=calloc(1,sizeof(*w));if(!w)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 w->loop=loop;w->limits=*limits;w->healthy=limits->threads;w->wake=-1;
 if(pthread_mutex_init(&w->lock,NULL)){free(w);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 if(pthread_cond_init(&w->changed,NULL)){pthread_mutex_destroy(&w->lock);free(w);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 w->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
 if(w->wake<0||loop_fd_add(loop,w->wake,EPOLLIN,ready,w))goto fail;
 for(uint32_t i=0;i<limits->threads;i++){
  if(pthread_create(&w->threads[i],NULL,work,w))goto fail_threads;
  w->started++;
 }
 *out=w;return error(0);
fail_threads:
 pthread_mutex_lock(&w->lock);w->stopping=1;pthread_cond_broadcast(&w->changed);pthread_mutex_unlock(&w->lock);
 for(uint32_t i=0;i<w->started;i++)pthread_join(w->threads[i],NULL);
 loop_fd_del(loop,w->wake);
fail:
 if(w->wake>=0)close(w->wake);
 pthread_cond_destroy(&w->changed);pthread_mutex_destroy(&w->lock);free(w);return error(STEER_PV1_RESOURCE_EXHAUSTED);
}
static struct steer_pv1_error submit_internal(struct steer_draft_host_worker *w,int namespace_fd,const void *input,size_t length,uint64_t deadline,steer_draft_host_work_run run,void *context,const struct steer_draft_host_work_guard *guard,steer_draft_host_work_done done,void *user,struct steer_draft_host_job **out){
 if(out)*out=NULL;
 if(!w||!out||(!input&&length)||!run||!done||!guard||!guard->retain||!guard->release||!deadline)return error(STEER_PV1_INVALID);
 if(w->foreign_depth)return error(STEER_PV1_POLICY_DENIED);
 if(now()>=deadline)return error(STEER_PV1_TIMEOUT);
 pthread_mutex_lock(&w->lock);int unavailable=w->stopping||w->live>=w->limits.max_jobs||length>w->limits.max_input||length>w->limits.max_bytes-w->bytes;pthread_mutex_unlock(&w->lock);
 if(unavailable)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 struct steer_draft_host_job *j=calloc(1,sizeof(*j));if(!j)return error(STEER_PV1_RESOURCE_EXHAUSTED);j->namespace_fd=-1;
 j->input=malloc(length?length:1);if(!j->input){free_job(j);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 if(length)memcpy(j->input,input,length);
 if(namespace_fd>=0){j->namespace_fd=fcntl(namespace_fd,F_DUPFD_CLOEXEC,0);if(j->namespace_fd<0){wipe(j->input,length);free(j->input);free_job(j);return error(STEER_PV1_IO);}}
 w->foreign_depth++;
 struct steer_pv1_error held=guard->retain(guard->context);
 if(held.code||held.transient){wipe(j->input,length);free(j->input);free_job(j);if(!held.code)guard->release(guard->context);w->foreign_depth--;return held.code&&held.code<=STEER_PV1_INTERNAL&&held.transient<=1?held:error(STEER_PV1_PROTOCOL);}
 j->worker=w;j->length=length;j->deadline=deadline;j->run=run;j->context=context;j->guard=*guard;j->done=done;j->user=user;atomic_init(&j->cancel.requested,0);
 pthread_mutex_lock(&w->lock);
 unavailable=w->stopping||w->live>=w->limits.max_jobs||length>w->limits.max_bytes-w->bytes;
 if(unavailable){pthread_mutex_unlock(&w->lock);guard->release(guard->context);wipe(j->input,length);free(j->input);free_job(j);w->foreign_depth--;return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 struct steer_draft_host_job **tail=&w->jobs;while(*tail)tail=&(*tail)->next;*tail=j;w->live++;w->bytes+=length;pthread_cond_signal(&w->changed);pthread_mutex_unlock(&w->lock);
 *out=j;w->foreign_depth--;return error(0);
}
void steer_draft_host_job_cancel(struct steer_draft_host_job *j){if(j)atomic_store_explicit(&j->cancel.requested,1,memory_order_release);}
struct steer_pv1_error steer_draft_host_job_release(struct steer_draft_host_job *j){
 if(!j)return error(STEER_PV1_INVALID);
 struct steer_draft_host_worker *w=j->worker;pthread_mutex_lock(&w->lock);
 if(j->state!=COMPLETE){pthread_mutex_unlock(&w->lock);return error(STEER_PV1_POLICY_DENIED);}
 struct steer_draft_host_job **at=&w->jobs;while(*at&&*at!=j)at=&(*at)->next;
 if(!*at){pthread_mutex_unlock(&w->lock);return error(STEER_PV1_INTERNAL);}
 *at=j->next;w->live--;pthread_mutex_unlock(&w->lock);
 w->foreign_depth++;j->guard.release(j->guard.context);free_job(j);notify(w);w->foreign_depth--;return error(0);
}
struct steer_pv1_error steer_draft_host_worker_on_drained(struct steer_draft_host_worker *w,void (*done)(void *),void *user){
 if(!w||!done)return error(STEER_PV1_INVALID);
 pthread_mutex_lock(&w->lock);
 if(w->drained||w->stopping){pthread_mutex_unlock(&w->lock);return error(STEER_PV1_POLICY_DENIED);}
 w->drained=done;w->drained_user=user;pthread_mutex_unlock(&w->lock);return error(0);
}
void steer_draft_host_worker_stop(struct steer_draft_host_worker *w){
 if(!w)return;
 pthread_mutex_lock(&w->lock);w->stopping=1;
 for(struct steer_draft_host_job *j=w->jobs;j;j=j->next)atomic_store_explicit(&j->cancel.requested,1,memory_order_release);
 pthread_cond_broadcast(&w->changed);notify(w);pthread_mutex_unlock(&w->lock);
}
struct steer_pv1_error steer_draft_host_worker_destroy(struct steer_draft_host_worker *w){
 if(!w)return error(STEER_PV1_INVALID);
 pthread_mutex_lock(&w->lock);int busy=!w->stopping||w->exited!=w->started||w->live||w->dispatching||w->foreign_depth||(w->drained&&!w->notified);pthread_mutex_unlock(&w->lock);
 if(busy)return error(STEER_PV1_POLICY_DENIED);
 for(uint32_t i=0;i<w->started;i++)pthread_join(w->threads[i],NULL);
 loop_fd_del(w->loop,w->wake);close(w->wake);pthread_cond_destroy(&w->changed);pthread_mutex_destroy(&w->lock);free(w);return error(0);
}
void steer_draft_host_worker_usage(struct steer_draft_host_worker *w,uint32_t *jobs,uint64_t *bytes){
 if(!w)return;
 pthread_mutex_lock(&w->lock);if(jobs)*jobs=w->live;if(bytes)*bytes=w->bytes;pthread_mutex_unlock(&w->lock);
}

struct loop *steer_draft_host_worker_owner(const struct steer_draft_host_worker *w){return w?w->loop:NULL;}

void steer_draft_host_worker_limits(const struct steer_draft_host_worker *w,struct steer_draft_host_worker_limits *out){if(out)*out=w?w->limits:(struct steer_draft_host_worker_limits){0};}

int steer_draft_host_job_cancelled(const struct steer_draft_host_job *j){return j?atomic_load_explicit(&j->cancel.requested,memory_order_acquire)!=0:0;}

struct steer_pv1_error steer_draft_host_worker_submit(struct steer_draft_host_worker *w,const void *input,size_t length,uint64_t deadline,steer_draft_host_work_run run,void *context,const struct steer_draft_host_work_guard *guard,steer_draft_host_work_done done,void *user,struct steer_draft_host_job **out){return submit_internal(w,-1,input,length,deadline,run,context,guard,done,user,out);}
struct steer_pv1_error steer_draft_host_worker_submit_ns(struct steer_draft_host_worker *w,int fd,const void *input,size_t length,uint64_t deadline,steer_draft_host_work_run run,void *context,const struct steer_draft_host_work_guard *guard,steer_draft_host_work_done done,void *user,struct steer_draft_host_job **out){if(fd<0){if(out)*out=NULL;return error(STEER_PV1_INVALID);}return submit_internal(w,fd,input,length,deadline,run,context,guard,done,user,out);}
