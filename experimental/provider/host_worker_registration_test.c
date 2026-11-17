#define _GNU_SOURCE
#include "host_worker.h"
#include "loop.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
struct fixture {struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;struct steer_draft_host_job *job;pthread_barrier_t barrier;atomic_uint guards;unsigned called,registered,notified,released;};
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static struct steer_draft_host_work_result run(void *arg,const void *input,size_t size,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)input;(void)size;(void)until;(void)cancel;int rc=pthread_barrier_wait(&f->barrier);assert(rc==0||rc==PTHREAD_BARRIER_SERIAL_THREAD);return (struct steer_draft_host_work_result){{0,0},f,STEER_DRAFT_HOST_QUARANTINE_THREAD};}
static void completed(void *arg,struct steer_draft_host_work_result result){struct fixture *f=arg;assert(!result.error.code&&result.value==f&&result.worker_flags==STEER_DRAFT_HOST_QUARANTINE_THREAD);assert(++f->called==1);wake(f);}
static void drained(void *arg){struct fixture *f=arg;assert(f->registered&&++f->notified==1);assert(steer_draft_host_worker_destroy(f->worker).code==STEER_PV1_POLICY_DENIED);wake(f);}
static void step(struct loop *l,struct loop_timer *t,void *arg){struct fixture *f=arg;(void)t;if(!f->called)return;if(!f->released){assert(!steer_draft_host_job_release(f->job).code);f->released=1;}if(f->registered&&!f->notified)return;assert(!steer_draft_host_worker_destroy(f->worker).code);loop_stop(l,0);}
static void scenario(void){
 struct fixture f={0};atomic_init(&f.guards,1);assert(!pthread_barrier_init(&f.barrier,NULL,2));f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);struct steer_draft_host_worker_limits limits={1,2,8,16};assert(!steer_draft_host_worker_create(f.loop,&limits,&f.worker).code);struct steer_draft_host_work_guard guard={&f,retain,release};assert(!steer_draft_host_worker_submit(f.worker,"x",1,deadline(),run,&f,&guard,completed,&f,&f.job).code);
 int rc=pthread_barrier_wait(&f.barrier);assert(rc==0||rc==PTHREAD_BARRIER_SERIAL_THREAD);
 struct steer_pv1_error e=steer_draft_host_worker_on_drained(f.worker,drained,&f);assert(!e.code||e.code==STEER_PV1_POLICY_DENIED);f.registered=!e.code;
 assert(!loop_run(f.loop)&&f.called==1&&f.released&&atomic_load(&f.guards)==1);loop_timer_free(f.work);loop_free(f.loop);assert(!pthread_barrier_destroy(&f.barrier));
}
int main(void){alarm(20);for(unsigned i=0;i<64;i++)scenario();puts("host-worker-registration: concurrent last-quarantine vs on-drained registration PASS64");return 0;}
