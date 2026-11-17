#define _GNU_SOURCE
#include "host_worker.h"
#include "loop.h"
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
struct fixture {struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;struct steer_draft_host_job *jobs[2];ino_t target,original;unsigned callbacks,phase,drained;atomic_uint guards;};
static ino_t current(void){struct stat s;assert(!stat("/proc/thread-self/ns/net",&s));return s.st_ino;}
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static struct steer_draft_host_work_result scoped(void *arg,const void *input,size_t size,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)input;(void)size;(void)until;(void)cancel;assert(current()==f->target);return (struct steer_draft_host_work_result){{0,0},f,0};}
static struct steer_draft_host_work_result baseline(void *arg,const void *input,size_t size,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)input;(void)size;(void)until;(void)cancel;assert(current()==f->original);return (struct steer_draft_host_work_result){{0,0},NULL,0};}
static void completed(void *arg,struct steer_draft_host_work_result r){struct fixture *f=arg;assert(!r.error.code&&!r.worker_flags&&current()==f->original);if(!f->callbacks)assert(r.value==f);else assert(!r.value);f->callbacks++;wake(f);}
static void drained(void *arg){struct fixture *f=arg;assert(++f->drained==1&&atomic_load(&f->guards)==1);wake(f);}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 if(!f->phase){if(!f->callbacks)return;assert(!steer_draft_host_job_release(f->jobs[0]).code);struct steer_draft_host_work_guard guard={f,retain,release};assert(!steer_draft_host_worker_submit(f->worker,"x",1,deadline(),baseline,f,&guard,completed,f,&f->jobs[1]).code);f->phase=1;return;}
 if(f->phase==1){if(f->callbacks!=2)return;assert(!steer_draft_host_job_release(f->jobs[1]).code);steer_draft_host_worker_stop(f->worker);f->phase=2;return;}
 if(f->phase==2&&f->drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->phase=3;loop_stop(loop,0);}
}
int main(void){
 alarm(20);struct fixture f={0};atomic_init(&f.guards,1);int original=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(original>=0);f.original=current();
 assert(!unshare(CLONE_NEWNET));int target=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(target>=0);f.target=current();assert(f.target!=f.original);assert(!setns(original,CLONE_NEWNET)&&current()==f.original);
 f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);struct steer_draft_host_worker_limits limits={1,4,8,32};assert(!steer_draft_host_worker_create(f.loop,&limits,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,drained,&f).code);
 struct steer_draft_host_work_guard guard={&f,retain,release};assert(!steer_draft_host_worker_submit_ns(f.worker,target,"x",1,deadline(),scoped,&f,&guard,completed,&f,&f.jobs[0]).code);close(target);
 assert(!loop_run(f.loop)&&f.phase==3&&current()==f.original);close(original);loop_timer_free(f.work);loop_free(f.loop);puts("host-worker-namespace-actual: fresh namespace enter/restore+same worker baseline+owner unchanged PASS");return 0;
}
