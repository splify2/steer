#define _GNU_SOURCE
#include "tls_stream_faults.h"
#include "host_worker.h"
#include "operations.h"
#include "loop.h"
#include "certverify.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
enum mode {NONE,FLAGS_PREPARE,FLAGS_VERIFY,PAUSE_PREPARE,PAUSE_VERIFY,REFUSE_JOB,CLOSE_READY,LOWER_RELEASE};
struct wrapped_job;
struct tls_probe_fault {
    struct loop *loop;enum mode mode;pthread_mutex_t mutex;pthread_cond_t changed;
    struct wrapped_job *jobs;int wake,selected,blocked,released;atomic_uint seen;
    void (*notify)(void *);void *userdata;struct steer_pv1_stream_ref lower;
    struct steer_draft_operations *tls_operations;struct steer_pv1_operation *tls_open;
};
struct wrapped_job {
    struct wrapped_job *next;struct tls_probe_fault *fault;struct steer_draft_host_job *job;
    steer_draft_host_work_run run;void *context;steer_draft_host_work_done done;void *userdata;
    int selected,callback_returned,refused;
};
static _Thread_local struct tls_probe_fault *active;
static _Thread_local struct tls_probe_fault *verifying;
static void pause_worker(struct tls_probe_fault *f){
    atomic_fetch_add_explicit(&f->seen,1,memory_order_release);
    pthread_mutex_lock(&f->mutex);uint64_t one=1;ssize_t n;
    do{n=write(f->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);assert(n==(ssize_t)sizeof(one)||(n<0&&errno==EAGAIN));
    while(!f->released)pthread_cond_wait(&f->changed,&f->mutex);
    pthread_mutex_unlock(&f->mutex);
}
static void wake_owner(struct loop *loop,int fd,uint32_t events,void *arg){
    struct tls_probe_fault *f=arg;uint64_t value;(void)loop;(void)events;
    while(read(fd,&value,sizeof(value))<0&&errno==EINTR){}
    f->blocked=1;f->notify(f->userdata);
}
struct tls_probe_fault *tls_probe_fault_create(struct loop *loop,const char *name,void (*notify)(void *),void *userdata){
    struct tls_probe_fault *f=calloc(1,sizeof(*f));assert(f);f->loop=loop;f->notify=notify;f->userdata=userdata;f->wake=-1;
    if(name){
        if(!strcmp(name,"flags-prepare"))f->mode=FLAGS_PREPARE;
        else if(!strcmp(name,"flags-verify"))f->mode=FLAGS_VERIFY;
        else if(!strcmp(name,"pause-prepare"))f->mode=PAUSE_PREPARE;
        else if(!strcmp(name,"pause-verify"))f->mode=PAUSE_VERIFY;
        else if(!strcmp(name,"refuse-job"))f->mode=REFUSE_JOB;
        else if(!strcmp(name,"close-ready"))f->mode=CLOSE_READY;
        else if(!strcmp(name,"lower-release"))f->mode=LOWER_RELEASE;
        else assert(!"unknown TLS probe fault");
    }
    assert(!pthread_mutex_init(&f->mutex,NULL)&&!pthread_cond_init(&f->changed,NULL));atomic_init(&f->seen,0);
    f->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(f->wake>=0&&!loop_fd_add(loop,f->wake,EPOLLIN,wake_owner,f));return f;
}
void tls_probe_fault_enter(struct tls_probe_fault *f){active=f;}
int tls_probe_fault_blocked(const struct tls_probe_fault *f){return f&&f->blocked;}
void tls_probe_fault_unblock(struct tls_probe_fault *f){assert(f);pthread_mutex_lock(&f->mutex);f->released=1;pthread_cond_broadcast(&f->changed);pthread_mutex_unlock(&f->mutex);}
void tls_probe_fault_lower(struct tls_probe_fault *f,struct steer_pv1_stream_ref lower){if(f)f->lower=lower;}
unsigned tls_probe_fault_seen(const struct tls_probe_fault *f){return f?atomic_load_explicit(&f->seen,memory_order_acquire):0;}
void tls_probe_fault_mark(struct tls_probe_fault *f){assert(f);atomic_fetch_add_explicit(&f->seen,1,memory_order_release);}
void tls_probe_fault_destroy(struct tls_probe_fault *f){assert(f&&!f->jobs);if(active==f)active=NULL;loop_fd_del(f->loop,f->wake);close(f->wake);pthread_cond_destroy(&f->changed);pthread_mutex_destroy(&f->mutex);free(f);}

struct steer_pv1_error __real_steer_draft_host_worker_submit(struct steer_draft_host_worker *,const void *,size_t,uint64_t,steer_draft_host_work_run,void *,const struct steer_draft_host_work_guard *,steer_draft_host_work_done,void *,struct steer_draft_host_job **);
struct steer_pv1_error __real_steer_draft_host_job_release(struct steer_draft_host_job *);
static struct steer_draft_host_work_result wrapped_run(void *arg,const void *input,size_t length,uint64_t deadline,const struct steer_draft_cancel *cancel){
    struct wrapped_job *w=arg;
    struct tls_probe_fault *previous=verifying;
    if(w->selected&&w->fault->mode==PAUSE_VERIFY)verifying=w->fault;
    struct steer_draft_host_work_result result=w->run(w->context,input,length,deadline,cancel);
    verifying=previous;
    struct tls_probe_fault *f=w->fault;
    if(w->selected&&!result.error.code){
        if(f->mode==FLAGS_PREPARE||f->mode==FLAGS_VERIFY){atomic_fetch_add_explicit(&f->seen,1,memory_order_release);result.worker_flags|=STEER_DRAFT_HOST_QUARANTINE_THREAD;}
        if(f->mode==PAUSE_PREPARE)pause_worker(f);
    }
    return result;
}
int __real_cert_verify_server_prepared(const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const char *,const struct cert_trust *,const struct cert_policy *);
int __wrap_cert_verify_server_prepared(const unsigned char *certificate,size_t certificate_length,
    const unsigned char *proof,size_t proof_length,const unsigned char *transcript,size_t transcript_length,
    const char *name,const struct cert_trust *roots,const struct cert_policy *policy){
    /* Pause AFTER the producer passed its cancel check, BEFORE crypto reads the
     * copied certificate/proof. Owner cancels, wipes/frees engine workspace and
     * consumes public open refs first; late factual verification still returns. */
    if(verifying)pause_worker(verifying);
    return __real_cert_verify_server_prepared(certificate,certificate_length,proof,proof_length,transcript,transcript_length,name,roots,policy);
}
static void wrapped_done(void *arg,struct steer_draft_host_work_result result){struct wrapped_job *w=arg;w->done(w->userdata,result);w->callback_returned=1;}
struct steer_pv1_error __wrap_steer_draft_host_worker_submit(struct steer_draft_host_worker *worker,const void *input,size_t length,uint64_t deadline,
    steer_draft_host_work_run run,void *context,const struct steer_draft_host_work_guard *guard,steer_draft_host_work_done done,void *userdata,struct steer_draft_host_job **out){
    if(!active||active->mode==NONE||active->mode==CLOSE_READY||active->mode==LOWER_RELEASE)return __real_steer_draft_host_worker_submit(worker,input,length,deadline,run,context,guard,done,userdata,out);
    struct wrapped_job *w=calloc(1,sizeof(*w));assert(w);w->fault=active;w->run=run;w->context=context;w->done=done;w->userdata=userdata;
    int verify=active->mode==FLAGS_VERIFY||active->mode==PAUSE_VERIFY;
    if(!active->selected&&((length>0)==verify)){w->selected=1;active->selected=1;}
    struct steer_pv1_error error=__real_steer_draft_host_worker_submit(worker,input,length,deadline,wrapped_run,w,guard,wrapped_done,w,out);
    if(error.code){free(w);return error;}
    w->job=*out;w->next=active->jobs;active->jobs=w;return error;
}
struct steer_pv1_error __wrap_steer_draft_host_job_release(struct steer_draft_host_job *job){
    struct wrapped_job **at=active?&active->jobs:NULL;while(at&&*at&&(*at)->job!=job)at=&(*at)->next;
    struct wrapped_job *w=at?*at:NULL;
    if(w&&w->selected&&w->fault->mode==REFUSE_JOB&&!w->refused){w->refused=1;atomic_fetch_add_explicit(&w->fault->seen,1,memory_order_release);struct steer_pv1_error e={STEER_PV1_POLICY_DENIED,0};return e;}
    struct steer_pv1_error error=__real_steer_draft_host_job_release(job);
    if(!error.code&&w){assert(w->callback_returned);*at=w->next;free(w);}return error;
}
struct steer_pv1_error __real_steer_draft_operations_create(uint32_t,const struct steer_draft_operation_allocator *,struct steer_draft_operations **);
struct steer_pv1_async_start __real_steer_draft_operation_start(struct steer_draft_operations *,steer_draft_operation_done,void *);
struct steer_pv1_error __real_steer_draft_operation_resolve(struct steer_pv1_operation *,struct steer_pv1_error);
struct steer_pv1_error __wrap_steer_draft_operations_create(uint32_t count,const struct steer_draft_operation_allocator *allocator,struct steer_draft_operations **out){
    struct steer_pv1_error e=__real_steer_draft_operations_create(count,allocator,out);
    if(!e.code&&active&&active->mode==CLOSE_READY&&count==67)active->tls_operations=*out;
    return e;
}
struct steer_pv1_async_start __wrap_steer_draft_operation_start(struct steer_draft_operations *operations,steer_draft_operation_done done,void *userdata){
    struct steer_pv1_async_start start=__real_steer_draft_operation_start(operations,done,userdata);
    if(active&&active->mode==CLOSE_READY&&operations==active->tls_operations&&!active->tls_open&&start.disposition==STEER_PV1_PENDING)active->tls_open=start.operation.handle;
    return start;
}
struct steer_pv1_error __wrap_steer_draft_operation_resolve(struct steer_pv1_operation *operation,struct steer_pv1_error result){
    struct steer_pv1_error e=__real_steer_draft_operation_resolve(operation,result);
    if(!e.code&&!result.code&&active&&active->mode==CLOSE_READY&&operation==active->tls_open&&!atomic_load_explicit(&active->seen,memory_order_acquire)){
        assert(active->lower.handle);atomic_fetch_add_explicit(&active->seen,1,memory_order_release);
        active->lower.api->close(active->lower.handle);
    }
    return e;
}
