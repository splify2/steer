#define _GNU_SOURCE
#include "device_authority_service.h"
#include "loop.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
static atomic_uint fail_sync;
static int inject_flags;
static uint64_t delay_until;
static struct steer_draft_host_job **cancel_slot;
int __real_fsync(int);
int __wrap_fsync(int fd){struct stat s;assert(!fstat(fd,&s));if(S_ISDIR(s.st_mode)&&atomic_exchange(&fail_sync,0)){errno=EIO;return -1;}return __real_fsync(fd);}
struct wrapped {steer_draft_host_work_done done;void *user;unsigned flags;uint64_t until;struct steer_draft_host_job **cancel;};
struct steer_pv1_error __real_steer_draft_host_worker_submit(struct steer_draft_host_worker *,const void *,size_t,uint64_t,steer_draft_host_work_run,void *,const struct steer_draft_host_work_guard *,steer_draft_host_work_done,void *,struct steer_draft_host_job **);
static void injected(void *arg,struct steer_draft_host_work_result r){
 struct wrapped *w=arg;steer_draft_host_work_done done=w->done;void *user=w->user;
 if(w->until){struct timespec t={(time_t)(w->until/1000000000ull),(long)(w->until%1000000000ull)};while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL)==EINTR){}}
 if(w->cancel)steer_draft_host_job_cancel(*w->cancel);
 r.worker_flags|=w->flags;free(w);done(user,r);
}
struct steer_pv1_error __wrap_steer_draft_host_worker_submit(struct steer_draft_host_worker *worker,const void *data,size_t size,uint64_t until,steer_draft_host_work_run run,void *context,const struct steer_draft_host_work_guard *guard,steer_draft_host_work_done done,void *user,struct steer_draft_host_job **out){
 if(!inject_flags&&!delay_until&&!cancel_slot)return __real_steer_draft_host_worker_submit(worker,data,size,until,run,context,guard,done,user,out);
 struct wrapped *w=malloc(sizeof(*w));assert(w);*w=(struct wrapped){done,user,inject_flags?STEER_DRAFT_HOST_QUARANTINE_THREAD:0,delay_until,cancel_slot};inject_flags=0;delay_until=0;cancel_slot=NULL;struct steer_pv1_error e=__real_steer_draft_host_worker_submit(worker,data,size,until,run,context,guard,injected,w,out);if(e.code)free(w);return e;
}
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;
 struct steer_spec_authority_service *service;struct steer_spec_authority_scope *scope;
 struct steer_draft_host_job *job;struct steer_spec_journal_record record;
 struct steer_draft_device_authorization authorization;struct steer_draft_device_permit permit;
 unsigned mode,phase,called,recovered,service_drained,worker_drained,destroyed;int resource;atomic_uint guards;
};
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static struct steer_spec_authority_status status(struct fixture *f){struct steer_spec_authority_status s;steer_spec_authority_status(f->service,&s);return s;}
static void denied(struct fixture *f){const struct steer_draft_device_authority *a=steer_spec_authority_scope_api(f->scope);struct steer_draft_device_permit p;assert(a->acquire(a->context,&f->authorization,&p).code&&!p.context);}
static void recorded(void *arg,struct steer_spec_journal_result result,const struct steer_spec_journal_record *r,int cancelled){
 struct fixture *f=arg;assert(!cancelled&&r->key.sequence==f->record.key.sequence&&++f->called==1);
 if(f->phase==1&&f->mode==2)assert(result.error.code==STEER_PV1_IO&&result.durability==STEER_SPEC_JOURNAL_RENAMED);
 else assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);
 assert(steer_spec_authority_scope_release(f->scope).code==STEER_PV1_POLICY_DENIED);wake(f);
}
static void submit(struct fixture *f){f->called=0;assert(!steer_spec_authority_record(f->scope,&f->record,deadline(),recorded,f,&f->job).code);}
static void job_release(struct fixture *f){assert(!steer_draft_host_job_release(f->job).code);f->job=NULL;}
static void recovery_done(void *arg,struct steer_pv1_error e,const struct steer_spec_ledger_summary *s,int cancelled){
 struct fixture *f=arg;assert(++f->recovered==1);
 if(f->phase==2)assert(e.code==STEER_PV1_IO&&!cancelled);
 else{assert(!e.code&&s->pending_intents==1&&s->recovery_required==1);assert(cancelled==(f->phase==20||f->phase==21));}
 wake(f);
}
static void recover_at(struct fixture *f,uint64_t until){f->recovered=0;assert(!steer_spec_authority_recover_journal(f->scope,until,recovery_done,f,&f->job).code);}
static void recover(struct fixture *f){recover_at(f,deadline());}
static void service_drained(void *arg){struct fixture *f=arg;assert(++f->service_drained==1);wake(f);}
static void worker_drained(void *arg){struct fixture *f=arg;assert(++f->worker_drained==1);wake(f);}
static struct steer_draft_host_work_result destroy(void *arg,const void *input,size_t size,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)input;(void)size;(void)until;(void)cancel;assert(!steer_spec_authority_service_destroy_worker(f->service).code);return (struct steer_draft_host_work_result){{0,0},NULL,0};}
static void destroyed(void *arg,struct steer_draft_host_work_result r){struct fixture *f=arg;assert(!r.error.code&&!r.value);f->destroyed=1;wake(f);}
static void step(struct loop *l,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 if(f->phase==0){if(!f->called)return;job_release(f);f->record.key.kind=STEER_SPEC_JOURNAL_INTENT;f->record.key.sequence=2;f->record.operation=1;f->record.phase=1;f->record.anchor_transaction=1;f->record.anchor_sequence=1;f->record.credits=f->record.cleanup_floor=0;f->record.grant_id=0;if(f->mode==1)inject_flags=1;else atomic_store(&fail_sync,1);submit(f);f->phase=1;return;}
 if(f->phase==1){if(!f->called)return;job_release(f);denied(f);struct steer_spec_authority_status s=status(f);assert(s.blocked_intents==1&&s.live_claims==1);if(f->mode==1){assert(s.host_fenced&&!s.storage_fenced);recover(f);f->phase=30;return;}assert(s.storage_fenced&&!s.host_fenced);atomic_store(&fail_sync,1);recover(f);f->phase=2;return;}
 if(f->phase==30){if(!f->recovered)return;job_release(f);assert(status(f).host_fenced&&!status(f).storage_fenced);denied(f);steer_spec_authority_service_stop(f->service);f->record.key.kind=STEER_SPEC_JOURNAL_OUTCOME;f->record.key.sequence=3;f->record.intent_sequence=2;f->record.effect=0;f->record.phase=5;submit(f);f->phase=7;return;}
 if(f->phase==2){if(!f->recovered)return;job_release(f);assert(status(f).storage_fenced&&status(f).blocked_intents==1);denied(f);assert(steer_spec_authority_scope_release(f->scope).code==STEER_PV1_POLICY_DENIED);uint64_t until=deadline()-4900000000ull;delay_until=until+20000000ull;recover_at(f,until);f->phase=20;return;}
 if(f->phase==20){if(!f->recovered)return;job_release(f);assert(status(f).storage_fenced&&status(f).blocked_intents==1);denied(f);cancel_slot=&f->job;recover(f);f->phase=21;return;}
 if(f->phase==21){if(!f->recovered)return;job_release(f);assert(status(f).storage_fenced&&status(f).blocked_intents==1);denied(f);recover(f);f->phase=3;return;}
 if(f->phase==3){if(!f->recovered)return;job_release(f);assert(!status(f).storage_fenced&&status(f).blocked_intents==1);denied(f);f->record.key.kind=STEER_SPEC_JOURNAL_OUTCOME;f->record.key.sequence=3;f->record.intent_sequence=2;f->record.effect=2;f->record.phase=4;submit(f);f->phase=4;return;}
 if(f->phase==4){if(!f->called)return;job_release(f);f->record.key=(struct steer_spec_journal_key){2,10,4,STEER_SPEC_JOURNAL_INTENT};f->record.intent_sequence=0;f->record.operation=3;f->record.effect=0;f->record.phase=4;f->authorization.transaction=2;f->authorization.intent_sequence=4;f->authorization.operation=3;submit(f);f->phase=5;return;}
 if(f->phase==5){if(!f->called)return;job_release(f);const struct steer_draft_device_authority *a=steer_spec_authority_scope_api(f->scope);assert(!a->acquire(a->context,&f->authorization,&f->permit).code);assert(f->resource>=0);int old=f->resource;assert(!close(old)&&fcntl(old,F_GETFD)<0&&errno==EBADF);f->resource=-1;
  f->record.key.kind=STEER_SPEC_JOURNAL_OUTCOME;f->record.key.sequence=5;f->record.intent_sequence=4;f->record.effect=1;f->record.phase=5;submit(f);f->phase=6;return;}
 if(f->phase==6||f->phase==7){if(!f->called)return;job_release(f);if(f->mode==2){assert(steer_spec_authority_scope_release(f->scope).code==STEER_PV1_POLICY_DENIED);f->permit.release(f->permit.context);}assert(!steer_spec_authority_scope_release(f->scope).code);f->scope=NULL;steer_spec_authority_service_stop(f->service);f->phase=8;return;}
 if(f->phase==8){if(!f->service_drained)return;assert(!steer_spec_authority_service_detach_owner(f->service).code);struct steer_draft_host_work_guard guard={f,retain,release};assert(!steer_draft_host_worker_submit(f->worker,"x",1,deadline(),destroy,f,&guard,destroyed,f,&f->job).code);f->phase=9;return;}
 if(f->phase==9){if(!f->destroyed)return;job_release(f);assert(atomic_load(&f->guards)==1);steer_draft_host_worker_stop(f->worker);f->phase=10;return;}
 if(f->phase==10&&f->worker_drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->phase=11;loop_stop(l,0);}
}
static void cleanup(const char *path){DIR *d=opendir(path);assert(d);struct dirent *e;while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))assert(!unlinkat(dirfd(d),e->d_name,0));closedir(d);assert(!rmdir(path));}
static void scenario(unsigned mode){
 char path[]="/tmp/steer-authority-recover-XXXXXX";assert(mkdtemp(path));struct steer_spec_ledger *ledger;assert(!steer_spec_ledger_open(path,32,16,&ledger).code);struct fixture f={0};f.mode=mode;f.resource=mode==2?eventfd(0,EFD_CLOEXEC):-1;if(mode==2)assert(f.resource>=0);atomic_init(&f.guards,1);f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);
 struct steer_draft_host_worker_limits wl={2,8,8192,16384};assert(!steer_draft_host_worker_create(f.loop,&wl,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,worker_drained,&f).code);
 struct steer_spec_authority_limits limits={2,4,4};assert(!steer_spec_authority_service_create(f.loop,f.worker,&ledger,&limits,&f.service).code&&!ledger);assert(!steer_spec_authority_service_on_drained(f.service,service_drained,&f).code);
 unsigned char digest[32]={0};memcpy(digest,"plan",4);struct steer_draft_host_work_guard guard={&f,retain,release};assert(!steer_spec_authority_scope_create(f.service,7,digest,&guard,&f.scope).code);
 f.record=(struct steer_spec_journal_record){.key={1,10,1,STEER_SPEC_JOURNAL_ANCHOR},.generation=7,.grant_id=1,.credits=8,.cleanup_floor=3,.length=7};strcpy(f.record.provider,"fixture.device");strcpy(f.record.provider_version,"1");memcpy(f.record.plan_digest,digest,32);memcpy(f.record.data,"opaque!",7);
 f.authorization=(struct steer_draft_device_authorization){.operation=1,.intent_sequence=2,.transaction=1,.generation=7,.instance_token=10,.provider_id={(const uint8_t *)"fixture.device",14},.provider_version={(const uint8_t *)"1",1},.recovery_record={(const uint8_t *)"opaque!",7}};
 submit(&f);assert(!loop_run(f.loop)&&f.phase==11&&f.resource<0);loop_timer_free(f.work);loop_free(f.loop);cleanup(path);
}
int main(void){alarm(20);atomic_init(&fail_sync,0);scenario(1);scenario(2);puts("device-authority-recovery: host flags preserve receipt/fence + uncertain fsync/failed recovery/fresh retire/owned resource drain PASS");return 0;}
