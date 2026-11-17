#define _GNU_SOURCE
#include "device_authority_service.h"
#include "loop.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct fixture {
 struct loop *loop;struct loop_timer *work;struct steer_draft_host_worker *worker;
 struct steer_spec_authority_service *service;struct steer_spec_authority_scope *scope;
 struct steer_draft_host_job *job,*destroy_job;struct steer_spec_journal_record record;
 struct steer_draft_device_permit permit;struct steer_draft_device_authorization request;
 unsigned calls,phase,service_drained,worker_drained,destroyed;atomic_uint guards;
};
static uint64_t deadline(void){return (uint64_t)loop_now_ms()*1000000ull+5000000000ull;}
static void wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error retain(void *arg){struct fixture *f=arg;atomic_fetch_add(&f->guards,1);return (struct steer_pv1_error){0,0};}
static void release(void *arg){struct fixture *f=arg;assert(atomic_fetch_sub(&f->guards,1)>1);}
static void recorded(void *arg,struct steer_spec_journal_result result,const struct steer_spec_journal_record *r,int cancelled){
 struct fixture *f=arg;assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED&&!cancelled&&r->key.sequence==f->record.key.sequence);f->calls++;
 assert(steer_draft_host_job_release(f->job).code==STEER_PV1_POLICY_DENIED);
 assert(steer_spec_authority_scope_release(f->scope).code==STEER_PV1_POLICY_DENIED);wake(f);
}
static void submit(struct fixture *f){f->calls=0;assert(!steer_spec_authority_record(f->scope,&f->record,deadline(),recorded,f,&f->job).code);}
static void release_job(struct fixture *f){assert(f->calls==1);assert(!steer_draft_host_job_release(f->job).code);f->job=NULL;}
static void expect_denied(struct fixture *f){const struct steer_draft_device_authority *api=steer_spec_authority_scope_api(f->scope);struct steer_draft_device_permit p;assert(api->acquire(api->context,&f->request,&p).code&&!p.context&&!p.release);}
static void acquire(struct fixture *f){const struct steer_draft_device_authority *api=steer_spec_authority_scope_api(f->scope);assert(!api->acquire(api->context,&f->request,&f->permit).code&&f->permit.context&&f->permit.release);}
static void service_drained(void *arg){struct fixture *f=arg;assert(++f->service_drained==1);assert(steer_spec_authority_service_detach_owner(f->service).code==STEER_PV1_POLICY_DENIED);wake(f);}
static void worker_drained(void *arg){struct fixture *f=arg;assert(++f->worker_drained==1);wake(f);}
static struct steer_draft_host_work_result destroy(void *arg,const void *data,size_t length,uint64_t until,const struct steer_draft_cancel *cancel){struct fixture *f=arg;(void)data;(void)length;(void)until;(void)cancel;assert(!steer_spec_authority_service_destroy_worker(f->service).code);return (struct steer_draft_host_work_result){{0,0},NULL,0};}
static void destroyed(void *arg,struct steer_draft_host_work_result result){struct fixture *f=arg;assert(!result.error.code&&!result.value);f->destroyed=1;wake(f);}
static void make_intent(struct fixture *f,uint64_t txn,uint32_t sequence,uint32_t operation){
 f->record.key.transaction=txn;f->record.key.sequence=sequence;f->record.key.kind=STEER_SPEC_JOURNAL_INTENT;f->record.intent_sequence=0;f->record.operation=operation;f->record.effect=0;f->record.phase=1;f->record.anchor_transaction=1;f->record.anchor_sequence=1;f->record.credits=f->record.cleanup_floor=0;f->record.grant_id=0;
}
static void make_outcome(struct fixture *f,uint32_t sequence,uint32_t phase){f->record.intent_sequence=f->record.key.sequence;f->record.key.sequence=sequence;f->record.key.kind=STEER_SPEC_JOURNAL_OUTCOME;f->record.effect=1;f->record.phase=phase;}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
 struct fixture *f=arg;(void)timer;
 if(f->phase<7&&!f->calls)return;
 if(f->phase==0){release_job(f);make_intent(f,1,2,1);f->request.intent_sequence=2;submit(f);expect_denied(f);f->phase=1;return;}
 if(f->phase==1){release_job(f);f->request.intent_sequence=1;expect_denied(f);f->request.intent_sequence=2;struct steer_pv1_span original=f->request.recovery_record;f->request.recovery_record=(struct steer_pv1_span){(const uint8_t *)"forged!",7};expect_denied(f);f->request.recovery_record=original;acquire(f);expect_denied(f);make_outcome(f,3,2);submit(f);f->phase=2;return;}
 if(f->phase==2){release_job(f);assert(steer_spec_authority_scope_release(f->scope).code==STEER_PV1_POLICY_DENIED);f->permit.release(f->permit.context);make_intent(f,1,4,1);submit(f);f->phase=3;return;}
 if(f->phase==3){release_job(f);expect_denied(f); /* consumed seq2 must NOT take newer same tuple seq4 */
  f->request.intent_sequence=4;acquire(f);steer_spec_authority_scope_retire(f->scope);make_outcome(f,5,2);submit(f);f->phase=4;return;}
 if(f->phase==4){release_job(f);f->permit.release(f->permit.context);make_intent(f,2,6,3);f->request.transaction=2;f->request.intent_sequence=6;f->request.operation=3;submit(f);f->phase=5;return;}
 if(f->phase==5){release_job(f);acquire(f);make_outcome(f,7,5);submit(f);f->phase=6;return;}
 if(f->phase==6){release_job(f);f->permit.release(f->permit.context);assert(!steer_spec_authority_scope_release(f->scope).code);f->scope=NULL;steer_spec_authority_service_stop(f->service);f->phase=7;return;}
 if(f->phase==7){if(!f->service_drained)return;assert(!steer_spec_authority_service_detach_owner(f->service).code);struct steer_draft_host_work_guard guard={f,retain,release};assert(!steer_draft_host_worker_submit(f->worker,"x",1,deadline(),destroy,f,&guard,destroyed,f,&f->destroy_job).code);f->phase=8;return;}
 if(f->phase==8){if(!f->destroyed)return;assert(!steer_draft_host_job_release(f->destroy_job).code);f->service=NULL;assert(atomic_load(&f->guards)==1);steer_draft_host_worker_stop(f->worker);f->phase=9;return;}
 if(f->phase==9&&f->worker_drained){assert(!steer_draft_host_worker_destroy(f->worker).code);f->phase=10;loop_stop(loop,0);}
}
static void cleanup(const char *path){DIR *d=opendir(path);assert(d);struct dirent *e;while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))assert(!unlinkat(dirfd(d),e->d_name,0));closedir(d);assert(!rmdir(path));}
int main(void){
 alarm(20);char path[]="/tmp/steer-authority-test-XXXXXX";assert(mkdtemp(path));struct steer_spec_ledger *ledger;assert(!steer_spec_ledger_open(path,32,16,&ledger).code);struct fixture f={0};atomic_init(&f.guards,1);f.loop=loop_new();f.work=loop_timer_new(f.loop,step,&f);
 struct steer_draft_host_worker_limits wl={2,8,8192,16384};assert(!steer_draft_host_worker_create(f.loop,&wl,&f.worker).code);assert(!steer_draft_host_worker_on_drained(f.worker,worker_drained,&f).code);
 struct steer_spec_authority_limits limits={2,4,4};assert(!steer_spec_authority_service_create(f.loop,f.worker,&ledger,&limits,&f.service).code&&!ledger);assert(!steer_spec_authority_service_on_drained(f.service,service_drained,&f).code);
 unsigned char digest[32]={0};memcpy(digest,"plan",4);struct steer_draft_host_work_guard guard={&f,retain,release};assert(!steer_spec_authority_scope_create(f.service,7,digest,&guard,&f.scope).code);
 f.record=(struct steer_spec_journal_record){.key={1,10,1,STEER_SPEC_JOURNAL_ANCHOR},.generation=7,.grant_id=1,.credits=8,.cleanup_floor=3,.length=7};strcpy(f.record.provider,"fixture.device");strcpy(f.record.provider_version,"1");memcpy(f.record.plan_digest,digest,32);memcpy(f.record.data,"opaque!",7);
 f.request=(struct steer_draft_device_authorization){.operation=1,.transaction=1,.generation=7,.instance_token=10,.provider_id={(const uint8_t *)"fixture.device",14},.provider_version={(const uint8_t *)"1",1},.recovery_record={(const uint8_t *)"opaque!",7}};
 submit(&f);assert(!loop_run(f.loop)&&f.phase==10);loop_timer_free(f.work);loop_free(f.loop);cleanup(path);puts("device-authority: actual durable receipts/exact one-shot intent key/stale replay/retired cleanup/permit+job drain PASS");return 0;
}
