#define _GNU_SOURCE
#include "device_authority_service.h"
#include "loop.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
enum claim_state {EMPTY,WAITING,READY,CLAIMED,CONSUMED,BLOCKED,TERMINAL};
struct steer_spec_authority_scope {
 struct steer_spec_authority_service *service;struct steer_draft_device_authority api;
 struct steer_draft_host_work_guard guard;uint64_t generation;unsigned char digest[32];
 uint32_t jobs,claims;int live,retired;
};
struct claim {
 struct steer_spec_authority_scope *scope;struct steer_spec_journal_record record;
 enum claim_state state;uint64_t deadline;int permit;
};
struct steer_spec_authority_service {
 struct loop *loop;struct steer_draft_host_worker *worker;struct steer_spec_ledger *ledger;
 struct steer_spec_authority_limits limits;struct steer_spec_authority_scope *scopes;struct claim *claims;
 uint32_t live_scopes,live_claims,jobs;int wake,pending,stopped,fenced,storage_fenced,host_fenced,dispatching,foreign_depth,notified,detached;
 void (*drained)(void *);void *drained_user;
};
struct pin {struct steer_spec_authority_scope *scope;unsigned refs;};
struct request {
 struct steer_spec_authority_scope *scope;struct steer_spec_journal_record record;
 struct steer_spec_journal_result result;struct steer_draft_host_job *job;uint64_t deadline;
 struct claim *claim;steer_spec_authority_record_done done;void *user;
};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static void notify(struct steer_spec_authority_service *s){uint64_t one=1;ssize_t n;do n=write(s->wake,&one,sizeof(one));while(n<0&&errno==EINTR);}
static void ready(struct loop *l,int fd,uint32_t events,void *arg){
 struct steer_spec_authority_service *s=arg;(void)l;(void)events;uint64_t count;while(read(fd,&count,sizeof(count))<0&&errno==EINTR){}
 if(s->stopped&&!s->live_scopes&&!s->live_claims&&!s->jobs&&!s->pending&&!s->notified&&s->drained){s->notified=1;s->dispatching=1;s->drained(s->drained_user);s->dispatching=0;}
}
static void clear_claim(struct claim *c){struct steer_spec_authority_service *s=c->scope->service;c->scope->claims--;s->live_claims--;memset(c,0,sizeof(*c));notify(s);}
static void release_permit(void *arg){struct claim *c=arg;if(!c||!c->permit)return;c->permit=0;if(c->state==TERMINAL)clear_claim(c);else c->state=CONSUMED;}
static int span_equal(struct steer_pv1_span a,const void *data,size_t size){return a.len==size&&(!size||(a.data&&!memcmp(a.data,data,size)));}
static struct steer_pv1_error acquire(void *arg,const struct steer_draft_device_authorization *r,struct steer_draft_device_permit *out){
 if(out)*out=(struct steer_draft_device_permit){0};
 struct steer_spec_authority_scope *scope=arg;
 if(!scope||!r||!out||!r->transaction||!r->intent_sequence||r->operation<1||r->operation>3)return error(STEER_PV1_INVALID);
 struct steer_spec_authority_service *s=scope->service;
 if(!scope->live||s->stopped||s->fenced||(scope->retired&&r->operation==STEER_DRAFT_DEVICE_COMMIT))return error(STEER_PV1_POLICY_DENIED);
 for(uint32_t i=0;i<s->limits.claims;i++){
  struct claim *c=&s->claims[i];const struct steer_spec_journal_record *record=&c->record;
  if(c->scope!=scope||c->state!=READY||record->key.transaction!=r->transaction||record->key.sequence!=r->intent_sequence||record->operation!=r->operation||record->generation!=r->generation||record->key.instance!=r->instance_token)continue;
  if(!span_equal(r->provider_id,record->provider,strlen(record->provider))||!span_equal(r->provider_version,record->provider_version,strlen(record->provider_version))||!span_equal(r->recovery_record,record->data,record->length))return error(STEER_PV1_POLICY_DENIED);
  if(now()>=c->deadline){c->state=BLOCKED;return error(STEER_PV1_TIMEOUT);}
  c->state=CLAIMED;c->permit=1;*out=(struct steer_draft_device_permit){c,release_permit};return error(0);
 }
 return error(STEER_PV1_POLICY_DENIED);
}
static void pin_drop(struct pin *p){if(!--p->refs)free(p);}
static struct steer_pv1_error pin_retain(void *arg){struct pin *p=arg;struct steer_spec_authority_scope *scope=p->scope;struct steer_spec_authority_service *s=scope->service;if(s->jobs==s->limits.jobs)return error(STEER_PV1_RESOURCE_EXHAUSTED);p->refs++;s->jobs++;scope->jobs++;return error(0);}
static void pin_release(void *arg){struct pin *p=arg;struct steer_spec_authority_service *s=p->scope->service;p->scope->jobs--;s->jobs--;notify(s);pin_drop(p);}
struct steer_pv1_error steer_spec_authority_service_create(struct loop *loop,struct steer_draft_host_worker *worker,struct steer_spec_ledger **ledger,const struct steer_spec_authority_limits *limits,struct steer_spec_authority_service **out){
 if(out)*out=NULL;
 if(!loop||!worker||!ledger||!*ledger||!limits||!out||steer_draft_host_worker_owner(worker)!=loop||!limits->generations||limits->generations>16||!limits->claims||limits->claims>128||!limits->jobs||limits->jobs>64)return error(STEER_PV1_INVALID);
 struct steer_draft_host_worker_limits worker_limits;steer_draft_host_worker_limits(worker,&worker_limits);
 if(worker_limits.max_input<sizeof(struct steer_spec_journal_record)||worker_limits.max_bytes<sizeof(struct steer_spec_journal_record))return error(STEER_PV1_UNSUPPORTED);
 struct steer_spec_authority_service *s=calloc(1,sizeof(*s));if(!s)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 s->loop=loop;s->worker=worker;s->limits=*limits;s->wake=-1;s->scopes=calloc(limits->generations,sizeof(*s->scopes));s->claims=calloc(limits->claims,sizeof(*s->claims));
 if(!s->scopes||!s->claims)goto fail;
 s->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);if(s->wake<0||loop_fd_add(loop,s->wake,EPOLLIN,ready,s))goto fail;
 s->ledger=*ledger;*ledger=NULL;*out=s;return error(0);
fail:if(s->wake>=0)close(s->wake);free(s->scopes);free(s->claims);free(s);return error(STEER_PV1_RESOURCE_EXHAUSTED);
}
struct steer_pv1_error steer_spec_authority_scope_create(struct steer_spec_authority_service *s,uint64_t generation,const unsigned char digest[32],const struct steer_draft_host_work_guard *guard,struct steer_spec_authority_scope **out){
 if(out)*out=NULL;
 if(!s||!generation||!digest||!guard||!guard->retain||!guard->release||!out)return error(STEER_PV1_INVALID);
 if(s->stopped||s->fenced||s->foreign_depth||s->live_scopes==s->limits.generations)return error(STEER_PV1_POLICY_DENIED);
 struct steer_spec_authority_scope *scope=NULL;
 for(uint32_t i=0;i<s->limits.generations;i++){if(s->scopes[i].live&&s->scopes[i].generation==generation)return error(STEER_PV1_POLICY_DENIED);if(!s->scopes[i].live)scope=&s->scopes[i];}
 s->foreign_depth++;struct steer_pv1_error held=guard->retain(guard->context);
 if(held.code||held.transient){if(!held.code)guard->release(guard->context);s->foreign_depth--;return held.code<=STEER_PV1_INTERNAL&&held.transient<=1&&held.code?held:error(STEER_PV1_PROTOCOL);}
 if(s->stopped||s->fenced){guard->release(guard->context);s->foreign_depth--;return error(STEER_PV1_POLICY_DENIED);}
 memset(scope,0,sizeof(*scope));scope->service=s;scope->generation=generation;memcpy(scope->digest,digest,32);scope->guard=*guard;scope->live=1;scope->api=(struct steer_draft_device_authority){s->loop,scope,acquire};s->live_scopes++;s->foreign_depth--;*out=scope;return error(0);
}
const struct steer_draft_device_authority *steer_spec_authority_scope_api(struct steer_spec_authority_scope *scope){return scope&&scope->live?&scope->api:NULL;}
void steer_spec_authority_scope_retire(struct steer_spec_authority_scope *scope){if(scope&&scope->live)scope->retired=1;}
struct steer_pv1_error steer_spec_authority_scope_release(struct steer_spec_authority_scope *scope){
 if(!scope||!scope->live)return error(STEER_PV1_INVALID);
 struct steer_spec_authority_service *s=scope->service;if(scope->jobs||scope->claims||s->foreign_depth)return error(STEER_PV1_POLICY_DENIED);
 s->foreign_depth++;scope->live=0;s->live_scopes--;scope->guard.release(scope->guard.context);notify(s);s->foreign_depth--;return error(0);
}
static struct steer_draft_host_work_result record_work(void *arg,const void *input,size_t size,uint64_t deadline,const struct steer_draft_cancel *cancel){
 struct request *request=arg;(void)deadline;(void)cancel;
 if(size!=sizeof(request->record))return (struct steer_draft_host_work_result){error(STEER_PV1_PROTOCOL),NULL,0};
 request->result=steer_spec_ledger_append(request->scope->service->ledger,input);
 return (struct steer_draft_host_work_result){request->result.error,request,0};
}
static void recorded(void *arg,struct steer_draft_host_work_result result){
 struct request *request=arg;struct steer_spec_authority_scope *scope=request->scope;struct steer_spec_authority_service *s=scope->service;s->pending=0;
 if(!result.value)request->result=(struct steer_spec_journal_result){result.error,STEER_SPEC_JOURNAL_NOT_RENAMED};
 int cancelled=steer_draft_host_job_cancelled(request->job);
 if(result.worker_flags)s->host_fenced=1;
 if(request->result.error.code==STEER_PV1_IO||request->result.durability==STEER_SPEC_JOURNAL_RENAMED)s->storage_fenced=1;
 s->fenced=s->host_fenced||s->storage_fenced;
 if(request->claim){
  if(!request->result.error.code&&request->result.durability==STEER_SPEC_JOURNAL_SYNCED){request->claim->state=!cancelled&&now()<request->deadline&&!s->fenced&&!s->stopped&&!(scope->retired&&request->record.operation==1)?READY:BLOCKED;}
  else if(request->result.durability==STEER_SPEC_JOURNAL_NOT_RENAMED)clear_claim(request->claim);
  else request->claim->state=BLOCKED;
 }
 if(!request->result.error.code&&(request->record.key.kind==STEER_SPEC_JOURNAL_OUTCOME||request->record.key.kind==STEER_SPEC_JOURNAL_RECONCILE)){
  for(uint32_t i=0;i<s->limits.claims;i++){
   struct claim *c=&s->claims[i];if(c->scope!=scope||c->state==EMPTY||c->record.key.transaction!=request->record.key.transaction||c->record.key.instance!=request->record.key.instance||c->record.key.sequence!=request->record.intent_sequence)continue;
   c->state=TERMINAL;if(!c->permit)clear_claim(c);
  }
 }
 request->done(request->user,request->result,&request->record,cancelled);
 volatile unsigned char *bytes=(volatile unsigned char *)request;for(size_t i=0;i<sizeof(*request);i++)bytes[i]=0;free(request);
}
struct steer_pv1_error steer_spec_authority_record(struct steer_spec_authority_scope *scope,const struct steer_spec_journal_record *record,uint64_t deadline,steer_spec_authority_record_done done,void *user,struct steer_draft_host_job **out){
 if(out)*out=NULL;
 if(!scope||!scope->live||!record||!done||!out||!steer_spec_journal_record_valid(record)||record->generation!=scope->generation||memcmp(record->plan_digest,scope->digest,32))return error(STEER_PV1_INVALID);
 struct steer_spec_authority_service *s=scope->service;
 int fact=record->key.kind==STEER_SPEC_JOURNAL_OUTCOME||record->key.kind==STEER_SPEC_JOURNAL_RECONCILE;
 if(s->detached||s->foreign_depth||s->pending||s->jobs==s->limits.jobs||((s->stopped||s->fenced)&&!fact)||(scope->retired&&record->key.kind==STEER_SPEC_JOURNAL_INTENT&&record->operation==1))return error(STEER_PV1_POLICY_DENIED);
 struct claim *claim=NULL;
 if(record->key.kind==STEER_SPEC_JOURNAL_INTENT){
  for(uint32_t i=0;i<s->limits.claims;i++)if(s->claims[i].state==EMPTY){claim=&s->claims[i];break;}
  if(!claim)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 }
 struct request *request=calloc(1,sizeof(*request));struct pin *pin=calloc(1,sizeof(*pin));
 if(!request||!pin){free(request);free(pin);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 request->scope=scope;request->record=*record;request->deadline=deadline;request->done=done;request->user=user;request->claim=claim;pin->scope=scope;pin->refs=1;
 if(claim){claim->scope=scope;claim->record=*record;claim->deadline=deadline;claim->state=WAITING;s->live_claims++;scope->claims++;}
 s->pending=1;struct steer_draft_host_work_guard guard={pin,pin_retain,pin_release};
 struct steer_pv1_error result=steer_draft_host_worker_submit(s->worker,record,sizeof(*record),deadline,record_work,request,&guard,recorded,request,out);
 if(result.code){s->pending=0;if(claim)clear_claim(claim);free(request);}else request->job=*out;
 pin_drop(pin);return result;
}
void steer_spec_authority_service_stop(struct steer_spec_authority_service *s){if(s&&!s->detached){s->stopped=1;notify(s);}}
struct steer_pv1_error steer_spec_authority_service_on_drained(struct steer_spec_authority_service *s,void (*done)(void *),void *user){
 if(!s||!done)return error(STEER_PV1_INVALID);
 if(s->drained||s->stopped||s->detached)return error(STEER_PV1_POLICY_DENIED);
 s->drained=done;s->drained_user=user;return error(0);
}
struct steer_pv1_error steer_spec_authority_service_detach_owner(struct steer_spec_authority_service *s){
 if(!s)return error(STEER_PV1_INVALID);
 if(s->detached||!s->notified||s->dispatching||s->foreign_depth||s->jobs||s->live_scopes||s->live_claims||s->pending)return error(STEER_PV1_POLICY_DENIED);
 loop_fd_del(s->loop,s->wake);close(s->wake);s->wake=-1;s->detached=1;return error(0);
}
struct steer_pv1_error steer_spec_authority_service_destroy_worker(struct steer_spec_authority_service *s){
 if(!s)return error(STEER_PV1_INVALID);
 if(!s->detached||s->dispatching||s->foreign_depth||s->jobs||s->live_scopes||s->live_claims||s->pending)return error(STEER_PV1_POLICY_DENIED);
 struct steer_pv1_error result=steer_spec_ledger_close(s->ledger);if(result.code)return result;
 free(s->scopes);free(s->claims);free(s);return error(0);
}

struct recovery_request {
 struct steer_spec_authority_scope *scope;struct steer_draft_host_job *job;uint64_t deadline;
 struct steer_spec_ledger_summary summary;struct steer_pv1_error result;
 steer_spec_authority_recovered done;void *user;
};
static struct steer_draft_host_work_result recover_work(void *arg,const void *input,size_t size,uint64_t deadline,const struct steer_draft_cancel *cancel){
 struct recovery_request *r=arg;(void)input;(void)size;(void)deadline;(void)cancel;
 r->result=steer_spec_ledger_recover_journal(r->scope->service->ledger,&r->summary);
 return (struct steer_draft_host_work_result){r->result,r,0};
}
static void recovered(void *arg,struct steer_draft_host_work_result result){
 struct recovery_request *r=arg;struct steer_spec_authority_service *s=r->scope->service;s->pending=0;
 int cancelled=steer_draft_host_job_cancelled(r->job)||now()>=r->deadline;
 if(!result.value)r->result=result.error;
 if(result.worker_flags)s->host_fenced=1;
 if(result.value&&r->result.code)s->storage_fenced=1;
 else if(result.value&&!r->result.code&&!cancelled&&!result.worker_flags)s->storage_fenced=0;
 s->fenced=s->storage_fenced||s->host_fenced;
 r->done(r->user,r->result,&r->summary,cancelled);free(r);
}
struct steer_pv1_error steer_spec_authority_recover_journal(struct steer_spec_authority_scope *scope,uint64_t deadline,steer_spec_authority_recovered done,void *user,struct steer_draft_host_job **out){
 if(out)*out=NULL;
 if(!scope||!scope->live||!done||!out)return error(STEER_PV1_INVALID);
 struct steer_spec_authority_service *s=scope->service;
 if(s->detached||s->foreign_depth||s->pending||s->jobs==s->limits.jobs)return error(STEER_PV1_POLICY_DENIED);
 struct recovery_request *r=calloc(1,sizeof(*r));struct pin *pin=calloc(1,sizeof(*pin));if(!r||!pin){free(r);free(pin);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 r->scope=scope;r->done=done;r->user=user;r->deadline=deadline;pin->scope=scope;pin->refs=1;s->pending=1;
 struct steer_draft_host_work_guard guard={pin,pin_retain,pin_release};struct steer_pv1_error result=steer_draft_host_worker_submit(s->worker,"R",1,deadline,recover_work,r,&guard,recovered,r,out);
 if(result.code){s->pending=0;free(r);}else r->job=*out;
 pin_drop(pin);return result;
}
void steer_spec_authority_status(const struct steer_spec_authority_service *s,struct steer_spec_authority_status *out){
 if(!out)return;
 *out=(struct steer_spec_authority_status){0};if(!s)return;
 out->storage_fenced=(uint32_t)s->storage_fenced;out->host_fenced=(uint32_t)s->host_fenced;out->live_claims=s->live_claims;out->journal_pending=(uint32_t)s->pending;
 for(uint32_t i=0;i<s->limits.claims;i++)if(s->claims[i].state==BLOCKED)out->blocked_intents++;
}
