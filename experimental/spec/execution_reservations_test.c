#define _GNU_SOURCE
#include "execution_reservations.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static struct steer_spec_journal_record anchor(uint64_t transaction,uint64_t instance){
 struct steer_spec_journal_record r={.key={transaction,instance,1,STEER_SPEC_JOURNAL_ANCHOR},.generation=7,.grant_id=1,.credits=5,.cleanup_floor=3,.length=7};strcpy(r.provider,"fixture.device");strcpy(r.provider_version,"1");memcpy(r.plan_digest,"plan",4);memcpy(r.data,"opaque!",7);return r;
}
static struct steer_spec_journal_record operation(const struct steer_spec_journal_record *a,uint64_t transaction,uint32_t sequence,uint32_t op){struct steer_spec_journal_record r=*a;r.key=(struct steer_spec_journal_key){transaction,a->key.instance,sequence,STEER_SPEC_JOURNAL_INTENT};r.anchor_transaction=a->key.transaction;r.anchor_sequence=a->key.sequence;r.operation=op;r.phase=1;r.credits=r.cleanup_floor=0;r.grant_id=0;return r;}
static struct steer_spec_journal_record outcome(struct steer_spec_journal_record intent,uint32_t sequence,uint32_t effect,uint32_t phase){intent.intent_sequence=intent.key.sequence;intent.key.sequence=sequence;intent.key.kind=STEER_SPEC_JOURNAL_OUTCOME;intent.effect=effect;intent.phase=phase;return intent;}
static struct steer_pv1_error visit(void *arg,const struct steer_spec_journal_record *r){(void)arg;(void)r;return (struct steer_pv1_error){0,0};}
static struct steer_spec_ledger_summary summary(struct steer_spec_ledger *l){struct steer_spec_ledger_summary s;assert(!steer_spec_ledger_scan(l,visit,NULL,&s).code);return s;}
static void append(struct steer_spec_ledger *l,const struct steer_spec_journal_record *r){struct steer_spec_journal_result result=steer_spec_ledger_append(l,r);if(result.error.code)fprintf(stderr,"append failed kind%u tx%llu seq%u code%u\n",r->key.kind,(unsigned long long)r->key.transaction,r->key.sequence,result.error.code);assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);}
static void cleanup(const char *path){DIR *d=opendir(path);assert(d);struct dirent *e;int fd=dirfd(d);while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))assert(!unlinkat(fd,e->d_name,0));closedir(d);assert(!rmdir(path));}
static void lifecycle(void){
 char path[]="/tmp/steer-reservations-life-XXXXXX";assert(mkdtemp(path));struct steer_spec_ledger *l;assert(!steer_spec_ledger_open(path,12,8,&l).code);
 struct steer_spec_journal_record a=anchor(1,10);append(l,&a);struct steer_spec_ledger_summary s=summary(l);assert(s.records==1&&s.reserved_records==5);
 struct steer_spec_journal_record i=operation(&a,1,2,1);append(l,&i);s=summary(l);assert(s.pending_intents==1&&s.reserved_records==4&&s.recovery_required==1);
 assert(!steer_spec_ledger_close(l).code);assert(!steer_spec_ledger_open(path,12,8,&l).code);s=summary(l);assert(s.pending_intents==1&&s.reserved_records==4);
 struct steer_spec_journal_record o=outcome(i,3,1,2);append(l,&o);s=summary(l);assert(!s.pending_intents&&s.reserved_records==3&&!s.recovery_required); /* ACTIVE retains floor */
 struct steer_spec_journal_record b=anchor(2,20);append(l,&b);s=summary(l);assert(s.records==4&&s.reserved_records==8);
 struct steer_spec_journal_record c=anchor(3,30);c.credits=c.cleanup_floor=2;assert(steer_spec_ledger_append(l,&c).error.code==STEER_PV1_RESOURCE_EXHAUSTED); /* would fit if ACTIVE donated floor */
 i=operation(&a,4,4,1);assert(steer_spec_ledger_append(l,&i).error.code==STEER_PV1_RESOURCE_EXHAUSTED); /* ordinary apply cannot spend floor */
 i=operation(&a,4,4,3);i.generation=8;append(l,&i);o=outcome(i,5,1,5);append(l,&o);s=summary(l);assert(s.retired==1&&s.reserved_records==5); /* later tx consumes original anchor credit */
 i=operation(&b,5,2,1);append(l,&i);o=outcome(i,3,2,4);append(l,&o);s=summary(l);assert(s.records==8&&s.reserved_records==3&&s.recovery_required==1);
 assert(steer_spec_ledger_append(l,&c).error.code==STEER_PV1_RESOURCE_EXHAUSTED); /* UNKNOWN never donates */
 assert(!steer_spec_ledger_close(l).code);assert(!steer_spec_ledger_open(path,12,8,&l).code);s=summary(l);assert(s.reserved_records==3&&s.retired==1&&s.recovery_required==1);
 struct steer_spec_ledger_recovery_check checks[]={
  {{1,10,2,STEER_SPEC_JOURNAL_INTENT},0}, /* historical fact, not latest operation on anchor */
  {i.key,0}, /* unknown effect still has a durable fact */
  {{4,20,2,STEER_SPEC_JOURNAL_INTENT},1}, /* same instance/sequence, unrelated transaction */
  {{0},1},
 };
 assert(!steer_spec_ledger_recover_journal(l,&s,checks,4).code&&s.recovery_required==1);
 assert(checks[0].has_fact&&checks[1].has_fact&&!checks[2].has_fact&&!checks[3].has_fact);
 struct steer_spec_journal_record grant=b;grant.key=(struct steer_spec_journal_key){6,20,4,STEER_SPEC_JOURNAL_GRANT};grant.anchor_transaction=b.key.transaction;grant.anchor_sequence=1;grant.grant_id=2;grant.credits=2;grant.cleanup_floor=0;
 assert(steer_spec_ledger_append(l,&grant).error.code==STEER_PV1_RESOURCE_EXHAUSTED); /* grant record itself needs physical space */
 assert(!steer_spec_ledger_close(l).code);assert(!steer_spec_ledger_open(path,20,8,&l).code);append(l,&grant);
 struct steer_spec_journal_record duplicate=grant;duplicate.key.sequence=5;assert(steer_spec_ledger_append(l,&duplicate).error.code==STEER_PV1_INVALID);
 i=operation(&b,7,5,3);append(l,&i);o=outcome(i,6,1,5);append(l,&o);s=summary(l);assert(s.retired==2&&!s.reserved_records&&!s.pending_intents);
 assert(!steer_spec_ledger_close(l).code);cleanup(path);
}
static void forged(unsigned mode){
 char path[]="/tmp/steer-reservations-forged-XXXXXX";assert(mkdtemp(path));struct steer_spec_ledger *l;assert(!steer_spec_ledger_open(path,20,8,&l).code);struct steer_spec_journal_record a=anchor(1,10);append(l,&a);
 struct steer_spec_journal_record r;
 if(mode==2){r=a;r.key.kind=STEER_SPEC_JOURNAL_GRANT;r.key.sequence=2;r.anchor_transaction=1;r.anchor_sequence=1;r.grant_id=2;r.credits=2;r.cleanup_floor=0;append(l,&r);r.key.sequence=3;}
 else{r=operation(&a,2,2,1);if(mode==0)r.anchor_transaction=99;else strcpy(r.provider,"foreign.provider");}
 assert(!steer_spec_ledger_close(l).code);
 /* Corrupt/foreign log construction is deliberately via raw primitive, never
  * the validated coordinator ledger. Whole restart validation must reject it. */
 struct steer_spec_journal *raw;assert(!steer_spec_journal_open(path,20,8,&raw).code);assert(!steer_spec_journal_append(raw,&r).error.code);assert(!steer_spec_journal_close(raw).code);
 assert(steer_spec_ledger_open(path,20,8,&l).code==STEER_PV1_INVALID&&!l);cleanup(path);
}
static void provenance(unsigned uncertain){
 char path[]="/tmp/steer-reservations-provenance-XXXXXX";assert(mkdtemp(path));struct steer_spec_ledger *l;assert(!steer_spec_ledger_open(path,32,16,&l).code);
 struct steer_spec_journal_record a=anchor(1,10);a.credits=12;a.cleanup_floor=4;append(l,&a);
 struct steer_spec_journal_record first=operation(&a,1,2,1),fact=outcome(first,3,uncertain?2u:1u,uncertain?4u:2u);append(l,&first);append(l,&fact);
 assert(!steer_spec_ledger_close(l).code);assert(!steer_spec_ledger_open(path,32,16,&l).code);
 struct steer_spec_journal_record next=operation(&a,2,4,1);
 if(uncertain){assert(steer_spec_ledger_append(l,&next).error.code);next.operation=3;append(l,&next);fact=outcome(next,5,1,5);append(l,&fact);}
 else{
  next.generation=8;append(l,&next);fact=outcome(next,5,1,2);append(l,&fact);
  struct steer_spec_journal_record stale=outcome(first,6,0,5);stale.key.kind=STEER_SPEC_JOURNAL_RECONCILE;
  assert(steer_spec_ledger_append(l,&stale).error.code);assert(!summary(l).retired&&summary(l).reserved_records==8);
  assert(!steer_spec_ledger_close(l).code);struct steer_spec_journal *raw;assert(!steer_spec_journal_open(path,32,16,&raw).code);assert(!steer_spec_journal_append(raw,&stale).error.code);assert(!steer_spec_journal_close(raw).code);
  assert(steer_spec_ledger_open(path,32,16,&l).code&&!l);cleanup(path);return;
 }
 assert(!steer_spec_ledger_close(l).code);cleanup(path);
}
static void restart_inventory(void){
 char path[]="/tmp/steer-reservations-restart-XXXXXX";assert(mkdtemp(path));
 struct steer_spec_ledger *l;
 pid_t child=fork();assert(child>=0);
 if(!child){
  assert(!steer_spec_ledger_open(path,48,16,&l).code);
  for(uint64_t id=1;id<=4;id++){
   struct steer_spec_journal_record a=anchor(id,id*10);append(l,&a);
   if(id==1)continue; /* anchor durable, no intent yet */
   struct steer_spec_journal_record i=operation(&a,id,2,1);append(l,&i);
   if(id==3){ /* last intent persisted; result never recorded */
    struct steer_spec_journal_record grant=a;
    grant.key=(struct steer_spec_journal_key){10,30,3,STEER_SPEC_JOURNAL_GRANT};
    grant.anchor_transaction=3;grant.anchor_sequence=1;grant.grant_id=2;grant.cleanup_floor=0;grant.credits=2;
    append(l,&grant);continue;
   }
   struct steer_spec_journal_record fact=outcome(i,3,1,id==4?5:4);append(l,&fact);
   if(id==2){fact.key.kind=STEER_SPEC_JOURNAL_RECONCILE;fact.key.sequence=4;fact.phase=2;fact.effect=0;append(l,&fact);}
  }
  _exit(0); /* no ledger close or shutdown hook */
 }
 int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
 assert(!steer_spec_ledger_open(path,48,16,&l).code);
 struct steer_spec_ledger_recovery_item items[3]={{.last_sequence=99}};uint32_t count;
 assert(steer_spec_ledger_recover_inventory(l,NULL,0,&count).code==STEER_PV1_RESOURCE_EXHAUSTED&&count==3);
 assert(steer_spec_ledger_recover_inventory(l,items,2,&count).code==STEER_PV1_RESOURCE_EXHAUSTED&&count==3&&items[0].last_sequence==99);
 assert(!steer_spec_ledger_recover_inventory(l,items,3,&count).code&&count==3);
 assert(items[0].anchor.instance==10&&!items[0].intent.kind&&!items[0].fact.kind);
 assert(items[1].anchor.instance==20&&items[1].fact.kind==STEER_SPEC_JOURNAL_RECONCILE&&items[1].fact.sequence==4);
 assert(items[2].anchor.instance==30&&items[2].intent.sequence==2&&!items[2].fact.kind);
 assert(items[2].last_sequence==3&&items[2].remaining==6&&items[2].cleanup_floor==3&&items[2].requires_recovery);
 struct steer_spec_ledger_recovery_item pending=items[2];
 struct steer_spec_journal_record a;assert(!steer_spec_ledger_read(l,&pending.anchor,&a).code);
 struct steer_spec_journal_record grant=a;
 grant.key=(struct steer_spec_journal_key){10,30,UINT32_MAX,STEER_SPEC_JOURNAL_GRANT};
 grant.anchor_transaction=3;grant.anchor_sequence=1;grant.grant_id=3;grant.cleanup_floor=0;grant.credits=1;
 assert(steer_spec_ledger_append(l,&grant).error.code==STEER_PV1_RESOURCE_EXHAUSTED);
 grant.key.sequence=4;append(l,&grant);
 assert(steer_spec_ledger_record_missing_outcome(l,&pending).error.code==STEER_PV1_POLICY_DENIED);
 assert(!steer_spec_ledger_recover_inventory(l,items,3,&count).code&&count==3&&items[2].last_sequence==4);
 pending=items[2];
 struct steer_spec_journal_result result=steer_spec_ledger_record_missing_outcome(l,&pending);
 assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);
 assert(steer_spec_ledger_record_missing_outcome(l,&pending).error.code);
 assert(!steer_spec_ledger_close(l).code&&!steer_spec_ledger_open(path,48,16,&l).code);
 assert(!steer_spec_ledger_recover_inventory(l,items,3,&count).code&&count==3);
 assert(items[2].fact.kind==STEER_SPEC_JOURNAL_OUTCOME&&items[2].fact.sequence==5&&items[2].requires_recovery);
 struct steer_spec_journal_record fact;
 assert(!steer_spec_ledger_read(l,&items[2].fact,&fact).code&&fact.intent_sequence==2&&fact.effect==2&&fact.phase==4);
 assert(fact.length==7&&!memcmp(fact.data,"opaque!",7)&&!memcmp(fact.plan_digest,"plan",4));
 struct steer_spec_journal_record retire=operation(&a,11,6,3);append(l,&retire);
 assert(!steer_spec_ledger_recover_inventory(l,items,3,&count).code&&count==3&&items[2].intent.sequence==6&&!items[2].fact.kind);
 fact=outcome(retire,7,0,5);append(l,&fact);
 assert(!steer_spec_ledger_recover_inventory(l,items,3,&count).code&&count==2);
 assert(!steer_spec_ledger_close(l).code);cleanup(path);
}
int main(void){alarm(20);lifecycle();for(unsigned mode=0;mode<3;mode++)forged(mode);provenance(0);provenance(1);restart_inventory();puts("execution-reservations: cleanup floors, provenance, restart inventory, exact missing outcome, stale replay PASS");return 0;}
