#define _GNU_SOURCE
#include "execution_reservations.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
int main(void){alarm(20);lifecycle();for(unsigned mode=0;mode<3;mode++)forged(mode);provenance(0);provenance(1);puts("execution-reservations: restart/ACTIVE+unknown floors/later-txn retire/topup physical budget/missing+foreign anchors/duplicate grants PASS");return 0;}
