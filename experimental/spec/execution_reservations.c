#include "execution_reservations.h"
#include <steer/draft/device_v1.h>
#include <stdlib.h>
#include <string.h>
struct steer_spec_ledger {struct steer_spec_journal *journal;uint32_t maximum,per_transaction;int busy,uncertain;};
struct entry {
 struct steer_spec_journal_key key;uint64_t generation,anchor_transaction,grant_id;
 uint32_t intent_sequence,operation,effect,phase,anchor_sequence,credits,floor;
 char provider[128],version[64];unsigned char digest[32];
 uint32_t anchor,remaining,pending,current_intent,current_fact,last_sequence;
 int retired,outcome,uncertain;
};
struct model {struct entry *entries;uint32_t count,capacity;struct steer_spec_ledger_summary summary;};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static int same_key(const struct steer_spec_journal_key *a,const struct steer_spec_journal_key *b){return a->transaction==b->transaction&&a->instance==b->instance&&a->sequence==b->sequence&&a->kind==b->kind;}
static int identity(const struct entry *a,const struct entry *b){return a->key.instance==b->key.instance&&!strcmp(a->provider,b->provider)&&!strcmp(a->version,b->version);}
static void copy_entry(struct entry *e,const struct steer_spec_journal_record *r){
 memset(e,0,sizeof(*e));e->key=r->key;e->generation=r->generation;e->anchor_transaction=r->anchor_transaction;e->grant_id=r->grant_id;e->intent_sequence=r->intent_sequence;e->operation=r->operation;e->effect=r->effect;e->phase=r->phase;e->anchor_sequence=r->anchor_sequence;e->credits=r->credits;e->floor=r->cleanup_floor;
 memcpy(e->provider,r->provider,sizeof(e->provider));memcpy(e->version,r->provider_version,sizeof(e->version));memcpy(e->digest,r->plan_digest,32);e->anchor=UINT32_MAX;
}
static struct steer_pv1_error count(void *arg,const struct steer_spec_journal_record *r){(void)arg;(void)r;return error(0);}
static struct steer_pv1_error collect(void *arg,const struct steer_spec_journal_record *r){struct model *m=arg;if(m->count==m->capacity)return error(STEER_PV1_RESOURCE_EXHAUSTED);copy_entry(&m->entries[m->count++],r);return error(0);}
static int compare(const void *aa,const void *bb){const struct entry *a=aa,*b=bb;
 if(a->key.sequence!=b->key.sequence)return a->key.sequence<b->key.sequence?-1:1;
 if(a->key.instance!=b->key.instance)return a->key.instance<b->key.instance?-1:1;
 if(a->key.transaction!=b->key.transaction)return a->key.transaction<b->key.transaction?-1:1;
 return a->key.kind<b->key.kind?-1:a->key.kind>b->key.kind;
}
static int sequence_overdrawn(const struct entry *a){return a->remaining>UINT32_MAX-a->last_sequence;}
static int needs_recovery(const struct entry *a){return a->uncertain||a->pending||a->remaining<a->floor+a->pending||sequence_overdrawn(a);}
static struct steer_pv1_error validate(struct steer_spec_ledger *ledger,struct model *m){
 qsort(m->entries,m->count,sizeof(*m->entries),compare);
 for(uint32_t i=0;i<m->count;i++){
  struct entry *e=&m->entries[i];
  if(e->key.kind==STEER_SPEC_JOURNAL_ANCHOR){
   for(uint32_t k=0;k<i;k++)if(m->entries[k].key.kind==STEER_SPEC_JOURNAL_ANCHOR&&identity(e,&m->entries[k]))return error(STEER_PV1_INVALID);
   e->anchor=i;e->remaining=e->credits;e->current_intent=e->current_fact=UINT32_MAX;e->last_sequence=e->key.sequence;m->summary.anchors++;continue;
  }
  for(uint32_t k=0;k<i;k++)if(m->entries[k].key.kind==STEER_SPEC_JOURNAL_ANCHOR&&m->entries[k].key.transaction==e->anchor_transaction&&m->entries[k].key.instance==e->key.instance&&m->entries[k].key.sequence==e->anchor_sequence){e->anchor=k;break;}
  if(e->anchor==UINT32_MAX)return error(STEER_PV1_INVALID);
  struct entry *a=&m->entries[e->anchor];if(!identity(a,e)||a->retired)return error(STEER_PV1_INVALID);
   for(uint32_t k=0;k<i;k++)if(m->entries[k].anchor==e->anchor&&m->entries[k].key.sequence==e->key.sequence)return error(STEER_PV1_INVALID);
   a->last_sequence=e->key.sequence;
  if(e->key.kind==STEER_SPEC_JOURNAL_GRANT){
   for(uint32_t k=0;k<i;k++)if(m->entries[k].anchor==e->anchor&&m->entries[k].grant_id==e->grant_id)return error(STEER_PV1_INVALID);
   if(e->credits>ledger->maximum-a->remaining)return error(STEER_PV1_RESOURCE_EXHAUSTED);
   a->remaining+=e->credits;continue;
  }
  if(e->key.kind==STEER_SPEC_JOURNAL_INTENT){
   if(a->uncertain&&e->operation!=3&&e->operation!=4)return error(STEER_PV1_POLICY_DENIED);
   uint32_t needed=e->operation==1?a->floor+2:2;
   if(a->pending||a->remaining<needed)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    a->remaining--;a->pending++;a->current_intent=i;a->current_fact=UINT32_MAX;a->uncertain=1;continue;
  }
  struct entry *intent=NULL;
  for(uint32_t k=0;k<i;k++)if(m->entries[k].key.kind==STEER_SPEC_JOURNAL_INTENT&&m->entries[k].key.transaction==e->key.transaction&&m->entries[k].key.instance==e->key.instance&&m->entries[k].key.sequence==e->intent_sequence){intent=&m->entries[k];break;}
  if(!intent||a->current_intent!=(uint32_t)(intent-m->entries)||intent->anchor!=e->anchor||intent->operation!=e->operation||intent->generation!=e->generation||memcmp(intent->digest,e->digest,32))return error(STEER_PV1_INVALID);
  if((e->key.kind==STEER_SPEC_JOURNAL_OUTCOME&&intent->outcome)||!a->remaining)return error(STEER_PV1_INVALID);
  if(e->effect==2&&e->phase!=4)return error(STEER_PV1_INVALID);
  a->remaining--;if(!intent->outcome){intent->outcome=1;if(!a->pending)return error(STEER_PV1_INVALID);a->pending--;}
   a->current_fact=i;a->uncertain=e->phase==4||e->effect==2;
  if(e->phase==5&&e->effect!=2){if(a->pending)return error(STEER_PV1_INVALID);a->retired=1;a->remaining=0;}
 }
 m->summary.records=m->count;
 for(uint32_t i=0;i<m->count;i++){
  struct entry *e=&m->entries[i];
   if(e->key.kind==STEER_SPEC_JOURNAL_ANCHOR){m->summary.reserved_records+=e->remaining;m->summary.pending_intents+=e->pending;if(e->retired)m->summary.retired++;else if(needs_recovery(e))m->summary.recovery_required++;}
  if(e->key.kind==STEER_SPEC_JOURNAL_INTENT&&!e->outcome){uint32_t physical=0,pending=0;for(uint32_t k=0;k<m->count;k++)if(m->entries[k].key.transaction==e->key.transaction){physical++;if(m->entries[k].key.kind==STEER_SPEC_JOURNAL_INTENT&&!m->entries[k].outcome)pending++;}if(physical+pending>ledger->per_transaction)return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 }
 return error((uint64_t)m->count+m->summary.orphan_temporaries+m->summary.reserved_records>ledger->maximum?STEER_PV1_RESOURCE_EXHAUSTED:0);
}
static struct steer_pv1_error build(struct steer_spec_ledger *ledger,const struct steer_spec_journal_record *candidate,struct model *m){
 memset(m,0,sizeof(*m));struct steer_spec_journal_scan_report report;
 struct steer_pv1_error result=steer_spec_journal_scan(ledger->journal,count,NULL,&report);if(result.code)return result;
 if(candidate&&(uint64_t)report.records+report.orphan_temporaries>=ledger->maximum)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 m->capacity=report.records+(candidate?1u:0u);m->entries=calloc(m->capacity?m->capacity:1,sizeof(*m->entries));if(!m->entries)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 result=steer_spec_journal_scan(ledger->journal,collect,m,&report);if(result.code)goto fail;
 m->summary.orphan_temporaries=report.orphan_temporaries;
 if(candidate){
  uint32_t last=0;
  for(uint32_t i=0;i<m->count;i++){
   struct entry *e=&m->entries[i];if(same_key(&e->key,&candidate->key)){result=error(STEER_PV1_POLICY_DENIED);goto fail;}
   if(candidate->key.kind!=STEER_SPEC_JOURNAL_ANCHOR&&e->key.instance==candidate->key.instance&&
    ((e->key.kind==STEER_SPEC_JOURNAL_ANCHOR&&e->key.transaction==candidate->anchor_transaction&&e->key.sequence==candidate->anchor_sequence)||
     (e->anchor_transaction==candidate->anchor_transaction&&e->anchor_sequence==candidate->anchor_sequence)))if(e->key.sequence>last)last=e->key.sequence;
  }
  if(candidate->key.kind!=STEER_SPEC_JOURNAL_ANCHOR&&candidate->key.sequence<=last){result=error(STEER_PV1_POLICY_DENIED);goto fail;}
  copy_entry(&m->entries[m->count++],candidate);
 }
 result=validate(ledger,m);if(result.code)goto fail;
 if(candidate){
  /* Physical slots alone are not a reserve: each remaining credit also needs
   * a usable sequence number on this anchor, regardless of transaction. */
  for(uint32_t i=0;i<m->count;i++)if(same_key(&m->entries[i].key,&candidate->key)){
   const struct entry *a=&m->entries[m->entries[i].anchor];
   if(sequence_overdrawn(a)){result=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
   break;
  }
 }
 return result;
fail:free(m->entries);m->entries=NULL;return result;
}
struct steer_pv1_error steer_spec_ledger_open(const char *path,uint32_t maximum,uint32_t per_transaction,struct steer_spec_ledger **out){
 if(out)*out=NULL;
 if(!out)return error(STEER_PV1_INVALID);
 struct steer_spec_ledger *ledger=calloc(1,sizeof(*ledger));if(!ledger)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 ledger->maximum=maximum;ledger->per_transaction=per_transaction;struct steer_pv1_error result=steer_spec_journal_open(path,maximum,per_transaction,&ledger->journal);
 if(!result.code){struct model model;result=build(ledger,NULL,&model);if(!result.code)free(model.entries);}
 if(result.code){if(ledger->journal)steer_spec_journal_close(ledger->journal);free(ledger);return result;}
 *out=ledger;return error(0);
}
struct steer_pv1_error steer_spec_ledger_close(struct steer_spec_ledger *ledger){
 if(!ledger)return error(STEER_PV1_INVALID);
 if(ledger->busy)return error(STEER_PV1_POLICY_DENIED);
 struct steer_pv1_error result=steer_spec_journal_close(ledger->journal);if(!result.code)free(ledger);return result;
}
struct steer_spec_journal_result steer_spec_ledger_append(struct steer_spec_ledger *ledger,const struct steer_spec_journal_record *record){
 struct steer_spec_journal_result result={error(STEER_PV1_INVALID),STEER_SPEC_JOURNAL_NOT_RENAMED};
 if(!ledger||!steer_spec_journal_record_valid(record))return result;
 if(ledger->busy||ledger->uncertain){result.error=error(STEER_PV1_POLICY_DENIED);return result;}
 ledger->busy=1;struct model model;result.error=build(ledger,record,&model);
 if(!result.error.code){free(model.entries);result=steer_spec_journal_append(ledger->journal,record);if(result.error.code&&result.durability==STEER_SPEC_JOURNAL_RENAMED)ledger->uncertain=1;}
 ledger->busy=0;return result;
}
struct steer_pv1_error steer_spec_ledger_scan(struct steer_spec_ledger *ledger,struct steer_pv1_error (*visit)(void *,const struct steer_spec_journal_record *),void *context,struct steer_spec_ledger_summary *summary){
 if(summary)memset(summary,0,sizeof(*summary));
 if(!ledger||!visit||!summary)return error(STEER_PV1_INVALID);
 if(ledger->busy)return error(STEER_PV1_POLICY_DENIED);
 ledger->busy=1;struct model model;struct steer_pv1_error result=build(ledger,NULL,&model);
 if(!result.code){struct steer_spec_journal_scan_report report;result=steer_spec_journal_scan(ledger->journal,visit,context,&report);if(!result.code)*summary=model.summary;free(model.entries);}
 ledger->busy=0;return result;
}

/* On success transfers the fully revalidated model; never touches the kernel. */
static struct steer_pv1_error recover_model(struct steer_spec_ledger *ledger,struct model *model){
 if(ledger->busy)return error(STEER_PV1_POLICY_DENIED);
 ledger->busy=1;
 struct steer_pv1_error result=build(ledger,NULL,model);
 if(!result.code){free(model->entries);result=steer_spec_journal_sync_existing(ledger->journal);}
 if(!result.code){result=build(ledger,NULL,model);if(!result.code)ledger->uncertain=0;}
 ledger->busy=0;
 return result;
}
struct steer_pv1_error steer_spec_ledger_recover_journal(struct steer_spec_ledger *ledger,struct steer_spec_ledger_summary *summary,
 struct steer_spec_ledger_recovery_check *checks,uint32_t check_count){
 if(summary)memset(summary,0,sizeof(*summary));
 if(check_count>STEER_SPEC_LEDGER_RECOVERY_CHECKS_MAX||(check_count&&!checks))return error(STEER_PV1_INVALID);
 for(uint32_t i=0;i<check_count;i++)checks[i].has_fact=0;
 if(!ledger||!summary)return error(STEER_PV1_INVALID);
 struct model model;struct steer_pv1_error result=recover_model(ledger,&model);
 if(result.code)return result;
 if(check_count){
  for(uint32_t i=0;i<model.count;i++){
   const struct entry *entry=&model.entries[i];
   if(entry->key.kind!=STEER_SPEC_JOURNAL_INTENT||!entry->outcome)continue;
   for(uint32_t k=0;k<check_count;k++)if(same_key(&entry->key,&checks[k].intent))checks[k].has_fact=1;
  }
 }
 *summary=model.summary;free(model.entries);return result;
}

struct steer_pv1_error steer_spec_ledger_recover_inventory(struct steer_spec_ledger *ledger,
 struct steer_spec_ledger_recovery_item *items,uint32_t capacity,uint32_t *count){
 if(count)*count=0;
 if(!ledger||!count||(capacity&&!items))return error(STEER_PV1_INVALID);
 struct model model;struct steer_pv1_error result=recover_model(ledger,&model);
 if(result.code)return result;
 *count=model.summary.anchors-model.summary.retired;
 if(*count>capacity){free(model.entries);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 uint32_t next=0;
 for(uint32_t i=0;i<model.count;i++){
  const struct entry *a=&model.entries[i];
  if(a->key.kind!=STEER_SPEC_JOURNAL_ANCHOR||a->retired)continue;
  struct steer_spec_ledger_recovery_item item={.anchor=a->key,.last_sequence=a->last_sequence,
   .remaining=a->remaining,.cleanup_floor=a->floor,.requires_recovery=needs_recovery(a)};
  if(a->current_intent!=UINT32_MAX)item.intent=model.entries[a->current_intent].key;
  if(a->current_fact!=UINT32_MAX)item.fact=model.entries[a->current_fact].key;
  items[next++]=item;
 }
 free(model.entries);return result;
}

struct steer_pv1_error steer_spec_ledger_read(struct steer_spec_ledger *ledger,
 const struct steer_spec_journal_key *key,struct steer_spec_journal_record *out){
 if(!out)return error(STEER_PV1_INVALID);
 struct steer_pv1_error result=error(STEER_PV1_INVALID);
 if(ledger&&key){
  if(ledger->busy||ledger->uncertain)result=error(STEER_PV1_POLICY_DENIED);
  else result=steer_spec_journal_read(ledger->journal,key,out);
 }
 if(result.code)memset(out,0,sizeof(*out));
 return result;
}

struct steer_spec_journal_result steer_spec_ledger_record_missing_outcome(struct steer_spec_ledger *ledger,
 const struct steer_spec_ledger_recovery_item *item){
 struct steer_spec_journal_result result={error(STEER_PV1_INVALID),STEER_SPEC_JOURNAL_NOT_RENAMED};
 if(!ledger||!item||item->anchor.kind!=STEER_SPEC_JOURNAL_ANCHOR||
    item->intent.kind!=STEER_SPEC_JOURNAL_INTENT||item->fact.kind||item->last_sequence<item->intent.sequence)return result;
 if(item->last_sequence==UINT32_MAX){result.error=error(STEER_PV1_RESOURCE_EXHAUSTED);return result;}
 struct steer_spec_journal_record fact;
 result.error=steer_spec_ledger_read(ledger,&item->intent,&fact);
 if(result.error.code)return result;
 const struct steer_spec_journal_key anchor={fact.anchor_transaction,fact.key.instance,fact.anchor_sequence,STEER_SPEC_JOURNAL_ANCHOR};
 if(!same_key(&anchor,&item->anchor)){result.error=error(STEER_PV1_INVALID);return result;}
 fact.intent_sequence=fact.key.sequence;
 fact.key.sequence=item->last_sequence+1;
 fact.key.kind=STEER_SPEC_JOURNAL_OUTCOME;
 fact.phase=STEER_PV1_DEVICE_UNCERTAIN;
 fact.effect=STEER_PV1_DEVICE_EFFECT_UNCERTAIN;
 return steer_spec_ledger_append(ledger,&fact);
}
