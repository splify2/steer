#include "execution_startup.h"
#include <string.h>

struct steer_pv1_error steer_spec_startup_inspect(struct steer_prototype_store *store,struct steer_spec_ledger *ledger,
 steer_spec_startup_verify verify,void *context,struct steer_spec_startup_revision *out,
 struct steer_spec_ledger_recovery_item *items,uint32_t capacity,uint32_t *count){
 if(out)*out=(struct steer_spec_startup_revision){0};
 if(count)*count=0;
 if(!store||!ledger||!verify||!out||!count||(capacity&&!items))return (struct steer_pv1_error){STEER_PV1_INVALID,0};
 struct steer_spec_startup_revision revision={0};
 struct steer_pv1_error result=steer_prototype_store_recover_document(store,&revision.document);
 if(result.code&&result.code!=STEER_PV1_UNSUPPORTED)return result;
 if(revision.document){
  if(revision.document->format!=STEER_STORE_FORMAT_SPEC_V3)result=(struct steer_pv1_error){STEER_PV1_INVALID,0};
  else result=verify(context,revision.document,revision.plan_digest);
  if(result.code||result.transient){steer_store_document_destroy(revision.document);return result;}
 }
 result=steer_spec_ledger_recover_inventory(ledger,items,capacity,count);
 if(result.code){steer_store_document_destroy(revision.document);return result;}
 *out=revision;
 return result;
}

enum steer_spec_startup_relation steer_spec_startup_compare(const struct steer_spec_startup_revision *revision,
 const struct steer_spec_journal_record *record){
 if(!revision->document)return STEER_SPEC_STARTUP_NO_REVISION;
 if(revision->document->generation!=record->generation)return STEER_SPEC_STARTUP_OTHER_GENERATION;
 if(memcmp(revision->plan_digest,record->plan_digest,sizeof(revision->plan_digest)))return STEER_SPEC_STARTUP_DIGEST_MISMATCH;
 return STEER_SPEC_STARTUP_MATCH;
}
