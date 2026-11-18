#define _GNU_SOURCE
#include "execution_startup.h"
#include "spec.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct steer_pv1_error verify(void *arg,const struct steer_store_document *doc,unsigned char digest[32]){
 unsigned *calls=arg;(*calls)++;
 struct steer_spec_plan *plan=steer_spec_compile(doc->document,doc->length,NULL,0);
 assert(plan);
 struct steer_spec_summary summary=steer_spec_summary(plan);
 steer_spec_destroy(plan);
 if(!summary.syntax_valid||!summary.topology_valid)return (struct steer_pv1_error){STEER_PV1_INVALID,0};
 /* Fixture plan identity; production verification also resolves the lock. */
 memset(digest,0x5a,32);
 return (struct steer_pv1_error){0,0};
}

static void commit(struct steer_prototype_store *store,uint32_t format,uint64_t generation,char *text){
 struct steer_store_document doc={generation,format,text,strlen(text)};
 struct steer_prototype_store_transaction *transaction;
 assert(!steer_prototype_store_prepare_document(store,&doc,&transaction).code);
 struct steer_prototype_store_result result=steer_prototype_store_commit(transaction);
 assert(!result.error.code&&result.phase==STEER_PROTOTYPE_STORE_SYNCED);
 assert(!steer_prototype_store_abort(transaction).code);
}

static void append(struct steer_spec_ledger *ledger,const struct steer_spec_journal_record *record){
 struct steer_spec_journal_result result=steer_spec_ledger_append(ledger,record);
 assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);
}

static void cleanup(const char *path){
 DIR *dir=opendir(path);assert(dir);
 struct dirent *entry;
 while((entry=readdir(dir)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))assert(!unlinkat(dirfd(dir),entry->d_name,0));
 assert(!closedir(dir)&&!rmdir(path));
}

int main(void){
 alarm(20);
 char config[]="/tmp/steer-startup-config-XXXXXX",journal[]="/tmp/steer-startup-journal-XXXXXX";
 assert(mkdtemp(config)&&mkdtemp(journal));
 struct steer_prototype_store *store;
 struct steer_spec_ledger *ledger;
 assert(!steer_prototype_store_open(config,&store).code&&!steer_spec_ledger_open(journal,32,8,&ledger).code);
 struct steer_spec_journal_record anchor={.key={10,20,1,STEER_SPEC_JOURNAL_ANCHOR},.generation=7,
  .grant_id=1,.credits=4,.cleanup_floor=2,.provider="test.device",.provider_version="1"};
 memset(anchor.plan_digest,0x5a,sizeof(anchor.plan_digest));append(ledger,&anchor);
 struct steer_spec_journal_record intent=anchor;
 intent.key=(struct steer_spec_journal_key){11,20,2,STEER_SPEC_JOURNAL_INTENT};
 intent.generation=8;intent.operation=3;intent.phase=4;
 intent.anchor_transaction=10;intent.anchor_sequence=1;
 intent.grant_id=intent.credits=intent.cleanup_floor=0;
 append(ledger,&intent);
 struct steer_spec_startup_revision revision;
 struct steer_spec_ledger_recovery_item items[1];
 uint32_t count;unsigned calls=0;
 assert(!steer_spec_startup_inspect(store,ledger,verify,&calls,&revision,items,1,&count).code);
 assert(!revision.document&&!calls&&count==1&&items[0].requires_recovery);
 assert(steer_spec_startup_compare(&revision,&anchor)==STEER_SPEC_STARTUP_NO_REVISION);

 char valid[]="{\"version\":3,\"plugin_remotes\":{},\"plugins\":{},\"inbounds\":{},\"outbounds\":{\"d\":{\"type\":\"direct\",\"flow\":[\"stream\"]}},\"routing\":{\"default\":\"d\",\"rules\":[]}}";
 char invalid[]="{\"version\":3}";
 commit(store,STEER_STORE_FORMAT_PROTOTYPE,6,valid);
 assert(steer_spec_startup_inspect(store,ledger,verify,&calls,&revision,items,1,&count).code==STEER_PV1_INVALID&&!revision.document&&!count&&!calls);
 commit(store,STEER_STORE_FORMAT_SPEC_V3,6,invalid);
 assert(steer_spec_startup_inspect(store,ledger,verify,&calls,&revision,items,1,&count).code==STEER_PV1_INVALID&&!revision.document&&!count&&calls==1);

 commit(store,STEER_STORE_FORMAT_SPEC_V3,7,valid);
 assert(!steer_prototype_store_close(store).code&&!steer_spec_ledger_close(ledger).code);
 assert(!steer_prototype_store_open(config,&store).code&&!steer_spec_ledger_open(journal,32,8,&ledger).code);
 assert(steer_spec_startup_inspect(store,ledger,verify,&calls,&revision,NULL,0,&count).code==STEER_PV1_RESOURCE_EXHAUSTED&&!revision.document&&count==1);
 assert(!steer_spec_startup_inspect(store,ledger,verify,&calls,&revision,items,1,&count).code&&revision.document&&count==1);
 struct steer_spec_journal_record record;
 assert(!steer_spec_ledger_read(ledger,&items[0].anchor,&record).code);
 assert(steer_spec_startup_compare(&revision,&record)==STEER_SPEC_STARTUP_MATCH);
 record.plan_digest[0]^=1;
 assert(steer_spec_startup_compare(&revision,&record)==STEER_SPEC_STARTUP_DIGEST_MISMATCH);
 assert(!steer_spec_ledger_read(ledger,&items[0].intent,&record).code&&!items[0].fact.kind);
 assert(steer_spec_startup_compare(&revision,&record)==STEER_SPEC_STARTUP_OTHER_GENERATION);
 steer_store_document_destroy(revision.document);
 assert(!steer_prototype_store_close(store).code&&!steer_spec_ledger_close(ledger).code);
 cleanup(journal);cleanup(config);
 puts("execution-startup: synced config/journal snapshot, v3 validation, exact revision vs anchor and cross-generation intent PASS");
 return 0;
}
