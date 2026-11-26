#define main coordinator_fixture_main
#define __wrap_fsync fixture_wrap_fsync
#include "kernel_wg_coordinator_test.c"
#undef __wrap_fsync
#undef main
#include "linked_inbound_participant.h"
#include "policy.h"
#include "blake3.h"

static int fail_directory_sync;
int __wrap_fsync(int fd){
    struct stat st;assert(!fstat(fd,&st));
    if(fail_directory_sync&&S_ISDIR(st.st_mode)){fail_directory_sync=0;errno=EIO;return -1;}
    return fixture_wrap_fsync(fd);
}

/* Reuse coordinator's deterministic kernel double, but let the real inbound
 * guard mint the table and marker. This does not exercise kernel networking. */
static int inbound_guard(void *ctx,const struct steer_draft_wg_guard_record *r,int publish,uint64_t d,uint32_t *effect,uint64_t *handle){
    struct fixture *f=ctx;
    if(!publish){strcpy(f->candidate.table,r->table);strcpy(f->candidate.marker,r->marker);}
    return guard(ctx,r,publish,d,effect,handle);
}
static const struct steer_draft_wg_backend inbound_backend={create,stage,inbound_guard,up,retire_link,lookup,retire_guard};
static int attest(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d){
    struct fixture *f=ctx;
    if(f->foreign)return ESTALE;
    if(f->mode==PUBLISH_UNCHANGED)return EPERM; /* injected wrong guard role */
    return verify_selected(ctx,r,d);
}
static void run(const char *base,int scenario){
    char path[4096];snprintf(path,sizeof(path),"%s/case%d",base,scenario);assert(!mkdir(path,0700));
    struct steer_draft_wg_selection *journal;assert(!steer_draft_wg_selection_open_inbound(path,32,&journal));
    struct awg_conf cfg={0};struct fixture f=fixture(NULL,&cfg,11,OK);
    struct steer_draft_kernel_wg_guard *slot=NULL;
    struct steer_linked_inbound p={.journal=journal,.backend=&inbound_backend,.context=&f,.backend_guard=&slot};
    struct steer_draft_wg_revision old={.generation=10,.digest={2},.without_wg=1},chosen={.generation=11,.digest={1}};
    struct steer_draft_wg_guard_record selected;uint64_t next;
    assert(!steer_linked_inbound_recover(&p,&old,attest,UINT64_MAX,&next,&selected));
    struct steer_draft_kernel_wg_guard_config g={.generation=11,.peer_count=1};
    strcpy(g.device,f.candidate.link.physical_name);strcpy(g.inbound_id,"vpn");
    strcpy(g.peers[0].principal_id,"alice");g.peers[0].allowed_count=1;strcpy(g.peers[0].allowed_ips[0],"10.8.0.2/32");
    struct steer_policy *policy=NULL;assert(!steer_policy_compile(11,NULL,0,STEER_POLICY_DIRECT,&policy).code);
    p.recovered=0;
    assert(steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX)==EINVAL);
    p.recovered=1;
    g.return_only=1;assert(steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX)==EINVAL);assert(!f.n);
    g.return_only=0;
    if(scenario==3){
        f.mode=STAGE_ERROR;
        assert(steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX)==EADDRINUSE);
        assert(p.fenced&&f.link&&!f.handle&&!strcmp(f.events,"CS"));
        assert(!steer_linked_inbound_recover(&p,&old,attest,UINT64_MAX,&next,&selected));
        assert(!p.fenced&&!f.link&&!f.handle&&!strcmp(f.events,"CSR"));
        steer_policy_destroy(policy);steer_draft_wg_selection_close(journal);return;
    }
    assert(!steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX));
    assert(!slot&&!strcmp(f.events,"CSBUP"));
    struct steer_prototype_store_result r={{0,0},STEER_PROTOTYPE_STORE_SYNCED};
    if(scenario==0){r.phase=STEER_PROTOTYPE_STORE_NOT_RENAMED;r.error.code=STEER_PV1_IO;
        assert(!steer_linked_inbound_finish(&p,r,attest,UINT64_MAX));assert(!f.link&&!f.handle&&!strcmp(f.events,"CSBUPRLD"));}
    else if(scenario==1){r.phase=STEER_PROTOTYPE_STORE_RENAMED;r.error.code=STEER_PV1_IO;
        assert(steer_linked_inbound_finish(&p,r,attest,UINT64_MAX)==EIO);assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
        assert(steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX)==EINVAL);
        assert(!steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected));assert(!p.fenced&&selected.handle==201);}
    else {assert(!steer_linked_inbound_finish(&p,r,attest,UINT64_MAX));assert(p.fenced);
        steer_draft_wg_selection_close(journal);
        assert(!steer_draft_wg_selection_open_inbound(path,32,&journal));p.journal=journal;
        f.foreign=1;assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==ESTALE);
        assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
        f.foreign=0;f.mode=PUBLISH_UNCHANGED;
        assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==EPERM);
        assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
        f.mode=OK;assert(!steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected));}
    steer_policy_destroy(policy);steer_draft_wg_selection_close(journal);
}
static void selection_digest(struct steer_draft_wg_revision *r,const char *doc,uint64_t generation){
    static const char context[]="steer linked spec v3: scoped WG stream";
    uint8_t hash[32];b3_hash(hash,doc,strlen(doc));
    *r=(struct steer_draft_wg_revision){.generation=generation};
    b3_derive_key(r->digest,sizeof(r->digest),context,sizeof(context)-1,hash,sizeof(hash));
}
static void actual_store(const char *base,int scenario){
    char path[4096],journal_path[4096],store_path[4096];
    assert(snprintf(path,sizeof(path),"%s/store%d",base,scenario)>0);
    assert(!mkdir(path,0700));
    assert(snprintf(journal_path,sizeof(journal_path),"%s/journal",path)>0);
    assert(snprintf(store_path,sizeof(store_path),"%s/store",path)>0);
    assert(!mkdir(journal_path,0700)&&!mkdir(store_path,0700));
    struct steer_prototype_store *store;assert(!steer_prototype_store_open(store_path,&store).code);
    struct steer_draft_wg_selection *journal;assert(!steer_draft_wg_selection_open_inbound(journal_path,32,&journal));
    struct awg_conf cfg={0};struct fixture f=fixture(NULL,&cfg,11,OK);
    struct steer_draft_kernel_wg_guard *slot=NULL;
    struct steer_linked_inbound p={.journal=journal,.backend=&inbound_backend,.context=&f,.backend_guard=&slot};
    const char old_doc[]="{\"version\":3,\"old\":true}",new_doc[]="{\"version\":3,\"device\":\"inbound\"}";
    struct steer_draft_wg_revision old,chosen;
    selection_digest(&old,old_doc,10);old.without_wg=1;
    selection_digest(&chosen,new_doc,11);memcpy(f.tx.plan_digest,chosen.digest,sizeof(chosen.digest));
    struct steer_store_document document={10,STEER_STORE_FORMAT_SPEC_V3,(char *)old_doc,strlen(old_doc)};
    struct steer_prototype_store_transaction *txn;
    assert(!steer_prototype_store_prepare_document(store,&document,&txn).code);
    struct steer_prototype_store_result result=steer_prototype_store_commit(txn);
    assert(!result.error.code&&result.phase==STEER_PROTOTYPE_STORE_SYNCED);
    assert(!steer_prototype_store_abort(txn).code);
    uint64_t next;struct steer_draft_wg_guard_record selected;
    assert(!steer_linked_inbound_recover(&p,&old,attest,UINT64_MAX,&next,&selected));
    struct steer_draft_kernel_wg_guard_config g={.generation=11,.peer_count=1};
    strcpy(g.device,f.candidate.link.physical_name);strcpy(g.inbound_id,"vpn");
    strcpy(g.peers[0].principal_id,"alice");g.peers[0].allowed_count=1;strcpy(g.peers[0].allowed_ips[0],"10.8.0.2/32");
    struct steer_policy *policy=NULL;assert(!steer_policy_compile(11,NULL,0,STEER_POLICY_DIRECT,&policy).code);
    assert(!steer_linked_inbound_prepare(&p,&f.tx,&f.candidate,&g,policy,0,UINT64_MAX));
    assert(!strcmp(f.events,"CSBUP")&&f.link&&f.allow&&f.up);
    document=(struct steer_store_document){11,STEER_STORE_FORMAT_SPEC_V3,(char *)new_doc,strlen(new_doc)};
    assert(!steer_prototype_store_prepare_document(store,&document,&txn).code);
    if(scenario==3)fail_directory_sync=1;
    result=steer_prototype_store_commit(txn);
    assert(!steer_prototype_store_abort(txn).code);
    assert(result.phase==(scenario==3?STEER_PROTOTYPE_STORE_RENAMED:STEER_PROTOTYPE_STORE_SYNCED));
    assert(!!result.error.code==(scenario==3));
    struct steer_store_document *loaded=NULL;
    assert(!steer_prototype_store_load_document(store,&loaded).code);
    assert(loaded->generation==11&&loaded->length==strlen(new_doc)&&!memcmp(loaded->document,new_doc,loaded->length));
    struct steer_draft_wg_revision observed;selection_digest(&observed,loaded->document,loaded->generation);
    assert(!memcmp(observed.digest,chosen.digest,sizeof(chosen.digest)));
    steer_store_document_destroy(loaded);
    if(scenario==1)observed.generation++;
    if(scenario==2)observed.digest[0]^=1;
    if(scenario==4)observed.without_wg=1;
    int rc=steer_linked_inbound_live_commit(&p,result,&observed);
    assert((scenario==0?rc==0:rc==ESTALE));
    assert(p.fenced==(scenario!=0)&&!p.staged&&f.link&&f.up&&f.allow&&f.handle==201);
    assert(!strcmp(f.events,"CSBUP")); /* neither recovery nor cleanup */
    assert(p.committed.generation==(scenario==0?11u:10u));
    if(!scenario){
        assert(!memcmp(p.committed.digest,chosen.digest,sizeof(chosen.digest)));
        struct steer_draft_wg_tx alias={12,12,12,{4}};
        assert(!steer_draft_wg_selection_reuse(journal,&p.committed,&alias,&p.candidate.guard,UINT64_MAX));
        assert(!strcmp(f.events,"CSBUP"));
    }
    assert(steer_linked_inbound_live_commit(&p,result,&observed)==EINVAL);
    steer_policy_destroy(policy);steer_draft_wg_selection_close(journal);
    assert(!steer_prototype_store_close(store).code);
}
static void role_boundary(const char *base){
    char path[4096];assert(snprintf(path,sizeof(path),"%s/legacy-role",base)>0&&!mkdir(path,0700));
    struct steer_draft_wg_selection *journal=NULL;
    assert(!steer_draft_wg_selection_open(path,32,&journal));
    struct awg_conf cfg={0};struct fixture f=fixture(NULL,&cfg,11,OK);
    struct steer_draft_wg_revision old={.generation=10,.digest={2},.without_wg=1},chosen={.generation=11,.digest={1}};
    struct steer_draft_wg_ready ready;
    assert(!steer_draft_wg_selection_stage(journal,&backend,&f,&old,0,&f.tx,&f.candidate,UINT64_MAX,&ready));
    assert(!strcmp(f.events,"CSBUP"));
    struct steer_linked_inbound p={.journal=journal,.backend=&backend,.context=&f};
    uint64_t next;struct steer_draft_wg_guard_record selected;
    assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==EINVAL);
    steer_draft_wg_selection_close(journal);
    assert(!steer_draft_wg_selection_open_inbound(path,32,&journal));p.journal=journal;
    assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==EPROTO);
    assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
    steer_draft_wg_selection_close(journal);
}
int main(int argc,char **argv){
    assert(argc==2);for(int i=0;i<4;i++)run(argv[1],i);
    for(int i=0;i<5;i++)actual_store(argv[1],i);
    role_boundary(argv[1]);
    puts("linked inbound participant and real store live commit PASS");return 0;
}
