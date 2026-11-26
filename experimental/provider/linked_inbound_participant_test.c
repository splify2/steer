#define main coordinator_fixture_main
#include "kernel_wg_coordinator_test.c"
#undef main
#include "linked_inbound_participant.h"
#include "policy.h"

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
    struct steer_draft_wg_selection *journal;assert(!steer_draft_wg_selection_open(path,32,&journal));
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
        assert(!steer_draft_wg_selection_open(path,32,&journal));p.journal=journal;
        f.foreign=1;assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==ESTALE);
        assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
        f.foreign=0;f.mode=PUBLISH_UNCHANGED;
        assert(steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected)==EPERM);
        assert(p.fenced&&f.link&&f.handle&&!strcmp(f.events,"CSBUP"));
        f.mode=OK;assert(!steer_linked_inbound_recover(&p,&chosen,attest,UINT64_MAX,&next,&selected));}
    steer_policy_destroy(policy);steer_draft_wg_selection_close(journal);
}
int main(int argc,char **argv){assert(argc==2);for(int i=0;i<4;i++)run(argv[1],i);puts("linked inbound participant transaction boundary PASS");return 0;}
