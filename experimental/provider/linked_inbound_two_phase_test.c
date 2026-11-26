#define _GNU_SOURCE
#include "linked_inbound_participant.h"
#include "kernel_wg_linux_guard.h"
#include "prototype_store.h"
#include "awg.h"
#include "awgdev.h"
#include "blake3.h"
#include <steer/draft/device_v1.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int fail_rename,fail_directory_sync,fail_publish,track_intent,file_synced,directory_synced;
static int track_publish,publish_file_synced,publish_directory_synced,fail_publication_sync;
static int fail_reconfirm,barrier_close_calls,fail_after_open,foreign_barrier;
static char events[32];static size_t events_n;static int receipt_confirmed;
static void event(char c){assert(events_n+1<sizeof events);events[events_n++]=c;events[events_n]=0;}
int __real_renameat(int,const char *,int,const char *);
int __wrap_renameat(int a,const char *b,int c,const char *d){
    if(fail_rename&&!strcmp(d,"config.json")){fail_rename=0;errno=EIO;return -1;}
    return __real_renameat(a,b,c,d);
}
int __real_fsync(int);
int __wrap_fsync(int fd){
    struct stat st;assert(!fstat(fd,&st));
    if(fail_directory_sync&&S_ISDIR(st.st_mode)){fail_directory_sync=0;errno=EIO;return -1;}
    if(fail_publication_sync&&S_ISREG(st.st_mode)){fail_publication_sync=0;errno=EIO;return -1;}
    int rc=__real_fsync(fd);
    if(!rc&&track_intent){
        if(S_ISREG(st.st_mode))file_synced=1;
        if(S_ISDIR(st.st_mode)&&file_synced)directory_synced=1;
    }
    if(!rc&&track_publish){
        if(S_ISREG(st.st_mode))publish_file_synced=1;
        if(S_ISDIR(st.st_mode)&&publish_file_synced)publish_directory_synced=1;
    }
    return rc;
}
static int guard(void *ctx,const struct steer_draft_wg_guard_record *record,int publish,uint64_t d,uint32_t *effect,uint64_t *handle){
    if(publish){
        assert(receipt_confirmed);
        assert(!awg_dev_link_require_down_owned_until(record->link.physical_name,record->link.kind,
            (int)record->ifindex,record->link.group,d));
        event('P');track_publish=1;
    }else{assert(!receipt_confirmed);event('B');}
    if(publish&&fail_publish==1){*effect=STEER_PV1_DEVICE_UNCHANGED;*handle=0;return EIO;}
    int rc=steer_draft_wg_linux_guard_backend.guard(ctx,record,publish,d,effect,handle);
    if(publish&&fail_publish==4&&!rc&&*effect==STEER_PV1_DEVICE_CHANGED)fail_publication_sync=1;
    if(publish&&fail_publish==3&&!rc&&*effect==STEER_PV1_DEVICE_CHANGED){
        puts("WINDOW POLICY CHANGED BEFORE OUTCOME");fflush(stdout);raise(SIGKILL);
    }
    if(publish&&fail_publish==2&&!rc&&*effect==STEER_PV1_DEVICE_CHANGED)return EIO;
    return rc;
}
static int barrier_close(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d,uint32_t *state){
    event('L');barrier_close_calls++;
    if(fail_reconfirm&&barrier_close_calls==2){*state=STEER_INBOUND_BARRIER_UNKNOWN;return EIO;}
    if(foreign_barrier){
        struct steer_draft_wg_guard_record foreign=*record;
        foreign.link.group=foreign.link.group==1?2:foreign.link.group^1;
        return steer_draft_wg_linux_guard_barrier_close(ctx,&foreign,d,state);
    }
    return steer_draft_wg_linux_guard_barrier_close(ctx,record,d,state);
}
static int barrier_open(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d,uint32_t *state){
    assert(publish_file_synced&&publish_directory_synced);
    event('O');int rc=steer_draft_wg_linux_guard_barrier_open(ctx,record,d,state);
    return !rc&&fail_after_open?EIO:rc;
}
static int create(void *ctx,const struct steer_draft_wg_identity *id,int mtu,uint64_t d,int *index){
    assert(track_intent&&file_synced&&directory_synced);
    track_intent=0;
    event('C');return steer_draft_wg_linux_guard_backend.create_down(ctx,id,mtu,d,index);
}
static int stage(void *ctx,const struct steer_draft_wg_identity *id,int index,const struct awg_conf *config,
    const struct awg_secrets *keys,uint32_t mark,uint64_t d){
    event('S');return steer_draft_wg_linux_guard_backend.stage_down(ctx,id,index,config,keys,mark,d);
}
static int up(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d){
    event('U');return steer_draft_wg_linux_guard_backend.up(ctx,record,d);
}
static int none(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d){(void)ctx;(void)record;(void)d;return EPROTO;}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec+10000000000u;}
static const char olddoc[]="{\"version\":3,\"generation\":\"old\"}";
static const char newdoc[]="{\"version\":3,\"generation\":\"device\"}";
static struct steer_draft_wg_revision choice(const char *doc,uint64_t generation,int without){
    struct steer_draft_wg_revision r={.generation=generation,.without_wg=without};
    static const char domain[]="steer test inbound closed v1";uint8_t digest[32];
    b3_hash(digest,doc,strlen(doc));b3_derive_key(r.digest,32,domain,sizeof(domain)-1,digest,sizeof(digest));return r;
}
int main(int argc,char **argv){
    if(argc!=4)return 2;
    if(!strcmp(argv[1],"--probe")){
        struct steer_draft_wg_linux_link *l=NULL;assert(!steer_draft_wg_linux_link_open(3,&l));
        struct steer_draft_wg_selection *j=NULL;assert(!steer_draft_wg_selection_open_inbound(argv[2],64,&j));
        struct steer_prototype_store *s=NULL;assert(!steer_prototype_store_open(argv[3],&s).code);
        struct steer_store_document *loaded=NULL;assert(!steer_prototype_store_recover_document(s,&loaded).code);
        assert(loaded->generation==2&&loaded->length==strlen(newdoc)&&!memcmp(loaded->document,newdoc,loaded->length));
        steer_store_document_destroy(loaded);
        struct steer_draft_wg_linux_guard g={.link=l};
        struct steer_linked_inbound p={.journal=j,.backend=&steer_draft_wg_linux_guard_backend,.context=&g,.backend_guard=&g.prepared};
        struct steer_draft_wg_revision selected=choice(newdoc,2,0);uint64_t next;
        struct steer_draft_wg_guard_record record;
        int rc=steer_linked_inbound_recover(&p,&selected,none,deadline(),&next,&record);
        printf("PROBE %d %d\n",rc,p.fenced);fflush(stdout);
        assert(!steer_prototype_store_close(s).code);steer_draft_wg_selection_close(j);steer_draft_wg_linux_link_close(l);
        return 0;
    }
    struct steer_draft_wg_linux_link *link=NULL;assert(!steer_draft_wg_linux_link_open(3,&link));
    struct steer_draft_wg_selection *journal=NULL;assert(!steer_draft_wg_selection_open_inbound(argv[1],64,&journal));
    struct steer_prototype_store *store=NULL;assert(!steer_prototype_store_open(argv[2],&store).code);
    struct steer_store_document doc={1,STEER_STORE_FORMAT_SPEC_V3,(char *)olddoc,strlen(olddoc)};
    struct steer_prototype_store_transaction *transaction=NULL;
    assert(!steer_prototype_store_prepare_document(store,&doc,&transaction).code);
    struct steer_prototype_store_result result=steer_prototype_store_commit(transaction);
    assert(result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code);
    assert(!steer_prototype_store_abort(transaction).code);
    struct steer_draft_wg_backend backend=steer_draft_wg_linux_guard_backend;
    backend.create_down=create;backend.stage_down=stage;backend.up=up;backend.guard=guard;
    struct steer_draft_wg_linux_guard gctx={.link=link};
    struct steer_linked_inbound p={.journal=journal,.backend=&backend,.context=&gctx,.backend_guard=&gctx.prepared,
        .barrier_close=barrier_close,.barrier_open=barrier_open};
    struct steer_draft_wg_revision old=choice(olddoc,1,1),selected=choice(newdoc,2,0);
    uint64_t next;struct steer_draft_wg_guard_record prior;
    assert(!steer_linked_inbound_recover(&p,&old,none,deadline(),&next,&prior));
    struct steer_draft_wg_tx tx={.transaction=2,.generation=2,.instance=2};memcpy(tx.plan_digest,selected.digest,32);
    struct awg_conf wg={.mtu=1420,.listen_port=51821,.has_listen_port=1,.addr_n=1,.peer_n=1,.aips_n=1};
    assert(!awg_prefix_parse("10.80.0.1/24",&wg.addr[0])&&!awg_prefix_parse("10.80.0.2/32",&wg.aips[0]));
    assert(!awg_key_from_b64(wg.peer[0].pub,argv[3]));wg.peer[0].aip_n=1;
    struct awg_secrets keys={.has_priv=1,.priv={1}};
    struct steer_draft_wg_candidate candidate={.config=&wg,.keys=&keys};
    assert(!steer_draft_wg_linux_link_prepare(link,&tx,deadline(),NULL,&candidate.link));
    struct steer_draft_kernel_wg_guard_config gc={.generation=2,.peer_count=1};
    strcpy(gc.device,candidate.link.physical_name);strcpy(gc.inbound_id,"vpn");
    strcpy(gc.peers[0].principal_id,"alice");gc.peers[0].allowed_count=1;strcpy(gc.peers[0].allowed_ips[0],"10.80.0.2/32");
    struct steer_policy *policy=NULL;assert(!steer_policy_compile(2,NULL,0,STEER_POLICY_DIRECT,&policy).code);
    p.barrier_close=NULL;
    assert(steer_linked_inbound_prepare_closed(&p,&tx,&candidate,&gc,policy,deadline())==EINVAL);
    p.barrier_close=barrier_close;p.barrier_open=NULL;
    assert(steer_linked_inbound_prepare_closed(&p,&tx,&candidate,&gc,policy,deadline())==EINVAL);
    p.barrier_open=barrier_open;assert(!events_n);
    track_intent=1;
    assert(!steer_linked_inbound_prepare_closed(&p,&tx,&candidate,&gc,policy,deadline()));awg_secrets_wipe(&keys);
    assert(!strcmp(events,"CSBU"));
    struct steer_prototype_store_result forged={{0,0},STEER_PROTOTYPE_STORE_SYNCED};
    assert(steer_linked_inbound_live_commit(&p,forged,&selected)==EINVAL);
    assert(p.staged&&p.closed_stage&&!strcmp(events,"CSBU"));
    printf("CLOSED %s %s\n",p.candidate.guard.link.physical_name,p.candidate.guard.table);fflush(stdout);
    int mode=getchar();assert(mode=='s'||mode=='n'||mode=='r'||mode=='p'||mode=='a'||mode=='u'||mode=='j'||mode=='o'||mode=='f'||mode=='m'||mode=='x'||mode=='k');
    doc=(struct steer_store_document){2,STEER_STORE_FORMAT_SPEC_V3,(char *)newdoc,strlen(newdoc)};
    assert(!steer_prototype_store_prepare_document(store,&doc,&transaction).code);
    if(mode=='n')fail_rename=1;
    if(mode=='r')fail_directory_sync=1;
    result=steer_prototype_store_commit(transaction);
    assert(!steer_prototype_store_abort(transaction).code);
    if(mode=='x'){
        assert(result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code);
        puts("WINDOW SYNCED BEFORE PUBLISH");fflush(stdout);
        assert(!steer_prototype_store_close(store).code);
        steer_draft_wg_selection_close(journal);steer_draft_wg_linux_link_close(link);
        return 0;
    }
    if(result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code){receipt_confirmed=1;event('D');}
    else event(result.phase==STEER_PROTOTYPE_STORE_RENAMED?'R':'N');
    if(mode=='p')fail_publish=1;
    if(mode=='a')fail_publish=2;
    if(mode=='u'){fail_publish=2;fail_reconfirm=1;}
    if(mode=='j')fail_publish=4;
    if(mode=='o')fail_after_open=1;
    if(mode=='f')foreign_barrier=1;
    if(mode=='k')fail_publish=3;
    if(mode=='m')selected.digest[0]^=1;
    int rc=steer_linked_inbound_finish_closed(&p,result,&selected,none,deadline());
    assert(!strcmp(events,mode=='s'?"CSBUDLPO":mode=='o'?"CSBUDLPOL":mode=='f'?"CSBUDLL":mode=='p'||mode=='a'||mode=='u'||mode=='j'?"CSBUDLPL":mode=='m'?"CSBUD":mode=='r'?"CSBUR":"CSBUN"));
    struct steer_store_document *on_disk=NULL;assert(!steer_prototype_store_load_document(store,&on_disk).code);
    printf("DONE %d %u %u %d %d %llu %llu %u %u\n",rc,result.phase,result.error.code,p.fenced,p.durable_unknown,
        (unsigned long long)p.committed.generation,(unsigned long long)on_disk->generation,p.barrier_state,p.publication_state);fflush(stdout);
    steer_store_document_destroy(on_disk);
    assert(getchar()=='\n');assert(getchar()=='q');
    steer_policy_destroy(policy);assert(!steer_prototype_store_close(store).code);
    steer_draft_wg_selection_close(journal);steer_draft_wg_linux_link_close(link);return 0;
}
