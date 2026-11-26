#define _GNU_SOURCE
#include "linked_inbound_recovery.h"
#include "prototype_store.h"
#include "awg.h"
#include "blake3.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char document[]="{\"version\":3,\"inbound\":\"vpn\",\"source\":\"10.80.0.2/32\","
    "\"public_key\":\"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\"}";
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec+10000000000u;}
static struct steer_draft_wg_revision choice(void){
    static const char domain[]="steer linked spec v3: scoped WG stream";uint8_t hash[32];
    struct steer_draft_wg_revision r={.generation=1};b3_hash(hash,document,strlen(document));
    b3_derive_key(r.digest,32,domain,sizeof(domain)-1,hash,sizeof hash);return r;
}
static int dummy(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d){(void)ctx;(void)record;(void)d;return EPROTO;}
static void conf(unsigned generation,struct awg_conf *wg,struct steer_draft_kernel_wg_guard_config *g){
    static const uint8_t public_key[32]={0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f};
    *wg=(struct awg_conf){.mtu=1420,.listen_port=(uint16_t)(51820+generation),.has_listen_port=1,.addr_n=1,.peer_n=1,.aips_n=1};
    assert(!awg_prefix_parse(generation==1?"10.80.0.1/24":"10.81.0.1/24",&wg->addr[0]));
    assert(!awg_prefix_parse(generation==1?"10.80.0.2/32":"10.81.0.2/32",&wg->aips[0]));
    memcpy(wg->peer[0].pub,public_key,32);wg->peer[0].aip_n=1;
    *g=(struct steer_draft_kernel_wg_guard_config){.generation=generation,.peer_count=1};
    strcpy(g->inbound_id,"vpn");strcpy(g->peers[0].principal_id,"alice");g->peers[0].allowed_count=1;
    strcpy(g->peers[0].allowed_ips[0],generation==1?"10.80.0.2/32":"10.81.0.2/32");
}
int main(int argc,char **argv){
    if(argc!=4)return 2;
    const char *mode=argv[1],*journal_path=argv[2],*store_path=argv[3];
    struct steer_draft_wg_linux_link *link=NULL;assert(!steer_draft_wg_linux_link_open(3,&link));
    struct steer_draft_wg_selection *journal=NULL;assert(!steer_draft_wg_selection_open_inbound(journal_path,64,&journal));
    struct steer_prototype_store *store=NULL;assert(!steer_prototype_store_open(store_path,&store).code);
    struct awg_conf wg;struct steer_draft_kernel_wg_guard_config g;conf(1,&wg,&g);
    struct steer_policy *policy=NULL;assert(!steer_policy_compile(1,NULL,0,STEER_POLICY_DIRECT,&policy).code);
    struct steer_linked_inbound_recovery ctx={.guard={.link=link},.revision=choice(),.inbound=&g,.policy=policy,.wireguard=&wg};
    struct steer_linked_inbound p={.journal=journal,.backend=&steer_draft_wg_linux_guard_backend,.context=&ctx,.backend_guard=&ctx.guard.prepared};
    struct steer_draft_wg_guard_record selected;uint64_t next;int rc=0;
    if(!strcmp(mode,"setup")){
        struct steer_draft_wg_revision empty={0};assert(!steer_linked_inbound_recover(&p,&empty,dummy,deadline(),&next,&selected));
    }else{
        struct steer_store_document *loaded=NULL;assert(!steer_prototype_store_recover_document(store,&loaded).code);
        assert(loaded->generation==1&&loaded->format==STEER_STORE_FORMAT_SPEC_V3&&loaded->length==strlen(document)&&!memcmp(loaded->document,document,loaded->length));steer_store_document_destroy(loaded);
        if(!strcmp(mode,"wrong-digest"))ctx.revision.digest[0]^=1;
        if(!strcmp(mode,"wrong-generation"))ctx.revision.generation++;
        if(!strcmp(mode,"wrong-role"))g.return_only=1;
        if(!strcmp(mode,"extra-policy")){
            const struct steer_policy_rule rule={.id={(const uint8_t *)"block",5},.match_all=1,.action=STEER_POLICY_BLOCK};
            steer_policy_destroy(policy);policy=NULL;
            assert(!steer_policy_compile(1,&rule,1,STEER_POLICY_DIRECT,&policy).code);
            ctx.policy=policy;
        }
        rc=steer_linked_inbound_recover_checked(&p,&ctx,!strcmp(mode,"expired")?1:deadline(),&next,&selected);
        printf("RECOVERY %d\n",rc);fflush(stdout);
        if(rc||strcmp(mode,"orphan"))goto done;
    }
    if(!strcmp(mode,"setup")||!strcmp(mode,"orphan")){
        unsigned generation=!strcmp(mode,"setup")?1:2;
        struct steer_draft_wg_tx tx={.transaction=generation,.generation=generation,.instance=generation};
        struct steer_draft_wg_revision selected_revision=choice();memcpy(tx.plan_digest,selected_revision.digest,32);
        if(generation==2)tx.plan_digest[0]^=0x55;
        struct steer_draft_wg_candidate candidate={0};
        struct awg_secrets keys={.has_priv=1,.priv={1}};conf(generation,&wg,&g);
        if(generation==2){steer_policy_destroy(policy);policy=NULL;assert(!steer_policy_compile(2,NULL,0,STEER_POLICY_DIRECT,&policy).code);}
        assert(!steer_draft_wg_linux_link_prepare(link,&tx,deadline(),NULL,&candidate.link));
        strcpy(g.device,candidate.link.physical_name);candidate.config=&wg;candidate.keys=&keys;
        rc=steer_linked_inbound_prepare(&p,&tx,&candidate,&g,policy,generation==1?0:51821,deadline());
        awg_secrets_wipe(&keys);
        if(rc){printf("PREPARE %d\n",rc);goto done;}
        printf("DEVICE %s %s %s %llu %u\n",p.candidate.guard.link.physical_name,p.candidate.guard.table,p.candidate.guard.marker,
            (unsigned long long)p.candidate.guard.handle,p.candidate.guard.ifindex);fflush(stdout);
        if(generation==1){
            struct steer_store_document doc={1,STEER_STORE_FORMAT_SPEC_V3,(char *)document,strlen(document)};
            struct steer_prototype_store_transaction *txn=NULL;assert(!steer_prototype_store_prepare_document(store,&doc,&txn).code);
            struct steer_prototype_store_result r=steer_prototype_store_commit(txn);assert(!steer_prototype_store_abort(txn).code);
            assert(!steer_linked_inbound_live_commit(&p,r,&selected_revision));
        }
    }
    done:steer_policy_destroy(policy);assert(!steer_prototype_store_close(store).code);
    steer_draft_wg_selection_close(journal);steer_draft_wg_linux_link_close(link);return rc?1:0;
}
