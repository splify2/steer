#define _GNU_SOURCE
#include "kernel_wg_ownership.h"
#include "kernel_wg_v3.h"
#include "../spec/execution_journal.h"
#include "../spec/spec.h"
#include "awgdev.h"
#include <steer/draft/device_v1.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/wireguard.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static _Thread_local int track;
static _Thread_local size_t live_bytes,peak_bytes;
static _Thread_local struct {void *p;size_t n;} allocation[8];
void *__real_malloc(size_t);void __real_free(void *);
void *__wrap_malloc(size_t n){void *p=__real_malloc(n);if(p&&track){unsigned j;for(j=0;j<8&&allocation[j].p;j++){}assert(j<8);allocation[j].p=p;allocation[j].n=n;live_bytes+=n;if(live_bytes>peak_bytes)peak_bytes=live_bytes;}return p;}
void __wrap_free(void *p){for(unsigned j=0;j<8;j++)if(p&&allocation[j].p==p){live_bytes-=allocation[j].n;allocation[j].p=NULL;break;}__real_free(p);}
/* Public RFC7748 section6.1 test vectors, never user credentials.
 * https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1 */
static const char scalar[]="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char peer[]="de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static void bytes(const char *s,uint8_t out[32]){for(unsigned j=0;j<32;j++){unsigned n;assert(sscanf(s+2*j,"%2x",&n)==1);out[j]=(uint8_t)n;}}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+2000000000u;}
static void config(struct awg_conf *c,struct awg_secrets *s){
    memset(c,0,sizeof *c);memset(s,0,sizeof *s);bytes(scalar,s->priv);s->has_priv=1;
    c->peer_n=1;c->aips_n=1;bytes(peer,c->peer[0].pub);c->peer[0].aip_n=1;
    c->aips[0].family=AF_INET;c->aips[0].cidr=32;c->aips[0].addr[0]=10;c->aips[0].addr[1]=77;c->aips[0].addr[3]=2;
}
static void wire(void){
    struct awg_conf *c=calloc(1,sizeof *c);struct awg_secrets s;assert(c);config(c,&s);
    _Alignas(8) uint8_t b[2048];size_t n=awg_build_set_index(b,sizeof b,33,1,0,123,c,&s,0,1,7);assert(n);
    size_t at=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(struct genlmsghdr));unsigned found=0;
    while(at<n){const struct nlattr *a=(const void *)(b+at);assert(a->nla_len>=sizeof *a&&a->nla_len<=n-at);
        assert((a->nla_type&NLA_TYPE_MASK)!=WGDEVICE_A_IFNAME);
        if((a->nla_type&NLA_TYPE_MASK)==WGDEVICE_A_IFINDEX){uint32_t index;assert(a->nla_len==sizeof *a+4);memcpy(&index,a+1,4);assert(index==123);found++;}at+=NLA_ALIGN(a->nla_len);
    }
    assert(found==1&&at==n&&!awg_build_set_index(b,sizeof b,33,1,0,0,c,&s,0,1,7));awg_secrets_wipe(&s);free(c);
}
static void *owner(void *arg){
    uintptr_t number=(uintptr_t)arg;assert(!unshare(CLONE_NEWNET));int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(ns>=0);
    struct awg_conf *c=calloc(1,sizeof *c);struct awg_live *live=calloc(1,sizeof *live);struct awg_secrets keys;assert(c&&live);config(c,&keys);
    atomic_uint cancel=0;struct steer_draft_wg_identity id;struct steer_draft_wg_observation o;
    assert(!steer_draft_wg_identity_prepare(ns,12,100+number,"wireguard",deadline(),&cancel,&id));
    assert(!steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel,&o));int index=o.index;
    for(unsigned j=0;j<6;j++){
        if(!number)assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group==1?2:1,c,&keys,0,deadline())==ESTALE);
        track=1;peak_bytes=0;
        assert(!awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline()));
        track=0;assert(!live_bytes&&peak_bytes<=131072u);
        assert(!awg_dev_live_read_owned_until(id.physical_name,id.kind,index,id.group,live,deadline())&&live->peer_n==1&&!memcmp(live->peer[0].pub,c->peer[0].pub,32));
    }
    c->peer_n=AWG_MAX_PEERS+1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EINVAL);c->peer_n=1;
    c->peer[0].aip_first=SIZE_MAX;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EINVAL);c->peer[0].aip_first=0;
    c->peer[0].has_ep=1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EDESTADDRREQ);c->peer[0].has_ep=0;
    c->u16_has=1u<<AWG_JC;c->u16[AWG_JC]=1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EOPNOTSUPP);c->u16_has=0;
    assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,1)==ETIMEDOUT);
    assert(!awg_dev_live_read_owned_until(id.physical_name,id.kind,index,id.group,live,deadline())&&live->peer_n==1&&!memcmp(live->peer[0].pub,c->peer[0].pub,32));
    assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel,&o));awg_secrets_wipe(&keys);free(live);free(c);close(ns);return NULL;
}
static int load_options(const char *path,struct steer_draft_wg_v3_config *config){
    static const struct steer_spec_capability options={
        "provider.wireguard:main/inbound/device/device/none/default",
        STEER_SPEC_BUILT|STEER_SPEC_SUPPORTED,steer_draft_wg_v3_options,NULL
    };
    char *source=malloc(STEER_SPEC_MAX_BYTES+1u);
    FILE *f=fopen(path,"rb");assert(source&&f);
    size_t n=fread(source,1,STEER_SPEC_MAX_BYTES+1u,f);
    assert(!ferror(f)&&n<=STEER_SPEC_MAX_BYTES);fclose(f);
    struct steer_spec_plan *plan=steer_spec_compile(source,n,&options,1);free(source);
    struct steer_spec_summary summary=steer_spec_summary(plan);
    assert(plan&&!summary.runtime_ready);
    int valid=0;
    for(uint32_t i=0;i<summary.nodes;i++){
        struct steer_spec_node_view node;assert(steer_spec_node(plan,i,&node));
        if(node.kind==STEER_SPEC_INBOUND&&!strcmp(node.id,"vpn"))
            valid=steer_draft_wg_v3_configure(plan,i,config);
    }
    steer_spec_destroy(plan);
    return valid;
}
static struct steer_pv1_error fixture_secret(void *unused,struct steer_pv1_span id,uint8_t out[44]){
    (void)unused;
    const char *key=NULL;
    if(id.len==3&&!memcmp(id.data,"psk",3))key=getenv("STEER_WG_TEST_PSK");
    if(id.len==6&&!memcmp(id.data,"server",6))key=getenv("STEER_WG_TEST_KEY");
    if(!key||strlen(key)!=44)return (struct steer_pv1_error){STEER_PV1_AUTH_FAILED,0};
    memcpy(out,key,44);
    return (struct steer_pv1_error){0,0};
}
static int options_fixture(const char *path){
    struct steer_draft_wg_v3_config config;
    struct awg_secrets keys;
    if(!load_options(path,&config))return 2;
    struct steer_pv1_error e=steer_draft_wg_v3_keys(&config,fixture_secret,NULL,&keys);
    if(e.code){
        const unsigned char *p=(const unsigned char *)&keys;
        for(size_t i=0;i<sizeof(keys);i++)assert(!p[i]);
        return 3;
    }
    assert(keys.has_priv&&config.kernel.peer_n==config.guard.peer_count);
    awg_secrets_wipe(&keys);
    return 0;
}
static int stage_fixture(const char *mode,const char *directory,const char *path){
    struct steer_spec_journal *journal=NULL;
    struct steer_spec_journal_key key={1,1,1,STEER_SPEC_JOURNAL_INTENT};
    struct steer_spec_journal_record record={0};
    struct steer_draft_wg_identity id;
    struct steer_draft_wg_observation o;
    atomic_uint cancel=0;
    int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(ns>=0);
    assert(!steer_spec_journal_open(directory,8,8,&journal).code);
    if(!strcmp(mode,"--recover")){
        assert(!steer_spec_journal_sync_existing(journal).code);
        assert(!steer_spec_journal_read(journal,&key,&record).code&&!strcmp(record.provider,"wireguard-fixture"));
        assert(!steer_draft_wg_identity_decode(record.data,record.length,&id));
        assert(id.generation==record.generation&&id.instance_token==record.key.instance);
        assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel,&o)&&o.state==STEER_DRAFT_WG_ABSENT);
        puts("RECOVERED");
    }else{
        struct steer_draft_wg_v3_config config;
        struct awg_conf *c=&config.kernel;struct awg_secrets keys;
        struct steer_draft_kernel_wg_guard *guard=NULL;
        assert(load_options(path,&config));
        assert(!steer_draft_wg_v3_keys(&config,fixture_secret,NULL,&keys).code);
        assert(!steer_draft_wg_identity_prepare(ns,1,key.instance,"wireguard",deadline(),&cancel,&id));
        struct steer_policy *policy=NULL;
        struct steer_policy_rule allow={.id={(const uint8_t *)"client-only",11},
            .principal={(const uint8_t *)"local-client",12},.action=STEER_POLICY_DIRECT};
        config.guard.generation=id.generation;
        strcpy(config.guard.device,id.physical_name);
        assert(!steer_policy_compile(id.generation,&allow,1,STEER_POLICY_BLOCK,&policy).code);
        assert(!steer_draft_kernel_wg_guard_prepare(&config.guard,policy,&guard).code);
        steer_policy_destroy(policy);
        record.key=key;record.generation=1;record.operation=1;record.phase=1;
        strcpy(record.provider,"wireguard-fixture");strcpy(record.provider_version,"1");
        record.length=STEER_DRAFT_WG_RECORD_BYTES;
        assert(!steer_draft_wg_identity_encode(&id,record.data));
        struct steer_spec_journal_result stored=steer_spec_journal_append(journal,&record);
        assert(!stored.error.code&&stored.durability==STEER_SPEC_JOURNAL_SYNCED);
        assert(!steer_draft_wg_identity_create(&id,ns,c->mtu,deadline(),&cancel,&o));
        int index=o.index;
        uint32_t wrong=id.group==1?2:1;
        assert(awg_dev_address_add_owned_until(id.physical_name,id.kind,index,wrong,&c->addr[0],deadline())==ESTALE);
        assert(awg_dev_link_up_owned_until(id.physical_name,id.kind,index,wrong,deadline())==ESTALE);
        assert(awg_dev_address_add_owned_until(id.physical_name,id.kind,index,id.group,&c->addr[0],1)==ETIMEDOUT);
        assert(awg_dev_link_up_owned_until(id.physical_name,id.kind,index,id.group,1)==ETIMEDOUT);
        atomic_store(&cancel,1);
        assert(steer_draft_wg_identity_stage(&id,ns,index,c,&keys,0,deadline(),&cancel,&o)==ECANCELED&&
            o.effect==STEER_PV1_DEVICE_UNCHANGED);
        atomic_store(&cancel,0);
        if(!strcmp(mode,"--rollback"))
            assert(!awg_dev_address_add_owned_until(id.physical_name,id.kind,index,id.group,&c->addr[0],deadline()));
        int rc=steer_draft_wg_identity_stage(&id,ns,index,c,&keys,0,deadline(),&cancel,&o);
        awg_secrets_wipe(&keys);
        assert(!awg_dev_link_require_down_owned_until(id.physical_name,id.kind,index,id.group,deadline()));
        if(!strcmp(mode,"--rollback")){
            assert(rc==EEXIST&&o.effect==STEER_PV1_DEVICE_EFFECT_UNCERTAIN);
            assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel,&o)&&o.state==STEER_DRAFT_WG_ABSENT);
            printf("ROLLED_BACK %s\n",id.physical_name);
        }else{
            assert(!rc&&o.effect==STEER_PV1_DEVICE_CHANGED);
            assert(!steer_draft_kernel_wg_guard_bind(guard,id.physical_name,index).code);
            printf("DOWN %s %s\n",id.physical_name,steer_draft_kernel_wg_guard_table(guard));fflush(stdout);
            assert(getchar()=='\n');
            assert(!awg_dev_link_up_owned_until(id.physical_name,id.kind,index,id.group,deadline()));
            assert(awg_dev_link_require_down_owned_until(id.physical_name,id.kind,index,id.group,deadline())==EBUSY);
            assert(awg_dev_link_up_owned_until(id.physical_name,id.kind,index,id.group,deadline())==EBUSY);
            puts("UP");fflush(stdout);
            assert(getchar()=='\n');
            struct steer_draft_kernel_wg_guard_result applied=steer_draft_kernel_wg_guard_publish(guard);
            assert(!applied.error.code&&applied.phase==STEER_DRAFT_WG_GUARD_CHANGED);
            puts("ALLOWED");fflush(stdout);
            assert(getchar()=='\n');
            assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel,&o)&&o.state==STEER_DRAFT_WG_ABSENT);
            assert(!steer_draft_kernel_wg_guard_retire(guard).code);
            puts("RETIRED");
        }
        assert(!steer_draft_kernel_wg_guard_destroy(guard).code);
    }
    assert(!steer_spec_journal_close(journal).code);
    close(ns);
    return 0;
}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"--options"))return options_fixture(argv[2]);
    wire();if(argc==2&&!strcmp(argv[1],"--wire")){puts("WG parsed config exact-index wire PASS");return 0;}
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_OWNED_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated namespace required\n",stderr);return 2;}
    if(argc==3&&!strcmp(argv[1],"--recover"))return stage_fixture(argv[1],argv[2],NULL);
    if(argc==4&&(!strcmp(argv[1],"--serve")||!strcmp(argv[1],"--rollback")))
        return stage_fixture(argv[1],argv[2],argv[3]);
    if(argc!=1)return 2;
    pthread_t t[4];for(uintptr_t j=0;j<4;j++)assert(!pthread_create(t+j,NULL,owner,(void *)j));for(unsigned j=0;j<4;j++)assert(!pthread_join(t[j],NULL));
    puts("WG parsed config: four thread namespaces, real key/peer SET+GET, isolated ownership failures, invalid/unresolved variants fail closed PASS");return 0;
}
