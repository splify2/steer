#define _GNU_SOURCE
#include "kernel_wg_linux_link.h"
#include "awgdev.h"
#include <steer/draft/device_v1.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct fixture {
    struct steer_draft_wg_linux_link *link;
    struct steer_spec_journal *journal;
    struct steer_draft_wg_tx tx;
    unsigned checked;
    int crash;
};

static uint64_t deadline(void){
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec+5000000000u;
}

static int create(void *ctx,const struct steer_draft_wg_identity *id,int mtu,uint64_t d,int *index){
    struct fixture *f=ctx;
    return steer_draft_wg_linux_link_backend.create_down(f->link,id,mtu,d,index);
}

static int stage(void *ctx,const struct steer_draft_wg_identity *id,int index,
    const struct awg_conf *cfg,const struct awg_secrets *keys,uint32_t mark,uint64_t d){
    struct fixture *f=ctx;
    return steer_draft_wg_linux_link_backend.stage_down(f->link,id,index,cfg,keys,mark,d);
}

static int retire(void *ctx,const struct steer_draft_wg_identity *id,uint64_t d){
    struct fixture *f=ctx;
    return steer_draft_wg_linux_link_backend.retire_link(f->link,id,d);
}

static void absent(const struct steer_draft_wg_identity *id,uint64_t d){
    uint32_t group;
    assert(awg_dev_link_query_owned_until(id->physical_name,NULL,0,NULL,&group,d)==ENODEV);
}

/* Public RFC 7748 test public key, never a user credential. */
static const uint8_t peer[32]={
    0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
    0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
};

static void verify_staged(const struct steer_draft_wg_guard_record *g,uint64_t d){
    const struct steer_draft_wg_identity *id=&g->link;
    int index=(int)g->ifindex;
    assert(!g->handle);
    assert(!awg_dev_link_require_down_owned_until(id->physical_name,id->kind,index,id->group,d));
    struct awg_live live={0};
    assert(!awg_dev_live_read_owned_until(id->physical_name,id->kind,index,id->group,&live,d));
    assert(live.peer_n==1&&!memcmp(live.peer[0].pub,peer,sizeof(peer)));
    struct ifaddrs *all;
    assert(!getifaddrs(&all));
    struct in_addr expected;
    assert(inet_pton(AF_INET,"192.0.2.1",&expected)==1);
    int found=0;
    for(struct ifaddrs *a=all;a;a=a->ifa_next){
        if(!a->ifa_addr||a->ifa_addr->sa_family!=AF_INET||strcmp(a->ifa_name,id->physical_name))continue;
        found|=((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr==expected.s_addr;
    }
    freeifaddrs(all);
    assert(found);
}

static struct steer_draft_wg_guard_record read_intent(const struct fixture *f){
    struct steer_spec_journal_key k={f->tx.transaction,f->tx.instance,2,STEER_SPEC_JOURNAL_INTENT};
    struct steer_spec_journal_record r;
    struct steer_draft_wg_guard_record g;
    assert(!steer_spec_journal_read(f->journal,&k,&r).code);
    assert(!steer_draft_wg_guard_record_decode(r.data,r.length,&g));
    return g;
}

static int guard_unavailable(void *ctx,const struct steer_draft_wg_guard_record *g,int publish,
    uint64_t d,uint32_t *effect,uint64_t *handle){
    struct fixture *f=ctx;
    assert(!publish&&!*handle);
    struct steer_draft_wg_guard_record durable=read_intent(f);
    uint8_t a[STEER_DRAFT_WG_GUARD_RECORD_BYTES],b[STEER_DRAFT_WG_GUARD_RECORD_BYTES];
    assert(!steer_draft_wg_guard_record_encode(&durable,a));
    assert(!steer_draft_wg_guard_record_encode(g,b)&&!memcmp(a,b,sizeof(a)));
    verify_staged(g,d);
    if(f->crash){raise(SIGKILL);_exit(1);}
    ++f->checked;
    *effect=STEER_PV1_DEVICE_UNCHANGED;
    return EOPNOTSUPP;
}

static int no_up(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d){
    (void)ctx;(void)g;(void)d;
    assert(!"guard unavailable: UP is forbidden");
    return EPERM;
}

static int never_installed(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d,
    uint64_t *handle,char comment[256]){
    (void)ctx;
    absent(&g->link,d);
    /* Test-only fact: this fixture never calls nft, in either process. */
    *handle=0;
    comment[0]='\0';
    return 0;
}

static const struct steer_draft_wg_backend backend={
    create,stage,guard_unavailable,no_up,retire,never_installed,no_up
};

static void apply(struct fixture *f){
    struct awg_conf c={.mtu=1420,.listen_port=51820,.has_listen_port=1,
        .addr_n=1,.peer_n=1,.aips_n=1};
    struct awg_secrets keys={.has_priv=1,.priv={1}}; /* synthetic local test key */
    assert(!awg_prefix_parse("192.0.2.1/32",&c.addr[0]));
    assert(!awg_prefix_parse("192.0.2.2/32",&c.aips[0]));
    memcpy(c.peer[0].pub,peer,sizeof(peer));
    c.peer[0].aip_n=1;
    struct steer_draft_wg_candidate candidate={
        .table="steer_wg_0123456789abcdef",.marker="steer-wg:0123456789abcdef0123456789abcdef",
        .config=&c,.keys=&keys
    };
    const uint64_t d=deadline();
    assert(!steer_draft_wg_linux_link_prepare(f->link,&f->tx,d,NULL,&candidate.link));
    struct steer_draft_wg_ready ready={0};
    int cleanup;
    assert(steer_draft_wg_coordinator_apply(f->journal,&backend,f,&f->tx,&candidate,NULL,d,NULL,
        &ready,&cleanup)==EOPNOTSUPP&&!cleanup&&!ready.guard.handle);
    awg_secrets_wipe(&keys);
    absent(&candidate.link,deadline());
}

int main(int argc,char **argv){
    struct steer_draft_wg_linux_link *link;
    if(argc==2&&!strcmp(argv[1],"--check-boundary")){
        int own=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);
        assert(own>=0);
        assert(steer_draft_wg_linux_link_open(own,&link)==EPERM&&!link);
        assert(!close(own));
        puts("WG Linux link: refuses caller's original network namespace");
        return 0;
    }
    assert(argc==2);
    alarm(20);
    /* The launcher pins the outer namespace on fd 3 BEFORE unshare -n. */
    assert(!steer_draft_wg_linux_link_open(3,&link));
    struct fixture f={.link=link,.tx={.transaction=1,.generation=1,.instance=1,.plan_digest={1}}};
    assert(!steer_spec_journal_open(argv[1],16,8,&f.journal).code);
    apply(&f);
    assert(f.checked==1);
    assert(!steer_spec_journal_close(f.journal).code);

    f.tx=(struct steer_draft_wg_tx){.transaction=2,.generation=2,.instance=2,.plan_digest={2}};
    f.crash=1;
    pid_t child=fork();
    assert(child>=0);
    if(!child){
        assert(!steer_spec_journal_open(argv[1],16,8,&f.journal).code);
        apply(&f);
        _exit(2);
    }
    int status;
    assert(waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    assert(!steer_spec_journal_open(argv[1],16,8,&f.journal).code);
    struct steer_draft_wg_guard_record g=read_intent(&f);
    verify_staged(&g,deadline());
    struct steer_draft_wg_identity foreign=g.link;
    foreign.group=foreign.group==1?2:1;
    assert(retire(&f,&foreign,deadline())==ESTALE);
    verify_staged(&g,deadline());
    assert(!steer_draft_wg_coordinator_recover(f.journal,&backend,&f,&f.tx,deadline()));
    assert(!steer_draft_wg_coordinator_recover(f.journal,&backend,&f,&f.tx,deadline()));
    absent(&g.link,deadline());
    assert(!steer_spec_journal_close(f.journal).code);
    steer_draft_wg_linux_link_close(link);
    puts("WG Linux link: real DOWN stage, no UP, rollback and exact journal recovery after SIGKILL PASS");
    return 0;
}
