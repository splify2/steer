#define _GNU_SOURCE
#include "kernel_wg_coordinator.h"
#include "awg.h"
#include <steer/draft/device_v1.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { OK, STAGE_ERROR, PUBLISH_UNCHANGED, PUBLISH_CHANGED_ERROR, LOST_OUTCOME, LOST_BIND_OUTCOME };
struct fixture {
    struct steer_spec_journal *journal;
    struct steer_draft_wg_tx tx;
    struct steer_draft_wg_candidate candidate;
    uint64_t handle;
    int link,up,allow,mode,foreign;
    char events[32];
    size_t n;
};

static int fail_file_sync;
int __real_fsync(int);
int __wrap_fsync(int fd){
    struct stat st;
    assert(!fstat(fd,&st));
    if(fail_file_sync&&S_ISREG(st.st_mode)){
        fail_file_sync=0;
        errno=EIO;
        return -1;
    }
    return __real_fsync(fd);
}

static void event(struct fixture *f,char e){
    assert(f->n+1<sizeof(f->events));
    f->events[f->n++]=e;
    f->events[f->n]='\0';
}

static struct steer_spec_journal_record read_fact(struct fixture *f,unsigned seq,unsigned kind){
    struct steer_spec_journal_key k={f->tx.transaction,f->tx.instance,seq,kind};
    struct steer_spec_journal_record r;
    assert(!steer_spec_journal_read(f->journal,&k,&r).code);
    return r;
}

static void check_link(const struct fixture *f,const struct steer_draft_wg_identity *link,uint64_t deadline){
    assert(deadline==UINT64_MAX);
    uint8_t a[STEER_DRAFT_WG_RECORD_BYTES],b[STEER_DRAFT_WG_RECORD_BYTES];
    assert(!steer_draft_wg_identity_encode(&f->candidate.link,a));
    assert(!steer_draft_wg_identity_encode(link,b)&&!memcmp(a,b,sizeof(a)));
}

static int create(void *ctx,const struct steer_draft_wg_identity *link,int mtu,uint64_t d,int *index){
    struct fixture *f=ctx;check_link(f,link,d);
    if(f->journal){
        struct steer_spec_journal_record r=read_fact(f,1,STEER_SPEC_JOURNAL_INTENT);
        struct steer_draft_wg_identity from_disk;
        assert(!steer_draft_wg_identity_decode(r.data,r.length,&from_disk));
        check_link(f,&from_disk,d);
    }
    assert(mtu==1420&&!f->link);
    event(f,'C');f->link=1;*index=37;
    return 0;
}

static int stage(void *ctx,const struct steer_draft_wg_identity *link,int index,const struct awg_conf *config,
    const struct awg_secrets *keys,uint32_t mark,uint64_t d){
    struct fixture *f=ctx;check_link(f,link,d);
    assert(f->link&&!f->up&&index==37&&config==f->candidate.config&&keys==f->candidate.keys&&!mark);
    event(f,'S');
    return f->mode==STAGE_ERROR?EADDRINUSE:0;
}

static void check_guard(const struct fixture *f,const struct steer_draft_wg_guard_record *g,uint64_t d){
    check_link(f,&g->link,d);
    assert(g->ifindex==37&&!strcmp(g->table,f->candidate.table)&&!strcmp(g->marker,f->candidate.marker));
}

static int guard(void *ctx,const struct steer_draft_wg_guard_record *g,int publish,uint64_t d,
    uint32_t *effect,uint64_t *handle){
    struct fixture *f=ctx;check_guard(f,g,d);
    if(f->journal){
        struct steer_spec_journal_record r=read_fact(f,publish?4:2,STEER_SPEC_JOURNAL_INTENT);
        struct steer_draft_wg_guard_record from_disk;
        assert(!steer_draft_wg_guard_record_decode(r.data,r.length,&from_disk));
        check_guard(f,&from_disk,d);
        assert(g->handle==from_disk.handle);
    }
    assert(f->link&&!f->allow&&f->up==publish&&f->handle==g->handle);
    event(f,publish?'P':'B');
    if(publish&&f->mode==PUBLISH_UNCHANGED){
        *effect=STEER_PV1_DEVICE_UNCHANGED;
        return EIO;
    }
    *effect=STEER_PV1_DEVICE_CHANGED;
    f->allow=publish;
    *handle=f->handle=publish?201:200;
    if(publish?f->mode==LOST_OUTCOME:f->mode==LOST_BIND_OUTCOME)fail_file_sync=1;
    return publish&&f->mode==PUBLISH_CHANGED_ERROR?EIO:0;
}

static int up(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d){
    struct fixture *f=ctx;check_guard(f,g,d);
    if(f->journal){
        struct steer_spec_journal_record r=read_fact(f,3,STEER_SPEC_JOURNAL_OUTCOME);
        struct steer_draft_wg_guard_record captured;
        assert(!steer_draft_wg_guard_record_decode(r.data,r.length,&captured));
        assert(captured.handle==g->handle);
    }
    assert(g->handle==f->handle&&g->handle&&f->link&&!f->up&&!f->allow);
    event(f,'U');f->up=1;
    return 0;
}

static int retire_link(void *ctx,const struct steer_draft_wg_identity *link,uint64_t d){
    struct fixture *f=ctx;check_link(f,link,d);
    event(f,'R');f->link=f->up=0;
    return 0;
}

static int lookup(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d,uint64_t *handle,char marker[256]){
    struct fixture *f=ctx;check_guard(f,g,d);
    assert(!f->link);
    event(f,'L');
    *handle=f->handle;
    strcpy(marker,*handle?(f->foreign?"foreign":g->marker):"");
    return 0;
}

static int retire_guard(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d){
    struct fixture *f=ctx;check_guard(f,g,d);
    assert(!f->link&&g->handle&&g->handle==f->handle);
    event(f,'D');f->handle=0;f->allow=0;
    return 0;
}

static const struct steer_draft_wg_backend backend={create,stage,guard,up,retire_link,lookup,retire_guard};
static const struct awg_secrets keys={0}; /* no key material needed by injected backend */
static struct fixture fixture(struct steer_spec_journal *j,struct awg_conf *cfg,unsigned n,int mode){
    struct fixture f={
        .journal=j,.tx={n,n,n,{1}},
        .candidate={
            .link={.generation=n,.instance_token=n,.namespace_inode=42,.intent_id={1},.boot_id={1},
                .physical_name="swabcdefghijklm",.kind="wireguard",.group=n},
            .marker="steer-wg:0123456789abcdef0123456789abcdef",.config=cfg,.keys=&keys
        },
        .mode=mode
    };
    f.candidate.link.physical_name[14]=(char)('a'+n);
    snprintf(f.candidate.table,sizeof(f.candidate.table),"steer_wg_%016x",n);
    f.candidate.marker[9]="0123456789abcdef"[n%16];
    cfg->listen_port=(uint16_t)(40000+n);
    cfg->has_listen_port=1;
    cfg->mtu=1420;
    return f;
}

static int apply(struct fixture *f,const struct steer_draft_wg_ready *previous,
    struct steer_draft_wg_ready *out,int *cleanup){
    return steer_draft_wg_coordinator_apply(f->journal,&backend,f,&f->tx,&f->candidate,
        previous,UINT64_MAX,NULL,out,cleanup);
}

static int verify_selected(void *ctx,const struct steer_draft_wg_guard_record *g,uint64_t d){
    struct fixture *f=ctx;
    check_guard(f,g,d);
    event(f,'V');
    return f->link&&f->up&&f->allow&&f->handle==g->handle?0:ESTALE;
}

static void linked_selection(const char *path){
    char local[4096];
    int n=snprintf(local,sizeof(local),"%s/linked",path);
    assert(n>0&&(size_t)n<sizeof(local)&&!mkdir(local,0700));
    struct steer_draft_wg_selection *s;
    assert(!steer_draft_wg_selection_open(local,32,&s));
    struct awg_conf cfg={0};
    struct fixture f=fixture(NULL,&cfg,11,OK);
    struct steer_draft_wg_revision direct={.generation=10,.digest={2},.without_wg=1};
    struct steer_draft_wg_guard_record selected;
    uint64_t next;
    assert(!steer_draft_wg_selection_startup(s,&backend,&f,&direct,verify_selected,UINT64_MAX,&next,&selected));
    assert(next==11&&!selected.handle&&!f.n);
    struct steer_draft_wg_ready candidate;
    assert(!steer_draft_wg_selection_stage(s,&backend,&f,&direct,0,&f.tx,&f.candidate,UINT64_MAX,&candidate));
    assert(candidate.guard.handle==201&&!strcmp(f.events,"CSBUP"));
    steer_draft_wg_selection_close(s);
    assert(!steer_draft_wg_selection_open(local,32,&s));
    struct steer_draft_wg_revision committed={.generation=11,.digest={1}};
    assert(!steer_draft_wg_selection_startup(s,&backend,&f,&committed,verify_selected,UINT64_MAX,&next,&selected));
    assert(next==12&&selected.handle==201&&!strcmp(f.events,"CSBUPV"));
    struct steer_draft_wg_tx reuse={12,12,12,{3}},reuse_again={13,13,13,{4}};
    struct steer_draft_wg_guard_record foreign=selected;
    foreign.handle++;
    assert(steer_draft_wg_selection_reuse(s,&committed,&reuse,&foreign,UINT64_MAX)==ESTALE);
    assert(!steer_draft_wg_selection_reuse(s,&committed,&reuse,&selected,UINT64_MAX));
    /* Visibility of an uncommitted alias never selects the newer revision. */
    assert(!steer_draft_wg_selection_startup(s,&backend,&f,&committed,verify_selected,UINT64_MAX,&next,&selected));
    assert(next==13&&selected.link.generation==11&&!strcmp(f.events,"CSBUPVV"));
    struct steer_draft_wg_revision aliased={.generation=12,.digest={3}};
    assert(!steer_draft_wg_selection_reuse(s,&aliased,&reuse_again,&selected,UINT64_MAX));
    aliased.generation=13;
    assert(steer_draft_wg_selection_startup(s,&backend,&f,&aliased,verify_selected,UINT64_MAX,&next,&selected)==EPROTO);
    aliased.digest[0]=4;
    assert(!steer_draft_wg_selection_startup(s,&backend,&f,&aliased,verify_selected,UINT64_MAX,&next,&selected));
    assert(next==14&&selected.link.generation==11&&!strcmp(f.events,"CSBUPVVV"));
    assert(steer_draft_wg_selection_retire(s,&backend,&f,&aliased,11,UINT64_MAX)==EBUSY);
    assert(!steer_draft_wg_selection_retire(s,&backend,&f,&aliased,12,UINT64_MAX));
    committed.without_wg=1; /* contradicts the WG record at the selected revision */
    assert(steer_draft_wg_selection_startup(s,&backend,&f,&committed,verify_selected,UINT64_MAX,&next,&selected)==EPROTO);
    committed.generation=15;
    committed.without_wg=0; /* required WG entry missing: no cleanup */
    assert(steer_draft_wg_selection_startup(s,&backend,&f,&committed,verify_selected,UINT64_MAX,&next,&selected)==EPROTO);
    assert(f.link&&!strcmp(f.events,"CSBUPVVV"));
    committed.without_wg=1;
    assert(!steer_draft_wg_selection_startup(s,&backend,&f,&committed,verify_selected,UINT64_MAX,&next,&selected));
    assert(next==16&&!selected.handle&&!f.link&&!strcmp(f.events,"CSBUPVVVRLD"));
    steer_draft_wg_selection_close(s);
    puts("WG linked selection: exact reuse anchor, active retirement fence, and intentional absence PASS");
}

int main(int argc,char **argv){
    assert(argc==2);
    alarm(20);
    struct steer_spec_journal *j;
    assert(!steer_spec_journal_open(argv[1],32,8,&j).code);
    struct awg_conf old_cfg={0},next_cfg={0};
    struct fixture old=fixture(j,&old_cfg,1,OK);
    struct steer_draft_wg_ready active={0},out={0};
    int cleanup;
    assert(!apply(&old,NULL,&active,&cleanup)&&!cleanup&&active.guard.handle==201);
    assert(!strcmp(old.events,"CSBUP")&&old.up&&old.allow);

    struct fixture f=fixture(j,&next_cfg,2,STAGE_ERROR);
    next_cfg.listen_port=active.listen_port;
    assert(apply(&f,&active,&out,&cleanup)==EEXIST&&!cleanup&&!f.n);
    next_cfg.listen_port=40002;
    assert(apply(&f,&active,&out,&cleanup)==EADDRINUSE&&!cleanup);
    assert(!out.guard.handle&&!strcmp(f.events,"CSR")&&!f.link);

    f=fixture(j,&next_cfg,3,PUBLISH_UNCHANGED);
    assert(apply(&f,&active,&out,&cleanup)==EIO&&!cleanup&&!out.guard.handle);
    assert(!strcmp(f.events,"CSBUPRLD")&&!f.link&&!f.handle);
    f=fixture(j,&next_cfg,4,PUBLISH_CHANGED_ERROR);
    assert(apply(&f,&active,&out,&cleanup)==EIO&&!cleanup&&!out.guard.handle);
    assert(!strcmp(f.events,"CSBUPRLD")&&!f.link&&!f.handle);

    f=fixture(j,&next_cfg,5,LOST_OUTCOME);
    assert(apply(&f,&active,&out,&cleanup)==EIO&&cleanup==EAGAIN&&!out.guard.handle);
    assert(!strcmp(f.events,"CSBUPRL")&&!f.link&&f.handle==201);
    assert(old.link&&old.up&&old.allow&&old.handle==active.guard.handle&&!strcmp(old.events,"CSBUP"));
    assert(!steer_spec_journal_close(j).code);

    assert(!steer_spec_journal_open(argv[1],32,8,&j).code);
    f.journal=j;
    struct steer_draft_wg_tx wrong=f.tx;
    wrong.plan_digest[0]^=1;
    assert(steer_draft_wg_coordinator_recover(j,&backend,&f,&wrong,UINT64_MAX)==EIO);
    assert(!strcmp(f.events,"CSBUPRL"));
    assert(steer_draft_wg_coordinator_recover(j,&backend,&f,&f.tx,UINT64_MAX)==EAGAIN&&f.handle==201);
    f.foreign=1;
    assert(steer_draft_wg_coordinator_recover(j,&backend,&f,&f.tx,UINT64_MAX)==ESTALE&&f.handle==201);
    f.handle=0; /* External reconciliation, not a coordinator deletion by name. */
    assert(!steer_draft_wg_coordinator_recover(j,&backend,&f,&f.tx,UINT64_MAX));

    /* A link intent that never becomes durable does not allow create. */
    f=fixture(j,&next_cfg,6,OK);
    fail_file_sync=1;
    assert(apply(&f,&active,&out,&cleanup)==EIO&&!cleanup&&!f.n&&!fail_file_sync);
    f=fixture(j,&next_cfg,7,LOST_BIND_OUTCOME);
    assert(apply(&f,&active,&out,&cleanup)==EIO&&cleanup==EAGAIN&&!out.guard.handle);
    assert(!strcmp(f.events,"CSBRL")&&!f.up&&!f.link&&f.handle==200);

    /* An old transaction isn't retired until explicitly selected after restart. */
    old.journal=j;
    assert(!steer_draft_wg_coordinator_recover(j,&backend,&old,&old.tx,UINT64_MAX));
    assert(!strcmp(old.events,"CSBUPRLD")&&!old.handle);
    assert(!steer_spec_journal_close(j).code);
    puts("WG coordinator: journaled admission, failed Apply retains active, exact rollback, lost outcome and restart PASS");
    linked_selection(argv[1]);
    return 0;
}
