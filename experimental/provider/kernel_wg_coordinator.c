#define _POSIX_C_SOURCE 200809L
#include "kernel_wg_coordinator.h"
#include "awg.h"
#include <steer/draft/device_v1.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { LINK=1, BIND, BOUND, PUBLISH, PUBLISHED, STEPS };
enum { CLEAN=STEPS, CLEANED };
static const char provider[]="wireguard-isolated";
static const char durable_provider[]="wireguard-isolated-selected";
static const char version[]="1";

static int running(uint64_t deadline,const atomic_uint *cancel){
    struct timespec now;
    if(!deadline)return EINVAL;
    if(cancel&&atomic_load_explicit(cancel,memory_order_relaxed))return ECANCELED;
    if(clock_gettime(CLOCK_MONOTONIC,&now))return errno;
    return (uint64_t)now.tv_sec*1000000000u+(uint64_t)now.tv_nsec>=deadline?ETIMEDOUT:0;
}

static int tx_valid(const struct steer_draft_wg_tx *t){
    return t&&t->transaction&&t->generation&&t->instance;
}

static int cleanup_backend(const struct steer_draft_wg_backend *b){
    return b&&b->retire_link&&b->lookup_guard&&b->retire_guard;
}

static struct steer_spec_journal_record record(const struct steer_draft_wg_tx *t,
    unsigned step,uint32_t effect,const char *owner){
    int result=step==BOUND||step==PUBLISHED;
    struct steer_spec_journal_record r={
        .key={t->transaction,t->instance,step,result?STEER_SPEC_JOURNAL_OUTCOME:STEER_SPEC_JOURNAL_INTENT},
        .generation=t->generation,.intent_sequence=result?step-1:0,
        .operation=step>=PUBLISH?2:1,.effect=effect,
        .phase=effect==STEER_PV1_DEVICE_EFFECT_UNCERTAIN?STEER_PV1_DEVICE_UNCERTAIN:
            step==PUBLISHED&&effect==STEER_PV1_DEVICE_CHANGED?STEER_PV1_DEVICE_ACTIVE:STEER_PV1_DEVICE_QUIESCENT,
        .length=step==LINK?STEER_DRAFT_WG_RECORD_BYTES:STEER_DRAFT_WG_GUARD_RECORD_BYTES
    };
    strcpy(r.provider,owner);
    memcpy(r.provider_version,version,sizeof(version));
    memcpy(r.plan_digest,t->plan_digest,sizeof(r.plan_digest));
    return r;
}

static int append(struct steer_spec_journal *j,const struct steer_draft_wg_tx *t,unsigned step,
    uint32_t effect,const struct steer_draft_wg_identity *link,const struct steer_draft_wg_guard_record *guard,
    const char *owner){
    struct steer_spec_journal_record r=record(t,step,effect,owner);
    int rc=step==LINK?steer_draft_wg_identity_encode(link,r.data):
        steer_draft_wg_guard_record_encode(guard,r.data);
    if(rc)return rc;
    struct steer_spec_journal_result stored=steer_spec_journal_append(j,&r);
    return stored.error.code||stored.error.transient||stored.durability!=STEER_SPEC_JOURNAL_SYNCED?EIO:0;
}

struct recovery {
    const struct steer_draft_wg_tx *tx;
    struct steer_spec_journal_record records[STEPS];
};

static int same_envelope(const struct steer_spec_journal_record *r,
    const struct steer_spec_journal_record *expected){
    return r->key.kind==expected->key.kind&&r->intent_sequence==expected->intent_sequence&&
        r->effect==expected->effect&&r->phase==expected->phase&&r->operation==expected->operation&&
        r->generation==expected->generation&&r->length==expected->length&&
        !strcmp(r->provider,expected->provider)&&!strcmp(r->provider_version,expected->provider_version)&&
        !memcmp(r->plan_digest,expected->plan_digest,sizeof(r->plan_digest))&&
        !r->anchor_transaction&&!r->anchor_sequence;
}

static int stage_envelope(const struct steer_spec_journal_record *r,
    const struct steer_draft_wg_tx *t,const char *owner){
    struct steer_spec_journal_record expected=record(t,r->key.sequence,r->effect,owner);
    return (expected.intent_sequence||!r->effect)&&same_envelope(r,&expected);
}

static struct steer_pv1_error collect(void *ctx,const struct steer_spec_journal_record *r){
    struct recovery *s=ctx;
    if(r->key.transaction!=s->tx->transaction||r->key.instance!=s->tx->instance)
        return (struct steer_pv1_error){0,0};
    unsigned step=r->key.sequence;
    struct steer_pv1_error invalid={STEER_PV1_INVALID,0};
    if(step<LINK||step>=STEPS||s->records[step].length||!stage_envelope(r,s->tx,provider))return invalid;
    s->records[step]=*r;
    return (struct steer_pv1_error){0,0};
}

static int guard_at(const struct steer_spec_journal_record *in,
    const struct steer_spec_journal_record *out,uint64_t old,struct steer_draft_wg_guard_record *g){
    if(steer_draft_wg_guard_record_decode(in->data,in->length,g)||g->handle!=old)
        return EPROTO;
    if(out->length&&out->effect==STEER_PV1_DEVICE_CHANGED)
        return steer_draft_wg_guard_record_restore(in->data,in->length,out->data,out->length,g);
    if(out->length&&memcmp(in->data,out->data,in->length))return EPROTO;
    if(!out->length||out->effect!=STEER_PV1_DEVICE_UNCHANGED)g->handle=0;
    return 0;
}

static int recovery_guard(const struct steer_spec_journal_record r[STEPS],
    const struct steer_draft_wg_identity *link,struct steer_draft_wg_guard_record *guard){
    if(!r[BIND].length)return r[BOUND].length||r[PUBLISH].length||r[PUBLISHED].length?EPROTO:0;
    int rc=guard_at(&r[BIND],&r[BOUND],0,guard);
    uint8_t expected[STEER_DRAFT_WG_RECORD_BYTES],actual[STEER_DRAFT_WG_RECORD_BYTES];
    if(rc||steer_draft_wg_identity_encode(link,expected)||
       steer_draft_wg_identity_encode(&guard->link,actual)||memcmp(expected,actual,sizeof(actual)))return EPROTO;
    if(!r[PUBLISH].length)return r[PUBLISHED].length?EPROTO:0;
    uint8_t bound[STEER_DRAFT_WG_GUARD_RECORD_BYTES];
    if(!guard->handle||steer_draft_wg_guard_record_encode(guard,bound)||
       memcmp(bound,r[PUBLISH].data,sizeof(bound)))return EPROTO;
    return guard_at(&r[PUBLISH],&r[PUBLISHED],guard->handle,guard);
}

static int reconcile_records(const struct steer_spec_journal_record r[STEPS],
    const struct steer_draft_wg_tx *t,struct steer_draft_wg_identity *link,
    struct steer_draft_wg_guard_record *guard){
    if(!r[LINK].length)return ENOENT;
    if(steer_draft_wg_identity_decode(r[LINK].data,r[LINK].length,link)||
       strcmp(link->kind,"wireguard")||link->generation!=t->generation||link->instance_token!=t->instance||
       recovery_guard(r,link,guard))return EPROTO;
    return 0;
}

static int retire_records(const struct steer_draft_wg_backend *b,void *ctx,
    const struct steer_spec_journal_record r[STEPS],const struct steer_draft_wg_tx *t,uint64_t deadline){
    struct steer_draft_wg_identity link;
    struct steer_draft_wg_guard_record guard={0};
    int rc=reconcile_records(r,t,&link,&guard);
    if(rc)return rc;
    if((rc=running(deadline,NULL))||(rc=b->retire_link(ctx,&link,deadline)))return rc;
    if(!r[BIND].length)return 0;
    uint64_t handle=0;
    char marker[256]={0};
    if((rc=running(deadline,NULL))||(rc=b->lookup_guard(ctx,&guard,deadline,&handle,marker)))return rc;
    if(!memchr(marker,'\0',sizeof(marker)))return EPROTO;
    unsigned seen=steer_draft_wg_guard_record_observe(&guard,handle,marker);
    if(seen==STEER_DRAFT_WG_ABSENT)return 0;
    if(seen!=STEER_DRAFT_WG_OWNED)return seen==STEER_DRAFT_WG_FOREIGN?ESTALE:EAGAIN;
    if((rc=running(deadline,NULL)))return rc;
    return b->retire_guard(ctx,&guard,deadline);
}

int steer_draft_wg_coordinator_recover(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_tx *t,uint64_t deadline){
    if(!j||!cleanup_backend(b)||!tx_valid(t))return EINVAL;
    int rc=running(deadline,NULL);
    if(rc)return rc;
    struct recovery s={.tx=t};
    if(steer_spec_journal_sync_existing(j).code||steer_spec_journal_scan(j,collect,&s,NULL).code)return EIO;
    return retire_records(b,ctx,s.records,t,deadline);
}

static int change_guard(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,void *ctx,
    const struct steer_draft_wg_tx *t,struct steer_draft_wg_guard_record *g,int publish,
    uint64_t deadline,const atomic_uint *cancel,const char *owner){
    unsigned step=publish?PUBLISH:BIND;
    int rc=append(j,t,step,0,NULL,g,owner);
    if(rc)return rc;
    rc=running(deadline,cancel);
    if(rc){
        int stored=append(j,t,step+1,STEER_PV1_DEVICE_UNCHANGED,NULL,g,owner);
        return stored?stored:rc;
    }
    uint32_t effect=STEER_PV1_DEVICE_EFFECT_UNCERTAIN;
    uint64_t handle=0;
    int work=b->guard(ctx,g,publish,deadline,&effect,&handle);
    if(effect>STEER_PV1_DEVICE_EFFECT_UNCERTAIN||
       (effect==STEER_PV1_DEVICE_CHANGED?(!handle||handle==g->handle):handle!=0)){
        effect=STEER_PV1_DEVICE_EFFECT_UNCERTAIN;
        work=EPROTO;
    }
    if(effect==STEER_PV1_DEVICE_CHANGED)g->handle=handle;
    rc=append(j,t,step+1,effect,NULL,g,owner);
    if(rc)return rc;
    return work?work:effect==STEER_PV1_DEVICE_CHANGED?0:EIO;
}

static int stage_candidate(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_tx *t,const struct steer_draft_wg_candidate *c,
    const struct steer_draft_wg_ready *previous,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_ready *ready,int *started,const char *owner){
    if(!j||!cleanup_backend(b)||!b->create_down||!b->stage_down||!b->guard||!b->up||
       !tx_valid(t)||!c||!ready||ready==previous||!c->config||!c->keys||!c->config->has_listen_port||
       !c->config->listen_port||c->link.generation!=t->generation||c->link.instance_token!=t->instance)
        return EINVAL;
    struct steer_draft_wg_guard_record g={.link=c->link,.ifindex=1};
    memcpy(g.table,c->table,sizeof(g.table));
    memcpy(g.marker,c->marker,sizeof(g.marker));
    uint8_t checked[STEER_DRAFT_WG_GUARD_RECORD_BYTES];
    if(steer_draft_wg_guard_record_encode(&g,checked))return EINVAL;
    if(previous&&(c->config->listen_port==previous->listen_port||
       c->link.generation<=previous->guard.link.generation||
       !memcmp(c->link.physical_name,previous->guard.link.physical_name,sizeof(c->link.physical_name))||
       !memcmp(c->table,previous->guard.table,sizeof(c->table))))return EEXIST;
    int rc=running(deadline,cancel),index=0;
    if(rc||(rc=append(j,t,LINK,0,&c->link,NULL,owner))||(rc=running(deadline,cancel)))return rc;
    *started=1;
    rc=b->create_down(ctx,&c->link,c->config->mtu,deadline,&index);
    if(!rc&&index<=0)rc=EPROTO;
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=b->stage_down(ctx,&c->link,index,c->config,c->keys,c->mark,deadline);
    if(!rc)rc=running(deadline,cancel);
    if(!rc){
        g.ifindex=(uint32_t)index;
        rc=change_guard(j,b,ctx,t,&g,0,deadline,cancel,owner);
    }
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=b->up(ctx,&g,deadline);
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=change_guard(j,b,ctx,t,&g,1,deadline,cancel,owner);
    if(!rc)rc=running(deadline,cancel);
    if(!rc)*ready=(struct steer_draft_wg_ready){g,c->config->listen_port};
    return rc;
}

int steer_draft_wg_coordinator_apply(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_tx *t,const struct steer_draft_wg_candidate *c,
    const struct steer_draft_wg_ready *previous,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_ready *ready,int *cleanup_error){
    if(!cleanup_error)return EINVAL;
    int started=0;
    *cleanup_error=0;
    int rc=stage_candidate(j,b,ctx,t,c,previous,deadline,cancel,ready,&started,provider);
    if(rc&&started)*cleanup_error=steer_draft_wg_coordinator_recover(j,b,ctx,t,deadline);
    return rc;
}

/* Append-only pilot: at most eight facts per transaction, no compaction.
 * Reserve one extra slot for an interrupted pre-rename write. Repeated orphan
 * accumulation fences admission; never repurpose an active cleanup reserve. */
#define SELECTION_MAX 128u
struct steer_draft_wg_selection { struct steer_spec_journal *j; uint32_t max; };
struct entry {
    struct steer_draft_wg_tx tx;
    struct steer_spec_journal_record r[CLEANED+1];
    struct steer_draft_wg_identity link;
    struct steer_draft_wg_guard_record guard;
};
struct inventory { struct entry *e; unsigned n,active,used,reserved,capacity; };

static struct steer_spec_journal_record selection_record(const struct steer_draft_wg_tx *t,unsigned step){
    struct steer_spec_journal_record r=record(t,step,0,durable_provider);
    r.operation=4;
    r.phase=step==CLEAN?STEER_PV1_DEVICE_RETIRING:STEER_PV1_DEVICE_RETIRED;
    r.length=STEER_DRAFT_WG_RECORD_BYTES;
    if(step==CLEANED){
        /* This fact certifies observed absence, not whether this particular
         * retry or an earlier attempt actually removed the objects. */
        r.key.kind=STEER_SPEC_JOURNAL_RECONCILE;
        r.intent_sequence=CLEAN;
    }
    return r;
}

static struct steer_pv1_error collect_selection(void *ctx,const struct steer_spec_journal_record *r){
    struct inventory *i=ctx;
    const struct steer_pv1_error invalid={STEER_PV1_INVALID,0};
    unsigned step=r->key.sequence,n=0;
    if(step<LINK||step>CLEANED||strcmp(r->provider,durable_provider))return invalid;
    for(;n<i->n;n++)if(i->e[n].tx.transaction==r->key.transaction)break;
    if(n==i->n){
        if(n>=i->capacity)return invalid;
        struct entry *e=&i->e[i->n++];
        e->tx=(struct steer_draft_wg_tx){.transaction=r->key.transaction,.generation=r->generation,
            .instance=r->key.instance};
        memcpy(e->tx.plan_digest,r->plan_digest,sizeof(e->tx.plan_digest));
    }
    struct entry *e=&i->e[n];
    if(e->r[step].length||e->tx.instance!=r->key.instance)return invalid;
    if(step<STEPS){
        if(!stage_envelope(r,&e->tx,durable_provider))return invalid;
    }else{
        struct steer_spec_journal_record expected=selection_record(&e->tx,step);
        if(!same_envelope(r,&expected))return invalid;
    }
    e->r[step]=*r;
    return (struct steer_pv1_error){0,0};
}

static int inventory_read(struct steer_draft_wg_selection *s,struct inventory *i,
    const struct steer_draft_wg_revision *revision){
    *i=(struct inventory){.active=SELECTION_MAX,.capacity=s->max};
    if(steer_spec_journal_sync_existing(s->j).code)return EIO;
    /* The physical journal bound also bounds allocation and pair checks. */
    i->e=calloc(s->max,sizeof(*i->e));
    if(!i->e)return ENOMEM;
    struct steer_spec_journal_scan_report report;
    if(steer_spec_journal_scan(s->j,collect_selection,i,&report).code)return EPROTO;
    i->used=report.records+report.orphan_temporaries;
    for(unsigned n=0;n<i->n;n++){
        struct entry *e=&i->e[n];
        const struct steer_spec_journal_record *r=e->r;
        if(reconcile_records(r,&e->tx,&e->link,&e->guard))return EPROTO;
        if(e->tx.generation==revision->generation){
            if(revision->without_wg||!r[PUBLISHED].length||r[PUBLISHED].effect!=STEER_PV1_DEVICE_CHANGED||
               !e->guard.handle||memcmp(e->tx.plan_digest,revision->digest,32))return EPROTO;
            i->active=n;
        }
        for(unsigned k=CLEAN;k<=CLEANED;k++)
            if(r[k].length&&memcmp(r[k].data,r[LINK].data,r[k].length))return EPROTO;
        if(!r[CLEANED].length)i->reserved+=r[CLEAN].length?1:2;
        for(unsigned prev=0;prev<n;prev++){
            const struct entry *other=&i->e[prev];
            if(other->tx.generation==e->tx.generation||
               !strcmp(other->link.physical_name,e->link.physical_name)||
               (other->guard.table[0]&&e->guard.table[0]&&!strcmp(other->guard.table,e->guard.table)))
                return EPROTO;
        }
    }
    if(revision->generation&&!revision->without_wg&&
       (i->active==SELECTION_MAX||i->e[i->active].r[CLEAN].length))return EPROTO;
    return 0;
}

static int revision_valid(const struct steer_draft_wg_revision *r){
    if(!r||(r->without_wg!=0&&r->without_wg!=1))return 0;
    if(r->generation)return 1;
    static const uint8_t zero[32];
    return !r->without_wg&&!memcmp(r->digest,zero,sizeof(zero));
}

static int synced(struct steer_spec_journal_result result){
    return !result.error.code&&!result.error.transient&&result.durability==STEER_SPEC_JOURNAL_SYNCED;
}

static int clean_entry(struct steer_draft_wg_selection *s,const struct steer_draft_wg_backend *b,
    void *ctx,const struct entry *e,uint64_t deadline){
    if(e->r[CLEANED].length)return 0;
    int rc=running(deadline,NULL);
    if(rc)return rc;
    if(!e->r[CLEAN].length){
        struct steer_spec_journal_record r=selection_record(&e->tx,CLEAN);
        memcpy(r.data,e->r[LINK].data,r.length);
        if(!synced(steer_spec_journal_append(s->j,&r)))return EIO;
    }
    rc=retire_records(b,ctx,e->r,&e->tx,deadline);
    if(rc)return rc;
    struct steer_spec_journal_record r=selection_record(&e->tx,CLEANED);
    memcpy(r.data,e->r[LINK].data,r.length);
    return synced(steer_spec_journal_append(s->j,&r))?0:EIO;
}

int steer_draft_wg_selection_open(const char *path,uint32_t max,struct steer_draft_wg_selection **out){
    if(!out)return EINVAL;
    *out=NULL;
    if(max<CLEANED+1||max>SELECTION_MAX)return EINVAL;
    struct steer_draft_wg_selection *s=calloc(1,sizeof(*s));
    if(!s)return ENOMEM;
    if(steer_spec_journal_open(path,max,CLEANED,&s->j).code){free(s);return EIO;}
    s->max=max;
    *out=s;
    return 0;
}

void steer_draft_wg_selection_close(struct steer_draft_wg_selection *s){
    if(s){steer_spec_journal_close(s->j);free(s);}
}

int steer_draft_wg_selection_startup(struct steer_draft_wg_selection *s,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_revision *revision,steer_draft_wg_verify_ready verify,
    uint64_t deadline,uint64_t *next_revision,struct steer_draft_wg_guard_record *selected){
    if(!s||!cleanup_backend(b)||!revision_valid(revision)||!verify||!next_revision)return EINVAL;
    *next_revision=0;
    if(selected)*selected=(struct steer_draft_wg_guard_record){0};
    int rc=running(deadline,NULL);
    if(rc)return rc;
    struct inventory i;
    rc=inventory_read(s,&i,revision);
    if(!rc&&i.active!=SELECTION_MAX)rc=verify(ctx,&i.e[i.active].guard,deadline);
    if(!rc&&i.used+i.reserved>s->max)rc=ENOSPC;
    if(!rc){
        uint64_t highest=revision->generation;
        for(unsigned n=0;n<i.n;n++)if(i.e[n].tx.generation>highest)highest=i.e[n].tx.generation;
        if(highest==UINT64_MAX){free(i.e);return EOVERFLOW;}
        for(unsigned n=0;n<i.n;n++){
            if(n==i.active)continue;
            int err=clean_entry(s,b,ctx,&i.e[n],deadline);
            /* Stop on any ambiguity, retaining reservations for retry. */
            if(err){rc=err;break;}
        }
        if(!rc)*next_revision=highest+1;
    }
    if(!rc&&selected&&i.active!=SELECTION_MAX)*selected=i.e[i.active].guard;
    free(i.e);
    return rc;
}

int steer_draft_wg_selection_stage(struct steer_draft_wg_selection *s,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_revision *revision,uint16_t previous_port,
    const struct steer_draft_wg_tx *t,const struct steer_draft_wg_candidate *c,uint64_t deadline,
    struct steer_draft_wg_ready *ready){
    if(!ready)return EINVAL;
    *ready=(struct steer_draft_wg_ready){0};
    if(!s||!tx_valid(t)||!c||!c->config||!revision_valid(revision)||
       (revision->generation&&!revision->without_wg)!=!!previous_port||
       t->generation<=revision->generation)return EINVAL;
    int rc=running(deadline,NULL);
    if(rc)return rc;
    struct inventory i;
    rc=inventory_read(s,&i,revision);
    struct steer_draft_wg_ready previous={0};
    if(!rc&&i.active!=SELECTION_MAX){
        const struct entry *e=&i.e[i.active];
        previous=(struct steer_draft_wg_ready){e->guard,previous_port};
    }
    /* Link records must never be replayed, even after their cleanup completed. */
    if(!rc)for(unsigned n=0;n<i.n;n++){
        const struct entry *e=&i.e[n];
        if(n!=i.active&&!e->r[CLEANED].length){rc=EBUSY;break;}
        if(t->transaction==e->tx.transaction||t->generation<=e->tx.generation||
           !memcmp(c->link.physical_name,e->link.physical_name,sizeof(e->link.physical_name))||
           !memcmp(c->table,e->guard.table,sizeof(c->table))){rc=EEXIST;break;}
    }
    if(!rc&&i.used+i.reserved+CLEANED+1>s->max)rc=ENOSPC;
    free(i.e);
    if(rc)return rc;
    int started=0;
    return stage_candidate(s->j,b,ctx,t,c,previous.listen_port?&previous:NULL,deadline,NULL,ready,
        &started,durable_provider);
}
