#define _POSIX_C_SOURCE 200809L
#include "kernel_wg_coordinator.h"
#include "awg.h"
#include <steer/draft/device_v1.h>
#include <errno.h>
#include <string.h>
#include <time.h>

enum { LINK=1, BIND, BOUND, PUBLISH, PUBLISHED, STEPS };
static const char provider[]="wireguard-isolated";
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
    unsigned step,uint32_t effect){
    int result=step==BOUND||step==PUBLISHED;
    struct steer_spec_journal_record r={
        .key={t->transaction,t->instance,step,result?STEER_SPEC_JOURNAL_OUTCOME:STEER_SPEC_JOURNAL_INTENT},
        .generation=t->generation,.intent_sequence=result?step-1:0,
        .operation=step>=PUBLISH?2:1,.effect=effect,
        .phase=effect==STEER_PV1_DEVICE_EFFECT_UNCERTAIN?STEER_PV1_DEVICE_UNCERTAIN:
            step==PUBLISHED&&effect==STEER_PV1_DEVICE_CHANGED?STEER_PV1_DEVICE_ACTIVE:STEER_PV1_DEVICE_QUIESCENT,
        .length=step==LINK?STEER_DRAFT_WG_RECORD_BYTES:STEER_DRAFT_WG_GUARD_RECORD_BYTES
    };
    memcpy(r.provider,provider,sizeof(provider));
    memcpy(r.provider_version,version,sizeof(version));
    memcpy(r.plan_digest,t->plan_digest,sizeof(r.plan_digest));
    return r;
}

static int append(struct steer_spec_journal *j,const struct steer_draft_wg_tx *t,unsigned step,
    uint32_t effect,const struct steer_draft_wg_identity *link,const struct steer_draft_wg_guard_record *guard){
    struct steer_spec_journal_record r=record(t,step,effect);
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

static struct steer_pv1_error collect(void *ctx,const struct steer_spec_journal_record *r){
    struct recovery *s=ctx;
    if(r->key.transaction!=s->tx->transaction||r->key.instance!=s->tx->instance)
        return (struct steer_pv1_error){0,0};
    unsigned step=r->key.sequence;
    struct steer_pv1_error invalid={STEER_PV1_INVALID,0};
    if(step<LINK||step>=STEPS||s->records[step].length)return invalid;
    struct steer_spec_journal_record expected=record(s->tx,step,r->effect);
    if((!expected.intent_sequence&&r->effect)||r->key.kind!=expected.key.kind||
       r->intent_sequence!=expected.intent_sequence||r->phase!=expected.phase||
       r->operation!=expected.operation||r->generation!=expected.generation||
       r->length!=expected.length||strcmp(r->provider,provider)||strcmp(r->provider_version,version)||
       memcmp(r->plan_digest,expected.plan_digest,sizeof(r->plan_digest)))return invalid;
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

int steer_draft_wg_coordinator_recover(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_tx *t,uint64_t deadline){
    if(!j||!cleanup_backend(b)||!tx_valid(t))return EINVAL;
    int rc=running(deadline,NULL);
    if(rc)return rc;
    struct recovery s={.tx=t};
    if(steer_spec_journal_sync_existing(j).code||steer_spec_journal_scan(j,collect,&s,NULL).code)return EIO;
    struct steer_draft_wg_identity link;
    struct steer_draft_wg_guard_record guard={0};
    const struct steer_spec_journal_record *r=s.records;
    if(!r[LINK].length)return ENOENT;
    if(steer_draft_wg_identity_decode(r[LINK].data,r[LINK].length,&link)||
       strcmp(link.kind,"wireguard")||link.generation!=t->generation||link.instance_token!=t->instance||
       recovery_guard(r,&link,&guard))return EPROTO;
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

static int change_guard(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,void *ctx,
    const struct steer_draft_wg_tx *t,struct steer_draft_wg_guard_record *g,int publish,
    uint64_t deadline,const atomic_uint *cancel){
    unsigned step=publish?PUBLISH:BIND;
    int rc=append(j,t,step,0,NULL,g);
    if(rc)return rc;
    rc=running(deadline,cancel);
    if(rc){
        int stored=append(j,t,step+1,STEER_PV1_DEVICE_UNCHANGED,NULL,g);
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
    rc=append(j,t,step+1,effect,NULL,g);
    if(rc)return rc;
    return work?work:effect==STEER_PV1_DEVICE_CHANGED?0:EIO;
}

int steer_draft_wg_coordinator_apply(struct steer_spec_journal *j,const struct steer_draft_wg_backend *b,
    void *ctx,const struct steer_draft_wg_tx *t,const struct steer_draft_wg_candidate *c,
    const struct steer_draft_wg_ready *previous,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_ready *ready,int *cleanup_error){
    if(!cleanup_error)return EINVAL;
    *cleanup_error=0;
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
    if(rc||(rc=append(j,t,LINK,0,&c->link,NULL))||(rc=running(deadline,cancel)))return rc;
    rc=b->create_down(ctx,&c->link,c->config->mtu,deadline,&index);
    if(!rc&&index<=0)rc=EPROTO;
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=b->stage_down(ctx,&c->link,index,c->config,c->keys,c->mark,deadline);
    if(!rc)rc=running(deadline,cancel);
    if(!rc){
        g.ifindex=(uint32_t)index;
        rc=change_guard(j,b,ctx,t,&g,0,deadline,cancel);
    }
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=b->up(ctx,&g,deadline);
    if(!rc)rc=running(deadline,cancel);
    if(!rc)rc=change_guard(j,b,ctx,t,&g,1,deadline,cancel);
    if(!rc)rc=running(deadline,cancel);
    if(rc){
        *cleanup_error=steer_draft_wg_coordinator_recover(j,b,ctx,t,deadline);
        return rc;
    }
    *ready=(struct steer_draft_wg_ready){g,c->config->listen_port};
    return 0;
}
