#include "kernel_wg_linux_guard.h"
#include "awgdev.h"
#include "nftdump.h"
#include <steer/draft/device_v1.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

static int create(void *ctx,const struct steer_draft_wg_identity *id,int mtu,uint64_t d,int *index){
    const struct steer_draft_wg_linux_guard *g=ctx;
    return g?steer_draft_wg_linux_link_backend.create_down(g->link,id,mtu,d,index):EINVAL;
}
static int stage(void *ctx,const struct steer_draft_wg_identity *id,int index,
    const struct awg_conf *conf,const struct awg_secrets *keys,uint32_t mark,uint64_t d){
    const struct steer_draft_wg_linux_guard *g=ctx;
    return g?steer_draft_wg_linux_link_backend.stage_down(g->link,id,index,conf,keys,mark,d):EINVAL;
}
static int retire(void *ctx,const struct steer_draft_wg_identity *id,uint64_t d){
    const struct steer_draft_wg_linux_guard *g=ctx;
    if(g&&g->scoped_route){
        struct steer_draft_wg_observation seen;
        int rc=steer_draft_wg_identity_reconcile(id,steer_draft_wg_linux_link_namespace(g->link),d,&seen);
        if(rc)return rc;
        if(seen.state!=STEER_DRAFT_WG_OWNED&&seen.state!=STEER_DRAFT_WG_ABSENT)return ESTALE;
        rc=awg_dev_scoped_rules_retire_until(id->physical_name,
            seen.state==STEER_DRAFT_WG_OWNED?seen.index:0,id->group,d);
        if(rc)return rc;
    }
    return g?steer_draft_wg_linux_link_backend.retire_link(g->link,id,d):EINVAL;
}
static int guard(void *ctx,const struct steer_draft_wg_guard_record *r,int publish,
    uint64_t d,uint32_t *effect,uint64_t *handle){
    const struct steer_draft_wg_linux_guard *g=ctx;
    if(!g||!g->prepared)return EINVAL;
    struct steer_draft_kernel_wg_guard_result result=steer_draft_kernel_wg_guard_apply_owned(
        g->prepared,r,steer_draft_wg_linux_link_namespace(g->link),publish,d,handle);
    *effect=result.phase==STEER_DRAFT_WG_GUARD_CHANGED?STEER_PV1_DEVICE_CHANGED:
        result.phase==STEER_DRAFT_WG_GUARD_UNCHANGED?STEER_PV1_DEVICE_UNCHANGED:STEER_PV1_DEVICE_EFFECT_UNCERTAIN;
    return result.error.code?EIO:0;
}
static int lookup(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d,
    uint64_t *handle,char comment[256]){
    const struct steer_draft_wg_linux_guard *g=ctx;
    if(!g||!r||!handle||!comment)return EINVAL;
    struct steer_draft_wg_observation link;
    int rc=steer_draft_wg_identity_reconcile(&r->link,steer_draft_wg_linux_link_namespace(g->link),d,&link);
    if(rc)return rc;
    if(link.state!=STEER_DRAFT_WG_ABSENT&&
       (link.state!=STEER_DRAFT_WG_OWNED||(uint32_t)link.index!=r->ifindex))return ESTALE;
    struct nfd_exact_table actual;
    rc=nfd_exact_inet_until(r->table,&actual,d);
    if(rc)return rc;
    *handle=actual.handle;
    memcpy(comment,actual.comment,sizeof(actual.comment));
    return 0;
}
static int up(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d){
    uint64_t handle;
    char marker[256];
    int rc=lookup(ctx,r,d,&handle,marker);
    if(rc)return rc;
    if(steer_draft_wg_guard_record_observe(r,handle,marker)!=STEER_DRAFT_WG_OWNED)return ESTALE;
    rc=awg_dev_link_up_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d);
    const struct steer_draft_wg_linux_guard *g=ctx;
    if(rc||!g->route)return rc;
    if(g->scoped_route)return awg_dev_scoped_route_add_until(r->link.physical_name,r->link.kind,
        (int)r->ifindex,r->link.group,g->route,d);
    /* Linux requires the route's nexthop to be UP. This is still before
     * policy publication: the journal-proven DROP remains installed. */
    rc=awg_dev_route_add_owned_until(r->link.physical_name,r->link.kind,
        (int)r->ifindex,r->link.group,g->route,d);
    if(rc)return rc;
    return awg_dev_route_check_owned_until(r->link.physical_name,r->link.kind,
        (int)r->ifindex,r->link.group,g->route,d);
}
static int retire_guard(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d){
    const struct steer_draft_wg_linux_guard *g=ctx;
    return g?steer_draft_kernel_wg_guard_retire_record(r,steer_draft_wg_linux_link_namespace(g->link),d):EINVAL;
}
const struct steer_draft_wg_backend steer_draft_wg_linux_guard_backend={
    .create_down=create,.stage_down=stage,.guard=guard,.up=up,.retire_link=retire,
    .lookup_guard=lookup,.retire_guard=retire_guard
};

static int barrier_identity(const struct steer_draft_wg_linux_guard *g,
    const struct steer_draft_wg_guard_record *r,uint64_t d){
    if(!g||!g->link||!r||!r->ifindex||r->ifindex>INT_MAX||strcmp(r->link.kind,"wireguard"))return EINVAL;
    struct steer_draft_wg_observation seen;
    int rc=steer_draft_wg_identity_reconcile(&r->link,steer_draft_wg_linux_link_namespace(g->link),d,&seen);
    if(rc)return rc;
    return seen.state==STEER_DRAFT_WG_OWNED&&seen.index==(int)r->ifindex?0:ESTALE;
}
static int barrier_state(const struct steer_draft_wg_linux_guard *g,
    const struct steer_draft_wg_guard_record *r,uint64_t d,int up){
    int rc=barrier_identity(g,r,d);if(rc)return rc;
    return up?awg_dev_link_require_up_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d):
        awg_dev_link_require_down_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d);
}
int steer_draft_wg_linux_guard_barrier_close(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d,uint32_t *state){
    if(!state)return EINVAL;
    *state=STEER_INBOUND_BARRIER_UNKNOWN;
    const struct steer_draft_wg_linux_guard *g=ctx;
    int rc=barrier_identity(g,r,d);
    if(rc)return rc;
    int mutate=awg_dev_link_down_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d);
    rc=barrier_state(g,r,d,0);
    if(!rc)*state=STEER_INBOUND_BARRIER_CLOSED;
    return mutate?mutate:rc;
}
int steer_draft_wg_linux_guard_barrier_open(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d,uint32_t *state){
    if(!state)return EINVAL;
    *state=STEER_INBOUND_BARRIER_UNKNOWN;
    const struct steer_draft_wg_linux_guard *g=ctx;
    int rc=barrier_state(g,r,d,0);
    if(rc)return rc;
    int mutate=awg_dev_link_up_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d);
    rc=barrier_state(g,r,d,1);
    if(!mutate&&!rc){*state=STEER_INBOUND_BARRIER_OPEN;return 0;}
    int failure=mutate?mutate:rc;
    (void)steer_draft_wg_linux_guard_barrier_close(ctx,r,d,state);
    return failure;
}
