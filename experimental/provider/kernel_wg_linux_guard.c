#include "kernel_wg_linux_guard.h"
#include "awgdev.h"
#include "nftdump.h"
#include <steer/draft/device_v1.h>
#include <errno.h>
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
    return awg_dev_link_up_owned_until(r->link.physical_name,r->link.kind,(int)r->ifindex,r->link.group,d);
}
static int retire_guard(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d){
    const struct steer_draft_wg_linux_guard *g=ctx;
    return g?steer_draft_kernel_wg_guard_retire_record(r,steer_draft_wg_linux_link_namespace(g->link),d):EINVAL;
}
const struct steer_draft_wg_backend steer_draft_wg_linux_guard_backend={
    .create_down=create,.stage_down=stage,.guard=guard,.up=up,.retire_link=retire,
    .lookup_guard=lookup,.retire_guard=retire_guard
};
