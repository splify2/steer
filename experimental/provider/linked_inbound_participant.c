#include "linked_inbound_participant.h"
#include <errno.h>
#include <string.h>

int steer_linked_inbound_recover(struct steer_linked_inbound *p,const struct steer_draft_wg_revision *chosen,
    steer_draft_wg_verify_ready verify,uint64_t deadline,uint64_t *next,struct steer_draft_wg_guard_record *selected){
    if(!p||!steer_draft_wg_selection_is_inbound(p->journal)||!p->backend||!chosen||!verify||!next||!selected||p->staged)return EINVAL;
    p->fenced=1;
    int rc=steer_draft_wg_selection_startup(p->journal,p->backend,p->context,chosen,verify,deadline,next,selected);
    if(!rc){p->committed=*chosen;p->fenced=0;p->recovered=1;}
    return rc;
}
int steer_linked_inbound_prepare(struct steer_linked_inbound *p,const struct steer_draft_wg_tx *tx,
    const struct steer_draft_wg_candidate *input,const struct steer_draft_kernel_wg_guard_config *config,
    const struct steer_policy *policy,uint16_t previous_port,uint64_t deadline){
    if(!p||!steer_draft_wg_selection_is_inbound(p->journal)||!p->backend||!p->backend_guard||*p->backend_guard||!tx||!input||!config||!policy||
       !p->recovered||p->fenced||p->staged||config->return_only||!config->peer_count||config->generation!=tx->generation||
       strcmp(config->device,input->link.physical_name)||input->link.generation!=tx->generation)return EINVAL;
    struct steer_draft_kernel_wg_guard *guard=NULL;
    if(steer_draft_kernel_wg_guard_prepare(config,policy,&guard).code)return EINVAL;
    struct steer_draft_wg_candidate c=*input;
    int rc=steer_draft_kernel_wg_guard_plan(guard,c.table,c.marker);
    if(!rc){
        *p->backend_guard=guard;
        rc=steer_draft_wg_selection_stage(p->journal,p->backend,p->context,&p->committed,previous_port,tx,&c,deadline,&p->candidate);
        *p->backend_guard=NULL;
    }
    steer_draft_kernel_wg_guard_forget_prepared(guard);
    if(rc){p->fenced=1;return rc;}
    p->pending=(struct steer_draft_wg_revision){.generation=tx->generation};
    memcpy(p->pending.digest,tx->plan_digest,sizeof(p->pending.digest));
    p->staged=1;
    return 0;
}
int steer_linked_inbound_live_commit(struct steer_linked_inbound *p,struct steer_prototype_store_result result,
    const struct steer_draft_wg_revision *chosen){
    if(!p||!p->staged)return EINVAL;
    p->staged=0;
    p->fenced=1;
    if(!chosen||result.phase!=STEER_PROTOTYPE_STORE_SYNCED||result.error.code||
       chosen->without_wg||chosen->generation!=p->pending.generation||
       memcmp(chosen->digest,p->pending.digest,sizeof(chosen->digest)))return ESTALE;
    p->committed=*chosen;
    p->fenced=0;
    return 0;
}
int steer_linked_inbound_finish(struct steer_linked_inbound *p,struct steer_prototype_store_result result,
    steer_draft_wg_verify_ready verify,uint64_t deadline){
    if(!p||!p->staged)return EINVAL;
    p->staged=0;
    if(result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code){
        /* Owner must supply the new committed selection through recovery before
         * another operation: no participant-owned revision selector. */
        p->fenced=1;
        return 0;
    }
    p->fenced=1;
    if(result.phase!=STEER_PROTOTYPE_STORE_NOT_RENAMED)return EIO;
    uint64_t next;struct steer_draft_wg_guard_record selected;
    return steer_linked_inbound_recover(p,&p->committed,verify,deadline,&next,&selected);
}
