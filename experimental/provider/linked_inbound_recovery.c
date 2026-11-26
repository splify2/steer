#include "linked_inbound_recovery.h"
#include "inbound_guard_capture.h"
#include "awg.h"
#include "awgdev.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

static struct steer_pv1_error reject_rule(void *ctx,const struct steer_policy_rule *rule){
    (void)ctx;(void)rule;return (struct steer_pv1_error){STEER_PV1_UNSUPPORTED,0};
}
static int verify(void *arg,const struct steer_draft_wg_guard_record *r,uint64_t deadline){
    const struct steer_linked_inbound_recovery *c=arg;
    const struct steer_draft_kernel_wg_guard_config *g=c->inbound;
    const struct awg_conf *wg=c->wireguard;
    uint32_t fallback=0;
    if(!g||!wg||!c->policy||!c->guard.link||c->guard.prepared||c->guard.route||c->guard.scoped_route||
       g->return_only||g->peer_count!=1||g->peers[0].allowed_count!=1||
       wg->peer_n!=1||wg->aips_n!=1||wg->peer[0].aip_first!=0||wg->peer[0].aip_n!=1||
       wg->aips[0].family!=AF_INET||wg->aips[0].cidr!=32||
       !g->inbound_id[0]||!g->peers[0].principal_id[0]||g->generation!=c->revision.generation||
       steer_policy_visit(c->policy,g->generation,reject_rule,NULL,&fallback).code||fallback!=STEER_POLICY_DIRECT)
        return EOPNOTSUPP;
    const char *s=g->peers[0].allowed_ips[0];
    if(!memchr(s,0,sizeof(g->peers[0].allowed_ips[0])))return EINVAL;
    char peer[INET_ADDRSTRLEN];const char *slash=strchr(s,'/');
    if(!slash||strcmp(slash,"/32")||slash==s||(size_t)(slash-s)>=sizeof(peer))return EOPNOTSUPP;
    memcpy(peer,s,(size_t)(slash-s));peer[slash-s]=0;
    struct in_addr address;char canonical[INET_ADDRSTRLEN];
    if(inet_pton(AF_INET,peer,&address)!=1||!inet_ntop(AF_INET,&address,canonical,sizeof canonical)||strcmp(peer,canonical))return EINVAL;
    if(memcmp(&address,wg->aips[0].addr,4))return EINVAL;
    if(strcmp(r->link.kind,"wireguard")||!r->handle||!r->ifindex)return ESTALE;
    struct steer_draft_wg_observation seen;
    int ns=steer_draft_wg_linux_link_namespace(c->guard.link);
    int rc=steer_draft_wg_identity_reconcile(&r->link,ns,deadline,&seen);
    if(rc)return rc;
    if(seen.state!=STEER_DRAFT_WG_OWNED||seen.index<=0||(uint32_t)seen.index!=r->ifindex)return ESTALE;
    struct steer_inbound_guard_plan plan={r->table,r->marker,peer,r->handle,r->ifindex};
    rc=steer_inbound_guard_capture_verify(&plan,deadline);
    if(rc)return rc;
    rc=awg_dev_attest_inbound_peer_until(r->link.physical_name,seen.index,r->link.group,
        wg->peer[0].pub,&wg->aips[0],deadline);
    if(rc)return rc;
    rc=steer_draft_wg_identity_reconcile(&r->link,ns,deadline,&seen);
    if(rc)return rc;
    return seen.state==STEER_DRAFT_WG_OWNED&&seen.index>0&&(uint32_t)seen.index==r->ifindex?0:ESTALE;
}
int steer_linked_inbound_recover_checked(struct steer_linked_inbound *p,
    struct steer_linked_inbound_recovery *c,uint64_t deadline,uint64_t *next,struct steer_draft_wg_guard_record *selected){
    if(!p||!c||p->context!=c||p->backend!=&steer_draft_wg_linux_guard_backend||
       p->backend_guard!=&c->guard.prepared||!c->revision.generation||c->revision.without_wg)return EINVAL;
    return steer_linked_inbound_recover(p,&c->revision,verify,deadline,next,selected);
}
