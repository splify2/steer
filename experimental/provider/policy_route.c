#include "policy_route.h"
struct steer_pv1_error steer_policy_route(void *context,
    const struct steer_draft_accepted *flow,uint32_t *action) {
    struct steer_policy_input input;
    struct steer_policy_decision decision;
    struct steer_pv1_error e={STEER_PV1_INVALID,0};
    if(action) *action=STEER_DRAFT_ROUTE_BLOCK;
    if(!flow || !action) return e;
    if(flow->principal || flow->flow_class!=STEER_PV1_FLOW_STREAM) {
        e.code=STEER_PV1_UNSUPPORTED; return e;
    }
    input.generation=flow->generation;
    input.inbound=flow->inbound_id;
    input.principal=flow->principal_id;
    input.destination=&flow->destination;
    e=steer_policy_evaluate(context,&input,&decision);
    if(!e.code && decision.action==STEER_POLICY_DIRECT) *action=STEER_DRAFT_ROUTE_DIRECT;
    return e;
}
