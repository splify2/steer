#ifndef STEER_EXPERIMENTAL_POLICY_ROUTE_H
#define STEER_EXPERIMENTAL_POLICY_ROUTE_H
#include "policy.h"
#include "route_dial.h"
/* Callback adapter; context is an immutable steer_policy. Non-NULL principals
 * require a future host identity service; never interpret an opaque handle as
 * a trusted user ID. principal_id must already be issued by the trusted host
 * after credential verification; empty explicitly means anonymous. */
struct steer_pv1_error steer_policy_route(void *,
    const struct steer_draft_accepted *, uint32_t *action);
#endif
