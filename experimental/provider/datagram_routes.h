#ifndef STEER_EXPERIMENTAL_DATAGRAM_ROUTES_H
#define STEER_EXPERIMENTAL_DATAGRAM_ROUTES_H
#include <steer/draft/datagram_route_v1.h>
#include "binding_lease.h"
struct steer_draft_datagram_router;
struct steer_draft_datagram_route_limits {
    uint32_t max_associations; /* 1..1024 */
    uint32_t max_targets; /* global, 1..1024; also bounds association*target product */
    uint32_t max_targets_per_association; /* 1..64, <=max_targets */
    uint32_t max_operations; /* includes terminal unreleased opens and IO, 1..4096 */
    uint64_t max_queued_bytes;
    uint64_t idle_ns; /* unreferenced cache entries only; no timer-based live free */
};
#define STEER_DRAFT_DATAGRAM_ROUTE_BLOCK 0u
#define STEER_DRAFT_DATAGRAM_ROUTE_DIRECT 1u
#define STEER_DRAFT_DATAGRAM_ROUTE_DETOUR 2u /* explicitly unsupported in first integration */
#define STEER_DRAFT_DATAGRAM_ROUTE_BLOCK_INDEX UINT32_MAX
#define STEER_DRAFT_DATAGRAM_BINDINGS_MAX 512u
#define STEER_DRAFT_DATAGRAM_BINDING_PREPARED UINT64_C(1)
#define STEER_DRAFT_DATAGRAM_BINDING_TARGET_DOMAIN UINT64_C(2)
/* Copied immutable host registry. Methods are owner-shard serialized; a shared
 * atomic lease does not make a provider's context concurrently callable. */
struct steer_draft_datagram_binding {
    struct loop *owner;
    struct steer_draft_binding_lease *lease;
    const struct steer_pv1_datagram_backend_api *api;
    void *context;
};
typedef struct steer_pv1_error (*steer_draft_datagram_route_select)(void *,
    const struct steer_pv1_flow_metadata *,uint32_t *binding_index);
/* Exact generation/class/prepared identities, unique provider/token tuples.
 * Copies entries and retains parent pins on success. Configuration lease pins
 * policy/context; entries pin backend instances until all private work drains.
 * Policy runs for every new open; exported refs retain their selected origin.
 * Invalid selection, unsupported destination or provider never falls back. */
struct steer_pv1_error steer_draft_datagram_router_create_registry(struct loop *,struct steer_pv1_host *,
    struct steer_draft_binding_lease *configuration_lease,
    const struct steer_draft_datagram_binding *,uint32_t binding_count,
    const struct steer_draft_datagram_route_limits *,steer_draft_datagram_route_select,void *policy_context,
    struct steer_draft_datagram_router **);
/* Bounded pure evaluation; input borrowed on call. No IO/reentry or default
 * direct on error. Context and selected backend stay pinned by the lease. */
typedef struct steer_pv1_error (*steer_draft_datagram_evaluate)(void *,
    const struct steer_pv1_flow_metadata *,uint32_t *action);
struct steer_pv1_error steer_draft_datagram_router_create(struct loop *,struct steer_pv1_host *,
    struct steer_draft_binding_lease *,const struct steer_pv1_datagram_backend_api *,void *backend_context,
    const struct steer_draft_datagram_route_limits *,steer_draft_datagram_evaluate,void *policy_context,
    struct steer_draft_datagram_router **);
void steer_draft_datagram_router_quiesce(struct steer_draft_datagram_router *);
void steer_draft_datagram_router_close(struct steer_draft_datagram_router *);
typedef void (*steer_draft_datagram_drained)(void *,struct steer_draft_datagram_router *);
/* Register once before creating associations. After quiesce/close, owner-loop
 * notification runs once when public refs/ops AND private cleanup have drained.
 * Never inline from foreign release. Router/context stay alive through return;
 * destroy is refused inside notification or before its delivery. Notify the
 * host owner to collect on a later turn. Quarantine prevents notification. */
struct steer_pv1_error steer_draft_datagram_router_on_drained(struct steer_draft_datagram_router *,
    steer_draft_datagram_drained,void *);
/* Explicit owner recovery after provider cleanup, never automatic retry.
 * Examines at most 32 entries/call, queues at most one release retry per entry.
 * Only a valid origin whose release previously refused is eligible; malformed
 * handles/operation tables remain quarantined and retain all ownership. */
uint32_t steer_draft_datagram_router_retry_cleanup(struct steer_draft_datagram_router *);
struct steer_pv1_error steer_draft_datagram_router_destroy(struct steer_draft_datagram_router *);
const struct steer_pv1_datagram_route_api *steer_draft_datagram_router_api(void);
void steer_draft_datagram_router_usage(const struct steer_draft_datagram_router *,
    uint32_t *associations,uint32_t *targets,uint32_t *operations,uint64_t *bytes);
#ifdef STEER_DRAFT_DATAGRAM_TEST_HOOKS
/* Deterministic owner-wake test only; callback schedules work, never reenters. */
void steer_draft_datagram_router_test_after_pump(struct steer_draft_datagram_router *,void (*)(void *),void *);
#endif
#endif
