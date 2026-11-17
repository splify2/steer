#ifndef STEER_EXPERIMENTAL_ROUTE_DIAL_H
#define STEER_EXPERIMENTAL_ROUTE_DIAL_H
#include "stream.h"
struct steer_draft_routes;
struct steer_draft_resolver;
/* Source-only accepted-flow seam, NOT a frozen provider ABI. Every span is
 * borrowed through route_dial start only. Destination retains domain/IP identity
 * until policy; source must be numeric. Currently TCP only: non-NULL opaque
 * principal, datagrams and unknown action fail closed. Domain direct resolution
 * requires an attached bounded resolver; otherwise returns UNSUPPORTED.
 * Inbound ID is 1..64 ASCII [A-Za-z0-9_.-], generation must be nonzero.
 * Host supplies metadata; it must not trust peer-supplied principal/generation. */
struct steer_draft_accepted {
    uint64_t generation;
    struct steer_pv1_span inbound_id;
    /* Host-validated stable ID, never credentials or arbitrary peer input.
     * Empty ID + NULL handle explicitly means anonymous. Nonempty ID is the
     * lab bridge after host credential verification; central auth is future. */
    struct steer_pv1_span principal_id;
    struct steer_pv1_endpoint source, destination;
    struct steer_pv1_principal *principal;
    uint32_t flow_class;
};
#define STEER_DRAFT_ROUTE_BLOCK UINT32_C(0)
#define STEER_DRAFT_ROUTE_DIRECT UINT32_C(1)
#define STEER_DRAFT_DIAL_NONE UINT32_C(0)
#define STEER_DRAFT_DIAL_REFUSED UINT32_C(1)
#define STEER_DRAFT_DIAL_NETWORK_UNREACHABLE UINT32_C(2)
#define STEER_DRAFT_DIAL_HOST_UNREACHABLE UINT32_C(3)
#define STEER_DRAFT_DIAL_OTHER UINT32_C(4)
/* Pure bounded evaluator: no IO/reentry. No default-direct on error. Evaluator
 * and context outlive service. Policy sees original domain before resolution.
 * The action is explicit; legacy nft rules are not automatically imported.
 * Service binds one nonzero generation and rejects mismatched flow generations.
 * Loop, stream runtime, evaluator/context outlive the service and its operations. */
typedef struct steer_pv1_error (*steer_draft_route_evaluate)(void *,
    const struct steer_draft_accepted *, uint32_t *action);
/* Callback bound endpoint is borrowed on callback only. Success transfers one
 * stream reference; caller closes/releases it. Error has stream/bound NULL.
 * Callback/userdata stay live through return, op release must follow return. */
/* dial_failure is diagnostic classification, never a native errno. Preserves
 * refused/network/host failure for protocol reply mapping (e.g. SOCKS5 5/3/4).
 * Error code TIMEOUT separately maps a protocol timeout; NONE is used otherwise.
 * Authenticated providers must preserve verified identity in principal_id;
 * opaque principal handle resolution remains unsupported. */
typedef void (*steer_draft_route_done)(void *, struct steer_pv1_error, uint32_t dial_failure,
    struct steer_pv1_stream *, const struct steer_pv1_endpoint *bound);
struct steer_pv1_error steer_draft_routes_create(struct loop *,
    struct steer_draft_stream_runtime *, uint64_t generation, uint32_t max_operations,
    steer_draft_route_evaluate, void *context, struct steer_draft_routes **);
/* Refuses pending/queued/completed-unreleased operations and callback dispatch. */
struct steer_pv1_error steer_draft_routes_destroy(struct steer_draft_routes *);
/* Optional shared resolver, attach before starting operations. Retained until
 * routes destruction; one pool can serve all generations. NULL keeps domains
 * unsupported. Existing numeric-only behavior and callback layout unchanged. */
struct steer_pv1_error steer_draft_routes_use_resolver(struct steer_draft_routes *,
    struct steer_draft_resolver *);
/* deadline_ns is absolute CLOCK_MONOTONIC, mandatory and strictly in future.
 * Rejected: no callback/no resources transferred. Pending: exactly one deferred
 * callback. Cancel closes connecting fd/removes readiness/deadline before queueing
 * completion. Queued success may win. Runs entirely on owning loop shard. */
struct steer_pv1_async_start steer_draft_route_dial(struct steer_draft_routes *,
    const struct steer_draft_accepted *, uint64_t deadline_ns,
    steer_draft_route_done, void *userdata);
#endif
