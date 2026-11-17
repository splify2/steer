/* Experimental source-only typed-plan preparation/execution; no loader ABI. */
#ifndef STEER_SPEC_EXECUTION_H
#define STEER_SPEC_EXECUTION_H
#include "spec.h"
#include "../provider/route_stream.h"
#include "../provider/datagram_routes.h"
#include <steer/draft/device_v1.h>
#include "../provider/cancel.h"
#define STEER_SPEC_EXECUTION_FACTORIES_MAX 512u
#define STEER_SPEC_EXECUTION_FACTORY_LAYOUT 2u
#define STEER_SPEC_EXECUTION_STEP 32u
struct steer_spec_execution;
/* Host-static module/catalogue guard. Caller owns a parent while submitting;
 * prepare retains one per descriptor before foreign callbacks, and releases
 * only after all owner cleanup and final worker discard callbacks RETURN.
 * Guard callbacks/context themselves cannot reside in the unloadable module. */
struct steer_spec_execution_guard {
    void *context;
    struct steer_pv1_error (*retain)(void *);
    void (*release)(void *);
};
struct steer_spec_execution_instance {
    void *handle; /* factory-owned, never interpreted by the executor */
    struct steer_draft_stream_binding stream;
    struct steer_draft_datagram_binding datagram;
    /* Factory instance owns the device reference until collect; the common
     * coordinator borrows this pair for journaled commit/quiesce/retire and
     * releases every exported operation before factory collect may consume it. */
    const struct steer_pv1_device_ref *device;
};
/* Array/records borrowed only during factory call; copy needed views/ref pairs.
 * Referenced objects remain owned through reverse graph cleanup. */
struct steer_spec_execution_dependency {
    struct steer_spec_edge_view edge;
    struct steer_spec_node_view target;
    const void *prepared; /* borrowed opaque resource/configuration, not secret bytes */
    const struct steer_spec_execution_instance *bound; /* NULL during worker prepare */
};
struct steer_spec_execution_owner {
    /* Record borrowed only during bind; copy fields needed later. */
    struct loop *loop;
    struct steer_pv1_host *host;
    uint64_t generation,instance_token;
    /* Owner-loop notification only. Must not reenter execution or collect;
     * schedules a later host turn. Outlives bound instance quiescence. */
    void (*wake)(void *);void *wake_context;
};
/* Worker-prepared state must be movable across fixed pool workers after a
 * synchronized handoff: no stored thread identity, TLS state or thread-local
 * namespace dependency. Failure unwind stays inline; later discard may use a
 * different worker, serialized without overlap. Owner-bound handles remain
 * exact-owner affine. Namespace jobs enter AND restore their pinned nsFD each
 * run; providers needing undeclared worker affinity are rejected.
 * Registration is host-trusted and exact; no wildcard type/provider/transport.
 * For protocol nodes provider is the resolved id:alias spelling, type NULL;
 * builtins/resources use an exact type (including empty for untyped resources).
 * transport/security/variant are explicit, including tcp/none/default defaults.
 * validate must check all supported options/common intent before any factory
 * dispatch. Matching kind/type alone never means options are supported.
 * The descriptor prefix is copied. Pointed-to names/callbacks/context remain
 * protected by the retained host guard through destroy, including callbacks.
 * A host guard spans every foreign callback return; releasing inside foreign
 * code is insufficient proof that its module may be unloaded. */
struct steer_spec_execution_factory {
    uint32_t size,version;
    enum steer_spec_node_kind kind;
    const char *type,*provider,*transport,*security,*variant;
    const char *node_id; /* optional exact typed-node selector, never wildcard */
    const char *stream_provider_id,*datagram_provider_id; /* exact origin identities for outbound classes */
    uint32_t flows;
    /* Exact implemented requirement names, <=64, each <=383 bytes. The executor
     * independently rejects unsupported common classifiers/actions; declaring
     * a capability here cannot manufacture an unimplemented core handler. */
    const char *const *capabilities;uint32_t capability_count;
    struct steer_spec_execution_guard guard;
    void *context;
    int (*validate)(void *,const struct steer_spec_node_view *); /* pure, bounded, no IO/reentry */
    /* Blocking preparation runs only on caller's bounded prepare worker.
     * No thread-per-node, owner-loop operations, publication or callbacks after
     * return. Cancellation/deadline cooperative; never forcibly kill a worker.
     * Any non-NULL state on error is discarded on this same worker. */
    struct steer_pv1_error (*prepare)(void *,const struct steer_spec_node_view *,
        const struct steer_spec_execution_dependency *,uint32_t,uint64_t deadline_ns,
        const struct steer_draft_cancel *,void **state);
    void (*discard)(void *,void *prepared); /* worker, reverse preparation order */
    /* Owner bind prepares quiescent resources. Failure may return an owned
     * partial instance, which is retained for owner retire/collect, not freed
     * on the worker. Exact generation/class/prepared bindings are verified. */
    struct steer_pv1_error (*bind)(void *,void *prepared,const struct steer_spec_node_view *,
        const struct steer_spec_execution_dependency *,uint32_t,
        const struct steer_spec_execution_owner *,struct steer_spec_execution_instance *);
    /* Memory-only no-fail publication. No file/netlink/listen/kernel activation:
     * all fallible effects require staged owner preparation/commit beforehand. */
    void (*publish)(void *,struct steer_spec_execution_instance *);
    void (*retire)(void *,struct steer_spec_execution_instance *); /* owner, stops admissions */
    /* OK consumes bound instance only after private callbacks/ops quiesce;
     * BUSY/error retains it and all dependency/module/plan ownership. */
    struct steer_pv1_error (*collect)(void *,struct steer_spec_execution_instance *);
};
struct steer_spec_execution_limits {
    uint32_t max_rules,max_match_values,max_match_bytes;
    uint32_t max_streams,max_stream_operations;
    struct steer_draft_datagram_route_limits datagrams;
};
/* Worker. Requires validated/runtime-ready plan AND concrete matching factories
 * and implemented common semantics. Unknown classifiers/actions are rejected.
 * Success transfers *owned_plan to execution and clears it; failure transfers
 * nothing and reverses every prepared factory on the same worker. Cancel input
 * is borrowed only through this call; later owner cancellation is retire. */
struct steer_pv1_error steer_spec_execution_prepare(struct steer_spec_plan **owned_plan,
    uint64_t generation,uint64_t first_instance_token,
    const struct steer_spec_execution_factory *,uint32_t factory_count,
    const struct steer_spec_execution_limits *,uint64_t deadline_ns,
    const struct steer_draft_cancel *,struct steer_spec_execution **);
/* Owner, max32 factory calls/step. MORE means call again on a later owner turn.
 * Nothing is exposed/published on partial success or failure. A bind failure
 * retains execution for reverse owner cleanup, then worker destruction. */
#define STEER_SPEC_EXECUTION_MORE 1u
#define STEER_SPEC_EXECUTION_READY 2u
struct steer_pv1_error steer_spec_execution_bind_step(struct steer_spec_execution *,
    struct loop *,struct steer_pv1_host *,void (*wake)(void *),void *wake_context,
    uint32_t *progress);
struct steer_pv1_error steer_spec_execution_publish(struct steer_spec_execution *);
void steer_spec_execution_retire(struct steer_spec_execution *);
/* Owner reverse dependency order, max32 factory calls/step. MORE retains all
 * worker-prepared state; READY permits worker destroy. Wake comes from origin
 * quiescence; callers must not invent timer polling to free live objects. */
struct steer_pv1_error steer_spec_execution_collect_step(struct steer_spec_execution *,uint32_t *progress);
/* Explicit retry after provider cleanup/reconciliation; ordinary owner wakes
 * never automatically repeat a failed foreign cleanup operation. */
struct steer_pv1_error steer_spec_execution_recover_owner(struct steer_spec_execution *);
struct steer_pv1_error steer_spec_execution_destroy_worker(struct steer_spec_execution *);
/* Borrowed owner routers are available only after complete publication. */
struct steer_draft_stream_routes *steer_spec_execution_streams(struct steer_spec_execution *);
struct steer_draft_datagram_router *steer_spec_execution_datagrams(struct steer_spec_execution *);
struct steer_draft_binding_lease *steer_spec_execution_configuration_lease(struct steer_spec_execution *,uint32_t flow_class);
#endif
