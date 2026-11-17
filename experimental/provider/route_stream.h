#ifndef STEER_EXPERIMENTAL_ROUTE_STREAM_H
#define STEER_EXPERIMENTAL_ROUTE_STREAM_H
#include "stream_backend.h"
#include "binding_lease.h"
#include "flow_metadata.h"
#define STEER_DRAFT_STREAM_ROUTE_BLOCK UINT32_MAX
#define STEER_DRAFT_STREAM_BINDINGS_MAX 512u
#define STEER_DRAFT_STREAM_BINDING_PREPARED UINT64_C(1)
#define STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN UINT64_C(2)
struct steer_draft_stream_routes;
/* Immutable host registry entry, prepared from validated provider/IR options.
 * No protocol enum or peer-selected context. Backend and API calls are local
 * to owner; the lease may be pinned across workers but does not make context
 * methods concurrent. Identity/generation/dependencies live in the lease. */
struct steer_draft_stream_binding {
    struct loop *owner;
    struct steer_draft_binding_lease *lease;
    const struct steer_pv1_stream_backend_api *api;
    void *context;
};
/* Pure bounded selection of an index in the copied immutable registry, or
 * BLOCK. Policy sees the original validated destination before any resolution.
 * An error, invalid index or unavailable binding never falls back to direct. */
typedef struct steer_pv1_error (*steer_draft_stream_route_select)(void *,
    const struct steer_pv1_flow_metadata *,uint32_t *binding_index);
/* Success copies entries, pins their exact generation, and consumes optional
 * already-retained configuration_pin. Failure consumes nothing. Select/context
 * must remain alive through routes destruction (configuration_pin can hold it).
 * max_operations includes completed-unreleased opens; max_streams bounds host
 * guards. Guard keeps origin API/lease until inner close+release returns and
 * all IO operation references retire; no fd reinterpretation or payload copy. */
struct steer_pv1_error steer_draft_stream_routes_create(struct loop *,uint64_t generation,
    uint32_t max_operations,uint32_t max_streams,
    const struct steer_draft_stream_binding *,uint32_t binding_count,
    steer_draft_stream_route_select,void *,const struct steer_draft_backend_pin *configuration_pin,
    struct steer_draft_stream_routes **);
struct steer_pv1_error steer_draft_stream_routes_destroy(struct steer_draft_stream_routes *);
typedef void (*steer_draft_stream_routes_drained)(void *,struct steer_draft_stream_routes *);
/* Register once before any opens. Quiesce stops new opens; exported streams
 * retain their origin and drain. Notification is deferred on the owner eventfd
 * after router opens/guards/quarantine drain, never inline from foreign release.
 * Provider-private jobs keep independent leases beyond router destruction.
 * Destroy refuses before delivery or inside callback; collect on a later turn. */
struct steer_pv1_error steer_draft_stream_routes_on_drained(struct steer_draft_stream_routes *,
    steer_draft_stream_routes_drained,void *);
void steer_draft_stream_routes_quiesce(struct steer_draft_stream_routes *);
/* Legacy route_dial remains native-only for current HY2 compatibility. This
 * new API returns origin pairs. PENDING always defers completion, including
 * backend rejection, and pins binding/open state until operation release. */
struct steer_pv1_async_start steer_draft_stream_route_open(struct steer_draft_stream_routes *,
    const struct steer_pv1_flow_metadata *,uint64_t deadline_ns,steer_pv1_stream_open_done,void *);
/* Provider-contract failures during discard are retained, not leaked/unpinned.
 * Quarantined entries count against open admission and block destruction.
 * No automatic retries. Explicit recovery attempts at most32 closed references
 * after the provider has quiesced; unreleased public open ops are not consumed. */
uint32_t steer_draft_stream_routes_quarantined(const struct steer_draft_stream_routes *);
struct steer_pv1_error steer_draft_stream_routes_recover(struct steer_draft_stream_routes *,uint32_t *recovered);
#endif
