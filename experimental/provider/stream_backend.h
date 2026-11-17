#ifndef STEER_EXPERIMENTAL_STREAM_BACKEND_H
#define STEER_EXPERIMENTAL_STREAM_BACKEND_H
#include <steer/draft/stream_backend_v1.h>
#include "stream.h"
struct loop;
struct steer_draft_backend_runtime;
/* Source-only generation lease: one already-retained reference transfers on
 * successful wrap. Release cannot reenter this runtime and must defer module
 * unloading until its enclosing API call returns. NULL means no lease.
 * Every call/callback below runs serialized on the same owner loop as native IO. */
struct steer_draft_backend_pin {void *context;void (*release)(void *);};
struct steer_pv1_error steer_draft_backend_runtime_create(struct loop *,
    uint32_t max_streams,uint32_t max_operations,uint64_t max_queued_bytes,
    struct steer_draft_backend_runtime **);
struct steer_pv1_error steer_draft_backend_runtime_destroy(struct steer_draft_backend_runtime *);
/* Wrap only a valid, exclusively owned stream created by stream.h on this loop.
 * Success consumes its one reference and the optional pin; failure consumes
 * neither. No fd adoption/casting: native stream API owns all socket IO.
 * Budgets count completed-unreleased operations and full submitted lengths
 * through callback entry; there are no payload copies/additional buffer refs. */
struct steer_pv1_error steer_draft_backend_wrap_native(struct steer_draft_backend_runtime *,
    struct steer_pv1_stream *,const struct steer_draft_backend_pin *,struct steer_pv1_stream_ref *);
void steer_draft_backend_usage(const struct steer_draft_backend_runtime *,uint32_t *streams,
    uint32_t *operations,uint64_t *bytes);
#endif
