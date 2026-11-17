#ifndef STEER_EXPERIMENTAL_HOST_H
#define STEER_EXPERIMENTAL_HOST_H
#include "buffers.h"
#define STEER_DRAFT_HOST_LOG_MAX UINT32_C(4096)
struct steer_draft_host_services {
    void *context;
    uint64_t (*monotonic_ns)(void *);
    void (*log)(void *, uint32_t severity, struct steer_pv1_span);
};
/* Services record and context are borrowed, immutable and live until host
 * destruction. Both callbacks required. Same owning shard, serialized, no
 * allocator/service callback reentry. Clock must return monotonic nanoseconds;
 * log sink must bound its own storage/rate and must not retain borrowed span.
 * Host drops messages >4096, invalid NULL spans and unknown severity; no IO,
 * clock source, secret redaction or rate limiter is supplied by this layer.
 * Create clears *out on failure. Destroy using steer_draft_buffers_destroy;
 * it refuses live buffers. No provider lifecycle/operations are tracked here. */
struct steer_pv1_error steer_draft_host_create(
    const struct steer_draft_buffer_limits *, const struct steer_draft_allocator *,
    const struct steer_draft_host_services *, struct steer_pv1_host **out);
/* Only host_create-configured hosts return OK. Buffer-only hosts unsupported.
 * On error *out=NULL. Returned table is immutable; use only with the configured
 * live host. api_major=1/minor=0 are draft-local, not a stable SDK advertisement.
 * Invalid/stale/forged host pointers are caller contract violations. */
struct steer_pv1_error steer_draft_host_get_api(struct steer_pv1_host *,
    const struct steer_pv1_host_api **out);
#endif
