/* Experimental host buffer table only. Not production integration or stable ABI. */
#ifndef STEER_EXPERIMENTAL_BUFFERS_H
#define STEER_EXPERIMENTAL_BUFFERS_H
#include <steer/draft/provider_v1.h>

struct steer_draft_buffer_limits {
    uint64_t max_bytes; /* live capacities plus per-buffer allocation metadata */
    uint32_t max_buffers;
    uint32_t max_references; /* 1..UINT32_MAX, also bounds retain */
};
struct steer_draft_allocator {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *allocation);
};
/* All calls, including allocator callbacks and destruction, run on the SAME
 * owning shard, serialized, without reentry. No locking/thread-ID detection.
 * NULL allocator uses malloc/free. A custom allocator must return suitably
 * aligned, disjoint allocations or NULL; callbacks/context outlive the host.
 * Host metadata is fixed overhead outside max_bytes. No IO or async service.
 * On any error *out=NULL when out exists. */
struct steer_pv1_error steer_draft_buffers_create(
    const struct steer_draft_buffer_limits *, const struct steer_draft_allocator *,
    struct steer_pv1_host **out);
const struct steer_pv1_buffer_api *steer_draft_buffers_api(void);
/* Refuses destruction while any buffer remains live. OK consumes host.
 * No handle/view may be used after successful release/destruction. */
struct steer_pv1_error steer_draft_buffers_destroy(struct steer_pv1_host *);
/* Diagnostic snapshot, same-shard only, output optional. */
void steer_draft_buffers_usage(const struct steer_pv1_host *, uint64_t *bytes,
                               uint32_t *buffers);
#endif
