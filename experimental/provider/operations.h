#ifndef STEER_EXPERIMENTAL_OPERATIONS_H
#define STEER_EXPERIMENTAL_OPERATIONS_H
#include <steer/draft/provider_v1.h>

struct steer_draft_operations;
typedef void (*steer_draft_operation_done)(void *, struct steer_pv1_error);
struct steer_draft_operation_allocator {
    void *context;
    void *(*allocate)(void *, size_t);
    void (*deallocate)(void *, void *);
};
/* Source-only completion scheduling, not real async IO cancellation.
 * Every call and callback is serialized on one owning shard. Allocators cannot
 * reenter; callbacks may start/resolve/cancel operations, but not dispatch.
 * Custom allocator/context outlive queue; NULL allocator uses malloc/free.
 * Live operations (including completed unreleased) never exceed max_live.
 * Queue storage is intrusive: no allocation during resolve/cancel/dispatch.
 * Handles must be valid/live, never stale/forged. No thread-ID enforcement. */
struct steer_pv1_error steer_draft_operations_create(uint32_t max_live,
    const struct steer_draft_operation_allocator *, struct steer_draft_operations **out);
/* Refuses while any live operation exists or dispatch is active. OK consumes q. */
struct steer_pv1_error steer_draft_operations_destroy(struct steer_draft_operations *q);
/* Callback/userdata retained by caller through completion return; no ownership
 * transfer. PENDING: callback deferred until dispatch, handle requires release.
 * REJECTED: no callback/handle, non-OK error. No data payload is supported. */
struct steer_pv1_async_start steer_draft_operation_start(struct steer_draft_operations *,
    steer_draft_operation_done, void *userdata);
/* First valid terminal result wins; duplicate result returns POLICY_DENIED.
 * Accepts draft status codes OK..INTERNAL, transient 0/1, OK requires 0.
 * Invalid result leaves state unchanged. Never invokes callback inline. */
struct steer_pv1_error steer_draft_operation_resolve(struct steer_pv1_operation *,
    struct steer_pv1_error terminal);
/* Processes at most min(max_count, queued-at-entry). Newly enqueued callbacks
 * wait for the next dispatch. Recursive dispatch returns POLICY_DENIED.
 * *dispatched is zero on error; output may be NULL. */
struct steer_pv1_error steer_draft_operations_dispatch(struct steer_draft_operations *,
    uint32_t max_count, uint32_t *dispatched);
/* Diagnostic counterpart of void ABI release: early release is POLICY_DENIED
 * and does nothing, including inside the terminal callback. OK consumes handle.
 * The ABI release silently uses this same safe check. */
struct steer_pv1_error steer_draft_operation_release_checked(struct steer_pv1_operation *);
void steer_draft_operations_usage(const struct steer_draft_operations *,
                                 uint32_t *live, uint32_t *queued);
#endif
