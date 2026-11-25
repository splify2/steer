#ifndef STEER_EXPERIMENTAL_NATIVE_STREAM_BACKEND_H
#define STEER_EXPERIMENTAL_NATIVE_STREAM_BACKEND_H
#include "route_stream.h"
#include "route_dial.h"
struct steer_draft_resolver;
struct steer_draft_native_stream_backend;
typedef void (*steer_draft_native_stream_retired)(void *);
/* Source-only prepared direct backend. All methods on owner loop; loop/native
 * and origin-wrapper runtimes/resolver outlive backend destruction. No new IO
 * engine: delegates connect/DNS to existing route_dial, then native stream API.
 * Identity becomes prepared only after all service allocations succeed. */
struct steer_pv1_error steer_draft_native_stream_backend_create(struct loop *,
    struct steer_draft_stream_runtime *,struct steer_draft_backend_runtime *,
    struct steer_draft_resolver *,uint64_t generation,uint64_t instance_token,
    uint32_t max_operations,uint32_t max_references,steer_draft_native_stream_retired,void *,
    struct steer_draft_native_stream_backend **);
const struct steer_draft_stream_binding *steer_draft_native_stream_binding(const struct steer_draft_native_stream_backend *);
struct steer_pv1_error steer_draft_native_stream_socket_guard(struct steer_draft_native_stream_backend *,
    steer_draft_socket_guard,void *);
/* Retire stops new admissions; already admitted opens/streams retain their
 * generation. Destroy refuses until finalizer notification and all pins/ops
 * retire. It runs only on owner and never unloads a module by itself. */
struct steer_pv1_error steer_draft_native_stream_backend_retire(struct steer_draft_native_stream_backend *);
struct steer_pv1_error steer_draft_native_stream_backend_destroy(struct steer_draft_native_stream_backend *);
#endif
