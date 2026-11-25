/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_HY2_STREAM_BACKEND_H
#define STEER_HY2_STREAM_BACKEND_H
#include "route_stream.h"
struct steer_hy2_profile;
struct steer_hy2_stream_backend;
/* Success consumes the prepared profile. All calls are on the owner loop.
 * The buffer host and loop outlive the backend. */
struct steer_pv1_error steer_hy2_stream_backend_create(struct loop *,
    struct steer_pv1_host *,struct steer_hy2_profile *,uint64_t generation,
    uint64_t token,uint32_t max_operations,uint64_t max_bytes,uint32_t max_references,
    unsigned drain_ms,void (*retired)(void *),void *,struct steer_hy2_stream_backend **);
const struct steer_draft_stream_binding *steer_hy2_stream_binding(const struct steer_hy2_stream_backend *);
void steer_hy2_stream_backend_retire(struct steer_hy2_stream_backend *);
struct steer_pv1_error steer_hy2_stream_backend_destroy(struct steer_hy2_stream_backend *);
#endif
