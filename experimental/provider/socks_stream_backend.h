/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_EXPERIMENTAL_SOCKS_STREAM_BACKEND_H
#define STEER_EXPERIMENTAL_SOCKS_STREAM_BACKEND_H
#include "route_stream.h"

#define STEER_DRAFT_SOCKS_HANDSHAKE_MAX 513u
struct steer_draft_socks_stream_backend;
/* Empty username/password means NOAUTH; otherwise both are required (1..255).
 * Borrowed secrets are copied into a private wire frame, never logged. */
struct steer_pv1_error steer_draft_socks_stream_backend_create(struct loop *,
    struct steer_pv1_host *, const struct steer_draft_stream_binding *,
    const struct steer_pv1_endpoint *, struct steer_pv1_span username,
    struct steer_pv1_span password, uint64_t generation, uint64_t instance_token,
    uint32_t max_opens, uint32_t max_references, void (*retired)(void *), void *,
    struct steer_draft_socks_stream_backend **);
const struct steer_draft_stream_binding *steer_draft_socks_stream_binding(
    const struct steer_draft_socks_stream_backend *);
void steer_draft_socks_stream_backend_retire(struct steer_draft_socks_stream_backend *);
struct steer_pv1_error steer_draft_socks_stream_backend_destroy(struct steer_draft_socks_stream_backend *);
/* Explicit recovery only for a lower provider refusing release. */
struct steer_pv1_error steer_draft_socks_stream_backend_recover(struct steer_draft_socks_stream_backend *);
#endif
