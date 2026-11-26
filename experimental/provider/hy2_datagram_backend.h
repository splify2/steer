/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_HY2_DATAGRAM_BACKEND_H
#define STEER_HY2_DATAGRAM_BACKEND_H
#include "datagram_routes.h"
struct steer_hy2_profile;
struct steer_hy2_datagram_backend;
/* Success consumes profile. All methods run on loop owner. */
struct steer_pv1_error steer_hy2_datagram_backend_create(struct loop *,
    struct steer_pv1_host *, struct steer_hy2_profile *, uint64_t generation,
    uint64_t token, uint32_t max_operations, uint64_t max_bytes,
    uint32_t max_references, unsigned drain_ms, void (*drained)(void *),
    void *, struct steer_hy2_datagram_backend **);
const struct steer_draft_datagram_binding *steer_hy2_datagram_binding(
    const struct steer_hy2_datagram_backend *);
void steer_hy2_datagram_backend_retire(struct steer_hy2_datagram_backend *);
struct steer_pv1_error steer_hy2_datagram_backend_destroy(struct steer_hy2_datagram_backend *);
#endif
