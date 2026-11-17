/* SPDX-License-Identifier: GPL-3.0-only
 * Internal experimental host seam, not a published provider ABI. */
#ifndef STEER_DRAFT_INBOUND_SERVICES_H
#define STEER_DRAFT_INBOUND_SERVICES_H
#include "route_dial.h"
struct steer_draft_route_lease {
    struct steer_draft_routes *routes;
    uint64_t generation;
    void *handle;
};
struct steer_draft_inbound_services {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    struct steer_draft_stream_runtime *streams;
    void *context;
    /* Host validates credentials using current listener/auth state, copies
     * principal and returns an admission epoch (never a credential hash/value).
     * Input credentials are borrowed only until callback returns. */
    int (*authenticate)(void *,struct steer_pv1_span inbound,const uint8_t *,size_t,
                         char principal[65],uint64_t *admission_epoch);
    /* CURRENT inbound must exist, be enabled/admitting, and still authorize
     * this principal/auth epoch. Reject retired/revoked epochs on old QUIC
     * connections. Success pins CURRENT policy generation in lease; no IO or
     * fallback here. The lease survives all flow IO/completion callbacks. */
    struct steer_pv1_error (*acquire_route)(void *,struct steer_pv1_span inbound,
        struct steer_pv1_span principal,uint64_t admission_epoch,struct steer_draft_route_lease *);
    void (*release_route)(void *,struct steer_draft_route_lease *);
};
#endif
