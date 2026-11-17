/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_DRAFT_HY2_INBOUND_H
#define STEER_DRAFT_HY2_INBOUND_H
#include "inbound_services.h"
#include "quic.h"
#include "hysteria2/server.h"
struct steer_draft_hy2;
struct steer_draft_hy2_config {
    const char *inbound_id;
    struct qc_endpoint_cfg endpoint;
    struct hy2_server_config protocol;
    unsigned max_flows; /* default256, ceiling1024 across all connections */
    int start_paused; /* prepare/bind without admitting QUIC connections */
};
/* Core owns UDP/TLS/loop/route/DNS/IO. Same host stream and buffer runtime is
 * injected; no independent routing or socket dial implementation. */
int steer_draft_hy2_open(const struct steer_draft_hy2_config *,
                        const struct steer_draft_inbound_services *,struct steer_draft_hy2 **);
uint16_t steer_draft_hy2_port(const struct steer_draft_hy2 *);
void steer_draft_hy2_activate(struct steer_draft_hy2 *); /* infallible, owning loop; not after retire */
/* Irreversible: reject new connections/auth/streams, drain admitted flows until
 * absolute CLOCK_MONOTONIC deadline_ms, then cancel and drain completions. Host
 * owns deadline policy and must keep object until destroy succeeds. */
void steer_draft_hy2_retire(struct steer_draft_hy2 *,uint64_t deadline_ms);
void steer_draft_hy2_stop(struct steer_draft_hy2 *); /* cancel, then drain owning loop */
int steer_draft_hy2_destroy(struct steer_draft_hy2 *); /* BUSY until callbacks drained */
size_t steer_draft_hy2_connections(const struct steer_draft_hy2 *);
size_t steer_draft_hy2_flows(const struct steer_draft_hy2 *);
struct steer_draft_hy2_usage {
    size_t routes_pending,reads_pending,writes_pending,cancelled_flows;
    uint64_t route_callbacks_after_cancel,io_callbacks_after_cancel,success_after_cancel;
    size_t queued_upload_bytes;
};
void steer_draft_hy2_usage(const struct steer_draft_hy2 *,struct steer_draft_hy2_usage *);
#endif
