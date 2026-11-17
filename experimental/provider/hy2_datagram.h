/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_DRAFT_HY2_DATAGRAM_H
#define STEER_DRAFT_HY2_DATAGRAM_H
#include "buffers.h"
#include <steer/draft/datagram_route_v1.h>
#define STEER_DRAFT_HY2_UDP_RECEIVES 8u
#define STEER_DRAFT_HY2_UDP_PACKETS 64u
#define STEER_DRAFT_HY2_UDP_UPLOAD_BYTES 262144u
#define STEER_DRAFT_HY2_UDP_MESSAGE_BYTES 65507u
struct steer_draft_hy2_datagram;
/* Host-selected CURRENT generation binding. One retained lease is transferred
 * on success; release after all association refs/operations have drained. */
struct steer_draft_hy2_datagram_binding {
    const struct steer_pv1_datagram_route_api *api;
    void *context,*lease;
    uint64_t generation;
};
/* Same-owning-loop shared service envelope; host owns through every adapter.
 * Receive capacity and upload memory are separate reserves. upload_bytes counts
 * partial assembly metadata/fragments, completed output overlap and queued or
 * transferred upload buffers. Packet limit includes in-flight sends. */
struct steer_draft_hy2_datagram_budget {
    unsigned max_receives,max_packets,receives,packets;
    uint64_t max_upload_bytes,upload_bytes;
};
void steer_draft_hy2_datagram_budget_init(struct steer_draft_hy2_datagram_budget *);
struct steer_draft_hy2_datagram_services {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    struct steer_draft_hy2_datagram_budget *budget;
    void *context;
    struct steer_pv1_error (*acquire)(void *,struct steer_pv1_span inbound,
        struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_hy2_datagram_binding *);
    void (*release)(void *,struct steer_draft_hy2_datagram_binding *);
};
struct steer_draft_hy2_datagram_config {
    struct steer_pv1_span inbound,principal;
    struct steer_pv1_endpoint source; /* real QUIC peer, never message payload */
    uint64_t admission_epoch;
    unsigned max_sessions,max_targets,max_contexts,max_packets;
    uint64_t max_queued_bytes,idle_ms,operation_ms;
    void *transport;
    size_t (*message_limit)(void *);
    int (*send)(void *,const uint8_t *,size_t); /* 0 queued, otherwise drop */
    void (*wake)(void *); /* schedule owning-loop poll; no inline poll */
};
int steer_draft_hy2_datagram_create(const struct steer_draft_hy2_datagram_config *,
    const struct steer_draft_hy2_datagram_services *,struct steer_draft_hy2_datagram **);
void steer_draft_hy2_datagram_input(struct steer_draft_hy2_datagram *,const uint8_t *,size_t);
void steer_draft_hy2_datagram_poll(struct steer_draft_hy2_datagram *);
/* Retire denies new session/destination admission, existing targets continue.
 * Stop cancels everything. Destroy is BUSY through deferred callbacks/leases. */
void steer_draft_hy2_datagram_retire(struct steer_draft_hy2_datagram *);
void steer_draft_hy2_datagram_stop(struct steer_draft_hy2_datagram *);
int steer_draft_hy2_datagram_destroy(struct steer_draft_hy2_datagram *);
struct steer_draft_hy2_datagram_usage {
    unsigned sessions,targets,contexts,operations,packets,quarantined,max_fragment_burst;
    uint64_t queued_bytes,dropped_packets,completed_after_cancel;
};
void steer_draft_hy2_datagram_usage(const struct steer_draft_hy2_datagram *,
    struct steer_draft_hy2_datagram_usage *);
#endif
