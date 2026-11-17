#ifndef STEER_EXPERIMENTAL_VLESS_STREAM_BACKEND_H
#define STEER_EXPERIMENTAL_VLESS_STREAM_BACKEND_H
#include "route_stream.h"
struct steer_draft_vless_stream_backend;
/* Plain VLESS v0 TCP layered over a prepared same-owner stream binding.
 * UUID/upstream are copied, never logged. No sockets, DNS, TLS/flow/UDP/mux or
 * legacy blocking transport_open. Lower binding is host-selected and pinned;
 * original target metadata is encoded into the request, not used to dial here.
 * Open success means ordered request-header acceptance, not target-connect ACK.
 * All API calls/callbacks serialized on owner. Runtimes/buffers outlive destroy. */
struct steer_pv1_error steer_draft_vless_stream_backend_create(struct loop *,
    struct steer_pv1_host *buffers,const struct steer_draft_stream_binding *lower,
    const struct steer_pv1_endpoint *upstream,const uint8_t uuid[16],
    uint64_t generation,uint64_t instance_token,uint32_t max_streams,
    uint32_t max_operations,uint64_t max_queued_bytes,uint32_t max_references,
    void (*retired)(void *),void *,struct steer_draft_vless_stream_backend **);
const struct steer_draft_stream_binding *steer_draft_vless_stream_binding(
    const struct steer_draft_vless_stream_backend *);
struct steer_pv1_error steer_draft_vless_stream_backend_retire(struct steer_draft_vless_stream_backend *);
struct steer_pv1_error steer_draft_vless_stream_backend_destroy(struct steer_draft_vless_stream_backend *);
/* Public release consumes independently of private lower cleanup. Invalid lower
 * release is retained with its own pin/budget and never automatically retried. */
uint32_t steer_draft_vless_stream_quarantined(const struct steer_draft_vless_stream_backend *);
struct steer_pv1_error steer_draft_vless_stream_recover(struct steer_draft_vless_stream_backend *,uint32_t *recovered);
#endif
