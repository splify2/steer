#ifndef STEER_LINKED_INBOUND_PARTICIPANT_H
#define STEER_LINKED_INBOUND_PARTICIPANT_H
#include "kernel_wg_coordinator.h"
#include "kernel_wg_guard.h"
#include "prototype_store.h"

/* Internal serialized worker participant; no store, revision selection or
 * schema. The owner supplies an already validated inbound config, externally
 * recovered revision, backend and exact identity/peer attestation callback.
 * This is not registered with the linked host or an advertised capability. */
struct steer_linked_inbound {
    struct steer_draft_wg_selection *journal;
    const struct steer_draft_wg_backend *backend;
    void *context;
    struct steer_draft_kernel_wg_guard **backend_guard;
    struct steer_draft_wg_revision committed;
    struct steer_draft_wg_ready candidate;
    int staged, fenced, recovered;
};
int steer_linked_inbound_recover(struct steer_linked_inbound *,const struct steer_draft_wg_revision *,
    steer_draft_wg_verify_ready,uint64_t,uint64_t *,struct steer_draft_wg_guard_record *);
int steer_linked_inbound_prepare(struct steer_linked_inbound *,const struct steer_draft_wg_tx *,
    const struct steer_draft_wg_candidate *,const struct steer_draft_kernel_wg_guard_config *,
    const struct steer_policy *,uint16_t,uint64_t);
/* SYNCED requires later recovery of the external selection; RENAMED fences
 * without cleanup; NOT_RENAMED reconciles the previous external selection.
 * Never rewrites store. */
int steer_linked_inbound_finish(struct steer_linked_inbound *,struct steer_prototype_store_result,
    steer_draft_wg_verify_ready,uint64_t);
#endif
