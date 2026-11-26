#ifndef STEER_LINKED_INBOUND_PARTICIPANT_H
#define STEER_LINKED_INBOUND_PARTICIPANT_H
#include "kernel_wg_coordinator.h"
#include "kernel_wg_guard.h"
#include "prototype_store.h"

/* Serialized callbacks must use the pinned namespace and freshly verify
 * ownership/state. UNKNOWN is not proof that the dataplane is closed. */
typedef int (*steer_inbound_barrier_fn)(void *,const struct steer_draft_wg_guard_record *,uint64_t,uint32_t *);
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
    struct steer_draft_wg_revision pending;
    struct steer_draft_wg_ready candidate;
    struct steer_draft_wg_tx closed_tx;
    struct steer_draft_kernel_wg_guard *closed_guard;
    steer_inbound_barrier_fn barrier_close,barrier_open;
    uint32_t barrier_state,publication_state;
    int staged, fenced, recovered, closed_stage, durable_unknown, removal_stage;
};
int steer_linked_inbound_recover(struct steer_linked_inbound *,const struct steer_draft_wg_revision *,
    steer_draft_wg_verify_ready,uint64_t,uint64_t *,struct steer_draft_wg_guard_record *);
int steer_linked_inbound_prepare(struct steer_linked_inbound *,const struct steer_draft_wg_tx *,
    const struct steer_draft_wg_candidate *,const struct steer_draft_kernel_wg_guard_config *,
    const struct steer_policy *,uint16_t,uint64_t);
/* The serialized store owner supplies its exact committed document selection
 * and the receipt from that same transaction. No IO or recovery; mismatch and
 * any non-SYNCED receipt fence until startup recovery. */
int steer_linked_inbound_live_commit(struct steer_linked_inbound *,
    struct steer_prototype_store_result,const struct steer_draft_wg_revision *);
/* First inbound device only; guard remains DROP until a matching SYNCED store
 * result. No cleanup is authorized on uncertain rename or post-sync failure. */
int steer_linked_inbound_prepare_closed(struct steer_linked_inbound *,const struct steer_draft_wg_tx *,
    const struct steer_draft_wg_candidate *,const struct steer_draft_kernel_wg_guard_config *,
    const struct steer_policy *,uint64_t);
int steer_linked_inbound_finish_closed(struct steer_linked_inbound *,struct steer_prototype_store_result,
    const struct steer_draft_wg_revision *,steer_draft_wg_verify_ready,uint64_t);
/* Owner-selected shutdown: never publish or open. Matching SYNCED records the
 * durable selection and returns ECANCELED after successful confirmed closure.
 * On error inspect barrier_state; UNKNOWN is not confirmed closed. Other receipts have
 * the same rollback/uncertainty rules as finish_closed. Not Apply success. */
int steer_linked_inbound_finish_closed_shutdown(struct steer_linked_inbound *,struct steer_prototype_store_result,
    const struct steer_draft_wg_revision *,steer_draft_wg_verify_ready,uint64_t);
/* Close the selected owned device before the owner queues the exact no-WG
 * document. Never reopen on failure; the owner must expose the fence. After
 * SYNCED, record the new selection before rechecking closure and retiring the
 * exact journaled resource. Cleanup ambiguity sets barrier UNKNOWN. */
int steer_linked_inbound_prepare_removal(struct steer_linked_inbound *,
    const struct steer_draft_wg_revision *,uint64_t);
int steer_linked_inbound_finish_removal(struct steer_linked_inbound *,
    struct steer_prototype_store_result,const struct steer_draft_wg_revision *,uint64_t,int);
/* SYNCED requires later recovery of the external selection; RENAMED fences
 * without cleanup; NOT_RENAMED reconciles the previous external selection.
 * Never rewrites store. */
int steer_linked_inbound_finish(struct steer_linked_inbound *,struct steer_prototype_store_result,
    steer_draft_wg_verify_ready,uint64_t);
#endif
