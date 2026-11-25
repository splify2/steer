#ifndef STEER_DRAFT_WG_GUARD_RECORD_H
#define STEER_DRAFT_WG_GUARD_RECORD_H

#include "kernel_wg_ownership.h"

#define STEER_DRAFT_WG_GUARD_RECORD_BYTES 216u

/* Nonsecret payload for execution_journal (which checksums the whole record).
 * The link generation identifies link creation, not a later policy revision.
 * The inet table's name and marker are known before creation. Zero handle
 * means no exact kernel handle was captured, not that the table is absent. */
struct steer_draft_wg_guard_record {
    struct steer_draft_wg_identity link;
    uint64_t handle;
    uint32_t ifindex;
    char table[26], marker[42];
};

int steer_draft_wg_guard_record_encode(const struct steer_draft_wg_guard_record *,
    uint8_t out[STEER_DRAFT_WG_GUARD_RECORD_BYTES]);
int steer_draft_wg_guard_record_decode(const uint8_t *,size_t,
    struct steer_draft_wg_guard_record *);

/* Restore a synced intent and optional captured outcome. The caller must first
 * validate and pair journal envelopes (transaction, instance, intent sequence,
 * operation and policy generation). A substituted payload is still refused.
 * For initial creation: intent has no handle, outcome has the captured handle.
 * For replacement: intent holds the old handle, outcome the new one; without
 * an outcome the old handle is not proof of what survived the replacement. */
int steer_draft_wg_guard_record_restore(const uint8_t *intent,size_t intent_len,
    const uint8_t *outcome,size_t outcome_len,struct steer_draft_wg_guard_record *);

/* Compare a successful fresh lookup of the recorded name in family inet.
 * Failed lookups must not be passed as absence: use NULL marker for UNKNOWN,
 * empty marker + zero handle for ABSENT. A matching marker without an exact
 * handle is UNKNOWN, never OWNED. This is evidence only, not authority to
 * mutate: the caller still needs boot/ns, exact-index and lifecycle checks. */
uint32_t steer_draft_wg_guard_record_observe(const struct steer_draft_wg_guard_record *,
    uint64_t handle,const char *marker);

#endif
