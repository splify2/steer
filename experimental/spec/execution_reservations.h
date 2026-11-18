#ifndef STEER_SPEC_EXECUTION_RESERVATIONS_H
#define STEER_SPEC_EXECUTION_RESERVATIONS_H
#include "execution_journal.h"
struct steer_spec_ledger;
struct steer_spec_ledger_summary {
 uint32_t records,orphan_temporaries,anchors,retired,pending_intents,recovery_required;
 uint64_t reserved_records;
};
#define STEER_SPEC_LEDGER_RECOVERY_CHECKS_MAX 128u
struct steer_spec_ledger_recovery_check {
 struct steer_spec_journal_key intent; /* zero kind skips an unused slot */
 int has_fact; /* exact intent has an OUTCOME or RECONCILE record */
};
/* Worker-owned ledger: validates complete ownership graph on scan/append.
 * ANCHOR grants initial credits and immutable cleanup_floor; GRANT has a fresh
 * anchor-unique grant_id. Both consume physical records. ACTIVE/unknown retains
 * cleanup credits. One pending operation reserves its outcome; commit preserves
 * floor, cleanup requires intent+outcome credit BEFORE mutation. Remaining
 * credits must fit in the anchor's unused sequence space. No compaction
 * or unlimited retries. Exhaustion blocks effects and retains guarded state. */
struct steer_pv1_error steer_spec_ledger_open(const char *,uint32_t,uint32_t,struct steer_spec_ledger **);
/* Explicit worker recovery: full model validation, directory fsync, full
 * validation again; clears STORAGE uncertainty only. Optional bounded checks
 * report only existing durable facts after complete validation. A fact can
 * itself report unknown device state. No kernel IO/effects. */
struct steer_pv1_error steer_spec_ledger_recover_journal(struct steer_spec_ledger *,struct steer_spec_ledger_summary *,
 struct steer_spec_ledger_recovery_check *,uint32_t check_count);
struct steer_spec_ledger_recovery_item {
 struct steer_spec_journal_key anchor,intent,fact;
 uint32_t last_sequence,remaining,cleanup_floor;
 int requires_recovery; /* ledger uncertainty, pending outcome or low reserve */
};
/* Startup worker snapshot after full validation, sync and revalidation. Reports
 * every non-retired anchor, including unused and known ACTIVE ones. Zero intent
 * kind means none; zero fact kind with an intent means the result is missing.
 * The fact is for the current intent only. last_sequence includes grants.
 * If capacity is too small, returns RESOURCE_EXHAUSTED with the required count
 * and leaves items untouched. Other failures report count zero. No item proves
 * current kernel state, config durability or authority to replay an operation. */
struct steer_pv1_error steer_spec_ledger_recover_inventory(struct steer_spec_ledger *,
 struct steer_spec_ledger_recovery_item *,uint32_t capacity,uint32_t *count);
/* Worker-only exact record lookup while retaining serialized ledger ownership.
 * Used to load the opaque recovery payload and plan identity for inventory keys.
 * A record is storage evidence, never a permit or fresh kernel observation. */
struct steer_pv1_error steer_spec_ledger_read(struct steer_spec_ledger *,
 const struct steer_spec_journal_key *,struct steer_spec_journal_record *);
/* Startup worker only, after excluding live operations: settle a missing
 * result from the inventory as EFFECT_UNCERTAIN/UNCERTAIN, retaining the exact
 * intent's identity and payload. Uses the reserved outcome slot. A stale item
 * cannot replace a fact. Caller checks durability before planning fresh recovery. */
struct steer_spec_journal_result steer_spec_ledger_record_missing_outcome(struct steer_spec_ledger *,
 const struct steer_spec_ledger_recovery_item *);
struct steer_pv1_error steer_spec_ledger_close(struct steer_spec_ledger *);
struct steer_spec_journal_result steer_spec_ledger_append(struct steer_spec_ledger *,const struct steer_spec_journal_record *);
/* Read-only accumulation; no prefix authorizes effects before full success. */
struct steer_pv1_error steer_spec_ledger_scan(struct steer_spec_ledger *,struct steer_pv1_error (*)(void *,const struct steer_spec_journal_record *),void *,struct steer_spec_ledger_summary *);
#endif
