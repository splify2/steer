#ifndef STEER_SPEC_EXECUTION_RESERVATIONS_H
#define STEER_SPEC_EXECUTION_RESERVATIONS_H
#include "execution_journal.h"
struct steer_spec_ledger;
struct steer_spec_ledger_summary {
 uint32_t records,orphan_temporaries,anchors,retired,pending_intents,recovery_required;
 uint64_t reserved_records;
};
/* Worker-owned ledger: validates complete ownership graph on scan/append.
 * ANCHOR grants initial credits and immutable cleanup_floor; GRANT has a fresh
 * anchor-unique grant_id. Both consume physical records. ACTIVE/unknown retains
 * cleanup credits. One pending operation reserves its outcome; commit preserves
 * floor, cleanup requires intent+outcome credit BEFORE mutation. No compaction
 * or unlimited retries. Exhaustion blocks effects and retains guarded state. */
struct steer_pv1_error steer_spec_ledger_open(const char *,uint32_t,uint32_t,struct steer_spec_ledger **);
/* Explicit worker recovery: full model validation, directory fsync, full
 * validation again; clears STORAGE uncertainty only. Old unknown operations
 * remain unknown and cannot regain commit permission. No kernel IO/effects. */
struct steer_pv1_error steer_spec_ledger_recover_journal(struct steer_spec_ledger *,struct steer_spec_ledger_summary *);
struct steer_pv1_error steer_spec_ledger_close(struct steer_spec_ledger *);
struct steer_spec_journal_result steer_spec_ledger_append(struct steer_spec_ledger *,const struct steer_spec_journal_record *);
/* Read-only accumulation; no prefix authorizes effects before full success. */
struct steer_pv1_error steer_spec_ledger_scan(struct steer_spec_ledger *,struct steer_pv1_error (*)(void *,const struct steer_spec_journal_record *),void *,struct steer_spec_ledger_summary *);
#endif
