/* Linux source-only journal primitives; blocking IO belongs on host_worker. */
#ifndef STEER_SPEC_EXECUTION_JOURNAL_H
#define STEER_SPEC_EXECUTION_JOURNAL_H
#include <steer/draft/provider_v1.h>
#define STEER_SPEC_JOURNAL_DATA_MAX 4096u
#define STEER_SPEC_JOURNAL_INTENT 1u
#define STEER_SPEC_JOURNAL_OUTCOME 2u
#define STEER_SPEC_JOURNAL_RECONCILE 3u
#define STEER_SPEC_JOURNAL_ANCHOR 4u
#define STEER_SPEC_JOURNAL_GRANT 5u
#define STEER_SPEC_JOURNAL_NOT_RENAMED 0u
#define STEER_SPEC_JOURNAL_RENAMED 1u
#define STEER_SPEC_JOURNAL_SYNCED 2u
struct steer_spec_journal;
/* Exact discriminator permits several instances/stages in one transaction.
 * Each immutable record has a fresh monotonically chosen nonzero sequence;
 * outcome/reconcile records reference the original intent sequence. An uncertain
 * fact is never overwritten by a later reconciliation. Initial bounded-store
 * implementation rejects full journals; safe resolved-transaction checkpoint
 * and compaction are required before unbounded service lifetime is claimed. */
struct steer_spec_journal_key {
 uint64_t transaction,instance;uint32_t sequence,kind;
};
struct steer_spec_journal_record {
 struct steer_spec_journal_key key;
 uint64_t generation;uint32_t intent_sequence,operation,effect,phase;
 /* Host reservation metadata, separate from provider recovery payload. Exact
  * anchor key uses anchor_transaction + key.instance + anchor_sequence. */
 uint64_t anchor_transaction,grant_id;
 uint32_t anchor_sequence,credits,cleanup_floor;
 unsigned char plan_digest[32];
 char provider[128],provider_version[64];
 uint32_t length;unsigned char data[STEER_SPEC_JOURNAL_DATA_MAX];
};
struct steer_spec_journal_result {struct steer_pv1_error error;uint32_t durability;};
/* Explicit existing private owned0700 directory only; no mkdir/source-file or
 * network changes. Exclusive writer lock; serialized external ownership may
 * transfer across host workers with happens-before, never concurrent calls.
 * max_records1..4096 bounds all files; max_transaction_records1..128. */
int steer_spec_journal_record_valid(const struct steer_spec_journal_record *);
struct steer_pv1_error steer_spec_journal_open(const char *,uint32_t max_records,
 uint32_t max_transaction_records,struct steer_spec_journal **);
/* Explicit worker-only synchronization of existing directory visibility; does
 * not infer any kernel/device state or synthesize outcome facts. */
struct steer_pv1_error steer_spec_journal_sync_existing(struct steer_spec_journal *);
struct steer_pv1_error steer_spec_journal_close(struct steer_spec_journal *);
/* Same-dir exclusive0600 temp+file fsync+renameat2 NOREPLACE+dir fsync. Duplicate
 * key never replaces a record. Unsupported renameat2 fails explicitly. Error
 * before rename leaves old state; RENAMED error means visible record with
 * uncertain directory durability. ONLY intent SYNCED authorizes provider work.
 * Identity is minted before intent; missing outcome on restart is UNCERTAIN,
 * never proof QUIESCENT. Config durable commit is an independent later stage.
 * Payload is versioned nonsecret recovery identity; never log it by default. */
struct steer_spec_journal_result steer_spec_journal_append(struct steer_spec_journal *,
 const struct steer_spec_journal_record *);
/* Exact owned snapshot; validates type/size/CRC/key/record bounds, no adoption
 * of external state. Missing is UNSUPPORTED. Caller owns copied record. */
struct steer_pv1_error steer_spec_journal_read(struct steer_spec_journal *,
 const struct steer_spec_journal_key *,struct steer_spec_journal_record *);
/* Worker-only bounded restart scan of ALL validated records. Unknown, unsafe,
 * truncated or malformed record entries fail closed. Recognized .tmp-hex orphan
 * files are bounded/private-inspected and reported, never authorization; they
 * remain owned for explicit later maintenance and count toward the file limit.
 * Visitor is READ-ONLY accumulation: no effects/publication are authorized
 * until the ENTIRE scan succeeds; a late malformed entry invalidates its prefix.
 * Visitor sees a borrowed record
 * for this call only, must copy needed bytes, and cannot reenter journal APIs.
 * Limits include all transaction records; no silently skipped foreign files. */
struct steer_spec_journal_scan_report {uint32_t records,orphan_temporaries;};
struct steer_pv1_error steer_spec_journal_scan(struct steer_spec_journal *,
 struct steer_pv1_error (*visitor)(void *,const struct steer_spec_journal_record *),void *,
 struct steer_spec_journal_scan_report *);
#endif
