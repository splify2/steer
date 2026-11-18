/* Source-only worker preflight for spec v3 startup. */
#ifndef STEER_SPEC_EXECUTION_STARTUP_H
#define STEER_SPEC_EXECUTION_STARTUP_H
#include "execution_reservations.h"
#include "../provider/prototype_store.h"

struct steer_spec_startup_revision {
 struct steer_store_document *document; /* owned on success; NULL if absent */
 unsigned char plan_digest[32];
};
/* Compile/validate the exact stored v3 document and derive the plan identity
 * with the same host catalogue/lock policy as apply. No effects or reentry. */
typedef struct steer_pv1_error (*steer_spec_startup_verify)(void *,const struct steer_store_document *,unsigned char digest[32]);
/* With both stores exclusively owned and no live execution, sync and inspect
 * the config and journal together. Failure returns no config or usable rows;
 * insufficient capacity reports the required count. On success release the
 * document with steer_store_document_destroy. This neither admits operations
 * nor decides that any kernel resource is safe to resume or remove. */
struct steer_pv1_error steer_spec_startup_inspect(struct steer_prototype_store *,struct steer_spec_ledger *,
 steer_spec_startup_verify,void *,struct steer_spec_startup_revision *,
 struct steer_spec_ledger_recovery_item *,uint32_t capacity,uint32_t *count);

enum steer_spec_startup_relation {
 STEER_SPEC_STARTUP_NO_REVISION, STEER_SPEC_STARTUP_OTHER_GENERATION,
 STEER_SPEC_STARTUP_DIGEST_MISMATCH, STEER_SPEC_STARTUP_MATCH
};
/* Compare a durable journal record with a successfully inspected revision.
 * Compare anchor and current intent separately: a later retire operation can
 * belong to a different generation than the resource it is cleaning up. */
enum steer_spec_startup_relation steer_spec_startup_compare(const struct steer_spec_startup_revision *,
 const struct steer_spec_journal_record *);
#endif
