#ifndef STEER_PROTOTYPE_STORE_H
#define STEER_PROTOTYPE_STORE_H
#include "prototype_config.h"
struct steer_prototype_store;
struct steer_prototype_store_transaction;
#define STEER_PROTOTYPE_STORE_NOT_RENAMED 0u
#define STEER_PROTOTYPE_STORE_RENAMED 1u
#define STEER_PROTOTYPE_STORE_SYNCED 2u
struct steer_prototype_store_result {
    struct steer_pv1_error error;
    uint32_t phase;
};
#define STEER_STORE_FORMAT_PROTOTYPE 1u
#define STEER_STORE_FORMAT_SPEC_V3 3u
#define STEER_STORE_DOCUMENT_MAX (1024u*1024u)
struct steer_store_document {uint64_t generation;uint32_t format;char *document;size_t length;};
/* Typed framing only, NOT a replacement schema validator. Caller must compile/
 * validate the exact matching schema+factory options and canonical refs-only
 * JSON before prepare, and again before activating a loaded snapshot. Prototype
 * envelope stays byte-compatible; v3 has an explicit format tag. Unknown tags
 * fail closed. Old prototype load rejects v3 as INVALID, never missing/fallback. */
struct steer_pv1_error steer_prototype_store_prepare_document(struct steer_prototype_store *,
 const struct steer_store_document *,struct steer_prototype_store_transaction **);
struct steer_pv1_error steer_prototype_store_load_document(struct steer_prototype_store *,struct steer_store_document **);
/* Startup/recovery worker. With no live transaction, read and check the visible
 * envelope then sync the directory before returning it. Missing stays
 * UNSUPPORTED only after sync; failures return no snapshot. No fallback, temp
 * adoption, rewrite or schema validation. A prior commit receipt is immutable. */
struct steer_pv1_error steer_prototype_store_recover_document(struct steer_prototype_store *,struct steer_store_document **);
void steer_store_document_destroy(struct steer_store_document *);
/* Linux, one serialized owner, no reentry or concurrent calls. Ownership may
 * transfer to another thread only through external synchronization establishing
 * happens-before (e.g. start worker after bootstrap; join before closing).
 * The module provides no locks for concurrent API calls. Existing directory must be
 * owned by effective UID with no group/other permissions; symlink final dir
 * rejected. Holds an exclusive nonblocking writer lock through close. No source
 * config, user directory mode, network or service defaults are changed. */
struct steer_pv1_error steer_prototype_store_open(const char *,struct steer_prototype_store **);
/* Refuses a live transaction. OK consumes store. */
struct steer_pv1_error steer_prototype_store_close(struct steer_prototype_store *);
/* Requires parser-owned config with canonical refs-only document and nonzero
 * generation. Copies snapshot to exclusive same-directory 0600 temp and fsyncs
 * it. Failure leaves config.json unchanged and clears out. One live transaction.
 * IO is blocking: host must budget disk work outside packet processing. */
struct steer_pv1_error steer_prototype_store_prepare(struct steer_prototype_store *,
    const struct steer_prototype_config *,struct steer_prototype_store_transaction **);
/* Does not consume transaction; release with abort afterwards on every result.
 * NOT_RENAMED error: old config untouched, rollback remains possible.
 * RENAMED error: new file visible, directory fsync failed; durability uncertain,
 * cannot claim old disk state or roll back by deleting config.json.
 * SYNCED OK: file+directory persisted. Repeated commit returns previous result.
 * Host must fully prepare fallible runtime work BEFORE commit; after rename its
 * prepared no-fail runtime publication must reflect the visible new revision. */
struct steer_prototype_store_result steer_prototype_store_commit(struct steer_prototype_store_transaction *);
/* Always consumes transaction, clears store busy state. Unlinks only a temp
 * before rename; after rename it never deletes/rewrites committed config.
 * Unlink failure returns IO (orphan temp may remain), no secret values in doc. */
struct steer_pv1_error steer_prototype_store_abort(struct steer_prototype_store_transaction *);
/* Atomically opens one committed file snapshot and parses canonical document
 * with stored generation. Missing file => UNSUPPORTED; corrupt/unsafe file =>
 * INVALID; IO/limits => IO/RESOURCE_EXHAUSTED. No fallback to source config here.
 * On error out=NULL; ownership matches prototype_config_destroy. */
struct steer_pv1_error steer_prototype_store_load(struct steer_prototype_store *,
    struct steer_prototype_config **);
#endif
