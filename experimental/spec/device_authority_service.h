/* Source-only coordinator journal writer and exact durable-intent cache. */
#ifndef STEER_SPEC_DEVICE_AUTHORITY_SERVICE_H
#define STEER_SPEC_DEVICE_AUTHORITY_SERVICE_H
#include "execution_reservations.h"
#include "../provider/device_authority.h"
#include "../provider/host_worker.h"
struct steer_spec_authority_service;
struct steer_spec_authority_scope;
struct steer_spec_authority_limits {uint32_t generations,claims,jobs;};
/* Owner. Transfers validated owned ledger on success; all subsequent ledger IO
 * is serialized through one shared host worker job at a time. Fixed worker pool
 * and its owner outlive service. Opaque results/cache bytes have their own bounds. */
struct steer_pv1_error steer_spec_authority_service_create(struct loop *,struct steer_draft_host_worker *,
 struct steer_spec_ledger **,const struct steer_spec_authority_limits *,struct steer_spec_authority_service **);
/* Immutable host generation/plan identity. Guard spans every callback and claim.
 * Scope is held until all borrowing device instances and their refs are gone. */
struct steer_pv1_error steer_spec_authority_scope_create(struct steer_spec_authority_service *,uint64_t,
 const unsigned char plan_digest[32],const struct steer_draft_host_work_guard *,struct steer_spec_authority_scope **);
const struct steer_draft_device_authority *steer_spec_authority_scope_api(struct steer_spec_authority_scope *);
void steer_spec_authority_scope_retire(struct steer_spec_authority_scope *); /* no new COMMIT claims */
struct steer_pv1_error steer_spec_authority_scope_release(struct steer_spec_authority_scope *);
/* Receipt is factual even on latecancel: caller owns no borrowed views beyond
 * return. INTENT_SYNCED only mints a claim if not cancelled/retired/fenced. Jobs
 * are released AFTER callback; result memory/guard remains budgeted meanwhile. */
typedef void (*steer_spec_authority_record_done)(void *,struct steer_spec_journal_result,
 const struct steer_spec_journal_record *,int cancelled);
struct steer_pv1_error steer_spec_authority_record(struct steer_spec_authority_scope *,
 const struct steer_spec_journal_record *,uint64_t deadline_ns,steer_spec_authority_record_done,void *,struct steer_draft_host_job **);
typedef void (*steer_spec_authority_recovered)(void *,struct steer_pv1_error,
 const struct steer_spec_ledger_summary *,int cancelled_or_expired);
/* Storage-only recovery; never rearms old claim. Lost resource result still
 * needs factual UNKNOWN outcome and a fresh guarded recovery intent. */
struct steer_pv1_error steer_spec_authority_recover_journal(struct steer_spec_authority_scope *,uint64_t,
 steer_spec_authority_recovered,void *,struct steer_draft_host_job **);
struct steer_spec_authority_status {uint32_t storage_fenced,host_fenced,blocked_intents,live_claims,journal_pending;};
void steer_spec_authority_status(const struct steer_spec_authority_service *,struct steer_spec_authority_status *);
/* Stops new effects/claims but permits factual OUTCOME/RECONCILE recording.
 * READY/BLOCKED unconsumed intents are NOT automatically discarded: coordinator
 * must record known UNCHANGED terminal facts when no work began, or preserve
 * unknown ownership for explicit recovery. Stop alone cannot promise drain. */
void steer_spec_authority_service_stop(struct steer_spec_authority_service *);
struct steer_pv1_error steer_spec_authority_service_on_drained(struct steer_spec_authority_service *,void (*)(void *),void *);
/* Exact-once deferred drain after scopes/claims/jobs disappear; never destroy
 * inside notification. Later owner turn detaches loop fd, then worker destroy
 * closes ledger and frees state. No owner fsync/IO or retry timers. */
struct steer_pv1_error steer_spec_authority_service_detach_owner(struct steer_spec_authority_service *);
struct steer_pv1_error steer_spec_authority_service_destroy_worker(struct steer_spec_authority_service *);
#endif
