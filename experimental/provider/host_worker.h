/* Source-only bounded off-loop work shared by preparation and device effects. */
#ifndef STEER_EXPERIMENTAL_HOST_WORKER_H
#define STEER_EXPERIMENTAL_HOST_WORKER_H
#include <steer/draft/provider_v1.h>
#include "cancel.h"
struct loop;
struct steer_draft_host_worker;
struct steer_draft_host_job;
#define STEER_DRAFT_HOST_QUARANTINE_THREAD 1u
#define STEER_DRAFT_HOST_NO_HEALTHY_WORKERS 2u
struct steer_draft_host_work_result {struct steer_pv1_error error;void *value;uint32_t worker_flags;};
struct steer_draft_host_work_guard {
 void *context;struct steer_pv1_error (*retain)(void *);void (*release)(void *);
};
/* run is foreign code protected by guard. Input is a private copied snapshot,
 * wiped after run returns. Cancellation is cooperative, with no forced thread
 * termination. A queued cancel/expiry skips run. Once run starts, its result is
 * factual and is NEVER overwritten by a late cancellation/deadline/shutdown.
 * In particular effectful CHANGED/UNCERTAIN results must reach the coordinator. */
typedef struct steer_draft_host_work_result (*steer_draft_host_work_run)(void *,
 const void *,size_t,uint64_t,const struct steer_draft_cancel *);
/* Always deferred to owner, including queued cancellation. Ownership of value
 * transfers unconditionally to done; service never discards/reinterprets it.
 * Callback/context and guard remain live through callback return and job release.
 * No recursive dispatch/destroy. Callback may submit/cancel other jobs. */
typedef void (*steer_draft_host_work_done)(void *,struct steer_draft_host_work_result);
struct steer_draft_host_worker_limits {uint32_t threads,max_jobs,max_input;uint64_t max_bytes;};
/* Fixed 1..4 workers; max_jobs1..1024 includes completed unreleased jobs;
 * max_input<=64KiB, total copied input bytes bounded independently. Opaque
 * result.value allocations require a separate provider/coordinator budget. Default small
 * platform profile should select one worker; independent jobs may use two+. */
struct steer_pv1_error steer_draft_host_worker_create(struct loop *,
 const struct steer_draft_host_worker_limits *,struct steer_draft_host_worker **);
/* Owner-only APIs; rejection consumes nothing. Success copies input and retains
 * guard before workers can call run. An outer host guard spans this API return. */
struct steer_pv1_error steer_draft_host_worker_submit(struct steer_draft_host_worker *,
 const void *,size_t,uint64_t,steer_draft_host_work_run,void *,
 const struct steer_draft_host_work_guard *,steer_draft_host_work_done,void *,
 struct steer_draft_host_job **);
/* Optional host-owned Linux network namespace scope. Duplicates namespace_fd;
 * worker saves baseline, enters target before run and restores before completion.
 * Restore failure preserves factual result, adds QUARANTINE_THREAD and exits
 * that thread. No respawn; queued jobs use healthy workers or return
 * RESOURCE_EXHAUSTED+NO_HEALTHY_WORKERS. Provider may not change namespaces
 * outside this scope. Duplicated fd remains owned through job release. */
struct steer_pv1_error steer_draft_host_worker_submit_ns(struct steer_draft_host_worker *,
 int namespace_fd,const void *,size_t,uint64_t,steer_draft_host_work_run,void *,
 const struct steer_draft_host_work_guard *,steer_draft_host_work_done,void *,
 struct steer_draft_host_job **);
int steer_draft_host_job_cancelled(const struct steer_draft_host_job *);
void steer_draft_host_job_cancel(struct steer_draft_host_job *);
/* Only after callback RETURN; early release refuses and consumes nothing. */
struct steer_pv1_error steer_draft_host_job_release(struct steer_draft_host_job *);
/* Register once before stop. Deferred exact-once after worker exit and every
 * job release; callback lifetime through return, no destroy inside callback.
 * Empty stop and final held-completed release both wake the existing eventfd. */
struct steer_pv1_error steer_draft_host_worker_on_drained(struct steer_draft_host_worker *,void (*)(void *),void *);
void steer_draft_host_worker_stop(struct steer_draft_host_worker *);
/* BUSY/POLICY until stopped, workers exited, callbacks and all jobs released.
 * Slow filesystem/kernel work cannot be force-stopped; no shutdown-time bound
 * is claimed. Once exit is observed, join completes before fd/object release. */
struct steer_pv1_error steer_draft_host_worker_destroy(struct steer_draft_host_worker *);
/* Immutable owner identity, valid while caller holds worker lifetime. */
struct loop *steer_draft_host_worker_owner(const struct steer_draft_host_worker *);
void steer_draft_host_worker_limits(const struct steer_draft_host_worker *,struct steer_draft_host_worker_limits *);
void steer_draft_host_worker_usage(struct steer_draft_host_worker *,uint32_t *,uint64_t *);
#endif
