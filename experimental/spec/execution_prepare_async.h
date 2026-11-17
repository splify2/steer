#ifndef STEER_SPEC_EXECUTION_PREPARE_ASYNC_H
#define STEER_SPEC_EXECUTION_PREPARE_ASYNC_H
#include "execution.h"
#include "../provider/host_worker.h"
/* Host registry/inventory views are immutable, held by guard through job release.
 * Execution takes independent factory guards when worker preparation succeeds.
 * Input is copied/wiped by the shared host service; no owner pointers to control
 * clients/listeners or bare TLS arenas may occur in these borrowed snapshots. */
struct steer_spec_execution_prepare_input {
 uint64_t generation,first_instance_token;
 const struct steer_spec_capability *inventory;uint32_t inventory_count;
 const struct steer_spec_execution_factory *factories;uint32_t factory_count;
 struct steer_spec_execution_limits limits;
};
/* Deferred owner callback always owns returned execution (if nonNULL), even if
 * cancel/deadline was requested after worker success. In that case callback
 * error is CANCELLED/TIMEOUT and the returned object is retired BEFORE handoff:
 * bind/publication are refused; worker destruction still consumes the object.
 * No callback from a rejected submission; release job only after done returns. */
typedef void (*steer_spec_execution_prepare_done)(void *,struct steer_pv1_error,
 struct steer_spec_execution *);
struct steer_pv1_error steer_spec_execution_submit(struct steer_draft_host_worker *,
 const void *,size_t,const struct steer_spec_execution_prepare_input *,uint64_t,
 const struct steer_draft_host_work_guard *,steer_spec_execution_prepare_done,void *,
 struct steer_draft_host_job **);
#endif
