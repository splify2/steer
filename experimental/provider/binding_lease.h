#ifndef STEER_EXPERIMENTAL_BINDING_LEASE_H
#define STEER_EXPERIMENTAL_BINDING_LEASE_H
#include <steer/draft/flow_v1.h>
struct loop;
struct steer_draft_binding_lease;
/* Immutable host-issued selected binding identity, never peer authority. */
struct steer_draft_binding_identity {
    uint32_t size,version;
    uint64_t generation,instance_token;
    struct steer_pv1_span provider_id;
    uint64_t prepared_capabilities;
    uint32_t flow_class;
};
typedef void (*steer_draft_binding_finalizer)(void *,const struct steer_draft_binding_identity *);
/* Finalizer signals lifecycle eligibility, not automatic DSO-unload safety.
 * A host-owned guard pin must span every foreign API call and be dropped by
 * host code only AFTER the foreign call returns. Dropping a pin inside foreign
 * release code alone cannot protect that code's remaining stack frame. */
/* Creation/retire/destroy run on the supplied loop's owner. Identity/provider ID
 * are copied. Initial owner reference is consumed only by retire. Context,
 * finalizer/module and loop outlive successful destruction. */
struct steer_pv1_error steer_draft_binding_lease_create(struct loop *,
    const struct steer_draft_binding_identity *,uint32_t max_references,
    steer_draft_binding_finalizer,void *,struct steer_draft_binding_lease **);
/* Bounded atomic reference operations can run on different workers. Caller
 * already owns a valid parent/published reference throughout acquisition.
 * admit rejects retired generations; pin permits derived operation/handle refs
 * while a retained parent remains, even after retirement. Both enforce identity.
 * Never call using an unowned stale pointer. */
struct steer_pv1_error steer_draft_binding_admit(struct steer_draft_binding_lease *,uint64_t generation,uint32_t flow_class);
struct steer_pv1_error steer_draft_binding_pin(struct steer_draft_binding_lease *,uint64_t generation,uint32_t flow_class);
struct steer_pv1_error steer_draft_binding_unpin(struct steer_draft_binding_lease *);
/* Idempotent. Stops new admissions, drops owner ref, never invokes finalizer
 * inline. Last pin schedules finalizer on the creation loop via eventfd. */
struct steer_pv1_error steer_draft_binding_retire(struct steer_draft_binding_lease *);
/* Refuses until retired, zero refs and finalizer has returned; no destroy from
 * its callback. Success consumes lease, with no future callbacks/writers. */
struct steer_pv1_error steer_draft_binding_lease_destroy(struct steer_draft_binding_lease *);
/* Borrowed immutable identity; caller must own a reference. */
const struct steer_draft_binding_identity *steer_draft_binding_identity(const struct steer_draft_binding_lease *);
uint32_t steer_draft_binding_references(const struct steer_draft_binding_lease *);
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
/* Install before publishing to workers; deterministic publication-window tests. */
void steer_draft_binding_test_hooks(struct steer_draft_binding_lease *,
    void (*before_ready)(void *),void (*retire_seen)(void *),void *);
#endif
#endif
