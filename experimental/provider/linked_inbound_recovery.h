#ifndef STEER_LINKED_INBOUND_RECOVERY_H
#define STEER_LINKED_INBOUND_RECOVERY_H
#include "linked_inbound_participant.h"
#include "kernel_wg_linux_guard.h"
struct awg_conf;
struct awg_secrets;
/* The owner constructs this from the exact validated committed document.
 * Only the explicitly role-tagged inbound selection journal is accepted.
 * The original UP verifier does not attest private keys and the full device;
 * only the separate DOWN verifier checks the narrow complete configuration.
 * Neither is permission to advertise production readiness. */
struct steer_linked_inbound_recovery {
    struct steer_draft_wg_linux_guard guard; /* must be first: backend context */
    struct steer_draft_wg_revision revision;
    const struct steer_draft_kernel_wg_guard_config *inbound;
    const struct steer_policy *policy;
    const struct awg_conf *wireguard;
    const struct awg_secrets *keys;
    int require_down;
};
int steer_linked_inbound_recover_checked(struct steer_linked_inbound *,
    struct steer_linked_inbound_recovery *,uint64_t,uint64_t *,struct steer_draft_wg_guard_record *);
int steer_linked_inbound_recover_down_checked(struct steer_linked_inbound *,
    struct steer_linked_inbound_recovery *,uint64_t,uint64_t *,struct steer_draft_wg_guard_record *);
int steer_linked_inbound_verify_down(struct steer_linked_inbound_recovery *,
    const struct steer_draft_wg_guard_record *,uint64_t);
int steer_linked_inbound_verify_up(struct steer_linked_inbound_recovery *,
    const struct steer_draft_wg_guard_record *,uint64_t);
#endif
