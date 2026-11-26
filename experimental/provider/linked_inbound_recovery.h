#ifndef STEER_LINKED_INBOUND_RECOVERY_H
#define STEER_LINKED_INBOUND_RECOVERY_H
#include "linked_inbound_participant.h"
#include "kernel_wg_linux_guard.h"
/* The owner constructs this from the exact validated committed document.
 * Only the explicitly role-tagged inbound selection journal is accepted.
 * No peer-key/live WG configuration attestation is provided here: success
 * is not permission to advertise production readiness or forward traffic. */
struct steer_linked_inbound_recovery {
    struct steer_draft_wg_linux_guard guard; /* must be first: backend context */
    struct steer_draft_wg_revision revision;
    const struct steer_draft_kernel_wg_guard_config *inbound;
    const struct steer_policy *policy;
};
int steer_linked_inbound_recover_checked(struct steer_linked_inbound *,
    struct steer_linked_inbound_recovery *,uint64_t,uint64_t *,struct steer_draft_wg_guard_record *);
#endif
