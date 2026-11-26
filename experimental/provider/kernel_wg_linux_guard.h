#ifndef STEER_DRAFT_KERNEL_WG_LINUX_GUARD_H
#define STEER_DRAFT_KERNEL_WG_LINUX_GUARD_H

#include "kernel_wg_linux_link.h"
#include "kernel_wg_guard.h"

/* Borrowed worker-local state. Restart cleanup needs link only, not prepared. */
struct steer_draft_wg_linux_guard {
    struct steer_draft_wg_linux_link *link;
    struct steer_draft_kernel_wg_guard *prepared;
    const struct awg_prefix *route; /* optional; valid through staging only */
    int scoped_route;
};
extern const struct steer_draft_wg_backend steer_draft_wg_linux_guard_backend;
/* Owned-link admission barrier; fresh namespace/identity and state checks.
 * On error, state distinguishes confirmed closed from unknown. */
int steer_draft_wg_linux_guard_barrier_close(void *,const struct steer_draft_wg_guard_record *,uint64_t,uint32_t *);
int steer_draft_wg_linux_guard_barrier_open(void *,const struct steer_draft_wg_guard_record *,uint64_t,uint32_t *);

#endif
