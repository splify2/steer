#ifndef STEER_DRAFT_KERNEL_WG_LINUX_GUARD_H
#define STEER_DRAFT_KERNEL_WG_LINUX_GUARD_H

#include "kernel_wg_linux_link.h"
#include "kernel_wg_guard.h"

/* Borrowed worker-local state. Restart cleanup needs link only, not prepared. */
struct steer_draft_wg_linux_guard {
    struct steer_draft_wg_linux_link *link;
    struct steer_draft_kernel_wg_guard *prepared;
};
extern const struct steer_draft_wg_backend steer_draft_wg_linux_guard_backend;

#endif
