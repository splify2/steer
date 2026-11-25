#ifndef STEER_DRAFT_KERNEL_WG_LINUX_LINK_H
#define STEER_DRAFT_KERNEL_WG_LINUX_LINK_H

#include "kernel_wg_coordinator.h"

/* Experimental link half only. Caller must explicitly enter a disposable netns
 * and supply an fd for the outer netns, pinned before entering. This adapter
 * never enters a namespace or falls back to another device. */
struct steer_draft_wg_linux_link;
int steer_draft_wg_linux_link_open(int outer_namespace_fd,struct steer_draft_wg_linux_link **);
void steer_draft_wg_linux_link_close(struct steer_draft_wg_linux_link *);
int steer_draft_wg_linux_link_prepare(struct steer_draft_wg_linux_link *,
    const struct steer_draft_wg_tx *,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_identity *);

/* Only create_down, stage_down and retire_link are populated. The coordinator
 * rejects this incomplete backend. Compose it with a real guard before adding
 * an UP callback; this adapter itself cannot bring a link UP. */
extern const struct steer_draft_wg_backend steer_draft_wg_linux_link_backend;

#endif
