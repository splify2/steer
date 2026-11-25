#ifndef STEER_DRAFT_KERNEL_WG_STREAM_H
#define STEER_DRAFT_KERNEL_WG_STREAM_H

#include "kernel_wg_linux_link.h"
#include "awg.h"
#include <sys/socket.h>

struct steer_draft_wg_stream;
/* Capture a generation-local connector from an exact candidate or selected
 * journal record. Owns a duplicate pinned namespace descriptor and copies all
 * identities. It never owns or retires kernel resources; host must keep the
 * selected device alive through the binding's admission/drain lifetime. */
int steer_draft_wg_stream_create(const struct steer_draft_wg_linux_link *,
    const struct steer_draft_wg_guard_record *,const struct awg_prefix *source,
    const struct awg_prefix *route,int scoped,uint64_t deadline,struct steer_draft_wg_stream **);
void steer_draft_wg_stream_destroy(struct steer_draft_wg_stream *);
uint64_t steer_draft_wg_stream_generation(const struct steer_draft_wg_stream *);
int steer_draft_wg_stream_contains(const struct steer_draft_wg_stream *,const uint8_t address[4]);
int steer_draft_wg_stream_verify(const struct steer_draft_wg_stream *,uint64_t deadline);
/* Native TCP socket constraint. No direct fallback, DNS or namespace changes.
 * Attachment to a native backend borrows this object through its finalizer. */
uint32_t steer_draft_wg_stream_bind(void *,int,const struct sockaddr_storage *,uint64_t deadline);

#endif
