#ifndef STEER_INBOUND_GUARD_CAPTURE_H
#define STEER_INBOUND_GUARD_CAPTURE_H
#include "inbound_guard_verify.h"
/* Experimental read-only bounded capture + snapshot comparison. Positive errno
 * on failure; deadline is absolute CLOCK_MONOTONIC ns. The trusted plan must
 * come from validated committed configuration and owned identity, not nft.
 * No peer/owned link attestation or atomicity against other netns writers. */
int steer_inbound_guard_capture_verify(const struct steer_inbound_guard_plan *,uint64_t deadline);
#endif
