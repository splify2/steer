#ifndef STEER_EXPERIMENTAL_FLOW_METADATA_H
#define STEER_EXPERIMENTAL_FLOW_METADATA_H
#include <steer/draft/flow_v1.h>
/* Fixed bounded copy; no routing selection. Non-NULL principal is UNSUPPORTED
 * until a negotiated host authentication/retention service exists. */
struct steer_draft_flow_owned {
    struct steer_pv1_flow_metadata value;
    uint8_t inbound[64], principal[64], source[16], destination[254];
};
struct steer_pv1_error steer_draft_flow_validate(const struct steer_pv1_flow_metadata *,uint32_t expected_class);
struct steer_pv1_error steer_draft_flow_copy(struct steer_draft_flow_owned *,
    const struct steer_pv1_flow_metadata *,uint32_t expected_class);
#endif
