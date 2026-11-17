/* Experimental portable ordered policy. No legacy nft model is replaced. */
#ifndef STEER_DRAFT_POLICY_H
#define STEER_DRAFT_POLICY_H
#include <steer/draft/provider_v1.h>

#define STEER_POLICY_DIRECT 1u
#define STEER_POLICY_BLOCK 2u
#define STEER_POLICY_MAX_RULES 1024u
struct steer_policy;
/* Empty inbound/principal means any. A domain matches the original requested
 * name, never a reverse lookup; suffix includes the apex and label descendants.
 * Domain and CIDR conditions are mutually exclusive. All conditions are AND.
 * CIDR uses endpoint IPv4/IPv6 tags and network-order bytes (host bits zero).
 * port_first=port_last=0 means any port. match_all must be explicit when all
 * conditions are empty. Only ASCII DNS names are accepted in this draft;
 * Unicode/IDNA must be normalized by a future validated resolver boundary. */
struct steer_policy_rule {
    struct steer_pv1_span id, inbound, principal, domain;
    uint32_t domain_suffix, cidr_tag, prefix_bits;
    uint8_t network[16];
    uint16_t port_first, port_last;
    uint32_t match_all, action;
};
struct steer_policy_input {
    uint64_t generation;
    struct steer_pv1_span inbound, principal;
    const struct steer_pv1_endpoint *destination;
};
struct steer_policy_decision {
    uint32_t action;
    /* UINT32_MAX means explicit default. Never points into input storage. */
    uint32_t rule_index;
};
/* Kernel-device packets retain numeric destination and authenticated ingress
 * identity; they have no requested domain. Portless protocols skip port rules.
 * IP protocol is 0..255; destination.port is considered only for TCP/UDP. */
struct steer_policy_packet_input {
    uint64_t generation;
    struct steer_pv1_span inbound, principal;
    const struct steer_pv1_endpoint *destination;
    uint32_t ip_protocol;
};
struct steer_pv1_error steer_policy_packet_evaluate(const struct steer_policy *,
    const struct steer_policy_packet_input *,struct steer_policy_decision *);
/* Validated immutable snapshot, same order/conditions as evaluator. Rule/spans
 * borrowed only on callback; compiler consumers must copy retained data. */
typedef struct steer_pv1_error (*steer_policy_rule_visitor)(void *,
    const struct steer_policy_rule *);
struct steer_pv1_error steer_policy_visit(const struct steer_policy *,uint64_t generation,
    steer_policy_rule_visitor,void *,uint32_t *default_action);
/* Copies and validates all rules before publication. Caller may discard rule
 * storage after return. Unknown/invalid fields fail closed; out is NULL. */
struct steer_pv1_error steer_policy_compile(uint64_t generation,
    const struct steer_policy_rule *, uint32_t count, uint32_t default_action,
    struct steer_policy **out);
void steer_policy_destroy(struct steer_policy *);
/* Allocation-free, immutable read. Invalid input/generation mismatch returns
 * error with BLOCK decision. Policy must outlive all concurrent evaluations. */
struct steer_pv1_error steer_policy_evaluate(const struct steer_policy *,
    const struct steer_policy_input *, struct steer_policy_decision *);
#endif
