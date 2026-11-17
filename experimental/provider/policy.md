# Experimental accepted-flow routing

`policy.c` compiles up to 1024 rules into an owned immutable snapshot. Compilation
copies all identifiers, domain patterns and CIDRs. Evaluation allocates nothing,
does no IO, and returns the first matching rule index or `UINT32_MAX` for the
explicit default. A snapshot belongs to a nonzero generation; mismatches fail
closed. The host must retain the snapshot through all evaluations.

Conditions currently supported: inbound ID, trusted principal ID, requested
destination domain (exact or suffix including apex), IPv4/IPv6 destination CIDR,
and inclusive destination port range. Conditions in a rule are AND. Domain
matching folds ASCII case, ignores one terminal dot, and respects DNS label
boundaries. An IP never acquires a domain through reverse DNS. CIDRs must be
canonical; IPv4 and IPv6 do not implicitly match one another. Empty conditions
require explicit `match_all`. Duplicate IDs, malformed inputs and unknown actions
are rejected. Default action is mandatory, with only direct/block implemented.

`policy_route.c` adapts this evaluator to `route_dial.h`. This is a source-only
experimental seam, not a published provider ABI or an import of legacy nft rules.
No production YAML parser or generation transaction uses it yet. Groups, multiple
values per condition, source matching, negation, lists, resolver policy, protocol
outbounds and identity-service integration remain work to do. Domain policy can
decide block before resolution; successful direct domain resolution is still
unsupported by the experimental dial service.

`policy_test.c` covers first-match precedence, suffix boundaries, case/trailing-dot
equivalence, IPv4 /13 and IPv6 /65 boundaries, AND conditions, compile ownership,
generation rejection, malformed names, duplicate IDs, noncanonical networks,
explicit match-all/default validation and route callback adaptation. Strict C11
and ASan/UBSan runs passed. This is semantic evidence, not a throughput benchmark.
