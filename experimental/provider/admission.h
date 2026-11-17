#ifndef STEER_EXPERIMENTAL_ADMISSION_H
#define STEER_EXPERIMENTAL_ADMISSION_H
#include <steer/draft/provider_v1.h>

enum steer_draft_admission_field {
    STEER_DRAFT_ADMIT_NONE = 0, STEER_DRAFT_ADMIT_EXPECTATION,
    STEER_DRAFT_ADMIT_PROVIDER, STEER_DRAFT_ADMIT_LIFECYCLE,
    STEER_DRAFT_ADMIT_DESCRIPTOR, STEER_DRAFT_ADMIT_IDENTITY,
    STEER_DRAFT_ADMIT_API_RANGE, STEER_DRAFT_ADMIT_TARGET,
    STEER_DRAFT_ADMIT_DIGEST, STEER_DRAFT_ADMIT_MODES,
    STEER_DRAFT_ADMIT_CAPABILITIES, STEER_DRAFT_ADMIT_COMBINATIONS
};
struct steer_draft_admission_result {
    uint32_t code;
    enum steer_draft_admission_field field;
};
struct steer_draft_admission_expected {
    struct steer_pv1_span package_id, package_version, provider_id;
    /* Mandatory exact text already negotiated against actual host by caller.
     * Equality here NEVER negotiates API compatibility. */
    struct steer_pv1_span api_range;
    const struct steer_pv1_target *target; /* actual runtime identity, verified pre-load */
    uint8_t options_schema_sha256[32];
    const uint32_t *host_capabilities;
    uint32_t host_capability_count;
};
/* Pure POST-query consistency check. Does not load/query/call any provider,
 * verify signatures, parse manifests, authorize native execution or negotiate
 * API versions. Host must supply independently verified/approved expectations.
 * IDs/target fields: 1..128 visible ASCII bytes. Version/range: 1..256 ASCII
 * bytes (range permits spaces). No NUL, no assumed trailing terminator.
 * Every pointer must reference valid backing storage for its advertised size/
 * count, including at least a readable size word for versioned records. Size
 * gates protect prefix access, not forged pointers or a lying native module.
 * Arrays/spans/tables must remain immutable for this call. No IO or allocation.
 * UNKNOWN API range/expectations must not be admitted using this function. */
struct steer_draft_admission_result steer_draft_provider_admit(
    const struct steer_pv1_provider_api *, const struct steer_draft_admission_expected *);
#endif
