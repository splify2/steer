#include "admission.h"
#include <string.h>

#define THROUGH(type, member) (offsetof(type, member) + sizeof(((type *)0)->member))
#define PREFIX(p,type,member) ((p) && (p)->size >= THROUGH(type,member))
static struct steer_draft_admission_result fail(uint32_t code, enum steer_draft_admission_field field) {
    struct steer_draft_admission_result r = {code, field};
    return r;
}
static int text(struct steer_pv1_span s, uint32_t max, int spaces) {
    uint32_t i;
    if (!s.data || !s.len || s.len > max) return 0;
    for (i = 0; i < s.len; i++)
        if (s.data[i] < (spaces ? 32 : 33) || s.data[i] > 126) return 0;
    return 1;
}
static int equal(struct steer_pv1_span a, struct steer_pv1_span b) {
    return a.len == b.len && !memcmp(a.data, b.data, a.len);
}
static int target_valid(const struct steer_pv1_target *t) {
    return PREFIX(t, struct steer_pv1_target, endian) &&
        t->version == STEER_PV1_DRAFT_LAYOUT &&
        text(t->os, 128, 0) && text(t->cpu, 128, 0) && text(t->abi, 128, 0) &&
        text(t->libc, 128, 0) && (t->pointer_bits == 32 || t->pointer_bits == 64) &&
        (t->endian == 1 || t->endian == 2);
}
struct steer_draft_admission_result steer_draft_provider_admit(
    const struct steer_pv1_provider_api *p, const struct steer_draft_admission_expected *e) {
    const struct steer_pv1_descriptor *d;
    const struct steer_pv1_target *t;
    uint32_t i, j;
    if (!e || !text(e->package_id,128,0) || !text(e->package_version,256,0) ||
        !text(e->provider_id,128,0) || !text(e->api_range,256,1) || !target_valid(e->target) ||
        e->host_capability_count > 64 || (e->host_capability_count && !e->host_capabilities))
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_EXPECTATION);
    if (!PREFIX(p,struct steer_pv1_provider_api,destroy))
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_PROVIDER);
    if (p->version != STEER_PV1_DRAFT_LAYOUT)
        return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_PROVIDER);
    if (!p->validate || !p->prepare || !p->activate || !p->quiesce || !p->drain || !p->destroy)
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_LIFECYCLE);
    d = p->descriptor;
    if (!PREFIX(d,struct steer_pv1_descriptor,options_schema_sha256))
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_DESCRIPTOR);
    if (d->version != STEER_PV1_DRAFT_LAYOUT)
        return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_DESCRIPTOR);
    if (!text(d->package_id,128,0) || !text(d->package_version,256,0) ||
        !text(d->provider_id,128,0)) return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_IDENTITY);
    if (!equal(d->package_id,e->package_id) || !equal(d->package_version,e->package_version) ||
        !equal(d->provider_id,e->provider_id)) return fail(STEER_PV1_POLICY_DENIED, STEER_DRAFT_ADMIT_IDENTITY);
    if (!text(d->api_range,256,1)) return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_API_RANGE);
    if (!equal(d->api_range,e->api_range)) return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_API_RANGE);
    t = d->target;
    if (!target_valid(t)) return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_TARGET);
    if (!equal(t->os,e->target->os) || !equal(t->cpu,e->target->cpu) ||
        !equal(t->abi,e->target->abi) || !equal(t->libc,e->target->libc) ||
        t->pointer_bits != e->target->pointer_bits || t->endian != e->target->endian)
        return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_TARGET);
    if (memcmp(d->options_schema_sha256,e->options_schema_sha256,32))
        return fail(STEER_PV1_POLICY_DENIED, STEER_DRAFT_ADMIT_DIGEST);
    if (!d->execution_mode_count || d->execution_mode_count > 8 || !d->execution_modes)
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_MODES);
    for (i=0; i<d->execution_mode_count; i++)
        if (d->execution_modes[i] != STEER_PV1_MODE_TRUSTED_NATIVE)
            return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_MODES);
    if (d->required_host_capability_count > 64 ||
        (d->required_host_capability_count && !d->required_host_capabilities))
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_CAPABILITIES);
    for (i=0; i<d->required_host_capability_count; i++) {
        for (j=0; j<e->host_capability_count; j++)
            if (d->required_host_capabilities[i] == e->host_capabilities[j]) break;
        if (j == e->host_capability_count)
            return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_CAPABILITIES);
    }
    if (!d->combination_count || d->combination_count > 128 || !d->combinations)
        return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_COMBINATIONS);
    for (i=0; i<d->combination_count; i++) {
        const struct steer_pv1_combination *c = d->combinations[i];
        if (!PREFIX(c,struct steer_pv1_combination,security))
            return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_COMBINATIONS);
        if (c->version != STEER_PV1_DRAFT_LAYOUT)
            return fail(STEER_PV1_UNSUPPORTED, STEER_DRAFT_ADMIT_COMBINATIONS);
        if ((c->direction != STEER_PV1_DIRECTION_INBOUND && c->direction != STEER_PV1_DIRECTION_OUTBOUND) ||
            (c->flow_class != STEER_PV1_FLOW_STREAM && c->flow_class != STEER_PV1_FLOW_DATAGRAM &&
             c->flow_class != STEER_PV1_FLOW_DEVICE) || !text(c->transport,128,0) || !text(c->security,128,0))
            return fail(STEER_PV1_INVALID, STEER_DRAFT_ADMIT_COMBINATIONS);
    }
    return fail(STEER_PV1_OK, STEER_DRAFT_ADMIT_NONE);
}
