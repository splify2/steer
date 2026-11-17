#include "admission.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
#define SPAN(s) ((struct steer_pv1_span){(const uint8_t *)(s), sizeof(s)-1})
/* Any lifecycle invocation is a test failure. Signatures exactly match SDK. */
static struct steer_pv1_error STEER_PV1_CALL validate(struct steer_pv1_host *h, const struct steer_pv1_config *c) { (void)h; (void)c; abort(); }
static struct steer_pv1_async_start STEER_PV1_CALL prepare(struct steer_pv1_host *h, const struct steer_pv1_host_api *a, const struct steer_pv1_config *c, steer_pv1_prepare_done cb, void *u) { (void)h; (void)a; (void)c; (void)cb; (void)u; abort(); }
static struct steer_pv1_error STEER_PV1_CALL activate(struct steer_pv1_instance *i) { (void)i; abort(); }
static void STEER_PV1_CALL quiesce(struct steer_pv1_instance *i) { (void)i; abort(); }
static struct steer_pv1_async_start STEER_PV1_CALL drain(struct steer_pv1_instance *i, uint64_t t, steer_pv1_drain_done cb, void *u) { (void)i; (void)t; (void)cb; (void)u; abort(); }
static void STEER_PV1_CALL destroy(struct steer_pv1_instance *i) { (void)i; abort(); }
int main(void) {
    struct steer_pv1_target target = {0}, expected_target;
    struct steer_pv1_combination tuple = {0};
    const struct steer_pv1_combination *tuples[1] = {&tuple};
    uint32_t modes[1] = {STEER_PV1_MODE_TRUSTED_NATIVE}, caps[1] = {17};
    struct steer_pv1_descriptor descriptor = {0}, original;
    struct steer_pv1_provider_api provider = {0};
    struct steer_draft_admission_expected expected = {0};
    struct steer_draft_admission_result r;
    char long_id[129];
#define EXPECT(code_,field_) do { r = steer_draft_provider_admit(&provider,&expected); CHECK(r.code==(code_) && r.field==(field_)); } while (0)
    target.size = sizeof(target); target.version = STEER_PV1_DRAFT_LAYOUT;
    target.os = SPAN("linux"); target.cpu = SPAN("x86_64"); target.abi = SPAN("sysv"); target.libc = SPAN("glibc");
    target.pointer_bits = 64; target.endian = 1;
    expected_target = target;
    tuple.size = sizeof(tuple); tuple.version = STEER_PV1_DRAFT_LAYOUT;
    tuple.direction = STEER_PV1_DIRECTION_INBOUND; tuple.flow_class = STEER_PV1_FLOW_STREAM;
    tuple.transport = SPAN("tcp"); tuple.security = SPAN("none");
    descriptor.size = sizeof(descriptor); descriptor.version = STEER_PV1_DRAFT_LAYOUT;
    descriptor.package_id = SPAN("test-package"); descriptor.package_version = SPAN("0.0.1");
    descriptor.provider_id = SPAN("socks"); descriptor.api_range = SPAN("^1.0"); descriptor.target = &target;
    descriptor.combinations = tuples; descriptor.combination_count = 1;
    descriptor.execution_modes = modes; descriptor.execution_mode_count = 1;
    descriptor.required_host_capabilities = caps; descriptor.required_host_capability_count = 1;
    provider.size = sizeof(provider); provider.version = STEER_PV1_DRAFT_LAYOUT;
    provider.descriptor = &descriptor; provider.validate = validate; provider.prepare = prepare;
    provider.activate = activate; provider.quiesce = quiesce; provider.drain = drain; provider.destroy = destroy;
    expected.package_id = descriptor.package_id; expected.package_version = descriptor.package_version;
    expected.provider_id = descriptor.provider_id; expected.api_range = descriptor.api_range;
    expected.target = &expected_target; expected.host_capabilities = caps; expected.host_capability_count = 1;
    original = descriptor;
    EXPECT(STEER_PV1_OK,STEER_DRAFT_ADMIT_NONE);
    provider.size = offsetof(struct steer_pv1_provider_api,destroy);
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_PROVIDER); provider.size = sizeof(provider);
    provider.version++;
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_PROVIDER); provider.version--;
#define MISSING(fn) do { provider.fn = NULL; EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_LIFECYCLE); provider.fn = fn; } while (0)
    MISSING(validate); MISSING(prepare); MISSING(activate); MISSING(quiesce); MISSING(drain); MISSING(destroy);
    provider.descriptor = NULL;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_DESCRIPTOR); provider.descriptor = &descriptor;
    descriptor.size = offsetof(struct steer_pv1_descriptor,options_schema_sha256);
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_DESCRIPTOR); descriptor = original;
    descriptor.package_id = SPAN("other");
    EXPECT(STEER_PV1_POLICY_DENIED,STEER_DRAFT_ADMIT_IDENTITY); descriptor = original;
    descriptor.package_version = SPAN("0.0.2");
    EXPECT(STEER_PV1_POLICY_DENIED,STEER_DRAFT_ADMIT_IDENTITY); descriptor = original;
    descriptor.provider_id = SPAN("SOCKS");
    EXPECT(STEER_PV1_POLICY_DENIED,STEER_DRAFT_ADMIT_IDENTITY); descriptor = original;
    descriptor.provider_id = SPAN("a\0b");
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_IDENTITY); descriptor = original;
    memset(long_id,'a',sizeof(long_id)); descriptor.provider_id.data = (uint8_t *)long_id; descriptor.provider_id.len = sizeof(long_id);
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_IDENTITY); descriptor = original;
    descriptor.api_range = SPAN(">=1");
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_API_RANGE); descriptor = original;
    target.size = offsetof(struct steer_pv1_target,endian);
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_TARGET); target = expected_target;
    target.libc = SPAN("musl");
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_TARGET); target = expected_target;
    target.pointer_bits = 32;
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_TARGET); target = expected_target;
    target.endian = 2;
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_TARGET); target = expected_target;
    descriptor.options_schema_sha256[31] = 1;
    EXPECT(STEER_PV1_POLICY_DENIED,STEER_DRAFT_ADMIT_DIGEST); descriptor = original;
    descriptor.execution_mode_count = 9;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_MODES); descriptor = original;
    modes[0] = 999;
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_MODES); modes[0] = STEER_PV1_MODE_TRUSTED_NATIVE;
    descriptor.execution_modes = NULL;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_MODES); descriptor = original;
    expected.host_capability_count = 0;
    EXPECT(STEER_PV1_UNSUPPORTED,STEER_DRAFT_ADMIT_CAPABILITIES); expected.host_capability_count = 1;
    descriptor.required_host_capability_count = 65;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_CAPABILITIES); descriptor = original;
    descriptor.combination_count = 129;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); descriptor = original;
    descriptor.combination_count = 0;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); descriptor = original;
    tuples[0] = NULL;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); tuples[0] = &tuple;
    tuple.size = offsetof(struct steer_pv1_combination,security);
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); tuple.size = sizeof(tuple);
    tuple.direction = 99;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); tuple.direction = STEER_PV1_DIRECTION_OUTBOUND;
    tuple.flow_class = 99;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); tuple.flow_class = STEER_PV1_FLOW_DATAGRAM;
    tuple.transport.len = 0;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_COMBINATIONS); tuple.transport = SPAN("udp");
    EXPECT(STEER_PV1_OK,STEER_DRAFT_ADMIT_NONE);
    expected.api_range.data = NULL;
    EXPECT(STEER_PV1_INVALID,STEER_DRAFT_ADMIT_EXPECTATION);
    CHECK(steer_draft_provider_admit(NULL,NULL).code == STEER_PV1_INVALID);
    puts("draft admission: ok");
    return 0;
}
