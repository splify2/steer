#include "host.h"
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) abort(); } while (0)
#define CODE(x,c) CHECK((x).code == (c))
struct services_state { uint64_t time; uint32_t logs, severity, length; };
static uint64_t clock_ns(void *ctx) {
    struct services_state *s = ctx;
    return s->time++;
}
static void sink(void *ctx, uint32_t severity, struct steer_pv1_span msg) {
    struct services_state *s = ctx;
    CHECK(msg.len <= STEER_DRAFT_HOST_LOG_MAX);
    s->logs++; s->severity = severity; s->length = msg.len;
}
int main(void) {
    struct services_state state = {1234,0,0,0};
    struct steer_draft_host_services services = {&state,clock_ns,sink}, bad;
    struct steer_draft_buffer_limits limits = {1024,1,2};
    struct steer_pv1_host *h = NULL, *plain = NULL;
    const struct steer_pv1_host_api *api = NULL;
    const void *table = NULL;
    const struct steer_pv1_buffer_api *buffers;
    struct steer_pv1_buffer *b = NULL, *extra = NULL;
    struct steer_pv1_mut_span view;
    uint8_t message[4097] = {0};
    struct steer_pv1_span msg = {message,4096};
    CODE(steer_draft_host_create(&limits,NULL,NULL,&h),STEER_PV1_INVALID); CHECK(!h);
    bad = services; bad.monotonic_ns = NULL;
    CODE(steer_draft_host_create(&limits,NULL,&bad,&h),STEER_PV1_INVALID); CHECK(!h);
    bad = services; bad.log = NULL;
    CODE(steer_draft_host_create(&limits,NULL,&bad,&h),STEER_PV1_INVALID); CHECK(!h);
    CODE(steer_draft_host_create(&limits,NULL,&services,NULL),STEER_PV1_INVALID);
    CODE(steer_draft_buffers_create(&limits,NULL,&plain),STEER_PV1_OK);
    CODE(steer_draft_host_get_api(plain,&api),STEER_PV1_UNSUPPORTED); CHECK(!api);
    CODE(steer_draft_host_create(&limits,NULL,&services,&h),STEER_PV1_OK);
    CODE(steer_draft_host_get_api(h,&api),STEER_PV1_OK);
    CHECK(api && api->size == sizeof(*api) && api->version == STEER_PV1_DRAFT_LAYOUT);
    CHECK(api->api_major == 1 && api->api_minor == 0);
    CHECK(api->monotonic_ns(h) == 1234 && api->monotonic_ns(h) == 1235);
    CODE(api->get_table(h,999,STEER_PV1_DRAFT_LAYOUT,&table),STEER_PV1_UNSUPPORTED); CHECK(!table);
    CODE(api->get_table(h,STEER_PV1_TABLE_BUFFERS,999,&table),STEER_PV1_UNSUPPORTED); CHECK(!table);
    CODE(api->get_table(h,STEER_PV1_TABLE_BUFFERS,STEER_PV1_DRAFT_LAYOUT,NULL),STEER_PV1_INVALID);
    CODE(api->get_table(h,STEER_PV1_TABLE_BUFFERS,STEER_PV1_DRAFT_LAYOUT,&table),STEER_PV1_OK);
    buffers = table;
    CHECK(buffers && buffers->size == sizeof(*buffers));
    CODE(buffers->allocate(h,16,&b),STEER_PV1_OK);
    CODE(buffers->allocate(h,16,&extra),STEER_PV1_RESOURCE_EXHAUSTED); CHECK(!extra);
    CODE(buffers->writable(h,b,&view),STEER_PV1_OK); CHECK(view.len==16);
    view.data[0] = 42;
    CODE(buffers->retain(h,b),STEER_PV1_OK);
    CODE(buffers->writable(h,b,&view),STEER_PV1_POLICY_DENIED);
    CODE(steer_draft_buffers_destroy(h),STEER_PV1_RESOURCE_EXHAUSTED);
    buffers->release(h,b); buffers->release(h,b);
    api->log(h,3,msg); CHECK(state.logs==1 && state.length==4096 && state.severity==3);
    msg.len=4097; api->log(h,3,msg); CHECK(state.logs==1);
    msg.data=NULL; msg.len=1; api->log(h,3,msg); CHECK(state.logs==1);
    msg.len=0; api->log(h,5,msg); CHECK(state.logs==1);
    api->log(h,4,msg); api->log(h,6,msg); api->log(h,7,msg);
    CHECK(state.logs==4 && state.length==0 && state.severity==7);
    table=buffers;
    CODE(api->get_table(plain,STEER_PV1_TABLE_BUFFERS,STEER_PV1_DRAFT_LAYOUT,&table),STEER_PV1_UNSUPPORTED); CHECK(!table);
    CODE(steer_draft_buffers_destroy(h),STEER_PV1_OK);
    CODE(steer_draft_buffers_destroy(plain),STEER_PV1_OK);
    CODE(steer_draft_host_get_api(NULL,&api),STEER_PV1_INVALID); CHECK(!api);
    return 0;
}
