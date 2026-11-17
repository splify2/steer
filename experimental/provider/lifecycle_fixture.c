/* Source-only integration fixture. No production provider or native IO. */
#include "host.h"
#include "operations.h"
#include "admission.h"
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) abort(); } while (0)
#define CODE(x,c) CHECK((x).code == (c))
#define S(s) {(const uint8_t *)(s), sizeof(s)-1}
struct steer_pv1_instance {
    struct steer_pv1_host *host;
    const struct steer_pv1_buffer_api *buffers;
    struct steer_pv1_buffer *buffer;
    int active, quiet, drained;
};
/* One fixture-local work slot, wrapping a separately owned real queue handle. */
struct work {
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_host *host;
    const struct steer_pv1_host_api *host_api;
    struct steer_pv1_instance *instance;
    steer_pv1_prepare_done prepared;
    steer_pv1_drain_done drained;
    void *userdata;
    int busy, cancellation, resolved, kind;
};
static struct work work;
static struct steer_draft_operations *queue;
static int fail_activate, reject_drain;
static unsigned instances;
static struct steer_pv1_error err(uint32_t code) {
    struct steer_pv1_error e = {code,0}; return e;
}
static void cleanup(struct steer_pv1_instance *i) {
    if (!i) return;
    if (i->buffer) i->buffers->release(i->host,i->buffer);
    instances--; free(i);
}
static void STEER_PV1_CALL cancel(struct steer_pv1_operation *handle) {
    struct work *w = (struct work *)handle;
    if (!w->resolved) w->cancellation = 1;
}
static void STEER_PV1_CALL release(struct steer_pv1_operation *handle) {
    struct work *w = (struct work *)handle;
    /* Calling-state release fails; never reuse slot before callback returns. */
    if (steer_draft_operation_release_checked(w->inner.handle).code == STEER_PV1_OK)
        memset(w,0,sizeof(*w));
}
static const struct steer_pv1_operation_api operation_api = {
    sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,cancel,release
};
static void completion(void *userdata, struct steer_pv1_error e) {
    struct work *w = userdata;
    if (w->kind == 1) w->prepared(w->userdata,e,e.code == STEER_PV1_OK ? w->instance : NULL);
    else {
        if (e.code == STEER_PV1_OK) w->instance->drained = 1;
        w->drained(w->userdata,e);
    }
}
static struct steer_pv1_async_start rejected(uint32_t code) {
    struct steer_pv1_async_start s = {STEER_PV1_REJECTED,{code,0},{NULL,NULL}}; return s;
}
static struct steer_pv1_async_start begin(int kind, void *userdata) {
    struct steer_pv1_async_start s;
    if (work.busy) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    s = steer_draft_operation_start(queue,completion,&work);
    if (s.disposition != STEER_PV1_PENDING) return s;
    work.inner = s.operation; work.busy = 1; work.kind = kind; work.userdata = userdata;
    s.operation.handle = (struct steer_pv1_operation *)&work;
    s.operation.api = &operation_api;
    return s;
}
static struct steer_pv1_error STEER_PV1_CALL validate(struct steer_pv1_host *h,
    const struct steer_pv1_config *c) {
    if (!h || !c || c->size < sizeof(*c) || c->version != STEER_PV1_DRAFT_LAYOUT)
        return err(STEER_PV1_INVALID);
    return err(STEER_PV1_OK);
}
static struct steer_pv1_async_start STEER_PV1_CALL prepare(struct steer_pv1_host *h,
    const struct steer_pv1_host_api *api, const struct steer_pv1_config *c,
    steer_pv1_prepare_done cb, void *userdata) {
    struct steer_pv1_async_start s;
    if (!cb || validate(h,c).code != STEER_PV1_OK) return rejected(STEER_PV1_INVALID);
    s = begin(1,userdata);
    if (s.disposition == STEER_PV1_PENDING) {
        work.host = h; work.host_api = api; work.prepared = cb;
    }
    return s;
}
/* Explicit fake scheduler step: reserve before deciding terminal outcome. */
static struct steer_pv1_error reserve_prepare(void) {
    const void *table = NULL;
    struct steer_pv1_error e;
    CHECK(work.busy && work.kind == 1 && !work.resolved && !work.instance);
    work.instance = calloc(1,sizeof(*work.instance));
    if (!work.instance) return err(STEER_PV1_RESOURCE_EXHAUSTED);
    instances++;
    work.instance->host = work.host;
    e = work.host_api->get_table(work.host,STEER_PV1_TABLE_BUFFERS,STEER_PV1_DRAFT_LAYOUT,&table);
    if (e.code != STEER_PV1_OK) return e;
    work.instance->buffers = table;
    return work.instance->buffers->allocate(work.host,16,&work.instance->buffer);
}
static void finish_prepare(struct steer_pv1_error reservation) {
    struct steer_pv1_error outcome = work.cancellation ? err(STEER_PV1_CANCELLED) : reservation;
    if (outcome.code != STEER_PV1_OK) { cleanup(work.instance); work.instance = NULL; }
    CODE(steer_draft_operation_resolve(work.inner.handle,outcome),STEER_PV1_OK);
    work.resolved = 1;
}
static struct steer_pv1_error STEER_PV1_CALL activate(struct steer_pv1_instance *i) {
    if (fail_activate) return err(STEER_PV1_IO);
    i->active = 1; return err(STEER_PV1_OK);
}
static void STEER_PV1_CALL quiesce(struct steer_pv1_instance *i) { i->quiet = 1; }
static struct steer_pv1_async_start STEER_PV1_CALL drain(struct steer_pv1_instance *i,
    uint64_t deadline, steer_pv1_drain_done cb, void *userdata) {
    struct steer_pv1_async_start s;
    (void)deadline; /* No IO: manual pump, no timer implementation. */
    if (!i->quiet || !cb) return rejected(STEER_PV1_INVALID);
    if (reject_drain) return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    s = begin(2,userdata);
    if (s.disposition == STEER_PV1_PENDING) { work.instance = i; work.drained = cb; }
    return s;
}
static void finish_drain(void) {
    CODE(steer_draft_operation_resolve(work.inner.handle,
        err(work.cancellation ? STEER_PV1_CANCELLED : STEER_PV1_OK)),STEER_PV1_OK);
    work.resolved = 1;
}
static void STEER_PV1_CALL destroy(struct steer_pv1_instance *i) {
    CHECK(i->quiet && i->drained && !work.busy); cleanup(i);
}
static int safe_destroy(const struct steer_pv1_provider_api *p, struct steer_pv1_instance *i) {
    if (!i->quiet || !i->drained || work.busy) return 0;
    p->destroy(i); return 1;
}
static const struct steer_pv1_target target = {
    sizeof(struct steer_pv1_target),STEER_PV1_DRAFT_LAYOUT,
    S("fixture"),S("synthetic"),S("test"),S("none"),64,1
};
static const struct steer_pv1_combination combination = {
    sizeof(struct steer_pv1_combination),STEER_PV1_DRAFT_LAYOUT,
    STEER_PV1_DIRECTION_INBOUND,STEER_PV1_FLOW_STREAM,S("mock"),S("none")
};
static const struct steer_pv1_combination *const combinations[] = {&combination};
static const uint32_t modes[] = {STEER_PV1_MODE_TRUSTED_NATIVE};
static const struct steer_pv1_descriptor descriptor = {
    sizeof(struct steer_pv1_descriptor),STEER_PV1_DRAFT_LAYOUT,
    S("fixture"),S("0.0.0"),S("mock"),S("fixture-api"),&target,
    combinations,1,modes,1,NULL,0,{0}
};
static const struct steer_pv1_provider_api provider = {
    sizeof(struct steer_pv1_provider_api),STEER_PV1_DRAFT_LAYOUT,&descriptor,
    validate,prepare,activate,quiesce,drain,destroy
};
static struct steer_pv1_error query(struct steer_pv1_host *h, const struct steer_pv1_host_api *a,
    const struct steer_pv1_provider_api **out) {
    if (out) *out = NULL;
    if (!h || !out || !STEER_PV1_HAS(a,struct steer_pv1_host_api,log)) return err(STEER_PV1_INVALID);
    if (a->version != STEER_PV1_DRAFT_LAYOUT || a->api_major != 1) return err(STEER_PV1_UNSUPPORTED);
    if (!a->get_table || !a->monotonic_ns || !a->log) return err(STEER_PV1_INVALID);
    *out = &provider; return err(STEER_PV1_OK);
}
struct observed { struct steer_pv1_instance *instance; uint32_t code, calls; };
static void STEER_PV1_CALL prepared(void *userdata, struct steer_pv1_error e, struct steer_pv1_instance *i) {
    struct observed *o = userdata; o->calls++; o->code = e.code; o->instance = i;
}
static void STEER_PV1_CALL drained(void *userdata, struct steer_pv1_error e) {
    struct observed *o = userdata; o->calls++; o->code = e.code;
}
static uint64_t clock_ns(void *c) { (void)c; return 1; }
static void log_sink(void *c, uint32_t s, struct steer_pv1_span m) { (void)c; (void)s; (void)m; }
static void dispatch(void) { uint32_t n; CODE(steer_draft_operations_dispatch(queue,1,&n),STEER_PV1_OK); CHECK(n==1); }
int main(void) {
    struct steer_draft_host_services services = {NULL,clock_ns,log_sink};
    struct steer_draft_buffer_limits limits = {1024,1,4};
    struct steer_pv1_host *h, *small;
    const struct steer_pv1_host_api *ha, *sa;
    const struct steer_pv1_provider_api *p = NULL;
    struct steer_pv1_host_api bad;
    struct steer_draft_admission_expected expected = {
        S("fixture"),S("0.0.0"),S("mock"),S("fixture-api"),&target,{0},NULL,0
    };
    struct steer_pv1_config config = {0};
    struct steer_pv1_async_start op;
    struct observed o = {0};
    uint64_t bytes; uint32_t count, live, queued;
    struct steer_pv1_error reservation;
    CODE(steer_draft_operations_create(1,NULL,&queue),STEER_PV1_OK);
    CODE(steer_draft_host_create(&limits,NULL,&services,&h),STEER_PV1_OK);
    CODE(steer_draft_host_get_api(h,&ha),STEER_PV1_OK);
    bad = *ha; bad.size = offsetof(struct steer_pv1_host_api,log);
    CODE(query(h,&bad,&p),STEER_PV1_INVALID); CHECK(!p);
    bad = *ha; bad.api_major++;
    CODE(query(h,&bad,&p),STEER_PV1_UNSUPPORTED); CHECK(!p);
    bad = *ha; bad.get_table = NULL;
    CODE(query(h,&bad,&p),STEER_PV1_INVALID); CHECK(!p);
    CODE(query(h,ha,&p),STEER_PV1_OK);
    CHECK(steer_draft_provider_admit(p,&expected).code == STEER_PV1_OK);
    config.size = sizeof(config); config.version = STEER_PV1_DRAFT_LAYOUT;
    CODE(p->validate(h,&config),STEER_PV1_OK);
    /* success and activate failure each require quiesce/drain/release/destroy */
    for (int failure=0; failure<2; failure++) {
        struct steer_pv1_async_start duplicate;
        o.calls=0; o.instance=NULL;
        op=p->prepare(h,ha,&config,prepared,&o); CHECK(op.disposition==STEER_PV1_PENDING);
        duplicate=p->prepare(h,ha,&config,prepared,&o);
        CHECK(duplicate.disposition==STEER_PV1_REJECTED && !duplicate.operation.handle && !duplicate.operation.api && !o.calls);
        CODE(duplicate.error,STEER_PV1_RESOURCE_EXHAUSTED);
        op.operation.api->release(op.operation.handle); CHECK(work.busy); /* early no-op */
        CHECK(!o.calls); reservation=reserve_prepare(); finish_prepare(reservation);
        op.operation.api->cancel(op.operation.handle); /* already resolved success wins */
        dispatch(); CHECK(o.calls==1 && o.code==STEER_PV1_OK && o.instance);
        duplicate=p->prepare(h,ha,&config,prepared,&o);
        CHECK(duplicate.disposition==STEER_PV1_REJECTED && o.calls==1 && work.busy);
        CHECK(!safe_destroy(p,o.instance));
        op.operation.api->release(op.operation.handle); CHECK(!work.busy);
        fail_activate=failure;
        CODE(p->activate(o.instance),failure ? STEER_PV1_IO : STEER_PV1_OK);
        p->quiesce(o.instance); reject_drain=1;
        op=p->drain(o.instance,1,drained,&o); CHECK(op.disposition==STEER_PV1_REJECTED);
        CHECK(!safe_destroy(p,o.instance)); reject_drain=0;
        op=p->drain(o.instance,1,drained,&o); CHECK(op.disposition==STEER_PV1_PENDING);
        finish_drain(); dispatch(); CHECK(o.calls==2 && o.code==STEER_PV1_OK);
        CHECK(!safe_destroy(p,o.instance)); /* callback done, op not released */
        op.operation.api->release(op.operation.handle); CHECK(safe_destroy(p,o.instance));
    }
    /* Cancellation after resources reserved: cleanup precedes terminal select. */
    o.calls=0; o.instance=NULL;
    op=p->prepare(h,ha,&config,prepared,&o); reservation=reserve_prepare();
    CHECK(instances==1); op.operation.api->cancel(op.operation.handle);
    finish_prepare(reservation); CHECK(!instances);
    dispatch(); CHECK(o.calls==1 && o.code==STEER_PV1_CANCELLED && !o.instance);
    op.operation.api->release(op.operation.handle);
    /* Buffer allocation failure unwinds the already-allocated mock instance. */
    limits.max_buffers=0;
    CODE(steer_draft_host_create(&limits,NULL,&services,&small),STEER_PV1_OK);
    CODE(steer_draft_host_get_api(small,&sa),STEER_PV1_OK);
    o.calls=0;
    op=p->prepare(small,sa,&config,prepared,&o); reservation=reserve_prepare();
    CODE(reservation,STEER_PV1_RESOURCE_EXHAUSTED); finish_prepare(reservation); CHECK(!instances);
    dispatch(); CHECK(o.calls==1 && o.code==STEER_PV1_RESOURCE_EXHAUSTED && !o.instance);
    op.operation.api->release(op.operation.handle);
    steer_draft_buffers_usage(h,&bytes,&count); CHECK(!bytes && !count);
    steer_draft_buffers_usage(small,&bytes,&count); CHECK(!bytes && !count);
    steer_draft_operations_usage(queue,&live,&queued); CHECK(!live && !queued && !instances && !work.busy);
    CODE(steer_draft_buffers_destroy(small),STEER_PV1_OK);
    CODE(steer_draft_buffers_destroy(h),STEER_PV1_OK);
    CODE(steer_draft_operations_destroy(queue),STEER_PV1_OK);
    return 0;
}
