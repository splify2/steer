#include "operations.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define CODE(x,c) CHECK((x).code == (c))
struct heap { unsigned live; int fail; };
static void *allocate(void *ctx, size_t n) {
    struct heap *h = ctx;
    void *p;
    if (h->fail) return NULL;
    p = malloc(n);
    if (p) h->live++;
    return p;
}
static void deallocate(void *ctx, void *p) {
    struct heap *h = ctx;
    CHECK(h->live > 0);
    h->live--;
    free(p);
}
struct completion {
    struct steer_draft_operations *queue;
    struct steer_pv1_async_start operation, child;
    unsigned calls;
    uint32_t code;
    int spawn;
};
static struct steer_pv1_error terminal(uint32_t code) {
    struct steer_pv1_error e = {code, 0};
    return e;
}
static void child_done(void *ctx, struct steer_pv1_error e) {
    unsigned *calls = ctx;
    CODE(e, STEER_PV1_OK);
    (*calls)++;
}
static unsigned child_calls;
static void done(void *ctx, struct steer_pv1_error e) {
    struct completion *c = ctx;
    uint32_t dispatched = 99;
    c->calls++;
    c->code = e.code;
    /* Neither ABI release nor diagnostic release may free the running node. */
    c->operation.operation.api->release(c->operation.operation.handle);
    CODE(steer_draft_operation_release_checked(c->operation.operation.handle), STEER_PV1_POLICY_DENIED);
    CODE(steer_draft_operations_dispatch(c->queue, 99, &dispatched), STEER_PV1_POLICY_DENIED);
    CHECK(dispatched == 0);
    CODE(steer_draft_operations_destroy(c->queue), STEER_PV1_POLICY_DENIED);
    if (c->spawn) {
        c->child = steer_draft_operation_start(c->queue, child_done, &child_calls);
        CHECK(c->child.disposition == STEER_PV1_PENDING);
        CODE(steer_draft_operation_resolve(c->child.operation.handle, terminal(STEER_PV1_OK)), STEER_PV1_OK);
    }
}
static void rejected(struct steer_pv1_async_start r, uint32_t code) {
    CHECK(r.disposition == STEER_PV1_REJECTED);
    CODE(r.error, code);
    CHECK(!r.operation.handle && !r.operation.api);
}
int main(void) {
    struct heap heap = {0, 0};
    struct steer_draft_operation_allocator a = {&heap, allocate, deallocate};
    struct steer_draft_operations *q = NULL;
    struct completion c = {0}, d = {0};
    uint32_t n, live, queued;
    struct steer_pv1_error invalid = {STEER_PV1_OK, 1};
    heap.fail = 1;
    CODE(steer_draft_operations_create(3, &a, &q), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!q && !heap.live);
    heap.fail = 0;
    CODE(steer_draft_operations_create(3, &a, &q), STEER_PV1_OK);
    c.queue = d.queue = q;
    rejected(steer_draft_operation_start(NULL, done, &c), STEER_PV1_INVALID);
    rejected(steer_draft_operation_start(q, NULL, &c), STEER_PV1_INVALID);
    heap.fail = 1;
    rejected(steer_draft_operation_start(q, done, &c), STEER_PV1_RESOURCE_EXHAUSTED);
    heap.fail = 0;
    c.operation = steer_draft_operation_start(q, done, &c);
    CHECK(c.operation.disposition == STEER_PV1_PENDING && !c.calls);
    CODE(c.operation.error, STEER_PV1_OK);
    CHECK(c.operation.operation.api->size == sizeof(struct steer_pv1_operation_api));
    CHECK(c.operation.operation.api->version == STEER_PV1_DRAFT_LAYOUT);
    CODE(steer_draft_operation_release_checked(c.operation.operation.handle), STEER_PV1_POLICY_DENIED);
    c.operation.operation.api->release(c.operation.operation.handle);
    CODE(steer_draft_operation_resolve(c.operation.operation.handle, invalid), STEER_PV1_INVALID);
    invalid.code = 999;
    invalid.transient = 0;
    CODE(steer_draft_operation_resolve(c.operation.operation.handle, invalid), STEER_PV1_INVALID);
    CODE(steer_draft_operation_resolve(c.operation.operation.handle, terminal(STEER_PV1_OK)), STEER_PV1_OK);
    c.operation.operation.api->cancel(c.operation.operation.handle); /* success already won */
    CODE(steer_draft_operation_resolve(c.operation.operation.handle, terminal(STEER_PV1_IO)), STEER_PV1_POLICY_DENIED);
    CHECK(!c.calls);
    d.operation = steer_draft_operation_start(q, done, &d);
    d.operation.operation.api->cancel(d.operation.operation.handle);
    d.operation.operation.api->cancel(d.operation.operation.handle);
    CODE(steer_draft_operation_resolve(d.operation.operation.handle, terminal(STEER_PV1_OK)), STEER_PV1_POLICY_DENIED);
    CODE(steer_draft_operations_dispatch(q, 0, &n), STEER_PV1_OK);
    CHECK(!n && !c.calls && !d.calls);
    c.spawn = 1;
    CODE(steer_draft_operations_dispatch(q, UINT32_MAX, &n), STEER_PV1_OK);
    CHECK(n == 2 && c.calls == 1 && d.calls == 1 && !child_calls);
    CHECK(c.code == STEER_PV1_OK && d.code == STEER_PV1_CANCELLED);
    steer_draft_operations_usage(q, &live, &queued);
    CHECK(live == 3 && queued == 1);
    rejected(steer_draft_operation_start(q, done, &c), STEER_PV1_RESOURCE_EXHAUSTED);
    CODE(steer_draft_operations_destroy(q), STEER_PV1_POLICY_DENIED);
    c.operation.operation.api->cancel(c.operation.operation.handle); /* completed no-op */
    CODE(steer_draft_operation_release_checked(c.operation.operation.handle), STEER_PV1_OK);
    d.operation.operation.api->release(d.operation.operation.handle);
    CODE(steer_draft_operations_dispatch(q, 1, &n), STEER_PV1_OK);
    CHECK(n == 1 && child_calls == 1);
    c.child.operation.api->release(c.child.operation.handle);
    /* Explicit non-cancel failure is preserved unchanged and delivered once. */
    c.calls = 0;
    c.spawn = 0;
    c.operation = steer_draft_operation_start(q, done, &c);
    CODE(steer_draft_operation_resolve(c.operation.operation.handle, terminal(STEER_PV1_IO)), STEER_PV1_OK);
    CODE(steer_draft_operations_dispatch(q, 1, &n), STEER_PV1_OK);
    CHECK(n == 1 && c.calls == 1 && c.code == STEER_PV1_IO);
    CODE(steer_draft_operations_dispatch(q, 1, &n), STEER_PV1_OK);
    CHECK(!n && c.calls == 1);
    c.operation.operation.api->release(c.operation.operation.handle);
    steer_draft_operations_usage(q, &live, &queued);
    CHECK(!live && !queued);
    CODE(steer_draft_operations_destroy(q), STEER_PV1_OK);
    CHECK(!heap.live);
    CODE(steer_draft_operations_create(0, &a, &q), STEER_PV1_OK);
    rejected(steer_draft_operation_start(q, done, &c), STEER_PV1_RESOURCE_EXHAUSTED);
    CODE(steer_draft_operations_destroy(q), STEER_PV1_OK);
    CHECK(!heap.live);
    puts("draft operations: ok");
    return 0;
}
