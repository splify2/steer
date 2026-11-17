#include "operations.h"
#include <stdlib.h>

enum operation_state { UNRESOLVED, QUEUED, CALLING, COMPLETED };
struct steer_pv1_operation {
    struct steer_draft_operations *owner;
    struct steer_pv1_operation *next;
    steer_draft_operation_done done;
    void *userdata;
    struct steer_pv1_error terminal;
    enum operation_state state;
};
struct steer_draft_operations {
    struct steer_draft_operation_allocator allocator;
    struct steer_pv1_operation *head, *tail;
    uint32_t max_live, live, queued;
    int dispatching;
};
static struct steer_pv1_error error(uint32_t code) {
    struct steer_pv1_error e = {code, 0};
    return e;
}
static void *default_allocate(void *ctx, size_t bytes) {
    (void)ctx;
    return malloc(bytes);
}
static void default_deallocate(void *ctx, void *p) {
    (void)ctx;
    free(p);
}
struct steer_pv1_error steer_draft_operations_create(uint32_t max_live,
    const struct steer_draft_operation_allocator *allocator, struct steer_draft_operations **out) {
    struct steer_draft_operation_allocator a = {NULL, default_allocate, default_deallocate};
    struct steer_draft_operations *q;
    if (out) *out = NULL;
    if (!out || (allocator && (!allocator->allocate || !allocator->deallocate)))
        return error(STEER_PV1_INVALID);
    if (allocator) a = *allocator;
    q = a.allocate(a.context, sizeof(*q));
    if (!q) return error(STEER_PV1_RESOURCE_EXHAUSTED);
    q->allocator = a;
    q->head = q->tail = NULL;
    q->max_live = max_live;
    q->live = q->queued = 0;
    q->dispatching = 0;
    *out = q;
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_operations_destroy(struct steer_draft_operations *q) {
    struct steer_draft_operation_allocator a;
    if (!q) return error(STEER_PV1_INVALID);
    if (q->live || q->dispatching) return error(STEER_PV1_POLICY_DENIED);
    a = q->allocator;
    a.deallocate(a.context, q);
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_operation_resolve(struct steer_pv1_operation *op,
    struct steer_pv1_error terminal) {
    struct steer_draft_operations *q;
    if (!op || terminal.code > STEER_PV1_INTERNAL || terminal.transient > 1 ||
        (terminal.code == STEER_PV1_OK && terminal.transient)) return error(STEER_PV1_INVALID);
    if (op->state != UNRESOLVED) return error(STEER_PV1_POLICY_DENIED);
    q = op->owner;
    op->terminal = terminal;
    op->state = QUEUED;
    op->next = NULL;
    if (q->tail) q->tail->next = op;
    else q->head = op;
    q->tail = op;
    q->queued++;
    return error(STEER_PV1_OK);
}
static void STEER_PV1_CALL cancel_operation(struct steer_pv1_operation *op) {
    if (op && op->state == UNRESOLVED)
        (void)steer_draft_operation_resolve(op, error(STEER_PV1_CANCELLED));
}
struct steer_pv1_error steer_draft_operation_release_checked(struct steer_pv1_operation *op) {
    struct steer_draft_operations *q;
    if (!op) return error(STEER_PV1_INVALID);
    if (op->state != COMPLETED) return error(STEER_PV1_POLICY_DENIED);
    q = op->owner;
    q->live--;
    q->allocator.deallocate(q->allocator.context, op);
    return error(STEER_PV1_OK);
}
static void STEER_PV1_CALL release_operation(struct steer_pv1_operation *op) {
    (void)steer_draft_operation_release_checked(op);
}
static const struct steer_pv1_operation_api api = {
    sizeof(struct steer_pv1_operation_api), STEER_PV1_DRAFT_LAYOUT,
    cancel_operation, release_operation
};
struct steer_pv1_async_start steer_draft_operation_start(struct steer_draft_operations *q,
    steer_draft_operation_done done, void *userdata) {
    struct steer_pv1_async_start r = {
        STEER_PV1_REJECTED, {STEER_PV1_INVALID, 0}, {NULL, NULL}
    };
    struct steer_pv1_operation *op;
    if (!q || !done) return r;
    r.error = error(STEER_PV1_RESOURCE_EXHAUSTED);
    if (q->live >= q->max_live) return r;
    op = q->allocator.allocate(q->allocator.context, sizeof(*op));
    if (!op) return r;
    op->owner = q;
    op->next = NULL;
    op->done = done;
    op->userdata = userdata;
    op->state = UNRESOLVED;
    op->terminal = error(STEER_PV1_INTERNAL);
    q->live++;
    r.disposition = STEER_PV1_PENDING;
    r.error = error(STEER_PV1_OK);
    r.operation.handle = op;
    r.operation.api = &api;
    return r;
}
struct steer_pv1_error steer_draft_operations_dispatch(struct steer_draft_operations *q,
    uint32_t max_count, uint32_t *dispatched) {
    uint32_t limit, n;
    if (dispatched) *dispatched = 0;
    if (!q) return error(STEER_PV1_INVALID);
    if (q->dispatching) return error(STEER_PV1_POLICY_DENIED);
    limit = q->queued < max_count ? q->queued : max_count;
    q->dispatching = 1;
    for (n = 0; n < limit; n++) {
        struct steer_pv1_operation *op = q->head;
        q->head = op->next;
        if (!q->head) q->tail = NULL;
        q->queued--;
        op->next = NULL;
        op->state = CALLING;
        op->done(op->userdata, op->terminal);
        op->state = COMPLETED;
    }
    q->dispatching = 0;
    if (dispatched) *dispatched = n;
    return error(STEER_PV1_OK);
}
void steer_draft_operations_usage(const struct steer_draft_operations *q,
    uint32_t *live, uint32_t *queued) {
    if (live) *live = q ? q->live : 0;
    if (queued) *queued = q ? q->queued : 0;
}
