#include "host.h"
#include <stdlib.h>

struct steer_pv1_buffer {
    struct steer_pv1_host *owner;
    struct steer_pv1_buffer *previous;
    struct steer_pv1_buffer *next;
    uint32_t references;
    uint32_t capacity;
    uint8_t data[];
};
struct steer_pv1_host {
    struct steer_draft_buffer_limits limits;
    struct steer_draft_allocator allocator;
    struct steer_pv1_buffer *head;
    uint64_t bytes;
    uint32_t buffers;
    const struct steer_draft_host_services *services;
};
static struct steer_pv1_error result(uint32_t code) {
    struct steer_pv1_error e = {code, 0};
    return e;
}
static void *default_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}
static void default_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}
/* Handles must be valid/live. This is not a forged/stale-pointer sandbox. */
static int owned(struct steer_pv1_host *h, struct steer_pv1_buffer *b) {
    return h && b && b->owner == h;
}
static struct steer_pv1_error STEER_PV1_CALL allocate_buffer(
    struct steer_pv1_host *h, uint32_t capacity, struct steer_pv1_buffer **out) {
    uint64_t charge = (uint64_t)sizeof(struct steer_pv1_buffer) + capacity;
    struct steer_pv1_buffer *b;
    if (out) *out = NULL;
    if (!h || !out) return result(STEER_PV1_INVALID);
    if (charge > SIZE_MAX || h->buffers >= h->limits.max_buffers ||
        charge > h->limits.max_bytes - h->bytes)
        return result(STEER_PV1_RESOURCE_EXHAUSTED);
    b = h->allocator.allocate(h->allocator.context, (size_t)charge);
    if (!b) return result(STEER_PV1_RESOURCE_EXHAUSTED);
    b->references = 1;
    b->capacity = capacity;
    b->owner = h;
    b->previous = NULL;
    b->next = h->head;
    if (h->head) h->head->previous = b;
    h->head = b;
    h->bytes += charge;
    h->buffers++;
    *out = b;
    return result(STEER_PV1_OK);
}
static struct steer_pv1_error STEER_PV1_CALL retain_buffer(
    struct steer_pv1_host *h, struct steer_pv1_buffer *b) {
    if (!owned(h, b)) return result(STEER_PV1_INVALID);
    if (b->references >= h->limits.max_references)
        return result(STEER_PV1_RESOURCE_EXHAUSTED);
    b->references++;
    return result(STEER_PV1_OK);
}
static void STEER_PV1_CALL release_buffer(struct steer_pv1_host *h,
                                         struct steer_pv1_buffer *b) {
    if (!owned(h, b)) return;
    if (--b->references) return;
    if (b->previous) b->previous->next = b->next;
    else h->head = b->next;
    if (b->next) b->next->previous = b->previous;
    h->bytes -= (uint64_t)sizeof(*b) + b->capacity;
    h->buffers--;
    h->allocator.deallocate(h->allocator.context, b);
}
static struct steer_pv1_error STEER_PV1_CALL writable_buffer(
    struct steer_pv1_host *h, struct steer_pv1_buffer *b,
    struct steer_pv1_mut_span *out) {
    if (out) { out->data = NULL; out->len = 0; }
    if (!out || !owned(h, b)) return result(STEER_PV1_INVALID);
    if (b->references != 1) return result(STEER_PV1_POLICY_DENIED);
    out->data = b->capacity ? b->data : NULL;
    out->len = b->capacity;
    return result(STEER_PV1_OK);
}
static const struct steer_pv1_buffer_api api = {
    sizeof(struct steer_pv1_buffer_api), STEER_PV1_DRAFT_LAYOUT,
    allocate_buffer, retain_buffer, release_buffer, writable_buffer
};
const struct steer_pv1_buffer_api *steer_draft_buffers_api(void) { return &api; }
struct steer_pv1_error steer_draft_buffers_create(
    const struct steer_draft_buffer_limits *limits,
    const struct steer_draft_allocator *allocator, struct steer_pv1_host **out) {
    struct steer_draft_allocator a = {NULL, default_allocate, default_deallocate};
    struct steer_pv1_host *h;
    if (out) *out = NULL;
    if (!out || !limits || !limits->max_references ||
        (allocator && (!allocator->allocate || !allocator->deallocate)))
        return result(STEER_PV1_INVALID);
    if (allocator) a = *allocator;
    h = a.allocate(a.context, sizeof(*h));
    if (!h) return result(STEER_PV1_RESOURCE_EXHAUSTED);
    h->limits = *limits;
    h->allocator = a;
    h->head = NULL;
    h->bytes = 0;
    h->buffers = 0;
    h->services = NULL;
    *out = h;
    return result(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_buffers_destroy(struct steer_pv1_host *h) {
    struct steer_draft_allocator a;
    if (!h) return result(STEER_PV1_INVALID);
    if (h->buffers) return result(STEER_PV1_RESOURCE_EXHAUSTED);
    a = h->allocator;
    a.deallocate(a.context, h);
    return result(STEER_PV1_OK);
}
void steer_draft_buffers_usage(const struct steer_pv1_host *h,
                              uint64_t *bytes, uint32_t *buffers) {
    if (bytes) *bytes = h ? h->bytes : 0;
    if (buffers) *buffers = h ? h->buffers : 0;
}

static struct steer_pv1_error STEER_PV1_CALL host_get_table(
    struct steer_pv1_host *h, uint32_t id, uint32_t layout, const void **out) {
    if (out) *out = NULL;
    if (!h || !out) return result(STEER_PV1_INVALID);
    if (!h->services || id != STEER_PV1_TABLE_BUFFERS || layout != STEER_PV1_DRAFT_LAYOUT)
        return result(STEER_PV1_UNSUPPORTED);
    *out = &api;
    return result(STEER_PV1_OK);
}
static uint64_t STEER_PV1_CALL host_monotonic_ns(struct steer_pv1_host *h) {
    /* Only configured live hosts may use this table: never invent a clock. */
    return h->services->monotonic_ns(h->services->context);
}
static void STEER_PV1_CALL host_log(struct steer_pv1_host *h, uint32_t severity,
                                  struct steer_pv1_span message) {
    if (message.len > STEER_DRAFT_HOST_LOG_MAX || (!message.data && message.len) ||
        (severity != 3 && severity != 4 && severity != 6 && severity != 7)) return;
    h->services->log(h->services->context, severity, message);
}
static const struct steer_pv1_host_api host_api = {
    sizeof(struct steer_pv1_host_api), STEER_PV1_DRAFT_LAYOUT, 1, 0,
    host_get_table, host_monotonic_ns, host_log
};
struct steer_pv1_error steer_draft_host_create(
    const struct steer_draft_buffer_limits *limits, const struct steer_draft_allocator *allocator,
    const struct steer_draft_host_services *services, struct steer_pv1_host **out) {
    struct steer_pv1_error e;
    if (out) *out = NULL;
    if (!out || !services || !services->monotonic_ns || !services->log)
        return result(STEER_PV1_INVALID);
    e = steer_draft_buffers_create(limits, allocator, out);
    if (e.code == STEER_PV1_OK) (*out)->services = services;
    return e;
}
struct steer_pv1_error steer_draft_host_get_api(struct steer_pv1_host *h,
    const struct steer_pv1_host_api **out) {
    if (out) *out = NULL;
    if (!h || !out) return result(STEER_PV1_INVALID);
    if (!h->services) return result(STEER_PV1_UNSUPPORTED);
    *out = &host_api;
    return result(STEER_PV1_OK);
}
