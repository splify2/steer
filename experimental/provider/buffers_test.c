#include "buffers.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define CODE(x, c) CHECK((x).code == (c))
struct heap { unsigned live; int fail; };
static void *test_allocate(void *ctx, size_t n) {
    struct heap *h = ctx;
    void *p;
    if (h->fail) return NULL;
    p = malloc(n);
    if (p) h->live++;
    return p;
}
static void test_free(void *ctx, void *p) {
    struct heap *h = ctx;
    CHECK(h->live > 0);
    h->live--;
    free(p);
}
int main(void) {
    const struct steer_pv1_buffer_api *api = steer_draft_buffers_api();
    struct steer_draft_buffer_limits limits = {1024, 2, 2};
    struct heap heap = {0, 0};
    struct steer_draft_allocator allocator = {&heap, test_allocate, test_free};
    struct steer_pv1_host *host = NULL, *other = NULL;
    struct steer_pv1_buffer *a = NULL, *b = NULL, *c = NULL, *out;
    struct steer_pv1_mut_span view;
    uint64_t charge, bytes;
    uint32_t count;
    CHECK(api->size == sizeof(*api) && api->version == STEER_PV1_DRAFT_LAYOUT);
    CODE(steer_draft_buffers_create(NULL, NULL, &host), STEER_PV1_INVALID);
    CHECK(!host);
    heap.fail = 1;
    CODE(steer_draft_buffers_create(&limits, &allocator, &host), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!host && !heap.live);
    heap.fail = 0;
    CODE(steer_draft_buffers_create(&limits, &allocator, &host), STEER_PV1_OK);
    CODE(steer_draft_buffers_create(&limits, &allocator, &other), STEER_PV1_OK);
    CODE(api->allocate(host, 16, &a), STEER_PV1_OK);
    steer_draft_buffers_usage(host, &charge, &count);
    CHECK(charge >= 16 && count == 1);
    CODE(api->writable(host, a, &view), STEER_PV1_OK);
    CHECK(view.data && view.len == 16);
    view.data[15] = 91;
    CODE(api->retain(host, a), STEER_PV1_OK);
    CODE(api->retain(host, a), STEER_PV1_RESOURCE_EXHAUSTED);
    CODE(api->writable(host, a, &view), STEER_PV1_POLICY_DENIED);
    CHECK(!view.data && !view.len);
    api->release(host, a);
    /* Failed retain did not increment/wrap: one reference remains. */
    CODE(api->writable(host, a, &view), STEER_PV1_OK);
    CHECK(view.data[15] == 91);
    CODE(api->retain(other, a), STEER_PV1_INVALID);
    CODE(api->writable(other, a, &view), STEER_PV1_INVALID);
    CHECK(!view.data && !view.len);
    api->release(other, a); /* foreign release must not consume the reference */
    CODE(api->allocate(host, 0, &b), STEER_PV1_OK);
    CODE(api->writable(host, b, &view), STEER_PV1_OK);
    CHECK(!view.data && !view.len);
    out = a;
    CODE(api->allocate(host, 0, &out), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!out);
    CODE(steer_draft_buffers_destroy(host), STEER_PV1_RESOURCE_EXHAUSTED);
    api->release(host, b);
    heap.fail = 1;
    out = a;
    CODE(api->allocate(host, 1, &out), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!out);
    heap.fail = 0;
    steer_draft_buffers_usage(host, &bytes, &count);
    CHECK(bytes == charge && count == 1);
    api->release(host, a);
    steer_draft_buffers_usage(host, &bytes, &count);
    CHECK(!bytes && !count);
    CODE(api->allocate(NULL, 1, &out), STEER_PV1_INVALID);
    CHECK(!out);
    CODE(api->allocate(host, 1, NULL), STEER_PV1_INVALID);
    CODE(api->writable(host, NULL, &view), STEER_PV1_INVALID);
    CHECK(!view.data && !view.len);
    CODE(api->writable(host, NULL, NULL), STEER_PV1_INVALID);
    CODE(steer_draft_buffers_destroy(host), STEER_PV1_OK);
    /* Exact byte ceiling includes metadata; released capacity is reusable. */
    limits.max_bytes = charge;
    CODE(steer_draft_buffers_create(&limits, &allocator, &host), STEER_PV1_OK);
    CODE(api->allocate(host, 16, &a), STEER_PV1_OK);
    CODE(api->allocate(host, 0, &out), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!out);
    api->release(host, a);
    CODE(api->allocate(host, 17, &out), STEER_PV1_RESOURCE_EXHAUSTED);
    CHECK(!out);
    CODE(api->allocate(host, 16, &a), STEER_PV1_OK);
    api->release(host, a);
    CODE(steer_draft_buffers_destroy(host), STEER_PV1_OK);
    limits.max_bytes = 1024;
    limits.max_buffers = 3;
    CODE(steer_draft_buffers_create(&limits, &allocator, &host), STEER_PV1_OK);
    CODE(api->allocate(host, 1, &a), STEER_PV1_OK);
    CODE(api->allocate(host, 1, &b), STEER_PV1_OK);
    CODE(api->allocate(host, 1, &c), STEER_PV1_OK);
    api->release(host, b); /* middle unlink updates both neighbors */
    api->release(host, a); /* tail unlink */
    CODE(api->writable(host, c, &view), STEER_PV1_OK);
    api->release(host, c); /* head and final unlink */
    steer_draft_buffers_usage(host, &bytes, &count);
    CHECK(!bytes && !count);
    CODE(steer_draft_buffers_destroy(host), STEER_PV1_OK);
    CODE(steer_draft_buffers_destroy(other), STEER_PV1_OK);
    CHECK(!heap.live);
    limits.max_references = 0;
    CODE(steer_draft_buffers_create(&limits, &allocator, &host), STEER_PV1_INVALID);
    CHECK(!host);
    puts("draft buffers: ok");
    return 0;
}
