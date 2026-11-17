#ifndef STEER_EXPERIMENTAL_DATAGRAM_H
#define STEER_EXPERIMENTAL_DATAGRAM_H
#include <steer/draft/datagram_v1.h>
struct loop;
struct steer_draft_resolver;
struct steer_draft_datagram_runtime;
/* Low-level backend: routing must enforce exact generation and hold its lease
 * through returned associations and every operation, including queued opens.
 * Linux native connected UDP, same loop/buffer/operation services. Limits count
 * pending and completed-unreleased operations, and full submitted IO lengths. */
struct steer_pv1_error steer_draft_datagram_runtime_create(struct loop *,
    struct steer_pv1_host *,uint32_t max_associations,uint32_t max_operations,
    uint64_t max_queued_bytes,struct steer_draft_datagram_runtime **);
struct steer_pv1_error steer_draft_datagram_runtime_destroy(struct steer_draft_datagram_runtime *);
/* Attach before opening. Retained until runtime destruction. */
struct steer_pv1_error steer_draft_datagram_use_resolver(struct steer_draft_datagram_runtime *,struct steer_draft_resolver *);
/* Owner-only cached service capability, for truthful prepared binding flags. */
int steer_draft_datagram_has_resolver(const struct steer_draft_datagram_runtime *);
const struct steer_pv1_datagram_backend_api *steer_draft_datagram_backend_api(void);
/* Test/host-owned connected UDP fd adoption: success consumes fd, failure leaves
 * caller ownership (flags may have changed). No descriptor crosses public ABI. */
struct steer_pv1_error steer_draft_datagram_adopt(struct steer_draft_datagram_runtime *,int,
    struct steer_pv1_datagram_ref *);
#endif
