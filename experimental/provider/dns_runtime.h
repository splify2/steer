#ifndef STEER_DRAFT_DNS_RUNTIME_H
#define STEER_DRAFT_DNS_RUNTIME_H
#include "dns_wire.h"
#include <steer/draft/provider_v1.h>
struct loop;
struct steer_dns_runtime;
struct steer_dns_job;
typedef void (*steer_dns_exchange_done)(void *,uint32_t,const uint8_t *,size_t);
/* Private owner-loop transport contract, not a public SDK operation. start
 * copies bytes/selection/deadline before returning. 0 accepts and MUST issue one
 * deferred terminal callback, including after cancel; nonzero rejects without
 * callback. cancel is idempotent, detaches network IO before return and queues
 * terminal cancellation. Terminal is delivered only after private network IO,
 * operations, workers and timers are drained. The transport independently pins
 * its code/context/generation through terminal callback return. Context/provider
 * generation is additionally pinned by the host until runtime destroy succeeds.
 * No independent DNS, socket or direct-route fallback.
 * Selection is an immutable host binding index, never peer-supplied authority. */
struct steer_dns_exchange {
    void *context;
    uint32_t (*start)(void *,uint32_t,const uint8_t *,size_t,uint64_t,steer_dns_exchange_done,void *,void **);
    void (*cancel)(void *,void *);
};
typedef void (*steer_dns_done)(void *,uint32_t,const uint8_t *,size_t,const struct steer_dns_answer *);
/* Exactly max_jobs fixed packet slots, no per-query allocations/threads. All
 * calls/callbacks serialized on owner. Deadline absolute monotonic ns. Runtime
 * adds a deferred terminal turn even if transport callback already deferred.
 * Successful submit gives exactly one terminal callback, cancel included. Handle
 * expires at callback entry; result/packet borrowed during callback. ipv4_only
 * synthesizes empty NOERROR for AAAA without contacting transport. */
uint32_t steer_dns_runtime_create(struct loop *,uint32_t,const struct steer_dns_exchange *,struct steer_dns_runtime **);
uint32_t steer_dns_submit(struct steer_dns_runtime *,uint32_t,const uint8_t *,size_t,uint64_t,int,steer_dns_done,void *,struct steer_dns_job **);
void steer_dns_cancel(struct steer_dns_job *);
void steer_dns_quiesce(struct steer_dns_runtime *);
uint32_t steer_dns_runtime_destroy(struct steer_dns_runtime *);
uint32_t steer_dns_runtime_jobs(const struct steer_dns_runtime *);
#endif
