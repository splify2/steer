#ifndef STEER_DRAFT_RESOLVER_H
#define STEER_DRAFT_RESOLVER_H
#include <steer/draft/provider_v1.h>
#include <sys/socket.h>
struct loop;
struct steer_draft_resolver;
struct steer_draft_resolve_job;
#define STEER_DRAFT_RESOLVE_ADDRESSES 8u
struct steer_draft_resolve_result {
    uint32_t code, count;
    struct sockaddr_storage addresses[STEER_DRAFT_RESOLVE_ADDRESSES];
};
/* Backend runs only on fixed workers; must fully initialize result. Host string
 * is NUL-terminated, bounded validated ASCII DNS; port host order. Backend/context
 * outlive pool. NULL backend uses NSS getaddrinfo, never on loop thread. */
typedef void (*steer_draft_resolve_backend)(void *,const char *,uint16_t,
    struct steer_draft_resolve_result *);
typedef void (*steer_draft_resolve_done)(void *,const struct steer_draft_resolve_result *);
struct steer_pv1_error steer_draft_resolver_create(struct loop *,uint32_t workers,
    uint32_t max_jobs,steer_draft_resolve_backend,void *,struct steer_draft_resolver **);
/* All public calls/terminal callbacks serialized on loop shard. Callback result
 * borrowed until return. Job handle expires at callback entry. Submission failure
 * gives no callback and clears out. Cancellation consumes handle, detaches callback
 * synchronously, but an already running NSS call keeps a bounded pool slot.
 * No pthread_cancel, thread-per-flow, synchronous fallback, or unsafe early free. */
struct steer_pv1_error steer_draft_resolver_submit(struct steer_draft_resolver *,
    struct steer_pv1_span host,uint16_t port,steer_draft_resolve_done,void *,
    struct steer_draft_resolve_job **);
void steer_draft_resolver_cancel(struct steer_draft_resolve_job *);
/* Users bind lifetime (e.g. route generations). Destroy refuses users/jobs,
 * including cancelled NSS still running. Caller must continue loop until idle.
 * Arbitrarily stuck NSS cannot be forcefully killed safely; shutdown waits. */
struct steer_pv1_error steer_draft_resolver_retain(struct steer_draft_resolver *);
void steer_draft_resolver_release(struct steer_draft_resolver *);
struct steer_pv1_error steer_draft_resolver_destroy(struct steer_draft_resolver *);
uint32_t steer_draft_resolver_jobs(struct steer_draft_resolver *);
#endif
