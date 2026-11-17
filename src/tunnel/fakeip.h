#ifndef STEER_TUNNEL_FAKEIP_H
#define STEER_TUNNEL_FAKEIP_H
#include "dialer.h"

/* Internal admission service, not a net1 ABI. Numeric destinations bypass it.
 * submit takes fd ownership only on success. Completion transfers that one fd
 * exactly once; destroy closes outstanding admissions without callbacks.
 * Workers are owned by one loop thread. Do not destroy a worker from inside its
 * completion callback/pump, and destroy all workers before their service. */
#define FAKEIP_PENDING_MAX 64u
#define FAKEIP_LOOKUP_MS 200u
#define FAKEIP_ENTRY_MAX 131072u
#define FAKEIP_FILE_MAX (FAKEIP_ENTRY_MAX * 512u)
struct fakeip_service;
struct fakeip_worker;
typedef void (*fakeip_complete_fn)(void *, int, const struct flow_key *, int);
struct fakeip_service *fakeip_service_create(const char *path);
/* Joins the sole refresh thread. Slow filesystem IO may delay this join; the
 * service and snapshots remain alive until it finishes. Never called on loop. */
void fakeip_service_destroy(struct fakeip_service *);
struct fakeip_worker *fakeip_worker_create(struct fakeip_service *, const char *table,
                                         fakeip_complete_fn, void *);
void fakeip_worker_destroy(struct fakeip_worker *);
int fakeip_worker_fd(const struct fakeip_worker *);
int fakeip_worker_submit(struct fakeip_worker *, int, const struct flow_key *, uint64_t accepted_ns);
void fakeip_worker_pump(struct fakeip_worker *, uint64_t now_ns);
int fakeip_worker_wait(const struct fakeip_worker *, uint64_t now_ns);
/* Bounded parser seam for deterministic malformed/late reply tests. Production
 * calls it only after recvmsg validates the kernel sender and truncation flags. */
void fakeip_worker_receive(struct fakeip_worker *, const void *, size_t, uint32_t sender,
                           unsigned flags, uint64_t now_ns);
#endif
