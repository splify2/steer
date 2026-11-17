#ifndef STEER_EXPERIMENTAL_STREAM_H
#define STEER_EXPERIMENTAL_STREAM_H
#include <steer/draft/stream_v1.h>
struct loop;
struct steer_draft_stream_runtime;
/* Linux only, serialized on loop shard. Loop and buffer host outlive runtime.
 * Byte budget charges full submitted lengths until IO is detached. Operation
 * limit includes terminal unreleased handles. No hidden payload copies. */
struct steer_pv1_error steer_draft_stream_runtime_create(struct loop *,
    struct steer_pv1_host *, uint32_t max_streams, uint32_t max_operations,
    uint64_t max_queued_bytes, struct steer_draft_stream_runtime **);
struct steer_pv1_error steer_draft_stream_runtime_destroy(struct steer_draft_stream_runtime *);
/* Success consumes connected SOCK_STREAM fd and sets O_NONBLOCK/FD_CLOEXEC.
 * Failure leaves ownership with caller (flags may have changed). */
struct steer_pv1_error steer_draft_stream_adopt(struct steer_draft_stream_runtime *,
    int fd, struct steer_pv1_stream **);
const struct steer_pv1_stream_api *steer_draft_stream_api(void);
#endif
