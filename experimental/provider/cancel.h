/* Source-only cooperative cancellation, borrowed through work return. */
#ifndef STEER_EXPERIMENTAL_CANCEL_H
#define STEER_EXPERIMENTAL_CANCEL_H
#include <stdatomic.h>
struct steer_draft_cancel {atomic_uint requested;};
/* Origin holds storage through every reader return; request is monotonic0->1.
 * Cancellation never rewrites an already committed/factual effect result. */
#endif
