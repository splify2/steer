/* Source-only host authorization, not a bearer credential or loader ABI. */
#ifndef STEER_EXPERIMENTAL_DEVICE_AUTHORITY_H
#define STEER_EXPERIMENTAL_DEVICE_AUTHORITY_H
#include <steer/draft/device_v1.h>
struct loop;
#define STEER_DRAFT_DEVICE_COMMIT 1u
#define STEER_DRAFT_DEVICE_QUIESCE 2u
#define STEER_DRAFT_DEVICE_RETIRE 3u
struct steer_draft_device_authorization {
 uint32_t operation,intent_sequence;uint64_t transaction,generation,instance_token;
 struct steer_pv1_span provider_id,provider_version,recovery_record;
};
/* Host-owned independent pin. Acquire consumes one matching cached claim BEFORE
 * enqueue. Hold through worker return, owner done return and origin op release.
 * Release never rearms a used claim or synchronously unloads enclosing code.
 * First checkpoint has no return-unused shortcut: rejected enqueue is recorded
 * UNCHANGED; retry requires a fresh intent. Future reuse must prove no admission. */
struct steer_draft_device_permit {void *context;void (*release)(void *);};
struct steer_draft_device_authority {
 struct loop *owner;void *context;
 /* Pure bounded owner-cache lookup, no IO. Exact operation/transaction/intent-sequence/gen/
  * instance/provider/version/recovery and host plan must match INTENT_SYNCED
  * plus durable ownership-anchor cleanup reserve. Reject missing/consumed/
  * uncertain entries. Any journal/coordinator uncertainty fences admission.
  * Request views borrowed during call; success returns independent permit. */
 struct steer_pv1_error (*acquire)(void *,const struct steer_draft_device_authorization *,struct steer_draft_device_permit *);
};
#endif
