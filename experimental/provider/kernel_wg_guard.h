#ifndef STEER_DRAFT_KERNEL_WG_GUARD_H
#define STEER_DRAFT_KERNEL_WG_GUARD_H
#include "kernel_wg.h"
#include "policy.h"
struct steer_draft_kernel_wg_guard;
#define STEER_DRAFT_WG_GUARD_UNCHANGED 0u
#define STEER_DRAFT_WG_GUARD_CHANGED 1u
#define STEER_DRAFT_WG_GUARD_UNCERTAIN 2u
struct steer_draft_kernel_wg_guard_result {
    struct steer_pv1_error error;
    uint32_t phase;
};
/* UNCHANGED means no own transaction committed. CHANGED means a kernel echo
 * confirmed the new table identity, even if the tool later reported error:
 * ownership transfers and caller must publish/report the matching policy.
 * UNCERTAIN retains both contexts and quiesces only the captured owned WG
 * interface before return. Never report an unchanged runtime/rollback success;
 * recover explicitly after owned device retirement and table reconciliation. */
#define STEER_DRAFT_WG_GUARD_RULES 128u
struct steer_draft_kernel_wg_guard_config {
    uint64_t generation;
    char inbound_id[65],device[16];
    uint32_t peer_count;
    struct {
        char principal_id[65];
        uint32_t allowed_count;
        char allowed_ips[STEER_DRAFT_WG_PREFIXES][64];
    } peers[STEER_DRAFT_WG_PEERS];
    /* Client-only outbound device: permit authenticated return traffic, not
     * peer-initiated connections to this host. */
    int return_only;
};
/* No kernel mutation; compiles shared immutable policy visitor into existing
 * nft IR. Overlapping peer prefixes and applicable domain rules fail closed.
 * Nonmatching inbound/principal rules remain unrelated and are skipped.
 * Input policy/config may be freed after success. */
struct steer_pv1_error steer_draft_kernel_wg_guard_prepare(
    const struct steer_draft_kernel_wg_guard_config *,const struct steer_policy *,
    struct steer_draft_kernel_wg_guard **);
/* Signature matches kernel_wg_before_up. Creates exclusive owned nft table
 * matching captured iif index with DROP. Must run before configure brings UP. */
struct steer_pv1_error steer_draft_kernel_wg_guard_bind(void *,const char *,int);
/* Atomic per-packet replacement; existing WG flows may change policy. Inspect
 * phase even on error. Namespace/table handle/interface identity checked. */
struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_publish(struct steer_draft_kernel_wg_guard *);
/* Prepared replacement with identical device/peer identity mapping. Atomic
 * policy-only update preserves the owned table handle; on success ownership
 * transfers to prepared and active can be destroyed. Failure preserves active. */
struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_replace(
    struct steer_draft_kernel_wg_guard *active,struct steer_draft_kernel_wg_guard *prepared);
/* Caller removes the owned WG device BEFORE removing its guard. The captured
 * ifindex must be absent in the owning namespace; an inconclusive lookup or
 * foreign nft table replacement is refused. Destroy refuses a still-owned table. */
struct steer_pv1_error steer_draft_kernel_wg_guard_retire(struct steer_draft_kernel_wg_guard *);
struct steer_pv1_error steer_draft_kernel_wg_guard_destroy(struct steer_draft_kernel_wg_guard *);
/* Read-only recovery after explicit external cleanup: requires owned WG device
 * gone and table absent. Clears an unknown-commit identity; never adopts/deletes
 * a table observed by name. Until reconciled, uncertain handles refuse destroy. */
struct steer_pv1_error steer_draft_kernel_wg_guard_reconcile_absent(struct steer_draft_kernel_wg_guard *);
const char *steer_draft_kernel_wg_guard_table(const struct steer_draft_kernel_wg_guard *);

struct steer_draft_wg_guard_record;
/* Enables managed use of this prepared guard, assigning its marker before
 * the first effect. Copy the plan into the durable intent before bind. */
int steer_draft_kernel_wg_guard_plan(struct steer_draft_kernel_wg_guard *,char table[26],char marker[42]);
/* A CHANGED result carries the exact newly created handle, even on a tool
 * error. Recovery after UNCERTAIN does not adopt a marker-only match. */
struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_apply_owned(
    struct steer_draft_kernel_wg_guard *,const struct steer_draft_wg_guard_record *,
    int pinned_netns_fd,int publish,uint64_t deadline,uint64_t *captured_handle);
int steer_draft_kernel_wg_guard_retire_record(const struct steer_draft_wg_guard_record *,
    int pinned_netns_fd,uint64_t deadline);
/* Memory only. Managed callers retain kernel responsibility in the journal. */
void steer_draft_kernel_wg_guard_forget_prepared(struct steer_draft_kernel_wg_guard *);
#endif
