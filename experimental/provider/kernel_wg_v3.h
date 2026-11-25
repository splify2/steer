#ifndef STEER_DRAFT_KERNEL_WG_V3_H
#define STEER_DRAFT_KERNEL_WG_V3_H
#include "awg.h"
#include "kernel_wg_guard.h"

struct steer_spec_plan;
struct ynode;
struct steer_draft_wg_v3_config {
    struct awg_conf kernel;
    struct steer_draft_kernel_wg_guard_config guard;
    char private_key[64], preshared_keys[STEER_DRAFT_WG_PEERS][64];
};

int steer_draft_wg_v3_options(void *, const struct ynode *);
/* No IO: lower one enabled default WireGuard device inbound. The coordinator
 * supplies guard generation and physical name from the owned link identity. */
int steer_draft_wg_v3_configure(const struct steer_spec_plan *, uint32_t,
    struct steer_draft_wg_v3_config *);
/* Opt-in kernel-backed TCP egress: one numeric UDP peer, one IPv4 /32 source
 * and one explicit route equal to its sole AllowedIPs prefix. */
int steer_draft_wg_v3_egress_options(void *,const struct ynode *);
int steer_draft_wg_v3_egress(const struct steer_spec_plan *,uint32_t,
    struct steer_draft_wg_v3_config *,struct awg_prefix *route);
/* Resolver receives validated secret declaration IDs, not names or values from
 * intent. On failure keys are wiped; on success caller must wipe after use. */
struct steer_pv1_error steer_draft_wg_v3_keys(const struct steer_draft_wg_v3_config *,
    steer_draft_kernel_wg_secret, void *, struct awg_secrets *);
#endif
