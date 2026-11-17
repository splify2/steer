#ifndef STEER_DRAFT_KERNEL_WG_OWNERSHIP_H
#define STEER_DRAFT_KERNEL_WG_OWNERSHIP_H
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#define STEER_DRAFT_WG_RECORD_BYTES 128u
struct steer_draft_wg_identity {
    uint64_t generation,instance_token,namespace_device,namespace_inode;
    uint8_t boot_id[16],intent_id[16];
    char physical_name[16],kind[16];
    uint32_t group;
};
#define STEER_DRAFT_WG_ABSENT 1u
#define STEER_DRAFT_WG_OWNED 2u
#define STEER_DRAFT_WG_FOREIGN 3u
#define STEER_DRAFT_WG_UNKNOWN 4u
struct steer_draft_wg_observation { uint32_t state,effect;int index,error; };
/* Worker-only blocking primitives, not a factory or private journal. Caller
 * owns/pins namespace_fd through return and enters that namespace on its bounded
 * worker. Every call verifies current thread namespace, pinned fd and boot.
 * Record is nonsecret provider version1, no descriptors/pointers/key material.
 * Coordinator copies/persists exact record before any create. */
int steer_draft_wg_identity_prepare(int namespace_fd,uint64_t generation,uint64_t instance_token,
    const char *kind,uint64_t deadline_ns,const atomic_uint *cancel,struct steer_draft_wg_identity *);
int steer_draft_wg_identity_encode(const struct steer_draft_wg_identity *,uint8_t out[STEER_DRAFT_WG_RECORD_BYTES]);
int steer_draft_wg_identity_decode(const uint8_t *,size_t,struct steer_draft_wg_identity *);
int steer_draft_wg_identity_reconcile(const struct steer_draft_wg_identity *,int namespace_fd,
    uint64_t deadline_ns,struct steer_draft_wg_observation *);
/* Create only a DOWN device, never keys/guard/publish. Before-effect cancel is
 * unchanged; an error after possible kernel effect remains uncertain. */
int steer_draft_wg_identity_create(const struct steer_draft_wg_identity *,int namespace_fd,
    int mtu,uint64_t deadline_ns,const atomic_uint *cancel,struct steer_draft_wg_observation *);
/* Fresh reconciliation then guarded precise-index cleanup. Foreign or wrong
 * boot/ns refuses all mutation; repeated absent recovery is read-only. */
int steer_draft_wg_identity_retire(const struct steer_draft_wg_identity *,int namespace_fd,
    uint64_t deadline_ns,const atomic_uint *cancel,struct steer_draft_wg_observation *);
#endif
