#ifndef STEER_DRAFT_KERNEL_WG_H
#define STEER_DRAFT_KERNEL_WG_H
#include <steer/draft/provider_v1.h>
#define STEER_DRAFT_WG_PEERS 8u
#define STEER_DRAFT_WG_PREFIXES 8u
struct steer_draft_kernel_wg;
struct steer_draft_kernel_wg_peer {
    char public_key[45];
    uint32_t allowed_count;
    char allowed_ips[STEER_DRAFT_WG_PREFIXES][64];
    char preshared_key_ref[100]; /* empty => no PSK */
};
struct steer_draft_kernel_wg_config {
    uint64_t generation;
    char inbound_id[65], device[16], private_key_ref[100];
    uint16_t listen_port, mtu; /* mtu 0 => 1420 */
    uint32_t fwmark, address_count, peer_count;
    char addresses[STEER_DRAFT_WG_PREFIXES][64];
    struct steer_draft_kernel_wg_peer peers[STEER_DRAFT_WG_PEERS];
};
/* Host secret service writes one 44-byte base64 key, no NUL required. Reference
 * is borrowed on callback only. Provider never logs keys or puts them in config.
 * All calls same serialized owning thread/net namespace; no callback reentry. */
typedef struct steer_pv1_error (*steer_draft_kernel_wg_secret)(void *,
    struct steer_pv1_span reference,uint8_t out_key[44]);
/* Source-only kernel device lifecycle, not stream/accepted-flow ABI. Pure kernel
 * WireGuard only; no Endpoint is required or emitted for inbound peers. Prepare
 * resolves bounded refs into a sealed anonymous memfd, validates existing awg
 * parser, records namespace and verifies device absent; no network mutation. */
struct steer_pv1_error steer_draft_kernel_wg_prepare(
    const struct steer_draft_kernel_wg_config *,steer_draft_kernel_wg_secret,
    void *,struct steer_draft_kernel_wg **);
/* Exclusive creation, existing awg_dev_configure, verified ownership/interface.
 * Failure rolls back only the newly created captured interface. Never adopts
 * an existing device. A different device name/port is needed for overlap reload;
 * there is no fake atomic in-place swap. CAP_NET_ADMIN is required here. */
struct steer_pv1_error steer_draft_kernel_wg_activate(struct steer_draft_kernel_wg *);
/* Fresh exclusive device is DOWN. Host installs fail-closed packet guard before
 * returning OK; callback failure rolls back only the captured owned device. */
typedef struct steer_pv1_error (*steer_draft_kernel_wg_before_up)(void *,const char *,int);
struct steer_pv1_error steer_draft_kernel_wg_activate_guarded(struct steer_draft_kernel_wg *,
    steer_draft_kernel_wg_before_up,void *);
/* Same cleanup for failed activation and retired generation; idempotent. Name,
 * kernel kind, captured ifindex and owning namespace must match. Foreign
 * replacement => POLICY_DENIED, never delete it. Kernel key/session state is
 * removed by deleting only the owned device. */
struct steer_pv1_error steer_draft_kernel_wg_rollback(struct steer_draft_kernel_wg *);
struct steer_pv1_error steer_draft_kernel_wg_retire(struct steer_draft_kernel_wg *);
/* Refuses an owned active device; after rollback/retire closes secret memfd.
 * Only host-minted handle valid; no stale/forged pointer protection. */
struct steer_pv1_error steer_draft_kernel_wg_destroy(struct steer_draft_kernel_wg *);
int steer_draft_kernel_wg_index(const struct steer_draft_kernel_wg *);
#endif
