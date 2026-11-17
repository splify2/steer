/* Static implementation inventory, not runtime permission or backend detection.
 * Independent of platform_ops and the legacy net1 ABI. Not yet a host export.
 * Android here means the existing privileged Android backend, not VpnService.
 * Linux NO describes the absent standalone profile, not whether today's
 * OpenWrt-profile binaries can execute on a generic Linux host. */
#ifndef STEER_PLATFORM_CAPABILITIES_H
#define STEER_PLATFORM_CAPABILITIES_H
#include <stdint.h>

#define STEER_PLATFORM_CAPABILITY_VERSION 1u
enum steer_capability_state {
    STEER_CAP_UNKNOWN = 0,
    STEER_CAP_NO = 1,
    STEER_CAP_YES = 2
};
enum steer_platform_capability {
    STEER_CAP_LEGACY_PROFILE = 0,
    STEER_CAP_NFT_ROUTE,
    STEER_CAP_TUN,
    STEER_CAP_EXEC_HELPERS,
    STEER_CAP_COUNT
};
struct steer_platform_capability_info {
    uint32_t size;
    uint32_t version;
    uint32_t supported;
    uint32_t built;
    uint32_t available;
    uint32_t authorized;
};
/* Exact lowercase platform names: linux, openwrt, windows, android, ios.
 * supported describes checked-in Steer implementation, not OS potential.
 * built/available/authorized are UNKNOWN until a build/runtime integration can
 * provide evidence; this standalone query never probes or selects a platform.
 * Returns 0 on success, -1 on invalid input; failure leaves out untouched.
 * Caller passes its allocated size. Larger buffers are accepted; their tail is
 * untouched. Smaller buffers are rejected without writing a partial result. */
int steer_platform_capability_query(const char *platform,
    enum steer_platform_capability capability,
    struct steer_platform_capability_info *out, uint32_t out_size);
#endif
