#include "capabilities.h"
#include <string.h>

int steer_platform_capability_query(const char *platform,
    enum steer_platform_capability capability,
    struct steer_platform_capability_info *out, uint32_t out_size) {
    int implemented;
    struct steer_platform_capability_info value = {
        sizeof(struct steer_platform_capability_info),
        STEER_PLATFORM_CAPABILITY_VERSION,
        STEER_CAP_NO, STEER_CAP_NO, STEER_CAP_NO, STEER_CAP_NO
    };
    if (!platform || !out || out_size < sizeof(value) ||
        (unsigned)capability >= STEER_CAP_COUNT) return -1;
    implemented = !strcmp(platform, "openwrt") || !strcmp(platform, "android");
    if (!implemented && strcmp(platform, "linux") && strcmp(platform, "windows") &&
        strcmp(platform, "ios")) return -1;
    if (implemented) {
        value.supported = STEER_CAP_YES;
        value.built = STEER_CAP_UNKNOWN;
        value.available = STEER_CAP_UNKNOWN;
        value.authorized = STEER_CAP_UNKNOWN;
    }
    *out = value;
    return 0;
}
