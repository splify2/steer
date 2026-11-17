#include "capabilities.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *selected = getenv("STEER_PLATFORM");
    char *saved = selected ? malloc(strlen(selected) + 1) : NULL;
    assert(!selected || saved);
    if (selected) strcpy(saved, selected);
    const char *names[] = {"openwrt", "android", "linux", "windows", "ios"};
    struct steer_platform_capability_info info, before;
    struct { struct steer_platform_capability_info info; uint32_t tail; } large;
    assert(sizeof(info) == 6 * sizeof(uint32_t));
    for (unsigned p = 0; p < sizeof(names) / sizeof(names[0]); p++) {
        for (unsigned c = 0; c < STEER_CAP_COUNT; c++) {
            assert(steer_platform_capability_query(names[p], c, &info, sizeof(info)) == 0);
            assert(info.size == sizeof(info));
            assert(info.version == STEER_PLATFORM_CAPABILITY_VERSION);
            assert(info.supported == (p < 2 ? STEER_CAP_YES : STEER_CAP_NO));
            assert(info.built == (p < 2 ? STEER_CAP_UNKNOWN : STEER_CAP_NO));
            assert(info.available == info.built && info.authorized == info.built);
        }
    }
    memset(&info, 0xa5, sizeof(info));
    before = info;
    assert(steer_platform_capability_query(NULL, 0, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("Linux", 0, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("unknown", 0, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("", 0, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("linux", -1, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("linux", STEER_CAP_COUNT, &info, sizeof(info)) == -1);
    assert(steer_platform_capability_query("linux", 0, &info, sizeof(info) - 1) == -1);
    assert(steer_platform_capability_query("linux", 0, NULL, sizeof(info)) == -1);
    assert(memcmp(&info, &before, sizeof(info)) == 0);
    large.tail = 0x12345678;
    assert(steer_platform_capability_query("linux", 0, &large.info, sizeof(large)) == 0);
    assert(large.tail == 0x12345678);
    /* Describing another platform must not select it for existing callers. */
    assert(selected ? getenv("STEER_PLATFORM") &&
        !strcmp(saved, getenv("STEER_PLATFORM")) : !getenv("STEER_PLATFORM"));
    free(saved);
    puts("capabilitiesmatch: ok");
    return 0;
}
