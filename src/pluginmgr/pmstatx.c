/* Для сырого syscall нужна структура Linux UAPI. Не смешивать её с
 * <sys/stat.h>: musl может объявлять свою struct statx без stx_mnt_id. */
#define _GNU_SOURCE
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "pmstatx.h"

int pm_statx_mount_id(const char *path, uint64_t *id) {
#if defined(SYS_statx) && defined(STATX_MNT_ID)
    struct statx sx;
    if (!syscall(SYS_statx, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &sx) &&
        (sx.stx_mask & STATX_MNT_ID)) {
        *id = sx.stx_mnt_id;
        return 0;
    }
#else
    (void)path;
    (void)id;
#endif
    return -1;
}
