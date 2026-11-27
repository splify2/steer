/* Отрицательный контроль, не наблюдатель обрыва. Реальная net1 остаётся
 * загруженной; только явной ABI-пробе вернуть отличающийся отпечаток. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "s2pnet.h"

const struct s2p_net_abi *s2p_net_abi(void) {
    const struct s2p_net_abi *(*real)(void) = dlsym(RTLD_NEXT, "s2p_net_abi");
    if (!real) _exit(122);
    const struct s2p_net_abi *a = real();
    if (!getenv("STEER_LIB_PROBE")) return a;
    const char *silent = getenv("NET1_SILENT_EXE");
    if (silent) {
        struct stat target, self;
        if (!stat(silent,&target) && !stat("/proc/self/exe",&self) &&
            self.st_dev == target.st_dev && self.st_ino == target.st_ino) _exit(0);
        return a;
    }
    static struct s2p_net_abi mismatch;
    mismatch = *a;
    mismatch.fingerprint ^= 1;
    return &mismatch;
}
