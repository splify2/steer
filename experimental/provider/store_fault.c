/* Linux test-only LD_PRELOAD shim. Never linked into runtime binaries. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static int marker(const char *name)
{
    const char *path = getenv(name);
    return path && !access(path, F_OK);
}
int fsync(int fd)
{
    struct stat state;
    if (!fstat(fd, &state)) {
        if (S_ISREG(state.st_mode) && marker("STEER_TEST_PAUSE_FILE_SYNC")) {
            const char *entered = getenv("STEER_TEST_SYNC_ENTERED");
            if (entered) {
                int signal = open(entered, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (signal >= 0) close(signal);
            }
            while (marker("STEER_TEST_PAUSE_FILE_SYNC")) usleep(10000);
        }
        if ((S_ISREG(state.st_mode) && marker("STEER_TEST_FAIL_FILE_SYNC")) ||
            (S_ISDIR(state.st_mode) && marker("STEER_TEST_FAIL_DIRECTORY_SYNC"))) {
            errno = ENOSPC; return -1;
        }
    }
    return (int)syscall(SYS_fsync, fd);
}
