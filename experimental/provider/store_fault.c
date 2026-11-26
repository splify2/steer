/* Linux test-only LD_PRELOAD shim. Never linked into runtime binaries. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static int marker(const char *name)
{
    const char *path = getenv(name);
    return path && !access(path, F_OK);
}
static int pause_target(int fd)
{
    if(!getenv("STEER_TEST_PAUSE_STORE_ONLY"))return 1;
    char path[64],name[4096];
    int n=snprintf(path,sizeof path,"/proc/self/fd/%d",fd);
    if(n<0||(size_t)n>=sizeof path)return 0;
    ssize_t len=readlink(path,name,sizeof name-1);
    if(len<0)return 0;
    name[len]=0;
    return strstr(name,"/.config.tmp.")!=NULL;
}
static int fail_target(int fd)
{
    const char *dir=getenv("STEER_TEST_FAIL_STORE_PATH");
    if(!dir)return 1;
    char path[64],name[4096];
    int n=snprintf(path,sizeof path,"/proc/self/fd/%d",fd);
    if(n<0||(size_t)n>=sizeof path)return 0;
    ssize_t len=readlink(path,name,sizeof name-1);
    if(len<0)return 0;
    name[len]=0;
    size_t size=strlen(dir);
    return !strcmp(name,dir)||(!strncmp(name,dir,size)&&!strncmp(name+size,"/.config.tmp.",13));
}
int fsync(int fd)
{
    struct stat state;
    if (!fstat(fd, &state)) {
        if (S_ISREG(state.st_mode) && marker("STEER_TEST_PAUSE_FILE_SYNC") && pause_target(fd)) {
            const char *entered = getenv("STEER_TEST_SYNC_ENTERED");
            if (entered) {
                int signal = open(entered, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (signal >= 0) close(signal);
            }
            while (marker("STEER_TEST_PAUSE_FILE_SYNC")) usleep(10000);
        }
        if (fail_target(fd) && ((S_ISREG(state.st_mode) && marker("STEER_TEST_FAIL_FILE_SYNC")) ||
            (S_ISDIR(state.st_mode) && marker("STEER_TEST_FAIL_DIRECTORY_SYNC")))) {
            errno = ENOSPC; return -1;
        }
    }
    return (int)syscall(SYS_fsync, fd);
}
