/* Test-only observations of real staging/publication barriers. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int fsetxattr(int fd,const char *name,const void *value,size_t size,int flags) {
    const char *cut=getenv("INSTALL_CUT");
    if (cut && !strcmp(cut,"partial") && !strcmp(name,"user.steer.supd2.phase")) raise(SIGKILL);
    return syscall(SYS_fsetxattr,fd,name,value,size,flags);
}

int fsync(int fd) {
    const char *cut=getenv("INSTALL_CUT");
    if (cut && faccessat(fd,"receipt",F_OK,0)==0) {
        int prepared=faccessat(fd,"new",F_OK,0)==0;
        if (prepared && !strcmp(cut,"prepared")) raise(SIGKILL);
        if (prepared && !strcmp(cut,"hold")) raise(SIGSTOP);
        if (!prepared && !strcmp(cut,"published")) raise(SIGKILL);
    }
    if (cut && !strcmp(cut,"parent-eio") && faccessat(fd,"subject/type",F_OK,0)==0) {
        errno=EIO;
        return -1;
    }
    return syscall(SYS_fsync,fd);
}
