/* Namespace test only: terminate the real owner at actual kernel operations.
 * Not built into steerd and not selected by an IPC field. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>

static void cut(const char *point) {
    const char *p=getenv("REMOVE_CUT");
    if (p && !strcmp(p,point)) kill(getpid(),SIGKILL);
}
int fsetxattr(int fd,const char *name,const void *value,size_t n,int flags) {
    int intent=!strcmp(name,"user.steer.supd2.intent"), commit=!strcmp(name,"user.steer.supd2.commit");
    if (intent) cut("before-decision");
    int rc=syscall(SYS_fsetxattr,fd,name,value,n,flags);
    if (!rc) {
        if (intent) cut("after-decision");
        if (commit) cut("after-commit-record");
        if (!strcmp(name,"user.steer.supd2.phase") && n==33 && *(const char *)value=='I') cut("after-intent-seal");
    }
    return rc;
}
int fsync(int fd) {
    struct stat st;
    if (!fstat(fd,&st) && S_ISDIR(st.st_mode)) {
        /* Only directory sync in this owner: immediately after rename, or
         * when re-confirming that rename on recovery. */
        cut("after-rename");
        const char *p=getenv("REMOVE_CUT");
        if (p && !strcmp(p,"sync-error")) { errno=EIO; return -1; }
    }
    return syscall(SYS_fsync,fd);
}
ssize_t send(int fd,const void *p,size_t n,int flags) {
    if (n>8 && !memcmp((const char *)p+n-8," removed",8)) cut("lost-reply");
    return syscall(SYS_sendto,fd,p,n,flags,NULL,0);
}
