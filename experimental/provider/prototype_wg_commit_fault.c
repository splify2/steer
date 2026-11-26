/* Test-only: kill the real Core immediately before or after its durable
 * prototype_store config commit. Does not replace any network backend. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static _Thread_local int fail_directory=-1;
int fsync(int fd){
    if(fd==fail_directory){fail_directory=-1;errno=EIO;return -1;}
    return (int)syscall(SYS_fsync,fd);
}

int renameat(int from,const char *old,int to,const char *name){
    const char *mode=getenv("STEER_TEST_WG_COMMIT_CRASH");
    int target=mode&&!strncmp(old,".config.tmp.",12)&&!strcmp(name,"config.json");
    if(target&&!strcmp(mode,"before")){raise(SIGKILL);_exit(1);}
    int rc=(int)syscall(SYS_renameat,from,old,to,name);
    if(!rc&&target&&!strcmp(mode,"unsynced"))fail_directory=to;
    if(!rc&&target&&!strcmp(mode,"after")){
        if(fsync(to))_exit(2);
        raise(SIGKILL);_exit(1);
    }
    return rc;
}
