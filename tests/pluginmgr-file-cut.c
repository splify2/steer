/* Только LD_PRELOAD процесса стенда. Реальные rename до SIGKILL. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int rename(const char *from, const char *to) {
    int (*next)(const char *,const char *) = dlsym(RTLD_NEXT,"rename");
    if (!next) _exit(120);
    const char *fault = getenv("CUT");
    if (!fault) return next(from,to);
    const char *name = strrchr(to,'/');
    static int states;
    const char *step = "";
    if (name && !strcmp(name,"/state.json")) step = ++states == 1 ? "state1" : "state2";
    if (name && !strcmp(name,"/.install-in-progress")) {
        char phase[16] = "";
        FILE *f = fopen(from,"r");
        if (f) { if (fscanf(f,"G1 %15s",phase) != 1) phase[0] = 0; fclose(f); }
        if (!strcmp(phase,"active")) step = "publish";
        if (!strcmp(phase,"preparing")) step = "preparing";
        if (!strcmp(phase,"finished")) step = "decision";
    }
    if (strstr(from,"/old-fixture-app")) step = "restore";
    if (strstr(from,"/new-fixture-app") && name && !strcmp(name,"/fixture-app")) step = "place";
    if (name && !strcmp(name,"/plugins") && strstr(to,"/keep.d/")) step = "keep";
    if (!strncmp(fault,"error:",6) && !strcmp(fault+6,step)) {
        unsetenv("CUT"); errno = ENOSPC; return -1;
    }
    int rc = next(from,to);
    if (!rc && !strcmp(fault,step)) kill(getpid(),SIGKILL);
    return rc;
}

int unlinkat(int fd, const char *name, int flags) {
    int (*next)(int,const char *,int) = dlsym(RTLD_NEXT,"unlinkat");
    if (!next) _exit(120);
    int rc = next(fd,name,flags);
    const char *fault = getenv("CUT");
    if (!rc && fault && !strcmp(fault,"gc") && !strcmp(name,"plan")) kill(getpid(),SIGKILL);
    return rc;
}
