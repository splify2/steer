/* Только для динамического Linux-стенда: авария на границе commit в штатном steerd. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

int unlink(const char *path) {
    const char *name = strrchr(path, '/');
    if (name && !strcmp(name, "/.install-in-progress")) raise(SIGKILL);
    int (*next)(const char *) = dlsym(RTLD_NEXT, "unlink");
    return next(path);
}
