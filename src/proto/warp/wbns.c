/* Пространство сети подбора: в нём живут устройства-кандидаты (awg_scan_up, src/kinds/awg.c) и
 * проверки через них. Создаётся один раз на процесс: unshare(CLONE_NEWNET) переводит поток в новое
 * пространство, дескриптор на него держит пространство живым, и поток сразу возвращается обратно.
 * Умирает процесс — пространство уходит вместе с последним дескриптором, и устройства в нём тоже:
 * мусора после падения модуля не остаётся. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wbns.h"

static int self_ns(void) {
    int fd = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    return fd >= 0 ? fd : open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
}

int wb_ns_new(void) {
    int old = self_ns();
    if (old < 0) return -1;
    if (unshare(CLONE_NEWNET) != 0) { int e = errno; close(old); errno = e; return -1; }
    int ns = self_ns();
    int e = errno;
    if (setns(old, CLONE_NEWNET) != 0) {
        /* Вернуться не вышло — дальше этот процесс жил бы без сети роутера. */
        fprintf(stderr, "steer-warpbox: не вернуться в пространство сети роутера: %s\n", strerror(errno));
        _exit(2);
    }
    close(old);
    if (ns < 0) errno = e;
    return ns;
}

int wb_ns_enter(int ns, int *old) {
    *old = self_ns();
    if (*old < 0) return -1;
    if (setns(ns, CLONE_NEWNET) != 0) { int e = errno; close(*old); *old = -1; errno = e; return -1; }
    return 0;
}

void wb_ns_leave(int old) {
    if (old < 0) return;
    if (setns(old, CLONE_NEWNET) != 0) {
        fprintf(stderr, "steer-warpbox: не вернуться в пространство сети роутера: %s\n", strerror(errno));
        _exit(2);
    }
    close(old);
}
