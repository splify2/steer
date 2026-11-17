/* SPDX-License-Identifier: GPL-3.0-only
 * Test-only LD_PRELOAD shim: one certificate-read pause per arm byte. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
static unsigned seen;
#ifdef STEER_PREPARE_WRAP_READ
extern ssize_t __real_read(int,void *,size_t);
extern ssize_t __real___read_chk(int,void *,size_t,size_t);
#endif
static void read_barrier(int fd,size_t length) {
    const char *target=getenv("STEER_TEST_TLS_READ_PATH"),*marker=getenv("STEER_TEST_TLS_READ_ARM");
    if(target&&marker&&length) {
        char name[64],path[PATH_MAX],arm=0;snprintf(name,sizeof name,"/proc/self/fd/%d",fd);
        ssize_t n=readlink(name,path,sizeof path-1);
        if(n>0) {
            path[n]=0;
            if(!strcmp(path,target)) {
                int gate=(int)syscall(SYS_openat,AT_FDCWD,marker,O_RDONLY|O_NONBLOCK|O_CLOEXEC,0);
                if(gate>=0) { if(syscall(SYS_read,gate,&arm,1)!=1)arm=0;syscall(SYS_close,gate); }
                unsigned old=__atomic_load_n(&seen,__ATOMIC_RELAXED),value=(unsigned char)arm;
                if(arm>='1'&&arm<='9'&&value>old&&__atomic_compare_exchange_n(&seen,&old,value,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) {
                    const char *notify=getenv("STEER_TEST_TLS_READ_NOTIFY"),*release=getenv("STEER_TEST_TLS_READ_RELEASE");
                    if(notify&&release) { char go;(void)syscall(SYS_write,atoi(notify),&arm,1);(void)syscall(SYS_read,atoi(release),&go,1); }
                }
            }
        }
    }
#ifdef STEER_PREPARE_WRAP_READ
}
ssize_t __wrap_read(int fd,void *buffer,size_t length) {
    read_barrier(fd,length);
    return __real_read(fd,buffer,length);
}
ssize_t __wrap___read_chk(int fd,void *buffer,size_t length,size_t buffer_length) {
    /* Preserve fortified bounds checking and sanitizer interception. */
    read_barrier(fd,length);
    return __real___read_chk(fd,buffer,length,buffer_length);
#else
}
ssize_t read(int fd,void *buffer,size_t length) {
    read_barrier(fd,length);
    return syscall(SYS_read,fd,buffer,length);
#endif
}
