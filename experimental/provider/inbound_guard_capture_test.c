#define _GNU_SOURCE
#include "inbound_guard_capture.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static int fail_snapshot_read;
ssize_t __real_read(int,void *,size_t);
ssize_t __real___read_chk(int,void *,size_t,size_t);
static int fail_regular(int fd){struct stat st;return fail_snapshot_read&&!fstat(fd,&st)&&S_ISREG(st.st_mode);}
ssize_t __wrap_read(int fd,void *buf,size_t size){
    if(fail_regular(fd)){errno=EIO;return -1;}
    return __real_read(fd,buf,size);
}
ssize_t __wrap___read_chk(int fd,void *buf,size_t size,size_t capacity){
    if(fail_regular(fd)){errno=EIO;return -1;}
    return __real___read_chk(fd,buf,size,capacity);
}
int main(int argc,char **argv){
    if(argc!=7)return 2;
    char *end;unsigned long long handle=strtoull(argv[3],&end,10);if(*end)return 2;
    unsigned long index=strtoul(argv[4],&end,10);if(*end||index>0xffffffffu)return 2;
    struct steer_inbound_guard_plan p={argv[1],argv[2],"10.80.0.2",handle,(unsigned)index};
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 2;
    uint64_t now=(uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;
    uint64_t deadline=now+(!strcmp(argv[5],"short")?100000000u:5000000000u);
    if(!strcmp(argv[5],"expired"))deadline=now-1;
    if(!strcmp(argv[5],"read-error"))fail_snapshot_read=1;
    int expected=(int)strtol(argv[6],&end,10);if(*end)return 2;
    int rc=steer_inbound_guard_capture_verify(&p,deadline);
    printf("capture rc=%d expected=%d\n",rc,expected);
    return rc==expected?0:1;
}
