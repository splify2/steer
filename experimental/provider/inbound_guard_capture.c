#define _GNU_SOURCE
#include "inbound_guard_capture.h"
#include "nltransport.h"
#include "run.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int deadline_check(uint64_t deadline){
    if(!deadline)return EINVAL;
    uint64_t now=steer_nl_now_ns();
    return !now?EIO:now>=deadline?ETIMEDOUT:0;
}
static int table_name(const char *s){
    static const char prefix[]="steer_wg_";
    if(!s||strnlen(s,26)!=25||memcmp(s,prefix,9))return 0;
    for(size_t i=9;i<25;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
int steer_inbound_guard_capture_verify(const struct steer_inbound_guard_plan *p,uint64_t deadline){
    if(!p||!table_name(p->table))return EINVAL;
    int rc=deadline_check(deadline);if(rc)return rc;
    int fd=memfd_create("steer-inbound-guard-snapshot",MFD_CLOEXEC);
    if(fd<0)return errno;
    const char *argv[]={"nft","-j","-n","list","table","inet",p->table,NULL};
    int child=run_output_until(argv,fd,deadline,STEER_INBOUND_GUARD_SNAPSHOT_MAX);
    if(child){rc=child<0?(errno?errno:EIO):EIO;goto done;}
    if((rc=deadline_check(deadline)))goto done;
    struct stat st;
    if(fstat(fd,&st)){rc=errno;goto done;}
    if(st.st_size<=0){rc=EPROTO;goto done;}
    if(st.st_size>STEER_INBOUND_GUARD_SNAPSHOT_MAX){rc=EFBIG;goto done;}
    if(lseek(fd,0,SEEK_SET)<0){rc=errno;goto done;}
    size_t length=(size_t)st.st_size,used=0;
    char *buffer=malloc(length);
    if(!buffer){rc=ENOMEM;goto done;}
    while(used<length){
        if((rc=deadline_check(deadline)))break;
        ssize_t n=read(fd,buffer+used,length-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){rc=n<0?errno:EIO;break;}
        used+=(size_t)n;
    }
    if(!rc)rc=steer_inbound_guard_verify(buffer,length,p);
    free(buffer);
    if(!rc)rc=deadline_check(deadline);
    done:close(fd);return rc;
}
