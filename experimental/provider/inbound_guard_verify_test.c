#include "inbound_guard_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){
    if(argc!=6)return 2;
    char *end;unsigned long long handle=strtoull(argv[3],&end,10);if(*end)return 2;
    unsigned long index=strtoul(argv[4],&end,10);if(*end||index>0xffffffffu)return 2;
    struct steer_inbound_guard_plan p={argv[1],argv[2],argv[5],handle,(unsigned)index};
    char data[STEER_INBOUND_GUARD_SNAPSHOT_MAX+1];size_t n=fread(data,1,sizeof(data),stdin);
    if(ferror(stdin)||n>STEER_INBOUND_GUARD_SNAPSHOT_MAX)return 2;
    int rc=steer_inbound_guard_verify(data,n,&p);
    if(rc)fprintf(stderr,"REJECT %d\n",rc);
    return rc?1:0;
}
