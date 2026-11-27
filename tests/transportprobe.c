/* Independent server interop driver. Fixed public lab UUID, numeric echo target. */
#define _POSIX_C_SOURCE 200809L
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
int main(int argc,char **argv) {
    if(argc!=5 && argc!=6)return 2;
    size_t length=strlen(argv[4]);if(length>32)return 2;
    int half=argc==6;
    struct tr_node node={.host="127.0.0.1",.port=(uint16_t)atoi(argv[1]),.type="xhttp",
        .security="tls",.sni="localhost",.fp="chrome",.insecure=1,.path="/lab",.mode=argv[2]};
    if(!strcmp(argv[2],"tcp"))node.type="tcp";
    if(!strcmp(argv[2],"grpc")){node.type="grpc";node.mode="gun";node.service="lab";}
    const char *reality_key = getenv("STEER_TEST_REALITY_KEY");
    if (reality_key) { node.security="reality"; node.pbk=reality_key; node.sid="abcd"; }
    struct transport initial;int rc=transport_open(&initial,&node,5);
    if(rc){fprintf(stderr,"open error %d\n",rc);return 1;}
    /* Same ownership transfer as vl_take: one owner survives, io.ctx rebased. */
    struct transport *t=malloc(sizeof(*t));if(!t){transport_close(&initial);return 2;}
    memcpy(t,&initial,sizeof(*t));memset(&initial,0,sizeof(initial));initial.link.fd=-1;
    transport_moved(t);
    transport_live(t);
    unsigned char request[64]={0},received[64];size_t count=0;
    request[16]=1; /* UUID 00000000-0000-0000-0000-000000000001 */
    request[18]=1;unsigned port=(unsigned)atoi(argv[3]);request[19]=(unsigned char)(port>>8);request[20]=(unsigned char)port;
    request[21]=1;request[22]=127;request[25]=1;
    memcpy(request+26,argv[4],length);
    rc=transport_write(t,request,26+length);
    if(rc){fprintf(stderr,"write error %d\n",rc);transport_close(t);free(t);return 1;}
    if(half) {
        for(int tries=0;tries<5000;tries++) {
            rc=transport_shutdown_write(t);
            if(rc!=1)break;
            struct timespec ts={0,1000000};nanosleep(&ts,NULL);
        }
        if(rc){fprintf(stderr,"shutdown error %d\n",rc);transport_close(t);free(t);return 1;}
    }
    for(int tries=0;tries<5000 && count<length+2;tries++) {
        unsigned char buf[32768];size_t n=0;
        rc=transport_read(t,buf,sizeof(buf),&n);
        if(rc){fprintf(stderr,"read error %d\n",rc);break;}
        if(n>sizeof(received)-count){rc=-1;break;}
        memcpy(received+count,buf,n);count+=n;
        struct timespec ts={0,1000000};nanosleep(&ts,NULL);
    }
    int terminal=0;
    if(half && !rc && count==length+2) {
        for(int tries=0;tries<5000;tries++) {
            unsigned char buf[32768];size_t n=0;
            int end=transport_read(t,buf,sizeof(buf),&n);
            if(end){terminal=transport_read_end(t,end);break;}
            if(n){terminal=2;break;}
            struct timespec ts={0,1000000};nanosleep(&ts,NULL);
        }
    }
    int status=t->h2.status;transport_close(t);free(t);
    if(rc||count!=length+2||received[0]||received[1]||memcmp(received+2,argv[4],length)) {
        fprintf(stderr,"echo mismatch rc=%d bytes=%zu expected=%zu status=%d\n",rc,count,length+2,status);return 1;
    }
    if(half && terminal!=1){fprintf(stderr,"terminal classification=%d\n",terminal);return 1;}
    puts("transportprobe real upstream echo PASS");return 0;
}
