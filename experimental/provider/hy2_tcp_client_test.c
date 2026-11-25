/* SPDX-License-Identifier: GPL-3.0-only */
#define _POSIX_C_SOURCE 200809L
#include "hy2_tcp_client.h"
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MASS (512u*1024u)
static uint64_t now_ms(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC,&ts)==0);
    return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000;
}
static uint8_t pattern(size_t i) { return (uint8_t)((i*17u)^(i>>9)); }
int main(int argc,char **argv) {
    assert(argc==7);
    struct steer_hy2_profile *profile=NULL;
    const char *password=getenv("STEER_LAB_HY2_TOKEN");
    int result=steer_hy2_profile_prepare(7,"127.0.0.1",(uint16_t)atoi(argv[1]),argv[2],argv[3],password,&profile);
    if(!strcmp(argv[6],"prepare-error")) { assert(result&&profile==NULL);return 0; }
    assert(!result&&profile);
    struct steer_hy2_tcp *flow=NULL;
    uint64_t now=now_ms(),deadline=now+3000;
    if(!strcmp(argv[6],"timeout")) deadline=now+100;
    uint16_t target_port=(uint16_t)atoi(argv[5]);
    assert(steer_hy2_tcp_open(profile,6,argv[4],target_port,now,deadline,&flow)&&!flow);
    assert(!steer_hy2_tcp_open(profile,7,argv[4],target_port,now,deadline,&flow));
    if(!strcmp(argv[6],"cancel")) {
        steer_hy2_tcp_destroy(flow);
        assert(!steer_hy2_profile_destroy(profile));
        return 0;
    }
    struct pollfd fd={steer_hy2_tcp_fd(flow),POLLIN,0};
    unsigned eof=0,retired=0,finned=0;
    size_t written=0,read_total=0;
    uint64_t end=now+7000;
    int success=!strcmp(argv[6],"success");
    if(success&&!strcmp(argv[2],"localhost")) {
        /* A pending open already admitted by an old generation is also pinned. */
        struct steer_hy2_tcp *stale=NULL;
        steer_hy2_profile_retire(profile);
        assert(steer_hy2_tcp_open(profile,7,argv[4],target_port,now_ms(),end,&stale)&&!stale);
        assert(steer_hy2_profile_destroy(profile));
        retired=1;
    }
    for(;;) {
        enum steer_hy2_state state=steer_hy2_tcp_state(flow);
        uint8_t buf[8191]; /* awkward size exercises ring wrapping */
        if(state==STEER_HY2_READY||state==STEER_HY2_FINISHED) {
            assert(success);
            if(!retired) {
                struct steer_hy2_tcp *stale=NULL;
                steer_hy2_profile_retire(profile);
                assert(steer_hy2_tcp_open(profile,7,argv[4],target_port,now_ms(),end,&stale)&&!stale);
                assert(steer_hy2_profile_destroy(profile));
                retired=1;
            }
            ssize_t n;
            if(!eof) {
                while((n=steer_hy2_tcp_read(flow,buf,sizeof buf))>0) {
                    for(ssize_t i=0;i<n;i++) assert(buf[i]==pattern(read_total++));
                }
                assert(n==0||n==-2);
                eof=n==0;
            }
            while(written<MASS&&steer_hy2_tcp_room(flow)) {
                size_t chunk=MASS-written;
                if(chunk>sizeof buf) chunk=sizeof buf;
                for(size_t i=0;i<chunk;i++) buf[i]=pattern(written+i);
                n=steer_hy2_tcp_write(flow,buf,chunk);
                assert(n>0);
                written+=(size_t)n;
            }
            if(!finned&&written==MASS&&read_total==MASS) {
                assert(!steer_hy2_tcp_shutdown_write(flow));
                finned=1;
            }
            if(state==STEER_HY2_FINISHED&&eof) break;
        } else if(state!=STEER_HY2_OPENING) {
            if(!strcmp(argv[6],"unavailable")) assert(state==STEER_HY2_UNAVAILABLE);
            else if(!strcmp(argv[6],"rejected")) assert(state==STEER_HY2_REJECTED);
            else if(!strcmp(argv[6],"timeout")) assert(state==STEER_HY2_TIMEOUT);
            else abort();
            assert(steer_hy2_tcp_read(flow,buf,sizeof buf)==-1&&!steer_hy2_tcp_room(flow));
            break;
        }
        now=now_ms();
        assert(now<end);
        int timeout=steer_hy2_tcp_timeout(flow,now);
        if(timeout<0||timeout>500) timeout=500;
        assert(poll(&fd,1,timeout)>=0);
        steer_hy2_tcp_drive(flow,now_ms(),fd.revents!=0);
    }
    if(success) assert(retired&&eof&&finned&&read_total==MASS);
    steer_hy2_tcp_destroy(flow);
    assert(!steer_hy2_profile_destroy(profile));
    puts("PASS");
    return 0;
}
