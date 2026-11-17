/* SPDX-License-Identifier: GPL-3.0-only */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hy2wire.h"
#include "quic.h"
int hy2c_test_response(const uint8_t *,size_t,size_t,uint8_t *,size_t,size_t *);
int hy2c_test_terminal(int,uint64_t);
int hy2c_test_terminal_ex(int,unsigned,uint64_t,uint64_t,uint64_t);
void stack_sess_ready(void *session,int result) { (void)session;(void)result; }
void stack_sess_rx(void *session) { (void)session; }
void stack_sess_room(void *session) { (void)session; }
uint64_t stack_now_ns(void) { return 0; }
void hy2_watch_seen(int result) { (void)result; }
int main(void) {
    assert(hy2c_test_terminal(0,0)); /* RESET code0 must not synthesize EOF. */
    assert(hy2c_test_terminal(0,7));
    assert(hy2c_test_terminal(1,7));
    assert(!hy2c_test_terminal(1,0));
    assert(hy2c_test_terminal_ex(1,QC_STREAM_RX_RESET|QC_STREAM_TX_RESET,0,7,7)==1);
    assert(hy2c_test_terminal_ex(1,QC_STREAM_TX_RESET,0,0,0)==1);
    assert(hy2c_test_terminal_ex(1,QC_STREAM_RX_RESET,0,0,0)==1);
    assert(hy2c_test_terminal_ex(1,0,0,0,0)==0);
    uint8_t *wire=malloc(80000),*out=malloc(65536);size_t got;
    assert(wire&&out);
    wire[0]=wire[1]=wire[2]=0;
    for(size_t i=0;i<65536;i++) wire[3+i]=(uint8_t)i;
    for(size_t split=0;split<=3;split++) {
        assert(!hy2c_test_response(wire,3+65536,split,out,65536,&got));
        assert(got==65536&&!memcmp(out,wire+3,got));
    }
    size_t n=0;wire[n++]=0;n+=hy2_varint_put(wire+n,8,4096);
    memset(wire+n,'m',4096);n+=4096;n+=hy2_varint_put(wire+n,8,4096);
    memset(wire+n,'p',4096);n+=4096;
    for(size_t i=0;i<100;i++) wire[n+i]=(uint8_t)i;
    struct hy2_tcp_resp response;
    assert(hy2_tcp_response(wire,n+100,&response)==(int)n&&response.ok);
    struct hy2_tcp_response_stream incremental={0};size_t consumed;
    assert(!hy2_tcp_response_feed(&incremental,wire,4095,&consumed,&response)&&consumed==4095);
    assert(hy2_tcp_response_feed(&incremental,wire+4095,n+100-4095,&consumed,&response)==1&&response.ok&&consumed==n-4095);
    assert(!hy2c_test_response(wire,n+100,4095,out,65536,&got));
    assert(got==100&&!memcmp(out,wire+n,got));
    /* Every incomplete header prefix must fail on EOF, including zero bytes.
     * A later independent stream still succeeds after each rejection. */
    for(size_t prefix=0;prefix<n;prefix++) {
        assert(hy2c_test_response(wire,prefix,prefix/2,out,65536,&got)<0);
        const uint8_t healthy[]={0,0,0,'o','k'};
        assert(!hy2c_test_response(healthy,sizeof healthy,2,out,65536,&got));
        assert(got==2&&!memcmp(out,"ok",2));
    }
    free(wire);free(out);puts("hy2respmatch: coalesced/fragmented response + payload PASS");return 0;
}
