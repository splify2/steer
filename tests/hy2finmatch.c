/* SPDX-License-Identifier: GPL-3.0-only
 * Real QUIC loss test: peer EOF first, application closes after ordered FIN,
 * final data/FIN lost, then retransmitted without application flow lifetime. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "quic.h"
#include "qccert.h"
int hy2c_test_graceful(struct qc *,int64_t,const uint8_t *,size_t);
void stack_sess_ready(void *s,int r) { (void)s;(void)r; }
void stack_sess_rx(void *s) { (void)s; }
void stack_sess_room(void *s) { (void)s; }
uint64_t stack_now_ns(void) { return 0; }
void hy2_watch_seen(int r) { (void)r; }
struct state { struct qc *client,*server;int hs,closed,peer_eof,server_fin,neighbor_fin;uint64_t drop_until;size_t received,neighbor;unsigned dropped; };
static uint8_t payload[4096];
static uint64_t now_ms(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static size_t tx(void *u,uint8_t *dst,const uint8_t *src,size_t n) {
    struct state *s=u;if(now_ms()<s->drop_until) { s->dropped++;return 0; }memcpy(dst,src,n);return n;
}
static void hs(void *u) { ((struct state *)u)->hs=1; }
static void closed(void *u,int reason,const char *why) { (void)reason;(void)why;((struct state *)u)->closed=1; }
static void server_data(void *u,int64_t sid,const uint8_t *d,size_t n,int fin) {
    struct state *s=u;
    if(sid==0) {
        if(!s->peer_eof) { assert(n==1&&d[0]==42&&!fin);s->peer_eof=1;assert(qc_stream_send(s->server,sid,NULL,0,1)==0);return; }
        assert(s->received+n<=sizeof payload);assert(!memcmp(d,payload+s->received,n));s->received+=n;
        if(fin) s->server_fin=1;
    } else { assert(qc_stream_send(s->server,sid,d,n,fin)==(ssize_t)n); }
}
static void client_data(void *u,int64_t sid,const uint8_t *d,size_t n,int fin) {
    struct state *s=u;
    if(sid==0) { assert(!n&&fin);s->drop_until=now_ms()+150;assert(!hy2c_test_graceful(s->client,sid,payload,sizeof payload)); }
    else { assert(s->neighbor+n<=sizeof payload);assert(!memcmp(d,payload+s->neighbor,n));s->neighbor+=n;if(fin)s->neighbor_fin=1; }
}
static void pump(struct state *s,int phase) {
    uint64_t end=now_ms()+5000;
    while(now_ms()<end&&!s->closed) {
        if((phase==0&&s->hs)||(phase==1&&s->server_fin)||(phase==2&&s->neighbor_fin)) return;
        qc_run(s->server,1);qc_run(s->client,1);
    }
    assert(!"bounded QUIC progress deadline");
}
int main(void) {
    struct state s={0};for(unsigned i=0;i<sizeof payload;i++) payload[i]=(uint8_t)(i*13);
    const struct qc_ops so={.on_stream_data=server_data,.on_closed=closed};
    const struct qc_ops co={.on_handshake=hs,.on_stream_data=client_data,.on_closed=closed};
    struct qc_srv_cfg sc={.bind_host="127.0.0.1",.alpn="fin-test",.cert_der=qc_cert_der,.cert_n=sizeof qc_cert_der,.key_der=qc_key_der,.key_n=sizeof qc_key_der};
    assert(!qc_listen(&sc,&so,&s,&s.server));
    const struct qc_filter filter={.tx=tx,.user=&s};
    struct qc_cfg cc={.host="127.0.0.1",.port=qc_local_port(s.server),.alpn="fin-test",.sni="localhost",.ca_pem=(const uint8_t *)qc_cert_pem,.ca_pem_n=sizeof qc_cert_pem-1,.filter=&filter};
    assert(!qc_open(&cc,&co,&s,&s.client));pump(&s,0);
    int64_t sid;assert(!qc_stream_open(s.client,&sid)&&sid==0);
    const uint8_t seed=42;assert(qc_stream_send(s.client,sid,&seed,1,0)==1);pump(&s,1);
    assert(s.dropped&&s.received==sizeof payload&&s.server_fin&&!s.closed);
    assert(qc_stream_send(s.client,0,payload,1,0)==QC_ENOSTREAM);
    assert(qc_stream_send(s.server,0,payload,1,0)==QC_ENOSTREAM);
    assert(!qc_stream_open(s.client,&sid)&&sid==4);
    assert(qc_stream_send(s.client,sid,payload,sizeof payload,1)==sizeof payload);pump(&s,2);
    assert(s.neighbor==sizeof payload&&!s.closed);
    qc_free(s.client);qc_free(s.server);
    puts("hy2finmatch: lost final data/FIN survives application detach; healthy neighbor PASS");return 0;
}
