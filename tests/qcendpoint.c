/* SPDX-License-Identifier: GPL-3.0-only
 * Disposable loopback endpoint oracle host; not an application protocol server. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include "quic.h"
#include "qccert.h"
struct server { struct qc_endpoint *endpoint; struct qc *latest; unsigned accepted,closed,idle,handshakes,errors; };
struct connection { struct server *server; struct qc *q; int handshake; };
static volatile sig_atomic_t stopping;
static void stop(int signum) { (void)signum; stopping=1; }
static void handshake(void *user) {
    struct connection *c=user; c->handshake=1; c->server->handshakes++;
}
static void stream(void *user,int64_t sid,const uint8_t *data,size_t length,int fin) {
    struct connection *c=user; struct server *s=c->server;
    if(!c->handshake||qc_stream_send(c->q,sid,data,length,fin)!=(ssize_t)length) s->errors++;
}
static void datagram(void *user,const uint8_t *data,size_t length) {
    struct connection *c=user; struct server *s=c->server;
    uint8_t maximum[1600];
    if(length==1&&data[0]==0xfe) {
        length=qc_datagram_max(c->q);
        if(length>sizeof maximum) { s->errors++;return; }
        memset(maximum,0xa5,length);data=maximum;
    }
    if(!c->handshake||qc_datagram_send(c->q,data,length)) s->errors++;
}
static void closed(void *user,int reason,const char *why) {
    struct connection *c=user; (void)why;
    c->server->closed++; if(reason==QC_CLOSE_IDLE) c->server->idle++;
    if(c->server->latest==c->q) c->server->latest=NULL;
    free(c);
}
static int connection(void *user,struct qc *q,struct qc_ops *ops,void **child_user) {
    struct server *s=user; struct connection *c=calloc(1,sizeof *c);
    if(!c) return -1;
    c->q=q; c->server=s; s->latest=q; s->accepted++;
    *ops=(struct qc_ops){.on_handshake=handshake,.on_stream_data=stream,.on_datagram=datagram,.on_closed=closed};
    *child_user=c; return 0;
}
int main(void) {
    struct server s={0}; struct qc_endpoint_ops ops={.on_connection=connection};
    struct qc_endpoint_cfg cfg={.max_connections=2,.server={
        .bind_host="127.0.0.1",.alpn="qcecho",.cert_der=qc_cert_der,.cert_n=sizeof qc_cert_der,
        .key_der=qc_key_der,.key_n=sizeof qc_key_der,.datagram_max=1200,.idle_ms=1500}};
    struct sigaction action={0}; time_t deadline=time(NULL)+30;
    if(qc_endpoint_open(&cfg,&ops,&s,&s.endpoint)) return 1;
    action.sa_handler=stop;sigemptyset(&action.sa_mask);
    sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);
    printf("PORT %u\n",qc_endpoint_port(s.endpoint));fflush(stdout);
    while(!stopping&&time(NULL)<deadline) {
        struct pollfd fds[2]={{.fd=qc_endpoint_fd(s.endpoint),.events=POLLIN},{.fd=STDIN_FILENO,.events=POLLIN}};
        int timeout=qc_endpoint_timeout_ms(s.endpoint),ready;
        if(timeout<0||timeout>100) timeout=100;
        ready=poll(fds,2,timeout);
        if(ready>0&&(fds[0].revents&POLLIN)) (void)qc_endpoint_on_readable(s.endpoint);
        (void)qc_endpoint_on_timer(s.endpoint);
        if(ready>0&&(fds[1].revents&POLLIN)) {
            char command[32];
            if(!fgets(command,sizeof command,stdin)) break;
            if(!strcmp(command,"stats\n")) {
                printf("STATS %zu %u %u %u %u %u\n",qc_endpoint_count(s.endpoint),s.accepted,s.closed,s.idle,s.handshakes,s.errors);fflush(stdout);
            } else if(!strcmp(command,"free\n")) { if(s.latest) qc_free(s.latest); }
            else if(!strcmp(command,"quit\n")) break;
        }
    }
    qc_endpoint_free(s.endpoint);
    return s.errors?1:0;
}
