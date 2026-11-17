/* SPDX-License-Identifier: GPL-3.0-only
 * Wildcard binding oracle MUST run in a separate network namespace. */
#define _GNU_SOURCE
#include "quic.h"
#include "qccert.h"
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
struct fixture { struct qc_endpoint *endpoint;int family;unsigned accepted,errors; };
struct peer { struct fixture *owner;struct qc *q; };
static void stream(void *user,int64_t sid,const uint8_t *data,size_t n,int fin) {
    struct peer *p=user;if(qc_stream_send(p->q,sid,data,n,fin)!=(ssize_t)n)p->owner->errors++;
}
static void datagram(void *user,const uint8_t *data,size_t n) { struct peer *p=user;if(qc_datagram_send(p->q,data,n))p->owner->errors++; }
static void closed(void *user,int reason,const char *why) { (void)reason;(void)why;free(user); }
static int connection(void *user,struct qc *q,struct qc_ops *ops,void **out) {
    struct fixture *f=user;char address[64];uint16_t port;uint8_t bytes[16];
    if(qc_endpoint_peer(q,address,sizeof address,&port)||!port||inet_pton(f->family,address,bytes)!=1||
       (f->family==AF_INET?memcmp(bytes,(uint8_t[4]){127,0,0,1},4):memcmp(bytes,(uint8_t[16]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},16))) {
        f->errors++;return -1;
    }
    struct peer *p=calloc(1,sizeof *p);if(!p)return -1;
    p->q=q;p->owner=f;f->accepted++;
    *ops=(struct qc_ops){.on_stream_data=stream,.on_datagram=datagram,.on_closed=closed};*out=p;return 0;
}
int main(void) {
    struct stat own,init;
    if(stat("/proc/self/ns/net",&own)||stat("/proc/1/ns/net",&init)||
       (own.st_ino==init.st_ino&&own.st_dev==init.st_dev)) { fputs("isolated network namespace required\n",stderr);return 2; }
    struct fixture v6={.family=AF_INET6},v4={.family=AF_INET};const struct qc_endpoint_ops ops={.on_connection=connection};
    struct qc_endpoint_cfg cfg={.max_connections=2,.server={.bind_host="::",.alpn="qcecho",.cert_der=qc_cert_der,.cert_n=sizeof qc_cert_der,
        .key_der=qc_key_der,.key_n=sizeof qc_key_der,.datagram_max=1200,.idle_ms=2000}};
    if(qc_endpoint_open(&cfg,&ops,&v6,&v6.endpoint))return 1;
    int only=0;socklen_t size=sizeof only;
    if(getsockopt(qc_endpoint_fd(v6.endpoint),IPPROTO_IPV6,IPV6_V6ONLY,&only,&size)||only!=1) { qc_endpoint_free(v6.endpoint);return 1; }
    cfg.server.bind_host="0.0.0.0";cfg.server.port=qc_endpoint_port(v6.endpoint);
    if(qc_endpoint_open(&cfg,&ops,&v4,&v4.endpoint)) { qc_endpoint_free(v6.endpoint);return 1; }
    printf("PORT %u\n",cfg.server.port);fflush(stdout);time_t end=time(NULL)+15;
    while(time(NULL)<end) {
        struct pollfd fds[3]={{qc_endpoint_fd(v6.endpoint),POLLIN,0},{qc_endpoint_fd(v4.endpoint),POLLIN,0},{0,POLLIN,0}};
        int ready=poll(fds,3,20);
        if(ready>0&&(fds[0].revents&POLLIN))(void)qc_endpoint_on_readable(v6.endpoint);
        if(ready>0&&(fds[1].revents&POLLIN))(void)qc_endpoint_on_readable(v4.endpoint);
        (void)qc_endpoint_on_timer(v6.endpoint);(void)qc_endpoint_on_timer(v4.endpoint);
        if(ready>0&&(fds[2].revents&POLLIN)) {
            char line[32];if(!fgets(line,sizeof line,stdin)||!strcmp(line,"quit\n"))break;
            if(!strcmp(line,"stats\n")) { printf("STATS %u %u %u\n",v4.accepted,v6.accepted,v4.errors+v6.errors);fflush(stdout); }
        }
    }
    qc_endpoint_free(v4.endpoint);qc_endpoint_free(v6.endpoint);return v4.errors||v6.errors;
}
