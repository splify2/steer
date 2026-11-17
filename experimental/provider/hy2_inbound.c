/* SPDX-License-Identifier: GPL-3.0-only
 * Experimental core-owned HY2 TCP adapter. No independent routing/socket dial. */
#define _GNU_SOURCE
#include "hy2_inbound.h"
#include "hy2_address.h"
#include "buffers.h"
#include "loop.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#define CHUNK 16384u
struct connection;
struct flow;
struct direction {
    struct flow *flow;
    struct steer_pv1_buffer *buffer;
    struct steer_pv1_async_start operation;
    uint32_t bytes,error,offset,length;
    int pending,completed;
};
struct flow {
    struct flow *next;
    struct connection *connection;
    struct hy2_server_tcp *tcp;
    struct steer_draft_route_lease lease;
    struct steer_pv1_async_start route;
    struct steer_pv1_stream *target;
    struct direction upload,download;
    uint32_t route_error;
    int route_pending,route_completed,cancelled,target_fin,remote_fin,lease_owned;
};
struct connection {
    struct connection *next;
    struct steer_draft_hy2 *owner;
    struct qc *quic;
    struct hy2_server_conn *protocol;
    struct steer_draft_hy2_datagram *datagrams;
    uint64_t epoch;
    char principal[65];
    uint8_t source[16];
    struct steer_pv1_endpoint peer;
    unsigned flows;
    int closed;
};
struct steer_draft_hy2 {
    struct steer_draft_inbound_services services;
    struct steer_draft_hy2_datagram_services datagram_services;
    struct hy2_server_config protocol_config;
    uint8_t *web_body;
    struct qc_endpoint *endpoint;
    struct loop_timer *work;
    struct connection *connections;
    struct flow *flows;
    const struct steer_pv1_stream_api *streams;
    const struct steer_pv1_buffer_api *buffers;
    char inbound[65];
    unsigned max_flows,flow_count;
    uint64_t route_callbacks_after_cancel,io_callbacks_after_cancel,success_after_cancel;
    uint64_t drain_deadline;
    int stopping,working,registered,admitting,retiring;
};
static struct steer_pv1_span span(const char *s) {
    return (struct steer_pv1_span){(const uint8_t *)s,(uint32_t)strlen(s)};
}
static void wake(struct steer_draft_hy2 *a) { if(!a->working) loop_timer_set(a->work,0); }
static struct flow *find_flow(struct connection *c,struct hy2_server_tcp *tcp) {
    for(struct flow *f=c->owner->flows;f;f=f->next) if(f->connection==c&&f->tcp==tcp)return f;
    return NULL;
}
static void cancel_flow(struct flow *f) {
    struct steer_draft_hy2 *a=f->connection->owner;
    if(f->cancelled)return;
    f->cancelled=1;
    if(f->route_pending) f->route.operation.api->cancel(f->route.operation.handle);
    if(f->target) a->streams->close(f->target);
    wake(a);
}
static void abort_flow(struct flow *f) {
    if(!f->cancelled) hy2_server_tcp_abort(f->tcp);
    cancel_flow(f);
}
static void completed(void *user,struct steer_pv1_error error,struct steer_pv1_buffer *buffer,uint32_t bytes) {
    struct direction *d=user;
    if(d->flow->cancelled)d->flow->connection->owner->io_callbacks_after_cancel++;
    d->buffer=buffer;d->bytes=bytes;d->error=error.code;d->completed=1;
    wake(d->flow->connection->owner);
}
static int submit(struct direction *d,int write,uint32_t offset,uint32_t length) {
    struct flow *f=d->flow;struct steer_draft_hy2 *a=f->connection->owner;
    d->offset=offset;d->length=length;
    d->operation=write?a->streams->write(f->target,d->buffer,offset,length,completed,d):
        a->streams->read(f->target,d->buffer,offset,length,completed,d);
    if(d->operation.disposition!=STEER_PV1_PENDING) { abort_flow(f);return -1; }
    d->pending=1;return 0;
}
static uint8_t *view(struct direction *d) {
    struct steer_draft_hy2 *a=d->flow->connection->owner;struct steer_pv1_mut_span v;
    if(a->buffers->writable(a->services.buffers,d->buffer,&v).code) { abort_flow(d->flow);return NULL; }
    return v.data;
}
static void route_done(void *user,struct steer_pv1_error error,uint32_t failure,
                       struct steer_pv1_stream *target,const struct steer_pv1_endpoint *bound) {
    struct flow *f=user;struct steer_draft_hy2 *a=f->connection->owner;
    (void)failure;(void)bound;
    f->route_error=error.code;f->target=target;f->route_completed=1;
    if(f->cancelled) { a->route_callbacks_after_cancel++;if(!error.code&&target)a->success_after_cancel++; }
    if(f->cancelled&&target)a->streams->close(target);
    wake(a);
}
/* Address identity stays intact until core policy/resolution. IPv6 requires
 * standard brackets; domains are borrowed only through route_dial start. */
static void request(void *user,struct hy2_server_tcp *tcp,const uint8_t *address,size_t length,const char *principal) {
    struct connection *c=user;struct steer_draft_hy2 *a=c->owner;
    struct flow *f;char host[2049];uint8_t ip[16];struct steer_draft_accepted accepted={0};
    if(!a->admitting||a->stopping||a->flow_count>=a->max_flows||strcmp(principal,c->principal)||
       steer_draft_hy2_address(address,length,host,ip,&accepted.destination)) {
        (void)hy2_server_tcp_ready(tcp,0);return;
    }
    f=calloc(1,sizeof *f);
    if(!f) { (void)hy2_server_tcp_ready(tcp,0);return; }
    f->connection=c;f->tcp=tcp;f->upload.flow=f;f->download.flow=f;
    f->next=a->flows;a->flows=f;a->flow_count++;c->flows++;
    if(a->services.acquire_route(a->services.context,span(a->inbound),span(c->principal),c->epoch,&f->lease).code) {
        (void)hy2_server_tcp_ready(tcp,0);return;
    }
    f->lease_owned=1;
    if(a->buffers->allocate(a->services.buffers,CHUNK,&f->upload.buffer).code||
       a->buffers->allocate(a->services.buffers,CHUNK,&f->download.buffer).code) {
        (void)hy2_server_tcp_ready(tcp,0);return;
    }
    accepted.generation=f->lease.generation;accepted.inbound_id=span(a->inbound);
    accepted.principal_id=span(c->principal);accepted.source=c->peer;accepted.flow_class=STEER_PV1_FLOW_STREAM;
    f->route=steer_draft_route_dial(f->lease.routes,&accepted,((uint64_t)loop_now_ms()+5000u)*1000000u,route_done,f);
    if(f->route.disposition==STEER_PV1_PENDING)f->route_pending=1;
    else (void)hy2_server_tcp_ready(tcp,0);
}
static void changed(void *user,struct hy2_server_tcp *tcp) { (void)tcp;wake(((struct connection *)user)->owner); }
static void cancelled(void *user,struct hy2_server_tcp *tcp) {
    struct connection *c=user;struct flow *f=find_flow(c,tcp);
    if(f)cancel_flow(f);
    else { /* No host allocation was transferred, but engine reference was. */
        (void)hy2_server_tcp_release(tcp);
    }
}
static uint64_t protocol_now(void *user) { (void)user;return (uint64_t)loop_now_ms(); }
static int open_uni(void *user,int64_t *id) { return qc_stream_open_uni(((struct connection *)user)->quic,id); }
static int send_data(void *user,int64_t id,const uint8_t *data,size_t length,int fin) {
    struct connection *c=user;ssize_t n;if(!c->quic||length>INT_MAX)return -1;
    n=qc_stream_send(c->quic,id,data,length,fin);return n<0?-1:(int)n;
}
static size_t room(void *user,int64_t id) { struct connection *c=user;return c->quic?qc_stream_room(c->quic,id):0; }
static void consumed(void *user,int64_t id,size_t n) { struct connection *c=user;if(c->quic)qc_stream_consumed(c->quic,id,n); }
static void reset(void *user,int64_t id,uint64_t code) { struct connection *c=user;if(c->quic)(void)qc_stream_reset(c->quic,id,code); }
static void stop_receive(void *user,int64_t id,uint64_t code) { struct connection *c=user;if(c->quic)(void)qc_stream_stop_receive(c->quic,id,code); }
static void close_connection(void *user,uint64_t code) { struct connection *c=user;if(c->quic)qc_close(c->quic,code); }
static size_t datagram_limit(void *user){struct connection *c=user;return c->quic?qc_datagram_max(c->quic):0;}
static int datagram_send(void *user,const uint8_t *data,size_t n){struct connection *c=user;return c->quic?qc_datagram_send(c->quic,data,n):-1;}
static void datagram_wake(void *user){struct connection *c=user;wake(c->owner);}
static void datagram_input(void *user,const uint8_t *data,size_t n,const char *principal){
    struct connection *c=user;if(c->datagrams&&!strcmp(principal,c->principal))steer_draft_hy2_datagram_input(c->datagrams,data,n);
}
static size_t datagram_targets(struct connection *c){
    struct steer_draft_hy2_datagram_usage usage;steer_draft_hy2_datagram_usage(c->datagrams,&usage);return usage.targets;
}
static int authenticate(void *user,const uint8_t *token,size_t length,char principal[65]) {
    struct connection *c=user;struct steer_draft_hy2 *a=c->owner;
    if(!a->admitting||a->stopping||a->services.authenticate(a->services.context,span(a->inbound),token,length,principal,&c->epoch)!=1)return 0;
    size_t n=strnlen(principal,65);if(!n||n>64)return 0;
    memcpy(c->principal,principal,n+1);
    if(a->services.datagrams&&!c->datagrams){
        struct steer_draft_hy2_datagram_config cfg={.inbound=span(a->inbound),.principal=span(c->principal),
            .source=c->peer,.admission_epoch=c->epoch,.transport=c,.message_limit=datagram_limit,.send=datagram_send,.wake=datagram_wake};
        if(steer_draft_hy2_datagram_create(&cfg,a->services.datagrams,&c->datagrams))return 0;
    }
    return 1;
}
static const struct hy2_server_ops protocol_ops={protocol_now,open_uni,send_data,room,consumed,reset,stop_receive,close_connection,authenticate,request,changed,changed,cancelled};
static void handshake(void *user) { struct connection *c=user;hy2_server_handshake(c->protocol);wake(c->owner); }
static void data(void *user,int64_t id,const uint8_t *bytes,size_t n,int fin) { struct connection *c=user;hy2_server_data(c->protocol,id,bytes,n,fin);wake(c->owner); }
static void datagram(void *user,const uint8_t *bytes,size_t n){struct connection *c=user;(void)hy2_server_datagram(c->protocol,bytes,n);wake(c->owner);}
static void stream_closed(void *user,int64_t id,uint64_t code) { struct connection *c=user;(void)code;hy2_server_stream_closed(c->protocol,id);wake(c->owner); }
static void closed(void *user,int reason,const char *why) {
    struct connection *c=user;(void)reason;(void)why;c->closed=1;c->quic=NULL;hy2_server_closed(c->protocol);steer_draft_hy2_datagram_stop(c->datagrams);wake(c->owner);
}
static int connection(void *user,struct qc *quic,struct qc_ops *ops,void **child_user) {
    struct steer_draft_hy2 *a=user;struct connection *c;char peer[64];uint16_t port;
    if(!a->admitting||a->stopping||qc_endpoint_peer(quic,peer,sizeof peer,&port))return -1;
    c=calloc(1,sizeof *c);if(!c)return -1;
    c->owner=a;c->quic=quic;c->peer=(struct steer_pv1_endpoint){.size=sizeof c->peer,.version=STEER_PV1_DRAFT_LAYOUT,.port=port};
    if(inet_pton(AF_INET,peer,c->source)==1) { c->peer.tag=STEER_PV1_ENDPOINT_IPV4;c->peer.address.len=4; }
    else if(inet_pton(AF_INET6,peer,c->source)==1) { c->peer.tag=STEER_PV1_ENDPOINT_IPV6;c->peer.address.len=16; }
    else { free(c);return -1; }
    c->peer.address.data=c->source;
    if(hy2_server_create(&a->protocol_config,&protocol_ops,c,&c->protocol)) { free(c);return -1; }
    if(a->services.datagrams&&hy2_server_enable_udp(c->protocol,datagram_input,c)){
        (void)hy2_server_destroy(c->protocol);free(c);return -1;
    }
    c->next=a->connections;a->connections=c;
    *ops=(struct qc_ops){.on_handshake=handshake,.on_stream_data=data,.on_stream_close=stream_closed,.on_datagram=datagram,.on_closed=closed};
    *child_user=c;return 0;
}
static void pump_flow(struct flow *f) {
    struct steer_draft_hy2 *a=f->connection->owner;struct direction *u=&f->upload,*d=&f->download;
    if(f->route_completed) {
        f->route.operation.api->release(f->route.operation.handle);f->route_pending=f->route_completed=0;
        if(!f->cancelled)(void)hy2_server_tcp_ready(f->tcp,!f->route_error&&f->target);
    }
    struct direction *directions[]={u,d};
    for(unsigned i=0;i<2;i++) if(directions[i]->completed) {
        struct direction *x=directions[i];
        x->operation.operation.api->release(x->operation.operation.handle);x->pending=x->completed=0;
        if(f->cancelled)continue;
        if(x->error) { abort_flow(f);continue; }
        if(!i) {
            if(!x->bytes||hy2_server_tcp_consume(f->tcp,x->bytes)) { abort_flow(f);continue; }
        } else if(!x->bytes) { f->remote_fin=1;x->length=0; }
        else { x->offset=0;x->length=x->bytes; }
    }
    if(f->cancelled||!f->target||f->route_pending)return;
    if(!u->pending&&!f->target_fin) {
        const uint8_t *bytes;int fin=0;size_t n=hy2_server_tcp_peek(f->tcp,&bytes,&fin);
        if(n) { if(n>CHUNK)n=CHUNK;uint8_t *out=view(u);if(!out)return;memcpy(out,bytes,n);if(submit(u,1,0,(uint32_t)n))return; }
        else if(fin) { if(a->streams->shutdown_write(f->target).code)abort_flow(f);else f->target_fin=1; }
    }
    if(f->cancelled||d->pending)return;
    if(d->length) {
        uint8_t *bytes=view(d);if(!bytes)return;
        int n=hy2_server_tcp_send(f->tcp,bytes+d->offset,d->length,0);
        if(n<0) { abort_flow(f);return; }
        d->offset+=(uint32_t)n;d->length-=(uint32_t)n;
    }
    if(!d->length) {
        if(f->remote_fin) { int r=hy2_server_tcp_finish(f->tcp);if(r<0)abort_flow(f); }
        else if(hy2_server_tcp_room(f->tcp)) (void)submit(d,0,0,CHUNK);
    }
}
static void reap(struct steer_draft_hy2 *a) {
    for(struct flow **p=&a->flows;*p;) {
        struct flow *f=*p;
        if(!f->cancelled||f->route_pending||f->upload.pending||f->download.pending) { p=&f->next;continue; }
        if(f->target) { a->streams->close(f->target);if(a->streams->release(f->target).code) { p=&f->next;continue; } }
        if(f->upload.buffer)a->buffers->release(a->services.buffers,f->upload.buffer);
        if(f->download.buffer)a->buffers->release(a->services.buffers,f->download.buffer);
        /* Last: only after route callback AND both stream operations drain. */
        if(f->lease_owned)a->services.release_route(a->services.context,&f->lease);
        (void)hy2_server_tcp_release(f->tcp);f->connection->flows--;a->flow_count--;
        *p=f->next;free(f);
    }
    for(struct connection **p=&a->connections;*p;) {
        struct connection *c=*p;
        if(!c->closed||c->flows) { p=&c->next;continue; }
        if(c->datagrams){
            if(steer_draft_hy2_datagram_destroy(c->datagrams)){p=&c->next;continue;}
            c->datagrams=NULL;
        }
        if(hy2_server_destroy(c->protocol)){p=&c->next;continue;}
        *p=c->next;free(c);
    }
}
static void work(struct loop *loop,struct loop_timer *timer,void *user) {
    struct steer_draft_hy2 *a=user;int timeout=-1;(void)loop;(void)timer;a->working=1;
    if(a->retiring&&!a->stopping&&(uint64_t)loop_now_ms()>=a->drain_deadline)steer_draft_hy2_stop(a);
    if(a->endpoint) { if(qc_endpoint_timeout_ms(a->endpoint)==0)(void)qc_endpoint_on_timer(a->endpoint);timeout=qc_endpoint_timeout_ms(a->endpoint); }
    for(struct connection *c=a->connections;c;c=c->next) if(!c->closed) {
        hy2_server_poll(c->protocol);int t=hy2_server_timeout_ms(c->protocol);if(t>=0&&(timeout<0||t<timeout))timeout=t;
    }
    for(struct flow *f=a->flows;f;f=f->next)pump_flow(f);
    for(struct connection *c=a->connections;c;c=c->next)if(c->datagrams)steer_draft_hy2_datagram_poll(c->datagrams);
    if(a->retiring)for(struct connection *c=a->connections;c;c=c->next)
        if(c->quic&&!c->flows&&!datagram_targets(c))qc_close(c->quic,0);
    for(struct connection *c=a->connections;c;c=c->next) if(c->quic)qc_flush_credit(c->quic);
    reap(a);
    if(a->endpoint) {
        int t=qc_endpoint_timeout_ms(a->endpoint);
        if(t>=0&&(timeout<0||t<timeout))timeout=t;
    }
    a->working=0;
    if(a->retiring&&!a->stopping) {
        uint64_t now=(uint64_t)loop_now_ms(),remaining=a->drain_deadline>now?a->drain_deadline-now:0;
        int t=remaining>INT_MAX?INT_MAX:(int)remaining;
        if(timeout<0||t<timeout)timeout=t;
    }
    if(timeout>=0)loop_timer_set(a->work,timeout);
}
static void readable(struct loop *loop,int fd,uint32_t events,void *user) {
    struct steer_draft_hy2 *a=user;(void)loop;(void)fd;(void)events;
    if(a->endpoint)(void)qc_endpoint_on_readable(a->endpoint);
    wake(a);
}
int steer_draft_hy2_open(const struct steer_draft_hy2_config *cfg,const struct steer_draft_inbound_services *services,struct steer_draft_hy2 **out) {
    struct steer_draft_hy2 *a;struct qc_endpoint_cfg ep;const struct qc_endpoint_ops ops={.on_connection=connection};size_t n;
    if(out)*out=NULL;
    if(!out||!cfg||!services||!services->loop||!services->buffers||!services->streams||!services->authenticate||!services->acquire_route||!services->release_route||!cfg->inbound_id)return -1;
    n=strnlen(cfg->inbound_id,65);if(!n||n>64||cfg->max_flows>1024||(cfg->start_paused!=0&&cfg->start_paused!=1))return -1;
    for(size_t i=0;i<n;i++) {
        unsigned char x=(unsigned char)cfg->inbound_id[i];
        if(!((x>='a'&&x<='z')||(x>='A'&&x<='Z')||(x>='0'&&x<='9')||x=='_'||x=='-'||x=='.'))return -1;
    }
    a=calloc(1,sizeof *a);if(!a)return -1;
    a->services=*services;
    if(services->datagrams){a->datagram_services=*services->datagrams;a->services.datagrams=&a->datagram_services;}
    a->protocol_config=cfg->protocol;a->max_flows=cfg->max_flows?cfg->max_flows:256;
    a->admitting=!cfg->start_paused;
    memcpy(a->inbound,cfg->inbound_id,n+1);a->streams=steer_draft_stream_api();a->buffers=steer_draft_buffers_api();
    a->work=loop_timer_new(services->loop,work,a);if(!a->work) { free(a);return -1; }
    /* Validate/normalize allocation limits before publishing any UDP listener.
     * Constructor owns no transport and this temporary engine has no streams. */
    struct connection validation={.owner=a};struct hy2_server_conn *probe=NULL;
    if(hy2_server_create(&a->protocol_config,&protocol_ops,&validation,&probe)) {
        loop_timer_free(a->work);free(a);return -1;
    }
    (void)hy2_server_destroy(probe);
    if(a->protocol_config.web_body_length) {
        a->web_body=malloc(a->protocol_config.web_body_length);
        if(!a->web_body) { loop_timer_free(a->work);free(a);return -1; }
        memcpy(a->web_body,a->protocol_config.web_body,a->protocol_config.web_body_length);
        a->protocol_config.web_body=a->web_body;
    }
    ep=cfg->endpoint;ep.flow_manual=1;
    if(services->datagrams&&!ep.server.datagram_max)ep.server.datagram_max=1500;
    /* Advertised QUIC receive credit must fit the protocol's retained queues.
     * Otherwise a conforming fast client can exhaust the engine before the
     * deferred target write completion returns credit. */
    size_t stream_queue=cfg->protocol.stream_queue?cfg->protocol.stream_queue:65536u;
    size_t connection_queue=cfg->protocol.connection_queue?cfg->protocol.connection_queue:1048576u;
    if(!ep.server.max_stream_data||ep.server.max_stream_data>stream_queue)ep.server.max_stream_data=stream_queue;
    if(!ep.server.max_data||ep.server.max_data>connection_queue)ep.server.max_data=connection_queue;
    if(qc_endpoint_open(&ep,&ops,a,&a->endpoint)||loop_fd_add(services->loop,qc_endpoint_fd(a->endpoint),EPOLLIN,readable,a)) {
        if(a->endpoint)qc_endpoint_free(a->endpoint);
        loop_timer_free(a->work);free(a->web_body);free(a);return -1;
    }
    a->registered=1;*out=a;return 0;
}
uint16_t steer_draft_hy2_port(const struct steer_draft_hy2 *a) { return a&&a->endpoint?qc_endpoint_port(a->endpoint):0; }
void steer_draft_hy2_activate(struct steer_draft_hy2 *a) { if(a&&!a->stopping&&!a->retiring)a->admitting=1; }
void steer_draft_hy2_retire(struct steer_draft_hy2 *a,uint64_t deadline_ms) {
    if(!a||a->stopping)return;
    if(!a->retiring||deadline_ms<a->drain_deadline)a->drain_deadline=deadline_ms;
    a->retiring=1;a->admitting=0;
    for(struct connection *c=a->connections;c;c=c->next)steer_draft_hy2_datagram_retire(c->datagrams);
    wake(a);
}
void steer_draft_hy2_stop(struct steer_draft_hy2 *a) {
    if(!a||a->stopping)return;
    a->stopping=1;
    if(a->registered) { loop_fd_del(a->services.loop,qc_endpoint_fd(a->endpoint));a->registered=0; }
    if(a->endpoint) { qc_endpoint_free(a->endpoint);a->endpoint=NULL; }
    wake(a);
}
int steer_draft_hy2_destroy(struct steer_draft_hy2 *a) {
    if(!a)return 0;
    if(!a->stopping||a->working||a->connections||a->flows)return -1;
    loop_timer_free(a->work);free(a->web_body);free(a);return 0;
}
size_t steer_draft_hy2_connections(const struct steer_draft_hy2 *a) { size_t n=0;if(a)for(struct connection *c=a->connections;c;c=c->next)if(!c->closed)n++;return n; }
size_t steer_draft_hy2_flows(const struct steer_draft_hy2 *a) { size_t n=a?a->flow_count:0;if(a)for(struct connection *c=a->connections;c;c=c->next)n+=datagram_targets(c);return n; }
void steer_draft_hy2_usage(const struct steer_draft_hy2 *a,struct steer_draft_hy2_usage *usage) {
    if(!usage)return;
    memset(usage,0,sizeof *usage);if(!a)return;
    usage->route_callbacks_after_cancel=a->route_callbacks_after_cancel;
    usage->io_callbacks_after_cancel=a->io_callbacks_after_cancel;
    usage->success_after_cancel=a->success_after_cancel;
    for(struct flow *f=a->flows;f;f=f->next) {
        usage->routes_pending+=(unsigned)f->route_pending;
        usage->reads_pending+=(unsigned)f->download.pending;
        usage->writes_pending+=(unsigned)f->upload.pending;
        usage->cancelled_flows+=(unsigned)f->cancelled;
        usage->queued_upload_bytes+=hy2_server_tcp_buffered(f->tcp);
    }
}
