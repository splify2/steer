/* SPDX-License-Identifier: GPL-3.0-only
 * Disposable loopback integration fixture, NOT a production host or UI path. */
#define _GNU_SOURCE
#include "hy2_inbound.h"
#include "buffers.h"
#include "loop.h"
#include "resolver.h"
#include "qccert.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <netdb.h>
struct lab {
    struct loop *loop;struct loop_timer *finish;
    struct steer_pv1_host *buffers;struct steer_draft_stream_runtime *streams;
    struct steer_draft_routes *routes;struct steer_draft_resolver *resolver;
    struct steer_draft_hy2 *hy2;
    const char *token;uint64_t epoch;unsigned leases;int admitting,stopping;
    pthread_mutex_t lock;pthread_cond_t changed;int hold_dns,hold_route;
};
static struct lab *active_lab;
struct delayed_route { int used,ready;steer_draft_route_done done;void *user;struct steer_pv1_error error;uint32_t failure;struct steer_pv1_stream *target; };
static struct delayed_route delayed[128];
struct steer_pv1_async_start __real_steer_draft_route_dial(struct steer_draft_routes *,const struct steer_draft_accepted *,uint64_t,steer_draft_route_done,void *);
static void delayed_done(void *user,struct steer_pv1_error error,uint32_t failure,struct steer_pv1_stream *target,const struct steer_pv1_endpoint *bound) {
    struct delayed_route *d=user;(void)bound;d->error=error;d->failure=failure;d->target=target;d->ready=1;
}
/* Lab-only callback scheduling perturbation. The real core route operation,
 * connected target and queued-success ownership remain intact. */
struct steer_pv1_async_start __wrap_steer_draft_route_dial(struct steer_draft_routes *routes,const struct steer_draft_accepted *flow,uint64_t deadline,steer_draft_route_done done,void *user) {
    if(!active_lab->hold_route)return __real_steer_draft_route_dial(routes,flow,deadline,done,user);
    struct delayed_route *d=NULL;for(unsigned i=0;i<128;i++)if(!delayed[i].used) { d=&delayed[i];break; }
    assert(d);*d=(struct delayed_route){.used=1,.done=done,.user=user};
    struct steer_pv1_async_start result=__real_steer_draft_route_dial(routes,flow,deadline,delayed_done,d);
    if(result.disposition!=STEER_PV1_PENDING)memset(d,0,sizeof *d);
    return result;
}
static void release_delayed(void) {
    for(unsigned i=0;i<128;i++)if(delayed[i].used&&delayed[i].ready) {
        struct delayed_route d=delayed[i];memset(&delayed[i],0,sizeof delayed[i]);
        d.done(d.user,d.error,d.failure,d.target,NULL);
    }
}
static void resolve(void *user,const char *host,uint16_t port,struct steer_draft_resolve_result *result) {
    struct lab *l=user;struct addrinfo hints={.ai_socktype=SOCK_STREAM},*addresses=NULL;char service[8];
    memset(result,0,sizeof *result);snprintf(service,sizeof service,"%u",port);
    if(getaddrinfo(host,service,&hints,&addresses))result->code=STEER_PV1_IO;
    else {
        for(struct addrinfo *p=addresses;p&&result->count<STEER_DRAFT_RESOLVE_ADDRESSES;p=p->ai_next)
            if(p->ai_addrlen<=sizeof result->addresses[0])memcpy(&result->addresses[result->count++],p->ai_addr,p->ai_addrlen);
        freeaddrinfo(addresses);
    }
    pthread_mutex_lock(&l->lock);while(l->hold_dns)pthread_cond_wait(&l->changed,&l->lock);pthread_mutex_unlock(&l->lock);
}
static int same(struct steer_pv1_span s,const char *text) { return s.len==strlen(text)&&!memcmp(s.data,text,s.len); }
static int authenticate(void *user,struct steer_pv1_span inbound,const uint8_t *token,size_t n,char principal[65],uint64_t *epoch) {
    struct lab *l=user;unsigned difference=0;size_t size=strlen(l->token);
    if(!l->admitting||!same(inbound,"hy2-lab")||n!=size)return 0;
    for(size_t i=0;i<n;i++)difference|=token[i]^(uint8_t)l->token[i];
    if(difference)return 0;
    strcpy(principal,"lab-user");*epoch=l->epoch;return 1;
}
static struct steer_pv1_error acquire(void *user,struct steer_pv1_span inbound,struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_route_lease *lease) {
    struct lab *l=user;
    if(!l->admitting||epoch!=l->epoch||!same(inbound,"hy2-lab")||!same(principal,"lab-user"))
        return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};
    *lease=(struct steer_draft_route_lease){l->routes,7,l,NULL};l->leases++;
    return (struct steer_pv1_error){0,0};
}
static void release(void *user,struct steer_draft_route_lease *lease) {
    struct lab *l=user;assert(lease->handle==l&&l->leases);l->leases--;memset(lease,0,sizeof *lease);
}
static struct steer_pv1_error evaluate(void *user,const struct steer_draft_accepted *flow,uint32_t *action) {
    (void)user;
    assert(flow->generation==7&&same(flow->inbound_id,"hy2-lab")&&same(flow->principal_id,"lab-user"));
    assert(flow->source.port&&flow->source.tag==STEER_PV1_ENDPOINT_IPV4&&flow->source.address.len==4);
    assert(flow->source.address.data[0]==127); /* genuine QUIC loopback peer */
    int local=flow->destination.tag==STEER_PV1_ENDPOINT_IPV4&&flow->destination.address.len==4&&flow->destination.address.data[0]==127;
    if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&same(flow->destination.address,"localhost"))local=1;
    *action=local?STEER_DRAFT_ROUTE_DIRECT:STEER_DRAFT_ROUTE_BLOCK;
    return (struct steer_pv1_error){0,0};
}
static void finish(struct loop *loop,struct loop_timer *timer,void *user) {
    struct lab *l=user;(void)timer;
    if(l->hy2&&steer_draft_hy2_destroy(l->hy2)) { loop_timer_set(l->finish,1);return; }
    l->hy2=NULL;assert(!l->leases);
    if(l->routes) { assert(!steer_draft_routes_destroy(l->routes).code);l->routes=NULL; }
    if(steer_draft_resolver_destroy(l->resolver).code) { loop_timer_set(l->finish,1);return; }
    assert(!steer_draft_stream_runtime_destroy(l->streams).code);
    assert(!steer_draft_buffers_destroy(l->buffers).code);
    puts("DRAINED leases=0 operations=0 buffers=0");fflush(stdout);loop_stop(loop,0);
}
static void input(struct loop *loop,int fd,uint32_t events,void *user) {
    struct lab *l=user;char command[64];(void)loop;(void)fd;(void)events;
    if(!fgets(command,sizeof command,stdin)||!strcmp(command,"stop\n")) {
        if(!l->stopping) {
            l->stopping=1;steer_draft_hy2_stop(l->hy2);release_delayed();
            pthread_mutex_lock(&l->lock);l->hold_dns=0;pthread_cond_broadcast(&l->changed);pthread_mutex_unlock(&l->lock);
            loop_timer_set(l->finish,0);
        }
    } else if(!strcmp(command,"deny\n")) { l->admitting=0;puts("ACK deny"); }
    else if(!strcmp(command,"allow\n")) { l->admitting=1;puts("ACK allow"); }
    else if(!strcmp(command,"epoch\n")) { l->epoch++;puts("ACK epoch"); }
    else if(!strcmp(command,"activate\n")) { steer_draft_hy2_activate(l->hy2);puts("ACK activate"); }
    else if(!strcmp(command,"retire\n")) { steer_draft_hy2_retire(l->hy2,(uint64_t)loop_now_ms()+1000);puts("ACK retire"); }
    else if(!strcmp(command,"dns-hold\n")) { pthread_mutex_lock(&l->lock);l->hold_dns=1;pthread_mutex_unlock(&l->lock);puts("ACK dns-hold"); }
    else if(!strcmp(command,"dns-release\n")) { pthread_mutex_lock(&l->lock);l->hold_dns=0;pthread_cond_broadcast(&l->changed);pthread_mutex_unlock(&l->lock);puts("ACK dns-release"); }
    else if(!strcmp(command,"route-hold\n")) { l->hold_route=1;puts("ACK route-hold"); }
    else if(!strcmp(command,"route-release\n")) { l->hold_route=0;release_delayed();puts("ACK route-release"); }
    else if(!strcmp(command,"stats\n")) {
        struct steer_draft_hy2_usage usage;steer_draft_hy2_usage(l->hy2,&usage);unsigned held=0;
        for(unsigned i=0;i<128;i++)held+=(unsigned)(delayed[i].used&&delayed[i].ready);
        printf("STATS %zu %zu %u %zu %zu %zu %zu %llu %llu %llu %u %zu\n",steer_draft_hy2_connections(l->hy2),steer_draft_hy2_flows(l->hy2),l->leases,
            usage.routes_pending,usage.reads_pending,usage.writes_pending,usage.cancelled_flows,
            (unsigned long long)usage.route_callbacks_after_cancel,(unsigned long long)usage.io_callbacks_after_cancel,(unsigned long long)usage.success_after_cancel,held,usage.queued_upload_bytes);
    }
    fflush(stdout);
}
int main(void) {
    struct lab l={.epoch=1,.admitting=1};
    active_lab=&l;assert(!pthread_mutex_init(&l.lock,NULL));assert(!pthread_cond_init(&l.changed,NULL));
    l.token=getenv("STEER_LAB_HY2_TOKEN");if(!l.token||!l.token[0]||strlen(l.token)>1024)return 2;
    l.loop=loop_new();assert(l.loop);
    struct steer_draft_buffer_limits limits={8u*1024u*1024u,512,1};
    assert(!steer_draft_buffers_create(&limits,NULL,&l.buffers).code);
    assert(!steer_draft_stream_runtime_create(l.loop,l.buffers,128,512,8u*1024u*1024u,&l.streams).code);
    assert(!steer_draft_routes_create(l.loop,l.streams,7,128,evaluate,&l,&l.routes).code);
    assert(!steer_draft_resolver_create(l.loop,2,64,resolve,&l,&l.resolver).code);
    assert(!steer_draft_routes_use_resolver(l.routes,l.resolver).code);
    struct steer_draft_inbound_services services={l.loop,l.buffers,l.streams,&l,authenticate,acquire,release,NULL};
    struct steer_draft_hy2_config cfg={.inbound_id="hy2-lab",.max_flows=64,.endpoint={.max_connections=8,.server={
        .bind_host="127.0.0.1",.alpn="h3",.cert_der=qc_cert_der,.cert_n=sizeof qc_cert_der,
        .key_der=qc_key_der,.key_n=sizeof qc_key_der,.idle_ms=5000}}};
    cfg.start_paused=getenv("STEER_LAB_PAUSED")!=NULL;
    unsigned engine_limit=getenv("STEER_LAB_ENGINE_LIMIT")?4u:0u;
    struct steer_draft_hy2 *invalid=(void *)1;
    cfg.protocol.max_tcp_streams=129;assert(steer_draft_hy2_open(&cfg,&services,&invalid)==-1&&!invalid);cfg.protocol.max_tcp_streams=0;
    cfg.protocol.stream_queue=262145;assert(steer_draft_hy2_open(&cfg,&services,&invalid)==-1&&!invalid);cfg.protocol.stream_queue=0;
    cfg.protocol.web_status=199;assert(steer_draft_hy2_open(&cfg,&services,&invalid)==-1&&!invalid);cfg.protocol.web_status=0;
    cfg.protocol.web_body_length=1;assert(steer_draft_hy2_open(&cfg,&services,&invalid)==-1&&!invalid);cfg.protocol.web_body_length=0;
    cfg.protocol.max_tcp_streams=engine_limit;
    const char body[]="owned fixture body";uint8_t *temporary=malloc(sizeof body-1);assert(temporary);
    memcpy(temporary,body,sizeof body-1);cfg.protocol.web_body=temporary;cfg.protocol.web_body_length=sizeof body-1;
    assert(!steer_draft_hy2_open(&cfg,&services,&l.hy2));
    memset(temporary,0xa5,sizeof body-1);free(temporary);memset(&cfg,0,sizeof cfg);
    l.finish=loop_timer_new(l.loop,finish,&l);assert(l.finish);
    assert(!loop_fd_add(l.loop,0,EPOLLIN,input,&l));
    printf("PORT %u\n",steer_draft_hy2_port(l.hy2));fflush(stdout);
    int result=loop_run(l.loop);loop_timer_free(l.finish);loop_free(l.loop);
    assert(!pthread_cond_destroy(&l.changed));assert(!pthread_mutex_destroy(&l.lock));return result;
}
