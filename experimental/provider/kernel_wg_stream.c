#define _GNU_SOURCE
#include "kernel_wg_stream.h"
#include "awgdev.h"
#include "nftdump.h"
#include "nltransport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62 /* Linux socket UAPI */
#endif

struct steer_draft_wg_stream {
    struct steer_draft_wg_guard_record guard;
    struct awg_prefix source,route;
    int ns,scoped;
};

int steer_draft_wg_stream_verify(const struct steer_draft_wg_stream *w,uint64_t d){
    if(!w||!d)return EINVAL;
    const struct steer_draft_wg_guard_record *r=&w->guard;
    struct steer_draft_wg_observation seen;
    int rc=steer_draft_wg_identity_reconcile(&r->link,w->ns,d,&seen);
    if(rc)return rc;
    if(seen.state!=STEER_DRAFT_WG_OWNED||(uint32_t)seen.index!=r->ifindex)return ESTALE;
    struct nfd_exact_table table;
    rc=nfd_exact_inet_until(r->table,&table,d);
    if(rc)return rc;
    if(steer_draft_wg_guard_record_observe(r,table.handle,table.comment)!=STEER_DRAFT_WG_OWNED)return ESTALE;
    /* The route check also checks UP, kind, group and index. */
    return (w->scoped?awg_dev_scoped_route_check_until:awg_dev_route_check_owned_until)(
        r->link.physical_name,r->link.kind,seen.index,
        r->link.group,&w->route,d);
}

int steer_draft_wg_stream_create(const struct steer_draft_wg_linux_link *link,
    const struct steer_draft_wg_guard_record *r,const struct awg_prefix *source,
    const struct awg_prefix *route,int scoped,uint64_t deadline,struct steer_draft_wg_stream **out){
    if(!out)return EINVAL;
    *out=NULL;
    uint8_t bytes[STEER_DRAFT_WG_GUARD_RECORD_BYTES];
    if(!link||!r||!r->handle||steer_draft_wg_guard_record_encode(r,bytes)||
       !source||source->family!=AF_INET||source->cidr!=32||
       !route||route->family!=AF_INET||route->cidr<24||route->cidr>32)return EINVAL;
    int ns=fcntl(steer_draft_wg_linux_link_namespace(link),F_DUPFD_CLOEXEC,3);
    if(ns<0)return errno;
    struct steer_draft_wg_stream *w=malloc(sizeof(*w));
    if(!w){close(ns);return ENOMEM;}
    *w=(struct steer_draft_wg_stream){.guard=*r,.source=*source,.route=*route,.ns=ns,.scoped=scoped};
    int rc=steer_draft_wg_stream_verify(w,deadline);
    if(rc){steer_draft_wg_stream_destroy(w);return rc;}
    *out=w;
    return 0;
}

void steer_draft_wg_stream_destroy(struct steer_draft_wg_stream *w){
    if(w){close(w->ns);free(w);}
}
uint64_t steer_draft_wg_stream_generation(const struct steer_draft_wg_stream *w){
    return w?w->guard.link.generation:0;
}
int steer_draft_wg_stream_contains(const struct steer_draft_wg_stream *w,const uint8_t addr[4]){
    if(!w)return 0;
    const struct awg_prefix *p=&w->route;
    unsigned n=p->cidr/8,tail=p->cidr%8;
    return !memcmp(p->addr,addr,n)&&(!tail||!((p->addr[n]^addr[n])&(0xffu<<(8-tail))));
}
uint32_t steer_draft_wg_stream_bind(void *ctx,int fd,const struct sockaddr_storage *to,uint64_t d){
    const struct steer_draft_wg_stream *w=ctx;
    if(!w||!to||to->ss_family!=AF_INET)return STEER_PV1_POLICY_DENIED;
    struct sockaddr_in source={.sin_family=AF_INET},target;
    memcpy(&target,to,sizeof(target));
    if(!steer_draft_wg_stream_contains(w,(const uint8_t *)&target.sin_addr))return STEER_PV1_POLICY_DENIED;
    uint64_t now=steer_nl_now_ns();
    if(!now)return STEER_PV1_IO;
    const uint64_t maximum=now+50000000u;
    if(d>maximum)d=maximum;
    int idx=(int)w->guard.ifindex;
    memcpy(&source.sin_addr,w->source.addr,4);
    if(setsockopt(fd,SOL_SOCKET,SO_BINDTOIFINDEX,&idx,sizeof(idx))||
       bind(fd,(const struct sockaddr *)&source,sizeof(source)))return STEER_PV1_POLICY_DENIED;
    if(steer_draft_wg_stream_verify(w,d))return STEER_PV1_POLICY_DENIED;
    if(w->scoped&&awg_dev_scoped_route_match_until(idx,w->guard.link.group,&w->route,
        w->source.addr,(const uint8_t *)&target.sin_addr,d))return STEER_PV1_POLICY_DENIED;
    return STEER_PV1_OK;
}
