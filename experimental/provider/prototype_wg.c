#define _GNU_SOURCE
#include "prototype_wg.h"
#include "kernel_wg_linux_guard.h"
#include "kernel_wg_v3.h"
#include "prototype_store.h"
#include "flow_metadata.h"
#include "../spec/spec.h"
#include "awgdev.h"
#include "blake3.h"
#include "jsonw.h"
#include "ynode.h"
#include <errno.h>
#include <limits.h>
#include <linux/capability.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62 /* Linux socket UAPI */
#endif

struct steer_prototype_wg {
    struct steer_prototype_store *store;
    struct steer_draft_wg_selection *journal;
    struct steer_draft_wg_linux_guard guard;
    struct steer_store_document *current;
    struct steer_draft_wg_revision revision;
    struct awg_prefix address;
    struct awg_prefix route,endpoint;
    struct steer_draft_wg_guard_record selected;
    uint16_t socks_port;
    uint16_t port;
    uint64_t next;
    int fenced,uncertain,egress;
};

struct parsed {
    struct steer_draft_wg_v3_config cfg;
    struct steer_store_document *doc;
    struct steer_spec_plan *plan;
    uint32_t action;
    struct awg_prefix route;
    int egress;
};

static int eq(const struct ynode *n,const char *s){
    return n&&n->kind==YN_SCALAR&&!n->tag&&!strcmp(n->str,s);
}
static int map(const struct ynode *n,size_t count){
    return n&&n->kind==YN_MAP&&!n->tag&&n->len==count;
}
static int contains(const struct awg_prefix *p,const uint8_t addr[4]){
    if(p->family!=AF_INET)return 0;
    unsigned n=p->cidr/8,tail=p->cidr%8;
    return !memcmp(p->addr,addr,n)&&(!tail||!((p->addr[n]^addr[n])&(0xffu<<(8-tail))));
}
static int socks_opts(void *unused,const struct ynode *options){
    (void)unused;
    return map(options,0);
}
static int one_flow(const struct ynode *seq,const char *flow){
    return seq&&seq->kind==YN_SEQ&&!seq->tag&&seq->len==1&&eq(ynode_at(seq,0),flow);
}
static int env_name(const char *name){
    if(strncmp(name,"STEER_WG_",9)||!name[9]||strlen(name)>63)return 0;
    for(const char *p=name+9;*p;p++)
        if(!((*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'))return 0;
    return 1;
}
static struct steer_pv1_error secret(void *ctx,struct steer_pv1_span id,uint8_t out[44]){
    const struct ynode *secrets=ctx;
    char name[64]={0};
    if(id.len>=sizeof(name))return (struct steer_pv1_error){STEER_PV1_INVALID,0};
    memcpy(name,id.data,id.len);
    const struct ynode *env=ynode_get(ynode_get(secrets,name),"name");
    const char *value=env&&env_name(env->str)?getenv(env->str):NULL;
    if(!value||strnlen(value,45)!=44)return (struct steer_pv1_error){STEER_PV1_AUTH_FAILED,0};
    memcpy(out,value,44);
    return (struct steer_pv1_error){0,0};
}

/* Profile validation leaves only three numeric positions, no boolean/nullable
 * values. Emit canonical refs-only JSON accepted by the normal durable store. */
static void write_intent(FILE *out,const struct ynode *n,const char *key){
    if(n->kind==YN_SCALAR){
        if(!strcmp(key,"version")||!strcmp(key,"listen_port")||!strcmp(key,"mtu")||!strcmp(key,"port")){
            long value;
            if(!ynode_long(n,&value)){fprintf(out,"%ld",value);return;}
        }
        jsonw_str(out,n->str);
        return;
    }
    fputc(n->kind==YN_MAP?'{':'[',out);
    for(size_t i=0;i<n->len;i++){
        if(i)fputc(',',out);
        if(n->kind==YN_MAP){
            const char *name=ynode_key_at(n,i)->str;
            jsonw_str(out,name);fputc(':',out);
            write_intent(out,ynode_val_at(n,i),name);
        }else write_intent(out,ynode_at(n,i),"");
    }
    fputc(n->kind==YN_MAP?'}':']',out);
}
static int lower(const char *data,size_t size,uint64_t generation,uint16_t socks,struct parsed *p){
    static const struct steer_spec_capability caps[]={
        {"core.spec-v3.apply",STEER_SPEC_READY,NULL,NULL},
        {"core.secret.env",STEER_SPEC_READY,NULL,NULL},
        {"core.outbound.direct",STEER_SPEC_READY,NULL,NULL},
        {"core.outbound.block",STEER_SPEC_READY,NULL,NULL},
        {"plugin.lock.main",STEER_SPEC_READY,NULL,NULL}, /* exact local builtin tuple below */
        {"core.transport.udp",STEER_SPEC_READY,NULL,NULL},
        {"provider.socks:main/inbound/stream/tcp/none/default",STEER_SPEC_READY,socks_opts,NULL},
        {"provider.wireguard:main/outbound/stream/udp/none/kernel",STEER_SPEC_READY,steer_draft_wg_v3_egress_options,NULL},
        {"provider.wireguard:main/inbound/device/device/none/default",STEER_SPEC_READY,steer_draft_wg_v3_options,NULL}
    };
    p->plan=steer_spec_compile(data,size,caps,sizeof(caps)/sizeof(*caps));
    struct steer_spec_summary s=steer_spec_summary(p->plan);
    if(!s.runtime_ready)return EINVAL;
    const struct ynode *root=steer_spec_intent(p->plan),*remotes=ynode_get(root,"plugin_remotes"),
        *plugins=ynode_get(root,"plugins"),*inbounds=ynode_get(root,"inbounds"),
        *outbounds=ynode_get(root,"outbounds"),*routing=ynode_get(root,"routing"),
        *secrets=ynode_get(root,"secrets"),*rules=ynode_get(routing,"rules"),
        *remote=ynode_get(remotes,"local"),*plugin=ynode_get(plugins,"main"),
        *in=ynode_get(inbounds,"vpn"),*out=ynode_get(outbounds,"local-output");
    const struct ynode *entry=ynode_get(inbounds,"socks-entry"),*tunnel=ynode_get(outbounds,"tunnel");
    const struct ynode *listen=ynode_get(entry,"listen");
    long version;
    if(!map(root,7)||ynode_long(ynode_get(root,"version"),&version)||version!=3||
       !map(remotes,1)||!map(remote,2)||!eq(ynode_get(remote,"url"),"https://example.invalid")||
       !eq(ynode_get(remote,"trust"),"local")||!map(plugins,1)||!map(plugin,3)||
       !eq(ynode_get(plugin,"remote"),"local")||!eq(ynode_get(plugin,"package"),"protocols")||
       !eq(ynode_get(plugin,"version"),"0.0.0")||!map(inbounds,1)||!map(outbounds,1)||
       !map(routing,2)||
       !rules||rules->kind!=YN_SEQ||rules->len||!secrets||secrets->kind!=YN_MAP||
       !secrets->len||secrets->len>9)return EINVAL;
    for(size_t i=0;i<secrets->len;i++){
        const struct ynode *decl=ynode_val_at(secrets,i),*name=ynode_get(decl,"name"),*kind=ynode_get(decl,"kind");
        if(!map(decl,3)||!eq(ynode_get(decl,"source"),"env")||!name||name->kind!=YN_SCALAR||
           !env_name(name->str)||(!eq(kind,"wireguard_private_key")&&!eq(kind,"wireguard_preshared_key")))
            return EINVAL;
    }
    p->egress=!!tunnel;
    if(p->egress){
        long port;
        if(!socks||!map(entry,4)||!eq(ynode_get(entry,"plugin"),"socks:main")||
           !one_flow(ynode_get(entry,"flow"),"stream")||!map(ynode_get(entry,"options"),0)||
           !map(listen,2)||!eq(ynode_get(listen,"address"),"127.0.0.1")||
           ynode_long(ynode_get(listen,"port"),&port)||port!=socks||
           !map(tunnel,6)||!eq(ynode_get(routing,"default"),"tunnel"))return EINVAL;
        /* TCP response packets from the sole authenticated peer must pass the
         * inbound guard. Host forwarding remains off. */
        p->action=STEER_POLICY_DIRECT;
    }else{
        if(!map(in,4)||!map(ynode_get(in,"device"),1)||!map(out,2)||
           !eq(ynode_get(routing,"default"),"local-output"))return EINVAL;
        p->action=eq(ynode_get(out,"type"),"direct")?STEER_POLICY_DIRECT:STEER_POLICY_BLOCK;
    }
    int got=0;
    for(uint32_t n=0;n<s.nodes;n++){
        struct steer_spec_node_view node;
        if(!steer_spec_node(p->plan,n,&node))return EINVAL;
        if(p->egress&&node.kind==STEER_SPEC_OUTBOUND)
            got=steer_draft_wg_v3_egress(p->plan,n,&p->cfg,&p->route);
        if(!p->egress&&node.kind==STEER_SPEC_INBOUND)
            got=steer_draft_wg_v3_configure(p->plan,n,&p->cfg);
        if(!p->egress&&node.kind==STEER_SPEC_OUTBOUND&&(!node.enabled||node.flows!=STEER_SPEC_FLOW_DEVICE||
           (!eq(ynode_get(out,"type"),"direct")&&!eq(ynode_get(out,"type"),"block"))))return EINVAL;
    }
    if(!got)return EINVAL;
    if(!p->egress&&(p->cfg.kernel.addr_n!=1||p->cfg.kernel.addr[0].family!=AF_INET||
       p->cfg.kernel.addr[0].cidr!=24||!p->cfg.kernel.addr[0].addr[3]||
       p->cfg.kernel.addr[0].addr[3]==255))return EINVAL;
    for(size_t i=0;!p->egress&&i<p->cfg.kernel.aips_n;i++){
        const struct awg_prefix *a=&p->cfg.kernel.aips[i],*host=&p->cfg.kernel.addr[0];
        if(a->family!=AF_INET||a->cidr!=32||memcmp(a->addr,host->addr,3)||!a->addr[3]||
           a->addr[3]==255||a->addr[3]==host->addr[3])return EINVAL;
    }
    p->doc=calloc(1,sizeof(*p->doc));
    if(!p->doc)return ENOMEM;
    FILE *out_file=open_memstream(&p->doc->document,&p->doc->length);
    if(!out_file)return ENOMEM;
    write_intent(out_file,root,"");
    if(fclose(out_file)||p->doc->length>STEER_PROTOTYPE_CONFIG_MAX_BYTES)return EINVAL;
    p->doc->generation=generation;
    p->doc->format=STEER_STORE_FORMAT_SPEC_V3;
    return 0;
}
static void parsed_free(struct parsed *p){
    steer_store_document_destroy(p->doc);
    steer_spec_destroy(p->plan);
}
static uint64_t deadline(void){
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec+8000000000u;
}
static int verify(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d){
    const struct steer_draft_wg_linux_guard *g=ctx;
    uint64_t handle;
    char marker[256];
    int rc=steer_draft_wg_linux_guard_backend.lookup_guard(ctx,r,d,&handle,marker);
    if(rc)return rc;
    if(steer_draft_wg_guard_record_observe(r,handle,marker)!=STEER_DRAFT_WG_OWNED)return ESTALE;
    rc=awg_dev_link_require_down_owned_until(r->link.physical_name,r->link.kind,
        (int)r->ifindex,r->link.group,d);
    if(rc!=EBUSY)return rc?rc:ESTALE;
    return g->route?awg_dev_route_check_owned_until(r->link.physical_name,r->link.kind,
        (int)r->ifindex,r->link.group,g->route,d):0;
}
static int recovery(struct steer_prototype_wg *w){
    w->guard.route=w->egress?&w->route:NULL;
    int rc=steer_draft_wg_selection_startup(w->journal,&steer_draft_wg_linux_guard_backend,&w->guard,
        &w->revision,verify,deadline(),&w->next,&w->selected);
    w->guard.route=NULL;
    return rc;
}
static void document_digest(uint8_t out[32],const struct steer_store_document *doc){
    static const char profile[]="steer spec v3: wg-netns-v1";
    uint8_t digest[32];
    b3_hash(digest,doc->document,doc->length);
    b3_derive_key(out,32,profile,sizeof(profile)-1,digest,sizeof(digest));
}
static void choose(struct steer_prototype_wg *w,struct parsed *p){
    steer_store_document_destroy(w->current);
    w->current=p->doc;p->doc=NULL;
    w->port=p->cfg.kernel.listen_port;
    w->address=p->cfg.kernel.addr[0];
    w->egress=p->egress;
    w->route=p->route;
    if(p->egress){
        struct sockaddr_in ep;
        memcpy(&ep,&p->cfg.kernel.peer[0].ep,sizeof(ep));
        memcpy(w->endpoint.addr,&ep.sin_addr,4);
    }
    w->revision.generation=w->current->generation;
    document_digest(w->revision.digest,w->current);
}
static int forwarding_disabled(void){
    FILE *f=fopen("/proc/sys/net/ipv4/ip_forward","r");
    if(!f)return 0;
    int allowed=fgetc(f)=='0'&&fgetc(f)=='\n';
    fclose(f);
    return allowed;
}
static int bind_index_available(void){
    unsigned idx=if_nametoindex("lo");
    if(!idx)return 0;
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(fd<0)return 0;
    int ok=!setsockopt(fd,SOL_SOCKET,SO_BINDTOIFINDEX,&idx,sizeof(idx));
    close(fd);
    return ok;
}
void steer_prototype_wg_close(struct steer_prototype_wg *w){
    if(!w)return;
    steer_store_document_destroy(w->current);
    steer_draft_wg_selection_close(w->journal);
    if(w->store)steer_prototype_store_close(w->store);
    steer_draft_wg_linux_link_close(w->guard.link);
    free(w);
}
int steer_prototype_wg_open(const char *state,int outer,uint16_t socks,struct steer_prototype_wg **out){
    *out=NULL;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={0};
    char journal[PATH_MAX];
    int len=snprintf(journal,sizeof(journal),"%s/wg-journal",state);
    if(geteuid()!=0||syscall(SYS_capget,&header,caps)||!(caps[0].effective&(1u<<CAP_NET_ADMIN))||
       len<0||(size_t)len>=sizeof(journal)||*state!='/')return EPERM;
    struct steer_prototype_wg *w=calloc(1,sizeof(*w));
    if(!w)return ENOMEM;
    w->socks_port=socks;
    int rc=EIO;
    struct steer_store_document *on_disk=NULL;
    if(steer_draft_wg_linux_link_open(outer,&w->guard.link)||!forwarding_disabled()||
       (socks&&!bind_index_available())||
       steer_prototype_store_open(state,&w->store).code||
       steer_draft_wg_selection_open(journal,32,&w->journal))goto fail;
    struct steer_pv1_error loaded=steer_prototype_store_recover_document(w->store,&on_disk);
    if(loaded.code!=STEER_PV1_UNSUPPORTED){
        if(loaded.code||on_disk->format!=STEER_STORE_FORMAT_SPEC_V3)goto fail;
        struct parsed p={0};
        rc=lower(on_disk->document,on_disk->length,on_disk->generation,w->socks_port,&p);
        if(!rc&&(on_disk->length!=p.doc->length||memcmp(on_disk->document,p.doc->document,p.doc->length)))rc=EPROTO;
        if(!rc)choose(w,&p);
        parsed_free(&p);
        if(rc)goto fail;
    }
    rc=recovery(w);
    if(rc)goto fail;
    steer_store_document_destroy(on_disk);
    *out=w;
    return 0;
fail:
    steer_store_document_destroy(on_disk);
    steer_prototype_wg_close(w);
    return rc;
}

static uint64_t stream_deadline(void);
static int egress_live(struct steer_prototype_wg *w,uint64_t d);

static int apply(struct steer_prototype_wg *w,struct parsed *p){
    struct awg_secrets keys={0};
    if(w->egress&&!egress_live(w,stream_deadline()))return 503;
    if(w->port){
        if(p->cfg.kernel.listen_port==w->port||p->egress!=w->egress)return 409;
        if(!p->egress&&!memcmp(p->cfg.kernel.addr[0].addr,w->address.addr,3))return 409;
        if(p->egress){
            struct sockaddr_in ep;
            memcpy(&ep,&p->cfg.kernel.peer[0].ep,sizeof(ep));
            const uint8_t *underlay=(const uint8_t *)&ep.sin_addr;
            const uint8_t *source=p->cfg.kernel.addr[0].addr;
            if(!memcmp(source,w->address.addr,4)||contains(&p->route,w->route.addr)||
               contains(&w->route,p->route.addr)||contains(&w->route,underlay)||
               contains(&p->route,w->endpoint.addr)||contains(&w->route,source)||
               contains(&p->route,w->address.addr)||!memcmp(source,w->endpoint.addr,4)||
               !memcmp(underlay,w->address.addr,4))return 409;
        }
    }
    if(steer_draft_wg_v3_keys(&p->cfg,secret,(void *)ynode_get(steer_spec_intent(p->plan),"secrets"),&keys).code)
        return 422;
    struct steer_prototype_store_transaction *txn=NULL;
    struct steer_policy *policy=NULL;
    struct steer_draft_wg_tx tx={.generation=w->next,.transaction=w->next,.instance=w->next};
    document_digest(tx.plan_digest,p->doc);
    struct steer_draft_wg_candidate c={.config=&p->cfg.kernel,.keys=&keys};
    uint64_t d=deadline();
    int status=503,attempted=0;
    if(steer_prototype_store_prepare_document(w->store,p->doc,&txn).code||
       steer_draft_wg_linux_link_prepare(w->guard.link,&tx,d,NULL,&c.link))goto done;
    struct steer_draft_kernel_wg_guard_config *cfg=&p->cfg.guard;
    cfg->generation=tx.generation;
    cfg->return_only=p->egress;
    strcpy(cfg->device,c.link.physical_name);
    if(steer_policy_compile(tx.generation,NULL,0,p->action,&policy).code||
       steer_draft_kernel_wg_guard_prepare(cfg,policy,&w->guard.prepared).code||
       steer_draft_kernel_wg_guard_plan(w->guard.prepared,c.table,c.marker))goto done;
    attempted=1;
    w->guard.route=p->egress?&p->route:NULL;
    if(steer_draft_wg_selection_stage(w->journal,&steer_draft_wg_linux_guard_backend,&w->guard,
        &w->revision,w->port,&tx,&c,d))goto done;
    struct steer_prototype_store_result r=steer_prototype_store_commit(txn);
    if(r.phase==STEER_PROTOTYPE_STORE_SYNCED&&!r.error.code){choose(w,p);status=200;}
    else if(r.phase>=STEER_PROTOTYPE_STORE_RENAMED)w->uncertain=w->fenced=1;
done:
    w->guard.route=NULL;
    awg_secrets_wipe(&keys);
    if(txn)steer_prototype_store_abort(txn);
    if(policy)steer_policy_destroy(policy);
    if(attempted&&!w->uncertain&&recovery(w))w->fenced=1;
    /* A selected kernel guard is intentionally retained, but this worker no
     * longer needs the policy IR. Drop only memory, never kernel ownership. */
    if(w->guard.prepared){
        steer_draft_kernel_wg_guard_forget_prepared(w->guard.prepared);
        w->guard.prepared=NULL;
    }
    return status;
}
static uint64_t stream_deadline(void){
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
    return (uint64_t)now.tv_sec*1000000000u+(uint64_t)now.tv_nsec+50000000u;
}
static int egress_live(struct steer_prototype_wg *w,uint64_t d){
    const struct steer_draft_wg_guard_record *r=&w->selected;
    if(!w->egress||w->fenced||!r->handle||!d)return 0;
    return !verify(&w->guard,r,d)&&!awg_dev_route_check_owned_until(r->link.physical_name,
        r->link.kind,(int)r->ifindex,r->link.group,&w->route,d);
}
int steer_prototype_wg_request(struct steer_prototype_wg *w,int op,uint64_t expected,
    const char *data,size_t size,char *out,size_t cap,size_t *length){
    int status=200,n=0;
    unsigned long long revision=w->revision.generation;
    if(op<1||op>4)status=400;
    else if(op==1)n=snprintf(out,cap,"{\"prototype\":\"steer-linux-wg-netns-v1\",\"revision\":%llu,"
        "\"runtimeReady\":%s,\"persistence\":true,\"durability_uncertain\":%s,\"cleanup_blocked\":%s,"
        "\"capabilities\":{\"wg_device_inbound_netns\":true,\"wg_device_outbound\":false%s}}",
        revision,w->current&&!w->fenced&&(!w->egress||egress_live(w,stream_deadline()))?"true":"false",
        w->uncertain?"true":"false",w->fenced?"true":"false",
        w->socks_port?",\"wg_stream_outbound_netns\":true,"
        "\"wg_stream_outbound_netns_schema\":\"wireguard-tcp-netns-outbound-v1\"":"");
    else if(op==2)n=snprintf(out,cap,"{\"revision\":%llu,\"persistence\":true,\"durability_uncertain\":%s,\"document\":%s}",
        revision,w->uncertain?"true":"false",w->current?w->current->document:"null");
    else if(op==4&&(w->fenced||expected!=revision))status=w->fenced?503:409;
    else{
        struct parsed p={0};
        if(lower(data,size,w->next,w->socks_port,&p))status=422;
        else if(op==3)n=snprintf(out,cap,"{\"valid\":true,\"persistence\":true}");
        else{
            status=apply(w,&p);
            if(status==200)n=snprintf(out,cap,"{\"applied\":true,\"revision\":%llu,\"persistence\":true}",
                (unsigned long long)w->revision.generation);
        }
        parsed_free(&p);
    }
    if(status!=200)n=snprintf(out,cap,"{\"error\":\"request rejected\",\"persistence\":true,"
        "\"durability_uncertain\":%s}",w->uncertain?"true":"false");
    if(n<0||(size_t)n>=cap){*length=0;return 500;}
    *length=(size_t)n;
    return status;
}

uint64_t steer_prototype_wg_revision(const struct steer_prototype_wg *w){
    return w->revision.generation;
}

int steer_prototype_wg_select(const struct steer_prototype_wg *w,uint64_t revision,
    const struct steer_pv1_flow_metadata *flow){
    static const char inlet[]="socks-entry";
    return w->egress&&!w->fenced&&revision&&revision==w->revision.generation&&w->selected.handle&&
        flow->flow_class==STEER_PV1_FLOW_STREAM&&flow->inbound_id.len==sizeof(inlet)-1&&
        !memcmp(flow->inbound_id.data,inlet,sizeof(inlet)-1)&&flow->destination.tag==STEER_PV1_ENDPOINT_IPV4&&
        flow->destination.address.len==4&&contains(&w->route,flow->destination.address.data);
}

uint32_t steer_prototype_wg_bind_stream(void *ctx,int fd,const struct sockaddr_storage *to,uint64_t d){
    struct steer_prototype_wg *w=ctx;
    struct sockaddr_in source={.sin_family=AF_INET},target;
    if(!w->egress||w->fenced||!w->selected.handle||to->ss_family!=AF_INET)return STEER_PV1_POLICY_DENIED;
    memcpy(&target,to,sizeof(target));
    if(!contains(&w->route,(const uint8_t *)&target.sin_addr))return STEER_PV1_POLICY_DENIED;
    /* Only a small bounded local netlink read on the owner. No DNS/resolver or
     * retry to another route. Verify the installed route and link afresh. */
    uint64_t cap=stream_deadline();
    if(d>cap)d=cap;
    const struct steer_draft_wg_guard_record *r=&w->selected;
    int idx=(int)r->ifindex;
    if(!egress_live(w,d))return STEER_PV1_POLICY_DENIED;
    memcpy(&source.sin_addr,w->address.addr,4);
    if(setsockopt(fd,SOL_SOCKET,SO_BINDTOIFINDEX,&idx,sizeof(idx))||
       bind(fd,(const struct sockaddr *)&source,sizeof(source)))return STEER_PV1_POLICY_DENIED;
    return STEER_PV1_OK;
}
