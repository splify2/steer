#define _GNU_SOURCE
#include "prototype_linked_wg.h"
#include "prototype_config.h"
#include "prototype_wg.h"
#include "kernel_wg_linux_guard.h"
#include "blake3.h"
#include "nltransport.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct steer_prototype_linked_wg {
    struct steer_draft_wg_linux_guard guard;
    struct steer_draft_wg_selection *journal;
    struct steer_draft_wg_revision committed;
    uint16_t port;
};

static uint64_t deadline(void){
    uint64_t now=steer_nl_now_ns();
    return now?now+8000000000u:0;
}
static struct steer_draft_wg_revision revision(const struct steer_prototype_config *cfg){
    struct steer_draft_wg_revision out={0};
    if(cfg){
        static const char profile[]="steer linked spec v3: scoped WG stream";
        uint8_t digest[32];
        b3_hash(digest,cfg->document_json,cfg->document_length);
        b3_derive_key(out.digest,32,profile,sizeof(profile)-1,digest,sizeof(digest));
        out.generation=cfg->generation;
        out.without_wg=!cfg->wg;
    }
    return out;
}
int steer_linked_wg_open(const char *state,int outer,struct steer_prototype_linked_wg **out){
    *out=NULL;
    char journal[PATH_MAX];
    int len=snprintf(journal,sizeof(journal),"%s/wg-linked-journal",state);
    if(*state!='/'||len<0||(size_t)len>=sizeof(journal))return EINVAL;
    const char *const incompatible[]={"wg-journal","wg-scoped-journal"};
    for(unsigned i=0;i<sizeof(incompatible)/sizeof(incompatible[0]);i++){
        char other[PATH_MAX];struct stat st;
        int n=snprintf(other,sizeof(other),"%s/%s",state,incompatible[i]);
        if(n<0||(size_t)n>=sizeof(other)||!lstat(other,&st)||errno!=ENOENT)return EINVAL;
    }
    struct steer_prototype_linked_wg *w=calloc(1,sizeof(*w));
    if(!w)return ENOMEM;
    w->guard.scoped_route=1;
    int rc=steer_prototype_wg_gate(outer,1,&w->guard.link);
    if(!rc)rc=steer_draft_wg_selection_open(journal,64,&w->journal);
    if(rc){steer_linked_wg_close(w);return rc;}
    *out=w;
    return 0;
}
void steer_linked_wg_close(struct steer_prototype_linked_wg *w){
    if(!w)return;
    steer_draft_wg_selection_close(w->journal);
    steer_draft_wg_linux_link_close(w->guard.link);
    free(w);
}
static struct steer_pv1_error resolve(void *ctx,struct steer_pv1_span id,uint8_t out[44]){
    const struct steer_linked_wg_config *w=ctx;
    const char *candidate=w->cfg.private_key;
    const char *env=NULL;
    if(id.len==strlen(candidate)&&!memcmp(id.data,candidate,id.len))env=w->private_env;
    candidate=w->cfg.preshared_keys[0];
    if(*candidate&&id.len==strlen(candidate)&&!memcmp(id.data,candidate,id.len))env=w->psk_env;
    const char *value=env&&*env?getenv(env):NULL;
    if(!value||strnlen(value,45)!=44)return (struct steer_pv1_error){STEER_PV1_AUTH_FAILED,0};
    memcpy(out,value,44);
    return (struct steer_pv1_error){0,0};
}
int steer_linked_wg_keys(const struct steer_linked_wg_config *w,struct awg_secrets *keys){
    return steer_draft_wg_v3_keys(&w->cfg,resolve,(void *)w,keys).code!=0;
}
struct recovery {
    struct steer_draft_wg_linux_guard guard; /* backend context is the first member */
    const struct steer_linked_wg_config *config;
    struct steer_draft_wg_stream **stream;
};
static int recover_stream(void *arg,const struct steer_draft_wg_guard_record *record,uint64_t d){
    struct recovery *r=arg;
    if(!r->config)return EPROTO;
    return steer_draft_wg_stream_create(r->guard.link,record,&r->config->cfg.kernel.addr[0],&r->config->route,1,d,r->stream);
}
int steer_linked_wg_recover(struct steer_prototype_linked_wg *w,const struct steer_prototype_config *cfg,
    uint64_t *next,struct steer_draft_wg_stream **stream){
    *stream=NULL;
    struct recovery r={.guard=w->guard,.config=cfg?cfg->wg:NULL,.stream=stream};
    struct steer_draft_wg_revision choice=revision(cfg);
    int rc=steer_draft_wg_selection_startup(w->journal,&steer_draft_wg_linux_guard_backend,&r,
        &choice,recover_stream,deadline(),next,NULL);
    if(rc){steer_draft_wg_stream_destroy(*stream);*stream=NULL;}
    else steer_linked_wg_commit(w,cfg);
    return rc;
}
void steer_linked_wg_commit(struct steer_prototype_linked_wg *w,const struct steer_prototype_config *cfg){
    w->committed=revision(cfg);
    w->port=cfg&&cfg->wg?cfg->wg->cfg.kernel.listen_port:0;
}
int steer_linked_wg_retire(struct steer_prototype_linked_wg *w,uint64_t generation){
    if(generation==w->committed.generation)return 0;
    return steer_draft_wg_selection_retire(w->journal,&steer_draft_wg_linux_guard_backend,
        &w->guard,&w->committed,generation,deadline());
}
int steer_linked_wg_stage(struct steer_prototype_linked_wg *w,const struct steer_prototype_config *cfg,
    const struct awg_secrets *keys,uint64_t requested,struct steer_draft_wg_stream **stream){
    const struct steer_linked_wg_config *out=cfg->wg;
    uint64_t d=deadline();
    if(requested&&requested<d)d=requested;
    struct steer_draft_wg_revision choice=revision(cfg);
    struct steer_draft_wg_tx tx={.generation=cfg->generation,.transaction=cfg->generation,.instance=cfg->generation};
    memcpy(tx.plan_digest,choice.digest,sizeof(tx.plan_digest));
    struct steer_draft_wg_candidate c={.config=&out->cfg.kernel,.keys=keys};
    int rc=steer_draft_wg_linux_link_prepare(w->guard.link,&tx,d,NULL,&c.link);
    if(rc)return rc;
    struct steer_draft_kernel_wg_guard_config guard_cfg=out->cfg.guard;
    guard_cfg.generation=cfg->generation;
    guard_cfg.return_only=1;
    strcpy(guard_cfg.device,c.link.physical_name);
    struct steer_policy *policy=NULL;
    if(steer_policy_compile(cfg->generation,NULL,0,STEER_POLICY_DIRECT,&policy).code)return EIO;
    if(steer_draft_kernel_wg_guard_prepare(&guard_cfg,policy,&w->guard.prepared).code)rc=EIO;
    if(!rc)rc=steer_draft_kernel_wg_guard_plan(w->guard.prepared,c.table,c.marker);
    w->guard.route=&out->route;
    struct steer_draft_wg_ready ready;
    if(!rc)rc=steer_draft_wg_selection_stage(w->journal,&steer_draft_wg_linux_guard_backend,&w->guard,
        &w->committed,w->port,&tx,&c,d,&ready);
    if(!rc)rc=steer_draft_wg_stream_create(w->guard.link,&ready.guard,&out->cfg.kernel.addr[0],&out->route,1,d,stream);
    w->guard.route=NULL;
    if(w->guard.prepared)steer_draft_kernel_wg_guard_forget_prepared(w->guard.prepared);
    w->guard.prepared=NULL;
    steer_policy_destroy(policy);
    return rc;
}
