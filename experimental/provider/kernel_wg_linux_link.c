#define _GNU_SOURCE
#include "kernel_wg_linux_link.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

struct steer_draft_wg_linux_link { int ns; };

static int same_ns(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;
}

int steer_draft_wg_linux_link_open(int outer,struct steer_draft_wg_linux_link **out){
    if(!out)return EINVAL;
    *out=NULL;
    if(outer<0||ioctl(outer,NS_GET_NSTYPE)!=CLONE_NEWNET)return EINVAL;
    int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);
    if(ns<0)return errno;
    struct stat current,original,init;
    int rc=0;
    if(fstat(ns,&current)||fstat(outer,&original)||stat("/proc/1/ns/net",&init))rc=errno;
    else if(same_ns(&current,&original)||same_ns(&current,&init))rc=EPERM;
    if(rc){close(ns);return rc;}
    struct steer_draft_wg_linux_link *link=malloc(sizeof(*link));
    if(!link){close(ns);return ENOMEM;}
    link->ns=ns;
    *out=link;
    return 0;
}

void steer_draft_wg_linux_link_close(struct steer_draft_wg_linux_link *link){
    if(link){close(link->ns);free(link);}
}

int steer_draft_wg_linux_link_namespace(const struct steer_draft_wg_linux_link *link){
    return link?link->ns:-1;
}

int steer_draft_wg_linux_link_prepare(struct steer_draft_wg_linux_link *link,
    const struct steer_draft_wg_tx *tx,uint64_t deadline,const atomic_uint *cancel,
    struct steer_draft_wg_identity *id){
    if(!link||!tx||!tx->transaction)return EINVAL;
    return steer_draft_wg_identity_prepare(link->ns,tx->generation,tx->instance,
        "wireguard",deadline,cancel,id);
}

static int create_down(void *ctx,const struct steer_draft_wg_identity *id,int mtu,
    uint64_t deadline,int *index){
    const struct steer_draft_wg_linux_link *link=ctx;
    struct steer_draft_wg_observation o;
    if(!link||!id||!index||memcmp(id->kind,"wireguard",10))return EINVAL;
    *index=0;
    int rc=steer_draft_wg_identity_create(id,link->ns,mtu,deadline,NULL,&o);
    if(rc)return rc; /* Coordinator must reconcile a possibly committed create. */
    if(o.state!=STEER_DRAFT_WG_OWNED||o.index<=0)return EPROTO;
    *index=o.index;
    return 0;
}

static int stage_down(void *ctx,const struct steer_draft_wg_identity *id,int index,
    const struct awg_conf *cfg,const struct awg_secrets *keys,uint32_t mark,uint64_t deadline){
    const struct steer_draft_wg_linux_link *link=ctx;
    struct steer_draft_wg_observation o;
    if(!link||!id||memcmp(id->kind,"wireguard",10))return EINVAL;
    return steer_draft_wg_identity_stage(id,link->ns,index,cfg,keys,mark,deadline,NULL,&o);
}

static int retire_link(void *ctx,const struct steer_draft_wg_identity *id,uint64_t deadline){
    const struct steer_draft_wg_linux_link *link=ctx;
    struct steer_draft_wg_observation o;
    if(!link||!id||memcmp(id->kind,"wireguard",10))return EINVAL;
    int rc=steer_draft_wg_identity_retire(id,link->ns,deadline,NULL,&o);
    return rc?rc:o.state==STEER_DRAFT_WG_ABSENT?0:EPROTO;
}

const struct steer_draft_wg_backend steer_draft_wg_linux_link_backend={
    .create_down=create_down,.stage_down=stage_down,.retire_link=retire_link
};
