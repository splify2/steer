/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "prototype_prepare.h"
#ifdef STEER_PROTOTYPE_HY2
#include "hy2_tcp_client.h"
#include "inbound_tls.h"
#include "quic.h"
#include "qcssl.h"
#endif
#include "loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
struct job { struct steer_prototype_prepared_input result;char *document;size_t length;uint64_t generation;unsigned cancelled;int done; };
struct steer_prototype_prepare {
    struct loop *loop;pthread_t thread;pthread_mutex_t lock;pthread_cond_t changed;
    struct job *job;steer_prototype_prepare_done done;void *user;
    const struct steer_prototype_socks_vpn_allowlist *socks_vpn;
    int wake,stopping,exited,dispatching;
};
static int interrupted(struct job *job) {
    if(__atomic_load_n(&job->cancelled,__ATOMIC_RELAXED))return 499;
    return (uint64_t)loop_now_ms()>=job->result.deadline_ms?408:0;
}
static void dispose(struct job *job) {
    if(!job)return;
#ifdef STEER_PROTOTYPE_HY2
    for(unsigned i=0;i<STEER_POLICY_STREAM_BINDINGS_MAX;i++) {
        (void)steer_hy2_profile_destroy(job->result.hy2_out[i]);
        (void)steer_hy2_profile_destroy(job->result.hy2_udp_out[i]);
    }
    for(unsigned i=0;i<STEER_PROTOTYPE_MAX_LISTENERS;i++)qc_server_tls_release(job->result.tls[i]);
#endif
    steer_prototype_config_destroy(job->result.config);free(job->document);free(job);
}
#ifdef STEER_PROTOTYPE_HY2
int steer_prototype_prepare_hy2_outbound(const struct steer_prototype_stream_outbound *spec,
    uint64_t generation,struct steer_hy2_profile **out) {
    char address[INET6_ADDRSTRLEN];
    int family=spec->endpoint_tag==STEER_PV1_ENDPOINT_IPV4?AF_INET:AF_INET6;
    *out=NULL;
    if(!inet_ntop(family,spec->address,address,sizeof address))return -1;
    return steer_hy2_profile_prepare(generation,address,spec->port,spec->tls_name,
        getenv(spec->ca_ref+4),getenv(spec->password_ref+4),out);
}
#endif
static void prepare(struct job *job,const struct steer_prototype_socks_vpn_allowlist *socks_vpn) {
    struct steer_prototype_prepared_input *r=&job->result;
    r->error=interrupted(job);if(r->error)return;
    uint32_t code=steer_prototype_config_parse_with_vpn(job->document,job->length,job->generation,socks_vpn,&r->config).code;
    if(code) { r->error=code==STEER_PV1_RESOURCE_EXHAUSTED?503:422;return; }
#ifdef STEER_PROTOTYPE_HY2
    for(unsigned i=0;i<r->config->stream_outbound_count;i++){
        const struct steer_prototype_stream_outbound *spec=&r->config->stream_outbounds[i];
        if(spec->protocol!=STEER_PROTOTYPE_HYSTERIA2)continue;
        r->error=interrupted(job);if(r->error)return;
        if(steer_prototype_prepare_hy2_outbound(spec,job->generation,&r->hy2_out[i])){
            r->error=422;
            return;
        }
        if(spec->hy2_datagram) {
            r->error=interrupted(job);if(r->error)return;
            if(steer_prototype_prepare_hy2_outbound(spec,job->generation,&r->hy2_udp_out[i])) {
                r->error=422;return;
            }
        }
    }
    for(unsigned i=0;i<r->config->listener_count;i++) {
        const struct steer_prototype_listener *spec=&r->config->listeners[i];struct steer_draft_tls_material material;
        char certificate[PATH_MAX],key[PATH_MAX];const char *path;
        r->error=interrupted(job);if(r->error)return;
        if(!spec->enabled||spec->protocol!=STEER_PROTOTYPE_HYSTERIA2)continue;
        /* Environment is inherited immutable host configuration. Snapshot its
         * bounded path bytes before IO; never retain getenv or document views. */
        path=getenv(spec->certificate_ref+4);
        if(!path||strnlen(path,sizeof certificate)>=sizeof certificate) { r->error=422;return; }
        strcpy(certificate,path);path=getenv(spec->private_key_ref+4);
        if(!path||strnlen(path,sizeof key)>=sizeof key) { r->error=422;return; }
        strcpy(key,path);
        if(steer_draft_tls_material_load(certificate,key,&material)) { r->error=422;return; }
        r->error=interrupted(job);
        if(r->error) { steer_draft_tls_material_clear(&material);return; }
        int error=qcssl_material_sha256(material.certificate,material.certificate_length,r->certificate_hash[i])||
            qcssl_material_sha256(material.private_key,material.private_key_length,r->private_key_hash[i]);
        if(!error)error=qc_server_tls_create(material.certificate,material.certificate_length,material.private_key,material.private_key_length,&r->tls[i]);
        steer_draft_tls_material_clear(&material);
        if(error) { r->error=error==QC_ENOMEM?503:422;return; }
    }
#endif
    r->error=interrupted(job);
}
static void notify(struct steer_prototype_prepare *p) { uint64_t value=1;while(write(p->wake,&value,sizeof value)<0&&errno==EINTR){} }
static void *worker(void *user) {
    struct steer_prototype_prepare *p=user;
    pthread_mutex_lock(&p->lock);
    for(;;) {
        while((!p->job||p->job->done)&&!p->stopping)pthread_cond_wait(&p->changed,&p->lock);
        if(p->stopping&&(!p->job||p->job->done))break;
        struct job *job=p->job;pthread_mutex_unlock(&p->lock);
        prepare(job,p->socks_vpn);
        pthread_mutex_lock(&p->lock);job->done=1;pthread_mutex_unlock(&p->lock);
        notify(p);pthread_mutex_lock(&p->lock);
    }
    p->exited=1;pthread_mutex_unlock(&p->lock);notify(p);return NULL;
}
static void ready(struct loop *loop,int fd,uint32_t events,void *user) {
    struct steer_prototype_prepare *p=user;struct job *job=NULL;uint64_t value;
    (void)loop;(void)events;while(read(fd,&value,sizeof value)>0){}
    pthread_mutex_lock(&p->lock);
    if(p->job&&p->job->done) { job=p->job;p->job=NULL;pthread_cond_signal(&p->changed); }
    pthread_mutex_unlock(&p->lock);
    if(job) {
        int error=interrupted(job);if(error)job->result.error=error;
        p->dispatching=1;p->done(p->user,&job->result);dispose(job);p->dispatching=0;
    }
}
int steer_prototype_prepare_create(struct loop *loop,steer_prototype_prepare_done done,void *user,
    const struct steer_prototype_socks_vpn_allowlist *socks_vpn,struct steer_prototype_prepare **out) {
    if(out)*out=NULL;
    if(!out||!loop||!done)return -1;
    struct steer_prototype_prepare *p=calloc(1,sizeof *p);if(!p)return -1;
    p->loop=loop;p->done=done;p->user=user;p->wake=-1;p->socks_vpn=socks_vpn;
    if(pthread_mutex_init(&p->lock,NULL)) { free(p);return -1; }
    if(pthread_cond_init(&p->changed,NULL)) { pthread_mutex_destroy(&p->lock);free(p);return -1; }
    p->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(p->wake<0||loop_fd_add(loop,p->wake,EPOLLIN,ready,p))goto fail;
    if(pthread_create(&p->thread,NULL,worker,p)) { loop_fd_del(loop,p->wake);goto fail; }
    *out=p;return 0;
fail:
    if(p->wake>=0)close(p->wake);
    pthread_cond_destroy(&p->changed);pthread_mutex_destroy(&p->lock);free(p);return -1;
}
int steer_prototype_prepare_submit(struct steer_prototype_prepare *p,const char *document,size_t length,uint64_t generation,uint64_t expected,unsigned index,uint64_t serial,int validate,uint64_t deadline) {
    if(!p||!document||!length||length>STEER_PROTOTYPE_CONFIG_MAX_BYTES||!generation)return 422;
    struct job *job=calloc(1,sizeof *job);if(!job)return 503;
    job->document=malloc(length);if(!job->document) { free(job);return 503; }
    memcpy(job->document,document,length);job->length=length;job->generation=generation;
    job->result.expected=expected;job->result.control_index=index;job->result.serial=serial;
    job->result.validate=validate;job->result.deadline_ms=deadline;
    pthread_mutex_lock(&p->lock);
    if(p->stopping||p->job) { pthread_mutex_unlock(&p->lock);dispose(job);return 503; }
    p->job=job;pthread_cond_signal(&p->changed);pthread_mutex_unlock(&p->lock);return 0;
}
void steer_prototype_prepare_cancel(struct steer_prototype_prepare *p,unsigned index,uint64_t serial) {
    if(!p)return;
    pthread_mutex_lock(&p->lock);
    if(p->job&&p->job->result.control_index==index&&p->job->result.serial==serial)
        __atomic_store_n(&p->job->cancelled,1,__ATOMIC_RELAXED);
    pthread_mutex_unlock(&p->lock);
}
void steer_prototype_prepare_stop(struct steer_prototype_prepare *p) {
    if(!p)return;
    pthread_mutex_lock(&p->lock);p->stopping=1;
    if(p->job)__atomic_store_n(&p->job->cancelled,1,__ATOMIC_RELAXED);
    pthread_cond_signal(&p->changed);pthread_mutex_unlock(&p->lock);
}
int steer_prototype_prepare_busy(struct steer_prototype_prepare *p) {
    if(!p)return 0;
    pthread_mutex_lock(&p->lock);int busy=p->job!=NULL;pthread_mutex_unlock(&p->lock);return busy;
}
int steer_prototype_prepare_result_pending(struct steer_prototype_prepare *p) {
    if(!p)return 0;
    pthread_mutex_lock(&p->lock);int pending=p->job&&p->job->done;pthread_mutex_unlock(&p->lock);return pending;
}
int steer_prototype_prepare_destroy(struct steer_prototype_prepare *p) {
    if(!p)return 0;
    pthread_mutex_lock(&p->lock);int safe=p->stopping&&p->exited&&!p->job;pthread_mutex_unlock(&p->lock);
    if(!safe||p->dispatching)return -1;
    pthread_join(p->thread,NULL);loop_fd_del(p->loop,p->wake);close(p->wake);
    pthread_cond_destroy(&p->changed);pthread_mutex_destroy(&p->lock);free(p);return 0;
}
void steer_prototype_prepare_join_destroy(struct steer_prototype_prepare *p) {
    if(!p)return;
    steer_prototype_prepare_stop(p);pthread_join(p->thread,NULL);
    dispose(p->job);loop_fd_del(p->loop,p->wake);close(p->wake);
    pthread_cond_destroy(&p->changed);pthread_mutex_destroy(&p->lock);free(p);
}
