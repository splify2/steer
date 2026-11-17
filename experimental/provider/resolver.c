#define _GNU_SOURCE
#include "resolver.h"
#include "loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
struct steer_draft_resolve_job {
    struct steer_draft_resolver *pool;
    char host[255];
    uint16_t port;
    int state;
    steer_draft_resolve_done done;
    void *userdata;
    struct steer_draft_resolve_result result;
}
;
struct steer_draft_resolver {
    struct loop *loop;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_t threads[4];
    uint32_t workers,max_jobs,jobs,users;
    int wake,stopping,dispatching;
    steer_draft_resolve_backend backend;
    void *context;
    struct steer_draft_resolve_job slots[];
}
;
static struct steer_pv1_error error(uint32_t c){
    struct steer_pv1_error e={
        c,0
    }
    ;
    return e;
}
static void notify(struct steer_draft_resolver *r){
    uint64_t one=1;
    ssize_t n;
    do{
        n=write(r->wake,&one,sizeof(one));
    }
    while(n<0&&errno==EINTR);
}
static void nss(void *context,const char *host,uint16_t port,struct steer_draft_resolve_result *out){
    struct addrinfo hints={
        0
    }
    ,*list=NULL,*p;
    char service[8];
    (void)context;
    memset(out,0,sizeof(*out));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;
    snprintf(service,sizeof(service),"%u",port);
    if(getaddrinfo(host,service,&hints,&list)){
        out->code=STEER_PV1_IO;
        return;
    }
    for(p=list;p&&out->count<STEER_DRAFT_RESOLVE_ADDRESSES;p=p->ai_next){
        size_t size=p->ai_family==AF_INET?sizeof(struct sockaddr_in):p->ai_family==AF_INET6?sizeof(struct sockaddr_in6):0;
        uint32_t i;
        if(!size||p->ai_addrlen!=size)continue;
        if(p->ai_family==AF_INET6&&((struct sockaddr_in6*)p->ai_addr)->sin6_scope_id)continue;
        for(i=0;i<out->count;i++)if(!memcmp(&out->addresses[i],p->ai_addr,size))break;
        if(i<out->count)continue;
        memcpy(&out->addresses[out->count++],p->ai_addr,size);
    }
    freeaddrinfo(list);
    if(!out->count)out->code=STEER_PV1_IO;
}
static void *worker(void *arg){
    struct steer_draft_resolver*r=arg;
    for(;;){
        uint32_t i;
        struct steer_draft_resolve_job*j=NULL;
        char host[255];
        uint16_t port;
        struct steer_draft_resolve_result result;
        pthread_mutex_lock(&r->lock);
        for(;;){
            for(i=0;i<r->max_jobs;i++)if(r->slots[i].state==1){
                j=&r->slots[i];
                break;
            }
            if(j||r->stopping)break;
            pthread_cond_wait(&r->changed,&r->lock);
        }
        if(r->stopping){
            pthread_mutex_unlock(&r->lock);
            return NULL;
        }
        j->state=2;
        memcpy(host,j->host,sizeof(host));
        port=j->port;
        pthread_mutex_unlock(&r->lock);
        memset(&result,0,sizeof(result));
        r->backend(r->context,host,port,&result);
        if(result.code>STEER_PV1_INTERNAL||result.count>STEER_DRAFT_RESOLVE_ADDRESSES||(!result.code&&!result.count)){
            result.code=STEER_PV1_IO;
            result.count=0;
        }
        pthread_mutex_lock(&r->lock);
        j->result=result;
        j->state=3;
        pthread_mutex_unlock(&r->lock);
        notify(r);
    }
}
static void ready(struct loop*l,int fd,uint32_t events,void*arg){
    struct steer_draft_resolver*r=arg;
    uint64_t counter;
    uint32_t i;
    ssize_t n;
    (void)l;
    (void)events;
    do{
        n=read(fd,&counter,sizeof(counter));
    }
    while(n<0&&errno==EINTR);
    r->dispatching=1;
    for(i=0;i<r->max_jobs;i++){
        steer_draft_resolve_done done=NULL;
        void*userdata=NULL;
        struct steer_draft_resolve_result result;
        pthread_mutex_lock(&r->lock);
        if(r->slots[i].state==3){
            done=r->slots[i].done;
            userdata=r->slots[i].userdata;
            result=r->slots[i].result;
            r->slots[i].state=0;
            r->slots[i].done=NULL;
            r->slots[i].userdata=NULL;
            r->jobs--;
        }
        pthread_mutex_unlock(&r->lock);
        if(done)done(userdata,&result);
    }
    r->dispatching=0;
}
struct steer_pv1_error steer_draft_resolver_create(struct loop*l,uint32_t workers,uint32_t max_jobs,steer_draft_resolve_backend backend,void*context,struct steer_draft_resolver**out){
    struct steer_draft_resolver*r;
    uint32_t i;
    if(out)*out=NULL;
    if(!l||!out||!workers||workers>4||!max_jobs||max_jobs>256)return error(STEER_PV1_INVALID);
    r=calloc(1,sizeof(*r)+(size_t)max_jobs*sizeof(r->slots[0]));
    if(!r)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    r->loop=l;
    r->max_jobs=max_jobs;
    r->backend=backend?backend:nss;
    r->context=context;
    r->wake=-1;
    if(pthread_mutex_init(&r->lock,NULL)){
        free(r);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    if(pthread_cond_init(&r->changed,NULL)){
        pthread_mutex_destroy(&r->lock);
        free(r);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(r->wake<0||loop_fd_add(l,r->wake,EPOLLIN,ready,r))goto fail;
    for(i=0;i<workers;i++){
        if(pthread_create(&r->threads[i],NULL,worker,r))goto fail;
        r->workers++;
    }
    for(i=0;i<max_jobs;i++)r->slots[i].pool=r;
    *out=r;
    return error(STEER_PV1_OK);
    fail:pthread_mutex_lock(&r->lock);
    r->stopping=1;
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    for(i=0;i<r->workers;i++)pthread_join(r->threads[i],NULL);
    if(r->wake>=0){
        loop_fd_del(l,r->wake);
        close(r->wake);
    }
    pthread_cond_destroy(&r->changed);
    pthread_mutex_destroy(&r->lock);
    free(r);
    return error(STEER_PV1_RESOURCE_EXHAUSTED);
}
static int valid_name(struct steer_pv1_span host){
    uint32_t i,n=host.len,label=0;
    if(!host.data||!n||n>254)return 0;
    if(host.data[n-1]=='.')n--;
    if(!n||n>253)return 0;
    for(i=0;i<n;i++){
        unsigned c=host.data[i];
        if(c=='.'){
            if(!label||host.data[i-1]=='-')return 0;
            label=0;
        }
        else{
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')||(!label&&c=='-')||++label>63)return 0;
        }
    }
    return label&&host.data[n-1]!='-';
}
struct steer_pv1_error steer_draft_resolver_submit(struct steer_draft_resolver*r,struct steer_pv1_span host,uint16_t port,steer_draft_resolve_done done,void*userdata,struct steer_draft_resolve_job**out){
    uint32_t i;
    if(out)*out=NULL;
    if(!r||!out||!done||!port||!valid_name(host))return error(STEER_PV1_INVALID);
    pthread_mutex_lock(&r->lock);
    for(i=0;i<r->max_jobs;i++)if(!r->slots[i].state)break;
    if(r->stopping||i==r->max_jobs){
        pthread_mutex_unlock(&r->lock);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    memcpy(r->slots[i].host,host.data,host.len);
    r->slots[i].host[host.len]=0;
    r->slots[i].port=port;
    r->slots[i].done=done;
    r->slots[i].userdata=userdata;
    r->slots[i].state=1;
    r->jobs++;
    *out=&r->slots[i];
    pthread_cond_signal(&r->changed);
    pthread_mutex_unlock(&r->lock);
    return error(STEER_PV1_OK);
}
void steer_draft_resolver_cancel(struct steer_draft_resolve_job*j){
    struct steer_draft_resolver*r;
    if(!j)return;
    r=j->pool;
    pthread_mutex_lock(&r->lock);
    j->done=NULL;
    j->userdata=NULL;
    if(j->state==1){
        j->state=0;
        r->jobs--;
    }
    pthread_mutex_unlock(&r->lock);
}
struct steer_pv1_error steer_draft_resolver_retain(struct steer_draft_resolver*r){
    if(!r)return error(STEER_PV1_INVALID);
    if(r->users==UINT32_MAX)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    r->users++;
    return error(STEER_PV1_OK);
}
void steer_draft_resolver_release(struct steer_draft_resolver*r){
    if(r&&r->users)r->users--;
}
uint32_t steer_draft_resolver_jobs(struct steer_draft_resolver*r){
    uint32_t n;
    if(!r)return 0;
    pthread_mutex_lock(&r->lock);
    n=r->jobs;
    pthread_mutex_unlock(&r->lock);
    return n;
}
struct steer_pv1_error steer_draft_resolver_destroy(struct steer_draft_resolver*r){
    uint32_t i;
    if(!r)return error(STEER_PV1_INVALID);
    if(r->users||r->dispatching||steer_draft_resolver_jobs(r))return error(STEER_PV1_POLICY_DENIED);
    pthread_mutex_lock(&r->lock);
    r->stopping=1;
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    for(i=0;i<r->workers;i++)pthread_join(r->threads[i],NULL);
    loop_fd_del(r->loop,r->wake);
    close(r->wake);
    pthread_cond_destroy(&r->changed);
    pthread_mutex_destroy(&r->lock);
    free(r);
    return error(STEER_PV1_OK);
}
