#define _GNU_SOURCE
#include "binding_lease.h"
#include "loop.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#define RETIRED UINT32_C(0x80000000)
#define REFERENCES UINT32_C(0x7fffffff)
#define READY_TOKEN (UINT64_C(1)<<32)
struct steer_draft_binding_lease {
    struct steer_draft_binding_identity identity;
    uint8_t provider_id[64];
    _Atomic uint32_t state;
    uint32_t maximum;
    struct loop *loop;
    int wake,dispatching,finalized;
    steer_draft_binding_finalizer finalize;
    void *userdata;
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
    void (*before_ready)(void *),(*retire_seen)(void *);
    void *hook_context;
#endif
};
static struct steer_pv1_error error(uint32_t code) {struct steer_pv1_error e={code,0};return e;}
/* fd is captured BEFORE dropping the last reference. READY is the final action:
 * after its successful write the producer never accesses lease or fd again. */
static struct steer_pv1_error publish(int fd,uint64_t token) {
    ssize_t n;
    do{n=write(fd,&token,sizeof(token));}while(n<0&&errno==EINTR);
    return error(n==(ssize_t)sizeof(token)?STEER_PV1_OK:STEER_PV1_IO);
}
static void received(struct loop *loop,int fd,uint32_t events,void *arg) {
    (void)loop;(void)events;struct steer_draft_binding_lease *lease=arg;
    uint64_t tokens;ssize_t n;
    do{n=read(fd,&tokens,sizeof(tokens));}while(n<0&&errno==EINTR);
    if(n!=(ssize_t)sizeof(tokens))return;
    if(tokens!=READY_TOKEN&&tokens!=READY_TOKEN+1){
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
        if(tokens==1&&lease->retire_seen)lease->retire_seen(lease->hook_context);
#endif
        return; /* A stale RETIRE notification plus refs0 is NOT completion. */
    }
    if(lease->finalized||atomic_load_explicit(&lease->state,memory_order_acquire)!=RETIRED)return;
    lease->dispatching=1;
    lease->finalize(lease->userdata,&lease->identity);
    lease->dispatching=0;lease->finalized=1;
}
struct steer_pv1_error steer_draft_binding_lease_create(struct loop *loop,
    const struct steer_draft_binding_identity *identity,uint32_t maximum,
    steer_draft_binding_finalizer finalize,void *userdata,struct steer_draft_binding_lease **out) {
    if(out)*out=NULL;
    if(!loop||!identity||identity->size<sizeof(*identity)||identity->version!=STEER_PV1_DRAFT_LAYOUT||
       !identity->generation||!identity->instance_token||!identity->provider_id.data||
       !identity->provider_id.len||identity->provider_id.len>64||!maximum||maximum>REFERENCES||!finalize||!out)
        return error(STEER_PV1_INVALID);
    if(identity->flow_class!=STEER_PV1_FLOW_STREAM&&identity->flow_class!=STEER_PV1_FLOW_DATAGRAM)
        return error(STEER_PV1_UNSUPPORTED);
    for(uint32_t i=0;i<identity->provider_id.len;i++){
        uint8_t c=identity->provider_id.data[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))
            return error(STEER_PV1_INVALID);
    }
    struct steer_draft_binding_lease *lease=calloc(1,sizeof(*lease));if(!lease)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    lease->identity=*identity;lease->identity.size=sizeof(lease->identity);
    memcpy(lease->provider_id,identity->provider_id.data,identity->provider_id.len);
    lease->identity.provider_id.data=lease->provider_id;
    atomic_init(&lease->state,1);lease->maximum=maximum;lease->loop=loop;
    lease->finalize=finalize;lease->userdata=userdata;
    lease->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(lease->wake<0||loop_fd_add(loop,lease->wake,EPOLLIN,received,lease)){
        if(lease->wake>=0)close(lease->wake);
        free(lease);return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=lease;return error(STEER_PV1_OK);
}
static struct steer_pv1_error acquire(struct steer_draft_binding_lease *lease,uint64_t generation,uint32_t flow_class,int admit) {
    if(!lease)return error(STEER_PV1_INVALID);
    if(generation!=lease->identity.generation)return error(STEER_PV1_POLICY_DENIED);
    if(flow_class!=lease->identity.flow_class)return error(STEER_PV1_UNSUPPORTED);
    uint32_t old=atomic_load_explicit(&lease->state,memory_order_acquire);
    for(;;){
        uint32_t count=old&REFERENCES;
        if(!count||(admit&&(old&RETIRED)))return error(STEER_PV1_POLICY_DENIED);
        if(count>=lease->maximum)return error(STEER_PV1_RESOURCE_EXHAUSTED);
        if(atomic_compare_exchange_weak_explicit(&lease->state,&old,old+1,memory_order_acq_rel,memory_order_acquire))
            return error(STEER_PV1_OK);
    }
}
struct steer_pv1_error steer_draft_binding_admit(struct steer_draft_binding_lease *l,uint64_t g,uint32_t c) {return acquire(l,g,c,1);}
struct steer_pv1_error steer_draft_binding_pin(struct steer_draft_binding_lease *l,uint64_t g,uint32_t c) {return acquire(l,g,c,0);}
struct steer_pv1_error steer_draft_binding_unpin(struct steer_draft_binding_lease *lease) {
    if(!lease)return error(STEER_PV1_INVALID);
    int wake=lease->wake;
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
    void (*hook)(void *)=lease->before_ready;void *context=lease->hook_context;
#endif
    uint32_t old=atomic_load_explicit(&lease->state,memory_order_acquire);
    for(;;){
        uint32_t count=old&REFERENCES;
        if(!count||(!(old&RETIRED)&&count==1))return error(STEER_PV1_POLICY_DENIED);
        uint32_t next=old-1;
        if(!atomic_compare_exchange_weak_explicit(&lease->state,&old,next,memory_order_acq_rel,memory_order_acquire))continue;
        if(next==RETIRED){
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
            if(hook)hook(context);
#endif
            return publish(wake,READY_TOKEN);
        }
        return error(STEER_PV1_OK);
    }
}
struct steer_pv1_error steer_draft_binding_retire(struct steer_draft_binding_lease *lease) {
    if(!lease)return error(STEER_PV1_INVALID);
    int wake=lease->wake;
    uint32_t old=atomic_load_explicit(&lease->state,memory_order_acquire);
    for(;;){
        if(old&RETIRED)return error(STEER_PV1_OK);
        if(!(old&REFERENCES))return error(STEER_PV1_POLICY_DENIED);
        uint32_t next=RETIRED|(old-1);
        if(!atomic_compare_exchange_weak_explicit(&lease->state,&old,next,memory_order_acq_rel,memory_order_acquire))continue;
        /* One RETIRE token total; at most one READY token total. No overflow. */
        struct steer_pv1_error e=publish(wake,1);if(e.code)return e;
        return next==RETIRED?publish(wake,READY_TOKEN):error(STEER_PV1_OK);
    }
}
struct steer_pv1_error steer_draft_binding_lease_destroy(struct steer_draft_binding_lease *lease) {
    if(!lease)return error(STEER_PV1_INVALID);
    if(atomic_load_explicit(&lease->state,memory_order_acquire)!=RETIRED||!lease->finalized||lease->dispatching)
        return error(STEER_PV1_POLICY_DENIED);
    loop_fd_del(lease->loop,lease->wake);close(lease->wake);free(lease);return error(STEER_PV1_OK);
}
const struct steer_draft_binding_identity *steer_draft_binding_identity(const struct steer_draft_binding_lease *l) {return l?&l->identity:NULL;}
uint32_t steer_draft_binding_references(const struct steer_draft_binding_lease *l) {
    return l?atomic_load_explicit(&l->state,memory_order_acquire)&REFERENCES:0;
}
#ifdef STEER_DRAFT_BINDING_TEST_HOOKS
void steer_draft_binding_test_hooks(struct steer_draft_binding_lease *lease,
    void (*before)(void *),void (*retire)(void *),void *context) {
    lease->before_ready=before;lease->retire_seen=retire;lease->hook_context=context;
}
#endif
