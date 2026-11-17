#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls13.h"
#include "tls13_engine.h"

static _Thread_local int hash_failure;
static _Thread_local const struct sc_hash_ctx *hash_target;
int __real_sc_hash_init(struct sc_hash_ctx *,enum sc_hash);
int __real_sc_hash_update(struct sc_hash_ctx *,const void *,size_t);
int __real_sc_hash_clone(struct sc_hash_ctx *,const struct sc_hash_ctx *);
int __wrap_sc_hash_init(struct sc_hash_ctx *c,enum sc_hash h) {
    if(hash_failure==1&&c==hash_target)return SC_ECRYPTO;
    return __real_sc_hash_init(c,h);
}
int __wrap_sc_hash_update(struct sc_hash_ctx *c,const void *p,size_t n) {
    if(hash_failure==2&&c==hash_target)return SC_ECRYPTO;
    return __real_sc_hash_update(c,p,n);
}
int __wrap_sc_hash_clone(struct sc_hash_ctx *c,const struct sc_hash_ctx *source) {
    if(hash_failure==3&&source==hash_target)return SC_ECRYPTO;
    return __real_sc_hash_clone(c,source);
}

int x25519_shared_ext(const unsigned char private_key[32],const unsigned char peer[32],unsigned char shared[32]) {
    return sc_x25519(shared,private_key,peer);
}
static void u16(unsigned char *p,size_t n){p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n;}
static size_t client(unsigned char *p,const unsigned char private_key[32]) {
    memset(p,0,256);p[0]=22;p[1]=p[2]=3;unsigned char *h=p+5;
    h[0]=1;h[4]=h[5]=3;h[38]=2;h[39]=42;h[40]=43;size_t at=41;
    u16(h+at,2);at+=2;u16(h+at,0x1301);at+=2;h[at++]=1;h[at++]=0;
    size_t extensions=at;at+=2;
    const unsigned char version[]={0,43,0,3,2,3,4};memcpy(h+at,version,sizeof(version));at+=sizeof(version);
    u16(h+at,51);u16(h+at+2,38);u16(h+at+4,36);u16(h+at+6,29);u16(h+at+8,32);
    assert(!sc_x25519_base(h+at+10,private_key));at+=42;
    const unsigned char signature[]={0,13,0,4,0,2,8,7};memcpy(h+at,signature,sizeof(signature));at+=sizeof(signature);
    u16(h+extensions,at-extensions-2);h[3]=(unsigned char)(at-4);u16(p+3,at);return at+5;
}
static size_t server(unsigned char *p) {
    memset(p,0,256);p[0]=22;p[1]=p[2]=3;unsigned char *h=p+5;
    h[0]=2;h[4]=h[5]=3;h[38]=2;h[39]=42;h[40]=43;u16(h+41,0x1301);size_t at=46;
    const unsigned char version[]={0,43,0,2,3,4};memcpy(h+at,version,sizeof(version));at+=sizeof(version);
    u16(h+at,51);u16(h+at+2,36);u16(h+at+4,29);u16(h+at+6,32);
    const unsigned char key[32]={31};assert(!sc_x25519_base(h+at+8,key));at+=40;
    u16(h+44,at-46);h[3]=(unsigned char)(at-4);u16(p+3,at);return at+5;
}
static void zeroed(const void *data,size_t length){const unsigned char *p=data;for(size_t i=0;i<length;i++)assert(!p[i]);}
struct instance {struct tls13 *tls;void *storage,*workspace;size_t workspace_length;struct tls13_engine *engine;};
static struct instance create(const struct tls13_engine_options *o) {
    struct instance i={0};assert(!tls13_engine_workspace_size(o,&i.workspace_length));
    i.tls=malloc(sizeof(*i.tls));i.storage=malloc(tls13_engine_storage_size());i.workspace=malloc(i.workspace_length);
    assert(i.tls&&i.storage&&i.workspace);
    assert(!tls13_engine_init(i.storage,tls13_engine_storage_size(),i.tls,i.workspace,i.workspace_length,o,&i.engine));
    assert(i.tls->fd==-1&&!i.tls->ready);return i;
}
static void destroy(struct instance *i) {
    tls13_engine_destroy(i->engine);tls13_engine_destroy(i->engine);
    zeroed(i->workspace,i->workspace_length);zeroed(i->storage,tls13_engine_storage_size());
    assert(!i->tls->ready&&!i->tls->rd.ctx_ready&&!i->tls->wr.ctx_ready);
    free(i->tls);free(i->storage);free(i->workspace);
}
static void drain(struct instance *i,size_t expected) {
    const unsigned char *p;size_t n;assert(!tls13_engine_output(i->engine,&p,&n)&&n==expected);
    assert(tls13_engine_output_consume(i->engine,n+1)==TLS13_ESTATE);
    while(n){assert(!tls13_engine_output_consume(i->engine,1));assert(!tls13_engine_output(i->engine,&p,&n));}
}
static void owner(void) {
    unsigned char hello[256],sh[256],private_key[32]={7};size_t hn=client(hello,private_key),sn=server(sh);
    struct tls13_engine_options o={.client_hello=hello,.client_hello_length=hn,.x25519_private=private_key,
        .limits={.max_records=64,.max_messages=4,.max_handshake_message=40960,.max_certificate=40960}};
    for(size_t cut=1;cut<sn;cut++) {
        struct instance i=create(&o);size_t consumed=99,accepted=99;
        assert(tls13_engine_write(i.engine,(const unsigned char *)"early",5,&accepted)==TLS13_ESTATE&&!accepted);
        assert(tls13_engine_feed(i.engine,sh,sn,&consumed)==TLS13_EAGAIN&&!consumed);
        drain(&i,hn);
        assert(!tls13_engine_feed(i.engine,sh,cut,&consumed)&&consumed==cut);
        assert(!tls13_engine_feed(i.engine,sh+cut,sn-cut,&consumed)&&consumed==sn-cut);
        assert(tls13_engine_state(i.engine)==TLS13_ENGINE_HANDSHAKE&&!i.tls->ready);
        assert(tls13_engine_workspace_in_use(i.engine));
        assert(tls13_engine_eof(i.engine)==TLS13_EIO); /* no authenticated close/Finished */
        assert(tls13_engine_eof(i.engine)==TLS13_EIO);destroy(&i);
    }
    o.limits.max_records=1;struct instance i=create(&o);drain(&i,hn);size_t n;
    assert(!tls13_engine_feed(i.engine,sh,sn,&n)&&n==sn);
    const unsigned char ccs[]={20,3,3,0,1,1};
    assert(tls13_engine_feed(i.engine,ccs,sizeof(ccs),&n)==TLS13_ETOOBIG);
    assert(!tls13_engine_workspace_in_use(i.engine));destroy(&i);
    o.limits.max_records=64;o.limits.max_handshake_message=4;i=create(&o);drain(&i,hn);
    assert(tls13_engine_feed(i.engine,sh,sn,&n)==TLS13_ETOOBIG);destroy(&i);
    o.limits.max_handshake_message=40960;i=create(&o);drain(&i,hn);
    const unsigned char oversized[]={23,3,3,0x41,1};
    assert(tls13_engine_feed(i.engine,oversized,sizeof(oversized),&n)==TLS13_EBADREC);destroy(&i);
    for(int kind=1;kind<=2;kind++) {
        size_t workspace_length;assert(!tls13_engine_workspace_size(&o,&workspace_length));
        struct tls13 *tls=malloc(sizeof(*tls));void *storage=malloc(tls13_engine_storage_size()),*workspace=malloc(workspace_length);
        assert(tls&&storage&&workspace);hash_target=&tls->tr;hash_failure=kind;
        struct tls13_engine *out=(struct tls13_engine *)(uintptr_t)1;
        assert(tls13_engine_init(storage,tls13_engine_storage_size(),tls,workspace,workspace_length,&o,&out)==TLS13_ECRYPTO);
        hash_failure=0;hash_target=NULL;
        assert(!out&&!tls->ready&&!tls->tr.alg&&!tls->tr384.alg);zeroed(workspace,workspace_length);
        free(tls);free(storage);free(workspace);
    }
    i=create(&o);drain(&i,hn);hash_target=&i.tls->tr;hash_failure=3;
    assert(tls13_engine_feed(i.engine,sh,sn,&n)==TLS13_ECRYPTO);
    hash_failure=0;hash_target=NULL;assert(!tls13_engine_workspace_in_use(i.engine));destroy(&i);
    for(int overlap=0;overlap<2;overlap++) {
        i=create(&o);destroy(&i);
        struct tls13 *tls=malloc(sizeof(*tls));assert(tls);memset(tls,0xa5,sizeof(*tls));
        unsigned char *saved=malloc(sizeof(*tls));assert(saved);
        struct tls13_engine_options aliased=o;
        if(overlap){memcpy(tls->rbuf,private_key,32);aliased.x25519_private=tls->rbuf;}
        else{memcpy(tls->rbuf,hello,hn);aliased.client_hello=tls->rbuf;}
        memcpy(saved,tls,sizeof(*tls));size_t workspace_length;assert(!tls13_engine_workspace_size(&aliased,&workspace_length));
        void *storage=malloc(tls13_engine_storage_size()),*workspace=malloc(workspace_length);assert(storage&&workspace);
        memset(storage,0x5a,tls13_engine_storage_size());memset(workspace,0x5a,workspace_length);
        struct tls13_engine *out=(struct tls13_engine *)(uintptr_t)1;
        assert(tls13_engine_init(storage,tls13_engine_storage_size(),tls,workspace,workspace_length,&aliased,&out)==TLS13_ESTATE);
        assert(!out&&!memcmp(saved,tls,sizeof(*tls)));
        for(size_t j=0;j<tls13_engine_storage_size();j++)assert(((unsigned char *)storage)[j]==0x5a);
        for(size_t j=0;j<workspace_length;j++)assert(((unsigned char *)workspace)[j]==0x5a);
        free(saved);free(tls);free(storage);free(workspace);
    }
}
static void *thread(void *unused){(void)unused;owner();return NULL;}
int main(void){owner();pthread_t threads[4];for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,thread,NULL));for(int i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));puts("TLS engine 1+4 independent owners: SH fragmentation, admission, overlap, teardown PASS");return 0;}
