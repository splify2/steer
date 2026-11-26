#define _GNU_SOURCE
#ifdef NDEBUG
#error "certpreparedmatch requires active assertions"
#endif
#include "certverify.h"
#include "scrypto.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static atomic_int forbid_files;
FILE *__real_fopen(const char *,const char *);
FILE *__wrap_fopen(const char *path,const char *mode){assert(!atomic_load(&forbid_files));return __real_fopen(path,mode);}
struct fixture {
    struct cert_trust *trust,*wrong;
    unsigned char certificate[8192],verify[256],hash[32];
    size_t certificate_n,verify_n;
};
static int verify(const struct fixture *f,const struct cert_trust *trust,const char *name){
    return cert_verify_server_prepared(f->certificate,f->certificate_n,f->verify,f->verify_n,
        f->hash,sizeof(f->hash),name,trust,NULL);
}
static void *worker(void *arg){
    const struct fixture *f=arg;
    for(unsigned i=0;i<32;i++){
        assert(!verify(f,f->trust,"tls.example"));
        assert(verify(f,f->trust,"wrong.example")==CERTV_ECHAIN);
        assert(verify(f,f->wrong,"tls.example")==CERTV_ECHAIN);
    }
    return NULL;
}
static size_t load(const char *path,unsigned char *bytes,size_t capacity){
    FILE *file=fopen(path,"rb");assert(file);size_t length=fread(bytes,1,capacity,file);
    assert(length&&length<capacity&&!ferror(file));assert(!fclose(file));return length;
}
static void trust_for(const char *path,struct cert_trust **out){
    unsigned char pem[8192];size_t length=load(path,pem,sizeof(pem));
    assert(!cert_trust_prepare_pem(pem,length,out)&&*out);
    memset(pem,0,sizeof(pem)); /* constructor retained no borrowed PEM bytes */
}
int main(int argc,char **argv){
    assert(argc==6);
    struct fixture f={0};unsigned char leaf[4096];size_t leaf_n=load(argv[3],leaf,sizeof(leaf));
    trust_for(argv[1],&f.trust);trust_for(argv[2],&f.wrong);
    size_t list_n=3+leaf_n+2;f.certificate[0]=0;
    f.certificate[1]=(unsigned char)(list_n>>16);f.certificate[2]=(unsigned char)(list_n>>8);f.certificate[3]=(unsigned char)list_n;
    f.certificate[4]=(unsigned char)(leaf_n>>16);f.certificate[5]=(unsigned char)(leaf_n>>8);f.certificate[6]=(unsigned char)leaf_n;
    memcpy(f.certificate+7,leaf,leaf_n);f.certificate[7+leaf_n]=f.certificate[8+leaf_n]=0;f.certificate_n=9+leaf_n;
    assert(!sc_hash(SC_SHA256,"transcript",10,f.hash));
    size_t sig_n=load(argv[4],f.verify+4,sizeof(f.verify)-4);
    f.verify[0]=4;f.verify[1]=3;f.verify[2]=(unsigned char)(sig_n>>8);f.verify[3]=(unsigned char)sig_n;f.verify_n=sig_n+4;
    struct cert_trust *bad=(struct cert_trust *)&f;
    assert(cert_trust_prepare_pem(NULL,0,&bad)==CERTV_EPARSE&&!bad);
    assert(cert_trust_prepare_pem(leaf,CERT_TRUST_PEM_MAX+1u,&bad)==CERTV_EPARSE&&!bad);
    assert(cert_trust_prepare_pem((const unsigned char *)"not PEM",7,&bad)==CERTV_ENOROOTS&&!bad);
    atomic_store(&forbid_files,1);
    assert(!verify(&f,f.trust,"tls.example"));
    assert(verify(&f,NULL,"tls.example")==CERTV_ENOROOTS);
    assert(verify(&f,f.trust,"")==CERTV_EPARSE);
    assert(cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,NULL,32,"tls.example",f.trust,NULL)==CERTV_EPARSE);
    f.verify[f.verify_n-1]^=1;assert(verify(&f,f.trust,"tls.example")==CERTV_ESIG);f.verify[f.verify_n-1]^=1;
    f.certificate[0]=255;assert(verify(&f,f.trust,"tls.example")==CERTV_EPARSE);f.certificate[0]=0;
    unsigned char fingerprint[32];char pin[65];assert(!sc_hash(SC_SHA256,leaf,leaf_n,fingerprint));
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<32;i++){pin[2*i]=hex[fingerprint[i]>>4];pin[2*i+1]=hex[fingerprint[i]&15];}pin[64]=0;
    struct cert_policy policy={pin,NULL,NULL,0};
    assert(!cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,f.hash,32,"wrong.example",f.wrong,&policy));
    pin[0]=pin[0]=='0'?'1':'0';
    assert(cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,f.hash,32,"tls.example",f.trust,&policy)==CERTV_EPIN);
    policy=(struct cert_policy){NULL,NULL,"wrong.example,tls.example",0};
    assert(!cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,f.hash,32,"wrong.example",f.trust,&policy));
    policy=(struct cert_policy){NULL,NULL,NULL,1};
    assert(!cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,f.hash,32,"wrong.example",f.wrong,&policy));
    f.verify[f.verify_n-1]^=1;
    assert(cert_verify_server_prepared(f.certificate,f.certificate_n,f.verify,f.verify_n,f.hash,32,"wrong.example",f.wrong,&policy)==CERTV_ESIG);
    f.verify[f.verify_n-1]^=1;
    worker(&f);pthread_t threads[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,worker,&f));
    for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
    atomic_store(&forbid_files,0);leaf_n=load(argv[5],leaf,sizeof(leaf));atomic_store(&forbid_files,1);
    list_n=3+leaf_n+2;f.certificate[1]=(unsigned char)(list_n>>16);f.certificate[2]=(unsigned char)(list_n>>8);f.certificate[3]=(unsigned char)list_n;
    f.certificate[4]=(unsigned char)(leaf_n>>16);f.certificate[5]=(unsigned char)(leaf_n>>8);f.certificate[6]=(unsigned char)leaf_n;
    memcpy(f.certificate+7,leaf,leaf_n);f.certificate[7+leaf_n]=f.certificate[8+leaf_n]=0;f.certificate_n=9+leaf_n;
    assert(verify(&f,f.trust,"tls.example")==CERTV_ECHAIN);
    cert_trust_destroy(f.trust);cert_trust_destroy(f.wrong);cert_trust_destroy(NULL);
    puts("prepared TLS trust: copied snapshot, valid/name/CA/expired/signature, explicit pins/insecure, no file fallback, 1+4 concurrent verifiers PASS");
    return 0;
}
