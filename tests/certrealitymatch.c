#ifdef NDEBUG
#error "certrealitymatch requires active assertions"
#endif
#include "certverify.h"
#include "scrypto.h"
#include "certgen.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
struct fixture {unsigned char certificate[256],cv[68],hash[48],auth[32],seed[32];size_t certificate_n,hash_n;};
static void content(const struct fixture *f,unsigned char out[176],size_t *length){
    static const char label[]="TLS 1.3, server CertificateVerify";
    memset(out,32,64);memcpy(out+64,label,sizeof(label));memcpy(out+64+sizeof(label),f->hash,f->hash_n);*length=64+sizeof(label)+f->hash_n;
}
static void make_fixture(struct fixture *f,size_t hash_n){
    memset(f,0,sizeof(*f));f->seed[0]=42;memset(f->auth,0x23,32);f->hash_n=hash_n;memset(f->hash,0x71,hash_n);
    unsigned char pub[32],signature[64],der[128];assert(!tcg_ed25519_public(f->seed,pub));assert(!sc_hmac(SC_SHA512,f->auth,32,pub,32,signature));
    static const unsigned char spki[]={0x30,0x2a,0x30,5,6,3,0x2b,0x65,0x70,3,0x21,0};
    size_t n=0;der[n++]=0x30;der[n++]=0x78;der[n++]=0x30;der[n++]=0x2c;memcpy(der+n,spki,sizeof(spki));n+=sizeof(spki);memcpy(der+n,pub,32);n+=32;
    static const unsigned char alg[]={0x30,5,6,3,0x2b,0x65,0x70};memcpy(der+n,alg,sizeof(alg));n+=sizeof(alg);der[n++]=3;der[n++]=0x41;der[n++]=0;memcpy(der+n,signature,64);n+=64;
    unsigned char *b=f->certificate;size_t list=3+n+2;b[0]=0;b[1]=0;b[2]=(unsigned char)(list>>8);b[3]=(unsigned char)list;b[4]=0;b[5]=0;b[6]=(unsigned char)n;memcpy(b+7,der,n);b[7+n]=b[8+n]=0;f->certificate_n=9+n;
    f->cv[0]=8;f->cv[1]=7;f->cv[2]=0;f->cv[3]=64;unsigned char message[176];size_t length;content(f,message,&length);assert(!tcg_ed25519_sign(f->seed,message,length,f->cv+4));
}
static int verify(const struct fixture *f){return cert_reality_verify(f->certificate,f->certificate_n,f->cv,sizeof(f->cv),f->hash,f->hash_n);}
static void *worker(void *arg){const struct fixture *f=arg;for(unsigned i=0;i<32;i++)assert(!verify(f));return NULL;}
int main(void){
    for(unsigned suite=0;suite<2;suite++){
        struct fixture f;make_fixture(&f,suite?48:32);assert(!cert_reality_check(f.certificate,f.certificate_n,f.auth));assert(!verify(&f));
        f.cv[67]^=1;assert(verify(&f)==CERTV_ESIG);f.cv[67]^=1;
        f.hash[0]^=1;assert(verify(&f)==CERTV_ESIG);f.hash[0]^=1;
        unsigned char message[176],other[32]={43};size_t length;content(&f,message,&length);assert(!tcg_ed25519_sign(other,message,length,f.cv+4));assert(verify(&f)==CERTV_ESIG);
        assert(!tcg_ed25519_sign(f.seed,message,length,f.cv+4));f.cv[1]=4;assert(verify(&f)==CERTV_EALG);f.cv[1]=7;
        assert(cert_reality_verify(f.certificate,f.certificate_n,f.cv,67,f.hash,f.hash_n)==CERTV_EPARSE);
        f.cv[3]=63;assert(verify(&f)==CERTV_EPARSE);f.cv[3]=64;
        worker(&f);pthread_t threads[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,worker,&f));for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
    }
    puts("REALITY CertificateVerify: actual Ed25519 signature, tamper/transcript/wrong-key/algorithm, SHA256/384 and 1+4 verifier owners PASS");return 0;
}
