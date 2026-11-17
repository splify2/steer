#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include "qcssl.h"
#include "scrypto.h"
#include "qccert.h"
static pthread_barrier_t barrier;
static void *worker(void *arg) {
    size_t kind=(size_t)arg;
    pthread_barrier_wait(&barrier);
    for(int i=0;i<40;i++) {
        if(kind<2) {
            void *p=kind?qcssl_ctx_server(qc_cert_der,sizeof(qc_cert_der),qc_key_der,sizeof(qc_key_der)):qcssl_ctx_client(1,0,0,0);
            if(!p) return (void *)1;
            qcssl_ctx_free(p);
        } else {
            struct sc_roots *r=0;
            if(sc_roots_load_der(&r,qc_cert_der,sizeof(qc_cert_der))) return (void *)1;
            sc_roots_free(r);
        }
    }
    return 0;
}
int main(void) {
    pthread_t t[4]; int failed=0;
    if(pthread_barrier_init(&barrier,0,4)) return 2;
    for(size_t i=0;i<4;i++) if(pthread_create(&t[i],0,worker,(void *)i)) return 2;
    for(int i=0;i<4;i++){void *r=0;pthread_join(t[i],&r);failed|=r!=0;}
    pthread_barrier_destroy(&barrier);
    puts(failed?"cold init FAIL":"cold init PASS");
    return failed;
}
