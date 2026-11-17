#include <pthread.h>
#include <stdatomic.h>
#include "steer_init.h"
static atomic_int calls;
int __wrap_wolfSSL_Init(void) { atomic_fetch_add(&calls, 1); return -1; }
static void *worker(void *arg) {
    (void)arg;
    for(int i=0;i<100;i++) if(wolfSSL_steer_init()!=-1) return (void *)1;
    return 0;
}
int main(void) {
    pthread_t t[4];
    for(int i=0;i<4;i++) if(pthread_create(t+i,0,worker,0)) return 2;
    for(int i=0;i<4;i++){void *r=0;pthread_join(t[i],&r);if(r) return 1;}
    return atomic_load(&calls)!=1;
}
