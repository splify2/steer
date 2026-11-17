#define _GNU_SOURCE
#include "nftdump.h"
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
static pthread_barrier_t start;
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+2000000000u;}
static void seen(void *p,const char *c,int has,uint64_t packets,uint64_t bytes){(void)c;(void)has;(void)packets;(void)bytes;(*(unsigned *)p)++;}
static void *query(void *unused){
    (void)unused;pthread_barrier_wait(&start);
    for(unsigned j=0;j<40;j++){struct nfd_tfp result;if((j&1?nfd_table_fp("steer_owned_absent_probe",&result):nfd_table_fp_until("steer_owned_absent_probe",&result,deadline()))||result.fams)return (void *)1;}
    return NULL;
}
int main(void){
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_NFT_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated namespace required\n",stderr);return 2;}
    struct nfd_tfp result;assert(nfd_table_fp_until("steer_owned_absent_probe",&result,0)==EINVAL&&!result.fams);
    assert(nfd_table_fp_until("steer_owned_absent_probe",&result,1)==ETIMEDOUT&&!result.fams);
    const char *chains[]={"ownership"};unsigned calls=0;assert(nfd_chain_rules_until(NFD_INET,"steer_owned_absent_probe",chains,1,seen,&calls,1)==ETIMEDOUT&&!calls);
    assert(!pthread_barrier_init(&start,NULL,4));pthread_t t[4];for(unsigned j=0;j<4;j++)assert(!pthread_create(t+j,NULL,query,NULL));
    for(unsigned j=0;j<4;j++){void *result;assert(!pthread_join(t[j],&result)&&!result);}pthread_barrier_destroy(&start);
    puts("nft query four concurrent isolated owners PASS");return 0;
}
