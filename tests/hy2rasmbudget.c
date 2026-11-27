/* SPDX-License-Identifier: GPL-3.0-only
 * Link with --wrap=malloc,--wrap=calloc for allocation-failure checks. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hy2wire.h"
void *__real_malloc(size_t);void *__real_calloc(size_t,size_t);
static int fail_malloc,fail_calloc;
void *__wrap_malloc(size_t n) { if(fail_malloc>0&&!--fail_malloc) return NULL;return __real_malloc(n); }
void *__wrap_calloc(size_t n,size_t size) { if(fail_calloc>0&&!--fail_calloc) return NULL;return __real_calloc(n,size); }
static const uint8_t payload[65507]={1};
static void empty(void) { unsigned entries,bytes;hy2_rasm_usage(&entries,&bytes);assert(!entries&&!bytes); }
static pthread_barrier_t barrier;
static void *stress(void *unused) {
    struct hy2_rasm *heads[200]={0};struct hy2_udp_msg m={.data=payload,.n=sizeof payload,.nfrag=2};size_t total;
    (void)unused;
    for(unsigned i=0;i<200;i++) { m.pkt=(uint16_t)i;assert(!hy2_rasm_feed(&heads[i],&m,1,0,&total)); }
    pthread_barrier_wait(&barrier);
    unsigned entries,bytes;hy2_rasm_usage(&entries,&bytes);
    assert(entries&&entries<=HY2_RASM_TOTAL_ENTRIES&&bytes&&bytes<=HY2_RASM_TOTAL_BYTES);
    pthread_barrier_wait(&barrier);
    for(unsigned i=0;i<200;i++) hy2_rasm_free(&heads[i]);
    return NULL;
}
int main(void) {
    struct hy2_rasm *head=NULL;
    struct hy2_udp_msg m={.data=payload,.n=4,.nfrag=2};size_t total;
    empty();fail_calloc=1;assert(!hy2_rasm_feed(&head,&m,1,0,&total)&&!head);empty();
    fail_malloc=1;assert(!hy2_rasm_feed(&head,&m,1,0,&total)&&!head);empty();
    assert(!hy2_rasm_feed(&head,&m,1,0,&total));
    unsigned before_e,before_b,after_e,after_b;hy2_rasm_usage(&before_e,&before_b);
    m.frag=1;fail_malloc=1;assert(!hy2_rasm_feed(&head,&m,2,0,&total));
    hy2_rasm_usage(&after_e,&after_b);assert(before_e==after_e&&before_b==after_b);
    fail_malloc=2;assert(!hy2_rasm_feed(&head,&m,3,0,&total)&&!head);empty();
    m.frag=0;assert(!hy2_rasm_feed(&head,&m,1,0,&total));
    hy2_rasm_expire(&head,1+HY2_RASM_TTL_MS);assert(!head);empty();
    hy2_rasm_free(&head);hy2_rasm_free(&head);empty();
    m.nfrag=1;assert(!hy2_rasm_feed(&head,&m,1,SIZE_MAX,&total)&&!head);empty();
    m.nfrag=2;m.frag=0;m.n=4;m.data=payload;strcpy(m.addr,"one.example:80");
    assert(!hy2_rasm_feed(&head,&m,1,0,&total));
    m.frag=1;strcpy(m.addr,"two.example:80");
    assert(!hy2_rasm_feed(&head,&m,2,0,&total)); /* never combine destinations */
    m.frag=0;uint8_t *assembled=hy2_rasm_feed(&head,&m,3,0,&total);
    assert(assembled&&total==8);free(assembled);assert(!head);empty();
    memset(m.addr,'x',sizeof m.addr);assert(!hy2_rasm_feed(&head,&m,4,0,&total)&&!head);m.addr[0]=0;
    struct hy2_rasm *heads[HY2_RASM_TOTAL_ENTRIES+1]={0};
    m.nfrag=2;m.n=0;m.data=NULL;
    for(unsigned i=0;i<=HY2_RASM_TOTAL_ENTRIES;i++) assert(!hy2_rasm_feed(&heads[i],&m,1,0,&total));
    hy2_rasm_usage(&after_e,&after_b);assert(after_e==HY2_RASM_TOTAL_ENTRIES&&!heads[HY2_RASM_TOTAL_ENTRIES]);
    for(unsigned i=0;i<=HY2_RASM_TOTAL_ENTRIES;i++) hy2_rasm_free(&heads[i]);
    empty();
    pthread_t workers[8];assert(!pthread_barrier_init(&barrier,NULL,8));
    for(unsigned i=0;i<8;i++) assert(!pthread_create(&workers[i],NULL,stress,NULL));
    for(unsigned i=0;i<8;i++) assert(!pthread_join(workers[i],NULL));
    assert(!pthread_barrier_destroy(&barrier));empty();
    puts("hy2rasmbudget: allocation rollback, TTL, entry/byte caps and 8-worker accounting PASS");return 0;
}
