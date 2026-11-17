#define _POSIX_C_SOURCE 200809L
#include "awgdev.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
int main(void){
 char kind[32],marker[256];int before=0,after=0;struct timespec t;
 assert(!awg_dev_link_query("lo",kind,sizeof kind,&before)&&before>0);
 assert(!clock_gettime(CLOCK_MONOTONIC,&t));uint64_t past=(uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec-1;
 assert(awg_dev_link_query_marked_until("lo",kind,sizeof kind,&after,marker,sizeof marker,past)==ETIMEDOUT);
 /* Even if a deadline were accidentally reset, wrong kind/marker on lo must
  * still refuse mutation. Expected TIMEOUT distinguishes deadline forwarding. */
 assert(awg_dev_link_down_marked_until("lo","wireguard",before,"test:owner",past)==ETIMEDOUT);
 assert(awg_dev_link_delete_marked_until("lo","wireguard",before,"test:owner",past)==ETIMEDOUT);
 assert(!awg_dev_link_query("lo",kind,sizeof kind,&after)&&after==before);
 int created=99;assert(awg_dev_link_create_marked_until("steerNoCreate","wireguard",1420,"test:owner",&created,0)==EINVAL&&!created);
 puts("netlink public deadline: expired query/mutation rejected, no deadline reset or link effect PASS");return 0;
}
