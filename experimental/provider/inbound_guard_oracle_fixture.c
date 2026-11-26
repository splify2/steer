#define _GNU_SOURCE
/* Disposable-netns fixture: invoke the real managed guard, not hand-written rules. */
#include "kernel_wg_guard.h"
#include "kernel_wg_guard_record.h"
#include "kernel_wg_ownership.h"
#include "policy.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec+10000000000u;}
int main(void){
    int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);struct stat inner,outer;
    assert(ns>=0&&!fstat(ns,&inner)&&!fstat(3,&outer));
    assert(inner.st_dev!=outer.st_dev||inner.st_ino!=outer.st_ino);
    struct steer_draft_wg_guard_record r={0};struct steer_draft_wg_observation seen;
    assert(!steer_draft_wg_identity_prepare(ns,1,1,"wireguard",deadline(),NULL,&r.link));
    assert(!steer_draft_wg_identity_create(&r.link,ns,1420,deadline(),NULL,&seen));
    assert(seen.state==STEER_DRAFT_WG_OWNED&&seen.index>0);r.ifindex=(uint32_t)seen.index;
    struct steer_draft_kernel_wg_guard_config c={.generation=1,.peer_count=1};
    strcpy(c.device,r.link.physical_name);strcpy(c.inbound_id,"vpn");
    strcpy(c.peers[0].principal_id,"alice");c.peers[0].allowed_count=1;
    strcpy(c.peers[0].allowed_ips[0],"10.80.0.2/32");
    struct steer_policy *policy=NULL;struct steer_draft_kernel_wg_guard *g=NULL;
    assert(!steer_policy_compile(1,NULL,0,STEER_POLICY_DIRECT,&policy).code);
    assert(!steer_draft_kernel_wg_guard_prepare(&c,policy,&g).code);
    assert(!steer_draft_kernel_wg_guard_plan(g,r.table,r.marker));
    uint64_t handle=0;
    struct steer_draft_kernel_wg_guard_result q=steer_draft_kernel_wg_guard_apply_owned(g,&r,ns,0,deadline(),&handle);
    assert(!q.error.code&&q.phase==STEER_DRAFT_WG_GUARD_CHANGED&&handle);r.handle=handle;
    q=steer_draft_kernel_wg_guard_apply_owned(g,&r,ns,1,deadline(),&handle);
    assert(!q.error.code&&q.phase==STEER_DRAFT_WG_GUARD_CHANGED&&handle);r.handle=handle;
    printf("%s %s %llu %u\n",r.table,r.marker,(unsigned long long)r.handle,r.ifindex);fflush(stdout);
    assert(getchar()=='q');
    assert(!steer_draft_wg_identity_retire(&r.link,ns,deadline(),NULL,&seen));
    assert(!steer_draft_kernel_wg_guard_retire_record(&r,ns,deadline()));
    steer_draft_kernel_wg_guard_forget_prepared(g);steer_policy_destroy(policy);close(ns);
    return 0;
}
