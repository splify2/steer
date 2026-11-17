#define _GNU_SOURCE
#include "kernel_wg.h"
#include "awgdev.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t stopped;
static void stop(int n){(void)n;stopped=1;}
const char *steer_state_dir(void){const char*p=getenv("STEER_TEST_STATE");return p?p:"/tmp";}
static struct steer_pv1_error secret(void*unused,struct steer_pv1_span ref,uint8_t out[44]){const char*key=getenv("STEER_TEST_PRIVATE");struct steer_pv1_error e={STEER_PV1_INVALID,0};(void)unused;if(ref.len!=sizeof("env:STEER_TEST_PRIVATE")-1||memcmp(ref.data,"env:STEER_TEST_PRIVATE",sizeof("env:STEER_TEST_PRIVATE")-1)||!key||strlen(key)!=44)return e;memcpy(out,key,44);e.code=0;return e;}
int main(int argc,char**argv){struct steer_draft_kernel_wg_config c={0};struct steer_draft_kernel_wg*h=NULL;struct steer_pv1_error e;struct sigaction sa={0};int index=0,rc;const char*mode;if(argc!=7)return 2;mode=argv[1];c.generation=1;snprintf(c.inbound_id,sizeof(c.inbound_id),"server");snprintf(c.device,sizeof(c.device),"%s",argv[2]);c.listen_port=(uint16_t)strtoul(argv[3],NULL,10);c.address_count=1;snprintf(c.addresses[0],sizeof(c.addresses[0]),"%s",argv[4]);c.peer_count=1;snprintf(c.peers[0].public_key,sizeof(c.peers[0].public_key),"%s",argv[5]);c.peers[0].allowed_count=1;snprintf(c.peers[0].allowed_ips[0],sizeof(c.peers[0].allowed_ips[0]),"%s",argv[6]);snprintf(c.private_key_ref,sizeof(c.private_key_ref),"env:STEER_TEST_PRIVATE");
if(!strcmp(mode,"zero-private")||!strcmp(mode,"zero-public")){
char zero[45];memset(zero,'A',43);zero[43]='=';zero[44]=0;
if(!strcmp(mode,"zero-private"))assert(!setenv("STEER_TEST_PRIVATE",zero,1));else memcpy(c.peers[0].public_key,zero,sizeof(zero));
e=steer_draft_kernel_wg_prepare(&c,secret,NULL,&h);assert(e.code==STEER_PV1_INVALID&&!h&&awg_dev_link_query(c.device,NULL,0,NULL)==ENODEV);puts("PASS zero key rejected before network mutation");return 0;
}
if(!strcmp(mode,"existing")){rc=awg_dev_link_query(c.device,NULL,0,&index);assert(!rc&&index>0);e=steer_draft_kernel_wg_prepare(&c,secret,NULL,&h);assert(e.code==STEER_PV1_POLICY_DENIED&&!h);{int now=0;assert(!awg_dev_link_query(c.device,NULL,0,&now)&&now==index);}puts("PASS existing device not adopted");return 0;}
e=steer_draft_kernel_wg_prepare(&c,secret,NULL,&h);if(e.code){fprintf(stderr,"prepare failed code=%u\n",e.code);return 1;}assert(awg_dev_link_query(c.device,NULL,0,NULL)==ENODEV);if(!strcmp(mode,"prepare-abort")){assert(!steer_draft_kernel_wg_destroy(h).code);puts("PASS prepare has no network mutation");return 0;}
if(!strcmp(mode,"activation-race")){assert(!awg_dev_link_create_exclusive(c.device,"wireguard",1420,&index)&&index>0);assert(steer_draft_kernel_wg_activate(h).code==STEER_PV1_POLICY_DENIED);assert(!steer_draft_kernel_wg_destroy(h).code);assert(!awg_dev_link_delete_owned(c.device,"wireguard",index));puts("PASS activation refuses raced foreign device");return 0;}
e=steer_draft_kernel_wg_activate(h);if(e.code){fprintf(stderr,"activate failed code=%u\n",e.code);(void)steer_draft_kernel_wg_rollback(h);(void)steer_draft_kernel_wg_destroy(h);return 1;}assert(steer_draft_kernel_wg_index(h)>0);assert(steer_draft_kernel_wg_destroy(h).code==STEER_PV1_POLICY_DENIED);if(!strcmp(mode,"namespace")){int saved=open("/proc/self/ns/net",O_RDONLY|O_CLOEXEC);assert(saved>=0&&!unshare(CLONE_NEWNET));assert(steer_draft_kernel_wg_retire(h).code==STEER_PV1_POLICY_DENIED);assert(steer_draft_kernel_wg_destroy(h).code==STEER_PV1_POLICY_DENIED);assert(!setns(saved,CLONE_NEWNET));close(saved);assert(!steer_draft_kernel_wg_retire(h).code);assert(!steer_draft_kernel_wg_destroy(h).code);puts("PASS namespace ownership enforced");return 0;}if(!strcmp(mode,"rollback")){assert(!steer_draft_kernel_wg_rollback(h).code);assert(awg_dev_link_query(c.device,NULL,0,NULL)==ENODEV);assert(!steer_draft_kernel_wg_destroy(h).code);puts("PASS activated device rollback");return 0;}
sa.sa_handler=stop;sigemptyset(&sa.sa_mask);assert(!sigaction(SIGTERM,&sa,NULL));assert(!sigaction(SIGINT,&sa,NULL));puts("ACTIVE");fflush(stdout);while(!stopped)pause();e=steer_draft_kernel_wg_retire(h);if(!strcmp(mode,"replacement")){assert(e.code==STEER_PV1_POLICY_DENIED);assert(!steer_draft_kernel_wg_destroy(h).code);puts("PASS foreign replacement preserved");return 0;}assert(!e.code);assert(!steer_draft_kernel_wg_retire(h).code);assert(!steer_draft_kernel_wg_destroy(h).code);puts("RETIRED");return 0;}
