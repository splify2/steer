#define main kernel_device_test_main
#include "kernel_wg_test.c"
#undef main
#include "kernel_wg_guard.h"
#include "policy.h"
#include "nftdump.h"
#include "run.h"
#include <ifaddrs.h>
#include <net/if.h>
static volatile sig_atomic_t policy_signal;
static int race_next,discard_echo,postcommit_failure;
static const char *race_table;
static struct nfd_tfp raced_snapshot;
int __real_run_output(const char *const[],int);
int __wrap_run_output(const char *const argv[],int fd){
    if(race_next){const char*del[]={"nft","delete","table","inet",race_table,NULL};const char*add[]={"nft","add","table","inet",race_table,NULL};struct nfd_tfp state;race_next=0;assert(!run(del)&&!run(add)&&!nfd_table_fp(race_table,&state)&&state.fams);raced_snapshot=state;}
    if(discard_echo){int devnull=open("/dev/null",O_WRONLY);int result;discard_echo=0;assert(devnull>=0);result=__real_run_output(argv,devnull);close(devnull);return result;}
    {int r=__real_run_output(argv,fd);if(postcommit_failure){postcommit_failure=0;return 1;}return r;}
}
static void policy_change(int n){policy_signal=n;}
static struct steer_pv1_span sp(const char*x){struct steer_pv1_span s={(const uint8_t*)x,(uint32_t)strlen(x)};return s;}
static struct steer_policy *make_policy(uint64_t generation,int direct){struct steer_policy*p=NULL;struct steer_policy_rule r[2]={0};r[0].id=sp("blocked-port");r[0].inbound=sp("server");r[0].principal=sp("alice");r[0].port_first=15353;r[0].port_last=15354;r[0].action=STEER_POLICY_BLOCK;r[1].id=sp("verified-peer");r[1].inbound=sp("server");r[1].principal=sp("alice");r[1].action=direct?STEER_POLICY_DIRECT:STEER_POLICY_BLOCK;assert(!steer_policy_compile(generation,r,2,STEER_POLICY_BLOCK,&p).code);return p;}
static void validate_boundaries(const struct steer_draft_kernel_wg_guard_config*base){struct steer_draft_kernel_wg_guard_config c=*base;struct steer_policy*p;struct steer_draft_kernel_wg_guard*g=NULL;struct steer_policy_rule r={0};r.id=sp("domain");r.inbound=sp("server");r.domain=sp("example.test");r.action=STEER_POLICY_DIRECT;assert(!steer_policy_compile(1,&r,1,STEER_POLICY_BLOCK,&p).code);assert(steer_draft_kernel_wg_guard_prepare(&c,p,&g).code==STEER_PV1_UNSUPPORTED&&!g);steer_policy_destroy(p);r.inbound=sp("another-inbound");assert(!steer_policy_compile(1,&r,1,STEER_POLICY_BLOCK,&p).code);assert(!steer_draft_kernel_wg_guard_prepare(&c,p,&g).code&&!steer_draft_kernel_wg_guard_destroy(g).code);g=NULL;steer_policy_destroy(p);p=make_policy(1,1);c.peer_count=2;c.peers[1]=c.peers[0];snprintf(c.peers[1].principal_id,sizeof(c.peers[1].principal_id),"bob");assert(steer_draft_kernel_wg_guard_prepare(&c,p,&g).code==STEER_PV1_INVALID&&!g);steer_policy_destroy(p);}
int main(int argc,char**argv){struct steer_draft_kernel_wg_config c={0};struct steer_draft_kernel_wg_guard_config gc={0};struct steer_draft_kernel_wg*h=NULL;struct steer_draft_kernel_wg_guard*g=NULL,*next=NULL;struct steer_policy*p;struct sigaction action={0};uint64_t generation=1;int published=0;const char*mode;struct steer_pv1_error e;if(argc!=7)return 2;mode=argv[1];c.generation=1;snprintf(c.inbound_id,sizeof(c.inbound_id),"server");snprintf(c.device,sizeof(c.device),"%s",argv[2]);c.listen_port=(uint16_t)strtoul(argv[3],NULL,10);c.address_count=1;snprintf(c.addresses[0],sizeof(c.addresses[0]),"%s",argv[4]);c.peer_count=1;snprintf(c.peers[0].public_key,sizeof(c.peers[0].public_key),"%s",argv[5]);c.peers[0].allowed_count=1;snprintf(c.peers[0].allowed_ips[0],sizeof(c.peers[0].allowed_ips[0]),"%s",argv[6]);snprintf(c.private_key_ref,sizeof(c.private_key_ref),"env:STEER_TEST_PRIVATE");gc.generation=1;snprintf(gc.inbound_id,sizeof(gc.inbound_id),"server");snprintf(gc.device,sizeof(gc.device),"%s",c.device);gc.peer_count=1;snprintf(gc.peers[0].principal_id,sizeof(gc.peers[0].principal_id),"alice");gc.peers[0].allowed_count=1;snprintf(gc.peers[0].allowed_ips[0],sizeof(gc.peers[0].allowed_ips[0]),"%s",argv[6]);validate_boundaries(&gc);p=make_policy(1,1);assert(!steer_draft_kernel_wg_guard_prepare(&gc,p,&g).code);steer_policy_destroy(p);assert(!steer_draft_kernel_wg_prepare(&c,secret,NULL,&h).code);
if(!strcmp(mode,"unknown-echo")){discard_echo=1;e=steer_draft_kernel_wg_activate_guarded(h,steer_draft_kernel_wg_guard_bind,g);assert(e.code&&awg_dev_link_query(c.device,NULL,0,NULL)==ENODEV);assert(!steer_draft_kernel_wg_destroy(h).code);assert(steer_draft_kernel_wg_guard_destroy(g).code==STEER_PV1_POLICY_DENIED);{const char*del[]={"nft","delete","table","inet",steer_draft_kernel_wg_guard_table(g),NULL};assert(!run(del));}assert(!steer_draft_kernel_wg_guard_reconcile_absent(g).code&&!steer_draft_kernel_wg_guard_destroy(g).code);puts("PASS missing echo retains explicit unknown identity until reconciliation");return 0;}
assert(!steer_draft_kernel_wg_activate_guarded(h,steer_draft_kernel_wg_guard_bind,g).code);
if(!strcmp(mode,"replace-exit")||!strcmp(mode,"replace-unknown")){
struct steer_draft_kernel_wg_guard_result changed;char table[64];
assert(!steer_draft_kernel_wg_guard_publish(g).error.code);gc.generation=2;p=make_policy(2,0);assert(!steer_draft_kernel_wg_guard_prepare(&gc,p,&next).code);steer_policy_destroy(p);
if(!strcmp(mode,"replace-exit"))postcommit_failure=1;else discard_echo=1;
changed=steer_draft_kernel_wg_guard_replace(g,next);assert(changed.error.code==STEER_PV1_IO);snprintf(table,sizeof(table),"%s",steer_draft_kernel_wg_guard_table(next));
if(!strcmp(mode,"replace-exit")){
assert(changed.phase==STEER_DRAFT_WG_GUARD_CHANGED);assert(!steer_draft_kernel_wg_guard_destroy(g).code);assert(steer_draft_kernel_wg_guard_destroy(next).code==STEER_PV1_POLICY_DENIED);
assert(!steer_draft_kernel_wg_retire(h).code&&!steer_draft_kernel_wg_destroy(h).code);assert(!steer_draft_kernel_wg_guard_retire(next).code&&!steer_draft_kernel_wg_guard_destroy(next).code);
puts("PASS postcommit tool error transfers confirmed new table owner");
}else{
struct ifaddrs *all,*a;int up=0;assert(changed.phase==STEER_DRAFT_WG_GUARD_UNCERTAIN);assert(!getifaddrs(&all));for(a=all;a;a=a->ifa_next)if(!strcmp(a->ifa_name,c.device)&&(a->ifa_flags&IFF_UP))up=1;freeifaddrs(all);assert(!up);{int still_owned=0;assert(!awg_dev_link_query(c.device,NULL,0,&still_owned)&&still_owned==steer_draft_kernel_wg_index(h));}
assert(steer_draft_kernel_wg_guard_destroy(g).code==STEER_PV1_POLICY_DENIED&&steer_draft_kernel_wg_guard_destroy(next).code==STEER_PV1_POLICY_DENIED);
assert(!steer_draft_kernel_wg_retire(h).code&&!steer_draft_kernel_wg_destroy(h).code);{const char*del[]={"nft","delete","table","inet",table,NULL};assert(!run(del));}
assert(!steer_draft_kernel_wg_guard_reconcile_absent(g).code&&!steer_draft_kernel_wg_guard_reconcile_absent(next).code);assert(!steer_draft_kernel_wg_guard_destroy(g).code&&!steer_draft_kernel_wg_guard_destroy(next).code);puts("PASS unknown replace keeps contexts and quiesces owned WG before return");
}return 0;
}
if(!strcmp(mode,"race")){struct nfd_tfp foreign,after;assert(!steer_draft_kernel_wg_guard_publish(g).error.code);gc.generation=2;p=make_policy(2,0);assert(!steer_draft_kernel_wg_guard_prepare(&gc,p,&next).code);steer_policy_destroy(p);race_table=steer_draft_kernel_wg_guard_table(g);race_next=1;struct steer_draft_kernel_wg_guard_result changed=steer_draft_kernel_wg_guard_replace(g,next);assert(changed.error.code&&changed.phase==STEER_DRAFT_WG_GUARD_UNCERTAIN&&!nfd_table_fp(race_table,&foreign)&&foreign.fams&&foreign.handle==raced_snapshot.handle&&foreign.fp==raced_snapshot.fp);assert(steer_draft_kernel_wg_guard_retire(g).code==STEER_PV1_POLICY_DENIED);assert(!nfd_table_fp(race_table,&after)&&after.handle==foreign.handle);assert(!steer_draft_kernel_wg_retire(h).code&&!steer_draft_kernel_wg_destroy(h).code);{const char*del[]={"nft","delete","table","inet",race_table,NULL};assert(!run(del));}assert(!steer_draft_kernel_wg_guard_reconcile_absent(g).code&&!steer_draft_kernel_wg_guard_reconcile_absent(next).code);assert(!steer_draft_kernel_wg_guard_destroy(g).code&&!steer_draft_kernel_wg_guard_destroy(next).code);puts("PASS raced foreign table survives captured-handle transaction");return 0;}
action.sa_handler=stop;sigemptyset(&action.sa_mask);assert(!sigaction(SIGTERM,&action,NULL));action.sa_handler=policy_change;assert(!sigaction(SIGUSR1,&action,NULL)&&!sigaction(SIGUSR2,&action,NULL));puts("ACTIVE_DROP");fflush(stdout);
while(!stopped){if(policy_signal){int signal_number=policy_signal;policy_signal=0;if(!published&&signal_number==SIGUSR1){assert(!steer_draft_kernel_wg_guard_publish(g).error.code);published=1;}else{gc.generation=++generation;p=make_policy(generation,signal_number==SIGUSR1);assert(!steer_draft_kernel_wg_guard_prepare(&gc,p,&next).code);steer_policy_destroy(p);assert(!steer_draft_kernel_wg_guard_replace(g,next).error.code);assert(!steer_draft_kernel_wg_guard_destroy(g).code);g=next;next=NULL;}puts(signal_number==SIGUSR1?"POLICY_DIRECT":"POLICY_BLOCK");fflush(stdout);}else pause();}
assert(!steer_draft_kernel_wg_retire(h).code);assert(!steer_draft_kernel_wg_guard_retire(g).code);assert(!steer_draft_kernel_wg_guard_destroy(g).code&&!steer_draft_kernel_wg_destroy(h).code);puts("RETIRED");return 0;}
