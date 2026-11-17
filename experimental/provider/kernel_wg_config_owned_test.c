#define _GNU_SOURCE
#include "kernel_wg_ownership.h"
#include "awgdev.h"
#include <steer/draft/device_v1.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/wireguard.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static _Thread_local int track;
static _Thread_local size_t live_bytes,peak_bytes;
static _Thread_local struct {void *p;size_t n;} allocation[8];
void *__real_malloc(size_t);void __real_free(void *);
void *__wrap_malloc(size_t n){void *p=__real_malloc(n);if(p&&track){unsigned j;for(j=0;j<8&&allocation[j].p;j++){}assert(j<8);allocation[j].p=p;allocation[j].n=n;live_bytes+=n;if(live_bytes>peak_bytes)peak_bytes=live_bytes;}return p;}
void __wrap_free(void *p){for(unsigned j=0;j<8;j++)if(p&&allocation[j].p==p){live_bytes-=allocation[j].n;allocation[j].p=NULL;break;}__real_free(p);}
/* Public RFC7748 section6.1 test vectors, never user credentials.
 * https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1 */
static const char scalar[]="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char peer[]="de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static void bytes(const char *s,uint8_t out[32]){for(unsigned j=0;j<32;j++){unsigned n;assert(sscanf(s+2*j,"%2x",&n)==1);out[j]=(uint8_t)n;}}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+2000000000u;}
static void config(struct awg_conf *c,struct awg_secrets *s){
    memset(c,0,sizeof *c);memset(s,0,sizeof *s);bytes(scalar,s->priv);s->has_priv=1;
    c->peer_n=1;c->aips_n=1;bytes(peer,c->peer[0].pub);c->peer[0].aip_n=1;
    c->aips[0].family=AF_INET;c->aips[0].cidr=32;c->aips[0].addr[0]=10;c->aips[0].addr[1]=77;c->aips[0].addr[3]=2;
}
static void wire(void){
    struct awg_conf *c=calloc(1,sizeof *c);struct awg_secrets s;assert(c);config(c,&s);
    _Alignas(8) uint8_t b[2048];size_t n=awg_build_set_index(b,sizeof b,33,1,0,123,c,&s,0,1,7);assert(n);
    size_t at=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(struct genlmsghdr));unsigned found=0;
    while(at<n){const struct nlattr *a=(const void *)(b+at);assert(a->nla_len>=sizeof *a&&a->nla_len<=n-at);
        assert((a->nla_type&NLA_TYPE_MASK)!=WGDEVICE_A_IFNAME);
        if((a->nla_type&NLA_TYPE_MASK)==WGDEVICE_A_IFINDEX){uint32_t index;assert(a->nla_len==sizeof *a+4);memcpy(&index,a+1,4);assert(index==123);found++;}at+=NLA_ALIGN(a->nla_len);
    }
    assert(found==1&&at==n&&!awg_build_set_index(b,sizeof b,33,1,0,0,c,&s,0,1,7));awg_secrets_wipe(&s);free(c);
}
static void *owner(void *arg){
    uintptr_t number=(uintptr_t)arg;assert(!unshare(CLONE_NEWNET));int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(ns>=0);
    struct awg_conf *c=calloc(1,sizeof *c);struct awg_live *live=calloc(1,sizeof *live);struct awg_secrets keys;assert(c&&live);config(c,&keys);
    atomic_uint cancel=0;struct steer_draft_wg_identity id;struct steer_draft_wg_observation o;
    assert(!steer_draft_wg_identity_prepare(ns,12,100+number,"wireguard",deadline(),&cancel,&id));
    assert(!steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel,&o));int index=o.index;
    for(unsigned j=0;j<6;j++){
        if(!number)assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group==1?2:1,c,&keys,0,deadline())==ESTALE);
        track=1;peak_bytes=0;
        assert(!awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline()));
        track=0;assert(!live_bytes&&peak_bytes<=131072u);
        assert(!awg_dev_live_read_owned_until(id.physical_name,id.kind,index,id.group,live,deadline())&&live->peer_n==1&&!memcmp(live->peer[0].pub,c->peer[0].pub,32));
    }
    c->peer_n=AWG_MAX_PEERS+1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EINVAL);c->peer_n=1;
    c->peer[0].aip_first=SIZE_MAX;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EINVAL);c->peer[0].aip_first=0;
    c->peer[0].has_ep=1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EDESTADDRREQ);c->peer[0].has_ep=0;
    c->u16_has=1u<<AWG_JC;c->u16[AWG_JC]=1;assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,deadline())==EOPNOTSUPP);c->u16_has=0;
    assert(awg_dev_configure_owned_until(id.physical_name,id.kind,index,id.group,c,&keys,0,1)==ETIMEDOUT);
    assert(!awg_dev_live_read_owned_until(id.physical_name,id.kind,index,id.group,live,deadline())&&live->peer_n==1&&!memcmp(live->peer[0].pub,c->peer[0].pub,32));
    assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel,&o));awg_secrets_wipe(&keys);free(live);free(c);close(ns);return NULL;
}
int main(int argc,char **argv){
    wire();if(argc==2&&!strcmp(argv[1],"--wire")){puts("WG parsed config exact-index wire PASS");return 0;}
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_OWNED_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated namespace required\n",stderr);return 2;}
    pthread_t t[4];for(uintptr_t j=0;j<4;j++)assert(!pthread_create(t+j,NULL,owner,(void *)j));for(unsigned j=0;j<4;j++)assert(!pthread_join(t[j],NULL));
    puts("WG parsed config: four thread namespaces, real key/peer SET+GET, isolated ownership failures, invalid/unresolved variants fail closed PASS");return 0;
}
