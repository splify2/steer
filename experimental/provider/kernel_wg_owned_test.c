#define _GNU_SOURCE
#include "awgdev.h"
#include <assert.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+2000000000u;}
static void marker(char name[16],uint32_t *group){
    static const char alphabet[]="abcdefghijklmnopqrstuvwxyz234567";unsigned char bytes[17];
    assert(getrandom(bytes,sizeof bytes,GRND_NONBLOCK)==sizeof bytes);
    memcpy(name,"sw",2);for(unsigned i=0;i<13;i++)name[i+2]=alphabet[bytes[i]&31];name[15]=0;
    memcpy(group,bytes+13,4);if(!*group)*group=1;
}
static void wire(const char *name,uint32_t group){
    _Alignas(8) uint8_t b[512];size_t n=awg_build_newlink_owned(b,sizeof b,name,"wireguard",1420,group,9);assert(n);
    const struct nlmsghdr *h=(const void *)b;assert(h->nlmsg_type==RTM_NEWLINK&&(h->nlmsg_flags&NLM_F_EXCL));
    size_t at=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(struct ifinfomsg));unsigned found=0;
    while(at<n){const struct nlattr *a=(const void *)(b+at);assert(a->nla_len>=sizeof *a&&a->nla_len<=n-at);
        assert((a->nla_type&NLA_TYPE_MASK)!=IFLA_IFALIAS);
        if((a->nla_type&NLA_TYPE_MASK)==IFLA_GROUP){uint32_t g=0;assert(a->nla_len==sizeof *a+4);memcpy(&g,a+1,4);assert(g==group);found++;}
        at+=NLA_ALIGN(a->nla_len);
    }
    assert(found==1&&at==n&&!awg_build_newlink_owned(b,sizeof b,name,"wireguard",1420,0,9));
}
static void ip(char *const args[]){pid_t p=fork();assert(p>=0);if(!p){execvp("ip",args);_exit(127);}int status;assert(waitpid(p,&status,0)==p&&WIFEXITED(status)&&!WEXITSTATUS(status));}
int main(int argc,char **argv){
    char name[16],other[16],third[16];uint32_t group,unused;marker(name,&group);marker(other,&unused);marker(third,&unused);wire(name,group);
    if(argc==2&&!strcmp(argv[1],"--wire")){puts("WG composite wire PASS");return 0;}
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_OWNED_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated namespace required\n",stderr);return 2;}
    int index=0,second=0;assert(awg_dev_link_create_owned_until(name,"wireguard",1420,group,&index,1)==ETIMEDOUT&&!index);
    assert(!awg_dev_link_create_owned_until(name,"wireguard",1420,group,&index,deadline())&&index>0);
    uint32_t observed=0;int actual=0;char kind[32];
    assert(!awg_dev_link_query_owned_until(name,kind,sizeof kind,&actual,&observed,deadline())&&actual==index&&observed==group&&!strcmp(kind,"wireguard"));
    int collision=0;assert(awg_dev_link_create_owned_until(name,"wireguard",1420,group,&collision,deadline())==EEXIST&&!collision);
    /* Same group is deliberately not unique: precise-index deletion must leave
     * this different-name device intact (no rtnl group-delete fallback). */
    assert(!awg_dev_link_create_owned_until(other,"wireguard",1420,group,&second,deadline()));
    uint32_t foreign=group==1?2:1;char number[16];snprintf(number,sizeof number,"%u",foreign);
    char *set[]={"ip","link","set","dev",name,"group",number,NULL};ip(set);
    assert(awg_dev_link_down_owned_until(name,"wireguard",index,group,deadline())==ESTALE);
    assert(awg_dev_link_delete_owned_until(name,"wireguard",index,group,deadline())==ESTALE);
    assert(!awg_dev_link_query_owned_until(name,kind,sizeof kind,&actual,&observed,deadline())&&actual==index&&observed==foreign);
    char *remove[]={"ip","link","del","dev",name,NULL};ip(remove);
    /* Same physical name and reused index with foreign marker is never adopted. */
    char idx[16];snprintf(idx,sizeof idx,"%d",index);
    char *replace[]={"ip","link","add","name",name,"index",idx,"type","wireguard",NULL};ip(replace);
    assert(awg_dev_link_delete_owned_until(name,"wireguard",index,group,deadline())==ESTALE);
    assert(!awg_dev_link_query_owned_until(name,kind,sizeof kind,&actual,&observed,deadline())&&actual==index&&!observed);
    ip(remove);
    assert(awg_dev_link_delete_owned_until(name,"wireguard",index,group,deadline())==ENODEV);
    int survivor=0;assert(!awg_dev_link_create_owned_until(third,"wireguard",1420,group,&survivor,deadline()));
    assert(!awg_dev_link_down_owned_until(other,"wireguard",second,group,deadline()));
    assert(!awg_dev_link_delete_owned_until(other,"wireguard",second,group,deadline()));
    assert(!awg_dev_link_query_owned_until(third,kind,sizeof kind,&actual,&observed,deadline())&&actual==survivor&&observed==group);
    assert(!awg_dev_link_delete_owned_until(third,"wireguard",survivor,group,deadline()));
    puts("WG composite kernel: persisted group, collision, foreign marker, exact-index cleanup, replacement refusal PASS");return 0;
}
