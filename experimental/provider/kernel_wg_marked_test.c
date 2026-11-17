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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static const char name[]="steerMark0",marker[]="steer:wg:0123456789abcdef0123456789abcdef",foreign[]="external:owner";
static void wire(void){
    uint8_t data[512];size_t n=awg_build_newlink_marked(data,sizeof data,name,"wireguard",1420,marker,7);assert(n);
    const struct nlmsghdr *h=(const void *)data;assert(h->nlmsg_type==RTM_NEWLINK&&h->nlmsg_seq==7);
    assert((h->nlmsg_flags&(NLM_F_CREATE|NLM_F_EXCL))==(NLM_F_CREATE|NLM_F_EXCL));
    size_t offset=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(struct ifinfomsg));unsigned found=0;
    while(offset<n){const struct nlattr *attr=(const void *)(data+offset);assert(attr->nla_len>=sizeof *attr&&attr->nla_len<=n-offset);
        if((attr->nla_type&NLA_TYPE_MASK)==IFLA_IFALIAS){assert(attr->nla_len-sizeof *attr==sizeof marker&&!memcmp(attr+1,marker,sizeof marker));found++;}
        offset+=NLA_ALIGN(attr->nla_len);
    }
    assert(found==1&&offset==n);
    assert(!awg_build_newlink_marked(data,4,name,"wireguard",1420,marker,7));
    assert(!awg_build_newlink_marked(data,sizeof data,name,"wireguard",1420,"",7));
}
static void ip(const char *a,const char *b,const char *c,const char *d){
    pid_t child=fork();assert(child>=0);if(!child){execlp("ip","ip","link",a,b,c,d,(char *)NULL);_exit(127);}
    int result;assert(waitpid(child,&result,0)==child&&WIFEXITED(result)&&WEXITSTATUS(result)==0);
}
static int flags(void){
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);struct ifreq request={0};assert(fd>=0);strcpy(request.ifr_name,name);
    assert(!ioctl(fd,SIOCGIFFLAGS,&request));close(fd);return request.ifr_flags;
}
int main(int argc,char **argv){
    wire();if(argc==2&&!strcmp(argv[1],"--wire")){puts("marked netlink wire: PASS");return 0;}
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_MARKED_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated test namespace required\n",stderr);return 2;}
    assert(awg_dev_link_query(name,NULL,0,NULL)==ENODEV);
    int index=0;int created=awg_dev_link_create_marked(name,"wireguard",1420,marker,&index);if(created){char k[32],m[256];int i=0;int q=awg_dev_link_query_marked(name,k,sizeof k,&i,m,sizeof m);fprintf(stderr,"marked create errno=%d captured_index=%d query=%d actual_index=%d kind=%s marker_equal=%d marker_len=%zu\n",created,index,q,i,q?"?":k,!q&&!strcmp(m,marker),q?0:strlen(m));}assert(!created&&index>0);
    char kind[32],observed[256];int now=0;assert(!awg_dev_link_query_marked(name,kind,sizeof kind,&now,observed,sizeof observed));
    assert(now==index&&!strcmp(kind,"wireguard")&&!strcmp(observed,marker));
    ip("set",name,"up",NULL);assert(flags()&IFF_UP);
    assert(awg_dev_link_down_marked(name,"wireguard",index,foreign)==ESTALE&&(flags()&IFF_UP));
    assert(awg_dev_link_delete_marked(name,"wireguard",index,foreign)==ESTALE);
    assert(!awg_dev_link_down_marked(name,"wireguard",index,marker)&&!(flags()&IFF_UP));
    ip("set",name,"alias",foreign);
    assert(awg_dev_link_down_marked(name,"wireguard",index,marker)==ESTALE);
    assert(awg_dev_link_delete_marked(name,"wireguard",index,marker)==ESTALE);
    assert(!awg_dev_link_query_marked(name,kind,sizeof kind,&now,observed,sizeof observed)&&now==index&&!strcmp(observed,foreign));
    int raced=0;assert(awg_dev_link_create_marked(name,"wireguard",1420,marker,&raced)==EEXIST&&!raced);
    assert(!awg_dev_link_delete_marked(name,"wireguard",index,foreign));
    assert(awg_dev_link_query(name,NULL,0,NULL)==ENODEV);
    assert(awg_dev_link_delete_marked(name,"wireguard",index,marker)==ENODEV);
    puts("marked WG netlink: atomic create marker, same-index foreign marker refusal, exclusive collision, idempotent absence PASS");return 0;
}
