#define _GNU_SOURCE
#include "fakeip.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int calls, found;
static struct flow_key result;
static void complete(void *context,int fd,const struct flow_key *key,int ok) {
    assert(context==&calls);calls++;found=ok;result=*key;close(fd);
}
static uint64_t clock_ns(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
}
static struct flow_key key4(const char *ip) {
    struct flow_key key={.proto=6,.sport=1234,.dport=443};
    assert(inet_pton(AF_INET,ip,&key.dst)==1);return key;
}
static int owned_fd(void) {int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(fd>=0);return fd;}
static size_t attr(unsigned char *p,size_t *length,unsigned type,const void *value,size_t n) {
    size_t start=*length;
    struct nlattr *a=(void *)(p+start);a->nla_type=(uint16_t)type;a->nla_len=(uint16_t)(NLA_HDRLEN+n);
    if(n)memcpy(p+start+NLA_HDRLEN,value,n);
    *length+=NLA_ALIGN(NLA_HDRLEN+n);return start;
}
static void finish_attr(unsigned char *p,size_t start,size_t length) {((struct nlattr *)(void *)(p+start))->nla_len=(uint16_t)(length-start);}
static size_t reply(unsigned char *p,uint32_t seq,const struct flow_key *key,const char *real) {
    memset(p,0,512);
    struct nlmsghdr *h=(void *)p;
    struct nfgenmsg *nf=(void *)(p+NLMSG_HDRLEN);
    nf->nfgen_family=NFPROTO_INET;
    size_t n=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(*nf));
    size_t list=attr(p,&n,NFTA_SET_ELEM_LIST_ELEMENTS|NLA_F_NESTED,NULL,0);
    size_t element=attr(p,&n,NFTA_LIST_ELEM|NLA_F_NESTED,NULL,0);
    size_t k=attr(p,&n,NFTA_SET_ELEM_KEY|NLA_F_NESTED,NULL,0);
    attr(p,&n,NFTA_DATA_VALUE,&key->dst,4);finish_attr(p,k,n);
    size_t v=attr(p,&n,NFTA_SET_ELEM_DATA|NLA_F_NESTED,NULL,0);
    uint32_t address;assert(inet_pton(AF_INET,real,&address)==1);
    attr(p,&n,NFTA_DATA_VALUE,&address,4);finish_attr(p,v,n);
    finish_attr(p,element,n);finish_attr(p,list,n);
    h->nlmsg_len=(uint32_t)n;h->nlmsg_seq=seq;
    h->nlmsg_type=(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWSETELEM;
    return n;
}
int main(void) {
    char path[]="/tmp/steer-fakeip-test.XXXXXX";
    int file=mkstemp(path);assert(file>=0);
    const char initial[]="test.invalid\t198.18.0.1\t203.0.113.1\t2001:db8::1\n";
    assert(write(file,initial,sizeof(initial)-1)==sizeof(initial)-1);close(file);
    struct fakeip_service *service=fakeip_service_create(path);assert(service);
    struct fakeip_worker *worker=fakeip_worker_create(service,"steer_admission_test_absent",complete,&calls);assert(worker);
    _Alignas(8) unsigned char packet[512];
    struct flow_key key=key4("198.18.0.99");
    uint64_t now=clock_ns();int fd=owned_fd();
    assert(!fakeip_worker_submit(worker,fd,&key,now));
    size_t n=reply(packet,1,&key,"203.0.113.99");
    fakeip_worker_receive(worker,packet,n,123,0,now);assert(!calls);
    fakeip_worker_receive(worker,packet,n,0,MSG_TRUNC,now);assert(!calls);
    fakeip_worker_receive(worker,packet,n-1,0,0,now);assert(!calls);
    ((struct nlmsghdr *)(void *)packet)->nlmsg_seq=2;
    fakeip_worker_receive(worker,packet,n,0,0,now);assert(!calls);
    ((struct nlmsghdr *)(void *)packet)->nlmsg_seq=1;
    fakeip_worker_receive(worker,packet,n,0,0,now);
    assert(calls==1&&found&&result.dst==key4("203.0.113.99").dst);
    assert(fcntl(fd,F_GETFD)<0&&errno==EBADF);
    fakeip_worker_receive(worker,packet,n,0,0,now);assert(calls==1);
    puts("PASS kernel reply sender/truncation/sequence validation and exactly-once fd transfer");

    calls=0;fd=owned_fd();assert(!fakeip_worker_submit(worker,fd,&key,now));
    fakeip_worker_pump(worker,now+199000000ull);assert(!calls);
    /* Deadline starts at acceptance; retransmission and refresh never extend it. */
    fakeip_worker_pump(worker,now+200000000ull);
    assert(calls==1&&!found&&fcntl(fd,F_GETFD)<0);
    fakeip_worker_pump(worker,now+500000000ull);assert(calls==1);
    puts("PASS missing mapping has bounded original deadline and no duplicate completion");

    calls=0;key=key4("198.18.0.1");now=clock_ns();fd=owned_fd();
    assert(!fakeip_worker_submit(worker,fd,&key,now));
    fakeip_worker_pump(worker,now+200000000ull);
    assert(calls==1&&found&&result.dst==key4("203.0.113.1").dst);
    puts("PASS immutable file fallback after unavailable kernel lookup");

    /* Demand refresh can publish a newly written mapping within this same
     * admission's original budget; no filesystem operation occurs in pump. */
    file=open(path,O_WRONLY|O_TRUNC);assert(file>=0);
    const char changed[]="new.invalid\t198.18.0.2\t203.0.113.2\n";
    assert(write(file,changed,sizeof(changed)-1)==sizeof(changed)-1);close(file);
    calls=0;key=key4("198.18.0.2");now=clock_ns();fd=owned_fd();
    assert(!fakeip_worker_submit(worker,fd,&key,now));
    while(!calls&&clock_ns()-now<210000000ull){fakeip_worker_pump(worker,clock_ns());usleep(1000);}
    assert(calls==1&&found&&result.dst==key4("203.0.113.2").dst);
    puts("PASS demand refresh resolves new file mapping within unchanged admission deadline");

    int retained[FAKEIP_PENDING_MAX];key=key4("198.18.0.99");now=clock_ns();calls=0;
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++){
        retained[i]=owned_fd();assert(!fakeip_worker_submit(worker,retained[i],&key,now));
    }
    fd=owned_fd();assert(fakeip_worker_submit(worker,fd,&key,now)<0);
    assert(fcntl(fd,F_GETFD)>=0);close(fd);
    fakeip_worker_destroy(worker);assert(!calls);
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)assert(fcntl(retained[i],F_GETFD)<0);
    fakeip_service_destroy(service);unlink(path);
    puts("PASS fixed admission bound, rejected ownership and cancellation before service join");
    return 0;
}
