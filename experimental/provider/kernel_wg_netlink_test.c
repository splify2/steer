#define _GNU_SOURCE
#include "awgdev.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
static int late_callback;
static int active,late_poll,late_recv,interrupt_poll,truncated,wrong_sender,fail_allocation;
static unsigned sent,received,calls,wiped,count,next;
static uint64_t now=1000000000ULL;
static uint8_t messages[4][512];static size_t lengths[4];static void *scratch;
#ifndef STEER_NETLINK_TEST_EXCHANGE
#define STEER_NETLINK_TEST_EXCHANGE steer_awg_netlink_test_exchange
#endif
extern int STEER_NETLINK_TEST_EXCHANGE(int,void *,size_t,void (*)(const struct nlmsghdr *,void *),void *,uint64_t);
void *__real_malloc(size_t);void __real_free(void *);
void *__wrap_malloc(size_t n){if(active&&n==65536){if(fail_allocation)return NULL;scratch=__real_malloc(n);return scratch;}return __real_malloc(n);}
void __wrap_free(void *p){if(active&&p&&p==scratch){for(size_t i=0;i<65536;i++)assert(!((uint8_t *)p)[i]);wiped++;scratch=NULL;}__real_free(p);}
int __real_clock_gettime(clockid_t,struct timespec *);
int __wrap_clock_gettime(clockid_t clock,struct timespec *t){if(active&&clock==CLOCK_MONOTONIC){t->tv_sec=(time_t)(now/1000000000ULL);t->tv_nsec=(long)(now%1000000000ULL);return 0;}return __real_clock_gettime(clock,t);}
int __real_poll(struct pollfd *,nfds_t,int);
int __wrap_poll(struct pollfd *p,nfds_t n,int timeout){
 if(!active||n!=1||p->fd!=77)return __real_poll(p,n,timeout);
 if(interrupt_poll){now+=1000000000ULL;errno=EINTR;return -1;}
 if(late_poll)now+=3000000000ULL;
 if(next==count){now+=3000000000ULL;return 0;}
 p->revents=p->events;return 1;
}
int __real___poll_chk(struct pollfd *,nfds_t,int,size_t);
int __wrap___poll_chk(struct pollfd *p,nfds_t n,int timeout,size_t bytes){
 if(active&&n==1&&p->fd==77){assert(bytes>=sizeof *p);return __wrap_poll(p,n,timeout);}
 return __real___poll_chk(p,n,timeout,bytes);
}
ssize_t __real_sendto(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
ssize_t __wrap_sendto(int fd,const void *p,size_t n,int flags,const struct sockaddr *address,socklen_t size){
 if(!active||fd!=77)return __real_sendto(fd,p,n,flags,address,size);
 assert(scratch);sent++;return (ssize_t)n;
}
ssize_t __real_recvmsg(int,struct msghdr *,int);
ssize_t __wrap_recvmsg(int fd,struct msghdr *msg,int flags){
 if(!active||fd!=77)return __real_recvmsg(fd,msg,flags);
 assert(next<count&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==65536);received++;
 memset(msg->msg_iov[0].iov_base,0xaf,65536);memcpy(msg->msg_iov[0].iov_base,messages[next],lengths[next]);
 struct sockaddr_nl source={.nl_family=AF_NETLINK,.nl_pid=wrong_sender?123:0};memcpy(msg->msg_name,&source,sizeof source);msg->msg_namelen=sizeof source;
 msg->msg_flags=truncated?MSG_TRUNC:0;if(late_recv)now+=3000000000ULL;
 return (ssize_t)lengths[next++];
}
static void callback(const struct nlmsghdr *message,void *unused){(void)message;(void)unused;calls++;if(late_callback)now+=3000000000ULL;}
static void reset(void){active=0;late_callback=0;late_poll=late_recv=interrupt_poll=truncated=wrong_sender=fail_allocation=0;sent=received=calls=wiped=count=next=0;now=1000000000ULL;scratch=NULL;memset(messages,0,sizeof messages);}
static void append(uint16_t type,uint16_t flags,size_t bytes,int value){
 assert(count<4&&bytes<=sizeof messages[0]-NLMSG_HDRLEN);struct nlmsghdr *h=(void *)messages[count];
 h->nlmsg_type=type;h->nlmsg_flags=flags;h->nlmsg_seq=9;h->nlmsg_len=(uint32_t)NLMSG_LENGTH(bytes);
 if(bytes>=sizeof value)memcpy(NLMSG_DATA(h),&value,sizeof value);
 lengths[count++]=NLMSG_ALIGN(h->nlmsg_len);
}
static int exchange(int dump,uint64_t deadline){
 struct nlmsghdr request={.nlmsg_len=sizeof request,.nlmsg_type=RTM_GETLINK,.nlmsg_flags=(uint16_t)(NLM_F_REQUEST|(dump?NLM_F_DUMP:NLM_F_ACK)),.nlmsg_seq=9};
 active=1;int result=STEER_NETLINK_TEST_EXCHANGE(77,&request,sizeof request,callback,NULL,deadline);active=0;assert(!scratch);return result;
}
int main(void){
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);int first=exchange(0,3000000000ULL);if(first||sent!=1||received!=1||wiped!=1)fprintf(stderr,"first result=%d sent=%u received=%u wiped=%u\n",first,sent,received,wiped);assert(!first&&sent==1&&received==1&&wiped==1);
 reset();append(NLMSG_ERROR,0,3,0);assert(exchange(0,3000000000ULL)==EPROTO&&wiped==1);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),INT_MIN);assert(exchange(0,3000000000ULL)==EPROTO);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),7);assert(exchange(0,3000000000ULL)==EPROTO);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),-EACCES);assert(exchange(0,3000000000ULL)==EACCES);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);assert(exchange(1,3000000000ULL)==ETIMEDOUT&&received==1&&!calls);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);append(RTM_NEWLINK,0,0,0);append(NLMSG_DONE,0,sizeof(int),0);assert(!exchange(1,3000000000ULL)&&received==3&&calls==1);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);append(RTM_NEWLINK,0,0,0);append(NLMSG_DONE,0,sizeof(int),0);memcpy(messages[0]+lengths[0],messages[1],lengths[1]);lengths[0]+=lengths[1];memcpy(messages[0]+lengths[0],messages[2],lengths[2]);lengths[0]+=lengths[2];count=1;assert(!exchange(1,3000000000ULL)&&received==1&&calls==1);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),-EIO);assert(exchange(1,3000000000ULL)==EIO&&received==2&&!calls);
 reset();append(NLMSG_DONE,0,sizeof(int),-EIO);assert(exchange(1,3000000000ULL)==EIO);
 reset();append(NLMSG_DONE,0,1,0);assert(exchange(1,3000000000ULL)==EPROTO);
 reset();append(RTM_NEWLINK,NLM_F_DUMP_INTR,0,0);append(NLMSG_DONE,0,sizeof(int),0);assert(exchange(1,3000000000ULL)==EINTR&&calls==1);
 reset();append(RTM_NEWLINK,NLM_F_DUMP_INTR,0,0);append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);assert(exchange(1,3000000000ULL)==EINTR&&calls==1);
 reset();append(RTM_NEWLINK,0,0,0);append(NLMSG_DONE,0,sizeof(int),0);memcpy(messages[0]+lengths[0],messages[1],lengths[1]);lengths[0]+=lengths[1];count=1;late_callback=1;
 assert(exchange(1,3000000000ULL)==ETIMEDOUT&&calls==1&&received==1&&wiped==1);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);truncated=1;assert(exchange(0,3000000000ULL)==EMSGSIZE);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);late_poll=1;assert(exchange(0,3000000000ULL)==ETIMEDOUT&&!received);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);late_recv=1;assert(exchange(0,3000000000ULL)==ETIMEDOUT&&!calls);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);interrupt_poll=1;assert(exchange(0,3000000000ULL)==ETIMEDOUT&&!received);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);wrong_sender=1;assert(exchange(0,3000000000ULL)==ETIMEDOUT&&!calls);
 reset();append(RTM_NEWLINK,0,0,0);((struct nlmsghdr *)messages[0])->nlmsg_len=100;assert(exchange(0,3000000000ULL)==EPROTO);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);assert(exchange(0,now)==ETIMEDOUT&&!sent&&!wiped);
 reset();append(NLMSG_ERROR,0,sizeof(struct nlmsgerr),0);fail_allocation=1;assert(exchange(0,3000000000ULL)==ENOMEM&&!sent&&!wiped);
 puts("netlink exchange: malformed/error/dump/late poll/EINTR/allocation-before-send/scratch wipe PASS");return 0;
}
