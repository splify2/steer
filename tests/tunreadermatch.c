/* Actual legacy reader_loop + SPSC, not redirected TCP listeners. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#ifndef STEER_READER_STACK_SOURCE
#define STEER_READER_STACK_SOURCE "../src/tunnel/stack.c"
#endif
#include STEER_READER_STACK_SOURCE
#define HEALTHY_PACKETS 32u
#define BLOCKED_PACKETS 64u
struct fixture {struct ring_work owners[2];struct tun_dev tun;unsigned received,ordered,expected,blocked_received,blocked_ordered;atomic_uint progress;uint64_t worst_ns;};
static void packet(unsigned char p[44],uint16_t port,uint32_t seq){
    memset(p,0,44);p[0]=0x45;p[3]=44;p[8]=64;p[9]=17;p[12]=10;p[13]=66;p[15]=2;p[16]=10;p[17]=66;p[19]=1;
    p[20]=0x9c;p[21]=0x40;p[22]=(unsigned char)(port>>8);p[23]=(unsigned char)port;p[25]=24;
    uint32_t value=htonl(seq);memcpy(p+28,&value,4);uint64_t stamp=now_ns();memcpy(p+32,&stamp,8);
}
static void *read_packets(void *arg){struct fixture *f=arg;reader_loop(&f->tun,f->owners,2);return NULL;}
static void *consume(void *arg){
    struct fixture *f=arg;uint64_t until=now_ns()+4000000000u;f->ordered=1;
    while(f->received<f->expected&&now_ns()<until){
        uint32_t n;const unsigned char *p=spsc_peek(&f->owners[1].ring,&n);
        if(!p){struct timespec nap={0,1000000};nanosleep(&nap,NULL);continue;}
        if(n!=44||stack_owner(p,n,2)!=1){f->ordered=0;break;}
        uint32_t seq;uint64_t stamp;memcpy(&seq,p+28,4);memcpy(&stamp,p+32,8);
        if(ntohl(seq)!=f->received)f->ordered=0;
        uint64_t lag=now_ns()-stamp;if(lag>f->worst_ns)f->worst_ns=lag;
        f->received++;atomic_store_explicit(&f->progress,f->received,memory_order_release);spsc_pop(&f->owners[1].ring);spsc_room(&f->owners[1].ring);
    }
    return NULL;
}
static void *consume_recovered(void *arg){
    struct fixture *f=arg;uint64_t until=now_ns()+4000000000u;f->blocked_ordered=1;
    while(f->blocked_received<BLOCKED_PACKETS&&now_ns()<until){uint32_t n;const unsigned char *p=spsc_peek(&f->owners[0].ring,&n);
        if(!p){struct timespec nap={0,1000000};nanosleep(&nap,NULL);continue;}
        uint32_t seq;memcpy(&seq,p+28,4);if(n!=44||ntohl(seq)!=RING_SLOTS+BLOCKED_PACKETS+f->blocked_received)f->blocked_ordered=0;
        f->blocked_received++;spsc_pop(&f->owners[0].ring);spsc_room(&f->owners[0].ring);
    }return NULL;
}
static unsigned drain_held(struct fixture *f){
    unsigned retained=0;uint32_t n;const unsigned char *p;
    while((p=spsc_peek(&f->owners[0].ring,&n))){uint32_t seq;memcpy(&seq,p+28,4);assert(n==44&&ntohl(seq)==retained);retained++;spsc_pop(&f->owners[0].ring);}spsc_room(&f->owners[0].ring);return retained;
}
static void ip(char *const argv[]){pid_t child=fork();assert(child>=0);if(!child){execvp("ip",argv);_exit(127);}int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));}
static void kernel_pair(int pair[2]){
    struct stat current,initial;assert(!stat("/proc/thread-self/ns/net",&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_READER_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated network namespace required\n",stderr);exit(2);}
    pair[0]=open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);assert(pair[0]>=0);
    struct ifreq request={0};strcpy(request.ifr_name,"steerrd0");request.ifr_flags=IFF_TUN|IFF_NO_PI;assert(!ioctl(pair[0],TUNSETIFF,&request));
    /* Keep this IPv4 driver fixture free of automatic IPv6 DAD/RS packets.
     * The sysctl is per-interface inside the required disposable namespace. */
    int disable=open("/proc/sys/net/ipv6/conf/steerrd0/disable_ipv6",O_WRONLY|O_CLOEXEC);assert(disable>=0&&write(disable,"1",1)==1&&!close(disable));
    char *address[]={"ip","addr","add","10.66.0.2/24","dev","steerrd0",NULL};ip(address);
    char *up[]={"ip","link","set","dev","steerrd0","up",NULL};ip(up);
    pair[1]=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);assert(pair[1]>=0);
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(40000)};assert(inet_pton(AF_INET,"10.66.0.2",&local.sin_addr)==1);
    assert(!bind(pair[1],(const struct sockaddr *)&local,sizeof local));
}
static void inject(int fd,int kernel,const unsigned char p[44]){
    if(!kernel){assert(send(fd,p,44,0)==44);return;}
    struct sockaddr_in dst={.sin_family=AF_INET};memcpy(&dst.sin_port,p+22,2);memcpy(&dst.sin_addr,p+16,4);
    assert(sendto(fd,p+28,16,0,(const struct sockaddr *)&dst,sizeof dst)==16);
}
static int run_case(int kernel,unsigned scenario){
    struct fixture f={0};f.expected=scenario==2?2*HEALTHY_PACKETS:HEALTHY_PACKETS;int pair[2];if(kernel)kernel_pair(pair);else assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,pair));
    assert(fcntl(pair[0],F_SETFL,O_NONBLOCK)==0);f.tun.fd=pair[0];
    for(unsigned j=0;j<2;j++){assert(!spsc_init(&f.owners[j].ring,RING_SLOTS,RING_SLOT_DATA));pthread_mutex_init(&f.owners[j].mail.mu,NULL);}
    g_rw=f.owners;g_nwork=2;g_stats=0;__atomic_store_n(&g_ring_stop,0,__ATOMIC_RELAXED);
    unsigned char p[44];uint16_t ports[2]={0};
    for(unsigned port=1000;port<65000&&(!ports[0]||!ports[1]);port++){packet(p,(uint16_t)port,0);ports[stack_owner(p,sizeof p,2)]=(uint16_t)port;}
    assert(ports[0]&&ports[1]);
    for(unsigned seq=0;scenario&&seq<RING_SLOTS;seq++){packet(p,ports[0],seq);unsigned char *slot=spsc_reserve(&f.owners[0].ring);assert(slot);memcpy(slot,p,sizeof p);spsc_commit(&f.owners[0].ring,sizeof p);}
    pthread_t reader,healthy;assert(!pthread_create(&reader,NULL,read_packets,&f)&&!pthread_create(&healthy,NULL,consume,&f));
    for(unsigned seq=0;scenario&&seq<BLOCKED_PACKETS;seq++){packet(p,ports[0],RING_SLOTS+seq);inject(pair[1],kernel,p);}
    for(unsigned seq=0;seq<HEALTHY_PACKETS;seq++){packet(p,ports[1],seq);inject(pair[1],kernel,p);if(!scenario){struct timespec pace={0,1000000};nanosleep(&pace,NULL);}}
    unsigned retained=0;pthread_t recovered;int recovery_started=0,barrier_failed=0;
    if(scenario==2){uint64_t until=now_ns()+4000000000u;
        while(atomic_load_explicit(&f.progress,memory_order_acquire)<HEALTHY_PACKETS&&now_ns()<until){struct timespec nap={0,1000000};nanosleep(&nap,NULL);}
        if(atomic_load_explicit(&f.progress,memory_order_acquire)<HEALTHY_PACKETS)barrier_failed=1;
        else {retained=drain_held(&f);assert(!pthread_create(&recovered,NULL,consume_recovered,&f));recovery_started=1;
            for(unsigned seq=0;seq<BLOCKED_PACKETS;seq++){packet(p,ports[0],RING_SLOTS+BLOCKED_PACKETS+seq);inject(pair[1],kernel,p);
                if(seq<HEALTHY_PACKETS){packet(p,ports[1],HEALTHY_PACKETS+seq);inject(pair[1],kernel,p);}}
        }
    }
    assert(!pthread_join(healthy,NULL));if(recovery_started)assert(!pthread_join(recovered,NULL));
    __atomic_store_n(&g_ring_stop,1,__ATOMIC_RELAXED);packet(p,ports[1],f.expected);inject(pair[1],kernel,p);assert(!pthread_join(reader,NULL));
    if(scenario!=2||barrier_failed)retained=drain_held(&f);
    printf("reader isolation kernelTUN=%d scenario=%u: healthy=%u/%u ordered=%u worst_ms=%.3f blocked_drops=%llu retained=%u recovered=%u/%u recovered_ordered=%u ring_bytes=%zu\n",kernel,scenario,f.received,f.expected,f.ordered,(double)f.worst_ns/1e6,f.owners[0].rd_full,retained,f.blocked_received,scenario==2?BLOCKED_PACKETS:0,f.blocked_ordered,2*SPSC_BYTES(RING_SLOTS,RING_SLOT_DATA));
    int failed=barrier_failed||f.received!=f.expected||!f.ordered||f.worst_ns>300000000u||retained!=(scenario?RING_SLOTS:0)||f.owners[0].rd_full!=(scenario?BLOCKED_PACKETS:0);
    if(scenario==2&&(f.blocked_received!=BLOCKED_PACKETS||!f.blocked_ordered||f.owners[0].rd_pkts!=BLOCKED_PACKETS))failed=1;
    for(unsigned j=0;j<2;j++){spsc_free(&f.owners[j].ring);pthread_mutex_destroy(&f.owners[j].mail.mu);}close(pair[0]);close(pair[1]);g_rw=NULL;return failed;
}
int main(int argc,char **argv){
    int kernel=argc==2&&!strcmp(argv[1],"--tun"),failed=0;
    for(unsigned scenario=0;scenario<3;scenario++)failed|=run_case(kernel,scenario);
    return failed;
}
