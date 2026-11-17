#define _GNU_SOURCE
#include "fakeip.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define FAKE4_BASE 0xc6120000u
struct fakeip_pair { uint32_t fake, real; unsigned char real6[16]; int has6; };
struct fakeip_service {
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    pthread_t thread;
    int stop, demand;
    char *path;
    struct fakeip_pair *pairs;
    size_t count;
};
static int pair_compare(const void *a, const void *b) {
    uint32_t x=((const struct fakeip_pair *)a)->fake, y=((const struct fakeip_pair *)b)->fake;
    return x<y?-1:x>y;
}
/* Runs before workers start or on the single refresh thread. Allocation and IO
 * never hold the snapshot lock. A failed/truncated refresh retains old state. */
static void snapshot_refresh(struct fakeip_service *s) {
    int fd=open(s->path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return;
    struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||
       (uint64_t)st.st_size>FAKEIP_FILE_MAX){close(fd);return;}
    FILE *f=fdopen(fd,"r");
    if(!f){close(fd);return;}
    size_t count=0, capacity=256, bytes=0;
    struct fakeip_pair *pairs=malloc(capacity*sizeof(*pairs));
    char line[512]; int valid=pairs!=NULL;
    while(valid&&fgets(line,sizeof(line),f)) {
        size_t length=strlen(line);
        if(length>FAKEIP_FILE_MAX-bytes){valid=0;break;}
        bytes+=length;
        if(!strchr(line,'\n')&&!feof(f)){valid=0;break;}
        char *fake=strchr(line,'\t'); if(!fake)continue; fake++;
        char *real=strchr(fake,'\t'); if(!real)continue; *real++=0;
        char *end=strpbrk(real,"\t\n"), *real6=NULL;
        if(end){if(*end=='\t')real6=end+1;*end=0;}
        if(real6){end=strpbrk(real6,"\t\r\n");if(end)*end=0;}
        else {end=strchr(real,'\r');if(end)*end=0;}
        struct in_addr address;
        struct fakeip_pair p={0};
        if(inet_pton(AF_INET,fake,&address)!=1)continue;
        p.fake=ntohl(address.s_addr);
        if(p.fake-FAKE4_BASE>=FAKEIP_ENTRY_MAX)continue;
        if(inet_pton(AF_INET,real,&address)==1)p.real=address.s_addr;
        if(real6&&inet_pton(AF_INET6,real6,p.real6)==1)p.has6=1;
        if(!p.real&&!p.has6)continue;
        if(count==FAKEIP_ENTRY_MAX){valid=0;break;}
        if(count==capacity){
            size_t next=capacity*2;
            if(next>FAKEIP_ENTRY_MAX)next=FAKEIP_ENTRY_MAX;
            struct fakeip_pair *grown=realloc(pairs,next*sizeof(*pairs));
            if(!grown){valid=0;break;} pairs=grown;capacity=next;
        }
        pairs[count++]=p;
    }
    if(ferror(f))valid=0;
    fclose(f);
    if(!valid){free(pairs);return;}
    qsort(pairs,count,sizeof(*pairs),pair_compare);
    for(size_t i=1;i<count;i++)if(pairs[i-1].fake==pairs[i].fake){free(pairs);return;}
    pthread_mutex_lock(&s->mutex);
    struct fakeip_pair *old=s->pairs;
    s->pairs=pairs;s->count=count;
    pthread_mutex_unlock(&s->mutex);
    /* Readers finish their bounded bsearch/copy under the same mutex. Thus no
     * retired-snapshot list grows under slow readers. At most two maps exist. */
    free(old);
}
static void *snapshot_thread(void *arg) {
    struct fakeip_service *s=arg;
    pthread_mutex_lock(&s->mutex);
    while(!s->stop){
        if(!s->demand){
            struct timespec until;clock_gettime(CLOCK_MONOTONIC,&until);until.tv_sec++;
            pthread_cond_timedwait(&s->wake,&s->mutex,&until);
        }
        if(s->stop)break;
        s->demand=0;
        pthread_mutex_unlock(&s->mutex);snapshot_refresh(s);pthread_mutex_lock(&s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);return NULL;
}
struct fakeip_service *fakeip_service_create(const char *path) {
    if(!path||!*path)return NULL;
    struct fakeip_service *s=calloc(1,sizeof(*s));if(!s)return NULL;
    s->path=strdup(path);if(!s->path){free(s);return NULL;}
    if(pthread_mutex_init(&s->mutex,NULL)){free(s->path);free(s);return NULL;}
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);pthread_condattr_setclock(&attr,CLOCK_MONOTONIC);
    int rc=pthread_cond_init(&s->wake,&attr);pthread_condattr_destroy(&attr);
    if(rc){pthread_mutex_destroy(&s->mutex);free(s->path);free(s);return NULL;}
    snapshot_refresh(s);
    if(pthread_create(&s->thread,NULL,snapshot_thread,s)){
        free(s->pairs);pthread_cond_destroy(&s->wake);pthread_mutex_destroy(&s->mutex);
        free(s->path);free(s);return NULL;
    }
    return s;
}
void fakeip_service_destroy(struct fakeip_service *s) {
    if(!s)return;
    pthread_mutex_lock(&s->mutex);s->stop=1;pthread_cond_signal(&s->wake);pthread_mutex_unlock(&s->mutex);
    pthread_join(s->thread,NULL);
    free(s->pairs);free(s->path);pthread_cond_destroy(&s->wake);pthread_mutex_destroy(&s->mutex);free(s);
}
static void snapshot_demand(struct fakeip_service *s) {
    pthread_mutex_lock(&s->mutex);s->demand=1;pthread_cond_signal(&s->wake);pthread_mutex_unlock(&s->mutex);
}
static int snapshot_lookup(struct fakeip_service *s,struct flow_key *key) {
    struct fakeip_pair search={0};
    uint32_t address=key->dst;
    if(key->v6)memcpy(&address,key->dst6+12,4);
    search.fake=ntohl(address);
    int found=0;
    pthread_mutex_lock(&s->mutex);
    const struct fakeip_pair *hit=s->count?bsearch(&search,s->pairs,s->count,sizeof(*s->pairs),pair_compare):NULL;
    if(hit){
        if(key->v6&&hit->has6){memcpy(key->dst6,hit->real6,16);found=1;}
        else if(!key->v6&&hit->real){key->dst=hit->real;found=1;}
    }
    pthread_mutex_unlock(&s->mutex);return found;
}

struct admission {
    int fd, sent, kernel_done;
    uint32_t sequence;
    uint64_t deadline;
    struct flow_key key;
};
struct fakeip_worker {
    struct fakeip_service *service;
    int socket;
    uint32_t port, sequence;
    char table[128];
    fakeip_complete_fn complete;
    void *context;
    struct admission pending[FAKEIP_PENDING_MAX];
};
static size_t attr_put(unsigned char *buf,size_t *n,unsigned type,const void *p,size_t length) {
    size_t at=*n;
    struct nlattr *a=(void *)(buf+at);a->nla_type=(uint16_t)type;a->nla_len=(uint16_t)(NLA_HDRLEN+length);
    if(length)memcpy(buf+at+NLA_HDRLEN,p,length);
    *n=at+NLA_ALIGN(NLA_HDRLEN+length);return at;
}
static void attr_end(unsigned char *buf,size_t n,size_t start) { ((struct nlattr *)(void *)(buf+start))->nla_len=(uint16_t)(n-start); }
static int query_send(struct fakeip_worker *w,struct admission *a) {
    if(w->socket<0){a->kernel_done=1;return -1;}
    _Alignas(8) unsigned char buf[512]={0};
    struct nlmsghdr *h=(void *)buf;
    struct nfgenmsg *nf=(void *)(buf+NLMSG_HDRLEN);
    size_t n=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(*nf));
    const char *set=a->key.v6?"fakeip6":"fakeip";
    attr_put(buf,&n,NFTA_SET_ELEM_LIST_TABLE,w->table,strlen(w->table)+1);
    attr_put(buf,&n,NFTA_SET_ELEM_LIST_SET,set,strlen(set)+1);
    size_t list=attr_put(buf,&n,NFTA_SET_ELEM_LIST_ELEMENTS|NLA_F_NESTED,NULL,0);
    size_t elem=attr_put(buf,&n,NFTA_LIST_ELEM|NLA_F_NESTED,NULL,0);
    size_t key=attr_put(buf,&n,NFTA_SET_ELEM_KEY|NLA_F_NESTED,NULL,0);
    attr_put(buf,&n,NFTA_DATA_VALUE,a->key.v6?(const void *)a->key.dst6:(const void *)&a->key.dst,a->key.v6?16:4);
    attr_end(buf,n,key);attr_end(buf,n,elem);attr_end(buf,n,list);
    h->nlmsg_len=(uint32_t)n;h->nlmsg_type=(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETSETELEM;
    h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK;h->nlmsg_seq=a->sequence;
    nf->nfgen_family=NFPROTO_INET;nf->version=NFNETLINK_V0;
    struct sockaddr_nl destination={.nl_family=AF_NETLINK};
    ssize_t sent=sendto(w->socket,buf,n,MSG_DONTWAIT,(struct sockaddr *)&destination,sizeof(destination));
    if(sent==(ssize_t)n){a->sent=1;return 0;}
    if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 1;
    a->kernel_done=1;return -1;
}
static void admission_finish(struct fakeip_worker *w,struct admission *a,int found) {
    int fd=a->fd;
    struct flow_key key=a->key;
    a->fd=-1; /* Detach before callback; callback may submit another admission. */
    w->complete(w->context,fd,&key,found);
}
struct fakeip_worker *fakeip_worker_create(struct fakeip_service *service,const char *table,
                                         fakeip_complete_fn complete,void *context) {
    if(!service||!table||!*table||strlen(table)>=128||!complete)return NULL;
    struct fakeip_worker *w=calloc(1,sizeof(*w));if(!w)return NULL;
    w->service=service;w->complete=complete;w->context=context;strcpy(w->table,table);
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)w->pending[i].fd=-1;
    w->socket=socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_NETFILTER);
    struct sockaddr_nl address={.nl_family=AF_NETLINK};
    socklen_t length=sizeof(address);
    if(w->socket>=0&&(bind(w->socket,(struct sockaddr *)&address,sizeof(address))||
       getsockname(w->socket,(struct sockaddr *)&address,&length))){close(w->socket);w->socket=-1;}
    if(w->socket>=0)w->port=address.nl_pid;
    return w; /* No netlink privilege/socket: bounded cached fallback remains. */
}
void fakeip_worker_destroy(struct fakeip_worker *w) {
    if(!w)return;
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)if(w->pending[i].fd>=0)close(w->pending[i].fd);
    if(w->socket>=0)close(w->socket);
    free(w);
}
int fakeip_worker_fd(const struct fakeip_worker *w) {return w?w->socket:-1;}
int fakeip_worker_submit(struct fakeip_worker *w,int fd,const struct flow_key *key,uint64_t accepted) {
    if(!w||fd<0||!key||accepted>UINT64_MAX-FAKEIP_LOOKUP_MS*1000000ull)return -1;
    struct admission *a=NULL;
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)if(w->pending[i].fd<0){a=&w->pending[i];break;}
    if(!a)return -1;
    uint32_t sequence;
    for(;;){
        sequence=++w->sequence;if(!sequence)continue;
        unsigned i;
        for(i=0;i<FAKEIP_PENDING_MAX;i++)if(w->pending[i].fd>=0&&w->pending[i].sequence==sequence)break;
        if(i==FAKEIP_PENDING_MAX)break;
    }
    *a=(struct admission){.fd=fd,.sequence=sequence,.deadline=accepted+FAKEIP_LOOKUP_MS*1000000ull,.key=*key};
    snapshot_demand(w->service);
    query_send(w,a);
    return 0;
}

/* A malformed or duplicate critical attribute is never treated as a mapping. */
static const struct nlattr *attr_find(const void *data,size_t length,unsigned wanted) {
    const unsigned char *p=data;const struct nlattr *found=NULL;
    while(length){
        if(length<NLA_HDRLEN)return NULL;
        const struct nlattr *a=(const void *)p;
        size_t n=a->nla_len,step=NLA_ALIGN(n);
        if(n<NLA_HDRLEN||n>length||step>length)return NULL;
        if((a->nla_type&NLA_TYPE_MASK)==wanted){if(found)return NULL;found=a;}
        p+=step;length-=step;
    }
    return found;
}
#define ATTR_DATA(a) ((const unsigned char *)(a)+NLA_HDRLEN)
#define ATTR_LENGTH(a) ((size_t)(a)->nla_len-NLA_HDRLEN)
static const struct nlattr *attr_child(const struct nlattr *a,unsigned wanted) {
    return a?attr_find(ATTR_DATA(a),ATTR_LENGTH(a),wanted):NULL;
}
void fakeip_worker_receive(struct fakeip_worker *w,const void *data,size_t length,uint32_t sender,
                           unsigned flags,uint64_t now) {
    if(!w||sender||(flags&(MSG_TRUNC|MSG_CTRUNC)))return;
    const unsigned char *p=data;
    while(length>=NLMSG_HDRLEN){
        const struct nlmsghdr *h=(const void *)p;
        size_t n=h->nlmsg_len,step=NLMSG_ALIGN(n);
        if(n<NLMSG_HDRLEN||n>length||step>length)return;
        struct admission *a=NULL;
        for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)
            if(w->pending[i].fd>=0&&w->pending[i].sequence==h->nlmsg_seq){a=&w->pending[i];break;}
        if(a&&now<=a->deadline&&(h->nlmsg_pid==0||h->nlmsg_pid==w->port)){
            if(h->nlmsg_type==NLMSG_ERROR&&n>=NLMSG_HDRLEN+sizeof(struct nlmsgerr))a->kernel_done=1;
            else if(h->nlmsg_type==NLMSG_DONE)a->kernel_done=1;
            else if(h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWSETELEM)&&
                    !(h->nlmsg_flags&NLM_F_DUMP_INTR)&&n>=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(struct nfgenmsg))){
                const struct nfgenmsg *nf=(const void *)(p+NLMSG_HDRLEN);
                size_t prefix=NLMSG_HDRLEN+NLMSG_ALIGN(sizeof(*nf));
                const struct nlattr *list=attr_find(p+prefix,n-prefix,NFTA_SET_ELEM_LIST_ELEMENTS);
                const struct nlattr *element=attr_child(list,NFTA_LIST_ELEM);
                const struct nlattr *key=attr_child(attr_child(element,NFTA_SET_ELEM_KEY),NFTA_DATA_VALUE);
                const struct nlattr *value=attr_child(attr_child(element,NFTA_SET_ELEM_DATA),NFTA_DATA_VALUE);
                size_t bytes=a->key.v6?16:4;
                const void *expected=a->key.v6?(const void *)a->key.dst6:(const void *)&a->key.dst;
                if(nf->nfgen_family==NFPROTO_INET&&nf->version==NFNETLINK_V0&&key&&value&&ATTR_LENGTH(key)==bytes&&
                   ATTR_LENGTH(value)==bytes&&!memcmp(ATTR_DATA(key),expected,bytes)){
                    if(a->key.v6)memcpy(a->key.dst6,ATTR_DATA(value),bytes);
                    else memcpy(&a->key.dst,ATTR_DATA(value),bytes);
                    admission_finish(w,a,1);
                }
            }
        }
        p+=step;length-=step;
    }
}
void fakeip_worker_pump(struct fakeip_worker *w,uint64_t now) {
    if(!w)return;
    for(unsigned i=0;w->socket>=0&&i<64;i++){
        _Alignas(8) unsigned char buffer[4096];
        struct sockaddr_nl source={0};
        struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};
        struct msghdr message={.msg_name=&source,.msg_namelen=sizeof(source),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t n=recvmsg(w->socket,&message,MSG_DONTWAIT);
        if(n<0){if(errno==EINTR)continue;break;}
        if(message.msg_namelen==sizeof(source)&&source.nl_family==AF_NETLINK&&!source.nl_groups)
            fakeip_worker_receive(w,buffer,(size_t)n,source.nl_pid,(unsigned)message.msg_flags,now);
    }
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++){
        struct admission *a=&w->pending[i];if(a->fd<0)continue;
        if(!a->sent&&!a->kernel_done&&now<a->deadline)query_send(w,a);
        if(a->kernel_done||now>=a->deadline){
            struct flow_key resolved=a->key;
            if(snapshot_lookup(w->service,&resolved)){a->key=resolved;admission_finish(w,a,1);}
            else if(now>=a->deadline)admission_finish(w,a,0);
        }
    }
}
int fakeip_worker_wait(const struct fakeip_worker *w,uint64_t now) {
    int wait=-1;if(!w)return wait;
    for(unsigned i=0;i<FAKEIP_PENDING_MAX;i++)if(w->pending[i].fd>=0){
        uint64_t deadline=w->pending[i].deadline;
        int ms=deadline<=now?0:(int)((deadline-now+999999)/1000000);
        if(ms>10)ms=10;
        if(wait<0||ms<wait)wait=ms;
    }
    return wait;
}
