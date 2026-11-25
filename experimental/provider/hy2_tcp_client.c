/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "hy2_tcp_client.h"
#include "hy2wire.h"
#include "quic.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define WINDOW (64u * 1024u)
#define CA_MAX (1024u * 1024u)
#define MAX_FLOWS 16u
#define PASSWORD_MAX 256u
#define NAME_MAX_BYTES 254u

struct steer_hy2_profile {
    uint64_t generation;
    struct qc_tls *tls;
    char upstream[INET6_ADDRSTRLEN], name[NAME_MAX_BYTES + 1], password[PASSWORD_MAX + 1];
    uint16_t port;
    unsigned live, retired;
};

enum stage { TLS, AUTH_START, AUTH_RESPONSE, REQUEST, RESPONSE, PAYLOAD };
struct steer_hy2_tcp {
    struct steer_hy2_profile *profile;
    struct qc *quic;
    uint64_t deadline;
    enum stage stage;
    enum steer_hy2_state state;
    int64_t auth_sid, sid, control_sid;
    int rx_fin, tx_fin;
    char target[NAME_MAX_BYTES + 1];
    uint16_t port;
    struct hy2_tcp_response_stream response;
    size_t auth_len, head, used;
    uint8_t auth[8192], rx[WINDOW];
};

static int numeric(const char *s, uint8_t ip[16]) {
    if (inet_pton(AF_INET,s,ip)==1) return AF_INET;
    return inet_pton(AF_INET6,s,ip)==1 ? AF_INET6 : 0;
}
static int peer_address(const char *s) {
    uint8_t ip[16];
    int family=numeric(s,ip);
    if(family==AF_INET) return ip[0]>0&&ip[0]<224;
    if(family!=AF_INET6) return 0;
    struct in6_addr ipv6;
    memcpy(&ipv6,ip,sizeof ipv6);
    return !IN6_IS_ADDR_UNSPECIFIED(&ipv6)&&!IN6_IS_ADDR_MULTICAST(&ipv6)&&
        !IN6_IS_ADDR_LINKLOCAL(&ipv6)&&!IN6_IS_ADDR_V4MAPPED(&ipv6);
}
static int name(const char *s,int absolute) {
    if(!s) return 0;
    size_t n=strnlen(s,NAME_MAX_BYTES+1),label=0;
    if(!n||n>NAME_MAX_BYTES) return 0;
    uint8_t ip[16];
    if(numeric(s,ip)) return 1;
    if(absolute&&s[n-1]=='.') n--;
    if(!n||n>253) return 0;
    for(size_t i=0;i<n;i++) {
        unsigned c=(unsigned char)s[i];
        if(c=='.') {
            if(!label||s[i-1]=='-') return 0;
            label=0;
        } else {
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')||
               (!label&&c=='-')||++label>63) return 0;
        }
    }
    return label&&s[n-1]!='-';
}

static struct qc_tls *load_ca(const char *path) {
    struct qc_tls *tls=NULL;
    uint8_t *data=NULL,extra;
    struct stat st;
    size_t done=0;
    if(!path||!*path||strnlen(path,PATH_MAX)>=PATH_MAX) return NULL;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
    if(fd<0) return NULL;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>CA_MAX) goto end;
    size_t length=(size_t)st.st_size;
    data=malloc(length);
    if(!data) goto end;
    while(done<length) {
        ssize_t n=read(fd,data+done,length-done);
        if(n<0&&errno==EINTR) continue;
        if(n<=0) goto end;
        done+=(size_t)n;
    }
    ssize_t n;
    do { n=read(fd,&extra,1); } while(n<0&&errno==EINTR);
    if(n==0) tls=qc_tls_new(0,data,length,NULL);
end:
    free(data);
    close(fd);
    return tls;
}

int steer_hy2_profile_prepare(uint64_t generation,const char *upstream,uint16_t port,
    const char *tls_name,const char *ca_path,const char *password,struct steer_hy2_profile **out) {
    if(!out) return -1;
    *out=NULL;
    if(!generation||!upstream||strnlen(upstream,INET6_ADDRSTRLEN)>=INET6_ADDRSTRLEN||
       !peer_address(upstream)||!port||!name(tls_name,0)||!password) return -1;
    size_t n=strnlen(password,PASSWORD_MAX+1);
    if(!n||n>PASSWORD_MAX) return -1;
    for(size_t i=0;i<n;i++) if((unsigned char)password[i]<0x21||(unsigned char)password[i]>0x7e) return -1;
    /* A successful nonblocking entropy check establishes CRNG readiness before
     * handing off to qc/wolfSSL's regular getrandom calls on the owner. */
    uint8_t ready;
    if(getrandom(&ready,1,GRND_NONBLOCK)!=1) return -1;
    struct steer_hy2_profile *p=calloc(1,sizeof *p);
    if(!p) return -1;
    p->tls=load_ca(ca_path);
    if(!p->tls) { free(p);return -1; }
    strcpy(p->upstream,upstream);
    strcpy(p->name,tls_name);
    memcpy(p->password,password,n+1);
    p->port=port;
    p->generation=generation;
    *out=p;
    return 0;
}

void steer_hy2_profile_retire(struct steer_hy2_profile *p) {
    if(p) p->retired=1;
}
int steer_hy2_profile_destroy(struct steer_hy2_profile *p) {
    if(!p) return 0;
    if(p->live) return -1;
    qc_tls_free(p->tls);
    explicit_bzero(p->password,sizeof p->password);
    free(p);
    return 0;
}

static void fail(struct steer_hy2_tcp *f,enum steer_hy2_state state) {
    if(f->state<=STEER_HY2_READY) {
        f->state=state;
        f->used=0;
    }
}

static void handshake(void *user) {
    struct steer_hy2_tcp *f=user;
    if(f->state==STEER_HY2_OPENING) f->stage=AUTH_START;
}
static void connection_closed(void *user,int reason,const char *why) {
    struct steer_hy2_tcp *f=user;
    (void)reason;
    (void)why;
    fail(f,STEER_HY2_UNAVAILABLE);
}
static void stream_closed(void *user,int64_t sid,uint64_t error) {
    struct steer_hy2_tcp *f=user;
    if(f->state==STEER_HY2_OPENING&&sid==f->auth_sid&&f->stage==AUTH_RESPONSE)
        fail(f,STEER_HY2_REJECTED);
    if(sid!=f->sid||f->state>STEER_HY2_READY) return;
    if(error||qc_stream_terminal_flags(f->quic,sid)!=QC_STREAM_TERMINAL_AVAILABLE||
       f->stage!=PAYLOAD||!f->rx_fin||!f->tx_fin) fail(f,STEER_HY2_UNAVAILABLE);
    else f->state=STEER_HY2_FINISHED;
}
static void stream_data(void *user,int64_t sid,const uint8_t *d,size_t n,int fin) {
    struct steer_hy2_tcp *f=user;
    if(f->state>STEER_HY2_READY) return;
    if(f->stage==AUTH_RESPONSE&&sid==f->auth_sid) {
        struct hy2_auth_resp r;
        if(n>sizeof f->auth-f->auth_len) { fail(f,STEER_HY2_REJECTED);return; }
        if(n) memcpy(f->auth+f->auth_len,d,n);
        f->auth_len+=n;
        qc_stream_consumed(f->quic,sid,n);
        int result=hy2_auth_response_strict(f->auth,f->auth_len,&r,NULL);
        if(result==1&&r.status==HY2_AUTH_OK) f->stage=REQUEST;
        else if(result||fin||f->auth_len==sizeof f->auth) fail(f,STEER_HY2_REJECTED);
        return;
    }
    if(sid!=f->sid) { qc_stream_consumed(f->quic,sid,n);return; }
    if(f->stage==RESPONSE) {
        size_t consumed=0;
        struct hy2_tcp_resp response;
        int result=hy2_tcp_response_feed(&f->response,d,n,&consumed,&response);
        if(result<0||(result==0&&fin)||(result>0&&!response.ok)) {
            fail(f,STEER_HY2_REJECTED);return;
        }
        qc_stream_consumed(f->quic,sid,consumed);
        if(!result) return;
        f->stage=PAYLOAD;
        f->state=STEER_HY2_READY;
        if(consumed) d+=consumed;
        n-=consumed;
    }
    if(f->stage!=PAYLOAD||n>WINDOW-f->used) { fail(f,STEER_HY2_UNAVAILABLE);return; }
    if(n) {
        size_t tail=(f->head+f->used)%WINDOW,first=WINDOW-tail;
        if(first>n) first=n;
        memcpy(f->rx+tail,d,first);
        memcpy(f->rx,d+first,n-first);
        f->used+=n;
    }
    if(fin) f->rx_fin=1;
}
static const struct qc_ops ops={
    .on_handshake=handshake,.on_closed=connection_closed,
    .on_stream_data=stream_data,.on_stream_close=stream_closed
};

/* Initiate only after returning from the transport callbacks. If the peer
 * temporarily has no stream credit, retry after subsequent QUIC events. */
static void advance(struct steer_hy2_tcp *f) {
    if(f->state!=STEER_HY2_OPENING) return;
    uint8_t wire[1400];
    if(f->stage==AUTH_START) {
        int result;
        if(f->control_sid<0) {
            result=qc_stream_open_uni(f->quic,&f->control_sid);
            if(result==QC_EAGAIN) return;
            if(result) goto broken;
            size_t n=hy2_h3_control(wire,sizeof wire);
            if(!n||qc_stream_send(f->quic,f->control_sid,wire,n,0)!=(ssize_t)n) goto broken;
        }
        result=qc_stream_open(f->quic,&f->auth_sid);
        if(result==QC_EAGAIN) return;
        if(result) goto broken;
        size_t n=hy2_auth_request(wire,sizeof wire,f->profile->password,0,64);
        ssize_t accepted=n?qc_stream_send(f->quic,f->auth_sid,wire,n,1):-1;
        explicit_bzero(wire,sizeof wire);
        if(accepted<0||(size_t)accepted!=n) goto broken;
        f->stage=AUTH_RESPONSE;
    } else if(f->stage==REQUEST) {
        int result=qc_stream_open(f->quic,&f->sid);
        if(result==QC_EAGAIN) return;
        if(result) goto broken;
        size_t n=hy2_tcp_request(wire,sizeof wire,f->target,f->port,32);
        if(!n||qc_stream_send(f->quic,f->sid,wire,n,0)!=(ssize_t)n) goto broken;
        f->stage=RESPONSE;
    }
    return;
broken:
    fail(f,STEER_HY2_UNAVAILABLE);
}

int steer_hy2_tcp_open(struct steer_hy2_profile *p,uint64_t generation,const char *target,
    uint16_t port,uint64_t now,uint64_t deadline,struct steer_hy2_tcp **out) {
    if(!out) return -1;
    *out=NULL;
    if(!p||p->generation!=generation||p->retired||p->live>=MAX_FLOWS||
       !name(target,1)||!port||deadline<=now) return -1;
    struct steer_hy2_tcp *f=calloc(1,sizeof *f);
    if(!f) return -1;
    f->profile=p;
    f->deadline=deadline;
    f->port=port;
    strcpy(f->target,target);
    f->sid=f->control_sid=f->auth_sid=-1;
    struct qc_cfg cfg={.host=p->upstream,.port=p->port,.sni=p->name,.alpn="h3",.tls=p->tls,
        .flow_manual=1,.bbr=1,.keepalive_ms=10000,.max_data=2*WINDOW,.max_stream_data=WINDOW,
        .send_buf=WINDOW};
    if(qc_open(&cfg,&ops,f,&f->quic)) { free(f);return -1; }
    p->live++;
    *out=f;
    return 0;
}
int steer_hy2_tcp_fd(const struct steer_hy2_tcp *f) { return qc_fd(f->quic); }
int steer_hy2_tcp_timeout(struct steer_hy2_tcp *f,uint64_t now) {
    if(f->state>STEER_HY2_READY) return -1;
    int timeout=qc_timeout_ms(f->quic);
    if(f->state==STEER_HY2_OPENING) {
        uint64_t left=f->deadline>now?f->deadline-now:0;
        if(timeout<0||left<(uint64_t)timeout) timeout=left>INT_MAX?INT_MAX:(int)left;
    }
    return timeout;
}
void steer_hy2_tcp_drive(struct steer_hy2_tcp *f,uint64_t now,int readable) {
    if(f->state>STEER_HY2_READY) return;
    if(f->state==STEER_HY2_OPENING&&now>=f->deadline) { fail(f,STEER_HY2_TIMEOUT);return; }
    if(readable) (void)qc_on_readable(f->quic);
    if(f->state<=STEER_HY2_READY&&qc_timeout_ms(f->quic)==0) (void)qc_on_timer(f->quic);
    advance(f);
}
enum steer_hy2_state steer_hy2_tcp_state(const struct steer_hy2_tcp *f) { return f->state; }
size_t steer_hy2_tcp_room(const struct steer_hy2_tcp *f) {
    return f->state==STEER_HY2_READY&&!f->tx_fin?qc_stream_room(f->quic,f->sid):0;
}
ssize_t steer_hy2_tcp_read(struct steer_hy2_tcp *f,void *out,size_t cap) {
    if(!out||!cap||f->state>STEER_HY2_FINISHED) return -1;
    if(!f->used) return f->rx_fin?0:-2;
    size_t n=f->used<cap?f->used:cap,first=WINDOW-f->head;
    if(first>n) first=n;
    memcpy(out,f->rx+f->head,first);
    memcpy((uint8_t *)out+first,f->rx,n-first);
    f->head=(f->head+n)%WINDOW;
    f->used-=n;
    if(f->state==STEER_HY2_READY) {
        qc_stream_consumed(f->quic,f->sid,n);
        qc_flush_credit(f->quic);
    }
    return (ssize_t)n;
}
ssize_t steer_hy2_tcp_write(struct steer_hy2_tcp *f,const void *data,size_t n) {
    if(f->state!=STEER_HY2_READY||f->tx_fin||(!data&&n)) return -1;
    ssize_t result=qc_stream_send(f->quic,f->sid,data,n,0);
    if(result<0) fail(f,STEER_HY2_UNAVAILABLE);
    return f->state>STEER_HY2_READY?-1:result;
}
int steer_hy2_tcp_shutdown_write(struct steer_hy2_tcp *f) {
    if(f->state!=STEER_HY2_READY||f->tx_fin) return -1;
    f->tx_fin=1;
    if(qc_stream_send(f->quic,f->sid,NULL,0,1)<0) fail(f,STEER_HY2_UNAVAILABLE);
    return f->state>STEER_HY2_FINISHED?-1:0;
}
void steer_hy2_tcp_destroy(struct steer_hy2_tcp *f) {
    if(!f) return;
    qc_close(f->quic,0);
    qc_free(f->quic);
    f->profile->live--;
    free(f);
}
