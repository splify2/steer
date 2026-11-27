/* SPDX-License-Identifier: GPL-3.0-only */
#include "table_ack.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int ack_socket;
static uint64_t ack_seq;
enum table_ack_decision table_ack_dispatch_decide(struct table_ack_dispatch *d,
    const struct table_ack_window *w, uint64_t fingerprint, int force) {
    force = force || d->force;
    if (!force && table_ack_window_matches(w, fingerprint)) return TABLE_ACK_NOOP;
    if (!table_ack_window_ready(w)) {
        d->pending = 1;
        d->force = force;
        return TABLE_ACK_DEFER;
    }
    return TABLE_ACK_SEND;
}
void table_ack_dispatch_done(struct table_ack_dispatch *d) {
    d->pending = d->force = 0;
}
int table_ack_window_ready(const struct table_ack_window *w) {
    return w && w->count<TABLE_ACK_WINDOW_MAX && w->sent<UINT64_MAX;
}
uint64_t table_ack_window_push(struct table_ack_window *w,uint64_t fingerprint) {
    if(!table_ack_window_ready(w))return 0;
    unsigned pos=(w->head+w->count)%TABLE_ACK_WINDOW_MAX;
    w->pending[pos].seq=++w->sent;w->pending[pos].fingerprint=fingerprint;w->count++;
    return w->sent;
}
int table_ack_window_settle(struct table_ack_window *w,uint64_t seq,int status) {
    if(!w||!w->count||w->pending[w->head].seq!=seq||(status!=1&&status!=2))return -1;
    uint64_t fingerprint=w->pending[w->head].fingerprint;
    w->head=(w->head+1)%TABLE_ACK_WINDOW_MAX;w->count--;
    if(status==1) { w->confirmed_fingerprint=fingerprint;w->confirmed=1; }
    else w->confirmed=0;
    return 0;
}
int table_ack_window_matches(const struct table_ack_window *w,uint64_t fingerprint) {
    return w && !w->count && w->confirmed && w->confirmed_fingerprint==fingerprint;
}
int table_ack_is_socket(int fd) {
    int type=0;socklen_t len=sizeof type;
    struct sockaddr_storage addr;socklen_t alen=sizeof addr;
    return fd>=0 && !getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&len) && type==SOCK_STREAM &&
        !getsockname(fd,(struct sockaddr *)&addr,&alen) && addr.ss_family==AF_UNIX;
}
void table_ack_reset(int fd) {
    ack_socket=table_ack_is_socket(fd);
    ack_seq=0;
}
int table_ack_emit(int fd,int rc) {
    if(!ack_socket)return 0;
    if((rc!=1&&rc!=2)||ack_seq==UINT64_MAX)goto broken;
    uint8_t record[TABLE_ACK_SIZE];
    uint64_t seq=++ack_seq;
    for(unsigned i=0;i<8;i++)record[i]=(uint8_t)(seq>>(56-8*i));
    record[8]=(uint8_t)rc;
    ssize_t n;
    do { n=send(fd,record,sizeof record,MSG_DONTWAIT|MSG_NOSIGNAL); } while(n<0&&errno==EINTR);
    if(n==(ssize_t)sizeof record)return 0;
broken:
    (void)shutdown(fd,SHUT_RDWR);
    ack_socket=0;
    return -1;
}
int table_ack_read(struct table_ack_reader *r,const uint8_t *data,size_t n,
                   void (*done)(void *,uint64_t,int),void *user) {
    if(!r||(!data&&n)||!done)return -1;
    int count=0;
    while(n) {
        size_t take=TABLE_ACK_SIZE-r->used;
        if(take>n)take=n;
        memcpy(r->bytes+r->used,data,take);r->used+=take;data+=take;n-=take;
        if(r->used==TABLE_ACK_SIZE) {
            uint64_t seq=0;
            for(unsigned i=0;i<8;i++)seq=(seq<<8)|r->bytes[i];
            if(r->next==UINT64_MAX||seq!=r->next+1||(r->bytes[8]!=1&&r->bytes[8]!=2))return -1;
            r->next=seq;r->used=0;count++;
            done(user,seq,r->bytes[8]);
        }
    }
    return count;
}
