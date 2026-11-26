/* SPDX-License-Identifier: GPL-3.0-only */
#include "table_ack.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
struct result { unsigned count; uint64_t seq[4]; int status[4]; };
static void done(void *arg,uint64_t seq,int status) {
    struct result *r=arg;
    assert(r->count<4);r->seq[r->count]=seq;r->status[r->count++]=status;
}
/* Exercise the same dispatch decisions as supd, with a replaceable current spec. */
static int dispatch(struct table_ack_window *w, struct table_ack_dispatch *d,
                    uint64_t current, int force) {
    enum table_ack_decision decision = table_ack_dispatch_decide(d,w,current,force);
    if (decision == TABLE_ACK_DEFER) return 2;
    if (decision == TABLE_ACK_SEND) assert(table_ack_window_push(w,current));
    table_ack_dispatch_done(d);
    return decision == TABLE_ACK_SEND;
}
static void test_dispatch(void) {
    struct table_ack_window w={0};
    struct table_ack_dispatch d={0};
    for (unsigned i=0;i<TABLE_ACK_WINDOW_MAX;i++) assert(table_ack_window_push(&w,10));
    assert(dispatch(&w,&d,20,0)==2 && d.pending && !d.force);
    assert(dispatch(&w,&d,30,1)==2 && d.pending && d.force);
    assert(dispatch(&w,&d,40,0)==2 && d.pending && d.force);
    assert(!table_ack_window_settle(&w,1,1));
    assert(dispatch(&w,&d,40,0)==1 && !d.pending && !d.force);
    unsigned last=(w.head+w.count-1)%TABLE_ACK_WINDOW_MAX;
    assert(w.pending[last].fingerprint==40 && w.pending[last].seq==129);
    /* No automatic retry on rejection after the deferred desire was queued. */
    while(w.count>1) assert(!table_ack_window_settle(&w,w.pending[w.head].seq,1));
    assert(!table_ack_window_settle(&w,129,2) && !d.pending);
    /* Cancellation/replacement by the current confirmed value becomes no-op. */
    assert(table_ack_window_push(&w,50)==130);
    assert(!table_ack_window_settle(&w,130,1));
    for(unsigned i=0;i<TABLE_ACK_WINDOW_MAX;i++) assert(table_ack_window_push(&w,50));
    assert(dispatch(&w,&d,60,0)==2);
    while(w.count) assert(!table_ack_window_settle(&w,w.pending[w.head].seq,1));
    assert(dispatch(&w,&d,50,0)==0 && !d.pending);
    for(unsigned i=0;i<TABLE_ACK_WINDOW_MAX;i++) assert(table_ack_window_push(&w,50));
    assert(dispatch(&w,&d,60,1)==2);
    while(w.count) assert(!table_ack_window_settle(&w,w.pending[w.head].seq,1));
    assert(dispatch(&w,&d,50,0)==1 && !d.pending);
    /* A new session never inherits a deferred force or a confirmation. */
    d.pending=1;d.force=1;
    memset(&w,0,sizeof w);table_ack_dispatch_done(&d);
    assert(dispatch(&w,&d,50,0)==1 && !d.pending);
}
int main(void) {
    test_dispatch();
    struct table_ack_window w={0};
    assert(table_ack_window_push(&w,11)==1 && table_ack_window_push(&w,22)==2);
    assert(!table_ack_window_matches(&w,11));
    assert(!table_ack_window_settle(&w,1,1));
    assert(!table_ack_window_matches(&w,11) && !table_ack_window_matches(&w,22));
    assert(table_ack_window_settle(&w,1,1)==-1);
    assert(!table_ack_window_settle(&w,2,2) && !table_ack_window_matches(&w,22));
    assert(table_ack_window_push(&w,22)==3);
    assert(!table_ack_window_settle(&w,3,1) && table_ack_window_matches(&w,22));
    memset(&w,0,sizeof w); /* new fd/session: no inherited confirmation */
    assert(!table_ack_window_matches(&w,22) && table_ack_window_settle(&w,3,1)==-1);
    for(unsigned i=0;i<TABLE_ACK_WINDOW_MAX;i++)assert(table_ack_window_push(&w,i)==i+1);
    assert(!table_ack_window_ready(&w) && !table_ack_window_push(&w,999));
    int fd[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));
    table_ack_reset(fd[0]);
    assert(!table_ack_emit(fd[0],1));
    assert(!table_ack_emit(fd[0],2));
    uint8_t bytes[2*TABLE_ACK_SIZE];size_t used=0;
    while(used<sizeof bytes) { ssize_t n=read(fd[1],bytes+used,sizeof bytes-used);assert(n>0);used+=(size_t)n; }
    struct table_ack_reader reader={0};struct result r={0};
    assert(table_ack_read(&reader,bytes,3,done,&r)==0 && !r.count);
    assert(table_ack_read(&reader,bytes+3,sizeof bytes-3,done,&r)==2);
    assert(r.count==2&&r.seq[0]==1&&r.status[0]==1&&r.seq[1]==2&&r.status[1]==2);
    assert(table_ack_read(&reader,bytes,TABLE_ACK_SIZE,done,&r)==-1);
    close(fd[0]);close(fd[1]);
    assert(!pipe(fd));table_ack_reset(fd[1]);
    assert(!table_ack_emit(fd[1],1));
    close(fd[1]);assert(read(fd[0],bytes,sizeof bytes)==0);close(fd[0]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,fd));table_ack_reset(fd[0]);
    memset(bytes,0,sizeof bytes);
    while(send(fd[0],bytes,sizeof bytes,MSG_DONTWAIT|MSG_NOSIGNAL)>0) {}
    assert(errno==EAGAIN||errno==EWOULDBLOCK);
    assert(table_ack_emit(fd[0],1)==-1);
    close(fd[0]);close(fd[1]);
    puts("table acknowledgements: batch, split, stale, pipe and backpressure PASS");
    return 0;
}
