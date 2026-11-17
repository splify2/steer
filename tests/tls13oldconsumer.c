/* Compiled against an explicitly pinned OLD header, loaded with NEW TLS DSO. */
#include "tls13.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
void tls13_test_post_init(struct tls13 *,const unsigned char *,const unsigned char *);
int tls13_test_traffic_update(struct tls13 *,int);
struct guarded {uint64_t before;struct tls13 tls;uint64_t after;};
static void init(struct guarded *g,int fd) {
    memset(g,0,sizeof(*g));g->before=UINT64_C(0xbefaee9321);g->after=UINT64_C(0xaafed93155);
    struct tls13 *t=&g->tls;unsigned char c[48]={0},s[48]={1};
    t->fd=fd;t->hash_n=32;t->rd.key_n=t->wr.key_n=16;
    tls13_test_post_init(t,c,s);
    assert(!tls13_test_traffic_update(t,0));assert(!tls13_test_traffic_update(t,1));t->ready=1;
}
int main(void) {
    int sv[2];struct guarded g;unsigned char wire[64];
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&g,sv[0]);
    assert(!tls13_write(&g.tls,(const unsigned char *)"old header",10));
    assert(read(sv[1],wire,sizeof(wire))==32);
    assert(!tls13_aead_open(&g.tls.wr,0,wire,5,wire+5,27));
    assert(!memcmp(wire+5,"old header\27",11));
    tls13_free(&g.tls);tls13_free(&g.tls);
    assert(g.before==UINT64_C(0xbefaee9321)&&g.after==UINT64_C(0xaafed93155));
    close(sv[0]);close(sv[1]);puts("old-header consumer/new TLS DSO real write+decrypt+repeated-free+canaries PASS");
}
