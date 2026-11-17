/* Real socket/worker lifecycle test backend; no production protocol substitute. */
#define _GNU_SOURCE
#include "stack.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
struct test_session {
    int socket, end;
    uint16_t port;
    size_t offset, length;
    unsigned char queued[32768];
};
static const char *test_peer(const void *ctx) { (void)ctx; return "loopback-test"; }
static void test_describe(const void *ctx, char *out, size_t n) { (void)ctx; snprintf(out,n,"test TCP lifecycle"); }
static const char *test_error(int rc) { (void)rc; return "test connection failed"; }
static void test_clear(void *sess) { struct test_session *s=sess; s->socket=-1; s->end=0; s->port=0; s->offset=s->length=0; }
static void test_close(void *sess) { struct test_session *s=sess; if(s->socket>=0)close(s->socket); s->socket=-1; }
static int test_open(const void *ctx,void *sess,const struct flow_key *key,int udp) {
    (void)ctx; if(udp)return -1;
    unsigned char expected6[16]; inet_pton(AF_INET6,"2001:db8::81",expected6);
    if(key->v6 ? memcmp(key->dst6,expected6,16)!=0 : key->dst!=inet_addr("203.0.113.81"))return -1; ((struct test_session*)sess)->port=key->dport; return 0;
}
static int test_connect(const void *ctx,void *sess,int timeout) {
    (void)ctx;(void)timeout;
    struct test_session *s=sess;
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(s->port)};
    inet_pton(AF_INET,"127.0.0.2",&a.sin_addr);
    s->socket=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(s->socket<0)return -1;
    if(connect(s->socket,(struct sockaddr*)&a,sizeof(a))){test_close(s);return -1;}
    fcntl(s->socket,F_SETFL,O_NONBLOCK); return 0;
}
static int test_fd(const void *sess) { return ((const struct test_session*)sess)->socket; }
static int test_has_data(const void *sess) { (void)sess;return 0; }
static int test_flush(const void *ctx,void *sess) {
    (void)ctx;struct test_session *s=sess;
    while(s->length){
        ssize_t n=send(s->socket,s->queued+s->offset,s->length,MSG_NOSIGNAL);
        if(n>0){s->offset+=(size_t)n;s->length-=(size_t)n;continue;}
        if(n<0&&errno==EINTR)continue;
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 1;
        s->end=STACK_FLOW_END_ERROR;return -1;
    }
    s->offset=0;return 0;
}
static size_t test_pending(const void *ctx,void *sess) { (void)ctx;return ((struct test_session*)sess)->length; }
static long test_room(const void *ctx,void *sess) { (void)ctx;return (long)(sizeof(((struct test_session*)sess)->queued)-((struct test_session*)sess)->length); }
static int test_send(const void *ctx,void *sess,const struct flow_key *k,int udp,const unsigned char *p,size_t n) {
    (void)k;(void)udp;struct test_session *s=sess;
    if(n>sizeof(s->queued)-s->length)return SEND_AGAIN;
    if(s->offset&&s->length)memmove(s->queued,s->queued+s->offset,s->length);
    s->offset=0;if(n)memcpy(s->queued+s->length,p,n);s->length+=n;
    return test_flush(ctx,sess)<0?SEND_FATAL:SEND_OK;
}
static int test_read(void *sess,unsigned char *buf,size_t cap,const unsigned char **p,size_t *got) {
    struct test_session *s=sess;ssize_t n=recv(s->socket,buf,cap,MSG_DONTWAIT);
    *p=buf;*got=0;
    if(n>0){*got=(size_t)n;return 0;}
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    s->end=n==0?STACK_FLOW_END_EOF:STACK_FLOW_END_ERROR;return -1;
}
static int test_deliver(const void *ctx,void *sess,int udp,const unsigned char *p,size_t n,dialer_emit_fn emit,void *arg) {
    (void)ctx;(void)sess;(void)udp;return emit(arg,p,n);
}
static int test_shutdown(void *ctx,const void *node,void *sess) {
    (void)ctx;int r=test_flush(node,sess);if(r)return r<0?SEND_FATAL:SEND_AGAIN;
    return shutdown(test_fd(sess),SHUT_WR)?SEND_FATAL:SEND_OK;
}
static int test_end(void *ctx,const void *sess) { (void)ctx;return ((const struct test_session*)sess)->end; }
static int test_cap(void *ctx,const void *node,const void *sess) { (void)ctx;(void)node;(void)sess;return 1; }
int main(void) {
    const char *fake_path=getenv("STEER_FLOW_FAKEIP_PATH");
    if(fake_path)stack_set_fakeip_path(fake_path);
    static const struct dialer_ops ops={.name="test-tcp",.sess_size=sizeof(struct test_session),
      .peer=test_peer,.describe=test_describe,.strerror=test_error,.connect=test_connect,
      .close=test_close,.clear=test_clear,.fd=test_fd,.has_data=test_has_data,
      .flow_open=test_open,.send=test_send,.room=test_room,.read=test_read,.deliver=test_deliver,
      .out_pending=test_pending,.out_flush=test_flush};
    const struct dialer d={.ops=&ops};
    const struct stack_flow_extensions ext={sizeof(ext),STACK_FLOW_EXT_VERSION,NULL,test_shutdown,test_end,test_cap};
    const struct tun_out o={.device="flowtest"};
    return stack_run_ex(&o,&d,&ext,NULL,NULL);
}
