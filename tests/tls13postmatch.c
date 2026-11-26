/* Real AEAD records; lab runner links the pinned wolfCrypt backend. */
#ifdef NDEBUG
#error "tls13postmatch requires active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "../src/proto/tls/tls13.h"
#include "../src/proto/tls/tls13_engine.h"
#include "../src/proto/vless/vision.h"
#include "tls13serverhello.h"
void tls13_test_post_init(struct tls13 *,const unsigned char *,const unsigned char *);
int tls13_test_traffic_update(struct tls13 *,int);
struct tls13_engine *tls13_test_engine_post(void *,size_t,struct tls13 *);
/* The engine feed object also references the handshake helper; this unit links
 * the real primitive without the ClientHello builder, and never enters that
 * handshake phase through its explicit post-Finished test seam. */
int x25519_shared_ext(const unsigned char private_key[32],const unsigned char peer[32],unsigned char shared[32]) {
    return sc_x25519(shared,private_key,peer);
}
#define post_init tls13_test_post_init
#define traffic_update tls13_test_traffic_update

/* Linker-only IO fault injection: production contains no fault hook. */
static int fault_fd=-1, fault_kind, fault_calls, fault_alloc;
ssize_t __real_write(int,const void *,size_t);
ssize_t __real_send(int,const void *,size_t,int);
void *__real_realloc(void *,size_t);
ssize_t __wrap_write(int fd,const void *p,size_t n) {
    if(fd==fault_fd && fault_kind==1) {
        if(!fault_calls++){if(n>3)n=3;return __real_write(fd,p,n);}
        errno=EIO;return -1;
    }
    return __real_write(fd,p,n);
}
ssize_t __wrap_send(int fd,const void *p,size_t n,int flags) {
    if(fd==fault_fd && fault_kind>=2) {
        if(!fault_calls++){if(n>3)n=3;return __real_send(fd,p,n,flags);}
        if(fault_kind==3){fault_alloc=1;errno=EAGAIN;}else errno=EIO;
        return -1;
    }
    return __real_send(fd,p,n,flags);
}
void *__wrap_realloc(void *p,size_t n) {
    if(fault_alloc){fault_alloc=0;errno=ENOMEM;return NULL;}
    return __real_realloc(p,n);
}
int tls13_test_decode_bounds(struct tls13 *,unsigned char *,size_t);
static void failed_closed(const struct tls13 *t,int error) {
    assert(!t->ready && !t->rd.ctx_ready && !t->wr.ctx_ready && t->post.error==error);
    for(size_t i=0;i<sizeof(t->rd.key);i++)assert(!t->rd.key[i]&&!t->wr.key[i]);
    for(size_t i=0;i<48;i++)assert(!t->post.app_rd_secret[i]&&!t->post.app_wr_secret[i]);
}
static void init(struct tls13 *t, int fd, int suite) {
    unsigned char client[48], server[48];
    memset(t, 0, sizeof(*t));
    memset(client, 0x31, sizeof(client)); memset(server, 0x72, sizeof(server));
    t->fd=fd; t->hash_n=suite==1?48:32;
    t->rd.aead=t->wr.aead=(enum tls13_aead)suite;
    t->rd.key_n=t->wr.key_n=suite==0?16:32;
    assert(!sc_hash_init(&t->tr, SC_SHA256));
    assert(!sc_hash_init(&t->tr384, SC_SHA384));
    post_init(t,client,server);
    /* Derive the first lab epoch through the same update API on both peers. */
    assert(!traffic_update(t,0)); assert(!traffic_update(t,1));
    /* Independent Python hashlib/hmac HKDF-Expand-Label vectors, secret=72*H. */
    const char *expected=suite==1?
        "b4ec72472e346049fabd3f3646d64834fb0dfd2e86201273569bc605e8b0c9620971c288790213797254d7c26f2c2171":
        "f2be226816b3217c89907e4ca0a2b7bb99d0fc456b8690e633cb32d9677adb24";
    for(size_t i=0;i<t->hash_n;i++) {
        unsigned byte;assert(sscanf(expected+2*i,"%2x",&byte)==1);
        assert(t->post.app_rd_secret[i]==byte);
    }
    t->ready=1;
}
static void record(int fd, struct tls13 *peer, unsigned char type, const void *p, size_t n) {
    unsigned char rec[512]; assert(n+22<=sizeof(rec));
    rec[0]=23; rec[1]=rec[2]=3; rec[3]=(unsigned char)((n+17)>>8);rec[4]=(unsigned char)(n+17);
    memcpy(rec+5,p,n);rec[5+n]=type;
    assert(!tls13_aead_seal(&peer->rd,peer->rd_seq++,rec,5,rec+5,n+1,rec+6+n));
    assert(write(fd,rec,n+22)==(ssize_t)(n+22));
}
static void consume(struct tls13 *t) {
    const unsigned char *p;size_t n;
    assert(!tls13_read_ref(t,&p,&n));assert(!n);
}
static void keyupdates(int suite) {
    int sv[2];struct tls13 t,peer;unsigned char reply[27],plain[8];size_t n;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],suite);init(&peer,sv[1],suite);
    unsigned char ku[]={24,0,0,1,1};
    for(size_t i=0;i<sizeof(ku);i++){record(sv[1],&peer,22,ku+i,1);consume(&t);}
    assert(t.rd_seq==0 && t.wr_seq==0);
    assert(read(sv[1],reply,sizeof(reply))==27);
    assert(!tls13_aead_open(&peer.wr,0,reply,5,reply+5,22));
    assert(!memcmp(reply+5,"\30\0\0\1\0\26",6));
    assert(!traffic_update(&peer,0));
    record(sv[1],&peer,23,"new",3);
    assert(!tls13_read(&t,plain,sizeof(plain),&n)&&n==3&&!memcmp(plain,"new",3));
    ku[4]=0;record(sv[1],&peer,22,ku,5);consume(&t);
    assert(!t.post.key_update_pending);
    assert(!traffic_update(&peer,0));ku[4]=2;
    record(sv[1],&peer,22,ku,5);
    assert(tls13_read(&t,plain,sizeof(plain),&n)==TLS13_EBADREC);
    assert(!t.ready);for(size_t i=0;i<48;i++)assert(!t.post.app_rd_secret[i]&&!t.post.app_wr_secret[i]);
    tls13_free(&t);tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
}
static void direct_fragment(void) {
    unsigned char frame[29]={0},uuid[16]={0},tail[16];
    /* UUID + DIRECT, data=3, padding=5; raw inner tail follows outer TLS. */
    frame[16]=VISION_CMD_DIRECT;frame[18]=3;frame[20]=5;memcpy(frame+21,"abc",3);
    for(size_t cut=1;cut<sizeof(frame);cut++) {
        int sv[2];struct tls13 t,peer;struct vision v;
        assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],0);init(&peer,sv[1],0);vision_init(&v,uuid);
        record(sv[1],&peer,23,frame,cut);record(sv[1],&peer,23,frame+cut,sizeof(frame)-cut);
        assert(write(sv[1],"raw",3)==3);
        size_t total=0;
        for(int part=0;part<2;part++) {
            const unsigned char *p;size_t n;
            assert(!tls13_read_ref(&t,&p,&n));
            while(n) {size_t used,pn;const unsigned char *payload;
                assert(!vision_unwrap(&v,p,n,&used,&payload,&pn));assert(used);
                if(pn)memcpy(tail+total,payload,pn);
                total+=pn;p+=used;n-=used;
            }
            if(!part)assert(!v.recv_direct&&!v.recv_done);
        }
        assert(v.recv_direct&&v.recv_done&&total==3&&!memcmp(tail,"abc",3));
        size_t buffered=tls13_take_pending(&t,tail,sizeof(tail));
        if(!buffered) {ssize_t got=read(sv[0],tail,sizeof(tail));assert(got==3);buffered=(size_t)got;}
        assert(buffered==3&&!memcmp(tail,"raw",3));
        tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
    }
}
static void blocked_reply(void) {
    int sv[2],small=4096;struct tls13 t,peer;unsigned char payload[4096]={0};
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    assert(!setsockopt(sv[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
    init(&t,sv[0],0);init(&peer,sv[1],0);t.live=1;
    for(int i=0;i<64;i++)assert(!tls13_write(&t,payload,sizeof(payload)));
    assert(outq_pending(&t.oq));uint64_t oldseq=t.wr_seq;
    unsigned char ku[]={24,0,0,1,1};
    for(int i=0;i<3;i++) {
        record(sv[1],&peer,22,ku,5);consume(&t);assert(!traffic_update(&peer,0));
    }
    assert(t.post.key_update_pending&&t.wr_seq==oldseq);
    size_t cap=64*(sizeof(payload)+22)+27,got=0;unsigned char *wire=malloc(cap);assert(wire);
    assert(fcntl(sv[1],F_SETFL,O_NONBLOCK)==0);
    for(int tries=0;got<cap&&tries<10000;tries++) {
        ssize_t n=read(sv[1],wire+got,cap-got);if(n>0)got+=(size_t)n;
        assert(tls13_flush(&t)>=0);
    }
    assert(got==cap&&!t.post.key_update_pending&&t.wr_seq==0);
    size_t off=0;uint64_t seq=0;
    while(off<got) {
        size_t n=((size_t)wire[off+3]<<8)|wire[off+4];
        assert(!tls13_aead_open(&peer.wr,seq++,wire+off,5,wire+off+5,n));
        if(off+n+5==got)assert(n==22&&!memcmp(wire+off+5,"\30\0\0\1\0\26",6));
        else assert(n==sizeof(payload)+17&&wire[off+5+sizeof(payload)]==23);
        off+=n+5;
    }
    assert(seq==65);free(wire);tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
}
static void tls_halfclose(int suite) {
    int sv[2];struct tls13 t,peer;unsigned char wire[64],out[16];size_t n;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],suite);init(&peer,sv[1],suite);
    assert(!tls13_shutdown_write(&t));assert(!tls13_shutdown_write(&t));
    assert(read(sv[1],wire,sizeof(wire))==24);
    assert(!tls13_aead_open(&peer.wr,0,wire,5,wire+5,19));
    assert(!memcmp(wire+5,"\1\0\25",3));assert(read(sv[1],wire,1)==0);
    unsigned char ku[]={24,0,0,1,1};record(sv[1],&peer,22,ku,sizeof(ku));consume(&t);
    assert(!t.post.key_update_pending&&!tls13_pending(&t));assert(!tls13_flush(&t));
    assert(!traffic_update(&peer,0));
    record(sv[1],&peer,23,"after-FIN",9);
    assert(!tls13_read(&t,out,sizeof(out),&n)&&n==9&&!memcmp(out,"after-FIN",9));
    unsigned char alert[]={1,0};record(sv[1],&peer,21,alert,sizeof(alert));
    assert(tls13_read(&t,out,sizeof(out),&n)==TLS13_ECLOSED&&t.post.read_closed);
    assert(tls13_write(&t,(const unsigned char *)"x",1)==TLS13_ESTATE);
    tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],suite);init(&peer,sv[1],suite);
    record(sv[1],&peer,21,alert,sizeof(alert));
    assert(tls13_read(&t,out,sizeof(out),&n)==TLS13_ECLOSED);
    assert(!tls13_write(&t,(const unsigned char *)"uplink",6));
    assert(read(sv[1],wire,sizeof(wire))==28);
    assert(!tls13_aead_open(&peer.wr,0,wire,5,wire+5,23));
    assert(!memcmp(wire+5,"uplink\27",7));
    tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],suite);
    assert(!shutdown(sv[1],SHUT_WR));assert(tls13_read(&t,out,sizeof(out),&n)==TLS13_EIO);
    tls13_free(&t);close(sv[0]);close(sv[1]);
}
static void blocked_close(void) {
    int sv[2],small=4096;struct tls13 t,peer;unsigned char payload[4096]={0},readback[16];size_t rn;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    assert(!setsockopt(sv[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
    init(&t,sv[0],0);init(&peer,sv[1],0);t.live=1;
    for(int i=0;i<64;i++)assert(!tls13_write(&t,payload,sizeof(payload)));
    assert(tls13_shutdown_write(&t)==1&&t.post.write_closed==1);
    unsigned char ku[]={24,0,0,1,1};record(sv[1],&peer,22,ku,sizeof(ku));consume(&t);
    assert(!traffic_update(&peer,0));record(sv[1],&peer,23,"reverse",7);
    assert(!tls13_read(&t,readback,sizeof(readback),&rn)&&rn==7&&!memcmp(readback,"reverse",7));
    size_t cap=64*(sizeof(payload)+22)+24,got=0;unsigned char *wire=malloc(cap);assert(wire);
    assert(fcntl(sv[1],F_SETFL,O_NONBLOCK)==0);
    int closed=1;
    for(int tries=0;(got<cap||closed)&&tries<10000;tries++) {
        ssize_t n=read(sv[1],wire+got,cap-got);if(n>0)got+=(size_t)n;
        closed=tls13_shutdown_write(&t);assert(closed>=0&&closed<=1);
    }
    assert(got==cap&&!closed&&t.post.write_closed==2);
    size_t off=0;uint64_t seq=0;
    while(off<got) {
        size_t n=((size_t)wire[off+3]<<8)|wire[off+4];
        assert(!tls13_aead_open(&peer.wr,seq++,wire+off,5,wire+off+5,n));
        if(off+n+5==got)assert(n==19&&!memcmp(wire+off+5,"\1\0\25",3));
        else assert(n==sizeof(payload)+17&&wire[off+5+sizeof(payload)]==23);
        off+=n+5;
    }
    assert(seq==65);assert(read(sv[1],readback,1)==0);
    free(wire);tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
}
static void terminal_record_errors(void) {
    for(int kind=1;kind<=3;kind++) {
        int sv[2];struct tls13 t;unsigned char prefix[3];
        assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],0);t.live=kind!=1;
        fault_fd=sv[0];fault_kind=kind;fault_calls=0;
        assert(tls13_write(&t,(const unsigned char *)"lost ciphertext",15)==TLS13_EIO);
        fault_fd=-1;fault_kind=0;assert(!fault_alloc && fault_calls==2);
        assert(read(sv[1],prefix,sizeof(prefix))==3); /* real prefix escaped before injected failure */
        failed_closed(&t,TLS13_EIO);assert(!t.oq.p && !t.oq.n);
        assert(tls13_write(&t,(const unsigned char *)"retry",5)==TLS13_EIO);
        tls13_free(&t);tls13_free(&t);close(sv[0]);close(sv[1]);
    }
    for(int type=0;type<=24;type+=24) {
        int sv[2];struct tls13 t,peer;unsigned char result[8];size_t n;
        assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));init(&t,sv[0],0);init(&peer,sv[1],0);
        record(sv[1],&peer,(unsigned char)type,"",0);
        assert(tls13_read(&t,result,sizeof(result),&n)==TLS13_EBADREC && !n);
        failed_closed(&t,TLS13_EBADREC);
        tls13_free(&t);tls13_free(&peer);close(sv[0]);close(sv[1]);
    }
    for(size_t n=0;n<17;n++) {
        struct tls13 t;unsigned char record_bytes[17]={0};init(&t,-1,0);
        assert(tls13_test_decode_bounds(&t,record_bytes,n)==TLS13_EBADREC);
        failed_closed(&t,TLS13_EBADREC);tls13_free(&t);
    }
}
static void feed_record(struct tls13_engine *e,int fd) {
    unsigned char wire[512];size_t have=0,want=5;
    while(have<want){ssize_t n=read(fd,wire+have,want-have);assert(n>0);have+=(size_t)n;}
    want=5+((size_t)wire[3]<<8)+wire[4];assert(want<=sizeof(wire));
    while(have<want){ssize_t n=read(fd,wire+have,want-have);assert(n>0);have+=(size_t)n;}
    size_t consumed=0;assert(!tls13_engine_feed(e,wire,have,&consumed)&&consumed==have);
}
static void engine_finish_control_order(int suite) {
    int sv[2];struct tls13 t,peer;assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    init(&t,-1,suite);init(&peer,-1,suite);
    void *storage=malloc(tls13_engine_storage_size());assert(storage);
    struct tls13_engine *e=tls13_test_engine_post(storage,tls13_engine_storage_size(),&t);assert(e);
    size_t accepted=0,length;const unsigned char *bytes;unsigned char app[64],close_record[64];
    assert(!tls13_engine_write(e,(const unsigned char *)"before",6,&accepted)&&accepted==6);
    assert(!tls13_engine_output(e,&bytes,&length)&&length==28);memcpy(app,bytes,length);
    assert(!tls13_aead_open(&peer.wr,0,app,5,app+5,length-5));assert(!memcmp(app+5,"before\27",7));
    assert(!tls13_engine_finish_write(e)); /* barrier accepted with held application ciphertext */
    assert(tls13_engine_write(e,(const unsigned char *)"forbidden",9,&accepted)==TLS13_ESTATE&&!accepted);
    assert(!tls13_engine_output_consume(e,3));
    unsigned char update[5]={24,0,0,1,1};record(sv[1],&peer,22,update,sizeof(update));feed_record(e,sv[0]);
    assert(!traffic_update(&peer,0));
    assert(!tls13_engine_output(e,&bytes,&length)&&length==25);assert(!tls13_engine_output_consume(e,length));
    assert(!tls13_engine_local_finished(e));
    /* No reply can leapfrog/starve closure: the next old-key record is exactly
     * close_notify, not KeyUpdate. Existing data remains complete and ordered. */
    assert(!tls13_engine_output(e,&bytes,&length)&&length==24);memcpy(close_record,bytes,length);
    assert(!tls13_aead_open(&peer.wr,1,close_record,5,close_record+5,length-5));
    assert(!memcmp(close_record+5,"\1\0\25",3));
    assert(!tls13_engine_output_consume(e,23)&&!tls13_engine_local_finished(e));
    assert(!tls13_engine_output_consume(e,1)&&tls13_engine_local_finished(e));
    record(sv[1],&peer,22,update,sizeof(update));feed_record(e,sv[0]);assert(!traffic_update(&peer,0));
    assert(!tls13_engine_output(e,&bytes,&length)&&!length); /* no app follows local close */
    record(sv[1],&peer,23,"after",5);feed_record(e,sv[0]);
    assert(!tls13_engine_plaintext(e,&bytes,&length)&&length==5&&!memcmp(bytes,"after",5));
    assert(!tls13_engine_plaintext_consume(e,length));
    const unsigned char alert[2]={1,0};record(sv[1],&peer,21,alert,sizeof(alert));feed_record(e,sv[0]);
    assert(tls13_engine_peer_finished(e)&&!tls13_engine_eof(e));
    tls13_engine_destroy(e);free(storage);tls13_free(&peer);close(sv[0]);close(sv[1]);
}
int main(void) {
    server_hello_bounds();
    terminal_record_errors();
    for(int i=0;i<3;i++){keyupdates(i);tls_halfclose(i);engine_finish_control_order(i);}
    direct_fragment();
    blocked_reply();
    blocked_close();
    puts("tls13postmatch: three AEAD suites, fragmented KU, old/new epochs, invalid KU, wipe/free, Vision splits/raw tail, queued KU/close_notify and bidirectional half-close PASS");
    return 0;
}
