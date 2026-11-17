#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "tls13.h"
#include "tls13_engine.h"
#include "certverify.h"
#include "reality.h"

static uint64_t now(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;
}
static struct cert_trust *trust(void) {
    const char *path=getenv("STEER_TEST_ROOTS"); assert(path);
    FILE *file=fopen(path,"rb"); assert(file);
    assert(!fseek(file,0,SEEK_END));long size=ftell(file);assert(size>0 && size<=8*1024*1024);
    rewind(file);unsigned char *pem=malloc((size_t)size);assert(pem);
    assert(fread(pem,1,(size_t)size,file)==(size_t)size);assert(!fclose(file));
    struct cert_trust *roots=NULL;assert(!cert_trust_prepare_pem(pem,(size_t)size,&roots));
    memset(pem,0xa5,(size_t)size);free(pem);return roots;
}
static int probe(int argc,char **argv) {
    if(argc<5 || strcmp(argv[2],"tcp"))return 2;
    int half=argc>5&&!strcmp(argv[5],"halfclose"),port=atoi(argv[1]),target=atoi(argv[3]);
    size_t payload=strlen(argv[4]);if(port<1||port>65535||target<1||target>65535||payload>128)return 2;
    struct cert_trust *roots=trust();
    unsigned char hello[8192];size_t hello_length=0;struct reality_state key;
    struct reality_cfg config={.sni="localhost",.fp="chrome",.plain=1};
    assert(!reality_build_hello(&config,&key,hello,sizeof(hello),&hello_length));
    struct tls13_engine_options options={.client_hello=hello,.client_hello_length=hello_length,
        .x25519_private=key.priv,.limits={.max_records=64,.max_messages=4,
        .max_handshake_message=40960,.max_certificate=40960}};
    const char *limit=getenv("STEER_TEST_ENGINE_LIMIT");
    if(limit&&!strcmp(limit,"records"))options.limits.max_records=1;
    if(limit&&!strcmp(limit,"messages"))options.limits.max_messages=1;
    if(limit&&!strcmp(limit,"certificate"))options.limits.max_certificate=4;
    size_t workspace_length=0;assert(!tls13_engine_workspace_size(&options,&workspace_length));
    void *workspace=malloc(workspace_length),*storage=malloc(tls13_engine_storage_size());
    struct tls13 *tls=malloc(sizeof(*tls));assert(workspace&&storage&&tls);
    struct tls13_engine *engine=NULL;
    assert(!tls13_engine_init(storage,tls13_engine_storage_size(),tls,workspace,workspace_length,&options,&engine));
    assert(tls->fd==-1);memset(hello,0xa5,sizeof(hello));memset(&key,0,sizeof(key));
    int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);int one=1;
    assert(!setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one)));
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons((uint16_t)port),.sin_addr={htonl(INADDR_LOOPBACK)}};
    assert(!connect(fd,(struct sockaddr *)&address,sizeof(address)));
    assert(!fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK));
    unsigned char request[256]={0},received[256],input[4096];size_t sent=0,got=0,input_have=0,input_offset=0;
    request[16]=1;request[18]=1;request[19]=(unsigned char)(target>>8);request[20]=(unsigned char)target;
    request[21]=1;request[22]=127;request[25]=1;memcpy(request+26,argv[4],payload);
    size_t request_length=26+payload;int finished=0,result=1,checked_wipe=0;unsigned turn=0;
    uint64_t deadline=now()+10000000000u;
    while(now()<deadline) {
        const unsigned char *bytes=NULL;size_t length=0;
        int rc=tls13_engine_output(engine,&bytes,&length);if(rc)break;
        if(length) {
            size_t prefix=1+turn++%31;if(prefix>length)prefix=length;
            ssize_t n=send(fd,bytes,prefix,MSG_NOSIGNAL);
            if(n>0){assert(!tls13_engine_output_consume(engine,(size_t)n));}
            else if(n==0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))break;
        }
        if(tls13_engine_state(engine)==TLS13_ENGINE_AUTH_PENDING) {
            struct tls13_engine_auth material;assert(!tls13_engine_auth_snapshot(engine,&material));
            if(getenv("STEER_TEST_CANCEL_AUTH")) {
                size_t total=material.certificate_length+material.certificate_verify_length+material.transcript_length;
                assert(total<=65536&&!sent&&!got&&!tls->ready);
                unsigned char *copy=malloc(total);assert(copy);
                memcpy(copy,material.certificate,material.certificate_length);
                memcpy(copy+material.certificate_length,material.certificate_verify,material.certificate_verify_length);
                memcpy(copy+material.certificate_length+material.certificate_verify_length,material.transcript,material.transcript_length);
                tls13_engine_destroy(engine);
                for(size_t j=0;j<workspace_length;j++)assert(!((unsigned char *)workspace)[j]);
                assert(!cert_verify_server_prepared(copy,material.certificate_length,
                    copy+material.certificate_length,material.certificate_verify_length,
                    copy+material.certificate_length+material.certificate_verify_length,material.transcript_length,"localhost",roots,NULL));
                memset(copy,0,total);free(copy);result=0;break;
            }
            const char *name=getenv("STEER_TEST_NAME");if(!name)name="localhost";
            rc=cert_verify_server_prepared(material.certificate,material.certificate_length,
                material.certificate_verify,material.certificate_verify_length,
                material.transcript,material.transcript_length,name,roots,NULL);
            if(tls13_engine_auth_complete(engine,rc)){fprintf(stderr,"engine authentication rejected\n");break;}
            assert(!tls->ready); /* ClientFinished still held by lower backpressure. */
        }
        if(tls13_engine_state(engine)==TLS13_ENGINE_READY) {
            if(!checked_wipe) {
                assert(!tls13_engine_workspace_in_use(engine));
                for(size_t i=0;i<workspace_length;i++)assert(!((unsigned char *)workspace)[i]);
                checked_wipe=1;
            }
            if(sent<request_length) {
                size_t accepted=0;rc=tls13_engine_write(engine,request+sent,request_length-sent,&accepted);
                if(rc&&rc!=TLS13_EAGAIN)break;
                sent+=accepted;
            }
            if(half&&sent==request_length&&!finished) {
                rc=tls13_engine_finish_write(engine);
                if(rc&&rc!=TLS13_EAGAIN)break;
                if(!rc)finished=1;
            }
            assert(!tls13_engine_plaintext(engine,&bytes,&length));
            if(length) {
                size_t take=1+turn++%7;if(take>length)take=length;
                if(take>sizeof(received)-got)break;
                memcpy(received+got,bytes,take);got+=take;assert(!tls13_engine_plaintext_consume(engine,take));
            }
            if(got==payload+2&&(!half||tls13_engine_peer_finished(engine))) {
                assert(received[0]==0&&received[1]==0&&!memcmp(received+2,argv[4],payload));
                result=0;break;
            }
        }
        if(input_offset<input_have) {
            size_t consumed=0;rc=tls13_engine_feed(engine,input+input_offset,input_have-input_offset,&consumed);
            input_offset+=consumed;if(rc&&rc!=TLS13_EAGAIN)break;
        } else {
            ssize_t n=recv(fd,input,sizeof(input),0);
            if(n>0){input_have=(size_t)n;input_offset=0;}
            else if(n==0){if(tls13_engine_eof(engine))break;}
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;
        }
        struct pollfd wait={.fd=fd,.events=POLLIN};
        assert(!tls13_engine_output(engine,&bytes,&length));if(length)wait.events|=POLLOUT;
        (void)poll(&wait,1,input_offset<input_have?0:1);
    }
    const char *expected=getenv("STEER_TEST_ENGINE_ERROR");
    if(expected) {
        assert(result&&!sent&&!got&&!tls->ready&&tls13_engine_state(engine)==TLS13_ENGINE_FAILED);
        assert(tls13_engine_error(engine)==atoi(expected)&&!tls13_engine_workspace_in_use(engine));
        result=0;
    }
    if(result)fprintf(stderr,"engine probe failed state=%d error=%d bytes=%zu\n",(int)tls13_engine_state(engine),tls13_engine_error(engine),got);
    tls13_engine_destroy(engine);tls13_engine_destroy(engine);close(fd);
    for(size_t i=0;i<workspace_length;i++)assert(!((unsigned char *)workspace)[i]);
    assert(!tls->ready&&!tls->rd.ctx_ready&&!tls->wr.ctx_ready);
    free(workspace);free(storage);free(tls);cert_trust_destroy(roots);
    if(!result)puts(expected||getenv("STEER_TEST_CANCEL_AUTH")?"incremental TLS engine negative/teardown PASS":"incremental TLS engine prepared-trust real upstream echo PASS");
    return result;
}
struct probe_owner {int argc,result;char **argv;};
static void *run_owner(void *arg) {
    struct probe_owner *owner=arg;owner->result=probe(owner->argc,owner->argv);return NULL;
}
int main(int argc,char **argv) {
    const char *value=getenv("STEER_ENGINE_OWNERS");int owners=value?atoi(value):1;
    if(owners!=1&&owners!=4)return 2;
    if(owners==1)return probe(argc,argv);
    struct probe_owner jobs[4];pthread_t threads[4];
    for(int i=0;i<4;i++){jobs[i]=(struct probe_owner){.argc=argc,.argv=argv};assert(!pthread_create(&threads[i],NULL,run_owner,&jobs[i]));}
    int failed=0;for(int i=0;i<4;i++){assert(!pthread_join(threads[i],NULL));failed|=jobs[i].result;}
    return failed;
}
