#define _GNU_SOURCE
#include "vless_stream_backend.h"
#include "native_stream_backend.h"
#include "buffers.h"
#include "loop.h"
#include "vless/inbound.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
static const uint8_t uuid[16]={42};
static const struct steer_pv1_buffer_api *ba;
struct server {int fd,mode;uint16_t port;};
static int authorize(void *context,const uint8_t received[16]){(void)context;return !memcmp(uuid,received,16);}
static void send_all(int fd,const void *data,size_t length){
    const uint8_t *bytes=data;while(length){ssize_t n=send(fd,bytes,length,MSG_NOSIGNAL);assert(n>0);bytes+=n;length-=(size_t)n;}
}
static void *serve(void *arg){
    struct server *s=arg;struct pollfd poller={s->fd,POLLIN,0};int rc=poll(&poller,1,2000);assert(rc>=0);
    if(!rc){assert(s->mode==4);return NULL;}
    int fd=accept(s->fd,NULL,NULL);assert(fd>=0);struct timeval timeout={3,0};assert(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
    uint8_t byte;
    if(s->mode!=5){
        struct vl_decoder decoder;vl_decoder_init(&decoder,authorize,NULL);
        while(decoder.result==VL_MORE){ssize_t n=recv(fd,&byte,1,0);if(n<=0){assert(s->mode==4);close(fd);return NULL;}size_t used;assert(vl_decoder_feed(&decoder,&byte,1,&used)>=0&&used==1);}
        assert(decoder.result==VL_DONE&&decoder.request.command==1&&decoder.request.port==443);
        assert(decoder.request.address_type==2&&decoder.request.address_length==19&&!memcmp(decoder.request.address,"destination.example",19));
    }
    uint8_t body[3];size_t have=0;ssize_t n;
    while(have<sizeof(body)&&(n=recv(fd,body+have,sizeof(body)-have,0))>0)have+=(size_t)n;
    assert(have==3&&!memcmp(body,"abc",3));
    if(s->mode!=5)assert(recv(fd,&byte,1,0)==0);
    if(s->mode==5)send_all(fd,"reply",5);
    else if(s->mode==2){byte=0;send_all(fd,&byte,1);}
    else if(s->mode==3){const uint8_t wrong[]={1,0,'x'};send_all(fd,wrong,sizeof(wrong));}
    else {
        uint8_t response[71]={0};size_t offset=2;
        if(s->mode==1){response[1]=64;for(unsigned i=0;i<64;i+=2){response[2+i]=10;response[3+i]=0;}offset+=64;}
        memcpy(response+offset,"reply",5);send_all(fd,response,offset+5);
    }
    assert(!shutdown(fd,SHUT_WR));close(fd);return NULL;
}
struct limited {struct steer_pv1_stream_ref inner;unsigned chunk,write_chunk;};
static uint64_t STEER_PV1_CALL limited_caps(const struct steer_pv1_backend_stream *s){const struct limited *l=(const struct limited *)s;return l->inner.api->capabilities(l->inner.handle);}
static struct steer_pv1_async_start STEER_PV1_CALL limited_read(struct steer_pv1_backend_stream *s,struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done done,void *u){
    struct limited *l=(struct limited *)s;if(n>l->chunk)n=l->chunk;return l->inner.api->read(l->inner.handle,b,o,n,done,u);
}
static struct steer_pv1_async_start STEER_PV1_CALL limited_write(struct steer_pv1_backend_stream *s,struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done done,void *u){
    struct limited *l=(struct limited *)s;if(n>l->write_chunk)n=l->write_chunk;return l->inner.api->write(l->inner.handle,b,o,n,done,u);
}
static struct steer_pv1_async_start STEER_PV1_CALL limited_finish(struct steer_pv1_backend_stream *s,steer_pv1_backend_finish_done done,void *u){struct limited *l=(struct limited *)s;return l->inner.api->finish_write(l->inner.handle,done,u);}
static void STEER_PV1_CALL limited_close(struct steer_pv1_backend_stream *s){struct limited *l=(struct limited *)s;l->inner.api->close(l->inner.handle);}
static struct steer_pv1_error STEER_PV1_CALL limited_release(struct steer_pv1_backend_stream *s){struct limited *l=(struct limited *)s;struct steer_pv1_error e=l->inner.api->release(l->inner.handle);if(!e.code)free(l);return e;}
static const struct steer_pv1_backend_stream_api limited_api={sizeof(limited_api),STEER_PV1_STREAM_BACKEND_LAYOUT,limited_caps,limited_read,limited_write,limited_finish,limited_close,limited_release};
struct fixture;
struct result {struct fixture *f;struct steer_pv1_async_start operation;struct steer_pv1_stream_ref stream;uint32_t code,bytes;int ready;};
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct steer_pv1_host *buffers;struct steer_draft_stream_runtime *native;
    struct steer_draft_backend_runtime *wrapper;struct steer_draft_native_stream_backend *direct;
    struct steer_draft_vless_stream_backend *vless;struct steer_draft_stream_routes *routes;
    struct steer_draft_stream_binding lower;struct steer_pv1_flow_metadata flow;
    struct steer_pv1_buffer *input,*output;struct result opened,reading,writing,finish;
    struct steer_pv1_operation_ref first_write;struct server server;pthread_t worker;
    steer_pv1_stream_open_done lower_done;void *lower_userdata;
    unsigned phase,sent,received;int own_finalized,direct_finalized,eof;uint16_t upstream_port;
};
static void shim_opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct fixture *f=arg;
    if(!e.code){struct limited *limited=calloc(1,sizeof(*limited));assert(limited);limited->inner=stream;limited->chunk=f->server.mode==0?1:512;limited->write_chunk=f->server.mode==5?512:1;stream.handle=(struct steer_pv1_backend_stream *)limited;stream.api=&limited_api;}
    f->lower_done(f->lower_userdata,e,stream,bound,peer,diagnostic);
}
static struct steer_pv1_async_start STEER_PV1_CALL shim_open(void *context,const struct steer_pv1_flow_metadata *flow,
    uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
    struct fixture *f=context;assert(flow->destination.tag==STEER_PV1_ENDPOINT_IPV4&&flow->destination.port==f->upstream_port);
    f->lower_done=done;f->lower_userdata=userdata;const struct steer_draft_stream_binding *direct=steer_draft_native_stream_binding(f->direct);
    return direct->api->open(direct->context,flow,deadline,shim_opened,f);
}
static const struct steer_pv1_stream_backend_api shim_api={sizeof(shim_api),STEER_PV1_STREAM_BACKEND_LAYOUT,shim_open};
static uint64_t deadline_ns(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec+UINT64_C(3000000000);}
static void pending(struct steer_pv1_async_start a){assert(a.disposition==STEER_PV1_PENDING&&!a.error.code&&a.operation.handle&&a.operation.api);}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,const struct steer_pv1_endpoint *bound,
    const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct result *r=arg;assert(!r->ready);r->ready=1;r->code=e.code;r->stream=stream;assert(!bound&&!peer&&diagnostic);
    assert(e.code?!stream.handle:!!stream.handle);loop_timer_set(r->f->work,0);
}
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct result *r=arg;assert(!r->ready);r->ready=1;r->code=e.code;r->bytes=bytes;
    if(r==&r->f->reading){
        assert(buffer==r->f->input);struct steer_pv1_mut_span view;assert(!ba->writable(r->f->buffers,buffer,&view).code);
        if(!e.code){assert(bytes<=5-r->f->received);assert(!memcmp(view.data+13,"reply"+r->f->received,bytes));r->f->received+=bytes;if(!bytes)r->f->eof=1;}
    }else assert(buffer==r->f->output);
    loop_timer_set(r->f->work,0);
}
static void finished(void *arg,struct steer_pv1_error e){struct result *r=arg;assert(!r->ready);r->ready=1;r->code=e.code;loop_timer_set(r->f->work,0);}
static void own_retired(void *arg){struct fixture *f=arg;assert(!f->own_finalized);f->own_finalized=1;loop_timer_set(f->work,0);}
static void direct_retired(void *arg){struct fixture *f=arg;assert(!f->direct_finalized);f->direct_finalized=1;loop_timer_set(f->work,0);}
static struct steer_pv1_error select_vless(void *arg,const struct steer_pv1_flow_metadata *flow,uint32_t *index){struct fixture *f=arg;assert(flow->destination.tag==(f->server.mode==5?STEER_PV1_ENDPOINT_IPV4:STEER_PV1_ENDPOINT_DOMAIN));*index=0;struct steer_pv1_error e={0,0};return e;}
static void release_result(struct result *r){assert(r->ready);r->operation.operation.api->release(r->operation.operation.handle);r->ready=0;}
static void start_write(struct fixture *f){struct steer_pv1_stream_ref s=f->opened.stream;f->writing.operation=s.api->write(s.handle,f->output,f->sent,3-f->sent,io_done,&f->writing);pending(f->writing.operation);}
static void start_read(struct fixture *f){struct steer_pv1_stream_ref s=f->opened.stream;f->reading.operation=s.api->read(s.handle,f->input,13,f->server.mode?16:1,io_done,&f->reading);pending(f->reading.operation);}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
    struct fixture *f=arg;struct steer_pv1_stream_ref s=f->opened.stream;(void)timer;
    switch(f->phase){
    case 0:
        f->opened.operation=steer_draft_stream_route_open(f->routes,&f->flow,deadline_ns(),opened,&f->opened);pending(f->opened.operation);
        if(f->server.mode==4)f->opened.operation.operation.api->cancel(f->opened.operation.operation.handle);
        assert(!steer_draft_vless_stream_backend_retire(f->vless).code&&!f->own_finalized);
        assert(steer_draft_vless_stream_backend_destroy(f->vless).code==STEER_PV1_POLICY_DENIED);f->phase=1;break;
    case 1:
        if(!f->opened.ready)return;
        if(f->server.mode==4){assert(f->opened.code==STEER_PV1_CANCELLED);f->phase=5;loop_timer_set(f->work,0);break;}
        assert(!f->opened.code&&(s.api->capabilities(s.handle)&STEER_PV1_STREAM_CAP_HALF_CLOSE));start_write(f);
        {struct steer_pv1_async_start rejected_finish=s.api->finish_write(s.handle,finished,&f->finish);assert(rejected_finish.disposition==STEER_PV1_REJECTED&&rejected_finish.error.code==STEER_PV1_POLICY_DENIED);}
        f->phase=2;break;
    case 2:
        if(!f->writing.ready)return;
        assert(!f->writing.code&&f->writing.bytes&&f->writing.bytes<=3-f->sent);f->sent+=f->writing.bytes;
        if(!f->first_write.handle){f->first_write=f->writing.operation.operation;f->writing.ready=0;}else release_result(&f->writing);
        if(f->sent<3){start_write(f);break;}
        if(f->server.mode!=5){
            f->finish.operation=s.api->finish_write(s.handle,finished,&f->finish);pending(f->finish.operation);
            struct steer_pv1_async_start rejected_write=s.api->write(s.handle,f->output,0,1,io_done,&f->writing);assert(rejected_write.disposition==STEER_PV1_REJECTED&&rejected_write.error.code==STEER_PV1_POLICY_DENIED);
        }
        start_read(f);f->phase=3;break;
    case 3:
        if(f->server.mode==5&&f->received==5&&!f->finish.operation.operation.handle){
            f->finish.operation=s.api->finish_write(s.handle,finished,&f->finish);pending(f->finish.operation);
        }
        if(f->reading.ready){
            if(f->server.mode==2||f->server.mode==3){assert(f->reading.code==STEER_PV1_PROTOCOL&&!f->reading.bytes);f->eof=1;}
            else assert(!f->reading.code);
            if(!f->eof){release_result(&f->reading);start_read(f);}
        }
        if(!f->eof||!f->finish.ready)return;
        if(f->server.mode<2||f->server.mode==5)assert(f->received==5&&!f->finish.code);
        s.api->close(s.handle);s.api->close(s.handle);assert(s.api->release(s.handle).code==STEER_PV1_POLICY_DENIED);
        release_result(&f->reading);release_result(&f->finish);f->first_write.api->release(f->first_write.handle);
        assert(!s.api->release(s.handle).code);f->phase=5;
        /* fall through */
    case 5:
        release_result(&f->opened);assert(!steer_draft_stream_routes_destroy(f->routes).code);f->routes=NULL;f->phase=6;break;
    case 6:
        if(!f->own_finalized)return;
        assert(!steer_draft_vless_stream_quarantined(f->vless));assert(!steer_draft_vless_stream_backend_destroy(f->vless).code);f->vless=NULL;
        assert(!steer_draft_native_stream_backend_retire(f->direct).code);f->phase=7;break;
    case 7:
        if(!f->direct_finalized)return;
        assert(!steer_draft_native_stream_backend_destroy(f->direct).code);assert(!steer_draft_backend_runtime_destroy(f->wrapper).code);
        assert(!steer_draft_stream_runtime_destroy(f->native).code);f->phase=8;loop_stop(loop,0);break;
    default:assert(0);
    }
}
static void watchdog(struct loop *loop,struct loop_timer *timer,void *arg){(void)loop;(void)timer;(void)arg;assert(!"vless backend watchdog");}
static void run(int mode,uint16_t external_port){
    struct fixture f={0};f.server.mode=mode;f.server.fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);assert(f.server.fd>=0);
    struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(!bind(f.server.fd,(struct sockaddr *)&address,sizeof(address))&&!listen(f.server.fd,4));socklen_t size=sizeof(address);assert(!getsockname(f.server.fd,(struct sockaddr *)&address,&size));f.server.port=ntohs(address.sin_port);
    f.upstream_port=external_port?external_port:f.server.port;
    assert(!pthread_create(&f.worker,NULL,serve,&f.server));f.loop=loop_new();assert(f.loop);
    struct steer_draft_buffer_limits limits={65536,32,1};assert(!steer_draft_buffers_create(&limits,NULL,&f.buffers).code);ba=steer_draft_buffers_api();
    assert(!steer_draft_stream_runtime_create(f.loop,f.buffers,4,16,65536,&f.native).code);
    assert(!steer_draft_backend_runtime_create(f.loop,4,16,65536,&f.wrapper).code);
    assert(!steer_draft_native_stream_backend_create(f.loop,f.native,f.wrapper,NULL,7,1,4,64,direct_retired,&f,&f.direct).code);
    f.lower=*steer_draft_native_stream_binding(f.direct);f.lower.api=&shim_api;f.lower.context=&f;
    uint8_t ip[4]={127,0,0,1};struct steer_pv1_endpoint upstream={sizeof(upstream),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},f.upstream_port,0};
    assert(!steer_draft_vless_stream_backend_create(f.loop,f.buffers,&f.lower,&upstream,uuid,7,2,2,16,65536,64,own_retired,&f,&f.vless).code);
    assert(!steer_draft_stream_routes_create(f.loop,7,2,2,steer_draft_vless_stream_binding(f.vless),1,select_vless,&f,NULL,&f.routes).code);
    f.flow.size=sizeof(f.flow);f.flow.version=STEER_PV1_DRAFT_LAYOUT;f.flow.generation=7;f.flow.flow_class=STEER_PV1_FLOW_STREAM;
    f.flow.inbound_id=(struct steer_pv1_span){(const uint8_t *)"test",4};f.flow.source=upstream;f.flow.source.port=1234;
    f.flow.destination=upstream;f.flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;f.flow.destination.address=(struct steer_pv1_span){(const uint8_t *)"destination.example",19};f.flow.destination.port=443;
    if(mode==5){f.flow.destination=upstream;f.flow.destination.port=f.server.port;}
    assert(!ba->allocate(f.buffers,64,&f.input).code&&!ba->allocate(f.buffers,64,&f.output).code);struct steer_pv1_mut_span view;assert(!ba->writable(f.buffers,f.output,&view).code);memcpy(view.data,"abc",3);
    f.opened.f=f.reading.f=f.writing.f=f.finish.f=&f;f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);assert(f.work&&f.watchdog);
    loop_timer_set(f.work,0);loop_timer_set(f.watchdog,5000);assert(!loop_run(f.loop)&&f.phase==8);
    assert(!pthread_join(f.worker,NULL));close(f.server.fd);ba->release(f.buffers,f.input);ba->release(f.buffers,f.output);assert(!steer_draft_buffers_destroy(f.buffers).code);
    loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
}
int main(int argc,char **argv){
    ba=steer_draft_buffers_api();
    if(argc==2){char *end;unsigned long port=strtoul(argv[1],&end,10);assert(*argv[1]&&!*end&&port&&port<=65535);run(5,(uint16_t)port);puts("vless origin backend via external upstream: plain TCP target echo PASS");}
    else {assert(argc==1);for(int mode=0;mode<5;mode++)run(mode,0);puts("vless origin backend: partial headers/body, coalesced tail, FIN response, malformed/truncated EOF, cancel and generation drain PASS");}
    return 0;
}
