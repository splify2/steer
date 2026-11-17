#define _GNU_SOURCE
#include "tls_stream_backend.h"
#include "vless_stream_backend.h"
#include "native_stream_backend.h"
#include "buffers.h"
#include "loop.h"
#include "tls_stream_faults.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct fixture;
struct result {struct fixture *f;struct steer_pv1_async_start start;struct steer_pv1_stream_ref stream;uint32_t code,bytes;int ready;};
struct fixture {
    struct fixture *parent,*children;
    struct loop *loop;struct loop_timer *work,*watchdog;
    struct steer_pv1_host *buffers;const struct steer_pv1_buffer_api *ba;
    struct steer_draft_stream_runtime *native;struct steer_draft_backend_runtime *wrapper;
    struct steer_draft_native_stream_backend *direct;struct steer_draft_tls_stream_backend *tls;
    struct steer_draft_vless_stream_backend *vless;struct steer_draft_stream_routes *routes;
    struct steer_draft_host_worker *worker;struct cert_trust *roots;
    struct tls_probe_fault *fault;const char *fault_name;unsigned recovery_attempts;
    struct steer_draft_stream_binding lower;
    struct steer_pv1_flow_metadata flow;struct steer_pv1_buffer *input,*output;
    struct result opened,reading,writing,finish;struct steer_pv1_operation_ref first_write;
    unsigned phase,sent,received,request_length,expected_length;uint32_t expected_error;
    unsigned char expected[256];unsigned chunk,lower_finishes,lower_releases;
    int half,raw,no_lower_finish,concurrent,cancel_open,cancel_issued,fault_released,eof,vless_final,tls_final,direct_final,worker_final;
};
struct limited {struct steer_pv1_stream_ref inner;struct fixture *f;};
struct limited_open {struct fixture *f;steer_pv1_stream_open_done done;void *userdata;struct steer_pv1_operation_ref inner;int completed;};
static uint64_t STEER_PV1_CALL limited_caps(const struct steer_pv1_backend_stream *opaque){const struct limited *l=(const struct limited *)opaque;return l->f->no_lower_finish?0:l->inner.api->capabilities(l->inner.handle);}
static struct steer_pv1_async_start STEER_PV1_CALL limited_read(struct steer_pv1_backend_stream *opaque,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *arg){struct limited *l=(struct limited *)opaque;if(length>l->f->chunk)length=l->f->chunk;return l->inner.api->read(l->inner.handle,buffer,offset,length,done,arg);}
static struct steer_pv1_async_start STEER_PV1_CALL limited_write(struct steer_pv1_backend_stream *opaque,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *arg){struct limited *l=(struct limited *)opaque;if(length>l->f->chunk)length=l->f->chunk;return l->inner.api->write(l->inner.handle,buffer,offset,length,done,arg);}
static struct steer_pv1_async_start STEER_PV1_CALL limited_finish(struct steer_pv1_backend_stream *opaque,steer_pv1_backend_finish_done done,void *arg){struct limited *l=(struct limited *)opaque;l->f->lower_finishes++;if(l->f->no_lower_finish){struct steer_pv1_async_start rejected={STEER_PV1_REJECTED,{STEER_PV1_UNSUPPORTED,0},{NULL,NULL}};return rejected;}return l->inner.api->finish_write(l->inner.handle,done,arg);}
static void STEER_PV1_CALL limited_close(struct steer_pv1_backend_stream *opaque){struct limited *l=(struct limited *)opaque;l->inner.api->close(l->inner.handle);}
static struct steer_pv1_error STEER_PV1_CALL limited_release(struct steer_pv1_backend_stream *opaque){
    struct limited *l=(struct limited *)opaque;l->f->lower_releases++;
    if(l->f->fault_name&&!strcmp(l->f->fault_name,"lower-release")&&l->f->lower_releases==1){tls_probe_fault_mark(l->f->fault);struct steer_pv1_error refused={STEER_PV1_POLICY_DENIED,0};return refused;}
    struct steer_pv1_error e=l->inner.api->release(l->inner.handle);if(!e.code)free(l);return e;
}
static const struct steer_pv1_backend_stream_api limited_api={sizeof(limited_api),STEER_PV1_STREAM_BACKEND_LAYOUT,limited_caps,limited_read,limited_write,limited_finish,limited_close,limited_release};
static void STEER_PV1_CALL cancel_lower_open(struct steer_pv1_operation *opaque){struct limited_open *o=(struct limited_open *)opaque;o->inner.api->cancel(o->inner.handle);}
static void STEER_PV1_CALL release_lower_open(struct steer_pv1_operation *opaque){struct limited_open *o=(struct limited_open *)opaque;assert(o->completed);o->inner.api->release(o->inner.handle);free(o);}
static const struct steer_pv1_operation_api lower_operation_api={sizeof(lower_operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_lower_open,release_lower_open};
static void lower_opened(void *arg,struct steer_pv1_error error,struct steer_pv1_stream_ref stream,const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct limited_open *o=arg;if(!error.code){tls_probe_fault_lower(o->f->fault,stream);struct limited *l=malloc(sizeof(*l));assert(l);l->inner=stream;l->f=o->f;stream.handle=(struct steer_pv1_backend_stream *)l;stream.api=&limited_api;}
    o->done(o->userdata,error,stream,bound,peer,diagnostic);o->completed=1;
}
static struct steer_pv1_async_start STEER_PV1_CALL lower_open(void *arg,const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
    struct fixture *f=arg;struct limited_open *o=calloc(1,sizeof(*o));assert(o);o->f=f;o->done=done;o->userdata=userdata;
    const struct steer_draft_stream_binding *native=steer_draft_native_stream_binding(f->direct);
    struct steer_pv1_async_start start=native->api->open(native->context,flow,deadline,lower_opened,o);
    if(start.disposition==STEER_PV1_PENDING){o->inner=start.operation;start.operation=(struct steer_pv1_operation_ref){(struct steer_pv1_operation *)o,&lower_operation_api};}
    else free(o);
    return start;
}
static const struct steer_pv1_stream_backend_api lower_api={sizeof(lower_api),STEER_PV1_STREAM_BACKEND_LAYOUT,lower_open};
static uint64_t deadline_ns(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec+UINT64_C(8000000000);}
static void pending(struct steer_pv1_async_start start){assert(start.disposition==STEER_PV1_PENDING&&!start.error.code&&start.operation.handle&&start.operation.api);}
static void opened(void *arg,struct steer_pv1_error error,struct steer_pv1_stream_ref stream,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct result *r=arg;assert(!r->ready&&!bound&&!peer&&diagnostic);
    assert(error.code?!stream.handle:!!stream.handle);r->ready=1;r->code=error.code;r->stream=stream;loop_timer_set(r->f->work,0);
}
static void io_done(void *arg,struct steer_pv1_error error,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct result *r=arg;struct fixture *f=r->f;assert(!r->ready);r->ready=1;r->code=error.code;r->bytes=bytes;
    if(r==&f->reading){
        assert(buffer==f->input);struct steer_pv1_mut_span span;assert(!f->ba->writable(f->buffers,buffer,&span).code);
        if(!error.code){assert(bytes<=f->expected_length-f->received);assert(!memcmp(span.data+11,f->expected+f->received,bytes));f->received+=bytes;if(!bytes)f->eof=1;}
    }else assert(buffer==f->output);
    loop_timer_set(f->work,0);
}
static void finished(void *arg,struct steer_pv1_error error){struct result *r=arg;assert(!r->ready);r->ready=1;r->code=error.code;loop_timer_set(r->f->work,0);}
static void vless_final(void *arg){struct fixture *f=arg;f->vless_final=1;loop_timer_set(f->work,0);}
static void tls_final(void *arg){struct fixture *f=arg;f->tls_final=1;loop_timer_set(f->work,0);}
static void direct_final(void *arg){struct fixture *f=arg;f->direct_final=1;loop_timer_set(f->work,0);}
static void worker_final(void *arg){struct fixture *f=arg;f->worker_final=1;loop_timer_set(f->work,0);}
static void fault_wake(void *arg){struct fixture *f=arg;loop_timer_set(f->work,0);}
static struct steer_pv1_error select_binding(void *arg,const struct steer_pv1_flow_metadata *flow,uint32_t *index){(void)arg;assert(flow->generation==7);*index=0;struct steer_pv1_error e={0,0};return e;}
static void release_result(struct result *r){assert(r->ready);r->start.operation.api->release(r->start.operation.handle);r->ready=0;}
static void start_write(struct fixture *f){struct steer_pv1_stream_ref s=f->opened.stream;f->writing.start=s.api->write(s.handle,f->output,f->sent,f->request_length-f->sent,io_done,&f->writing);pending(f->writing.start);}
static void start_read(struct fixture *f){struct steer_pv1_stream_ref s=f->opened.stream;f->reading.start=s.api->read(s.handle,f->input,11,7,io_done,&f->reading);pending(f->reading.start);}
static void start_finish(struct fixture *f){struct steer_pv1_stream_ref s=f->opened.stream;f->finish.start=s.api->finish_write(s.handle,finished,&f->finish);pending(f->finish.start);}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
    struct fixture *f=arg;struct steer_pv1_stream_ref s=f->opened.stream;(void)timer;
    switch(f->phase){
    case 0:
        f->opened.start=steer_draft_stream_route_open(f->routes,&f->flow,deadline_ns(),opened,&f->opened);pending(f->opened.start);
        if(f->cancel_open)f->opened.start.operation.api->cancel(f->opened.start.operation.handle);
        if(!f->parent){
            if(f->vless)assert(!steer_draft_vless_stream_backend_retire(f->vless).code);
            assert(!steer_draft_tls_stream_backend_retire(f->tls).code&&!f->tls_final);
        }
        f->phase=1;break;
    case 1:
        if(!f->parent&&tls_probe_fault_blocked(f->fault)&&!f->cancel_issued){
            assert(!f->opened.ready);f->cancel_issued=1;f->opened.start.operation.api->cancel(f->opened.start.operation.handle);
        }
        if(!f->opened.ready)return;
        if(f->expected_error){assert(f->opened.code==f->expected_error&&!s.handle);f->phase=5;loop_timer_set(f->work,0);break;}
        assert(!f->opened.code&&(s.api->capabilities(s.handle)&STEER_PV1_STREAM_CAP_HALF_CLOSE));
        start_write(f);
        {struct steer_pv1_async_start finish=s.api->finish_write(s.handle,finished,&f->finish);assert(finish.disposition==STEER_PV1_REJECTED&&finish.error.code==STEER_PV1_POLICY_DENIED);}
        f->phase=2;break;
    case 2:
        if(!f->writing.ready)return;
        assert(!f->writing.code&&f->writing.bytes&&f->writing.bytes<=f->request_length-f->sent);f->sent+=f->writing.bytes;
        if(!f->first_write.handle){f->first_write=f->writing.start.operation;f->writing.ready=0;}else release_result(&f->writing);
        if(f->sent<f->request_length){start_write(f);break;}
        if(f->half)start_finish(f);
        start_read(f);f->phase=3;break;
    case 3:
        if(f->reading.ready){
            assert(!f->reading.code);
            if(!f->eof&&(f->received<f->expected_length||f->half)){release_result(&f->reading);start_read(f);}
        }
        if(!f->half&&f->received==f->expected_length&&!f->finish.start.operation.handle)start_finish(f);
        if(f->received!=f->expected_length||(f->half&&!f->eof)||!f->finish.ready)return;
        assert(!f->finish.code);
        s.api->close(s.handle);assert(s.api->release(s.handle).code==STEER_PV1_POLICY_DENIED);
        release_result(&f->reading);release_result(&f->finish);f->first_write.api->release(f->first_write.handle);
        assert(!s.api->release(s.handle).code);f->phase=5;
        /* fall through */
    case 5:
        release_result(&f->opened);
        if(f->parent){
            f->ba->release(f->buffers,f->input);f->ba->release(f->buffers,f->output);f->input=f->output=NULL;
            f->phase=9;loop_timer_set(f->parent->work,0);break;
        }
        assert(!steer_draft_stream_routes_destroy(f->routes).code);f->routes=NULL;f->phase=6;
        if(!f->vless){f->phase=7;loop_timer_set(f->work,0);}break;
    case 6:
        if(!f->vless_final)return;
        assert(!steer_draft_vless_stream_backend_destroy(f->vless).code);f->vless=NULL;f->phase=7;loop_timer_set(f->work,0);break;
    case 7:
        if(tls_probe_fault_blocked(f->fault)&&!f->fault_released){
            assert(!f->tls_final&&steer_draft_tls_stream_backend_destroy(f->tls).code==STEER_PV1_POLICY_DENIED);
            uint32_t jobs=0;steer_draft_host_worker_usage(f->worker,&jobs,NULL);assert(jobs);
            tls_probe_fault_unblock(f->fault);f->fault_released=1;
        }
        if(steer_draft_tls_stream_quarantined(f->tls)){
            assert(f->fault_name&&(!strcmp(f->fault_name,"refuse-job")||!strcmp(f->fault_name,"lower-release"))&&!f->tls_final);
            uint32_t recovered=0;struct steer_pv1_error e=steer_draft_tls_stream_recover(f->tls,&recovered);
            assert(e.code==0||e.code==STEER_PV1_POLICY_DENIED);assert(++f->recovery_attempts<=64);
            if(!recovered){loop_timer_set(f->work,1);return;}
            assert(recovered==1);
        }
        if(!f->tls_final)return;
        assert(!steer_draft_tls_stream_quarantined(f->tls));assert(!steer_draft_tls_stream_backend_destroy(f->tls).code);f->tls=NULL;
        assert(!steer_draft_native_stream_backend_retire(f->direct).code);steer_draft_host_worker_stop(f->worker);f->phase=8;break;
    case 8:
        if(!f->direct_final||!f->worker_final)return;
        assert(!steer_draft_native_stream_backend_destroy(f->direct).code);
        assert(!steer_draft_host_worker_destroy(f->worker).code);
        assert(!steer_draft_backend_runtime_destroy(f->wrapper).code&&!steer_draft_stream_runtime_destroy(f->native).code);
        f->phase=9;loop_stop(loop,0);break;
    case 20:
        for(unsigned i=0;i<5;i++)step(loop,NULL,&f->children[i]);
        if(f->vless)assert(!steer_draft_vless_stream_backend_retire(f->vless).code);
        assert(!steer_draft_tls_stream_backend_retire(f->tls).code);f->phase=21;break;
    case 21:
        if(tls_probe_fault_blocked(f->fault)&&!f->cancel_issued){
            for(unsigned i=1;i<5;i++)if(f->children[i].phase!=9)return;
            struct fixture *held=&f->children[0];assert(!held->opened.ready&&held->phase==1);
            held->expected_error=STEER_PV1_CANCELLED;held->opened.start.operation.api->cancel(held->opened.start.operation.handle);f->cancel_issued=1;
        }
        for(unsigned i=0;i<5;i++)if(f->children[i].phase!=9)return;
        assert(!steer_draft_stream_routes_destroy(f->routes).code);f->routes=NULL;
        f->phase=f->vless?6:7;loop_timer_set(f->work,0);break;
    default:assert(0);
    }
}
static void watchdog(struct loop *loop,struct loop_timer *timer,void *arg){(void)loop;(void)timer;struct fixture *f=arg;fprintf(stderr,"TLS origin watchdog phase=%u sent=%u got=%u\n",f->phase,f->sent,f->received);assert(!"TLS origin watchdog");}
static struct cert_trust *prepare_roots(void){
    const char *path=getenv("STEER_TEST_ROOTS");assert(path);FILE *file=fopen(path,"rb");assert(file);
    assert(!fseek(file,0,SEEK_END));long length=ftell(file);assert(length>0&&length<=8*1024*1024);rewind(file);
    unsigned char *pem=malloc((size_t)length);assert(pem);assert(fread(pem,1,(size_t)length,file)==(size_t)length);assert(!fclose(file));
    struct cert_trust *roots=NULL;assert(!cert_trust_prepare_pem(pem,(size_t)length,&roots));memset(pem,0,(size_t)length);free(pem);return roots;
}
static int run(int argc,char **argv){
    if(argc<5||strcmp(argv[2],"tcp"))return 2;
    unsigned long port=strtoul(argv[1],NULL,10),target=strtoul(argv[3],NULL,10);size_t payload=strlen(argv[4]);assert(port&&port<=65535&&target&&target<=65535&&payload<128);
    struct fixture f={0};f.half=argc>5&&!strcmp(argv[5],"halfclose");f.raw=getenv("STEER_TEST_TLS_DIRECT")!=NULL;
    f.concurrent=getenv("STEER_TLS_CONCURRENT")!=NULL;
    f.fault_name=getenv("STEER_TLS_FAULT");
    if(getenv("STEER_TEST_CANCEL_AUTH"))return 2; /* use the engine fixture until adapter barrier mode is installed */
    const char *chunk=getenv("STEER_TLS_CHUNK");f.chunk=chunk?(unsigned)strtoul(chunk,NULL,10):16384;assert(f.chunk&&f.chunk<=16384);
    f.no_lower_finish=getenv("STEER_TLS_LOWER_NO_FINISH")!=NULL;
    const char *expected=getenv("STEER_TEST_ENGINE_ERROR");if(expected)f.expected_error=atoi(expected)==-22?STEER_PV1_AUTH_FAILED:STEER_PV1_RESOURCE_EXHAUSTED;
    assert(!f.concurrent||!f.expected_error);
    if(f.fault_name){
        assert(!f.concurrent||!strcmp(f.fault_name,"pause-prepare"));
        if(!strncmp(f.fault_name,"flags-",6))f.expected_error=STEER_PV1_INTERNAL;
        else if(!strncmp(f.fault_name,"pause-",6)){if(!f.concurrent)f.expected_error=STEER_PV1_CANCELLED;}
        else if(!strcmp(f.fault_name,"refuse-job"))f.expected_error=STEER_PV1_PROTOCOL;
        else if(!strcmp(f.fault_name,"close-ready")){f.expected_error=STEER_PV1_POLICY_DENIED;f.raw=1;}
    }
    f.roots=prepare_roots();f.loop=loop_new();assert(f.loop);f.ba=steer_draft_buffers_api();
    f.fault=tls_probe_fault_create(f.loop,f.fault_name,fault_wake,&f);tls_probe_fault_enter(f.fault);
    struct steer_draft_buffer_limits buffers={1048576,64,1};assert(!steer_draft_buffers_create(&buffers,NULL,&f.buffers).code);
    assert(!steer_draft_stream_runtime_create(f.loop,f.buffers,8,128,262144,&f.native).code);
    assert(!steer_draft_backend_runtime_create(f.loop,8,128,262144,&f.wrapper).code);
    assert(!steer_draft_native_stream_backend_create(f.loop,f.native,f.wrapper,NULL,7,1,16,512,direct_final,&f,&f.direct).code);
    f.lower=*steer_draft_native_stream_binding(f.direct);f.lower.api=&lower_api;f.lower.context=&f;
    struct steer_draft_host_worker_limits worker={2,16,65536,262144};assert(!steer_draft_host_worker_create(f.loop,&worker,&f.worker).code);
    assert(!steer_draft_host_worker_on_drained(f.worker,worker_final,&f).code);
    const char *name=getenv("STEER_TEST_NAME");if(!name)name="localhost";
    struct steer_draft_tls_stream_profile profile={.kind=STEER_DRAFT_TLS13_STANDARD_X25519,
        .server_name={(const uint8_t *)name,strlen(name)},.roots=f.roots,.engine={64,4,40960,40960}};
    const char *limit=getenv("STEER_TEST_ENGINE_LIMIT");
    if(limit&&!strcmp(limit,"records"))profile.engine.max_records=1;
    if(limit&&!strcmp(limit,"messages"))profile.engine.max_messages=1;
    if(limit&&!strcmp(limit,"certificate"))profile.engine.max_certificate=4;
    struct steer_draft_tls_stream_limits limits={8,64,4,512,262144,2097152};
    if(f.fault_name&&!strcmp(f.fault_name,"close-ready"))limits.max_operations=67;
    assert(!steer_draft_tls_stream_backend_create(f.loop,f.buffers,f.worker,&f.lower,&profile,&limits,7,2,tls_final,&f,&f.tls).code);
    uint8_t ip[4]={127,0,0,1},uuid[16]={0};uuid[15]=1;
    struct steer_pv1_endpoint upstream={sizeof(upstream),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},(uint16_t)port,0};
    const struct steer_draft_stream_binding *binding=steer_draft_tls_stream_binding(f.tls);
    if(!f.raw){assert(!steer_draft_vless_stream_backend_create(f.loop,f.buffers,binding,&upstream,uuid,7,3,8,64,262144,512,vless_final,&f,&f.vless).code);binding=steer_draft_vless_stream_binding(f.vless);}
    assert(!steer_draft_stream_routes_create(f.loop,7,16,8,binding,1,select_binding,&f,NULL,&f.routes).code);
    f.flow.size=sizeof(f.flow);f.flow.version=STEER_PV1_DRAFT_LAYOUT;f.flow.generation=7;f.flow.flow_class=STEER_PV1_FLOW_STREAM;
    f.flow.inbound_id=(struct steer_pv1_span){(const uint8_t *)"tls-test",8};f.flow.source=upstream;f.flow.source.port=1234;f.flow.destination=upstream;
    if(!f.raw)f.flow.destination.port=(uint16_t)target;
    assert(!f.ba->allocate(f.buffers,256,&f.input).code&&!f.ba->allocate(f.buffers,256,&f.output).code);
    struct steer_pv1_mut_span span;assert(!f.ba->writable(f.buffers,f.output,&span).code);
    if(f.raw){memset(span.data,0,26);span.data[16]=1;span.data[18]=1;span.data[19]=(uint8_t)(target>>8);span.data[20]=(uint8_t)target;span.data[21]=1;span.data[22]=127;span.data[25]=1;memcpy(span.data+26,argv[4],payload);f.request_length=(unsigned)payload+26;f.expected[0]=f.expected[1]=0;memcpy(f.expected+2,argv[4],payload);f.expected_length=(unsigned)payload+2;}
    else{memcpy(span.data,argv[4],payload);f.request_length=(unsigned)payload;memcpy(f.expected,argv[4],payload);f.expected_length=(unsigned)payload;}
    f.opened.f=f.reading.f=f.writing.f=f.finish.f=&f;f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);assert(f.work&&f.watchdog);
    struct fixture children[5];memset(children,0,sizeof(children));
    if(f.concurrent){
        f.children=children;f.phase=20;
        for(unsigned i=0;i<5;i++){
            struct fixture *c=&children[i];c->parent=&f;c->loop=f.loop;c->buffers=f.buffers;c->ba=f.ba;c->tls=f.tls;c->vless=f.vless;c->routes=f.routes;
            c->flow=f.flow;c->half=f.half;c->raw=f.raw;c->request_length=f.request_length;c->expected_length=f.expected_length;memcpy(c->expected,f.expected,sizeof(c->expected));
            c->expected_error=i==1?STEER_PV1_CANCELLED:i==4?STEER_PV1_RESOURCE_EXHAUSTED:0;c->cancel_open=i==1;
            assert(!c->ba->allocate(c->buffers,256,&c->input).code&&!c->ba->allocate(c->buffers,256,&c->output).code);
            struct steer_pv1_mut_span target_view;assert(!c->ba->writable(c->buffers,c->output,&target_view).code);memcpy(target_view.data,span.data,f.request_length);
            c->opened.f=c->reading.f=c->writing.f=c->finish.f=c;c->work=loop_timer_new(f.loop,step,c);assert(c->work);
        }
    }
    loop_timer_set(f.work,0);loop_timer_set(f.watchdog,12000);assert(!loop_run(f.loop)&&f.phase==9);
    if(f.concurrent)for(unsigned i=0;i<5;i++){assert(children[i].phase==9);loop_timer_free(children[i].work);}
    assert(!f.lower_finishes); /* logical TLS EOF never becomes a fabricated native FIN */
    if(f.fault_name)assert(tls_probe_fault_seen(f.fault));
    if(f.fault_name&&!strcmp(f.fault_name,"lower-release"))assert(f.lower_releases==2);
    f.ba->release(f.buffers,f.input);f.ba->release(f.buffers,f.output);assert(!steer_draft_buffers_destroy(f.buffers).code);
    tls_probe_fault_destroy(f.fault);loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);cert_trust_destroy(f.roots);
    puts(f.expected_error||f.fault_name?"origin TLS expected failure and lifecycle PASS":"origin VLESS/TLS/native shared-worker generation/half-close gate PASS");return 0;
}
struct owner {int argc,result;char **argv;};
static void *run_owner(void *arg){struct owner *o=arg;o->result=run(o->argc,o->argv);return NULL;}
int main(int argc,char **argv){
    const char *value=getenv("STEER_ENGINE_OWNERS");int owners=value?atoi(value):1;if(owners!=1&&owners!=4)return 2;
    if(owners==1)return run(argc,argv);
    pthread_t threads[4];struct owner jobs[4];
    for(int i=0;i<4;i++){jobs[i]=(struct owner){.argc=argc,.argv=argv};assert(!pthread_create(&threads[i],NULL,run_owner,&jobs[i]));}
    int result=0;for(int i=0;i<4;i++){assert(!pthread_join(threads[i],NULL));result|=jobs[i].result;}return result;
}
