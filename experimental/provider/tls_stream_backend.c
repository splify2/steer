#define _GNU_SOURCE
#include "tls_stream_backend.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include "reality.h"
#include "tls13.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#define TLS_BATCH 32u
#define TLS_STEPS 8u
#define TLS_IO_BYTES 16384u
#define TLS_HELLO_BYTES 8192u
#define TLS_PIN_BYTES 4096u
enum tls_operation_kind {TLS_OPEN,TLS_READ,TLS_WRITE,TLS_FINISH};
enum tls_job_kind {TLS_PREPARE,TLS_VERIFY};
struct tls_context;
struct tls_operation;
struct tls_public {struct tls_context *context;};
struct tls_child {
    struct steer_pv1_operation_ref operation;
    struct steer_pv1_error error;
    struct steer_pv1_buffer *returned;
    uint32_t bytes,submitted;
    int done;
};
struct tls_context {
    struct steer_draft_tls_stream_backend *backend;
    struct tls_context *next,*queue_next,*quarantine_next;
    struct tls_public *public_handle;
    struct steer_pv1_stream_ref lower;
    struct tls_child opening,reading,writing;
    struct steer_pv1_buffer *rx,*tx;
    struct tls13 *tls;
    struct tls13_engine *engine;
    void *engine_storage,*workspace;
    size_t workspace_length,rx_length,rx_offset,tx_length,tx_offset,write_remaining;
    struct tls_operation *open,*read,*write,*finish;
    struct steer_draft_host_job *job;
    struct steer_draft_host_work_result job_result;
    enum tls_job_kind job_kind;
    struct loop_timer *deadline_timer;
    uint64_t deadline,handshake_reservation;
    uint32_t exported_operations,close_code;
    int queued,closed,lower_ready,job_done,job_refused,write_barrier,finish_started,quarantined,bad_child;
    struct steer_pv1_stream_open_diagnostic diagnostic;
};
struct tls_operation {
    struct steer_draft_tls_stream_backend *backend;
    struct tls_context *context;
    struct steer_pv1_operation_ref completion;
    struct steer_pv1_buffer *buffer;
    enum tls_operation_kind kind;
    uint32_t offset,length,bytes;
    steer_pv1_stream_open_done open_done;
    steer_pv1_backend_io_done io_done;
    steer_pv1_backend_finish_done finish_done;
    void *userdata;
    int terminal,completed;
};
struct steer_draft_tls_stream_backend {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    const struct steer_pv1_buffer_api *buffer_api;
    struct steer_draft_host_worker *worker;
    struct steer_draft_stream_binding binding,lower;
    struct steer_draft_operations *operations;
    struct steer_draft_tls_stream_limits limits;
    struct tls13_engine_limits engine_limits;
    const struct cert_trust *roots;
    struct cert_policy policy;
    char name[254],alpn[16],pcs[TLS_PIN_BYTES+1],pks[TLS_PIN_BYTES+1],vcn[1025];
    unsigned char *scratch;
    size_t scratch_length,handshake_cost;
    struct tls_context *contexts,*head,*tail,*quarantine_head,*quarantine_tail;
    uint32_t streams,live,handshakes,quarantined;
    uint64_t bytes,handshake_bytes;
    int wake,dispatching,finalized;
    void (*retired)(void *);void *userdata;
};
struct tls_hello {size_t length;unsigned char bytes[TLS_HELLO_BYTES],private_key[32];};
struct tls_verify_input {uint32_t certificate,verify,transcript;unsigned char bytes[];};
static struct steer_pv1_error error(uint32_t code){struct steer_pv1_error e={code,0};return e;}
static struct steer_pv1_async_start rejected(uint32_t code){struct steer_pv1_async_start a={STEER_PV1_REJECTED,{code,0},{NULL,NULL}};return a;}
static void wipe(void *data,size_t length){volatile unsigned char *p=data;while(length--)*p++=0;}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static void notify(struct steer_draft_tls_stream_backend *b){uint64_t one=1;ssize_t n;do{n=write(b->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);}
static void enqueue(struct tls_context *c){
    if(c->queued)return;
    c->queued=1;c->queue_next=NULL;
    if(c->backend->tail)c->backend->tail->queue_next=c;else c->backend->head=c;
    c->backend->tail=c;notify(c->backend);
}
static int valid_operation(struct steer_pv1_operation_ref o){return o.handle&&o.api&&o.api->size>=sizeof(*o.api)&&o.api->version==STEER_PV1_DRAFT_LAYOUT&&o.api->cancel&&o.api->release;}
static int valid_stream(struct steer_pv1_stream_ref s){return s.handle&&s.api&&s.api->size>=sizeof(*s.api)&&s.api->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&s.api->capabilities&&s.api->read&&s.api->write&&s.api->close&&s.api->release;}
static void append_quarantine(struct tls_context *c){
    c->quarantine_next=NULL;
    if(c->backend->quarantine_tail)c->backend->quarantine_tail->quarantine_next=c;else c->backend->quarantine_head=c;
    c->backend->quarantine_tail=c;
}
static void quarantine(struct tls_context *c){if(!c->quarantined){c->quarantined=1;c->backend->quarantined++;append_quarantine(c);}}
static void close_context(struct tls_context *,uint32_t);
static void complete(struct tls_operation *,uint32_t);
static const struct steer_pv1_backend_stream_api origin_api;

static struct steer_pv1_error job_pin(void *arg){
    struct steer_draft_tls_stream_backend *b=arg;
    const struct steer_draft_binding_identity *i=steer_draft_binding_identity(b->binding.lease);
    return steer_draft_binding_pin(b->binding.lease,i->generation,STEER_PV1_FLOW_STREAM);
}
static void job_unpin(void *arg){struct steer_draft_tls_stream_backend *b=arg;(void)steer_draft_binding_unpin(b->binding.lease);}
static struct steer_draft_host_work_result prepare_hello(void *arg,const void *input,size_t length,
    uint64_t deadline,const struct steer_draft_cancel *cancel){
    struct steer_draft_tls_stream_backend *b=arg;(void)input;(void)length;
    struct steer_draft_host_work_result result={.error={STEER_PV1_CANCELLED,0}};
    if(atomic_load_explicit(&cancel->requested,memory_order_acquire))return result;
    if(now_ns()>=deadline){result.error=error(STEER_PV1_TIMEOUT);return result;}
    struct tls_hello *hello=calloc(1,sizeof(*hello));
    if(!hello){result.error=error(STEER_PV1_RESOURCE_EXHAUSTED);return result;}
    struct reality_state key;memset(&key,0,sizeof(key));
    struct reality_cfg config={.sni=b->name,.fp="chrome",.plain=1};
    int rc=reality_build_hello(&config,&key,hello->bytes,sizeof(hello->bytes),&hello->length);
    if(!rc)memcpy(hello->private_key,key.priv,32);
    wipe(&key,sizeof(key));
    if(rc||now_ns()>=deadline||atomic_load_explicit(&cancel->requested,memory_order_acquire)){
        wipe(hello,sizeof(*hello));free(hello);
        result.error=error(rc?STEER_PV1_INTERNAL:now_ns()>=deadline?STEER_PV1_TIMEOUT:STEER_PV1_CANCELLED);return result;
    }
    result.error=error(0);result.value=hello;return result;
}
static struct steer_draft_host_work_result verify_peer(void *arg,const void *input,size_t length,
    uint64_t deadline,const struct steer_draft_cancel *cancel){
    struct steer_draft_tls_stream_backend *b=arg;
    struct steer_draft_host_work_result result={.error={STEER_PV1_PROTOCOL,0}};
    if(length<sizeof(struct tls_verify_input))return result;
    const struct tls_verify_input *v=input;
    size_t needed=sizeof(*v)+(size_t)v->certificate+v->verify+v->transcript;
    if(v->certificate>b->engine_limits.max_certificate||v->verify>1024||
       (v->transcript!=32&&v->transcript!=48)||needed!=length)return result;
    if(atomic_load_explicit(&cancel->requested,memory_order_acquire)){result.error=error(STEER_PV1_CANCELLED);return result;}
    if(now_ns()>=deadline){result.error=error(STEER_PV1_TIMEOUT);return result;}
    int rc=cert_verify_server_prepared(v->bytes,v->certificate,v->bytes+v->certificate,v->verify,
        v->bytes+v->certificate+v->verify,v->transcript,b->name,b->roots,&b->policy);
    result.error=error(rc?STEER_PV1_AUTH_FAILED:STEER_PV1_OK);return result;
}
static void job_done(void *arg,struct steer_draft_host_work_result result){
    struct tls_context *c=arg;c->job_result=result;c->job_done=1;enqueue(c);
}
static void lower_open_done(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,
    const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct tls_context *c=arg;(void)bound;(void)peer;c->opening.error=e;c->opening.done=1;c->lower=stream;
    if(diagnostic&&diagnostic->size>=sizeof(*diagnostic)&&diagnostic->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&diagnostic->dial_failure<=STEER_PV1_STREAM_DIAL_OTHER){c->diagnostic=*diagnostic;c->diagnostic.size=sizeof(c->diagnostic);}
    if(c->closed&&valid_stream(stream))stream.api->close(stream.handle);
    enqueue(c);
}
static void lower_read_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct tls_context *c=arg;c->reading.error=e;c->reading.returned=buffer;c->reading.bytes=bytes;c->reading.done=1;enqueue(c);
}
static void lower_write_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct tls_context *c=arg;c->writing.error=e;c->writing.returned=buffer;c->writing.bytes=bytes;c->writing.done=1;enqueue(c);
}
static void STEER_PV1_CALL cancel_operation(struct steer_pv1_operation *opaque){
    struct tls_operation *op=(struct tls_operation *)opaque;
    if(op->terminal)return;
    if(op->kind==TLS_READ){complete(op,STEER_PV1_CANCELLED);return;}
    if(op->kind==TLS_WRITE&&!op->bytes){complete(op,STEER_PV1_CANCELLED);return;}
    close_context(op->context,STEER_PV1_CANCELLED);
}
static void STEER_PV1_CALL release_operation(struct steer_pv1_operation *opaque){
    struct tls_operation *op=(struct tls_operation *)opaque;if(!op->completed)return;
    struct steer_draft_tls_stream_backend *b=op->backend;
    op->completion.api->release(op->completion.handle);
    if(op->context){op->context->exported_operations--;enqueue(op->context);}
    b->live--;free(op);(void)steer_draft_binding_unpin(b->binding.lease);
}
static const struct steer_pv1_operation_api operation_api={sizeof(operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_operation,release_operation};
static void delivered(void *arg,struct steer_pv1_error e){
    struct tls_operation *op=arg;struct steer_draft_tls_stream_backend *b=op->backend;struct tls_context *c=op->context;
    b->bytes-=op->length;
    if(op->kind==TLS_OPEN){
        struct steer_pv1_stream_ref result={NULL,NULL};
        if(!e.code&&c->closed)e=error(c->close_code?c->close_code:STEER_PV1_CANCELLED);
        if(!e.code&&now_ns()>=c->deadline){e=error(STEER_PV1_TIMEOUT);close_context(c,STEER_PV1_TIMEOUT);}
        if(!e.code){result.handle=(struct steer_pv1_backend_stream *)c->public_handle;result.api=&origin_api;}
        else if(c->public_handle){free(c->public_handle);c->public_handle=NULL;}
        c->exported_operations--;op->context=NULL;enqueue(c);
        op->open_done(op->userdata,e,result,NULL,NULL,&c->diagnostic);
    }else{
        if(op->kind==TLS_READ)c->read=NULL;else if(op->kind==TLS_WRITE)c->write=NULL;else c->finish=NULL;
        if(op->kind==TLS_FINISH)op->finish_done(op->userdata,e);
        else{struct steer_pv1_buffer *buffer=op->buffer;op->buffer=NULL;op->io_done(op->userdata,e,buffer,e.code?0:op->bytes);}
    }
    op->completed=1;
}
static struct tls_operation *new_operation(struct steer_draft_tls_stream_backend *b,struct tls_context *c,enum tls_operation_kind kind){
    if(b->live>=b->limits.max_operations)return NULL;
    const struct steer_draft_binding_identity *i=steer_draft_binding_identity(b->binding.lease);
    if(steer_draft_binding_pin(b->binding.lease,i->generation,STEER_PV1_FLOW_STREAM).code)return NULL;
    struct tls_operation *op=calloc(1,sizeof(*op));if(!op)goto fail;
    struct steer_pv1_async_start a=steer_draft_operation_start(b->operations,delivered,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);goto fail;}
    op->backend=b;op->context=c;op->kind=kind;op->completion=a.operation;b->live++;c->exported_operations++;return op;
fail:(void)steer_draft_binding_unpin(b->binding.lease);return NULL;
}
static struct steer_pv1_async_start exported(struct tls_operation *op){struct steer_pv1_async_start a={STEER_PV1_PENDING,{0,0},{(struct steer_pv1_operation *)op,&operation_api}};return a;}
static void complete(struct tls_operation *op,uint32_t code){
    if(!op||op->terminal)return;
    op->terminal=1;
    if(op->kind==TLS_OPEN){
        if(!code&&now_ns()>=op->context->deadline)code=STEER_PV1_TIMEOUT;
        if(op->context->deadline_timer){loop_timer_free(op->context->deadline_timer);op->context->deadline_timer=NULL;}
        op->context->open=NULL;
    }
    (void)steer_draft_operation_resolve(op->completion.handle,error(code));notify(op->backend);
}
static uint32_t tls_error(int code){
    if(code==TLS13_ECERT)return STEER_PV1_AUTH_FAILED;
    if(code==TLS13_EIO||code==TLS13_ECLOSED)return STEER_PV1_IO;
    if(code==TLS13_ETOOBIG)return STEER_PV1_RESOURCE_EXHAUSTED;
    if(code==TLS13_ECRYPTO)return STEER_PV1_INTERNAL;
    return STEER_PV1_PROTOCOL;
}
static int valid_error(struct steer_pv1_error e){return e.code<=STEER_PV1_INTERNAL&&e.transient<=1&&(e.code||!e.transient);}
static void free_hello(void *value){if(value){wipe(value,sizeof(struct tls_hello));free(value);}}
static void discard_job_result(struct tls_context *c){
    if(c->job_kind==TLS_PREPARE)free_hello(c->job_result.value);
    else if(c->job_result.value){c->bad_child=1;quarantine(c);}
    c->job_result.value=NULL;
}
static void release_handshake(struct tls_context *c){
    if(!c->handshake_reservation||c->job)return;
    if(!c->closed&&(!c->engine||tls13_engine_workspace_in_use(c->engine)))return;
    if(c->workspace){wipe(c->workspace,c->workspace_length);free(c->workspace);c->workspace=NULL;}
    c->backend->handshake_bytes-=c->handshake_reservation;c->handshake_reservation=0;
    c->backend->handshakes--;
}
static void close_context(struct tls_context *c,uint32_t code){
    if(c->closed)return;
    {
        c->closed=1;c->close_code=code;
        if(c->deadline_timer){loop_timer_free(c->deadline_timer);c->deadline_timer=NULL;}
        if(c->engine){tls13_engine_destroy(c->engine);c->engine=NULL;}
        free(c->engine_storage);c->engine_storage=NULL;free(c->tls);c->tls=NULL;
        if(c->workspace){wipe(c->workspace,c->workspace_length);free(c->workspace);c->workspace=NULL;}
        if(c->job)steer_draft_host_job_cancel(c->job);
        if(valid_operation(c->opening.operation))c->opening.operation.api->cancel(c->opening.operation.handle);
        if(valid_operation(c->reading.operation))c->reading.operation.api->cancel(c->reading.operation.handle);
        if(valid_operation(c->writing.operation))c->writing.operation.api->cancel(c->writing.operation.handle);
        if(valid_stream(c->lower))c->lower.api->close(c->lower.handle);
    }
    complete(c->open,code);complete(c->read,code);complete(c->write,code);complete(c->finish,code);
    enqueue(c);
}
static int collect_context(struct tls_context *c,int recovery,uint32_t *budget){
    struct steer_draft_tls_stream_backend *b=c->backend;
    if(!c->closed||c->public_handle||c->exported_operations||c->queued||c->bad_child)return 0;
    if(c->opening.operation.handle||c->reading.operation.handle||c->writing.operation.handle)return 0;
    if(c->job){
        if(!recovery||!c->job_done||!c->job_refused||!*budget)return 0;
        (*budget)--;
        if(steer_draft_host_job_release(c->job).code)return 0;
        c->job=NULL;c->job_done=c->job_refused=0;discard_job_result(c);
    }
    release_handshake(c);
    if(c->lower.handle){
        if(c->quarantined&&!recovery)return 0;
        if(!valid_stream(c->lower)){c->bad_child=1;quarantine(c);return 0;}
        if(recovery){if(!*budget)return 0;(*budget)--;}
        if(c->lower.api->release(c->lower.handle).code){quarantine(c);return 0;}
        c->lower=(struct steer_pv1_stream_ref){NULL,NULL};
    }
    if(c->rx)b->buffer_api->release(b->buffers,c->rx);
    if(c->tx)b->buffer_api->release(b->buffers,c->tx);
    struct tls_context **at=&b->contexts;while(*at&&*at!=c)at=&(*at)->next;
    if(*at)*at=c->next;
    if(c->quarantined)b->quarantined--;
    b->streams--;free(c);(void)steer_draft_binding_unpin(b->binding.lease);return 1;
}
static void arm_deadline(struct tls_context *c){
    uint64_t current=now_ns(),remaining=c->deadline>current?c->deadline-current:0;
    uint64_t ms=remaining/UINT64_C(1000000)+(remaining%UINT64_C(1000000)!=0);
    loop_timer_set(c->deadline_timer,ms>(uint64_t)LONG_MAX?LONG_MAX:(long)ms);
}
static void open_timeout(struct loop *loop,struct loop_timer *timer,void *arg){
    struct tls_context *c=arg;(void)loop;(void)timer;
    if(c->closed||!c->open)return;
    if(now_ns()<c->deadline){arm_deadline(c);return;}
    close_context(c,STEER_PV1_TIMEOUT);
}
static int start_job(struct tls_context *c,enum tls_job_kind kind,const void *input,size_t length){
    struct steer_draft_tls_stream_backend *b=c->backend;
    struct steer_draft_host_work_guard guard={b,job_pin,job_unpin};
    c->job_kind=kind;c->job_done=0;memset(&c->job_result,0,sizeof(c->job_result));
    struct steer_pv1_error e=steer_draft_host_worker_submit(b->worker,input,length,c->deadline,
        kind==TLS_PREPARE?prepare_hello:verify_peer,b,&guard,job_done,c,&c->job);
    if(e.code){close_context(c,e.code);return 0;}return 1;
}
static int initialize_engine(struct tls_context *c,struct tls_hello *hello){
    struct steer_draft_tls_stream_backend *b=c->backend;
    if(!hello||hello->length<48||hello->length>sizeof(hello->bytes))return 0;
    struct tls13_engine_options options={hello->bytes,hello->length,hello->private_key,b->engine_limits};
    if(tls13_engine_workspace_size(&options,&c->workspace_length))return 0;
    c->workspace=malloc(c->workspace_length);c->engine_storage=malloc(tls13_engine_storage_size());c->tls=malloc(sizeof(*c->tls));
    if(!c->workspace||!c->engine_storage||!c->tls)return 0;
    return !tls13_engine_init(c->engine_storage,tls13_engine_storage_size(),c->tls,c->workspace,c->workspace_length,&options,&c->engine);
}
static int consume_job(struct tls_context *c){
    if(!c->job||!c->job_done||c->job_refused)return 1;
    struct steer_pv1_error released=steer_draft_host_job_release(c->job);
    if(released.code){c->job_refused=1;discard_job_result(c);quarantine(c);close_context(c,STEER_PV1_PROTOCOL);return 0;}
    c->job=NULL;c->job_done=0;
    if(c->closed){discard_job_result(c);return 1;}
    if(!valid_error(c->job_result.error)||c->job_result.worker_flags){discard_job_result(c);close_context(c,STEER_PV1_INTERNAL);return 0;}
    if(now_ns()>=c->deadline){discard_job_result(c);close_context(c,STEER_PV1_TIMEOUT);return 0;}
    if(c->job_result.error.code){uint32_t code=c->job_result.error.code;discard_job_result(c);close_context(c,code);return 0;}
    if(c->job_kind==TLS_PREPARE){
        int initialized=initialize_engine(c,c->job_result.value);discard_job_result(c);
        if(!initialized){close_context(c,STEER_PV1_RESOURCE_EXHAUSTED);return 0;}
    }else{
        if(c->job_result.value){discard_job_result(c);close_context(c,STEER_PV1_PROTOCOL);return 0;}
        int rc=tls13_engine_auth_complete(c->engine,0);
        if(rc){close_context(c,tls_error(rc));return 0;}
    }
    return 1;
}
static void release_child(struct tls_child *child){
    child->operation.api->release(child->operation.handle);
    child->operation=(struct steer_pv1_operation_ref){NULL,NULL};child->done=0;
}
static int consume_children(struct tls_context *c){
    if(c->opening.operation.handle&&c->opening.done){
        if(!valid_operation(c->opening.operation)){c->bad_child=1;quarantine(c);close_context(c,STEER_PV1_PROTOCOL);return 0;}
        release_child(&c->opening);
        if(!c->closed){
            if(!valid_error(c->opening.error)||(!c->opening.error.code&&!valid_stream(c->lower))){close_context(c,STEER_PV1_PROTOCOL);return 0;}
            if(c->opening.error.code){close_context(c,c->opening.error.code);return 0;}
            c->lower_ready=1;
        }
    }
    if(c->reading.operation.handle&&c->reading.done){
        if(!valid_operation(c->reading.operation)||c->reading.returned!=c->rx){c->bad_child=1;quarantine(c);close_context(c,STEER_PV1_PROTOCOL);return 0;}
        release_child(&c->reading);
        if(!c->closed){
            if(!valid_error(c->reading.error)||c->reading.bytes>c->reading.submitted){close_context(c,STEER_PV1_PROTOCOL);return 0;}
            if(c->reading.error.code){close_context(c,c->reading.error.code);return 0;}
            if(!c->reading.bytes){
                int rc=tls13_engine_eof(c->engine);if(rc){close_context(c,tls_error(rc));return 0;}
            }else{c->rx_length=c->reading.bytes;c->rx_offset=0;}
        }
    }
    if(c->writing.operation.handle&&c->writing.done){
        if(!valid_operation(c->writing.operation)||c->writing.returned!=c->tx){c->bad_child=1;quarantine(c);close_context(c,STEER_PV1_PROTOCOL);return 0;}
        release_child(&c->writing);
        if(!c->closed){
            if(!valid_error(c->writing.error)||(!c->writing.error.code&&(!c->writing.bytes||c->writing.bytes>c->writing.submitted))){close_context(c,STEER_PV1_PROTOCOL);return 0;}
            if(c->writing.error.code){close_context(c,c->writing.error.code);return 0;}
            size_t bytes=c->writing.bytes;
            if(bytes>c->tx_length-c->tx_offset){close_context(c,STEER_PV1_PROTOCOL);return 0;}
            c->tx_offset+=bytes;
            if(c->tx_offset==c->tx_length)c->tx_offset=c->tx_length=0;
            if(c->write_remaining){if(bytes>c->write_remaining){close_context(c,STEER_PV1_PROTOCOL);return 0;}c->write_remaining-=bytes;}
            int rc=tls13_engine_output_consume(c->engine,bytes);if(rc){close_context(c,tls_error(rc));return 0;}
            if(c->write&&!c->write->terminal&&c->write->bytes&&!c->write_remaining)complete(c->write,0);
            if(c->finish&&!c->finish->terminal&&c->finish_started&&tls13_engine_local_finished(c->engine))complete(c->finish,0);
        }
    }
    return 1;
}
static int begin_verify(struct tls_context *c){
    struct steer_draft_tls_stream_backend *b=c->backend;
    if(b->alpn[0]&&(strlen(c->tls->alpn)!=strlen(b->alpn)||memcmp(c->tls->alpn,b->alpn,strlen(b->alpn)))){
        close_context(c,STEER_PV1_PROTOCOL);return 0;
    }
    struct tls13_engine_auth material;
    if(tls13_engine_auth_snapshot(c->engine,&material)){close_context(c,STEER_PV1_INTERNAL);return 0;}
    size_t length=sizeof(struct tls_verify_input)+material.certificate_length+material.certificate_verify_length+material.transcript_length;
    if(length>b->scratch_length||material.certificate_length>UINT32_MAX||material.certificate_verify_length>1024||material.transcript_length>48){close_context(c,STEER_PV1_PROTOCOL);return 0;}
    struct tls_verify_input *input=(struct tls_verify_input *)b->scratch;
    input->certificate=(uint32_t)material.certificate_length;input->verify=(uint32_t)material.certificate_verify_length;input->transcript=(uint32_t)material.transcript_length;
    memcpy(input->bytes,material.certificate,material.certificate_length);
    memcpy(input->bytes+material.certificate_length,material.certificate_verify,material.certificate_verify_length);
    memcpy(input->bytes+material.certificate_length+material.certificate_verify_length,material.transcript,material.transcript_length);
    int started=start_job(c,TLS_VERIFY,input,length);wipe(b->scratch,length);return started;
}
static int accept_child(struct tls_context *c,struct tls_child *child,struct steer_pv1_async_start start){
    if(start.disposition==STEER_PV1_PENDING){
        child->operation=start.operation;
        if(valid_operation(start.operation))return 1;
        c->bad_child=1;quarantine(c);close_context(c,STEER_PV1_PROTOCOL);return 0;
    }
    if(start.operation.handle){child->operation=start.operation;c->bad_child=1;quarantine(c);}
    uint32_t code=start.disposition==STEER_PV1_REJECTED&&valid_error(start.error)&&start.error.code?start.error.code:STEER_PV1_PROTOCOL;
    close_context(c,code);return 0;
}
static int send_output(struct tls_context *c){
    if(c->writing.operation.handle)return 1;
    if(c->tx_offset==c->tx_length){
        const unsigned char *bytes;size_t length;
        int rc=tls13_engine_output(c->engine,&bytes,&length);
        if(rc){close_context(c,tls_error(rc));return 0;}
        if(!length)return 1;
        if(length>TLS_IO_BYTES)length=TLS_IO_BYTES;
        struct steer_pv1_mut_span span;
        if(c->backend->buffer_api->writable(c->backend->buffers,c->tx,&span).code||span.len<length){close_context(c,STEER_PV1_INTERNAL);return 0;}
        memcpy(span.data,bytes,length);c->tx_offset=0;c->tx_length=length;
    }
    uint32_t length=(uint32_t)(c->tx_length-c->tx_offset);
    c->writing.submitted=length;c->writing.done=0;c->writing.returned=NULL;
    struct steer_pv1_async_start start=c->lower.api->write(c->lower.handle,c->tx,(uint32_t)c->tx_offset,length,lower_write_done,c);
    return accept_child(c,&c->writing,start);
}
static int start_read(struct tls_context *c){
    if(c->reading.operation.handle||c->rx_offset!=c->rx_length||tls13_engine_peer_finished(c->engine))return 1;
    enum tls13_engine_state state=tls13_engine_state(c->engine);
    if(state==TLS13_ENGINE_AUTH_PENDING||state==TLS13_ENGINE_FINISH_DRAIN)return 1;
    const unsigned char *plain;size_t length;
    int rc=tls13_engine_plaintext(c->engine,&plain,&length);
    if(!rc&&length)return 1;
    if(rc&&rc!=TLS13_EAGAIN){close_context(c,tls_error(rc));return 0;}
    c->rx_offset=c->rx_length=0;c->reading.submitted=TLS_IO_BYTES;c->reading.done=0;c->reading.returned=NULL;
    struct steer_pv1_async_start start=c->lower.api->read(c->lower.handle,c->rx,0,TLS_IO_BYTES,lower_read_done,c);
    return accept_child(c,&c->reading,start);
}
static int service_plaintext(struct tls_context *c){
    if(!c->read||c->read->terminal)return 1;
    const unsigned char *bytes;size_t length;
    int rc=tls13_engine_plaintext(c->engine,&bytes,&length);
    if(rc==TLS13_EAGAIN)return 1;
    if(rc){close_context(c,tls_error(rc));return 0;}
    if(!length){if(tls13_engine_peer_finished(c->engine))complete(c->read,0);return 1;}
    if(length>c->read->length)length=c->read->length;
    struct steer_pv1_mut_span span;
    if(c->backend->buffer_api->writable(c->backend->buffers,c->read->buffer,&span).code){close_context(c,STEER_PV1_INTERNAL);return 0;}
    memcpy(span.data+c->read->offset,bytes,length);
    rc=tls13_engine_plaintext_consume(c->engine,length);
    if(rc){close_context(c,tls_error(rc));return 0;}
    c->read->bytes=(uint32_t)length;complete(c->read,0);return 1;
}
static int service_write(struct tls_context *c){
    if(c->write&&!c->write->terminal&&!c->write->bytes){
        struct steer_pv1_mut_span span;
        if(c->backend->buffer_api->writable(c->backend->buffers,c->write->buffer,&span).code){close_context(c,STEER_PV1_INTERNAL);return 0;}
        size_t accepted=0;int rc=tls13_engine_write(c->engine,span.data+c->write->offset,c->write->length,&accepted);
        if(rc&&rc!=TLS13_EAGAIN){close_context(c,tls_error(rc));return 0;}
        if(accepted){
            const unsigned char *bytes;size_t length;
            if(tls13_engine_output(c->engine,&bytes,&length)||!length||accepted>c->write->length){close_context(c,STEER_PV1_PROTOCOL);return 0;}
            c->write->bytes=(uint32_t)accepted;c->write_remaining=length;
        }
    }
    if(c->finish&&!c->finish->terminal&&!c->finish_started){
        int rc=tls13_engine_finish_write(c->engine);
        if(rc&&rc!=TLS13_EAGAIN){close_context(c,tls_error(rc));return 0;}
        if(!rc){
            c->finish_started=1;
        }
    }
    return 1;
}
static void progress(struct tls_context *c){
    if(c->open&&!c->closed&&now_ns()>=c->deadline)close_context(c,STEER_PV1_TIMEOUT);
    (void)consume_job(c);release_handshake(c);
    if(!consume_children(c))return;
    if(c->closed){uint32_t unused=0;(void)collect_context(c,0,&unused);return;}
    if(!c->engine||!c->lower_ready)return;
    for(uint32_t step=0;step<TLS_STEPS&&!c->closed;step++){
        if(c->open&&now_ns()>=c->deadline){close_context(c,STEER_PV1_TIMEOUT);return;}
        enum tls13_engine_state state=tls13_engine_state(c->engine);
        if(state==TLS13_ENGINE_AUTH_PENDING&&!c->job){(void)begin_verify(c);break;}
        if(state==TLS13_ENGINE_READY){
            if(c->open)complete(c->open,0);
            release_handshake(c);
            if(!service_plaintext(c)||!service_write(c))return;
        }
        if(c->rx_offset==c->rx_length)break;
        struct steer_pv1_mut_span span;
        if(c->backend->buffer_api->writable(c->backend->buffers,c->rx,&span).code){close_context(c,STEER_PV1_INTERNAL);return;}
        size_t consumed=0;
        int rc=tls13_engine_feed(c->engine,span.data+c->rx_offset,c->rx_length-c->rx_offset,&consumed);
        if(consumed>c->rx_length-c->rx_offset){close_context(c,STEER_PV1_PROTOCOL);return;}
        c->rx_offset+=consumed;
        if(rc==TLS13_EAGAIN)break;
        if(rc){close_context(c,tls_error(rc));return;}
        if(step+1==TLS_STEPS&&c->rx_offset<c->rx_length)enqueue(c);
    }
    if(c->closed)return;
    if(tls13_engine_state(c->engine)==TLS13_ENGINE_AUTH_PENDING&&!c->job){
        if(!begin_verify(c))return;
    }
    if(tls13_engine_state(c->engine)==TLS13_ENGINE_READY){
        if(!service_plaintext(c)||!service_write(c))return;
    }
    if(!send_output(c))return;
    (void)start_read(c);
}
static void pump(struct loop *loop,int fd,uint32_t events,void *arg){
    struct steer_draft_tls_stream_backend *b=arg;uint64_t counter;ssize_t n;(void)loop;(void)events;
    do{n=read(fd,&counter,sizeof(counter));}while(n<0&&errno==EINTR);
    b->dispatching++;
    for(uint32_t count=0;b->head&&count<TLS_BATCH;count++){
        struct tls_context *c=b->head;b->head=c->queue_next;if(!b->head)b->tail=NULL;
        c->queue_next=NULL;c->queued=0;progress(c);
    }
    (void)steer_draft_operations_dispatch(b->operations,TLS_BATCH,NULL);b->dispatching--;
    uint32_t queued=0;steer_draft_operations_usage(b->operations,NULL,&queued);
    if(b->head||queued)notify(b);
}
static struct steer_pv1_async_start start_io(struct tls_public *public_handle,struct steer_pv1_buffer *buffer,
    uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata,int writing){
    if(!public_handle||!public_handle->context)return rejected(STEER_PV1_INVALID);
    struct tls_context *c=public_handle->context;struct steer_draft_tls_stream_backend *b=c->backend;
    if(c->closed||(writing&&c->write_barrier))return rejected(STEER_PV1_POLICY_DENIED);
    if(!buffer||!done||!length)return rejected(STEER_PV1_INVALID);
    if(writing?c->write!=NULL:c->read!=NULL)return rejected(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_mut_span span;struct steer_pv1_error e=b->buffer_api->writable(b->buffers,buffer,&span);
    if(e.code||offset>span.len||length>span.len-offset)return rejected(e.code?e.code:STEER_PV1_INVALID);
    if(length>b->limits.max_queued_bytes-b->bytes)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct tls_operation *op=new_operation(b,c,writing?TLS_WRITE:TLS_READ);
    if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->buffer=buffer;op->offset=offset;op->length=length;op->io_done=done;op->userdata=userdata;b->bytes+=length;
    if(writing)c->write=op;else c->read=op;enqueue(c);return exported(op);
}
static uint64_t STEER_PV1_CALL capabilities(const struct steer_pv1_backend_stream *opaque){
    const struct tls_public *p=(const struct tls_public *)opaque;
    return p&&p->context&&!p->context->closed?STEER_PV1_STREAM_CAP_HALF_CLOSE:0;
}
static struct steer_pv1_async_start STEER_PV1_CALL read_stream(struct steer_pv1_backend_stream *p,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *arg){return start_io((struct tls_public *)p,buffer,offset,length,done,arg,0);}
static struct steer_pv1_async_start STEER_PV1_CALL write_stream(struct steer_pv1_backend_stream *p,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *arg){return start_io((struct tls_public *)p,buffer,offset,length,done,arg,1);}
static struct steer_pv1_async_start STEER_PV1_CALL finish_stream(struct steer_pv1_backend_stream *opaque,steer_pv1_backend_finish_done done,void *userdata){
    struct tls_public *p=(struct tls_public *)opaque;if(!p||!p->context||!done)return rejected(STEER_PV1_INVALID);
    struct tls_context *c=p->context;
    if(c->closed||c->write_barrier||c->write)return rejected(STEER_PV1_POLICY_DENIED);
    struct tls_operation *op=new_operation(c->backend,c,TLS_FINISH);if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->finish_done=done;op->userdata=userdata;c->finish=op;c->write_barrier=1;enqueue(c);return exported(op);
}
static void STEER_PV1_CALL close_stream(struct steer_pv1_backend_stream *opaque){struct tls_public *p=(struct tls_public *)opaque;if(p&&p->context)close_context(p->context,STEER_PV1_CANCELLED);}
static struct steer_pv1_error STEER_PV1_CALL release_stream(struct steer_pv1_backend_stream *opaque){
    struct tls_public *p=(struct tls_public *)opaque;if(!p||!p->context)return error(STEER_PV1_INVALID);
    struct tls_context *c=p->context;if(!c->closed||c->exported_operations)return error(STEER_PV1_POLICY_DENIED);
    c->public_handle=NULL;p->context=NULL;free(p);enqueue(c);return error(0);
}
static const struct steer_pv1_backend_stream_api origin_api={sizeof(origin_api),STEER_PV1_STREAM_BACKEND_LAYOUT,capabilities,read_stream,write_stream,finish_stream,close_stream,release_stream};
static struct steer_pv1_async_start STEER_PV1_CALL open_tls(void *arg,const struct steer_pv1_flow_metadata *flow,
    uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
    struct steer_draft_tls_stream_backend *b=arg;
    if(!b||!done||!deadline)return rejected(STEER_PV1_INVALID);
    struct steer_draft_flow_owned owned;struct steer_pv1_error e=steer_draft_flow_copy(&owned,flow,STEER_PV1_FLOW_STREAM);
    if(e.code)return rejected(e.code);
    const struct steer_draft_binding_identity *identity=steer_draft_binding_identity(b->binding.lease);
    if(flow->generation!=identity->generation)return rejected(STEER_PV1_POLICY_DENIED);
    if(flow->destination.tag==STEER_PV1_ENDPOINT_DOMAIN&&!(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN))return rejected(STEER_PV1_UNSUPPORTED);
    if(now_ns()>=deadline)return rejected(STEER_PV1_TIMEOUT);
    if(b->streams>=b->limits.max_streams||b->handshakes>=b->limits.max_handshakes||
       b->handshake_cost>b->limits.max_handshake_bytes-b->handshake_bytes)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
    struct tls_context *c=calloc(1,sizeof(*c));
    if(!c){(void)steer_draft_binding_unpin(b->binding.lease);return rejected(STEER_PV1_RESOURCE_EXHAUSTED);}
    c->backend=b;c->deadline=deadline;c->diagnostic=(struct steer_pv1_stream_open_diagnostic){sizeof(c->diagnostic),STEER_PV1_STREAM_BACKEND_LAYOUT,0};
    c->public_handle=calloc(1,sizeof(*c->public_handle));
    if(!c->public_handle){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    c->public_handle->context=c;
    e=b->buffer_api->allocate(b->buffers,TLS_IO_BYTES,&c->rx);if(e.code)goto fail;
    e=b->buffer_api->allocate(b->buffers,TLS_IO_BYTES,&c->tx);if(e.code)goto fail;
    struct tls_operation *op=new_operation(b,c,TLS_OPEN);
    if(!op){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    op->open_done=done;op->userdata=userdata;c->open=op;
    c->handshake_reservation=b->handshake_cost;b->handshake_bytes+=b->handshake_cost;b->handshakes++;b->streams++;
    c->next=b->contexts;b->contexts=c;
    c->deadline_timer=loop_timer_new(b->loop,open_timeout,c);
    if(!c->deadline_timer){close_context(c,STEER_PV1_RESOURCE_EXHAUSTED);return exported(op);}
    arm_deadline(c);
    if(now_ns()>=deadline){close_context(c,STEER_PV1_TIMEOUT);return exported(op);}
    struct steer_pv1_async_start start=b->lower.api->open(b->lower.context,&owned.value,deadline,lower_open_done,c);
    if(accept_child(c,&c->opening,start))(void)start_job(c,TLS_PREPARE,NULL,0);
    enqueue(c);return exported(op);
fail:
    if(c->rx)b->buffer_api->release(b->buffers,c->rx);
    if(c->tx)b->buffer_api->release(b->buffers,c->tx);
    free(c->public_handle);free(c);(void)steer_draft_binding_unpin(b->binding.lease);return rejected(e.code);
}
static const struct steer_pv1_stream_backend_api backend_api={sizeof(backend_api),STEER_PV1_STREAM_BACKEND_LAYOUT,open_tls};
static void finalized(void *arg,const struct steer_draft_binding_identity *identity){
    struct steer_draft_tls_stream_backend *b=arg;(void)identity;b->finalized=1;
    if(b->retired)b->retired(b->userdata);
}
static int copy_span(char *out,size_t capacity,struct steer_pv1_span input,int empty){
    if((!input.data&&input.len)||input.len>=capacity||(!empty&&!input.len))return 0;
    for(size_t i=0;i<input.len;i++)if(input.data[i]<33||input.data[i]>126)return 0;
    if(input.len)memcpy(out,input.data,input.len);
    out[input.len]=0;return 1;
}
static int copy_policy(char *out,size_t capacity,const char *input){
    if(!input){out[0]=0;return 1;}
    size_t length=strnlen(input,capacity);if(length==capacity)return 0;
    for(size_t i=0;i<length;i++)if((unsigned char)input[i]<32||(unsigned char)input[i]>126)return 0;
    memcpy(out,input,length+1);return 1;
}
struct steer_pv1_error steer_draft_tls_stream_backend_create(struct loop *loop,struct steer_pv1_host *buffers,
    struct steer_draft_host_worker *worker,const struct steer_draft_stream_binding *lower,
    const struct steer_draft_tls_stream_profile *profile,const struct steer_draft_tls_stream_limits *limits,
    uint64_t generation,uint64_t token,void (*retired)(void *),void *userdata,
    struct steer_draft_tls_stream_backend **out){
    if(out)*out=NULL;
    if(!out||!loop||!buffers||!worker||!lower||!profile||!limits||!generation||!token||
       lower->owner!=loop||steer_draft_host_worker_owner(worker)!=loop||!lower->lease||!lower->api||
       !limits->max_streams||limits->max_streams>1024||!limits->max_operations||limits->max_operations>16384||
       !limits->max_handshakes||limits->max_handshakes>limits->max_streams||limits->max_references<4||
       !limits->max_queued_bytes)return error(STEER_PV1_INVALID);
    if(profile->kind!=STEER_DRAFT_TLS13_STANDARD_X25519)return error(STEER_PV1_UNSUPPORTED);
    const struct steer_draft_binding_identity *identity=steer_draft_binding_identity(lower->lease);
    if(identity->generation!=generation||identity->flow_class!=STEER_PV1_FLOW_STREAM)return error(STEER_PV1_POLICY_DENIED);
    if(!(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_PREPARED)||
       lower->api->size<sizeof(*lower->api)||lower->api->version!=STEER_PV1_STREAM_BACKEND_LAYOUT||!lower->api->open)return error(STEER_PV1_UNSUPPORTED);
    static const unsigned char dummy[TLS_HELLO_BYTES]={0};
    struct tls13_engine_options options={dummy,sizeof(dummy),dummy,profile->engine};size_t workspace_length;
    if(tls13_engine_workspace_size(&options,&workspace_length))return error(STEER_PV1_INVALID);
    size_t scratch_length=sizeof(struct tls_verify_input)+profile->engine.max_certificate+1024+48;
    size_t handshake_cost=workspace_length+sizeof(struct tls_hello)+scratch_length;
    struct steer_draft_host_worker_limits work_limits;steer_draft_host_worker_limits(worker,&work_limits);
    if(work_limits.max_input<scratch_length||work_limits.max_bytes<scratch_length||
       limits->max_handshake_bytes<scratch_length+handshake_cost)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_draft_tls_stream_backend *b=calloc(1,sizeof(*b));if(!b)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    b->wake=-1;b->loop=loop;b->buffers=buffers;b->buffer_api=steer_draft_buffers_api();b->worker=worker;
    b->limits=*limits;b->engine_limits=profile->engine;b->roots=profile->roots;b->retired=retired;b->userdata=userdata;
    b->scratch_length=scratch_length;b->handshake_cost=handshake_cost;b->handshake_bytes=scratch_length;
    if(!copy_span(b->name,sizeof(b->name),profile->server_name,0)||!copy_span(b->alpn,sizeof(b->alpn),profile->required_alpn,1))goto invalid;
    if(b->alpn[0]&&strcmp(b->alpn,"h2")&&strcmp(b->alpn,"http/1.1")){free(b);return error(STEER_PV1_UNSUPPORTED);}
    struct cert_policy policy={0};if(profile->policy)policy=*profile->policy;
    if((policy.insecure!=0&&policy.insecure!=1)||!copy_policy(b->pcs,sizeof(b->pcs),policy.pcs)||
       !copy_policy(b->pks,sizeof(b->pks),policy.pks)||!copy_policy(b->vcn,sizeof(b->vcn),policy.vcn))goto invalid;
    if(!b->roots&&!policy.insecure&&!b->pcs[0]&&!b->pks[0])goto invalid;
    b->policy=(struct cert_policy){b->pcs,b->pks,b->vcn,policy.insecure};
    b->scratch=malloc(scratch_length);if(!b->scratch){free(b);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
    struct steer_pv1_error e=steer_draft_binding_admit(lower->lease,generation,STEER_PV1_FLOW_STREAM);
    if(e.code){free(b->scratch);free(b);return e;}
    b->lower=*lower;
    e=steer_draft_operations_create(limits->max_operations,NULL,&b->operations);if(e.code)goto fail;
    b->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(b->wake<0||loop_fd_add(loop,b->wake,EPOLLIN,pump,b)){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    static const unsigned char provider[]="steer.tls13.standard.x25519";
    struct steer_draft_binding_identity own={sizeof(own),STEER_PV1_DRAFT_LAYOUT,generation,token,{provider,sizeof(provider)-1},
        STEER_DRAFT_STREAM_BINDING_PREPARED|(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN),STEER_PV1_FLOW_STREAM};
    e=steer_draft_binding_lease_create(loop,&own,limits->max_references,finalized,b,&b->binding.lease);if(e.code)goto fail;
    b->binding.owner=loop;b->binding.api=&backend_api;b->binding.context=b;*out=b;return error(0);
invalid:free(b);return error(STEER_PV1_INVALID);
fail:
    if(b->wake>=0){loop_fd_del(loop,b->wake);close(b->wake);}
    if(b->operations)(void)steer_draft_operations_destroy(b->operations);
    (void)steer_draft_binding_unpin(lower->lease);free(b->scratch);free(b);return e;
}
const struct steer_draft_stream_binding *steer_draft_tls_stream_binding(const struct steer_draft_tls_stream_backend *b){return b?&b->binding:NULL;}
struct steer_pv1_error steer_draft_tls_stream_backend_retire(struct steer_draft_tls_stream_backend *b){return b?steer_draft_binding_retire(b->binding.lease):error(STEER_PV1_INVALID);}
struct steer_pv1_error steer_draft_tls_stream_backend_destroy(struct steer_draft_tls_stream_backend *b){
    if(!b)return error(STEER_PV1_INVALID);
    if(!b->finalized||b->streams||b->live||b->contexts||b->head||b->dispatching)return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);if(e.code)return e;
    (void)steer_draft_operations_destroy(b->operations);loop_fd_del(b->loop,b->wake);close(b->wake);
    (void)steer_draft_binding_unpin(b->lower.lease);wipe(b->scratch,b->scratch_length);free(b->scratch);wipe(b,sizeof(*b));free(b);return error(0);
}
uint32_t steer_draft_tls_stream_quarantined(const struct steer_draft_tls_stream_backend *b){return b?b->quarantined:0;}
struct steer_pv1_error steer_draft_tls_stream_recover(struct steer_draft_tls_stream_backend *b,uint32_t *recovered){
    if(recovered)*recovered=0;
    if(!b)return error(STEER_PV1_INVALID);
    if(b->dispatching)return error(STEER_PV1_POLICY_DENIED);
    uint32_t budget=TLS_BATCH,inspected=0,available=b->quarantined;struct steer_pv1_error result=error(0);
    while(b->quarantine_head&&budget&&inspected<TLS_BATCH&&inspected<available){
        struct tls_context *c=b->quarantine_head;b->quarantine_head=c->quarantine_next;
        if(!b->quarantine_head)b->quarantine_tail=NULL;
        c->quarantine_next=NULL;inspected++;
        if(c->queued||c->bad_child){result=error(c->bad_child?STEER_PV1_UNSUPPORTED:STEER_PV1_POLICY_DENIED);append_quarantine(c);}
        else if(collect_context(c,1,&budget)){if(recovered)(*recovered)++;}
        else{result=error(STEER_PV1_POLICY_DENIED);append_quarantine(c);}
    }
    return result;
}
