#define _GNU_SOURCE
#include "vless_stream_backend.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include "vless/outbound.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
#define VLESS_BATCH 32u
enum operation_kind { OPEN_LOWER, OPEN_HEADER, READ_BODY, WRITE_BODY, FINISH_BODY };
struct vless_operation;
struct vless_stream {
    struct steer_draft_vless_stream_backend *backend;
    struct steer_pv1_stream_ref lower;
    struct vl_response_decoder response;
    struct vless_operation *read,*write;
    struct vless_stream *quarantine_next;
    uint32_t operations;
    int closed,write_closing;
};
struct steer_draft_vless_stream_backend {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    const struct steer_pv1_buffer_api *buffer_api;
    struct steer_draft_operations *operations;
    struct steer_draft_stream_binding binding,lower;
    struct steer_draft_flow_owned upstream;
    uint8_t uuid[16];
    struct vless_operation *head,*tail;
    struct vless_stream *quarantine;
    uint32_t streams,live,max_streams,max_operations,quarantined;
    uint64_t bytes,max_bytes;
    int wake,dispatching,finalized;
    void (*retired)(void *);void *userdata;
};
struct vless_operation {
    struct steer_draft_vless_stream_backend *backend;
    struct vless_stream *stream;
    struct vless_operation *next;
    struct steer_pv1_operation_ref completion,inner;
    struct steer_pv1_buffer *buffer;
    struct loop_timer *deadline;
    steer_pv1_stream_open_done open_done;
    steer_pv1_backend_io_done io_done;
    steer_pv1_backend_finish_done finish_done;
    void *userdata;
    struct steer_pv1_error result;
    struct steer_pv1_stream_open_diagnostic diagnostic;
    uint32_t offset,length,bytes,header_offset;
    uint64_t absolute_deadline;
    enum operation_kind kind;
    int queued,inner_done,terminal,completed,abort_code;
};
static struct steer_pv1_error error(uint32_t code){struct steer_pv1_error e={code,0};return e;}
static struct steer_pv1_async_start rejected(uint32_t code){struct steer_pv1_async_start a={STEER_PV1_REJECTED,{code,0},{NULL,NULL}};return a;}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static void wipe(void *p,size_t length){volatile uint8_t *bytes=p;while(length--)*bytes++=0;}
static void notify(struct steer_draft_vless_stream_backend *b){uint64_t one=1;ssize_t n;do{n=write(b->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);}
static void enqueue(struct vless_operation *op){
    if(op->queued||op->terminal)return;
    op->queued=1;op->next=NULL;
    if(op->backend->tail)op->backend->tail->next=op;else op->backend->head=op;
    op->backend->tail=op;notify(op->backend);
}
static int valid_stream(struct steer_pv1_stream_ref s){
    return s.handle&&s.api&&s.api->size>=sizeof(*s.api)&&s.api->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&
        s.api->capabilities&&s.api->read&&s.api->write&&s.api->close&&s.api->release;
}
static void close_stream(struct vless_stream *s){
    if(s->closed)return;
    s->closed=1;
    if(valid_stream(s->lower))s->lower.api->close(s->lower.handle);
}
static struct steer_pv1_error free_stream(struct vless_stream *s){
    struct steer_draft_vless_stream_backend *b=s->backend;
    if(s->lower.handle){
        if(!valid_stream(s->lower))return error(STEER_PV1_UNSUPPORTED);
        struct steer_pv1_error e=s->lower.api->release(s->lower.handle);if(e.code)return e;
    }
    b->streams--;free(s);(void)steer_draft_binding_unpin(b->binding.lease);return error(STEER_PV1_OK);
}
static void consume_stream(struct vless_stream *s){
    close_stream(s);
    if(free_stream(s).code){s->quarantine_next=s->backend->quarantine;s->backend->quarantine=s;s->backend->quarantined++;}
}
static void io_ready(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct vless_operation *op=arg;op->result=e;op->buffer=buffer;op->bytes=bytes;op->inner_done=1;enqueue(op);
}
static void finish_ready(void *arg,struct steer_pv1_error e){
    struct vless_operation *op=arg;op->result=e;op->inner_done=1;enqueue(op);
}
static void lower_ready(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref lower,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,
    const struct steer_pv1_stream_open_diagnostic *diagnostic){
    struct vless_operation *op=arg;(void)bound;(void)peer;
    op->result=e;op->stream->lower=lower;
    if(op->stream->closed&&valid_stream(lower))lower.api->close(lower.handle);
    if(diagnostic&&diagnostic->size>=sizeof(*diagnostic)&&diagnostic->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&
       diagnostic->dial_failure<=STEER_PV1_STREAM_DIAL_OTHER){op->diagnostic=*diagnostic;op->diagnostic.size=sizeof(op->diagnostic);}
    op->inner_done=1;enqueue(op);
}
static void STEER_PV1_CALL cancel_operation(struct steer_pv1_operation *opaque){
    struct vless_operation *op=(struct vless_operation *)opaque;
    if(op->terminal)return;
    if(op->kind==OPEN_LOWER||op->kind==OPEN_HEADER||op->kind==FINISH_BODY){
        op->abort_code=STEER_PV1_CANCELLED;close_stream(op->stream);
    }
    if(op->inner.handle)op->inner.api->cancel(op->inner.handle);
}
static void STEER_PV1_CALL release_operation(struct steer_pv1_operation *opaque){
    struct vless_operation *op=(struct vless_operation *)opaque;if(!op->completed)return;
    struct steer_draft_vless_stream_backend *b=op->backend;
    op->completion.api->release(op->completion.handle);
    int opening=op->kind==OPEN_LOWER||op->kind==OPEN_HEADER;
    if(!opening)op->stream->operations--;
    b->live--;free(op);
    if(opening)(void)steer_draft_binding_unpin(b->binding.lease);
}
static const struct steer_pv1_operation_api operation_api={sizeof(operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_operation,release_operation};
static const struct steer_pv1_backend_stream_api origin_api;
static void delivered(void *arg,struct steer_pv1_error e){
    struct vless_operation *op=arg;struct steer_draft_vless_stream_backend *b=op->backend;
    b->bytes-=op->length;
    if(op->open_done){
        struct steer_pv1_stream_ref result={NULL,NULL};
        if(!e.code&&now_ns()>=op->absolute_deadline){e=error(STEER_PV1_TIMEOUT);consume_stream(op->stream);op->stream=NULL;}
        if(!e.code){result.handle=(struct steer_pv1_backend_stream *)op->stream;result.api=&origin_api;op->stream=NULL;}
        op->open_done(op->userdata,e,result,NULL,NULL,&op->diagnostic);
    }else{
        if(op->kind==READ_BODY)op->stream->read=NULL;else op->stream->write=NULL;
        if(op->kind==FINISH_BODY)op->finish_done(op->userdata,e);
        else {struct steer_pv1_buffer *buffer=op->buffer;op->buffer=NULL;op->io_done(op->userdata,e,buffer,e.code?0:op->bytes);}
    }
    op->completed=1;
}
static struct vless_operation *new_operation(struct steer_draft_vless_stream_backend *b){
    if(b->live>=b->max_operations)return NULL;
    struct vless_operation *op=calloc(1,sizeof(*op));if(!op)return NULL;
    struct steer_pv1_async_start a=steer_draft_operation_start(b->operations,delivered,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);return NULL;}
    op->backend=b;op->completion=a.operation;b->live++;
    op->diagnostic.size=sizeof(op->diagnostic);op->diagnostic.version=STEER_PV1_STREAM_BACKEND_LAYOUT;
    return op;
}
static struct steer_pv1_async_start exported(struct vless_operation *op){
    struct steer_pv1_async_start a={STEER_PV1_PENDING,{STEER_PV1_OK,0},
        {(struct steer_pv1_operation *)op,&operation_api}};return a;
}
static void complete(struct vless_operation *op,struct steer_pv1_error e){
    if(op->terminal)return;
    op->terminal=1;
    if(op->deadline){loop_timer_free(op->deadline);op->deadline=NULL;}
    if(op->open_done){
        if(!e.code&&now_ns()>=op->absolute_deadline)e=error(STEER_PV1_TIMEOUT);
        if(op->buffer){
            struct steer_pv1_mut_span span;
            if(!op->backend->buffer_api->writable(op->backend->buffers,op->buffer,&span).code)wipe(span.data,span.len);
            op->backend->buffer_api->release(op->backend->buffers,op->buffer);op->buffer=NULL;
        }
        if(e.code){consume_stream(op->stream);op->stream=NULL;}
    }
    (void)steer_draft_operation_resolve(op->completion.handle,e);notify(op->backend);
}
static void arm_deadline(struct vless_operation *op,uint64_t current){
    uint64_t remaining=op->absolute_deadline>current?op->absolute_deadline-current:0;
    uint64_t milliseconds=remaining/UINT64_C(1000000)+(remaining%UINT64_C(1000000)!=0);
    loop_timer_set(op->deadline,milliseconds>(uint64_t)LONG_MAX?LONG_MAX:(long)milliseconds);
}
static void open_timeout(struct loop *loop,struct loop_timer *timer,void *arg){
    struct vless_operation *op=arg;(void)loop;(void)timer;
    if(op->terminal)return;
    uint64_t current=now_ns();
    if(current<op->absolute_deadline){arm_deadline(op,current);return;}
    op->abort_code=STEER_PV1_TIMEOUT;close_stream(op->stream);
    if(op->inner.handle)op->inner.api->cancel(op->inner.handle);
}
static void read_again(struct vless_operation *op){
    struct steer_pv1_stream_ref lower=op->stream->lower;
    struct steer_pv1_async_start a=lower.api->read(lower.handle,op->buffer,op->offset,op->length,io_ready,op);
    if(a.disposition==STEER_PV1_PENDING){op->inner=a.operation;op->inner_done=0;}
    else complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
}
static void header_again(struct vless_operation *op){
    struct steer_pv1_stream_ref lower=op->stream->lower;
    struct steer_pv1_async_start a=lower.api->write(lower.handle,op->buffer,op->header_offset,
        op->length-op->header_offset,io_ready,op);
    if(a.disposition==STEER_PV1_PENDING){op->inner=a.operation;op->inner_done=0;}
    else complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
}
static void progress(struct vless_operation *op){
    if(op->inner_done&&op->inner.handle){op->inner.api->release(op->inner.handle);op->inner.handle=NULL;op->inner.api=NULL;}
    if(op->abort_code){complete(op,error((uint32_t)op->abort_code));return;}
    if(op->open_done&&now_ns()>=op->absolute_deadline){complete(op,error(STEER_PV1_TIMEOUT));return;}
    if(op->result.code>STEER_PV1_INTERNAL||op->result.transient>1||(!op->result.code&&op->result.transient))op->result=error(STEER_PV1_PROTOCOL);
    if(op->result.code){complete(op,op->result);return;}
    if(op->kind==OPEN_LOWER){
        if(!valid_stream(op->stream->lower)){complete(op,error(STEER_PV1_PROTOCOL));return;}
        op->kind=OPEN_HEADER;header_again(op);return;
    }
    if(op->kind==OPEN_HEADER){
        if(!op->bytes||op->bytes>op->length-op->header_offset){complete(op,error(STEER_PV1_PROTOCOL));return;}
        op->header_offset+=op->bytes;
        if(op->header_offset<op->length)header_again(op);else complete(op,error(STEER_PV1_OK));
        return;
    }
    if(op->kind==READ_BODY){
        if(op->bytes>op->length){close_stream(op->stream);complete(op,error(STEER_PV1_PROTOCOL));return;}
        if(op->stream->response.result!=VL_DONE){
            if(!op->bytes){close_stream(op->stream);complete(op,error(STEER_PV1_PROTOCOL));return;}
            struct steer_pv1_mut_span span;
            struct steer_pv1_error e=op->backend->buffer_api->writable(op->backend->buffers,op->buffer,&span);
            if(e.code){close_stream(op->stream);complete(op,e);return;}
            size_t consumed;enum vl_result result=vl_response_decoder_feed(&op->stream->response,
                span.data+op->offset,op->bytes,&consumed);
            if(result<0){close_stream(op->stream);complete(op,error(STEER_PV1_PROTOCOL));return;}
            op->bytes-=(uint32_t)consumed;
            if(op->bytes)memmove(span.data+op->offset,span.data+op->offset+consumed,op->bytes);
            else {read_again(op);return;}
        }
    }else if(op->kind==WRITE_BODY&&(!op->bytes||op->bytes>op->length)){close_stream(op->stream);complete(op,error(STEER_PV1_PROTOCOL));return;}
    complete(op,error(STEER_PV1_OK));
}
static void pump(struct loop *loop,int fd,uint32_t events,void *arg){
    struct steer_draft_vless_stream_backend *b=arg;uint64_t counter;ssize_t n;uint32_t queued;(void)loop;(void)events;
    do{n=read(fd,&counter,sizeof(counter));}while(n<0&&errno==EINTR);
    b->dispatching++;
    for(uint32_t count=0;b->head&&count<VLESS_BATCH;count++){
        struct vless_operation *op=b->head;b->head=op->next;if(!b->head)b->tail=NULL;op->queued=0;op->next=NULL;
        progress(op);
    }
    (void)steer_draft_operations_dispatch(b->operations,VLESS_BATCH,NULL);b->dispatching--;
    steer_draft_operations_usage(b->operations,NULL,&queued);if(queued||b->head)notify(b);
}
static struct steer_pv1_async_start start_io(struct vless_stream *s,struct steer_pv1_buffer *buffer,
    uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata,int writing){
    if(!s||!buffer||!length||!done)return rejected(STEER_PV1_INVALID);
    if(s->closed||(writing&&(s->write_closing||s->write))||(!writing&&s->read))return rejected(STEER_PV1_POLICY_DENIED);
    struct steer_draft_vless_stream_backend *b=s->backend;
    struct steer_pv1_mut_span mutable;
    struct steer_pv1_error e=b->buffer_api->writable(b->buffers,buffer,&mutable);
    if(e.code)return rejected(e.code);
    uint32_t capacity=mutable.len;
    if(offset>capacity||length>capacity-offset)return rejected(STEER_PV1_INVALID);
    if(length>b->max_bytes-b->bytes)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct vless_operation *op=new_operation(b);if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->stream=s;op->buffer=buffer;op->offset=offset;op->length=length;op->io_done=done;op->userdata=userdata;
    op->kind=writing?WRITE_BODY:READ_BODY;s->operations++;b->bytes+=length;
    if(writing)s->write=op;else s->read=op;
    struct steer_pv1_async_start a=writing?s->lower.api->write(s->lower.handle,buffer,offset,length,io_ready,op):
        s->lower.api->read(s->lower.handle,buffer,offset,length,io_ready,op);
    if(a.disposition==STEER_PV1_PENDING)op->inner=a.operation;
    else complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
    return exported(op);
}
static struct steer_pv1_async_start STEER_PV1_CALL read_body(struct steer_pv1_backend_stream *handle,
    struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata){
    return start_io((struct vless_stream *)handle,buffer,offset,length,done,userdata,0);
}
static struct steer_pv1_async_start STEER_PV1_CALL write_body(struct steer_pv1_backend_stream *handle,
    struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata){
    return start_io((struct vless_stream *)handle,buffer,offset,length,done,userdata,1);
}
static uint64_t STEER_PV1_CALL capabilities(const struct steer_pv1_backend_stream *handle){
    const struct vless_stream *s=(const struct vless_stream *)handle;
    return s&&s->lower.api->finish_write?(s->lower.api->capabilities(s->lower.handle)&STEER_PV1_STREAM_CAP_HALF_CLOSE):0;
}
static struct steer_pv1_async_start STEER_PV1_CALL finish_body(struct steer_pv1_backend_stream *handle,
    steer_pv1_backend_finish_done done,void *userdata){
    struct vless_stream *s=(struct vless_stream *)handle;
    if(!s||!done)return rejected(STEER_PV1_INVALID);
    if(s->closed||s->write_closing||s->write)return rejected(STEER_PV1_POLICY_DENIED);
    if(!(capabilities(handle)&STEER_PV1_STREAM_CAP_HALF_CLOSE))return rejected(STEER_PV1_UNSUPPORTED);
    struct vless_operation *op=new_operation(s->backend);if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->stream=s;op->kind=FINISH_BODY;op->finish_done=done;op->userdata=userdata;
    s->operations++;s->write=op;s->write_closing=1;
    struct steer_pv1_async_start a=s->lower.api->finish_write(s->lower.handle,finish_ready,op);
    if(a.disposition!=STEER_PV1_PENDING){
        /* Upper PENDING has accepted its barrier. A failed lower finish aborts
         * it; only pre-admission upper rejection leaves writes usable. */
        close_stream(s);
        complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
    }else op->inner=a.operation;
    return exported(op);
}
static void STEER_PV1_CALL close_body(struct steer_pv1_backend_stream *handle){close_stream((struct vless_stream *)handle);}
static struct steer_pv1_error STEER_PV1_CALL release_body(struct steer_pv1_backend_stream *handle){
    struct vless_stream *s=(struct vless_stream *)handle;
    if(!s)return error(STEER_PV1_INVALID);
    if(!s->closed||s->operations)return error(STEER_PV1_POLICY_DENIED);
    consume_stream(s);return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api origin_api={sizeof(origin_api),STEER_PV1_STREAM_BACKEND_LAYOUT,
    capabilities,read_body,write_body,finish_body,close_body,release_body};
static struct steer_pv1_async_start STEER_PV1_CALL open_vless(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
    struct steer_draft_vless_stream_backend *b=context;
    if(!b||!done)return rejected(STEER_PV1_INVALID);
    struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
    if(deadline<=now_ns())return rejected(STEER_PV1_TIMEOUT);
    e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
    if(b->streams>=b->max_streams||b->live>=b->max_operations||VL_REQUEST_TCP_MAX>b->max_bytes-b->bytes){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail_pin;}
    struct vless_stream *s=calloc(1,sizeof(*s));if(!s){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail_pin;}
    e=steer_draft_binding_pin(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);if(e.code){free(s);goto fail_pin;}
    s->backend=b;b->streams++;vl_response_decoder_init(&s->response);
    struct steer_pv1_buffer *buffer=NULL;
    e=b->buffer_api->allocate(b->buffers,VL_REQUEST_TCP_MAX,&buffer);if(e.code){consume_stream(s);goto fail_pin;}
    struct steer_pv1_mut_span span;e=b->buffer_api->writable(b->buffers,buffer,&span);
    if(e.code){b->buffer_api->release(b->buffers,buffer);consume_stream(s);goto fail_pin;}
    struct vl_request request={0};request.command=1;request.port=flow->destination.port;
    request.address_type=flow->destination.tag==STEER_PV1_ENDPOINT_IPV4?1:
        flow->destination.tag==STEER_PV1_ENDPOINT_IPV6?3:2;
    request.address_length=flow->destination.address.len;memcpy(request.address,flow->destination.address.data,request.address_length);
    size_t length;enum vl_result encoded=vl_request_encode(span.data,span.len,b->uuid,&request,&length);
    if(encoded!=VL_DONE){wipe(span.data,span.len);b->buffer_api->release(b->buffers,buffer);consume_stream(s);e=error(STEER_PV1_INVALID);goto fail_pin;}
    struct vless_operation *op=new_operation(b);
    if(!op){wipe(span.data,span.len);b->buffer_api->release(b->buffers,buffer);consume_stream(s);e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail_pin;}
    op->stream=s;op->kind=OPEN_LOWER;op->buffer=buffer;op->length=(uint32_t)length;op->open_done=done;op->userdata=userdata;
    op->absolute_deadline=deadline;b->bytes+=length;
    op->deadline=loop_timer_new(b->loop,open_timeout,op);
    if(!op->deadline){complete(op,error(STEER_PV1_RESOURCE_EXHAUSTED));return exported(op);}
    arm_deadline(op,now_ns());
    struct steer_pv1_flow_metadata upstream=*flow;upstream.destination=b->upstream.value.destination;
    struct steer_pv1_async_start a=b->lower.api->open(b->lower.context,&upstream,deadline,lower_ready,op);
    if(a.disposition==STEER_PV1_PENDING)op->inner=a.operation;
    else complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
    return exported(op);
fail_pin:
    (void)steer_draft_binding_unpin(b->binding.lease);return rejected(e.code);
}
static const struct steer_pv1_stream_backend_api backend_api={sizeof(backend_api),STEER_PV1_STREAM_BACKEND_LAYOUT,open_vless};
static void finalized(void *arg,const struct steer_draft_binding_identity *identity){
    struct steer_draft_vless_stream_backend *b=arg;(void)identity;b->finalized=1;
    if(b->retired)b->retired(b->userdata);
}
struct steer_pv1_error steer_draft_vless_stream_backend_create(struct loop *loop,
    struct steer_pv1_host *buffers,const struct steer_draft_stream_binding *lower,
    const struct steer_pv1_endpoint *upstream,const uint8_t uuid[16],
    uint64_t generation,uint64_t token,uint32_t max_streams,uint32_t max_operations,
    uint64_t max_bytes,uint32_t max_references,void (*retired)(void *),void *userdata,
    struct steer_draft_vless_stream_backend **out){
    if(out)*out=NULL;
    if(!loop||!buffers||!lower||!upstream||!uuid||!generation||!token||!max_streams||!max_operations||
       max_bytes<VL_REQUEST_TCP_MAX||!out||lower->owner!=loop||!lower->lease||!lower->api)return error(STEER_PV1_INVALID);
    const struct steer_draft_binding_identity *identity=steer_draft_binding_identity(lower->lease);
    if(identity->generation!=generation||identity->flow_class!=STEER_PV1_FLOW_STREAM)return error(STEER_PV1_POLICY_DENIED);
    if(!(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_PREPARED)||
       (upstream->tag==STEER_PV1_ENDPOINT_DOMAIN&&!(identity->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN))||
       lower->api->size<sizeof(*lower->api)||lower->api->version!=STEER_PV1_STREAM_BACKEND_LAYOUT||!lower->api->open)return error(STEER_PV1_UNSUPPORTED);
    uint8_t source[4]={127,0,0,1};
    struct steer_pv1_flow_metadata flow={0};flow.size=sizeof(flow);flow.version=STEER_PV1_DRAFT_LAYOUT;flow.generation=generation;
    flow.inbound_id=(struct steer_pv1_span){(const uint8_t *)"prepared",8};flow.flow_class=STEER_PV1_FLOW_STREAM;
    flow.source.size=sizeof(flow.source);flow.source.version=STEER_PV1_DRAFT_LAYOUT;flow.source.tag=STEER_PV1_ENDPOINT_IPV4;
    flow.source.address=(struct steer_pv1_span){source,4};flow.source.port=1;flow.destination=*upstream;
    struct steer_draft_vless_stream_backend *b=calloc(1,sizeof(*b));if(!b)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_error e=steer_draft_flow_copy(&b->upstream,&flow,STEER_PV1_FLOW_STREAM);if(e.code){free(b);return e;}
    e=steer_draft_binding_admit(lower->lease,generation,STEER_PV1_FLOW_STREAM);if(e.code){free(b);return e;}
    b->lower=*lower;b->loop=loop;b->buffers=buffers;b->buffer_api=steer_draft_buffers_api();b->wake=-1;
    b->max_streams=max_streams;b->max_operations=max_operations;b->max_bytes=max_bytes;b->retired=retired;b->userdata=userdata;
    memcpy(b->uuid,uuid,16);
    e=steer_draft_operations_create(max_operations,NULL,&b->operations);if(e.code)goto fail;
    b->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(b->wake<0||loop_fd_add(loop,b->wake,EPOLLIN,pump,b)){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    static const uint8_t provider[]="steer.vless.plain.tcp";
    struct steer_draft_binding_identity own={sizeof(own),STEER_PV1_DRAFT_LAYOUT,generation,token,
        {provider,sizeof(provider)-1},STEER_DRAFT_STREAM_BINDING_PREPARED|STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN,STEER_PV1_FLOW_STREAM};
    e=steer_draft_binding_lease_create(loop,&own,max_references,finalized,b,&b->binding.lease);if(e.code)goto fail;
    b->binding.owner=loop;b->binding.context=b;b->binding.api=&backend_api;*out=b;return error(STEER_PV1_OK);
fail:
    if(b->wake>=0){loop_fd_del(loop,b->wake);close(b->wake);}
    if(b->operations)(void)steer_draft_operations_destroy(b->operations);
    (void)steer_draft_binding_unpin(lower->lease);wipe(b->uuid,sizeof(b->uuid));free(b);return e;
}
const struct steer_draft_stream_binding *steer_draft_vless_stream_binding(const struct steer_draft_vless_stream_backend *b){return b?&b->binding:NULL;}
struct steer_pv1_error steer_draft_vless_stream_backend_retire(struct steer_draft_vless_stream_backend *b){return b?steer_draft_binding_retire(b->binding.lease):error(STEER_PV1_INVALID);}
struct steer_pv1_error steer_draft_vless_stream_backend_destroy(struct steer_draft_vless_stream_backend *b){
    if(!b)return error(STEER_PV1_INVALID);
    if(!b->finalized||b->live||b->streams||b->dispatching||b->head||b->quarantine)return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);if(e.code)return e;
    (void)steer_draft_operations_destroy(b->operations);loop_fd_del(b->loop,b->wake);close(b->wake);
    (void)steer_draft_binding_unpin(b->lower.lease);wipe(b->uuid,sizeof(b->uuid));free(b);return error(STEER_PV1_OK);
}
uint32_t steer_draft_vless_stream_quarantined(const struct steer_draft_vless_stream_backend *b){return b?b->quarantined:0;}
struct steer_pv1_error steer_draft_vless_stream_recover(struct steer_draft_vless_stream_backend *b,uint32_t *recovered){
    if(recovered)*recovered=0;
    if(!b)return error(STEER_PV1_INVALID);
    struct vless_stream **link=&b->quarantine;struct steer_pv1_error result=error(STEER_PV1_OK);
    for(uint32_t count=0;*link&&count<VLESS_BATCH;count++){
        struct vless_stream *s=*link,*next=s->quarantine_next;struct steer_pv1_error e=free_stream(s);
        if(e.code){result=e;link=&s->quarantine_next;}else{*link=next;b->quarantined--;if(recovered)(*recovered)++;}
    }
    return result;
}
