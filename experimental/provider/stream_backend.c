#define _GNU_SOURCE
#include "stream_backend.h"
#include "operations.h"
#include "loop.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#define BACKEND_BATCH 32u

struct backend_op;
struct steer_draft_backend_runtime {
    struct loop *loop;
    struct steer_draft_operations *operations;
    struct backend_op *finish_head,*finish_tail;
    uint32_t streams,max_streams,live,max_operations;
    uint64_t bytes,max_bytes;
    int wake,dispatching;
};
struct steer_pv1_backend_stream {
    struct steer_draft_backend_runtime *runtime;
    struct steer_pv1_stream *native;
    struct steer_draft_backend_pin pin;
    struct backend_op *read,*write,*finish;
    uint32_t live;
    int closed,write_closing;
};
struct backend_op {
    struct steer_pv1_backend_stream *stream;
    struct steer_pv1_operation_ref inner;
    struct backend_op *next,*previous;
    steer_pv1_backend_io_done io_done;
    steer_pv1_backend_finish_done finish_done;
    void *userdata;
    uint32_t length;
    int writing,finishing,resolved,completed,queued;
};
static struct steer_pv1_error error(uint32_t code){struct steer_pv1_error e={code,0};return e;}
static struct steer_pv1_async_start rejected(uint32_t code){
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{code,0},{NULL,NULL}};return a;
}
static void notify(struct steer_draft_backend_runtime *r){
    uint64_t one=1;ssize_t n;
    do{n=write(r->wake,&one,sizeof(one));}while(n<0&&errno==EINTR);
}
static void unlink_finish(struct backend_op *op){
    if(!op->queued)return;
    struct steer_draft_backend_runtime *r=op->stream->runtime;
    if(op->previous)op->previous->next=op->next;else r->finish_head=op->next;
    if(op->next)op->next->previous=op->previous;else r->finish_tail=op->previous;
    op->previous=op->next=NULL;op->queued=0;
}
static void resolve_finish(struct backend_op *op,struct steer_pv1_error result){
    if(op->resolved)return;
    unlink_finish(op);
    op->resolved=1;
    (void)steer_draft_operation_resolve(op->inner.handle,result);
    notify(op->stream->runtime);
}
static void STEER_PV1_CALL close_backend(struct steer_pv1_backend_stream *s){
    if(!s||s->closed)return;
    s->closed=1;
    steer_draft_stream_api()->close(s->native);
    if(s->finish)resolve_finish(s->finish,error(STEER_PV1_CANCELLED));
}
static void STEER_PV1_CALL cancel_op(struct steer_pv1_operation *opaque){
    struct backend_op *op=(struct backend_op *)opaque;
    if(op->finishing){if(!op->resolved)close_backend(op->stream);}
    else op->inner.api->cancel(op->inner.handle);
}
static void STEER_PV1_CALL release_op(struct steer_pv1_operation *opaque){
    struct backend_op *op=(struct backend_op *)opaque;
    if(!op->completed)return;
    op->inner.api->release(op->inner.handle);
    op->stream->live--;op->stream->runtime->live--;free(op);
}
static const struct steer_pv1_operation_api operation_api={
    sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_op,release_op
};
static void io_delivered(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *b,uint32_t bytes){
    struct backend_op *op=arg;struct steer_pv1_backend_stream *s=op->stream;
    if(op->writing)s->write=NULL;else s->read=NULL;
    s->runtime->bytes-=op->length;s->runtime->dispatching++;
    op->io_done(op->userdata,e,b,bytes);
    op->completed=1;s->runtime->dispatching--;
}
static struct steer_pv1_async_start start_io(struct steer_pv1_backend_stream *s,
    struct steer_pv1_buffer *b,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata,int writing){
    if(!s||!b||!done||!length)return rejected(STEER_PV1_INVALID);
    if(s->closed||(writing&&s->write_closing)||(writing?s->write:s->read))return rejected(STEER_PV1_POLICY_DENIED);
    struct steer_draft_backend_runtime *r=s->runtime;
    if(r->live>=r->max_operations || length>r->max_bytes-r->bytes)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct backend_op *op=calloc(1,sizeof(*op));if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->stream=s;op->length=length;op->writing=writing;op->io_done=done;op->userdata=userdata;
    const struct steer_pv1_stream_api *api=steer_draft_stream_api();
    struct steer_pv1_async_start a=writing?api->write(s->native,b,offset,length,io_delivered,op):api->read(s->native,b,offset,length,io_delivered,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);return a;}
    op->inner=a.operation;a.operation.handle=(struct steer_pv1_operation *)op;a.operation.api=&operation_api;
    s->live++;r->live++;r->bytes+=length;
    if(writing)s->write=op;else s->read=op;
    return a;
}
static struct steer_pv1_async_start STEER_PV1_CALL read_backend(struct steer_pv1_backend_stream *s,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done d,void *u){return start_io(s,b,o,n,d,u,0);}
static struct steer_pv1_async_start STEER_PV1_CALL write_backend(struct steer_pv1_backend_stream *s,
    struct steer_pv1_buffer *b,uint32_t o,uint32_t n,steer_pv1_backend_io_done d,void *u){return start_io(s,b,o,n,d,u,1);}
static void finish_delivered(void *arg,struct steer_pv1_error e){
    struct backend_op *op=arg;struct steer_pv1_backend_stream *s=op->stream;
    s->finish=NULL;s->runtime->dispatching++;
    op->finish_done(op->userdata,e);
    op->completed=1;s->runtime->dispatching--;
}
static struct steer_pv1_async_start STEER_PV1_CALL finish_backend(struct steer_pv1_backend_stream *s,
    steer_pv1_backend_finish_done done,void *userdata){
    if(!s||!done)return rejected(STEER_PV1_INVALID);
    if(s->closed||s->write_closing||s->write)return rejected(STEER_PV1_POLICY_DENIED);
    struct steer_draft_backend_runtime *r=s->runtime;
    if(r->live>=r->max_operations)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    struct backend_op *op=calloc(1,sizeof(*op));if(!op)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    op->stream=s;op->finishing=1;op->finish_done=done;op->userdata=userdata;
    struct steer_pv1_async_start a=steer_draft_operation_start(r->operations,finish_delivered,op);
    if(a.disposition!=STEER_PV1_PENDING){free(op);return a;}
    op->inner=a.operation;a.operation.handle=(struct steer_pv1_operation *)op;a.operation.api=&operation_api;
    s->write_closing=1;s->finish=op;s->live++;r->live++;
    op->previous=r->finish_tail;op->queued=1;
    if(r->finish_tail)r->finish_tail->next=op;else r->finish_head=op;
    r->finish_tail=op;notify(r);return a;
}
static uint64_t STEER_PV1_CALL capabilities(const struct steer_pv1_backend_stream *s){return s?STEER_PV1_STREAM_CAP_HALF_CLOSE:0;}
static struct steer_pv1_error STEER_PV1_CALL release_backend(struct steer_pv1_backend_stream *s){
    if(!s)return error(STEER_PV1_INVALID);
    if(!s->closed||s->live)return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_stream_api()->release(s->native);if(e.code)return e;
    struct steer_draft_backend_pin pin=s->pin;s->runtime->streams--;free(s);
    if(pin.release)pin.release(pin.context);
    return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api api={
    sizeof(struct steer_pv1_backend_stream_api),STEER_PV1_STREAM_BACKEND_LAYOUT,
    capabilities,read_backend,write_backend,finish_backend,close_backend,release_backend
};
static void pump(struct loop *loop,int fd,uint32_t events,void *arg){
    struct steer_draft_backend_runtime *r=arg;uint64_t counter;ssize_t n;uint32_t queued;
    (void)loop;(void)events;
    do{n=read(fd,&counter,sizeof(counter));}while(n<0&&errno==EINTR);
    r->dispatching++;
    for(uint32_t count=0;r->finish_head && count<BACKEND_BATCH;count++){
        struct backend_op *op=r->finish_head;unlink_finish(op);
        if(op->resolved)continue;
        if(op->stream->closed)resolve_finish(op,error(STEER_PV1_CANCELLED));
        else {
            struct steer_pv1_error e=steer_draft_stream_api()->shutdown_write(op->stream->native);
            resolve_finish(op,e);
            if(e.code)close_backend(op->stream);
        }
    }
    (void)steer_draft_operations_dispatch(r->operations,BACKEND_BATCH,NULL);
    r->dispatching--;
    steer_draft_operations_usage(r->operations,NULL,&queued);
    if(queued||r->finish_head)notify(r);
}
struct steer_pv1_error steer_draft_backend_runtime_create(struct loop *loop,uint32_t streams,
    uint32_t operations,uint64_t bytes,struct steer_draft_backend_runtime **out){
    if(out)*out=NULL;
    if(!loop||!out||!streams||!operations||!bytes)return error(STEER_PV1_INVALID);
    struct steer_draft_backend_runtime *r=calloc(1,sizeof(*r));if(!r)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    r->wake=-1;r->loop=loop;r->max_streams=streams;r->max_operations=operations;r->max_bytes=bytes;
    struct steer_pv1_error e=steer_draft_operations_create(operations,NULL,&r->operations);
    if(e.code){free(r);return e;}
    r->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if(r->wake<0||loop_fd_add(loop,r->wake,EPOLLIN,pump,r)){
        if(r->wake>=0)close(r->wake);
        (void)steer_draft_operations_destroy(r->operations);free(r);return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=r;return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_backend_runtime_destroy(struct steer_draft_backend_runtime *r){
    if(!r)return error(STEER_PV1_INVALID);
    if(r->streams||r->live||r->dispatching||r->finish_head)return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_operations_destroy(r->operations);if(e.code)return e;
    loop_fd_del(r->loop,r->wake);close(r->wake);free(r);return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_backend_wrap_native(struct steer_draft_backend_runtime *r,
    struct steer_pv1_stream *native,const struct steer_draft_backend_pin *pin,struct steer_pv1_stream_ref *out){
    if(out){out->handle=NULL;out->api=NULL;}
    if(!r||!native||!out||(pin&&!pin->release))return error(STEER_PV1_INVALID);
    if(r->streams>=r->max_streams)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_pv1_backend_stream *s=calloc(1,sizeof(*s));if(!s)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    s->runtime=r;s->native=native;if(pin)s->pin=*pin;
    r->streams++;out->handle=s;out->api=&api;return error(STEER_PV1_OK);
}
void steer_draft_backend_usage(const struct steer_draft_backend_runtime *r,uint32_t *streams,
    uint32_t *operations,uint64_t *bytes){
    if(streams)*streams=r?r->streams:0;
    if(operations)*operations=r?r->live:0;
    if(bytes)*bytes=r?r->bytes:0;
}
