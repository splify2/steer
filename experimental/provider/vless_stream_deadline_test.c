#define _GNU_SOURCE
#include "vless_stream_backend.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
/* Test-only linker seam: suppress precisely the initial open timer arms so
 * delayed lower/header/publication success cannot accidentally pass because
 * the timer won first. Production has no clock/timer hook. */
static int suppress_timers;
void __real_loop_timer_set(struct loop_timer *,long);
void __wrap_loop_timer_set(struct loop_timer *timer,long ms){if(!suppress_timers)__real_loop_timer_set(timer,ms);}
struct fixture;
struct fake_stream {struct fixture *f;int closed;};
struct fake_operation {
    struct steer_pv1_operation_ref completion;struct fixture *f;struct fake_stream *stream;
    steer_pv1_stream_open_done opened;steer_pv1_backend_io_done wrote;
    struct steer_pv1_buffer *buffer;uint32_t length;void *userdata;int completed;
};
struct result {struct fixture *f;struct steer_pv1_async_start op;struct steer_pv1_stream_ref stream;int ready;uint32_t code;unsigned index;};
struct fixture {
    struct loop *loop;struct loop_timer *work,*watchdog;struct steer_pv1_host *buffers;
    struct steer_draft_operations *operations;struct steer_draft_binding_lease *lease;
    struct steer_draft_stream_binding lower;struct steer_draft_vless_stream_backend *backend;
    struct result results[2];int wake,mode,phase,finalized,lower_finalized,reject_release;unsigned live_streams,live_operations;
};
static uint64_t now_ns(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static void delay(void){struct timespec t={0,40000000};while(nanosleep(&t,&t))assert(errno==EINTR);}
static void notify(struct fixture *f){uint64_t one=1;assert(write(f->wake,&one,sizeof(one))==sizeof(one));}
static struct steer_pv1_error error(uint32_t code){struct steer_pv1_error e={code,0};return e;}
static void STEER_PV1_CALL cancel_fake(struct steer_pv1_operation *handle){struct fake_operation *op=(struct fake_operation *)handle;op->completion.api->cancel(op->completion.handle);}
static void STEER_PV1_CALL release_fake(struct steer_pv1_operation *handle){
    struct fake_operation *op=(struct fake_operation *)handle;if(!op->completed)return;
    op->completion.api->release(op->completion.handle);op->f->live_operations--;free(op);
}
static const struct steer_pv1_operation_api operation_api={sizeof(operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_fake,release_fake};
static uint64_t STEER_PV1_CALL capabilities(const struct steer_pv1_backend_stream *handle){(void)handle;return 0;}
static struct steer_pv1_async_start STEER_PV1_CALL reject_read(struct steer_pv1_backend_stream *s,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata){
    (void)s;(void)buffer;(void)offset;(void)length;(void)done;(void)userdata;
    struct steer_pv1_async_start a={STEER_PV1_REJECTED,{STEER_PV1_UNSUPPORTED,0},{NULL,NULL}};return a;
}
static void STEER_PV1_CALL close_fake(struct steer_pv1_backend_stream *handle){((struct fake_stream *)handle)->closed=1;}
static struct steer_pv1_error STEER_PV1_CALL release_stream(struct steer_pv1_backend_stream *handle){
    struct fake_stream *s=(struct fake_stream *)handle;assert(s->closed);
    if(s->f->reject_release)return error(STEER_PV1_POLICY_DENIED);
    s->f->live_streams--;free(s);return error(STEER_PV1_OK);
}
static const struct steer_pv1_backend_stream_api stream_api;
static void fake_delivered(void *arg,struct steer_pv1_error e){
    struct fake_operation *op=arg;struct fixture *f=op->f;
    if((f->mode==1&&op->opened)||(f->mode==2&&op->wrote))delay();
    if(op->opened){struct steer_pv1_stream_ref stream={NULL,NULL};if(!e.code){stream.handle=(struct steer_pv1_backend_stream *)op->stream;stream.api=&stream_api;}else{close_fake((struct steer_pv1_backend_stream *)op->stream);assert(!release_stream((struct steer_pv1_backend_stream *)op->stream).code);}
        op->opened(op->userdata,e,stream,NULL,NULL,NULL);
    }else op->wrote(op->userdata,e,op->buffer,e.code?0:op->length);
    op->completed=1;
}
static struct fake_operation *start(struct fixture *f){
    struct fake_operation *op=calloc(1,sizeof(*op));assert(op);op->f=f;
    struct steer_pv1_async_start a=steer_draft_operation_start(f->operations,fake_delivered,op);assert(a.disposition==STEER_PV1_PENDING);
    op->completion=a.operation;assert(!steer_draft_operation_resolve(a.operation.handle,error(STEER_PV1_OK)).code);f->live_operations++;notify(f);return op;
}
static struct steer_pv1_async_start exported(struct fake_operation *op){struct steer_pv1_async_start a={STEER_PV1_PENDING,{0,0},{(struct steer_pv1_operation *)op,&operation_api}};return a;}
static struct steer_pv1_async_start STEER_PV1_CALL write_fake(struct steer_pv1_backend_stream *handle,struct steer_pv1_buffer *buffer,uint32_t offset,uint32_t length,steer_pv1_backend_io_done done,void *userdata){
    struct fake_stream *s=(struct fake_stream *)handle;assert(!s->closed);struct steer_pv1_mut_span view;
    assert(!steer_draft_buffers_api()->writable(s->f->buffers,buffer,&view).code&&offset+length<=view.len);
    struct fake_operation *op=start(s->f);op->stream=s;op->buffer=buffer;op->length=length;op->wrote=done;op->userdata=userdata;return exported(op);
}
static const struct steer_pv1_backend_stream_api stream_api={sizeof(stream_api),STEER_PV1_STREAM_BACKEND_LAYOUT,capabilities,reject_read,write_fake,NULL,close_fake,release_stream};
static struct steer_pv1_async_start STEER_PV1_CALL open_fake(void *context,const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
    struct fixture *f=context;(void)deadline;assert(flow->generation==1);
    struct fake_operation *op=start(f);op->stream=calloc(1,sizeof(*op->stream));assert(op->stream);op->stream->f=f;f->live_streams++;
    op->opened=done;op->userdata=userdata;return exported(op);
}
static const struct steer_pv1_stream_backend_api backend_api={sizeof(backend_api),STEER_PV1_STREAM_BACKEND_LAYOUT,open_fake};
static void pump(struct loop *loop,int fd,uint32_t events,void *arg){struct fixture *f=arg;uint64_t value;(void)loop;(void)events;assert(read(fd,&value,sizeof(value))==sizeof(value));assert(!steer_draft_operations_dispatch(f->operations,32,NULL).code);}
static void finalized(void *arg){struct fixture *f=arg;f->finalized=1;loop_timer_set(f->work,0);}
static void lower_finalized(void *arg,const struct steer_draft_binding_identity *id){struct fixture *f=arg;(void)id;f->lower_finalized=1;loop_timer_set(f->work,0);}
static void opened(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,const struct steer_pv1_stream_open_diagnostic *diag){
    struct result *r=arg;assert(!r->ready&&!bound&&!peer&&diag);r->ready=1;r->code=e.code;r->stream=stream;
    if(r->f->mode==3&&!r->index){assert(!e.code);delay();assert(!r->f->results[1].ready);}
    loop_timer_set(r->f->work,0);
}
static void step(struct loop *loop,struct loop_timer *timer,void *arg){
    struct fixture *f=arg;(void)timer;
    if(f->phase==0){
        unsigned count=f->mode==3?2:1;
        for(unsigned i=0;i<count;i++)if(!f->results[i].ready)return;
        if(f->mode==4)f->reject_release=1;
        for(unsigned i=0;i<count;i++){
            struct result *r=&f->results[i];uint32_t expected=(f->mode==1||f->mode==2||(f->mode==3&&i))?STEER_PV1_TIMEOUT:STEER_PV1_OK;
            assert(r->code==expected);
            if(expected)assert(!r->stream.handle&&!r->stream.api);
            else {assert(r->stream.handle);r->stream.api->close(r->stream.handle);assert(!r->stream.api->release(r->stream.handle).code);}
            r->op.operation.api->release(r->op.operation.handle);
        }
        if(f->mode==4){
            assert(steer_draft_vless_stream_quarantined(f->backend)==1&&!f->finalized);
            uint32_t recovered=99;
            assert(steer_draft_vless_stream_recover(f->backend,&recovered).code==STEER_PV1_POLICY_DENIED&&!recovered);
            assert(steer_draft_vless_stream_backend_destroy(f->backend).code==STEER_PV1_POLICY_DENIED);
            f->reject_release=0;
            assert(!steer_draft_vless_stream_recover(f->backend,&recovered).code&&recovered==1&&!f->finalized);
        }
        f->phase=1;
    }else if(f->phase==1){
        if(!f->finalized)return;
        assert(!steer_draft_vless_stream_backend_destroy(f->backend).code);f->backend=NULL;
        assert(!steer_draft_binding_retire(f->lease).code);f->phase=2;
    }else if(f->phase==2){
        if(!f->lower_finalized)return;
        assert(!f->live_operations&&!f->live_streams);
        assert(!steer_draft_binding_lease_destroy(f->lease).code);
        assert(!steer_draft_operations_destroy(f->operations).code);
        loop_fd_del(f->loop,f->wake);close(f->wake);f->phase=3;loop_stop(loop,0);
    }else assert(0);
}
static void watchdog(struct loop *loop,struct loop_timer *timer,void *arg){(void)loop;(void)timer;(void)arg;assert(!"deadline test watchdog");}
static void run(int mode){
    struct fixture f={0};f.mode=mode;f.loop=loop_new();assert(f.loop);
    struct steer_draft_buffer_limits limits={4096,8,1};assert(!steer_draft_buffers_create(&limits,NULL,&f.buffers).code);
    assert(!steer_draft_operations_create(8,NULL,&f.operations).code);f.wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(f.wake>=0);
    assert(!loop_fd_add(f.loop,f.wake,EPOLLIN,pump,&f));
    struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,1,1,
        {(const uint8_t *)"fake.lower",10},STEER_DRAFT_STREAM_BINDING_PREPARED,STEER_PV1_FLOW_STREAM};
    assert(!steer_draft_binding_lease_create(f.loop,&id,64,lower_finalized,&f,&f.lease).code);
    f.lower=(struct steer_draft_stream_binding){f.loop,f.lease,&backend_api,&f};
    uint8_t ip[4]={127,0,0,1},uuid[16]={42};struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},1234,0};
    assert(!steer_draft_vless_stream_backend_create(f.loop,f.buffers,&f.lower,&endpoint,uuid,1,2,2,4,4096,64,finalized,&f,&f.backend).code);
    struct steer_pv1_flow_metadata flow={0};flow.size=sizeof(flow);flow.version=STEER_PV1_DRAFT_LAYOUT;flow.generation=1;flow.flow_class=STEER_PV1_FLOW_STREAM;
    flow.inbound_id=(struct steer_pv1_span){(const uint8_t *)"test",4};flow.source=endpoint;flow.destination=endpoint;
    flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;flow.destination.address=(struct steer_pv1_span){(const uint8_t *)"example.test",12};
    const struct steer_draft_stream_binding *binding=steer_draft_vless_stream_binding(f.backend);
    uint64_t soon=now_ns()+UINT64_C(20000000);
    for(unsigned i=0;i<(mode==3?2u:1u);i++){
        struct result *r=&f.results[i];r->f=&f;r->index=i;
        uint64_t deadline=(mode==0||mode==4||(mode==3&&!i))?UINT64_MAX:soon;
        suppress_timers=mode==1||mode==2||mode==3;
        r->op=binding->api->open(binding->context,&flow,deadline,opened,r);suppress_timers=0;
        assert(r->op.disposition==STEER_PV1_PENDING&&!r->ready);
    }
    assert(!steer_draft_vless_stream_backend_retire(f.backend).code);
    f.work=loop_timer_new(f.loop,step,&f);f.watchdog=loop_timer_new(f.loop,watchdog,&f);assert(f.work&&f.watchdog);
    loop_timer_set(f.watchdog,5000);assert(!loop_run(f.loop)&&f.phase==3);
    assert(!steer_draft_buffers_destroy(f.buffers).code);loop_timer_free(f.work);loop_timer_free(f.watchdog);loop_free(f.loop);
}
int main(int argc,char **argv){
    if(argc==2){char *end;long mode=strtol(argv[1],&end,10);assert(*argv[1]&&!*end&&mode>=0&&mode<5);run((int)mode);}
    else {assert(argc==1);for(int mode=0;mode<5;mode++)run(mode);}
    puts("vless fake lower: late open/header/publication, UINT64_MAX deadline, public release/private quarantine PASS");return 0;
}
