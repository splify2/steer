/* SPDX-License-Identifier: GPL-3.0-only */
#include "socks_stream_backend.h"
#include "buffers.h"
#include "operations.h"
#include "stream_open_deadline.h"
#include "socks5/outbound.h"
#include <stdlib.h>
#include <string.h>

#define BATCH 32u
enum phase { DIAL, TX_GREETING, RX_METHOD, TX_AUTH, RX_AUTH, TX_CONNECT, RX_CONNECT };
struct socks_open;
struct steer_draft_socks_stream_backend {
    struct loop *loop;
    struct steer_pv1_host *host;
    const struct steer_pv1_buffer_api *buffers;
    struct steer_draft_operations *operations;
    struct loop_timer *work;
    struct steer_draft_stream_binding binding, lower;
    struct steer_draft_flow_owned upstream;
    struct socks_open *head, *tail, *quarantine;
    uint8_t auth[STEER_DRAFT_SOCKS_HANDSHAKE_MAX];
    size_t auth_len;
    uint32_t live, max_opens;
    int finalized, dispatching;
    void (*retired)(void *);
    void *user;
};
struct socks_open {
    struct steer_draft_socks_stream_backend *backend;
    struct socks_open *next;
    struct steer_pv1_operation_ref inner, completion;
    struct steer_pv1_stream_ref stream;
    struct steer_pv1_buffer *buffer;
    struct loop_timer *timer;
    struct s5_address target;
    struct s5_out_reply reply;
    steer_pv1_stream_open_done done;
    void *user;
    struct steer_pv1_error result;
    struct steer_pv1_stream_open_diagnostic diagnostic;
    uint64_t deadline;
    unsigned offset, length, bytes, aborted;
    enum phase phase;
    int terminal, completed, quarantined, released;
};

static struct steer_pv1_error error(uint32_t code) { return (struct steer_pv1_error){code,0}; }
static struct steer_pv1_async_start rejected(uint32_t code)
{
    return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{code,0},{NULL,NULL}};
}
static void wipe(void *p,size_t n)
{
    volatile uint8_t *bytes=p;
    while(n--) *bytes++=0;
}
static int valid_stream(struct steer_pv1_stream_ref s)
{
    return s.handle&&s.api&&s.api->size>=sizeof(*s.api)&&
        s.api->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&s.api->capabilities&&
        s.api->read&&s.api->write&&s.api->close&&s.api->release;
}
static void enqueue(struct socks_open *op)
{
    struct steer_draft_socks_stream_backend *b=op->backend;
    if(b->tail)b->tail->next=op;else b->head=op;
    b->tail=op;loop_timer_set(b->work,0);
}
static int discard(struct socks_open *op)
{
    if(!op->stream.handle)return 1;
    if(!valid_stream(op->stream))return 0;
    op->stream.api->close(op->stream.handle);
    if(op->stream.api->release(op->stream.handle).code)return 0;
    op->stream=(struct steer_pv1_stream_ref){0};
    return 1;
}
static void discard_or_keep(struct socks_open *op)
{
    if(discard(op))return;
    op->quarantined=1;
    op->next=op->backend->quarantine;op->backend->quarantine=op;
}
static void dispose(struct socks_open *op)
{
    struct steer_draft_socks_stream_backend *b=op->backend;
    b->live--;free(op);(void)steer_draft_binding_unpin(b->binding.lease);
}
static void complete(struct socks_open *op,struct steer_pv1_error e)
{
    struct steer_draft_socks_stream_backend *b=op->backend;
    op->terminal=1;
    loop_timer_free(op->timer);op->timer=NULL;
    if(op->buffer){
        struct steer_pv1_mut_span view;
        if(!b->buffers->writable(b->host,op->buffer,&view).code)wipe(view.data,view.len);
        b->buffers->release(b->host,op->buffer);op->buffer=NULL;
    }
    if(e.code)discard_or_keep(op);
    (void)steer_draft_operation_resolve(op->completion.handle,e);
    loop_timer_set(b->work,0);
}
static void delivered(void *arg,struct steer_pv1_error e)
{
    struct socks_open *op=arg;
    struct steer_pv1_stream_ref stream={0};
    struct steer_pv1_endpoint bound={0};
    if(!e.code&&steer_draft_stream_now_ns()>=op->deadline){
        e=error(STEER_PV1_TIMEOUT);discard_or_keep(op);
    }
    if(!e.code){
        const uint8_t *p=op->reply.frame;
        if(p[3]==1||p[3]==4){
            uint32_t n=p[3]==1?4:16;
            uint16_t port=(uint16_t)(p[4+n]*256u+p[5+n]);
            bound=(struct steer_pv1_endpoint){sizeof(bound),STEER_PV1_DRAFT_LAYOUT,
                n==4?STEER_PV1_ENDPOINT_IPV4:STEER_PV1_ENDPOINT_IPV6,{p+4,n},port,0};
        }
        /* Pure tunnel: all negotiation IO has been released. The lower
         * origin owns the stream; the host route guard pins this binding. */
        stream=op->stream;op->stream=(struct steer_pv1_stream_ref){0};
    }
    op->done(op->user,e,stream,bound.port?&bound:NULL,NULL,&op->diagnostic);
    op->completed=1;
}
static void abort_open(struct socks_open *op,uint32_t reason)
{
    if(op->terminal||op->aborted)return;
    op->aborted=reason;
    if(valid_stream(op->stream))op->stream.api->close(op->stream.handle);
    if(op->inner.handle)op->inner.api->cancel(op->inner.handle);
}
static void STEER_PV1_CALL cancel(struct steer_pv1_operation *handle)
{
    abort_open((struct socks_open *)handle,STEER_PV1_CANCELLED);
}
static void STEER_PV1_CALL release(struct steer_pv1_operation *handle)
{
    struct socks_open *op=(struct socks_open *)handle;
    if(!op->completed||op->released)return;
    op->completion.api->release(op->completion.handle);
    op->released=1;
    if(!op->quarantined)dispose(op);
}
static const struct steer_pv1_operation_api operation_api={
    sizeof(operation_api),STEER_PV1_DRAFT_LAYOUT,cancel,release
};
static void timeout(struct loop *loop,struct loop_timer *timer,void *arg)
{
    struct socks_open *op=arg;uint64_t now=steer_draft_stream_now_ns();(void)loop;
    if(now<op->deadline)steer_draft_stream_arm_deadline(timer,op->deadline,now);
    else abort_open(op,STEER_PV1_TIMEOUT);
}
static void lower_done(void *arg,struct steer_pv1_error e,struct steer_pv1_stream_ref stream,
    const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer,
    const struct steer_pv1_stream_open_diagnostic *diagnostic)
{
    struct socks_open *op=arg;(void)bound;(void)peer;
    op->result=e;op->stream=stream;
    if(diagnostic&&diagnostic->size>=sizeof(*diagnostic)&&
       diagnostic->version==STEER_PV1_STREAM_BACKEND_LAYOUT&&diagnostic->dial_failure<=STEER_PV1_STREAM_DIAL_OTHER)
        op->diagnostic.dial_failure=diagnostic->dial_failure;
    enqueue(op);
}
static void io_done(void *arg,struct steer_pv1_error e,struct steer_pv1_buffer *buffer,uint32_t bytes)
{
    struct socks_open *op=arg;
    op->result=e;op->buffer=buffer;op->bytes=bytes;enqueue(op);
}
static int writing(enum phase p) { return p==TX_GREETING||p==TX_AUTH||p==TX_CONNECT; }
static void submit(struct socks_open *op)
{
    if(steer_draft_stream_now_ns()>=op->deadline){complete(op,error(STEER_PV1_TIMEOUT));return;}
    struct steer_pv1_stream_ref s=op->stream;
    struct steer_pv1_async_start a=writing(op->phase)?
        s.api->write(s.handle,op->buffer,op->offset,op->length-op->offset,io_done,op):
        s.api->read(s.handle,op->buffer,op->offset,op->length-op->offset,io_done,op);
    if(a.disposition==STEER_PV1_PENDING){op->inner=a.operation;op->buffer=NULL;}
    else complete(op,a.error.code?a.error:error(STEER_PV1_PROTOCOL));
}
static void next(struct socks_open *op,enum phase phase,uint8_t *data)
{
    struct steer_draft_socks_stream_backend *b=op->backend;
    unsigned length=2;
    switch(phase){
    case TX_GREETING: length=(unsigned)s5_out_greeting(b->auth_len?S5_USERPASS:S5_NOAUTH,data,3);break;
    case TX_AUTH: length=(unsigned)b->auth_len;memcpy(data,b->auth,length);break;
    case TX_CONNECT: length=(unsigned)s5_out_connect(&op->target,data,STEER_DRAFT_SOCKS_HANDSHAKE_MAX);break;
    case RX_AUTH: wipe(data,b->auth_len);break;
    case RX_CONNECT: length=4;break;
    default: break;
    }
    if(!length){complete(op,error(STEER_PV1_PROTOCOL));return;}
    op->phase=phase;op->offset=0;op->length=length;submit(op);
}
static void connect_reply(struct socks_open *op,const uint8_t *data)
{
    size_t consumed;
    enum s5_out_event event=s5_out_reply_feed(&op->reply,data,op->length,&consumed);
    if(consumed!=op->length||event==S5_OUT_BAD_REPLY){complete(op,error(STEER_PV1_PROTOCOL));return;}
    if(event==S5_OUT_CONNECTED){complete(op,error(STEER_PV1_OK));return;}
    if(event==S5_OUT_REFUSED){
        switch(op->reply.code){
        case 2: complete(op,error(STEER_PV1_POLICY_DENIED));return;
        case 3: op->diagnostic.dial_failure=STEER_PV1_STREAM_DIAL_NETWORK_UNREACHABLE;break;
        case 4: op->diagnostic.dial_failure=STEER_PV1_STREAM_DIAL_HOST_UNREACHABLE;break;
        case 5: op->diagnostic.dial_failure=STEER_PV1_STREAM_DIAL_REFUSED;break;
        case 6: complete(op,error(STEER_PV1_TIMEOUT));return;
        default: op->diagnostic.dial_failure=STEER_PV1_STREAM_DIAL_OTHER;break;
        }
        complete(op,error(STEER_PV1_IO));return;
    }
    /* Read exactly the missing frame bytes. Any coalesced application data
     * stays in the transport, with no prefetch buffer or second relay. */
    op->offset=0;
    op->length=(unsigned)(op->reply.total?op->reply.total-op->reply.used:1);
    submit(op);
}
static void progress(struct socks_open *op)
{
    struct steer_draft_socks_stream_backend *b=op->backend;
    op->inner.api->release(op->inner.handle);op->inner=(struct steer_pv1_operation_ref){0};
    if(op->aborted){complete(op,error(op->aborted));return;}
    if(steer_draft_stream_now_ns()>=op->deadline){complete(op,error(STEER_PV1_TIMEOUT));return;}
    struct steer_pv1_error e=op->result;
    if(e.code>STEER_PV1_INTERNAL||e.transient>1||(!e.code&&e.transient))e=error(STEER_PV1_PROTOCOL);
    if(e.code){complete(op,e);return;}
    if(!valid_stream(op->stream)){complete(op,error(STEER_PV1_PROTOCOL));return;}
    if(op->phase!=DIAL){
        if(!op->bytes||op->bytes>op->length-op->offset){complete(op,error(STEER_PV1_PROTOCOL));return;}
        op->offset+=op->bytes;
        if(op->offset<op->length){submit(op);return;}
    }
    struct steer_pv1_mut_span view;
    e=b->buffers->writable(b->host,op->buffer,&view);
    if(e.code){complete(op,e);return;}
    switch(op->phase){
    case DIAL: next(op,TX_GREETING,view.data);break;
    case TX_GREETING: next(op,RX_METHOD,view.data);break;
    case RX_METHOD:
        if(!s5_out_method_ok(b->auth_len?S5_USERPASS:S5_NOAUTH,view.data,2))
            complete(op,error(STEER_PV1_AUTH_FAILED));
        else next(op,b->auth_len?TX_AUTH:TX_CONNECT,view.data);
        break;
    case TX_AUTH: next(op,RX_AUTH,view.data);break;
    case RX_AUTH:
        if(!s5_out_userpass_ok(view.data,2))complete(op,error(STEER_PV1_AUTH_FAILED));
        else next(op,TX_CONNECT,view.data);
        break;
    case TX_CONNECT: next(op,RX_CONNECT,view.data);break;
    case RX_CONNECT: connect_reply(op,view.data);break;
    }
}
static void work(struct loop *loop,struct loop_timer *timer,void *arg)
{
    struct steer_draft_socks_stream_backend *b=arg;
    uint32_t queued;(void)loop;
    b->dispatching=1;
    for(unsigned i=0;b->head&&i<BATCH;i++){
        struct socks_open *op=b->head;
        b->head=op->next;op->next=NULL;if(!b->head)b->tail=NULL;
        progress(op);
    }
    (void)steer_draft_operations_dispatch(b->operations,BATCH,NULL);
    b->dispatching=0;
    steer_draft_operations_usage(b->operations,NULL,&queued);
    if(queued||b->head)loop_timer_set(timer,0);else loop_timer_stop(timer);
}
static struct steer_pv1_async_start STEER_PV1_CALL open_socks(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *user)
{
    struct steer_draft_socks_stream_backend *b=context;
    if(!b||!done)return rejected(STEER_PV1_INVALID);
    struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM);
    if(e.code)return rejected(e.code);
    if(deadline<=steer_draft_stream_now_ns())return rejected(STEER_PV1_TIMEOUT);
    if(b->live>=b->max_opens)return rejected(STEER_PV1_RESOURCE_EXHAUSTED);
    e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);
    if(e.code)return rejected(e.code);
    struct socks_open *op=calloc(1,sizeof(*op));
    if(!op){(void)steer_draft_binding_unpin(b->binding.lease);return rejected(STEER_PV1_RESOURCE_EXHAUSTED);}
    op->backend=b;op->deadline=deadline;op->done=done;op->user=user;b->live++;
    op->target.type=flow->destination.tag==STEER_PV1_ENDPOINT_IPV4?1:
        flow->destination.tag==STEER_PV1_ENDPOINT_IPV6?4:3;
    op->target.length=(uint8_t)flow->destination.address.len;op->target.port=flow->destination.port;
    memcpy(op->target.bytes,flow->destination.address.data,op->target.length);
    s5_out_reply_init(&op->reply);
    op->diagnostic=(struct steer_pv1_stream_open_diagnostic){sizeof(op->diagnostic),STEER_PV1_STREAM_BACKEND_LAYOUT,0};
    op->timer=loop_timer_new(b->loop,timeout,op);
    if(!op->timer){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    e=b->buffers->allocate(b->host,STEER_DRAFT_SOCKS_HANDSHAKE_MAX,&op->buffer);
    if(e.code)goto fail;
    struct steer_pv1_async_start result=steer_draft_operation_start(b->operations,delivered,op);
    if(result.disposition!=STEER_PV1_PENDING){e=result.error;goto fail;}
    op->completion=result.operation;
    result.operation=(struct steer_pv1_operation_ref){(struct steer_pv1_operation *)op,&operation_api};
    uint64_t now=steer_draft_stream_now_ns();
    if(now>=deadline){complete(op,error(STEER_PV1_TIMEOUT));return result;}
    steer_draft_stream_arm_deadline(op->timer,deadline,now);
    struct steer_pv1_flow_metadata upstream=*flow;upstream.destination=b->upstream.value.destination;
    struct steer_pv1_async_start lower=b->lower.api->open(b->lower.context,&upstream,deadline,lower_done,op);
    if(lower.disposition==STEER_PV1_PENDING)op->inner=lower.operation;
    else complete(op,lower.error.code?lower.error:error(STEER_PV1_PROTOCOL));
    return result;
fail:
    if(op->buffer)b->buffers->release(b->host,op->buffer);
    loop_timer_free(op->timer);dispose(op);return rejected(e.code);
}
static const struct steer_pv1_stream_backend_api backend_api={
    sizeof(backend_api),STEER_PV1_STREAM_BACKEND_LAYOUT,open_socks
};
static void finalized(void *arg,const struct steer_draft_binding_identity *identity)
{
    struct steer_draft_socks_stream_backend *b=arg;(void)identity;
    b->finalized=1;if(b->retired)b->retired(b->user);
}
struct steer_pv1_error steer_draft_socks_stream_backend_create(struct loop *loop,struct steer_pv1_host *host,
    const struct steer_draft_stream_binding *lower,const struct steer_pv1_endpoint *upstream,
    struct steer_pv1_span username,struct steer_pv1_span password,uint64_t generation,uint64_t token,
    uint32_t max_opens,uint32_t max_references,void (*retired)(void *),void *user,
    struct steer_draft_socks_stream_backend **out)
{
    if(out)*out=NULL;
    if(!loop||!host||!lower||lower->owner!=loop||!lower->lease||!lower->api||
       !upstream||!generation||!token||!max_opens||!max_references||!out||
       (!!username.len!=!!password.len)||username.len>255||password.len>255||
       (username.len&&(!username.data||!password.data)))return error(STEER_PV1_INVALID);
    const struct steer_draft_binding_identity *id=steer_draft_binding_identity(lower->lease);
    if(id->generation!=generation||id->flow_class!=STEER_PV1_FLOW_STREAM)return error(STEER_PV1_POLICY_DENIED);
    if(!(id->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_PREPARED)||
       (upstream->tag==STEER_PV1_ENDPOINT_DOMAIN&&!(id->prepared_capabilities&STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN))||
       lower->api->size<sizeof(*lower->api)||lower->api->version!=STEER_PV1_STREAM_BACKEND_LAYOUT||
       !lower->api->open)return error(STEER_PV1_UNSUPPORTED);
    struct steer_draft_socks_stream_backend *b=calloc(1,sizeof(*b));
    if(!b)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    static const uint8_t source[4]={127,0,0,1},inbound[]="prepared",provider[]="steer.socks5.tcp";
    struct steer_pv1_flow_metadata sample={.size=sizeof(sample),.version=STEER_PV1_DRAFT_LAYOUT,
        .generation=generation,.inbound_id={inbound,sizeof(inbound)-1},
        .source={sizeof(sample.source),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{source,4},1,0},
        .destination=*upstream,.flow_class=STEER_PV1_FLOW_STREAM};
    struct steer_pv1_error e=steer_draft_flow_copy(&b->upstream,&sample,STEER_PV1_FLOW_STREAM);
    if(e.code)goto fail;
    e=steer_draft_binding_admit(lower->lease,generation,STEER_PV1_FLOW_STREAM);
    if(e.code)goto fail;
    b->lower=*lower;b->loop=loop;b->host=host;b->buffers=steer_draft_buffers_api();
    b->max_opens=max_opens;b->retired=retired;b->user=user;
    if(username.len){
        b->auth_len=s5_out_userpass(username.data,username.len,password.data,password.len,b->auth,sizeof(b->auth));
        if(!b->auth_len){e=error(STEER_PV1_INVALID);goto fail;}
    }
    e=steer_draft_operations_create(max_opens,NULL,&b->operations);if(e.code)goto fail;
    b->work=loop_timer_new(loop,work,b);if(!b->work){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}
    struct steer_draft_binding_identity own={sizeof(own),STEER_PV1_DRAFT_LAYOUT,generation,token,
        {provider,sizeof(provider)-1},STEER_DRAFT_STREAM_BINDING_PREPARED|STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN,
        STEER_PV1_FLOW_STREAM};
    e=steer_draft_binding_lease_create(loop,&own,max_references,finalized,b,&b->binding.lease);
    if(e.code)goto fail;
    b->binding.owner=loop;b->binding.api=&backend_api;b->binding.context=b;*out=b;return error(STEER_PV1_OK);
fail:
    loop_timer_free(b->work);
    if(b->operations)(void)steer_draft_operations_destroy(b->operations);
    if(b->lower.lease)(void)steer_draft_binding_unpin(b->lower.lease);
    wipe(b->auth,sizeof(b->auth));free(b);return e;
}
const struct steer_draft_stream_binding *steer_draft_socks_stream_binding(const struct steer_draft_socks_stream_backend *b)
{
    return b?&b->binding:NULL;
}
void steer_draft_socks_stream_backend_retire(struct steer_draft_socks_stream_backend *b)
{
    if(b)(void)steer_draft_binding_retire(b->binding.lease);
}
struct steer_pv1_error steer_draft_socks_stream_backend_destroy(struct steer_draft_socks_stream_backend *b)
{
    if(!b)return error(STEER_PV1_INVALID);
    if(!b->finalized||b->dispatching||b->live)return error(STEER_PV1_POLICY_DENIED);
    struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);if(e.code)return e;
    (void)steer_draft_operations_destroy(b->operations);loop_timer_free(b->work);
    (void)steer_draft_binding_unpin(b->lower.lease);wipe(b->auth,sizeof(b->auth));free(b);
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_socks_stream_backend_recover(struct steer_draft_socks_stream_backend *b)
{
    if(!b||b->dispatching)return error(STEER_PV1_INVALID);
    struct socks_open **link=&b->quarantine;
    for(unsigned i=0;*link&&i<BATCH;i++){
        struct socks_open *op=*link;
        if(op->released&&discard(op)){*link=op->next;dispose(op);}
        else link=&op->next;
    }
    return error(b->quarantine?STEER_PV1_POLICY_DENIED:STEER_PV1_OK);
}
