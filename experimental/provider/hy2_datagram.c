/* SPDX-License-Identifier: GPL-3.0-only */
#define _POSIX_C_SOURCE 200809L
#include "hy2_datagram.h"
#include "hy2_address.h"
#include "flow_metadata.h"
#include "hy2wire.h"
#include "loop.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
struct session;
struct target;
struct packet {struct packet *next;struct steer_pv1_buffer *buffer;uint32_t length,charge;};
struct context {
    struct context *next;
    struct steer_draft_hy2_datagram_binding binding;
    struct steer_pv1_datagram_association_ref association;
    int quarantined;
};
struct io {
    struct target *target;struct steer_pv1_async_start operation;
    struct steer_pv1_buffer *buffer;uint32_t bytes,error;
    int pending,done;
};
struct target {
    struct target *next,*dispatch_next;struct session *session;struct context *context;
    struct steer_pv1_datagram_ref origin;
    struct steer_pv1_async_start opening;
    struct packet *head,*tail;
    struct io send,receive;
    char address[264],reply_address[264];uint64_t used;
    size_t reply_length,reply_offset,reply_part,reply_count,reply_index;
    uint16_t reply_packet;
    uint32_t open_error;
    int open_pending,open_done,closing,reply_pending,quarantined,receive_reserved,receive_allocated;
};
struct session {
    struct session *next;struct steer_draft_hy2_datagram *owner;
    struct context *contexts;struct target *targets;struct hy2_rasm *reassembly;
    uint32_t id;uint16_t packet;uint64_t used;
};
struct steer_draft_hy2_datagram {
    struct steer_draft_hy2_datagram_config cfg;
    struct steer_draft_hy2_datagram_services services;
    const struct steer_pv1_buffer_api *buffers;
    struct session *sessions;
    struct target *dispatch_head,*dispatch_tail;
    struct loop_timer *timer;
    char inbound[65],principal[65];uint8_t source[16];
    struct steer_draft_hy2_datagram_usage usage;
    int retired,stopping,polling,wake_requested;
};
static uint64_t now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
static uint64_t now_ms(void){return now_ns()/1000000;}
static void wake(struct steer_draft_hy2_datagram *a){a->wake_requested=1;if(!a->polling)loop_timer_set(a->timer,0);a->cfg.wake(a->cfg.transport);}
void steer_draft_hy2_datagram_budget_init(struct steer_draft_hy2_datagram_budget *budget){
    if(budget)*budget=(struct steer_draft_hy2_datagram_budget){.max_receives=STEER_DRAFT_HY2_UDP_RECEIVES,.max_packets=STEER_DRAFT_HY2_UDP_PACKETS,.max_upload_bytes=STEER_DRAFT_HY2_UDP_UPLOAD_BYTES};
}
static int upload_reserve(struct steer_draft_hy2_datagram *a,size_t bytes){
    struct steer_draft_hy2_datagram_budget *b=a->services.budget;
    if(b->upload_bytes>b->max_upload_bytes||bytes>b->max_upload_bytes-b->upload_bytes||bytes>a->cfg.max_queued_bytes-a->usage.queued_bytes)return 0;
    b->upload_bytes+=bytes;a->usage.queued_bytes+=bytes;return 1;
}
static void upload_release(struct steer_draft_hy2_datagram *a,size_t bytes){
    struct steer_draft_hy2_datagram_budget *b=a->services.budget;
    if(bytes>b->upload_bytes||bytes>a->usage.queued_bytes)abort();
    b->upload_bytes-=bytes;a->usage.queued_bytes-=bytes;
}
static void expire_assembly(struct session *s,uint64_t now){
    size_t before=hy2_rasm_local_bytes(s->reassembly);hy2_rasm_expire(&s->reassembly,now);
    upload_release(s->owner,before-hy2_rasm_local_bytes(s->reassembly));
}
static void packet_free(struct steer_draft_hy2_datagram *a,struct packet *p){
    a->buffers->release(a->services.buffers,p->buffer);a->usage.packets--;a->services.budget->packets--;upload_release(a,p->charge);free(p);
}
static void close_target(struct target *t){
    if(t->closing)return;
    t->closing=1;t->reply_pending=0;
    if(t->open_pending&&!t->open_done)t->opening.operation.api->cancel(t->opening.operation.handle);
    if(t->origin.handle)t->origin.api->close(t->origin.handle);
    wake(t->session->owner);
}
static void io_done(void *user,struct steer_pv1_error error,struct steer_pv1_buffer *buffer,uint32_t bytes){
    struct io *io=user;struct steer_draft_hy2_datagram *a=io->target->session->owner;
    if(io->target->closing)a->usage.completed_after_cancel++;
    io->buffer=buffer;io->error=error.code;io->bytes=bytes;io->done=1;wake(a);
}
static int peer_address(const struct steer_pv1_endpoint *peer,char out[264]){
    char host[255];int length;
    if(!peer||peer->size<sizeof *peer||peer->version!=STEER_PV1_DRAFT_LAYOUT||!peer->port||!peer->address.data)return -1;
    if(peer->tag==STEER_PV1_ENDPOINT_IPV4&&peer->address.len==4){
        if(!inet_ntop(AF_INET,peer->address.data,host,sizeof host))return -1;
        length=snprintf(out,264,"%s:%u",host,peer->port);
    }else if(peer->tag==STEER_PV1_ENDPOINT_IPV6&&peer->address.len==16){
        if(!inet_ntop(AF_INET6,peer->address.data,host,sizeof host))return -1;
        length=snprintf(out,264,"[%s]:%u",host,peer->port);
    }else if(peer->tag==STEER_PV1_ENDPOINT_DOMAIN&&peer->address.len&&peer->address.len<=254&&!memchr(peer->address.data,0,peer->address.len)){
        memcpy(host,peer->address.data,peer->address.len);host[peer->address.len]=0;
        length=snprintf(out,264,"%s:%u",host,peer->port);
    }else return -1;
    return length>0&&length<264?0:-1;
}
static void opened(void *user,struct steer_pv1_error error,struct steer_pv1_datagram_ref ref,
                   const struct steer_pv1_endpoint *bound,const struct steer_pv1_endpoint *peer){
    struct target *t=user;(void)bound;
    t->origin=ref;t->open_error=error.code;t->open_done=1;
    if(!error.code&&peer_address(peer,t->reply_address))t->open_error=STEER_PV1_INVALID;
    if(t->closing){t->session->owner->usage.completed_after_cancel++;if(ref.handle)ref.api->close(ref.handle);}
    wake(t->session->owner);
}
static void reply_begin(struct target *t,size_t length){
    struct session *s=t->session;struct steer_draft_hy2_datagram *a=s->owner;
    uint8_t header[300];size_t limit=a->cfg.message_limit(a->cfg.transport);
    size_t n=hy2_udp_header(header,sizeof header,s->id,0,0,1,t->reply_address);
    if(!n||limit<=n||limit>65535){a->usage.dropped_packets++;return;}
    size_t part=limit-n,count=length?(length+part-1)/part:1;
    if(count>255){a->usage.dropped_packets++;return;}
    t->reply_pending=1;t->reply_length=length;t->reply_offset=0;t->reply_index=0;
    t->reply_part=part;t->reply_count=count;t->reply_packet=count>1?++s->packet:0;
}
static void reply_flush(struct target *t,unsigned *budget){
    struct steer_draft_hy2_datagram *a=t->session->owner;struct steer_pv1_mut_span view;uint8_t wire[65535];
    if(!t->reply_pending||t->closing)return;
    if(a->buffers->writable(a->services.buffers,t->receive.buffer,&view).code){close_target(t);return;}
    while(*budget&&t->reply_index<t->reply_count){
        size_t amount=t->reply_length-t->reply_offset;if(amount>t->reply_part)amount=t->reply_part;
        size_t header=hy2_udp_header(wire,sizeof wire,t->session->id,t->reply_packet,
            (uint8_t)t->reply_index,(uint8_t)t->reply_count,t->reply_address);
        if(amount)memcpy(wire+header,view.data+t->reply_offset,amount);
        (*budget)--;
        if(a->cfg.send(a->cfg.transport,wire,header+amount)){a->usage.dropped_packets++;t->reply_pending=0;return;}
        t->reply_offset+=amount;t->reply_index++;
    }
    if(t->reply_index==t->reply_count)t->reply_pending=0;else wake(a);
}
static struct steer_pv1_flow_metadata metadata(struct steer_draft_hy2_datagram *a,
    uint64_t generation,struct steer_pv1_endpoint destination){
    struct steer_pv1_flow_metadata value={.size=sizeof value,.version=STEER_PV1_DRAFT_LAYOUT,
        .generation=generation,.inbound_id=a->cfg.inbound,.principal_id=a->cfg.principal,
        .source=a->cfg.source,.destination=destination,.flow_class=STEER_PV1_FLOW_DATAGRAM};return value;
}
static struct target *target_create(struct session *s,const char *address){
    struct steer_draft_hy2_datagram *a=s->owner;struct steer_draft_hy2_datagram_binding binding={0};
    char host[2049];uint8_t ip[16];struct steer_pv1_endpoint destination;
    if(a->retired||a->stopping||a->usage.targets>=a->cfg.max_targets||a->services.budget->receives>=a->services.budget->max_receives||
       steer_draft_hy2_address((const uint8_t *)address,strlen(address),host,ip,&destination))return NULL;
    if(a->services.acquire(a->services.context,a->cfg.inbound,a->cfg.principal,a->cfg.admission_epoch,&binding).code)return NULL;
    struct steer_pv1_flow_metadata flow=metadata(a,binding.generation,destination);
    if(!binding.api||binding.api->size<sizeof *binding.api||binding.api->version!=STEER_PV1_DRAFT_LAYOUT||
       !binding.api->create||!binding.api->open_target||!binding.api->close||!binding.api->release||
       !binding.context||!binding.generation||steer_draft_flow_validate(&flow,STEER_PV1_FLOW_DATAGRAM).code){a->services.release(a->services.context,&binding);return NULL;}
    struct context *ctx=s->contexts;
    while(ctx&&ctx->binding.generation!=binding.generation)ctx=ctx->next;
    if(ctx){a->services.release(a->services.context,&binding);}
    else{
        if(a->usage.contexts>=a->cfg.max_contexts){a->services.release(a->services.context,&binding);return NULL;}
        ctx=calloc(1,sizeof *ctx);
        if(!ctx){a->services.release(a->services.context,&binding);return NULL;}
        ctx->binding=binding;
        if(binding.api->create(binding.context,&flow,&ctx->association).code){a->services.release(a->services.context,&ctx->binding);free(ctx);return NULL;}
        ctx->next=s->contexts;s->contexts=ctx;a->usage.contexts++;
    }
    struct target *t=calloc(1,sizeof *t);if(!t)return NULL;
    a->services.budget->receives++;t->receive_reserved=1;
    t->session=s;t->context=ctx;t->used=now_ms();t->send.target=t;t->receive.target=t;strcpy(t->address,address);
    t->opening=ctx->association.api->open_target(ctx->association.handle,&destination,
        now_ns()+a->cfg.operation_ms*1000000,opened,t);
    if(t->opening.disposition!=STEER_PV1_PENDING){a->services.budget->receives--;free(t);return NULL;}
    t->open_pending=1;
    if(a->dispatch_tail)a->dispatch_tail->dispatch_next=t;else a->dispatch_head=t;
    a->dispatch_tail=t;
    t->next=s->targets;s->targets=t;a->usage.targets++;a->usage.operations++;return t;
}
static int queue_packet(struct target *t,const uint8_t *data,size_t length){
    struct steer_draft_hy2_datagram *a=t->session->owner;uint32_t charge=length?(uint32_t)length:1;
    if(a->usage.packets>=a->cfg.max_packets||a->services.budget->packets>=a->services.budget->max_packets||!upload_reserve(a,charge))return -1;
    struct packet *p=calloc(1,sizeof *p);if(!p){upload_release(a,charge);return -1;}
    if(a->buffers->allocate(a->services.buffers,charge,&p->buffer).code){free(p);upload_release(a,charge);return -1;}
    struct steer_pv1_mut_span view;
    if(a->buffers->writable(a->services.buffers,p->buffer,&view).code){a->buffers->release(a->services.buffers,p->buffer);free(p);upload_release(a,charge);return -1;}
    if(length)memcpy(view.data,data,length);
    p->length=(uint32_t)length;p->charge=charge;
    if(t->tail)t->tail->next=p;else t->head=p;t->tail=p;
    a->usage.packets++;a->services.budget->packets++;t->used=now_ms();return 0;
}
void steer_draft_hy2_datagram_input(struct steer_draft_hy2_datagram *a,const uint8_t *data,size_t length){
    struct hy2_udp_msg message;struct session *s;uint8_t *assembled=NULL;size_t size=0;
    if(!a||a->stopping||!data||hy2_udp_parse(data,length,&message)||message.n>65507){if(a)a->usage.dropped_packets++;return;}
    for(s=a->sessions;s&&s->id!=message.sid;s=s->next){}
    if(!s){
        if(a->retired||a->usage.sessions>=a->cfg.max_sessions)goto drop;
        s=calloc(1,sizeof *s);if(!s)goto drop;
        s->owner=a;s->id=message.sid;s->next=a->sessions;a->sessions=s;a->usage.sessions++;
    }
    s->used=now_ms();
    if(message.nfrag>1){
        expire_assembly(s,s->used);
        size_t before=hy2_rasm_local_bytes(s->reassembly),reserve=hy2_rasm_required(s->reassembly,&message);
        if(!upload_reserve(a,reserve))goto drop;
        assembled=hy2_rasm_feed(&s->reassembly,&message,s->used,0,&size);
        size_t retained=hy2_rasm_local_bytes(s->reassembly),output=assembled?(size?size:1):0;
        if(before+reserve<retained+output)abort();
        upload_release(a,before+reserve-retained-output);
        if(!assembled){wake(a);return;}
        message.data=assembled;message.n=size;
    }
    struct target *t=s->targets;
    while(t&&strcmp(t->address,message.addr))t=t->next;
    if(t&&t->closing)goto drop;
    if(!t)t=target_create(s,message.addr);
    if(!t||queue_packet(t,message.data,message.n))goto drop;
    if(assembled)upload_release(a,size?size:1);
    free(assembled);wake(a);return;
drop:
    if(assembled)upload_release(a,size?size:1);
    free(assembled);a->usage.dropped_packets++;wake(a);
}

static void pump_target(struct target *t,unsigned *fragment_budget){
    struct steer_draft_hy2_datagram *a=t->session->owner;
    if(t->open_done){
        t->opening.operation.api->release(t->opening.operation.handle);
        t->open_done=t->open_pending=0;a->usage.operations--;
        if(t->open_error||!t->origin.handle)close_target(t);
    }
    if(t->send.done){
        struct packet *p=t->head;
        t->send.operation.operation.api->release(t->send.operation.operation.handle);
        t->send.pending=t->send.done=0;a->usage.operations--;
        p->buffer=t->send.buffer;t->send.buffer=NULL;
        if(t->send.error||t->send.bytes!=p->length){a->usage.dropped_packets++;close_target(t);}
        t->head=p->next;if(!t->head)t->tail=NULL;packet_free(a,p);
    }
    if(t->receive.done){
        t->receive.operation.operation.api->release(t->receive.operation.operation.handle);
        t->receive.pending=t->receive.done=0;a->usage.operations--;
        if(!t->closing){
            if(!t->receive.error){
                reply_begin(t,t->receive.bytes);t->used=now_ms();
            }else if(t->receive.error==STEER_PV1_RESOURCE_EXHAUSTED){a->usage.dropped_packets++;}
            else if(t->receive.error!=STEER_PV1_TIMEOUT)close_target(t);
        }
    }
    reply_flush(t,fragment_budget);
    if(t->closing||t->open_pending||!t->origin.handle)return;
    if(!t->receive.buffer&&!t->receive.pending){
        if(65507>a->cfg.max_queued_bytes-a->usage.queued_bytes||a->buffers->allocate(a->services.buffers,65507,&t->receive.buffer).code){close_target(t);return;}
        t->receive_allocated=1;a->usage.queued_bytes+=65507;
    }
    if(!t->receive.pending&&!t->reply_pending){
        t->receive.operation=t->origin.api->receive(t->origin.handle,t->receive.buffer,0,65507,
            now_ns()+a->cfg.operation_ms*1000000,io_done,&t->receive);
        if(t->receive.operation.disposition!=STEER_PV1_PENDING){close_target(t);return;}
        t->receive.buffer=NULL;t->receive.pending=1;a->usage.operations++;
    }
    if(t->head&&!t->send.pending){
        struct packet *p=t->head;
        if(p->length>t->origin.api->message_limit(t->origin.handle)){a->usage.dropped_packets++;t->head=p->next;if(!t->head)t->tail=NULL;packet_free(a,p);wake(a);return;}
        t->send.operation=t->origin.api->send(t->origin.handle,p->buffer,0,p->length,
            now_ns()+a->cfg.operation_ms*1000000,io_done,&t->send);
        if(t->send.operation.disposition!=STEER_PV1_PENDING){close_target(t);return;}
        p->buffer=NULL;t->send.pending=1;a->usage.operations++;
    }
}
void steer_draft_hy2_datagram_poll(struct steer_draft_hy2_datagram *a){
    if(!a||a->polling)return;
    a->polling=1;a->wake_requested=0;
    unsigned fragment_budget=32,dispatch=a->usage.targets<32?a->usage.targets:32;
    for(unsigned i=0;i<dispatch;i++){
        struct target *t=a->dispatch_head;
        if(a->dispatch_head!=a->dispatch_tail){a->dispatch_head=t->dispatch_next;t->dispatch_next=NULL;a->dispatch_tail->dispatch_next=t;a->dispatch_tail=t;}
        pump_target(t,&fragment_budget);
    }
    uint64_t time=now_ms();struct session **link=&a->sessions;
    while(*link){
        struct session *s=*link;expire_assembly(s,time);
        struct target **next=&s->targets;
        while(*next){
            struct target *t=*next;
            if(a->stopping||time-t->used>=a->cfg.idle_ms)close_target(t);
            if(t->closing&&!t->quarantined&&!t->open_pending&&!t->send.pending&&!t->receive.pending){
                if(t->origin.handle){
                    struct steer_pv1_error error=t->origin.api->release(t->origin.handle);
                    if(error.code){t->quarantined=1;a->usage.quarantined++;next=&t->next;continue;}t->origin.handle=NULL;
                }
                while(t->head){struct packet *p=t->head;t->head=p->next;packet_free(a,p);}
                if(t->receive_allocated){if(!t->receive.buffer)abort();a->buffers->release(a->services.buffers,t->receive.buffer);a->usage.queued_bytes-=65507;}
                if(t->receive_reserved)a->services.budget->receives--;
                struct target **global=&a->dispatch_head,*previous=NULL;
                while(*global!=t){previous=*global;global=&(*global)->dispatch_next;}
                *global=t->dispatch_next;if(a->dispatch_tail==t)a->dispatch_tail=previous;
                *next=t->next;free(t);a->usage.targets--;continue;
            }
            next=&t->next;
        }
        struct context **context=&s->contexts;
        while(*context){
            struct context *ctx=*context;struct target *t=s->targets;
            while(t&&t->context!=ctx)t=t->next;
            if(t){context=&ctx->next;continue;}
            if(ctx->quarantined){context=&ctx->next;continue;}
            ctx->association.api->close(ctx->association.handle);
            if(ctx->association.api->release(ctx->association.handle).code){ctx->quarantined=1;a->usage.quarantined++;context=&ctx->next;continue;}
            a->services.release(a->services.context,&ctx->binding);
            *context=ctx->next;free(ctx);a->usage.contexts--;
        }
        if(!s->targets&&!s->contexts&&(a->stopping||time-s->used>=a->cfg.idle_ms)){
            upload_release(a,hy2_rasm_local_bytes(s->reassembly));hy2_rasm_free(&s->reassembly);*link=s->next;free(s);a->usage.sessions--;continue;
        }
        link=&s->next;
    }
    unsigned burst=32-fragment_budget;
    if(burst>a->usage.max_fragment_burst)a->usage.max_fragment_burst=burst;
    for(struct target *t=a->dispatch_head;t;t=t->dispatch_next)
        if(t->open_done||t->send.done||t->receive.done||t->reply_pending||
           (!t->closing&&!t->open_pending&&t->origin.handle&&(!t->receive.pending||(!t->send.pending&&t->head))))a->wake_requested=1;
    a->polling=0;
    if(a->wake_requested)loop_timer_set(a->timer,0);else if(a->sessions)loop_timer_set(a->timer,1000);
}
void steer_draft_hy2_datagram_retire(struct steer_draft_hy2_datagram *a){if(a)a->retired=1;}
void steer_draft_hy2_datagram_stop(struct steer_draft_hy2_datagram *a){
    if(!a||a->stopping)return;
    a->stopping=a->retired=1;
    for(struct session *s=a->sessions;s;s=s->next)for(struct target *t=s->targets;t;t=t->next)close_target(t);
    wake(a);
}
int steer_draft_hy2_datagram_destroy(struct steer_draft_hy2_datagram *a){
    if(!a)return 0;
    if(!a->stopping||a->polling||a->sessions||a->usage.operations)return -1;
    loop_timer_free(a->timer);free(a);return 0;
}
void steer_draft_hy2_datagram_usage(const struct steer_draft_hy2_datagram *a,struct steer_draft_hy2_datagram_usage *out){
    if(out){memset(out,0,sizeof *out);if(a)*out=a->usage;}
}
static void timed(struct loop *loop,struct loop_timer *timer,void *user){(void)loop;(void)timer;steer_draft_hy2_datagram_poll(user);}
int steer_draft_hy2_datagram_create(const struct steer_draft_hy2_datagram_config *cfg,
    const struct steer_draft_hy2_datagram_services *services,struct steer_draft_hy2_datagram **out){
    if(out)*out=NULL;
    if(!out||!cfg||!services||!services->loop||!services->buffers||!services->budget||!services->budget->max_receives||!services->budget->max_packets||!services->budget->max_upload_bytes||!services->acquire||!services->release||
       !cfg->message_limit||!cfg->send||!cfg->wake)return -1;
    struct steer_draft_hy2_datagram_config normalized=*cfg;
    if(!normalized.max_sessions)normalized.max_sessions=16;
    if(!normalized.max_targets)normalized.max_targets=64;
    if(!normalized.max_contexts)normalized.max_contexts=64;
    if(!normalized.max_packets)normalized.max_packets=64;
    if(!normalized.max_queued_bytes)normalized.max_queued_bytes=1048576;
    if(!normalized.idle_ms)normalized.idle_ms=60000;
    if(!normalized.operation_ms)normalized.operation_ms=5000;
    if(normalized.max_sessions>128||normalized.max_targets>256||normalized.max_contexts>256||normalized.max_packets>1024||
       normalized.max_queued_bytes<65508||normalized.max_queued_bytes>16777216||normalized.idle_ms>600000||normalized.operation_ms>60000)return -1;
    struct steer_draft_hy2_datagram *a=calloc(1,sizeof *a);if(!a)return -1;
    a->cfg=normalized;a->services=*services;a->buffers=steer_draft_buffers_api();
    /* Reuse the common validator for trusted identity/source before copying. */
    struct steer_pv1_flow_metadata check=metadata(a,1,cfg->source);
    if(steer_draft_flow_validate(&check,STEER_PV1_FLOW_DATAGRAM).code){free(a);return -1;}
    memcpy(a->inbound,cfg->inbound.data,cfg->inbound.len);if(cfg->principal.len)memcpy(a->principal,cfg->principal.data,cfg->principal.len);
    memcpy(a->source,cfg->source.address.data,cfg->source.address.len);
    a->cfg.inbound.data=(const uint8_t *)a->inbound;a->cfg.principal.data=(const uint8_t *)a->principal;a->cfg.source.address.data=a->source;
    a->timer=loop_timer_new(services->loop,timed,a);if(!a->timer){free(a);return -1;}
    *out=a;return 0;
}
