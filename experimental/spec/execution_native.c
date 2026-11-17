#include "execution_native.h"
#include "ynode.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
struct prepared {uint32_t flows;};
struct bound {
    struct steer_spec_native_services *services;
    struct steer_spec_execution_owner owner;
    struct steer_draft_native_stream_backend *stream;
    struct steer_draft_binding_lease *datagram;
    int datagram_done;
};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static int validate(void *context,const struct steer_spec_node_view *node){
    const struct steer_spec_native_services *s=context;
    return node->kind==STEER_SPEC_OUTBOUND&&!strcmp(node->type,"direct")&&!node->options&&!node->endpoint&&
        !node->listen&&!node->device&&!node->transport&&!node->security&&!node->variant&&
        !ynode_get(node->intent,"detour")&&!ynode_get(node->intent,"resolve_via")&&
        (!(node->flows&STEER_SPEC_FLOW_STREAM)||(s->streams&&s->stream_refs))&&
        (!(node->flows&STEER_SPEC_FLOW_DATAGRAM)||s->datagrams)&&!(node->flows&~3u);
}
static struct steer_pv1_error prepare(void *context,const struct steer_spec_node_view *node,
    const struct steer_spec_execution_dependency *deps,uint32_t count,uint64_t deadline,
    const struct steer_draft_cancel *cancel,void **out){
    (void)context;(void)deps;(void)deadline;(void)cancel;*out=NULL;
    if(count)return error(STEER_PV1_UNSUPPORTED);
    struct prepared *p=calloc(1,sizeof(*p));if(!p)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    p->flows=node->flows;*out=p;return error(0);
}
static void discard(void *context,void *state){(void)context;free(state);}
static void stream_done(void *arg){struct bound *b=arg;b->owner.wake(b->owner.wake_context);}
static void datagram_done(void *arg,const struct steer_draft_binding_identity *id){
    (void)id;struct bound *b=arg;b->datagram_done=1;b->owner.wake(b->owner.wake_context);
}
static struct steer_pv1_error bind_instance(void *context,void *state,const struct steer_spec_node_view *node,
    const struct steer_spec_execution_dependency *deps,uint32_t count,const struct steer_spec_execution_owner *owner,
    struct steer_spec_execution_instance *out){
    (void)node;(void)deps;struct steer_spec_native_services *s=context;struct prepared *p=state;
    if(s->owner!=owner->loop||count)return error(STEER_PV1_INVALID);
    struct bound *b=calloc(1,sizeof(*b));if(!b)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    b->services=s;b->owner=*owner;out->handle=b;struct steer_pv1_error result=error(0);
    if(p->flows&STEER_SPEC_FLOW_STREAM){
        result=steer_draft_native_stream_backend_create(owner->loop,s->streams,s->stream_refs,s->resolver,
            owner->generation,owner->instance_token,s->max_operations,s->max_references,stream_done,b,&b->stream);
        if(result.code)return result;
        out->stream=*steer_draft_native_stream_binding(b->stream);
    }
    if(p->flows&STEER_SPEC_FLOW_DATAGRAM){
        static const uint8_t provider[]="steer.native.udp";
        struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,owner->generation,owner->instance_token,
            {provider,sizeof(provider)-1},STEER_DRAFT_DATAGRAM_BINDING_PREPARED,STEER_PV1_FLOW_DATAGRAM};
        if(steer_draft_datagram_has_resolver(s->datagrams))id.prepared_capabilities|=STEER_DRAFT_DATAGRAM_BINDING_TARGET_DOMAIN;
        result=steer_draft_binding_lease_create(owner->loop,&id,s->max_references,datagram_done,b,&b->datagram);
        if(result.code)return result;
        out->datagram=(struct steer_draft_datagram_binding){owner->loop,b->datagram,steer_draft_datagram_backend_api(),s->datagrams};
    }
    return result;
}
static void retire(void *context,struct steer_spec_execution_instance *out){
    (void)context;struct bound *b=out->handle;
    if(b->stream)(void)steer_draft_native_stream_backend_retire(b->stream);
    if(b->datagram)(void)steer_draft_binding_retire(b->datagram);
}
static struct steer_pv1_error collect(void *context,struct steer_spec_execution_instance *out){
    (void)context;struct bound *b=out->handle;
    if(b->stream){
        struct steer_pv1_error e=steer_draft_native_stream_backend_destroy(b->stream);if(e.code)return e;
        b->stream=NULL;memset(&out->stream,0,sizeof(out->stream));
    }
    if(b->datagram){
        if(!b->datagram_done)return error(STEER_PV1_POLICY_DENIED);
        struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->datagram);if(e.code)return e;
        b->datagram=NULL;memset(&out->datagram,0,sizeof(out->datagram));
    }
    free(b);memset(out,0,sizeof(*out));return error(0);
}
struct steer_pv1_error steer_spec_native_factory(struct steer_spec_native_services *s,
    const struct steer_spec_execution_guard *guard,struct steer_spec_execution_factory *out){
    if(!s||!guard||!guard->retain||!guard->release||!out||!s->owner||
       (!!s->streams!=!!s->stream_refs)||(!s->streams&&!s->datagrams)||!s->max_operations||s->max_operations>4096||
       s->max_references<4||s->max_references>65536)return error(STEER_PV1_INVALID);
    static const char *const caps[]={"core.outbound.direct"};
    *out=(struct steer_spec_execution_factory){.size=sizeof(*out),.version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT,
        .kind=STEER_SPEC_OUTBOUND,.type="direct",.transport="tcp",.security="none",.variant="default",
        .stream_provider_id=s->streams?"steer.native.tcp":NULL,.datagram_provider_id=s->datagrams?"steer.native.udp":NULL,
        .flows=(s->streams?STEER_SPEC_FLOW_STREAM:0)|(s->datagrams?STEER_SPEC_FLOW_DATAGRAM:0),
        .capabilities=caps,.capability_count=1,.guard=*guard,.context=s,.validate=validate,.prepare=prepare,
        .discard=discard,.bind=bind_instance,.retire=retire,.collect=collect};
    return error(0);
}
