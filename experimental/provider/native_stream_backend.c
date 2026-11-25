#include "native_stream_backend.h"
#include "route_dial.h"
#include <stdlib.h>

struct steer_draft_native_stream_backend {
 struct steer_draft_stream_binding binding;
 struct steer_draft_routes *routes;
 struct steer_draft_backend_runtime *streams;
 uint32_t live,max_operations;int finalized;
 steer_draft_native_stream_retired retired;void *userdata;
};
struct native_open {
 struct steer_draft_native_stream_backend *backend;
 struct steer_draft_flow_owned flow;
 struct steer_pv1_operation_ref inner;
 steer_pv1_stream_open_done done;void *userdata;int completed;
};
static struct steer_pv1_error error(uint32_t c){struct steer_pv1_error e={c,0};return e;}
static struct steer_pv1_async_start rejected(uint32_t c){struct steer_pv1_async_start a={STEER_PV1_REJECTED,{c,0},{NULL,NULL}};return a;}
static void unpin(void *lease){(void)steer_draft_binding_unpin(lease);}
static struct steer_pv1_error direct(void *ctx,const struct steer_draft_accepted *f,uint32_t *action){
 (void)ctx;(void)f;*action=STEER_DRAFT_ROUTE_DIRECT;return error(STEER_PV1_OK);
}
static void finalized(void *arg,const struct steer_draft_binding_identity *identity){
 (void)identity;struct steer_draft_native_stream_backend *b=arg;b->finalized=1;
 if(b->retired)b->retired(b->userdata);
}
static void STEER_PV1_CALL cancel_open(struct steer_pv1_operation *opaque){
 struct native_open *op=(struct native_open *)opaque;op->inner.api->cancel(op->inner.handle);
}
static void STEER_PV1_CALL release_open(struct steer_pv1_operation *opaque){
 struct native_open *op=(struct native_open *)opaque;if(!op->completed)return;
 struct steer_draft_native_stream_backend *b=op->backend;
 op->inner.api->release(op->inner.handle);b->live--;free(op);unpin(b->binding.lease);
}
static const struct steer_pv1_operation_api operation_api={
 sizeof(struct steer_pv1_operation_api),STEER_PV1_DRAFT_LAYOUT,cancel_open,release_open
};
static void connected(void *arg,struct steer_pv1_error e,uint32_t failure,
    struct steer_pv1_stream *native,const struct steer_pv1_endpoint *bound){
 struct native_open *op=arg;struct steer_draft_native_stream_backend *b=op->backend;
 struct steer_pv1_stream_ref stream={NULL,NULL};
 if(!e.code){
  e=steer_draft_binding_pin(b->binding.lease,op->flow.value.generation,STEER_PV1_FLOW_STREAM);
  if(!e.code){
   struct steer_draft_backend_pin pin={b->binding.lease,unpin};
   e=steer_draft_backend_wrap_native(b->streams,native,&pin,&stream);
   if(e.code)unpin(b->binding.lease);
  }
  if(e.code){steer_draft_stream_api()->close(native);(void)steer_draft_stream_api()->release(native);}
 }
 struct steer_pv1_stream_open_diagnostic diagnostic={sizeof(diagnostic),STEER_PV1_STREAM_BACKEND_LAYOUT,
   e.code?failure:STEER_PV1_STREAM_DIAL_NONE};
 op->done(op->userdata,e,stream,e.code?NULL:bound,NULL,&diagnostic);
 op->completed=1;
}
static struct steer_pv1_async_start STEER_PV1_CALL open_native(void *context,
    const struct steer_pv1_flow_metadata *flow,uint64_t deadline,steer_pv1_stream_open_done done,void *userdata){
 struct steer_draft_native_stream_backend *b=context;
 if(!b||!done)return rejected(STEER_PV1_INVALID);
 struct steer_pv1_error e=steer_draft_flow_validate(flow,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
 e=steer_draft_binding_admit(b->binding.lease,flow->generation,STEER_PV1_FLOW_STREAM);if(e.code)return rejected(e.code);
 if(b->live>=b->max_operations){unpin(b->binding.lease);return rejected(STEER_PV1_RESOURCE_EXHAUSTED);}
 struct native_open *op=calloc(1,sizeof(*op));if(!op){unpin(b->binding.lease);return rejected(STEER_PV1_RESOURCE_EXHAUSTED);}
 e=steer_draft_flow_copy(&op->flow,flow,STEER_PV1_FLOW_STREAM);
 if(e.code){free(op);unpin(b->binding.lease);return rejected(e.code);}
 op->backend=b;op->done=done;op->userdata=userdata;
 const struct steer_pv1_flow_metadata *f=&op->flow.value;
 struct steer_draft_accepted accepted={f->generation,f->inbound_id,f->principal_id,f->source,f->destination,f->principal,f->flow_class};
 struct steer_pv1_async_start a=steer_draft_route_dial(b->routes,&accepted,deadline,connected,op);
 if(a.disposition!=STEER_PV1_PENDING){free(op);unpin(b->binding.lease);return a;}
 op->inner=a.operation;a.operation.handle=(struct steer_pv1_operation *)op;a.operation.api=&operation_api;b->live++;
 return a;
}
static const struct steer_pv1_stream_backend_api backend_api={
 sizeof(struct steer_pv1_stream_backend_api),STEER_PV1_STREAM_BACKEND_LAYOUT,open_native
};
struct steer_pv1_error steer_draft_native_stream_backend_create(struct loop *loop,
    struct steer_draft_stream_runtime *native,struct steer_draft_backend_runtime *streams,
    struct steer_draft_resolver *resolver,uint64_t generation,uint64_t token,
    uint32_t max_operations,uint32_t max_references,steer_draft_native_stream_retired retired,void *userdata,
    struct steer_draft_native_stream_backend **out){
 if(out)*out=NULL;
 if(!loop||!native||!streams||!generation||!token||!max_operations||!out)return error(STEER_PV1_INVALID);
 struct steer_draft_native_stream_backend *b=calloc(1,sizeof(*b));if(!b)return error(STEER_PV1_RESOURCE_EXHAUSTED);
 struct steer_pv1_error e=steer_draft_routes_create(loop,native,generation,max_operations,direct,NULL,&b->routes);
 if(e.code){free(b);return e;}
 if(resolver){e=steer_draft_routes_use_resolver(b->routes,resolver);if(e.code)goto fail;}
 static const uint8_t provider[]="steer.native.tcp";
 struct steer_draft_binding_identity identity={sizeof(identity),STEER_PV1_DRAFT_LAYOUT,generation,token,
    {provider,sizeof(provider)-1},STEER_DRAFT_STREAM_BINDING_PREPARED,STEER_PV1_FLOW_STREAM};
 if(resolver)identity.prepared_capabilities|=STEER_DRAFT_STREAM_BINDING_TARGET_DOMAIN;
 e=steer_draft_binding_lease_create(loop,&identity,max_references,finalized,b,&b->binding.lease);
 if(e.code)goto fail;
 b->binding.owner=loop;b->binding.api=&backend_api;b->binding.context=b;b->streams=streams;b->max_operations=max_operations;
 b->retired=retired;b->userdata=userdata;
 *out=b;return error(STEER_PV1_OK);
fail:
 (void)steer_draft_routes_destroy(b->routes);free(b);return e;
}
const struct steer_draft_stream_binding *steer_draft_native_stream_binding(const struct steer_draft_native_stream_backend *b){return b?&b->binding:NULL;}
struct steer_pv1_error steer_draft_native_stream_socket_guard(struct steer_draft_native_stream_backend *b,
    steer_draft_socket_guard guard,void *ctx){
    return b?steer_draft_routes_socket_guard(b->routes,guard,ctx):error(STEER_PV1_INVALID);
}
struct steer_pv1_error steer_draft_native_stream_backend_retire(struct steer_draft_native_stream_backend *b){
 return b?steer_draft_binding_retire(b->binding.lease):error(STEER_PV1_INVALID);
}
struct steer_pv1_error steer_draft_native_stream_backend_destroy(struct steer_draft_native_stream_backend *b){
 if(!b)return error(STEER_PV1_INVALID);
 if(!b->finalized||b->live)return error(STEER_PV1_POLICY_DENIED);
 if(b->routes){struct steer_pv1_error e=steer_draft_routes_destroy(b->routes);if(e.code)return e;b->routes=NULL;}
 struct steer_pv1_error e=steer_draft_binding_lease_destroy(b->binding.lease);if(e.code)return e;
 free(b);return error(STEER_PV1_OK);
}
