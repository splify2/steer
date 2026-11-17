#define _POSIX_C_SOURCE 200809L
#include "execution.h"
#include "ynode.h"
#include "loop.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EXECUTION_RULES_MAX 1024u
#define EXECUTION_VALUES_MAX 65536u
#define EXECUTION_BYTES_MAX STEER_SPEC_MAX_BYTES
enum state {WORKER_PREPARED,OWNER_BINDING,OWNER_READY,PUBLISHED,RETIRING,OWNER_DRAINED};
enum field {MATCH_INBOUND,MATCH_USER,MATCH_FLOW,MATCH_DOMAIN,MATCH_SUFFIX,MATCH_CIDR,MATCH_PROTOCOL,MATCH_PORT};
struct item {const char *text;size_t length;uint32_t tag,bits;uint8_t network[16];uint16_t first,last;};
struct criterion {enum field field;struct item *items;uint32_t count;};
struct rule {struct criterion criteria[8];uint32_t count,target;int reject;};
struct node {
    struct steer_spec_node_view view;
    int factory;
    void *prepared;
    struct steer_spec_execution_instance instance;
    int bound,retired;
};
struct configuration_notice {struct steer_spec_execution *execution;unsigned index;};
struct steer_spec_execution {
    struct steer_spec_plan *plan;
    struct steer_spec_execution_factory *factories;uint32_t factory_count,guards;
    struct node *nodes;uint32_t node_count;
    uint32_t *order,order_count,bind_cursor,retire_cursor,collect_cursor;
    struct steer_spec_edge_view *edges;uint32_t edge_count;
    struct steer_spec_execution_dependency *dependencies;
    struct rule *rules;uint32_t rule_count,default_target,values,match_bytes;
    uint32_t *stream_index,*datagram_index;
    uint64_t generation,first_token,deadline;
    const struct steer_draft_cancel *cancel;
    struct steer_spec_execution_limits limits;
    enum state state;
    struct steer_spec_execution_owner owner;
    struct steer_draft_stream_routes *streams;
    struct steer_draft_datagram_router *datagrams;
    struct steer_draft_binding_lease *configuration[2];int configuration_done[2];
    struct configuration_notice notices[2];int streams_drained,datagrams_drained;
    unsigned owner_depth,worker_depth;int destroying,retire_requested,cleanup_failed;
    struct steer_pv1_error failure,cleanup_error;
};
static struct steer_pv1_error error(uint32_t code){struct steer_pv1_error e={code,0};return e;}
static struct steer_pv1_error checked(struct steer_pv1_error e){
    return e.code>STEER_PV1_INTERNAL||e.transient>1||(!e.code&&e.transient)?error(STEER_PV1_PROTOCOL):e;
}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;}
static struct steer_pv1_error cancelled(const struct steer_spec_execution *e){
    if(e->cancel&&atomic_load_explicit(&e->cancel->requested,memory_order_acquire))return error(STEER_PV1_CANCELLED);
    return error(now_ns()>=e->deadline?STEER_PV1_TIMEOUT:STEER_PV1_OK);
}
static const char *value(const struct ynode *map,const char *key,const char *fallback){
    const struct ynode *n=ynode_get(map,key);return n&&n->kind==YN_SCALAR?n->str:fallback;
}
static const char *node_type(const struct steer_spec_node_view *n){
    if(n->type[0])return n->type;
    return value(n->intent,"type",value(n->intent,"source",""));
}
static int block(const struct node *n){return n->view.kind==STEER_SPEC_OUTBOUND&&!strcmp(n->view.type,"block");}
static int node_index(const struct steer_spec_execution *e,enum steer_spec_node_kind kind,const char *id){
    for(uint32_t i=0;i<e->node_count;i++)if(e->nodes[i].view.kind==kind&&!strcmp(e->nodes[i].view.id,id))return (int)i;
    return -1;
}
static int visit(struct steer_spec_execution *e,uint32_t index,uint8_t *marks){
    if(marks[index]==1)return -1;
    if(marks[index]==2||!e->nodes[index].view.enabled)return 0;
    marks[index]=1;
    for(uint32_t i=0;i<e->edge_count;i++){
        const struct steer_spec_edge_view *edge=&e->edges[i];
        if(edge->source!=index||!edge->construction_dependency)continue;
        if(edge->target>=e->node_count||!e->nodes[edge->target].view.enabled||visit(e,edge->target,marks))return -1;
        if(edge->required_flows&&(e->nodes[edge->target].view.flows&edge->required_flows)!=edge->required_flows)return -1;
    }
    marks[index]=2;e->order[e->order_count++]=index;return 0;
}
static uint32_t dependencies(struct steer_spec_execution *e,uint32_t source,int owner){
    uint32_t count=0;
    for(uint32_t i=0;i<e->edge_count;i++){
        const struct steer_spec_edge_view *edge=&e->edges[i];
        if(edge->source!=source||!edge->construction_dependency)continue;
        struct node *target=&e->nodes[edge->target];
        struct steer_spec_execution_dependency *d=&e->dependencies[count++];
        d->edge=*edge;d->target=target->view;d->prepared=target->prepared;
        d->bound=owner&&target->bound?&target->instance:NULL;
    }
    return count;
}
static int same(const char *a,const char *b){return a&&b&&!strcmp(a,b);}
static int matches(const struct steer_spec_execution_factory *f,const struct steer_spec_node_view *n){
    if(f->kind!=n->kind||(f->node_id&&!same(f->node_id,n->id)))return 0;
    if(n->provider[0]){if(!same(f->provider,n->provider))return 0;}
    else if(f->provider||!same(f->type,node_type(n)))return 0;
    if((n->kind==STEER_SPEC_INBOUND||n->kind==STEER_SPEC_OUTBOUND)&&(f->flows&n->flows)!=n->flows)return 0;
    return same(f->transport,value(n->transport,"type","tcp"))&&
        same(f->security,value(n->security,"type","none"))&&same(f->variant,n->variant?n->variant->str:"default");
}
static int common_capability(const char *name){
    static const char *const names[]={"core.spec-v3.apply","core.outbound.block","core.routing.action.route","core.routing.action.reject",
        "core.classifier.inbound","core.classifier.user","core.classifier.flow","core.classifier.domain",
        "core.classifier.domain_suffix","core.classifier.cidr","core.classifier.protocol","core.classifier.port"};
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)if(!strcmp(name,names[i]))return 1;
    return 0;
}
static int unsupported_common(const char *name){
    return !strncmp(name,"core.classifier.",16)||!strncmp(name,"core.routing.action.",20)||
        !strcmp(name,"core.dns.policy")||!strncmp(name,"core.profile.network.",21)||
        !strncmp(name,"core.capture.",13)||!strcmp(name,"core.adapter.ip_stack");
}
static int capability(const struct steer_spec_execution *e,const struct steer_spec_requirement_view *r){
    if(common_capability(r->name))return 1;
    if(unsupported_common(r->name))return 0;
    if(r->owner_node>=e->node_count)return 0;
    const struct node *n=&e->nodes[r->owner_node];if(n->factory<0)return 0;
    const struct steer_spec_execution_factory *f=&e->factories[n->factory];
    for(uint32_t j=0;j<f->capability_count;j++)if(!strcmp(f->capabilities[j],r->name))return 1;
    return 0;
}
static int decimal(const char *s,size_t length,unsigned maximum,unsigned *out){
    unsigned n=0;if(!length)return -1;
    for(size_t i=0;i<length;i++){
        if(s[i]<'0'||s[i]>'9'||n>(maximum-(unsigned)(s[i]-'0'))/10)return -1;
        n=n*10+(unsigned)(s[i]-'0');
    }
    *out=n;return 0;
}
static int cidr(const struct ynode *n,struct item *item){
    if(!n||n->kind!=YN_SCALAR||n->len>64)return -1;
    const char *slash=strchr(n->str,'/');if(!slash)return -1;
    char address[64];size_t length=(size_t)(slash-n->str);if(!length||length>=sizeof(address))return -1;
    memcpy(address,n->str,length);address[length]=0;
    unsigned bits;int family=strchr(address,':')?AF_INET6:AF_INET;unsigned width=family==AF_INET6?128:32;
    if(decimal(slash+1,strlen(slash+1),width,&bits)||inet_pton(family,address,item->network)!=1)return -1;
    for(unsigned i=bits;i<width;i++)if(item->network[i/8]&(uint8_t)(0x80u>>(i%8)))return -1;
    item->bits=bits;item->tag=family==AF_INET6?STEER_PV1_ENDPOINT_IPV6:STEER_PV1_ENDPOINT_IPV4;return 0;
}
static int domain(const struct ynode *n){
    uint8_t source[4]={127,0,0,1};
    struct steer_pv1_endpoint endpoint={sizeof(endpoint),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{source,4},1,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=1,
        .inbound_id={(const uint8_t *)"validator",9},.source=endpoint,.destination=endpoint,.flow_class=STEER_PV1_FLOW_STREAM};
    if(!n||n->kind!=YN_SCALAR)return -1;
    flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;flow.destination.address=(struct steer_pv1_span){(const uint8_t *)n->str,n->len};
    return steer_draft_flow_validate(&flow,STEER_PV1_FLOW_STREAM).code?-1:0;
}
static struct steer_pv1_error criterion(struct steer_spec_execution *e,struct rule *rule,const char *key,const struct ynode *list){
    static const char *const names[]={"inbound","user","flow","domain","domain_suffix","cidr","protocol","port"};
    unsigned which=8;for(unsigned i=0;i<8;i++)if(!strcmp(key,names[i]))which=i;
    if(which==8)return error(STEER_PV1_UNSUPPORTED);
    if(!list||list->kind!=YN_SEQ||rule->count==8||list->len>e->limits.max_match_values-e->values)return error(STEER_PV1_INVALID);
    struct criterion *c=&rule->criteria[rule->count++];c->field=(enum field)which;c->count=(uint32_t)list->len;
    if(c->count){c->items=calloc(c->count,sizeof(*c->items));if(!c->items)return error(STEER_PV1_RESOURCE_EXHAUSTED);}
    e->values+=c->count;
    for(uint32_t i=0;i<c->count;i++){
        const struct ynode *n=ynode_at(list,i);struct item *item=&c->items[i];
        if(!n||n->kind!=YN_SCALAR||n->tag||n->len>e->limits.max_match_bytes-e->match_bytes)return error(STEER_PV1_INVALID);
        e->match_bytes+=(uint32_t)n->len;item->text=n->str;item->length=n->len;
        if(which==MATCH_CIDR){if(cidr(n,item))return error(STEER_PV1_INVALID);}
        else if(which==MATCH_DOMAIN||which==MATCH_SUFFIX){if(domain(n))return error(STEER_PV1_INVALID);}
        else if(which==MATCH_PORT){
            const char *dash=strchr(n->str,'-');unsigned first,last;
            if(decimal(n->str,dash?(size_t)(dash-n->str):n->len,65535,&first)||!first)return error(STEER_PV1_INVALID);
            if(dash){if(decimal(dash+1,strlen(dash+1),65535,&last)||last<first)return error(STEER_PV1_INVALID);}else last=first;
            item->first=(uint16_t)first;item->last=(uint16_t)last;
        }else if(which==MATCH_FLOW||which==MATCH_PROTOCOL){
            const char *stream=which==MATCH_FLOW?"stream":"tcp",*datagram=which==MATCH_FLOW?"datagram":"udp";
            if(!strcmp(n->str,stream))item->tag=STEER_PV1_FLOW_STREAM;
            else if(!strcmp(n->str,datagram))item->tag=STEER_PV1_FLOW_DATAGRAM;
            else return error(STEER_PV1_UNSUPPORTED);
        }
    }
    return error(STEER_PV1_OK);
}
static struct steer_pv1_error rules_prepare(struct steer_spec_execution *e){
    const struct ynode *root=steer_spec_intent(e->plan),*routing=ynode_get(root,"routing");
    const char *fallback=value(routing,"default","");int found=node_index(e,STEER_SPEC_OUTBOUND,fallback);
    if(found<0||!e->nodes[found].view.enabled)return error(STEER_PV1_INVALID);
    e->default_target=(uint32_t)found;
    for(uint32_t i=0;;i++){
        struct steer_spec_rule_view view;if(!steer_spec_rule(e->plan,i,&view))break;
        if(!view.enabled)continue;
        if(view.dns_rule||view.strategy||view.cache_timeout)return error(STEER_PV1_UNSUPPORTED);
        if(e->rule_count==e->limits.max_rules)return error(STEER_PV1_RESOURCE_EXHAUSTED);
        struct rule *rule=&e->rules[e->rule_count++];
        if(!strcmp(view.action,"reject"))rule->reject=1;
        else if(!strcmp(view.action,"route")){
            int target=node_index(e,STEER_SPEC_OUTBOUND,view.target);
            if(target<0||!e->nodes[target].view.enabled)return error(STEER_PV1_INVALID);
            rule->target=(uint32_t)target;
        }else return error(STEER_PV1_UNSUPPORTED);
        if(!view.match||view.match->kind!=YN_MAP)return error(STEER_PV1_INVALID);
        for(size_t j=0;j<view.match->len;j++){
            struct steer_pv1_error result=criterion(e,rule,ynode_key_at(view.match,j)->str,ynode_val_at(view.match,j));
            if(result.code)return result;
        }
    }
    return error(STEER_PV1_OK);
}
static void memory_free(struct steer_spec_execution *e){
    for(uint32_t i=0;i<e->rule_count;i++)for(uint32_t j=0;j<e->rules[i].count;j++)free(e->rules[i].criteria[j].items);
    free(e->rules);free(e->factories);free(e->nodes);free(e->order);free(e->edges);
    free(e->dependencies);free(e->stream_index);free(e->datagram_index);free(e);
}
static void worker_unwind(struct steer_spec_execution *e){
    for(uint32_t at=e->order_count;at>0;at--){
        struct node *n=&e->nodes[e->order[at-1]];
        if(n->prepared){const struct steer_spec_execution_factory *f=&e->factories[n->factory];
            e->worker_depth++;f->discard(f->context,n->prepared);e->worker_depth--;n->prepared=NULL;}
    }
}
static void guards_release(struct steer_spec_execution *e){
    while(e->guards){struct steer_spec_execution_guard guard=e->factories[--e->guards].guard;guard.release(guard.context);}
}
static int factory_valid(const struct steer_spec_execution_factory *f){
    if(f->size<sizeof(*f)||f->version!=STEER_SPEC_EXECUTION_FACTORY_LAYOUT||
       f->kind<STEER_SPEC_INBOUND||f->kind>STEER_SPEC_PLUGIN||(!f->type==!f->provider)||
       !f->transport||!f->security||!f->variant||!f->validate||!f->prepare||!f->discard||
       !f->bind||!f->retire||!f->collect||!f->guard.retain||!f->guard.release||f->capability_count>64||
       (f->capability_count&&!f->capabilities)||f->flows&~7u)return 0;
    if(f->node_id&&(!f->node_id[0]||strnlen(f->node_id,64)==64||strchr(f->node_id,'*')))return 0;
    const char *names[]={f->type?f->type:f->provider,f->transport,f->security,f->variant};
    for(unsigned i=0;i<4;i++)if(strnlen(names[i],128)==128||strchr(names[i],'*'))return 0;
    for(uint32_t i=0;i<f->capability_count;i++)if(!f->capabilities[i]||
        !f->capabilities[i][0]||strnlen(f->capabilities[i],384)==384||strchr(f->capabilities[i],'*'))return 0;
    if(f->kind==STEER_SPEC_OUTBOUND&&(((f->flows&STEER_SPEC_FLOW_STREAM)&&!f->stream_provider_id)||
       ((f->flows&STEER_SPEC_FLOW_DATAGRAM)&&!f->datagram_provider_id)))return 0;
    if((f->stream_provider_id&&(!f->stream_provider_id[0]||strnlen(f->stream_provider_id,65)==65))||
       (f->datagram_provider_id&&(!f->datagram_provider_id[0]||strnlen(f->datagram_provider_id,65)==65)))return 0;
    return 1;
}
struct steer_pv1_error steer_spec_execution_prepare(struct steer_spec_plan **owned,
    uint64_t generation,uint64_t token,const struct steer_spec_execution_factory *factories,uint32_t count,
    const struct steer_spec_execution_limits *limits,uint64_t deadline,
    const struct steer_draft_cancel *cancel,struct steer_spec_execution **out){
    if(out)*out=NULL;
    if(!owned||!*owned||!generation||!token||!out||!limits||count>STEER_SPEC_EXECUTION_FACTORIES_MAX||
       (count&&!factories)||limits->max_rules>EXECUTION_RULES_MAX||!limits->max_match_values||
       limits->max_match_values>EXECUTION_VALUES_MAX||!limits->max_match_bytes||limits->max_match_bytes>EXECUTION_BYTES_MAX||
       !limits->max_streams||limits->max_streams>4096||!limits->max_stream_operations||limits->max_stream_operations>4096||
       !limits->datagrams.max_associations||limits->datagrams.max_associations>1024||
       !limits->datagrams.max_targets||limits->datagrams.max_targets>1024||!limits->datagrams.max_targets_per_association||
       limits->datagrams.max_targets_per_association>64||limits->datagrams.max_targets_per_association>limits->datagrams.max_targets||
       !limits->datagrams.max_operations||limits->datagrams.max_operations>4096||!limits->datagrams.idle_ns)return error(STEER_PV1_INVALID);
    struct steer_spec_summary summary=steer_spec_summary(*owned);
    if(!summary.syntax_valid||!summary.topology_valid||!summary.runtime_ready)return error(STEER_PV1_UNSUPPORTED);
    if(cancel&&atomic_load_explicit(&cancel->requested,memory_order_acquire))return error(STEER_PV1_CANCELLED);
    if(now_ns()>=deadline)return error(STEER_PV1_TIMEOUT);
    if(token>UINT64_MAX-summary.nodes-2)return error(STEER_PV1_INVALID);
    for(uint32_t i=0;i<count;i++)if(factories[i].size<sizeof(factories[i])||
        factories[i].version!=STEER_SPEC_EXECUTION_FACTORY_LAYOUT||!factories[i].guard.retain||!factories[i].guard.release)return error(STEER_PV1_INVALID);
    struct steer_spec_execution *e=calloc(1,sizeof(*e));if(!e)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    e->plan=*owned;e->generation=generation;e->first_token=token;e->limits=*limits;e->deadline=deadline;e->cancel=cancel;
    e->node_count=summary.nodes;e->edge_count=summary.edges;e->factory_count=count;
    if(count)e->factories=calloc(count,sizeof(*e->factories));
    e->nodes=calloc(summary.nodes?summary.nodes:1,sizeof(*e->nodes));
    e->order=calloc(summary.nodes?summary.nodes:1,sizeof(*e->order));
    e->edges=calloc(summary.edges?summary.edges:1,sizeof(*e->edges));
    e->dependencies=calloc(summary.edges?summary.edges:1,sizeof(*e->dependencies));
    e->rules=calloc(limits->max_rules?limits->max_rules:1,sizeof(*e->rules));
    e->stream_index=malloc((summary.nodes?summary.nodes:1)*sizeof(*e->stream_index));
    e->datagram_index=malloc((summary.nodes?summary.nodes:1)*sizeof(*e->datagram_index));
    struct steer_pv1_error result=error(STEER_PV1_RESOURCE_EXHAUSTED);
    if((count&&!e->factories)||!e->nodes||!e->order||!e->edges||!e->dependencies||!e->rules||!e->stream_index||!e->datagram_index)goto fail;
    if(count)memcpy(e->factories,factories,count*sizeof(*factories));
    for(uint32_t i=0;i<count;i++){
        e->factories[i].size=sizeof(e->factories[i]);
        result=e->factories[i].guard.retain(e->factories[i].guard.context);
        if(!result.code)e->guards++;
        result=checked(result);if(result.code)goto fail;
        if(!factory_valid(&e->factories[i])){result=error(STEER_PV1_INVALID);goto fail;}
    }
    for(uint32_t i=0;i<summary.nodes;i++){
        struct node *n=&e->nodes[i];n->factory=-1;
        e->stream_index[i]=e->datagram_index[i]=UINT32_MAX;
        if(!steer_spec_node(e->plan,i,&n->view)){result=error(STEER_PV1_INVALID);goto fail;}
    }
    for(uint32_t i=0;i<summary.edges;i++)if(!steer_spec_edge(e->plan,i,&e->edges[i])){result=error(STEER_PV1_INVALID);goto fail;}
    uint8_t marks[STEER_SPEC_MAX_NODES]={0};
    for(uint32_t i=0;i<summary.nodes;i++)if(visit(e,i,marks)){result=error(STEER_PV1_INVALID);goto fail;}
    result=rules_prepare(e);if(result.code)goto fail;
    for(uint32_t i=0;i<summary.nodes;i++){
        struct node *n=&e->nodes[i];if(!n->view.enabled)continue;
        if((n->view.kind==STEER_SPEC_INBOUND||n->view.kind==STEER_SPEC_OUTBOUND)&&(n->view.flows&STEER_SPEC_FLOW_DEVICE)){
            result=error(STEER_PV1_UNSUPPORTED);goto fail; /* requires common journaled device commit coordinator */
        }
        if(block(n)){
            if(ynode_get(n->view.intent,"detour")||ynode_get(n->view.intent,"resolve_via")){result=error(STEER_PV1_UNSUPPORTED);goto fail;}
            continue;
        }
        for(uint32_t j=0;j<count;j++)if(matches(&e->factories[j],&n->view)){
            if(n->factory>=0){result=error(STEER_PV1_INVALID);goto fail;}n->factory=(int)j;
        }
        if(n->factory<0){result=error(STEER_PV1_UNSUPPORTED);goto fail;}
        if(n->view.provider[0]&&!n->view.options_validated){result=error(STEER_PV1_UNSUPPORTED);goto fail;}
        e->worker_depth++;
        int valid=e->factories[n->factory].validate(e->factories[n->factory].context,&n->view);
        e->worker_depth--;
        if(valid!=1){result=error(STEER_PV1_UNSUPPORTED);goto fail;}
    }
    for(uint32_t i=0;i<summary.requirements;i++){
        struct steer_spec_requirement_view r;
        if(!steer_spec_requirement(e->plan,i,&r)||!capability(e,&r)){result=error(STEER_PV1_UNSUPPORTED);goto fail;}
    }
    for(uint32_t i=0;i<e->order_count;i++){
        result=cancelled(e);if(result.code)goto fail;
        struct node *n=&e->nodes[e->order[i]];if(n->factory<0)continue;
        const struct steer_spec_execution_factory *f=&e->factories[n->factory];
        e->worker_depth++;result=checked(f->prepare(f->context,&n->view,e->dependencies,dependencies(e,e->order[i],0),deadline,cancel,&n->prepared));e->worker_depth--;
        if(!result.code&&!n->prepared)result=error(STEER_PV1_PROTOCOL);
        if(result.code)goto fail;
        result=cancelled(e);if(result.code)goto fail;
    }
    e->cancel=NULL;e->state=WORKER_PREPARED;*owned=NULL;*out=e;return error(STEER_PV1_OK);
fail:
    worker_unwind(e);guards_release(e);memory_free(e);return result;
}
struct steer_pv1_error steer_spec_execution_destroy_worker(struct steer_spec_execution *e){
    if(!e)return error(STEER_PV1_INVALID);
    if((e->state!=WORKER_PREPARED&&e->state!=OWNER_DRAINED)||e->owner_depth||e->worker_depth||e->destroying)return error(STEER_PV1_POLICY_DENIED);
    e->destroying=1;
    worker_unwind(e);steer_spec_destroy(e->plan);guards_release(e);memory_free(e);return error(STEER_PV1_OK);
}
static unsigned fold(unsigned c){return c>='A'&&c<='Z'?c+('a'-'A'):c;}
static int domain_equal(const uint8_t *left,size_t nl,const char *right,size_t nr,int suffix){
    if(nl&&left[nl-1]=='.')nl--;
    if(nr&&right[nr-1]=='.')nr--;
    if(nl<nr||(!suffix&&nl!=nr)||(suffix&&nl>nr&&left[nl-nr-1]!='.'))return 0;
    for(size_t i=0;i<nr;i++)if(fold(left[nl-nr+i])!=fold((unsigned char)right[i]))return 0;
    return 1;
}
static int item_matches(enum field field,const struct item *item,const struct steer_pv1_flow_metadata *flow){
    const struct steer_pv1_endpoint *dest=&flow->destination;
    if(field==MATCH_INBOUND||field==MATCH_USER){
        struct steer_pv1_span span=field==MATCH_INBOUND?flow->inbound_id:flow->principal_id;
        return span.len==item->length&&(!span.len||!memcmp(span.data,item->text,span.len));
    }
    if(field==MATCH_FLOW||field==MATCH_PROTOCOL)return flow->flow_class==item->tag;
    if(field==MATCH_PORT)return dest->port>=item->first&&dest->port<=item->last;
    if(field==MATCH_DOMAIN||field==MATCH_SUFFIX)return dest->tag==STEER_PV1_ENDPOINT_DOMAIN&&
        domain_equal(dest->address.data,dest->address.len,item->text,item->length,field==MATCH_SUFFIX);
    if(dest->tag!=item->tag)return 0;
    unsigned full=item->bits/8,remaining=item->bits%8;
    return (!full||!memcmp(dest->address.data,item->network,full))&&
        (!remaining||((dest->address.data[full]&(0xffu<<(8-remaining)))==item->network[full]));
}
static int rule_matches(const struct rule *rule,const struct steer_pv1_flow_metadata *flow){
    for(uint32_t i=0;i<rule->count;i++){
        const struct criterion *c=&rule->criteria[i];int found=0;
        for(uint32_t j=0;j<c->count;j++)if(item_matches(c->field,&c->items[j],flow)){found=1;break;}
        if(!found)return 0;
    }
    return 1;
}
static struct steer_pv1_error select_route(void *arg,const struct steer_pv1_flow_metadata *flow,uint32_t *index){
    struct steer_spec_execution *e=arg;*index=UINT32_MAX;
    if(e->state!=PUBLISHED||flow->generation!=e->generation)return error(STEER_PV1_POLICY_DENIED);
    uint32_t target=e->default_target;
    for(uint32_t i=0;i<e->rule_count;i++)if(rule_matches(&e->rules[i],flow)){
        if(e->rules[i].reject)return error(STEER_PV1_OK);
        target=e->rules[i].target;break;
    }
    if(block(&e->nodes[target]))return error(STEER_PV1_OK);
    *index=flow->flow_class==STEER_PV1_FLOW_STREAM?e->stream_index[target]:e->datagram_index[target];
    return error(*index==UINT32_MAX?STEER_PV1_UNSUPPORTED:STEER_PV1_OK);
}
static void wake_owner(struct steer_spec_execution *e){if(e->owner.wake)e->owner.wake(e->owner.wake_context);}
static void configuration_finalized(void *arg,const struct steer_draft_binding_identity *id){
    (void)id;struct configuration_notice *notice=arg;
    notice->execution->configuration_done[notice->index]=1;wake_owner(notice->execution);
}
static void stream_drained(void *arg,struct steer_draft_stream_routes *r){
    (void)r;struct steer_spec_execution *e=arg;e->streams_drained=1;wake_owner(e);
}
static void datagram_drained(void *arg,struct steer_draft_datagram_router *r){
    (void)r;struct steer_spec_execution *e=arg;e->datagrams_drained=1;wake_owner(e);
}
static void configuration_unpin(void *lease){(void)steer_draft_binding_unpin(lease);}
static struct steer_pv1_async_start reject_stream(void *ctx,const struct steer_pv1_flow_metadata *flow,uint64_t until,
    steer_pv1_stream_open_done done,void *user){
    (void)ctx;(void)flow;(void)until;(void)done;(void)user;
    return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{STEER_PV1_POLICY_DENIED,0},{NULL,NULL}};
}
static struct steer_pv1_async_start reject_datagram(void *ctx,const struct steer_pv1_flow_metadata *flow,uint64_t until,
    steer_pv1_datagram_open_done done,void *user){
    (void)ctx;(void)flow;(void)until;(void)done;(void)user;
    return (struct steer_pv1_async_start){STEER_PV1_REJECTED,{STEER_PV1_POLICY_DENIED,0},{NULL,NULL}};
}
static const struct steer_pv1_stream_backend_api blocked_stream={sizeof(blocked_stream),STEER_PV1_STREAM_BACKEND_LAYOUT,reject_stream};
static const struct steer_pv1_datagram_backend_api blocked_datagram={sizeof(blocked_datagram),STEER_PV1_DRAFT_LAYOUT,reject_datagram};
static struct steer_pv1_error configurations_create(struct steer_spec_execution *e){
    static const uint8_t provider[]="steer.spec";
    for(unsigned i=0;i<2;i++){
        struct steer_draft_binding_identity id={sizeof(id),STEER_PV1_DRAFT_LAYOUT,e->generation,e->first_token+e->node_count+i,
            {provider,sizeof(provider)-1},3,i?STEER_PV1_FLOW_DATAGRAM:STEER_PV1_FLOW_STREAM};
        e->notices[i]=(struct configuration_notice){e,i};
        struct steer_pv1_error result=steer_draft_binding_lease_create(e->owner.loop,&id,16384,configuration_finalized,&e->notices[i],&e->configuration[i]);
        if(result.code)return result;
    }
    return error(STEER_PV1_OK);
}
static int identity_matches(struct steer_spec_execution *e,uint32_t node,uint32_t flow,const char *provider,
    struct steer_draft_binding_lease *lease){
    if(!lease||!provider)return 0;
    const struct steer_draft_binding_identity *id=steer_draft_binding_identity(lease);
    return id->generation==e->generation&&id->instance_token==e->first_token+node&&id->flow_class==flow&&
        (id->prepared_capabilities&1)&&id->provider_id.len==strlen(provider)&&!memcmp(id->provider_id.data,provider,id->provider_id.len);
}
static struct steer_pv1_error instance_validate(struct steer_spec_execution *e,uint32_t index){
    struct node *n=&e->nodes[index];struct steer_spec_execution_instance *b=&n->instance;
    const struct steer_spec_execution_factory *f=&e->factories[n->factory];
    if(!b->handle)return error(STEER_PV1_PROTOCOL);
    if(b->device)return error(STEER_PV1_UNSUPPORTED);
    uint32_t required=n->view.kind==STEER_SPEC_OUTBOUND?n->view.flows:0;
    if(required&STEER_SPEC_FLOW_STREAM){
        if(b->stream.owner!=e->owner.loop||!identity_matches(e,index,STEER_PV1_FLOW_STREAM,f->stream_provider_id,b->stream.lease)||
           !b->stream.api||b->stream.api->size<sizeof(*b->stream.api)||b->stream.api->version!=STEER_PV1_STREAM_BACKEND_LAYOUT||!b->stream.api->open)return error(STEER_PV1_PROTOCOL);
    }else if(b->stream.lease||b->stream.api||b->stream.context)return error(STEER_PV1_PROTOCOL);
    if(required&STEER_SPEC_FLOW_DATAGRAM){
        if(b->datagram.owner!=e->owner.loop||!identity_matches(e,index,STEER_PV1_FLOW_DATAGRAM,f->datagram_provider_id,b->datagram.lease)||
           !b->datagram.api||b->datagram.api->size<sizeof(*b->datagram.api)||b->datagram.api->version!=STEER_PV1_DRAFT_LAYOUT||!b->datagram.api->open)return error(STEER_PV1_PROTOCOL);
    }else if(b->datagram.lease||b->datagram.api||b->datagram.context)return error(STEER_PV1_PROTOCOL);
    return error(STEER_PV1_OK);
}
static int instance_present(const struct steer_spec_execution_instance *b){
    return b->handle||b->device||b->stream.owner||b->stream.lease||b->stream.api||b->stream.context||
        b->datagram.owner||b->datagram.lease||b->datagram.api||b->datagram.context;
}
static struct steer_pv1_error dependencies_validate(struct steer_spec_execution *e,uint32_t count){
    for(uint32_t i=0;i<count;i++){
        const struct steer_spec_execution_dependency *d=&e->dependencies[i];
        if(!d->bound)return error(STEER_PV1_PROTOCOL);
        if((d->edge.required_flows&STEER_SPEC_FLOW_STREAM)&&!d->bound->stream.api)return error(STEER_PV1_UNSUPPORTED);
        if((d->edge.required_flows&STEER_SPEC_FLOW_DATAGRAM)&&!d->bound->datagram.api)return error(STEER_PV1_UNSUPPORTED);
        if(d->edge.required_flows&STEER_SPEC_FLOW_DEVICE)return error(STEER_PV1_UNSUPPORTED);
    }
    return error(STEER_PV1_OK);
}
static struct steer_pv1_error registries_create(struct steer_spec_execution *e){
    struct steer_draft_stream_binding *streams=calloc(e->node_count?e->node_count:1,sizeof(*streams));
    struct steer_draft_datagram_binding *datagrams=calloc(e->node_count?e->node_count:1,sizeof(*datagrams));
    if(!streams||!datagrams){free(streams);free(datagrams);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
    uint32_t ns=0,nd=0;
    for(uint32_t i=0;i<e->node_count;i++){
        struct node *n=&e->nodes[i];if(!n->view.enabled||n->view.kind!=STEER_SPEC_OUTBOUND||block(n))continue;
        if(n->view.flows&STEER_SPEC_FLOW_STREAM){e->stream_index[i]=ns;streams[ns++]=n->instance.stream;}
        if(n->view.flows&STEER_SPEC_FLOW_DATAGRAM){e->datagram_index[i]=nd;datagrams[nd++]=n->instance.datagram;}
    }
    struct steer_pv1_error result=steer_draft_binding_admit(e->configuration[0],e->generation,STEER_PV1_FLOW_STREAM);
    if(result.code)goto done;
    struct steer_draft_backend_pin pin={e->configuration[0],configuration_unpin};
    result=steer_draft_stream_routes_create(e->owner.loop,e->generation,e->limits.max_stream_operations,e->limits.max_streams,
        streams,ns,select_route,e,&pin,&e->streams);
    if(result.code){configuration_unpin(pin.context);goto done;}
    result=steer_draft_stream_routes_on_drained(e->streams,stream_drained,e);if(result.code)goto done;
    result=steer_draft_datagram_router_create_registry(e->owner.loop,e->owner.host,e->configuration[1],datagrams,nd,
        &e->limits.datagrams,select_route,e,&e->datagrams);
    if(result.code)goto done;
    result=steer_draft_datagram_router_on_drained(e->datagrams,datagram_drained,e);
done:free(streams);free(datagrams);return result;
}
struct steer_pv1_error steer_spec_execution_bind_step(struct steer_spec_execution *e,struct loop *loop,
    struct steer_pv1_host *host,void (*wake)(void *),void *user,uint32_t *progress){
    if(progress)*progress=STEER_SPEC_EXECUTION_MORE;
    if(!e||!loop||!host||!wake||!progress)return error(STEER_PV1_INVALID);
    if(e->owner_depth||e->worker_depth||e->destroying)return error(STEER_PV1_POLICY_DENIED);
    if(e->state==OWNER_READY){*progress=STEER_SPEC_EXECUTION_READY;return error(0);}
    if(e->state!=WORKER_PREPARED&&e->state!=OWNER_BINDING)return error(STEER_PV1_POLICY_DENIED);
    if(e->state==WORKER_PREPARED){
        e->owner=(struct steer_spec_execution_owner){loop,host,e->generation,0,wake,user};e->state=OWNER_BINDING;
        e->failure=configurations_create(e);
        if(e->failure.code){steer_spec_execution_retire(e);return e->failure;}
    }else if(e->owner.loop!=loop||e->owner.host!=host||e->owner.wake!=wake||e->owner.wake_context!=user)return error(STEER_PV1_INVALID);
    for(uint32_t calls=0;e->bind_cursor<e->order_count&&calls<STEER_SPEC_EXECUTION_STEP;calls++){
        e->failure=cancelled(e);if(e->failure.code)break;
        uint32_t index=e->order[e->bind_cursor++];struct node *n=&e->nodes[index];
        if(block(n)){
            n->instance.handle=e;
            n->instance.stream=(struct steer_draft_stream_binding){loop,e->configuration[0],&blocked_stream,e};
            n->instance.datagram=(struct steer_draft_datagram_binding){loop,e->configuration[1],&blocked_datagram,e};n->bound=1;continue;
        }
        const struct steer_spec_execution_factory *f=&e->factories[n->factory];
        uint32_t count=dependencies(e,index,1);e->failure=dependencies_validate(e,count);if(e->failure.code)break;
        struct steer_spec_execution_owner owner=e->owner;owner.instance_token=e->first_token+index;e->owner_depth++;
        e->failure=checked(f->bind(f->context,n->prepared,&n->view,e->dependencies,count,&owner,&n->instance));e->owner_depth--;
        n->bound=instance_present(&n->instance);
        if(!e->failure.code)e->failure=instance_validate(e,index);
        if(!e->failure.code)e->failure=cancelled(e);
        if(e->retire_requested&&!e->failure.code)e->failure=error(STEER_PV1_CANCELLED);
        if(e->failure.code)break;
    }
    if(e->failure.code){steer_spec_execution_retire(e);return e->failure;}
    if(e->bind_cursor<e->order_count){wake_owner(e);return error(0);}
    e->failure=registries_create(e);
    if(!e->failure.code)e->failure=cancelled(e);
    if(e->failure.code){steer_spec_execution_retire(e);return e->failure;}
    e->state=OWNER_READY;*progress=STEER_SPEC_EXECUTION_READY;return error(0);
}
struct steer_pv1_error steer_spec_execution_publish(struct steer_spec_execution *e){
    if(!e)return error(STEER_PV1_INVALID);
    if(e->state!=OWNER_READY||e->owner_depth||e->destroying)return error(STEER_PV1_POLICY_DENIED);
    /* The coordinator has completed all fallible/durable work. Do not turn a
     * known committed transaction into a timeout while publishing memory. */
    e->state=PUBLISHED;
    for(uint32_t i=0;i<e->order_count;i++){
        struct node *n=&e->nodes[e->order[i]];if(n->factory<0)continue;
        const struct steer_spec_execution_factory *f=&e->factories[n->factory];
        if(f->publish){e->owner_depth++;f->publish(f->context,&n->instance);e->owner_depth--;}
    }
    if(e->retire_requested)steer_spec_execution_retire(e);
    return error(STEER_PV1_OK);
}
void steer_spec_execution_retire(struct steer_spec_execution *e){
    if(!e||e->destroying||e->state==OWNER_DRAINED||e->state==RETIRING)return;
    e->retire_requested=1;
    if(e->owner_depth||e->worker_depth)return;
    if(e->state==WORKER_PREPARED){e->state=OWNER_DRAINED;return;}
    e->state=RETIRING;e->retire_cursor=e->collect_cursor=e->bind_cursor;
    if(e->streams)steer_draft_stream_routes_quiesce(e->streams);
    if(e->datagrams)steer_draft_datagram_router_quiesce(e->datagrams);
    for(unsigned i=0;i<2;i++)if(e->configuration[i])(void)steer_draft_binding_retire(e->configuration[i]);
    wake_owner(e);
}
static struct steer_pv1_error cleanup_failure(struct steer_spec_execution *e,struct steer_pv1_error result){
    e->cleanup_failed=1;e->cleanup_error=result;return result;
}
struct steer_pv1_error steer_spec_execution_collect_step(struct steer_spec_execution *e,uint32_t *progress){
    if(progress)*progress=STEER_SPEC_EXECUTION_MORE;
    if(!e||!progress)return error(STEER_PV1_INVALID);
    if(e->owner_depth||e->worker_depth||e->destroying)return error(STEER_PV1_POLICY_DENIED);
    if(e->state==OWNER_DRAINED){*progress=STEER_SPEC_EXECUTION_READY;return error(0);}
    if(e->state!=RETIRING)return error(STEER_PV1_POLICY_DENIED);
    if(e->cleanup_failed)return e->cleanup_error;
    uint32_t calls=0;
    while(e->retire_cursor&&calls++<STEER_SPEC_EXECUTION_STEP){
        struct node *n=&e->nodes[e->order[--e->retire_cursor]];
        if(!n->bound||n->retired)continue;
        n->retired=1;
        if(n->factory>=0){const struct steer_spec_execution_factory *f=&e->factories[n->factory];
            e->owner_depth++;f->retire(f->context,&n->instance);e->owner_depth--;}
    }
    if(e->retire_cursor){wake_owner(e);return error(0);}
    if(e->streams){
        if(!e->streams_drained)return error(0);
        struct steer_pv1_error result=steer_draft_stream_routes_destroy(e->streams);
        if(result.code==STEER_PV1_POLICY_DENIED)return error(0);
        if(result.code)return cleanup_failure(e,result);
        e->streams=NULL;
    }
    if(e->datagrams){
        if(!e->datagrams_drained)return error(0);
        struct steer_pv1_error result=steer_draft_datagram_router_destroy(e->datagrams);
        if(result.code==STEER_PV1_POLICY_DENIED)return error(0);
        if(result.code)return cleanup_failure(e,result);
        e->datagrams=NULL;
    }
    while(e->collect_cursor&&calls++<STEER_SPEC_EXECUTION_STEP){
        struct node *n=&e->nodes[e->order[e->collect_cursor-1]];
        if(n->bound&&n->factory>=0){
            const struct steer_spec_execution_factory *f=&e->factories[n->factory];
            e->owner_depth++;struct steer_pv1_error result=checked(f->collect(f->context,&n->instance));e->owner_depth--;
            if(result.code==STEER_PV1_POLICY_DENIED)return error(0);
            if(result.code)return cleanup_failure(e,result);
        }
        memset(&n->instance,0,sizeof(n->instance));n->bound=0;e->collect_cursor--;
    }
    if(e->collect_cursor){wake_owner(e);return error(0);}
    for(unsigned i=0;i<2;i++)if(e->configuration[i]){
        if(!e->configuration_done[i])return error(0);
        struct steer_pv1_error result=steer_draft_binding_lease_destroy(e->configuration[i]);
        if(result.code==STEER_PV1_POLICY_DENIED)return error(0);
        if(result.code)return cleanup_failure(e,result);
        e->configuration[i]=NULL;
    }
    e->state=OWNER_DRAINED;*progress=STEER_SPEC_EXECUTION_READY;return error(0);
}
struct steer_pv1_error steer_spec_execution_recover_owner(struct steer_spec_execution *e){
    if(!e)return error(STEER_PV1_INVALID);
    if(e->state!=RETIRING||e->owner_depth||!e->cleanup_failed)return error(STEER_PV1_POLICY_DENIED);
    e->cleanup_failed=0;e->cleanup_error=error(0);wake_owner(e);return error(0);
}
struct steer_draft_stream_routes *steer_spec_execution_streams(struct steer_spec_execution *e){return e&&e->state==PUBLISHED?e->streams:NULL;}
struct steer_draft_datagram_router *steer_spec_execution_datagrams(struct steer_spec_execution *e){return e&&e->state==PUBLISHED?e->datagrams:NULL;}
struct steer_draft_binding_lease *steer_spec_execution_configuration_lease(struct steer_spec_execution *e,uint32_t flow){
    if(!e||e->state!=PUBLISHED)return NULL;
    return flow==STEER_PV1_FLOW_STREAM?e->configuration[0]:flow==STEER_PV1_FLOW_DATAGRAM?e->configuration[1]:NULL;
}
