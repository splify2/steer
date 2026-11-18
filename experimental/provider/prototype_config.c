#define _GNU_SOURCE
#include "prototype_config.h"
#include "../spec/spec.h"
#include "ynode.h"
#include "jsonw.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
static struct steer_pv1_error err(uint32_t c){
    struct steer_pv1_error e={
        c,0
    }
    ;
    return e;
}
static int scalar(const struct ynode*n){
    int b;
    long value;
    char *end;
    if(!n||n->kind!=YN_SCALAR||n->tag||memchr(n->str,0,n->len))return 0;
    if(n->style!=YS_PLAIN)return 1;
    if(ynode_is_null(n)||!ynode_bool(n,&b)||!ynode_long(n,&value))return 0;
    (void)strtod(n->str,&end);
    if(end!=n->str&&!*end)return 0;
    return strcasecmp(n->str,".inf")&&strcasecmp(n->str,"+.inf")&&strcasecmp(n->str,"-.inf")&&strcasecmp(n->str,".nan");
}
static int eq(const struct ynode*n,const char*s){
    return scalar(n)&&!strcmp(n->str,s);
}
static int keys(const struct ynode*n,const char*a){
    size_t i;
    if(!n||n->kind!=YN_MAP)return 0;
    for(i=0;i<n->len;i++){
        const struct ynode*k=ynode_key_at(n,i);
        const char*p=a;
        int found=0;
        while(*p){
            const char*end=strchr(p,' ');
            size_t len=end?(size_t)(end-p):strlen(p);
            if(len==k->len&&!memcmp(p,k->str,len))found=1;
            if(!end)break;
            p=end+1;
        }
        if(!found)return 0;
    }
    return 1;
}
static int copy(const struct ynode*n,char*s,size_t cap){
    if(!scalar(n)||!n->len||n->len>=cap)return 0;
    memcpy(s,n->str,n->len+1);
    return 1;
}
static int id(const struct ynode*n,char*s){
    size_t i;
    if(!copy(n,s,65))return 0;
    for(i=0;i<n->len;i++){
        unsigned c=(unsigned char)s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;
    }
    return 1;
}
static int env_name(const char *name,size_t length){
    if(!length||length>95)return 0;
    for(size_t i=0;i<length;i++){
        unsigned c=(unsigned char)name[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||(i&&c>='0'&&c<='9')))return 0;
    }
    return 1;
}
static int reference(const struct ynode*n,char*s){
    return copy(n,s,100)&&n->len>4&&!memcmp(s,"env:",4)&&env_name(s+4,n->len-4);
}
static int flag(const struct ynode*n,uint32_t fallback,uint32_t*out){
    int b;
    if(!n){
        *out=fallback;
        return 1;
    }
    if(ynode_bool(n,&b))return 0;
    *out=(uint32_t)b;
    return 1;
}
static int label(const struct ynode*n,char*s){
    size_t i;
    if(!n){
        s[0]=0;
        return 1;
    }
    if(!scalar(n)||n->len>128)return 0;
    for(i=0;i<n->len;i++){
        unsigned c=(unsigned char)n->str[i];
        if(c<32||c==127||(c==194&&i+1<n->len&&(unsigned char)n->str[i+1]>=128&&(unsigned char)n->str[i+1]<=159))return 0;
    }
    memcpy(s,n->str,n->len+1);
    return 1;
}
static int port(const struct ynode*n,uint16_t*out){
    long x;
    if(ynode_long(n,&x)||x<1||x>65535)return 0;
    *out=(uint16_t)x;
    return 1;
}
static int tags(const struct ynode*n){
    size_t i,total;
    if(!n||n->tag||(n->kind==YN_SCALAR&&memchr(n->str,0,n->len)))return 0;
    total=n->kind==YN_MAP?2*n->len:n->kind==YN_SEQ?n->len:0;
    for(i=0;i<total;i++)if(!tags(n->items[i]))return 0;
    return 1;
}
static int listen_address(const struct ynode*v,struct steer_prototype_listener*l){
    uint8_t ip[16];
    int family;
    if(!keys(v,"address port")||!copy(ynode_get(v,"address"),l->address,sizeof(l->address))||!port(ynode_get(v,"port"),&l->port))return 0;
    family=inet_pton(AF_INET,l->address,ip)==1?AF_INET:inet_pton(AF_INET6,l->address,ip)==1?AF_INET6:0;
    if(!family)return 0;
    if(family==AF_INET && (ip[0]>=224 ||
       (ip[0]==0 && (ip[1]||ip[2]||ip[3]))))return 0;
    if(family==AF_INET6 && (ip[0]==0xff ||
       !memcmp(ip,(uint8_t[12]){0,0,0,0,0,0,0,0,0,0,255,255},12)))return 0;
    return inet_ntop(family,ip,l->address,sizeof(l->address))!=NULL;
}
static int listener(const struct ynode*n,struct steer_prototype_listener*l){
    const struct ynode*a,*v,*tls;
    if(!keys(n,"id label enabled protocol listen auth tls")||!id(ynode_get(n,"id"),l->id)||!label(ynode_get(n,"label"),l->label)||!flag(ynode_get(n,"enabled"),1,&l->enabled))return 0;
    if(eq(ynode_get(n,"protocol"),"socks"))l->protocol=STEER_PROTOTYPE_SOCKS;
    else if(eq(ynode_get(n,"protocol"),"vless"))l->protocol=STEER_PROTOTYPE_VLESS;
    else if(eq(ynode_get(n,"protocol"),"hysteria2"))l->protocol=STEER_PROTOTYPE_HYSTERIA2;
    else return 0;
    tls=ynode_get(n,"tls");
    if(l->protocol==STEER_PROTOTYPE_HYSTERIA2) {
        if(!keys(tls,"certificate_ref private_key_ref")||tls->len!=2||
           !reference(ynode_get(tls,"certificate_ref"),l->certificate_ref)||
           !reference(ynode_get(tls,"private_key_ref"),l->private_key_ref))return 0;
    } else if(tls)return 0;
    v=ynode_get(n,"listen");
    a=ynode_get(n,"auth");
    if(!listen_address(v,l)||!keys(a,"type principal_id username_ref password_ref uuid_ref"))return 0;
    v=ynode_get(a,"type");
    if(eq(v,"none"))return l->protocol==STEER_PROTOTYPE_SOCKS&&a->len==1;
    if(!id(ynode_get(a,"principal_id"),l->principal_id))return 0;
    if(eq(v,"userpass")){
        l->auth=STEER_PROTOTYPE_AUTH_USERPASS;
        return l->protocol==STEER_PROTOTYPE_SOCKS&&a->len==4&&reference(ynode_get(a,"username_ref"),l->username_ref)&&reference(ynode_get(a,"password_ref"),l->password_ref);
    }
    if(eq(v,"uuid")){
        l->auth=STEER_PROTOTYPE_AUTH_UUID;
        return l->protocol==STEER_PROTOTYPE_VLESS&&a->len==3&&reference(ynode_get(a,"uuid_ref"),l->uuid_ref);
    }
    if(eq(v,"password")){
        l->auth=STEER_PROTOTYPE_AUTH_PASSWORD;
        return l->protocol==STEER_PROTOTYPE_HYSTERIA2&&a->len==3&&reference(ynode_get(a,"password_ref"),l->password_ref);
    }
    return 0;
}
static struct steer_pv1_span span(const struct ynode*n){
    struct steer_pv1_span s={
        NULL,0
    }
    ;
    if(n){
        s.data=(const uint8_t*)n->str;
        s.len=(uint32_t)n->len;
    }
    return s;
}
static int action(const struct ynode*n,uint32_t*out){
    if(eq(n,"direct"))*out=STEER_POLICY_DIRECT;
    else if(eq(n,"block"))*out=STEER_POLICY_BLOCK;
    else return 0;
    return 1;
}
static int rule(const struct ynode*n,struct steer_policy_rule*r,uint32_t*enabled,const struct steer_prototype_config*c){
    const struct ynode*v;
    char scratch[129];
    uint32_t i;
    if(!keys(n,"id label enabled inbound principal domain domain_suffix cidr ports match_all action")||!id(ynode_get(n,"id"),scratch)||!label(ynode_get(n,"label"),scratch)||!flag(ynode_get(n,"enabled"),1,enabled)||!flag(ynode_get(n,"domain_suffix"),0,&r->domain_suffix)||!flag(ynode_get(n,"match_all"),0,&r->match_all)||!action(ynode_get(n,"action"),&r->action))return 0;
    r->id=span(ynode_get(n,"id"));
    v=ynode_get(n,"inbound");
    if(v){
        if(!id(v,scratch))return 0;
        for(i=0;i<c->listener_count;i++)if(!strcmp(scratch,c->listeners[i].id))break;
        if(i==c->listener_count)return 0;
        r->inbound=span(v);
    }
    v=ynode_get(n,"principal");
    if(v){
        if(!id(v,scratch))return 0;
        r->principal=span(v);
    }
    v=ynode_get(n,"domain");
    if(v){
        if(!scalar(v))return 0;
        r->domain=span(v);
    }
    v=ynode_get(n,"ports");
    if(v&&(v->kind!=YN_SEQ||v->len!=2||!port(ynode_at(v,0),&r->port_first)||!port(ynode_at(v,1),&r->port_last)))return 0;
    v=ynode_get(n,"cidr");
    if(v){
        char*slash,*end;
        unsigned long bits;
        if(!copy(v,scratch,sizeof(scratch)))return 0;
        slash=strchr(scratch,'/');
        if(!slash)return 0;
        *slash++=0;
        if(!*slash)return 0;
        for(end=slash;*end;end++)if(*end<'0'||*end>'9')return 0;
        bits=strtoul(slash,&end,10);
        if(*end||bits>128)return 0;
        if(inet_pton(AF_INET,scratch,r->network)==1)r->cidr_tag=STEER_PV1_ENDPOINT_IPV4;
        else if(inet_pton(AF_INET6,scratch,r->network)==1)r->cidr_tag=STEER_PV1_ENDPOINT_IPV6;
        else return 0;
        r->prefix_bits=(uint32_t)bits;
    }
    return 1;
}
static void json(FILE*f,const struct ynode*n,const char*key,unsigned depth){
    size_t i;
    if(n->kind==YN_SCALAR){
        int b;
        if(!strcmp(key,"port")||!strcmp(key,"ports")||(depth==1&&!strcmp(key,"version"))){
            long x=0;
            (void)ynode_long(n,&x);
            fprintf(f,"%ld",x);
        }
        else if((!strcmp(key,"enabled")||!strcmp(key,"domain_suffix")||!strcmp(key,"match_all"))&&!ynode_bool(n,&b)){
            fputs(b?"true":"false",f);
        }
        else jsonw_str(f,n->str);
    }
    else{
        fputc(n->kind==YN_MAP?'{':'[',f);
        for(i=0;i<n->len;i++){
            if(i)fputc(',',f);
            if(n->kind==YN_MAP){
                const struct ynode*k=ynode_key_at(n,i);
                jsonw_str(f,k->str);
                fputc(':',f);
                json(f,ynode_val_at(n,i),k->str,depth+1);
            }
            else json(f,ynode_at(n,i),key,depth+1);
        }
        fputc(n->kind==YN_MAP?'}':']',f);
    }
}
void steer_prototype_config_destroy(struct steer_prototype_config*c){
    if(c){
        steer_policy_destroy(c->policy);
        free(c->document_json);
        free(c);
    }
}

static int distinct_listener(const struct steer_prototype_config *c,uint32_t i){
    const struct steer_prototype_listener *l=&c->listeners[i];
    for(uint32_t j=0;j<i;j++){
        const struct steer_prototype_listener *prev=&c->listeners[j];
        if(!strcmp(l->id,prev->id)||(l->enabled&&prev->enabled&&
            (l->protocol==STEER_PROTOTYPE_HYSTERIA2)==(prev->protocol==STEER_PROTOTYPE_HYSTERIA2)&&
            l->port==prev->port&&!strcmp(l->address,prev->address)))return 0;
    }
    return 1;
}

static struct steer_pv1_error compile_policy(struct steer_prototype_config *c,
    const struct steer_policy_rule *all,uint32_t total,const struct steer_policy_rule *active,
    uint32_t count,uint32_t fallback){
    struct steer_pv1_error e=steer_policy_compile(c->generation,all,total,fallback,&c->policy);
    if(e.code||count==total)return e;
    steer_policy_destroy(c->policy);
    c->policy=NULL;
    return steer_policy_compile(c->generation,active,count,fallback,&c->policy);
}

static int v3_socks_options(void *unused,const struct ynode *options){
    (void)unused;
    return keys(options,"");
}
static const struct ynode *v3_vless_secret(const struct ynode *options,char principal[65]){
    if(!keys(options,"principal_id uuid")||!id(ynode_get(options,"principal_id"),principal))return NULL;
    const struct ynode *uuid=ynode_get(options,"uuid"),*secret=ynode_get(uuid,"secret");
    char identifier[65];
    return keys(uuid,"secret")&&id(secret,identifier)?secret:NULL;
}
static int v3_vless_options(void *unused,const struct ynode *options){
    (void)unused;
    char principal[65];
    return v3_vless_secret(options,principal)!=NULL;
}
static int v3_inbound(const struct steer_spec_node_view *node,const struct ynode *secrets,
    struct steer_prototype_listener *l){
    if(!keys(node->intent,"label enabled plugin options listen flow"))return 0;
    if(!strncmp(node->provider,"socks:",6)&&v3_socks_options(NULL,node->options)){
        l->protocol=STEER_PROTOTYPE_SOCKS;
    }else if(!strncmp(node->provider,"vless:",6)){
        const struct ynode *ref=v3_vless_secret(node->options,l->principal_id);
        const struct ynode *name=ref?ynode_get(ynode_get(secrets,ref->str),"name"):NULL;
        if(!name)return 0;
        l->protocol=STEER_PROTOTYPE_VLESS;
        l->auth=STEER_PROTOTYPE_AUTH_UUID;
        memcpy(l->uuid_ref,"env:",4);
        memcpy(l->uuid_ref+4,name->str,name->len+1);
    }else return 0;
    l->enabled=(uint32_t)node->enabled;
    strcpy(l->id,node->id);
    return label(ynode_get(node->intent,"label"),l->label)&&listen_address(node->listen,l)&&
        (!strncmp(l->address,"127.",4)||!strcmp(l->address,"::1"));
}
static int v3_named_action(const struct ynode *outbounds,const char *name,uint32_t *out){
    return action(ynode_get(ynode_get(outbounds,name),"type"),out);
}
static int v3_rule(const struct steer_spec_rule_view *r,const struct ynode *source,
    const struct ynode *outbounds,struct steer_policy_rule *out){
    static const char *fields[]={"inbound","domain","domain_suffix"};
    if(r->dns_rule||!keys(source,"name enabled match action outbound")||
        !keys(r->match,"inbound domain domain_suffix"))return 0;
    if(!strcmp(r->action,"route")){
        if(!v3_named_action(outbounds,r->target,&out->action))return 0;
    }else if(!strcmp(r->action,"reject")&&!ynode_get(source,"outbound"))out->action=STEER_POLICY_BLOCK;
    else return 0;
    out->id=span(ynode_get(source,"name"));
    out->match_all=r->match->len==0;
    for(size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++){
        const struct ynode *list=ynode_get(r->match,fields[i]);
        if(!list)continue;
        if(list->kind!=YN_SEQ||list->len!=1||!scalar(ynode_at(list,0)))return 0;
        if(i==0)out->inbound=span(ynode_at(list,0));
        else {
            if(out->domain.len||!ynode_at(list,0)->len)return 0;
            out->domain=span(ynode_at(list,0));
            out->domain_suffix=i==2;
        }
    }
    return 1;
}
static struct steer_pv1_error parse_v3(const char *data,size_t length,const struct ynode *root,
    struct steer_prototype_config *c){
    const struct ynode *remotes=ynode_get(root,"plugin_remotes"),*plugins=ynode_get(root,"plugins"),
        *inbounds=ynode_get(root,"inbounds"),*outbounds=ynode_get(root,"outbounds"),
        *routing=ynode_get(root,"routing"),*rules=ynode_get(routing,"rules"),*secrets=ynode_get(root,"secrets");
    static const struct steer_spec_capability core[]={
        {"core.spec-v3.apply",STEER_SPEC_READY,NULL,NULL},
        {"core.outbound.direct",STEER_SPEC_READY,NULL,NULL},
        {"core.outbound.block",STEER_SPEC_READY,NULL,NULL},
        {"core.routing.action.route",STEER_SPEC_READY,NULL,NULL},
        {"core.routing.action.reject",STEER_SPEC_READY,NULL,NULL},
        {"core.classifier.inbound",STEER_SPEC_READY,NULL,NULL},
        {"core.classifier.domain",STEER_SPEC_READY,NULL,NULL},
        {"core.classifier.domain_suffix",STEER_SPEC_READY,NULL,NULL},
        {"core.secret.env",STEER_SPEC_READY,NULL,NULL},
    };
    struct steer_spec_capability inventory[sizeof(core)/sizeof(core[0])+3*STEER_PROTOTYPE_MAX_LISTENERS];
    size_t count=sizeof(core)/sizeof(core[0]);
    char requirements[STEER_PROTOTYPE_MAX_LISTENERS][3][128];
    struct steer_policy_rule all[STEER_PROTOTYPE_MAX_RULES]={0},active[STEER_PROTOTYPE_MAX_RULES]={0};
    struct steer_pv1_error result=err(STEER_PV1_INVALID);
    uint32_t enabled=0,fallback;
    if(!keys(root,"version plugin_remotes plugins inbounds outbounds routing secrets")||
        !remotes||remotes->kind!=YN_MAP||remotes->len>1||
        !plugins||plugins->kind!=YN_MAP||plugins->len>STEER_PROTOTYPE_MAX_LISTENERS||
        !inbounds||inbounds->kind!=YN_MAP||inbounds->len>STEER_PROTOTYPE_MAX_LISTENERS||
        !outbounds||outbounds->kind!=YN_MAP||outbounds->len>STEER_PROTOTYPE_MAX_LISTENERS||
        (secrets&&(secrets->kind!=YN_MAP||secrets->len>STEER_PROTOTYPE_MAX_LISTENERS))||
        !keys(routing,"default rules")||!rules||rules->kind!=YN_SEQ||rules->len>STEER_PROTOTYPE_MAX_RULES)return result;
    memcpy(inventory,core,sizeof(core));
    /* Only the code linked into this binary satisfies this local profile. The
     * declared remote is a fixed identity, never a source of code or trust. */
    for(size_t i=0;i<remotes->len;i++){
        const struct ynode *remote=ynode_val_at(remotes,i);
        if(!keys(remote,"url trust")||
            !eq(ynode_get(remote,"url"),"https://github.com/splify2/steer-protocols")||
            !eq(ynode_get(remote,"trust"),"steer-linked-prototype-v1"))return result;
    }
    for(size_t i=0;i<plugins->len;i++){
        const struct ynode *plugin=ynode_val_at(plugins,i),*remote=ynode_get(plugin,"remote");
        const struct ynode *alias=ynode_key_at(plugins,i);
        if(alias->len>63||!keys(plugin,"remote package version")||!scalar(remote)||!ynode_get(remotes,remote->str)||
            !eq(ynode_get(plugin,"package"),"steer-protocols")||!eq(ynode_get(plugin,"version"),"0.0.0"))return result;
        snprintf(requirements[i][0],sizeof(requirements[i][0]),"plugin.lock.%s",alias->str);
        snprintf(requirements[i][1],sizeof(requirements[i][1]),"provider.socks:%s/inbound/stream/tcp/none/default",alias->str);
        snprintf(requirements[i][2],sizeof(requirements[i][2]),"provider.vless:%s/inbound/stream/tcp/none/default",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][0],STEER_SPEC_READY,NULL,NULL};
        inventory[count++]=(struct steer_spec_capability){requirements[i][1],STEER_SPEC_READY,v3_socks_options,NULL};
        inventory[count++]=(struct steer_spec_capability){requirements[i][2],STEER_SPEC_READY,v3_vless_options,NULL};
    }
    for(size_t i=0;secrets&&i<secrets->len;i++){
        const struct ynode *secret=ynode_val_at(secrets,i),*name=ynode_get(secret,"name");
        if(!keys(secret,"source name kind")||!eq(ynode_get(secret,"source"),"env")||
            !eq(ynode_get(secret,"kind"),"uuid")||!scalar(name)||!env_name(name->str,name->len))return result;
    }
    struct steer_spec_plan *plan=steer_spec_compile(data,length,inventory,count);
    if(!plan)return err(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_spec_summary summary=steer_spec_summary(plan);
    if(!summary.runtime_ready)goto done;
    for(uint32_t i=0;i<summary.nodes;i++){
        struct steer_spec_node_view node;
        if(!steer_spec_node(plan,i,&node))goto done;
        if(node.kind==STEER_SPEC_PLUGIN||node.kind==STEER_SPEC_SECRET)continue;
        if(node.flows!=STEER_SPEC_FLOW_STREAM)goto done;
        if(node.kind==STEER_SPEC_OUTBOUND){
            uint32_t a;
            if(!keys(node.intent,"type label flow")||
                !v3_named_action(outbounds,node.id,&a))goto done;
            continue;
        }
        if(node.kind!=STEER_SPEC_INBOUND||c->listener_count>=STEER_PROTOTYPE_MAX_LISTENERS||
            !v3_inbound(&node,secrets,&c->listeners[c->listener_count])||
            !distinct_listener(c,c->listener_count))goto done;
        c->listener_count++;
    }
    const struct ynode *target=ynode_get(routing,"default");
    if(!scalar(target)||!v3_named_action(outbounds,target->str,&fallback))goto done;
    for(uint32_t i=0;i<rules->len;i++){
        struct steer_spec_rule_view r;
        if(!steer_spec_rule(plan,i,&r)||!v3_rule(&r,ynode_at(rules,i),outbounds,&all[i]))goto done;
        if(r.enabled)active[enabled++]=all[i];
    }
    result=compile_policy(c,all,(uint32_t)rules->len,active,enabled,fallback);
    done:steer_spec_destroy(plan);
    return result;
}

struct steer_pv1_error steer_prototype_config_parse(const char*data,size_t length,uint64_t generation,struct steer_prototype_config**out){
    struct err diagnostic={
        0
    }
    ;
    struct ydoc*doc;
    const struct ynode*root,*list,*routing,*rules;
    struct steer_prototype_config*c=NULL;
    struct steer_policy_rule all[STEER_PROTOTYPE_MAX_RULES]={
        0
    }
    ,active[STEER_PROTOTYPE_MAX_RULES]={
        0
    }
    ;
    uint32_t i,count=0,fallback;
    struct steer_pv1_error e=err(STEER_PV1_INVALID);
    FILE*f;
    if(out)*out=NULL;
    if(!out||!data||!length||length>STEER_PROTOTYPE_CONFIG_MAX_BYTES||!generation)return e;
    doc=ydoc_parse_buf(data,length,"prototype-config",&diagnostic);
    if(!doc)return e;
    root=ydoc_root(doc);
    if(!tags(root))goto done;
    c=calloc(1,sizeof(*c));
    if(!c){
        e=err(STEER_PV1_RESOURCE_EXHAUSTED);
        goto done;
    }
    c->generation=generation;
    if(ynode_get(root,"version")){
        c->format=STEER_STORE_FORMAT_SPEC_V3;
        e=parse_v3(data,length,root,c);
        if(e.code)goto done;
        goto serialize;
    }
    if(!keys(root,"prototype listeners routing")||!eq(ynode_get(root,"prototype"),"steer-linux-v1"))goto done;
    c->format=STEER_STORE_FORMAT_PROTOTYPE;
    list=ynode_get(root,"listeners");
    routing=ynode_get(root,"routing");
    if(!list||list->kind!=YN_SEQ||list->len>STEER_PROTOTYPE_MAX_LISTENERS||!keys(routing,"default rules"))goto done;
    rules=ynode_get(routing,"rules");
    if(!rules||rules->kind!=YN_SEQ||rules->len>STEER_PROTOTYPE_MAX_RULES||!action(ynode_get(routing,"default"),&fallback))goto done;
    c->listener_count=(uint32_t)list->len;
    for(i=0;i<c->listener_count;i++){
        if(!listener(ynode_at(list,i),&c->listeners[i])||!distinct_listener(c,i))goto done;
    }
    for(i=0;i<rules->len;i++){
        uint32_t enabled;
        if(!rule(ynode_at(rules,i),&all[i],&enabled,c))goto done;
        if(enabled)active[count++]=all[i];
    }
    e=compile_policy(c,all,(uint32_t)rules->len,active,count,fallback);
    if(e.code)goto done;
    serialize:
    c->document_json=calloc(1,STEER_PROTOTYPE_CONFIG_MAX_BYTES+1);
    if(!c->document_json){
        e=err(STEER_PV1_RESOURCE_EXHAUSTED);
        goto done;
    }
    f=fmemopen(c->document_json,STEER_PROTOTYPE_CONFIG_MAX_BYTES+1,"w");
    if(!f){
        e=err(STEER_PV1_RESOURCE_EXHAUSTED);
        goto done;
    }
    json(f,root,"",0);
    if(fflush(f)||ferror(f)){
        fclose(f);
        e=err(STEER_PV1_RESOURCE_EXHAUSTED);
        goto done;
    }
    {
        long n=ftell(f);
        fclose(f);
        if(n<0||(size_t)n>STEER_PROTOTYPE_CONFIG_MAX_BYTES){
            e=err(STEER_PV1_INVALID);
            goto done;
        }
        c->document_length=(size_t)n;
    }
    *out=c;
    c=NULL;
    e=err(STEER_PV1_OK);
    done:ydoc_free(doc);
    steer_prototype_config_destroy(c);
    return e;
}
