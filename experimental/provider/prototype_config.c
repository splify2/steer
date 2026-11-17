#define _GNU_SOURCE
#include "prototype_config.h"
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
static int reference(const struct ynode*n,char*s){
    size_t i;
    if(!copy(n,s,100)||n->len<=4||memcmp(s,"env:",4))return 0;
    for(i=4;i<n->len;i++){
        unsigned c=(unsigned char)s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||(i>4&&c>='0'&&c<='9')))return 0;
    }
    return 1;
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
    if(!n||n->tag)return 0;
    total=n->kind==YN_MAP?2*n->len:n->kind==YN_SEQ?n->len:0;
    for(i=0;i<total;i++)if(!tags(n->items[i]))return 0;
    return 1;
}
static int listener(const struct ynode*n,struct steer_prototype_listener*l){
    const struct ynode*a,*v;
    uint8_t ip[16];
    int family;
    if(!keys(n,"id label enabled protocol listen auth")||!id(ynode_get(n,"id"),l->id)||!label(ynode_get(n,"label"),l->label)||!flag(ynode_get(n,"enabled"),1,&l->enabled))return 0;
    if(eq(ynode_get(n,"protocol"),"socks"))l->protocol=STEER_PROTOTYPE_SOCKS;
    else if(eq(ynode_get(n,"protocol"),"vless"))l->protocol=STEER_PROTOTYPE_VLESS;
    else return 0;
    v=ynode_get(n,"listen");
    a=ynode_get(n,"auth");
    if(!keys(v,"address port")||!copy(ynode_get(v,"address"),l->address,sizeof(l->address))||!port(ynode_get(v,"port"),&l->port))return 0;
    family=inet_pton(AF_INET,l->address,ip)==1?AF_INET:inet_pton(AF_INET6,l->address,ip)==1?AF_INET6:0;
    /* Explicit numeric server bindings; examples still default to loopback.
     * Multicast/reserved IPv4 and mapped IPv6 are not listener identities. */
    if(!family)return 0;
    if(family==AF_INET && (ip[0]>=224 ||
       (ip[0]==0 && (ip[1]||ip[2]||ip[3]))))return 0;
    if(family==AF_INET6 && (ip[0]==0xff ||
       !memcmp(ip,(uint8_t[12]){0,0,0,0,0,0,0,0,0,0,255,255},12)))return 0;
    if(!inet_ntop(family,ip,l->address,sizeof(l->address))||!keys(a,"type principal_id username_ref password_ref uuid_ref"))return 0;
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
static void json(FILE*f,const struct ynode*n,const char*key){
    size_t i;
    if(n->kind==YN_SCALAR){
        if(!strcmp(key,"port")||!strcmp(key,"ports")){
            long x=0;
            (void)ynode_long(n,&x);
            fprintf(f,"%ld",x);
        }
        else if(!strcmp(key,"enabled")||!strcmp(key,"domain_suffix")||!strcmp(key,"match_all")){
            int b=0;
            (void)ynode_bool(n,&b);
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
                json(f,ynode_val_at(n,i),k->str);
            }
            else json(f,ynode_at(n,i),key);
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
    uint32_t i,j,count=0,fallback;
    struct steer_pv1_error e=err(STEER_PV1_INVALID);
    FILE*f;
    if(out)*out=NULL;
    if(!out||!data||!length||length>STEER_PROTOTYPE_CONFIG_MAX_BYTES||!generation)return e;
    doc=ydoc_parse_buf(data,length,"prototype-config",&diagnostic);
    if(!doc)return e;
    root=ydoc_root(doc);
    if(!tags(root)||!keys(root,"prototype listeners routing")||!eq(ynode_get(root,"prototype"),"steer-linux-v1"))goto done;
    list=ynode_get(root,"listeners");
    routing=ynode_get(root,"routing");
    if(!list||list->kind!=YN_SEQ||list->len>STEER_PROTOTYPE_MAX_LISTENERS||!keys(routing,"default rules"))goto done;
    rules=ynode_get(routing,"rules");
    if(!rules||rules->kind!=YN_SEQ||rules->len>STEER_PROTOTYPE_MAX_RULES||!action(ynode_get(routing,"default"),&fallback))goto done;
    c=calloc(1,sizeof(*c));
    if(!c){
        e=err(STEER_PV1_RESOURCE_EXHAUSTED);
        goto done;
    }
    c->generation=generation;
    c->listener_count=(uint32_t)list->len;
    for(i=0;i<c->listener_count;i++){
        if(!listener(ynode_at(list,i),&c->listeners[i]))goto done;
        for(j=0;j<i;j++)if(!strcmp(c->listeners[i].id,c->listeners[j].id)||(c->listeners[i].enabled&&c->listeners[j].enabled&&c->listeners[i].port==c->listeners[j].port&&!strcmp(c->listeners[i].address,c->listeners[j].address)))goto done;
    }
    for(i=0;i<rules->len;i++){
        uint32_t enabled;
        if(!rule(ynode_at(rules,i),&all[i],&enabled,c))goto done;
        if(enabled)active[count++]=all[i];
    }
    e=steer_policy_compile(generation,all,(uint32_t)rules->len,fallback,&c->policy);
    if(e.code)goto done;
    steer_policy_destroy(c->policy);
    c->policy=NULL;
    e=steer_policy_compile(generation,active,count,fallback,&c->policy);
    if(e.code)goto done;
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
    json(f,root,"");
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
