#define _GNU_SOURCE
#include "prototype_config.h"
#ifdef STEER_PROTOTYPE_WG_NETNS
#include "prototype_linked_wg.h"
#endif
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
static int numeric_address(const char *address,char *canonical,size_t size){
    uint8_t ip[16];
    int family=inet_pton(AF_INET,address,ip)==1?AF_INET:inet_pton(AF_INET6,address,ip)==1?AF_INET6:0;
    if(!family)return 0;
    if(family==AF_INET && (ip[0]>=224 ||
       (ip[0]==0 && (ip[1]||ip[2]||ip[3]))))return 0;
    if(family==AF_INET6 && (ip[0]==0xff ||
       !memcmp(ip,(uint8_t[12]){0,0,0,0,0,0,0,0,0,0,255,255},12)))return 0;
    return inet_ntop(family,ip,canonical,size)!=NULL;
}
static int loopback_address(const char *address){
    return !strncmp(address,"127.",4)||!strcmp(address,"::1");
}
int steer_prototype_socks_vpn_allow(struct steer_prototype_socks_vpn_allowlist *allow,
    const char *address,const char *username_env,const char *password_env){
    char canonical[46];
    struct in6_addr ip6;
    if(allow->count>=STEER_PROTOTYPE_MAX_LISTENERS||
        !numeric_address(address,canonical,sizeof canonical)||loopback_address(canonical)||
        !strcmp(canonical,"0.0.0.0")||!strcmp(canonical,"::")||
        (inet_pton(AF_INET6,canonical,&ip6)==1&&IN6_IS_ADDR_LINKLOCAL(&ip6))||
        !env_name(username_env,strlen(username_env))||!env_name(password_env,strlen(password_env))||
        !strcmp(username_env,password_env))return 0;
    for(unsigned i=0;i<allow->count;i++)
        if(!strcmp(allow->entries[i].address,canonical))return 0;
    unsigned i=allow->count++;
    strcpy(allow->entries[i].address,canonical);
    snprintf(allow->entries[i].username_ref,sizeof allow->entries[i].username_ref,"env:%s",username_env);
    snprintf(allow->entries[i].password_ref,sizeof allow->entries[i].password_ref,"env:%s",password_env);
    return 1;
}
static int listen_address(const struct ynode*v,struct steer_prototype_listener*l){
    char address[46];
    return keys(v,"address port")&&copy(ynode_get(v,"address"),address,sizeof address)&&
        port(ynode_get(v,"port"),&l->port)&&numeric_address(address,l->address,sizeof l->address);
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
        if(!strcmp(key,"port")||!strcmp(key,"ports")||!strcmp(key,"listen_port")||!strcmp(key,"mtu")||
           (depth==1&&!strcmp(key,"version"))){
            long x=0;
            (void)ynode_long(n,&x);
            fprintf(f,"%ld",x);
        }
        else if((!strcmp(key,"enabled")||!strcmp(key,"domain_suffix")||!strcmp(key,"match_all")
#ifdef STEER_PROTOTYPE_HY2
                 ||!strcmp(key,"verify")
#endif
                )&&!ynode_bool(n,&b)){
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
        free(c->wg);
        free(c->wg_inbound_validate);
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
    struct steer_pv1_error e=steer_policy_compile_stream(c->generation,all,total,fallback,
        c->stream_outbound_count,&c->policy);
    if(e.code||count==total)return e;
    steer_policy_destroy(c->policy);
    c->policy=NULL;
    return steer_policy_compile_stream(c->generation,active,count,fallback,
        c->stream_outbound_count,&c->policy);
}

static const struct ynode *v3_secret_id(const struct ynode *ref){
    const struct ynode *secret=ynode_get(ref,"secret");
    char identifier[65];
    return keys(ref,"secret")&&id(secret,identifier)?secret:NULL;
}
static int v3_env_ref(const struct ynode *secrets,const struct ynode *ref,const char *kind,char out[100]){
    const struct ynode *id=v3_secret_id(ref);
    const struct ynode *secret=id?ynode_get(secrets,id->str):NULL;
    const struct ynode *name=ynode_get(secret,"name");
    if(!eq(ynode_get(secret,"kind"),kind)||!scalar(name)||!env_name(name->str,name->len))return 0;
    memcpy(out,"env:",4);
    memcpy(out+4,name->str,name->len+1);
    return 1;
}
static int v3_auth_options(const struct ynode *options,const char *allowed,const char *field,char principal[65]){
    return keys(options,allowed)&&id(ynode_get(options,"principal_id"),principal)&&v3_secret_id(ynode_get(options,field));
}
static int v3_socks_options(void *unused,const struct ynode *options){
    (void)unused;
    char principal[65];
    return keys(options,"")||
        (v3_auth_options(options,"principal_id username password","username",principal)&&
         v3_secret_id(ynode_get(options,"password")));
}
static int v3_vless_options(void *unused,const struct ynode *options){
    (void)unused;
    char principal[65];
    return v3_auth_options(options,"principal_id uuid","uuid",principal);
}
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
static int v3_vless_outbound_options(void *unused,const struct ynode *options){
    (void)unused;
    return keys(options,"uuid")&&v3_secret_id(ynode_get(options,"uuid"));
}
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
static int v3_socks_outbound_options(void *unused,const struct ynode *options){
    (void)unused;
    return keys(options,"username password")&&(!options->len||
        (v3_secret_id(ynode_get(options,"username"))&&v3_secret_id(ynode_get(options,"password"))));
}
#endif
#ifdef STEER_PROTOTYPE_HY2
static int v3_hy2_outbound_options(void *unused,const struct ynode *options){
    (void)unused;
    return keys(options,"password ca_bundle")&&v3_secret_id(ynode_get(options,"password"))&&
        v3_secret_id(ynode_get(options,"ca_bundle"));
}
#endif
#if defined(STEER_PROTOTYPE_VLESS_OUTBOUND) || defined(STEER_PROTOTYPE_SOCKS_OUTBOUND) || defined(STEER_PROTOTYPE_HY2)
static int v3_stream_outbound(const struct steer_spec_node_view *node,const struct ynode *secrets,
    struct steer_prototype_stream_outbound *out){
    const struct ynode *address=ynode_get(node->endpoint,"address");
    if(!node->enabled||!node->options_validated||
        !(node->flows&STEER_SPEC_FLOW_STREAM)||
        !keys(node->endpoint,"address port")||!scalar(address)||
        !port(ynode_get(node->endpoint,"port"),&out->port))return 0;
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
    if(!strncmp(node->provider,"vless:",6)){
        if(!v3_env_ref(secrets,ynode_get(node->options,"uuid"),"uuid",out->uuid_ref))return 0;
        out->protocol=STEER_PROTOTYPE_VLESS;
    }
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
    if(!strncmp(node->provider,"socks:",6)){
        if(node->options->len&&
           (!v3_env_ref(secrets,ynode_get(node->options,"username"),"username",out->username_ref)||
            !v3_env_ref(secrets,ynode_get(node->options,"password"),"password",out->password_ref)))return 0;
        out->protocol=STEER_PROTOTYPE_SOCKS;
    }
#endif
#ifdef STEER_PROTOTYPE_HY2
    if(!strncmp(node->provider,"hysteria2:",10)){
        const struct ynode *tls=node->security,*transport=node->transport;
        uint32_t verify;
        if(node->flows==(STEER_SPEC_FLOW_STREAM|STEER_SPEC_FLOW_DATAGRAM)) {
            if(!eq(node->variant,"numeric-udp-1000"))return 0;
            out->hy2_datagram=1;
        } else if(node->flows!=STEER_SPEC_FLOW_STREAM || node->variant) return 0;
        if(!keys(node->intent,"label enabled plugin flow endpoint options transport security variant")||
           !keys(transport,"type")||!eq(ynode_get(transport,"type"),"quic")||
           !keys(tls,"type server_name verify")||!eq(ynode_get(tls,"type"),"tls")||
           !flag(ynode_get(tls,"verify"),1,&verify)||!verify||
           !copy(ynode_get(tls,"server_name"),out->tls_name,sizeof out->tls_name)||
           !v3_env_ref(secrets,ynode_get(node->options,"password"),"password",out->password_ref)||
           !v3_env_ref(secrets,ynode_get(node->options,"ca_bundle"),"certificate",out->ca_ref))return 0;
        out->protocol=STEER_PROTOTYPE_HYSTERIA2;
    }else
#endif
    if(!keys(node->intent,"label enabled plugin flow endpoint options"))return 0;
    if(!out->protocol)return 0;
#ifdef STEER_PROTOTYPE_HY2
    if(out->protocol!=STEER_PROTOTYPE_HYSTERIA2 && node->flows!=STEER_SPEC_FLOW_STREAM)return 0;
#else
    if(node->flows!=STEER_SPEC_FLOW_STREAM)return 0;
#endif
    if(inet_pton(AF_INET,address->str,out->address)==1){
        if(!out->address[0]||out->address[0]>=224)return 0;
        out->endpoint_tag=STEER_PV1_ENDPOINT_IPV4;
    }else if(inet_pton(AF_INET6,address->str,out->address)==1){
        struct in6_addr ip;
        memcpy(&ip,out->address,sizeof(ip));
        if(IN6_IS_ADDR_UNSPECIFIED(&ip)||IN6_IS_ADDR_MULTICAST(&ip)||IN6_IS_ADDR_V4MAPPED(&ip)||
           IN6_IS_ADDR_LINKLOCAL(&ip))return 0;
        out->endpoint_tag=STEER_PV1_ENDPOINT_IPV6;
    }else return 0;
    strcpy(out->id,node->id);
    return 1;
}
#endif
#ifdef STEER_PROTOTYPE_HY2
static int v3_hy2_options(void *unused,const struct ynode *options){
    (void)unused;
    char principal[65];
    return v3_auth_options(options,"principal_id password","password",principal);
}
static int v3_hy2_inbound(const struct steer_spec_node_view *node,const struct ynode *secrets,
    struct steer_prototype_listener *l){
    const struct ynode *transport=node->transport,*tls=node->security;
    if((node->flows!=STEER_SPEC_FLOW_STREAM&&
        node->flows!=(STEER_SPEC_FLOW_STREAM|STEER_SPEC_FLOW_DATAGRAM))||
        !keys(node->intent,"label enabled plugin options listen flow transport security")||
        !keys(transport,"type")||!eq(ynode_get(transport,"type"),"quic")||
        !keys(tls,"type certificate private_key")||!eq(ynode_get(tls,"type"),"tls")||
        !v3_auth_options(node->options,"principal_id password","password",l->principal_id)||
        !v3_env_ref(secrets,ynode_get(node->options,"password"),"password",l->password_ref)||
        !v3_env_ref(secrets,ynode_get(tls,"certificate"),"certificate",l->certificate_ref)||
        !v3_env_ref(secrets,ynode_get(tls,"private_key"),"private_key",l->private_key_ref))return 0;
    l->protocol=STEER_PROTOTYPE_HYSTERIA2;
    l->auth=STEER_PROTOTYPE_AUTH_PASSWORD;
    l->datagram_disabled=node->flows==STEER_SPEC_FLOW_STREAM;
    return 1;
}
#endif
static int v3_tcp_inbound(const struct steer_spec_node_view *node,const struct ynode *secrets,
    struct steer_prototype_listener *l){
    if(node->flows!=STEER_SPEC_FLOW_STREAM||!keys(node->intent,"label enabled plugin options listen flow"))return 0;
    if(!strncmp(node->provider,"socks:",6)&&v3_socks_options(NULL,node->options)){
        l->protocol=STEER_PROTOTYPE_SOCKS;
        if(node->options->len){
            if(!id(ynode_get(node->options,"principal_id"),l->principal_id)||
                !v3_env_ref(secrets,ynode_get(node->options,"username"),"username",l->username_ref)||
                !v3_env_ref(secrets,ynode_get(node->options,"password"),"password",l->password_ref))return 0;
            l->auth=STEER_PROTOTYPE_AUTH_USERPASS;
        }
        return 1;
    }
    if(strncmp(node->provider,"vless:",6)||!v3_auth_options(node->options,"principal_id uuid","uuid",l->principal_id)||
        !v3_env_ref(secrets,ynode_get(node->options,"uuid"),"uuid",l->uuid_ref))return 0;
    l->protocol=STEER_PROTOTYPE_VLESS;
    l->auth=STEER_PROTOTYPE_AUTH_UUID;
    return 1;
}
static int v3_inbound(const struct steer_spec_node_view *node,const struct ynode *secrets,
    const struct steer_prototype_socks_vpn_allowlist *allow,struct steer_prototype_listener *l){
#ifdef STEER_PROTOTYPE_HY2
    if(!strncmp(node->provider,"hysteria2:",10)){
        if(!v3_hy2_inbound(node,secrets,l))return 0;
    }else
#endif
    if(!v3_tcp_inbound(node,secrets,l))return 0;
    l->enabled=(uint32_t)node->enabled;
    strcpy(l->id,node->id);
    if(!label(ynode_get(node->intent,"label"),l->label)||!listen_address(node->listen,l))return 0;
    if(loopback_address(l->address))return 1;
    if(!allow||l->protocol!=STEER_PROTOTYPE_SOCKS||l->auth!=STEER_PROTOTYPE_AUTH_USERPASS)return 0;
    for(unsigned i=0;i<allow->count;i++)
        if(!strcmp(l->address,allow->entries[i].address)&&
            !strcmp(l->username_ref,allow->entries[i].username_ref)&&
            !strcmp(l->password_ref,allow->entries[i].password_ref))return 1;
    return 0;
}
static int v3_secret_kind(const struct ynode *kind){
    if(eq(kind,"username")||eq(kind,"password"))return 1;
#ifdef STEER_PROTOTYPE_HY2
    if(eq(kind,"certificate")||eq(kind,"private_key"))return 1;
#endif
    return eq(kind,"uuid");
}
static int v3_named_action(const struct steer_prototype_config *c,
    const struct ynode *outbounds,const char *name,uint32_t *out){
    for(uint32_t i=0;i<c->stream_outbound_count;i++)if(!strcmp(c->stream_outbounds[i].id,name)){
        *out=STEER_POLICY_STREAM_BINDING_BASE+i;
        return 1;
    }
    return action(ynode_get(ynode_get(outbounds,name),"type"),out);
}
static int v3_rule(const struct steer_spec_rule_view *r,const struct ynode *source,
    const struct steer_prototype_config *c,const struct ynode *outbounds,struct steer_policy_rule *out){
    static const char *fields[]={"inbound","domain","domain_suffix"};
    if(r->dns_rule||!keys(source,"name enabled match action outbound")||
        !keys(r->match,"inbound domain domain_suffix"))return 0;
    if(!strcmp(r->action,"route")){
        if(!v3_named_action(c,outbounds,r->target,&out->action))return 0;
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
    const struct steer_prototype_socks_vpn_allowlist *allow,struct steer_prototype_config *c){
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
#ifdef STEER_PROTOTYPE_HY2
        {"core.transport.quic",STEER_SPEC_READY,NULL,NULL},
        {"core.security.tls",STEER_SPEC_READY,NULL,NULL},
#endif
    };
    const unsigned outbound_flows=STEER_SPEC_FLOW_STREAM
#ifdef STEER_PROTOTYPE_HY2
        |STEER_SPEC_FLOW_DATAGRAM
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
        |((allow&&allow->wg_inbound_validate)?STEER_SPEC_FLOW_DEVICE:0)
#endif
        ;
    enum { alias_requirements=12 };
    struct steer_spec_capability inventory[1+sizeof(core)/sizeof(core[0])+alias_requirements*STEER_PROTOTYPE_MAX_LISTENERS];
    size_t count=sizeof(core)/sizeof(core[0]);
    char requirements[STEER_PROTOTYPE_MAX_LISTENERS][alias_requirements][128];
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
#ifdef STEER_PROTOTYPE_WG_NETNS
    int wg_allowed=allow&&allow->wg_stream;
    int wg_inbound_validate=allow&&allow->wg_inbound_validate;
    int device_output=0;
    if(wg_allowed)inventory[count++]=(struct steer_spec_capability){"core.transport.udp",STEER_SPEC_READY,NULL,NULL};
#endif
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
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(wg_allowed){
            snprintf(requirements[i][8],sizeof(requirements[i][8]),"provider.wireguard:%s/outbound/stream/udp/none/kernel",alias->str);
            inventory[count++]=(struct steer_spec_capability){requirements[i][8],STEER_SPEC_READY,steer_draft_wg_v3_egress_options,NULL};
        }
        if(wg_inbound_validate){
            snprintf(requirements[i][9],sizeof(requirements[i][9]),"provider.wireguard:%s/inbound/device/device/none/default",alias->str);
            inventory[count++]=(struct steer_spec_capability){requirements[i][9],STEER_SPEC_READY,steer_draft_wg_v3_options,NULL};
        }
#endif
#ifdef STEER_PROTOTYPE_HY2
        snprintf(requirements[i][3],sizeof(requirements[i][3]),"provider.hysteria2:%s/inbound/stream/quic/tls/default",alias->str);
        snprintf(requirements[i][4],sizeof(requirements[i][4]),"provider.hysteria2:%s/inbound/datagram/quic/tls/default",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][3],STEER_SPEC_READY,v3_hy2_options,NULL};
        inventory[count++]=(struct steer_spec_capability){requirements[i][4],STEER_SPEC_READY,v3_hy2_options,NULL};
        snprintf(requirements[i][7],sizeof(requirements[i][7]),"provider.hysteria2:%s/outbound/stream/quic/tls/default",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][7],STEER_SPEC_READY,v3_hy2_outbound_options,NULL};
        snprintf(requirements[i][10],sizeof(requirements[i][10]),"provider.hysteria2:%s/outbound/stream/quic/tls/numeric-udp-1000",alias->str);
        snprintf(requirements[i][11],sizeof(requirements[i][11]),"provider.hysteria2:%s/outbound/datagram/quic/tls/numeric-udp-1000",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][10],STEER_SPEC_READY,v3_hy2_outbound_options,NULL};
        inventory[count++]=(struct steer_spec_capability){requirements[i][11],STEER_SPEC_READY,v3_hy2_outbound_options,NULL};
#endif
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
        snprintf(requirements[i][5],sizeof(requirements[i][5]),"provider.vless:%s/outbound/stream/tcp/none/default",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][5],STEER_SPEC_READY,v3_vless_outbound_options,NULL};
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        snprintf(requirements[i][6],sizeof(requirements[i][6]),"provider.socks:%s/outbound/stream/tcp/none/default",alias->str);
        inventory[count++]=(struct steer_spec_capability){requirements[i][6],STEER_SPEC_READY,v3_socks_outbound_options,NULL};
#endif
    }
    for(size_t i=0;secrets&&i<secrets->len;i++){
        const struct ynode *secret=ynode_val_at(secrets,i),*name=ynode_get(secret,"name");
        int kind=v3_secret_kind(ynode_get(secret,"kind"));
#ifdef STEER_PROTOTYPE_WG_NETNS
        if((wg_allowed||wg_inbound_validate)&&(eq(ynode_get(secret,"kind"),"wireguard_private_key")||
            eq(ynode_get(secret,"kind"),"wireguard_preshared_key")))
            kind=scalar(name)&&name->len>9&&name->len<64&&!strncmp(name->str,"STEER_WG_",9);
#endif
        if(!keys(secret,"source name kind")||!eq(ynode_get(secret,"source"),"env")||
            !kind||!scalar(name)||!env_name(name->str,name->len))return result;
    }
    struct steer_spec_plan *plan=steer_spec_compile(data,length,inventory,count);
    if(!plan)return err(STEER_PV1_RESOURCE_EXHAUSTED);
    struct steer_spec_summary summary=steer_spec_summary(plan);
    if(!summary.runtime_ready)goto done;
    for(uint32_t i=0;i<summary.nodes;i++){
        struct steer_spec_node_view node;
        if(!steer_spec_node(plan,i,&node))goto done;
        if(node.kind==STEER_SPEC_PLUGIN||node.kind==STEER_SPEC_SECRET)continue;
        if(node.kind==STEER_SPEC_OUTBOUND){
#ifdef STEER_PROTOTYPE_WG_NETNS
            if(node.flows&STEER_SPEC_FLOW_DEVICE)device_output=1;
            if(!strncmp(node.provider,"wireguard:",10)){
                if(!wg_allowed||c->wg||c->stream_outbound_count>=STEER_POLICY_STREAM_BINDINGS_MAX||
                   !keys(node.intent,"plugin flow variant transport endpoint options label"))goto done;
                c->wg=calloc(1,sizeof(*c->wg));
                if(!c->wg||!steer_draft_wg_v3_egress(plan,i,&c->wg->cfg,&c->wg->route))goto done;
                const struct ynode *name=ynode_get(ynode_get(secrets,c->wg->cfg.private_key),"name");
                const char *psk=c->wg->cfg.preshared_keys[0];
                if(!scalar(name)||name->len>=sizeof(c->wg->private_env))goto done;
                strcpy(c->wg->private_env,name->str);
                if(*psk){
                    name=ynode_get(ynode_get(secrets,psk),"name");
                    if(!scalar(name)||name->len>=sizeof(c->wg->psk_env))goto done;
                    strcpy(c->wg->psk_env,name->str);
                }
                struct steer_prototype_stream_outbound *out=&c->stream_outbounds[c->stream_outbound_count++];
                strcpy(out->id,node.id);
                out->protocol=STEER_PROTOTYPE_WIREGUARD;
                continue;
            }
#endif
#if defined(STEER_PROTOTYPE_VLESS_OUTBOUND) || defined(STEER_PROTOTYPE_SOCKS_OUTBOUND) || defined(STEER_PROTOTYPE_HY2)
            if(node.provider[0]){
                if(c->stream_outbound_count>=STEER_POLICY_STREAM_BINDINGS_MAX||
                   !v3_stream_outbound(&node,secrets,&c->stream_outbounds[c->stream_outbound_count]))goto done;
                c->stream_outbound_count++;
                continue;
            }
#endif
            uint32_t a;
            if(!node.flows||(node.flows&~outbound_flows)||!keys(node.intent,"type label flow")||
                !action(ynode_get(node.intent,"type"),&a))goto done;
            continue;
        }
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(node.kind==STEER_SPEC_INBOUND&&!strncmp(node.provider,"wireguard:",10)){
            if(!wg_inbound_validate||c->wg_inbound_validate||c->wg||
               !keys(node.intent,"plugin flow device options label variant"))goto done;
            c->wg_inbound_validate=calloc(1,sizeof(*c->wg_inbound_validate));
            if(!c->wg_inbound_validate||!steer_draft_wg_v3_configure(plan,i,&c->wg_inbound_validate->cfg))goto done;
            struct steer_linked_wg_config *w=c->wg_inbound_validate;
            if(w->cfg.kernel.peer_n!=1||w->cfg.kernel.aips_n!=1||
               w->cfg.kernel.aips[0].family!=AF_INET||w->cfg.kernel.aips[0].cidr!=32||
               w->cfg.kernel.addr_n!=1||w->cfg.kernel.addr[0].family!=AF_INET||
               w->cfg.kernel.addr[0].cidr!=24||!w->cfg.kernel.addr[0].addr[0]||
               w->cfg.kernel.addr[0].addr[0]==127||w->cfg.kernel.addr[0].addr[0]>=224||
               !w->cfg.kernel.addr[0].addr[3]||
               w->cfg.kernel.addr[0].addr[3]==255||
               memcmp(w->cfg.kernel.addr[0].addr,w->cfg.kernel.aips[0].addr,3)||
               !w->cfg.kernel.aips[0].addr[3]||w->cfg.kernel.aips[0].addr[3]==255||
               w->cfg.kernel.aips[0].addr[3]==w->cfg.kernel.addr[0].addr[3]||
               !secrets||secrets->len!=(size_t)(*w->cfg.preshared_keys[0]?2:1))goto done;
            const struct ynode *name=ynode_get(ynode_get(secrets,w->cfg.private_key),"name");
            if(!scalar(name)||name->len>=sizeof(w->private_env))goto done;
            strcpy(w->private_env,name->str);
            if(*w->cfg.preshared_keys[0]){
                name=ynode_get(ynode_get(secrets,w->cfg.preshared_keys[0]),"name");
                if(!scalar(name)||name->len>=sizeof(w->psk_env))goto done;
                strcpy(w->psk_env,name->str);
            }
            continue;
        }
#endif
        if(node.kind!=STEER_SPEC_INBOUND||c->listener_count>=STEER_PROTOTYPE_MAX_LISTENERS||
            !v3_inbound(&node,secrets,allow,&c->listeners[c->listener_count])||
            !distinct_listener(c,c->listener_count))goto done;
        c->listener_count++;
    }
    const struct ynode *target=ynode_get(routing,"default");
    if(!scalar(target)||!v3_named_action(c,outbounds,target->str,&fallback))goto done;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(device_output&&!c->wg_inbound_validate)goto done;
    if(c->wg_inbound_validate&&(c->wg||inbounds->len!=2||outbounds->len!=1||c->listener_count!=1||
       c->listeners[0].protocol!=STEER_PROTOTYPE_SOCKS||!c->listeners[0].enabled||
       c->stream_outbound_count||rules->len||fallback!=STEER_POLICY_DIRECT))goto done;
#endif
    /* The v3 graph has already required that default and named targets
     * support every selected ingress class, including HY2's datagrams. */
    for(uint32_t i=0;i<rules->len;i++){
        struct steer_spec_rule_view r;
        if(!steer_spec_rule(plan,i,&r)||!v3_rule(&r,ynode_at(rules,i),c,outbounds,&all[i]))goto done;
        if(r.enabled)active[enabled++]=all[i];
    }
    result=compile_policy(c,all,(uint32_t)rules->len,active,enabled,fallback);
    done:steer_spec_destroy(plan);
    return result;
}

struct steer_pv1_error steer_prototype_config_parse_with_vpn(const char*data,size_t length,uint64_t generation,
    const struct steer_prototype_socks_vpn_allowlist *allow,struct steer_prototype_config**out){
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
        e=parse_v3(data,length,root,allow,c);
        if(e.code)goto done;
        goto serialize;
    }
    if((allow&&allow->count)||!keys(root,"prototype listeners routing")||
        !eq(ynode_get(root,"prototype"),"steer-linux-v1"))goto done;
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
struct steer_pv1_error steer_prototype_config_parse(const char*data,size_t length,uint64_t generation,struct steer_prototype_config**out){
    return steer_prototype_config_parse_with_vpn(data,length,generation,NULL,out);
}
