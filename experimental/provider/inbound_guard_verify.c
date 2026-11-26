#define _GNU_SOURCE
#include "inbound_guard_verify.h"
#include "ynode.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

/* ynode supports YAML too. Restrict the input to JSON before using its bounded,
 * duplicate-key rejecting tree parser, retaining plain-vs-quoted types. */
struct json_cursor {const unsigned char *p,*end;};
static void ws(struct json_cursor *c){while(c->p<c->end&&(*c->p==' '||*c->p=='\n'||*c->p=='\r'||*c->p=='\t'))c->p++;}
static int string_token(struct json_cursor *c){
    if(c->p==c->end||*c->p++!='"')return 0;
    while(c->p<c->end){
        unsigned ch=*c->p++;
        if(ch=='"')return 1;
        if(ch<32)return 0;
        if(ch=='\\'){
            if(c->p==c->end)return 0;
            ch=*c->p++;
            if(ch=='u'){
                for(int i=0;i<4;i++){
                    if(c->p==c->end)return 0;
                    ch=*c->p++;
                    if(!((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f')||(ch>='A'&&ch<='F')))return 0;
                }
            }else if(!ch||!strchr("\"\\/bfnrt",(int)ch))return 0;
        }
    }
    return 0;
}
static int value_token(struct json_cursor *c,unsigned depth){
    if(depth>64)return 0;
    ws(c);if(c->p==c->end)return 0;
    if(*c->p=='"')return string_token(c);
    if(*c->p=='{'||*c->p=='['){
        int object=*c->p++=='{';unsigned char close=(unsigned char)(object?'}':']');
        ws(c);if(c->p<c->end&&*c->p==close){c->p++;return 1;}
        for(;;){
            if(object){if(!string_token(c))return 0;ws(c);if(c->p==c->end||*c->p++!=':')return 0;}
            if(!value_token(c,depth+1))return 0;
            ws(c);if(c->p==c->end)return 0;
            if(*c->p==close){c->p++;return 1;}
            if(*c->p++!=',')return 0;
            ws(c);
        }
    }
    static const char *const literals[]={"true","false","null"};
    for(size_t i=0;i<3;i++){
        size_t n=strlen(literals[i]);
        if((size_t)(c->end-c->p)>=n&&!memcmp(c->p,literals[i],n)){c->p+=n;return 1;}
    }
    if(*c->p=='-')c->p++;
    if(c->p==c->end)return 0;
    if(*c->p=='0')c->p++;
    else if(*c->p>='1'&&*c->p<='9'){do{c->p++;}while(c->p<c->end&&*c->p>='0'&&*c->p<='9');}
    else return 0;
    if(c->p<c->end&&*c->p=='.'){
        c->p++;if(c->p==c->end||*c->p<'0'||*c->p>'9')return 0;
        do{c->p++;}while(c->p<c->end&&*c->p>='0'&&*c->p<='9');
    }
    if(c->p<c->end&&(*c->p=='e'||*c->p=='E')){
        c->p++;if(c->p<c->end&&(*c->p=='+'||*c->p=='-'))c->p++;
        if(c->p==c->end||*c->p<'0'||*c->p>'9')return 0;
        do{c->p++;}while(c->p<c->end&&*c->p>='0'&&*c->p<='9');
    }
    return 1;
}
static int json_only(const void *bytes,size_t length){
    struct json_cursor c={bytes,(const unsigned char *)bytes+length};
    if(!value_token(&c,0))return 0;
    ws(&c);return c.p==c.end;
}

static int digits(const struct ynode *n,int nonzero){
    if(!n||n->kind!=YN_SCALAR||n->style!=YS_PLAIN||n->tag||!n->len||n->len>20)return 0;
    uint64_t value=0;
    for(size_t i=0;i<n->len;i++){
        if(n->str[i]<'0'||n->str[i]>'9')return 0;
        unsigned digit=(unsigned)(n->str[i]-'0');
        if(value>(UINT64_MAX-digit)/10u)return 0;
        value=value*10u+digit;
    }
    return !nonzero||value!=0;
}
static int text(const struct ynode *n){return n&&n->kind==YN_SCALAR&&n->style==YS_DOUBLE&&!n->tag;}
static int prefix_hex(const char *s,const char *prefix,size_t count){
    if(!s||strncmp(s,prefix,strlen(prefix))||strlen(s)!=strlen(prefix)+count)return 0;
    s+=strlen(prefix);for(size_t i=0;i<count;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
static int safe_ifname(const char *s){
    if(!s||!*s)return 0;
    for(;*s;s++)if(!((*s>='a'&&*s<='z')||(*s>='A'&&*s<='Z')||(*s>='0'&&*s<='9')||*s=='_'||*s=='-'||*s=='.'))return 0;
    return 1;
}
/* Exact tree comparison, including scalar type and unknown keys. Only values
 * intentionally nonsemantic in nft listings are exempted, with strict types. */
static int equal(const struct ynode *actual,const struct ynode *expected,const char *key,const struct ynode *parent){
    if(!actual||!expected||actual->kind!=expected->kind||actual->tag||expected->tag)return 0;
    if(actual->kind==YN_SCALAR){
        if(parent&&key&&(!strcmp(key,"packets")||!strcmp(key,"bytes"))&&ynode_get(parent,"packets")&&ynode_get(parent,"bytes"))return digits(actual,0);
        if(parent&&key&&!strcmp(key,"handle")&&ynode_get(parent,"table"))return digits(actual,1);
        if(parent&&key&&(!strcmp(key,"version")||!strcmp(key,"release_name"))&&ynode_get(parent,"json_schema_version"))return text(actual);
        return actual->style==expected->style&&actual->len==expected->len&&!memcmp(actual->str,expected->str,actual->len);
    }
    if(actual->len!=expected->len)return 0;
    if(actual->kind==YN_SEQ){for(size_t i=0;i<actual->len;i++)if(!equal(ynode_at(actual,i),ynode_at(expected,i),NULL,NULL))return 0;return 1;}
    for(size_t i=0;i<expected->len;i++){
        const struct ynode *k=ynode_key_at(expected,i);const struct ynode *a=ynode_get(actual,k->str);
        if(!a||!equal(a,ynode_val_at(expected,i),k->str,actual))return 0;
    }
    return 1;
}
int steer_inbound_guard_verify(const void *bytes,size_t length,const struct steer_inbound_guard_plan *p){
    if(!bytes||!length||length>STEER_INBOUND_GUARD_SNAPSHOT_MAX||!p||!p->table_handle||!p->ifindex||
       !prefix_hex(p->table,"steer_wg_",16)||!prefix_hex(p->marker,"steer-wg:",32)||!p->peer_ipv4)return EINVAL;
    struct in_addr addr;char peer[INET_ADDRSTRLEN],name[IF_NAMESIZE];
    if(inet_pton(AF_INET,p->peer_ipv4,&addr)!=1||!inet_ntop(AF_INET,&addr,peer,sizeof(peer))||strcmp(peer,p->peer_ipv4)||
       !if_indextoname(p->ifindex,name)||!safe_ifname(name)||if_nametoindex(name)!=p->ifindex)return EINVAL;
    char expected[8192];
    int n=snprintf(expected,sizeof(expected),
      "{\"nftables\":[{\"metainfo\":{\"version\":\"x\",\"release_name\":\"x\",\"json_schema_version\":1}},"
      "{\"table\":{\"family\":\"inet\",\"name\":\"%s\",\"handle\":%" PRIu64 ",\"comment\":\"%s\"}},"
      "{\"chain\":{\"family\":\"inet\",\"table\":\"%s\",\"name\":\"peer_0\",\"handle\":1}},"
      "{\"chain\":{\"family\":\"inet\",\"table\":\"%s\",\"name\":\"ingress\",\"handle\":1,\"type\":\"filter\",\"hook\":\"prerouting\",\"prio\":-160,\"policy\":\"accept\"}},"
      "{\"rule\":{\"family\":\"inet\",\"table\":\"%s\",\"chain\":\"peer_0\",\"handle\":1,\"expr\":[{\"counter\":{\"packets\":0,\"bytes\":0}},{\"accept\":null}]}},"
      "{\"rule\":{\"family\":\"inet\",\"table\":\"%s\",\"chain\":\"ingress\",\"handle\":1,\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"iif\"}},\"right\":\"%s\"}},{\"match\":{\"op\":\"in\",\"left\":{\"ct\":{\"key\":\"state\"}},\"right\":1}},{\"drop\":null}]}},"
      "{\"rule\":{\"family\":\"inet\",\"table\":\"%s\",\"chain\":\"ingress\",\"handle\":1,\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"iif\"}},\"right\":\"%s\"}},{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"ip\",\"field\":\"saddr\"}},\"right\":\"%s\"}},{\"goto\":{\"target\":\"peer_0\"}}]}},"
      "{\"rule\":{\"family\":\"inet\",\"table\":\"%s\",\"chain\":\"ingress\",\"handle\":1,\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"iif\"}},\"right\":\"%s\"}},{\"counter\":{\"packets\":0,\"bytes\":0}},{\"drop\":null}]}}]}",
      p->table,p->table_handle,p->marker,p->table,p->table,p->table,p->table,name,p->table,name,peer,p->table,name);
    if(n<0||(size_t)n>=sizeof(expected))return EINVAL;
    if(!json_only(bytes,length))return ESTALE;
    struct err e={0};struct ydoc *want=ydoc_parse_buf(expected,(size_t)n,"guard-plan",&e);
    struct ydoc *got=ydoc_parse_buf(bytes,length,"guard-snapshot",&e);
    int ok=want&&got&&equal(ydoc_root(got),ydoc_root(want),NULL,NULL);
    ydoc_free(want);ydoc_free(got);
    return ok?0:ESTALE;
}
