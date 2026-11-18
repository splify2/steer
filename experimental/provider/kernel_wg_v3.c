#include "kernel_wg_v3.h"
#include "../spec/spec.h"
#include "ynode.h"
#include <arpa/inet.h>
#include <string.h>

static const char *text(const struct ynode *node){
    return node&&node->kind==YN_SCALAR&&!node->tag?node->str:"";
}

static int map(const struct ynode *node,const char *const fields[],size_t count){
    if(!node||node->kind!=YN_MAP||node->tag||node->len>count)return 0;
    for(size_t i=0;i<node->len;i++){
        const char *key=text(ynode_key_at(node,i));
        size_t j=0;
        while(j<count&&strcmp(key,fields[j]))j++;
        if(j==count)return 0;
    }
    return 1;
}

static int identifier(const struct ynode *node){
    long number;int flag;
    const char *value=text(node);
    size_t len=strlen(value);
    if(!len||len>63||ynode_is_null(node)||!ynode_bool(node,&flag)||!ynode_long(node,&number))return 0;
    for(size_t i=0;i<len;i++){
        unsigned ch=(unsigned char)value[i];
        if(!((ch>='a'&&ch<='z')||(ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')||
             ch=='_'||(i&&(ch=='.'||ch=='-'))))return 0;
    }
    return 1;
}

static int integer(const struct ynode *node,long low,long high,long *value){
    return node&&!node->tag&&!ynode_long(node,value)&&*value>=low&&*value<=high;
}

static int bounded_list(const struct ynode *node,size_t max){
    return node&&node->kind==YN_SEQ&&!node->tag&&node->len&&node->len<=max;
}

static int key(const char *value,uint8_t out[AWG_KEY_LEN]){
    static const uint8_t zero[AWG_KEY_LEN]={0};
    return !awg_key_from_b64(out,value)&&memcmp(out,zero,sizeof(zero));
}

static int prefix(const struct ynode *node,struct awg_prefix *out){
    const char *value=text(node),*slash=strchr(value,'/');
    return slash&&strlen(slash+1)<=3&&!awg_prefix_parse(value,out);
}

static int overlap(const struct awg_prefix *a,const struct awg_prefix *b){
    if(a->family!=b->family)return 0;
    unsigned bits=a->cidr<b->cidr?a->cidr:b->cidr;
    if(memcmp(a->addr,b->addr,bits/8))return 0;
    return !(bits%8)||!((a->addr[bits/8]^b->addr[bits/8])&(0xffu<<(8-bits%8)));
}

static int secret(const struct ynode *node,char out[64]){
    const struct ynode *id=ynode_get(node,"secret");
    if(!id||node->tag||node->len!=1||!identifier(id))return 0;
    strcpy(out,id->str);
    return 1;
}

static int parse(const struct ynode *options,struct steer_draft_wg_v3_config *out){
    static const char *const fields[]={"private_key","listen_port","mtu","addresses","peers"};
    static const char *const peer_fields[]={"public_key","preshared_key","principal_id","allowed_ips"};
    struct awg_conf *kernel=&out->kernel;
    const struct ynode *addresses=ynode_get(options,"addresses"),*peers=ynode_get(options,"peers");
    const struct ynode *mtu=ynode_get(options,"mtu");
    long port,mtu_value=1420;
    memset(out,0,sizeof(*out));
    if(!map(options,fields,sizeof(fields)/sizeof(fields[0]))||
       !secret(ynode_get(options,"private_key"),out->private_key)||
       !integer(ynode_get(options,"listen_port"),1,65535,&port)||
       (mtu&&!integer(mtu,1280,9000,&mtu_value))||
       !bounded_list(addresses,STEER_DRAFT_WG_PREFIXES)||!bounded_list(peers,STEER_DRAFT_WG_PEERS))return 0;
    kernel->listen_port=(uint16_t)port;
    kernel->has_listen_port=1;
    kernel->mtu=(int)mtu_value;
    for(size_t i=0;i<addresses->len;i++){
        struct awg_prefix *addr=&kernel->addr[i];
        if(!prefix(ynode_at(addresses,i),addr))return 0;
        for(size_t j=0;j<i;j++)
            if(addr->family==kernel->addr[j].family&&!memcmp(addr->addr,kernel->addr[j].addr,sizeof(addr->addr)))return 0;
    }
    kernel->addr_n=addresses->len;
    for(size_t i=0;i<peers->len;i++){
        const struct ynode *peer=ynode_at(peers,i),*allowed=ynode_get(peer,"allowed_ips");
        const struct ynode *psk=ynode_get(peer,"preshared_key"),*principal=ynode_get(peer,"principal_id");
        struct awg_peer *wg=&kernel->peer[i];
        if(!map(peer,peer_fields,sizeof(peer_fields)/sizeof(peer_fields[0]))||!identifier(principal)||
           !key(text(ynode_get(peer,"public_key")),wg->pub)||!bounded_list(allowed,STEER_DRAFT_WG_PREFIXES)||
           (psk&&!secret(psk,out->preshared_keys[i])))return 0;
        for(size_t j=0;j<i;j++)if(!memcmp(wg->pub,kernel->peer[j].pub,sizeof(wg->pub)))return 0;
        strcpy(out->guard.peers[i].principal_id,principal->str);
        wg->has_psk=psk!=NULL;
        wg->aip_first=kernel->aips_n;
        for(size_t j=0;j<allowed->len;j++){
            const struct ynode *source=ynode_at(allowed,j);
            struct awg_prefix *aip=&kernel->aips[kernel->aips_n];
            if(!prefix(source,aip))return 0;
            unsigned width=aip->family==AF_INET?32u:128u;
            for(unsigned bit=aip->cidr;bit<width;bit++)
                if(aip->addr[bit/8]&(0x80u>>(bit%8)))return 0;
            for(size_t k=0;k<kernel->aips_n;k++)if(overlap(aip,&kernel->aips[k]))return 0;
            strcpy(out->guard.peers[i].allowed_ips[j],source->str);
            kernel->aips_n++;
        }
        wg->aip_n=allowed->len;
        out->guard.peers[i].allowed_count=(uint32_t)allowed->len;
    }
    kernel->peer_n=peers->len;
    out->guard.peer_count=(uint32_t)peers->len;
    return 1;
}

int steer_draft_wg_v3_options(void *unused,const struct ynode *options){
    (void)unused;
    struct steer_draft_wg_v3_config config;
    return parse(options,&config);
}

int steer_draft_wg_v3_configure(const struct steer_spec_plan *plan,uint32_t index,
    struct steer_draft_wg_v3_config *out){
    struct steer_spec_node_view node;
    if(!steer_spec_summary(plan).topology_valid||!steer_spec_node(plan,index,&node)||
       !node.enabled||node.kind!=STEER_SPEC_INBOUND||node.flows!=STEER_SPEC_FLOW_DEVICE||
       strncmp(node.provider,"wireguard:",10)||(node.variant&&strcmp(text(node.variant),"default"))||
       !parse(node.options,out))return 0;
    const struct ynode *secrets=ynode_get(steer_spec_intent(plan),"secrets");
    if(strcmp(text(ynode_get(ynode_get(secrets,out->private_key),"kind")),"wireguard_private_key"))return 0;
    for(size_t i=0;i<out->kernel.peer_n;i++)
        if(out->kernel.peer[i].has_psk&&strcmp(text(ynode_get(ynode_get(secrets,out->preshared_keys[i]),"kind")),
           "wireguard_preshared_key"))return 0;
    strcpy(out->guard.inbound_id,node.id);
    return 1;
}

static struct steer_pv1_error resolve_key(steer_draft_kernel_wg_secret resolve,void *context,
    const char *id,uint8_t out[AWG_KEY_LEN]){
    uint8_t encoded[45]={0};
    struct steer_pv1_span ref={(const uint8_t *)id,(uint32_t)strlen(id)};
    struct steer_pv1_error e=resolve(context,ref,encoded);
    if(!e.code&&!key((const char *)encoded,out))e.code=STEER_PV1_INVALID;
    volatile uint8_t *wipe=encoded;
    for(size_t i=0;i<sizeof(encoded);i++)wipe[i]=0;
    return e;
}

struct steer_pv1_error steer_draft_wg_v3_keys(const struct steer_draft_wg_v3_config *config,
    steer_draft_kernel_wg_secret resolve,void *context,struct awg_secrets *keys){
    awg_secrets_wipe(keys);
    struct steer_pv1_error e=resolve_key(resolve,context,config->private_key,keys->priv);
    for(size_t i=0;!e.code&&i<config->kernel.peer_n;i++)
        if(config->kernel.peer[i].has_psk)e=resolve_key(resolve,context,config->preshared_keys[i],keys->psk[i]);
    if(e.code)awg_secrets_wipe(keys);
    else keys->has_priv=1;
    return e;
}
