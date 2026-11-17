#include "flow_metadata.h"
#include <string.h>
static struct steer_pv1_error error(uint32_t code) {struct steer_pv1_error e={code,0};return e;}
static int identifier(struct steer_pv1_span s,int empty) {
    if(!s.len)return empty;
    if(!s.data||s.len>64)return 0;
    for(uint32_t i=0;i<s.len;i++){
        unsigned c=s.data[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return 0;
    }
    return 1;
}
static int dns_name(struct steer_pv1_span s) {
    if(!s.data||!s.len||s.len>254)return 0;
    uint32_t length=s.len,label=0;
    if(s.data[length-1]=='.')length--;
    if(!length||length>253)return 0;
    for(uint32_t i=0;i<length;i++){
        unsigned c=s.data[i];
        if(c=='.'){if(!label||s.data[i-1]=='-')return 0;label=0;}
        else {
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')||
               (!label&&c=='-')||++label>63)return 0;
        }
    }
    return label&&s.data[length-1]!='-';
}
static int endpoint(const struct steer_pv1_endpoint *e,int domain) {
    if(e->size<sizeof(*e)||e->version!=STEER_PV1_DRAFT_LAYOUT||e->reserved||!e->port||!e->address.data)return 0;
    if(e->tag==STEER_PV1_ENDPOINT_IPV4)return e->address.len==4;
    if(e->tag==STEER_PV1_ENDPOINT_IPV6)return e->address.len==16;
    return domain&&e->tag==STEER_PV1_ENDPOINT_DOMAIN&&dns_name(e->address);
}
struct steer_pv1_error steer_draft_flow_validate(const struct steer_pv1_flow_metadata *f,uint32_t expected) {
    if(!f||f->size<sizeof(*f))return error(STEER_PV1_INVALID);
    if(f->version!=STEER_PV1_DRAFT_LAYOUT)return error(STEER_PV1_UNSUPPORTED);
    if(expected!=STEER_PV1_FLOW_STREAM&&expected!=STEER_PV1_FLOW_DATAGRAM)return error(STEER_PV1_UNSUPPORTED);
    if(f->flow_class!=expected)return error(STEER_PV1_UNSUPPORTED);
    /* No negotiated principal retention/auth service exists in this host yet. */
    if(f->principal)return error(STEER_PV1_UNSUPPORTED);
    if(!f->generation||!identifier(f->inbound_id,0)||!identifier(f->principal_id,1)||
       !endpoint(&f->source,0)||!endpoint(&f->destination,1))return error(STEER_PV1_INVALID);
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_flow_copy(struct steer_draft_flow_owned *out,
    const struct steer_pv1_flow_metadata *f,uint32_t expected) {
    if(!out)return error(STEER_PV1_INVALID);
    struct steer_pv1_error e=steer_draft_flow_validate(f,expected);
    if(e.code)return e;
    struct steer_pv1_flow_metadata copy=*f;
    memmove(out->inbound,f->inbound_id.data,f->inbound_id.len);
    if(f->principal_id.len)memmove(out->principal,f->principal_id.data,f->principal_id.len);
    memmove(out->source,f->source.address.data,f->source.address.len);
    memmove(out->destination,f->destination.address.data,f->destination.address.len);
    out->value=copy;
    out->value.size=sizeof(out->value);
    out->value.inbound_id.data=out->inbound;
    out->value.principal_id.data=copy.principal_id.len?out->principal:NULL;
    out->value.source.address.data=out->source;
    out->value.source.size=sizeof(out->value.source);
    out->value.destination.address.data=out->destination;
    out->value.destination.size=sizeof(out->value.destination);
    return error(STEER_PV1_OK);
}
