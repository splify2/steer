#include "policy.h"
#include <stdlib.h>
#include <string.h>

struct rule {
    char id[65], inbound[65], principal[65], domain[254];
    uint32_t domain_length, suffix, tag, bits, action;
    uint8_t network[16];
    uint16_t first, last;
};
struct steer_policy {
    uint64_t generation;
    uint32_t count, fallback;
    struct rule rules[];
};
static struct steer_pv1_error error(uint32_t code) {
    struct steer_pv1_error e = {code, 0}; return e;
}
static int action_ok(uint32_t action) {
    return action == STEER_POLICY_DIRECT || action == STEER_POLICY_BLOCK;
}
static int identifier(struct steer_pv1_span s, int empty) {
    uint32_t i;
    if (!s.len) return empty;
    if (!s.data || s.len > 64) return 0;
    for (i=0; i<s.len; i++) {
        unsigned c=s.data[i];
        if (!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
              (c>='0' && c<='9') || c=='_' || c=='-' || c=='.')) return 0;
    }
    return 1;
}
static unsigned lower(unsigned c) {
    return c>='A' && c<='Z' ? c+('a'-'A') : c;
}
/* One terminal dot is accepted and removed for DNS equivalence. */
static int domain_length(struct steer_pv1_span s, uint32_t *length) {
    uint32_t i,n=s.len,label=0;
    if (!s.data || !n || n>254) return 0;
    if (s.data[n-1]=='.') n--;
    if (!n || n>253) return 0;
    for (i=0;i<n;i++) {
        unsigned c=lower(s.data[i]);
        if (c=='.') {
            if (!label || s.data[i-1]=='-') return 0;
            label=0;
        } else {
            if (!((c>='a' && c<='z') || (c>='0' && c<='9') || c=='-')) return 0;
            if ((!label && c=='-') || ++label>63) return 0;
        }
    }
    if (!label || s.data[n-1]=='-') return 0;
    *length=n; return 1;
}
static int prefix_equal(const uint8_t *a,const uint8_t *b,uint32_t bits) {
    uint32_t whole=bits/8, part=bits%8;
    return (!whole || !memcmp(a,b,whole)) &&
        (!part || !((a[whole]^b[whole]) & (0xffu << (8-part))));
}
struct steer_pv1_error steer_policy_compile(uint64_t generation,
    const struct steer_policy_rule *rules,uint32_t count,uint32_t fallback,
    struct steer_policy **out) {
    struct steer_policy *p;
    uint32_t i,j;
    if (out) *out=NULL;
    if (!out || !generation || count>STEER_POLICY_MAX_RULES ||
        (count && !rules) || !action_ok(fallback)) return error(STEER_PV1_INVALID);
    p=calloc(1,sizeof(*p)+(size_t)count*sizeof(struct rule));
    if (!p) return error(STEER_PV1_RESOURCE_EXHAUSTED);
    p->generation=generation; p->count=count; p->fallback=fallback;
    for(i=0;i<count;i++) {
        const struct steer_policy_rule *s=&rules[i];
        struct rule *r=&p->rules[i];
        uint32_t bytes=0,n=0;
        int any=s->inbound.len || s->principal.len || s->domain.len ||
                s->cidr_tag || s->port_first || s->port_last;
        if (!identifier(s->id,0) || !identifier(s->inbound,1) ||
            !identifier(s->principal,1) || !action_ok(s->action) ||
            s->match_all>1 || s->domain_suffix>1 ||
            (any ? s->match_all!=0 : s->match_all!=1) ||
            ((!s->port_first)!=(!s->port_last)) || s->port_first>s->port_last ||
            (s->domain.len && s->cidr_tag) || (!s->domain.len && s->domain_suffix)) goto invalid;
        if(s->domain.len && !domain_length(s->domain,&n)) goto invalid;
        if(s->cidr_tag==STEER_PV1_ENDPOINT_IPV4) bytes=4;
        else if(s->cidr_tag==STEER_PV1_ENDPOINT_IPV6) bytes=16;
        else if(s->cidr_tag) goto invalid;
        if(s->prefix_bits>bytes*8) goto invalid;
        /* Reject noncanonical networks and hidden data beyond the family. */
        for(j=s->prefix_bits;j<128;j++)
            if(s->network[j/8] & (0x80u>>(j%8))) goto invalid;
        memcpy(r->id,s->id.data,s->id.len);
        for(j=0;j<i;j++) if(!strcmp(r->id,p->rules[j].id)) goto invalid;
        if(s->inbound.len) memcpy(r->inbound,s->inbound.data,s->inbound.len);
        if(s->principal.len) memcpy(r->principal,s->principal.data,s->principal.len);
        for(j=0;j<n;j++) r->domain[j]=(char)lower(s->domain.data[j]);
        r->domain_length=n; r->suffix=s->domain_suffix;
        r->tag=s->cidr_tag; r->bits=s->prefix_bits;
        memcpy(r->network,s->network,16);
        r->first=s->port_first; r->last=s->port_last; r->action=s->action;
    }
    *out=p; return error(STEER_PV1_OK);
invalid:
    free(p); return error(STEER_PV1_INVALID);
}
void steer_policy_destroy(struct steer_policy *p) { free(p); }
static int id_matches(const char *id,struct steer_pv1_span value) {
    size_t n=strlen(id);
    return !n || (n==value.len && !memcmp(id,value.data,n));
}
static struct steer_pv1_error evaluate(const struct steer_policy *p,
    const struct steer_policy_input *f,struct steer_policy_decision *out,
    int packet,uint32_t ip_protocol) {
    const struct steer_pv1_endpoint *e;
    uint32_t i,n=0;
    if(out) { out->action=STEER_POLICY_BLOCK; out->rule_index=UINT32_MAX; }
    if(!p || !f || !out || !identifier(f->inbound,0) || !identifier(f->principal,1))
        return error(STEER_PV1_INVALID);
    if(f->generation!=p->generation) return error(STEER_PV1_POLICY_DENIED);
    e=f->destination;
    if(!e || e->size<sizeof(*e) || e->version!=STEER_PV1_DRAFT_LAYOUT ||
        e->reserved || (!packet&&!e->port) || !e->address.data) return error(STEER_PV1_INVALID);
    if(e->tag==STEER_PV1_ENDPOINT_IPV4) { if(e->address.len!=4) return error(STEER_PV1_INVALID); }
    else if(e->tag==STEER_PV1_ENDPOINT_IPV6) { if(e->address.len!=16) return error(STEER_PV1_INVALID); }
    else if(e->tag==STEER_PV1_ENDPOINT_DOMAIN) {
        if(packet) return error(STEER_PV1_UNSUPPORTED);
        if(!domain_length(e->address,&n)) return error(STEER_PV1_INVALID);
    } else return error(STEER_PV1_UNSUPPORTED);
    for(i=0;i<p->count;i++) {
        const struct rule *r=&p->rules[i];
        uint32_t j,offset;
        if(!id_matches(r->inbound,f->inbound) || !id_matches(r->principal,f->principal)) continue;
        if(r->first && ((packet&&ip_protocol!=6&&ip_protocol!=17)||e->port<r->first||e->port>r->last)) continue;
        if(r->tag && (e->tag!=r->tag || !prefix_equal(r->network,e->address.data,r->bits))) continue;
        if(r->domain_length) {
            if(e->tag!=STEER_PV1_ENDPOINT_DOMAIN || n<r->domain_length) continue;
            offset=n-r->domain_length;
            if(offset && (!r->suffix || e->address.data[offset-1]!='.')) continue;
            for(j=0;j<r->domain_length;j++)
                if(lower(e->address.data[offset+j])!=(unsigned char)r->domain[j]) break;
            if(j!=r->domain_length) continue;
        }
        out->action=r->action; out->rule_index=i; return error(STEER_PV1_OK);
    }
    out->action=p->fallback; return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_policy_evaluate(const struct steer_policy *p,
    const struct steer_policy_input *f,struct steer_policy_decision *out) {
    return evaluate(p,f,out,0,0);
}
struct steer_pv1_error steer_policy_packet_evaluate(const struct steer_policy *p,
    const struct steer_policy_packet_input *packet,struct steer_policy_decision *out) {
    struct steer_policy_input f;
    if(!packet||packet->ip_protocol>255) {
        if(out) { out->action=STEER_POLICY_BLOCK;out->rule_index=UINT32_MAX; }
        return error(STEER_PV1_INVALID);
    }
    f.generation=packet->generation;f.inbound=packet->inbound;
    f.principal=packet->principal;f.destination=packet->destination;
    return evaluate(p,&f,out,1,packet->ip_protocol);
}
struct steer_pv1_error steer_policy_visit(const struct steer_policy *p,uint64_t generation,
    steer_policy_rule_visitor visitor,void *context,uint32_t *fallback) {
    uint32_t i;
    if(fallback) *fallback=STEER_POLICY_BLOCK;
    if(!p||!visitor||!fallback) return error(STEER_PV1_INVALID);
    if(generation!=p->generation) return error(STEER_PV1_POLICY_DENIED);
    for(i=0;i<p->count;i++) {
        const struct rule *r=&p->rules[i];
        struct steer_policy_rule view={0};
        struct steer_pv1_error e;
        view.id.data=(const uint8_t *)r->id;view.id.len=(uint32_t)strlen(r->id);
        view.inbound.data=(const uint8_t *)r->inbound;view.inbound.len=(uint32_t)strlen(r->inbound);
        view.principal.data=(const uint8_t *)r->principal;view.principal.len=(uint32_t)strlen(r->principal);
        view.domain.data=(const uint8_t *)r->domain;view.domain.len=r->domain_length;
        view.domain_suffix=r->suffix;view.cidr_tag=r->tag;view.prefix_bits=r->bits;
        memcpy(view.network,r->network,sizeof(view.network));
        view.port_first=r->first;view.port_last=r->last;view.action=r->action;
        view.match_all=!view.inbound.len&&!view.principal.len&&!view.domain.len&&!view.cidr_tag&&!view.port_first;
        e=visitor(context,&view);if(e.code) return e;
    }
    *fallback=p->fallback;return error(STEER_PV1_OK);
}
