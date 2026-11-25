#include "policy.h"
#include "policy_route.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct steer_pv1_span span(const char *s) {
    struct steer_pv1_span v={(const uint8_t *)s,(uint32_t)strlen(s)}; return v;
}
static struct steer_policy_decision evaluate(struct steer_policy *p,const char *name) {
    struct steer_pv1_endpoint e={sizeof(e),STEER_PV1_DRAFT_LAYOUT,
        STEER_PV1_ENDPOINT_DOMAIN,{NULL,0},443,0};
    struct steer_policy_input f={7,{NULL,0},{NULL,0},&e};
    struct steer_policy_decision d;
    e.address=span(name); f.inbound=span("public");
    assert(!steer_policy_evaluate(p,&f,&d).code); return d;
}
static struct steer_pv1_error packet_rule(void *context,const struct steer_policy_rule *rule) {
    unsigned *visited=context;
    assert(rule->action==STEER_POLICY_BLOCK);
    ++*visited;
    return (struct steer_pv1_error){0};
}
int main(void) {
    struct steer_draft_accepted accepted;
    uint32_t route_action;
    struct steer_policy_rule r[3];
    struct steer_policy *p=NULL;
    struct steer_policy_decision d;
    uint8_t ip[16]={10,24,7,1};
    struct steer_pv1_endpoint e={sizeof(e),STEER_PV1_DRAFT_LAYOUT,
        STEER_PV1_ENDPOINT_IPV4,{ip,4},443,0};
    struct steer_policy_input f={7,{NULL,0},{NULL,0},&e};
    memset(r,0,sizeof(r));
    r[0].id=span("exception"); r[0].domain=span("allowed.example.com");
    r[0].action=STEER_POLICY_DIRECT;
    r[1].id=span("deny-domain"); r[1].domain=span("EXAMPLE.com.");
    r[1].domain_suffix=1; r[1].action=STEER_POLICY_BLOCK;
    assert(!steer_policy_compile(7,r,2,STEER_POLICY_DIRECT,&p).code);
    assert(evaluate(p,"allowed.example.com").rule_index==0);
    assert(evaluate(p,"child.EXAMPLE.COM.").action==STEER_POLICY_BLOCK);
    assert(evaluate(p,"example.com").rule_index==1);
    assert(evaluate(p,"notexample.com").rule_index==UINT32_MAX);
    assert(evaluate(p,"example.com.evil").action==STEER_POLICY_DIRECT);
    /* Compile copies data, not borrowed caller rule records. */
    r[1].domain=span("changed.example");
    assert(evaluate(p,"example.com").action==STEER_POLICY_BLOCK);
    f.inbound=span("public");
    f.generation=8;
    assert(steer_policy_evaluate(p,&f,&d).code==STEER_PV1_POLICY_DENIED);
    assert(d.action==STEER_POLICY_BLOCK);
    f.generation=7; e.tag=STEER_PV1_ENDPOINT_DOMAIN;
    e.address=span("bad..example");
    assert(steer_policy_evaluate(p,&f,&d).code==STEER_PV1_INVALID);
    e.address.data=(const uint8_t *)"a\0evil"; e.address.len=6;
    assert(steer_policy_evaluate(p,&f,&d).code==STEER_PV1_INVALID);
    steer_policy_destroy(p);
    memset(r,0,sizeof(r));
    r[0].id=span("private"); r[0].inbound=span("public");
    r[0].principal=span("alice"); r[0].cidr_tag=STEER_PV1_ENDPOINT_IPV4;
    r[0].prefix_bits=13; r[0].network[0]=10; r[0].network[1]=24;
    r[0].port_first=443; r[0].port_last=444; r[0].action=STEER_POLICY_BLOCK;
    assert(!steer_policy_compile(7,r,1,STEER_POLICY_DIRECT,&p).code);
    e.tag=STEER_PV1_ENDPOINT_IPV4; e.address.data=ip; e.address.len=4;
    f.principal=span("alice");
    assert(!steer_policy_evaluate(p,&f,&d).code && d.rule_index==0);
    memset(&accepted,0,sizeof(accepted));
    accepted.generation=7; accepted.inbound_id=f.inbound;
    accepted.destination=e; accepted.flow_class=STEER_PV1_FLOW_STREAM;
    accepted.principal_id=f.principal;
    assert(!steer_policy_route(p,&accepted,&route_action).code);
    assert(route_action==STEER_DRAFT_ROUTE_BLOCK);
    accepted.principal_id=span("bob");
    assert(!steer_policy_route(p,&accepted,&route_action).code);
    assert(route_action==STEER_DRAFT_ROUTE_DIRECT);
    ip[1]=31; assert(!steer_policy_evaluate(p,&f,&d).code && d.rule_index==0);
    ip[1]=32; assert(!steer_policy_evaluate(p,&f,&d).code && d.rule_index==UINT32_MAX);
    ip[1]=24; f.principal=span("bob");
    assert(!steer_policy_evaluate(p,&f,&d).code && d.action==STEER_POLICY_DIRECT);
    f.principal=span("alice"); e.port=445;
    assert(!steer_policy_evaluate(p,&f,&d).code && d.action==STEER_POLICY_DIRECT);
    e.port=443; steer_policy_destroy(p);
    r[0].network[3]=1; /* noncanonical host bits */
    assert(steer_policy_compile(7,r,1,STEER_POLICY_DIRECT,&p).code && !p);
    r[0].network[3]=0; r[1]=r[0];
    assert(steer_policy_compile(7,r,2,STEER_POLICY_DIRECT,&p).code && !p);
    memset(r,0,sizeof(r)); r[0].id=span("all"); r[0].action=STEER_POLICY_BLOCK;
    assert(steer_policy_compile(7,r,1,STEER_POLICY_DIRECT,&p).code && !p);
    r[0].match_all=1;
    assert(!steer_policy_compile(7,r,1,STEER_POLICY_DIRECT,&p).code);
    assert(evaluate(p,"any.example").action==STEER_POLICY_BLOCK);
    memset(&accepted,0,sizeof(accepted));
    accepted.generation=7; accepted.inbound_id=span("public");
    accepted.destination=e; accepted.flow_class=STEER_PV1_FLOW_STREAM;
    assert(!steer_policy_route(p,&accepted,&route_action).code);
    assert(route_action==STEER_DRAFT_ROUTE_BLOCK);
    accepted.generation=8;
    assert(steer_policy_route(p,&accepted,&route_action).code==STEER_PV1_POLICY_DENIED);
    accepted.generation=7; accepted.flow_class=STEER_PV1_FLOW_DATAGRAM;
    assert(steer_policy_route(p,&accepted,&route_action).code==STEER_PV1_UNSUPPORTED);
    steer_policy_destroy(p);
    /* IPv6 /65 boundary, separate family semantics. */
    memset(r,0,sizeof(r)); r[0].id=span("v6"); r[0].cidr_tag=STEER_PV1_ENDPOINT_IPV6;
    r[0].prefix_bits=65; r[0].network[0]=0x20; r[0].network[1]=1;
    r[0].network[8]=0x80; r[0].action=STEER_POLICY_BLOCK;
    assert(!steer_policy_compile(7,r,1,STEER_POLICY_DIRECT,&p).code);
    memcpy(ip,r[0].network,16); ip[15]=42;
    e.tag=STEER_PV1_ENDPOINT_IPV6; e.address.len=16;
    assert(!steer_policy_evaluate(p,&f,&d).code && d.rule_index==0);
    ip[8]=0x7f;
    assert(!steer_policy_evaluate(p,&f,&d).code && d.rule_index==UINT32_MAX);
    steer_policy_destroy(p);
    assert(steer_policy_compile(0,NULL,0,STEER_POLICY_BLOCK,&p).code && !p);
    assert(steer_policy_compile(7,NULL,0,99,&p).code && !p);
    memset(r,0,sizeof(r)); r[0].id=span("proxy"); r[0].inbound=span("public");
    r[0].action=STEER_POLICY_STREAM_BINDING_BASE+1;
    assert(steer_policy_compile(7,r,1,STEER_POLICY_BLOCK,&p).code && !p);
    assert(steer_policy_compile_stream(7,r,1,STEER_POLICY_BLOCK,1,&p).code && !p);
    assert(!steer_policy_compile_stream(7,r,1,STEER_POLICY_STREAM_BINDING_BASE,2,&p).code);
    assert(evaluate(p,"any.example").action==STEER_POLICY_STREAM_BINDING_BASE+1);
    struct steer_policy_packet_input packet={7,span("public"),{0},&e,6};
    assert(!steer_policy_packet_evaluate(p,&packet,&d).code && d.action==STEER_POLICY_BLOCK && d.rule_index==0);
    packet.inbound=span("other");
    assert(!steer_policy_packet_evaluate(p,&packet,&d).code && d.action==STEER_POLICY_BLOCK && d.rule_index==UINT32_MAX);
    unsigned visited=0; uint32_t fallback;
    assert(!steer_policy_visit(p,7,packet_rule,&visited,&fallback).code && visited==1 && fallback==STEER_POLICY_BLOCK);
    steer_policy_destroy(p);
    puts("ordered policy tests passed"); return 0;
}
