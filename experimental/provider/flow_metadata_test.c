#include "flow_metadata.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    uint8_t ip[4]={127,0,0,1},id[]="inbound",principal[]="verified",domain[]="Example.TEST.";
    struct steer_pv1_endpoint ep={sizeof(ep),STEER_PV1_DRAFT_LAYOUT,STEER_PV1_ENDPOINT_IPV4,{ip,4},53,0};
    struct steer_pv1_flow_metadata flow={.size=sizeof(flow),.version=STEER_PV1_DRAFT_LAYOUT,.generation=7,
        .inbound_id={id,7},.principal_id={principal,8},.source=ep,.destination=ep,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    flow.destination.tag=STEER_PV1_ENDPOINT_DOMAIN;flow.destination.address=(struct steer_pv1_span){domain,sizeof(domain)-1};
    struct steer_draft_flow_owned copy;assert(!steer_draft_flow_copy(&copy,&flow,STEER_PV1_FLOW_DATAGRAM).code);
    memset(ip,0,sizeof(ip));memset(id,'x',7);memset(principal,'y',8);memset(domain,'z',sizeof(domain)-1);
    assert(!memcmp(copy.value.inbound_id.data,"inbound",7)&&!memcmp(copy.value.principal_id.data,"verified",8));
    assert(!memcmp(copy.value.destination.address.data,"Example.TEST.",13)&&copy.source[0]==127);
    assert(steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code==STEER_PV1_UNSUPPORTED);
    copy.value.flow_class=STEER_PV1_FLOW_STREAM;assert(!steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code);
    copy.value.source.port=0;assert(steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code==STEER_PV1_INVALID);
    copy.value.source.port=53;copy.value.principal=(void *)&flow;
    assert(steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code==STEER_PV1_UNSUPPORTED);
    copy.value.principal=NULL;copy.value.generation=0;
    assert(steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code==STEER_PV1_INVALID);
    copy.value.generation=7;copy.destination[0]='-';assert(steer_draft_flow_validate(&copy.value,STEER_PV1_FLOW_STREAM).code==STEER_PV1_INVALID);
    puts("flow metadata: owned copy, both classes, identity/domain/port bounds PASS");return 0;
}
