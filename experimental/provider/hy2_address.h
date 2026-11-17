/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_DRAFT_HY2_ADDRESS_H
#define STEER_DRAFT_HY2_ADDRESS_H
#include <steer/draft/provider_v1.h>
#include <arpa/inet.h>
#include <string.h>
static inline int steer_draft_hy2_address(const uint8_t *data,size_t length,char host[2049],uint8_t ip[16],struct steer_pv1_endpoint *ep) {
    size_t begin=0,end=0,colon;unsigned port=0;
    if(!length||length>2048||memchr(data,0,length))return -1;
    if(data[0]=='[') {
        begin=1;for(end=1;end<length&&data[end]!=']';end++){}
        if(end==length||end+1>=length||data[end+1]!=':')return -1;
        colon=end+1;
    } else {
        for(colon=length;colon&&data[colon-1]!=':';colon--){}
        if(!colon)return -1;
        colon--;end=colon;
        if(memchr(data,':',end))return -1;
    }
    if(end<=begin||colon+1==length)return -1;
    for(size_t i=colon+1;i<length;i++) {
        if(data[i]<'0'||data[i]>'9'||port>6553)return -1;
        port=port*10u+data[i]-'0';if(port>65535)return -1;
    }
    if(!port)return -1;
    memcpy(host,data+begin,end-begin);host[end-begin]=0;
    *ep=(struct steer_pv1_endpoint){.size=sizeof *ep,.version=STEER_PV1_DRAFT_LAYOUT,.port=(uint16_t)port};
    if(inet_pton(AF_INET,host,ip)==1) { ep->tag=STEER_PV1_ENDPOINT_IPV4;ep->address=(struct steer_pv1_span){ip,4}; }
    else if(inet_pton(AF_INET6,host,ip)==1) { ep->tag=STEER_PV1_ENDPOINT_IPV6;ep->address=(struct steer_pv1_span){ip,16}; }
    else {
        if(begin)return -1;
        ep->tag=STEER_PV1_ENDPOINT_DOMAIN;ep->address=(struct steer_pv1_span){(const uint8_t *)host,(uint32_t)(end-begin)};
    }
    return 0;
}
#endif
