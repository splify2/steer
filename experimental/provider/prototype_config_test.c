#include "prototype_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char good[]="prototype: steer-linux-v1\nlisteners:\n- id: socks\n  label: 'Локальный SOCKS'\n  protocol: socks\n  enabled: true\n  listen: {address: 127.0.0.1, port: 1080}\n  auth: {type: none}\n- id: vl\n  enabled: false\n  protocol: vless\n  listen: {address: '::1', port: 1081}\n  auth: {type: uuid, principal_id: alice, uuid_ref: 'env:STEER_UUID'}\nrouting:\n  default: block\n  rules:\n  - {id: off, inbound: socks, enabled: false, action: block}\n  - {id: local, inbound: socks, cidr: 127.0.0.0/8, ports: [1,65535], action: direct}\n";
static void bad(const char *s){
    struct steer_prototype_config*c=(void*)1;
    assert(steer_prototype_config_parse(s,strlen(s),1,&c).code);
    assert(!c);
}
static void replace_bad(const char *from,const char *to){
    char changed[4096];
    const char*p=strstr(good,from);
    assert(p);
    snprintf(changed,sizeof(changed),"%.*s%s%s",(int)(p-good),good,to,p+strlen(from));
    bad(changed);
}
static void valid_address(const char *address){
    char changed[4096], replacement[128];
    const char *from="address: 127.0.0.1", *p=strstr(good,from);
    struct steer_prototype_config *c=NULL;
    snprintf(replacement,sizeof(replacement),"address: '%s'",address);
    snprintf(changed,sizeof(changed),"%.*s%s%s",(int)(p-good),good,replacement,p+strlen(from));
    assert(!steer_prototype_config_parse(changed,strlen(changed),1,&c).code);
    assert(!strcmp(c->listeners[0].address,address));
    steer_prototype_config_destroy(c);
}
int main(void){
    struct steer_prototype_config*c=NULL,*round=NULL;
    uint8_t ip[4]={
        127,0,0,1
    }
    ;
    struct steer_pv1_endpoint endpoint={
        sizeof(endpoint),1,1,{
            ip,4
        }
        ,80,0
    }
    ;
    struct steer_policy_input in={
        9,{
            (const uint8_t*)"socks",5
        }
        ,{
            NULL,0
        }
        ,&endpoint
    }
    ;
    struct steer_policy_decision out;
    assert(!steer_prototype_config_parse(good,strlen(good),9,&c).code);
    assert(c&&c->listener_count==2&&c->listeners[0].enabled&&!c->listeners[1].enabled);
    assert(!strcmp(c->listeners[1].uuid_ref,"env:STEER_UUID"));
    assert(c->document_length==strlen(c->document_json));
    assert(strstr(c->document_json,"\"enabled\":false"));
    assert(!steer_prototype_config_parse(c->document_json,c->document_length,9,&round).code);
    assert(!steer_policy_evaluate(c->policy,&in,&out).code&&out.action==STEER_POLICY_DIRECT);
    steer_prototype_config_destroy(round);
    steer_prototype_config_destroy(c);
    assert(!steer_prototype_config_parse("{\"prototype\":\"steer-linux-v1\",\"listeners\":[],\"routing\":{\"default\":\"block\",\"rules\":[]}}",strlen("{\"prototype\":\"steer-linux-v1\",\"listeners\":[],\"routing\":{\"default\":\"block\",\"rules\":[]}}"),1,&c).code);
    steer_prototype_config_destroy(c);
    replace_bad("id: socks","id: true");
    replace_bad("id: socks","id: 123");
    replace_bad("id: socks","id: 1.5");
    replace_bad("id: socks","id: null");
    replace_bad("id: socks","id: !!str socks");
    replace_bad("enabled: true","enabled: 'true'");
    replace_bad("port: 1080","port: '1080'");
    valid_address("0.0.0.0");
    valid_address("192.0.2.1");
    valid_address("::");
    valid_address("2001:db8::1");
    replace_bad("address: 127.0.0.1","address: 224.0.0.1");
    replace_bad("address: 127.0.0.1","address: 255.255.255.255");
    replace_bad("address: 127.0.0.1","address: 0.1.2.3");
    replace_bad("address: '::1'","address: 'ff02::1'");
    replace_bad("address: '::1'","address: '::ffff:127.0.0.1'");
    replace_bad("address: 127.0.0.1","address: localhost");
    replace_bad("cidr: 127.0.0.0/8","cidr: 127.0.0.1/8");
    replace_bad("inbound: socks","inbound: missing");
    replace_bad("uuid_ref: 'env:STEER_UUID'","uuid_ref: 'literal-secret'");
    replace_bad("principal_id: alice","principal_id: alice, password: secret");
    replace_bad("id: vl","id: socks");
    replace_bad("enabled: false","enabled: false, extra: 1");
    replace_bad("id: off","id: local");
    replace_bad("prototype: steer-linux-v1","prototype: steer-linux-v1\nversion: 3");
    bad("version: 3\nlisteners: []\n");
    bad("prototype: steer-linux-v1\nprototype: steer-linux-v1\n");
    bad("prototype: &a steer-linux-v1\n");
    bad("prototype: 'steer-linux-v1'\nlisteners: [*a]\n");
    bad("prototype: \"steer-linux-v1\\u0000\"\n");
    puts("prototype config tests passed");
    return 0;
}
