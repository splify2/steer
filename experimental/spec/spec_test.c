#include "spec.h"
#include "ynode.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct steer_spec_plan *compile(const char *settings,const char *rule) {
    char source[8192];
    int n=snprintf(source,sizeof(source),
        "{\"version\":3,\"plugin_remotes\":{},\"plugins\":{},\"inbounds\":{},"
        "\"outbounds\":{\"direct\":{\"type\":\"direct\"}},"
        "\"routing\":{\"rules\":[],\"default\":\"direct\"},"
        "\"dns\":{\"servers\":{\"local\":{\"type\":\"local\"}},\"default\":\"local\",%s"
        "\"rules\":[%s]}}",settings,rule);
    assert(n>0&&(size_t)n<sizeof(source));
    struct steer_spec_plan *p=steer_spec_compile(source,(size_t)n,NULL,0);assert(p);return p;
}
static void syntax(const char *settings,const char *rule,int valid) {
    struct steer_spec_plan *p=compile(settings,rule);
    struct steer_spec_summary s=steer_spec_summary(p);
    assert(s.syntax_valid==valid);assert(!s.runtime_ready);
    if(valid)assert(s.topology_valid);
    steer_spec_destroy(p);
}
static void types(void) {
    const char *bad[]={"\"strategy\":{\"invalid\":\"type\"},","\"reverse_mapping\":{},",
        "\"cache\":{\"invalid\":\"type\"},","\"cache\":{\"capacity\":1024,\"persistent\":{}},",
        "\"cache\":{\"capacity\":-1},","\"cache\":131073,","\"cache\":\"1024\",",
        "\"strategy\":\"random\",","\"reverse_mapping\":\"true\","};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++)syntax(bad[i],"",0);
    syntax("\"strategy\":\"prefer_ipv6\",\"reverse_mapping\":true,\"cache\":131072,","",1);
    syntax("\"cache\":{\"capacity\":1024,\"persistent\":true},","",1);
    const char *values[]={"{}","12","\"-1s\"","\"169h\"","\"604800001ms\"","\"999999999999999999999s\"","\"1.5s\""};
    char rule[512];
    for(size_t i=0;i<sizeof(values)/sizeof(values[0]);i++){
        snprintf(rule,sizeof(rule),"{\"name\":\"r\",\"match\":{},\"server\":\"local\",\"cache_timeout\":%s}",values[i]);
        syntax("",rule,0);
    }
    const char *good[]={"0s","168h","10080m","604800s","604800000ms"};
    for(size_t i=0;i<sizeof(good)/sizeof(good[0]);i++){
        snprintf(rule,sizeof(rule),"{\"name\":\"r\",\"enabled\":false,\"match\":{},\"server\":\"local\",\"strategy\":\"ipv4_only\",\"cache_timeout\":\"%s\"}",good[i]);
        struct steer_spec_plan *p=compile("",rule);assert(steer_spec_summary(p).syntax_valid);
        struct steer_spec_rule_view view;assert(steer_spec_rule(p,0,&view));
        assert(!view.enabled&&view.dns_rule&&!strcmp(view.cache_timeout->str,good[i]));
        assert(!strcmp(view.strategy->str,"ipv4_only"));steer_spec_destroy(p);
    }
    syntax("","{\"name\":\"r\",\"action\":\"reject\",\"match\":{},\"strategy\":\"ipv4_only\"}",0);
}
static void readiness(void) {
    struct steer_spec_plan *p=compile("\"cache\":{\"capacity\":1024,\"persistent\":true},","");
    struct steer_spec_summary s=steer_spec_summary(p);assert(s.requirements<32);
    struct steer_spec_capability caps[32]={0};size_t persistent=32,length;
    for(uint32_t i=0;i<s.requirements;i++){
        struct steer_spec_requirement_view v;assert(steer_spec_requirement(p,i,&v));
        caps[i].name=v.name;caps[i].state=STEER_SPEC_READY;
        if(!strcmp(v.name,"core.dns.cache.persistent"))persistent=i;
    }
    assert(persistent<32);const char *source=steer_spec_document(p,&length);
    caps[persistent].state=STEER_SPEC_BUILT|STEER_SPEC_SUPPORTED;
    struct steer_spec_plan *q=steer_spec_compile(source,length,caps,s.requirements);assert(q);
    assert(!steer_spec_summary(q).runtime_ready);steer_spec_destroy(q);
    caps[persistent].state=STEER_SPEC_READY;
    q=steer_spec_compile(source,length,caps,s.requirements);assert(q);
    assert(steer_spec_summary(q).runtime_ready);steer_spec_destroy(q);steer_spec_destroy(p);
}
static void views(void) {
    char source[]="{\"version\":3,\"plugin_remotes\":{\"official\":{\"url\":\"https://example.invalid\",\"trust\":\"root\"}},"
        "\"plugins\":{\"protocols\":{\"remote\":\"official\",\"package\":\"protocols\",\"version\":\"^1.0.0\"}},"
        "\"secrets\":{\"key_ref\":{\"source\":\"env\",\"name\":\"EXAMPLE_SECRET\"}},"
        "\"inbounds\":{\"off\":{\"enabled\":false,\"plugin\":\"vless:protocols\",\"listen\":{\"address\":\"127.0.0.1\",\"port\":1234},"
        "\"transport\":{\"type\":\"ws\",\"path\":\"/private-path\"},\"security\":{\"type\":\"tls\",\"server_name\":\"example.invalid\"},"
        "\"variant\":\"plain\",\"options\":{\"private_value\":\"never-diagnostic\",\"token\":{\"secret\":\"key_ref\"},\"other\":{\"secret\":\"key_ref\"}}}},"
        "\"outbounds\":{\"direct\":{\"type\":\"direct\"}},\"routing\":{\"default\":\"direct\",\"rules\":[]}}";
    struct steer_spec_plan *p=steer_spec_compile(source,strlen(source),NULL,0);assert(p);
    memset(source,'x',strlen(source));
    struct steer_spec_summary s=steer_spec_summary(p);assert(s.syntax_valid&&s.topology_valid&&!s.runtime_ready);
    struct steer_spec_node_view v;int found=0;uint32_t inbound=UINT32_MAX,plugin=UINT32_MAX,secret=UINT32_MAX;
    for(uint32_t i=0;i<s.nodes;i++){assert(steer_spec_node(p,i,&v));
        if(v.kind==STEER_SPEC_PLUGIN)plugin=i;
        if(v.kind==STEER_SPEC_SECRET)secret=i;
        if(v.kind!=STEER_SPEC_INBOUND)continue;
        inbound=i;
        found++;assert(!v.enabled&&!v.options_validated&&v.intent&&v.listen&&v.transport&&v.security&&v.variant);
        assert(!strcmp(ynode_get(v.transport,"path")->str,"/private-path"));
        assert(!strcmp(ynode_get(v.options,"private_value")->str,"never-diagnostic"));
    }
    assert(found==1&&ynode_get(steer_spec_intent(p),"routing"));
    unsigned plugin_edges=0,secret_edges=0,decisions=0;
    for(uint32_t i=0;i<s.edges;i++){
        struct steer_spec_edge_view e;assert(steer_spec_edge(p,i,&e));
        if(e.source==inbound&&e.target==plugin){assert(e.construction_dependency&&e.kind==STEER_SPEC_REFERENCE);plugin_edges++;}
        if(e.source==inbound&&e.target==secret){assert(e.construction_dependency&&e.kind==STEER_SPEC_REFERENCE);secret_edges++;}
        if(e.kind==STEER_SPEC_ROUTE_TARGET){assert(!e.construction_dependency);decisions++;}
    }
    assert(plugin_edges==1&&secret_edges==2&&decisions>0); /* one shared secret node, two references */
    FILE *f=tmpfile();assert(f);steer_spec_write_json(p,f);rewind(f);
    char output[8192]={0};assert(fread(output,1,sizeof(output)-1,f)>0);fclose(f);
    assert(!strstr(output,"never-diagnostic")&&!strstr(output,"private-path"));steer_spec_destroy(p);
}
static void dangling(void){
    const char *aliases[]={"protocols","missing"};const char *secrets[]={"key_ref","missing"};
    for(unsigned i=0;i<3;i++){
        char source[4096];int n=snprintf(source,sizeof(source),
            "{\"version\":3,\"plugin_remotes\":{\"official\":{\"url\":\"https://example.invalid\",\"trust\":\"root\"}},"
            "\"plugins\":{\"protocols\":{\"remote\":\"official\",\"package\":\"protocols\",\"version\":\"^1.0.0\"}},"
            "\"secrets\":{\"key_ref\":{\"source\":\"env\",\"name\":\"EXAMPLE_SECRET\"}},"
            "\"inbounds\":{\"in\":{\"plugin\":\"vless:%s\",\"options\":{\"token\":{\"secret\":\"%s\"}}}},"
            "\"outbounds\":{\"direct\":{\"type\":\"direct\"}},\"routing\":{\"default\":\"direct\",\"rules\":[]}}",
            aliases[i==1],secrets[i==2]);
        assert(n>0&&(size_t)n<sizeof(source));
        struct steer_spec_plan *p=steer_spec_compile(source,(size_t)n,NULL,0);assert(p);
        struct steer_spec_summary s=steer_spec_summary(p);assert(s.syntax_valid&&!s.runtime_ready);
        assert(s.topology_valid==(i==0));
        unsigned unresolved=0;
        for(uint32_t j=0;j<s.edges;j++){
            struct steer_spec_edge_view e;assert(steer_spec_edge(p,j,&e));
            if(e.construction_dependency&&e.target==UINT32_MAX)unresolved++;
        }
        assert((unresolved!=0)==(i!=0));steer_spec_destroy(p);
    }
}
static void device_inbound(void){
    const char *variants[]={
        "\"flow\":[\"device\"],\"device\":{\"name\":\"gateway\"}",
        "\"flow\":[\"device\"]",
        "\"flow\":[\"device\"],\"device\":{\"name\":\"gateway\"},\"listen\":{\"address\":\"127.0.0.1\",\"port\":51820}",
        "\"flow\":[\"device\",\"stream\"],\"device\":{\"name\":\"gateway\"}",
        "\"flow\":[\"stream\"],\"device\":{\"name\":\"gateway\"}",
        "\"flow\":[\"device\"],\"device\":{\"name\":\"bad/name\"}",
    };
    for(size_t i=0;i<sizeof(variants)/sizeof(variants[0]);i++){
        char source[1024];
        int n=snprintf(source,sizeof(source),
            "{\"version\":3,\"plugin_remotes\":{\"local\":{\"url\":\"https://example.invalid\",\"trust\":\"local\"}},"
            "\"plugins\":{\"protocols\":{\"remote\":\"local\",\"package\":\"protocols\",\"version\":\"0.0.0\"}},"
            "\"inbounds\":{\"vpn\":{\"plugin\":\"wireguard:protocols\",\"options\":{},%s}},"
            "\"outbounds\":{\"deny\":{\"type\":\"block\",\"flow\":[\"device\"]}},\"routing\":{\"default\":\"deny\",\"rules\":[]}}",
            variants[i]);
        assert(n>0&&(size_t)n<sizeof(source));
        struct steer_spec_plan *p=steer_spec_compile(source,(size_t)n,NULL,0);assert(p);
        struct steer_spec_summary s=steer_spec_summary(p);
        assert(s.syntax_valid==(i==0)&&!s.runtime_ready);
        if(i==0){
            unsigned found=0;
            assert(s.topology_valid);
            for(uint32_t j=0;j<s.requirements;j++){
                struct steer_spec_requirement_view r;assert(steer_spec_requirement(p,j,&r));
                if(strcmp(r.name,"provider.wireguard:protocols/inbound/device/device/none/default"))continue;
                struct steer_spec_node_view v;assert(!r.state&&steer_spec_node(p,r.owner_node,&v));
                assert(v.kind==STEER_SPEC_INBOUND&&v.flows==STEER_SPEC_FLOW_DEVICE&&v.device&&!v.listen);
                assert(!strcmp(ynode_get(v.device,"name")->str,"gateway"));found++;
            }
            assert(found==1);
        }
        steer_spec_destroy(p);
    }
    puts("spec device inbound: exact non-socket tuple, mixed flow and socket fields rejected PASS");
}
int main(void){types();views();readiness();dangling();device_inbound();puts("spec typed DNS settings/private views/construction edges PASS");return 0;}
