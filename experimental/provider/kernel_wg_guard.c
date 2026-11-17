#define _GNU_SOURCE
#include "kernel_wg_guard.h"
#include "awgdev.h"
#include "ir.h"
#include "nftdump.h"
#include "run.h"
#include "ynode.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
struct source_prefix {uint8_t family,bits,address[16];uint32_t peer,count;};
struct steer_draft_kernel_wg_guard {struct nft_rs drop,policy;char table[48],device[16],inbound[65],principals[8][65],index_match[40];struct source_prefix sources[64];uint32_t source_count,peer_count;uint64_t generation,handle;int index,uncertain;dev_t ns_device;ino_t ns_inode;};
static struct steer_pv1_error error(uint32_t c){struct steer_pv1_error e={c,0};return e;}
static int identifier(const char*s,size_t cap){size_t i;if(!memchr(s,0,cap)||!*s)return 0;for(i=0;s[i];i++){unsigned c=(unsigned char)s[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;}return 1;}
static int prefix(const char*s,struct source_prefix*out){char text[64],*slash,*p;unsigned bits=0;uint32_t i;if(!memchr(s,0,64))return 0;snprintf(text,sizeof(text),"%s",s);slash=strchr(text,'/');if(!slash)return 0;*slash++=0;if(!*slash)return 0;for(p=slash;*p;p++){if(*p<'0'||*p>'9'||bits>128)return 0;bits=bits*10+(unsigned)(*p-'0');}out->family=inet_pton(AF_INET,text,out->address)==1?4:inet_pton(AF_INET6,text,out->address)==1?6:0;if(!out->family||bits>(out->family==4?32u:128u))return 0;out->bits=(uint8_t)bits;for(i=bits;i<(out->family==4?32u:128u);i++)if(out->address[i/8]&(0x80u>>(i%8)))return 0;return 1;}
static int overlap(const struct source_prefix*a,const struct source_prefix*b){uint32_t i,bits=a->bits<b->bits?a->bits:b->bits;if(a->family!=b->family)return 0;for(i=0;i<bits;i++)if((a->address[i/8]^b->address[i/8])&(0x80u>>(i%8)))return 0;return 1;}
static int same_namespace(const struct steer_draft_kernel_wg_guard*g){struct stat st;return !stat("/proc/self/ns/net",&st)&&st.st_dev==g->ns_device&&st.st_ino==g->ns_inode;}
static int same_identity(const struct steer_draft_kernel_wg_guard*g){char kind[32];int index;return same_namespace(g)&&!awg_dev_link_query(g->device,kind,sizeof(kind),&index)&&index==g->index&&!strcmp(kind,"wireguard");}
static int table_owned(const struct steer_draft_kernel_wg_guard*g){struct nfd_tfp actual;return same_namespace(g)&&!nfd_table_fp(g->table,&actual)&&actual.fams&&actual.handle==g->handle&&g->handle;}
static void ingress_match(struct steer_draft_kernel_wg_guard*g,struct nft_rule*r){ir_x(r,"meta iif 0");if(r&&r->x)r->x->text=g->index_match;}
struct visitor {struct steer_draft_kernel_wg_guard*g;struct nft_chain*chain;uint32_t peer,count;};
static int span_equal(struct steer_pv1_span value,const char*text){return value.len==strlen(text)&&!memcmp(value.data,text,value.len);}
static void emit_rule(struct visitor*v,const struct steer_policy_rule*rule,int protocol){struct nft_rule*r=ir_rule(v->chain);char address[INET6_ADDRSTRLEN];if(rule->cidr_tag){int family=rule->cidr_tag==STEER_PV1_ENDPOINT_IPV4?AF_INET:AF_INET6;inet_ntop(family,rule->network,address,sizeof(address));ir_x(r,"%s daddr %s/%u",family==AF_INET?"ip":"ip6",address,rule->prefix_bits);}if(protocol)ir_x(r,"%s dport %u-%u",protocol==6?"tcp":"udp",rule->port_first,rule->port_last);ir_counter(r,0,0);ir_x(r,"%s",rule->action==STEER_POLICY_DIRECT?"accept":"drop");ir_comment(r,"steer-wg:%.*s",(int)rule->id.len,rule->id.data);}
static struct steer_pv1_error visit(void*context,const struct steer_policy_rule*rule){struct visitor*v=context;if(rule->inbound.len&&!span_equal(rule->inbound,v->g->inbound))return error(STEER_PV1_OK);if(rule->principal.len&&!span_equal(rule->principal,v->g->principals[v->peer]))return error(STEER_PV1_OK);if(rule->domain.len)return error(STEER_PV1_UNSUPPORTED);if(v->count++>=STEER_DRAFT_WG_GUARD_RULES)return error(STEER_PV1_RESOURCE_EXHAUSTED);if(rule->port_first){emit_rule(v,rule,6);emit_rule(v,rule,17);}else emit_rule(v,rule,0);return error(STEER_PV1_OK);}
struct steer_pv1_error steer_draft_kernel_wg_guard_prepare(const struct steer_draft_kernel_wg_guard_config*c,const struct steer_policy*p,struct steer_draft_kernel_wg_guard**out){struct steer_draft_kernel_wg_guard*g;struct stat ns;struct nft_table*table;struct nft_chain*base;uint32_t i,j,k,fallback;uint64_t random;struct steer_pv1_error e=error(STEER_PV1_INVALID);if(out)*out=NULL;if(!c||!p||!out||!c->generation||!identifier(c->inbound_id,sizeof(c->inbound_id))||!identifier(c->device,sizeof(c->device))||!c->peer_count||c->peer_count>8)return e;if(stat("/proc/self/ns/net",&ns)||getrandom(&random,sizeof(random),0)!=(ssize_t)sizeof(random))return error(STEER_PV1_IO);g=calloc(1,sizeof(*g));if(!g)return error(STEER_PV1_RESOURCE_EXHAUSTED);nft_rs_init(&g->drop);nft_rs_init(&g->policy);g->generation=c->generation;g->ns_device=ns.st_dev;g->ns_inode=ns.st_ino;g->peer_count=c->peer_count;snprintf(g->inbound,sizeof(g->inbound),"%s",c->inbound_id);snprintf(g->device,sizeof(g->device),"%s",c->device);snprintf(g->table,sizeof(g->table),"steer_wg_%016llx",(unsigned long long)random);snprintf(g->index_match,sizeof(g->index_match),"meta iif 0");
for(i=0;i<c->peer_count;i++){if(!identifier(c->peers[i].principal_id,sizeof(c->peers[i].principal_id))||!c->peers[i].allowed_count||c->peers[i].allowed_count>8)goto fail;snprintf(g->principals[i],sizeof(g->principals[i]),"%s",c->peers[i].principal_id);for(j=0;j<c->peers[i].allowed_count;j++){struct source_prefix*source=&g->sources[g->source_count];if(!prefix(c->peers[i].allowed_ips[j],source))goto fail;source->peer=i;for(k=0;k<g->source_count;k++)if(overlap(source,&g->sources[k]))goto fail;g->source_count++;}}
table=ir_table_add(&g->drop,NFT_FAM_INET,g->table);base=ir_base_chain_add(table,"ingress","filter","prerouting","mangle",-10);{struct nft_rule*r=ir_rule(base);ingress_match(g,r);ir_counter(r,0,0);ir_x(r,"drop");}
table=ir_table_add(&g->policy,NFT_FAM_INET,g->table);
for(i=0;i<g->peer_count;i++){char name[24];struct visitor v;struct nft_rule*r;snprintf(name,sizeof(name),"peer_%u",i);v.g=g;v.peer=i;v.count=0;v.chain=ir_chain_add(table,name);e=steer_policy_visit(p,c->generation,visit,&v,&fallback);if(e.code)goto fail;r=ir_rule(v.chain);ir_counter(r,0,0);ir_x(r,"%s",fallback==STEER_POLICY_DIRECT?"accept":"drop");}
base=ir_base_chain_add(table,"ingress","filter","prerouting","mangle",-10);
{struct nft_rule*r=ir_rule(base);ingress_match(g,r);ir_x(r,"ct state invalid drop");}
for(i=0;i<g->source_count;i++){struct source_prefix*s=&g->sources[i];struct nft_rule*r=ir_rule(base);char address[INET6_ADDRSTRLEN];inet_ntop(s->family==4?AF_INET:AF_INET6,s->address,address,sizeof(address));ingress_match(g,r);ir_x(r,"%s saddr %s/%u",s->family==4?"ip":"ip6",address,s->bits);ir_x(r,"goto peer_%u",s->peer);}
{struct nft_rule*r=ir_rule(base);ingress_match(g,r);ir_counter(r,0,0);ir_x(r,"drop");}
if(g->drop.oom||g->policy.oom){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto fail;}*out=g;return error(STEER_PV1_OK);
fail:nft_rs_free(&g->drop);nft_rs_free(&g->policy);free(g);return e;}
static uint64_t echo_handle(int fd,const char *table){
    struct stat st;char *buffer;size_t used=0;struct err diagnostic={0};struct ydoc *doc;const struct ynode *events;uint64_t handle=0;size_t i;
    if(fstat(fd,&st)||st.st_size<=0||st.st_size>3*1024*1024||lseek(fd,0,SEEK_SET)<0)return 0;
    buffer=malloc((size_t)st.st_size+1);if(!buffer)return 0;
    while(used<(size_t)st.st_size){ssize_t n=read(fd,buffer+used,(size_t)st.st_size-used);if(n<0&&errno==EINTR)continue;if(n<=0){free(buffer);return 0;}used+=(size_t)n;}buffer[used]=0;
    doc=ydoc_parse_buf(buffer,used,"nft-echo",&diagnostic);free(buffer);if(!doc)return 0;
    events=ynode_get(ydoc_root(doc),"nftables");
    if(events&&events->kind==YN_SEQ)for(i=0;i<events->len;i++){
        const struct ynode *t=ynode_get(ynode_get(ynode_at(events,i),"create"),"table");
        const struct ynode *name=ynode_get(t,"name"),*family=ynode_get(t,"family");long value=0;
        if(name&&name->kind==YN_SCALAR&&family&&family->kind==YN_SCALAR&&!strcmp(name->str,table)&&!strcmp(family->str,"inet")&&!ynode_long(ynode_get(t,"handle"),&value)&&value>0){if(handle){handle=0;break;}handle=(uint64_t)value;}
    }
    ydoc_free(doc);return handle;
}
static struct steer_draft_kernel_wg_guard_result outcome(uint32_t code,uint32_t phase){struct steer_draft_kernel_wg_guard_result r={{code,0},phase};return r;}
static struct steer_draft_kernel_wg_guard_result uncertain(struct steer_draft_kernel_wg_guard*g,uint32_t code){g->uncertain=1;if(g->index)(void)awg_dev_link_down_owned(g->device,"wireguard",g->index);return outcome(code,STEER_DRAFT_WG_GUARD_UNCERTAIN);}
static struct steer_draft_kernel_wg_guard_result apply(struct steer_draft_kernel_wg_guard*g,const struct nft_rs*rules,int fresh,int remove){
    int fd,output,result;FILE *f;char path[96];uint64_t captured;struct nfd_tfp live;const char *argv[7]={"nft","--echo","--json","--handle","-f",path,NULL};
    if(!same_namespace(g))return outcome(STEER_PV1_POLICY_DENIED,STEER_DRAFT_WG_GUARD_UNCHANGED);
    if(g->uncertain)return uncertain(g,STEER_PV1_POLICY_DENIED);
    if(!fresh&&!table_owned(g))return uncertain(g,STEER_PV1_POLICY_DENIED);
    fd=memfd_create("steer-wg-rules",MFD_CLOEXEC);output=memfd_create("steer-wg-echo",MFD_CLOEXEC);
    if(fd<0||output<0){if(fd>=0)close(fd);if(output>=0)close(output);return outcome(STEER_PV1_RESOURCE_EXHAUSTED,0);}
    f=fdopen(fd,"w");if(!f){close(fd);close(output);return outcome(STEER_PV1_IO,0);}
    if(!fresh)fprintf(f,"delete table inet handle %llu\n",(unsigned long long)g->handle);
    if(!remove)fprintf(f,"create table inet %s\n",g->table);
    if(!remove&&nft_print_chains(rules,f)){fclose(f);close(output);return outcome(STEER_PV1_IO,0);}
    if(fflush(f)||ferror(f)){fclose(f);close(output);return outcome(STEER_PV1_IO,0);}
    snprintf(path,sizeof(path),"/proc/%ld/fd/%d",(long)getpid(),fd);
    result=run_output(argv,output);captured=remove?0:echo_handle(output,g->table);fclose(f);close(output);
    if(remove&&!result){g->handle=0;return outcome(STEER_PV1_OK,STEER_DRAFT_WG_GUARD_CHANGED);}
    if(captured){g->handle=captured;return outcome(result?STEER_PV1_IO:STEER_PV1_OK,STEER_DRAFT_WG_GUARD_CHANGED);}
    if(!nfd_table_fp(g->table,&live)){
        if(remove&&!live.fams){g->handle=0;return outcome(STEER_PV1_IO,STEER_DRAFT_WG_GUARD_CHANGED);}
        if(result&&((fresh&&!live.fams)||(!fresh&&live.fams&&live.handle==g->handle)))return outcome(STEER_PV1_IO,STEER_DRAFT_WG_GUARD_UNCHANGED);
    }
    return uncertain(g,STEER_PV1_IO);
}
struct steer_pv1_error steer_draft_kernel_wg_guard_bind(void*context,const char*device,int index){struct steer_draft_kernel_wg_guard*g=context;if(!g||!device||index<=0)return error(STEER_PV1_INVALID);if(g->index||g->handle||strcmp(device,g->device)||!same_namespace(g))return error(STEER_PV1_POLICY_DENIED);g->index=index;if(!same_identity(g)){g->index=0;return error(STEER_PV1_POLICY_DENIED);}snprintf(g->index_match,sizeof(g->index_match),"meta iif %d",index);return apply(g,&g->drop,1,0).error;}
struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_publish(struct steer_draft_kernel_wg_guard*g){if(!g)return outcome(STEER_PV1_INVALID,0);if(!same_identity(g))return uncertain(g,STEER_PV1_POLICY_DENIED);return apply(g,&g->policy,0,0);}
struct steer_pv1_error steer_draft_kernel_wg_guard_retire(struct steer_draft_kernel_wg_guard*g){int index;char kind[32];int rc;if(!g)return error(STEER_PV1_INVALID);if(!same_namespace(g)||g->uncertain)return error(STEER_PV1_POLICY_DENIED);if(!g->handle)return error(STEER_PV1_OK);rc=awg_dev_link_query(g->device,kind,sizeof(kind),&index);if(!rc&&index==g->index&&!strcmp(kind,"wireguard"))return error(STEER_PV1_POLICY_DENIED);return apply(g,NULL,0,1).error;}
struct steer_pv1_error steer_draft_kernel_wg_guard_destroy(struct steer_draft_kernel_wg_guard*g){if(!g)return error(STEER_PV1_INVALID);if(g->uncertain)return error(STEER_PV1_POLICY_DENIED);if(g->handle){struct nfd_tfp actual;if(!same_namespace(g)||nfd_table_fp(g->table,&actual))return error(STEER_PV1_IO);if(actual.fams&&actual.handle==g->handle)return error(STEER_PV1_POLICY_DENIED);}nft_rs_free(&g->drop);nft_rs_free(&g->policy);free(g);return error(STEER_PV1_OK);}
const char*steer_draft_kernel_wg_guard_table(const struct steer_draft_kernel_wg_guard*g){return g?g->table:NULL;}

struct steer_draft_kernel_wg_guard_result steer_draft_kernel_wg_guard_replace(struct steer_draft_kernel_wg_guard*active,struct steer_draft_kernel_wg_guard*prepared){struct steer_draft_kernel_wg_guard_result e;struct nft_table*t;if(!active||!prepared||active==prepared)return outcome(STEER_PV1_INVALID,0);if(prepared->handle||prepared->index||!same_identity(active)||!same_namespace(prepared)||strcmp(active->device,prepared->device)||strcmp(active->inbound,prepared->inbound)||active->peer_count!=prepared->peer_count||active->source_count!=prepared->source_count||memcmp(active->principals,prepared->principals,sizeof(active->principals))||memcmp(active->sources,prepared->sources,active->source_count*sizeof(active->sources[0])))return outcome(STEER_PV1_POLICY_DENIED,0);snprintf(prepared->table,sizeof(prepared->table),"%s",active->table);for(t=prepared->policy.tables;t;t=t->next)t->name=prepared->table;for(t=prepared->drop.tables;t;t=t->next)t->name=prepared->table;prepared->index=active->index;snprintf(prepared->index_match,sizeof(prepared->index_match),"meta iif %d",prepared->index);prepared->handle=active->handle;e=apply(prepared,&prepared->policy,0,0);if(e.phase==STEER_DRAFT_WG_GUARD_CHANGED){active->handle=0;active->index=0;}else if(e.phase==STEER_DRAFT_WG_GUARD_UNCHANGED){prepared->handle=0;prepared->index=0;}else{active->uncertain=1;prepared->uncertain=1;}return e;}



struct steer_pv1_error steer_draft_kernel_wg_guard_reconcile_absent(struct steer_draft_kernel_wg_guard*g){struct nfd_tfp state;int index;char kind[32];if(!g)return error(STEER_PV1_INVALID);if(!same_namespace(g))return error(STEER_PV1_POLICY_DENIED);if(!awg_dev_link_query(g->device,kind,sizeof(kind),&index)&&index==g->index&&!strcmp(kind,"wireguard"))return error(STEER_PV1_POLICY_DENIED);if(nfd_table_fp(g->table,&state))return error(STEER_PV1_IO);if(state.fams)return error(STEER_PV1_POLICY_DENIED);g->uncertain=0;g->handle=0;g->index=0;return error(STEER_PV1_OK);}
