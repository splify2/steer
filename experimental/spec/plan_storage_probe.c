/* SPDX-License-Identifier: GPL-3.0-only
 * Linked against one compiler implementation; the allocation hooks are used
 * only while compiling spec.c, not by the YAML parser or this driver. */
#include "spec.h"
#include "ynode.h"
#include "jsonw.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned alloc_count, fail_at;
static void *live[8];
static void *track(void *p) {
    if (!p) return NULL;
    for(size_t i=0;i<sizeof(live)/sizeof(live[0]);i++)
        if(!live[i]) { live[i]=p;return p; }
    abort();
}
static void assert_released(void) {
    for(size_t i=0;i<sizeof(live)/sizeof(live[0]);i++) assert(!live[i]);
}
void *plan_test_malloc(size_t n) {
    if (++alloc_count == fail_at) return NULL;
    void *p = malloc(n);
    if (p) memset(p, 0xa5, n);
    return track(p);
}
void *plan_test_calloc(size_t n, size_t size) {
    if (++alloc_count == fail_at) return NULL;
    return track(calloc(n, size));
}
void plan_test_free(void *p) {
    if(!p)return;
    for(size_t i=0;i<sizeof(live)/sizeof(live[0]);i++)
        if(live[i]==p) { live[i]=NULL;free(p);return; }
    abort();
}

static void tree(const struct ynode *n) {
    if (!n) { fputs("null", stdout); return; }
    printf("[%d,%d,%u,%u,", n->kind, n->style, n->line, n->col);
    if (n->tag) jsonw_str(stdout, n->tag); else fputs("null", stdout);
    putchar(',');
    if (n->kind == YN_SCALAR) jsonw_str(stdout, n->str);
    else {
        putchar('[');
        size_t count = n->kind == YN_MAP ? 2*n->len : n->len;
        for (size_t i=0;i<count;i++) { if (i) putchar(','); tree(n->items[i]); }
        putchar(']');
    }
    putchar(']');
}
static void str(const char *s) { if (s) jsonw_str(stdout,s); else fputs("null",stdout); }

static void snapshot(struct steer_spec_plan *p) {
    struct steer_spec_summary s=steer_spec_summary(p);
    printf("summary %d %d %d %u %u %u %u\n",s.syntax_valid,s.topology_valid,s.runtime_ready,s.nodes,s.edges,s.requirements,s.diagnostics);
    steer_spec_write_json(p,stdout);
    size_t len=123; const char *source=steer_spec_document(p,&len);
    printf("document %zu ",len);str(source);putchar('\n');
    fputs("intent ",stdout);tree(steer_spec_intent(p));putchar('\n');
    for (uint32_t i=0;i<s.nodes;i++) {
        struct steer_spec_node_view v; assert(steer_spec_node(p,i,&v));
        printf("node %d %u %d %d ",v.kind,v.flows,v.enabled,v.options_validated);
        str(v.id);putchar(' ');str(v.path);putchar(' ');str(v.type);putchar(' ');str(v.provider);
        const struct ynode *a[]={v.options,v.intent,v.listen,v.device,v.endpoint,v.transport,v.security,v.variant,v.resolved_remote};
        for(size_t j=0;j<sizeof(a)/sizeof(a[0]);j++){putchar(' ');tree(a[j]);}putchar('\n');
    }
    struct steer_spec_node_view nv; assert(!steer_spec_node(p,s.nodes,&nv));
    for(uint32_t i=0;i<s.edges;i++) {
        struct steer_spec_edge_view v;assert(steer_spec_edge(p,i,&v));
        printf("edge %d %u %u %u %d ",v.kind,v.source,v.target,v.required_flows,v.construction_dependency);str(v.path);putchar('\n');
    }
    struct steer_spec_edge_view ev;assert(!steer_spec_edge(p,s.edges,&ev));
    for(uint32_t i=0;;i++) {
        struct steer_spec_rule_view v;if(!steer_spec_rule(p,i,&v))break;
        printf("rule %u %d %d ",v.flows,v.dns_rule,v.enabled);str(v.id);putchar(' ');str(v.path);
        putchar(' ');str(v.action);putchar(' ');str(v.target);putchar(' ');tree(v.match);
        putchar(' ');tree(v.strategy);putchar(' ');tree(v.cache_timeout);putchar('\n');
    }
    for(uint32_t i=0;i<s.requirements;i++) {
        struct steer_spec_requirement_view v;assert(steer_spec_requirement(p,i,&v));
        printf("requirement %u %u ",v.state,v.owner_node);str(v.name);putchar(' ');str(v.path);putchar('\n');
    }
    struct steer_spec_requirement_view rv;assert(!steer_spec_requirement(p,s.requirements,&rv));
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"oom")) {
        const char *source="{}";
        for(fail_at=1;fail_at<=2;fail_at++) {
            alloc_count=0;struct steer_spec_plan *p=steer_spec_compile(source,2,NULL,0);
            assert(!p && alloc_count==fail_at);
            assert_released();
        }
        fail_at=0;alloc_count=0;
        struct steer_spec_plan *p=steer_spec_compile(NULL,0,NULL,0);assert(p);
        struct steer_spec_summary s=steer_spec_summary(p);
        assert(!s.syntax_valid && s.diagnostics==1 && !s.nodes && !s.edges && !s.requirements);
        snapshot(p);steer_spec_destroy(p);assert_released();return 0;
    }
    assert(argc==2 || (argc==3 && !strcmp(argv[2],"ready")));
    FILE *f=fopen(argv[1],"rb");assert(f);
    assert(!fseek(f,0,SEEK_END));long size=ftell(f);assert(size>=0);rewind(f);
    char *source=malloc((size_t)size+1);assert(source);
    assert(fread(source,1,(size_t)size,f)==(size_t)size);fclose(f);source[size]=0;
    struct steer_spec_plan *first=steer_spec_compile(source,(size_t)size,NULL,0);
    assert(first);struct steer_spec_plan *p=first;
    struct steer_spec_capability *caps=NULL;
    if(argc==3) {
        struct steer_spec_summary s=steer_spec_summary(first);
        caps=calloc(s.requirements ? s.requirements : 1,sizeof(*caps));assert(caps);
        for(uint32_t i=0;i<s.requirements;i++) {
            struct steer_spec_requirement_view v;assert(steer_spec_requirement(first,i,&v));
            caps[i].name=v.name;caps[i].state=STEER_SPEC_READY;
        }
        p=steer_spec_compile(source,(size_t)size,caps,s.requirements);assert(p);
    }
    snapshot(p);
    if(p!=first)steer_spec_destroy(p);
    free(caps);steer_spec_destroy(first);free(source);assert_released();return 0;
}
