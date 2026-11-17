#include "execution_static.h"
#include "ynode.h"
#include "pm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct prepared {const struct steer_spec_static_module *module;};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static int bounded(const char *s,size_t n){return s&&*s&&strnlen(s,n)<n;}
static const char *value(const struct ynode *n,const char *key){const struct ynode *v=ynode_get(n,key);return v&&v->kind==YN_SCALAR?v->str:NULL;}
static int equal(const char *a,const char *b){return a&&b&&!strcmp(a,b);}
static int validate(void *arg,const struct steer_spec_node_view *node){
 const struct steer_spec_static_module *module=arg;const struct steer_spec_static_catalogue *catalogue=module->catalogue;
 const struct ynode *deps=ynode_get(node->intent,"dependencies");
 return node->kind==STEER_SPEC_PLUGIN&&equal(node->id,module->alias)&&node->resolved_remote&&
  equal(value(node->intent,"package"),catalogue->package)&&
  value(node->intent,"version")&&pm_range_match(value(node->intent,"version"),catalogue->version)==1&&
  equal(value(node->resolved_remote,"url"),catalogue->remote_url)&&equal(value(node->resolved_remote,"trust"),catalogue->remote_trust)&&
  (!deps||(deps->kind==YN_SEQ&&!deps->len));
}
static struct steer_pv1_error prepare(void *arg,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,uint64_t deadline,const struct steer_draft_cancel *cancel,void **out){
 (void)node;(void)deps;(void)deadline;(void)cancel;*out=NULL;if(count)return error(STEER_PV1_UNSUPPORTED);
 struct prepared *p=malloc(sizeof(*p));if(!p)return error(STEER_PV1_RESOURCE_EXHAUSTED);p->module=arg;*out=p;return error(0);
}
static void discard(void *arg,void *state){(void)arg;free(state);}
static struct steer_pv1_error bind_instance(void *arg,void *state,const struct steer_spec_node_view *node,const struct steer_spec_execution_dependency *deps,uint32_t count,const struct steer_spec_execution_owner *owner,struct steer_spec_execution_instance *out){
 (void)arg;(void)node;(void)deps;(void)owner;if(count)return error(STEER_PV1_UNSUPPORTED);out->handle=state;return error(0);
}
static void retire(void *arg,struct steer_spec_execution_instance *out){(void)arg;(void)out;}
static struct steer_pv1_error collect(void *arg,struct steer_spec_execution_instance *out){(void)arg;memset(out,0,sizeof(*out));return error(0);}
struct steer_pv1_error steer_spec_static_module_factory(struct steer_spec_static_module *module,const struct steer_spec_static_catalogue *catalogue,const char *alias,struct steer_spec_execution_factory *out){
 if(!module||!catalogue||!out||catalogue->origin!=STEER_SPEC_STATIC_LINKED||!bounded(alias,64)||!bounded(catalogue->origin_id,128)||!bounded(catalogue->package,65)||!pm_id_ok(catalogue->package)||!bounded(catalogue->version,128)||!pm_ver_ok(catalogue->version)||!bounded(catalogue->source_sha256,65)||strlen(catalogue->source_sha256)!=64||!bounded(catalogue->remote_url,1024)||strncmp(catalogue->remote_url,"https://",8)||strchr(catalogue->remote_url,'@')||strchr(catalogue->remote_url,'#')||!bounded(catalogue->remote_trust,256)||!catalogue->guard.retain||!catalogue->guard.release)return error(STEER_PV1_INVALID);
 unsigned nonzero=0;for(size_t i=0;i<64;i++){char c=catalogue->source_sha256[i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return error(STEER_PV1_INVALID);nonzero|=(unsigned)(c!='0');}if(!nonzero)return error(STEER_PV1_INVALID);
 for(const char *p=alias;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'||*p=='.'))return error(STEER_PV1_INVALID);
 memset(module,0,sizeof(*module));module->catalogue=catalogue;strcpy(module->alias,alias);snprintf(module->requirement,sizeof(module->requirement),"plugin.lock.%s",alias);module->capabilities[0]=module->requirement;
 *out=(struct steer_spec_execution_factory){.size=sizeof(*out),.version=STEER_SPEC_EXECUTION_FACTORY_LAYOUT,.kind=STEER_SPEC_PLUGIN,.type="",.node_id=module->alias,.transport="tcp",.security="none",.variant="default",.capabilities=module->capabilities,.capability_count=1,.guard=catalogue->guard,.context=module,.validate=validate,.prepare=prepare,.discard=discard,.bind=bind_instance,.retire=retire,.collect=collect};return error(0);
}
