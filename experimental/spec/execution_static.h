#ifndef STEER_SPEC_EXECUTION_STATIC_H
#define STEER_SPEC_EXECUTION_STATIC_H
#include "execution.h"
#define STEER_SPEC_STATIC_LINKED 1u
/* Trusted BUILD metadata, never copied from input plugin_remote. Separate real
 * bundle version+source digest; describes static local linkage, not remote load. */
struct steer_spec_static_catalogue {
 uint32_t origin;const char *origin_id,*package,*version,*source_sha256;
 const char *remote_url,*remote_trust;struct steer_spec_execution_guard guard;
};
struct steer_spec_static_module {
 const struct steer_spec_static_catalogue *catalogue;
 char alias[64],requirement[80];const char *capabilities[1];
};
/* Exact plugin.lock.alias factory. Checks actual trusted package/version and
 * remote policy; URL equality alone is not provenance. Binding+catalogue live
 * immutable under guard until worker destruction. Nonempty deps unsupported. */
struct steer_pv1_error steer_spec_static_module_factory(struct steer_spec_static_module *,
 const struct steer_spec_static_catalogue *,const char *,struct steer_spec_execution_factory *);
#endif
