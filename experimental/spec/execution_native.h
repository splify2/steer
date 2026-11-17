#ifndef STEER_SPEC_EXECUTION_NATIVE_H
#define STEER_SPEC_EXECUTION_NATIVE_H
#include "execution.h"
#include "../provider/native_stream_backend.h"
#include "../provider/datagram.h"
/* Owner runtimes/resolver are shared bounded services, not one pool per node.
 * Services and registration guard remain alive through every generation's
 * owner collection and final worker destruction. Immutable after registration. */
struct steer_spec_native_services {
    struct loop *owner;
    struct steer_draft_stream_runtime *streams;
    struct steer_draft_backend_runtime *stream_refs;
    struct steer_draft_datagram_runtime *datagrams;
    struct steer_draft_resolver *resolver;
    uint32_t max_operations,max_references;
};
/* Makes one concrete direct factory covering stream+datagram. Domain support
 * reflects attached services. Explicit resolve_via/detour is not silently
 * ignored: this factory rejects it until a selected dependency implementation
 * is supplied. Other factories can implement typed detours through the DAG. */
struct steer_pv1_error steer_spec_native_factory(struct steer_spec_native_services *,
    const struct steer_spec_execution_guard *,struct steer_spec_execution_factory *);
#endif
