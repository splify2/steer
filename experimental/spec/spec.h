/* SPDX-License-Identifier: GPL-3.0-only
 * Experimental core intent compiler; not a provider ABI or stable spec API. */
#ifndef STEER_SPEC_COMPILER_H
#define STEER_SPEC_COMPILER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define STEER_SPEC_MAX_BYTES (1024u * 1024u)
#define STEER_SPEC_MAX_NODES 512u
#define STEER_SPEC_MAX_EDGES 4096u
#define STEER_SPEC_MAX_DIAGNOSTICS 256u
#define STEER_SPEC_FLOW_STREAM 1u
#define STEER_SPEC_FLOW_DATAGRAM 2u
#define STEER_SPEC_FLOW_DEVICE 4u
#define STEER_SPEC_BUILT 1u
#define STEER_SPEC_SUPPORTED 2u
#define STEER_SPEC_AVAILABLE 4u
#define STEER_SPEC_AUTHORIZED 8u
#define STEER_SPEC_READY 15u
struct ynode;
struct steer_spec_plan;
enum steer_spec_node_kind {
    STEER_SPEC_INBOUND, STEER_SPEC_OUTBOUND, STEER_SPEC_DNS,
    STEER_SPEC_RULE_SET, STEER_SPEC_SECRET, STEER_SPEC_USER,
    STEER_SPEC_PROFILE, STEER_SPEC_PLUGIN
};
enum steer_spec_edge_kind {
    STEER_SPEC_DETOUR, STEER_SPEC_MEMBER, STEER_SPEC_BOOTSTRAP,
    STEER_SPEC_DNS_TRANSPORT, STEER_SPEC_ROUTE_TARGET,
    STEER_SPEC_OBSERVE, STEER_SPEC_REFERENCE
};
/* Inventory is trusted host input, not a capability claim from the document.
 * Exact names include transport/security variants. State bits remain separate.
 * Provider options are borrowed only during the pure validator callback; no
 * allocation/IO or reentry through the compiler. NULL validator is unavailable,
 * never validation success. Inventory and strings need live only through compile. */
struct steer_spec_capability {
    const char *name;
    uint32_t state;
    int (*validate_options)(void *, const struct ynode *);
    void *context;
};
struct steer_spec_summary {
    int syntax_valid, topology_valid, runtime_ready;
    uint32_t nodes, edges, requirements, diagnostics;
};
/* Borrowed read-only views remain valid until plan destroy. Indices are stable.
 * Unresolved edge target is UINT32_MAX. Execution must require runtime_ready;
 * views on an invalid plan exist for diagnostics/review only. Rules retain
 * source order; provider options are never reconstructed from summary JSON. */
struct steer_spec_node_view {
    enum steer_spec_node_kind kind;
    const char *id, *path, *type, *provider;
    uint32_t flows;
    const struct ynode *options;
    int options_validated;
};
struct steer_spec_edge_view {
    enum steer_spec_edge_kind kind;
    uint32_t source, target, required_flows;
    const char *path;
    int construction_dependency;
};
struct steer_spec_rule_view {
    const char *id, *path, *action, *target;
    const struct ynode *match;
    uint32_t flows;
    int dns_rule;
};
struct steer_spec_requirement_view {
    const char *name, *path;
    uint32_t state;
};
/* Owns parsed intent/IR until destroy. Unknown provider options are preserved in
 * the plan but never emitted by summary/diagnostics. Failure may still return a
 * diagnostic plan; NULL means allocation failure. No network/device/process IO. */
struct steer_spec_plan *steer_spec_compile(const char *, size_t,
    const struct steer_spec_capability *, size_t);
struct steer_spec_summary steer_spec_summary(const struct steer_spec_plan *);
int steer_spec_node(const struct steer_spec_plan *, uint32_t, struct steer_spec_node_view *);
int steer_spec_edge(const struct steer_spec_plan *, uint32_t, struct steer_spec_edge_view *);
int steer_spec_rule(const struct steer_spec_plan *, uint32_t, struct steer_spec_rule_view *);
int steer_spec_requirement(const struct steer_spec_plan *, uint32_t, struct steer_spec_requirement_view *);
/* Original private intent, not a redacted status/export. Caller must preserve
 * its secret-handling policy; this accessor is never used by JSON diagnostics. */
const char *steer_spec_document(const struct steer_spec_plan *, size_t *);
void steer_spec_write_json(const struct steer_spec_plan *, FILE *);
void steer_spec_destroy(struct steer_spec_plan *);
#endif
