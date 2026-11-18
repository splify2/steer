/* SPDX-License-Identifier: GPL-3.0-only */
#include "spec.h"
#include "ynode.h"
#include "jsonw.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define REQUIREMENTS 2048u
#define RULES 1024u
struct node {
    enum steer_spec_node_kind kind;
    char id[64], path[192], type[32], provider[128];
    uint32_t flows;
    int enabled, options_validated;
    const struct ynode *intent, *options, *resolved_remote;
};
struct edge {
    enum steer_spec_edge_kind kind;
    enum steer_spec_node_kind target_kind;
    uint32_t source, target, flows;
    char id[64], path[192];
    int dependency;
};
struct diagnostic { unsigned phase; char code[64], path[192]; };
struct requirement { char name[384], path[192]; uint32_t state,owner_node; };
struct rule { char id[64], path[192], action[32], target[64]; const struct ynode *match,*strategy,*cache_timeout; uint32_t flows; int dns,enabled; };
struct steer_spec_plan {
    struct steer_spec_summary summary;
    struct ydoc *document;
    char *source; size_t source_length;
    struct node nodes[STEER_SPEC_MAX_NODES];
    struct edge edges[STEER_SPEC_MAX_EDGES];
    struct diagnostic diagnostics[STEER_SPEC_MAX_DIAGNOSTICS];
    struct requirement requirements[REQUIREMENTS];
    struct rule rules[RULES]; uint32_t rule_count;
    const struct steer_spec_capability *inventory; size_t inventory_count;
    uint32_t requirement_owner;
};
static void copy(char *out, size_t capacity, const char *text) {
    size_t n = strlen(text); if (n >= capacity) n = capacity - 1;
    memcpy(out, text, n); out[n] = 0;
}
static void path_at(char out[192], const char *base, const char *field) {
    size_t n = strlen(base), m = strlen(field);
    if (n > 189) n = 189;
    memcpy(out, base, n); out[n++] = '.';
    if (m > 191 - n) m = 191 - n;
    memcpy(out + n, field, m); out[n + m] = 0;
}
static void diagnostic(struct steer_spec_plan *p, unsigned phase, const char *code, const char *path) {
    struct diagnostic *d;
    p->summary.runtime_ready = 0;
    if (phase < 2) p->summary.topology_valid = 0;
    if (!phase) p->summary.syntax_valid = 0;
    if (p->summary.diagnostics == STEER_SPEC_MAX_DIAGNOSTICS) return;
    d = &p->diagnostics[p->summary.diagnostics++]; d->phase = phase;
    copy(d->code, sizeof(d->code), code); copy(d->path, sizeof(d->path), path);
}
static int scalar(const struct ynode *n) { return n && n->kind == YN_SCALAR && !n->tag; }
static int text(const struct ynode *n) {
    long number; int flag;
    return scalar(n) && n->len && !(n->style == YS_PLAIN &&
        (ynode_is_null(n) || !ynode_long(n, &number) || !ynode_bool(n, &flag)));
}
static int identifier(const char *s) {
    size_t n = 0;
    for (; *s; s++, n++) {
        unsigned c = (unsigned char)*s;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || (n && (c == '.' || c == '-')))) return 0;
    }
    return n && n <= 63;
}
static int keys(struct steer_spec_plan *p, const struct ynode *n, const char *allowed, const char *path) {
    size_t i; int valid = 1;
    if (!n || n->kind != YN_MAP || n->tag) { diagnostic(p, 0, "expected_object", path); return 0; }
    for (i = 0; i < n->len; i++) {
        const struct ynode *k = ynode_key_at(n, i); const char *cursor = allowed; int found = 0;
        while (*cursor) {
            const char *end = strchr(cursor, ' '); size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
            if (k->len == length && !memcmp(k->str, cursor, length)) found = 1;
            if (!end) break;
            cursor = end + 1;
        }
        if (!found) { char at[192]; path_at(at, path, k->str); diagnostic(p, 0, "unknown_field", at); valid = 0; }
    }
    return valid;
}
static const struct ynode *field(struct steer_spec_plan *p, const struct ynode *n, const char *name, const char *path, int required) {
    const struct ynode *v = ynode_get(n, name);
    if (!v && required) { char at[192]; path_at(at, path, name); diagnostic(p, 0, "missing_field", at); }
    return v;
}
static int boolean(struct steer_spec_plan *p, const struct ynode *n, int fallback, const char *path) {
    int value;
    if (!n) return fallback;
    if (n->tag || ynode_bool(n, &value)) { diagnostic(p, 0, "expected_boolean", path); return fallback; }
    return value;
}
static int unsigned_value(struct steer_spec_plan *p, const struct ynode *n, long min, long max, const char *path) {
    long value;
    if (!n || n->tag || ynode_long(n, &value) || value < min || value > max) {
        diagnostic(p, 0, "integer_out_of_range", path); return 0;
    }
    return 1;
}
static int dns_strategy(struct steer_spec_plan *p,const struct ynode *n,const char *path) {
    if(!n)return 1;
    if(!text(n)||(strcmp(n->str,"ipv4_only")&&strcmp(n->str,"ipv6_only")&&
        strcmp(n->str,"prefer_ipv4")&&strcmp(n->str,"prefer_ipv6"))){
        diagnostic(p,0,"unknown_dns_strategy",path);return 0;
    }
    return 1;
}
static int cache_duration(struct steer_spec_plan *p,const struct ynode *n,const char *path) {
    uint64_t value=0,multiplier;size_t i=0;
    if(!text(n)||n->len>12)goto invalid;
    while(i<n->len&&n->str[i]>='0'&&n->str[i]<='9'){
        unsigned digit=(unsigned)(n->str[i++]-'0');
        if(value>(604800000ull-digit)/10)goto invalid;
        value=value*10+digit;
    }
    if(!i)goto invalid;
    if(!strcmp(n->str+i,"ms"))multiplier=1;
    else if(!strcmp(n->str+i,"s"))multiplier=1000;
    else if(!strcmp(n->str+i,"m"))multiplier=60000;
    else if(!strcmp(n->str+i,"h"))multiplier=3600000;
    else goto invalid;
    if(value>604800000ull/multiplier)goto invalid;
    return 1;
invalid:diagnostic(p,0,"invalid_cache_duration",path);return 0;
}
static int named(struct steer_spec_plan *p, const struct ynode *n, char out[64], const char *path) {
    if (!text(n) || !identifier(n->str)) { diagnostic(p, 0, "invalid_identifier", path); return 0; }
    copy(out, 64, n->str); return 1;
}
static uint32_t flows(struct steer_spec_plan *p, const struct ynode *n, uint32_t fallback, const char *path) {
    size_t i; uint32_t result = 0;
    if (!n) return fallback;
    if (n->kind != YN_SEQ || !n->len || n->len > 3 || n->tag) { diagnostic(p, 0, "invalid_flow_classes", path); return fallback; }
    for (i = 0; i < n->len; i++) {
        const struct ynode *v = ynode_at(n, i); uint32_t bit = 0;
        if (text(v)) {
            if (!strcmp(v->str, "stream")) bit = STEER_SPEC_FLOW_STREAM;
            else if (!strcmp(v->str, "datagram")) bit = STEER_SPEC_FLOW_DATAGRAM;
            else if (!strcmp(v->str, "device")) bit = STEER_SPEC_FLOW_DEVICE;
        }
        if (!bit || (result & bit)) diagnostic(p, 0, "invalid_flow_classes", path);
        result |= bit;
    }
    return result;
}
static int lookup(const struct steer_spec_plan *p, enum steer_spec_node_kind kind, const char *id) {
    uint32_t i;
    for (i = 0; i < p->summary.nodes; i++) if (p->nodes[i].kind == kind && !strcmp(p->nodes[i].id, id)) return (int)i;
    return -1;
}
static int requirement(struct steer_spec_plan *p, const char *name, const char *path, const struct ynode *options) {
    struct requirement *r; const struct steer_spec_capability *cap = NULL; size_t i;
    if (p->summary.requirements == REQUIREMENTS) { diagnostic(p, 0, "requirement_limit", path); return 0; }
    for (i = 0; i < p->inventory_count; i++) if (!strcmp(p->inventory[i].name, name)) { cap = &p->inventory[i]; break; }
    r = &p->requirements[p->summary.requirements++]; copy(r->name, sizeof(r->name), name); copy(r->path, sizeof(r->path), path);
    r->owner_node=p->requirement_owner;
    r->state = cap ? cap->state : 0;
    if ((r->state & STEER_SPEC_READY) != STEER_SPEC_READY) diagnostic(p, 2, "capability_unavailable", path);
    if (options && (!cap || !cap->validate_options)) { diagnostic(p, 2, "provider_options_unvalidated", path); return 0; }
    if (options && !cap->validate_options(cap->context, options)) { diagnostic(p, 0, "invalid_provider_options", path); return 0; }
    return 1;
}
static void edge(struct steer_spec_plan *p, uint32_t source, enum steer_spec_node_kind target,
                 const struct ynode *reference, enum steer_spec_edge_kind kind, uint32_t required,
                 int dependency, const char *path) {
    struct edge *e; char id[64];
    if (!named(p, reference, id, path)) return;
    if (p->summary.edges == STEER_SPEC_MAX_EDGES) { diagnostic(p, 0, "edge_limit", path); return; }
    e = &p->edges[p->summary.edges++]; e->source = source; e->target = UINT32_MAX;
    e->target_kind = target; e->kind = kind; e->flows = required; e->dependency = dependency;
    copy(e->id, sizeof(e->id), id); copy(e->path, sizeof(e->path), path);
}
static void reference(struct steer_spec_plan *p, uint32_t source, enum steer_spec_node_kind target,
                      const struct ynode *object, const char *field_name,
                      enum steer_spec_edge_kind kind, uint32_t required, int dependency) {
    const struct ynode *v = ynode_get(object, field_name); char path[192];
    if (!v) return;
    path_at(path, p->nodes[source].path, field_name); edge(p, source, target, v, kind, required, dependency, path);
}
static void collect(struct steer_spec_plan *p, enum steer_spec_node_kind kind, const struct ynode *map, const char *path) {
    size_t i;
    if (!map) return;
    if (map->kind != YN_MAP || map->tag) { diagnostic(p, 0, "expected_object", path); return; }
    for (i = 0; i < map->len; i++) {
        const struct ynode *key = ynode_key_at(map, i); struct node *node; char at[192];
        path_at(at, path, key->str);
        if (!identifier(key->str)) { diagnostic(p, 0, "invalid_identifier", at); continue; }
        if (p->summary.nodes == STEER_SPEC_MAX_NODES) { diagnostic(p, 0, "node_limit", path); return; }
        node = &p->nodes[p->summary.nodes++]; node->kind = kind;
        copy(node->id, sizeof(node->id), key->str); copy(node->path, sizeof(node->path), at);
        node->intent = ynode_val_at(map, i); node->enabled = 1;
        node->flows = STEER_SPEC_FLOW_STREAM;
    }
}
static int list_text(struct steer_spec_plan *p, const struct ynode *list, const char *path, size_t limit) {
    size_t i;
    if (!list || list->kind != YN_SEQ || list->len > limit || list->tag) { diagnostic(p, 0, "invalid_string_list", path); return 0; }
    for (i = 0; i < list->len; i++) if (!text(ynode_at(list, i))) { diagnostic(p, 0, "expected_string", path); return 0; }
    return 1;
}
static void common_node(struct steer_spec_plan *p, uint32_t index) {
    struct node *node = &p->nodes[index]; const struct ynode *n = node->intent, *v;
    char at[192];
    path_at(at, node->path, "enabled"); node->enabled = boolean(p, ynode_get(n, "enabled"), 1, at);
    node->options = ynode_get(n, "options");
    v = ynode_get(n, "label"); if (v && (!text(v) || v->len > 128)) diagnostic(p, 0, "invalid_label", node->path);
    path_at(at, node->path, "flow"); node->flows = flows(p, ynode_get(n, "flow"), node->flows, at);
}
static void secret_references(struct steer_spec_plan *p, uint32_t index, const struct ynode *n, const char *path, unsigned depth) {
    size_t i;
    if (!n || depth > 64) return;
    if (n->kind == YN_MAP) {
        const struct ynode *secret = ynode_get(n, "secret");
        if (secret) {
            if (n->len != 1) diagnostic(p, 0, "invalid_secret_reference", path);
            edge(p, index, STEER_SPEC_SECRET, secret, STEER_SPEC_REFERENCE, 0, 1, path);
            return;
        }
        for (i = 0; i < n->len; i++) {
            char at[192]; path_at(at, path, ynode_key_at(n, i)->str);
            secret_references(p, index, ynode_val_at(n, i), at, depth + 1);
        }
    } else if (n->kind == YN_SEQ) {
        for (i = 0; i < n->len; i++) secret_references(p, index, ynode_at(n, i), path, depth + 1);
    }
}
static void transport_security(struct steer_spec_plan *p, uint32_t index, char transport[32], char security[32]) {
    struct node *node = &p->nodes[index]; const struct ynode *n, *type, *v; char at[192], cap[384];
    copy(transport, 32, "tcp"); copy(security, 32, "none");
    n = ynode_get(node->intent, "transport");
    if (n && keys(p, n, "type path headers service_name idle_timeout max_streams", node->path)) {
        type = field(p, n, "type", node->path, 1);
        if (!text(type) || (strcmp(type->str, "tcp") && strcmp(type->str, "udp") && strcmp(type->str, "ws") &&
            strcmp(type->str, "http2") && strcmp(type->str, "quic"))) diagnostic(p, 0, "unknown_transport", node->path);
        else copy(transport, 32, type->str);
        v = ynode_get(n, "headers");
        if (v) {
            size_t i;
            if (v->kind != YN_MAP || v->len > 128) diagnostic(p, 0, "invalid_headers", node->path);
            else for (i = 0; i < v->len; i++) if (!text(ynode_val_at(v, i)) || ynode_val_at(v, i)->len > 4096)
                diagnostic(p, 0, "invalid_header_value", node->path);
        }
        v = ynode_get(n, "path"); if (v && (!text(v) || v->len > 4096)) diagnostic(p, 0, "invalid_transport_path", node->path);
        if (node->enabled) { snprintf(cap, sizeof(cap), "core.transport.%s", transport); requirement(p, cap, node->path, NULL); }
    }
    n = ynode_get(node->intent, "security");
    if (n && keys(p, n, "type server_name verify utls alpn certificate private_key", node->path)) {
        type = field(p, n, "type", node->path, 1);
        if (!text(type) || (strcmp(type->str, "none") && strcmp(type->str, "tls") && strcmp(type->str, "reality")))
            diagnostic(p, 0, "unknown_security", node->path);
        else copy(security, 32, type->str);
        v = ynode_get(n, "server_name"); if (v && (!text(v) || v->len > 253)) diagnostic(p, 0, "invalid_server_name", node->path);
        path_at(at, node->path, "security.verify");
        if (!boolean(p, ynode_get(n, "verify"), 1, at) && node->enabled)
            requirement(p, "core.security.insecure.authorized", at, NULL);
        v = ynode_get(n, "alpn"); if (v) list_text(p, v, node->path, 16);
        v = ynode_get(n, "utls");
        if (v) {
            if (!text(v) || !identifier(v->str)) diagnostic(p, 0, "invalid_utls_profile", node->path);
            else if (node->enabled) { snprintf(cap, sizeof(cap), "core.tls.utls.%s", v->str); requirement(p, cap, node->path, NULL); }
        }
        secret_references(p, index, n, node->path, 0);
        if (node->enabled) { snprintf(cap, sizeof(cap), "core.security.%s", security); requirement(p, cap, node->path, NULL); }
    }
}
static void endpoint(struct steer_spec_plan *p, uint32_t index, const struct ynode *n) {
    const struct ynode *address, *resolver; uint8_t bytes[16];
    if (!n || !keys(p, n, "address port resolve_via", p->nodes[index].path)) return;
    address = field(p, n, "address", p->nodes[index].path, 1);
    if (!text(address) || address->len > 253) diagnostic(p, 0, "invalid_endpoint_address", p->nodes[index].path);
    unsigned_value(p, field(p, n, "port", p->nodes[index].path, 1), 1, 65535, p->nodes[index].path);
    resolver = ynode_get(n, "resolve_via");
    if (resolver) reference(p, index, STEER_SPEC_DNS, n, "resolve_via", STEER_SPEC_BOOTSTRAP, 0, 1);
    else if (text(address) && inet_pton(AF_INET, address->str, bytes) != 1 && inet_pton(AF_INET6, address->str, bytes) != 1)
        diagnostic(p, 1, "explicit_bootstrap_required", p->nodes[index].path);
}
static void provider(struct steer_spec_plan *p, uint32_t index, const char *transport, const char *security) {
    struct node *node = &p->nodes[index]; const struct ynode *plugin = field(p, node->intent, "plugin", node->path, 1);
    const struct ynode *variant = ynode_get(node->intent, "variant"); char id[64], alias[64], cap[384];
    const char *colon; uint32_t bit; int validated = 1;
    if (!text(plugin) || plugin->len >= sizeof(node->provider) || !(colon = strchr(plugin->str, ':')) || strchr(colon + 1, ':')) {
        diagnostic(p, 0, "invalid_provider_reference", node->path); return;
    }
    if ((size_t)(colon - plugin->str) >= sizeof(id)) { diagnostic(p, 0, "invalid_provider_reference", node->path); return; }
    memcpy(id, plugin->str, (size_t)(colon - plugin->str)); id[colon - plugin->str] = 0; copy(alias, sizeof(alias), colon + 1);
    if (!identifier(id) || !identifier(alias)) { diagnostic(p, 0, "invalid_provider_reference", node->path); return; }
    copy(node->provider, sizeof(node->provider), plugin->str);
    if (lookup(p, STEER_SPEC_PLUGIN, alias) < 0) diagnostic(p, 1, "dangling_plugin_alias", node->path);
    /* Alias/module verification precedes provider preparation. Keep this in
     * typed IR rather than requiring an executor to parse provider spelling. */
    struct ynode alias_node={0};alias_node.kind=YN_SCALAR;alias_node.style=YS_DOUBLE;
    alias_node.str=alias;alias_node.len=strlen(alias);
    edge(p,index,STEER_SPEC_PLUGIN,&alias_node,STEER_SPEC_REFERENCE,0,1,node->path);
    if (variant && (!text(variant) || !identifier(variant->str))) diagnostic(p, 0, "invalid_provider_variant", node->path);
    node->options = field(p, node->intent, "options", node->path, 1);
    if (!node->options || node->options->kind != YN_MAP) diagnostic(p, 0, "expected_provider_options", node->path);
    secret_references(p, index, node->options, node->path, 0);
    if (!node->enabled) return;
    for (bit = 1; bit <= STEER_SPEC_FLOW_DEVICE; bit <<= 1) if (node->flows & bit) {
        snprintf(cap, sizeof(cap), "provider.%s/%s/%s/%s/%s/%s", node->provider,
            node->kind == STEER_SPEC_INBOUND ? "inbound" : "outbound",
            bit == 1 ? "stream" : bit == 2 ? "datagram" : "device", transport, security, text(variant) ? variant->str : "default");
        if (!requirement(p, cap, node->path, node->options)) validated = 0;
    }
    node->options_validated = validated;
}
static void flow_node(struct steer_spec_plan *p, uint32_t index) {
    struct node *node = &p->nodes[index]; const struct ynode *n = node->intent, *type, *plugin;
    char transport[32], security[32], cap[384];
    if (!keys(p, n, "label enabled plugin type flow listen device endpoint options transport security variant detour resolve_via strategy members probe interrupt_existing", node->path)) return;
    common_node(p, index); transport_security(p, index, transport, security);
    type = ynode_get(n, "type"); plugin = ynode_get(n, "plugin");
    if (!!type == !!plugin) { diagnostic(p, 0, "provider_or_builtin_required", node->path); return; }
    if (plugin) {
        if (node->kind == STEER_SPEC_INBOUND && node->flows == STEER_SPEC_FLOW_DEVICE) {
            const struct ynode *device = field(p, n, "device", node->path, 1), *name;
            keys(p, n, "label enabled plugin flow device options variant", node->path);
            if (device && keys(p, device, "name", node->path)) {
                name = field(p, device, "name", node->path, 1);
                if (!text(name) || !identifier(name->str)) diagnostic(p, 0, "invalid_device_name", node->path);
            }
            copy(transport, sizeof(transport), "device");
        } else {
            keys(p, n, node->kind == STEER_SPEC_INBOUND ?
                "label enabled plugin flow listen options transport security variant" :
                "label enabled plugin flow endpoint options transport security variant detour resolve_via", node->path);
            if (node->kind == STEER_SPEC_INBOUND && (node->flows & STEER_SPEC_FLOW_DEVICE))
                diagnostic(p, 0, "mixed_device_inbound", node->path);
        }
        provider(p, index, transport, security);
    }
    else if (!text(type)) diagnostic(p, 0, "invalid_builtin_type", node->path);
    else {
        copy(node->type, sizeof(node->type), type->str);
        if (node->kind == STEER_SPEC_INBOUND) {
            const struct ynode *options = ynode_get(n, "options");
            if (strcmp(type->str, "tun")) diagnostic(p, 0, "unknown_inbound_builtin", node->path);
            else {
                keys(p, n, "label enabled type flow device options", node->path);
                const struct ynode *device = field(p, n, "device", node->path, 1);
                if (device && keys(p, device, "name", node->path) && !text(field(p, device, "name", node->path, 1)))
                    diagnostic(p, 0, "invalid_device_name", node->path);
                if (options && keys(p, options, "stack auto_route strict_route addresses mtu", node->path)) {
                    const struct ynode *stack = field(p, options, "stack", node->path, 1); char at[192];
                    if (!text(stack) || (strcmp(stack->str, "mixed") && strcmp(stack->str, "system") && strcmp(stack->str, "userspace"))) diagnostic(p, 0, "unknown_tun_stack", node->path);
                    path_at(at, node->path, "options.auto_route"); boolean(p, ynode_get(options, "auto_route"), 0, at);
                    path_at(at, node->path, "options.strict_route"); boolean(p, ynode_get(options, "strict_route"), 0, at);
                    if (text(stack) && node->enabled) { snprintf(cap, sizeof(cap), "core.capture.tun.stack.%s", stack->str); requirement(p, cap, node->path, NULL); }
                } else diagnostic(p, 0, "tun_options_required", node->path);
                if (node->enabled) requirement(p, "core.capture.tun.packet_demux", node->path, NULL);
            }
        } else if (!strcmp(type->str, "group")) {
            const struct ynode *strategy = field(p, n, "strategy", node->path, 1), *members = field(p, n, "members", node->path, 1);
            size_t i, j;
            keys(p, n, "label enabled type flow strategy members probe interrupt_existing", node->path);
            if (!text(strategy) || (strcmp(strategy->str, "order") && strcmp(strategy->str, "latency") && strcmp(strategy->str, "manual") && strcmp(strategy->str, "balance") && strcmp(strategy->str, "failover"))) diagnostic(p, 0, "unknown_group_strategy", node->path);
            else if (node->enabled) { snprintf(cap, sizeof(cap), "core.group.%s", strategy->str); requirement(p, cap, node->path, NULL); }
            if (list_text(p, members, node->path, STEER_SPEC_MAX_NODES) && members->len) for (i = 0; i < members->len; i++) {
                for (j = 0; j < i; j++) if (!strcmp(ynode_at(members, i)->str, ynode_at(members, j)->str)) diagnostic(p, 0, "duplicate_group_member", node->path);
                edge(p, index, STEER_SPEC_OUTBOUND, ynode_at(members, i), STEER_SPEC_MEMBER, node->flows, 1, node->path);
            } else if (!members || !members->len) diagnostic(p, 0, "empty_group", node->path);
            if (ynode_get(n, "probe")) {
                const struct ynode *probe = ynode_get(n, "probe");
                if (keys(p, probe, "type url interval tolerance bootstrap", node->path)) {
                    const struct ynode *url = field(p, probe, "url", node->path, 1), *interval = field(p, probe, "interval", node->path, 1);
                    if (!text(url) || !text(interval)) diagnostic(p, 0, "invalid_group_probe", node->path);
                    reference(p, index, STEER_SPEC_DNS, probe, "bootstrap", STEER_SPEC_OBSERVE, 0, 0);
                    if (node->enabled) requirement(p, "core.group.probe.member_direct", node->path, NULL);
                }
            }
            boolean(p, ynode_get(n, "interrupt_existing"), 0, node->path);
        } else if (!strcmp(type->str, "ip-stack")) {
            keys(p, n, "label enabled type flow device", node->path);
            reference(p, index, STEER_SPEC_OUTBOUND, n, "device", STEER_SPEC_DETOUR, STEER_SPEC_FLOW_DEVICE, 1);
            if (!ynode_get(n, "device")) diagnostic(p, 0, "device_reference_required", node->path);
            if (node->enabled) requirement(p, "core.adapter.ip_stack", node->path, NULL);
        } else if (strcmp(type->str, "direct") && strcmp(type->str, "block")) diagnostic(p, 0, "unknown_outbound_builtin", node->path);
        else {
            keys(p, n, "label enabled type flow detour resolve_via", node->path);
            if (node->enabled) { snprintf(cap, sizeof(cap), "core.outbound.%s", type->str); requirement(p, cap, node->path, NULL); }
        }
    }
    if (node->kind == STEER_SPEC_INBOUND && ynode_get(n, "listen")) {
        const struct ynode *listen = ynode_get(n, "listen");
        if (keys(p, listen, "address port", node->path)) {
            const struct ynode *address = field(p, listen, "address", node->path, 1);
            if (!text(address)) diagnostic(p, 0, "invalid_bind_address", node->path);
            unsigned_value(p, field(p, listen, "port", node->path, 1), 1, 65535, node->path);
        }
    }
    if (ynode_get(n, "endpoint")) endpoint(p, index, ynode_get(n, "endpoint"));
    reference(p, index, STEER_SPEC_OUTBOUND, n, "detour", STEER_SPEC_DETOUR,
        !strcmp(transport, "udp") || !strcmp(transport, "quic") ? STEER_SPEC_FLOW_DATAGRAM : STEER_SPEC_FLOW_STREAM, 1);
    reference(p, index, STEER_SPEC_DNS, n, "resolve_via", STEER_SPEC_BOOTSTRAP, 0, 1);
}
static void resource_node(struct steer_spec_plan *p, uint32_t index, const struct ynode *remotes) {
    struct node *node = &p->nodes[index]; const struct ynode *n = node->intent, *v, *type; char cap[384];
    size_t i;
    if (node->kind == STEER_SPEC_PLUGIN) {
        if (!keys(p, n, "remote package version dependencies", node->path)) return;
        v = field(p, n, "remote", node->path, 1);
        if (!text(v) || !identifier(v->str)) diagnostic(p, 0, "invalid_remote_reference", node->path);
        else if (!ynode_get(remotes, v->str)) diagnostic(p, 1, "dangling_remote", node->path);
        if(text(v))node->resolved_remote=ynode_get(remotes,v->str);
        if (!text(field(p, n, "package", node->path, 1)) || !text(field(p, n, "version", node->path, 1)))
            diagnostic(p, 0, "invalid_package_constraint", node->path);
        v = ynode_get(n, "dependencies");
        if (v && list_text(p, v, node->path, STEER_SPEC_MAX_NODES)) for (i = 0; i < v->len; i++)
            edge(p, index, STEER_SPEC_PLUGIN, ynode_at(v, i), STEER_SPEC_REFERENCE, 0, 1, node->path);
        snprintf(cap, sizeof(cap), "plugin.lock.%s", node->id); requirement(p, cap, node->path, NULL);
    } else if (node->kind == STEER_SPEC_SECRET) {
        if (!keys(p, n, "source name kind", node->path)) return;
        type = field(p, n, "source", node->path, 1); v = field(p, n, "name", node->path, 1);
        if (!text(type) || (strcmp(type->str, "env") && strcmp(type->str, "store"))) diagnostic(p, 0, "unknown_secret_source", node->path);
        if (!text(v) || v->len > 128) diagnostic(p, 0, "invalid_secret_name", node->path);
        if (text(type)) { snprintf(cap, sizeof(cap), "core.secret.%s", type->str); requirement(p, cap, node->path, NULL); }
    } else if (node->kind == STEER_SPEC_USER) {
        if (!keys(p, n, "label enabled credentials", node->path)) return;
        common_node(p, index);
        v = field(p, n, "credentials", node->path, 1);
        if (!v || v->kind != YN_MAP || !v->len) diagnostic(p, 0, "invalid_credentials", node->path);
        secret_references(p, index, v, node->path, 0);
        if (node->enabled) requirement(p, "core.principal.verified_identity", node->path, NULL);
    } else if (node->kind == STEER_SPEC_RULE_SET) {
        if (!keys(p, n, "label enabled type domains cidrs url format download_via bootstrap refresh verify", node->path)) return;
        common_node(p, index); type = field(p, n, "type", node->path, 1);
        if (text(type) && !strcmp(type->str, "inline")) {
            v = ynode_get(n, "domains"); if (v) list_text(p, v, node->path, 4096);
            v = ynode_get(n, "cidrs"); if (v) list_text(p, v, node->path, 4096);
            if (!ynode_get(n, "domains") && !ynode_get(n, "cidrs")) diagnostic(p, 0, "empty_inline_rule_set", node->path);
            if (node->enabled) requirement(p, "core.ruleset.inline", node->path, NULL);
        } else if (text(type) && !strcmp(type->str, "remote")) {
            const struct ynode *format = field(p, n, "format", node->path, 1), *url = field(p, n, "url", node->path, 1);
            if (!text(url) || strncmp(url->str, "https://", 8) || strchr(url->str, '@')) diagnostic(p, 0, "invalid_ruleset_url", node->path);
            if (!text(format) || (strcmp(format->str, "srs") && strcmp(format->str, "json"))) diagnostic(p, 0, "unknown_ruleset_format", node->path);
            reference(p, index, STEER_SPEC_OUTBOUND, n, "download_via", STEER_SPEC_REFERENCE, STEER_SPEC_FLOW_STREAM, 1);
            reference(p, index, STEER_SPEC_DNS, n, "bootstrap", STEER_SPEC_BOOTSTRAP, 0, 1);
            if (node->enabled && text(format)) { snprintf(cap, sizeof(cap), "core.ruleset.remote.%s", format->str); requirement(p, cap, node->path, NULL); }
        } else diagnostic(p, 0, "unknown_ruleset_type", node->path);
    } else if (node->kind == STEER_SPEC_PROFILE) {
        const struct ynode *match;
        if (!keys(p, n, "label enabled match routing_default dns_default", node->path)) return;
        common_node(p, index); match = field(p, n, "match", node->path, 1);
        if (match && keys(p, match, "network_type", node->path)) {
            v = field(p, match, "network_type", node->path, 1);
            if (list_text(p, v, node->path, 32)) for (i = 0; i < v->len; i++) {
                const struct ynode *network = ynode_at(v, i);
                if (!identifier(network->str)) diagnostic(p, 0, "invalid_network_type", node->path);
                else if (node->enabled) { snprintf(cap, sizeof(cap), "core.profile.network.%s", network->str); requirement(p, cap, node->path, NULL); }
            }
        }
        reference(p, index, STEER_SPEC_OUTBOUND, n, "routing_default", STEER_SPEC_ROUTE_TARGET, 0, 0);
        reference(p, index, STEER_SPEC_DNS, n, "dns_default", STEER_SPEC_ROUTE_TARGET, 0, 0);
    }
}
static void dns_node(struct steer_spec_plan *p, uint32_t index) {
    struct node *node = &p->nodes[index]; const struct ynode *n = node->intent, *type, *v; char cap[384];
    uint32_t wire_flow = STEER_SPEC_FLOW_STREAM;
    if (!keys(p, n, "label enabled type endpoint url detour bootstrap strategy", node->path)) return;
    common_node(p, index); type = field(p, n, "type", node->path, 1);
    if (!text(type) || (strcmp(type->str, "local") && strcmp(type->str, "udp") && strcmp(type->str, "tcp") && strcmp(type->str, "https"))) {
        diagnostic(p, 0, "unknown_dns_transport", node->path); return;
    }
    copy(node->type, sizeof(node->type), type->str);
    v=ynode_get(n,"strategy");
    if(v&&dns_strategy(p,v,node->path)&&node->enabled)requirement(p,"core.dns.strategy",node->path,NULL);
    if (!strcmp(type->str, "udp")) wire_flow = STEER_SPEC_FLOW_DATAGRAM;
    if (ynode_get(n, "endpoint")) endpoint(p, index, ynode_get(n, "endpoint"));
    if (!strcmp(type->str, "https")) {
        v = field(p, n, "url", node->path, 1);
        if (!text(v) || strncmp(v->str, "https://", 8) || strchr(v->str, '@')) diagnostic(p, 0, "invalid_doh_url", node->path);
        if (!ynode_get(n, "bootstrap")) diagnostic(p, 1, "explicit_bootstrap_required", node->path);
    }
    reference(p, index, STEER_SPEC_OUTBOUND, n, "detour", STEER_SPEC_DNS_TRANSPORT, wire_flow, 1);
    reference(p, index, STEER_SPEC_DNS, n, "bootstrap", STEER_SPEC_BOOTSTRAP, 0, 1);
    if (node->enabled) { snprintf(cap, sizeof(cap), "core.dns.%s", type->str); requirement(p, cap, node->path, NULL); }
}
static uint32_t inbound_flows(struct steer_spec_plan *p, const struct ynode *match, const char *path) {
    const struct ynode *ids = ynode_get(match, "inbound"), *selected = ynode_get(match, "flow");
    uint32_t result = 0, i;
    if (ids && list_text(p, ids, path, STEER_SPEC_MAX_NODES)) {
        for (i = 0; i < ids->len; i++) {
            int found = lookup(p, STEER_SPEC_INBOUND, ynode_at(ids, i)->str);
            if (found >= 0) result |= p->nodes[found].flows;
            edge(p, UINT32_MAX, STEER_SPEC_INBOUND, ynode_at(ids, i), STEER_SPEC_REFERENCE, 0, 0, path);
        }
    } else for (i = 0; i < p->summary.nodes; i++) if (p->nodes[i].kind == STEER_SPEC_INBOUND && p->nodes[i].enabled) result |= p->nodes[i].flows;
    if (selected) result &= flows(p, selected, 0, path);
    return result;
}
static void rules(struct steer_spec_plan *p, const struct ynode *list, int dns, const char *base) {
    size_t i, j; uint32_t begin = p->rule_count;
    if (!list || list->kind != YN_SEQ || list->len > RULES || list->tag) { diagnostic(p, 0, "invalid_rule_list", base); return; }
    for (i = 0; i < list->len; i++) {
        const struct ynode *n = ynode_at(list, i), *match, *action, *name, *target, *v;
        struct rule *rule; char position[32], path[192], at[192], cap[384]; int enabled;
        snprintf(position, sizeof(position), "%zu", i); path_at(path, base, position);
        if (!keys(p, n, "name enabled match action outbound server strategy cache_timeout", path)) continue;
        if (p->rule_count == RULES) { diagnostic(p, 0, "rule_limit", path); return; }
        rule = &p->rules[p->rule_count++]; copy(rule->path, sizeof(rule->path), path); rule->dns = dns;
        name = field(p, n, "name", path, 1); named(p, name, rule->id, path);
        for (j = begin; j + 1 < p->rule_count; j++) if (!strcmp(p->rules[j].id, rule->id)) diagnostic(p, 0, "duplicate_rule_name", path);
        enabled = boolean(p, ynode_get(n, "enabled"), 1, path);
        rule->enabled = enabled;
        match = field(p, n, "match", path, 1); rule->match = match;
        if (match && keys(p, match, "inbound user flow domain domain_suffix cidr rule_set network_type protocol port", path)) {
            static const char *lists[] = {"user", "domain", "domain_suffix", "cidr", "rule_set", "network_type", "protocol"};
            size_t k;
            for (k = 0; k < sizeof(lists)/sizeof(lists[0]); k++) {
                v = ynode_get(match, lists[k]); if (v) list_text(p, v, path, 4096);
            }
            v = ynode_get(match, "rule_set");
            if (v && v->kind == YN_SEQ) for (j = 0; j < v->len; j++) edge(p, UINT32_MAX, STEER_SPEC_RULE_SET, ynode_at(v, j), STEER_SPEC_REFERENCE, 0, 0, path);
            v = ynode_get(match, "user");
            if (v && v->kind == YN_SEQ) for (j = 0; j < v->len; j++) edge(p, UINT32_MAX, STEER_SPEC_USER, ynode_at(v, j), STEER_SPEC_REFERENCE, 0, 0, path);
            rule->flows = inbound_flows(p, match, path);
            if (enabled) for (k = 0; k < match->len; k++) {
                snprintf(cap, sizeof(cap), "core.classifier.%s", ynode_key_at(match, k)->str);
                requirement(p, cap, path, NULL);
            }
        }
        action = ynode_get(n, "action");
        if (!action) copy(rule->action, sizeof(rule->action), dns ? "resolve" : "route");
        else if (!text(action)) diagnostic(p, 0, "invalid_rule_action", path);
        else copy(rule->action, sizeof(rule->action), action->str);
        if (!strcmp(rule->action, "route")) {
            if (dns) diagnostic(p, 0, "invalid_dns_rule_action", path);
            target = field(p, n, "outbound", path, 1);
            if (named(p, target, rule->target, path)) edge(p, UINT32_MAX, STEER_SPEC_OUTBOUND, target, STEER_SPEC_ROUTE_TARGET, rule->flows, 0, path);
        } else if (!strcmp(rule->action, "resolve") || !strcmp(rule->action, "hijack_dns")) {
            target = field(p, n, "server", path, 1);
            if (named(p, target, rule->target, path)) edge(p, UINT32_MAX, STEER_SPEC_DNS, target, STEER_SPEC_ROUTE_TARGET, 0, 0, path);
        } else if (strcmp(rule->action, "sniff") && strcmp(rule->action, "reject")) diagnostic(p, 0, "unknown_rule_action", path);
        if (enabled) { snprintf(cap, sizeof(cap), "core.%s.action.%s", dns ? "dns" : "routing", rule->action); requirement(p, cap, path, NULL); }
        path_at(at, path, "strategy"); v = ynode_get(n, "strategy");
        rule->strategy = v; rule->cache_timeout = ynode_get(n, "cache_timeout");
        if(v){
            if(strcmp(rule->action,"resolve")&&strcmp(rule->action,"hijack_dns"))diagnostic(p,0,"strategy_requires_dns_action",at);
            if(dns_strategy(p,v,at)&&enabled)requirement(p,"core.dns.strategy",at,NULL);
        }
        v=rule->cache_timeout;path_at(at,path,"cache_timeout");
        if(v){
            if(!dns||strcmp(rule->action,"resolve"))diagnostic(p,0,"cache_timeout_requires_dns_resolve",at);
            if(cache_duration(p,v,at)&&enabled)requirement(p,"core.dns.rule.cache_timeout",at,NULL);
        }
    }
}
static int dependency_cycle(struct steer_spec_plan *p, uint32_t node, unsigned char *marks) {
    uint32_t i;
    if (marks[node] == 1) return 1;
    if (marks[node] == 2) return 0;
    marks[node] = 1;
    for (i = 0; i < p->summary.edges; i++) {
        struct edge *e = &p->edges[i];
        if (e->source == node && e->dependency && e->target != UINT32_MAX &&
            dependency_cycle(p, e->target, marks)) { diagnostic(p, 1, "dependency_cycle", e->path); return 1; }
    }
    marks[node] = 2; return 0;
}
static void resolve(struct steer_spec_plan *p) {
    uint32_t i; unsigned char marks[STEER_SPEC_MAX_NODES] = {0};
    for (i = 0; i < p->summary.edges; i++) {
        struct edge *e = &p->edges[i]; int target = lookup(p, e->target_kind, e->id);
        if (target < 0) { diagnostic(p, 1, "dangling_reference", e->path); continue; }
        e->target = (uint32_t)target;
        if (!p->nodes[target].enabled) diagnostic(p, 1, "disabled_reference_target", e->path);
        if (e->flows && (p->nodes[target].flows & e->flows) != e->flows) diagnostic(p, 1, "flow_type_mismatch", e->path);
    }
    for (i = 0; i < p->summary.nodes; i++) if (!marks[i]) (void)dependency_cycle(p, i, marks);
}
struct steer_spec_plan *steer_spec_compile(const char *source, size_t length,
    const struct steer_spec_capability *inventory, size_t inventory_count) {
    struct steer_spec_plan *p = calloc(1, sizeof(*p)); struct err error = {0};
    const struct ynode *root, *routing, *dns, *remotes, *v; long version; uint32_t i; size_t j;
    if (!p) return NULL;
    p->requirement_owner=UINT32_MAX;
    p->summary.syntax_valid = p->summary.topology_valid = p->summary.runtime_ready = 1;
    if (!source || !length || length > STEER_SPEC_MAX_BYTES || (!inventory && inventory_count)) {
        diagnostic(p, 0, "invalid_input_bounds", "$ "); return p;
    }
    p->source = malloc(length + 1);
    if (!p->source) { free(p); return NULL; }
    memcpy(p->source, source, length); p->source[length] = 0; p->source_length = length;
    p->inventory = inventory; p->inventory_count = inventory_count;
    p->document = ydoc_parse_buf(source, length, "spec", &error);
    if (!p->document) { diagnostic(p, 0, "parse_error", "$"); return p; }
    root = ydoc_root(p->document);
    if (!keys(p, root, "version plugin_remotes plugins inbounds outbounds routing secrets users dns rule_sets profiles", "$")) return p;
    v = field(p, root, "version", "$", 1);
    if (!v || v->tag || ynode_long(v, &version) || version != 3) diagnostic(p, 0, "unsupported_spec_version", "$.version");
    remotes = field(p, root, "plugin_remotes", "$", 1);
    if (!remotes || remotes->kind != YN_MAP) diagnostic(p, 0, "expected_object", "$.plugin_remotes");
    else for (j = 0; j < remotes->len; j++) {
        const struct ynode *r = ynode_val_at(remotes, j), *url, *trust; char path[192];
        path_at(path, "$.plugin_remotes", ynode_key_at(remotes, j)->str);
        if (!identifier(ynode_key_at(remotes, j)->str)) diagnostic(p, 0, "invalid_identifier", path);
        if (!keys(p, r, "url trust", path)) continue;
        url = field(p, r, "url", path, 1); trust = field(p, r, "trust", path, 1);
        if (!text(url) || strncmp(url->str, "https://", 8) || strchr(url->str, '@') || strchr(url->str, '#') || !text(trust)) diagnostic(p, 0, "invalid_remote_identity", path);
    }
    collect(p, STEER_SPEC_PLUGIN, field(p, root, "plugins", "$", 1), "$.plugins");
    collect(p, STEER_SPEC_INBOUND, field(p, root, "inbounds", "$", 1), "$.inbounds");
    collect(p, STEER_SPEC_OUTBOUND, field(p, root, "outbounds", "$", 1), "$.outbounds");
    collect(p, STEER_SPEC_SECRET, ynode_get(root, "secrets"), "$.secrets");
    collect(p, STEER_SPEC_USER, ynode_get(root, "users"), "$.users");
    collect(p, STEER_SPEC_RULE_SET, ynode_get(root, "rule_sets"), "$.rule_sets");
    collect(p, STEER_SPEC_PROFILE, ynode_get(root, "profiles"), "$.profiles");
    dns = ynode_get(root, "dns");
    if (dns && keys(p, dns, "servers rules default strategy reverse_mapping cache", "$.dns")) {
        v=ynode_get(dns,"strategy");
        if(v&&dns_strategy(p,v,"$.dns.strategy"))requirement(p,"core.dns.strategy","$.dns.strategy",NULL);
        v=ynode_get(dns,"reverse_mapping");
        if(v&&boolean(p,v,0,"$.dns.reverse_mapping"))requirement(p,"core.dns.reverse_mapping","$.dns.reverse_mapping",NULL);
        v=ynode_get(dns,"cache");
        if(v){
            if(v->kind==YN_MAP){
                if(keys(p,v,"capacity persistent","$.dns.cache")){
                    unsigned_value(p,field(p,v,"capacity","$.dns.cache",1),0,131072,"$.dns.cache.capacity");
                    if(boolean(p,ynode_get(v,"persistent"),0,"$.dns.cache.persistent"))
                        requirement(p,"core.dns.cache.persistent","$.dns.cache.persistent",NULL);
                }
            }else unsigned_value(p,v,0,131072,"$.dns.cache");
            requirement(p,"core.dns.cache","$.dns.cache",NULL);
        }
        collect(p, STEER_SPEC_DNS, field(p, dns, "servers", "$.dns", 1), "$.dns.servers");
        requirement(p, "core.dns.policy", "$.dns", NULL);
    }
    /* Parse flows before reference requirements; declaration order is irrelevant. */
    for (i = 0; i < p->summary.nodes; i++) {
        struct node *node = &p->nodes[i];
        node->flows = flows(p, ynode_get(node->intent, "flow"), STEER_SPEC_FLOW_STREAM, node->path);
    }
    for (i = 0; i < p->summary.nodes; i++) {
        enum steer_spec_node_kind kind = p->nodes[i].kind;
        p->requirement_owner=i;
        if (kind == STEER_SPEC_INBOUND || kind == STEER_SPEC_OUTBOUND) flow_node(p, i);
        else if (kind == STEER_SPEC_DNS) dns_node(p, i);
        else resource_node(p, i, remotes);
    }
    p->requirement_owner=UINT32_MAX;
    routing = field(p, root, "routing", "$", 1);
    if (routing && keys(p, routing, "rules default default_domain_resolver", "$.routing")) {
        uint32_t required = inbound_flows(p, NULL, "$.routing.default");
        v = field(p, routing, "default", "$.routing", 1);
        if (v) edge(p, UINT32_MAX, STEER_SPEC_OUTBOUND, v, STEER_SPEC_ROUTE_TARGET, required, 0, "$.routing.default");
        v = ynode_get(routing, "default_domain_resolver");
        if (v) edge(p, UINT32_MAX, STEER_SPEC_DNS, v, STEER_SPEC_ROUTE_TARGET, 0, 0, "$.routing.default_domain_resolver");
        rules(p, field(p, routing, "rules", "$.routing", 1), 0, "$.routing.rules");
    }
    if (dns) {
        v = field(p, dns, "default", "$.dns", 1);
        if (v) edge(p, UINT32_MAX, STEER_SPEC_DNS, v, STEER_SPEC_ROUTE_TARGET, 0, 0, "$.dns.default");
        v = ynode_get(dns, "rules"); if (v) rules(p, v, 1, "$.dns.rules");
    }
    requirement(p, "core.spec-v3.apply", "$", NULL);
    resolve(p);
    p->inventory = NULL; p->inventory_count = 0;
    return p;
}
struct steer_spec_summary steer_spec_summary(const struct steer_spec_plan *p) {
    struct steer_spec_summary none = {0}; return p ? p->summary : none;
}
int steer_spec_node(const struct steer_spec_plan *p, uint32_t i, struct steer_spec_node_view *out) {
    const struct node *n;
    if (!p || !out || i >= p->summary.nodes) return 0;
    n = &p->nodes[i]; out->kind = n->kind; out->id = n->id; out->path = n->path;
    out->type = n->type; out->provider = n->provider; out->flows = n->flows;
    out->options = n->options; out->options_validated = n->options_validated;
    out->enabled = n->enabled; out->intent = n->intent;out->resolved_remote=n->resolved_remote;
    out->listen = ynode_get(n->intent, "listen"); out->device = ynode_get(n->intent, "device");
    out->endpoint = ynode_get(n->intent, "endpoint"); out->transport = ynode_get(n->intent, "transport");
    out->security = ynode_get(n->intent, "security"); out->variant = ynode_get(n->intent, "variant"); return 1;
}
int steer_spec_edge(const struct steer_spec_plan *p, uint32_t i, struct steer_spec_edge_view *out) {
    const struct edge *e;
    if (!p || !out || i >= p->summary.edges) return 0;
    e = &p->edges[i]; out->kind = e->kind; out->source = e->source; out->target = e->target;
    out->required_flows = e->flows; out->path = e->path; out->construction_dependency = e->dependency; return 1;
}
int steer_spec_rule(const struct steer_spec_plan *p, uint32_t i, struct steer_spec_rule_view *out) {
    const struct rule *r;
    if (!p || !out || i >= p->rule_count) return 0;
    r = &p->rules[i]; out->id = r->id; out->path = r->path; out->action = r->action;
    out->target = r->target; out->match = r->match; out->flows = r->flows; out->dns_rule = r->dns;
    out->enabled = r->enabled; out->strategy = r->strategy; out->cache_timeout = r->cache_timeout; return 1;
}
int steer_spec_requirement(const struct steer_spec_plan *p, uint32_t i, struct steer_spec_requirement_view *out) {
    if (!p || !out || i >= p->summary.requirements) return 0;
    out->name = p->requirements[i].name; out->path = p->requirements[i].path; out->state = p->requirements[i].state;
    out->owner_node=p->requirements[i].owner_node; return 1;
}
const char *steer_spec_document(const struct steer_spec_plan *p, size_t *length) {
    if (!p || !length) return NULL;
    *length = p->source_length; return p->source;
}
const struct ynode *steer_spec_intent(const struct steer_spec_plan *p) {
    return p && p->document ? ydoc_root(p->document) : NULL;
}
void steer_spec_write_json(const struct steer_spec_plan *p, FILE *f) {
    uint32_t i;
    if (!p || !f) return;
    fprintf(f, "{\"syntax_valid\":%s,\"topology_valid\":%s,\"runtime_ready\":%s,\"nodes\":%u,\"edges\":%u,\"requirements\":[",
        p->summary.syntax_valid ? "true" : "false", p->summary.topology_valid ? "true" : "false",
        p->summary.runtime_ready ? "true" : "false", p->summary.nodes, p->summary.edges);
    for (i = 0; i < p->summary.requirements; i++) {
        const struct requirement *r = &p->requirements[i];
        if (i) fputc(',', f);
        fputs("{\"name\":", f); jsonw_str(f, r->name); fputs(",\"path\":", f); jsonw_str(f, r->path);
        fprintf(f, ",\"built\":%s,\"supported\":%s,\"available\":%s,\"authorized\":%s}",
            r->state & 1 ? "true" : "false", r->state & 2 ? "true" : "false",
            r->state & 4 ? "true" : "false", r->state & 8 ? "true" : "false");
    }
    fputs("],\"diagnostics\":[", f);
    for (i = 0; i < p->summary.diagnostics; i++) {
        const struct diagnostic *d = &p->diagnostics[i];
        if (i) fputc(',', f);
        fputs("{\"phase\":", f); jsonw_str(f, d->phase == 0 ? "syntax" : d->phase == 1 ? "topology" : "capability");
        fputs(",\"code\":", f); jsonw_str(f, d->code); fputs(",\"path\":", f); jsonw_str(f, d->path); fputc('}', f);
    }
    fputs("]}\n", f);
}
void steer_spec_destroy(struct steer_spec_plan *p) {
    if (!p) return;
    ydoc_free(p->document); free(p->source); free(p);
}
