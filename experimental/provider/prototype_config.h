#ifndef STEER_PROTOTYPE_CONFIG_H
#define STEER_PROTOTYPE_CONFIG_H
#include "policy.h"
#include <stddef.h>
#define STEER_PROTOTYPE_CONFIG_MAX_BYTES 65536u
#define STEER_PROTOTYPE_MAX_LISTENERS 16u
#define STEER_PROTOTYPE_MAX_RULES 128u
#define STEER_PROTOTYPE_SOCKS 1u
#define STEER_PROTOTYPE_VLESS 2u
#define STEER_PROTOTYPE_HYSTERIA2 3u
#define STEER_PROTOTYPE_AUTH_NONE 0u
#define STEER_PROTOTYPE_AUTH_USERPASS 1u
#define STEER_PROTOTYPE_AUTH_UUID 2u
#define STEER_PROTOTYPE_AUTH_PASSWORD 3u
#define STEER_STORE_FORMAT_PROTOTYPE 1u
#define STEER_STORE_FORMAT_SPEC_V3 3u
struct steer_prototype_listener {
    char id[65], address[46];
    uint16_t port;
    uint32_t protocol, auth;
    uint32_t enabled;
    uint32_t datagram_disabled; /* explicit v3 stream-only HY2; legacy defaults to enabled */
    char label[129];
    char principal_id[65], username_ref[100], password_ref[100], uuid_ref[100];
    char certificate_ref[100],private_key_ref[100]; /* env refs to PEM/DER file paths */
};
struct steer_prototype_stream_outbound {
    char id[65], uuid_ref[100], username_ref[100], password_ref[100];
    uint32_t protocol, endpoint_tag;
    uint8_t address[16];
    uint16_t port;
#ifdef STEER_PROTOTYPE_HY2
    char tls_name[254], ca_ref[100];
#endif
};
struct steer_prototype_config {
    uint64_t generation;
    uint32_t format;
    uint32_t listener_count;
    struct steer_prototype_listener listeners[STEER_PROTOTYPE_MAX_LISTENERS];
    uint32_t stream_outbound_count;
    struct steer_prototype_stream_outbound stream_outbounds[STEER_POLICY_STREAM_BINDINGS_MAX];
    struct steer_policy *policy;
    char *document_json;
    size_t document_length;
};
/* Immutable process startup policy, not part of intent or the durable store.
 * Each address has exactly one operator-provisioned credential pair. */
struct steer_prototype_socks_vpn_allowlist {
    unsigned count;
    struct {
        char address[46], username_ref[100], password_ref[100];
    } entries[STEER_PROTOTYPE_MAX_LISTENERS];
};
int steer_prototype_socks_vpn_allow(struct steer_prototype_socks_vpn_allowlist *,
    const char *address, const char *username_env, const char *password_env);
/* steer-linux-v1 or the linked v3 subset (optional HY2). YAML and JSON
 * through existing bounded ynode. Unknown fields/tags/duplicates fail closed.
 * Generation is host-owned, never read from document. All result data owned.
 * No credential values are read or logged: env:NAME references only.
 * Explicit numeric IPv4/IPv6 binds; 1..65535 ports. Caller resolves
 * refs and checks credentials before publication. Failures clear *out and expose
 * only error code (no raw parser message or secret-bearing document excerpt). */
struct steer_pv1_error steer_prototype_config_parse(const char *, size_t,
    uint64_t generation, struct steer_prototype_config **out);
struct steer_pv1_error steer_prototype_config_parse_with_vpn(const char *, size_t,
    uint64_t generation, const struct steer_prototype_socks_vpn_allowlist *,
    struct steer_prototype_config **out);
void steer_prototype_config_destroy(struct steer_prototype_config *);
#endif
