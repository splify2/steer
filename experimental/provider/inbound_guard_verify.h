#ifndef STEER_INBOUND_GUARD_VERIFY_H
#define STEER_INBOUND_GUARD_VERIFY_H
#include <stddef.h>
#include <stdint.h>
/* Read-only snapshot comparison for the single-peer IPv4 /32, empty-policy,
 * default-DIRECT inbound profile. Caller provides a bounded snapshot and a
 * trusted plan derived from the configuration/owned record, not a prior dump.
 * Not a recovery verifier: no kernel ownership, peer or atomicity attestation.
 * Returns zero on exact supported geometry, otherwise positive errno. */
struct steer_inbound_guard_plan {
    const char *table, *marker, *peer_ipv4;
    uint64_t table_handle;
    unsigned ifindex;
};
#define STEER_INBOUND_GUARD_SNAPSHOT_MAX (64u * 1024u)
int steer_inbound_guard_verify(const void *,size_t,const struct steer_inbound_guard_plan *);
#endif
