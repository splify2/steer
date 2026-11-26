/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_EXPERIMENTAL_SOCKS_DATAGRAM_H
#define STEER_EXPERIMENTAL_SOCKS_DATAGRAM_H
#include "hy2_datagram.h"
#include "codec.h"
#include <netinet/in.h>

struct steer_socks_datagram;
/* All calls and callbacks are serialized on services.loop. The caller owns and
 * pins the admitted generation until destroy succeeds. acquire must return that
 * generation; an unexpected generation is released and denied. authorize runs
 * for EVERY valid packet before any target is opened or reused; it must evaluate
 * the immutable admitted policy, and return zero only for a permitted target.
 * The TCP owner calls stop on control EOF or generation retirement. */
struct steer_socks_datagram_config {
    struct steer_pv1_span inbound, principal;
    struct sockaddr_in tcp_peer;
    struct s5_address requested_peer;
    uint64_t generation, admission_epoch, idle_ms;
    void *user;
    int (*authorize)(void *, const struct s5_address *);
    void (*wake)(void *); /* schedule owner turn, never destroy inline */
};
int steer_socks_datagram_open(const struct steer_socks_datagram_config *,
    const struct steer_draft_hy2_datagram_services *, struct steer_socks_datagram **,
    struct s5_address *bound);
void steer_socks_datagram_stop(struct steer_socks_datagram *);
/* Returns -1 while asynchronous callbacks/refs are still draining. */
int steer_socks_datagram_destroy(struct steer_socks_datagram *);
#endif
