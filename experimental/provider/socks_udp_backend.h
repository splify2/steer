/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_SOCKS_UDP_BACKEND_H
#define STEER_SOCKS_UDP_BACKEND_H
#include "datagram_routes.h"
#include <netinet/in.h>
struct steer_socks_udp_backend;
/* NOAUTH, numeric IPv4 targets, loopback IPv4 upstream. Owner-loop only. */
struct steer_pv1_error steer_socks_udp_backend_create(struct loop *,struct steer_pv1_host *,
    const struct sockaddr_in *upstream,uint64_t generation,uint64_t token,
    uint32_t max_operations,uint64_t max_bytes,uint32_t max_references,
    unsigned drain_ms,void (*drained)(void *),void *,struct steer_socks_udp_backend **);
const struct steer_draft_datagram_binding *steer_socks_udp_backend_binding(const struct steer_socks_udp_backend *);
void steer_socks_udp_backend_retire(struct steer_socks_udp_backend *);
struct steer_pv1_error steer_socks_udp_backend_destroy(struct steer_socks_udp_backend *);
void steer_socks_udp_backend_usage(const struct steer_socks_udp_backend *,uint32_t *,uint64_t *);
#endif
