/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_SOCKS_UDP_TRANSPORT_H
#define STEER_SOCKS_UDP_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
struct steer_socks_udp_transport;
#define STEER_SOCKS_UDP_MESSAGE_LIMIT 65000u
enum steer_socks_udp_state { SOCKS_UDP_CONNECTING, SOCKS_UDP_READY, SOCKS_UDP_FAILED };
/* Loop-owner API: NOAUTH only, IPv4 loopback upstream and numeric IPv4 target.
 * TCP control and UDP fd are owned until destroy. Never blocks or falls back. */
int steer_socks_udp_transport_open(const struct sockaddr_in *upstream,
    const struct sockaddr_in *target, struct steer_socks_udp_transport **);
int steer_socks_udp_transport_tcp_fd(const struct steer_socks_udp_transport *);
int steer_socks_udp_transport_udp_fd(const struct steer_socks_udp_transport *);
enum steer_socks_udp_state steer_socks_udp_transport_state(const struct steer_socks_udp_transport *);
int steer_socks_udp_transport_wants_write(const struct steer_socks_udp_transport *);
/* Drive on TCP readiness. After READY TCP stays watched for EOF/errors. */
void steer_socks_udp_transport_drive(struct steer_socks_udp_transport *);
/* 0 success, -2 temporary backpressure/no packet, -1 terminal,
 * -3 consumed oversized datagram. Receive length 0 is a valid datagram. */
int steer_socks_udp_transport_send(struct steer_socks_udp_transport *,const uint8_t *,size_t);
int steer_socks_udp_transport_receive(struct steer_socks_udp_transport *,uint8_t *,size_t,size_t *);
void steer_socks_udp_transport_destroy(struct steer_socks_udp_transport *);
#endif
