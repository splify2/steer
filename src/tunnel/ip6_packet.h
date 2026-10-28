#ifndef STEER_IP6_PACKET_H
#define STEER_IP6_PACKET_H

#include <stddef.h>
#include <stdint.h>

struct ip6_packet {
    uint8_t src[16], dst[16], protocol, flags, wscale, ws_seen;
    uint16_t sport, dport, window;
    uint32_t seq, ack;
    size_t payload_offset, payload_length;
};

/* Parse one complete, non-fragmented IPv6 TCP/UDP packet. Unknown extension
 * semantics, jumbograms, mapped IPv4 addresses and invalid checksums fail
 * closed. */
int ip6_packet_parse(const uint8_t *packet, size_t length,
                     struct ip6_packet *result);

size_t ip6_tcp_build(uint8_t *out, size_t capacity,
                     const uint8_t src[16], const uint8_t dst[16],
                     uint16_t sport, uint16_t dport, uint32_t seq,
                     uint32_t ack, uint8_t flags, uint16_t window,
                     unsigned mss, int wscale, const uint8_t *payload,
                     size_t payload_length);

size_t ip6_udp_build(uint8_t *out, size_t capacity,
                     const uint8_t src[16], const uint8_t dst[16],
                     uint16_t sport, uint16_t dport,
                     const uint8_t *payload, size_t payload_length);

#endif
