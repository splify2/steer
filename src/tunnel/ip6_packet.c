#include "ip6_packet.h"

#include <string.h>

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read32(const uint8_t *p) {
    return ((uint32_t)read16(p) << 16) | read16(p + 2);
}

static void write16(uint8_t *p, uint16_t n) {
    p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n;
}

static void write32(uint8_t *p, uint32_t n) {
    write16(p, (uint16_t)(n >> 16)); write16(p + 2, (uint16_t)n);
}

static int mapped4(const uint8_t *p) {
    for (unsigned i = 0; i < 10; i++) if (p[i]) return 0;
    return p[10] == 255 && p[11] == 255;
}

static uint32_t sum_bytes(const uint8_t *p, size_t n, uint32_t sum) {
    while (n >= 2) { sum += read16(p); p += 2; n -= 2; }
    if (n) sum += (uint32_t)*p << 8;
    return sum;
}

static uint16_t checksum(const uint8_t src[16], const uint8_t dst[16],
                         uint8_t protocol, const uint8_t *body, size_t n) {
    uint32_t sum = sum_bytes(src, 16, 0);
    sum = sum_bytes(dst, 16, sum);
    sum += (uint32_t)(n >> 16) + (uint32_t)(n & 65535) + protocol;
    sum = sum_bytes(body, n, sum);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

static int options(const uint8_t *p, size_t n) {
    size_t at = 2;
    while (at < n) {
        if (p[at] == 0) { at++; continue; }
        if (at + 2 > n || (size_t)p[at + 1] > n - at - 2) return -1;
        if (p[at] != 1) return -1;
        for (size_t j = 0; j < p[at + 1]; j++)
            if (p[at + 2 + j] != 0) return -1;
        at += 2 + p[at + 1];
    }
    return 0;
}

int ip6_packet_parse(const uint8_t *p, size_t n, struct ip6_packet *out) {
    if (!p || !out || n < 40 || (p[0] >> 4) != 6 || p[7] == 0) return -1;
    if (mapped4(p + 8) || mapped4(p + 24)) return -1;
    size_t declared = read16(p + 4);
    if (!declared || declared != n - 40) return -1;
    uint8_t next = p[6];
    size_t at = 40, headers = 0, extension_bytes = 0;
    while (next == 0 || next == 60) {
        if (++headers > 8 || at + 2 > n || (next == 0 && at != 40)) return -1;
        size_t bytes = ((size_t)p[at + 1] + 1) * 8;
        if (bytes > n - at || bytes > 256 - extension_bytes || options(p + at, bytes)) return -1;
        extension_bytes += bytes; next = p[at]; at += bytes;
    }
    if (next != 6 && next != 17) return -1;
    size_t transport = n - at;
    if (transport < (next == 6 ? 20u : 8u) ||
        checksum(p + 8, p + 24, next, p + at, transport) != 0) return -1;
    struct ip6_packet result = {0};
    memcpy(result.src, p + 8, 16); memcpy(result.dst, p + 24, 16);
    result.protocol = next; result.sport = read16(p + at);
    result.dport = read16(p + at + 2);
    size_t header = 8;
    if (next == 17) {
        if (read16(p + at + 4) != transport || read16(p + at + 6) == 0) return -1;
    } else {
        header = (size_t)(p[at + 12] >> 4) * 4;
        if (header < 20 || header > transport) return -1;
        result.seq = read32(p + at + 4); result.ack = read32(p + at + 8);
        result.flags = p[at + 13]; result.window = read16(p + at + 14);
        for (size_t option = 20; option < header;) {
            uint8_t kind = p[at + option];
            if (kind == 0) break;
            if (kind == 1) { option++; continue; }
            if (option + 2 > header) return -1;
            size_t bytes = p[at + option + 1];
            if (bytes < 2 || bytes > header - option) return -1;
            if (kind == 3) {
                if (bytes != 3 || result.ws_seen) return -1;
                if (result.flags & 2) {
                    result.ws_seen = 1;
                    result.wscale = p[at + option + 2] > 14 ? 14 : p[at + option + 2];
                }
            }
            option += bytes;
        }
    }
    result.payload_offset = at + header;
    result.payload_length = transport - header;
    *out = result;
    return 0;
}

static void header(uint8_t *out, const uint8_t src[16], const uint8_t dst[16],
                   uint8_t protocol, size_t transport) {
    memset(out, 0, 40); out[0] = 0x60;
    write16(out + 4, (uint16_t)transport); out[6] = protocol; out[7] = 64;
    memcpy(out + 8, src, 16); memcpy(out + 24, dst, 16);
}

size_t ip6_tcp_build(uint8_t *out, size_t cap,
                     const uint8_t src[16], const uint8_t dst[16],
                     uint16_t sport, uint16_t dport, uint32_t seq,
                     uint32_t ack, uint8_t flags, uint16_t window,
                     unsigned mss, int wscale, const uint8_t *payload, size_t n) {
    if (!out || !src || !dst || (!payload && n) || mss > 65535 || wscale < -1 || wscale > 14) return 0;
    if ((mss || wscale >= 0) && !(flags & 2)) return 0;
    size_t opts = (mss ? 4u : 0u) + (wscale >= 0 ? 4u : 0u), th = 20 + opts;
    if (n > 65535 - th || cap < 40 + th + n) return 0;
    if (n) memmove(out + 40 + th, payload, n);
    header(out, src, dst, 6, th + n); memset(out + 40, 0, th);
    uint8_t *t = out + 40;
    write16(t, sport); write16(t + 2, dport); write32(t + 4, seq); write32(t + 8, ack);
    t[12] = (uint8_t)((th / 4) << 4); t[13] = flags; write16(t + 14, window);
    size_t at = 20;
    if (mss) { t[at++] = 2; t[at++] = 4; write16(t + at, (uint16_t)mss); at += 2; }
    if (wscale >= 0) { t[at++] = 1; t[at++] = 3; t[at++] = 3; t[at] = (uint8_t)wscale; }
    write16(t + 16, checksum(out + 8, out + 24, 6, t, th + n));
    return 40 + th + n;
}

size_t ip6_udp_build(uint8_t *out, size_t cap,
                     const uint8_t src[16], const uint8_t dst[16],
                     uint16_t sport, uint16_t dport,
                     const uint8_t *payload, size_t n) {
    if (!out || !src || !dst || (!payload && n) || n > 65527 || cap < 48 + n) return 0;
    if (n) memmove(out + 48, payload, n);
    header(out, src, dst, 17, 8 + n);
    uint8_t *u = out + 40; memset(u, 0, 8);
    write16(u, sport); write16(u + 2, dport); write16(u + 4, (uint16_t)(8 + n));
    uint16_t value = checksum(out + 8, out + 24, 17, u, 8 + n);
    write16(u + 6, value ? value : 65535);
    return 48 + n;
}
