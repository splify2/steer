/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_HY2_TCP_CLIENT_H
#define STEER_HY2_TCP_CLIENT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct steer_hy2_profile;
struct steer_hy2_tcp;
enum steer_hy2_state {
    STEER_HY2_OPENING, STEER_HY2_READY, STEER_HY2_FINISHED,
    STEER_HY2_UNAVAILABLE, STEER_HY2_REJECTED, STEER_HY2_TIMEOUT
};

/* Worker/startup only: read one bounded regular PEM file and parse trust
 * roots. Explicit TLS identity, numeric upstream, no insecure mode. Hand off
 * the result through a synchronized queue; subsequent calls are owner-only.
 * All error paths leave *out NULL. No remote packets during preparation. */
int steer_hy2_profile_prepare(uint64_t generation, const char *upstream,
    uint16_t port, const char *tls_name, const char *ca_path, const char *password,
    struct steer_hy2_profile **out);
void steer_hy2_profile_retire(struct steer_hy2_profile *);
/* NULL is a no-op. Returns -1 (without consuming) while any flow owns it. */
int steer_hy2_profile_destroy(struct steer_hy2_profile *);

/* Start TCP to an IPv4/IPv6 literal or wire DNS name (no local target lookup).
 * One QUIC connection per flow, bounded per profile. Times are monotonic ms.
 * Nonzero return means no flow, with no fallback. */
int steer_hy2_tcp_open(struct steer_hy2_profile *, uint64_t generation,
    const char *target, uint16_t port, uint64_t now, uint64_t deadline,
    struct steer_hy2_tcp **out);
int steer_hy2_tcp_fd(const struct steer_hy2_tcp *);
/* Owner drives UDP readability (including ERR/HUP), or timer expiry. Re-arm
 * after all calls that can change timing, including read/write/shutdown. */
int steer_hy2_tcp_timeout(struct steer_hy2_tcp *, uint64_t now);
void steer_hy2_tcp_drive(struct steer_hy2_tcp *, uint64_t now, int readable);
enum steer_hy2_state steer_hy2_tcp_state(const struct steer_hy2_tcp *);
size_t steer_hy2_tcp_room(const struct steer_hy2_tcp *);
/* read: byte count, 0 for FIN, -1 for terminal error, -2 for would-block.
 * write: bytes accepted (zero if full) or -1 for error. */
ssize_t steer_hy2_tcp_read(struct steer_hy2_tcp *, void *, size_t);
ssize_t steer_hy2_tcp_write(struct steer_hy2_tcp *, const void *, size_t);
int steer_hy2_tcp_shutdown_write(struct steer_hy2_tcp *);
/* Unwatch the UDP fd before destroy. Also cancels a pending open. */
void steer_hy2_tcp_destroy(struct steer_hy2_tcp *);
#endif
