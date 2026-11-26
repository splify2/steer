/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_HY2_DATAGRAM_BACKEND_IO_H
#define STEER_HY2_DATAGRAM_BACKEND_IO_H
#include <stdint.h>
struct steer_hy2_udp;
/* Owner-loop attempt for the SDK receive operation. Returns 0 when no message
 * is available and 1 when the operation must be completed with status/bytes.
 * The caller owns operation deadlines, buffer transfer and deferred callback. */
int steer_hy2_datagram_receive_attempt(struct steer_hy2_udp *, void *, uint32_t,
                                        uint32_t *status, uint32_t *bytes);
#endif
