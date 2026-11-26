/* SPDX-License-Identifier: GPL-3.0-only */
#include "hy2_datagram_backend_io.h"
#include "hy2_tcp_client.h"
#include <steer/draft/datagram_v1.h>

int steer_hy2_datagram_receive_attempt(struct steer_hy2_udp *udp, void *buffer,
    uint32_t capacity, uint32_t *status, uint32_t *bytes) {
    if (!udp || !buffer || !capacity || !status || !bytes) return 0;
    *bytes = 0;
    if (steer_hy2_udp_state(udp) != STEER_HY2_READY) {
        *status = STEER_PV1_IO;
        return 1;
    }
    ssize_t n = steer_hy2_udp_receive(udp, buffer, capacity);
    if (n == -2) return 0;
    if (n < 0) {
        /* Transport intentionally retains an undersized read. SDK requires
         * exactly one consume on RESOURCE_EXHAUSTED instead. */
        steer_hy2_udp_discard(udp);
        *status = STEER_PV1_RESOURCE_EXHAUSTED;
        return 1;
    }
    *status = STEER_PV1_OK;
    *bytes = (uint32_t)n; /* zero is a message, not EOF */
    return 1;
}
