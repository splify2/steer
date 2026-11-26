/* SPDX-License-Identifier: GPL-3.0-only */
#define _POSIX_C_SOURCE 200809L
#include "hy2_tcp_client.h"
#include "hy2_datagram_backend_io.h"
#include <steer/draft/datagram_v1.h>
#include <assert.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void) {
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    assert(argc == 5);
    const char *token = getenv("STEER_LAB_HY2_TOKEN");
    struct steer_hy2_profile *profile = NULL;
    assert(!steer_hy2_profile_prepare(7, "127.0.0.1", (uint16_t)atoi(argv[1]),
                                       "localhost", argv[2], token, &profile));
    uint64_t now = now_ms(), deadline = now + 3000;
    struct steer_hy2_udp *f = NULL;
    const char *target = getenv("STEER_TEST_UDP_TARGET");
    if (!target) target = "127.0.0.1";
    assert(steer_hy2_udp_open(profile, 6, target, (uint16_t)atoi(argv[3]), now, deadline, &f) && !f);
    if (!strcmp(argv[4], "domain")) {
        assert(steer_hy2_udp_open(profile, 7, target, (uint16_t)atoi(argv[3]), now, deadline, &f) && !f);
        assert(!steer_hy2_profile_destroy(profile));
        puts("PASS domain");
        return 0;
    }
    assert(!steer_hy2_udp_open(profile, 7, target, (uint16_t)atoi(argv[3]), now, deadline, &f));
    assert(steer_hy2_profile_destroy(profile));
    struct pollfd p = { steer_hy2_udp_fd(f), POLLIN, 0 };
    int sent = 0, success = !strcmp(argv[4], "success");
    uint8_t tx[1000], rx[1000];
    for (size_t i = 0; i < sizeof tx; i++) tx[i] = (uint8_t)(i * 17u);
    uint64_t end = now + 7000;
    for (;;) {
        enum steer_hy2_state state = steer_hy2_udp_state(f);
        if (state == STEER_HY2_READY) {
            assert(success);
            if (!sent) {
                uint32_t status, bytes;
                assert(!steer_hy2_udp_test_inject(f, NULL, 0));
                assert(steer_hy2_datagram_receive_attempt(f, rx, sizeof rx, &status, &bytes));
                assert(status == STEER_PV1_OK && bytes == 0);
                assert(steer_hy2_udp_receive(f, rx, sizeof rx) == -2);
                assert(!steer_hy2_udp_test_inject(f, tx, sizeof tx));
                assert(steer_hy2_udp_receive(f, rx, 1) == -1);
                assert(steer_hy2_datagram_receive_attempt(f, rx, 1, &status, &bytes));
                assert(status == STEER_PV1_RESOURCE_EXHAUSTED && bytes == 0);
                assert(steer_hy2_udp_receive(f, rx, sizeof rx) == -2);
                assert(steer_hy2_udp_send(f, tx, 0) == 0);
                assert(steer_hy2_udp_send(f, tx, sizeof tx + 1) == -1);
                assert(!steer_hy2_udp_send(f, tx, sizeof tx));
                sent = 1;
            }
            ssize_t n = steer_hy2_udp_receive(f, rx, 1);
            if (n == -1) {
                n = steer_hy2_udp_receive(f, rx, sizeof rx);
                assert(n == (ssize_t)sizeof tx && !memcmp(tx, rx, sizeof tx));
                assert(steer_hy2_udp_receive(f, rx, sizeof rx) == -2);
                break;
            }
            assert(n == -2);
        } else if (state != STEER_HY2_OPENING) {
            assert(!success);
            if (!strcmp(argv[4], "no-udp")) assert(state == STEER_HY2_REJECTED);
            else if (!strcmp(argv[4], "timeout")) assert(state == STEER_HY2_TIMEOUT);
            else abort();
            assert(steer_hy2_udp_send(f, tx, sizeof tx) == -1);
            break;
        }
        now = now_ms(); assert(now < end);
        int timeout = steer_hy2_udp_timeout(f, now);
        if (timeout < 0 || timeout > 500) timeout = 500;
        assert(poll(&p, 1, timeout) >= 0);
        steer_hy2_udp_drive(f, now_ms(), p.revents != 0);
    }
    steer_hy2_profile_retire(profile);
    struct steer_hy2_udp *late = NULL;
    assert(steer_hy2_udp_open(profile, 7, target, (uint16_t)atoi(argv[3]),
                               now_ms(), now_ms() + 1000, &late) && !late);
    steer_hy2_udp_destroy(f);
    assert(!steer_hy2_profile_destroy(profile));
    printf("PASS %s\n", argv[4]);
    return 0;
}
