/* Один ответ VLESS, разные границы чтения. Время и транспорт локальны:
 * poll доводит часы до следующего куска или до конца запрошенного ожидания. */
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "client.h"

/* Событие: время от запроса и сколько байт ответа доступно к этому времени.
 * Последнее поле -1 означает конец потока. */
struct event { int at, end; };
static const struct event *events;
static int ms, start, part, opens, closes, live;
static const unsigned char response[] = {0, 2, 0x0a, 0, 'H'};

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts) {
    assert(clk == CLOCK_MONOTONIC);
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000L;
    return 0;
}

int __wrap_poll(struct pollfd *p, nfds_t n, int timeout) {
    assert(live && n == 1 && p->fd == 42 && timeout > 0);
    int next = start + events[part].at;
    if (ms + timeout >= next) {
        if (ms < next) ms = next;
        p->revents = POLLIN;
        return 1;
    }
    ms += timeout;
    p->revents = 0;
    return 0;
}

int transport_open(struct transport *t, const struct tr_node *node, int timeout) {
    (void)node;
    assert(!live && timeout == 1);
    live = 1;
    opens++;
    part = 0;
    t->link.fd = 42;
    return 0;
}
int transport_write(struct transport *t, const unsigned char *b, size_t len) {
    (void)t;
    assert(live && len > 26 && b[0] == 0);
    start = ms;
    return 0;
}
int transport_read(struct transport *t, unsigned char *b, size_t cap, size_t *got) {
    (void)t;
    assert(live && cap >= sizeof(response));
    *got = 0;
    if (ms < start + events[part].at) return 0;
    if (events[part].end < 0) return TR_ECLOSED;
    int offset = part ? events[part - 1].end : 0;
    *got = (size_t)(events[part].end - offset);
    memcpy(b, response + offset, *got);
    part++;
    return 0;
}
int transport_has_data(const struct transport *t) { (void)t; return 0; }
void transport_close(struct transport *t) {
    (void)t;
    assert(live);
    live = 0;
    closes++;
}
const char *transport_strerror(int rc) { (void)rc; return "transport"; }

static int run(const char *name, const struct event *seq, int expected, int attempts, int elapsed) {
    struct vless_node node = {.uuid = "00000000-0000-4000-8000-000000000001"};
    int ttfb;
    char why[128];
    ms = opens = closes = 0;
    events = seq;
    int rc = vless_probe_timed(&node, 1, why, sizeof(why), NULL, &ttfb);
    printf("%s: rc=%d ttfb=%d elapsed=%d opens=%d closes=%d\n",
           name, rc, ttfb, ms, opens, closes);
    return rc != expected || ttfb != 73 || ms != elapsed ||
           opens != attempts || closes != opens || live;
}

int main(void) {
    const struct event whole[] = {{73, 5}, {73, -1}};
    const struct event split[] = {{73, 1}, {300, 3}, {600, 5}, {600, -1}};
    const struct event eof[] = {{73, 1}, {300, -1}};
    /* Последний кусок позже срока от запроса, но раньше срока от первого байта. */
    const struct event late[] = {{73, 1}, {1020, 5}, {1020, -1}};
    int fail = run("whole", whole, 0, 1, 73);
    fail |= run("split", split, 0, 1, 600);
    /* Штатная повторная цель получает собственное соединение и бюджет. */
    fail |= run("eof", eof, TR_ECLOSED, 2, 600);
    fail |= run("timeout", late, TR_EIO, 2, 2000);
    return fail;
}
