/* Internal table result transport; the tabfmt stream itself is unchanged. */
#ifndef STEER_TABLE_ACK_H
#define STEER_TABLE_ACK_H
#include <stddef.h>
#include <stdint.h>
#define TABLE_ACK_SIZE 9u
#define TABLE_ACK_WINDOW_MAX 128u
struct table_ack_reader {
    uint8_t bytes[TABLE_ACK_SIZE];
    size_t used;
    uint64_t next;
};
struct table_ack_window {
    struct { uint64_t seq, fingerprint; } pending[TABLE_ACK_WINDOW_MAX];
    uint64_t sent, confirmed_fingerprint;
    unsigned head,count;
    int confirmed;
};
/* One deferred desire; its content is re-read from the current spec. */
struct table_ack_dispatch { int pending, force; };
enum table_ack_decision { TABLE_ACK_NOOP, TABLE_ACK_SEND, TABLE_ACK_DEFER };
enum table_ack_decision table_ack_dispatch_decide(struct table_ack_dispatch *,
    const struct table_ack_window *, uint64_t fingerprint, int force);
void table_ack_dispatch_done(struct table_ack_dispatch *);
int table_ack_window_ready(const struct table_ack_window *);
uint64_t table_ack_window_push(struct table_ack_window *,uint64_t fingerprint);
int table_ack_window_settle(struct table_ack_window *,uint64_t seq,int status);
int table_ack_window_matches(const struct table_ack_window *,uint64_t fingerprint);
int table_ack_is_socket(int fd);
/* Reset on every newly attached fd; pipes are deliberately receive-only. */
void table_ack_reset(int fd);
/* rc is 1 (accepted) or 2 (rejected). On nonblocking send failure the
 * socket is shut down: a partial record must never shift later records. */
int table_ack_emit(int fd,int rc);
/* Parse fixed-size, big-endian sequence plus status; strict 1..N per fd.
 * Returns complete count or -1 on malformed/out-of-order/overflow. */
int table_ack_read(struct table_ack_reader *,const uint8_t *,size_t,
                   void (*)(void *,uint64_t,int),void *);
#endif
