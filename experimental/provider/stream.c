#define _GNU_SOURCE
#include "stream.h"
#include "buffers.h"
#include "operations.h"
#include "loop.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#define STREAM_COMPLETION_BATCH 32u

struct io;
struct steer_draft_stream_runtime {
    struct loop *loop;
    int wake;
    struct steer_pv1_host *host;
    struct steer_draft_operations *operations;
    uint64_t bytes, max_bytes;
    uint32_t streams, max_streams, live;
    int dispatching;
};
struct steer_pv1_stream {
    struct steer_draft_stream_runtime *runtime;
    struct io *read, *write;
    uint32_t live;
    int fd, watching, write_closed;
};
struct io {
    struct steer_pv1_stream *stream;
    struct steer_pv1_operation_ref inner;
    struct steer_pv1_buffer *buffer;
    uint8_t *data;
    uint32_t length, bytes;
    steer_pv1_stream_done done;
    void *userdata;
    int writing, detached, completed;
};
static struct steer_pv1_error err(uint32_t c) {
    struct steer_pv1_error e = {c, 0}; return e;
}
static void ready(struct loop *, int, uint32_t, void *);
static void wake(struct steer_draft_stream_runtime *r) {
    uint64_t one = 1;
    ssize_t n;
    do { n = write(r->wake, &one, sizeof(one)); } while (n < 0 && errno == EINTR);
    /* EAGAIN means an unread wake already exists. All calls are same-shard. */
}
static int arm(struct steer_pv1_stream *s) {
    uint32_t events = 0;
    if (s->read && !s->read->detached) events |= EPOLLIN | EPOLLRDHUP;
    if (s->write && !s->write->detached) events |= EPOLLOUT;
    if (!events || s->fd < 0) {
        if (s->watching) loop_fd_del(s->runtime->loop, s->fd);
        s->watching = 0;
        return 0;
    }
    if (s->watching) return loop_fd_mod(s->runtime->loop, s->fd, events);
    if (loop_fd_add(s->runtime->loop, s->fd, events, ready, s)) return -1;
    s->watching = 1;
    return 0;
}
static void finish(struct io *io, uint32_t code, uint32_t bytes) {
    if (io->detached) return;
    io->detached = 1;
    io->bytes = bytes;
    io->stream->runtime->bytes -= io->length;
    (void)arm(io->stream);
    (void)steer_draft_operation_resolve(io->inner.handle, err(code));
    wake(io->stream->runtime);
}
static void attempt(struct io *io) {
    ssize_t n;
    if (!io || io->detached) return;
    do {
        n = io->writing ? send(io->stream->fd, io->data, io->length, MSG_NOSIGNAL) :
                         recv(io->stream->fd, io->data, io->length, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    finish(io, n < 0 ? STEER_PV1_IO : STEER_PV1_OK, n < 0 ? 0 : (uint32_t)n);
}
static void ready(struct loop *l, int fd, uint32_t events, void *arg) {
    struct steer_pv1_stream *s = arg;
    (void)l; (void)fd;
    if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) attempt(s->read);
    if (events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) attempt(s->write);
}
static void deliver(void *arg, struct steer_pv1_error e) {
    struct io *io = arg;
    struct steer_pv1_stream *s = io->stream;
    struct steer_pv1_buffer *b = io->buffer;
    if (io->writing) s->write = NULL; else s->read = NULL;
    io->buffer = NULL;
    io->done(io->userdata, e, b, io->bytes);
    io->completed = 1;
}
static void pump(struct loop *l, int fd, uint32_t events, void *arg) {
    struct steer_draft_stream_runtime *r = arg;
    uint64_t counter;
    uint32_t queued;
    ssize_t n;
    (void)l; (void)events;
    do { n = read(fd, &counter, sizeof(counter)); } while (n < 0 && errno == EINTR);
    r->dispatching = 1;
    (void)steer_draft_operations_dispatch(r->operations, STREAM_COMPLETION_BATCH, NULL);
    r->dispatching = 0;
    steer_draft_operations_usage(r->operations, NULL, &queued);
    if (queued) wake(r);
}
static void STEER_PV1_CALL cancel(struct steer_pv1_operation *op) {
    finish((struct io *)op, STEER_PV1_CANCELLED, 0);
}
static void STEER_PV1_CALL release_op(struct steer_pv1_operation *op) {
    struct io *io = (struct io *)op;
    if (!io->completed) return;
    io->inner.api->release(io->inner.handle);
    io->stream->live--;
    io->stream->runtime->live--;
    free(io);
}
static const struct steer_pv1_operation_api operation_api = {
    sizeof(struct steer_pv1_operation_api), STEER_PV1_DRAFT_LAYOUT, cancel, release_op
};
static struct steer_pv1_async_start start(struct steer_pv1_stream *s,
    struct steer_pv1_buffer *b, uint32_t offset, uint32_t length,
    steer_pv1_stream_done done, void *userdata, int writing) {
    struct steer_pv1_async_start a = {STEER_PV1_REJECTED, {STEER_PV1_INVALID,0}, {NULL,NULL}};
    struct steer_pv1_mut_span view;
    struct io *io;
    if (!s || !b || !done || !length) return a;
    if (s->fd < 0 || (writing && s->write_closed) || (writing ? s->write : s->read)) {
        a.error = err(STEER_PV1_POLICY_DENIED); return a;
    }
    a.error = steer_draft_buffers_api()->writable(s->runtime->host, b, &view);
    if (a.error.code) return a;
    a.error = err(STEER_PV1_INVALID);
    if (offset > view.len || length > view.len - offset) return a;
    a.error = err(STEER_PV1_RESOURCE_EXHAUSTED);
    if (length > s->runtime->max_bytes - s->runtime->bytes) return a;
    io = calloc(1, sizeof(*io));
    if (!io) return a;
    io->stream = s; io->buffer = b; io->data = view.data + offset;
    io->length = length; io->done = done; io->userdata = userdata; io->writing = writing;
    a = steer_draft_operation_start(s->runtime->operations, deliver, io);
    if (a.disposition != STEER_PV1_PENDING) { free(io); return a; }
    io->inner = a.operation;
    a.operation.handle = (struct steer_pv1_operation *)io;
    a.operation.api = &operation_api;
    s->live++; s->runtime->live++; s->runtime->bytes += length;
    if (writing) s->write = io; else s->read = io;
    attempt(io);
    if (!io->detached && arm(s)) finish(io, STEER_PV1_IO, 0);
    return a;
}
static struct steer_pv1_async_start STEER_PV1_CALL read_stream(struct steer_pv1_stream *s,
    struct steer_pv1_buffer *b, uint32_t o, uint32_t n, steer_pv1_stream_done d, void *u) {
    return start(s,b,o,n,d,u,0);
}
static struct steer_pv1_async_start STEER_PV1_CALL write_stream(struct steer_pv1_stream *s,
    struct steer_pv1_buffer *b, uint32_t o, uint32_t n, steer_pv1_stream_done d, void *u) {
    return start(s,b,o,n,d,u,1);
}
static struct steer_pv1_error STEER_PV1_CALL shutdown_stream(struct steer_pv1_stream *s) {
    if (!s) return err(STEER_PV1_INVALID);
    if (s->fd < 0 || s->write) return err(STEER_PV1_POLICY_DENIED);
    if (s->write_closed) return err(STEER_PV1_OK);
    if (shutdown(s->fd, SHUT_WR)) return err(STEER_PV1_IO);
    s->write_closed = 1; return err(STEER_PV1_OK);
}
static void STEER_PV1_CALL close_stream(struct steer_pv1_stream *s) {
    if (!s || s->fd < 0) return;
    if (s->watching) loop_fd_del(s->runtime->loop, s->fd);
    s->watching = 0;
    close(s->fd); s->fd = -1;
    if (s->read) finish(s->read, STEER_PV1_CANCELLED, 0);
    if (s->write) finish(s->write, STEER_PV1_CANCELLED, 0);
}
static struct steer_pv1_error STEER_PV1_CALL release_stream(struct steer_pv1_stream *s) {
    if (!s) return err(STEER_PV1_INVALID);
    if (s->fd >= 0 || s->live) return err(STEER_PV1_POLICY_DENIED);
    s->runtime->streams--; free(s); return err(STEER_PV1_OK);
}
static const struct steer_pv1_stream_api api = {
    sizeof(struct steer_pv1_stream_api), STEER_PV1_DRAFT_LAYOUT,
    read_stream, write_stream, shutdown_stream, close_stream, release_stream
};
const struct steer_pv1_stream_api *steer_draft_stream_api(void) { return &api; }
struct steer_pv1_error steer_draft_stream_runtime_create(struct loop *l,
    struct steer_pv1_host *h, uint32_t streams, uint32_t operations, uint64_t bytes,
    struct steer_draft_stream_runtime **out) {
    struct steer_draft_stream_runtime *r;
    struct steer_pv1_error e;
    if (out) *out = NULL;
    if (!l || !h || !out) return err(STEER_PV1_INVALID);
    r = calloc(1,sizeof(*r));
    if (!r) return err(STEER_PV1_RESOURCE_EXHAUSTED);
    e = steer_draft_operations_create(operations,NULL,&r->operations);
    if (e.code) { free(r); return e; }
    r->loop=l; r->host=h; r->max_streams=streams; r->max_bytes=bytes;
    r->wake=eventfd(0,EFD_NONBLOCK | EFD_CLOEXEC);
    if (r->wake < 0 || loop_fd_add(l,r->wake,EPOLLIN,pump,r)) {
        if (r->wake >= 0) close(r->wake);
        (void)steer_draft_operations_destroy(r->operations); free(r);
        return err(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    *out=r; return err(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_stream_runtime_destroy(struct steer_draft_stream_runtime *r) {
    if (!r) return err(STEER_PV1_INVALID);
    if (r->streams || r->live || r->dispatching) return err(STEER_PV1_POLICY_DENIED);
    loop_fd_del(r->loop,r->wake); close(r->wake);
    (void)steer_draft_operations_destroy(r->operations); free(r);
    return err(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_stream_adopt(struct steer_draft_stream_runtime *r,
    int fd, struct steer_pv1_stream **out) {
    struct steer_pv1_stream *s;
    int flags, type; socklen_t n=sizeof(type);
    struct sockaddr_storage peer; socklen_t pn=sizeof(peer);
    if (out) *out=NULL;
    if (!r || !out || fd < 0 || getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n) ||
        type != SOCK_STREAM || getpeername(fd,(struct sockaddr *)&peer,&pn)) return err(STEER_PV1_INVALID);
    if (r->streams >= r->max_streams) return err(STEER_PV1_RESOURCE_EXHAUSTED);
    s=calloc(1,sizeof(*s));
    if (!s) return err(STEER_PV1_RESOURCE_EXHAUSTED);
    flags=fcntl(fd,F_GETFL);
    if (flags < 0 || fcntl(fd,F_SETFL,flags | O_NONBLOCK) < 0 ||
        (flags=fcntl(fd,F_GETFD)) < 0 || fcntl(fd,F_SETFD,flags | FD_CLOEXEC) < 0) {
        free(s); return err(STEER_PV1_IO);
    }
    s->runtime=r; s->fd=fd; r->streams++; *out=s; return err(STEER_PV1_OK);
}
