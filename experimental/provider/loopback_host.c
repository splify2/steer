/* SPDX-License-Identifier: GPL-3.0-only
 * Disposable Linux lab host. Not production Steer or a provider loader. */
#define _GNU_SOURCE
#include "stream.h"
#include "buffers.h"
#include "loop.h"
#include "codec.h"
#include "inbound.h"
#include "loopback_host.h"
#include "route_dial.h"
#include "policy_route.h"
#include "prototype_config.h"
#include "resolver.h"
#include "prototype_store.h"
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/eventfd.h>

#define CLIENTS 32
#define CAPACITY 16384
#define GENERATIONS 8
#define LISTENERS 32 /* 16 published plus 16 transactionally prepared */
#define CONTROLS 8
#define CONTROL_INPUT (STEER_PROTOTYPE_CONFIG_MAX_BYTES + 128u)
#define CONTROL_OUTPUT (STEER_PROTOTYPE_CONFIG_MAX_BYTES + 2048u)
struct host;
struct prepared;
struct store_writer {
    struct host *host;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int wake, initialized, started, stopping, queued, done;
    struct prepared *prepared;
    struct steer_prototype_store_result result;
};
struct control {
    struct host *host;
    struct loop_timer *deadline;
    int fd, writing, operation, parsed, waiting_store;
    uint64_t serial;
    uint64_t expected;
    size_t used, header_length, body_length, sent, output_length;
    char input[CONTROL_INPUT], output[CONTROL_OUTPUT];
};
struct generation {
    struct steer_draft_routes *routes;
    struct steer_policy *policy;
    struct steer_prototype_config *config;
    char *document;
    size_t document_length;
    uint64_t number;
    unsigned references;
    int preparing;
};
struct listener_identity {
    int vless;
    char id[65], principal[65];
    const char *user, *password;
    size_t user_length, password_length;
    uint8_t uuid[16];
};
struct listener {
    struct host *host;
    int fd;
    int active;
    struct steer_prototype_listener spec;
    struct listener_identity identity;
};
enum phase { HANDSHAKE, REPLY, DIALING, RELAY, CLOSING };
struct client;
struct direction {
    struct client *client;
    struct steer_pv1_buffer *buffer;
    struct steer_pv1_async_start operation;
    uint32_t offset, length, bytes, error;
    int pending, completed, writing, eof;
};
struct host {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    struct steer_draft_stream_runtime *runtime;
    struct steer_draft_resolver *resolver;
    struct steer_prototype_store *store;
    struct store_writer writer;
    int store_busy, durability_uncertain;
    struct generation generations[GENERATIONS], *current;
    struct listener listeners[LISTENERS];
    struct loop_timer *work;
    struct client *clients;
    int stopping;
    int control_fd;
    char control_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    struct control *controls;
    unsigned live;
};
struct prepared {
    struct generation *generation;
    unsigned keep[LISTENERS], created[LISTENERS];
    struct control *control;
    uint64_t control_serial;
};
struct client {
    struct host *host;
    struct generation *generation;
    struct listener_identity identity;
    struct steer_pv1_stream *down, *up;
    struct loop_timer *deadline;
    struct direction directions[2]; /* down->up, up->down */
    struct s5_codec codec;
    struct vl_decoder vless;
    struct s5_address target; /* normalized numeric/domain target for host dial */
    struct steer_pv1_endpoint source;
    uint8_t source_bytes[16];
    struct steer_pv1_async_start route;
    struct s5_address bound;
    uint32_t route_error, dial_failure;
    enum phase phase, after_reply;
    uint32_t input_offset, input_length;
    int live, authenticated, route_pending, route_completed;
};
static const struct steer_pv1_stream_api *sa;
static const struct steer_pv1_buffer_api *ba;
static void advance(struct client *);
static void reap_generations(struct host *);
static void close_control(struct control *);
static void stop_writer(struct host *);
static void close_client(struct client *c)
{
    if (!c->live || c->phase == CLOSING) return;
    c->phase = CLOSING;
    loop_timer_stop(c->deadline);
    if (c->route_pending) c->route.operation.api->cancel(c->route.operation.handle);
    if (c->down) sa->close(c->down);
    if (c->up) sa->close(c->up);
    loop_timer_set(c->host->work, 0);
}
static void deadline(struct loop *l, struct loop_timer *t, void *arg)
{
    (void)l; (void)t; close_client(arg);
}
static void done(void *arg, struct steer_pv1_error e,
                 struct steer_pv1_buffer *buffer, uint32_t bytes)
{
    struct direction *d = arg;
    /* The transferred reference returns at callback entry. Operation release
     * must wait until the streamservice has returned from this callback. */
    d->buffer = buffer; d->error = e.code; d->bytes = bytes;
    d->completed = 1;
    loop_timer_set(d->client->host->work, 0);
}
static int submit(struct direction *d, struct steer_pv1_stream *stream,
                  int writing, uint32_t offset, uint32_t length)
{
    d->writing = writing; d->offset = offset; d->length = length;
    d->operation = writing ? sa->write(stream, d->buffer, offset, length, done, d) :
                             sa->read(stream, d->buffer, offset, length, done, d);
    if (d->operation.disposition != STEER_PV1_PENDING) {
        close_client(d->client); return 0;
    }
    d->pending = 1;
    return 1;
}
static uint8_t *view(struct client *c, unsigned index)
{
    struct steer_pv1_mut_span span;
    if (ba->writable(c->host->buffers, c->directions[index].buffer, &span).code) {
        close_client(c); return NULL;
    }
    return span.data;
}
static void reply(struct client *c, enum phase next)
{
    uint8_t *p = view(c, 1);
    if (!p) return;
    memcpy(p, c->codec.reply, c->codec.reply_length);
    c->after_reply = next; c->phase = REPLY;
    (void)submit(&c->directions[1], c->down, 1, 0, (uint32_t)c->codec.reply_length);
}
static void dial_reply(struct client *c, uint8_t code, const struct s5_address *bound)
{
    if (c->identity.vless) {
        if (code) { close_client(c); return; }
        c->codec.reply_length = vl_response_encode(c->codec.reply, sizeof(c->codec.reply));
        reply(c, RELAY);
    } else {
        (void)s5_dial_result(&c->codec, code, bound);
        reply(c, code ? CLOSING : RELAY);
    }
}
static int verify_uuid(void *arg, const uint8_t uuid[16])
{
    struct client *c = arg;
    c->authenticated = !memcmp(uuid, c->identity.uuid, sizeof(c->identity.uuid));
    return c->authenticated;
}
static int verify(void *arg, const uint8_t *user, size_t un,
                  const uint8_t *password, size_t pn)
{
    struct client *c = arg;
    struct listener_identity *identity = &c->identity;
    /* Lab credentials only; no logging. Not an authentication database. */
    c->authenticated = un == identity->user_length && pn == identity->password_length &&
           !memcmp(user, identity->user, un) && !memcmp(password, identity->password, pn);
    return c->authenticated;
}
static void route_done(void *arg, struct steer_pv1_error error, uint32_t failure,
                       struct steer_pv1_stream *stream, const struct steer_pv1_endpoint *bound)
{
    struct client *c = arg;
    c->route_error = error.code; c->dial_failure = failure;
    c->route_completed = 1; c->up = stream;
    if (bound) {
        c->bound.type = bound->tag == STEER_PV1_ENDPOINT_IPV4 ? 1 : 4;
        c->bound.length = (uint8_t)bound->address.len; c->bound.port = bound->port;
        memcpy(c->bound.bytes, bound->address.data, bound->address.len);
    }
    if (c->phase == CLOSING && stream) sa->close(stream);
    loop_timer_set(c->host->work, 0);
}
static uint8_t route_reply_code(uint32_t error, uint32_t failure)
{
    if (!error) return 0;
    if (error == STEER_PV1_POLICY_DENIED) return 2;
    if (error == STEER_PV1_UNSUPPORTED) return 4; /* unresolved domain */
    if (error == STEER_PV1_TIMEOUT) return 6;
    if (failure == STEER_DRAFT_DIAL_REFUSED) return 5;
    if (failure == STEER_DRAFT_DIAL_NETWORK_UNREACHABLE) return 3;
    if (failure == STEER_DRAFT_DIAL_HOST_UNREACHABLE) return 4;
    return 1;
}
static void dial(struct client *c)
{
    struct steer_draft_accepted flow = {0};
    const char *inbound = c->identity.id;
    const char *principal = c->identity.principal;
    flow.generation = c->generation->number;
    flow.inbound_id.data = (const uint8_t *)inbound;
    flow.inbound_id.len = (uint32_t)strlen(inbound);
    if (c->authenticated) {
        flow.principal_id.data = (const uint8_t *)principal;
        flow.principal_id.len = (uint32_t)strlen(principal);
    }
    flow.source = c->source; flow.flow_class = STEER_PV1_FLOW_STREAM;
    flow.destination.size = sizeof(flow.destination);
    flow.destination.version = STEER_PV1_DRAFT_LAYOUT;
    flow.destination.tag = c->target.type == 1 ? STEER_PV1_ENDPOINT_IPV4 :
        c->target.type == 4 ? STEER_PV1_ENDPOINT_IPV6 : STEER_PV1_ENDPOINT_DOMAIN;
    flow.destination.address.data = c->target.bytes;
    flow.destination.address.len = c->target.length;
    flow.destination.port = c->target.port;
    c->phase = DIALING;
    loop_timer_set(c->deadline, 5000);
    c->route = steer_draft_route_dial(c->generation->routes, &flow,
        ((uint64_t)loop_now_ms() + 5000u) * 1000000u, route_done, c);
    if (c->route.disposition == STEER_PV1_PENDING) c->route_pending = 1;
    else dial_reply(c, route_reply_code(c->route.error.code, 0), NULL);
}
static void handshake(struct client *c)
{
    uint8_t *p = view(c, 0);
    size_t consumed;
    enum s5_event event;
    if (!p) return;
    if (c->identity.vless) {
        enum vl_result result = vl_decoder_feed(&c->vless, p + c->input_offset,
                                                c->input_length, &consumed);
        c->input_offset += (uint32_t)consumed;
        c->input_length -= (uint32_t)consumed;
        if (result < 0 || (result == VL_DONE && c->vless.request.command != 1)) {
            close_client(c); return;
        }
        if (result == VL_DONE) {
            const struct vl_request *r = &c->vless.request;
            c->target.type = r->address_type == 1 ? 1 : r->address_type == 3 ? 4 : 3;
            c->target.length = (uint8_t)r->address_length; c->target.port = r->port;
            memcpy(c->target.bytes, r->address, r->address_length);
            dial(c); return;
        }
        c->input_offset = 0;
        (void)submit(&c->directions[0], c->down, 0, 0, CAPACITY);
        return;
    }
    event = s5_feed(&c->codec, p + c->input_offset, c->input_length, &consumed);
    c->input_offset += (uint32_t)consumed;
    c->input_length -= (uint32_t)consumed;
    if (event == S5_METHOD || event == S5_AUTH) reply(c, HANDSHAKE);
    else if (event == S5_ERROR) {
        if (c->codec.reply_length) reply(c, CLOSING);
        else close_client(c);
    } else if (event == S5_CONNECT) { c->target = c->codec.target; dial(c); }
    else {
        c->input_offset = 0;
        (void)submit(&c->directions[0], c->down, 0, 0, CAPACITY);
    }
}
static void relay_start(struct client *c)
{
    struct direction *d = &c->directions[0];
    if (c->input_length) (void)submit(d, c->up, 1, c->input_offset, c->input_length);
    else (void)submit(d, c->down, 0, 0, CAPACITY);
    if (c->phase != CLOSING) (void)submit(&c->directions[1], c->up, 0, 0, CAPACITY);
    c->input_length = c->input_offset = 0;
}
static void relay_done(struct client *c, unsigned index)
{
    struct direction *d = &c->directions[index];
    struct steer_pv1_stream *source = index ? c->up : c->down;
    struct steer_pv1_stream *target = index ? c->down : c->up;
    if (d->writing) {
        if (!d->bytes) { close_client(c); return; }
        if (d->bytes < d->length) {
            (void)submit(d, target, 1, d->offset + d->bytes, d->length - d->bytes);
        } else (void)submit(d, source, 0, 0, CAPACITY);
    } else if (d->bytes) (void)submit(d, target, 1, 0, d->bytes);
    else {
        d->eof = 1;
        if (sa->shutdown_write(target).code) close_client(c);
        else if (c->directions[1-index].eof) close_client(c);
    }
}
static void advance(struct client *c)
{
    unsigned i;
    if (c->route_completed) {
        c->route.operation.api->release(c->route.operation.handle);
        c->route_pending = c->route_completed = 0;
        if (c->phase != CLOSING) {
            if (!c->route_error) loop_timer_set(c->deadline, 30000);
            dial_reply(c, route_reply_code(c->route_error, c->dial_failure), c->route_error ? NULL : &c->bound);
        }
    }
    for (i = 0; i < 2; ++i) {
        struct direction *d = &c->directions[i];
        if (!d->completed) continue;
        d->operation.operation.api->release(d->operation.operation.handle);
        d->pending = d->completed = 0;
        if (c->phase == CLOSING) continue;
        if (d->error) { close_client(c); continue; }
        if (c->phase == RELAY) {
            loop_timer_set(c->deadline, 30000); relay_done(c, i);
        } else if (c->phase == HANDSHAKE) {
            if (!d->bytes) close_client(c);
            else { c->input_offset = 0; c->input_length = d->bytes; handshake(c); }
        } else if (c->phase == REPLY) {
            if (!d->bytes) { close_client(c); continue; }
            if (d->bytes < d->length) {
                (void)submit(d, c->down, 1, d->offset + d->bytes, d->length - d->bytes);
            } else if (c->after_reply == CLOSING) close_client(c);
            else {
                c->phase = c->after_reply;
                if (c->phase == RELAY) relay_start(c); else handshake(c);
            }
        }
    }
    if (c->phase == CLOSING && !c->route_pending && !c->directions[0].pending && !c->directions[1].pending) {
        if (c->up && sa->release(c->up).code) abort();
        if (c->down && sa->release(c->down).code) abort();
        for (i = 0; i < 2; ++i)
            if (c->directions[i].buffer) ba->release(c->host->buffers, c->directions[i].buffer);
        loop_timer_free(c->deadline); c->deadline = NULL;
        c->generation->references--;
        c->live = 0; c->host->live--;
    }
}
static void work(struct loop *l, struct loop_timer *t, void *arg)
{
    struct host *h = arg; unsigned i;
    (void)t;
    for (i = 0; i < CLIENTS; ++i) if (h->clients[i].live) advance(&h->clients[i]);
    reap_generations(h);
    if (h->stopping && !h->live && !h->store_busy) {
        h->current = NULL;
        reap_generations(h); /* release route-generation resolver references */
        if (h->resolver && steer_draft_resolver_jobs(h->resolver)) {
            loop_timer_set(h->work, 10); /* cancelled NSS still owns bounded job */
        } else loop_stop(l, 0);
    }
}
static void accept_clients(struct loop *l, int fd, uint32_t events, void *arg)
{
    struct listener *listener = arg;
    struct host *h = listener->host; unsigned attempt, i;
    (void)events;
    for (attempt = 0; attempt < CLIENTS; ++attempt) {
        struct client *c;
        struct sockaddr_storage peer; socklen_t peer_length = sizeof(peer);
        int accepted = accept4(fd, (struct sockaddr *)&peer, &peer_length, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (accepted < 0) { if (errno == EINTR) continue; return; }
        if (!listener->active) { close(accepted); continue; }
        for (i = 0; i < CLIENTS && h->clients[i].live; ++i) {}
        if (i == CLIENTS) { close(accepted); continue; }
        c = &h->clients[i]; memset(c, 0, sizeof(*c));
        c->host = h; c->live = 1; h->live++;
        c->generation = h->current; c->generation->references++;
        c->identity = listener->identity;
        c->source.size = sizeof(c->source); c->source.version = STEER_PV1_DRAFT_LAYOUT;
        c->source.address.data = c->source_bytes;
        if (peer.ss_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)&peer;
            c->source.tag = STEER_PV1_ENDPOINT_IPV4; c->source.address.len = 4;
            c->source.port = ntohs(a->sin_port); memcpy(c->source_bytes, &a->sin_addr, 4);
        } else {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&peer;
            c->source.tag = STEER_PV1_ENDPOINT_IPV6; c->source.address.len = 16;
            c->source.port = ntohs(a->sin6_port); memcpy(c->source_bytes, &a->sin6_addr, 16);
        }
        c->deadline = loop_timer_new(l, deadline, c);
        c->directions[0].client = c; c->directions[1].client = c;
        if (!c->deadline || steer_draft_stream_adopt(h->runtime, accepted, &c->down).code) {
            close(accepted); close_client(c); continue;
        }
        if (ba->allocate(h->buffers, CAPACITY, &c->directions[0].buffer).code ||
            ba->allocate(h->buffers, CAPACITY, &c->directions[1].buffer).code) {
            close_client(c); continue;
        }
        if (c->identity.vless) vl_decoder_init(&c->vless, verify_uuid, c);
        else s5_init(&c->codec, c->identity.user ? S5_USERPASS : S5_NOAUTH, verify, c);
        loop_timer_set(c->deadline, 5000);
        (void)submit(&c->directions[0], c->down, 0, 0, CAPACITY);
    }
}
static void stop(struct loop *l, int signo, void *arg)
{
    struct host *h = arg; unsigned i;
    (void)l; (void)signo;
    h->stopping = 1;
    if (h->control_fd >= 0) {
        loop_fd_del(h->loop, h->control_fd); close(h->control_fd); h->control_fd = -1;
    }
    if (h->controls) for (i = 0; i < CONTROLS; ++i) close_control(&h->controls[i]);
    for (i = 0; i < LISTENERS; ++i) if (h->listeners[i].fd >= 0) {
        loop_fd_del(h->loop, h->listeners[i].fd); close(h->listeners[i].fd); h->listeners[i].fd = -1;
    }
    for (i = 0; i < CLIENTS; ++i) if (h->clients[i].live) close_client(&h->clients[i]);
    loop_timer_set(h->work, 0);
}
static int hex_digit(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
static int parse_uuid(const char *text, uint8_t uuid[16])
{
    size_t i, out = 0;
    if (!text || strlen(text) != 36) return 0;
    for (i = 0; i < 36;) {
        int high, low;
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i++] != '-') return 0;
            continue;
        }
        high = hex_digit((unsigned char)text[i++]);
        low = hex_digit((unsigned char)text[i++]);
        if (high < 0 || low < 0) return 0;
        uuid[out++] = (uint8_t)(high * 16 + low);
    }
    return out == 16;
}
static void destroy_generation(struct generation *g)
{
    if (g->routes && steer_draft_routes_destroy(g->routes).code) abort();
    if (g->config) steer_prototype_config_destroy(g->config);
    else steer_policy_destroy(g->policy);
    free(g->document);
    memset(g, 0, sizeof(*g));
}
static void reap_generations(struct host *h)
{
    unsigned i;
    for (i = 0; i < GENERATIONS; ++i) {
        struct generation *g = &h->generations[i];
        if (g != h->current && g->number && !g->references && !g->preparing) destroy_generation(g);
    }
}
static int initialize_host(struct host *h, struct client *clients)
{
    unsigned i;
    struct steer_draft_buffer_limits limits = {2 * CLIENTS * (CAPACITY + 256), 2 * CLIENTS, 1};
    h->clients = clients;
    h->control_fd = -1;
    h->writer.wake = -1;
    for (i = 0; i < LISTENERS; ++i) h->listeners[i].fd = -1;
    sa = steer_draft_stream_api(); ba = steer_draft_buffers_api();
    h->loop = loop_new();
    if (!h->loop || steer_draft_buffers_create(&limits, NULL, &h->buffers).code) return 0;
    if (steer_draft_stream_runtime_create(h->loop, h->buffers, 2*CLIENTS, 2*CLIENTS,
                                        2*CLIENTS*CAPACITY, &h->runtime).code) return 0;
    h->work = loop_timer_new(h->loop, work, h);
    if (!h->work) return 0;
    (void)loop_signal(h->loop, SIGTERM, stop, h); (void)loop_signal(h->loop, SIGINT, stop, h);
    return 1;
}
static void close_listener(struct host *h, struct listener *listener)
{
    if (listener->fd >= 0) {
        loop_fd_del(h->loop, listener->fd); close(listener->fd); listener->fd = -1;
    }
    listener->active = 0;
}
static int bind_listener(struct host *h, struct listener *listener)
{
    struct sockaddr_storage address;
    socklen_t length;
    int family, reuse = 1;
    memset(&address, 0, sizeof(address)); listener->host = h;
    if (strchr(listener->spec.address, ':')) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
        family = AF_INET6; length = sizeof(*a); a->sin6_family = AF_INET6;
        a->sin6_port = htons(listener->spec.port);
        if (inet_pton(AF_INET6, listener->spec.address, &a->sin6_addr) != 1) return 0;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&address;
        family = AF_INET; length = sizeof(*a); a->sin_family = AF_INET;
        a->sin_port = htons(listener->spec.port);
        if (inet_pton(AF_INET, listener->spec.address, &a->sin_addr) != 1) return 0;
    }
    listener->fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener->fd < 0 || setsockopt(listener->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
        (family == AF_INET6 && setsockopt(listener->fd, IPPROTO_IPV6, IPV6_V6ONLY, &reuse, sizeof(reuse))) ||
        bind(listener->fd, (struct sockaddr *)&address, length) ||
        listen(listener->fd, CLIENTS) || getsockname(listener->fd, (struct sockaddr *)&address, &length) ||
        loop_fd_add(h->loop, listener->fd, EPOLLIN, accept_clients, listener)) {
        close_listener(h, listener); return 0;
    }
    listener->spec.port = family == AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port) :
                                            ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    return 1;
}
static void cleanup_host(struct host *h)
{
    unsigned i;
    if (h->control_fd >= 0) { loop_fd_del(h->loop, h->control_fd); close(h->control_fd); }
    if (h->controls) {
        for (i = 0; i < CONTROLS; ++i) close_control(&h->controls[i]);
        free(h->controls);
    }
    if (h->control_path[0]) unlink(h->control_path);
    stop_writer(h);
    for (i = 0; i < LISTENERS; ++i) close_listener(h, &h->listeners[i]);
    loop_timer_free(h->work);
    for (i = 0; i < GENERATIONS; ++i) destroy_generation(&h->generations[i]);
    if (h->resolver && steer_draft_resolver_destroy(h->resolver).code) abort();
    if (h->store && steer_prototype_store_close(h->store).code) abort();
    if (h->runtime && steer_draft_stream_runtime_destroy(h->runtime).code) abort();
    if (h->buffers && steer_draft_buffers_destroy(h->buffers).code) abort();
    if (h->loop) loop_free(h->loop);
}
int steer_lab_loopback_main(int argc, char **argv, int vless)
{
    struct host h = {0}; struct client clients[CLIENTS] = {{0}};
    struct generation *g = &h.generations[0];
    struct listener *listener = &h.listeners[0];
    struct listener_identity identity = {0};
    struct steer_policy_rule rule = {0};
    const char *bind_address = argc > 2 ? argv[2] : "127.0.0.1";
    char *end; unsigned long port = 0; int status = 1;
    if (argc < 2 || argc > 4 || (strcmp(argv[1], "direct") && strcmp(argv[1], "block"))) {
        fprintf(stderr, "usage: %s-loopback direct|block [127.0.0.1|::1] [port]\n", vless ? "vless" : "socks"); return 2;
    }
    if (strcmp(bind_address, "127.0.0.1") && strcmp(bind_address, "::1")) return 2;
    if (argc == 4) {
        errno = 0; port = strtoul(argv[3], &end, 10);
        if (errno || !*argv[3] || *end || port > 65535) return 2;
    }
    identity.vless = vless;
    strcpy(identity.id, vless ? "lab-vless" : "lab-socks");
    strcpy(identity.principal, vless ? "lab-vless-user" : "lab-socks-user");
    if (vless) {
        if (!parse_uuid(getenv("STEER_LAB_UUID"), identity.uuid)) return 2;
    } else {
        identity.user = getenv("STEER_LAB_USER"); identity.password = getenv("STEER_LAB_PASSWORD");
        if (identity.user || identity.password) {
            if (!identity.user || !identity.password) return 2;
            identity.user_length = strlen(identity.user); identity.password_length = strlen(identity.password);
            if (!identity.user_length || identity.user_length > 255 || !identity.password_length || identity.password_length > 255) return 2;
        }
    }
    if (!initialize_host(&h, clients)) goto cleanup;
    g->number = 1;
    rule.id.data = (const uint8_t *)"lab-entry"; rule.id.len = 9;
    rule.inbound.data = (const uint8_t *)identity.id; rule.inbound.len = (uint32_t)strlen(identity.id);
    if (vless || identity.user) {
        rule.principal.data = (const uint8_t *)identity.principal; rule.principal.len = (uint32_t)strlen(identity.principal);
    }
    rule.action = !strcmp(argv[1], "block") ? STEER_POLICY_BLOCK : STEER_POLICY_DIRECT;
    if (steer_policy_compile(1, &rule, 1, STEER_POLICY_BLOCK, &g->policy).code) goto cleanup;
    if (steer_draft_routes_create(h.loop, h.runtime, 1, CLIENTS, steer_policy_route, g->policy, &g->routes).code) goto cleanup;
    h.current = g; listener->identity = identity;
    listener->active = 1;
    strcpy(listener->spec.id, identity.id); strcpy(listener->spec.address, bind_address);
    listener->spec.port = (uint16_t)port;
    listener->spec.protocol = vless ? STEER_PROTOTYPE_VLESS : STEER_PROTOTYPE_SOCKS;
    if (!bind_listener(&h, listener)) goto cleanup;
    printf("PORT %u\n", listener->spec.port); fflush(stdout);
    status = loop_run(h.loop);
cleanup:
    cleanup_host(&h);
    return status;
}
static int resolve_identity(const struct steer_prototype_listener *spec, struct listener_identity *identity)
{
    memset(identity, 0, sizeof(*identity));
    identity->vless = spec->protocol == STEER_PROTOTYPE_VLESS;
    strcpy(identity->id, spec->id); strcpy(identity->principal, spec->principal_id);
    if (spec->auth == STEER_PROTOTYPE_AUTH_UUID)
        return parse_uuid(getenv(spec->uuid_ref + 4), identity->uuid);
    if (spec->auth == STEER_PROTOTYPE_AUTH_USERPASS) {
        identity->user = getenv(spec->username_ref + 4);
        identity->password = getenv(spec->password_ref + 4);
        if (!identity->user || !identity->password) return 0;
        identity->user_length = strlen(identity->user); identity->password_length = strlen(identity->password);
        return identity->user_length && identity->user_length <= 255 &&
               identity->password_length && identity->password_length <= 255;
    }
    return !identity->vless && spec->auth == STEER_PROTOTYPE_AUTH_NONE;
}
static int same_listener(const struct steer_prototype_listener *a, const struct steer_prototype_listener *b)
{
    return a->port == b->port && a->protocol == b->protocol && a->auth == b->auth &&
        !strcmp(a->id, b->id) && !strcmp(a->address, b->address) &&
        !strcmp(a->principal_id, b->principal_id) && !strcmp(a->username_ref, b->username_ref) &&
        !strcmp(a->password_ref, b->password_ref) && !strcmp(a->uuid_ref, b->uuid_ref);
}
/* No callbacks interleave preparation/publication: one owning loop shard.
 * New sockets are closed on failure; old listeners and generation stay live. */
static int prepare_configuration(struct host *h, const char *document, size_t length,
                                 uint64_t expected, int validate, uint64_t initial_revision,
                                 struct prepared *prepared_state)
{
    struct steer_prototype_config *config = NULL;
    struct listener_identity identities[STEER_PROTOTYPE_MAX_LISTENERS];
    struct generation *g = NULL;
    unsigned i, j;
    int result = 422;
    uint64_t next = h->current ? h->current->number + 1 : initial_revision;
    memset(prepared_state, 0, sizeof(*prepared_state));
    if (!validate && expected != (h->current ? h->current->number : 0)) return 409;
    if (!next || steer_prototype_config_parse(document, length, next, &config).code) return 422;
    if (!config->document_json || config->document_length > STEER_PROTOTYPE_CONFIG_MAX_BYTES) goto cleanup;
    for (i = 0; i < config->listener_count; ++i)
        if (config->listeners[i].enabled && !resolve_identity(&config->listeners[i], &identities[i])) goto cleanup;
    if (validate) { result = 200; goto cleanup; }
    reap_generations(h);
    for (i = 0; i < GENERATIONS; ++i) if (!h->generations[i].number) { g = &h->generations[i]; break; }
    if (!g) { result = 503; goto cleanup; }
    g->number = next; g->preparing = 1;
    g->config = config; g->policy = config->policy; config = NULL;
    length = g->config->document_length;
    g->document = malloc(length + 1);
    if (!g->document) { result = 503; goto cleanup; }
    memcpy(g->document, g->config->document_json, length); g->document[length] = 0; g->document_length = length;
    if (steer_draft_routes_create(h->loop, h->runtime, next, CLIENTS,
                                  steer_policy_route, g->policy, &g->routes).code) {
        result = 503; goto cleanup;
    }
    if (h->resolver && steer_draft_routes_use_resolver(g->routes, h->resolver).code) {
        result = 503; goto cleanup;
    }
    for (i = 0; i < g->config->listener_count; ++i) {
        const struct steer_prototype_listener *spec = &g->config->listeners[i];
        struct listener *listener = NULL;
        if (!spec->enabled) continue;
        for (j = 0; j < LISTENERS; ++j) if (h->listeners[j].fd >= 0 &&
            same_listener(&h->listeners[j].spec, spec)) {
            listener = &h->listeners[j]; prepared_state->keep[j] = 1; break;
        }
        if (listener) continue;
        /* Changing a live endpoint's protocol/auth/ID requires disable then
         * create. No SO_REUSEPORT split or nontransactional close/rebind. */
        for (j = 0; j < LISTENERS; ++j) if (h->listeners[j].fd >= 0 &&
            h->listeners[j].spec.port == spec->port && !strcmp(h->listeners[j].spec.address, spec->address)) goto cleanup;
        for (j = 0; j < LISTENERS; ++j) if (h->listeners[j].fd < 0) { listener = &h->listeners[j]; break; }
        if (!listener) { result = 503; goto cleanup; }
        listener->spec = *spec; listener->identity = identities[i]; listener->active = 0;
        if (!bind_listener(h, listener)) goto cleanup;
        prepared_state->keep[j] = prepared_state->created[j] = 1;
    }
    prepared_state->generation = g; g = NULL; result = 200;
cleanup:
    if (result != 200) for (i = 0; i < LISTENERS; ++i) if (prepared_state->created[i]) close_listener(h, &h->listeners[i]);
    if (g) destroy_generation(g);
    steer_prototype_config_destroy(config);
    return result;
}
static void discard_prepared(struct host *h, struct prepared *prepared)
{
    unsigned i;
    for (i = 0; i < LISTENERS; ++i) if (prepared->created[i]) close_listener(h, &h->listeners[i]);
    if (prepared->generation) destroy_generation(prepared->generation);
    memset(prepared, 0, sizeof(*prepared));
}
/* All fallible runtime work completed before disk rename. Only pointer/state
 * publication and closing old admission descriptors remain after commit. */
static void publish_prepared(struct host *h, struct prepared *prepared)
{
    unsigned i;
    for (i = 0; i < LISTENERS; ++i) {
        if (!prepared->keep[i] || h->stopping) close_listener(h, &h->listeners[i]);
        else h->listeners[i].active = 1;
    }
    h->current = prepared->generation; h->current->preparing = 0;
    prepared->generation = NULL;
    reap_generations(h);
}
static int configure(struct host *h, const char *document, size_t length, uint64_t expected,
                     int validate, uint64_t initial_revision)
{
    struct prepared prepared;
    int result = prepare_configuration(h, document, length, expected, validate, initial_revision, &prepared);
    if (result == 200 && !validate) publish_prepared(h, &prepared);
    return result;
}
static size_t status_json(struct host *h, char *out, size_t capacity)
{
    size_t used;
    unsigned i, count = 0;
    int n = snprintf(out, capacity, "{\"prototype\":\"steer-linux-v1\",\"generation\":%llu,\"revision\":%llu,\"runtimeReady\":true,\"persistence\":%s,\"durability_uncertain\":%s,\"activeClients\":%u,\"listeners\":[",
        (unsigned long long)h->current->number, (unsigned long long)h->current->number,
        h->store ? "true" : "false", h->durability_uncertain ? "true" : "false", h->live);
    if (n < 0 || (size_t)n >= capacity) return 0;
    used = (size_t)n;
    for (i = 0; i < LISTENERS; ++i) if (h->listeners[i].fd >= 0 && h->listeners[i].active) {
        const struct listener *listener = &h->listeners[i];
        n = snprintf(out + used, capacity - used, "%s{\"id\":\"%s\",\"protocol\":\"%s\",\"address\":\"%s\",\"port\":%u}",
            count++ ? "," : "", listener->identity.id, listener->identity.vless ? "vless" : "socks",
            listener->spec.address, listener->spec.port);
        if (n < 0 || (size_t)n >= capacity - used) return 0;
        used += (size_t)n;
    }
    if (capacity - used < 3) return 0;
    memcpy(out + used, "]}", 3);
    return used + 2;
}
static void close_control(struct control *c)
{
    if (c->fd < 0) return;
    loop_fd_del(c->host->loop, c->fd); close(c->fd); c->fd = -1;
    loop_timer_free(c->deadline); c->deadline = NULL;
}
static void control_timeout(struct loop *l, struct loop_timer *t, void *arg)
{
    (void)l; (void)t; close_control(arg);
}
static void control_response(struct control *c, int code, const char *body, size_t length)
{
    int n;
    if (code == 200) n = snprintf(c->output, sizeof(c->output), "OK %zu\n", length);
    else n = snprintf(c->output, sizeof(c->output), "ERR %d %zu\n", code, length);
    if (n < 0 || length > sizeof(c->output) - (size_t)n) { close_control(c); return; }
    memcpy(c->output + n, body, length); c->output_length = (size_t)n + length;
    c->writing = 1;
    if (loop_fd_mod(c->host->loop, c->fd, EPOLLOUT)) close_control(c);
}
static void control_error(struct control *c, int code)
{
    char body[160];
    int n = snprintf(body, sizeof(body), "{\"error\":\"request rejected\",\"persistence\":%s,\"durability_uncertain\":%s}",
        c->host->store ? "true" : "false", c->host->durability_uncertain ? "true" : "false");
    control_response(c, code, body, (size_t)n);
}
static void applied_response(struct control *c, int code)
{
    struct host *h = c->host;
    char body[320];
    int n = snprintf(body, sizeof(body), "{\"applied\":true,\"revision\":%llu,\"generation\":%llu,\"persistence\":%s,\"durability_uncertain\":%s%s}",
        (unsigned long long)h->current->number, (unsigned long long)h->current->number,
        h->store ? "true" : "false", h->durability_uncertain ? "true" : "false",
        code == 200 ? "" : ",\"error\":\"durability_uncertain\"");
    control_response(c, code, body, (size_t)n);
}
static void *store_worker(void *arg)
{
    struct store_writer *writer = arg;
    for (;;) {
        struct steer_prototype_store_transaction *transaction = NULL;
        struct steer_prototype_store_result result = {{STEER_PV1_OK, 0}, 0};
        struct prepared *prepared;
        uint64_t wake = 1;
        pthread_mutex_lock(&writer->lock);
        while (!writer->queued && !writer->stopping) pthread_cond_wait(&writer->changed, &writer->lock);
        if (writer->stopping) { pthread_mutex_unlock(&writer->lock); break; }
        prepared = writer->prepared; writer->queued = 0;
        pthread_mutex_unlock(&writer->lock);
        result.error = steer_prototype_store_prepare(writer->host->store, prepared->generation->config, &transaction);
        if (!result.error.code) {
            result = steer_prototype_store_commit(transaction);
            (void)steer_prototype_store_abort(transaction);
        }
        pthread_mutex_lock(&writer->lock);
        writer->result = result; writer->done = 1;
        pthread_mutex_unlock(&writer->lock);
        while (write(writer->wake, &wake, sizeof(wake)) < 0 && errno == EINTR) {}
    }
    return NULL;
}
static void writer_ready(struct loop *l, int fd, uint32_t events, void *arg)
{
    struct host *h = arg;
    struct store_writer *writer = &h->writer;
    struct steer_prototype_store_result result;
    struct prepared *prepared;
    struct control *control;
    uint64_t wake, serial;
    (void)l; (void)events;
    while (read(fd, &wake, sizeof(wake)) < 0 && errno == EINTR) {}
    pthread_mutex_lock(&writer->lock);
    if (!writer->done) { pthread_mutex_unlock(&writer->lock); return; }
    prepared = writer->prepared; result = writer->result;
    writer->prepared = NULL; writer->done = 0;
    pthread_mutex_unlock(&writer->lock);
    control = prepared->control; serial = prepared->control_serial;
    if (result.phase >= STEER_PROTOTYPE_STORE_RENAMED) {
        h->durability_uncertain = result.phase != STEER_PROTOTYPE_STORE_SYNCED;
        publish_prepared(h, prepared);
    } else discard_prepared(h, prepared);
    h->store_busy = 0; free(prepared);
    if (control && control->fd >= 0 && control->serial == serial && control->waiting_store) {
        control->waiting_store = 0;
        if (result.phase >= STEER_PROTOTYPE_STORE_RENAMED) applied_response(control, result.error.code ? 503 : 200);
        else control_error(control, 503);
    }
    loop_timer_set(h->work, 0);
}
static int start_writer(struct host *h)
{
    struct store_writer *writer = &h->writer;
    writer->host = h;
    if (pthread_mutex_init(&writer->lock, NULL)) return 0;
    if (pthread_cond_init(&writer->changed, NULL)) { pthread_mutex_destroy(&writer->lock); return 0; }
    writer->initialized = 1;
    writer->wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (writer->wake < 0 || loop_fd_add(h->loop, writer->wake, EPOLLIN, writer_ready, h)) return 0;
    if (pthread_create(&writer->thread, NULL, store_worker, writer)) return 0;
    writer->started = 1; return 1;
}
static void stop_writer(struct host *h)
{
    struct store_writer *writer = &h->writer;
    if (writer->started) {
        pthread_mutex_lock(&writer->lock); writer->stopping = 1;
        pthread_cond_signal(&writer->changed); pthread_mutex_unlock(&writer->lock);
        pthread_join(writer->thread, NULL);
    }
    if (writer->wake >= 0) { loop_fd_del(h->loop, writer->wake); close(writer->wake); }
    if (writer->initialized) { pthread_cond_destroy(&writer->changed); pthread_mutex_destroy(&writer->lock); }
}
static int durable_apply(struct control *c)
{
    struct host *h = c->host;
    struct prepared *prepared;
    int result;
    if (h->store_busy) return 503;
    prepared = calloc(1, sizeof(*prepared));
    if (!prepared) return 503;
    result = prepare_configuration(h, c->input + c->header_length, c->body_length,
                                   c->expected, 0, 1, prepared);
    if (result != 200) { free(prepared); return result; }
    prepared->control = c; prepared->control_serial = c->serial;
    if (loop_fd_mod(h->loop, c->fd, EPOLLRDHUP)) {
        discard_prepared(h, prepared); free(prepared); return 503;
    }
    c->waiting_store = 1; h->store_busy = 1;
    pthread_mutex_lock(&h->writer.lock);
    h->writer.prepared = prepared; h->writer.queued = 1;
    pthread_cond_signal(&h->writer.changed); pthread_mutex_unlock(&h->writer.lock);
    return 0; /* response deferred until the writer's eventfd completion */
}
static int decimal(const char **cursor, uint64_t *value)
{
    const char *p = *cursor;
    *value = 0;
    if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') {
        unsigned digit = (unsigned)(*p++ - '0');
        if (*value > (UINT64_MAX - digit) / 10) return 0;
        *value = *value * 10 + digit;
    }
    *cursor = p;
    return 1;
}
static int control_header(struct control *c)
{
    char header[128], *newline = memchr(c->input, '\n', c->used);
    const char *p;
    uint64_t length = 0;
    if (!newline) return c->used < sizeof(header) ? 0 : -1;
    c->header_length = (size_t)(newline - c->input) + 1;
    if (c->header_length >= sizeof(header)) return -1;
    if (memchr(c->input, 0, c->header_length)) return -1;
    memcpy(header, c->input, c->header_length - 1); header[c->header_length - 1] = 0;
    if (!strcmp(header, "STATUS")) c->operation = 1;
    else if (!strcmp(header, "GET")) c->operation = 2;
    else if (!strncmp(header, "VALIDATE ", 9)) {
        p = header + 9; c->operation = 3;
        if (!decimal(&p, &length) || *p) return -1;
    } else if (!strncmp(header, "APPLY ", 6)) {
        p = header + 6; c->operation = 4;
        if (!decimal(&p, &c->expected) || *p++ != ' ' || !decimal(&p, &length) || *p) return -1;
    } else return -1;
    if (length > STEER_PROTOTYPE_CONFIG_MAX_BYTES || (c->operation >= 3 && !length)) return -1;
    c->body_length = (size_t)length; c->parsed = 1;
    return 1;
}
static void control_execute(struct control *c)
{
    struct host *h = c->host;
    char status[8192], prefix[128];
    size_t length;
    int code, n;
    if (c->operation == 1) {
        length = status_json(h, status, sizeof(status));
        control_response(c, 200, status, length);
    } else if (c->operation == 2) {
        struct generation *g = h->current;
        n = snprintf(prefix, sizeof(prefix), "{\"revision\":%llu,\"persistence\":%s,\"durability_uncertain\":%s,\"document\":",
                     (unsigned long long)g->number, h->store ? "true" : "false",
                     h->durability_uncertain ? "true" : "false");
        length = (size_t)n + g->document_length + 1;
        if (length > sizeof(c->output) - 64) { control_error(c, 500); return; }
        /* Build in input storage after execution; no request bytes are needed. */
        memcpy(c->input, prefix, (size_t)n);
        memcpy(c->input + n, g->document, g->document_length);
        c->input[n + g->document_length] = '}';
        control_response(c, 200, c->input, length);
    } else {
        if (c->operation == 4 && h->store) {
            code = durable_apply(c);
            if (code) control_error(c, code);
            return;
        }
        code = configure(h, c->input + c->header_length, c->body_length, c->expected, c->operation == 3, 1);
        if (code != 200) { control_error(c, code); return; }
        if (c->operation == 3) {
            n = snprintf(status, sizeof(status), "{\"valid\":true,\"persistence\":%s}", h->store ? "true" : "false");
            control_response(c, 200, status, (size_t)n);
        } else applied_response(c, 200);
    }
}
static void control_ready(struct loop *l, int fd, uint32_t events, void *arg)
{
    struct control *c = arg;
    ssize_t n;
    (void)l;
    if (c->waiting_store) {
        if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) close_control(c);
        return;
    }
    if (c->writing) {
        do { n = send(fd, c->output + c->sent, c->output_length - c->sent, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) { close_control(c); return; }
        c->sent += (size_t)n;
        if (c->sent == c->output_length) close_control(c);
        return;
    }
    do { n = recv(fd, c->input + c->used, sizeof(c->input) - c->used, 0); } while (n < 0 && errno == EINTR);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    if (n <= 0) { close_control(c); return; }
    c->used += (size_t)n;
    if (!c->parsed && control_header(c) < 0) { control_error(c, 400); return; }
    if (!c->parsed) return;
    if (c->used > c->header_length + c->body_length) { control_error(c, 400); return; }
    if (c->used == c->header_length + c->body_length) control_execute(c);
}
static void accept_controls(struct loop *l, int fd, uint32_t events, void *arg)
{
    struct host *h = arg;
    unsigned attempt, i;
    (void)events;
    for (attempt = 0; attempt < CONTROLS; ++attempt) {
        struct control *c;
        struct ucred peer; socklen_t peer_length = sizeof(peer);
        int accepted = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (accepted < 0) return;
        if (getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) || peer.uid != geteuid()) {
            close(accepted); continue;
        }
        for (i = 0; i < CONTROLS && h->controls[i].fd >= 0; ++i) {}
        if (i == CONTROLS) { close(accepted); continue; }
        c = &h->controls[i];
        { uint64_t serial = c->serial + 1; memset(c, 0, sizeof(*c)); c->serial = serial; }
        c->host = h; c->fd = accepted;
        c->deadline = loop_timer_new(l, control_timeout, c);
        if (!c->deadline || loop_fd_add(l, accepted, EPOLLIN | EPOLLRDHUP, control_ready, c)) {
            close_control(c); continue;
        }
        loop_timer_set(c->deadline, 5000);
    }
}
static int bind_control(struct host *h, const char *path)
{
    struct sockaddr_un address = {0};
    struct stat directory;
    char parent[sizeof(address.sun_path)], *slash;
    mode_t previous;
    unsigned i;
    if (*path != '/' || strlen(path) >= sizeof(address.sun_path)) return 0;
    strcpy(parent, path); slash = strrchr(parent, '/');
    if (!slash || slash == parent) return 0;
    *slash = 0;
    if (stat(parent, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != geteuid() || (directory.st_mode & 0077)) return 0;
    h->controls = calloc(CONTROLS, sizeof(*h->controls));
    if (!h->controls) return 0;
    for (i = 0; i < CONTROLS; ++i) h->controls[i].fd = -1;
    address.sun_family = AF_UNIX; strcpy(address.sun_path, path);
    h->control_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (h->control_fd < 0) return 0;
    previous = umask(0077);
    i = (unsigned)bind(h->control_fd, (struct sockaddr *)&address, sizeof(address));
    umask(previous);
    if (i != 0) return 0; /* Never unlink an existing path. */
    strcpy(h->control_path, path);
    if (chmod(path, 0600)) return 0;
    if (listen(h->control_fd, CONTROLS) || loop_fd_add(h->loop, h->control_fd, EPOLLIN, accept_controls, h)) return 0;
    return 1;
}
int steer_prototype_main(int argc, char **argv)
{
    struct host h = {0}; struct client clients[CLIENTS] = {{0}};
    char *document = NULL, status[8192];
    struct steer_prototype_config *snapshot = NULL;
    struct steer_pv1_error error;
    FILE *file;
    size_t length = 0;
    uint64_t revision = 1;
    int result = 1, seed = 0;
    if ((argc != 5 && argc != 7) || strcmp(argv[1], "--config") || strcmp(argv[3], "--control") ||
        (argc == 7 && strcmp(argv[5], "--state-dir"))) return 2;
    if (!initialize_host(&h, clients)) goto cleanup;
    if (steer_draft_resolver_create(h.loop, 2, 64, NULL, NULL, &h.resolver).code) goto cleanup;
    if (argc == 7) {
        if (steer_prototype_store_open(argv[6], &h.store).code) goto cleanup;
        error = steer_prototype_store_load(h.store, &snapshot);
        if (error.code && error.code != STEER_PV1_UNSUPPORTED) goto cleanup;
        seed = error.code == STEER_PV1_UNSUPPORTED;
    }
    if (snapshot) {
        revision = snapshot->generation;
        if (configure(&h, snapshot->document_json, snapshot->document_length, 0, 0, revision) != 200) goto cleanup;
        steer_prototype_config_destroy(snapshot); snapshot = NULL;
    } else {
        document = malloc(STEER_PROTOTYPE_CONFIG_MAX_BYTES + 1);
        if (!document) goto cleanup;
        file = fopen(argv[2], "rb");
        if (!file) { result = 2; goto cleanup; }
        length = fread(document, 1, STEER_PROTOTYPE_CONFIG_MAX_BYTES + 1, file);
        if (ferror(file) || length > STEER_PROTOTYPE_CONFIG_MAX_BYTES) { fclose(file); result = 2; goto cleanup; }
        fclose(file);
        if (configure(&h, document, length, 0, 0, revision) != 200) goto cleanup;
    }
    if (!bind_control(&h, argv[4])) goto cleanup;
    if (h.store && !start_writer(&h)) goto cleanup;
    if (seed) {
        struct steer_prototype_store_transaction *transaction = NULL;
        struct steer_prototype_store_result committed;
        /* Startup has no dispatched packet IO. After this bootstrap, disk
         * operations are exclusively handed to the single writer worker. */
        if (steer_prototype_store_prepare(h.store, h.current->config, &transaction).code) goto cleanup;
        committed = steer_prototype_store_commit(transaction);
        (void)steer_prototype_store_abort(transaction);
        if (committed.phase < STEER_PROTOTYPE_STORE_RENAMED) goto cleanup;
        h.durability_uncertain = committed.phase != STEER_PROTOTYPE_STORE_SYNCED;
    }
    length = status_json(&h, status, sizeof(status));
    printf("READY %.*s\n", (int)length, status); fflush(stdout);
    result = loop_run(h.loop);
cleanup:
    cleanup_host(&h); free(document); steer_prototype_config_destroy(snapshot);
    return result;
}
