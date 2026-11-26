/* SPDX-License-Identifier: GPL-3.0-only
 * Disposable Linux lab host. Not production Steer or a provider loader. */
#define _GNU_SOURCE
#include "stream.h"
#include "buffers.h"
#include "prototype_resources.h"
#include "loop.h"
#include "codec.h"
#include "vless/inbound.h"
#include "loopback_host.h"
#include "route_dial.h"
#include "route_stream.h"
#include "native_stream_backend.h"
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
#include "vless_stream_backend.h"
#include "vless/outbound.h"
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
#include "socks_stream_backend.h"
#endif
#include "policy_route.h"
#include "prototype_config.h"
#include "resolver.h"
#include "prototype_store.h"
#include "control_get.h"
#ifdef STEER_PROTOTYPE_WG_NETNS
#include "prototype_wg.h"
#include "prototype_linked_wg.h"
#include "nltransport.h"
#include "linked_inbound_participant.h"
#include "linked_inbound_recovery.h"
#include "kernel_wg_linux_guard.h"
#include "blake3.h"
#include <steer/draft/device_v1.h>
#endif
#include "prototype_prepare.h"
#include "inbound_tls.h"
#ifdef STEER_PROTOTYPE_HY2
#include "hy2_inbound.h"
#include "hy2_stream_backend.h"
#include "hy2_datagram_backend.h"
#include "hy2_tcp_client.h"
#include "datagram.h"
#include "datagram_routes.h"
#include "qcssl.h"
#endif
#ifdef STEER_PROTOTYPE_SOCKS_UDP
#include "socks_datagram.h"
#endif
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
#include <limits.h>
#include <sys/eventfd.h>

#define CLIENTS 32
#define CAPACITY 16384
#define GENERATIONS 8
#define LISTENERS 32 /* 16 published plus 16 transactionally prepared */
#define HY2_DRAIN_MS 30000u /* host-owned monotonic retirement policy */
#ifndef STEER_PROTOTYPE_HY2_OUTBOUND_DRAIN_MS
#define STEER_PROTOTYPE_HY2_OUTBOUND_DRAIN_MS 30000u
#endif
#define CONTROLS 8
#define CONTROL_INPUT (STEER_PROTOTYPE_CONFIG_MAX_BYTES + 128u)
#define CONTROL_OUTPUT (STEER_PROTOTYPE_CONFIG_MAX_BYTES + 2048u)
struct host;
struct prepared;
struct steer_prototype_prepared_input;
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
    int fd, writing, operation, parsed, waiting_store,waiting_prepare;
    uint64_t serial,deadline_ms;
    uint64_t expected;
    size_t used, header_length, body_length, sent, output_length;
    char input[CONTROL_INPUT], output[CONTROL_OUTPUT];
};
/* One source-linked SOCKS instance per listener slot and generation. Listener
 * sockets may survive publication; their protocol instances never do. Auth
 * secrets remain host-owned process environment strings, as before. */
struct socks_instance {
    uint64_t generation;
    char inbound[65], principal[65];
    const char *user, *password;
    size_t user_length, password_length;
    int admitting;
    int udp_associate;
};
struct generation {
    struct steer_draft_routes *routes;
    struct steer_draft_stream_routes *streams;
    struct steer_draft_native_stream_backend *native;
#ifdef STEER_PROTOTYPE_WG_NETNS
    struct steer_draft_native_stream_backend *wg_native;
    struct steer_draft_wg_stream *wg_stream;
    int wg_staged; /* including staging failures with a possible journal record */
#endif
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
    struct steer_draft_vless_stream_backend *vless[STEER_POLICY_STREAM_BINDINGS_MAX];
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
    struct steer_draft_socks_stream_backend *socks_out[STEER_POLICY_STREAM_BINDINGS_MAX];
#endif
    unsigned prepared_outbounds;
#ifdef STEER_PROTOTYPE_HY2
    struct steer_hy2_stream_backend *hy2_out[STEER_POLICY_STREAM_BINDINGS_MAX];
    struct steer_hy2_datagram_backend *hy2_udp_out[STEER_POLICY_STREAM_BINDINGS_MAX];
    uint32_t udp_index[STEER_POLICY_STREAM_BINDINGS_MAX];
    struct steer_draft_datagram_runtime *datagram_native;
    struct steer_draft_datagram_router *datagrams;
    struct steer_draft_binding_lease *datagram_binding;
    int datagram_retired,datagram_finalized;
#endif
    struct host *host;
    struct steer_policy *policy;
    struct steer_prototype_config *config;
    char *document;
    size_t document_length;
    uint64_t number;
    unsigned references, socks_sessions;
    int preparing;
    struct socks_instance socks[LISTENERS];
};
struct listener_identity {
    int vless;
    char id[65], principal[65];
    const char *user, *password;
    size_t user_length, password_length;
    uint8_t uuid[16];
    const char *token;size_t token_length;
    uint8_t certificate_hash[32],private_key_hash[32]; /* never exposed in status/logs */
};
struct listener {
    struct host *host;
    int fd;
    int active;
    struct steer_prototype_listener spec;
    struct listener_identity identity;
#ifdef STEER_PROTOTYPE_HY2
    struct steer_draft_hy2 *hy2;
    uint64_t admission_epoch,drain_deadline;
    int retiring;
#endif
};
enum phase { HANDSHAKE, REPLY, DIALING, RELAY, CLOSING, UDP_CONTROL };
struct client;
struct direction {
    struct client *client;
    struct steer_pv1_buffer *buffer;
    struct steer_pv1_async_start operation;
    uint32_t offset, length, bytes, error;
    int pending, completed, writing, eof, finishing, finished;
};
struct host {
    struct loop *loop;
    struct steer_pv1_host *buffers;
    const struct steer_pv1_buffer_api *buffer_api;
    struct steer_draft_stream_runtime *runtime;
    struct steer_draft_backend_runtime *backend_runtime;
    struct steer_draft_resolver *resolver;
    struct steer_prototype_store *store;
#ifdef STEER_PROTOTYPE_WG_NETNS
    struct steer_prototype_wg *wg;
    struct steer_prototype_linked_wg *linked_wg;
    uint64_t wg_next;
    int wg_fenced,wg_retire_error;
    int inbound_runtime,inbound_shutdown_error,inbound_removed;
    struct steer_draft_wg_linux_guard inbound_guard;
    struct steer_linked_inbound inbound;
#ifdef STEER_PROTOTYPE_INBOUND_FAULT
    struct steer_draft_wg_backend inbound_fault_backend;
#endif
#endif
    struct store_writer writer;
    struct steer_prototype_prepare *preparer;
    struct steer_prototype_socks_vpn_allowlist socks_vpn;
#ifdef STEER_PROTOTYPE_HY2
    struct steer_draft_hy2_datagram_budget datagram_budget;
#endif
    int store_busy, durability_uncertain;
    int experimental_durable_split, split_fenced;
    char *selected_document;
    size_t selected_length;
    uint64_t selected_revision;
#ifdef STEER_PROTOTYPE_SPLIT_FAULT
    int test_fail_after_sync;
#endif
    struct generation generations[GENERATIONS], *current;
    struct listener listeners[LISTENERS];
    struct loop_timer *work;
    struct client *clients;
    int stopping;
    int control_fd;
    char control_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    struct control *controls;
    unsigned live;
    uint64_t next_admission_epoch;
};
struct prepared {
    struct generation *generation;
    unsigned keep[LISTENERS], created[LISTENERS];
    int validation_only;
#ifdef STEER_PROTOTYPE_WG_NETNS
    int inbound_slot;
    struct steer_draft_wg_revision inbound_choice;
#endif
    struct control *control;
    uint64_t control_serial;
};
struct client {
    struct host *host;
    struct generation *generation;
#ifdef STEER_PROTOTYPE_WG_NETNS
    uint64_t wg_revision;
#endif
    struct socks_instance *socks; /* pins the instance and its parent generation */
    struct listener_identity identity;
    struct steer_pv1_stream_ref down, up;
    struct loop_timer *deadline;
    struct direction directions[2]; /* down->up, up->down */
    struct s5_codec codec;
    struct vl_decoder vless;
    struct steer_pv1_endpoint source;
    uint8_t source_bytes[16];
    struct steer_pv1_async_start route;
    struct s5_address bound;
    uint32_t route_error, dial_failure;
    enum phase phase, after_reply;
    uint32_t input_offset, input_length;
    int live, authenticated, route_pending, route_completed, release_failed;
#ifdef STEER_PROTOTYPE_SOCKS_UDP
    struct steer_socks_datagram *udp;
#endif
};
static void advance(struct client *);
static void reap_generations(struct host *);
static void close_control(struct control *);
static void stop_writer(struct host *);
static void close_listener(struct host *,struct listener *);
#ifdef STEER_PROTOTYPE_HY2
static int reap_hy2_listeners(struct host *);
static void prepared_ready(void *,struct steer_prototype_prepared_input *);
#endif
/* All instance transitions run on the existing owning shard. Preparation is
 * resource-free; activating after commit cannot fail. */
static void prepare_socks(struct generation *g, unsigned slot,
                          const struct listener *listener)
{
    if (listener->spec.protocol != STEER_PROTOTYPE_SOCKS) return;
    struct socks_instance *instance = &g->socks[slot];
    const struct listener_identity *id = &listener->identity;
    instance->generation = g->number;
    strcpy(instance->inbound, id->id);
    strcpy(instance->principal, id->principal);
    instance->user = id->user; instance->user_length = id->user_length;
    instance->password = id->password; instance->password_length = id->password_length;
    for(unsigned i=0;g->config && i<g->config->listener_count;i++)
        if(!strcmp(g->config->listeners[i].id,id->id))
            instance->udp_associate=g->config->listeners[i].socks_udp_associate;
}
static void set_socks_admission(struct generation *g, int active)
{
    if (g) for (unsigned i = 0; i < LISTENERS; ++i)
        g->socks[i].admitting = active && g->socks[i].generation != 0;
}
static void close_client(struct client *c)
{
    if (!c->live || c->phase == CLOSING) return;
    c->phase = CLOSING;
#ifdef STEER_PROTOTYPE_SOCKS_UDP
    if(c->udp)steer_socks_datagram_stop(c->udp);
#endif
    loop_timer_stop(c->deadline);
    if (c->route_pending) c->route.operation.api->cancel(c->route.operation.handle);
    if (c->down.handle) c->down.api->close(c->down.handle);
    if (c->up.handle) c->up.api->close(c->up.handle);
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
static void finish_done(void *arg, struct steer_pv1_error error)
{
    struct direction *d = arg;
    d->error = error.code; d->bytes = 0; d->completed = 1;
    loop_timer_set(d->client->host->work, 0);
}
static int submit(struct direction *d, struct steer_pv1_stream_ref stream,
                  int writing, uint32_t offset, uint32_t length)
{
    d->writing = writing; d->offset = offset; d->length = length;
    d->operation = writing ? stream.api->write(stream.handle, d->buffer, offset, length, done, d) :
                             stream.api->read(stream.handle, d->buffer, offset, length, done, d);
    if (d->operation.disposition != STEER_PV1_PENDING) {
        close_client(d->client); return 0;
    }
    d->pending = 1;
    return 1;
}
static uint8_t *view(struct client *c, unsigned index)
{
    struct steer_pv1_mut_span span;
    if (c->host->buffer_api->writable(c->host->buffers, c->directions[index].buffer, &span).code) {
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
    if (!c->socks) {
        if (code) { close_client(c); return; }
        c->codec.reply_length = vl_response_encode(c->codec.reply, sizeof(c->codec.reply));
        reply(c, RELAY);
    } else {
        /* Some layered protocols have no final-target BND.ADDR/BND.PORT. */
        const struct s5_address unspecified = {.type=1,.length=4};
        if (!s5_dial_result(&c->codec, code, !code && !bound ? &unspecified : bound)) {
            close_client(c); return;
        }
        reply(c, code ? CLOSING : RELAY);
    }
}
static int verify_uuid(void *arg, const uint8_t uuid[16])
{
    struct client *c = arg;
    c->authenticated = !memcmp(uuid, c->identity.uuid, sizeof(c->identity.uuid));
    return c->authenticated;
}
static int verify_socks(void *arg, const uint8_t *user, size_t un,
                        const uint8_t *password, size_t pn)
{
    struct client *c = arg;
    const struct socks_instance *identity = c->socks;
    /* Lab credentials only; no logging. Not an authentication database. */
    c->authenticated = un == identity->user_length && pn == identity->password_length &&
           !memcmp(user, identity->user, un) && !memcmp(password, identity->password, pn);
    return c->authenticated;
}
static void route_done(void *arg, struct steer_pv1_error error,
                       struct steer_pv1_stream_ref stream, const struct steer_pv1_endpoint *bound,
                       const struct steer_pv1_endpoint *peer,
                       const struct steer_pv1_stream_open_diagnostic *diagnostic)
{
    struct client *c = arg;
    (void)peer;
    c->route_error = error.code; c->dial_failure = diagnostic ? diagnostic->dial_failure : 0;
    c->route_completed = 1; c->up = stream;
    if (bound) {
        c->bound.type = bound->tag == STEER_PV1_ENDPOINT_IPV4 ? 1 : 4;
        c->bound.length = (uint8_t)bound->address.len; c->bound.port = bound->port;
        memcpy(c->bound.bytes, bound->address.data, bound->address.len);
    }
    if (c->phase == CLOSING && stream.handle) stream.api->close(stream.handle);
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
/* The source-linked inbound hands the SDK accepted-flow record to the shared
 * host router. Only the host selects/dials a backend; metadata is call-borrowed. */
static void accept_flow(struct client *c, const struct steer_pv1_flow_metadata *flow)
{
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(c->host->wg_fenced){dial_reply(c,2,NULL);return;}
    if(c->host->wg&&c->wg_revision!=steer_prototype_wg_revision(c->host->wg)){
        dial_reply(c,2,NULL);
        return;
    }
#endif
    c->phase = DIALING;
    loop_timer_set(c->deadline, 5000);
    c->route = steer_draft_stream_route_open(c->generation->streams, flow,
        ((uint64_t)loop_now_ms() + 5000u) * 1000000u, route_done, c);
    if (c->route.disposition == STEER_PV1_PENDING) c->route_pending = 1;
    else dial_reply(c, route_reply_code(c->route.error.code, 0), NULL);
}
static void publish_flow(struct client *c, const struct s5_address *target)
{
    struct steer_pv1_flow_metadata flow = {0};
    const char *inbound = c->socks ? c->socks->inbound : c->identity.id;
    const char *principal = c->socks ? c->socks->principal : c->identity.principal;
    flow.size = sizeof(flow); flow.version = STEER_PV1_DRAFT_LAYOUT;
    flow.generation = c->socks ? c->socks->generation : c->generation->number;
    flow.inbound_id.data = (const uint8_t *)inbound;
    flow.inbound_id.len = (uint32_t)strlen(inbound);
    if (c->authenticated) {
        flow.principal_id.data = (const uint8_t *)principal;
        flow.principal_id.len = (uint32_t)strlen(principal);
    }
    flow.source = c->source; flow.flow_class = STEER_PV1_FLOW_STREAM;
    flow.destination.size = sizeof(flow.destination);
    flow.destination.version = STEER_PV1_DRAFT_LAYOUT;
    flow.destination.tag = target->type == 1 ? STEER_PV1_ENDPOINT_IPV4 :
        target->type == 4 ? STEER_PV1_ENDPOINT_IPV6 : STEER_PV1_ENDPOINT_DOMAIN;
    flow.destination.address.data = target->bytes;
    flow.destination.address.len = target->length;
    flow.destination.port = target->port;
    accept_flow(c, &flow);
}
#ifdef STEER_PROTOTYPE_SOCKS_UDP
static void socks_udp_wake(void *user) {
    struct client *c=user;loop_timer_set(c->host->work,0);
}
static int socks_udp_authorize(void *user,const struct s5_address *a) {
    struct client *c=user;
    struct steer_pv1_endpoint dest={.size=sizeof dest,.version=STEER_PV1_DRAFT_LAYOUT,
        .tag=a->type==1?STEER_PV1_ENDPOINT_IPV4:a->type==4?STEER_PV1_ENDPOINT_IPV6:STEER_PV1_ENDPOINT_DOMAIN,
        .address={a->bytes,a->length},.port=a->port};
    const char *principal=c->authenticated?c->socks->principal:"";
    struct steer_policy_input input={c->generation->number,
        {(const uint8_t *)c->socks->inbound,(uint32_t)strlen(c->socks->inbound)},
        {(const uint8_t *)principal,(uint32_t)strlen(principal)},&dest};
    struct steer_policy_decision decision;
    return steer_policy_evaluate(c->generation->policy,&input,&decision).code ||
        decision.action!=STEER_POLICY_DIRECT;
}
static struct steer_pv1_error socks_udp_acquire(void *user,struct steer_pv1_span inbound,
    struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_hy2_datagram_binding *out) {
    struct client *c=user;struct generation *g=c->generation;(void)inbound;(void)principal;(void)epoch;
    if(c->phase==CLOSING || c->host->current!=g || !g->datagrams)
        return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};
    struct steer_pv1_error e=steer_draft_binding_admit(g->datagram_binding,g->number,STEER_PV1_FLOW_DATAGRAM);
    if(e.code)return e;
    g->references++;
    *out=(struct steer_draft_hy2_datagram_binding){steer_draft_datagram_router_api(),g->datagrams,g,g->number};
    return (struct steer_pv1_error){0,0};
}
static void socks_udp_release(void *user,struct steer_draft_hy2_datagram_binding *binding) {
    struct client *c=user;struct generation *g=binding->lease;
    if(!g||!g->references||steer_draft_binding_unpin(g->datagram_binding).code)abort();
    g->references--;memset(binding,0,sizeof *binding);socks_udp_wake(c);
}
static void socks_udp_start(struct client *c) {
    struct s5_address bound;struct sockaddr_in peer={0};
    const char *principal=c->authenticated?c->socks->principal:"";
    if(c->input_length || c->source.tag!=STEER_PV1_ENDPOINT_IPV4 ||
       c->host->current!=c->generation)goto fail;
    peer.sin_family=AF_INET;peer.sin_port=htons(c->source.port);
    memcpy(&peer.sin_addr,c->source_bytes,4);
    struct steer_socks_datagram_config cfg={
        .inbound={(const uint8_t *)c->socks->inbound,(uint32_t)strlen(c->socks->inbound)},
        .principal={(const uint8_t *)principal,(uint32_t)strlen(principal)},
        .tcp_peer=peer,.requested_peer=c->codec.target,.generation=c->generation->number,
        .admission_epoch=c->generation->number,.idle_ms=60000,.user=c,
        .authorize=socks_udp_authorize,.wake=socks_udp_wake};
    struct steer_draft_hy2_datagram_services svc={c->host->loop,c->host->buffers,
        &c->host->datagram_budget,c,socks_udp_acquire,socks_udp_release};
    if(steer_socks_datagram_open(&cfg,&svc,&c->udp,&bound))goto fail;
    if(!s5_udp_result(&c->codec,0,&bound)){close_client(c);return;}
    reply(c,UDP_CONTROL);return;
fail:
    if(s5_udp_result(&c->codec,1,NULL))reply(c,CLOSING);else close_client(c);
}
#endif
static void handshake(struct client *c)
{
    uint8_t *p = view(c, 0);
    size_t consumed;
    enum s5_event event;
    if (!p) return;
    if (!c->socks) {
        enum vl_result result = vl_decoder_feed(&c->vless, p + c->input_offset,
                                                c->input_length, &consumed);
        c->input_offset += (uint32_t)consumed;
        c->input_length -= (uint32_t)consumed;
        if (result < 0 || (result == VL_DONE && c->vless.request.command != 1)) {
            close_client(c); return;
        }
        if (result == VL_DONE) {
            const struct vl_request *r = &c->vless.request;
            struct s5_address target;
            target.type = r->address_type == 1 ? 1 : r->address_type == 3 ? 4 : 3;
            target.length = (uint8_t)r->address_length; target.port = r->port;
            memcpy(target.bytes, r->address, r->address_length);
            publish_flow(c, &target); return;
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
    } else if (event == S5_CONNECT) publish_flow(c, &c->codec.target);
#ifdef STEER_PROTOTYPE_SOCKS_UDP
    else if (event == S5_UDP_ASSOCIATE) socks_udp_start(c);
#endif
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
    struct steer_pv1_stream_ref source = index ? c->up : c->down;
    struct steer_pv1_stream_ref target = index ? c->down : c->up;
    if (d->finishing) {
        d->finishing = 0; d->finished = 1;
        if (c->directions[1-index].finished) close_client(c);
        return;
    }
    if (d->writing) {
        if (!d->bytes) { close_client(c); return; }
        if (d->bytes < d->length) {
            (void)submit(d, target, 1, d->offset + d->bytes, d->length - d->bytes);
        } else (void)submit(d, source, 0, 0, CAPACITY);
    } else if (d->bytes) (void)submit(d, target, 1, 0, d->bytes);
    else {
        d->eof = 1;
        if (!(target.api->capabilities(target.handle) & STEER_PV1_STREAM_CAP_HALF_CLOSE)) {
            close_client(c); return;
        }
        d->operation = target.api->finish_write(target.handle, finish_done, d);
        if (d->operation.disposition != STEER_PV1_PENDING) close_client(c);
        else { d->pending = 1; d->finishing = 1; }
    }
}
static void advance(struct client *c)
{
    unsigned i;
#ifdef STEER_PROTOTYPE_SOCKS_UDP
    if(c->udp && c->phase!=CLOSING && steer_socks_datagram_stopped(c->udp))close_client(c);
#endif
    if (c->route_completed) {
        c->route.operation.api->release(c->route.operation.handle);
        c->route_pending = c->route_completed = 0;
        if (c->phase != CLOSING) {
            if (!c->route_error) loop_timer_set(c->deadline, 30000);
            dial_reply(c, route_reply_code(c->route_error, c->dial_failure),
                       !c->route_error && c->bound.length ? &c->bound : NULL);
        }
    }
    for (i = 0; i < 2; ++i) {
        struct direction *d = &c->directions[i];
        if (!d->completed) continue;
        d->operation.operation.api->release(d->operation.operation.handle);
        d->pending = d->completed = 0;
        if (c->phase == CLOSING) continue;
        if (d->error) { close_client(c); continue; }
        if (c->phase == UDP_CONTROL) {
            close_client(c); /* EOF or unexpected control payload */
        } else if (c->phase == RELAY) {
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
                if (c->phase == RELAY) relay_start(c);
                else if(c->phase == UDP_CONTROL) {
                    loop_timer_stop(c->deadline);
                    (void)submit(&c->directions[0],c->down,0,0,CAPACITY);
                } else handshake(c);
            }
        }
    }
    if (c->phase == CLOSING && !c->release_failed && !c->route_pending &&
        !c->directions[0].pending && !c->directions[1].pending) {
#ifdef STEER_PROTOTYPE_SOCKS_UDP
        if(c->udp) {
            if(steer_socks_datagram_destroy(c->udp)) {
                if(steer_socks_datagram_quarantined(c->udp)) {
                    c->release_failed=1;
                    fputs("SOCKS UDP provider release refused; client quarantined\n",stderr);
                } else loop_timer_set(c->host->work,10);
                return;
            }
            c->udp=NULL;
        }
#endif
        struct steer_pv1_stream_ref *streams[2] = {&c->up, &c->down};
        for (i = 0; i < 2; ++i) if (streams[i]->handle) {
            if (streams[i]->api->release(streams[i]->handle).code) {
                /* Contract violation: retain the handle, client budget and
                 * generation. Do not retry a foreign release on every pump. */
                c->release_failed = 1;
                fputs("stream provider release refused; client quarantined\n", stderr);
                return;
            }
            memset(streams[i], 0, sizeof(*streams[i]));
        }
        for (i = 0; i < 2; ++i)
            if (c->directions[i].buffer)
                c->host->buffer_api->release(c->host->buffers, c->directions[i].buffer);
        loop_timer_free(c->deadline); c->deadline = NULL;
        /* All route/IO callbacks and origin operation references are gone. */
        if (c->socks) c->generation->socks_sessions--;
        else c->generation->references--;
        c->live = 0; c->host->live--;
    }
}
static void work(struct loop *l, struct loop_timer *t, void *arg)
{
    struct host *h = arg; unsigned i;
    (void)t;
    for (i = 0; i < CLIENTS; ++i) if (h->clients[i].live) advance(&h->clients[i]);
#ifdef STEER_PROTOTYPE_HY2
    int pending=reap_hy2_listeners(h);
#else
    int pending=0;
#endif
    if(h->stopping&&h->preparer) {
        if(!steer_prototype_prepare_destroy(h->preparer))h->preparer=NULL;
        else { pending=1;loop_timer_set(h->work,10); }
    }
    reap_generations(h);
    if (h->stopping && !h->live && !h->store_busy && !pending) {
        h->current = NULL;
        reap_generations(h); /* release route-generation resolver references */
        unsigned generations = 0;
        for (i = 0; i < GENERATIONS; ++i) generations += h->generations[i].number != 0;
        if (generations || (h->resolver && steer_draft_resolver_jobs(h->resolver))) {
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
        struct generation *g = h->current;
        if (!listener->active || !g
#ifdef STEER_PROTOTYPE_WG_NETNS
            ||h->wg_fenced
#endif
        ) { close(accepted); continue; }
        struct socks_instance *socks = NULL;
        if (listener->spec.protocol == STEER_PROTOTYPE_SOCKS) {
            socks = &g->socks[listener - h->listeners];
            if (!socks->admitting) { close(accepted); continue; }
        } else if (listener->spec.protocol != STEER_PROTOTYPE_VLESS) { close(accepted); continue; }
        for (i = 0; i < CLIENTS && h->clients[i].live; ++i) {}
        if (i == CLIENTS) { close(accepted); continue; }
        c = &h->clients[i]; memset(c, 0, sizeof(*c));
        c->host = h; c->live = 1; h->live++;
        c->generation = g; c->socks = socks;
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(h->wg)c->wg_revision=steer_prototype_wg_revision(h->wg);
#endif
        if (socks) g->socks_sessions++;
        else { g->references++; c->identity = listener->identity; }
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
        struct steer_pv1_stream *native = NULL;
        if (!c->deadline || steer_draft_stream_adopt(h->runtime, accepted, &native).code) {
            close(accepted); close_client(c); continue;
        }
        if (steer_draft_backend_wrap_native(h->backend_runtime, native, NULL, &c->down).code) {
            steer_draft_stream_api()->close(native);
            (void)steer_draft_stream_api()->release(native);
            close_client(c); continue;
        }
        if (h->buffer_api->allocate(h->buffers, CAPACITY, &c->directions[0].buffer).code ||
            h->buffer_api->allocate(h->buffers, CAPACITY, &c->directions[1].buffer).code) {
            close_client(c); continue;
        }
        if (socks) {
            s5_init(&c->codec, socks->user ? S5_USERPASS : S5_NOAUTH, verify_socks, c);
#ifdef STEER_PROTOTYPE_SOCKS_UDP
            if(socks->udp_associate && !s5_enable_udp(&c->codec)){close_client(c);continue;}
#endif
        }
        else vl_decoder_init(&c->vless, verify_uuid, c);
        loop_timer_set(c->deadline, 5000);
        (void)submit(&c->directions[0], c->down, 0, 0, CAPACITY);
    }
}
#ifdef STEER_PROTOTYPE_HY2
static void retire_hy2_outbounds(struct generation *g) {
    if(g) for(unsigned i=0;i<g->prepared_outbounds;i++) {
        steer_hy2_stream_backend_retire(g->hy2_out[i]);
        steer_hy2_datagram_backend_retire(g->hy2_udp_out[i]);
    }
}
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
static uint64_t inbound_deadline(void);
#endif
static void stop(struct loop *l, int signo, void *arg)
{
    struct host *h = arg; unsigned i;
    (void)l; (void)signo;
    h->stopping = 1;
#ifdef STEER_PROTOTYPE_WG_NETNS
    /* The loop serializes this decision with writer_ready. A staged slot
     * takes the shutdown finish path after its actual writer receipt. */
    if(h->inbound_runtime&&!h->inbound.staged&&h->inbound.committed.generation&&
       !h->inbound.committed.without_wg){
        h->inbound.fenced=1;
        h->inbound.barrier_state=STEER_INBOUND_BARRIER_UNKNOWN;
        int rc=h->inbound.barrier_close(h->inbound.context,&h->inbound.candidate.guard,
            inbound_deadline(),&h->inbound.barrier_state);
        if(rc||h->inbound.barrier_state!=STEER_INBOUND_BARRIER_CLOSED)h->inbound_shutdown_error=1;
    }
#endif
    set_socks_admission(h->current, 0);
#ifdef STEER_PROTOTYPE_HY2
    retire_hy2_outbounds(h->current);
#endif
    if(h->preparer)steer_prototype_prepare_stop(h->preparer);
    if (h->control_fd >= 0) {
        loop_fd_del(h->loop, h->control_fd); close(h->control_fd); h->control_fd = -1;
    }
    if (h->controls) for (i = 0; i < CONTROLS; ++i) close_control(&h->controls[i]);
    for (i = 0; i < LISTENERS; ++i) close_listener(h,&h->listeners[i]);
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
static struct steer_pv1_error select_stream(void *context,
    const struct steer_pv1_flow_metadata *flow, uint32_t *index)
{
    struct steer_policy_input input = {flow->generation, flow->inbound_id,
                                      flow->principal_id, &flow->destination};
    struct steer_policy_decision decision;
    struct steer_pv1_error error = steer_policy_evaluate(context, &input, &decision);
    *index = STEER_DRAFT_STREAM_ROUTE_BLOCK;
    if (!error.code) {
        if (decision.action == STEER_POLICY_DIRECT) *index = 0;
        else if (decision.action >= STEER_POLICY_STREAM_BINDING_BASE)
            *index = 1 + decision.action - STEER_POLICY_STREAM_BINDING_BASE;
    }
    return error;
}
#ifdef STEER_PROTOTYPE_WG_NETNS
static struct steer_pv1_error select_wg_stream(void *context,const struct steer_pv1_flow_metadata *flow,
    uint32_t *index){
    const struct steer_prototype_wg *w=context;
    /* This registry has exactly one binding: the kernel-pinned connector.
     * No general direct or resolver binding is installed in this profile. */
    *index=steer_prototype_wg_select(w,steer_prototype_wg_revision(w),flow)?0:STEER_DRAFT_STREAM_ROUTE_BLOCK;
    return (struct steer_pv1_error){STEER_PV1_OK,0};
}
#endif
static void generation_retired(void *arg)
{
    struct generation *g = arg;
    loop_timer_set(g->host->work, 0);
}
struct outbound_credentials {
    uint8_t uuid[16];
    struct steer_pv1_span username, password;
#ifdef STEER_PROTOTYPE_HY2
    struct steer_hy2_profile *hy2;
    struct steer_hy2_profile *hy2_udp;
#endif
};
static int prepare_stream_routes(struct host *h, struct generation *g,
                                 struct outbound_credentials *credentials)
{
    g->host = h;
    if (steer_draft_native_stream_backend_create(h->loop, h->runtime, h->backend_runtime,
        h->resolver, g->number, g->number, CLIENTS, 16*CLIENTS,
        generation_retired, g, &g->native).code) return 0;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->wg&&steer_draft_native_stream_socket_guard(g->native,steer_prototype_wg_bind_stream,h->wg).code)
        return 0;
#endif
    struct steer_draft_stream_binding bindings[1 + STEER_POLICY_STREAM_BINDINGS_MAX];
    unsigned count = 1;
    bindings[0] = *steer_draft_native_stream_binding(g->native);
#if defined(STEER_PROTOTYPE_VLESS_OUTBOUND) || defined(STEER_PROTOTYPE_SOCKS_OUTBOUND) || defined(STEER_PROTOTYPE_HY2) || defined(STEER_PROTOTYPE_WG_NETNS)
    if (g->config) for (uint32_t i = 0; i < g->config->stream_outbound_count; ++i) {
        const struct steer_prototype_stream_outbound *cfg = &g->config->stream_outbounds[i];
#if defined(STEER_PROTOTYPE_VLESS_OUTBOUND) || defined(STEER_PROTOTYPE_SOCKS_OUTBOUND)
        struct steer_pv1_endpoint upstream = {sizeof upstream, STEER_PV1_DRAFT_LAYOUT,
            cfg->endpoint_tag, {cfg->address, cfg->endpoint_tag == STEER_PV1_ENDPOINT_IPV4 ? 4 : 16},
            cfg->port, 0};
#endif
        switch(cfg->protocol){
#ifdef STEER_PROTOTYPE_WG_NETNS
        case STEER_PROTOTYPE_WIREGUARD:
            if(!g->wg_stream||steer_draft_native_stream_backend_create(h->loop,h->runtime,h->backend_runtime,
                NULL,g->number,g->number==1?2:1,CLIENTS,16*CLIENTS,generation_retired,g,&g->wg_native).code||
               steer_draft_native_stream_socket_guard(g->wg_native,steer_draft_wg_stream_bind,g->wg_stream).code)return 0;
            bindings[count++]=*steer_draft_native_stream_binding(g->wg_native);
            break;
#endif
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
        case STEER_PROTOTYPE_VLESS:
            if (steer_draft_vless_stream_backend_create(h->loop, h->buffers, &bindings[0],
                &upstream, credentials[i].uuid, g->number, i + 1, CLIENTS, 2*CLIENTS, 2*CLIENTS*CAPACITY,
                16*CLIENTS, generation_retired, g, &g->vless[i]).code) return 0;
            bindings[count++] = *steer_draft_vless_stream_binding(g->vless[i]);
            break;
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        case STEER_PROTOTYPE_SOCKS:
            if (steer_draft_socks_stream_backend_create(h->loop, h->buffers, &bindings[0],
                &upstream, credentials[i].username, credentials[i].password, g->number, i + 1,
                CLIENTS, 16*CLIENTS, generation_retired, g, &g->socks_out[i]).code) return 0;
            bindings[count++] = *steer_draft_socks_stream_binding(g->socks_out[i]);
            break;
#endif
#ifdef STEER_PROTOTYPE_HY2
        case STEER_PROTOTYPE_HYSTERIA2:
            if (steer_hy2_stream_backend_create(h->loop,h->buffers,credentials[i].hy2,
                g->number,i+1,4*CLIENTS,2*CLIENTS*CAPACITY,16*CLIENTS,
                STEER_PROTOTYPE_HY2_OUTBOUND_DRAIN_MS,generation_retired,g,&g->hy2_out[i]).code)return 0;
            credentials[i].hy2=NULL;
            bindings[count++]=*steer_hy2_stream_binding(g->hy2_out[i]);
            break;
#endif
        default: return 0;
        }
        g->prepared_outbounds++;
    }
#else
    (void)credentials;
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->wg)return !steer_draft_stream_routes_create(h->loop,g->number,CLIENTS,CLIENTS,
        bindings,count,select_wg_stream,h->wg,NULL,&g->streams).code;
#endif
    return !steer_draft_stream_routes_create(h->loop, g->number, CLIENTS, CLIENTS,
        bindings, count, select_stream, g->policy,
        NULL, &g->streams).code;
}
#ifdef STEER_PROTOTYPE_HY2
static struct steer_pv1_error select_datagram(void *context,const struct steer_pv1_flow_metadata *flow,uint32_t *action){
    struct generation *g=context;
    struct steer_policy_input input={flow->generation,flow->inbound_id,flow->principal_id,&flow->destination};
    struct steer_policy_decision decision;struct steer_pv1_error error=steer_policy_evaluate(g->policy,&input,&decision);
    *action=STEER_DRAFT_DATAGRAM_ROUTE_BLOCK_INDEX;
    if(!error.code&&decision.action==STEER_POLICY_DIRECT)*action=0;
    else if(!error.code&&decision.action>=STEER_POLICY_STREAM_BINDING_BASE) {
        uint32_t i=decision.action-STEER_POLICY_STREAM_BINDING_BASE;
        if(i<STEER_POLICY_STREAM_BINDINGS_MAX)*action=g->udp_index[i];
    }
    return error;
}
static void datagram_finalized(void *user,const struct steer_draft_binding_identity *identity){
    struct generation *g=user;(void)identity;g->datagram_finalized=1;loop_timer_set(g->host->work,0);
}
static void retire_datagram_generation(struct generation *g){
    if(g->datagrams)steer_draft_datagram_router_quiesce(g->datagrams);
    if(g->datagram_binding&&!g->datagram_retired){
        (void)steer_draft_binding_retire(g->datagram_binding);g->datagram_retired=1;
    }
}
static void datagram_drained(void *user,struct steer_draft_datagram_router *router){
    struct generation *g=user;if(g->datagrams!=router)abort();
    /* Destroy only from the separate host-owner turn, after notification. */
    loop_timer_set(g->host->work,0);
}
static int prepare_datagram_routes(struct host *h,struct generation *g,struct outbound_credentials *credentials){
    struct steer_draft_binding_identity identity={.size=sizeof identity,.version=STEER_PV1_DRAFT_LAYOUT,
        .generation=g->number,.instance_token=g->number,.provider_id={(const uint8_t *)"native-udp",10},
        .prepared_capabilities=STEER_DRAFT_DATAGRAM_BINDING_PREPARED|STEER_DRAFT_DATAGRAM_BINDING_TARGET_DOMAIN,.flow_class=STEER_PV1_FLOW_DATAGRAM};
    struct steer_draft_datagram_route_limits limits={64,64,8,256,8*65507+262144,60000000000ULL};
    if(steer_draft_binding_lease_create(h->loop,&identity,4096,datagram_finalized,g,&g->datagram_binding).code||
       steer_draft_datagram_runtime_create(h->loop,h->buffers,64,256,8*65507+262144,&g->datagram_native).code)return 0;
    if(h->resolver&&steer_draft_datagram_use_resolver(g->datagram_native,h->resolver).code)return 0;
    struct steer_draft_datagram_binding bindings[1+STEER_POLICY_STREAM_BINDINGS_MAX];
    uint32_t count=1;
    bindings[0]=(struct steer_draft_datagram_binding){h->loop,g->datagram_binding,steer_draft_datagram_backend_api(),g->datagram_native};
    for(unsigned i=0;i<STEER_POLICY_STREAM_BINDINGS_MAX;i++)g->udp_index[i]=STEER_DRAFT_DATAGRAM_ROUTE_BLOCK_INDEX;
    if(g->config)for(unsigned i=0;i<g->config->stream_outbound_count;i++) {
        if(!g->config->stream_outbounds[i].hy2_datagram)continue;
        if(!credentials||!credentials[i].hy2_udp||
           steer_hy2_datagram_backend_create(h->loop,h->buffers,credentials[i].hy2_udp,g->number,i+1,
             4*CLIENTS,2*CLIENTS*CAPACITY,16*CLIENTS,STEER_PROTOTYPE_HY2_OUTBOUND_DRAIN_MS,
             generation_retired,g,&g->hy2_udp_out[i]).code)return 0;
        credentials[i].hy2_udp=NULL;
        g->udp_index[i]=count;bindings[count++]=*steer_hy2_datagram_binding(g->hy2_udp_out[i]);
    }
    if(steer_draft_datagram_router_create_registry(h->loop,h->buffers,g->datagram_binding,
        bindings,count,&limits,select_datagram,g,&g->datagrams).code)return 0;
    return !steer_draft_datagram_router_on_drained(g->datagrams,datagram_drained,g).code;
}
#endif
static int destroy_generation(struct generation *g)
{
    g->preparing = 0;
    set_socks_admission(g, 0);
    if (g->references || g->socks_sessions) return 0;
#ifdef STEER_PROTOTYPE_HY2
    retire_hy2_outbounds(g);
    retire_datagram_generation(g);
    if(g->datagrams){
        steer_draft_datagram_router_close(g->datagrams);
        if(steer_draft_datagram_router_destroy(g->datagrams).code)return 0;
        g->datagrams=NULL;
    }
    if(g->datagram_native){if(steer_draft_datagram_runtime_destroy(g->datagram_native).code)return 0;g->datagram_native=NULL;}
    if(g->datagram_binding){
        if(!g->datagram_finalized||steer_draft_binding_lease_destroy(g->datagram_binding).code)return 0;
        g->datagram_binding=NULL;
    }
#endif
    if (g->streams) {
        if (steer_draft_stream_routes_destroy(g->streams).code) return 0;
        g->streams = NULL;
    }
    /* Release router pins first, then layers, then the lower TCP binding. */
    for (unsigned i = 0; i < g->prepared_outbounds; ++i) {
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
        if(g->vless[i])(void)steer_draft_vless_stream_backend_retire(g->vless[i]);
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        steer_draft_socks_stream_backend_retire(g->socks_out[i]);
#endif
    }
    while (g->prepared_outbounds) {
        unsigned i = g->prepared_outbounds - 1;
        (void)i;
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
        if(g->vless[i]&&steer_draft_vless_stream_backend_destroy(g->vless[i]).code)return 0;
        g->vless[i]=NULL;
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        if(g->socks_out[i]&&steer_draft_socks_stream_backend_destroy(g->socks_out[i]).code)return 0;
        g->socks_out[i]=NULL;
#endif
#ifdef STEER_PROTOTYPE_HY2
        if(g->hy2_out[i]&&steer_hy2_stream_backend_destroy(g->hy2_out[i]).code)return 0;
        g->hy2_out[i]=NULL;
        if(g->hy2_udp_out[i]&&steer_hy2_datagram_backend_destroy(g->hy2_udp_out[i]).code)return 0;
        g->hy2_udp_out[i]=NULL;
#endif
        g->prepared_outbounds--;
    }
    if (g->native) {
        (void)steer_draft_native_stream_backend_retire(g->native);
        if (steer_draft_native_stream_backend_destroy(g->native).code) return 0;
        g->native = NULL;
    }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(g->wg_native){
        (void)steer_draft_native_stream_backend_retire(g->wg_native);
        if(steer_draft_native_stream_backend_destroy(g->wg_native).code)return 0;
        g->wg_native=NULL;
    }
    uint64_t resource=steer_draft_wg_stream_generation(g->wg_stream);
    steer_draft_wg_stream_destroy(g->wg_stream);
    g->wg_stream=NULL;
    if(g->wg_staged&&!g->host->wg_fenced){
        if(!resource)resource=g->number; /* failed physical staging, possibly journaled */
        int pinned=0;
        for(unsigned i=0;i<GENERATIONS;i++)
            if(steer_draft_wg_stream_generation(g->host->generations[i].wg_stream)==resource)pinned=1;
        if(!pinned&&steer_linked_wg_retire(g->host->linked_wg,resource))
            g->host->wg_retire_error=1; /* retain ambiguous journal state until restart */
        g->wg_staged=0;
    }
#endif
    if (g->routes) {
        if (steer_draft_routes_destroy(g->routes).code) return 0;
        g->routes = NULL;
    }
    if (g->config) steer_prototype_config_destroy(g->config);
    else steer_policy_destroy(g->policy);
    free(g->document);
    memset(g, 0, sizeof(*g));
    return 1;
}
static void reap_generations(struct host *h)
{
    unsigned i;
    for (i = 0; i < GENERATIONS; ++i) {
        struct generation *g = &h->generations[i];
        if (g != h->current && g->number && !g->references && !g->socks_sessions && !g->preparing)
            destroy_generation(g);
    }
}
static int initialize_host(struct host *h, struct client *clients)
{
    unsigned i;
    struct steer_draft_buffer_limits limits = steer_draft_prototype_buffer_limits(CLIENTS,CAPACITY,0);
#ifdef STEER_PROTOTYPE_HY2
    steer_draft_hy2_datagram_budget_init(&h->datagram_budget);
    /* Keep the original TCP byte and slot reserve even at full UDP envelope. */
    limits=steer_draft_prototype_buffer_limits(CLIENTS,CAPACITY,1);
#endif
#if defined(STEER_PROTOTYPE_VLESS_OUTBOUND) || defined(STEER_PROTOTYPE_SOCKS_OUTBOUND)
    /* One bounded handshake buffer per pending TCP open, in addition to relay. */
    unsigned handshake_max=0;
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
    handshake_max=VL_REQUEST_TCP_MAX;
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
    if(handshake_max<STEER_DRAFT_SOCKS_HANDSHAKE_MAX)handshake_max=STEER_DRAFT_SOCKS_HANDSHAKE_MAX;
#endif
    limits.max_buffers += CLIENTS;
    limits.max_bytes += CLIENTS*(handshake_max+256ULL);
#endif
    h->clients = clients;
    h->control_fd = -1;
    h->writer.wake = -1;
    for (i = 0; i < LISTENERS; ++i) h->listeners[i].fd = -1;
    h->buffer_api = steer_draft_buffers_api();
    h->loop = loop_new();
    if (!h->loop || steer_draft_buffers_create(&limits, NULL, &h->buffers).code) return 0;
    if (steer_draft_stream_runtime_create(h->loop, h->buffers, 2*CLIENTS, 2*CLIENTS,
                                        2*CLIENTS*CAPACITY, &h->runtime).code) return 0;
    h->work = loop_timer_new(h->loop, work, h);
    if (!h->work) return 0;
    if (steer_draft_backend_runtime_create(h->loop, 2*CLIENTS, 4*CLIENTS,
                                          2*CLIENTS*CAPACITY, &h->backend_runtime).code) return 0;
    (void)loop_signal(h->loop, SIGTERM, stop, h); (void)loop_signal(h->loop, SIGINT, stop, h);
    return 1;
}
static void close_listener(struct host *h, struct listener *listener)
{
#ifdef STEER_PROTOTYPE_HY2
    if(listener->hy2) {
        steer_draft_hy2_stop(listener->hy2);
        if(!steer_draft_hy2_destroy(listener->hy2)) { listener->hy2=NULL;listener->retiring=0; }
        else if(h->work)loop_timer_set(h->work,0);
    }
#endif
    if (listener->fd >= 0) {
        loop_fd_del(h->loop, listener->fd); close(listener->fd); listener->fd = -1;
    }
    listener->active = 0;
}
static int listener_bound(const struct listener *listener) {
#ifdef STEER_PROTOTYPE_HY2
    if(listener->hy2)return 1;
#endif
    return listener->fd>=0;
}
static int same_transport(const struct steer_prototype_listener *a,const struct steer_prototype_listener *b) {
    return (a->protocol==STEER_PROTOTYPE_HYSTERIA2)==(b->protocol==STEER_PROTOTYPE_HYSTERIA2);
}
#ifdef STEER_PROTOTYPE_HY2
static int hy2_authenticate(void *user,struct steer_pv1_span inbound,const uint8_t *token,size_t n,char principal[65],uint64_t *epoch) {
    struct listener *l=user;unsigned difference=0;
    if(!l->active||l->host->stopping||inbound.len!=strlen(l->spec.id)||memcmp(inbound.data,l->spec.id,inbound.len)||n!=l->identity.token_length)return 0;
    for(size_t i=0;i<n;i++)difference|=token[i]^(uint8_t)l->identity.token[i];
    if(difference)return 0;
    strcpy(principal,l->identity.principal);*epoch=l->admission_epoch;return 1;
}
static struct steer_pv1_error hy2_acquire(void *user,struct steer_pv1_span inbound,struct steer_pv1_span principal,uint64_t epoch,struct steer_draft_route_lease *lease) {
    struct listener *l=user;struct host *h=l->host;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->wg_fenced)return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};
#endif
    if(!l->active||h->stopping||epoch!=l->admission_epoch||!h->current||
       inbound.len!=strlen(l->spec.id)||memcmp(inbound.data,l->spec.id,inbound.len)||
       principal.len!=strlen(l->identity.principal)||memcmp(principal.data,l->identity.principal,principal.len))
        return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};
    if(h->current->references==UINT_MAX)return (struct steer_pv1_error){STEER_PV1_RESOURCE_EXHAUSTED,0};
    h->current->references++;
    *lease=(struct steer_draft_route_lease){h->current->routes,h->current->number,h->current,h->current->streams};
    return (struct steer_pv1_error){0,0};
}
static void hy2_release(void *user,struct steer_draft_route_lease *lease) {
    struct listener *l=user;struct generation *g=lease->handle;
    if(!g||!g->references)abort();
    g->references--;memset(lease,0,sizeof *lease);loop_timer_set(l->host->work,0);
}
static struct steer_pv1_error hy2_datagram_acquire(void *user,struct steer_pv1_span inbound,struct steer_pv1_span principal,
    uint64_t epoch,struct steer_draft_hy2_datagram_binding *out){
    struct listener *listener=user;struct steer_draft_route_lease lease={0};
    struct steer_pv1_error error=hy2_acquire(user,inbound,principal,epoch,&lease);if(error.code)return error;
    struct generation *g=lease.handle;
    /* Consult the admitted generation, not the reusable socket's old spec. */
    int allowed=0;
    for(uint32_t i=0;i<g->config->listener_count;i++){
        const struct steer_prototype_listener *spec=&g->config->listeners[i];
        if(strlen(spec->id)==inbound.len&&!memcmp(spec->id,inbound.data,inbound.len)){
            allowed=spec->protocol==STEER_PROTOTYPE_HYSTERIA2&&!spec->datagram_disabled;
            break;
        }
    }
    if(!allowed){hy2_release(user,&lease);return (struct steer_pv1_error){STEER_PV1_POLICY_DENIED,0};}
    error=steer_draft_binding_admit(g->datagram_binding,g->number,STEER_PV1_FLOW_DATAGRAM);
    if(error.code){hy2_release(user,&lease);return error;}
    *out=(struct steer_draft_hy2_datagram_binding){steer_draft_datagram_router_api(),g->datagrams,g,g->number};
    (void)listener;return (struct steer_pv1_error){0,0};
}
static void hy2_datagram_release(void *user,struct steer_draft_hy2_datagram_binding *binding){
    struct listener *listener=user;struct generation *g=binding->lease;
    if(!g||!g->references||steer_draft_binding_unpin(g->datagram_binding).code)abort();
    g->references--;memset(binding,0,sizeof *binding);loop_timer_set(listener->host->work,0);
}
static int bind_hy2(struct host *h,struct listener *listener,struct qc_server_tls *tls) {
    if(!tls||h->next_admission_epoch==UINT64_MAX)return 0;
    listener->admission_epoch=++h->next_admission_epoch;
    struct steer_draft_hy2_datagram_services datagrams={h->loop,h->buffers,&h->datagram_budget,listener,hy2_datagram_acquire,hy2_datagram_release};
    struct steer_draft_inbound_services services={h->loop,h->buffers,h->runtime,listener,hy2_authenticate,hy2_acquire,hy2_release,&datagrams};
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg&&listener->spec.datagram_disabled)services.datagrams=NULL;
#endif
    struct steer_draft_hy2_config cfg={.inbound_id=listener->spec.id,.max_flows=CLIENTS,.start_paused=1,
        .endpoint={.max_connections=8,.prepared_tls=tls,.server={.bind_host=listener->spec.address,.port=listener->spec.port,.alpn="h3"}}};
    int result=steer_draft_hy2_open(&cfg,&services,&listener->hy2);
    if(result)return 0;
    listener->spec.port=steer_draft_hy2_port(listener->hy2);return 1;
}
static void retire_listener(struct host *h,struct listener *listener) {
    if(listener->hy2&&!h->stopping) {
        listener->active=0;
        if(!listener->retiring) {
            listener->retiring=1;listener->drain_deadline=(uint64_t)loop_now_ms()+HY2_DRAIN_MS;
            steer_draft_hy2_retire(listener->hy2,listener->drain_deadline);
        }
        loop_timer_set(h->work,100);return;
    }
    close_listener(h,listener);
}
static int reap_hy2_listeners(struct host *h) {
    int pending=0;
    for(unsigned i=0;i<LISTENERS;i++) {
        struct listener *l=&h->listeners[i];
        if(!l->hy2||(!h->stopping&&!l->retiring))continue;
        if(h->stopping)steer_draft_hy2_stop(l->hy2);
        if(!steer_draft_hy2_connections(l->hy2)&&!steer_draft_hy2_flows(l->hy2)) {
            steer_draft_hy2_stop(l->hy2);
            if(!steer_draft_hy2_destroy(l->hy2)) { l->hy2=NULL;l->retiring=0;continue; }
        }
        pending=1;
    }
    if(pending)loop_timer_set(h->work,100);
    return pending;
}
#endif
struct qc_server_tls;
static int bind_listener(struct host *h, struct listener *listener,struct qc_server_tls *tls)
{
    struct sockaddr_storage address;
    socklen_t length;
    int family, reuse = 1;
    memset(&address, 0, sizeof(address)); listener->host = h;
    if(listener->spec.protocol==STEER_PROTOTYPE_HYSTERIA2) {
#ifdef STEER_PROTOTYPE_HY2
        return bind_hy2(h,listener,tls);
#else
        (void)tls;
        return 0;
#endif
    }
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
#ifdef STEER_PROTOTYPE_WG_NETNS
static int wg_generation_ready(const struct generation *g){
    if(!g||!g->wg_stream)return 1;
    uint64_t now=steer_nl_now_ns();
    return now&&!steer_draft_wg_stream_verify(g->wg_stream,now+50000000u);
}
#endif
static void cleanup_host(struct host *h)
{
    unsigned i;
    if (h->control_fd >= 0) {
        loop_fd_del(h->loop, h->control_fd); close(h->control_fd); h->control_fd = -1;
    }
    if (h->controls) {
        for (i = 0; i < CONTROLS; ++i) close_control(&h->controls[i]);
        free(h->controls); h->controls = NULL;
    }
    if (h->control_path[0]) unlink(h->control_path);
    stop_writer(h);
    steer_prototype_prepare_join_destroy(h->preparer);h->preparer=NULL;
    for (i = 0; i < LISTENERS; ++i) close_listener(h, &h->listeners[i]);
    /* Startup rollback may retire a prepared binding before the first loop
     * dispatch. Its deferred finalizer still owns generation storage. */
    h->current = NULL;
    unsigned pending = 0;
    for (i = 0; i < GENERATIONS; ++i) pending += !destroy_generation(&h->generations[i]);
    if (pending && h->work) {
        h->stopping = 1; loop_timer_set(h->work, 0);
        (void)loop_run(h->loop);
    }
    loop_timer_free(h->work);
    if (h->resolver && steer_draft_resolver_destroy(h->resolver).code) abort();
    if (h->store && steer_prototype_store_close(h->store).code) abort();
    if (h->backend_runtime && steer_draft_backend_runtime_destroy(h->backend_runtime).code) abort();
    if (h->runtime && steer_draft_stream_runtime_destroy(h->runtime).code) abort();
    if (h->buffers && steer_draft_buffers_destroy(h->buffers).code) abort();
    if (h->loop) loop_free(h->loop);
    free(h->selected_document);
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
    if (!prepare_stream_routes(&h, g, NULL)) goto cleanup;
#ifdef STEER_PROTOTYPE_HY2
    if (!prepare_datagram_routes(&h, g, NULL)) goto cleanup;
#endif
    listener->identity = identity;
    strcpy(listener->spec.id, identity.id); strcpy(listener->spec.address, bind_address);
    listener->spec.port = (uint16_t)port;
    listener->spec.protocol = vless ? STEER_PROTOTYPE_VLESS : STEER_PROTOTYPE_SOCKS;
    prepare_socks(g, 0, listener);
    if (!bind_listener(&h, listener,NULL)) goto cleanup;
    h.current = g; listener->active = 1;
    set_socks_admission(g, 1);
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
    if(spec->auth==STEER_PROTOTYPE_AUTH_PASSWORD&&spec->protocol==STEER_PROTOTYPE_HYSTERIA2) {
        identity->token=getenv(spec->password_ref+4);
        if(!identity->token)return 0;
        identity->token_length=strlen(identity->token);
        return identity->token_length&&identity->token_length<=1024;
    }
    return !identity->vless && spec->auth == STEER_PROTOTYPE_AUTH_NONE;
}
static int same_listener(const struct steer_prototype_listener *a, const struct steer_prototype_listener *b)
{
    return a->port == b->port && a->protocol == b->protocol && a->auth == b->auth &&
        !strcmp(a->id, b->id) && !strcmp(a->address, b->address) &&
        !strcmp(a->principal_id, b->principal_id) && !strcmp(a->username_ref, b->username_ref) &&
        !strcmp(a->password_ref, b->password_ref) && !strcmp(a->uuid_ref, b->uuid_ref)&&
        !strcmp(a->certificate_ref,b->certificate_ref)&&!strcmp(a->private_key_ref,b->private_key_ref);
}
static int same_identity(const struct listener_identity *a,const struct listener_identity *b) {
    return a->user_length==b->user_length&&a->password_length==b->password_length&&a->token_length==b->token_length&&
        (!a->user_length||!memcmp(a->user,b->user,a->user_length))&&
        (!a->password_length||!memcmp(a->password,b->password,a->password_length))&&
        (!a->token_length||!memcmp(a->token,b->token,a->token_length))&&
        !memcmp(a->uuid,b->uuid,sizeof a->uuid)&&!memcmp(a->certificate_hash,b->certificate_hash,32)&&
        !memcmp(a->private_key_hash,b->private_key_hash,32);
}
/* No callbacks interleave preparation/publication: one owning loop shard.
 * New sockets are closed on failure; old listeners and generation stay live. */
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
static int credential_span(const char *reference,struct steer_pv1_span *out)
{
    const char *value=getenv(reference+4);
    size_t length=value?strnlen(value,256):0;
    if(!length||length>255)return 0;
    *out=(struct steer_pv1_span){(const uint8_t *)value,(uint32_t)length};
    return 1;
}
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
#ifdef STEER_PROTOTYPE_INBOUND_PAUSE
static int inbound_pause_open(void *ctx,const struct steer_draft_wg_guard_record *r,uint64_t d,uint32_t *state){
    const char *pause=getenv("STEER_TEST_INBOUND_PAUSE");
    const char *entered=getenv("STEER_TEST_INBOUND_ENTERED");
    if(pause&&entered){
        int fd=open(entered,O_WRONLY|O_CREAT|O_CLOEXEC,0600);
        if(fd>=0)close(fd);
        while(!access(pause,F_OK))usleep(10000);
    }
    return steer_draft_wg_linux_guard_barrier_open(ctx,r,d,state);
}
#endif
#ifdef STEER_PROTOTYPE_INBOUND_FAULT
static int inbound_fault_guard(void *ctx,const struct steer_draft_wg_guard_record *r,int publish,
    uint64_t d,uint32_t *effect,uint64_t *handle){
    int rc=steer_draft_wg_linux_guard_backend.guard(ctx,r,publish,d,effect,handle);
    return publish&&!rc&&*effect==STEER_PV1_DEVICE_CHANGED?EIO:rc;
}
#endif
static uint64_t inbound_deadline(void){
    uint64_t now=steer_nl_now_ns();
    return now?now+8000000000u:0;
}
static int inbound_verify_none(void *ctx,const struct steer_draft_wg_guard_record *record,uint64_t d){
    (void)ctx;(void)record;(void)d;return EPROTO;
}
static struct steer_draft_wg_revision inbound_revision(const struct steer_prototype_config *config){
    struct steer_draft_wg_revision r={.generation=config->generation,.without_wg=!config->wg_inbound_validate};
    static const char domain[]="steer linked spec v3: inbound device";
    uint8_t digest[32];b3_hash(digest,config->document_json,config->document_length);
    b3_derive_key(r.digest,32,domain,sizeof(domain)-1,digest,sizeof digest);
    return r;
}
static int inbound_prepare_slot(struct host *h,struct prepared *prepared,const struct awg_secrets *keys){
    const struct steer_prototype_config *cfg=prepared->generation->config;
    const struct steer_linked_wg_config *wg=cfg->wg_inbound_validate;
    struct steer_draft_wg_revision selected=inbound_revision(cfg);
    struct steer_draft_wg_tx tx={.transaction=cfg->generation,.generation=cfg->generation,.instance=cfg->generation};
    memcpy(tx.plan_digest,selected.digest,sizeof tx.plan_digest);
    struct steer_draft_wg_candidate candidate={.config=&wg->cfg.kernel,.keys=keys};
    uint64_t deadline=inbound_deadline();
    int rc=steer_draft_wg_linux_link_prepare(h->inbound_guard.link,&tx,deadline,NULL,&candidate.link);
    if(rc)return rc;
    struct steer_draft_kernel_wg_guard_config guard=wg->cfg.guard;
    guard.generation=cfg->generation;
    strcpy(guard.device,candidate.link.physical_name);
    rc=steer_linked_inbound_prepare_closed(&h->inbound,&tx,&candidate,&guard,cfg->policy,deadline);
    if(!rc){prepared->inbound_slot=1;prepared->inbound_choice=selected;}
    return rc;
}
static int inbound_finish_slot(struct host *h,struct prepared *prepared,struct steer_prototype_store_result result){
    if(!prepared->inbound_slot)return 0;
    int removal=prepared->inbound_slot==2;
    prepared->inbound_slot=0;
    if(removal){
        int rc=steer_linked_inbound_finish_removal(&h->inbound,result,&prepared->inbound_choice,
            inbound_deadline(),h->stopping);
        if(h->inbound.barrier_state==STEER_INBOUND_BARRIER_ABSENT)h->inbound_removed=1;
        return rc;
    }
    return h->stopping?
        steer_linked_inbound_finish_closed_shutdown(&h->inbound,result,&prepared->inbound_choice,inbound_verify_none,inbound_deadline()):
        steer_linked_inbound_finish_closed(&h->inbound,result,&prepared->inbound_choice,inbound_verify_none,inbound_deadline());
}
static struct steer_pv1_error inbound_no_rules(void *ctx,const struct steer_policy_rule *rule){
    (void)ctx;(void)rule;return (struct steer_pv1_error){STEER_PV1_UNSUPPORTED,0};
}
#endif
static int prepare_configuration(struct host *h, const char *document, size_t length,
                                 uint64_t expected, int validate, uint64_t initial_revision,uint32_t initial_format,
                                 struct prepared *prepared_state,struct steer_prototype_prepared_input *inputs)
{
    struct steer_prototype_config *config = NULL;
    struct listener_identity identities[STEER_PROTOTYPE_MAX_LISTENERS];
    struct outbound_credentials credentials[STEER_POLICY_STREAM_BINDINGS_MAX] = {0};
#ifdef STEER_PROTOTYPE_HY2
    struct qc_server_tls *contexts[STEER_PROTOTYPE_MAX_LISTENERS]={0};
#endif
    struct generation *g = NULL;
    unsigned i, j;
    int result = 422;
    uint64_t next = h->current ? h->current->number + 1 : initial_revision;
#ifdef STEER_PROTOTYPE_WG_NETNS
    struct awg_secrets wg_keys={0};
    struct steer_draft_wg_stream *recovered_wg=NULL;
    if(h->linked_wg&&h->current)next=h->wg_next;
#endif
    memset(prepared_state, 0, sizeof(*prepared_state));
    if (!validate && expected != (h->current ? h->current->number : 0)) return 409;
    if(!next)return 422;
    if(inputs) { config=inputs->config;inputs->config=NULL;if(!config)return 422; }
    else if(steer_prototype_config_parse_with_vpn(document,length,next,&h->socks_vpn,&config).code)return 422;
    if(initial_format&&initial_format!=config->format)goto cleanup;
    /* A managed control session must not sidestep its bind policy by applying
     * the legacy developer format, which intentionally supports wildcard. */
    if(h->current&&h->current->config->format==STEER_STORE_FORMAT_SPEC_V3&&
        config->format!=STEER_STORE_FORMAT_SPEC_V3)goto cleanup;
    if (!config->document_json || config->document_length > STEER_PROTOTYPE_CONFIG_MAX_BYTES) goto cleanup;
    if(!validate&&config->generation!=next) { result=409;goto cleanup; }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(config->wg&&(!h->linked_wg||steer_linked_wg_keys(config->wg,&wg_keys)))goto cleanup;
    /* The validation-only flag must never activate a device; the separate
     * runtime opt-in admits only the first SOCKS-to-SOCKS+DEVICE transition. */
    if(config->wg_inbound_validate&&((!validate&&!h->inbound_runtime)||
       steer_linked_wg_keys(config->wg_inbound_validate,&wg_keys)))goto cleanup;
    if(!validate&&h->inbound_runtime&&!h->current){
        if(config->wg_inbound_validate&&!initial_format)goto cleanup;
        if(config->wg_inbound_validate&&(length!=config->document_length||
            memcmp(document,config->document_json,length)))goto cleanup;
    }
    if(h->inbound_runtime&&h->current){
        int old_wg=h->current->config->wg_inbound_validate!=NULL;
        int new_wg=config->wg_inbound_validate!=NULL;
        uint32_t fallback=0;
        if(old_wg==new_wg||(!old_wg&&h->inbound_removed)||config->format!=STEER_STORE_FORMAT_SPEC_V3||
           config->stream_outbound_count||
           steer_policy_visit(config->policy,config->generation,inbound_no_rules,NULL,&fallback).code||
           fallback!=STEER_POLICY_DIRECT)goto cleanup;
    }
    if(h->inbound_runtime&&h->current&&
       (h->current->config->format!=STEER_STORE_FORMAT_SPEC_V3||
        h->current->config->listener_count!=1||config->listener_count!=1||
        !config->listeners[0].enabled||
        !h->current->config->listeners[0].enabled||
        !same_listener(&h->current->config->listeners[0],&config->listeners[0])))goto cleanup;
    if(!validate&&h->linked_wg&&!wg_generation_ready(h->current)){result=503;goto cleanup;}
    if(h->linked_wg&&!h->current){
        if(config->format!=STEER_STORE_FORMAT_SPEC_V3)goto cleanup;
        if(initial_format&&(length!=config->document_length||memcmp(document,config->document_json,length)))goto cleanup;
        if(!initial_format&&config->generation!=h->wg_next){result=503;goto cleanup;}
    }
#endif
    for (i = 0; i < config->stream_outbound_count; ++i) {
        const struct steer_prototype_stream_outbound *out=&config->stream_outbounds[i];
        if (out->protocol==STEER_PROTOTYPE_VLESS&&!parse_uuid(getenv(out->uuid_ref+4),credentials[i].uuid))
            goto cleanup;
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        if (out->protocol==STEER_PROTOTYPE_SOCKS&&out->username_ref[0]&&
            (!credential_span(out->username_ref,&credentials[i].username)||
             !credential_span(out->password_ref,&credentials[i].password)))goto cleanup;
#endif
#ifdef STEER_PROTOTYPE_HY2
        if(out->protocol==STEER_PROTOTYPE_HYSTERIA2) {
            if(inputs) {
                credentials[i].hy2=inputs->hy2_out[i];inputs->hy2_out[i]=NULL;
                if(!credentials[i].hy2)goto cleanup;
                if(out->hy2_datagram) {
                    credentials[i].hy2_udp=inputs->hy2_udp_out[i];inputs->hy2_udp_out[i]=NULL;
                    if(!credentials[i].hy2_udp)goto cleanup;
                }
            }else if(steer_prototype_prepare_hy2_outbound(out,next,&credentials[i].hy2))goto cleanup;
            if(!inputs&&out->hy2_datagram&&
               steer_prototype_prepare_hy2_outbound(out,next,&credentials[i].hy2_udp))goto cleanup;
        }
#endif
    }
    for (i = 0; i < config->listener_count; ++i)if(config->listeners[i].enabled) {
#ifndef STEER_PROTOTYPE_HY2
        if(config->listeners[i].protocol==STEER_PROTOTYPE_HYSTERIA2)goto cleanup;
#endif
        if(!resolve_identity(&config->listeners[i],&identities[i]))goto cleanup;
#ifdef STEER_PROTOTYPE_HY2
        if(config->listeners[i].protocol==STEER_PROTOTYPE_HYSTERIA2) {
            if(inputs) {
                contexts[i]=inputs->tls[i];inputs->tls[i]=NULL;if(!contexts[i])goto cleanup;
                memcpy(identities[i].certificate_hash,inputs->certificate_hash[i],32);
                memcpy(identities[i].private_key_hash,inputs->private_key_hash[i],32);
            } else {
                /* Bootstrap only: no packet IO has been dispatched yet. */
                const struct steer_prototype_listener *spec=&config->listeners[i];struct steer_draft_tls_material material;
                if(steer_draft_tls_material_load(getenv(spec->certificate_ref+4),getenv(spec->private_key_ref+4),&material))goto cleanup;
                int error=qcssl_material_sha256(material.certificate,material.certificate_length,identities[i].certificate_hash)||
                    qcssl_material_sha256(material.private_key,material.private_key_length,identities[i].private_key_hash);
                if(!error)error=qc_server_tls_create(material.certificate,material.certificate_length,material.private_key,material.private_key_length,&contexts[i]);
                steer_draft_tls_material_clear(&material);if(error)goto cleanup;
            }
        }
#endif
    }
    if (validate) {
        prepared_state->validation_only=config->wg_inbound_validate!=NULL
#ifdef STEER_PROTOTYPE_WG_NETNS
            &&!h->inbound_runtime
#endif
            ;
        result = 200; goto cleanup;
    }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg&&initial_format&&steer_linked_wg_recover(h->linked_wg,config,&wg_keys,&h->wg_next,&recovered_wg)){
        result=503;goto cleanup;
    }
#endif
    reap_generations(h);
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg&&h->wg_retire_error){result=503;goto cleanup;}
#endif
    for (i = 0; i < GENERATIONS; ++i) if (!h->generations[i].number) { g = &h->generations[i]; break; }
    if (!g) { result = 503; goto cleanup; }
    g->number = next; g->preparing = 1;
    g->host=h;
    g->config = config; g->policy = config->policy; config = NULL;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg){
        if(!initial_format){
            if(next==UINT64_MAX){result=503;goto cleanup;}
            h->wg_next=next+1;
        }
        if(g->config->wg){
            if(initial_format){
                g->wg_stream=recovered_wg;recovered_wg=NULL;
                g->wg_staged=1;
            }else if(h->current&&steer_linked_wg_same_device(h->current->config->wg,g->config->wg)){
                int rc=steer_linked_wg_reuse(h->linked_wg,g->config,&wg_keys,h->current->config->wg,h->current->wg_stream,
                    inputs?inputs->deadline_ms*1000000u:0,&g->wg_stream);
                if(rc){result=rc==ESTALE?409:503;goto cleanup;}
                g->wg_staged=1;
            }else{
                for(unsigned k=0;k<GENERATIONS;k++){
                    const struct generation *old=&h->generations[k];
                    if(old==g||!old->config||!old->config->wg)continue;
                    const struct awg_conf *a=&old->config->wg->cfg.kernel,*b=&g->config->wg->cfg.kernel;
                    if(a->listen_port==b->listen_port||!memcmp(a->addr[0].addr,b->addr[0].addr,4)){
                        result=409;goto cleanup;
                    }
                }
                g->wg_staged=1;
                if(steer_linked_wg_stage(h->linked_wg,g->config,&wg_keys,
                    inputs?inputs->deadline_ms*1000000u:0,&g->wg_stream)){
                    result=503;goto cleanup;
                }
            }
        }
    }
#endif
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
    if (!prepare_stream_routes(h, g, credentials)) { result = 503; goto cleanup; }
#ifdef STEER_PROTOTYPE_HY2
    if (!prepare_datagram_routes(h, g, credentials)) { result = 503; goto cleanup; }
#endif
    for (i = 0; i < g->config->listener_count; ++i) {
        const struct steer_prototype_listener *spec = &g->config->listeners[i];
        struct listener *listener = NULL;
        if (!spec->enabled) continue;
        for (j = 0; j < LISTENERS; ++j) if (listener_bound(&h->listeners[j])&&h->listeners[j].active&&
            same_listener(&h->listeners[j].spec, spec)&&same_identity(&h->listeners[j].identity,&identities[i])
#ifdef STEER_PROTOTYPE_WG_NETNS
            &&(!h->linked_wg||h->listeners[j].spec.datagram_disabled==spec->datagram_disabled)
#endif
        ) {
            listener = &h->listeners[j]; prepared_state->keep[j] = 1; break;
        }
        if (listener) continue;
        /* Changing a live endpoint's protocol/auth/ID requires disable then
         * create. No SO_REUSEPORT split or nontransactional close/rebind. */
        for (j = 0; j < LISTENERS; ++j) if (listener_bound(&h->listeners[j])&&same_transport(&h->listeners[j].spec,spec)&&
            h->listeners[j].spec.port == spec->port && !strcmp(h->listeners[j].spec.address, spec->address)) goto cleanup;
        for (j = 0; j < LISTENERS; ++j) if (!listener_bound(&h->listeners[j])) { listener = &h->listeners[j]; break; }
        if (!listener) { result = 503; goto cleanup; }
        listener->spec = *spec; listener->identity = identities[i]; listener->active = 0;
        struct qc_server_tls *tls=NULL;
#ifdef STEER_PROTOTYPE_HY2
        tls=contexts[i];
#endif
        if (!bind_listener(h, listener,tls)) goto cleanup;
        prepared_state->keep[j] = prepared_state->created[j] = 1;
    }
    for (i = 0; i < LISTENERS; ++i)
        if (prepared_state->keep[i]) prepare_socks(g, i, &h->listeners[i]);
    prepared_state->generation = g;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->inbound_runtime&&g->config->wg_inbound_validate&&!initial_format){
        if(inbound_prepare_slot(h,prepared_state,&wg_keys)){
            h->split_fenced=1;prepared_state->generation=NULL;result=503;goto cleanup;
        }
    }
    if(h->inbound_runtime&&h->current&&h->current->config->wg_inbound_validate&&!g->config->wg_inbound_validate){
        prepared_state->inbound_choice=inbound_revision(g->config);
        if(steer_linked_inbound_prepare_removal(&h->inbound,&prepared_state->inbound_choice,inbound_deadline())){
            h->split_fenced=1;prepared_state->generation=NULL;result=503;goto cleanup;
        }
        prepared_state->inbound_slot=2;
    }
#endif
    g = NULL; result = 200;
cleanup:
#ifdef STEER_PROTOTYPE_WG_NETNS
    awg_secrets_wipe(&wg_keys);
    steer_draft_wg_stream_destroy(recovered_wg);
#endif
#ifdef STEER_PROTOTYPE_HY2
    for(i=0;i<STEER_POLICY_STREAM_BINDINGS_MAX;i++) {
        (void)steer_hy2_profile_destroy(credentials[i].hy2);
        (void)steer_hy2_profile_destroy(credentials[i].hy2_udp);
    }
    for(i=0;i<STEER_PROTOTYPE_MAX_LISTENERS;i++)qc_server_tls_release(contexts[i]);
#endif
    explicit_bzero(credentials, sizeof credentials);
    if (result != 200) for (i = 0; i < LISTENERS; ++i) if (prepared_state->created[i]) close_listener(h, &h->listeners[i]);
    if (g) destroy_generation(g);
    steer_prototype_config_destroy(config);
    return result;
}
static void discard_prepared(struct host *h, struct prepared *prepared)
{
    unsigned i;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(prepared->inbound_slot){
        struct steer_prototype_store_result not_renamed={{0,0},STEER_PROTOTYPE_STORE_NOT_RENAMED};
        (void)inbound_finish_slot(h,prepared,not_renamed);
        if(h->inbound.fenced)h->split_fenced=1;
    }
#endif
    for (i = 0; i < LISTENERS; ++i) if (prepared->created[i]) close_listener(h, &h->listeners[i]);
    if (prepared->generation) destroy_generation(prepared->generation);
    memset(prepared, 0, sizeof(*prepared));
}
/* All fallible runtime work completed before disk rename. Only pointer/state
 * publication and closing old admission descriptors remain after commit. */
static void publish_prepared(struct host *h, struct prepared *prepared)
{
    unsigned i;
#ifdef STEER_PROTOTYPE_SOCKS_UDP
    for(i=0;i<CLIENTS;i++)
        if(h->clients[i].live && h->clients[i].udp && h->clients[i].generation==h->current)
            close_client(&h->clients[i]);
#endif
    set_socks_admission(h->current, 0);
    for (i = 0; i < LISTENERS; ++i) {
        if (!prepared->keep[i] || h->stopping) {
#ifdef STEER_PROTOTYPE_HY2
            retire_listener(h,&h->listeners[i]);
#else
            close_listener(h,&h->listeners[i]);
#endif
        } else {
            h->listeners[i].active = 1;
#ifdef STEER_PROTOTYPE_HY2
            if(h->listeners[i].hy2)steer_draft_hy2_activate(h->listeners[i].hy2);
#endif
        }
    }
#ifdef STEER_PROTOTYPE_HY2
    retire_hy2_outbounds(h->current);
    if(h->current)retire_datagram_generation(h->current);
#endif
    h->current = prepared->generation; h->current->preparing = 0;
    set_socks_admission(h->current, !h->stopping);
    prepared->generation = NULL;
    reap_generations(h);
}
static int configure_initial(struct host *h,const char *document,size_t length,
                             uint64_t revision,uint32_t format)
{
    struct prepared prepared;
    int result = prepare_configuration(h,document,length,0,0,revision,format,&prepared,NULL);
    if (result == 200) publish_prepared(h, &prepared);
    return result;
}
static size_t status_json(struct host *h, char *out, size_t capacity)
{
    size_t used;
    unsigned i, count = 0;
    unsigned retained=0;for(i=0;i<GENERATIONS;i++)retained+=h->generations[i].number!=0;
    unsigned active_clients=h->live;
    int ready=1;
#ifdef STEER_PROTOTYPE_WG_NETNS
    ready=!h->wg_fenced&&wg_generation_ready(h->current);
    if(h->inbound_runtime&&h->inbound.removal_stage)ready=0;
    if(h->inbound_runtime&&h->current&&h->current->config->wg_inbound_validate&&
       h->inbound.barrier_state!=STEER_INBOUND_BARRIER_OPEN)ready=0;
    if(ready&&h->inbound_runtime&&h->current&&h->current->config->wg_inbound_validate&&
       !h->split_fenced&&!h->inbound.staged){
        struct steer_prototype_config *cfg=h->current->config;
        struct steer_draft_kernel_wg_guard_config guard=cfg->wg_inbound_validate->cfg.guard;
        guard.generation=cfg->generation;
        struct steer_linked_inbound_recovery check={.guard=h->inbound_guard,.revision=inbound_revision(cfg),
            .inbound=&guard,.policy=cfg->policy,.wireguard=&cfg->wg_inbound_validate->cfg.kernel};
        uint64_t now=steer_nl_now_ns();
        if(!now||steer_linked_inbound_verify_up(&check,&h->inbound.candidate.guard,now+50000000u))ready=0;
    }
#endif
    if(h->experimental_durable_split&&h->split_fenced)ready=0;
#ifdef STEER_PROTOTYPE_HY2
    for(i=0;i<LISTENERS;i++)if(h->listeners[i].hy2)active_clients+=(unsigned)steer_draft_hy2_flows(h->listeners[i].hy2);
#endif
    char revision[32];
    if(h->experimental_durable_split&&h->durability_uncertain)strcpy(revision,"null");
    else snprintf(revision,sizeof revision,"%llu",(unsigned long long)(h->selected_document?h->selected_revision:h->current->number));
    int n = snprintf(out, capacity, "{\"prototype\":\"steer-linux-v1\",\"generation\":%llu,\"revision\":%s,\"runtimeReady\":%s,\"persistence\":%s,\"durability_uncertain\":%s,\"activeClients\":%u,\"retainedGenerations\":%u,\"listeners\":[",
        (unsigned long long)h->current->number, revision,
        ready?"true":"false",h->store ? "true" : "false", h->durability_uncertain ? "true" : "false", active_clients,retained);
    if (n < 0 || (size_t)n >= capacity) return 0;
    used = (size_t)n;
    for (i = 0; i < LISTENERS; ++i) if (listener_bound(&h->listeners[i]) && h->listeners[i].active) {
        const struct listener *listener = &h->listeners[i];
        n = snprintf(out + used, capacity - used, "%s{\"id\":\"%s\",\"protocol\":\"%s\",\"address\":\"%s\",\"port\":%u}",
            count++ ? "," : "", listener->identity.id, listener->spec.protocol==STEER_PROTOTYPE_HYSTERIA2?"hysteria2":listener->identity.vless ? "vless" : "socks",
            listener->spec.address, listener->spec.port);
        if (n < 0 || (size_t)n >= capacity - used) return 0;
        used += (size_t)n;
    }
    const char *hy2="false",*hy2_udp="false",*provider="",*wg_cap="";
    char inbound_cap[256]="";
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg)wg_cap="\"spec_v3_wireguard_stream_outbound_netns\":true,";
    if(h->socks_vpn.wg_inbound_validate){
        int active=h->current&&h->current->config&&h->current->config->wg_inbound_validate!=NULL;
        int available=h->inbound_runtime&&!h->split_fenced&&!h->durability_uncertain&&!h->stopping&&
            !h->store_busy&&h->inbound.recovered&&!h->inbound.fenced&&!h->inbound.staged&&ready&&h->current&&h->current->config&&
            h->current->config->format==STEER_STORE_FORMAT_SPEC_V3&&
            h->current->config->listener_count==1&&h->current->config->listeners[0].enabled&&
            h->current->config->listeners[0].protocol==STEER_PROTOTYPE_SOCKS;
        snprintf(inbound_cap,sizeof inbound_cap,
            "\"spec_v3_wg_inbound_netns\":{\"mode\":\"%s\",\"add\":%s,\"remove\":%s,\"replace\":false},",
            h->inbound_runtime?"experimental":"validate-only",
            available&&!active&&!h->inbound_removed?"true":"false",available&&active?"true":"false");
    }
#endif
#ifdef STEER_PROTOTYPE_HY2
    hy2="true";hy2_udp=h->current&&h->current->datagrams?"true":"false";provider=",\"hysteria2\"";
#endif
    if(h->experimental_durable_split){
        n=snprintf(out+used,capacity-used,"],\"selectedRevision\":%s",revision);
        if(n<0||(size_t)n>=capacity-used)return 0;
        used+=(size_t)n;
        n=snprintf(out+used,capacity-used,",\"runtimeGeneration\":%llu,\"splitFenced\":%s",
            (unsigned long long)h->current->number,h->split_fenced?"true":"false");
        if(n<0||(size_t)n>=capacity-used)return 0;
        used+=(size_t)n;
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(h->inbound_runtime){
            const char *barrier=h->inbound.barrier_state==STEER_INBOUND_BARRIER_CLOSED?"closed":
                h->inbound.barrier_state==STEER_INBOUND_BARRIER_OPEN?"open":
                h->inbound.barrier_state==STEER_INBOUND_BARRIER_ABSENT?"absent":"unknown";
            n=snprintf(out+used,capacity-used,",\"inboundBarrier\":\"%s\"",barrier);
            if(n<0||(size_t)n>=capacity-used)return 0;
            used+=(size_t)n;
        }
#endif
    }else{
        if(used+1>=capacity)return 0;
        out[used++]=']';
    }
    n=snprintf(out+used,capacity-used,",\"capabilities\":{\"spec_v3_profile\":\"linked-socks-v1\",\"spec_v3_vless_tcp\":true,"
        "%s%s\"spec_v3_socks_tcp_userpass\":true,\"spec_v3_socks_vpn_bind\":{\"auth\":\"userpass\",\"addresses\":[",wg_cap,inbound_cap);
    if(n<0||(size_t)n>=capacity-used)return 0;
    used+=(size_t)n;
    for(i=0;i<h->socks_vpn.count;i++){
        n=snprintf(out+used,capacity-used,"%s\"%s\"",i?",":"",h->socks_vpn.entries[i].address);
        if(n<0||(size_t)n>=capacity-used)return 0;
        used+=(size_t)n;
    }
    n=snprintf(out+used,capacity-used,"]},"
#ifdef STEER_PROTOTYPE_SOCKS_UDP
        "\"spec_v3_socks_udp_associate_loopback_ipv4\":true,"
#endif
#ifdef STEER_PROTOTYPE_VLESS_OUTBOUND
        "\"spec_v3_vless_tcp_outbound\":true,"
#endif
#ifdef STEER_PROTOTYPE_SOCKS_OUTBOUND
        "\"spec_v3_socks_tcp_outbound\":true,"
#endif
#ifdef STEER_PROTOTYPE_HY2
        "\"spec_v3_hysteria2_stream_only_inbound\":true,"
        "\"spec_v3_hysteria2_tcp_outbound\":true,"
        "\"spec_v3_hysteria2_numeric_udp_1000_outbound\":true,"
#endif
        "\"spec_v3_hysteria2\":%s,\"providers\":[\"socks\",\"vless\"%s],\"inbound\":{\"hysteria2\":{\"tcp\":%s,\"udp\":%s,\"tls\":%s}}},\"drainingListeners\":[",hy2_udp,provider,hy2,hy2_udp,hy2);
    if(n<0||(size_t)n>=capacity-used)return 0;
    used+=(size_t)n;count=0;
#ifdef STEER_PROTOTYPE_HY2
    for(i=0;i<LISTENERS;i++)if(h->listeners[i].hy2&&h->listeners[i].retiring) {
        const struct listener *listener=&h->listeners[i];uint64_t now=(uint64_t)loop_now_ms();
        n=snprintf(out+used,capacity-used,"%s{\"id\":\"%s\",\"protocol\":\"hysteria2\",\"port\":%u,\"drainRemainingMs\":%llu}",
            count++?",":"",listener->spec.id,listener->spec.port,(unsigned long long)(listener->drain_deadline>now?listener->drain_deadline-now:0));
        if(n<0||(size_t)n>=capacity-used)return 0;
        used+=(size_t)n;
    }
#endif
#ifdef STEER_PROTOTYPE_HY2
    n=snprintf(out+used,capacity-used,"],\"udpBudget\":{\"receiveSlots\":%u,\"maxReceiveSlots\":%u,\"uploadBytes\":%llu,\"maxUploadBytes\":%llu,\"packets\":%u,\"maxPackets\":%u}}",
        h->datagram_budget.receives,h->datagram_budget.max_receives,(unsigned long long)h->datagram_budget.upload_bytes,
        (unsigned long long)h->datagram_budget.max_upload_bytes,h->datagram_budget.packets,h->datagram_budget.max_packets);
    if(n<0||(size_t)n>=capacity-used)return 0;
    return used+(size_t)n;
#else
    if (capacity - used < 3) return 0;
    memcpy(out + used, "]}", 3);
    return used + 2;
#endif
}
static void close_control(struct control *c)
{
    if (c->fd < 0) return;
    if(c->waiting_prepare&&c->host->preparer)steer_prototype_prepare_cancel(c->host->preparer,(unsigned)(c-c->host->controls),c->serial);
    c->waiting_prepare=0;
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
    int published=result.phase>=STEER_PROTOTYPE_STORE_RENAMED;
    if(h->experimental_durable_split&&published&&
       (result.phase!=STEER_PROTOTYPE_STORE_SYNCED||result.error.code)){
        h->durability_uncertain=1;
        h->split_fenced=1;
        published=0;
    }
    int publication_failed=0;
#ifdef STEER_PROTOTYPE_SPLIT_FAULT
    publication_failed=h->test_fail_after_sync;
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(prepared->inbound_slot){
        int removal=prepared->inbound_slot==2;
        int rc=inbound_finish_slot(h,prepared,result);
        if(h->stopping&&((result.phase==STEER_PROTOTYPE_STORE_SYNCED&&
                         (rc!=ECANCELED||(removal&&h->inbound.barrier_state!=STEER_INBOUND_BARRIER_ABSENT)))||
                         h->inbound.durable_unknown))h->inbound_shutdown_error=1;
        if(rc){
            published=0;
            if(h->inbound.fenced)h->split_fenced=1;
            if(h->inbound.durable_unknown)h->durability_uncertain=1;
            if(result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code&&
               !h->inbound.durable_unknown)publication_failed=1;
        }
    }
#endif
    if(h->experimental_durable_split&&publication_failed&&
       result.phase==STEER_PROTOTYPE_STORE_SYNCED&&!result.error.code){
        struct generation *candidate=prepared->generation;
        free(h->selected_document);
        h->selected_document=candidate->document;
        h->selected_length=candidate->document_length;
        h->selected_revision=candidate->number;
        candidate->document=NULL;candidate->document_length=0;
        h->split_fenced=1;h->durability_uncertain=0;
        published=0;
    }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->linked_wg&&published&&result.phase!=STEER_PROTOTYPE_STORE_SYNCED){
        h->durability_uncertain=1;
        h->wg_fenced=1; /* leave both journal generations for restart */
        published=0;
    }
    if(h->linked_wg&&published)steer_linked_wg_commit(h->linked_wg,prepared->generation->config,
        prepared->generation->wg_stream);
#endif
    if (published) {
        h->durability_uncertain = result.phase != STEER_PROTOTYPE_STORE_SYNCED;
        publish_prepared(h, prepared);
    } else discard_prepared(h, prepared);
    h->store_busy = 0; free(prepared);
    if (control && control->fd >= 0 && control->serial == serial && control->waiting_store) {
        control->waiting_store = 0;
        if (published) applied_response(control, result.error.code ? 503 : 200);
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
static int queue_durable(struct control *c,struct prepared *prepared)
{
    struct host *h = c->host;
    if (h->store_busy) return 503;
    prepared->control = c; prepared->control_serial = c->serial;
    if (loop_fd_mod(h->loop, c->fd, 0))return 503;
    c->waiting_store = 1; h->store_busy = 1;
    pthread_mutex_lock(&h->writer.lock);
    h->writer.prepared = prepared; h->writer.queued = 1;
    pthread_cond_signal(&h->writer.changed); pthread_mutex_unlock(&h->writer.lock);
    return 0; /* response deferred until the writer's eventfd completion */
}
static void prepared_ready(void *user,struct steer_prototype_prepared_input *input) {
    struct host *h=user;struct control *c;struct prepared *prepared;int code,n;char body[128];
    loop_timer_set(h->work,0);
    if(h->stopping||input->control_index>=CONTROLS)return;
    c=&h->controls[input->control_index];
    if(c->fd<0||c->serial!=input->serial||!c->waiting_prepare)return;
    c->waiting_prepare=0;
    if(input->error||(uint64_t)loop_now_ms()>=input->deadline_ms) {
        control_error(c,input->error&&input->error!=499?input->error:408);return;
    }
    /* CAS is rechecked after worker result, before any bind/route preparation. */
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->inbound_runtime&&h->split_fenced) { control_error(c,503);return; }
#endif
    if(!input->validate&&h->split_fenced) { control_error(c,503);return; }
    if(!input->validate&&input->expected!=h->current->number) { control_error(c,409);return; }
    prepared=calloc(1,sizeof *prepared);if(!prepared) { control_error(c,503);return; }
    code=prepare_configuration(h,NULL,0,input->expected,input->validate,0,0,prepared,input);
    if(code!=200) { free(prepared);control_error(c,code);return; }
    if((uint64_t)loop_now_ms()>=input->deadline_ms) {
        if(prepared->generation)discard_prepared(h,prepared);
        free(prepared);control_error(c,408);return;
    }
    if(input->validate) {
        int validation_only=prepared->validation_only;
        free(prepared);n=snprintf(body,sizeof body,"{\"valid\":true,\"persistence\":%s%s}",h->store?"true":"false",
            validation_only?",\"validationOnly\":true,\"candidateRuntimeReady\":false":"");
        control_response(c,200,body,(size_t)n);return;
    }
    if(h->store) {
        code=queue_durable(c,prepared);
        if(code) { discard_prepared(h,prepared);free(prepared);control_error(c,code); }
    } else { publish_prepared(h,prepared);free(prepared);applied_response(c,200); }
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
    char status[8192];
    size_t length;
    int code;
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h->wg){
        code=steer_prototype_wg_request(h->wg,c->operation,c->expected,c->input+c->header_length,
            c->body_length,c->input,sizeof(c->input),&length);
        control_response(c,code,c->input,length);
        return;
    }
#endif
    if (c->operation == 1) {
        length = status_json(h, status, sizeof(status));
        control_response(c, 200, status, length);
    } else if (c->operation == 2) {
        struct generation *g = h->current;
        if(h->experimental_durable_split&&h->durability_uncertain){control_error(c,503);return;}
        const char *document=h->selected_document?h->selected_document:g->document;
        size_t document_length=h->selected_document?h->selected_length:g->document_length;
        uint64_t revision=h->selected_document?h->selected_revision:g->number;
        if(!steer_control_get_frame(c->output,sizeof c->output,&c->output_length,document,document_length,
            revision,g->number,h->experimental_durable_split,h->split_fenced,h->store!=NULL,h->durability_uncertain)){
            control_error(c,500);return;
        }
        c->writing=1;
        if(loop_fd_mod(c->host->loop,c->fd,EPOLLOUT))close_control(c);
    } else {
        uint64_t generation=h->current->number+1;
        if(c->operation==4&&h->split_fenced){control_error(c,503);return;}
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(h->linked_wg){
            if(h->wg_fenced||(c->operation==4&&h->wg_retire_error)){control_error(c,503);return;}
            generation=h->wg_next;
        }
#endif
        if(c->operation==4&&c->expected!=h->current->number) { control_error(c,409);return; }
        if(!h->preparer||h->store_busy||steer_prototype_prepare_busy(h->preparer)) { control_error(c,503);return; }
        code=steer_prototype_prepare_submit(h->preparer,c->input+c->header_length,c->body_length,generation,
            c->expected,(unsigned)(c-h->controls),c->serial,c->operation==3,c->deadline_ms);
        if(code) { control_error(c,code);return; }
        c->waiting_prepare=1;
        /* The full request is already buffered. A peer may close only its
         * write half and still expect the reply. HUP/ERR are always reported. */
        if(loop_fd_mod(h->loop,c->fd,0)) {
            steer_prototype_prepare_cancel(h->preparer,(unsigned)(c-h->controls),c->serial);c->waiting_prepare=0;control_error(c,503);
        }
    }
}
static void control_ready(struct loop *l, int fd, uint32_t events, void *arg)
{
    struct control *c = arg;
    ssize_t n;
    (void)l;
    if (c->waiting_store||c->waiting_prepare) {
        if (events & (EPOLLHUP | EPOLLERR)) close_control(c);
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
        c->deadline_ms=(uint64_t)loop_now_ms()+5000;
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
    const char *state_dir = NULL;
    struct steer_store_document *snapshot = NULL;
    struct steer_pv1_error error;
    FILE *file;
    size_t length = 0;
    int result = 1, seed = 0, linked_wg=0, inbound_validate=0, inbound_runtime=0;
#ifdef STEER_PROTOTYPE_WG_NETNS
    /* One exclusive opt-in profile, kernel dataplane, serialized control.
     * fd 3 must pin the original netns from before entry into the fixture. */
    if((argc==6||argc==8||argc==9)&&!strcmp(argv[1],"--wg-netns-profile")&&!strcmp(argv[2],"--control")&&
       !strcmp(argv[4],"--state-dir")){
        uint64_t socks=0;
        if(argc>=8){
            const char *p=argv[7];
            if(strcmp(argv[6],"--socks-port")||!decimal(&p,&socks)||*p||!socks||socks>UINT16_MAX)return 2;
        }
        if(argc==9&&strcmp(argv[8],"--scoped-route"))return 2;
        if(!initialize_host(&h,clients))goto cleanup;
        if(steer_prototype_wg_open(argv[5],3,(uint16_t)socks,argc==9,&h.wg))goto cleanup;
        if(socks){
            /* Frontend lifetime is independent of WG revisions; each accepted
             * SOCKS request still pins the published WG revision. */
            struct generation *g=&h.generations[0];
            struct listener *l=&h.listeners[0];
            g->number=1;
            if(!prepare_stream_routes(&h,g,NULL))goto cleanup;
            strcpy(l->identity.id,"socks-entry");
            strcpy(l->spec.id,"socks-entry");
            strcpy(l->spec.address,"127.0.0.1");
            l->spec.protocol=STEER_PROTOTYPE_SOCKS;
            l->spec.port=(uint16_t)socks;
            prepare_socks(g,0,l);
            if(!bind_listener(&h,l,NULL))goto cleanup;
            h.current=g;l->active=1;
            set_socks_admission(g,1);
        }
        if(!bind_control(&h,argv[3]))goto cleanup;
        size_t ready;
        (void)steer_prototype_wg_request(h.wg,1,0,NULL,0,status,sizeof(status),&ready);
        printf("READY %.*s\n",(int)ready,status);fflush(stdout);
        result=loop_run(h.loop);
        goto cleanup;
    }
#endif
    if(argc<5||strcmp(argv[1],"--config")||strcmp(argv[3],"--control"))return 2;
    for(int i=5;i<argc;){
        if(!strcmp(argv[i],"--state-dir")&&i+1<argc&&!state_dir){
            state_dir=argv[i+1];i+=2;
        }else if(!strcmp(argv[i],"--allow-socks-vpn-bind")&&i+3<argc){
            if(!steer_prototype_socks_vpn_allow(&h.socks_vpn,argv[i+1],argv[i+2],argv[i+3])){
                fputs("invalid or duplicate SOCKS VPN startup allowlist entry\n",stderr);
                return 2;
            }
            i+=4;
        }
        else if(!strcmp(argv[i],"--experimental-durable-split")&&!h.experimental_durable_split){
            h.experimental_durable_split=1;i++;
        }
#ifdef STEER_PROTOTYPE_SPLIT_FAULT
        else if(!strcmp(argv[i],"--test-fail-after-sync")&&!h.test_fail_after_sync){
            h.test_fail_after_sync=1;i++;
        }
#endif
#if defined(STEER_PROTOTYPE_WG_NETNS) && defined(STEER_PROTOTYPE_HY2)
        else if(!strcmp(argv[i],"--allow-wg-stream-netns")&&!linked_wg){linked_wg=1;i++;}
        else if(!strcmp(argv[i],"--validate-wg-inbound-netns")&&!inbound_validate){inbound_validate=1;i++;}
#endif
#ifdef STEER_PROTOTYPE_WG_NETNS
        else if(!strcmp(argv[i],"--experimental-wg-inbound-netns")&&!inbound_runtime){inbound_runtime=1;i++;}
#endif
        else return 2;
    }
    if(h.experimental_durable_split&&!state_dir)return 2;
    if(h.experimental_durable_split&&(linked_wg||inbound_validate))return 2;
    if(inbound_runtime&&(linked_wg||inbound_validate||!state_dir))return 2;
#ifdef STEER_PROTOTYPE_SPLIT_FAULT
    if(h.test_fail_after_sync&&(!h.experimental_durable_split||inbound_runtime))return 2;
#endif
    if(inbound_validate||inbound_runtime){
#ifdef STEER_PROTOTYPE_WG_NETNS
        struct steer_draft_wg_linux_link *gate=NULL;
        if(linked_wg||!state_dir||steer_prototype_wg_gate(3,0,&gate))return 2;
        if(inbound_runtime){h.inbound_runtime=1;h.inbound_guard.link=gate;h.experimental_durable_split=1;}
        else steer_draft_wg_linux_link_close(gate);
        h.socks_vpn.wg_inbound_validate=1;
#else
        return 2;
#endif
    }
    if (!initialize_host(&h, clients)) goto cleanup;
    if (steer_draft_resolver_create(h.loop, 2, 64, NULL, NULL, &h.resolver).code) goto cleanup;
    if (state_dir) {
        if (steer_prototype_store_open(state_dir, &h.store).code) goto cleanup;
        if(!linked_wg){
            char path[PATH_MAX];struct stat st;
            int n=snprintf(path,sizeof(path),"%s/wg-linked-journal",state_dir);
            if(n<0||(size_t)n>=sizeof(path)||!lstat(path,&st)||errno!=ENOENT)goto cleanup;
        }
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(linked_wg){
            if(steer_linked_wg_open(state_dir,3,&h.linked_wg))goto cleanup;
            h.socks_vpn.wg_stream=1;
        }
#endif
        error = steer_prototype_store_recover_document(h.store, &snapshot);
        if (error.code && error.code != STEER_PV1_UNSUPPORTED) goto cleanup;
        seed = error.code == STEER_PV1_UNSUPPORTED;
    }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(linked_wg&&!h.linked_wg)goto cleanup;
#endif
    if (snapshot) {
        if(configure_initial(&h,snapshot->document,snapshot->length,snapshot->generation,snapshot->format)!=200)goto cleanup;
        steer_store_document_destroy(snapshot);snapshot=NULL;
    } else {
        document = malloc(STEER_PROTOTYPE_CONFIG_MAX_BYTES + 1);
        if (!document) goto cleanup;
        file = fopen(argv[2], "rb");
        if (!file) { result = 2; goto cleanup; }
        length = fread(document, 1, STEER_PROTOTYPE_CONFIG_MAX_BYTES + 1, file);
        if (ferror(file) || length > STEER_PROTOTYPE_CONFIG_MAX_BYTES) { fclose(file); result = 2; goto cleanup; }
        fclose(file);
        uint64_t initial=1;
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(h.linked_wg){
            struct steer_draft_wg_stream *unused=NULL;
            if(steer_linked_wg_recover(h.linked_wg,NULL,NULL,&h.wg_next,&unused))goto cleanup;
            initial=h.wg_next;
        }
#endif
        if(configure_initial(&h,document,length,initial,0)!=200)goto cleanup;
    }
    if (!bind_control(&h, argv[4])) goto cleanup;
    if (h.store && !start_writer(&h)) goto cleanup;
    if(steer_prototype_prepare_create(h.loop,prepared_ready,&h,&h.socks_vpn,&h.preparer))goto cleanup;
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
        if(h.experimental_durable_split&&h.durability_uncertain)goto cleanup;
#ifdef STEER_PROTOTYPE_WG_NETNS
        if(h.linked_wg){
            if(h.durability_uncertain){h.wg_fenced=1;goto cleanup;}
            steer_linked_wg_commit(h.linked_wg,h.current->config,h.current->wg_stream);
        }
#endif
    }
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h.inbound_runtime){
        char path[PATH_MAX];
        int n=snprintf(path,sizeof path,"%s/wg-inbound-journal",state_dir);
        if(n<0||(size_t)n>=sizeof path)goto cleanup;
        if(mkdir(path,0700)&&errno!=EEXIST)goto cleanup;
        int fd=open(state_dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0)goto cleanup;
        int sync_error=fsync(fd);close(fd);
        if(sync_error)goto cleanup;
        if(steer_draft_wg_selection_open_inbound(path,64,&h.inbound.journal))goto cleanup;
        h.inbound.backend=&steer_draft_wg_linux_guard_backend;
#ifdef STEER_PROTOTYPE_INBOUND_FAULT
        h.inbound_fault_backend=steer_draft_wg_linux_guard_backend;
        h.inbound_fault_backend.guard=inbound_fault_guard;
        h.inbound.backend=&h.inbound_fault_backend;
#endif
        h.inbound.context=&h.inbound_guard;h.inbound.backend_guard=&h.inbound_guard.prepared;
        h.inbound.barrier_close=steer_draft_wg_linux_guard_barrier_close;
        h.inbound.barrier_open=steer_draft_wg_linux_guard_barrier_open;
#ifdef STEER_PROTOTYPE_INBOUND_PAUSE
        h.inbound.barrier_open=inbound_pause_open;
#endif
        struct steer_prototype_config *config=h.current->config;
        struct steer_draft_wg_revision revision=inbound_revision(config);
        uint64_t next;struct steer_draft_wg_guard_record record;
        if(!config->wg_inbound_validate){
            if(steer_linked_inbound_recover(&h.inbound,&revision,inbound_verify_none,inbound_deadline(),&next,&record))goto cleanup;
            if(steer_draft_wg_selection_inbound_had_published(h.inbound.journal,&revision,
                inbound_deadline(),&h.inbound_removed))goto cleanup;
        }else{
            struct awg_secrets keys={0};
            struct steer_draft_kernel_wg_guard_config guard=config->wg_inbound_validate->cfg.guard;
            guard.generation=config->generation;
            struct steer_linked_inbound_recovery recovery={.guard=h.inbound_guard,.revision=revision,
                .inbound=&guard,.policy=config->policy,.wireguard=&config->wg_inbound_validate->cfg.kernel,
                .keys=&keys,.require_down=1};
            h.inbound.context=&recovery;h.inbound.backend_guard=&recovery.guard.prepared;
            int rc=steer_linked_wg_keys(config->wg_inbound_validate,&keys)?EACCES:
                steer_linked_inbound_recover_down_checked(&h.inbound,&recovery,inbound_deadline(),&next,&record);
            if(!rc)rc=steer_linked_inbound_verify_down(&recovery,&record,inbound_deadline());
            h.inbound.context=&h.inbound_guard;h.inbound.backend_guard=&h.inbound_guard.prepared;
            awg_secrets_wipe(&keys);
            if(rc)goto cleanup;
            h.inbound.candidate.guard=record;
            h.inbound.barrier_state=STEER_INBOUND_BARRIER_UNKNOWN;
            rc=h.inbound.barrier_open(h.inbound.context,&record,inbound_deadline(),&h.inbound.barrier_state);
            if(rc||h.inbound.barrier_state!=STEER_INBOUND_BARRIER_OPEN)goto cleanup;
        }
    }
#endif
    length = status_json(&h, status, sizeof(status));
    printf("READY %.*s\n", (int)length, status); fflush(stdout);
    result = loop_run(h.loop);
#ifdef STEER_PROTOTYPE_WG_NETNS
    if(h.inbound_shutdown_error)result=1;
#endif
cleanup:
    cleanup_host(&h);
#ifdef STEER_PROTOTYPE_WG_NETNS
    steer_prototype_wg_close(h.wg);
    steer_linked_wg_close(h.linked_wg);
    steer_draft_wg_selection_close(h.inbound.journal);
    steer_draft_wg_linux_link_close(h.inbound_guard.link);
#endif
    free(document); steer_store_document_destroy(snapshot);
    return result;
}
