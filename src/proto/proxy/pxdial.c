/* Общее между дайлерами steer-proxy: узел глазами транспорта, открытие потока, проба и подъём
 * (pxdial.h). Стек туннеля — src/tunnel/stack.c, транспорт — src/proto/transport. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

#include "pxdial.h"
#include "sublink.h"
#include "stack.h"
#include "pool.h"

const struct dialer_ops *px_dialer_for(enum px_proto p) {
    switch (p) {
    case PX_TROJAN: return &proxy_trojan_dialer;
    case PX_SS:     return &proxy_ss_dialer;
    case PX_SOCKS:  return &proxy_socks_dialer;
    case PX_HTTP:   return &proxy_http_dialer;
    case PX_VMESS:  return &proxy_vmess_dialer;
    }
    return NULL;
}

void px_tr_node(const struct px_node *n, struct tr_node *t) {
    sl_tr_node(&n->vn, t);
}

int px_stream_open(const struct px_node *n, struct transport *t, int timeout_s) {
    struct tr_node tn;
    px_tr_node(n, &tn);
    return transport_open(t, &tn, timeout_s);
}

const char *px_strerror(int rc) {
    switch (rc) {
    case PX_EAUTH:  return "сервер отверг авторизацию";
    case PX_EPROTO: return "ответ не по протоколу";
    case PX_EADDR:  return "сервер отказал в адресе назначения";
    default:        return transport_strerror(rc);
    }
}

/* ---- проба --------------------------------------------------------------------------------- */

static int probe_emit(void *arg, const unsigned char *p, size_t n) {
    (void)p; (void)n;
    *(int *)arg = 1;
    return 0;
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int px_probe(const struct px_node *n, int timeout_s, char *why, size_t why_n, int *hs_ms) {
    if (hs_ms) *hs_ms = -1;
    const struct dialer_ops *ops = px_dialer_for(n->proto);
    if (!ops) { snprintf(why, why_n, "протокол не поддержан"); return PX_EPROTO; }
    void *sess = calloc(1, ops->sess_size);
    if (!sess) { snprintf(why, why_n, "нет памяти"); return TR_EIO; }
    ops->clear(sess);

    struct flow_key k;
    memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "10.0.0.1", &k.src);
    inet_pton(AF_INET, "1.1.1.1", &k.dst);
    k.sport = 40000;
    k.dport = 80;

    int rc = 0;
    if (ops->flow_open(n, sess, &k, 0) != 0) {
        snprintf(why, why_n, "поток не завёлся");
        rc = PX_EPROTO; goto out;
    }
    int64_t t0 = now_ms();
    rc = ops->connect(n, sess, timeout_s > 0 ? timeout_s : 8);
    if (rc) { snprintf(why, why_n, "%s", px_strerror(rc)); goto out; }
    if (hs_ms) *hs_ms = (int)(now_ms() - t0);

    static const char req[] = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    int sr = ops->send(n, sess, &k, 0, (const unsigned char *)req, sizeof(req) - 1);
    if (sr == SEND_FATAL) { snprintf(why, why_n, "запрос не ушёл"); rc = TR_EIO; goto out; }

    static __thread unsigned char buf[TUNNEL_BUF];
    int64_t deadline = now_ms() + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    int ok = 0;
    for (;;) {
        const unsigned char *data = NULL;
        size_t got = 0;
        int rr = ops->read(sess, buf, sizeof buf, &data, &got);
        if (rr) { snprintf(why, why_n, "ответа нет: %s", px_strerror(rr)); rc = rr; goto out; }
        if (got && ops->deliver(n, sess, 0, data, got, probe_emit, &ok) != 0) {
            snprintf(why, why_n, "ответ не по протоколу"); rc = PX_EPROTO; goto out;
        }
        if (ok) break;
        if (now_ms() >= deadline) break;
        struct pollfd pw = { .fd = ops->fd(sess), .events = POLLIN, .revents = 0 };
        poll(&pw, 1, 200);
    }
    if (!ok) { snprintf(why, why_n, "сервер не прислал данных"); rc = TR_EIO; goto out; }
    snprintf(why, why_n, "ok");
    rc = 0;
out:
    ops->close(sess);
    free(sess);
    return rc;
}

/* ---- подъём -------------------------------------------------------------------------------- */

int px_tunnel_run(const struct tun_out *o, const struct pool_cfg *pc,
                  void (*ready)(void *arg, const char *dev), void *arg) {
    const struct px_node *node = (const struct px_node *)pc->nodes + pc->first;
    if (!pc->proto->ops) {
        fprintf(stderr, "steer[warn]: proxy: протокол узла %s не поддержан — туннель %s не поднят\n",
                node->name, o->device);
        return 1;
    }
    return pool_run(o, pc, ready, arg);
}
