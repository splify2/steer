/* kind: tunnel, protocol: trojan|shadowsocks|socks|http|vmess — туннели протоколов прокси, их
 * устройство создаёт процесс `steer proxy <выход>` (src/proto/proxy; стек — src/tunnel/stack.c).
 *
 * Пять протоколов — пять видов в реестре (так их находит разбор v2: kind_by_name(protocol)), но
 * настройка и помощник у них общие (struct proxy_cfg): различается только proto, который и
 * запоминается при разборе по имени вида. По устройству это тот же туннель, что vless и hysteria2.
 *
 * Виды ТОЛЬКО пакета steer-proxy (как hysteria2 — своего): в steer-extended и в телефон не входят,
 * нет модуля — отказ при разборе спеки «kind … требует пакет steer-proxy» (kind.c). Довод тот же,
 * что у vless.c: отказать сразу, а не дать выходу молча никуда не вести.
 *
 * transport у выхода нет: транспорт берётся из ссылки узла (у trojan/vmess он есть, у ss/socks/http
 * — голый tcp). insecure тоже нет: у trojan/vmess/http это свойство узла (и общий ключ выхода
 * vless.insecure, который модуль ставит до разбора подписки). */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "spec.h"
#include "tunpool.h"

/* enum px_proto (proxy.h) — числами, чтобы ядро не зависело от заголовка модуля. */
enum { PXK_TROJAN = 1, PXK_SS, PXK_SOCKS, PXK_HTTP, PXK_VMESS };

static int proto_of_kind(const struct kind_ops *k) {
    if (k == &kind_trojan) return PXK_TROJAN;
    if (k == &kind_shadowsocks) return PXK_SS;
    if (k == &kind_socks) return PXK_SOCKS;
    if (k == &kind_http) return PXK_HTTP;
    if (k == &kind_vmess) return PXK_VMESS;
    return 0;
}

const struct proxy_cfg *out_proxy(const struct output *o) {
    return proto_of_kind(kind_of(o)) ? &o->proxy : NULL;
}

static int proxy_parse(struct output *o, const struct out_keys *k, struct err *e) {
    o->proxy.proto = proto_of_kind(kind_of(o));
    snprintf(o->proxy.sub_file, sizeof(o->proxy.sub_file), "%s", k->sub_file);
    o->proxy.nodes = k->nodes;
    o->proxy.nodes_n = k->nodes_n;
    o->proxy.insecure = k->insecure;
    o->proxy.excl = k->excl;
    o->proxy.pool = k->pool;
    if (tun_pool_check(o, k, e) != 0) return -1;
    if (!o->proxy.sub_file[0]) {
        char msg[160];
        snprintf(msg, sizeof(msg), "outputs.%s: kind %s нужен %s с подпиской", o->name,
                 kind_of(o)->name, "subscription");
        return err_set(e, "%s", msg);
    }
    char msg[200];
    /* transport — выбор транспорта узла VLESS; у прокси он берётся из ссылки узла. */
    if (k->transports) {
        snprintf(msg, sizeof(msg), "outputs.%s: у kind %s нет transport — он берётся из ссылки узла",
                 o->name, kind_of(o)->name);
        return err_set(e, "%s", msg);
    }
    /* insecure — только там, где есть TLS: trojan, vmess, http(s). У ss и socks его нет. */
    if (k->insecure && o->proxy.proto != PXK_TROJAN && o->proxy.proto != PXK_VMESS &&
        o->proxy.proto != PXK_HTTP) {
        snprintf(msg, sizeof(msg), "outputs.%s: у kind %s нет insecure — у него нет TLS",
                 o->name, kind_of(o)->name);
        return err_set(e, "%s", msg);
    }
    if (!o->device[0]) snprintf(o->device, sizeof(o->device), "%.15s", o->name);
    return 0;
}

static void proxy_keys_of(const struct output *o, struct out_keys *k) {
    snprintf(k->sub_file, sizeof(k->sub_file), "%s", o->proxy.sub_file);
    k->nodes = o->proxy.nodes;
    k->nodes_n = o->proxy.nodes_n;
    k->insecure = o->proxy.insecure;
    k->excl = o->proxy.excl;
    k->pool = o->proxy.pool;
    char dev[32];
    snprintf(dev, sizeof(dev), "%.15s", o->name);
    k->device_derived = !strcmp(dev, o->device);
}

/* Файл состояния модуля (proxy-<выход>) пишет пул узлов (src/tunnel/pool.c); читает tun_state_read
 * (tunpool.h): верен, пока жив процесс из поля pid. */
static void proxy_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    fprintf(out, ",\"nodes\":[");
    for (size_t d = 0; d < o->proxy.nodes_n; d++)
        fprintf(out, "%s%d", d ? "," : "", o->proxy.nodes[d]);
    fprintf(out, "]");
    char *st = tun_state_load("proxy", o->name);
    if (st) fprintf(out, ",\"proxy\":%s", st);
    free(st);
}

static void proxy_diag(kind_diag_fn *put, const struct spec *sp, const struct output *o) {
    (void)sp;
    char what[200];
    char *buf = tun_state_load("proxy", o->name);
    if (!buf) {
        snprintf(what, sizeof(what), "выход %.40s: клиент %s не запущен", o->name, kind_of(o)->name);
        put("proxy", "fail", what, "перезапустите ядро steer: /etc/init.d/steer restart");
        return;
    }
    int up = strstr(buf, "\"up\":true") != NULL;
    free(buf);
    snprintf(what, sizeof(what), "выход %.40s: соединение с узлом %s %s", o->name, kind_of(o)->name,
             up ? "поднято" : "не поднято");
    put("proxy", up ? "ok" : "fail", what,
        up ? "" : "узел не принял соединение: `steer proxy-probe` называет причину");
    if (up) tun_pool_diag(put, "proxy", o, &o->proxy.pool);
}

static int proxy_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    snprintf(h->cmd, sizeof(h->cmd), "proxy");
    kind_sig_mix(&h->sig, o->proxy.sub_file, strlen(o->proxy.sub_file));
    kind_sig_mix(&h->sig, &o->proxy.proto, sizeof(o->proxy.proto));
    if (o->proxy.insecure) kind_sig_mix(&h->sig, "insecure", 8);
    FILE *f = fopen(o->proxy.sub_file, "r");
    if (f) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(&h->sig, buf, n);
        fclose(f);
    }
    for (size_t i = 0; i < o->proxy.nodes_n; i++)
        kind_sig_mix(&h->sig, &o->proxy.nodes[i], sizeof(o->proxy.nodes[i]));
    kind_sig_excl(&h->sig, &o->proxy.excl);
    /* Пул узлов (active, by, interval, silence) клиент читает при старте, как и выбор узлов. */
    if (o->proxy.pool.active || o->proxy.pool.by || o->proxy.pool.interval_s || o->proxy.pool.silence_s ||
        o->proxy.pool.pick || o->proxy.pool.tol_set)
        kind_sig_mix(&h->sig, &o->proxy.pool, sizeof(o->proxy.pool));
    return 0;
}

size_t out_proxy_node_list(const struct output *o, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!o->proxy.nodes_n) {
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < o->proxy.nodes_n && n < max; i++)
        if (o->proxy.nodes[i] >= 0 && (size_t)o->proxy.nodes[i] < usable) dst[n++] = o->proxy.nodes[i];
    return n;
}

int out_proxy_node_named(const struct output *o) { return o->proxy.nodes_n == 1; }

/* Общая таблица пяти видов: различается только name. selfnat_why и caps — те же, что у vless. */
#define PROXY_KIND(ident, nm) \
    const struct kind_ops ident = { \
        .name = nm, \
        .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_SELF_NAT | KC_OVER | \
                KC_SKIP_ZAPRET | KC_TCP_PROBE | KC_FLOW_UDP | KC_TCP_REDIR, \
        .keys = KK_NODES | KK_SUB, \
        .selfnat_why = "masquerade не нужен: туннель завершает TCP сам, адреса клиентов " \
                       "наружу не уходят", \
        .parse = proxy_parse, .keys_of = proxy_keys_of, \
        .status = proxy_status, .diag = proxy_diag, .helper = proxy_helper, \
    }

PROXY_KIND(kind_trojan, "trojan");
PROXY_KIND(kind_shadowsocks, "shadowsocks");
PROXY_KIND(kind_socks, "socks");
PROXY_KIND(kind_http, "http");
PROXY_KIND(kind_vmess, "vmess");
