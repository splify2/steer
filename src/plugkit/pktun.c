/* Ключи туннеля по подписке (pktun.h). */
#define _GNU_SOURCE
#include "pktun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonw.h"

static const char *const TT_NAMES[TT_COUNT] = { "tcp", "grpc", "xhttp", "ws", "httpupgrade" };

unsigned pk_transport_bit(const char *name) {
    for (unsigned i = 0; i < TT_COUNT; i++)
        if (!strcmp(name, TT_NAMES[i])) return 1u << i;
    return 0;
}

static int cc_list(const struct pk_out *o, const char *key, char (**cc)[3], size_t *n) {
    const char **s;
    size_t k;
    *cc = NULL;
    *n = 0;
    if (pk_key_strs(o, key, &s, &k) != 0) return -1;
    if (!k) return 0;
    *cc = calloc(k, 3);
    if (!*cc) { free(s); return -1; }
    for (size_t i = 0; i < k; i++) snprintf((*cc)[i], 3, "%.2s", s[i]);
    *n = k;
    free(s);
    return 0;
}

int pk_tun_load(const struct pk_out *o, struct pk_tun *t, char *err, size_t errn) {
    memset(t, 0, sizeof(*t));
    t->sub_file = pk_key_str(o, "subscription");
    if (!t->sub_file || !*t->sub_file) {
        snprintf(err, errn, "нужен subscription — файл подписки");
        return -1;
    }
    if (pk_key_ints(o, "nodes", &t->nodes, &t->nodes_n) != 0) { snprintf(err, errn, "nodes: нужны номера узлов"); return -1; }
    const char **tr;
    size_t trn;
    if (pk_key_strs(o, "transport", &tr, &trn) != 0) { snprintf(err, errn, "transport: нужны имена"); return -1; }
    for (size_t i = 0; i < trn; i++) t->transports |= pk_transport_bit(tr[i]);
    free(tr);
    t->insecure = pk_key_bool(o, "insecure", 0);
    if (cc_list(o, "exclude", &t->excl.cc, &t->excl.cc_n) != 0 ||
        cc_list(o, "only", &t->excl.only, &t->excl.only_n) != 0 ||
        pk_key_strs(o, "exclude_name", &t->excl.names, &t->excl.names_n) != 0) {
        snprintf(err, errn, "exclude, only, exclude_name: нужны строки");
        return -1;
    }
    struct pk_pool *p = &t->pool;
    p->active = (int)pk_key_long(o, "active", 0);
    p->interval_s = (int)pk_key_long(o, "interval", 0);
    long sil = pk_key_long(o, "silence", -2);
    p->silence_s = sil == -2 ? 0 : sil == 0 ? -1 : (int)sil;
    const char *by = pk_key_str(o, "by");
    if (by) {
        p->by_set = 1;
        p->by = !strcmp(by, "site") ? 1 : !strcmp(by, "site_client") ? 2 : 0;
    }
    const char *pick = pk_key_str(o, "pick");
    p->pick = pick && !strcmp(pick, "latency");
    long tol = pk_key_long(o, "tolerance", -1);
    if (tol >= 0) { p->tolerance_ms = (int)tol; p->tol_set = 1; }
    return 0;
}

int pk_tun_check(const struct pk_tun *t, char *err, size_t errn) {
    const struct pk_pool *p = &t->pool;
    if (p->by_set && p->active <= 1) {
        snprintf(err, errn, "by — раздача соединений между активными узлами, она есть только при active "
                 "больше 1");
        return -1;
    }
    if (t->nodes_n && (size_t)p->active > t->nodes_n) {
        snprintf(err, errn, "active %d, а узлов в nodes %zu — активных не бывает больше выбранных", p->active,
                 t->nodes_n);
        return -1;
    }
    if (p->tol_set && !p->pick) {
        snprintf(err, errn, "tolerance — допуск смены узла по замеру, он есть только у pick: latency");
        return -1;
    }
    /* silence: 0 — порога нет; от 1 до 4 с — меньше повторной передачи на медленной линии. */
    if (p->silence_s > 0 && p->silence_s < 5) {
        snprintf(err, errn, "silence: %d с — меньше 5 с: столько длится повторная передача на медленной "
                 "линии, и живые соединения обрывались бы; 0 — порога нет", p->silence_s);
        return -1;
    }
    for (size_t i = 0; i < t->excl.only_n; i++)
        for (size_t b = 0; b < t->excl.cc_n; b++)
            if (!strcmp(t->excl.only[i], t->excl.cc[b])) {
                snprintf(err, errn, "%s — и в only, и в exclude", t->excl.cc[b]);
                return -1;
            }
    return 0;
}

size_t pk_node_list(const struct pk_tun *t, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!t->nodes_n) {
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < t->nodes_n && n < max; i++)
        if (t->nodes[i] >= 0 && (size_t)t->nodes[i] < usable) dst[n++] = t->nodes[i];
    return n;
}

int pk_node_named(const struct pk_tun *t) { return t->nodes_n == 1; }

int pk_tun_check_hook(int (*extra)(const struct pk_tun *t, const struct pk_out *o, char *err, size_t errn)) {
    char err[512];
    struct pk_out o;
    memset(&o, 0, sizeof o);
    o.doc = pkj_load("-", err, sizeof err);
    if (!o.doc) pk_fail("check: %s", err);
    o.output = pkj_get(o.doc, "output");
    o.keys = pkj_get(o.output, "keys");
    snprintf(o.tun.name, sizeof o.tun.name, "%s", pkj_str(pkj_get(o.output, "name")) ? pkj_str(pkj_get(o.output, "name")) : "");
    snprintf(o.kind, sizeof o.kind, "%s", pkj_str(pkj_get(o.output, "kind")) ? pkj_str(pkj_get(o.output, "kind")) : "");
    struct pk_tun t;
    if (pk_tun_load(&o, &t, err, sizeof err) != 0 || pk_tun_check(&t, err, sizeof err) != 0 ||
        (extra && extra(&t, &o, err, sizeof err) != 0)) {
        fprintf(stderr, "%s\n", err);
        return 2;
    }
    return 0;
}

void pk_diag_json(char **buf, const char *id, const char *verdict, const char *what, const char *why) {
    char *f = NULL;
    size_t n = 0;
    FILE *m = open_memstream(&f, &n);
    if (!m) return;
    if (*buf && **buf) fprintf(m, "%s,", *buf);
    fputs("{\"id\":", m);
    jsonw_str(m, id);
    fputs(",\"verdict\":", m);
    jsonw_str(m, verdict);
    fputs(",\"what\":", m);
    jsonw_str(m, what);
    fputs(",\"why\":", m);
    jsonw_str(m, why ? why : "");
    fputc('}', m);
    fclose(m);
    free(*buf);
    *buf = f;
}
