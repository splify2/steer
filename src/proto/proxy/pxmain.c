/* Модуль steer-proxy: подкоманды `steer proxy`, `proxy-nodes`, `proxy-probe`. Повторяет устройство
 * vlmain.c (общее — «прочитать спеку, выбрать узел, поднять стек на пуле узлов»), различается узлом
 * и мерой. Слежка за узлами и файл состояния для status/diag — у пула (src/tunnel/pool.c). */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "proxy.h"
#include "pxdial.h"
#include "sublink.h"
#include "spec.h"
#include "evline.h"
#include "jsonw.h"
#include "probe.h"
#include "pool.h"

#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

static struct px_node *g_nodes;

static struct spec *spec_new(void) {
    struct spec *sp = calloc(1, sizeof(*sp));
    if (!sp) die("нет памяти под спеку", NULL);
    return sp;
}

static int *sel_alloc(const struct output *o, size_t cnt, size_t *cap) {
    size_t c = cnt;
    if (o && o->proxy.nodes_n > c) c = o->proxy.nodes_n;
    *cap = c;
    int *s = calloc(c + 1, sizeof(*s));
    if (!s) die("нет памяти под список узлов", NULL);
    return s;
}

static int load_nodes_file(const char *path, enum px_proto want, size_t *cnt, struct px_sub_stats *st) {
    free(g_nodes);
    g_nodes = px_load_sub(path, want, cnt, st);
    if (!g_nodes) { fprintf(stderr, LOG_W2 "%s не читается (или больше 64 МиБ)\n", path); return 2; }
    return 0;
}

static int load_nodes(struct spec *sp, const char *spec_path, const char *out_name,
                      struct output **out, size_t *cnt, struct px_sub_stats *st) {
    struct err e = {0};
    if (load_spec(spec_path, sp, &e) < 0) err_die(&e);
    struct output *o = out_by_name(sp, out_name);
    if (!o) { fprintf(stderr, LOG_W2 "выхода %s нет в спеке\n", out_name); return 2; }
    const struct proxy_cfg *pc = out_proxy(o);
    if (!pc) { fprintf(stderr, LOG_W2 "выход %s не протокол прокси (kind другой)\n", out_name); return 2; }
    *out = o;
    /* insecure выхода — до разбора подписки: от него зависит пригодность узлов с allowInsecure
     * (общий ключ sublink.c, как у vless). */
    vless_set_insecure(pc->insecure);
    if (pc->insecure)
        fprintf(stderr, LOG_W2 "выход %s: insecure — сертификат узлов security=tls НЕ проверяется\n", out_name);
    return load_nodes_file(pc->sub_file, (enum px_proto)pc->proto, cnt, st);
}

/* Метка сокетов к узлам — до соединения (как у vless): проба и туннель идут одним путём (via). */
static void underlay_setup(struct spec *sp, const struct output *o) {
    static const struct output none;
    if (o && o->over[0]) {
        struct err e = {0};
        if (registry_assign(sp, &e) < 0) err_die(&e);
    }
    transport_set_sock_mark(out_underlay_mark(sp, o ? o : &none), o && o->over[0]);
}

/* x — исключение выхода; NULL — перечень по файлу. cc и excluded — как у vless (vlmain.c). */
static void node_json(const struct px_node *n, int index, const struct node_exclude *x) {
    printf("{\"index\":%d,\"name\":", index);
    jsonw_str(stdout, n->name);
    printf(",\"host\":");
    jsonw_str(stdout, n->vn.host);
    printf(",\"port\":%u,\"type\":", n->vn.port);
    jsonw_str(stdout, px_proto_name(n->proto));
    printf(",\"security\":");
    jsonw_str(stdout, n->vn.security[0] ? n->vn.security : "none");
    printf(",\"transport\":");
    jsonw_str(stdout, n->vn.type[0] ? n->vn.type : "tcp");
    /* Для бейджей конфигурации — только у тех узлов, где поле что-то значит, поэтому прежние поля
     * прежних узлов не меняются. method — шифр shadowsocks; cipher — шифр тела vmess (scy: auto,
     * aes-128-gcm, chacha20-poly1305); fp — отпечаток браузера в ClientHello у узлов с TLS/Reality;
     * insecure — узел TLS несёт allowInsecure (в перечне он есть лишь при insecure выхода или
     * `--insecure` по файлу, и сертификат его не проверяется). */
    if (n->proto == PX_SS) { printf(",\"method\":"); jsonw_str(stdout, px_ss_method_name(n->ss_method)); }
    if (n->proto == PX_VMESS) { printf(",\"cipher\":"); jsonw_str(stdout, px_vmess_sec_name(n->vmess_sec)); }
    if (n->vn.fp[0] && n->vn.security[0] && strcmp(n->vn.security, "none") != 0) {
        printf(",\"fp\":"); jsonw_str(stdout, n->vn.fp);
    }
    if (n->vn.allow_insecure && !strcmp(n->vn.security, "tls")) printf(",\"insecure\":true");
    char cc[3];
    if (node_cc(n->name, cc)) { printf(",\"cc\":"); jsonw_str(stdout, cc); }
    if (node_excluded(x, n->name)) printf(",\"excluded\":true");
    printf("}");
}

/* exclude, exclude_name (proxy_cfg.excl): исключённые уходят из кандидатов, номера не сдвигаются.
 * Одна функция на подъём и на `proxy-probe`. */
static size_t exclude_filter(const struct output *o, const struct px_node *nodes, int *sel, size_t n) {
    if (!o) return n;
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (!node_excluded(&o->proxy.excl, nodes[sel[i]].name)) sel[k++] = sel[i];
    return k;
}

static void skipped_json(const struct px_sub_stats *st) {
    printf(",\"skipped_reasons\":[");
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (i) putchar(',');
        printf("{\"reason\":");
        jsonw_str(stdout, st->reasons[i].reason);
        printf(",\"count\":%zu,\"example\":", st->reasons[i].count);
        jsonw_str(stdout, st->reasons[i].example);
        printf("}");
    }
    printf("]");
    if (st->reasons_dropped) printf(",\"skipped_other\":%zu", st->reasons_dropped);
}

int cmd_proxy_nodes(const char *spec_path, const char *out_name, int insecure) {
    struct output *o = NULL;
    size_t cnt = 0;
    struct px_sub_stats st;
    int by_file = out_name && out_name[0] == '/';
    /* Пригодность узла TLS с allowInsecure решает insecure выхода (общий ключ sublink.c, как у vless);
     * без выхода — `--insecure`, тем же вызовом до того же разбора, что в load_nodes. Номера по файлу
     * с флагом поэтому совпадают с номерами выхода с `insecure: true` (у файла — сквозные по пяти
     * протоколам, у выхода — внутри его протокола: порядок внутри протокола один и тот же). */
    if (by_file) vless_set_insecure(insecure);
    int rc = by_file ? load_nodes_file(out_name, 0, &cnt, &st)
                     : load_nodes(spec_new(), spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->proxy.sub_file);
    size_t chosen_n = o ? o->proxy.nodes_n : 0;
    printf(",\"node\":%d,\"chosen\":[", chosen_n == 1 ? o->proxy.nodes[0] : -1);
    for (size_t i = 0; i < chosen_n; i++) printf("%s%d", i ? "," : "", o->proxy.nodes[i]);
    printf("],\"usable\":%zu,\"skipped\":%zu,\"foreign\":%zu,\"nodes\":[", cnt, st.skipped, st.foreign);
    for (size_t i = 0; i < cnt; i++) { if (i) putchar(','); node_json(&g_nodes[i], (int)i, o ? &o->proxy.excl : NULL); }
    printf("]");
    skipped_json(&st);
    printf("}\n");
    return 0;
}

int cmd_proxy_probe(const char *spec_path, const char *out_name, int node, int timeout_s,
                    int insecure) {
    struct output *o = NULL;
    size_t cnt = 0;
    struct px_sub_stats st;
    int by_file = out_name && out_name[0] == '/';
    if (by_file) vless_set_insecure(insecure);         /* как у proxy-nodes: номера те же */
    struct spec *sp = spec_new();
    int rc = by_file ? load_nodes_file(out_name, 0, &cnt, &st)
                     : load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    if (!cnt) {
        printf("{\"ok\":false,\"error\":\"в подписке нет пригодных узлов\",\"skipped\":%zu,\"foreign\":%zu",
               st.skipped, st.foreign);
        skipped_json(&st);
        printf("}\n");
        return 1;
    }
    if (node >= (int)cnt) { printf("{\"ok\":false,\"error\":\"узла %d нет, всего %zu\"}\n", node, cnt); return 1; }
    size_t cap;
    int *sel = sel_alloc(o, cnt, &cap);
    size_t sel_n = 0;
    if (node >= 0) { sel[0] = node; sel_n = 1; }
    else if (by_file) { for (size_t i = 0; i < cnt; i++) sel[sel_n++] = (int)i; }
    else {
        sel_n = out_proxy_node_list(o, cnt, sel, cap);
        if (!sel_n) { printf("{\"ok\":false,\"error\":\"выбранных узлов нет в подписке, пригодных всего %zu\"}\n", cnt); return 1; }
        sel_n = exclude_filter(o, g_nodes, sel, sel_n);
        if (!sel_n) {
            printf("{\"ok\":false,\"error\":\"все выбранные узлы исключены exclude или exclude_name\"}\n");
            return 1;
        }
    }
    int found = -1;
    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->proxy.sub_file);
    printf(",\"results\":[");
    for (size_t k = 0; k < sel_n; k++) {
        size_t i = (size_t)sel[k];
        char why[256] = "";
        int hs = -1;
        int pr = px_probe(&g_nodes[i], timeout_s > 0 ? timeout_s : 8, why, sizeof(why), &hs);
        if (k) putchar(',');
        printf("{\"index\":%zu,\"name\":", i);
        jsonw_str(stdout, g_nodes[i].name);
        printf(",\"type\":");
        jsonw_str(stdout, px_proto_name(g_nodes[i].proto));
        printf(",\"ok\":%s,\"handshake_ms\":%d,\"ttfb_ms\":-1,\"why\":", pr == 0 ? "true" : "false", hs);
        jsonw_str(stdout, why);
        printf("}");
        if (pr == 0) { found = (int)i; if (node < 0) break; }
    }
    printf("],\"working\":%d}\n", found);
    return found >= 0 ? 0 : 1;
}

/* Файл состояния (proxy-<выход>, status и diag) и слежку за узлами ведёт пул узлов выхода
 * (src/tunnel/pool.c): N активных узлов сразу, проверка каждого, замена мёртвого без перезапуска
 * процесса. Прежде здесь жили своя слежка за одним узлом (копия vlwatch.c) и поток, переписывавший
 * файл состояния раз в три секунды. */

/* ---- подъём -------------------------------------------------------------------------------- */

static void px_probe_report(const char *out_name, enum probe_state st, int node, int total) {
    if (!evline_enabled()) probe_report(out_name, st, node, total);
}

/* Устройство поднято: up демону и слежку завёл пул; здесь — только строка о маршруте без демона. */
static void px_ready(void *arg, const char *dev) {
    (void)arg;
    if (!evline_enabled())
        fprintf(stderr, LOG_I2 "%s поднят; маршрут выхода к нему ставит демон — без демона таблица выхода не тронута\n", dev);
}

/* Узел глазами пула: проверка — та же px_probe, что при подъёме и у `proxy-probe`. */
static int px_pool_probe(const void *node, int timeout_s, char *why, size_t why_n) {
    int hs;
    return px_probe(node, timeout_s, why, why_n, &hs);
}
static const char *px_pool_name(const void *node) { return ((const struct px_node *)node)->name; }

int cmd_proxy(const char *spec_path, const char *out_name) {
    evline_open();
    struct output *o = NULL;
    size_t cnt = 0;
    struct px_sub_stats st;
    struct spec *sp = spec_new();
    int rc = load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    struct px_node *nodes = g_nodes;
    if (!cnt) {
        px_probe_report(out_name, PROBE_FAILED, 0, 0);
        evline_emit("down", "why", EVLINE_STR, "в подписке нет пригодных узлов", (const char *)NULL);
        fprintf(stderr, LOG_W2 "в подписке нет пригодных узлов (пропущено %zu, чужих %zu)\n", st.skipped, st.foreign);
        for (size_t i = 0; i < st.reasons_n; i++)
            fprintf(stderr, LOG_W2 "  %s — узлов %zu%s%s\n", st.reasons[i].reason, st.reasons[i].count,
                    st.reasons[i].example[0] ? ", например " : "", st.reasons[i].example);
        return 1;
    }
    fprintf(stderr, LOG_I2 "узлов %zu (пропущено %zu, чужих %zu)\n", cnt, st.skipped, st.foreign);
    size_t cap;
    int *sel = sel_alloc(o, cnt, &cap);
    size_t sel_n = out_proxy_node_list(o, cnt, sel, cap);
    if (!sel_n) {
        px_probe_report(out_name, PROBE_NO_SUCH_NODE, o->proxy.nodes_n ? o->proxy.nodes[0] : -1, (int)cnt);
        evline_emit("nonode", "node", EVLINE_INT, (long)(o->proxy.nodes_n ? o->proxy.nodes[0] : -1),
                    "total", EVLINE_INT, (long)cnt, (const char *)NULL);
        fprintf(stderr, LOG_W2 "выбранных узлов нет в подписке (пригодных всего %zu) — проверьте nodes\n", cnt);
        return 1;
    }
    size_t before = sel_n;
    sel_n = exclude_filter(o, nodes, sel, sel_n);
    if (!sel_n) {
        px_probe_report(out_name, PROBE_ALL_EXCLUDED, 0, (int)before);
        evline_emit("excluded", "total", EVLINE_INT, (long)before, (const char *)NULL);
        evline_emit("down", "why", EVLINE_STR, "все узлы-кандидаты исключены exclude", (const char *)NULL);
        fprintf(stderr, LOG_W2 "все %zu узлов-кандидатов исключены exclude или exclude_name — проверьте "
                        "исключение и подписку\n", before);
        return 1;
    }
    int chosen = -1;
    if (out_proxy_node_named(o)) { chosen = sel[0]; probe_clear(out_name); }
    else {
        for (size_t i = 0; i < sel_n; i++) {
            char why[256];
            int hs = 0;
            px_probe_report(out_name, PROBE_RUNNING, (int)i + 1, (int)sel_n);
            evline_emit("node", "n", EVLINE_INT, (long)(i + 1), "total", EVLINE_INT, (long)sel_n, (const char *)NULL);
            if (px_probe(&nodes[sel[i]], 8, why, sizeof(why), &hs) == 0) {
                fprintf(stderr, LOG_I2 "выбран %s (рукопожатие %d мс)\n", nodes[sel[i]].name, hs);
                chosen = sel[i];
                break;
            }
            fprintf(stderr, LOG_I2 "%s — %s\n", nodes[sel[i]].name, why);
        }
    }
    if (chosen < 0) {
        px_probe_report(out_name, PROBE_FAILED, 0, (int)sel_n);
        evline_emit("down", "why", EVLINE_STR, "ни один узел подписки не отвечает", (const char *)NULL);
        fprintf(stderr, LOG_W2 "ни один узел подписки не отвечает\n");
        return 1;
    }
    probe_clear(out_name);
    /* Пул узлов (src/tunnel/pool.c), как у vless: первый активный — выбранный здесь, остальные
     * `active - 1` пул найдёт среди кандидатов сам. */
    static struct pool_proto proto;
    static char extra[48];
    snprintf(extra, sizeof extra, "\"protocol\":\"%s\"", px_proto_name(nodes[chosen].proto));
    proto.ops = px_dialer_for(nodes[chosen].proto);
    proto.probe = px_pool_probe;
    proto.name = px_pool_name;
    proto.tag = "proxy";
    proto.extra = extra;
    static struct pool_cfg pc;
    const struct tun_pool *tp = &o->proxy.pool;
    pc.proto = &proto;
    pc.nodes = nodes;
    pc.stride = sizeof(*nodes);
    pc.sel = sel;
    pc.sel_n = sel_n;
    pc.first = chosen;
    pc.checked = !out_proxy_node_named(o);
    pc.active = tp->active ? tp->active : 1;
    pc.by = tp->by;
    pc.pick = tp->pick;
    pc.tolerance_ms = tp->tol_set ? tp->tolerance_ms : -1;
    pc.interval_s = tp->interval_s;         /* 0 — умолчание пула: у pick: latency своё */
    pc.silence_s = tp->silence_s < 0 ? 0 : tp->silence_s ? tp->silence_s : POOL_SILENCE_S;
    pc.out = out_name;
    struct err e = {0};
    if (registry_assign(sp, &e) < 0) err_die(&e);
    return px_tunnel_run(o, &pc, px_ready, NULL);
}
