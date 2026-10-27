/* Выдача ресурсов плагинам (plugalloc.h): alloc.json, порты, очереди, биты метки. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "spec.h"
#include "plugin.h"
#include "plugalloc.h"
#include "plugutil.h"
#include "ynode.h"

/* ---- ресурсы: alloc.json ---------------------------------------------------------------------- */

/* Выданные номера хранятся в <данные менеджера>/alloc.json:
 *   {"schema":1,"outputs":{"<плагин>/<выход>":{"ports":[…],"queues":[…]}}}
 * и постоянны между перезагрузками и обновлениями плагина (steer-api.md, 6). */
void pal_free(struct pal *a) {
    for (size_t i = 0; i < a->n; i++) { free(a->e[i].owner); free(a->e[i].ports); free(a->e[i].queues); free(a->e[i].bits); }
    free(a->e);
    memset(a, 0, sizeof(*a));
}

static void alloc_path(char *buf, size_t n) {
    char etc[PATH_MAX];
    plugin_etc(etc, sizeof(etc));
    snprintf(buf, n, "%s/alloc.json", etc);
}

static int pal_nums(const struct ynode *l, uint32_t **dst, size_t *n, long lo) {
    *dst = NULL;
    *n = 0;
    for (size_t i = 0; l && l->kind == YN_SEQ && i < l->len; i++) {
        long v;
        if (ynode_long(ynode_at(l, i), &v) != 0 || v < lo || v > 65535) continue;
        uint32_t *nd = realloc(*dst, (*n + 1) * sizeof(uint32_t));
        if (!nd) return -1;
        *dst = nd;
        (*dst)[(*n)++] = (uint32_t)v;
    }
    return 0;
}

int pal_load(struct pal *a) {
    memset(a, 0, sizeof(*a));
    char p[PATH_MAX + 16];
    alloc_path(p, sizeof(p));
    size_t n;
    char *t = slurp(p, &n);
    if (!t) return 0;
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(t, n, p, &e);
    free(t);
    if (!d) return 0;
    const struct ynode *o = ynode_get(ydoc_root(d), "outputs");
    for (size_t i = 0; o && o->kind == YN_MAP && i < ynode_len(o); i++) {
        struct pal_ent *ne = realloc(a->e, (a->n + 1) * sizeof(*ne));
        if (!ne) { ydoc_free(d); pal_free(a); return -1; }
        a->e = ne;
        struct pal_ent *en = &a->e[a->n];
        memset(en, 0, sizeof(*en));
        en->owner = strdup(ynode_key_at(o, i)->str);
        const struct ynode *v = ynode_val_at(o, i);
        if (!en->owner || pal_nums(ynode_get(v, "ports"), &en->ports, &en->pn, 1) != 0 ||
            pal_nums(ynode_get(v, "queues"), &en->queues, &en->qn, 1) != 0 ||
            pal_nums(ynode_get(v, "mark_bits"), &en->bits, &en->bn, 0) != 0) {
            ydoc_free(d);
            a->n++;
            pal_free(a);
            return -1;
        }
        a->n++;
    }
    ydoc_free(d);
    return 0;
}

int pal_save(const struct pal *a) {
    struct sbuf b = { 0 };
    sb_str(&b, "{\"schema\":1,\"outputs\":{");
    for (size_t i = 0; i < a->n; i++) {
        sb_printf(&b, "%s", i ? ",\n" : "\n");
        sb_json(&b, a->e[i].owner);
        sb_str(&b, ":{\"ports\":[");
        for (size_t k = 0; k < a->e[i].pn; k++) sb_printf(&b, "%s%u", k ? "," : "", a->e[i].ports[k]);
        sb_str(&b, "],\"queues\":[");
        for (size_t k = 0; k < a->e[i].qn; k++) sb_printf(&b, "%s%u", k ? "," : "", a->e[i].queues[k]);
        sb_str(&b, "]");
        if (a->e[i].bn) {
            sb_str(&b, ",\"mark_bits\":[");
            for (size_t k = 0; k < a->e[i].bn; k++) sb_printf(&b, "%s%u", k ? "," : "", a->e[i].bits[k]);
            sb_str(&b, "]");
        }
        sb_str(&b, "}");
    }
    sb_str(&b, "\n}}\n");
    int rc = -1;
    if (!b.oom && b.p) {
        char p[PATH_MAX + 16], etc[PATH_MAX];
        plugin_etc(etc, sizeof(etc));
        pu_mkdir_p(etc);
        alloc_path(p, sizeof(p));
        rc = pu_write_atomic(p, b.p, b.n, 0644);
    }
    free(b.p);
    return rc;
}

static struct pal_ent *pal_find(struct pal *a, const char *owner) {
    for (size_t i = 0; i < a->n; i++) if (!strcmp(a->e[i].owner, owner)) return &a->e[i];
    return NULL;
}

/* Порты и очереди, занятые у ядра: сокеты /proc/net/{tcp,udp}{,6}. */
static void sockets_used(unsigned char *used /* 65536 */) {
    static const char *const F[] = { "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", NULL };
    for (size_t i = 0; F[i]; i++) {
        FILE *f = fopen(F[i], "r");
        if (!f) continue;
        char line[512];
        if (!fgets(line, sizeof(line), f)) { fclose(f); continue; }
        while (fgets(line, sizeof(line), f)) {
            const char *c = strchr(line, ':');          /* «  0: 0100007F:1F90 …»: после номера записи */
            if (!c) continue;
            c = strchr(c + 1, ':');                     /* порт — после двоеточия адреса */
            if (!c) continue;
            unsigned long p = strtoul(c + 1, NULL, 16);
            if (p < 65536) used[p] = 1;
        }
        fclose(f);
    }
}

#define PORT_FIRST  10480
#define QUEUE_FIRST 4300

/* Выдать выходу owner n портов и m очередей (сколько уже есть — остаётся). 0 — готово; -1 — отказ,
 * называющий число свободных и занятых (steer-api.md, 6: «ресурс кончается только вместе с номерами»). */
int pal_ensure(struct pal *a, const char *owner, size_t n, size_t m, int *changed, struct err *e) {
    struct pal_ent *en = pal_find(a, owner);
    if (!en) {
        struct pal_ent *ne = realloc(a->e, (a->n + 1) * sizeof(*ne));
        if (!ne) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
        a->e = ne;
        en = &a->e[a->n++];
        memset(en, 0, sizeof(*en));
        en->owner = strdup(owner);
        if (!en->owner) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
        *changed = 1;
    }
    unsigned char *used = NULL;
    while (en->pn < n) {
        if (!used) {
            used = calloc(65536, 1);
            if (!used) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
            sockets_used(used);
            for (size_t i = 0; i < a->n; i++)
                for (size_t k = 0; k < a->e[i].pn; k++) used[a->e[i].ports[k]] = 1;
        }
        unsigned p = PORT_FIRST;
        while (p < 65536 && used[p]) p++;
        if (p >= 65536) {
            size_t taken = 0;
            for (size_t i = 0; i < a->n; i++) taken += a->e[i].pn;
            free(used);
            char msg[300];
            snprintf(msg, sizeof(msg), "порты: свободных нет — от %d до 65535 занято сокетами и выдано %zu "
                     "портов выходам плагинов", PORT_FIRST, taken);
            return err_set(e, "%s", msg);
        }
        uint32_t *np = realloc(en->ports, (en->pn + 1) * sizeof(uint32_t));
        if (!np) { free(used); return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов"); }
        en->ports = np;
        en->ports[en->pn++] = p;
        used[p] = 1;
        *changed = 1;
    }
    free(used);
    while (en->qn < m) {
        unsigned q = QUEUE_FIRST;
        for (;;) {
            int busy = 0;
            for (size_t i = 0; i < a->n && !busy; i++)
                for (size_t k = 0; k < a->e[i].qn; k++) if (a->e[i].queues[k] == q) busy = 1;
            if (!busy) break;
            q++;
        }
        if (q > 65535) return err_set(e, "%s", "очереди NFQUEUE: свободных нет — выдано всё от 4300 до 65535");
        uint32_t *nq = realloc(en->queues, (en->qn + 1) * sizeof(uint32_t));
        if (!nq) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
        en->queues = nq;
        en->queues[en->qn++] = q;
        *changed = 1;
    }
    return 0;
}

/* Биты метки, которые плагину нельзя отдавать: поле метки steer, бит 28 мини-сборки tgws, 29 и 30 —
 * zapret (DESYNC и пропуск), 16–23 — Tailscale и pbr, 8–13 — mwan3 (marks.h; steer-api.md, 6). */
static uint32_t bits_excluded(void) {
    return plat()->mark_mask | (1u << 28) | 0x60000000u | 0x00ff0000u | 0x00003f00u;
}

/* «29–31 у recheck, 0–7 у foo» — кто какие биты держит: для отказа «свободных нет». */
static void bits_holders(const struct pal *a, struct sbuf *b) {
    size_t put = 0;
    for (size_t i = 0; i < a->n; i++) {
        if (!a->e[i].bn) continue;
        uint32_t m = 0;
        for (size_t k = 0; k < a->e[i].bn; k++) m |= 1u << a->e[i].bits[k];
        for (int lo = 0; lo < 32; lo++) {
            if (!(m >> lo & 1u)) continue;
            int hi = lo;
            while (hi + 1 < 32 && (m >> (hi + 1) & 1u)) hi++;
            if (put++) sb_str(b, ", ");
            if (hi > lo) sb_printf(b, "%d–%d", lo, hi); else sb_printf(b, "%d", lo);
            sb_printf(b, " у %s", a->e[i].owner);
            lo = hi;
        }
    }
}

/* Выдать плагину запрошенное (resources манифеста): порты, очереди, биты метки. Ключ — «plugin:<id>». */
int pal_ensure_plugin(struct pal *a, const struct plugin *pl, int *changed, struct err *e) {
    char owner[200];
    snprintf(owner, sizeof(owner), "plugin:%s", pl->id);
    if (pal_ensure(a, owner, pl->res_ports, pl->res_queues, changed, e) != 0) return -1;
    struct pal_ent *en = pal_find(a, owner);
    while (en->bn < pl->res_marks) {
        uint32_t held = bits_excluded();
        for (size_t i = 0; i < a->n; i++)
            for (size_t k = 0; k < a->e[i].bn; k++) held |= 1u << a->e[i].bits[k];
        int bit = 31;
        while (bit >= 0 && (held >> bit & 1u)) bit--;
        if (bit < 0) {
            struct sbuf b = { 0 };
            bits_holders(a, &b);
            char m[600];
            snprintf(m, sizeof(m), "бит метки: свободных нет — %s", b.p ? b.p : "все заняты соседями и полем метки steer");
            free(b.p);
            return err_set(e, "%s", m);
        }
        uint32_t *nb = realloc(en->bits, (en->bn + 1) * sizeof(uint32_t));
        if (!nb) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
        en->bits = nb;
        en->bits[en->bn++] = (uint32_t)bit;
        *changed = 1;
    }
    return 0;
}

/* Ресурсы плагина для подстановок ({mark}, {queue0}, {port0}): один разбор alloc.json на файл
 * (по размеру и времени), а не на каждое слово argv и правило nft. */
static struct pal g_res_cache;
static struct timespec g_res_mtime;
static off_t g_res_size = -1;
static int g_res_have;

int plugin_res_get(const struct plugin *pl, struct plugin_res *r) {
    memset(r, 0, sizeof(*r));
    char p[PATH_MAX + 16];
    alloc_path(p, sizeof(p));
    struct stat st;
    if (stat(p, &st) != 0) { if (g_res_have) pal_free(&g_res_cache); g_res_have = 0; g_res_size = -1; return -1; }
    if (!g_res_have || st.st_size != g_res_size || st.st_mtim.tv_sec != g_res_mtime.tv_sec ||
        st.st_mtim.tv_nsec != g_res_mtime.tv_nsec) {
        if (g_res_have) pal_free(&g_res_cache);
        g_res_have = pal_load(&g_res_cache) == 0;
        g_res_size = st.st_size;
        g_res_mtime = st.st_mtim;
        if (!g_res_have) return -1;
    }
    char owner[200];
    snprintf(owner, sizeof(owner), "plugin:%s", pl->id);
    const struct pal_ent *en = pal_find(&g_res_cache, owner);
    if (!en || en->pn < pl->res_ports || en->qn < pl->res_queues || en->bn < pl->res_marks) return -1;
    r->ports = en->pn ? malloc(en->pn * sizeof(uint32_t)) : NULL;
    r->queues = en->qn ? malloc(en->qn * sizeof(uint32_t)) : NULL;
    r->bits = en->bn ? malloc(en->bn * sizeof(uint32_t)) : NULL;
    if ((en->pn && !r->ports) || (en->qn && !r->queues) || (en->bn && !r->bits)) { plugin_res_free(r); return -1; }
    if (en->pn) memcpy(r->ports, en->ports, en->pn * sizeof(uint32_t));
    if (en->qn) memcpy(r->queues, en->queues, en->qn * sizeof(uint32_t));
    if (en->bn) memcpy(r->bits, en->bits, en->bn * sizeof(uint32_t));
    r->ports_n = en->pn; r->queues_n = en->qn; r->bits_n = en->bn;
    return 0;
}

void plugin_res_free(struct plugin_res *r) {
    free(r->ports); free(r->queues); free(r->bits);
    memset(r, 0, sizeof(*r));
}

int plugin_alloc_lookup(struct spec *sp, const struct plugin_kind *pk, const char *out,
                        uint32_t **ports, size_t *pn, uint32_t **queues, size_t *qn) {
    *ports = *queues = NULL;
    *pn = *qn = 0;
    if (!pk->res_ports && !pk->res_queues) return 0;
    struct pal a;
    if (pal_load(&a) != 0) return -1;
    char owner[200];
    snprintf(owner, sizeof(owner), "%s/%s", pk->owner->id, out);
    const struct pal_ent *en = pal_find(&a, owner);
    int rc = -1;
    if (en && en->pn >= pk->res_ports && en->qn >= pk->res_queues) {
        if (en->pn) *ports = spec_memdup(sp, en->ports, en->pn * sizeof(uint32_t));
        if (en->qn) *queues = spec_memdup(sp, en->queues, en->qn * sizeof(uint32_t));
        if ((!en->pn || *ports) && (!en->qn || *queues)) {
            *pn = en->pn;
            *qn = en->qn;
            rc = 0;
        }
    }
    pal_free(&a);
    return rc;
}

int plugin_alloc_out(struct spec *sp, const struct plugin_kind *pk, const char *out,
                     uint32_t **ports, size_t *pn, uint32_t **queues, size_t *qn, struct err *e) {
    if (plugin_alloc_lookup(sp, pk, out, ports, pn, queues, qn) == 0) return 0;
    struct pal a;
    if (pal_load(&a) != 0) return err_set(e, "%s", "недостаточно памяти для выдачи ресурсов");
    char owner[200];
    snprintf(owner, sizeof(owner), "%s/%s", pk->owner->id, out);
    int ch = 0;
    int rc = pal_ensure(&a, owner, pk->res_ports, pk->res_queues, &ch, e);
    if (rc == 0 && ch && pal_save(&a) != 0) rc = err_set(e, "ресурсы выхода %s не записаны (alloc.json)", out);
    pal_free(&a);
    if (rc != 0) return -1;
    if (plugin_alloc_lookup(sp, pk, out, ports, pn, queues, qn) != 0)
        return err_set(e, "ресурсы выхода %s не выданы (alloc.json)", out);
    return 0;
}
