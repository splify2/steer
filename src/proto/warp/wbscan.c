/* Подбор точек WARP — знание апстрима Zapret Manager (ZapretManager_LuCI.sh, _st_warp_scan1 и
 * соседи) на устройствах ядра steer вместо интерфейсов netifd.
 *
 * КАНДИДАТЫ. Адреса Cloudflare, на которых отвечает WARP: пулы 162.159.192/193/195, 188.114.96–99
 * и несколько 8.x; от каждого пула — «.1» и ещё WB_RAND случайных адресов из пулов. Порты: основные
 * 2408 500 1701 4500, а если все молчат (провайдер режет порты WARP) — 50 запасных. Какие порты
 * отвечают, выясняется один раз и помнится WB_PORTS_TTL (файл в каталоге состояния).
 *
 * РАЗВЕДКА РАЗОМ. Рукопожатие с кандидатами проверяется сразу на WB_PAR устройствах подбора (у ZM — 8
 * фоновых процессов shell; устройство ядра дешевле, и 16 вдвое сокращают разведку)
 * (PersistentKeepalive 5 — рукопожатие начинается без трафика); ответившие идут первыми.
 *
 * ПРИГОВОР — по одной точке на устройстве с адресом и маршрутом в пространстве подбора:
 *   рукопожатие (до WB_HS_WAIT с; нет — ещё до двух других открытых портов),
 *   10 эхо-запросов к 1.1.1.1 (wbping.c): потери, задержка, обрыв — обрыв отбрасывает точку сразу,
 *   trace https://one.one.one.one/cdn-cgi/trace на 1.1.1.1: HTTPS проходит, колония, страна,
 *     которую видят сайты, и warp=on — устройство включено (регистрация без PATCH даст warp=off),
 *   speed.cloudflare.com/meta — город и страна колонии (не обязательно: не ответил — без них).
 * Хороших точек набирается s->want, дальше подбор не идёт.
 *
 * СТРАНЫ (решение владельца: выбор и исключение опцией, в том числе российской — она нужна
 * ReCheck). Страна точки — та, что видят сайты (loc trace), а исключение действует и по стране
 * колонии: выход через российскую колонию заблокированного не открывает, даже если адрес числится
 * зарубежным. Без countries и exclude_countries — любые страны (решение владельца 2026-10-13). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/stat.h>

#include "awg.h"
#include "wbconf.h"
#include "wbhttps.h"
#include "wbjson.h"
#include "wbns.h"
#include "wbping.h"
#include "wbscan.h"

#define WB_RAND 10
#define WB_PAR 16
#define WB_PRE_WAIT_MS 6000
#define WB_EXT_WAIT_MS 3000
#define WB_HS_WAIT_MS 8000
#define WB_PORTS_TTL (12 * 3600)
#define WB_PORTS_MAX 3
#define WB_TORN_GIVEUP 6

static const char *const POOLS[] = {
    "162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "8.34.70.", "8.34.146.", "8.39.214.", "8.39.204.", "8.6.112.", "8.35.211.",
    "8.39.125.", "8.47.69.",
};
#define POOLS_N (sizeof(POOLS) / sizeof(POOLS[0]))

static const unsigned PORTS[] = { 2408, 500, 1701, 4500 };
static const unsigned PORTS_EXT[] = {
    854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
    987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581,
    3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
};

/* Российские колонии (ST_RU_COLOS апстрима). */
static const char *const RU_COLOS[] = { "DME", "SVX", "LED", "KJA", "REN", "OVB", "KZN", "AER", "VVO" };

int wb_colo_is_ru(const char *colo) {
    for (size_t i = 0; i < sizeof(RU_COLOS) / sizeof(RU_COLOS[0]); i++)
        if (!strcmp(colo, RU_COLOS[i])) return 1;
    return 0;
}

static unsigned rnd(unsigned n) {
    unsigned v = 0;
    if (getrandom(&v, sizeof(v), 0) != sizeof(v)) v = (unsigned)time(NULL) * 2654435761u;
    return n ? v % n : 0;
}

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void sleep_ms(long ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {}
}

#define LOG(...) fprintf(stderr, "steer-warpbox: " __VA_ARGS__)

/* ---- устройства подбора --------------------------------------------------------------------- */

static int dev_up(struct wb_scan *s, const char *dev, const char *ip, unsigned port, int addr, int keepalive) {
    char conf[512], ep[40];
    snprintf(conf, sizeof(conf), "%s/%s.conf", s->dir, dev);
    snprintf(ep, sizeof(ep), "%s:%u", ip, port);
    struct wb_conf c = { .reg = s->reg, .endpoint = ep, .i1 = s->i1, .obfs = s->obfs, .addr = addr,
                         .keepalive = keepalive };
    if (wb_conf_write(conf, &c) != 0) { LOG("файл %s не записан: %s\n", conf, strerror(errno)); return -1; }
    char err[256];
    int rc = awg_scan_up(dev, conf, s->fwmark, s->over, s->ns, err, sizeof(err));
    unlink(conf);
    if (rc) LOG("%s\n", err);
    return rc;
}

/* Разведка: рукопожатие с каждой точкой eps[i] разом, по WB_PAR устройств. ok[i] = 1 — ответила.
 * -1 — устройства подбора не создаются вовсе (проверять так нельзя). */
static int prescreen(struct wb_scan *s, char (*ips)[16], const unsigned *ports, size_t n, int *ok, long wait_ms) {
    size_t made_total = 0;
    for (size_t b = 0; b < n; b += WB_PAR) {
        size_t m = n - b < WB_PAR ? n - b : WB_PAR;
        int up[WB_PAR] = { 0 };
        char dev[WB_PAR][16];
        for (size_t k = 0; k < m; k++) {
            snprintf(dev[k], sizeof(dev[k]), "wbp%zu", k);
            up[k] = dev_up(s, dev[k], ips[b + k], ports[b + k], 0, 5) == 0;
            made_total += (size_t)up[k];
            ok[b + k] = 0;
        }
        long end = mono_ms() + wait_ms;
        for (;;) {
            int left = 0;
            for (size_t k = 0; k < m; k++) {
                if (!up[k] || ok[b + k]) continue;
                int64_t hs;
                uint64_t rx, tx;
                if (awg_scan_stat(dev[k], s->ns, &hs, &rx, &tx) == 0 && hs > 0) ok[b + k] = 1;
                else left++;
            }
            if (!left || mono_ms() >= end) break;
            sleep_ms(250);
        }
        for (size_t k = 0; k < m; k++) if (up[k]) awg_scan_down(dev[k], s->ns);
    }
    return made_total ? 0 : -1;
}

/* ---- порты ---------------------------------------------------------------------------------- */

static size_t ports_cached(struct wb_scan *s, unsigned *out) {
    char p[512];
    snprintf(p, sizeof(p), "%s/warp-ports", s->dir);
    struct stat st;
    if (stat(p, &st) != 0 || time(NULL) - st.st_mtime >= WB_PORTS_TTL) return 0;
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    size_t n = 0;
    unsigned v;
    while (n < WB_PORTS_MAX && fscanf(f, "%u", &v) == 1) if (v && v < 65536) out[n++] = v;
    fclose(f);
    return n;
}

static void ports_save(struct wb_scan *s, const unsigned *pt, size_t n) {
    char p[512];
    snprintf(p, sizeof(p), "%s/warp-ports", s->dir);
    FILE *f = fopen(p, "w");
    if (!f) return;
    for (size_t i = 0; i < n; i++) fprintf(f, "%u\n", pt[i]);
    fclose(f);
}

/* Открытые порты WARP. Порты пробуются разом на трёх адресах РАЗНЫХ семейств (162.159, 188.114, 8.x):
 * у апстрима ZM — на первых трёх адресах списка, то есть на одном семействе 188.114, и там, где
 * отвечает только другое (машина разработки 2026-10-12: 188.114.96–97 и 162.159.193 молчат,
 * 162.159.192 отвечает — тот самый адрес, что API отдаёт в регистрации), подбор заканчивался на
 * «ни один порт не ответил». Запасные порты — на первом из ответивших семейств или на первом. */
static size_t ports_find(struct wb_scan *s, unsigned *out) {
    size_t n = ports_cached(s, out);
    if (n) return n;
    static const char *const FAM[] = { "162.159.192.1", "188.114.96.1", "8.6.112.1" };
    size_t fn = s->quick ? 1 : sizeof(FAM) / sizeof(FAM[0]), pk = sizeof(PORTS) / sizeof(PORTS[0]);
    size_t ext = sizeof(PORTS_EXT) / sizeof(PORTS_EXT[0]), cap = ext > fn * pk ? ext : fn * pk;
    char (*ips)[16] = calloc(cap, sizeof(*ips));
    unsigned *pt = calloc(cap, sizeof(*pt));
    int *okv = calloc(cap, sizeof(*okv));
    if (!ips || !pt || !okv) goto out;
    size_t m = 0;
    for (size_t f = 0; f < fn; f++)
        for (size_t i = 0; i < pk; i++) { snprintf(ips[m], 16, "%s", FAM[f]); pt[m++] = PORTS[i]; }
    if (prescreen(s, ips, pt, m, okv, WB_PRE_WAIT_MS) != 0) goto out;
    /* Порт открыт, если ответил хоть на одном адресе; порядок — как в PORTS. */
    for (size_t i = 0; i < pk && n < WB_PORTS_MAX; i++)
        for (size_t f = 0; f < fn; f++) if (okv[f * pk + i]) { out[n++] = PORTS[i]; break; }
    if (!n && !s->quick) {
        LOG("основные порты WARP (2408 500 1701 4500) молчат — проверяю 50 запасных, это до минуты\n");
        for (size_t i = 0; i < ext; i++) { snprintf(ips[i], 16, "%s", FAM[0]); pt[i] = PORTS_EXT[i]; }
        if (prescreen(s, ips, pt, ext, okv, WB_EXT_WAIT_MS) == 0)
            for (size_t i = 0; i < ext && n < WB_PORTS_MAX; i++) if (okv[i]) out[n++] = PORTS_EXT[i];
        if (n) {
            char l[64] = "";
            for (size_t i = 0; i < n; i++) snprintf(l + strlen(l), sizeof(l) - strlen(l), " %u", out[i]);
            LOG("открыты запасные порты:%s\n", l);
        }
    }
    if (n) ports_save(s, out, n);
out:
    free(ips);
    free(pt);
    free(okv);
    return n;
}

/* ---- приговор точке ------------------------------------------------------------------------- */

/* Ответ trace: «ключ=значение» по строке. */
static void trace_field(const char *body, const char *key, char *dst, size_t n) {
    dst[0] = '\0';
    size_t kl = strlen(key);
    for (const char *l = body; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL)
        if (!strncmp(l, key, kl) && l[kl] == '=') {
            size_t v = strcspn(l + kl + 1, "\r\n");
            snprintf(dst, n, "%.*s", (int)v, l + kl + 1);
            return;
        }
}

static int trace_via(const struct wb_route *rt, struct wb_pt *p) {
    struct wb_req q = { .host = "one.one.one.one", .addr = "1.1.1.1", .method = "GET",
                        .path = "/cdn-cgi/trace", .timeout_ms = 8000 };
    struct wb_resp r;
    char why[256];
    if (wb_https(&q, rt, &r, why, sizeof(why)) != 0) return -1;
    int ok = r.status == 200 && r.body;
    if (ok) {
        char w[16];
        trace_field(r.body, "colo", p->colo, sizeof(p->colo));
        trace_field(r.body, "loc", p->seen, sizeof(p->seen));
        trace_field(r.body, "warp", w, sizeof(w));
        p->warp = !strcmp(w, "on") || !strcmp(w, "plus");
        ok = p->colo[0] != '\0';
    }
    wb_resp_free(&r);
    return ok ? 0 : -1;
}

int wb_trace_dev(const char *dev, struct wb_pt *p) {
    struct wb_route rt = { .dev = dev };
    return trace_via(&rt, p);
}

/* Город и страна колонии — speed.cloudflare.com/meta; адрес разрешается в пространстве роутера. */
static void meta_via(const char *addr, struct wb_pt *p) {
    if (!addr[0]) return;
    struct wb_req q = { .host = "speed.cloudflare.com", .addr = addr, .method = "GET", .path = "/meta",
                        .headers = "Referer: https://speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\n",
                        .timeout_ms = 8000 };
    struct wb_resp r;
    char why[256];
    if (wb_https(&q, NULL, &r, why, sizeof(why)) != 0) return;
    if (r.status == 200 && r.body) {
        char colo[8] = "";
        if (wb_json_get(r.body, "colo.iata", colo, sizeof(colo)) == 0 && strlen(colo) == 3 && !strcmp(colo, p->colo)) {
            wb_json_get(r.body, "colo.cca2", p->cc, sizeof(p->cc));
            wb_json_get(r.body, "colo.city", p->city, sizeof(p->city));
        }
    }
    wb_resp_free(&r);
}

static int cc_in(const char *c, const char (*l)[3], size_t n) {
    for (size_t i = 0; c[0] && i < n; i++) if (!strcasecmp(c, l[i])) return 1;
    return 0;
}

/* Проходит ли точка фильтр стран. */
static int country_ok(const struct wb_scan *s, const struct wb_pt *p) {
    const char *own = p->seen[0] ? p->seen : p->cc;
    int ru_colo = wb_colo_is_ru(p->colo);
    if (cc_in(p->seen, s->xcc, s->xcc_n) || cc_in(p->cc, s->xcc, s->xcc_n)) return 0;
    if (ru_colo && cc_in("RU", s->xcc, s->xcc_n)) return 0;
    if (s->cc_n) {
        if (cc_in(own, s->cc, s->cc_n)) return 1;
        return ru_colo && cc_in("RU", s->cc, s->cc_n);
    }
    return 1;
}

static int busy_colo(const struct wb_scan *s, const char *colo) {
    for (size_t i = 0; i < s->busy_colo_n; i++) if (!strcmp(s->busy_colo[i], colo)) return 1;
    return 0;
}

static int busy_ip(const struct wb_scan *s, const char *ip) {
    for (size_t i = 0; i < s->busy_ip_n; i++) if (!strcmp(s->busy_ip[i], ip)) return 1;
    return 0;
}

static int wait_hs(struct wb_scan *s, const char *dev, long ms) {
    long end = mono_ms() + ms;
    do {
        int64_t hs;
        uint64_t rx, tx;
        if (awg_scan_stat(dev, s->ns, &hs, &rx, &tx) == 0 && hs > 0) return 1;
        sleep_ms(250);
    } while (mono_ms() < end);
    return 0;
}

/* Рукопожатие с ip:port на устройстве приговора; эхо-запрос его подталкивает. */
static int link_try(struct wb_scan *s, const char *dev, const char *ip, unsigned port) {
    awg_scan_down(dev, s->ns);
    if (dev_up(s, dev, ip, port, 1, 25) != 0) return -1;
    int old;
    if (wb_ns_enter(s->ns, &old) == 0) {
        struct wb_ping pg;
        wb_ping_burst("1.1.1.1", 1, 0, 0, &pg);
        wb_ns_leave(old);
    }
    if (wait_hs(s, dev, WB_HS_WAIT_MS)) return 0;
    awg_scan_down(dev, s->ns);
    return 1;
}

static void out_add(struct wb_scan *s, const struct wb_pt *p) {
    if (s->out_n == s->out_cap) {
        size_t nc = s->out_cap ? s->out_cap * 2 : 8;
        struct wb_pt *n = realloc(s->out, nc * sizeof(*n));
        if (!n) return;
        s->out = n;
        s->out_cap = nc;
    }
    s->out[s->out_n++] = *p;
}

static int pt_cmp(const void *a, const void *b) {
    const struct wb_pt *x = a, *y = b;
    if (x->cls != y->cls) return x->cls - y->cls;
    if (x->loss != y->loss) return x->loss - y->loss;
    return x->rtt - y->rtt;
}

/* ---- подбор --------------------------------------------------------------------------------- */

enum { J_OK = 0, J_SILENT, J_TORN, J_NOTLS };

/* Приговор точке ip:port на устройстве dev (рукопожатие уже есть — link_try): эхо, trace, meta. p —
 * итог (loss, rtt, колония, страны). */
static int judge(struct wb_scan *s, const char *dev, const char *meta_addr, struct wb_pt *p) {
    struct wb_ping pg = { 0 };
    int old, pr = -1, tr = -1;
    if (wb_ns_enter(s->ns, &old) == 0) {
        pr = wb_ping_burst("1.1.1.1", 10, 200, 2000, &pg);
        if (pr == 0 && pg.got == 0) pr = wb_ping_burst("8.8.8.8", 10, 200, 2000, &pg);
        if (pr == 0 && pg.got && !pg.torn) {
            tr = trace_via(NULL, p);
            if (tr == 0) meta_via(meta_addr, p);
        }
        wb_ns_leave(old);
    }
    awg_scan_down(dev, s->ns);
    if (pr != 0 || !pg.got) return J_SILENT;
    p->loss = pg.loss;
    p->rtt = pg.rtt;
    if (pg.torn) return J_TORN;
    return tr != 0 ? J_NOTLS : J_OK;
}

/* Точка, которая уже стоит в туннеле (s->also_ip), — той же мерой, что кандидаты: смена на ходу
 * сравнивает их на равных (wbmain.c, «самая быстрая точка»). */
static void judge_also(struct wb_scan *s, const char *dev, const char *meta_addr) {
    struct wb_pt *p = &s->also;
    memset(p, 0, sizeof(*p));
    snprintf(p->ip, sizeof(p->ip), "%s", s->also_ip);
    p->port = s->also_port;
    s->also_ok = 0;
    if (link_try(s, dev, s->also_ip, s->also_port) != 0) {
        LOG("текущая точка %s:%u — рукопожатия нет\n", s->also_ip, s->also_port);
        return;
    }
    int j = judge(s, dev, meta_addr, p);
    if (j == J_OK) {
        s->also_ok = 1;
        LOG("текущая точка %s:%u — потери %d%%, %d мс, колония %s\n", p->ip, p->port, p->loss, p->rtt, p->colo);
    } else
        LOG("текущая точка %s:%u — %s\n", p->ip, p->port,
            j == J_SILENT ? "туннель молчит" : j == J_TORN ? "трафик обрывается" : "HTTPS через туннель не идёт");
}

int wb_scan_run(struct wb_scan *s) {
    s->out_n = 0;
    s->torn = s->rufilt = 0;
    s->why[0] = '\0';
    if (!s->want) s->want = 3;
    /* Кандидаты: «.1» каждого пула и случайные. */
    size_t cmax = POOLS_N + WB_RAND, cn = 0;
    char (*cand)[16] = calloc(cmax, sizeof(*cand));
    unsigned *cport = calloc(cmax, sizeof(*cport));
    int *alive = calloc(cmax, sizeof(*alive));
    if (!cand || !cport || !alive) { free(cand); free(cport); free(alive); snprintf(s->why, sizeof(s->why), "нет памяти"); return -1; }
    size_t base = s->quick ? 4 : POOLS_N, extra = s->quick ? 2 : WB_RAND;
    for (size_t i = 0; i < base; i++) snprintf(cand[cn++], 16, "%s1", POOLS[i]);
    for (size_t i = 0; i < extra; i++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "%s%u", POOLS[rnd(POOLS_N)], 2 + rnd(253));
        int dup = 0;
        for (size_t k = 0; k < cn; k++) if (!strcmp(cand[k], ip)) dup = 1;
        if (!dup) memcpy(cand[cn++], ip, 16);
    }
    unsigned ports[WB_PORTS_MAX];
    size_t pn = ports_find(s, ports);
    int rc = -1;
    if (!pn) {
        snprintf(s->why, sizeof(s->why), "ни один порт WARP не ответил — ни основные, ни запасные");
        goto out;
    }
    /* У каждого туннеля группы свой первый порт: одна заблокированная пара адрес:порт не кладёт всех. */
    unsigned p0 = ports[s->rot % pn];
    /* Разведка разом: ответившие — вперёд. */
    {
        size_t m = 0;
        char (*ips)[16] = calloc(cn, sizeof(*ips));
        size_t *idx = calloc(cn, sizeof(*idx));
        if (ips && idx) {
            for (size_t i = 0; i < cn; i++) {
                if (busy_ip(s, cand[i])) continue;
                memcpy(ips[m], cand[i], 16);
                cport[m] = p0;
                idx[m++] = i;
            }
            int *okv = calloc(m ? m : 1, sizeof(*okv));
            if (okv && m && prescreen(s, ips, cport, m, okv, WB_PRE_WAIT_MS) == 0) {
                size_t na = 0;
                for (size_t k = 0; k < m; k++) if (okv[k]) { alive[idx[k]] = 1; na++; }
                LOG("рукопожатие разом: ответили %zu из %zu точек (порт %u)\n", na, m, p0);
            }
            free(okv);
        }
        free(ips);
        free(idx);
    }
    /* Порядок приговора: ответившие, затем остальные. */
    size_t order_n = 0;
    size_t *order = calloc(cn, sizeof(*order));
    if (!order) goto out;
    for (int pass = 1; pass >= 0; pass--)
        for (size_t i = 0; i < cn; i++) if (alive[i] == pass) order[order_n++] = i;

    const char *dev = "wbv0";
    char meta_addr[64] = "";
    {
        struct addrinfo h = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *r = NULL;
        if (getaddrinfo("speed.cloudflare.com", "443", &h, &r) == 0 && r) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)r->ai_addr)->sin_addr, meta_addr, sizeof(meta_addr));
            freeaddrinfo(r);
        }
    }
    if (s->also_ip && s->also_ip[0]) judge_also(s, dev, meta_addr);
    size_t good = 0;
    int altleft = 2;
    /* Хватит, когда набралось want хороших — или want + 2 годных любого класса: если все колонии
     * заняты соседями (у машины разработки все точки — HEL), хорошей не будет ни одной, и без этого
     * предела подбор перебирал бы всех кандидатов до последнего. Не ответившие разведке пробуются,
     * только пока годных меньше want: каждая такая — до трёх рукопожатий по WB_HS_WAIT_MS. */
    for (size_t oi = 0; oi < order_n && good < s->want && s->out_n < s->want + 2; oi++) {
        const char *ip = cand[order[oi]];
        if (busy_ip(s, ip) || (s->also_ip && !strcmp(ip, s->also_ip))) continue;
        if (!alive[order[oi]] && s->out_n >= s->want) break;
        struct wb_pt p;
        memset(&p, 0, sizeof(p));
        snprintf(p.ip, sizeof(p.ip), "%s", ip);
        p.port = p0;
        int lr = link_try(s, dev, ip, p0);
        if (lr < 0) break;                       /* устройство не создаётся — дальше то же */
        if (lr > 0) {
            unsigned alt = 0;
            if (altleft > 0 && pn > 1) {
                altleft--;
                for (size_t k = 0; k < pn && !alt; k++)
                    if (ports[k] != p0 && link_try(s, dev, ip, ports[k]) == 0) alt = ports[k];
            }
            if (!alt) { LOG("%s:%u — рукопожатия нет\n", ip, p0); continue; }
            LOG("%s:%u — рукопожатия нет, через порт %u есть\n", ip, p0, alt);
            p.port = alt;
        }
        int j = judge(s, dev, meta_addr, &p);
        if (j == J_SILENT) { LOG("%s:%u — туннель молчит\n", ip, p.port); continue; }
        if (j == J_TORN) {
            s->torn++;
            LOG("%s:%u — трафик пошёл и оборвался: так DPI рвёт туннель\n", ip, p.port);
            if (s->torn >= WB_TORN_GIVEUP && !s->out_n) break;
            continue;
        }
        if (j == J_NOTLS) {
            p.cls = WB_NOTLS;
            snprintf(p.colo, sizeof(p.colo), "?");
            LOG("%s:%u — пинг идёт (%d мс), HTTPS через туннель — нет\n", ip, p.port, p.rtt);
            out_add(s, &p);
            continue;
        }
        LOG("%s:%u — потери %d%%, %d мс, колония %s%s%s%s, сайты видят %s%s\n", ip, p.port, p.loss, p.rtt,
            p.colo, p.city[0] ? " (" : "", p.city, p.city[0] ? ")" : "", p.seen[0] ? p.seen : "?",
            p.warp ? "" : ", а WARP выключен (warp=off)");
        if (!country_ok(s, &p)) { s->rufilt++; continue; }
        p.cls = busy_colo(s, p.colo) ? WB_SAME : WB_GOOD;
        out_add(s, &p);
        if (p.cls == WB_GOOD) good++;
    }
    free(order);
    if (s->out_n) {
        qsort(s->out, s->out_n, sizeof(*s->out), pt_cmp);
        rc = 0;
    } else if (s->torn)
        snprintf(s->why, sizeof(s->why), "через все ответившие точки (%d) DPI обрывает туннель — нужна другая маска", s->torn);
    else if (s->rufilt)
        snprintf(s->why, sizeof(s->why), "точки отвечают, но ни одна не проходит фильтр стран (отсеяно %d)", s->rufilt);
    else
        snprintf(s->why, sizeof(s->why), "ни одна точка не ответила рукопожатием");
out:
    free(cand);
    free(cport);
    free(alive);
    return rc;
}

void wb_scan_free(struct wb_scan *s) {
    free(s->out);
    s->out = NULL;
    s->out_n = s->out_cap = 0;
}
