/* steer dns-probe — быстрая проверка DNS-серверов тем же кодом, которым ходит резолвер.
 *
 * ЗАЧЕМ. Вкладка DNS splify2 при открытии ставит каждому серверу (готовые профили и добавленные
 * человеком — их десятки) зелёную или красную лампочку. Проверять надо с роутера и тем же путём, что
 * у резолвера: DoH, DoH3, DoT, DoQ, TCP и UDP, bootstrap, адреса из `ips`, разрез ClientHello
 * (`fragment`) и выход запроса. Отдельный клиент (curl, nslookup) мерил бы не то: у него свой TLS,
 * своё разрешение имени и нет метки выхода.
 *
 * КАК. Слой апстримов резолвера (dup.h) поднимается в этом процессе со своим циклом epoll: каждый
 * сервер — апстрим настройки, вопрос A `--name` уходит всем разом, ответ приходит обратным вызовом.
 * Срок один на всех (`--timeout`). Число серверов не ограничено.
 *
 * ЧТО ЗНАЧИТ ms. Первый вопрос к серверу с соединением (всё, кроме udp) ещё и поднимает соединение:
 * bootstrap, TCP, TLS или QUIC. Поэтому после годного ответа уходит второй вопрос по готовому
 * соединению, и `ms` — его время, то есть оборот запроса к серверу. Время первого — `first_ms`
 * (с подъёмом соединения). Второй не успел до срока — `ms` равно первому. У udp вопрос один.
 *
 * ГОДНЫЙ ОТВЕТ — по dup_ans_good (любой, кроме SERVFAIL и REFUSED), как у резолвера. Текст отказа —
 * последняя ошибка апстрима, как в `dns-log`.
 *
 * Вывод — одна строка JSON в stdout, код 0, даже если отказали все:
 *   {"name":"cloudflare.com","results":[{"url":…,"proto":"doh","ok":true,"ms":41,"first_ms":120},
 *                                       {"url":…,"proto":"dot","ok":false,"error":"…"}]}
 * Неразборчивый адрес сервера — запись с ok false и причиной, остальные проверяются. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/random.h>

#include "dnsd_int.h"
#include "dup.h"
#include "err.h"
#include "jsonw.h"
#include "platform.h"
#include "registry.h"
#include "spec.h"

#define DP_TIMEOUT_MS 3000
#define DP_NAME "cloudflare.com"

struct dp {
    const char *arg;            /* как назван в командной строке (URL[=IP,IP]) */
    char url[256];
    char why[200];              /* отказ разбора: сервер не спрашивается */
    int idx;                    /* номер апстрима в настройке; -1 — не спрашивается */
    int stage;                  /* 0 — ждём первый ответ, 1 — второй, 2 — готово */
    int ok;
    long t0, t1;                /* отправка первого и второго вопроса */
    long first_ms, ms;
    char err[200];
};

static struct dp *g_dp;
static size_t g_dp_n, g_dp_left;
static uint8_t g_q[300];
static size_t g_qn;

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Вопрос A name, RD, со случайным номером (номер у каждого вопроса свой — dup ставит свой поверх
 * при передаче, но годность ответа и разбор от него не зависят). */
static size_t build_query(const char *name, uint8_t *q, size_t cap) {
    uint16_t id;
    if (getrandom(&id, sizeof id, GRND_NONBLOCK) != (ssize_t)sizeof id) id = (uint16_t)mono_ms();
    size_t n = 0;
    q[n++] = (uint8_t)(id >> 8); q[n++] = (uint8_t)id;
    q[n++] = 0x01; q[n++] = 0x00;                       /* RD */
    q[n++] = 0; q[n++] = 1;                             /* QDCOUNT 1 */
    memset(q + n, 0, 6); n += 6;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63 || n + l + 6 > cap) return 0;
        q[n++] = (uint8_t)l;
        memcpy(q + n, p, l);
        n += l;
        p += l;
        if (*p == '.') p++;
    }
    q[n++] = 0;
    q[n++] = 0; q[n++] = 1;                             /* A */
    q[n++] = 0; q[n++] = 1;                             /* IN */
    return n;
}

static void finish(struct dp *d, int ok, long ms) {
    if (d->stage == 2) return;
    d->ok = ok;
    if (ok) d->ms = ms;
    d->stage = 2;
    g_dp_left--;
}

static void on_answer(void *ctx, const uint8_t *ans, size_t n, const uint8_t *q, size_t qn) {
    (void)q; (void)qn;
    struct dp *d = ctx;
    long now = mono_ms();
    int good = ans && dup_ans_good(ans, n);
    if (d->stage == 0) {
        d->first_ms = now - d->t0;
        if (!good) {
            const char *e = dup_error((size_t)d->idx);
            snprintf(d->err, sizeof d->err, "%s", ans ? "сервер ответил отказом (SERVFAIL или REFUSED)"
                                                    : e && e[0] ? e : "нет ответа");
            finish(d, 0, 0);
            return;
        }
        /* Соединение поднято — второй вопрос по нему: оборот без подъёма. У udp поднимать нечего. */
        const struct dup_cfg *c = &g_dup_cfg[d->idx];
        if (c->u.proto != DNSP_UDP) {
            d->stage = 1;
            d->t1 = now;
            if (dup_ask((size_t)d->idx, g_q, g_qn, on_answer, d) == 0) return;
        }
        finish(d, 1, d->first_ms);
        return;
    }
    if (d->stage == 1) finish(d, 1, good ? now - d->t1 : d->first_ms);
}

/* Настройка апстрима из «URL[=IP,IP]». 0 — годна. */
static int dp_cfg(struct dp *d, size_t i, struct dup_cfg *c, const struct spec *sp, int have_sp,
                  const char *out, int frag) {
    memset(c, 0, sizeof *c);
    const char *eq = strchr(d->arg, '=');
    size_t ul = eq ? (size_t)(eq - d->arg) : strlen(d->arg);
    if (ul >= sizeof d->url) { snprintf(d->why, sizeof d->why, "адрес длиннее %zu байт", sizeof d->url - 1); return -1; }
    memcpy(d->url, d->arg, ul);
    d->url[ul] = '\0';
    /* Голый адрес (как сервер в настройке dnsmasq) — DNS по UDP. */
    if (!strstr(d->url, "://")) {
        char t[sizeof d->url];
        snprintf(t, sizeof t, "%s", d->url);
        if (snprintf(d->url, sizeof d->url, "udp://%s", t) >= (int)sizeof d->url) {
            snprintf(d->why, sizeof d->why, "адрес слишком длинный");
            return -1;
        }
    }
    snprintf(c->u.name, sizeof c->u.name, "probe%zu", i);
    snprintf(c->u.url, sizeof c->u.url, "%s", d->url);
    c->u.out = -1;
    char why[160];
    if (dnsurl_parse(d->url, &c->u, why, sizeof why) != 0) {
        snprintf(d->why, sizeof d->why, "%s", why);
        return -1;
    }
    if (frag) {
        if (c->u.proto != DNSP_DOT && c->u.proto != DNSP_DOH) {
            snprintf(d->why, sizeof d->why, "--fragment — только у DoT и DoH");
            return -1;
        }
        c->u.frag = 1;
    }
    /* Адреса сервера после «=»: минуют bootstrap, как `ips` апстрима спеки. */
    if (eq) {
        size_t cnt = 1;
        for (const char *p = eq + 1; *p; p++) cnt += *p == ',';
        c->u.ips = calloc(cnt, sizeof(*c->u.ips));
        if (!c->u.ips) { snprintf(d->why, sizeof d->why, "нет памяти"); return -1; }
        const char *p = eq + 1;
        while (*p) {
            size_t l = strcspn(p, ",");
            if (l && l < sizeof(c->u.ips[0])) {
                memcpy(c->u.ips[c->u.ips_n], p, l);
                c->u.ips[c->u.ips_n][l] = '\0';
                c->u.ips_n++;
            } else if (l) {
                snprintf(d->why, sizeof d->why, "адрес сервера «%.*s» — не адрес", (int)(l > 60 ? 60 : l), p);
                return -1;
            }
            p += l;
            if (*p == ',') p++;
        }
    }
    /* Bootstrap: общий из спеки, иначе 1.1.1.1 и 8.8.8.8. */
    static char defboot[2][46] = { "1.1.1.1", "8.8.8.8" };
    if (have_sp && sp->dns.boot_n) {
        c->u.boot = sp->dns.boot;
        c->u.boot_n = sp->dns.boot_n;
    } else {
        c->u.boot = defboot;
        c->u.boot_n = 2;
    }
    if (out) {
        const struct output *o = have_sp ? out_by_name(sp, out) : NULL;
        if (!o) { snprintf(d->why, sizeof d->why, "выхода «%s» нет в спеке", out); return -1; }
        snprintf(c->via, sizeof c->via, "%s", out);
        c->mark = o->mark;
        c->need_mark = 1;
    }
    return 0;
}

static void usage(FILE *f) {
    fputs("steer dns-probe [--timeout MS] [--name ИМЯ] [--fragment] [--out ВЫХОД] [--spec ФАЙЛ] URL[=IP,IP] ...\n", f);
}

void dns_probe_usage_flags(FILE *f) {
    fputs("  --timeout MS   общий срок на все серверы, мс (умолчание 3000)\n"
          "  --name ИМЯ     о каком имени спрашивать (A), умолчание cloudflare.com\n"
          "  --fragment     ClientHello двумя записями TLS (DoT и DoH), как fragment апстрима\n"
          "  --out ВЫХОД    запрос через выход спеки (его меткой), иначе напрямую\n"
          "  --spec ФАЙЛ    спека: bootstrap и метки выходов (без неё — 1.1.1.1 и 8.8.8.8)\n", f);
}

int dns_probe_main(int argc, char **argv) {
    long timeout = DP_TIMEOUT_MS;
    const char *name = DP_NAME, *out = NULL, *spec_path = NULL;
    int frag = 0;
    size_t cap = (size_t)(argc > 0 ? argc : 1);
    g_dp = calloc(cap, sizeof(*g_dp));
    if (!g_dp) return 1;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--timeout") && i + 1 < argc) {
            char *end;
            timeout = strtol(argv[++i], &end, 10);
            if (*end || timeout < 100 || timeout > 60000) {
                fprintf(stderr, "steer: --timeout — от 100 до 60000 мс\n");
                return 2;
            }
        } else if (!strcmp(a, "--name") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(a, "--out") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(a, "--spec") && i + 1 < argc) spec_path = argv[++i];
        else if (!strcmp(a, "--state-dir") && i + 1 < argc) steer_set_state_dir(argv[++i]);
        else if (!strcmp(a, "--fragment")) frag = 1;
        else if (a[0] == '-' && a[1]) { usage(stderr); return 2; }
        else g_dp[g_dp_n++].arg = a;
    }
    if (!g_dp_n) { usage(stderr); return 2; }
    g_qn = build_query(name, g_q, sizeof g_q);
    if (!g_qn) { fprintf(stderr, "steer: --name «%s» — не имя\n", name); return 2; }

    /* Спека — ради bootstrap и меток выходов. Нет её — проверка всё равно идёт (напрямую). */
    static struct spec sp;
    int have_sp = 0;
    struct err e = { 0 };
    if (load_spec(plat_spec_resolve(spec_path), &sp, &e) == 0 && registry_assign(&sp, &e) == 0) have_sp = 1;
    else if (out) { fprintf(stderr, "steer: --out без спеки: %s\n", e.msg); return 2; }

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) { perror("epoll_create1"); return 1; }
    struct dup_cfg *cfg = calloc(g_dp_n, sizeof(*cfg));
    if (!cfg) return 1;
    size_t cn = 0;
    for (size_t i = 0; i < g_dp_n; i++) {
        struct dp *d = &g_dp[i];
        d->idx = -1;
        if (dp_cfg(d, i, &cfg[cn], &sp, have_sp, out, frag) != 0) { d->stage = 2; continue; }
        d->idx = (int)cn++;
    }
    /* Настройка — та, что видит dup (g_dup_cfg): dp_cfg кладёт адреса и протокол туда же. */
    g_dup_cfg = cfg;
    g_dup_cfg_n = g_dup_cfg_cap = cn;
    dup_apply(cfg, cn);
    long start = mono_ms(), deadline = start + timeout;
    for (size_t i = 0; i < g_dp_n; i++) {
        struct dp *d = &g_dp[i];
        if (d->idx < 0) continue;
        g_dp_left++;
        d->t0 = mono_ms();
        if (dup_ask((size_t)d->idx, g_q, g_qn, on_answer, d) != 0) {
            const char *er = dup_error((size_t)d->idx);
            snprintf(d->err, sizeof d->err, "%s", er && er[0] ? er : "вопрос не принят");
            finish(d, 0, 0);
        }
    }
    struct epoll_event ev[64];
    while (g_dp_left) {
        long now = mono_ms();
        if (now >= deadline) break;
        int wait = (int)(deadline - now);
        int dw = dup_wait_ms();
        if (dw >= 0 && dw < wait) wait = dw ? dw : 1;
        int k = epoll_wait(g_epfd, ev, 64, wait);
        for (int j = 0; j < k; j++) dup_event(ev[j].data.ptr, ev[j].events);
        dup_tick();
    }
    long now = mono_ms();
    for (size_t i = 0; i < g_dp_n; i++) {
        struct dp *d = &g_dp[i];
        if (d->stage == 1) finish(d, 1, d->first_ms);         /* второй не успел — первое время */
        else if (d->stage == 0) {
            const char *er = d->idx >= 0 ? dup_error((size_t)d->idx) : NULL;
            snprintf(d->err, sizeof d->err, "%s", er && er[0] ? er : "нет ответа");
            d->first_ms = now - d->t0;
            finish(d, 0, 0);
        }
    }

    printf("{\"name\":");
    jsonw_str(stdout, name);
    printf(",\"timeout_ms\":%ld,\"results\":[", timeout);
    for (size_t i = 0; i < g_dp_n; i++) {
        struct dp *d = &g_dp[i];
        printf("%s{\"url\":", i ? "," : "");
        /* url — как названо (с «=адреса» — без них): по нему интерфейс сопоставляет ответ. */
        char shown[256];
        size_t sl = strcspn(d->arg, "=");
        snprintf(shown, sizeof shown, "%.*s", (int)(sl < sizeof shown ? sl : sizeof shown - 1), d->arg);
        jsonw_str(stdout, shown);
        const char *proto = "?";
        if (d->idx >= 0) {
            switch (cfg[d->idx].u.proto) {
            case DNSP_UDP: proto = "udp"; break;
            case DNSP_TCP: proto = "tcp"; break;
            case DNSP_DOT: proto = "dot"; break;
            case DNSP_DOH: proto = "doh"; break;
            case DNSP_QUIC: proto = "doq"; break;
            case DNSP_DOH3: proto = "doh3"; break;
            }
        }
        printf(",\"proto\":\"%s\",\"ok\":%s", proto, d->ok ? "true" : "false");
        if (d->ok) printf(",\"ms\":%ld,\"first_ms\":%ld", d->ms, d->first_ms);
        else {
            printf(",\"error\":");
            jsonw_str(stdout, d->why[0] ? d->why : d->err[0] ? d->err : "нет ответа");
        }
        putchar('}');
    }
    printf("]}\n");
    fflush(stdout);
    dup_close_all();
    return 0;
}
